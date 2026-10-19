// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Modül: github.com/Xmar1881/Gash

package plugin

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/time/rate"
)

// ErrorClass classifies transport errors for retry/backoff decisions.
type ErrorClass int

const (
	ErrorClassUnknown ErrorClass = iota
	ErrorClassTimeout
	ErrorClassNetwork
	ErrorClassPolicy
	ErrorClassServer
	ErrorClassClient
	ErrorClassRedirect
	ErrorClassScope
)

// ClassifyError maps an error to its class for deterministic retry logic.
// What: Single classification point so callers don't guess error types.
// Why: Retry/backoff and logging must be consistent across probe, plugins, and tests.
func ClassifyError(err error) ErrorClass {
	if err == nil {
		return ErrorClassUnknown
	}
	var perr *PolicyError
	if errors.As(err, &perr) {
		switch perr.Op {
		case "scope":
			return ErrorClassScope
		case "rate":
			return ErrorClassPolicy
		case "budget":
			return ErrorClassPolicy
		case "method":
			return ErrorClassPolicy
		}
		return ErrorClassPolicy
	}
	var netErr net.Error
	if errors.As(err, &netErr) {
		if netErr.Timeout() {
			return ErrorClassTimeout
		}
		return ErrorClassNetwork
	}
	var urlErr *url.Error
	if errors.As(err, &urlErr) {
		if urlErr.Timeout() {
			return ErrorClassTimeout
		}
		return ErrorClassNetwork
	}
	// http.ProtocolError, http.ErrHandlerTimeout, etc.
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		return ErrorClassTimeout
	}
	// Check for redirect-related errors
	if strings.Contains(err.Error(), "redirect") || strings.Contains(err.Error(), "Redirect") {
		return ErrorClassRedirect
	}
	return ErrorClassUnknown
}

// IsRetryable returns true if the error class warrants a retry per RetryConfig.
// What: Central retryability decision so plugins and probe share logic.
// Why: Prevents ad-hoc retry loops that violate budget/rate limits.
func IsRetryable(class ErrorClass, statusCode int, retryableStatus []int) bool {
	switch class {
	case ErrorClassTimeout, ErrorClassNetwork:
		return true
	case ErrorClassServer:
		for _, s := range retryableStatus {
			if s == statusCode {
				return true
			}
		}
		return false
	case ErrorClassPolicy, ErrorClassScope, ErrorClassClient:
		return false
	default:
		return false
	}
}

// PolicyConfig PolicySession davranışıdır (bayraklar → buraya).
type PolicyConfig struct {
	// SafeDefault tarama safe varsayılanıdır; Safe=false plugin'ler ayrıca filtrelenir.
	MaxRequestsPerTarget int64
	MaxRequestsTotal     int64
	Scope                []string // CIDR/domain allowlist; boşsa open mod (blok yok, operatör sorumluluğu)
	RatePerSecond        float64  // per-target token bucket; <=0 ise limitsiz (testler için)
	MaxResponseBytes     int64

	// P1.1: Global rate limit (all targets combined)
	GlobalRatePerSecond float64
	// P1.1: Per-host concurrency limit
	MaxConcurrencyPerHost int
	// P1.1: Total scan timeout
	ScanTimeout time.Duration
	// P1.1: Retry configuration
	RetryConfig RetryConfig
	// P1.1: Redirect policy
	RedirectPolicy RedirectPolicy
	// P1.1: Request/response size limits
	MaxRequestBytes int64
	// P1.1: Backpressure threshold (in-flight requests)
	BackpressureLimit int
	// ProxyURL upstream HTTP proxy URL (örn. http://127.0.0.1:8080).
	ProxyURL *url.URL
}

// RetryConfig controls retry behavior for idempotent requests.
type RetryConfig struct {
	MaxRetries      int
	BaseDelay       time.Duration
	MaxDelay        time.Duration
	RetryableStatus []int
}

// RedirectPolicy controls redirect behavior and scope re-validation.
type RedirectPolicy struct {
	MaxRedirects    int
	FollowRedirects bool
	RevalidateScope bool // Re-validate scope after each redirect
	// AllowCrossScheme allows http→https upgrade redirects only.
	// https→http downgrades are never allowed, regardless of this flag.
	AllowCrossScheme bool
}

// DefaultPolicyConfig bayrak default'larıdır (architecture.md §14.1).
func DefaultPolicyConfig() PolicyConfig {
	return PolicyConfig{
		MaxRequestsPerTarget:  1000,
		MaxRequestsTotal:      10000,
		RatePerSecond:         10,
		MaxResponseBytes:      5 * 1024 * 1024,
		GlobalRatePerSecond:   50,
		MaxConcurrencyPerHost: 10,
		ScanTimeout:           10 * time.Minute,
		RetryConfig: RetryConfig{
			MaxRetries:      3,
			BaseDelay:       100 * time.Millisecond,
			MaxDelay:        5 * time.Second,
			RetryableStatus: []int{408, 429, 500, 502, 503, 504},
		},
		RedirectPolicy: RedirectPolicy{
			MaxRedirects:     5,
			FollowRedirects:  true,
			RevalidateScope:  true,
			AllowCrossScheme: true,
		},
		MaxRequestBytes:   1024 * 1024, // 1MB
		BackpressureLimit: 100,
	}
}

// ctxKey plugin taşıma anahtarıdır (RoundTripper plugin-safe'i ctx'ten okur).
type ctxKey struct{}

// WithPlugin ctx'e plugin kimliği + safe bayrağını gömer.
func WithPlugin(ctx context.Context, id string, safe bool, maxRequests *int) context.Context {
	return context.WithValue(ctx, ctxKey{}, pluginCtx{ID: id, Safe: safe, MaxRequests: maxRequests})
}

// noRedirectKey login akışının manuel redirect kontrolü işaretçisidir.
type noRedirectKey struct{}

// WithNoRedirect ctx'e "redirect izleme" iptal işareti gömer.
// What: RoundTripWithRetry 3xx yanıtını izlemeden döner; diğer tüm politika
// kontrolleri (scope/rate/bütçe/safe) her istekte aynen uygulanır.
// Why: Login akışı Set-Cookie'yi her hop'ta görmek ve https→http downgrade
// kararını kendisi vermek zorundadır; politika yine atlanmaz.
func WithNoRedirect(ctx context.Context) context.Context {
	return context.WithValue(ctx, noRedirectKey{}, true)
}

// noRedirectFromCtx işaretçiyi okur (yoksa false).
func noRedirectFromCtx(ctx context.Context) bool {
	v, _ := ctx.Value(noRedirectKey{}).(bool)
	return v
}

type pluginCtx struct {
	ID          string
	Safe        bool
	MaxRequests *int
}

func pluginFromCtx(ctx context.Context) pluginCtx {
	if v, ok := ctx.Value(ctxKey{}).(pluginCtx); ok {
		return v
	}
	return pluginCtx{}
}

// PolicySession tüm probe.Send çağrılarının geçtiği http.RoundTripper sarmalayıcıdır (A-11).
// Beyana güvenilmez: safe=true POST atamaz, bütçe/scope/rate/retry/redirect/backpressure burada enforce edilir.
type PolicySession struct {
	cfg  PolicyConfig
	base http.RoundTripper

	total     atomic.Int64
	perTarget map[string]*atomic.Int64
	perPlugin map[string]*atomic.Int64
	mu        sync.Mutex

	limiters        map[string]*rate.Limiter
	globalLimiter   *rate.Limiter
	hostSemaphores  map[string]chan struct{}
	hostSemMu       sync.Mutex
	backpressureSem chan struct{}
	inFlight        atomic.Int64
	scanDeadline    atomic.Pointer[time.Time]

	// P1.3: Scope management
	scopeManager *scopeManager
	// P1.3: Scan budget
	scanBudget *scanBudget
}

// NewPolicySession proxy'yi kurar (base nil ise http.DefaultTransport).
func NewPolicySession(cfg PolicyConfig, base http.RoundTripper) *PolicySession {
	if base == nil {
		if cfg.ProxyURL != nil {
			if defTr, ok := http.DefaultTransport.(*http.Transport); ok {
				tr := defTr.Clone()
				tr.Proxy = http.ProxyURL(cfg.ProxyURL)
				base = tr
			} else {
				base = &http.Transport{
					Proxy: http.ProxyURL(cfg.ProxyURL),
				}
			}
		} else {
			base = http.DefaultTransport
		}
	}
	ps := &PolicySession{
		cfg:             cfg,
		base:            base,
		perTarget:       make(map[string]*atomic.Int64),
		perPlugin:       make(map[string]*atomic.Int64),
		limiters:        make(map[string]*rate.Limiter),
		hostSemaphores:  make(map[string]chan struct{}),
		backpressureSem: make(chan struct{}, max(cfg.BackpressureLimit, 1)),
		scopeManager:    newScopeManager(cfg.Scope),
		scanBudget:      newScanBudget(cfg.MaxRequestsTotal, cfg.MaxRequestsPerTarget, 1000), // per-path budget
	}
	if cfg.GlobalRatePerSecond > 0 {
		ps.globalLimiter = rate.NewLimiter(rate.Limit(cfg.GlobalRatePerSecond), int(cfg.GlobalRatePerSecond)+1)
	}
	// Host semaphores are created lazily on first per-host use.
	if cfg.ScanTimeout > 0 {
		deadline := time.Now().Add(cfg.ScanTimeout)
		ps.scanDeadline.Store(&deadline)
	}
	return ps
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// scopeManager manages allowed targets with IP rebinding detection (P1.3).
// What: Explicit --scope entries only; empty entry list = open mode (no
// host enforcement, no IP pinning - DNS decides).
// Why: Scope is an opt-in strict mode (Nuclei/ZAP operator-responsibility
// model); without --scope the operator carries the authorization burden.
type scopeManager struct {
	mu          sync.RWMutex
	entries     []scopeEntry
	resolvedIPs map[string][]net.IP
	resolver    *net.Resolver
	cacheTTL    time.Duration
}

type scopeEntryType int

const (
	scopeTypeDomain scopeEntryType = iota
	scopeTypeCIDR
	scopeTypeURLPrefix
)

type scopeEntry struct {
	Type     scopeEntryType
	Value    string
	Port     int
	Protocol string
	Path     string
}

func newScopeManager(entries []string) *scopeManager {
	sm := &scopeManager{
		entries:     make([]scopeEntry, 0, len(entries)),
		resolvedIPs: make(map[string][]net.IP),
		resolver:    &net.Resolver{},
		cacheTTL:    5 * time.Minute,
	}
	for _, e := range entries {
		if parsed := sm.parseEntry(e); parsed != nil {
			sm.entries = append(sm.entries, *parsed)
		}
	}
	return sm
}

func (sm *scopeManager) parseEntry(entry string) *scopeEntry {
	entry = strings.TrimSpace(entry)
	if entry == "" {
		return nil
	}
	if _, _, err := net.ParseCIDR(entry); err == nil {
		return &scopeEntry{Type: scopeTypeCIDR, Value: entry}
	}
	if strings.HasPrefix(entry, "http://") || strings.HasPrefix(entry, "https://") {
		u, err := url.Parse(entry)
		if err != nil {
			return nil
		}
		portNum, _ := strconv.Atoi(u.Port())
		return &scopeEntry{
			Type:     scopeTypeURLPrefix,
			Value:    strings.ToLower(u.Hostname()),
			Port:     portNum,
			Protocol: strings.ToLower(u.Scheme),
			Path:     strings.TrimSuffix(u.Path, "/"),
		}
	}
	if h, p, err := net.SplitHostPort(entry); err == nil {
		portNum, _ := strconv.Atoi(p)
		return &scopeEntry{Type: scopeTypeDomain, Value: strings.ToLower(h), Port: portNum}
	}
	return &scopeEntry{Type: scopeTypeDomain, Value: strings.ToLower(entry)}
}

// setOriginalTarget records the scan target and warms the resolver cache.
// What: Diagnostics/DNS-cache seed only; open mode has no enforcement role.
// Why: Keeps SetOriginalTarget call sites working without implicit-scope blocking.
func (sm *scopeManager) setOriginalTarget(target string) {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	u, _ := url.Parse(target)
	if u != nil {
		sm.resolveAndCache(u.Hostname())
	}
}

func (sm *scopeManager) resolveAndCache(host string) []net.IP {
	if ips, ok := sm.resolvedIPs[host]; ok {
		return ips
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ips, err := sm.resolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil
	}
	var ipList []net.IP
	for _, ip := range ips {
		ipList = append(ipList, ip.IP)
	}
	sm.resolvedIPs[host] = ipList
	return ipList
}

// check validates a URL against the session scope (single decision point).
// What: Explicit --scope -> strict allowlist + rebinding; no --scope -> open
// mode: every host is allowed (redirects, crawl links, cross-scheme included).
// Why: Operator-responsibility model (Nuclei/ZAP): software blocks are gone,
// strictness must be opted in via --scope.
func (sm *scopeManager) check(ctx context.Context, u *url.URL) error {
	sm.mu.RLock()
	entries := sm.entries
	sm.mu.RUnlock()

	if len(entries) == 0 {
		// Open mode: no --scope configured. No host is denied and DNS
		// rebinding pinning is off (DNS decides).
		return nil
	}

	host := strings.ToLower(u.Hostname())
	scheme := strings.ToLower(u.Scheme)
	path := strings.TrimSuffix(u.Path, "/")
	port := u.Port()

	for _, e := range entries {
		if sm.match(u, host, scheme, path, port, e) {
			if e.Type == scopeTypeDomain {
				if err := sm.checkIPRebinding(ctx, host, e.Value); err != nil {
					return err
				}
			}
			return nil
		}
	}

	return fmt.Errorf("%w: host %s not in scope", ErrScopeViolation, host)
}

// hasExplicitScope reports whether an explicit --scope allowlist is in force.
func (sm *scopeManager) hasExplicitScope() bool {
	if sm == nil {
		return false
	}
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	return len(sm.entries) > 0
}

func (sm *scopeManager) match(u *url.URL, host, scheme, path, port string, e scopeEntry) bool {
	switch e.Type {
	case scopeTypeDomain:
		if host == e.Value || strings.HasSuffix(host, "."+e.Value) {
			if e.Protocol != "" && scheme != e.Protocol {
				return false
			}
			if e.Port > 0 && port != "" && port != fmt.Sprintf("%d", e.Port) {
				return false
			}
			if e.Path != "" && !strings.HasPrefix(path, e.Path) {
				return false
			}
			return true
		}
	case scopeTypeCIDR:
		ips := sm.resolveAndCache(host)
		if ips == nil {
			return false
		}
		_, cidr, _ := net.ParseCIDR(e.Value)
		for _, ip := range ips {
			if cidr.Contains(ip) {
				return true
			}
		}
	case scopeTypeURLPrefix:
		if host == e.Value || strings.HasSuffix(host, "."+e.Value) {
			if e.Protocol != "" && scheme != e.Protocol {
				return false
			}
			if !strings.HasPrefix(path, e.Path) {
				return false
			}
			return true
		}
	}
	return false
}

func (sm *scopeManager) checkIPRebinding(ctx context.Context, host, allowedDomain string) error {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	currentIPs := sm.resolveAndCache(host)
	if currentIPs == nil {
		return nil
	}

	allowedIPs := sm.resolvedIPs[allowedDomain]
	if allowedIPs == nil {
		allowedIPs = sm.resolveAndCache(allowedDomain)
		if allowedIPs == nil {
			return nil
		}
	}

	for _, curr := range currentIPs {
		found := false
		for _, allowed := range allowedIPs {
			if curr.Equal(allowed) {
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("%w: host %s resolved to new IP %s not in original allowlist", ErrScopeViolation, host, curr.String())
		}
	}
	return nil
}

// isSchemeUpgrade reports an http→https transition (strict-mode allowed hop).
func isSchemeUpgrade(from, to string) bool {
	return strings.EqualFold(from, "http") && strings.EqualFold(to, "https")
}

// isSchemeDowngrade reports an https→http transition (strict mode: never).
func isSchemeDowngrade(from, to string) bool {
	return strings.EqualFold(from, "https") && strings.EqualFold(to, "http")
}

// scanBudget tracks total scan budget to prevent unlimited scans (P1.3).
type scanBudget struct {
	maxRequestsTotal   int64
	maxRequestsPerHost int64
	maxRequestsPerPath int64
	requestsTotal      atomic.Int64
	requestsPerHost    map[string]*atomic.Int64
	requestsPerPath    map[string]*atomic.Int64
	mu                 sync.Mutex
}

func newScanBudget(maxTotal, maxPerHost, maxPerPath int64) *scanBudget {
	return &scanBudget{
		maxRequestsTotal:   maxTotal,
		maxRequestsPerHost: maxPerHost,
		maxRequestsPerPath: maxPerPath,
		requestsPerHost:    make(map[string]*atomic.Int64),
		requestsPerPath:    make(map[string]*atomic.Int64),
	}
}

func (sb *scanBudget) hostKey(u *url.URL) string {
	return strings.ToLower(u.Hostname())
}

func (sb *scanBudget) pathKey(u *url.URL) string {
	return strings.ToLower(u.Hostname() + u.Path)
}

func (sb *scanBudget) counterFor(m map[string]*atomic.Int64, key string) *atomic.Int64 {
	sb.mu.Lock()
	defer sb.mu.Unlock()
	c, ok := m[key]
	if !ok {
		c = &atomic.Int64{}
		m[key] = c
	}
	return c
}

func (sb *scanBudget) checkAndIncrement(u *url.URL) error {
	if sb.maxRequestsTotal > 0 && sb.requestsTotal.Load() >= sb.maxRequestsTotal {
		return fmt.Errorf("%w: total request budget %d exhausted", ErrBudgetExceeded, sb.maxRequestsTotal)
	}
	if sb.maxRequestsPerHost > 0 {
		if sb.counterFor(sb.requestsPerHost, sb.hostKey(u)).Add(1) > sb.maxRequestsPerHost {
			return fmt.Errorf("%w: per-host request budget %d exhausted for %s", ErrBudgetExceeded, sb.maxRequestsPerHost, sb.hostKey(u))
		}
	}
	if sb.maxRequestsPerPath > 0 {
		if sb.counterFor(sb.requestsPerPath, sb.pathKey(u)).Add(1) > sb.maxRequestsPerPath {
			return fmt.Errorf("%w: per-path request budget %d exhausted for %s", ErrBudgetExceeded, sb.maxRequestsPerPath, sb.pathKey(u))
		}
	}
	sb.requestsTotal.Add(1)
	return nil
}

// targetKey host normalizasyonu (port düşürme, lowercase).
func targetKey(u *url.URL) string {
	h := strings.ToLower(u.Hostname())
	if h == "" {
		h = strings.ToLower(u.Host)
	}
	return h
}

func (p *PolicySession) counterFor(m map[string]*atomic.Int64, key string) *atomic.Int64 {
	p.mu.Lock()
	defer p.mu.Unlock()
	c, ok := m[key]
	if !ok {
		c = &atomic.Int64{}
		m[key] = c
	}
	return c
}

func (p *PolicySession) limiterFor(key string) *rate.Limiter {
	if p.cfg.RatePerSecond <= 0 {
		return nil
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	l, ok := p.limiters[key]
	if !ok {
		l = rate.NewLimiter(rate.Limit(p.cfg.RatePerSecond), int(p.cfg.RatePerSecond)+1)
		p.limiters[key] = l
	}
	return l
}

// RoundTrip policy enforcement uygular.
func (p *PolicySession) RoundTrip(req *http.Request) (*http.Response, error) {
	pc := pluginFromCtx(req.Context())

	// 1. safe allowlist: safe=true yalnızca GET/HEAD/OPTIONS.
	if pc.Safe {
		switch req.Method {
		case http.MethodGet, http.MethodHead, http.MethodOptions:
		default:
			return nil, &PolicyError{PluginID: pc.ID, Op: "method",
				Err: fmt.Errorf("%w: safe plugin %s atamaz (got %s)", ErrPolicyViolation, pc.ID, req.Method)}
		}
	}

	// 2. scope/host allowlist + DNS-rebinding çift kontrolü.
	if err := p.checkScope(req.Context(), req.URL); err != nil {
		return nil, &PolicyError{PluginID: pc.ID, Op: "scope", Err: err}
	}

	// 3. rate-limit (per-target).
	if lim := p.limiterFor(targetKey(req.URL)); lim != nil {
		if err := lim.Wait(req.Context()); err != nil {
			return nil, &PolicyError{PluginID: pc.ID, Op: "rate",
				Err: fmt.Errorf("%w: %v", ErrRateLimited, err)}
		}
	}

	// 4. bütçe sayaçları (atomic).
	if p.cfg.MaxRequestsTotal > 0 && p.total.Load() >= p.cfg.MaxRequestsTotal {
		return nil, &PolicyError{PluginID: pc.ID, Op: "budget",
			Err: fmt.Errorf("%w: total %d", ErrBudgetExceeded, p.cfg.MaxRequestsTotal)}
	}
	tk := targetKey(req.URL)
	if p.cfg.MaxRequestsPerTarget > 0 && p.counterFor(p.perTarget, tk).Load() >= p.cfg.MaxRequestsPerTarget {
		return nil, &PolicyError{PluginID: pc.ID, Op: "budget",
			Err: fmt.Errorf("%w: per-target %d", ErrBudgetExceeded, p.cfg.MaxRequestsPerTarget)}
	}
	if pc.MaxRequests != nil && pc.ID != "" {
		if p.counterFor(p.perPlugin, pc.ID).Load() >= int64(*pc.MaxRequests) {
			return nil, &PolicyError{PluginID: pc.ID, Op: "budget",
				Err: fmt.Errorf("%w: plugin %d", ErrBudgetExceeded, *pc.MaxRequests)}
		}
	}

	resp, err := p.base.RoundTrip(req)
	if err != nil {
		return nil, fmt.Errorf("policy roundtrip: %w", err)
	}
	// Sayaçlar yalnızca giden istekte artar (başarılı transport).
	p.total.Add(1)
	p.counterFor(p.perTarget, tk).Add(1)
	if pc.ID != "" {
		p.counterFor(p.perPlugin, pc.ID).Add(1)
	}
	return resp, nil
}

func (p *PolicySession) checkScope(ctx context.Context, u *url.URL) error {
	if p.scopeManager == nil {
		return nil
	}
	return p.scopeManager.check(ctx, u)
}

// CheckScope reports whether u is permitted under the session's scope allowlist.
func (p *PolicySession) CheckScope(ctx context.Context, u *url.URL) error {
	if p == nil {
		return nil
	}
	return p.checkScope(ctx, u)
}

// strictScope reports whether an explicit --scope allowlist is in force.
// What: Open mode (no --scope) follows cross-host/cross-scheme redirects;
// strict mode keeps upgrade-only/downgrade-never redirect rules.
// Why: Scope is the opt-in strict mode; without it the operator decides.
func (p *PolicySession) strictScope() bool {
	if p == nil || p.scopeManager == nil {
		return false
	}
	return p.scopeManager.hasExplicitScope()
}

// TotalCount test/rapor için toplam istek sayısı.
func (p *PolicySession) TotalCount() int64 { return p.total.Load() }

// InFlightCount returns current in-flight request count.
func (p *PolicySession) InFlightCount() int64 { return p.inFlight.Load() }

// SetOriginalTarget sets the original scan target for scope rebinding detection.
// What: Initializes the scope manager with the original target for IP change detection.
// Why: Enables DNS rebinding protection by comparing redirect targets to original.
func (p *PolicySession) SetOriginalTarget(target string) {
	if p.scopeManager != nil {
		p.scopeManager.setOriginalTarget(target)
	}
}

// SetBase sets the underlying RoundTripper.
func (p *PolicySession) SetBase(base http.RoundTripper) {
	if p != nil {
		p.base = base
	}
}

// Base returns the underlying RoundTripper.
func (p *PolicySession) Base() http.RoundTripper {
	if p == nil {
		return nil
	}
	return p.base
}

// Transport returns base as *http.Transport if it is one.
func (p *PolicySession) Transport() *http.Transport {
	if p == nil {
		return nil
	}
	if tr, ok := p.base.(*http.Transport); ok {
		return tr
	}
	return nil
}

// acquireHostSemaphore acquires a per-host concurrency slot.
func (p *PolicySession) acquireHostSemaphore(host string) (chan struct{}, func()) {
	if p.cfg.MaxConcurrencyPerHost <= 0 {
		return nil, func() {}
	}
	p.hostSemMu.Lock()
	sem, ok := p.hostSemaphores[host]
	if !ok {
		sem = make(chan struct{}, p.cfg.MaxConcurrencyPerHost)
		p.hostSemaphores[host] = sem
	}
	p.hostSemMu.Unlock()
	return sem, func() { <-sem }
}

// waitGlobalRate waits for global rate limiter.
func (p *PolicySession) waitGlobalRate(ctx context.Context) error {
	if p.globalLimiter == nil {
		return nil
	}
	return p.globalLimiter.Wait(ctx)
}

// waitBackpressure waits for backpressure semaphore.
func (p *PolicySession) waitBackpressure(ctx context.Context) error {
	select {
	case p.backpressureSem <- struct{}{}:
		p.inFlight.Add(1)
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// releaseBackpressure releases the backpressure semaphore.
func (p *PolicySession) releaseBackpressure() {
	p.inFlight.Add(-1)
	select {
	case <-p.backpressureSem:
	default:
	}
}

// checkScanTimeout returns error if scan deadline passed.
func (p *PolicySession) checkScanTimeout() error {
	deadline := p.scanDeadline.Load()
	if deadline != nil && time.Now().After(*deadline) {
		return &PolicyError{PluginID: "", Op: "scan-timeout",
			Err: fmt.Errorf("%w: scan deadline exceeded", ErrTimeout)}
	}
	return nil
}

// RoundTripWithRetry executes a request with retry/backoff, redirect handling, and scope re-validation.
// What: Centralized HTTP execution with all P1.1 policies enforced.
// Why: Eliminates ad-hoc retry logic in plugins/probe; single audit point.
func (p *PolicySession) RoundTripWithRetry(req *http.Request) (*http.Response, error) {
	pc := pluginFromCtx(req.Context())

	// Check scan timeout before starting
	if err := p.checkScanTimeout(); err != nil {
		return nil, err
	}

	// Wait for global rate limit
	if err := p.waitGlobalRate(req.Context()); err != nil {
		return nil, &PolicyError{PluginID: pc.ID, Op: "global-rate", Err: err}
	}

	// Wait for backpressure
	if err := p.waitBackpressure(req.Context()); err != nil {
		return nil, &PolicyError{PluginID: pc.ID, Op: "backpressure", Err: err}
	}
	defer p.releaseBackpressure()

	// Acquire per-host semaphore
	host := targetKey(req.URL)
	hostSem, releaseHost := p.acquireHostSemaphore(host)
	if hostSem != nil {
		select {
		case hostSem <- struct{}{}:
			defer releaseHost()
		case <-req.Context().Done():
			return nil, req.Context().Err()
		}
	}

	// Request size limit check
	if p.cfg.MaxRequestBytes > 0 && req.ContentLength > p.cfg.MaxRequestBytes {
		return nil, &PolicyError{PluginID: pc.ID, Op: "request-size",
			Err: fmt.Errorf("%w: request body %d > limit %d", ErrBudgetExceeded, req.ContentLength, p.cfg.MaxRequestBytes)}
	}

	// Scan budget check (total/per-host/per-path)
	if p.scanBudget != nil {
		if err := p.scanBudget.checkAndIncrement(req.URL); err != nil {
			return nil, &PolicyError{PluginID: pc.ID, Op: "scan-budget", Err: err}
		}
	}

	var lastResp *http.Response
	var lastErr error
	redirectCount := 0
	currentReq := req

	for attempt := 0; attempt <= p.cfg.RetryConfig.MaxRetries; attempt++ {
		// Check context cancellation
		select {
		case <-currentReq.Context().Done():
			return nil, currentReq.Context().Err()
		default:
		}

		// Check scan timeout
		if err := p.checkScanTimeout(); err != nil {
			return nil, err
		}

		// Policy checks (safe, scope, rate, budget)
		if err := p.enforcePreflight(currentReq, pc); err != nil {
			return nil, err
		}

		// Execute request
		resp, err := p.base.RoundTrip(currentReq)
		if err != nil {
			lastErr = err
			class := ClassifyError(err)

			// Don't retry on policy/scope errors
			if class == ErrorClassPolicy || class == ErrorClassScope {
				return nil, err
			}

			// Check if retryable
			if attempt < p.cfg.RetryConfig.MaxRetries && IsRetryable(class, 0, p.cfg.RetryConfig.RetryableStatus) {
				delay := p.backoffDelay(attempt)
				select {
				case <-time.After(delay):
					continue
				case <-currentReq.Context().Done():
					return nil, currentReq.Context().Err()
				}
			}
			return nil, fmt.Errorf("policy roundtrip (attempt %d): %w", attempt+1, err)
		}

		// Response size limit check
		if p.cfg.MaxResponseBytes > 0 && resp.ContentLength > p.cfg.MaxResponseBytes {
			resp.Body.Close()
			return nil, &PolicyError{PluginID: pc.ID, Op: "response-size",
				Err: fmt.Errorf("%w: response body %d > limit %d", ErrBudgetExceeded, resp.ContentLength, p.cfg.MaxResponseBytes)}
		}

		// Update counters on successful transport (legacy counters for backward compat)
		p.total.Add(1)
		p.counterFor(p.perTarget, host).Add(1)
		if pc.ID != "" {
			p.counterFor(p.perPlugin, pc.ID).Add(1)
		}

		// Handle redirects. WithNoRedirect taşıyan çağrılar (login akışı) 3xx'i
		// izlemeden alır; kararı kendileri verir.
		if p.cfg.RedirectPolicy.FollowRedirects && isRedirect(resp.StatusCode) && !noRedirectFromCtx(currentReq.Context()) {
			if redirectCount >= p.cfg.RedirectPolicy.MaxRedirects {
				resp.Body.Close()
				return nil, &PolicyError{PluginID: pc.ID, Op: "redirect",
					Err: fmt.Errorf("%w: redirect limit %d exceeded", ErrPolicyViolation, p.cfg.RedirectPolicy.MaxRedirects)}
			}

			location := resp.Header.Get("Location")
			resp.Body.Close()

			// Resolve redirect URL
			nextURL, err := req.URL.Parse(location)
			if err != nil {
				return nil, &PolicyError{PluginID: pc.ID, Op: "redirect",
					Err: fmt.Errorf("%w: invalid redirect location %q: %v", ErrPolicyViolation, location, err)}
			}

			// Cross-scheme redirect handling:
			//  - https→http downgrades are never followed (credential/cookie safety).
			//  - http→https upgrades are followed when allowed.
			//  - non-http(s) stays unsupported.
			if !strings.EqualFold(nextURL.Scheme, currentReq.URL.Scheme) {
				nextScheme := strings.ToLower(nextURL.Scheme)
				switch {
				case nextScheme != "http" && nextScheme != "https":
					return nil, &PolicyError{PluginID: pc.ID, Op: "redirect",
						Err: fmt.Errorf("%w: redirect to unsupported scheme %q", ErrPolicyViolation, nextURL.Scheme)}
				case isSchemeDowngrade(currentReq.URL.Scheme, nextURL.Scheme):
					return nil, &PolicyError{PluginID: pc.ID, Op: "redirect",
						Err: fmt.Errorf("%w: scheme downgrade %s→%s never allowed", ErrPolicyViolation, currentReq.URL.Scheme, nextURL.Scheme)}
				case isSchemeUpgrade(currentReq.URL.Scheme, nextURL.Scheme):
					if !p.cfg.RedirectPolicy.AllowCrossScheme {
						return nil, &PolicyError{PluginID: pc.ID, Op: "redirect",
							Err: fmt.Errorf("%w: cross-scheme redirect %s→%s not allowed", ErrPolicyViolation, currentReq.URL.Scheme, nextURL.Scheme)}
					}
				}
			}

			// Scope re-validation after redirect (uses new scopeManager with rebinding detection)
			if p.cfg.RedirectPolicy.RevalidateScope {
				if err := p.checkScope(currentReq.Context(), nextURL); err != nil {
					return nil, &PolicyError{PluginID: pc.ID, Op: "redirect-scope", Err: err}
				}
			}

			// Scan budget check for redirect target
			if p.scanBudget != nil {
				if err := p.scanBudget.checkAndIncrement(nextURL); err != nil {
					return nil, &PolicyError{PluginID: pc.ID, Op: "redirect-scan-budget", Err: err}
				}
			}

			// Create new request for redirect (GET for 301/302/303 unless original was HEAD)
			redirectMethod := currentReq.Method
			if redirectCount > 0 || resp.StatusCode == 303 {
				redirectMethod = http.MethodGet
			}
			newReq, err := http.NewRequestWithContext(currentReq.Context(), redirectMethod, nextURL.String(), nil)
			if err != nil {
				return nil, fmt.Errorf("policy redirect new request: %w", err)
			}
			// Copy headers except Host (will be set by transport)
			for k, v := range currentReq.Header {
				if strings.EqualFold(k, "Host") {
					continue
				}
				newReq.Header[k] = v
			}

			redirectCount++
			currentReq = newReq
			continue
		}

		// Check for retryable server status codes
		if attempt < p.cfg.RetryConfig.MaxRetries && isRetryableStatus(resp.StatusCode, p.cfg.RetryConfig.RetryableStatus) {
			resp.Body.Close()
			delay := p.backoffDelay(attempt)
			select {
			case <-time.After(delay):
				continue
			case <-currentReq.Context().Done():
				return nil, currentReq.Context().Err()
			}
		}

		return resp, nil
	}

	return lastResp, lastErr
}

// enforcePreflight runs safe/scope/rate/budget checks before each request attempt.
func (p *PolicySession) enforcePreflight(req *http.Request, pc pluginCtx) error {
	// 1. safe allowlist
	if pc.Safe {
		switch req.Method {
		case http.MethodGet, http.MethodHead, http.MethodOptions:
		default:
			return &PolicyError{PluginID: pc.ID, Op: "method",
				Err: fmt.Errorf("%w: safe plugin %s cannot use %s", ErrPolicyViolation, pc.ID, req.Method)}
		}
	}

	// 2. scope check
	if err := p.checkScope(req.Context(), req.URL); err != nil {
		return &PolicyError{PluginID: pc.ID, Op: "scope", Err: err}
	}

	// 3. rate-limit (per-target)
	if lim := p.limiterFor(targetKey(req.URL)); lim != nil {
		if err := lim.Wait(req.Context()); err != nil {
			return &PolicyError{PluginID: pc.ID, Op: "rate",
				Err: fmt.Errorf("%w: %v", ErrRateLimited, err)}
		}
	}

	// 4. budget checks
	if p.cfg.MaxRequestsTotal > 0 && p.total.Load() >= p.cfg.MaxRequestsTotal {
		return &PolicyError{PluginID: pc.ID, Op: "budget",
			Err: fmt.Errorf("%w: total %d", ErrBudgetExceeded, p.cfg.MaxRequestsTotal)}
	}
	tk := targetKey(req.URL)
	if p.cfg.MaxRequestsPerTarget > 0 && p.counterFor(p.perTarget, tk).Load() >= p.cfg.MaxRequestsPerTarget {
		return &PolicyError{PluginID: pc.ID, Op: "budget",
			Err: fmt.Errorf("%w: per-target %d", ErrBudgetExceeded, p.cfg.MaxRequestsPerTarget)}
	}
	if pc.MaxRequests != nil && pc.ID != "" {
		if p.counterFor(p.perPlugin, pc.ID).Load() >= int64(*pc.MaxRequests) {
			return &PolicyError{PluginID: pc.ID, Op: "budget",
				Err: fmt.Errorf("%w: plugin %d", ErrBudgetExceeded, *pc.MaxRequests)}
		}
	}

	return nil
}

func isRedirect(status int) bool {
	return status == 301 || status == 302 || status == 303 || status == 307 || status == 308
}

func isRetryableStatus(status int, retryableStatus []int) bool {
	for _, s := range retryableStatus {
		if s == status {
			return true
		}
	}
	return false
}

func (p *PolicySession) backoffDelay(attempt int) time.Duration {
	if attempt < 0 {
		attempt = 0
	}
	delay := p.cfg.RetryConfig.BaseDelay * time.Duration(1<<attempt)
	if delay > p.cfg.RetryConfig.MaxDelay {
		delay = p.cfg.RetryConfig.MaxDelay
	}
	// Add jitter: ±25%
	jitter := delay / 4
	if jitter > 0 {
		//nolint:unconvert // time.Duration/int64 karışık aritmetik bilerek korunur
		delay += time.Duration(int64(jitter) - int64(time.Now().UnixNano())%(2*int64(jitter)))
	}
	return delay
}

// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Modül: github.com/Xmar1881/Gash

package plugin

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Xmar1881/Gash/internal/proxypool"
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
	// ProxyURLs upstream proxy pool. Multiple entries rotate; a single entry
	// behaves like ProxyURL. Empty means direct traffic.
	ProxyURLs []*url.URL
	// ProxyRotate is the pool strategy (per-host default, or per-request).
	ProxyRotate proxypool.Strategy
	// ProxyCooldown skips a failing proxy for this long.
	ProxyCooldown time.Duration
	// AttemptTimeout bounds one transport attempt (not the whole retry chain),
	// so a hanging proxy can fail over to the next one.
	AttemptTimeout time.Duration
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

// PluginIDFromContext returns the plugin ID embedded by WithPlugin.
// What: Read-only accessor for the WAF bypass layer's class selection.
// Why: Semantic variants need to know whether the payload is SQLi/XSS/shell.
func PluginIDFromContext(ctx context.Context) string {
	return pluginFromCtx(ctx).ID
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

	// Proxy pool (optional) and per-attempt timeout for retry/failover.
	proxyPool      *proxypool.Pool
	attemptTimeout atomic.Int64

	// Retry amplification guard: correlated target/WAF failures must not turn
	// every request into four attempts. The budget grows with observed
	// responses but keeps an initial allowance for proxy failover.
	retrySpent     atomic.Int64
	responses      atomic.Int64
	retryExhausted atomic.Int64
}

// NewPolicySession proxy'yi kurar (base nil ise http.DefaultTransport).
func NewPolicySession(cfg PolicyConfig, base http.RoundTripper) *PolicySession {
	if cfg.BackpressureLimit <= 0 {
		cfg.BackpressureLimit = 100
	}
	if cfg.MaxConcurrencyPerHost <= 0 {
		cfg.MaxConcurrencyPerHost = 50
	}
	if cfg.MaxResponseBytes <= 0 {
		cfg.MaxResponseBytes = 5 * 1024 * 1024
	}
	if cfg.MaxRequestBytes <= 0 {
		cfg.MaxRequestBytes = 1024 * 1024
	}

	proxyURLs := make([]*url.URL, 0, len(cfg.ProxyURLs)+1)
	if cfg.ProxyURL != nil {
		proxyURLs = append(proxyURLs, cfg.ProxyURL)
	}
	proxyURLs = append(proxyURLs, cfg.ProxyURLs...)

	var pool *proxypool.Pool
	if base == nil {
		if len(proxyURLs) > 0 {
			pool = proxypool.New(proxyURLs, proxypool.Config{
				Strategy: cfg.ProxyRotate,
				Cooldown: cfg.ProxyCooldown,
			})
			if defTr, ok := http.DefaultTransport.(*http.Transport); ok {
				base = proxypool.NewRoundTripper(pool, defTr.Clone())
			} else {
				base = proxypool.NewRoundTripper(pool, nil)
			}
		} else {
			base = http.DefaultTransport
		}
	}
	maxPerPath := cfg.MaxRequestsPerTarget
	if cfg.MaxRequestsTotal > maxPerPath {
		maxPerPath = cfg.MaxRequestsTotal
	}
	ps := &PolicySession{
		cfg:             cfg,
		base:            base,
		proxyPool:       pool,
		perTarget:       make(map[string]*atomic.Int64),
		perPlugin:       make(map[string]*atomic.Int64),
		limiters:        make(map[string]*rate.Limiter),
		hostSemaphores:  make(map[string]chan struct{}),
		backpressureSem: make(chan struct{}, max(cfg.BackpressureLimit, 50)),
		scopeManager:    newScopeManager(cfg.Scope),
		scanBudget:      newScanBudget(cfg.MaxRequestsTotal, cfg.MaxRequestsPerTarget, maxPerPath),
	}
	if cfg.AttemptTimeout > 0 {
		ps.attemptTimeout.Store(int64(cfg.AttemptTimeout))
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
	u, _ := url.Parse(target)
	if u != nil {
		sm.resolveAndCache(u.Hostname())
	}
}

// resolveAndCache returns the first-seen IP set for host. Resolution happens
// outside the lock so one slow DNS answer cannot block every scope check; the
// double-check keeps concurrent callers on the same pinned set.
func (sm *scopeManager) resolveAndCache(host string) []net.IP {
	if host == "" {
		return nil
	}
	sm.mu.RLock()
	ips, ok := sm.resolvedIPs[host]
	sm.mu.RUnlock()
	if ok {
		return ips
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	addrs, err := sm.resolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil
	}
	ipList := make([]net.IP, 0, len(addrs))
	for _, ip := range addrs {
		ipList = append(ipList, ip.IP)
	}
	sm.mu.Lock()
	defer sm.mu.Unlock()
	if existing, ok := sm.resolvedIPs[host]; ok {
		return existing
	}
	sm.resolvedIPs[host] = ipList
	return ipList
}

// cachedIPs returns the pinned IP set without performing DNS work.
func (sm *scopeManager) cachedIPs(host string) []net.IP {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	return sm.resolvedIPs[host]
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
			if !scopePortMatches(e.Port, scheme, port) {
				return false
			}
			if !scopePathMatches(path, e.Path) {
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
			if !scopePortMatches(e.Port, scheme, port) {
				return false
			}
			if !scopePathMatches(path, e.Path) {
				return false
			}
			return true
		}
	}
	return false
}

func scopePortMatches(want int, scheme, got string) bool {
	if want <= 0 {
		return true
	}
	if got == "" {
		switch scheme {
		case "http":
			got = "80"
		case "https":
			got = "443"
		}
	}
	return got == strconv.Itoa(want)
}

func scopePathMatches(path, prefix string) bool {
	if prefix == "" || path == prefix {
		return true
	}
	return strings.HasPrefix(path, prefix+"/")
}

func (sm *scopeManager) checkIPRebinding(ctx context.Context, host, allowedDomain string) error {
	currentIPs := sm.resolveAndCache(host)
	if currentIPs == nil {
		return nil
	}

	// The allowed domain's IP set is pinned on first use and never refreshed:
	// scope pinning must compare against the original infrastructure, not a
	// second lookup that could follow the same rebinding.
	allowedIPs := sm.cachedIPs(allowedDomain)
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

// sameRedirectOrigin reports whether credentials may safely follow a redirect.
// What: Compare scheme, hostname, and effective port rather than raw Host text.
// Why: A redirect to another authority must not inherit authentication or
// session headers, even when the operator intentionally scans in open mode.
func sameRedirectOrigin(from, to *url.URL) bool {
	if from == nil || to == nil {
		return false
	}
	return strings.EqualFold(from.Scheme, to.Scheme) &&
		strings.EqualFold(from.Hostname(), to.Hostname()) &&
		effectiveURLPort(from) == effectiveURLPort(to)
}

func effectiveURLPort(u *url.URL) string {
	if u == nil {
		return ""
	}
	if port := u.Port(); port != "" {
		return port
	}
	switch strings.ToLower(u.Scheme) {
	case "http":
		return "80"
	case "https":
		return "443"
	default:
		return ""
	}
}

func isSensitiveRedirectHeader(name string) bool {
	switch strings.ToLower(name) {
	case "authorization", "proxy-authorization", "cookie",
		"x-api-key", "x-auth-token", "x-csrf-token":
		return true
	default:
		return false
	}
}

func copyRedirectHeaders(dst, src http.Header, sameOrigin bool) {
	for k, values := range src {
		if strings.EqualFold(k, "Host") {
			continue
		}
		if !sameOrigin && isSensitiveRedirectHeader(k) {
			continue
		}
		dst[k] = append([]string(nil), values...)
	}
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
	total := sb.requestsTotal.Add(1)
	if sb.maxRequestsTotal > 0 && total > sb.maxRequestsTotal {
		sb.requestsTotal.Add(-1)
		return fmt.Errorf("%w: total request budget %d exhausted", ErrBudgetExceeded, sb.maxRequestsTotal)
	}
	if sb.maxRequestsPerHost > 0 {
		host := sb.counterFor(sb.requestsPerHost, sb.hostKey(u))
		if host.Add(1) > sb.maxRequestsPerHost {
			host.Add(-1)
			sb.requestsTotal.Add(-1)
			return fmt.Errorf("%w: per-host request budget %d exhausted for %s", ErrBudgetExceeded, sb.maxRequestsPerHost, sb.hostKey(u))
		}
	}
	if sb.maxRequestsPerPath > 0 {
		path := sb.counterFor(sb.requestsPerPath, sb.pathKey(u))
		if path.Add(1) > sb.maxRequestsPerPath {
			path.Add(-1)
			if sb.maxRequestsPerHost > 0 {
				sb.counterFor(sb.requestsPerHost, sb.hostKey(u)).Add(-1)
			}
			sb.requestsTotal.Add(-1)
			return fmt.Errorf("%w: per-path request budget %d exhausted for %s", ErrBudgetExceeded, sb.maxRequestsPerPath, sb.pathKey(u))
		}
	}
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
		// Burst keeps parallel plugin workers from stalling in the rate limiter
		// queue. Use rate*4 with a floor of 40 for small concurrent batches.
		burst := int(p.cfg.RatePerSecond) * 4
		if burst < 40 {
			burst = 40
		}
		l = rate.NewLimiter(rate.Limit(p.cfg.RatePerSecond), burst)
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
	// Paylaşılan limiter'ın plugin context'inin deadline'ına yaklaşmasında
	// beklemek yerine kısa bir pencereyle (max 5s) dener; bitiremezse
	// rate hatasını fırlatır ama plugin'i anında öldürmez — kalan istekler
	// bir sonraki slot'ta denemesini yapabilir.
	if lim := p.limiterFor(targetKey(req.URL)); lim != nil {
		waitCtx := req.Context()
		if dl, ok := waitCtx.Deadline(); ok {
			remaining := time.Until(dl)
			maxWait := 5 * time.Second
			if remaining > maxWait {
				var cancel context.CancelFunc
				waitCtx, cancel = context.WithTimeout(waitCtx, maxWait)
				defer cancel()
			}
		}
		if err := lim.Wait(waitCtx); err != nil {
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

// SetAttemptTimeout bounds one transport attempt. It is intentionally separate
// from the caller's deadline: retries and proxy failover need room to run.
func (p *PolicySession) SetAttemptTimeout(d time.Duration) {
	if p != nil {
		p.attemptTimeout.Store(int64(d))
	}
}

// AttemptTimeout returns the per-attempt timeout (0 = caller deadline only).
func (p *PolicySession) AttemptTimeout() time.Duration {
	if p == nil {
		return 0
	}
	return time.Duration(p.attemptTimeout.Load())
}

// allowRetry applies a global retry budget: at least 32 retries are available
// for startup/proxy failover, then the budget grows with responses at 20%.
// Under a correlated outage this stops retry amplification early.
func (p *PolicySession) allowRetry() bool {
	if p == nil {
		return true
	}
	for {
		spent := p.retrySpent.Load()
		limit := p.responses.Load() / 5
		if limit < 32 {
			limit = 32
		}
		if spent >= limit {
			p.retryExhausted.Add(1)
			return false
		}
		if p.retrySpent.CompareAndSwap(spent, spent+1) {
			return true
		}
	}
}

// RetryBudgetExhausted reports how many retries were suppressed by the budget.
func (p *PolicySession) RetryBudgetExhausted() int64 {
	if p == nil {
		return 0
	}
	return p.retryExhausted.Load()
}

// isIdempotentMethod reports whether a server-side failure can be retried
// without risking a duplicate state change. 5xx errors are ambiguous; POST and
// PATCH are not replayed, while 429/proxy rotations remain method-agnostic.
func isIdempotentMethod(method string) bool {
	switch strings.ToUpper(strings.TrimSpace(method)) {
	case "", http.MethodGet, http.MethodHead, http.MethodOptions, http.MethodPut, http.MethodDelete:
		return true
	default:
		return false
	}
}

// retryAfterDelay parses Retry-After seconds or an HTTP date.
func retryAfterDelay(header http.Header, now time.Time) (time.Duration, bool) {
	raw := strings.TrimSpace(header.Get("Retry-After"))
	if raw == "" {
		return 0, false
	}
	if secs, err := strconv.Atoi(raw); err == nil {
		if secs < 0 {
			return 0, false
		}
		return time.Duration(secs) * time.Second, true
	}
	if at, err := http.ParseTime(raw); err == nil {
		d := at.Sub(now)
		if d < 0 {
			d = 0
		}
		return d, true
	}
	return 0, false
}

// ProxyPool returns the rotating proxy pool, or nil for direct traffic.
func (p *PolicySession) ProxyPool() *proxypool.Pool {
	if p == nil {
		return nil
	}
	return p.proxyPool
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

	// A rotating base (proxy pool) can turn block-style responses into another
	// attempt through a different source IP. Without one these lists stay empty.
	var rotator interface{ Rotate(*http.Request) }
	if r, ok := p.base.(interface{ Rotate(*http.Request) }); ok {
		rotator = r
	}
	var proxyRetryStatuses []int
	if advisor, ok := p.base.(interface{ RetryStatuses() []int }); ok {
		proxyRetryStatuses = advisor.RetryStatuses()
	}
	proxyRotations := 0
	const maxProxyRotations = 2

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

		// A retried request must replay its body: the previous transport
		// attempt already consumed it. GetBody is set by the probe client.
		if currentReq.GetBody != nil {
			if body, berr := currentReq.GetBody(); berr == nil {
				currentReq.Body = body
			}
		}

		// Per-attempt timeout keeps one hanging proxy from consuming the whole
		// retry budget, which is what used to leave no room for failover.
		attemptReq, cancel := p.attemptRequest(currentReq)
		resp, err := p.base.RoundTrip(attemptReq)
		if err != nil {
			if cancel != nil {
				cancel()
			}
			lastErr = err
			class := ClassifyError(err)

			// Don't retry on policy/scope errors
			if class == ErrorClassPolicy || class == ErrorClassScope {
				return nil, err
			}

			// Check if retryable
			if attempt < p.cfg.RetryConfig.MaxRetries && IsRetryable(class, 0, p.cfg.RetryConfig.RetryableStatus) {
				if !p.allowRetry() {
					return nil, fmt.Errorf("policy retry budget exhausted: %w", err)
				}
				if rotator != nil {
					rotator.Rotate(currentReq)
				}
				if !p.waitRetry(currentReq.Context(), p.backoffDelay(attempt)) {
					return nil, currentReq.Context().Err()
				}
				continue
			}
			return nil, fmt.Errorf("policy roundtrip (attempt %d): %w", attempt+1, err)
		}
		if cancel != nil {
			resp.Body = &cancelReadCloser{ReadCloser: resp.Body, cancel: cancel}
		}
		p.responses.Add(1)

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

			// Resolve against the current hop. Using the original request here
			// breaks relative redirects after the first path segment.
			nextURL, err := currentReq.URL.Parse(location)
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
			// Copy ordinary headers, but never carry credentials across an
			// origin boundary. The transport sets Host from the new URL.
			copyRedirectHeaders(newReq.Header, currentReq.Header, sameRedirectOrigin(currentReq.URL, nextURL))

			redirectCount++
			currentReq = newReq
			continue
		}

		// Block-style responses rotate to another proxy before they are handed
		// back as evidence: a 403/407/429 may be the source IP, not the target.
		if rotator != nil && attempt < p.cfg.RetryConfig.MaxRetries &&
			proxyRotations < maxProxyRotations &&
			isRetryableStatus(resp.StatusCode, proxyRetryStatuses) {
			if !p.allowRetry() {
				return resp, nil
			}
			resp.Body.Close()
			rotator.Rotate(currentReq)
			proxyRotations++
			if !p.waitRetry(currentReq.Context(), p.backoffDelay(attempt)) {
				return nil, currentReq.Context().Err()
			}
			continue
		}

		// Check for retryable server status codes. A 429 means the request was
		// rejected, so it is safe to retry for any method; ambiguous 5xx
		// statuses are only replayed for idempotent methods.
		if attempt < p.cfg.RetryConfig.MaxRetries &&
			isRetryableStatus(resp.StatusCode, p.cfg.RetryConfig.RetryableStatus) &&
			(isIdempotentMethod(currentReq.Method) || resp.StatusCode == http.StatusTooManyRequests) {
			wait := p.backoffDelay(attempt)
			if ra, ok := retryAfterDelay(resp.Header, time.Now()); ok {
				if ra > p.cfg.RetryConfig.MaxDelay {
					return resp, nil
				}
				if ra > wait {
					wait = ra
				}
			}
			if !p.allowRetry() {
				return resp, nil
			}
			resp.Body.Close()
			if !p.waitRetry(currentReq.Context(), wait) {
				return nil, currentReq.Context().Err()
			}
			continue
		}

		return resp, nil
	}

	return lastResp, lastErr
}

// attemptRequest applies the per-attempt deadline while preserving the caller's
// cancellation (plugin/scan deadline).
func (p *PolicySession) attemptRequest(req *http.Request) (*http.Request, context.CancelFunc) {
	d := p.AttemptTimeout()
	if d <= 0 {
		return req, nil
	}
	ctx, cancel := context.WithTimeout(req.Context(), d)
	return req.WithContext(ctx), cancel
}

// waitRetry sleeps before a retry, returning false when the caller is done.
func (p *PolicySession) waitRetry(ctx context.Context, d time.Duration) bool {
	if d <= 0 {
		return ctx.Err() == nil
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return true
	case <-ctx.Done():
		return false
	}
}

// cancelReadCloser keeps the per-attempt deadline alive until the response body
// is closed (body reads happen after RoundTripWithRetry returns).
type cancelReadCloser struct {
	io.ReadCloser
	cancel context.CancelFunc
}

func (c *cancelReadCloser) Close() error {
	err := c.ReadCloser.Close()
	c.cancel()
	return err
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
	if delay > p.cfg.RetryConfig.MaxDelay {
		delay = p.cfg.RetryConfig.MaxDelay
	}
	if delay < 0 {
		delay = 0
	}
	return delay
}

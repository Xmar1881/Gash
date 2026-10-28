// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Modül: github.com/Xmar1881/Gash

// Package proxypool provides a rotating upstream proxy pool for scan traffic.
//
// The pool is deliberately transport-level: scope, budgets, and rate limits
// stay in plugin.PolicySession. A pool only decides which source IP a request
// leaves through, cools down proxies that keep failing, and lets the policy
// retry a different proxy after a timeout or an IP-block style response.
package proxypool

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Strategy controls how a proxy is picked for a request.
type Strategy string

const (
	// PerHost keeps one proxy per target host so cookie/IP-bound sessions stay
	// stable; a failure rotates only that host's proxy.
	PerHost Strategy = "per-host"
	// PerRequest advances the pool on every request.
	PerRequest Strategy = "per-request"
)

// ParseStrategy validates a strategy name. An empty value selects PerHost.
func ParseStrategy(raw string) (Strategy, error) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "", string(PerHost), "host":
		return PerHost, nil
	case string(PerRequest), "request", "round-robin":
		return PerRequest, nil
	default:
		return "", fmt.Errorf("invalid proxy rotation strategy %q (want %s or %s)", raw, PerHost, PerRequest)
	}
}

// DefaultCooldown is how long a repeatedly failing proxy is skipped.
const DefaultCooldown = 30 * time.Second

// DefaultRotateStatus lists responses that usually mean the source IP is
// blocked or the proxy itself rejected the request.
var DefaultRotateStatus = []int{http.StatusForbidden, http.StatusProxyAuthRequired, http.StatusTooManyRequests}

// Config tunes pool selection and health handling.
type Config struct {
	Strategy Strategy
	// Cooldown is how long a failed proxy is skipped. Zero uses
	// DefaultCooldown; a negative value disables skipping.
	Cooldown time.Duration
	// FailureThreshold is the number of consecutive transport failures before
	// a proxy cools down. Block-status responses cool down immediately.
	FailureThreshold int
	// RotateOnStatus lists response codes that trigger proxy rotation.
	RotateOnStatus []int
}

func (c Config) withDefaults() Config {
	if c.Strategy != PerRequest {
		c.Strategy = PerHost
	}
	if c.Cooldown == 0 {
		c.Cooldown = DefaultCooldown
	}
	if c.Cooldown < 0 {
		c.Cooldown = 0
	}
	if c.FailureThreshold <= 0 {
		c.FailureThreshold = 2
	}
	if len(c.RotateOnStatus) == 0 {
		c.RotateOnStatus = append([]int(nil), DefaultRotateStatus...)
	}
	return c
}

type entry struct {
	url           *url.URL
	failures      int
	cooldownUntil time.Time
}

// Pool is a concurrency-safe proxy selector.
type Pool struct {
	cfg Config

	mu     sync.Mutex
	items  []*entry
	cursor int
	sticky map[string]int

	rotations atomic.Int64
	failures  atomic.Int64
	// directFallbacks counts hosts switched to direct after repeated proxy
	// failures so a dead pool cannot stall the whole scan.
	directFallbacks atomic.Int64
}

// Stats is a point-in-time snapshot for scan reports.
type Stats struct {
	Size            int
	Healthy         int
	CoolingDown     int
	Rotations       int64
	Failures        int64
	DirectFallbacks int64
}

// New builds a pool. Duplicate URLs are collapsed; nil entries are ignored.
func New(urls []*url.URL, cfg Config) *Pool {
	cfg = cfg.withDefaults()
	p := &Pool{cfg: cfg, sticky: make(map[string]int)}
	seen := make(map[string]struct{}, len(urls))
	for _, u := range urls {
		if u == nil {
			continue
		}
		key := u.String()
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		p.items = append(p.items, &entry{url: u})
	}
	return p
}

// Len reports the number of configured proxies.
func (p *Pool) Len() int {
	if p == nil {
		return 0
	}
	return len(p.items)
}

// Strategy reports the configured rotation strategy.
func (p *Pool) Strategy() Strategy {
	if p == nil {
		return PerHost
	}
	return p.cfg.Strategy
}

// RotateOnStatus returns the response codes that mark a proxy as blocked.
func (p *Pool) RotateOnStatus() []int {
	if p == nil {
		return nil
	}
	return append([]int(nil), p.cfg.RotateOnStatus...)
}

// Next selects a proxy for host. It never returns nil when the pool has at
// least one entry: if every proxy is cooling down it falls back to the one
// whose cooldown ends first, so a scan degrades instead of failing outright.
func (p *Pool) Next(host string) *url.URL {
	if p == nil || len(p.items) == 0 {
		return nil
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	now := time.Now()

	if len(p.items) == 1 {
		return p.items[0].url
	}

	if p.cfg.Strategy == PerHost && host != "" {
		if idx, ok := p.sticky[host]; ok && p.healthy(p.items[idx], now) {
			return p.items[idx].url
		}
		idx := p.pickLocked(now)
		p.sticky[host] = idx
		return p.items[idx].url
	}

	return p.items[p.pickLocked(now)].url
}

// Rotate moves host (or the per-request cursor) to another proxy.
func (p *Pool) Rotate(host string) {
	if p == nil || len(p.items) < 2 {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.rotations.Add(1)
	if p.cfg.Strategy == PerHost && host != "" {
		p.sticky[host] = p.nextLocked(p.sticky[host])
		return
	}
	// PerRequest advances in Next; counting the rotation is enough here.
}

// ReportSuccess clears a proxy's failure streak.
func (p *Pool) ReportSuccess(u *url.URL) {
	e := p.find(u)
	if e == nil {
		return
	}
	p.mu.Lock()
	e.failures = 0
	e.cooldownUntil = time.Time{}
	p.mu.Unlock()
}

// ReportError records a transport-level failure and cools the proxy down
// after repeated failures.
func (p *Pool) ReportError(u *url.URL) {
	p.fail(u, false)
}

// ReportStatus records a response. Block-style statuses cool the proxy down
// immediately; other responses count as success.
func (p *Pool) ReportStatus(u *url.URL, status int) {
	if p == nil {
		return
	}
	if containsStatus(p.cfg.RotateOnStatus, status) {
		p.fail(u, true)
		return
	}
	p.ReportSuccess(u)
}

func (p *Pool) fail(u *url.URL, immediate bool) {
	e := p.find(u)
	if e == nil {
		return
	}
	p.failures.Add(1)
	p.mu.Lock()
	defer p.mu.Unlock()
	e.failures++
	if !immediate && e.failures < p.cfg.FailureThreshold {
		return
	}
	if p.cfg.Cooldown <= 0 {
		return
	}
	e.cooldownUntil = time.Now().Add(p.cfg.Cooldown)
}

func (p *Pool) find(u *url.URL) *entry {
	if p == nil || u == nil {
		return nil
	}
	key := u.String()
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, e := range p.items {
		if e.url.String() == key {
			return e
		}
	}
	return nil
}

func (p *Pool) healthy(e *entry, now time.Time) bool {
	return e.cooldownUntil.IsZero() || now.After(e.cooldownUntil)
}

// pickLocked returns the next healthy index, falling back to the proxy whose
// cooldown ends first when everything is cooling down.
func (p *Pool) pickLocked(now time.Time) int {
	start := p.cursor % len(p.items)
	for i := 0; i < len(p.items); i++ {
		idx := (start + i) % len(p.items)
		if p.healthy(p.items[idx], now) {
			p.cursor = (idx + 1) % len(p.items)
			return idx
		}
	}
	best := start
	for i := 0; i < len(p.items); i++ {
		idx := (start + i) % len(p.items)
		if p.items[idx].cooldownUntil.Before(p.items[best].cooldownUntil) {
			best = idx
		}
	}
	p.cursor = (best + 1) % len(p.items)
	return best
}

func (p *Pool) nextLocked(from int) int {
	now := time.Now()
	for i := 1; i <= len(p.items); i++ {
		idx := (from + i) % len(p.items)
		if p.healthy(p.items[idx], now) {
			return idx
		}
	}
	return (from + 1) % len(p.items)
}

// Stats returns pool health counters.
func (p *Pool) Stats() Stats {
	if p == nil {
		return Stats{}
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	now := time.Now()
	st := Stats{Size: len(p.items), Rotations: p.rotations.Load(), Failures: p.failures.Load(), DirectFallbacks: p.directFallbacks.Load()}
	for _, e := range p.items {
		if p.healthy(e, now) {
			st.Healthy++
		} else {
			st.CoolingDown++
		}
	}
	return st
}

// ParseURL validates one proxy URL. Credentials are allowed (http://user:pass@host:port).
// Bare `host:port`, `user:pass@host:port`, and the common `host:port:user:pass`
// provider format are normalized to http:// before validation.
func ParseURL(raw string) (*url.URL, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, errors.New("empty proxy URL")
	}
	raw = normalizeProxyEntry(raw)
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("parse proxy URL %q: %w", raw, err)
	}
	switch strings.ToLower(u.Scheme) {
	case "http", "https", "socks5", "socks5h":
	default:
		return nil, fmt.Errorf("proxy URL %q: scheme must be http, https, socks5, or socks5h", redact(u))
	}
	if u.Host == "" {
		return nil, fmt.Errorf("proxy URL %q: host is required", redact(u))
	}
	if u.Path != "" && u.Path != "/" {
		return nil, fmt.Errorf("proxy URL %q: path is not allowed", redact(u))
	}
	if u.RawQuery != "" || u.Fragment != "" {
		return nil, fmt.Errorf("proxy URL %q: query/fragment is not allowed", redact(u))
	}
	return u, nil
}

// ParseList parses proxy URLs, skipping blanks and # comments.
func ParseList(raw []string) ([]*url.URL, error) {
	out := make([]*url.URL, 0, len(raw))
	for _, line := range raw {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		u, err := ParseURL(line)
		if err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, nil
}

func normalizeProxyEntry(raw string) string {
	if strings.Contains(raw, "://") || strings.HasPrefix(raw, "[") {
		return raw
	}
	parts := strings.Split(raw, ":")
	switch len(parts) {
	case 2:
		// host:port
		return "http://" + raw
	case 3:
		// user:pass@host:port or host:port:garbage; validation decides.
		return "http://" + raw
	case 4:
		// host:port:user:pass (common reseller list format).
		if !strings.Contains(raw, "@") {
			host, port, user, pass := parts[0], parts[1], parts[2], parts[3]
			return "http://" + url.UserPassword(user, pass).String() + "@" + host + ":" + port
		}
	}
	return raw
}

func redact(u *url.URL) string {
	if u == nil {
		return ""
	}
	c := *u
	if c.User != nil {
		c.User = url.User("***")
	}
	return c.String()
}

func containsStatus(list []int, status int) bool {
	for _, s := range list {
		if s == status {
			return true
		}
	}
	return false
}

// RoundTripper sends each request through a pooled proxy and feeds health
// results back to the pool.
type RoundTripper struct {
	pool *Pool
	base *http.Transport
	// direct is used per host after directFallbackThreshold consecutive proxy
	// failures; it never carries a proxy.
	direct *http.Transport

	mu           sync.Mutex
	transports   map[string]*http.Transport
	hostFailures map[string]int
	hostDirect   map[string]bool
}

// directFallbackThreshold is the number of consecutive proxy failures for one
// host before the transport switches that host to direct traffic.
const directFallbackThreshold = 6

// NewRoundTripper builds a proxying RoundTripper. base is cloned per proxy so
// TLS/dial settings survive; nil falls back to a clone of http.DefaultTransport.
func NewRoundTripper(pool *Pool, base *http.Transport) *RoundTripper {
	if base == nil {
		if def, ok := http.DefaultTransport.(*http.Transport); ok {
			base = def.Clone()
		} else {
			base = &http.Transport{}
		}
	}
	direct := base.Clone()
	direct.Proxy = nil
	if base.MaxResponseHeaderBytes == 0 {
		base.MaxResponseHeaderBytes = 1 << 20
	}
	if direct.MaxResponseHeaderBytes == 0 {
		direct.MaxResponseHeaderBytes = 1 << 20
	}
	// Parallel scan workers need a deeper per-host idle pool; the stdlib
	// default of two causes a reconnect (and proxy CONNECT) per request.
	if base.MaxIdleConnsPerHost < 32 {
		base.MaxIdleConnsPerHost = 32
	}
	if base.MaxIdleConns < 200 {
		base.MaxIdleConns = 200
	}
	if direct.MaxIdleConnsPerHost < 32 {
		direct.MaxIdleConnsPerHost = 32
	}
	return &RoundTripper{
		pool:         pool,
		base:         base,
		direct:       direct,
		transports:   make(map[string]*http.Transport),
		hostFailures: make(map[string]int),
		hostDirect:   make(map[string]bool),
	}
}

func (rt *RoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	host := strings.ToLower(req.URL.Hostname())
	rt.mu.Lock()
	direct := rt.hostDirect[host]
	rt.mu.Unlock()
	if direct {
		return rt.direct.RoundTrip(req)
	}
	proxy := rt.pool.Next(req.URL.Host)
	if proxy == nil {
		return nil, errors.New("proxy pool is empty")
	}
	resp, err := rt.transportFor(proxy).RoundTrip(req)
	if err != nil {
		rt.pool.ReportError(proxy)
		rt.noteHostFailure(host)
		return nil, err
	}
	rt.pool.ReportStatus(proxy, resp.StatusCode)
	rt.noteHostSuccess(host)
	return resp, nil
}

func (rt *RoundTripper) noteHostFailure(host string) {
	if host == "" {
		return
	}
	rt.mu.Lock()
	defer rt.mu.Unlock()
	if rt.hostDirect[host] {
		return
	}
	rt.hostFailures[host]++
	if rt.hostFailures[host] >= directFallbackThreshold {
		rt.hostDirect[host] = true
		rt.pool.directFallbacks.Add(1)
	}
}

func (rt *RoundTripper) noteHostSuccess(host string) {
	if host == "" {
		return
	}
	rt.mu.Lock()
	delete(rt.hostFailures, host)
	rt.mu.Unlock()
}

// Rotate implements the rotation hook used by plugin.PolicySession.
func (rt *RoundTripper) Rotate(req *http.Request) {
	host := ""
	if req != nil && req.URL != nil {
		host = req.URL.Host
	}
	rt.pool.Rotate(host)
}

// RetryStatuses implements the retry hook used by plugin.PolicySession.
// A single proxy cannot fail over, so it exposes no extra retry statuses.
func (rt *RoundTripper) RetryStatuses() []int {
	if rt.pool.Len() < 2 {
		return nil
	}
	return rt.pool.RotateOnStatus()
}

// CloseIdleConnections closes cached proxy connections.
func (rt *RoundTripper) CloseIdleConnections() {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	for _, tr := range rt.transports {
		tr.CloseIdleConnections()
	}
}

func (rt *RoundTripper) transportFor(proxy *url.URL) *http.Transport {
	key := proxy.String()
	rt.mu.Lock()
	defer rt.mu.Unlock()
	if tr, ok := rt.transports[key]; ok {
		return tr
	}
	tr := rt.base.Clone()
	tr.Proxy = http.ProxyURL(proxy)
	rt.transports[key] = tr
	return tr
}

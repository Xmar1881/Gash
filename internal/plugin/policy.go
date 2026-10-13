// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Modül: github.com/Xmar1881/Gash

package plugin

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"

	"golang.org/x/time/rate"
)

// PolicyConfig PolicySession davranışıdır (bayraklar → buraya).
type PolicyConfig struct {
	// SafeDefault tarama safe varsayılanıdır; Safe=false plugin'ler ayrıca filtrelenir.
	MaxRequestsPerTarget int64
	MaxRequestsTotal     int64
	Scope                []string // CIDR veya domain allowlist; boşsa implicit-scope (hedefe izin)
	RatePerSecond        float64  // per-target token bucket; <=0 ise limitsiz (testler için)
	MaxResponseBytes     int64
}

// DefaultPolicyConfig bayrak default'larıdır (architecture.md §14.1).
func DefaultPolicyConfig() PolicyConfig {
	return PolicyConfig{
		MaxRequestsPerTarget: 1000,
		MaxRequestsTotal:     10000,
		RatePerSecond:        10,
		MaxResponseBytes:     5 * 1024 * 1024,
	}
}

// ctxKey plugin taşıma anahtarıdır (RoundTripper plugin-safe'i ctx'ten okur).
type ctxKey struct{}

// WithPlugin ctx'e plugin kimliği + safe bayrağını gömer.
func WithPlugin(ctx context.Context, id string, safe bool, maxRequests *int) context.Context {
	return context.WithValue(ctx, ctxKey{}, pluginCtx{ID: id, Safe: safe, MaxRequests: maxRequests})
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
// Beyana güvenilmez: safe=true POST atamaz, bütçe/scope/rate burada enforce edilir.
type PolicySession struct {
	cfg  PolicyConfig
	base http.RoundTripper

	total     atomic.Int64
	perTarget map[string]*atomic.Int64
	perPlugin map[string]*atomic.Int64
	mu        sync.Mutex

	limiters map[string]*rate.Limiter
}

// NewPolicySession proxy'yi kurar (base nil ise http.DefaultTransport).
func NewPolicySession(cfg PolicyConfig, base http.RoundTripper) *PolicySession {
	if base == nil {
		base = http.DefaultTransport
	}
	return &PolicySession{
		cfg:       cfg,
		base:      base,
		perTarget: make(map[string]*atomic.Int64),
		perPlugin: make(map[string]*atomic.Int64),
		limiters:  make(map[string]*rate.Limiter),
	}
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
	if len(p.cfg.Scope) == 0 {
		return nil
	}
	host := strings.ToLower(u.Hostname())
	if host == "" {
		return fmt.Errorf("%w: empty host (scope-mismatch)", ErrScopeViolation)
	}
	for _, entry := range p.cfg.Scope {
		e := strings.ToLower(strings.TrimSpace(entry))
		if e == "" {
			continue
		}
		if _, cidr, err := net.ParseCIDR(e); err == nil {
			// CIDR entry: resolve the hostname and check allowlist membership (rebinding double-check).
			ips, err := net.DefaultResolver.LookupIPAddr(ctx, host)
			if err != nil {
				// Unresolvable hosts never match a CIDR entry (fail-closed).
				continue
			}
			for _, ip := range ips {
				if cidr.Contains(ip.IP) {
					return nil
				}
			}
			continue
		}
		// Domain match: exact host or subdomain.
		if host == e || strings.HasSuffix(host, "."+e) {
			// Additional IP check is best-effort for plain domain entries;
			// a hostname match is sufficient without CIDR cross-check.
			return nil
		}
	}
	return fmt.Errorf("%w: host %q outside scope (scope-mismatch)", ErrScopeViolation, host)
}

// TotalCount test/rapor için toplam istek sayısı.
func (p *PolicySession) TotalCount() int64 { return p.total.Load() }

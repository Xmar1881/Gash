// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Module: github.com/Xmar1881/Gash

package plugin

import (
	"context"
	"errors"
	"net"
	"net/url"
	"strings"
	"testing"
	"time"
)

type testNetError struct {
	timeout bool
}

func (e testNetError) Error() string   { return "net error" }
func (e testNetError) Timeout() bool   { return e.timeout }
func (e testNetError) Temporary() bool { return true }

func TestClassifyErrorMatrix(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want ErrorClass
	}{
		{"nil", nil, ErrorClassUnknown},
		{"scope policy", &PolicyError{Op: "scope"}, ErrorClassScope},
		{"rate policy", &PolicyError{Op: "rate"}, ErrorClassPolicy},
		{"budget policy", &PolicyError{Op: "budget"}, ErrorClassPolicy},
		{"method policy", &PolicyError{Op: "method"}, ErrorClassPolicy},
		{"other policy", &PolicyError{Op: "other"}, ErrorClassPolicy},
		{"wrapped policy", errors.Join(errors.New("outer"), &PolicyError{Op: "scope"}), ErrorClassScope},
		{"net timeout", testNetError{timeout: true}, ErrorClassTimeout},
		{"net error", testNetError{}, ErrorClassNetwork},
		{"url timeout", &url.Error{Op: "Get", URL: "http://x", Err: context.DeadlineExceeded}, ErrorClassTimeout},
		{"url network", &url.Error{Op: "Get", URL: "http://x", Err: errors.New("reset")}, ErrorClassNetwork},
		{"deadline", context.DeadlineExceeded, ErrorClassTimeout},
		{"canceled", context.Canceled, ErrorClassTimeout},
		{"redirect", errors.New("too many redirects"), ErrorClassRedirect},
		{"unknown", errors.New("boom"), ErrorClassUnknown},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := ClassifyError(tc.err); got != tc.want {
				t.Fatalf("ClassifyError(%v) = %v, want %v", tc.err, got, tc.want)
			}
		})
	}
}

func TestIsRetryableMatrix(t *testing.T) {
	statuses := []int{408, 429, 500, 502, 503, 504}
	tests := []struct {
		name   string
		class  ErrorClass
		status int
		want   bool
	}{
		{"timeout", ErrorClassTimeout, 0, true},
		{"network", ErrorClassNetwork, 0, true},
		{"server retryable", ErrorClassServer, 503, true},
		{"server non-retryable", ErrorClassServer, 501, false},
		{"policy", ErrorClassPolicy, 503, false},
		{"scope", ErrorClassScope, 503, false},
		{"client", ErrorClassClient, 503, false},
		{"unknown", ErrorClassUnknown, 503, false},
		{"redirect", ErrorClassRedirect, 503, false},
		{"nil status list", ErrorClassServer, 503, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			list := statuses
			if tc.name == "nil status list" {
				list = nil
			}
			if got := IsRetryable(tc.class, tc.status, list); got != tc.want {
				t.Fatalf("IsRetryable(%v,%d) = %v, want %v", tc.class, tc.status, got, tc.want)
			}
		})
	}
}

func TestDefaultPolicyConfigInvariants(t *testing.T) {
	cfg := DefaultPolicyConfig()
	if cfg.MaxRequestsPerTarget <= 0 || cfg.MaxRequestsTotal <= 0 || cfg.RatePerSecond <= 0 {
		t.Fatalf("budgets must be positive: %+v", cfg)
	}
	if cfg.MaxRequestsTotal < cfg.MaxRequestsPerTarget {
		t.Fatalf("total budget must cover per-target: %+v", cfg)
	}
	if cfg.MaxResponseBytes <= 0 || cfg.MaxRequestBytes <= 0 || cfg.BackpressureLimit <= 0 {
		t.Fatalf("size/backpressure limits must be positive: %+v", cfg)
	}
	if cfg.GlobalRatePerSecond < cfg.RatePerSecond {
		t.Fatalf("global rate must be >= per-target: %+v", cfg)
	}
	if cfg.ScanTimeout <= 0 {
		t.Fatalf("scan timeout must be positive: %+v", cfg)
	}
	if cfg.RetryConfig.MaxRetries < 0 || cfg.RetryConfig.MaxDelay <= 0 || cfg.RetryConfig.BaseDelay <= 0 {
		t.Fatalf("retry config invalid: %+v", cfg.RetryConfig)
	}
	if len(cfg.RetryConfig.RetryableStatus) == 0 {
		t.Fatal("retryable status list must not be empty")
	}
	if !cfg.RedirectPolicy.FollowRedirects || !cfg.RedirectPolicy.RevalidateScope {
		t.Fatalf("redirect policy must follow and revalidate: %+v", cfg.RedirectPolicy)
	}
}

func TestScopeParseEntryMatrix(t *testing.T) {
	sm := newScopeManager(nil)
	tests := []struct {
		name     string
		entry    string
		wantNil  bool
		wantType scopeEntryType
		value    string
		port     int
		protocol string
		path     string
	}{
		{"empty", "", true, 0, "", 0, "", ""},
		{"spaces", "  ", true, 0, "", 0, "", ""},
		{"domain", "Example.COM", false, scopeTypeDomain, "example.com", 0, "", ""},
		{"domain port", "example.com:8443", false, scopeTypeDomain, "example.com", 8443, "", ""},
		{"cidr", "127.0.0.0/8", false, scopeTypeCIDR, "127.0.0.0/8", 0, "", ""},
		{"url", "https://Example.COM/API/", false, scopeTypeURLPrefix, "example.com", 0, "https", "/API"},
		{"url port", "https://example.com:8443/api/", false, scopeTypeURLPrefix, "example.com", 8443, "https", "/api"},
		{"ipv6 url", "http://[::1]:8080/x", false, scopeTypeURLPrefix, "::1", 8080, "http", "/x"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := sm.parseEntry(tc.entry)
			if tc.wantNil {
				if got != nil {
					t.Fatalf("parseEntry(%q) = %+v, want nil", tc.entry, got)
				}
				return
			}
			if got == nil {
				t.Fatalf("parseEntry(%q) = nil", tc.entry)
			}
			if got.Type != tc.wantType || got.Value != tc.value || got.Port != tc.port ||
				got.Protocol != tc.protocol || got.Path != tc.path {
				t.Fatalf("parseEntry(%q) = %+v", tc.entry, got)
			}
		})
	}
}

func TestScopeURLPrefixPortAndPath(t *testing.T) {
	sm := newScopeManager([]string{"https://example.com:8443/api"})
	allowed := []string{
		"https://example.com:8443/api",
		"https://example.com:8443/api/",
		"https://example.com:8443/api/v1",
	}
	for _, raw := range allowed {
		if err := sm.check(context.Background(), mustParseScopeURL(t, raw)); err != nil {
			t.Fatalf("URL prefix rejected allowed %s: %v", raw, err)
		}
	}
	rejected := []string{
		"https://example.com:8443/apix",
		"https://example.com:8443/other",
		"https://example.com:9443/api",
		"http://example.com:8443/api",
	}
	for _, raw := range rejected {
		if err := sm.check(context.Background(), mustParseScopeURL(t, raw)); err == nil {
			t.Fatalf("URL prefix allowed rejected %s", raw)
		}
	}
}

func TestScopeDomainPort(t *testing.T) {
	sm := newScopedManager(t, "http://127.0.0.1:8080", []string{"127.0.0.1:8080"}, map[string][]net.IP{
		"127.0.0.1": ipList("127.0.0.1"),
	})
	if err := sm.check(context.Background(), mustParseScopeURL(t, "http://127.0.0.1:8080/")); err != nil {
		t.Fatalf("explicit domain port rejected: %v", err)
	}
	if err := sm.check(context.Background(), mustParseScopeURL(t, "http://127.0.0.1:9090/")); err == nil {
		t.Fatal("wrong explicit port allowed")
	}
}

func TestPluginScanBudgetLimits(t *testing.T) {
	u := mustParseScopeURL(t, "https://Example.COM/a")
	if got := (&scanBudget{}).requestsTotal.Load(); got != 0 {
		t.Fatalf("zero-value total = %d", got)
	}
	sb := newScanBudget(2, 0, 0)
	if err := sb.checkAndIncrement(u); err != nil {
		t.Fatal(err)
	}
	if err := sb.checkAndIncrement(u); err != nil {
		t.Fatal(err)
	}
	if err := sb.checkAndIncrement(u); !errors.Is(err, ErrBudgetExceeded) {
		t.Fatalf("total budget err = %v", err)
	}
	if got := sb.requestsTotal.Load(); got != 2 {
		t.Fatalf("total = %d, want 2", got)
	}

	sb = newScanBudget(0, 2, 0)
	for i := 0; i < 2; i++ {
		if err := sb.checkAndIncrement(u); err != nil {
			t.Fatal(err)
		}
	}
	if err := sb.checkAndIncrement(u); !errors.Is(err, ErrBudgetExceeded) {
		t.Fatalf("per-host err = %v", err)
	}
	if err := sb.checkAndIncrement(mustParseScopeURL(t, "https://other.example/a")); err != nil {
		t.Fatalf("other host should have its own budget: %v", err)
	}
}

func TestPluginScanBudgetPerPath(t *testing.T) {
	sb := newScanBudget(0, 0, 1)
	u := mustParseScopeURL(t, "https://example.com/a")
	if err := sb.checkAndIncrement(u); err != nil {
		t.Fatal(err)
	}
	if err := sb.checkAndIncrement(u); !errors.Is(err, ErrBudgetExceeded) {
		t.Fatalf("per-path err = %v", err)
	}
	if err := sb.checkAndIncrement(mustParseScopeURL(t, "https://example.com/b")); err != nil {
		t.Fatalf("different path should have its own budget: %v", err)
	}
}

func TestPluginScanBudgetRejectedRequestDoesNotConsume(t *testing.T) {
	sb := newScanBudget(0, 2, 1)
	a := mustParseScopeURL(t, "https://example.com/a")
	b := mustParseScopeURL(t, "https://example.com/b")
	if err := sb.checkAndIncrement(a); err != nil {
		t.Fatal(err)
	}
	if err := sb.checkAndIncrement(a); !errors.Is(err, ErrBudgetExceeded) {
		t.Fatalf("second same-path request err = %v", err)
	}
	if err := sb.checkAndIncrement(b); err != nil {
		t.Fatalf("rejected request consumed host budget: %v", err)
	}
	if got := sb.requestsTotal.Load(); got != 2 {
		t.Fatalf("total = %d, want 2", got)
	}
}

func TestPluginScanBudgetNoLimits(t *testing.T) {
	sb := newScanBudget(0, 0, 0)
	u := mustParseScopeURL(t, "https://example.com/a")
	for i := 0; i < 5; i++ {
		if err := sb.checkAndIncrement(u); err != nil {
			t.Fatal(err)
		}
	}
	if got := sb.requestsTotal.Load(); got != 5 {
		t.Fatalf("total = %d, want 5", got)
	}
}

func TestContextHelpers(t *testing.T) {
	base := context.Background()
	if pluginFromCtx(base).ID != "" || pluginFromCtx(base).Safe {
		t.Fatal("empty context must yield zero plugin context")
	}
	max := 7
	ctx := WithPlugin(base, "plugin-a", true, &max)
	pc := pluginFromCtx(ctx)
	if pc.ID != "plugin-a" || !pc.Safe || pc.MaxRequests == nil || *pc.MaxRequests != 7 {
		t.Fatalf("plugin context = %+v", pc)
	}
	if noRedirectFromCtx(base) {
		t.Fatal("base context must not request no-redirect")
	}
	if !noRedirectFromCtx(WithNoRedirect(base)) {
		t.Fatal("WithNoRedirect marker missing")
	}
}

func TestTargetKey(t *testing.T) {
	tests := []struct {
		raw  string
		want string
	}{
		{"https://Example.COM:8443/path", "example.com"},
		{"http://127.0.0.1:8080/", "127.0.0.1"},
		{"http://[::1]:8080/", "::1"},
	}
	for _, tc := range tests {
		if got := targetKey(mustParseScopeURL(t, tc.raw)); got != tc.want {
			t.Fatalf("targetKey(%q) = %q, want %q", tc.raw, got, tc.want)
		}
	}
}

func TestSchemeHelpers(t *testing.T) {
	upgrades := [][2]string{{"http", "https"}, {"HTTP", "HTTPS"}}
	for _, pair := range upgrades {
		if !isSchemeUpgrade(pair[0], pair[1]) {
			t.Fatalf("%v must be an upgrade", pair)
		}
		if isSchemeDowngrade(pair[0], pair[1]) {
			t.Fatalf("%v must not be a downgrade", pair)
		}
	}
	downgrades := [][2]string{{"https", "http"}, {"HTTPS", "HTTP"}}
	for _, pair := range downgrades {
		if !isSchemeDowngrade(pair[0], pair[1]) {
			t.Fatalf("%v must be a downgrade", pair)
		}
		if isSchemeUpgrade(pair[0], pair[1]) {
			t.Fatalf("%v must not be an upgrade", pair)
		}
	}
	for _, pair := range [][2]string{{"http", "http"}, {"https", "https"}, {"http", "ftp"}} {
		if isSchemeUpgrade(pair[0], pair[1]) || isSchemeDowngrade(pair[0], pair[1]) {
			t.Fatalf("%v must not be a scheme transition", pair)
		}
	}
}

func TestMaxHelper(t *testing.T) {
	for _, tc := range []struct{ a, b, want int }{{1, 2, 2}, {2, 1, 2}, {0, 0, 0}, {-1, 0, 0}} {
		if got := max(tc.a, tc.b); got != tc.want {
			t.Fatalf("max(%d,%d) = %d, want %d", tc.a, tc.b, got, tc.want)
		}
	}
}

func TestBackoffDelayBounds(t *testing.T) {
	cfg := DefaultPolicyConfig()
	cfg.RetryConfig.BaseDelay = 10 * time.Millisecond
	cfg.RetryConfig.MaxDelay = 40 * time.Millisecond
	p := NewPolicySession(cfg, nil)
	for _, attempt := range []int{-1, 0, 1, 10} {
		got := p.backoffDelay(attempt)
		if got < 0 || got > cfg.RetryConfig.MaxDelay {
			t.Fatalf("backoffDelay(%d) = %v outside [0,%v]", attempt, got, cfg.RetryConfig.MaxDelay)
		}
	}
}

func TestScopeHasExplicitScope(t *testing.T) {
	var nilManager *scopeManager
	if nilManager.hasExplicitScope() {
		t.Fatal("nil manager must not report explicit scope")
	}
	if newScopeManager(nil).hasExplicitScope() {
		t.Fatal("open mode must not report explicit scope")
	}
	if !newScopeManager([]string{"example.com"}).hasExplicitScope() {
		t.Fatal("configured manager must report explicit scope")
	}
}

func TestPolicyErrorText(t *testing.T) {
	err := &PolicyError{PluginID: "x", Op: "scope", Err: ErrScopeViolation}
	if got := err.Error(); !strings.Contains(got, "plugin \"x\" policy scope") || !strings.Contains(got, ErrScopeViolation.Error()) {
		t.Fatalf("PolicyError text = %q", got)
	}
	if !errors.Is(err, ErrScopeViolation) {
		t.Fatal("PolicyError must unwrap its cause")
	}
}

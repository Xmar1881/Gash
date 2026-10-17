// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Modül: github.com/Xmar1881/Gash

package plugin

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"
)

func mustParseScopeURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parse %q: %v", raw, err)
	}
	return u
}

func ipList(vals ...string) []net.IP {
	ips := make([]net.IP, 0, len(vals))
	for _, v := range vals {
		ips = append(ips, net.ParseIP(v))
	}
	return ips
}

// newScopedManager builds a manager with explicit --scope entries and seeded
// resolved IPs so tests never depend on real DNS.
func newScopedManager(t *testing.T, original string, scope []string, resolved map[string][]net.IP) *scopeManager {
	t.Helper()
	sm := newScopeManager(scope)
	for host, ips := range resolved {
		sm.resolvedIPs[host] = ips
	}
	sm.setOriginalTarget(original)
	return sm
}

// TestOpenMode_NoScopeAllowsAnyHost proves that without --scope no host is
// blocked (operator-responsibility model; old implicit scope is gone).
func TestOpenMode_NoScopeAllowsAnyHost(t *testing.T) {
	sm := newScopeManager(nil)
	sm.setOriginalTarget("https://example.com")
	for _, raw := range []string{
		"https://example.com/",
		"https://www.example.com/",
		"https://api.example.com/",
		"https://evil-example.com/",
		"https://example.org/",
		"http://example.com/", // cross-scheme variant: still allowed in open mode
		"http://93.184.216.34/",
	} {
		if err := sm.check(context.Background(), mustParseScopeURL(t, raw)); err != nil {
			t.Fatalf("open mode (no --scope) must not block %s: %v", raw, err)
		}
	}
}

// TestOpenMode_CrossHostRedirectFollowed locks open-mode redirect following
// (cross-host, cross-scheme, cross-registrable-domain).
func TestOpenMode_CrossHostRedirectFollowed(t *testing.T) {
	policy, rt := newTestPolicySession(t, "https://example.com", map[string][]net.IP{
		"example.com": ipList("93.184.216.34"),
	}, scriptedRedirect("https://cdn.other-domain.net/home"))

	resp, err := doRedirectRequest(t, policy, "https://example.com/")
	if err != nil {
		t.Fatalf("open mode must follow cross-host redirects: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 after cross-host redirect, got %d", resp.StatusCode)
	}
	seen := rt.seen()
	if len(seen) != 2 || seen[0] != "https://example.com/" || seen[1] != "https://cdn.other-domain.net/home" {
		t.Fatalf("unexpected request chain: %v", seen)
	}
}

// TestOpenMode_CrossSchemeDowngradeFollowed proves open mode follows
// https→http redirects (scheme difference included; strict mode never does).
func TestOpenMode_CrossSchemeDowngradeFollowed(t *testing.T) {
	policy, rt := newTestPolicySession(t, "https://example.com", map[string][]net.IP{
		"example.com": ipList("93.184.216.34"),
	}, scriptedRedirect("http://example.com/plain"))

	resp, err := doRedirectRequest(t, policy, "https://example.com/")
	if err != nil {
		t.Fatalf("open mode must follow cross-scheme redirects: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 after cross-scheme redirect, got %d", resp.StatusCode)
	}
	if got := rt.seen(); len(got) != 2 {
		t.Fatalf("expected the downgrade hop to be requested, saw %v", got)
	}
}

// TestScope_ExternalHostsRejected keeps the strict --scope behavior:
// external registrable domains and suffix tricks stay rejected.
func TestScope_ExternalHostsRejected(t *testing.T) {
	sm := newScopedManager(t, "https://example.com", []string{"example.com"}, map[string][]net.IP{
		"example.com":     ipList("93.184.216.34"),
		"www.example.com": ipList("93.184.216.34"),
		"api.example.com": ipList("93.184.216.34"),
	})
	for _, candidate := range []string{
		"https://evil-example.com/",
		"https://www.example.com.evil.com/", // suffix trick
		"https://example.org/",
	} {
		err := sm.check(context.Background(), mustParseScopeURL(t, candidate))
		if err == nil {
			t.Fatalf("candidate %s must be rejected with --scope", candidate)
		}
		if !errors.Is(err, ErrScopeViolation) {
			t.Fatalf("candidate %s: expected ErrScopeViolation, got %v", candidate, err)
		}
	}
	// Domain entries stay wide: apex↔www variant and subdomains are in scope.
	for _, candidate := range []string{"https://www.example.com/", "https://api.example.com/"} {
		if err := sm.check(context.Background(), mustParseScopeURL(t, candidate)); err != nil {
			t.Fatalf("candidate %s must be in scope: %v", candidate, err)
		}
	}
}

// TestScope_HTTPToHTTPSUpgradeAllowed http→https hop stays allowed under scope.
func TestScope_HTTPToHTTPSUpgradeAllowed(t *testing.T) {
	sm := newScopedManager(t, "http://example.com", []string{"example.com"}, map[string][]net.IP{
		"example.com": ipList("93.184.216.34"),
	})
	if err := sm.check(context.Background(), mustParseScopeURL(t, "https://example.com/")); err != nil {
		t.Fatalf("http→https upgrade must be allowed under --scope: %v", err)
	}
}

// TestScope_DNSRebindingWWWDifferentIPRejected rebinding pinning stays on
// with --scope: a www variant resolving to a new IP is rejected.
func TestScope_DNSRebindingWWWDifferentIPRejected(t *testing.T) {
	policy, rt := newTestPolicySessionScoped(t, "https://example.com", []string{"example.com"}, map[string][]net.IP{
		"example.com":     ipList("93.184.216.34"),
		"www.example.com": ipList("203.0.113.9"), // rebinding: different IP
	}, scriptedRedirect("https://www.example.com/home"))

	_, err := doRedirectRequest(t, policy, "https://example.com/")
	if err == nil {
		t.Fatal("www variant resolving to a different IP must be rejected (DNS rebinding)")
	}
	var perr *PolicyError
	if !errors.As(err, &perr) || perr.Op != "redirect-scope" {
		t.Fatalf("expected redirect-scope PolicyError, got %v", err)
	}
	if !errors.Is(err, ErrScopeViolation) {
		t.Fatalf("expected ErrScopeViolation, got %v", err)
	}
	if got := rt.seen(); len(got) != 1 {
		t.Fatalf("rebinding target must not be requested, saw %v", got)
	}

	// One extra IP alongside the original is still rebinding.
	policy2, rt2 := newTestPolicySessionScoped(t, "https://example.com", []string{"example.com"}, map[string][]net.IP{
		"example.com":     ipList("93.184.216.34"),
		"www.example.com": ipList("93.184.216.34", "203.0.113.9"),
	}, scriptedRedirect("https://www.example.com/home"))
	if _, err := doRedirectRequest(t, policy2, "https://example.com/"); err == nil {
		t.Fatalf("www variant with an additional unknown IP must be rejected (saw %v)", rt2.seen())
	}
}

// TestScope_IPHostExactMatchOnly exact IP+port scope entry stays strict.
func TestScope_IPHostExactMatchOnly(t *testing.T) {
	sm := newScopedManager(t, "http://127.0.0.1:8080", []string{"127.0.0.1:8080"}, map[string][]net.IP{
		"127.0.0.1": ipList("127.0.0.1"),
	})

	if err := sm.check(context.Background(), mustParseScopeURL(t, "http://127.0.0.1:8080/scan")); err != nil {
		t.Fatalf("exact IP+port match must be allowed: %v", err)
	}
	for _, candidate := range []string{
		"http://127.0.0.2:8080/", // different IP
		"http://127.0.0.1:9090/", // different port
	} {
		if err := sm.check(context.Background(), mustParseScopeURL(t, candidate)); err == nil {
			t.Fatalf("candidate %s must be rejected for exact IP scope entry", candidate)
		}
	}
}

func TestDefaultRedirectPolicy_UpgradeOnly(t *testing.T) {
	cfg := DefaultPolicyConfig()
	if !cfg.RedirectPolicy.AllowCrossScheme {
		t.Fatal("AllowCrossScheme default must allow the http→https upgrade")
	}
	if !isSchemeUpgrade("http", "https") {
		t.Fatal("http→https must be the allowed upgrade axis")
	}
	if isSchemeUpgrade("https", "http") {
		t.Fatal("https→http must never be an upgrade")
	}
	if !isSchemeDowngrade("https", "http") {
		t.Fatal("https→http must be the downgrade axis")
	}
	if isSchemeUpgrade("http", "ftp") || isSchemeUpgrade("http", "ws") {
		t.Fatal("non-http(s) scheme transitions must not be treated as upgrades")
	}
}

type scriptedRoundTripper struct {
	mu       sync.Mutex
	requests []string
	handler  func(*http.Request) *http.Response
}

func (s *scriptedRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	s.mu.Lock()
	s.requests = append(s.requests, req.URL.String())
	s.mu.Unlock()
	return s.handler(req), nil
}

func (s *scriptedRoundTripper) seen() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.requests...)
}

// scriptedRedirect answers 301 with location on the first hop and 200 afterwards.
func scriptedRedirect(location string) func(*http.Request) *http.Response {
	return func(req *http.Request) *http.Response {
		if req.URL.Path == "/" {
			return &http.Response{
				StatusCode: http.StatusMovedPermanently,
				Header:     http.Header{"Location": []string{location}},
				Body:       http.NoBody,
				Request:    req,
			}
		}
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     http.Header{},
			Body:       io.NopCloser(strings.NewReader("ok")),
			Request:    req,
		}
	}
}

func newTestPolicySession(t *testing.T, original string, resolved map[string][]net.IP, handler func(*http.Request) *http.Response) (*PolicySession, *scriptedRoundTripper) {
	t.Helper()
	return newTestPolicySessionScoped(t, original, nil, resolved, handler)
}

// newTestPolicySessionScoped builds an open-mode (scope == nil) or strict-mode
// (scope != nil) session with pre-seeded DNS to avoid real lookups in tests.
func newTestPolicySessionScoped(t *testing.T, original string, scope []string, resolved map[string][]net.IP, handler func(*http.Request) *http.Response) (*PolicySession, *scriptedRoundTripper) {
	t.Helper()
	rt := &scriptedRoundTripper{handler: handler}
	cfg := DefaultPolicyConfig()
	cfg.Scope = scope
	policy := NewPolicySession(cfg, rt)
	for host, ips := range resolved {
		policy.scopeManager.resolvedIPs[host] = ips
	}
	policy.SetOriginalTarget(original)
	return policy, rt
}

func doRedirectRequest(t *testing.T, policy *PolicySession, rawURL string) (*http.Response, error) {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, rawURL, nil)
	if err != nil {
		t.Fatalf("new request %q: %v", rawURL, err)
	}
	return policy.RoundTripWithRetry(req)
}

func TestRedirectPolicy_HTTPToHTTPSUpgradeFollowed(t *testing.T) {
	policy, rt := newTestPolicySession(t, "http://example.com", map[string][]net.IP{
		"example.com": ipList("93.184.216.34"),
	}, scriptedRedirect("https://example.com/home"))

	resp, err := doRedirectRequest(t, policy, "http://example.com/")
	if err != nil {
		t.Fatalf("http→https upgrade must be followed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 after upgrade redirect, got %d", resp.StatusCode)
	}
	seen := rt.seen()
	if len(seen) != 2 || seen[0] != "http://example.com/" || seen[1] != "https://example.com/home" {
		t.Fatalf("unexpected request chain: %v", seen)
	}
}

// TestScope_HTTPToHTTPSUpgradeRedirectFollowed strict mode keeps the
// upgrade-only cross-scheme redirect rule.
func TestScope_HTTPToHTTPSUpgradeRedirectFollowed(t *testing.T) {
	policy, rt := newTestPolicySessionScoped(t, "http://example.com", []string{"example.com"}, map[string][]net.IP{
		"example.com": ipList("93.184.216.34"),
	}, scriptedRedirect("https://example.com/home"))

	resp, err := doRedirectRequest(t, policy, "http://example.com/")
	if err != nil {
		t.Fatalf("http→https upgrade must be followed under --scope: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 after upgrade redirect, got %d", resp.StatusCode)
	}
	if got := rt.seen(); len(got) != 2 {
		t.Fatalf("expected 2 requests (http + https), saw %v", got)
	}
}

func TestRedirectPolicy_UpgradeRejectedWhenFlagDisabled(t *testing.T) {
	rt := &scriptedRoundTripper{handler: scriptedRedirect("https://example.com/home")}
	cfg := DefaultPolicyConfig()
	cfg.RedirectPolicy.AllowCrossScheme = false
	policy := NewPolicySession(cfg, rt)
	policy.scopeManager.resolvedIPs["example.com"] = ipList("93.184.216.34")
	policy.SetOriginalTarget("http://example.com")

	_, err := doRedirectRequest(t, policy, "http://example.com/")
	if err == nil {
		t.Fatal("upgrade must be rejected when AllowCrossScheme=false")
	}
	if len(rt.seen()) != 1 {
		t.Fatalf("redirect target must not be requested, saw %v", rt.seen())
	}
}

// TestScope_HTTPSDowngradeRedirectRejected strict mode never follows
// https→http downgrades (open mode follows them; see the open-mode test).
func TestScope_HTTPSDowngradeRedirectRejected(t *testing.T) {
	policy, rt := newTestPolicySessionScoped(t, "https://example.com", []string{"example.com"}, map[string][]net.IP{
		"example.com": ipList("93.184.216.34"),
	}, scriptedRedirect("http://example.com/plain"))

	_, err := doRedirectRequest(t, policy, "https://example.com/")
	if err == nil {
		t.Fatal("https→http downgrade must be rejected under --scope")
	}
	var perr *PolicyError
	if !errors.As(err, &perr) || perr.Op != "redirect" {
		t.Fatalf("expected redirect PolicyError, got %v", err)
	}
	if !errors.Is(err, ErrPolicyViolation) {
		t.Fatalf("expected ErrPolicyViolation, got %v", err)
	}
	if got := rt.seen(); len(got) != 1 {
		t.Fatalf("downgrade target must not be requested, saw %v", got)
	}
}

func TestRedirectPolicy_WWWVariantFollowed(t *testing.T) {
	policy, rt := newTestPolicySession(t, "https://example.com", map[string][]net.IP{
		"example.com":     ipList("93.184.216.34"),
		"www.example.com": ipList("93.184.216.34"),
	}, scriptedRedirect("https://www.example.com/home"))

	resp, err := doRedirectRequest(t, policy, "https://example.com/")
	if err != nil {
		t.Fatalf("apex→www redirect must be followed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 after www redirect, got %d", resp.StatusCode)
	}
	if got := rt.seen(); len(got) != 2 {
		t.Fatalf("expected 2 requests (apex + www), saw %v", got)
	}
}

// TestScope_WWWVariantRedirectFollowed strict mode keeps apex↔www redirects
// (domain entries cover the variant; rebinding pinning still applies).
func TestScope_WWWVariantRedirectFollowed(t *testing.T) {
	policy, rt := newTestPolicySessionScoped(t, "https://example.com", []string{"example.com"}, map[string][]net.IP{
		"example.com":     ipList("93.184.216.34"),
		"www.example.com": ipList("93.184.216.34"),
	}, scriptedRedirect("https://www.example.com/home"))

	resp, err := doRedirectRequest(t, policy, "https://example.com/")
	if err != nil {
		t.Fatalf("apex→www redirect must be followed under --scope: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 after www redirect, got %d", resp.StatusCode)
	}
	if got := rt.seen(); len(got) != 2 {
		t.Fatalf("expected 2 requests (apex + www), saw %v", got)
	}
}

func TestScope_EvilDomainRedirectRejected(t *testing.T) {
	policy, rt := newTestPolicySessionScoped(t, "https://example.com", []string{"example.com"}, map[string][]net.IP{
		"example.com": ipList("93.184.216.34"),
	}, scriptedRedirect("https://evil-example.com/home"))

	_, err := doRedirectRequest(t, policy, "https://example.com/")
	if err == nil {
		t.Fatal("redirect to a different registrable domain must be rejected with --scope")
	}
	var perr *PolicyError
	if !errors.As(err, &perr) || perr.Op != "redirect-scope" {
		t.Fatalf("expected redirect-scope PolicyError, got %v", err)
	}
	if !errors.Is(err, ErrScopeViolation) {
		t.Fatalf("expected ErrScopeViolation, got %v", err)
	}
	if got := rt.seen(); len(got) != 1 {
		t.Fatalf("out-of-scope target must not be requested, saw %v", got)
	}
}

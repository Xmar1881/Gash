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

// newImplicitScopeManager builds an implicit-scope manager with resolved IPs
// pre-seeded so tests never depend on real DNS.
func newImplicitScopeManager(t *testing.T, original string, resolved map[string][]net.IP) *scopeManager {
	t.Helper()
	sm := newScopeManager(nil)
	for host, ips := range resolved {
		sm.resolvedIPs[host] = ips
	}
	sm.setOriginalTarget(original)
	return sm
}

func TestImplicitScope_HTTPToHTTPSUpgradeAllowed(t *testing.T) {
	sm := newImplicitScopeManager(t, "http://example.com", map[string][]net.IP{
		"example.com": ipList("93.184.216.34"),
	})
	if err := sm.check(context.Background(), mustParseScopeURL(t, "https://example.com/")); err != nil {
		t.Fatalf("http→https upgrade must be allowed: %v", err)
	}
}

func TestImplicitScope_ApexWWWVariantAllowed(t *testing.T) {
	httpSM := newImplicitScopeManager(t, "http://example.com", map[string][]net.IP{
		"example.com":     ipList("93.184.216.34"),
		"www.example.com": ipList("93.184.216.34"),
	})
	for _, candidate := range []string{"https://www.example.com/", "http://www.example.com/"} {
		if err := httpSM.check(context.Background(), mustParseScopeURL(t, candidate)); err != nil {
			t.Fatalf("apex↔www variant %s must be in implicit scope: %v", candidate, err)
		}
	}

	httpsSM := newImplicitScopeManager(t, "https://example.com", map[string][]net.IP{
		"example.com":     ipList("93.184.216.34"),
		"www.example.com": ipList("93.184.216.34"),
	})
	if err := httpsSM.check(context.Background(), mustParseScopeURL(t, "https://www.example.com/")); err != nil {
		t.Fatalf("https apex→www variant must be in implicit scope: %v", err)
	}
	// https apex → http www is a downgrade: still out of implicit scope.
	if err := httpsSM.check(context.Background(), mustParseScopeURL(t, "http://www.example.com/")); err == nil {
		t.Fatal("http www variant under https apex must be rejected (downgrade)")
	}
}

func TestImplicitScope_OutOfScopeHostsRejected(t *testing.T) {
	sm := newImplicitScopeManager(t, "https://example.com", map[string][]net.IP{
		"example.com": ipList("93.184.216.34"),
	})
	for _, candidate := range []string{
		"https://evil-example.com/",
		"https://api.example.com/",         // arbitrary subdomain: NOT widened
		"https://www.example.com.evil.com/", // suffix trick
		"https://example.org/",
	} {
		err := sm.check(context.Background(), mustParseScopeURL(t, candidate))
		if err == nil {
			t.Fatalf("candidate %s must be rejected", candidate)
		}
		if !errors.Is(err, ErrScopeViolation) {
			t.Fatalf("candidate %s: expected ErrScopeViolation, got %v", candidate, err)
		}
	}
}

func TestImplicitScope_HTTPSDowngradeRejected(t *testing.T) {
	sm := newImplicitScopeManager(t, "https://example.com", map[string][]net.IP{
		"example.com": ipList("93.184.216.34"),
	})
	err := sm.check(context.Background(), mustParseScopeURL(t, "http://example.com/"))
	if err == nil {
		t.Fatal("https→http downgrade must be rejected")
	}
	if !errors.Is(err, ErrScopeViolation) {
		t.Fatalf("expected ErrScopeViolation, got %v", err)
	}
}

func TestImplicitScope_IPHostExactMatchOnly(t *testing.T) {
	sm := newImplicitScopeManager(t, "http://127.0.0.1:8080", nil)

	if err := sm.check(context.Background(), mustParseScopeURL(t, "http://127.0.0.1:8080/scan")); err != nil {
		t.Fatalf("exact IP+port match must be allowed: %v", err)
	}
	for _, candidate := range []string{
		"http://www.127.0.0.1:8080/", // no www expansion for IP targets
		"http://127.0.0.2:8080/",     // different IP
		"http://127.0.0.1:9090/",     // different port
	} {
		if err := sm.check(context.Background(), mustParseScopeURL(t, candidate)); err == nil {
			t.Fatalf("candidate %s must be rejected for IP target", candidate)
		}
	}
}

func TestImplicitScope_DNSRebindingWWWDifferentIPRejected(t *testing.T) {
	sm := newImplicitScopeManager(t, "https://example.com", map[string][]net.IP{
		"example.com":     ipList("93.184.216.34"),
		"www.example.com": ipList("203.0.113.9"), // rebinding: different IP
	})
	err := sm.check(context.Background(), mustParseScopeURL(t, "https://www.example.com/"))
	if err == nil {
		t.Fatal("www variant resolving to a different IP must be rejected (DNS rebinding)")
	}
	if !errors.Is(err, ErrScopeViolation) {
		t.Fatalf("expected ErrScopeViolation, got %v", err)
	}

	// One extra IP alongside the original is still rebinding.
	sm2 := newImplicitScopeManager(t, "https://example.com", map[string][]net.IP{
		"example.com":     ipList("93.184.216.34"),
		"www.example.com": ipList("93.184.216.34", "203.0.113.9"),
	})
	if err := sm2.check(context.Background(), mustParseScopeURL(t, "https://www.example.com/")); err == nil {
		t.Fatal("www variant with an additional unknown IP must be rejected")
	}
}

func TestDefaultRedirectPolicy_UpgradeOnly(t *testing.T) {
	cfg := DefaultPolicyConfig()
	if !cfg.RedirectPolicy.AllowCrossScheme {
		t.Fatal("AllowCrossScheme default must allow the http→https upgrade")
	}
	if !schemeAllowed("http", "https") {
		t.Fatal("http→https must be allowed")
	}
	if schemeAllowed("https", "http") {
		t.Fatal("https→http must never be allowed")
	}
	if schemeAllowed("http", "ftp") || schemeAllowed("http", "ws") {
		t.Fatal("non-http(s) scheme transitions must not be allowed")
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
	rt := &scriptedRoundTripper{handler: handler}
	policy := NewPolicySession(DefaultPolicyConfig(), rt)
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

func TestRedirectPolicy_HTTPSDowngradeRejected(t *testing.T) {
	policy, rt := newTestPolicySession(t, "https://example.com", map[string][]net.IP{
		"example.com": ipList("93.184.216.34"),
	}, scriptedRedirect("http://example.com/plain"))

	_, err := doRedirectRequest(t, policy, "https://example.com/")
	if err == nil {
		t.Fatal("https→http downgrade must be rejected even with AllowCrossScheme=true")
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

func TestRedirectPolicy_WWWRebindingRejected(t *testing.T) {
	policy, rt := newTestPolicySession(t, "https://example.com", map[string][]net.IP{
		"example.com":     ipList("93.184.216.34"),
		"www.example.com": ipList("203.0.113.9"), // different IP: rebinding
	}, scriptedRedirect("https://www.example.com/home"))

	_, err := doRedirectRequest(t, policy, "https://example.com/")
	if err == nil {
		t.Fatal("www redirect resolving to a different IP must be rejected")
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
}

func TestRedirectPolicy_EvilDomainRejected(t *testing.T) {
	policy, rt := newTestPolicySession(t, "https://example.com", map[string][]net.IP{
		"example.com": ipList("93.184.216.34"),
	}, scriptedRedirect("https://evil-example.com/home"))

	_, err := doRedirectRequest(t, policy, "https://example.com/")
	if err == nil {
		t.Fatal("redirect to a different registrable domain must be rejected")
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

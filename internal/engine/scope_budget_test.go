// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Module: github.com/Xmar1881/Gash

package engine

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/Xmar1881/Gash/internal/plugin"
)

func mustURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parse %q: %v", raw, err)
	}
	return u
}

func TestScopeManagerConcurrentCIDR(t *testing.T) {
	sm := NewScopeManager([]string{"127.0.0.0/8"})
	urls := make([]*url.URL, 0, 32)
	for i := 1; i <= 32; i++ {
		u, err := url.Parse(fmt.Sprintf("http://127.0.0.%d/", i))
		if err != nil {
			t.Fatal(err)
		}
		urls = append(urls, u)
	}
	var wg sync.WaitGroup
	for _, u := range urls {
		wg.Add(1)
		go func(target *url.URL) {
			defer wg.Done()
			for i := 0; i < 20; i++ {
				if err := sm.CheckScope(context.Background(), target); err != nil {
					t.Errorf("in-scope CIDR host rejected: %v", err)
					return
				}
			}
		}(u)
	}
	wg.Wait()
}

func TestParseEntryMatrix(t *testing.T) {
	tests := []struct {
		name     string
		entry    string
		wantNil  bool
		wantType ScopeEntryType
		value    string
		port     int
		protocol string
		path     string
	}{
		{"empty", "", true, 0, "", 0, "", ""},
		{"spaces", "   ", true, 0, "", 0, "", ""},
		{"domain lowercase", "Example.COM", false, ScopeTypeDomain, "example.com", 0, "", ""},
		{"domain with port", "example.com:8443", false, ScopeTypeDomain, "example.com", 8443, "", ""},
		{"ipv4 cidr", "10.0.0.0/8", false, ScopeTypeCIDR, "10.0.0.0/8", 0, "", ""},
		{"url prefix", "https://Example.COM/API/", false, ScopeTypeURLPrefix, "example.com", 0, "https", "/API"},
		{"url prefix port", "https://example.com:8443/api/", false, ScopeTypeURLPrefix, "example.com", 8443, "https", "/api"},
		{"url prefix ipv6", "http://[::1]:8080/x", false, ScopeTypeURLPrefix, "::1", 8080, "http", "/x"},
		{"url prefix root", "http://example.com", false, ScopeTypeURLPrefix, "example.com", 0, "http", ""},
	}
	sm := NewScopeManager(nil)
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

func TestCheckScopeOpenMode(t *testing.T) {
	for _, entries := range [][]string{nil, {}, {""}, {"   "}} {
		sm := NewScopeManager(entries)
		for _, raw := range []string{
			"https://example.com/",
			"http://other.example/",
			"http://127.0.0.1:8080/",
			"https://evil.example/path",
		} {
			if err := sm.CheckScope(context.Background(), mustURL(t, raw)); err != nil {
				t.Fatalf("open mode entries=%v blocked %s: %v", entries, raw, err)
			}
		}
	}
}

func seededScope(entries []string, ips map[string][]net.IP) *ScopeManager {
	sm := NewScopeManager(entries)
	for host, values := range ips {
		sm.resolvedIPs[host] = values
	}
	return sm
}

func TestCheckScopeDomain(t *testing.T) {
	ip := []net.IP{net.ParseIP("93.184.216.34")}
	sm := seededScope([]string{"Example.COM"}, map[string][]net.IP{
		"example.com":          ip,
		"sub.example.com":      ip,
		"deep.sub.example.com": ip,
	})
	allowed := []string{
		"https://example.com/",
		"http://example.com/path",
		"https://sub.example.com/",
		"https://deep.sub.example.com/",
	}
	for _, raw := range allowed {
		if err := sm.CheckScope(context.Background(), mustURL(t, raw)); err != nil {
			t.Fatalf("domain scope rejected allowed %s: %v", raw, err)
		}
	}
	rejected := []string{
		"https://notexample.com/",
		"https://example.com.evil/",
		"https://evil-example.com/",
		"https://example.com@evil.com/",
	}
	for _, raw := range rejected {
		if err := sm.CheckScope(context.Background(), mustURL(t, raw)); err == nil {
			t.Fatalf("domain scope allowed %s", raw)
		}
	}
}

func TestCheckScopeDomainPort(t *testing.T) {
	sm := seededScope([]string{"127.0.0.1:8080"}, map[string][]net.IP{
		"127.0.0.1": {net.ParseIP("127.0.0.1")},
	})
	if err := sm.CheckScope(context.Background(), mustURL(t, "http://127.0.0.1:8080/")); err != nil {
		t.Fatalf("explicit domain port rejected: %v", err)
	}
	if err := sm.CheckScope(context.Background(), mustURL(t, "http://127.0.0.1:9090/")); err == nil {
		t.Fatal("wrong explicit port allowed")
	}
}

func TestCheckScopeURLPrefix(t *testing.T) {
	sm := NewScopeManager([]string{"https://example.com:8443/api"})
	allowed := []string{
		"https://example.com:8443/api",
		"https://example.com:8443/api/",
		"https://example.com:8443/api/v1",
	}
	for _, raw := range allowed {
		if err := sm.CheckScope(context.Background(), mustURL(t, raw)); err != nil {
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
		if err := sm.CheckScope(context.Background(), mustURL(t, raw)); err == nil {
			t.Fatalf("URL prefix allowed rejected %s", raw)
		}
	}
}

func TestCheckScopeURLPrefixWithoutPortAllowsAnyPort(t *testing.T) {
	sm := NewScopeManager([]string{"https://example.com/api"})
	for _, raw := range []string{
		"https://example.com:443/api",
		"https://example.com:8443/api",
	} {
		if err := sm.CheckScope(context.Background(), mustURL(t, raw)); err != nil {
			t.Fatalf("URL prefix without explicit port rejected %s: %v", raw, err)
		}
	}
}

func TestCheckScopeCIDR(t *testing.T) {
	sm := seededScope([]string{"127.0.0.0/8"}, map[string][]net.IP{
		"127.0.0.1": {net.ParseIP("127.0.0.1")},
		"10.1.2.3":  {net.ParseIP("10.1.2.3")},
	})
	if err := sm.CheckScope(context.Background(), mustURL(t, "http://127.0.0.1/")); err != nil {
		t.Fatalf("CIDR rejected in-range IP: %v", err)
	}
	if err := sm.CheckScope(context.Background(), mustURL(t, "http://10.1.2.3/")); err == nil {
		t.Fatal("CIDR allowed out-of-range IP")
	}
}

func TestScopeErrorHelpers(t *testing.T) {
	base := &ScopeError{Op: "scope-mismatch", URL: "https://evil/", Err: plugin.ErrScopeViolation}
	if !IsScopeError(base) {
		t.Fatal("direct ScopeError not recognized")
	}
	if !IsScopeError(fmt.Errorf("outer: %w", base)) {
		t.Fatal("wrapped ScopeError not recognized")
	}
	if IsScopeError(nil) || IsScopeError(errors.New("plain")) {
		t.Fatal("non-scope error recognized")
	}
	if got := base.Error(); got == "" || !strings.Contains(got, "scope-mismatch") ||
		!strings.Contains(got, "https://evil/") || !strings.Contains(got, plugin.ErrScopeViolation.Error()) {
		t.Fatalf("ScopeError text = %q", got)
	}
	if !errors.Is(base, plugin.ErrScopeViolation) {
		t.Fatal("ScopeError must unwrap to ErrScopeViolation")
	}
}

func TestValidateSizes(t *testing.T) {
	reqCases := []struct {
		name  string
		body  []byte
		limit int64
		ok    bool
	}{
		{"zero limit", []byte("abcdef"), 0, true},
		{"negative limit", []byte("abcdef"), -1, true},
		{"exact limit", []byte("abcdef"), 6, true},
		{"over limit", []byte("abcdef"), 5, false},
		{"empty over zero", nil, 1, true},
	}
	for _, tc := range reqCases {
		t.Run("request "+tc.name, func(t *testing.T) {
			err := ValidateRequestSize(tc.body, tc.limit)
			if tc.ok {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if !errors.Is(err, plugin.ErrBudgetExceeded) {
				t.Fatalf("err = %v, want ErrBudgetExceeded", err)
			}
		})
	}
	respCases := []struct {
		name   string
		length int64
		limit  int64
		ok     bool
	}{
		{"zero limit", 100, 0, true},
		{"negative limit", 100, -1, true},
		{"exact limit", 100, 100, true},
		{"over limit", 101, 100, false},
		{"negative length", -1, 100, true},
	}
	for _, tc := range respCases {
		t.Run("response "+tc.name, func(t *testing.T) {
			err := ValidateResponseSize(tc.length, tc.limit)
			if tc.ok {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if !errors.Is(err, plugin.ErrBudgetExceeded) {
				t.Fatalf("err = %v, want ErrBudgetExceeded", err)
			}
		})
	}
}

func TestScanBudgetLimits(t *testing.T) {
	u := mustURL(t, "https://Example.COM/a")
	if got := (&ScanBudget{}).Total(); got != 0 {
		t.Fatalf("zero-value total = %d", got)
	}
	sb := NewScanBudget(2, 0, 0)
	if err := sb.CheckAndIncrement(u); err != nil {
		t.Fatal(err)
	}
	if err := sb.CheckAndIncrement(u); err != nil {
		t.Fatal(err)
	}
	if err := sb.CheckAndIncrement(u); !errors.Is(err, plugin.ErrBudgetExceeded) {
		t.Fatalf("total budget err = %v", err)
	}
	if got := sb.Total(); got != 2 {
		t.Fatalf("Total = %d, want 2", got)
	}

	sb = NewScanBudget(0, 2, 0)
	for i := 0; i < 2; i++ {
		if err := sb.CheckAndIncrement(u); err != nil {
			t.Fatal(err)
		}
	}
	if err := sb.CheckAndIncrement(u); !errors.Is(err, plugin.ErrBudgetExceeded) {
		t.Fatalf("per-host err = %v", err)
	}
	if err := sb.CheckAndIncrement(mustURL(t, "https://other.example/a")); err != nil {
		t.Fatalf("other host should have its own budget: %v", err)
	}
}

func TestScanBudgetPerPath(t *testing.T) {
	sb := NewScanBudget(0, 0, 1)
	u := mustURL(t, "https://example.com/a")
	if err := sb.CheckAndIncrement(u); err != nil {
		t.Fatal(err)
	}
	if err := sb.CheckAndIncrement(u); !errors.Is(err, plugin.ErrBudgetExceeded) {
		t.Fatalf("per-path err = %v", err)
	}
	if err := sb.CheckAndIncrement(mustURL(t, "https://example.com/b")); err != nil {
		t.Fatalf("different path should have its own budget: %v", err)
	}
}

func TestScanBudgetRejectedRequestDoesNotConsume(t *testing.T) {
	sb := NewScanBudget(0, 2, 1)
	a := mustURL(t, "https://example.com/a")
	b := mustURL(t, "https://example.com/b")
	if err := sb.CheckAndIncrement(a); err != nil {
		t.Fatal(err)
	}
	if err := sb.CheckAndIncrement(a); !errors.Is(err, plugin.ErrBudgetExceeded) {
		t.Fatalf("second same-path request err = %v", err)
	}
	if err := sb.CheckAndIncrement(b); err != nil {
		t.Fatalf("rejected request consumed host budget: %v", err)
	}
	if got := sb.Total(); got != 2 {
		t.Fatalf("Total = %d, want 2", got)
	}
}

func TestScanBudgetNoLimits(t *testing.T) {
	sb := NewScanBudget(0, 0, 0)
	u := mustURL(t, "https://example.com/a")
	for i := 0; i < 5; i++ {
		if err := sb.CheckAndIncrement(u); err != nil {
			t.Fatal(err)
		}
	}
	if got := sb.Total(); got != 5 {
		t.Fatalf("Total = %d, want 5", got)
	}
}

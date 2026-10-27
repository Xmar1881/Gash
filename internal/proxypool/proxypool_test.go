// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Module: github.com/Xmar1881/Gash

package proxypool

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"
)

func mustURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := ParseURL(raw)
	if err != nil {
		t.Fatalf("ParseURL(%q): %v", raw, err)
	}
	return u
}

func TestParseURL(t *testing.T) {
	good := []string{
		"http://127.0.0.1:8080",
		"https://user:pass@proxy.example:8443",
		"socks5://127.0.0.1:1080",
		"127.0.0.1:8080",
		"user:pass@127.0.0.1:8080",
	}
	for _, raw := range good {
		if _, err := ParseURL(raw); err != nil {
			t.Errorf("ParseURL(%q) unexpected error: %v", raw, err)
		}
	}
	bad := []string{
		"",
		"not-a-url",
		"ftp://proxy.example:21",
		"http:///missing-host",
		"http://proxy.example:8080/path",
		"http://proxy.example:8080?x=1",
	}
	for _, raw := range bad {
		if _, err := ParseURL(raw); err == nil {
			t.Errorf("ParseURL(%q) expected error", raw)
		}
	}
}

func TestParseURLNormalizesProviderFormat(t *testing.T) {
	u, err := ParseURL("127.0.0.1:8080:alice:secret")
	if err != nil {
		t.Fatal(err)
	}
	if u.Scheme != "http" || u.Host != "127.0.0.1:8080" {
		t.Fatalf("unexpected normalized URL: %s", u)
	}
	if u.User == nil || u.User.Username() != "alice" {
		t.Fatalf("credentials were not preserved: %s", u)
	}
	if pass, _ := u.User.Password(); pass != "secret" {
		t.Fatalf("password was not preserved: %s", u)
	}
}

func TestParseStrategy(t *testing.T) {
	for raw, want := range map[string]Strategy{
		"":            PerHost,
		"per-host":    PerHost,
		"host":        PerHost,
		"per-request": PerRequest,
		"round-robin": PerRequest,
	} {
		got, err := ParseStrategy(raw)
		if err != nil {
			t.Fatalf("ParseStrategy(%q): %v", raw, err)
		}
		if got != want {
			t.Errorf("ParseStrategy(%q) = %q, want %q", raw, got, want)
		}
	}
	if _, err := ParseStrategy("random"); err == nil {
		t.Fatal("invalid strategy should fail")
	}
}

func TestPerHostStickyAndRotate(t *testing.T) {
	p := New([]*url.URL{
		mustURL(t, "http://p1.example:8080"),
		mustURL(t, "http://p2.example:8080"),
	}, Config{Strategy: PerHost, Cooldown: time.Minute})

	first := p.Next("a.example")
	again := p.Next("a.example")
	if first.String() != again.String() {
		t.Fatalf("per-host must stay sticky: %s vs %s", first, again)
	}

	other := p.Next("b.example")
	if other == nil {
		t.Fatal("Next returned nil")
	}

	p.Rotate("a.example")
	rotated := p.Next("a.example")
	if rotated.String() == first.String() {
		t.Fatalf("Rotate did not change host proxy: %s", rotated)
	}
}

func TestPerRequestRotates(t *testing.T) {
	p := New([]*url.URL{
		mustURL(t, "http://p1.example:8080"),
		mustURL(t, "http://p2.example:8080"),
	}, Config{Strategy: PerRequest, Cooldown: time.Minute})

	first := p.Next("a.example")
	second := p.Next("a.example")
	if first.String() == second.String() {
		t.Fatalf("per-request did not rotate: %s", first)
	}
}

func TestCooldownSkipsFailingProxy(t *testing.T) {
	p := New([]*url.URL{
		mustURL(t, "http://p1.example:8080"),
		mustURL(t, "http://p2.example:8080"),
	}, Config{Strategy: PerRequest, Cooldown: time.Minute, FailureThreshold: 1})

	first := p.Next("a.example")
	p.ReportError(first)

	st := p.Stats()
	if st.Size != 2 || st.Healthy != 1 || st.CoolingDown != 1 {
		t.Fatalf("unexpected stats after failure: %+v", st)
	}

	second := p.Next("a.example")
	if second.String() == first.String() {
		t.Fatalf("cooled proxy was selected again: %s", second)
	}

	// Every proxy cooling down must degrade to a fallback, not a nil result.
	p.ReportError(second)
	st = p.Stats()
	if st.Healthy != 0 || st.CoolingDown != 2 {
		t.Fatalf("unexpected stats: %+v", st)
	}
	if got := p.Next("a.example"); got == nil {
		t.Fatal("Next returned nil when all proxies were cooling down")
	}
}

func TestBlockStatusCoolsImmediately(t *testing.T) {
	p := New([]*url.URL{
		mustURL(t, "http://p1.example:8080"),
		mustURL(t, "http://p2.example:8080"),
	}, Config{Strategy: PerRequest, Cooldown: time.Minute})

	first := p.Next("a.example")
	p.ReportStatus(first, 403)
	if st := p.Stats(); st.CoolingDown != 1 {
		t.Fatalf("403 must cool the proxy immediately: %+v", st)
	}
	second := p.Next("a.example")
	if second.String() == first.String() {
		t.Fatalf("cooled proxy was selected again: %s", second)
	}
}

func TestRoundTripperDirectFallback(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()

	pool := New([]*url.URL{mustURL(t, "http://127.0.0.1:1")}, Config{})
	rt := NewRoundTripper(pool, nil)
	for i := 0; i < directFallbackThreshold; i++ {
		req, err := http.NewRequest(http.MethodGet, srv.URL, nil)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := rt.RoundTrip(req); err == nil {
			t.Fatalf("dead proxy attempt %d unexpectedly succeeded", i)
		}
	}
	req, err := http.NewRequest(http.MethodGet, srv.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := rt.RoundTrip(req)
	if err != nil {
		t.Fatalf("direct fallback failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("direct fallback status = %d", resp.StatusCode)
	}
	if got := pool.Stats().DirectFallbacks; got != 1 {
		t.Fatalf("direct fallbacks = %d, want 1", got)
	}
}

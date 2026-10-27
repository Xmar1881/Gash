// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Module: github.com/Xmar1881/Gash

package probe

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/Xmar1881/Gash/internal/plugin"
)

// wafTestServer bloklayan bir WAF öykünür: bypass başlığı YOKSA ve query
// değeri double-encode DEĞİLSE 403 + WAF işareti döner.
func wafTestServer(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Forwarded-For") == "127.0.0.1" {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("<html>hello bypassed</html>"))
			return
		}
		if strings.Contains(r.URL.RawQuery, "%25") {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("<html>hello encoded</html>"))
			return
		}
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte("<html>request blocked by waf</html>"))
	}))
}

func wafTestClient(bypass bool) (*Client, context.Context) {
	policy := plugin.NewPolicySession(plugin.DefaultPolicyConfig(), nil)
	c := NewClient(Options{Policy: policy, EnableWAFBypass: bypass})
	ctx := plugin.WithPlugin(context.Background(), "waf-test", true, nil)
	return c, ctx
}

func TestSendWAFBypassHeaderOnly(t *testing.T) {
	srv := wafTestServer(t)
	defer srv.Close()
	c, ctx := wafTestClient(true)
	resp, err := c.Send(ctx, http.MethodGet, srv.URL+"/s?q=1", nil, nil)
	if err != nil {
		t.Fatalf("send: %v", err)
	}
	if resp.Status != http.StatusOK {
		t.Fatalf("bypass 200 döndürmeli, got %d", resp.Status)
	}
	if !resp.WAFBypassed {
		t.Fatal("başarılı deneme WAFBypassed işaretlenmeli")
	}
	if !resp.WAFDetected {
		t.Fatal("orijinal engel WAFDetected taşınmalı")
	}
	if !strings.Contains(resp.ClassifyNote, "waf-bypass-verified:header-only") {
		t.Fatalf("teknik nota işlenmeli: %q", resp.ClassifyNote)
	}
	if det, byp := c.WAFStats(); det != 1 || byp != 1 {
		t.Fatalf("stats detected=1 bypassed=1 olmalı, got %d/%d", det, byp)
	}
}

func TestSendWAFDoesNotCountAuthSoft404OrDynamicResponses(t *testing.T) {
	cases := []struct {
		name   string
		body   func(int) string
		status int
	}{
		{name: "auth rejection", status: http.StatusOK, body: func(int) string { return "<html>Please log in to continue</html>" }},
		{name: "soft 404", status: http.StatusOK, body: func(int) string { return "<html><h1>Page not found</h1></html>" }},
		{name: "dynamic response", status: http.StatusOK, body: func(n int) string { return "<html>request id=" + string(rune('a'+n)) + "</html>" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			count := 0
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Header.Get("X-Forwarded-For") != "127.0.0.1" {
					w.WriteHeader(http.StatusForbidden)
					_, _ = w.Write([]byte("request blocked by waf"))
					return
				}
				body := tc.body(count)
				count++
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte(body))
			}))
			defer srv.Close()
			c, ctx := wafTestClient(true)
			resp, err := c.Send(ctx, http.MethodGet, srv.URL+"/s?q=1", nil, nil)
			if err != nil {
				t.Fatal(err)
			}
			if resp.WAFBypassed {
				t.Fatalf("%s bypass olarak sayilmamali: %+v", tc.name, resp)
			}
			if _, bypassed := c.WAFStats(); bypassed != 0 {
				t.Fatalf("%s bypass sayaci artmamali: %d", tc.name, bypassed)
			}
		})
	}
}

func TestSendDoesNotTreatGenericForbiddenAsWAF(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte("authorization required"))
	}))
	defer srv.Close()
	c, ctx := wafTestClient(true)
	resp, err := c.Send(ctx, http.MethodGet, srv.URL+"/private", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if resp.WAFBypassed {
		t.Fatal("generic authorization 403 must not be treated as a WAF bypass")
	}
	if detected, bypassed := c.WAFStats(); detected != 0 || bypassed != 0 {
		t.Fatalf("generic authorization 403 must not change WAF stats: %d/%d", detected, bypassed)
	}
}

func TestSendWAFBypassEncodedVariant(t *testing.T) {
	// Header-only varyantı engellenir, double-encode varyantı stabil 200
	// döndürür: sayaçlar 403→200 bypass'ı kanıtlar (§9 WAF satırı).
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.RawQuery, "%25") {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("<html>application page</html>"))
			return
		}
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte("<html>request blocked by waf</html>"))
	}))
	defer srv.Close()
	c, ctx := wafTestClient(true)
	resp, err := c.Send(ctx, http.MethodGet, srv.URL+"/s?q=hello%20world", nil, nil)
	if err != nil {
		t.Fatalf("send: %v", err)
	}
	if resp.Status != http.StatusOK || !resp.WAFBypassed {
		t.Fatalf("encode varyantı bypass sayılmalı, got %+v", resp)
	}
	if !strings.Contains(resp.ClassifyNote, "waf-bypass-verified:double-encode") {
		t.Fatalf("teknik nota işlenmeli: %q", resp.ClassifyNote)
	}
	if det, byp := c.WAFStats(); det != 1 || byp != 1 {
		t.Fatalf("stats detected=1 bypassed=1 olmalı, got %d/%d", det, byp)
	}
}

func TestSendWAFDisabledKeepsBlock(t *testing.T) {
	srv := wafTestServer(t)
	defer srv.Close()
	c, ctx := wafTestClient(false)
	resp, err := c.Send(ctx, http.MethodGet, srv.URL+"/s?q=1", nil, nil)
	if err != nil {
		t.Fatalf("send: %v", err)
	}
	if resp.Status != http.StatusForbidden {
		t.Fatalf("bypass kapalıyken 403 korunmalı, got %d", resp.Status)
	}
	if resp.WAFBypassed {
		t.Fatal("bypass kapalıyken WAFBypassed false olmalı")
	}
	if !resp.WAFDetected {
		t.Fatal("bypass kapalıyken de engel WAFDetected işaretlenmeli (sessiz düşürme yok)")
	}
	if det, byp := c.WAFStats(); det != 1 || byp != 0 {
		t.Fatalf("kapalı modda detected=1 bypassed=0 olmalı, got %d/%d", det, byp)
	}
}

// TestSendNoWAFBypassMarker: login akışı işareti WAF-bypass varyantlarını
// kapatır; kimlik taşıyan istek TEK sefer gönderilir (yeniden oynatma yok).
func TestSendNoWAFBypassMarker(t *testing.T) {
	var hits atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte("<html>request blocked by waf</html>"))
	}))
	defer srv.Close()
	c := NewClient(Options{Policy: plugin.NewPolicySession(plugin.DefaultPolicyConfig(), nil), EnableWAFBypass: true})
	ctx := plugin.WithPlugin(context.Background(), "login", false, nil)
	ctx = WithNoWAFBypass(ctx)
	resp, err := c.Send(ctx, http.MethodPost, srv.URL+"/login",
		map[string]string{"Content-Type": "application/x-www-form-urlencoded"},
		[]byte("username=u&password=p"))
	if err != nil {
		t.Fatalf("send: %v", err)
	}
	if resp.WAFBypassed {
		t.Fatal("marker varken bypass denemesi yapılmamalı")
	}
	if hits.Load() != 1 {
		t.Fatalf("tek istek beklenir (varyant/replay yok), got %d", hits.Load())
	}
	if !resp.WAFDetected {
		t.Fatal("engel yine de WAFDetected işaretlenmeli (sessiz düşürme yok)")
	}
}

func TestSendWAFUnbypassableStaysBlocked(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte("<html>request blocked by waf</html>"))
	}))
	defer srv.Close()
	c, ctx := wafTestClient(true)
	resp, err := c.Send(ctx, http.MethodGet, srv.URL+"/s?q=1", nil, nil)
	if err != nil {
		t.Fatalf("send: %v", err)
	}
	if resp.Status != http.StatusForbidden {
		t.Fatalf("aşılamayan engel 403 kalmalı, got %d", resp.Status)
	}
	if resp.WAFBypassed {
		t.Fatal("başarısız deneme bypassed işaretlenmemeli")
	}
	if !resp.WAFDetected {
		t.Fatal("WAF işareti taşınmalı")
	}
	// §9: sürekli-403 → detected sayacı artar, bypass sayacı artmaz.
	if det, byp := c.WAFStats(); det != 1 || byp != 0 {
		t.Fatalf("aşılamayan engelde detected=1 bypassed=0 olmalı, got %d/%d", det, byp)
	}
}

func TestWAFChallengeIsCountedNotBlocking(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte("<html>Just a moment...</html>"))
	}))
	defer srv.Close()
	c, ctx := wafTestClient(true)
	for i := 0; i < 3; i++ {
		if _, err := c.Send(ctx, http.MethodGet, srv.URL+"/s?q=1", nil, nil); err != nil {
			t.Fatalf("send %d: %v", i, err)
		}
	}
	if challenges := c.WAFChallengeStats(); challenges == 0 {
		t.Fatal("challenge responses must be counted")
	}
	resp, err := c.Send(ctx, http.MethodGet, srv.URL+"/s?q=2", nil, nil)
	if err != nil {
		t.Fatalf("challenge must not block later requests: %v", err)
	}
	if resp.Status != http.StatusForbidden {
		t.Fatalf("expected the challenge response, got %d", resp.Status)
	}
}

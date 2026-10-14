// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Module: github.com/Xmar1881/Gash

package probe

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
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
	if !strings.Contains(resp.ClassifyNote, "waf-bypass:header-only") {
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
}

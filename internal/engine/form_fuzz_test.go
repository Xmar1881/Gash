// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Module: github.com/Xmar1881/Gash

package engine

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/Xmar1881/Gash/internal/discovery"
	"github.com/Xmar1881/Gash/internal/plugin"
	"github.com/Xmar1881/Gash/internal/probe"
)

func formFuzzEngine(t *testing.T, active bool) (*Engine, *probe.Client) {
	t.Helper()
	policy := plugin.NewPolicySession(plugin.PolicyConfig{
		MaxRequestsPerTarget: 10000,
		MaxRequestsTotal:     10000,
		RatePerSecond:        0,
	}, nil)
	client := probe.NewClient(probe.Options{Policy: policy})
	cfg := DefaultConfig()
	cfg.Active = active
	return New(plugin.NewRegistry(), cfg), client
}

func formForTest(sourceURL, actionURL, method string, fields []discovery.FormField) []discovery.Form {
	return []discovery.Form{{
		SourceURL: sourceURL,
		ActionURL: actionURL,
		Method:    method,
		Enctype:   "application/x-www-form-urlencoded",
		Fields:    fields,
	}}
}

// TestRunActiveFormFuzzSQLiRefresh proves the stale CSRF snapshot is
// refreshed from the source page before replay and a quote probe confirms
// through the SQL error oracle.
func TestRunActiveFormFuzzSQLiRefresh(t *testing.T) {
	var mu sync.Mutex
	serverToken := "tok-2"
	tokenFuzzed := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		switch r.URL.Path {
		case "/page":
			mu.Lock()
			p := fmt.Sprintf(`<html><body><form action="/submit" method="POST">`+
				`<input type="hidden" name="csrf_token" value="%s">`+
				`<input type="text" name="q" value="hello"></form></body></html>`, serverToken)
			mu.Unlock()
			_, _ = w.Write([]byte(p))
		case "/submit":
			_ = r.ParseForm()
			got := r.PostFormValue("csrf_token")
			if strings.Contains(got, "'") || strings.Contains(got, "%27") {
				mu.Lock()
				tokenFuzzed = true
				mu.Unlock()
			}
			mu.Lock()
			valid := got == serverToken
			mu.Unlock()
			if !valid {
				w.WriteHeader(http.StatusForbidden)
				_, _ = w.Write([]byte("<html>your csrf token is invalid or expired</html>"))
				return
			}
			if q := r.PostFormValue("q"); strings.Contains(q, "'") {
				w.WriteHeader(http.StatusInternalServerError)
				_, _ = w.Write([]byte("<html>You have an error in your SQL syntax near '''</html>"))
				return
			}
			_, _ = w.Write([]byte("<html><body>normal product page stable</body></html>"))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	forms := discovery.ExtractForms(srv.URL+"/page", []byte(fmt.Sprintf(
		`<html><body><form action="/submit" method="POST">`+
			`<input type="hidden" name="csrf_token" value="%s">`+
			`<input type="text" name="q" value="hello"></form></body></html>`, serverToken)))
	if len(forms) != 1 {
		t.Fatalf("expected 1 form, got %d", len(forms))
	}
	// Crawl snapshot carries a stale token; the engine must refresh it.
	for i := range forms[0].Fields {
		if forms[0].Fields[i].IsToken {
			forms[0].Fields[i].Value = "tok-stale"
		}
	}

	e, client := formFuzzEngine(t, true)
	ctx := plugin.WithPlugin(context.Background(), "form-fuzz-test", true, nil)
	got, reqs := e.runActiveFormFuzz(ctx, srv.URL, client, forms)
	if reqs != 3 {
		t.Fatalf("expected refresh + control + 1 probe = 3 requests, got %d", reqs)
	}
	if len(got) != 1 {
		t.Fatalf("expected exactly 1 finding, got %d", len(got))
	}
	f := got[0]
	if f.PluginID != "form-fuzz-anomaly" || f.RuleID != "GASH-004" || f.Confidence != plugin.ConfidenceTentative {
		t.Fatalf("finding shape wrong: %+v", f)
	}
	mu.Lock()
	fuzzed := tokenFuzzed
	mu.Unlock()
	if fuzzed {
		t.Fatal("token fieldi fuzz payload'u taşımamalı (yalnızca tazelenir)")
	}
}

// TestRunActiveFormFuzzTokenRotationNoFalseFindings proves per-request token
// rotation never fabricates findings from rejection pages and respects the
// refresh cap.
func TestRunActiveFormFuzzTokenRotationNoFalseFindings(t *testing.T) {
	var mu sync.Mutex
	counter := 1
	tokenFuzzed := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		switch r.URL.Path {
		case "/page":
			mu.Lock()
			tok := fmt.Sprintf("t%d", counter)
			mu.Unlock()
			_, _ = w.Write([]byte(fmt.Sprintf(`<html><body><form action="/submit" method="POST">`+
				`<input type="hidden" name="csrf_token" value="%s">`+
				`<input type="text" name="q" value="hello"></form></body></html>`, tok)))
		case "/submit":
			_ = r.ParseForm()
			got := r.PostFormValue("csrf_token")
			if strings.Contains(got, "'") {
				mu.Lock()
				tokenFuzzed = true
				mu.Unlock()
			}
			mu.Lock()
			valid := got == fmt.Sprintf("t%d", counter)
			if valid {
				counter++ // her kabul edilen POST token'ı döndürür
			}
			mu.Unlock()
			if !valid {
				w.WriteHeader(http.StatusForbidden)
				_, _ = w.Write([]byte("<html>csrf token mismatch, request rejected</html>"))
				return
			}
			_, _ = w.Write([]byte("<html><body>stable content page</body></html>"))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	forms := formForTest(srv.URL+"/page", srv.URL+"/submit", http.MethodPost, []discovery.FormField{
		{Name: "csrf_token", Value: "t0-stale", InputType: "hidden", IsToken: true},
		{Name: "q", Value: "hello", InputType: "text"},
	})

	e, client := formFuzzEngine(t, true)
	ctx := context.Background()
	got, reqs := e.runActiveFormFuzz(ctx, srv.URL, client, forms)
	if len(got) != 0 {
		t.Fatalf("rotasyon reddi bulgu ÜRETMEMELİ, got %d: %+v", len(got), got)
	}
	if reqs > 20 {
		t.Fatalf("refresh üst sınırı aşılmalı: %d istek", reqs)
	}
	mu.Lock()
	fuzzed := tokenFuzzed
	mu.Unlock()
	if fuzzed {
		t.Fatal("token fieldi fuzz payload'u taşımamalı")
	}
}

// TestRunActiveFormFuzzBooleanDifferential proves the masked true/false pair
// fires when the differing response stays under the divergence threshold.
func TestRunActiveFormFuzzBooleanDifferential(t *testing.T) {
	var words []string
	for i := 1; i <= 40; i++ {
		words = append(words, fmt.Sprintf("w%d", i))
	}
	pageA := "<html><body> " + strings.Join(words, " ") + " </body></html>"
	pageB := "<html><body> " + strings.Join(words, " ") + " w41 </body></html>"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_ = r.ParseForm()
		if r.PostFormValue("q") == "' AND '1'='2" {
			_, _ = w.Write([]byte(pageB))
			return
		}
		_, _ = w.Write([]byte(pageA))
	}))
	defer srv.Close()

	forms := formForTest(srv.URL+"/page", srv.URL+"/submit", http.MethodPost, []discovery.FormField{
		{Name: "q", Value: "hello", InputType: "text"},
	})
	e, client := formFuzzEngine(t, true)
	ctx := context.Background()
	got, reqs := e.runActiveFormFuzz(ctx, srv.URL, client, forms)
	if reqs != 13 {
		t.Fatalf("expected control + 12 probes = 13 requests, got %d", reqs)
	}
	if len(got) != 1 {
		t.Fatalf("expected exactly 1 boolean finding, got %d: %+v", len(got), got)
	}
	if got[0].RuleID != "GASH-004" || got[0].Confidence != plugin.ConfidenceTentative {
		t.Fatalf("boolean bulgu şekli yanlış: %+v", got[0])
	}
}

// TestRunActiveFormFuzzFieldCap proves at most 10 fields are fuzzed with the
// 12-probe corpus each.
func TestRunActiveFormFuzzFieldCap(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte("<html><body>stable content page</body></html>"))
	}))
	defer srv.Close()

	fields := make([]discovery.FormField, 0, 15)
	for i := 0; i < 15; i++ {
		fields = append(fields, discovery.FormField{Name: fmt.Sprintf("f%d", i), Value: "v", InputType: "text"})
	}
	e, client := formFuzzEngine(t, true)
	ctx := context.Background()
	got, reqs := e.runActiveFormFuzz(ctx, srv.URL, client, formForTest(srv.URL+"/page", srv.URL+"/submit", http.MethodPost, fields))
	if len(got) != 0 {
		t.Fatalf("stabil hedefte bulgu olmamalı, got %d", len(got))
	}
	if reqs != 121 {
		t.Fatalf("alan üst sınırı 10 (10x12+1 kontrol): 121 istek beklenir, got %d", reqs)
	}
}

// TestRunActiveFormFuzzSafeAndCrossOriginGates proves the --active gate and
// the same-origin action gate both stop all traffic.
func TestRunActiveFormFuzzGates(t *testing.T) {
	forms := formForTest("http://example.com/page", "http://other.example/submit", http.MethodPost, []discovery.FormField{
		{Name: "q", Value: "v", InputType: "text"},
	})
	e, client := formFuzzEngine(t, true)
	got, reqs := e.runActiveFormFuzz(context.Background(), "http://example.com/", client, forms)
	if len(got) != 0 || reqs != 0 {
		t.Fatalf("çapraz-origin action trafik ÜRETMEMELİ: %d/%d", len(got), reqs)
	}

	e2, client2 := formFuzzEngine(t, false)
	forms2 := formForTest("http://example.com/page", "http://example.com/submit", http.MethodPost, []discovery.FormField{
		{Name: "q", Value: "v", InputType: "text"},
	})
	got2, reqs2 := e2.runActiveFormFuzz(context.Background(), "http://example.com/", client2, forms2)
	if len(got2) != 0 || reqs2 != 0 {
		t.Fatalf("safe modda form fuzz trafiği YOK: %d/%d", len(got2), reqs2)
	}

	// GET formlar replay edilmez (yalnızca POST/PUT/PATCH).
	forms3 := formForTest("http://example.com/page", "http://example.com/search", http.MethodGet, []discovery.FormField{
		{Name: "q", Value: "v", InputType: "text"},
	})
	got3, reqs3 := e.runActiveFormFuzz(context.Background(), "http://example.com/", client, forms3)
	if len(got3) != 0 || reqs3 != 0 {
		t.Fatalf("GET form trafik ÜRETMEMELİ: %d/%d", len(got3), reqs3)
	}
}

func TestFormHasTextInput(t *testing.T) {
	toggle := []discovery.FormField{
		{Name: "security", InputType: "select"},
		{Name: "php_ids", InputType: "select"},
		{Name: "seclev_submit", InputType: "submit"},
	}
	if formHasTextInput(toggle) {
		t.Fatal("select-only settings form must not be fuzzed")
	}
	text := []discovery.FormField{
		{Name: "id", InputType: "text"},
		{Name: "Submit", InputType: "submit"},
	}
	if !formHasTextInput(text) {
		t.Fatal("text form must be fuzzable")
	}
}

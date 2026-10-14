// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Module: github.com/Xmar1881/Gash

package engine

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Xmar1881/Gash/internal/plugin"
	"github.com/Xmar1881/Gash/internal/plugin/loader"
	"github.com/Xmar1881/Gash/internal/probe"
)

func fuzzPointFor(url string) []loader.JSPoint {
	return []loader.JSPoint{{
		URL: url, Method: http.MethodGet, ParamName: "id", ParamLocation: "query",
	}}
}

// TestRunActiveFuzzFindsSQL500 proves a quote-triggered SQL 500 becomes a
// tentative finding with control comparison.
func TestRunActiveFuzzFindsSQL500(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		if strings.Contains(r.URL.Query().Get("id"), "'") {
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte("<html>You have an error in your SQL syntax near '''</html>"))
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("<html><body>normal product page, stable content here</body></html>"))
	}))
	defer srv.Close()

	policy := plugin.NewPolicySession(plugin.DefaultPolicyConfig(), nil)
	client := probe.NewClient(probe.Options{Policy: policy})
	cfg := DefaultConfig()
	cfg.Active = true
	e := New(plugin.NewRegistry(), cfg)
	ctx := plugin.WithPlugin(context.Background(), "fuzz-active-test", true, nil)

	got, reqs := e.runActiveFuzz(ctx, srv.URL, client, fuzzPointFor(srv.URL))
	if reqs < 1 {
		t.Fatal("fuzz en az kontrol isteği atmalı")
	}
	if len(got) == 0 {
		t.Fatal("SQL 500 anomalisi bulgu üretmeli")
	}
	for _, f := range got {
		if f.Confidence != plugin.ConfidenceTentative {
			t.Fatalf("fuzz bulgusu tentative olmalı, got %s", f.Confidence)
		}
		if f.RuleID == "" || f.PluginID != "fuzz-anomaly" {
			t.Fatalf("bulgu kimliği bozuk: %+v", f)
		}
	}
}

// TestRunActiveFuzzStableEmpty proves a stable backend yields no findings.
func TestRunActiveFuzzStableEmpty(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("<html><body>stable content</body></html>"))
	}))
	defer srv.Close()

	policy := plugin.NewPolicySession(plugin.DefaultPolicyConfig(), nil)
	client := probe.NewClient(probe.Options{Policy: policy})
	cfg := DefaultConfig()
	cfg.Active = true
	e := New(plugin.NewRegistry(), cfg)
	ctx := plugin.WithPlugin(context.Background(), "fuzz-active-test", true, nil)

	got, _ := e.runActiveFuzz(ctx, srv.URL, client, fuzzPointFor(srv.URL))
	if len(got) != 0 {
		t.Fatalf("stabil hedefte bulgu olmamalı, got %d", len(got))
	}
}

// TestRunActiveFuzzSafeGate proves the safe default sends zero fuzz traffic.
func TestRunActiveFuzzSafeGate(t *testing.T) {
	policy := plugin.NewPolicySession(plugin.DefaultPolicyConfig(), nil)
	client := probe.NewClient(probe.Options{Policy: policy})
	cfg := DefaultConfig()
	cfg.Active = false
	e := New(plugin.NewRegistry(), cfg)
	ctx := plugin.WithPlugin(context.Background(), "fuzz-active-test", true, nil)

	got, reqs := e.runActiveFuzz(ctx, "http://example.com/", client, fuzzPointFor("http://example.com/"))
	if len(got) != 0 || reqs != 0 {
		t.Fatalf("safe modda fuzz trafiği YOK: got %d/%d", len(got), reqs)
	}
}

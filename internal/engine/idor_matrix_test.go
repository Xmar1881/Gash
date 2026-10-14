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

	"github.com/Xmar1881/Gash/internal/auth"
	"github.com/Xmar1881/Gash/internal/plugin"
	"github.com/Xmar1881/Gash/internal/plugin/loader"
	"github.com/Xmar1881/Gash/internal/probe"
)

// matrixHarness çift kimlikli motor + istemci kurar.
func matrixHarness(t *testing.T, srv *httptest.Server) (*Engine, *probe.Client, context.Context) {
	t.Helper()
	policy := plugin.NewPolicySession(plugin.DefaultPolicyConfig(), nil)
	client := probe.NewClient(probe.Options{Policy: policy})
	cfg := DefaultConfig()
	cfg.Active = true
	authA, authB := auth.New(), auth.New()
	if err := authA.ParseAuthHeader("Authorization: Bearer AAAA"); err != nil {
		t.Fatal(err)
	}
	if err := authB.ParseAuthHeader("Authorization: Bearer BBBB"); err != nil {
		t.Fatal(err)
	}
	cfg.AuthA, cfg.AuthB = authA, authB
	e := New(plugin.NewRegistry(), cfg)
	ctx := plugin.WithPlugin(context.Background(), "matrix-test", true, nil)
	_ = srv
	return e, client, ctx
}

func matrixPoint(srvURL string) []loader.JSPoint {
	return []loader.JSPoint{{
		URL: srvURL + "/obj?id=1", Method: http.MethodGet,
		ParamName: "id", ParamLocation: "query", Value: "1",
	}}
}

// TestCrossUserMatrixFindsDivergence proves stably different per-user content
// becomes one tentative GASH-005 finding.
func TestCrossUserMatrixFindsDivergence(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.Header.Get("Authorization") {
		case "Bearer AAAA":
			_, _ = w.Write([]byte(`{"id":1,"owner":"alice","email":"alice@example.com"}`))
		case "Bearer BBBB":
			_, _ = w.Write([]byte(`{"id":1,"owner":"bob","email":"bob@example.com"}`))
		default:
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"error":"unauthorized"}`))
		}
	}))
	defer srv.Close()

	e, client, ctx := matrixHarness(t, srv)
	got, reqs := e.runCrossUserMatrix(ctx, client, matrixPoint(srv.URL))
	if reqs != 6 {
		t.Fatalf("nokta başına 6 istek beklenir, got %d", reqs)
	}
	if len(got) != 1 {
		t.Fatalf("1 matris bulgusu beklenir, got %d", len(got))
	}
	f := got[0]
	if f.Confidence != plugin.ConfidenceTentative {
		t.Fatalf("matris bulgusu tentative olmalı, got %s", f.Confidence)
	}
	if f.RuleID != "GASH-005" || f.CWE != "CWE-639" {
		t.Fatalf("BOLA etiketi GASH-005/CWE-639 olmalı, got %s/%s", f.RuleID, f.CWE)
	}
	if f.PluginID != "idor-bola-matrix" {
		t.Fatalf("plugin kimliği idor-bola-matrix olmalı, got %s", f.PluginID)
	}
}

// TestCrossUserMatrixSameBodyEmpty proves identical content stays silent.
func TestCrossUserMatrixSameBodyEmpty(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":1,"title":"public item","price":42}`))
	}))
	defer srv.Close()

	e, client, ctx := matrixHarness(t, srv)
	got, _ := e.runCrossUserMatrix(ctx, client, matrixPoint(srv.URL))
	if len(got) != 0 {
		t.Fatalf("aynı içerikte bulgu olmamalı, got %d", len(got))
	}
}

// TestCrossUserMatrixGates proves single-auth and safe defaults send nothing.
func TestCrossUserMatrixGates(t *testing.T) {
	policy := plugin.NewPolicySession(plugin.DefaultPolicyConfig(), nil)
	client := probe.NewClient(probe.Options{Policy: policy})
	ctx := plugin.WithPlugin(context.Background(), "matrix-test", true, nil)
	pts := matrixPoint("http://example.com")

	// Tek kimlik: matris koşmaz.
	cfg := DefaultConfig()
	cfg.Active = true
	onlyA := auth.New()
	if err := onlyA.ParseAuthHeader("Authorization: Bearer AAAA"); err != nil {
		t.Fatal(err)
	}
	cfg.AuthA = onlyA
	e1 := New(plugin.NewRegistry(), cfg)
	if got, reqs := e1.runCrossUserMatrix(ctx, client, pts); len(got) != 0 || reqs != 0 {
		t.Fatalf("tek kimlikte trafik YOK: got %d/%d", len(got), reqs)
	}
	if e1.HasDualAuth() {
		t.Fatal("tek kimlik dual sayılmamalı")
	}

	// Çift kimlik ama safe: matris koşmaz.
	cfg2 := DefaultConfig()
	cfg2.Active = false
	authB := auth.New()
	if err := authB.ParseAuthHeader("Authorization: Bearer BBBB"); err != nil {
		t.Fatal(err)
	}
	cfg2.AuthA, cfg2.AuthB = onlyA, authB
	e2 := New(plugin.NewRegistry(), cfg2)
	if !e2.HasDualAuth() {
		t.Fatal("çift kimlik dual sayılmalı")
	}
	if got, reqs := e2.runCrossUserMatrix(ctx, client, pts); len(got) != 0 || reqs != 0 {
		t.Fatalf("safe modda trafik YOK: got %d/%d", len(got), reqs)
	}
}

// TestIDORLikeParamFilter ensures non-object params are never matrixed.
func TestIDORLikeParamFilter(t *testing.T) {
	if idorLikeParam["q"] || idorLikeParam["search"] {
		t.Fatal("arama parametreleri matrise girmemeli")
	}
	for _, p := range []string{"id", "user_id", "order_id", "uuid"} {
		if !idorLikeParam[strings.ToLower(p)] {
			t.Fatalf("%s matrise girmeli", p)
		}
	}
}

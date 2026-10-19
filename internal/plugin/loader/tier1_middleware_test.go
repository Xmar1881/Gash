// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Module: github.com/Xmar1881/Gash

package loader

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/Xmar1881/Gash/internal/plugin"
)

func TestTier1MiddlewareBypassControlAndVariant(t *testing.T) {
	var calls []string
	send := func(ctx context.Context, method, rawURL string, h map[string]string, body []byte) (int, http.Header, string, error) {
		calls = append(calls, rawURL)
		if v := h["x-middleware-subrequest"]; v != "" {
			if v != "middleware" {
				t.Fatalf("expected first configured header value, got %q", v)
			}
			return 200, http.Header{}, "<html><body>Admin dashboard with user management and settings.</body></html>", nil
		}
		return 401, http.Header{}, "Unauthorized", nil
	}
	spec := &plugin.PluginSpec{ID: "nextjs-middleware-bypass"}
	file := &Tier1File{
		Request: Tier1Request{Method: http.MethodGet, Paths: []string{"/admin"}},
		Oracle:  Tier1Oracle{Name: "middleware-bypass"},
	}
	results, err := ExecuteTier1(context.Background(), spec, file, "http://target.test", send)
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 1 {
		t.Fatalf("want 1 accepted bypass, got %d", len(results))
	}
	if results[0].Candidate.OracleName != "middleware-bypass" {
		t.Fatalf("oracle %q", results[0].Candidate.OracleName)
	}
	if results[0].Candidate.InjectionPoint.ParamLocation != "header" {
		t.Fatalf("injection point %#v", results[0].Candidate.InjectionPoint)
	}
	if len(calls) != 2 {
		t.Fatalf("want control + one accepting variant, got %d calls", len(calls))
	}
	if _, ok := results[0].Evidence.Artifacts["control_status"]; !ok {
		t.Fatalf("missing control evidence: %#v", results[0].Evidence.Artifacts)
	}
}

func TestTier1MiddlewareBypassSkipsPublicRoute(t *testing.T) {
	calls := 0
	send := func(ctx context.Context, method, rawURL string, h map[string]string, body []byte) (int, http.Header, string, error) {
		calls++
		return 200, http.Header{}, "<html><body>Public page with the same content.</body></html>", nil
	}
	spec := &plugin.PluginSpec{ID: "nextjs-middleware-bypass"}
	file := &Tier1File{
		Request: Tier1Request{Method: http.MethodGet},
		Oracle:  Tier1Oracle{Name: "middleware-bypass"},
	}
	results, err := ExecuteTier1(context.Background(), spec, file, "http://target.test", send)
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 0 || calls != 1 {
		t.Fatalf("public route must only send the control request: findings=%d calls=%d", len(results), calls)
	}
}

func TestWithStaticQuery(t *testing.T) {
	got, err := withStaticQuery("http://target.test/_next/image?url=a", map[string]string{"w": "640", "q": "75"}, "", "", "")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(got, "w=640") || !strings.Contains(got, "q=75") || !strings.Contains(got, "url=a") {
		t.Fatalf("unexpected query: %s", got)
	}
}

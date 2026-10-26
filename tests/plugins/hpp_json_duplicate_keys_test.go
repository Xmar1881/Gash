// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Module: github.com/Xmar1881/Gash

package plugins

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Xmar1881/Gash/internal/oracle"
	"github.com/Xmar1881/Gash/internal/plugin"
	"github.com/Xmar1881/Gash/internal/plugin/loader"
)

// jsHeaderValue resolves a script-supplied header without the engine helper.
// What: Case-insensitive lookup over a point's header map.
// Why: The test asserts what the engine will actually send on the wire.
func jsHeaderValue(headers map[string]string, name string) string {
	for k, v := range headers {
		if strings.EqualFold(k, name) {
			return v
		}
	}
	return ""
}

// TestHPPJSONDuplicateKeysE2E proves duplicated JSON key emission end to end.
// What: Executes hpp-json-duplicate-keys.js against a mocked transport that
// inspects the raw body plus content type and distinguishes the duplicate key.
// Why: A duplicated JSON key needs a raw body with an explicit JSON content
// type; Tier 1 cannot express either. The proof must stay inside the existing
// probe.send plus host.oracles bindings.
func TestHPPJSONDuplicateKeysE2E(t *testing.T) {
	root := repoRoot(t)
	path := filepath.Join(root, "plugins", "hpp", "hpp-json-duplicate-keys.js")
	src, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	spec, err := loader.LoadTier2Frontmatter(path)
	if err != nil {
		t.Fatalf("frontmatter %s: %v", path, err)
	}
	if spec.ID != "hpp-json-duplicate-keys" {
		t.Fatalf("unexpected id %q", spec.ID)
	}

	bodyPoint := loader.JSPoint{URL: "http://example.com/api/user", Method: "POST", ParamName: "role", ParamLocation: "body"}
	const duplicateBody = `{"role":1,"role":2}`

	t.Run("duplicate json key diverges", func(t *testing.T) {
		var rawBody, jsonContentType atomic.Bool
		env := &loader.JSEnv{
			Points: []loader.JSPoint{bodyPoint},
			Send: func(p loader.JSPoint) (loader.JSResponse, error) {
				if p.ParamName == "" {
					rawBody.Store(true)
				}
				if strings.Contains(strings.ToLower(jsHeaderValue(p.Headers, "Content-Type")), "json") {
					jsonContentType.Store(true)
				}
				h := map[string]string{"Content-Type": "application/json"}
				if strings.Contains(p.Value, duplicateBody) {
					return loader.JSResponse{Status: 200, Headers: h, Body: `{"role":"admin"}`, URL: p.URL}, nil
				}
				return loader.JSResponse{Status: 200, Headers: h, Body: `{"role":"guest"}`, URL: p.URL}, nil
			},
		}
		cands, err := loader.ExecuteJS(context.Background(), spec, string(src), env, 10*time.Second)
		if err != nil {
			t.Fatalf("execute: %v", err)
		}
		if len(cands) != 1 {
			t.Fatalf("one HPP JSON candidate expected, got %d", len(cands))
		}
		ev := cands[0].Evidence
		if ev == nil || ev.Verdict != oracle.VerdictAccept {
			t.Fatalf("accepted evidence required: %+v", cands[0])
		}
		if ev.ConfidenceContribution != plugin.ConfidenceConfirmed {
			t.Fatalf("confirmed required, got %s", ev.ConfidenceContribution)
		}
		if cands[0].Candidate.OracleName != "differential" {
			t.Fatalf("oracle must stay differential, got %q", cands[0].Candidate.OracleName)
		}
		if !rawBody.Load() {
			t.Fatal("duplicate JSON must be sent as a raw body (empty paramName)")
		}
		if !jsonContentType.Load() {
			t.Fatal("point headers must carry Content-Type: application/json")
		}
	})

	t.Run("strict parser rejection is not pollution", func(t *testing.T) {
		env := &loader.JSEnv{
			Points: []loader.JSPoint{bodyPoint},
			Send: func(p loader.JSPoint) (loader.JSResponse, error) {
				h := map[string]string{"Content-Type": "application/json"}
				if strings.Contains(p.Value, duplicateBody) {
					return loader.JSResponse{Status: 400, Headers: h, Body: `{"error":"duplicate key"}`, URL: p.URL}, nil
				}
				return loader.JSResponse{Status: 200, Headers: h, Body: `{"role":"guest"}`, URL: p.URL}, nil
			},
		}
		cands, err := loader.ExecuteJS(context.Background(), spec, string(src), env, 10*time.Second)
		if err != nil {
			t.Fatalf("execute: %v", err)
		}
		if len(cands) != 0 {
			t.Fatalf("a parser rejection must not confirm, got %d", len(cands))
		}
	})

	t.Run("query points are skipped", func(t *testing.T) {
		env := &loader.JSEnv{
			Points: []loader.JSPoint{{URL: "http://example.com/search", Method: "GET", ParamName: "q", ParamLocation: "query"}},
			Send: func(p loader.JSPoint) (loader.JSResponse, error) {
				return loader.JSResponse{Status: 200, Body: "neutral", URL: p.URL}, nil
			},
		}
		cands, err := loader.ExecuteJS(context.Background(), spec, string(src), env, 10*time.Second)
		if err != nil {
			t.Fatalf("execute: %v", err)
		}
		if len(cands) != 0 {
			t.Fatalf("query points must not be probed, got %d", len(cands))
		}
	})

	t.Run("large surfaces stay within send budget", func(t *testing.T) {
		points := make([]loader.JSPoint, 20)
		for i := range points {
			points[i] = loader.JSPoint{
				URL:           "http://example.com/api/" + itoaTest(i),
				Method:        "POST",
				ParamName:     "id",
				ParamLocation: "body",
			}
		}
		var sends atomic.Int64
		env := &loader.JSEnv{
			Points: points,
			Send: func(p loader.JSPoint) (loader.JSResponse, error) {
				sends.Add(1)
				return loader.JSResponse{Status: 200, URL: p.URL, Body: "neutral"}, nil
			},
		}
		if _, err := loader.ExecuteJS(context.Background(), spec, string(src), env, 2*time.Second); err != nil {
			t.Fatalf("execute: %v", err)
		}
		if got := sends.Load(); got > 60 {
			t.Fatalf("HPP JSON send budget exceeded: got %d, want <= 60", got)
		}
	})

	t.Run("no new sandbox surface", func(t *testing.T) {
		lower := strings.ToLower(string(src))
		if !strings.Contains(lower, "host.oracles.differential") {
			t.Fatal("must use host.oracles.differential")
		}
		for _, forbidden := range []string{"host.oracles.error", "host.oracles.timing", "host.oracles.oob", "require(", "fetch("} {
			if strings.Contains(lower, forbidden) {
				t.Fatalf("forbidden sandbox surface in source: %s", forbidden)
			}
		}
	})
}

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

// loadTier2 loads a reference Tier 2 plugin and asserts its id.
// What: Shared loader for the JSON/multipart Tier 2 suites.
// Why: One helper keeps the per-plugin tests free of path/auth boilerplate.
func loadTier2(t *testing.T, relPath, wantID string) (*plugin.PluginSpec, string) {
	t.Helper()
	path := filepath.Join(repoRoot(t), filepath.FromSlash(relPath))
	src, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	spec, err := loader.LoadTier2Frontmatter(path)
	if err != nil {
		t.Fatalf("frontmatter %s: %v", path, err)
	}
	if spec.ID != wantID {
		t.Fatalf("unexpected id %q, want %q", spec.ID, wantID)
	}
	return spec, string(src)
}

// jsonBodyPoint is the discovered body point every JSON test drives.
// What: A POST body field named id.
// Why: Mirrors the shape the engine hands to a Tier 2 plugin.
func jsonBodyPoint() loader.JSPoint {
	return loader.JSPoint{URL: "http://example.com/api/items", Method: "POST", ParamName: "id", ParamLocation: "body"}
}

// TestSQLiJSONBodyErrorE2E proves per-field JSON injection with a control.
// What: Executes sqli-json-body-error.js against a mocked JSON backend.
// Why: Tier 1 can only send one static body; discovering a field and rebuilding
// the JSON object with an explicit content type is what Tier 2 adds.
func TestSQLiJSONBodyErrorE2E(t *testing.T) {
	spec, src := loadTier2(t, "plugins/sqli/sqli-json-body-error.js", "sqli-json-body-error")
	point := jsonBodyPoint()

	t.Run("closure payload raises a signature", func(t *testing.T) {
		var rawBody, jsonContentType atomic.Bool
		env := &loader.JSEnv{
			Points: []loader.JSPoint{point},
			Send: func(p loader.JSPoint) (loader.JSResponse, error) {
				if p.ParamName == "" && strings.HasPrefix(strings.TrimSpace(p.Value), "{") {
					rawBody.Store(true)
				}
				if strings.Contains(strings.ToLower(jsHeaderValue(p.Headers, "Content-Type")), "json") {
					jsonContentType.Store(true)
				}
				h := map[string]string{"Content-Type": "application/json"}
				if strings.Contains(p.Value, "'") {
					return loader.JSResponse{Status: 500, Headers: h, Body: "<html><body>ERROR: You have an error in your SQL syntax</body></html>", URL: p.URL}, nil
				}
				return loader.JSResponse{Status: 200, Headers: h, Body: `{"id":1}`, URL: p.URL}, nil
			},
		}
		cands, err := loader.ExecuteJS(context.Background(), spec, src, env, 10*time.Second)
		if err != nil {
			t.Fatalf("execute: %v", err)
		}
		if len(cands) != 1 {
			t.Fatalf("one JSON SQLi candidate expected, got %d", len(cands))
		}
		ev := cands[0].Evidence
		if ev == nil || ev.Verdict != oracle.VerdictAccept || ev.ConfidenceContribution != plugin.ConfidenceConfirmed {
			t.Fatalf("confirmed evidence required: %+v", cands[0])
		}
		if cands[0].Candidate.OracleName != "error" {
			t.Fatalf("oracle must stay error, got %q", cands[0].Candidate.OracleName)
		}
		if !rawBody.Load() {
			t.Fatal("JSON field must be sent as a raw body (empty paramName)")
		}
		if !jsonContentType.Load() {
			t.Fatal("point headers must carry Content-Type: application/json")
		}
	})

	t.Run("signature in the control rejects", func(t *testing.T) {
		env := &loader.JSEnv{
			Points: []loader.JSPoint{point},
			Send: func(p loader.JSPoint) (loader.JSResponse, error) {
				h := map[string]string{"Content-Type": "application/json"}
				return loader.JSResponse{Status: 500, Headers: h, Body: "<html><body>ERROR: You have an error in your SQL syntax</body></html>", URL: p.URL}, nil
			},
		}
		cands, err := loader.ExecuteJS(context.Background(), spec, src, env, 10*time.Second)
		if err != nil {
			t.Fatalf("execute: %v", err)
		}
		if len(cands) != 0 {
			t.Fatalf("a non-distinguishing signature must not confirm, got %d", len(cands))
		}
	})

	t.Run("query points are skipped", func(t *testing.T) {
		env := &loader.JSEnv{
			Points: []loader.JSPoint{{URL: "http://example.com/search", Method: "GET", ParamName: "q", ParamLocation: "query"}},
			Send: func(p loader.JSPoint) (loader.JSResponse, error) {
				return loader.JSResponse{Status: 200, Body: "neutral", URL: p.URL}, nil
			},
		}
		cands, err := loader.ExecuteJS(context.Background(), spec, src, env, 10*time.Second)
		if err != nil {
			t.Fatalf("execute: %v", err)
		}
		if len(cands) != 0 {
			t.Fatalf("query points must not be probed, got %d", len(cands))
		}
	})

	t.Run("send budget holds", func(t *testing.T) {
		assertSendBudget(t, spec, src, 60, "POST", "body")
	})

	t.Run("no new sandbox surface", func(t *testing.T) {
		assertOracleSurface(t, src, []string{"host.oracles.error"}, []string{"host.oracles.differential", "host.oracles.timing", "host.oracles.reflection"})
	})
}

// TestSQLiJSONBodyDifferentialE2E proves the JSON boolean differential path.
// What: Executes sqli-json-body-differential.js against a mocked JSON backend.
// Why: The query-point plugin replays body points as urlencoded forms, which a
// JSON API never parses; the true/false closures only reach the sink when the
// body is rebuilt as JSON.
func TestSQLiJSONBodyDifferentialE2E(t *testing.T) {
	spec, src := loadTier2(t, "plugins/sqli/sqli-json-body-differential.js", "sqli-json-body-differential")
	point := jsonBodyPoint()
	const truePay = "1' AND '1'='1"
	const falsePay = "1' AND '1'='2"

	t.Run("true and false closures diverge", func(t *testing.T) {
		env := &loader.JSEnv{
			Points: []loader.JSPoint{point},
			Send: func(p loader.JSPoint) (loader.JSResponse, error) {
				h := map[string]string{"Content-Type": "application/json"}
				if strings.Contains(p.Value, truePay) {
					return loader.JSResponse{Status: 200, Headers: h, Body: `{"items":[1,2,3]}`, URL: p.URL}, nil
				}
				if strings.Contains(p.Value, falsePay) {
					return loader.JSResponse{Status: 200, Headers: h, Body: `{"items":[]}`, URL: p.URL}, nil
				}
				return loader.JSResponse{Status: 200, Headers: h, Body: "neutral page", URL: p.URL}, nil
			},
		}
		cands, err := loader.ExecuteJS(context.Background(), spec, src, env, 10*time.Second)
		if err != nil {
			t.Fatalf("execute: %v", err)
		}
		if len(cands) != 1 {
			t.Fatalf("one JSON differential candidate expected, got %d", len(cands))
		}
		ev := cands[0].Evidence
		if ev == nil || ev.Verdict != oracle.VerdictAccept || ev.ConfidenceContribution != plugin.ConfidenceConfirmed {
			t.Fatalf("confirmed evidence required: %+v", cands[0])
		}
		if cands[0].Candidate.OracleName != "differential" {
			t.Fatalf("oracle must stay differential, got %q", cands[0].Candidate.OracleName)
		}
	})

	t.Run("payload echo is not proof", func(t *testing.T) {
		env := &loader.JSEnv{
			Points: []loader.JSPoint{point},
			Send: func(p loader.JSPoint) (loader.JSResponse, error) {
				h := map[string]string{"Content-Type": "application/json"}
				if strings.Contains(p.Value, truePay) {
					return loader.JSResponse{Status: 200, Headers: h, Body: `{"echo":"` + truePay + `"}`, URL: p.URL}, nil
				}
				if strings.Contains(p.Value, falsePay) {
					return loader.JSResponse{Status: 200, Headers: h, Body: `{"echo":"` + falsePay + `"}`, URL: p.URL}, nil
				}
				return loader.JSResponse{Status: 200, Headers: h, Body: "neutral page", URL: p.URL}, nil
			},
		}
		cands, err := loader.ExecuteJS(context.Background(), spec, src, env, 10*time.Second)
		if err != nil {
			t.Fatalf("execute: %v", err)
		}
		if len(cands) != 0 {
			t.Fatalf("reflected payloads must not confirm, got %d", len(cands))
		}
	})

	t.Run("send budget holds", func(t *testing.T) {
		assertSendBudget(t, spec, src, 60, "POST", "body")
	})

	t.Run("no new sandbox surface", func(t *testing.T) {
		assertOracleSurface(t, src, []string{"host.oracles.differential"}, []string{"host.oracles.error", "host.oracles.timing", "host.oracles.reflection"})
	})
}

// TestHPPMultipartDuplicateKeysE2E proves duplicated multipart field emission.
// What: Executes hpp-multipart-duplicate-keys.js against a transport that
// distinguishes a body carrying the same field name twice.
// Why: The engine form builder writes one part per field name, so the body,
// the boundary and the content type must come from the script.
func TestHPPMultipartDuplicateKeysE2E(t *testing.T) {
	spec, src := loadTier2(t, "plugins/hpp/hpp-multipart-duplicate-keys.js", "hpp-multipart-duplicate-keys")
	point := jsonBodyPoint()

	t.Run("duplicated multipart field diverges", func(t *testing.T) {
		var multipartCT, duplicated atomic.Bool
		env := &loader.JSEnv{
			Points: []loader.JSPoint{point},
			Send: func(p loader.JSPoint) (loader.JSResponse, error) {
				ct := strings.ToLower(jsHeaderValue(p.Headers, "Content-Type"))
				if strings.Contains(ct, "multipart/form-data") && strings.Contains(ct, "boundary=") {
					multipartCT.Store(true)
				}
				if strings.Count(p.Value, `name="id"`) >= 2 {
					duplicated.Store(true)
					return loader.JSResponse{Status: 200, Headers: map[string]string{"Content-Type": "text/html"}, Body: "<ul><li>polluted-admin</li></ul>", URL: p.URL}, nil
				}
				return loader.JSResponse{Status: 200, Headers: map[string]string{"Content-Type": "text/html"}, Body: "<ul><li>guest</li></ul>", URL: p.URL}, nil
			},
		}
		cands, err := loader.ExecuteJS(context.Background(), spec, src, env, 10*time.Second)
		if err != nil {
			t.Fatalf("execute: %v", err)
		}
		if len(cands) != 1 {
			t.Fatalf("one multipart HPP candidate expected, got %d", len(cands))
		}
		ev := cands[0].Evidence
		if ev == nil || ev.Verdict != oracle.VerdictAccept || ev.ConfidenceContribution != plugin.ConfidenceConfirmed {
			t.Fatalf("confirmed evidence required: %+v", cands[0])
		}
		if !multipartCT.Load() {
			t.Fatal("point headers must carry a multipart/form-data content type with a boundary")
		}
		if !duplicated.Load() {
			t.Fatal("duplicate part must be emitted on the wire")
		}
	})

	t.Run("rejected duplicate part is not pollution", func(t *testing.T) {
		env := &loader.JSEnv{
			Points: []loader.JSPoint{point},
			Send: func(p loader.JSPoint) (loader.JSResponse, error) {
				h := map[string]string{"Content-Type": "text/html"}
				if strings.Count(p.Value, `name="id"`) >= 2 {
					return loader.JSResponse{Status: 400, Headers: h, Body: "<html><body>malformed multipart</body></html>", URL: p.URL}, nil
				}
				return loader.JSResponse{Status: 200, Headers: h, Body: "<ul><li>guest</li></ul>", URL: p.URL}, nil
			},
		}
		cands, err := loader.ExecuteJS(context.Background(), spec, src, env, 10*time.Second)
		if err != nil {
			t.Fatalf("execute: %v", err)
		}
		if len(cands) != 0 {
			t.Fatalf("a rejection must not confirm, got %d", len(cands))
		}
	})

	t.Run("send budget holds", func(t *testing.T) {
		assertSendBudget(t, spec, src, 60, "POST", "body")
	})

	t.Run("no new sandbox surface", func(t *testing.T) {
		assertOracleSurface(t, src, []string{"host.oracles.differential"}, []string{"host.oracles.error", "host.oracles.timing", "host.oracles.reflection"})
	})
}

// assertSendBudget drives the plugin across a wide surface and fails when the
// declared request budget is exceeded.
// What: Budget proof shared by the JSON/multipart suites.
// Why: Runaway sends are a policy violation, not a style issue.
func assertSendBudget(t *testing.T, spec *plugin.PluginSpec, src string, limit int64, method, location string) {
	t.Helper()
	points := make([]loader.JSPoint, 20)
	for i := range points {
		points[i] = loader.JSPoint{
			URL:           "http://example.com/api/" + itoaTest(i),
			Method:        method,
			ParamName:     "id",
			ParamLocation: location,
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
	if _, err := loader.ExecuteJS(context.Background(), spec, src, env, 2*time.Second); err != nil {
		t.Fatalf("execute: %v", err)
	}
	if got := sends.Load(); got > limit {
		t.Fatalf("send budget exceeded: got %d, want <= %d", got, limit)
	}
}

// assertOracleSurface fails when a plugin uses an unexpected oracle binding or
// reaches for a forbidden primitive.
// What: Source-level sandbox surface assertion.
// Why: Tier 2 plugins must stay inside the existing host bindings.
func assertOracleSurface(t *testing.T, src string, required, forbidden []string) {
	t.Helper()
	lower := strings.ToLower(src)
	for _, want := range required {
		if !strings.Contains(lower, strings.ToLower(want)) {
			t.Fatalf("missing required binding %s", want)
		}
	}
	for _, bad := range append(append([]string{}, forbidden...), "require(", "fetch(") {
		if strings.Contains(lower, strings.ToLower(bad)) {
			t.Fatalf("forbidden sandbox surface in source: %s", bad)
		}
	}
}

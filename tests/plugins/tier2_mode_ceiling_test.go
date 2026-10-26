// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Module: github.com/Xmar1881/Gash

package plugins

import (
	"context"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Xmar1881/Gash/internal/oracle"
	"github.com/Xmar1881/Gash/internal/plugin"
	"github.com/Xmar1881/Gash/internal/plugin/loader"
)

// TestLFIJSONBodyE2E proves per-field JSON traversal detection.
// What: Executes lfi-json-body.js against a mocked JSON file endpoint.
// Why: The signature family comes from the plugin-level oracle_params block,
// not from an inline argument, so the fixture runner and a live scan apply the
// same mode. Without that plumbing a file-content proof would be evaluated as
// a SQL signature and silently rejected.
func TestLFIJSONBodyE2E(t *testing.T) {
	spec, src := loadTier2(t, "plugins/path-traversal/lfi-json-body.js", "lfi-json-body")
	point := loader.JSPoint{URL: "http://example.com/api/export", Method: "POST", ParamName: "file", ParamLocation: "body"}

	t.Run("traversal payload leaks file content", func(t *testing.T) {
		var jsonContentType, rawBody atomic.Bool
		env := &loader.JSEnv{
			Points: []loader.JSPoint{point},
			Send: func(p loader.JSPoint) (loader.JSResponse, error) {
				if p.ParamName == "" && strings.HasPrefix(strings.TrimSpace(p.Value), "{") {
					rawBody.Store(true)
				}
				if strings.Contains(strings.ToLower(jsHeaderValue(p.Headers, "Content-Type")), "json") {
					jsonContentType.Store(true)
				}
				h := map[string]string{"Content-Type": "text/html"}
				if strings.Contains(p.Value, "passwd") || strings.Contains(p.Value, "win.ini") {
					return loader.JSResponse{Status: 200, Headers: h, Body: "<pre>root:x:0:0:root:/root:/bin/bash</pre>", URL: p.URL}, nil
				}
				return loader.JSResponse{Status: 200, Headers: h, Body: "<p>file not available</p>", URL: p.URL}, nil
			},
		}
		cands, err := loader.ExecuteJS(context.Background(), spec, src, env, 10*time.Second)
		if err != nil {
			t.Fatalf("execute: %v", err)
		}
		if len(cands) != 1 {
			t.Fatalf("one traversal candidate expected, got %d", len(cands))
		}
		ev := cands[0].Evidence
		if ev == nil || ev.Verdict != oracle.VerdictAccept || ev.ConfidenceContribution != plugin.ConfidenceConfirmed {
			t.Fatalf("confirmed evidence required: %+v", cands[0])
		}
		if cands[0].Candidate.OracleName != "error" {
			t.Fatalf("oracle must stay error, got %q", cands[0].Candidate.OracleName)
		}
		if !jsonContentType.Load() || !rawBody.Load() {
			t.Fatal("the payload must be a raw application/json body")
		}
	})

	t.Run("sanitised backend rejects", func(t *testing.T) {
		env := &loader.JSEnv{
			Points: []loader.JSPoint{point},
			Send: func(p loader.JSPoint) (loader.JSResponse, error) {
				h := map[string]string{"Content-Type": "text/html"}
				return loader.JSResponse{Status: 200, Headers: h, Body: "<p>file not available</p>", URL: p.URL}, nil
			},
		}
		cands, err := loader.ExecuteJS(context.Background(), spec, src, env, 10*time.Second)
		if err != nil {
			t.Fatalf("execute: %v", err)
		}
		if len(cands) != 0 {
			t.Fatalf("a sanitised path must not confirm, got %d", len(cands))
		}
	})

	t.Run("send budget holds", func(t *testing.T) {
		assertSendBudget(t, spec, src, 60, "POST", "body")
	})

	t.Run("mode is declared once in oracle_params", func(t *testing.T) {
		lower := strings.ToLower(src)
		if !strings.Contains(lower, "oracle_params:") || !strings.Contains(lower, "mode: path_traversal") {
			t.Fatal("mode must be declared in the frontmatter oracle_params block")
		}
		if !strings.Contains(lower, "host.oracles.error(resp, controlresp)") {
			t.Fatal("the error call must not pass an inline mode: oracle_params is the single source")
		}
		assertOracleSurface(t, src,
			[]string{"host.oracles.error"},
			[]string{"host.oracles.differential", "host.oracles.timing", "host.oracles.reflection"})
	})
}

// TestGraphQLBatchAbuseE2E proves the batch-accepted divergence and its ceiling.
// What: Executes graphql-batch-abuse.js against a batch-accepting GraphQL mock.
// Why: Accepting a batch is a hardening gap, not an exploitable flaw. The
// divergence is proven at 3/3, so only the declared ceiling keeps the finding
// honest; this test locks that ceiling in place.
func TestGraphQLBatchAbuseE2E(t *testing.T) {
	spec, src := loadTier2(t, "plugins/graphql/graphql-batch-abuse.js", "graphql-batch-abuse")
	const endpoint = "http://example.com/graphql"
	point := loader.JSPoint{URL: endpoint, Method: "POST", ParamName: "query", ParamLocation: "body"}

	t.Run("accepted batch is reported at firm", func(t *testing.T) {
		env := &loader.JSEnv{
			Points: []loader.JSPoint{point},
			Send: func(p loader.JSPoint) (loader.JSResponse, error) {
				h := map[string]string{"Content-Type": "application/json"}
				body := strings.TrimSpace(p.Value)
				switch {
				case strings.HasPrefix(body, "["):
					return loader.JSResponse{Status: 200, Headers: h, Body: `[{"data":{"__typename":"Query"}},{"data":{"__typename":"Query"}},{"data":{"__typename":"Query"}}]`, URL: p.URL}, nil
				case strings.Contains(body, "gashControlProbeField"):
					return loader.JSResponse{Status: 200, Headers: h, Body: `{"errors":[{"message":"Cannot query field"}]}`, URL: p.URL}, nil
				default:
					return loader.JSResponse{Status: 200, Headers: h, Body: `{"data":{"__typename":"Query"}}`, URL: p.URL}, nil
				}
			},
		}
		cands, err := loader.ExecuteJS(context.Background(), spec, src, env, 10*time.Second)
		if err != nil {
			t.Fatalf("execute: %v", err)
		}
		if len(cands) != 1 {
			t.Fatalf("one batch-abuse candidate expected, got %d", len(cands))
		}
		ev := cands[0].Evidence
		if ev == nil || ev.Verdict != oracle.VerdictAccept {
			t.Fatalf("accepted evidence required: %+v", cands[0])
		}
		if ev.ConfidenceContribution != plugin.ConfidenceFirm {
			t.Fatalf("ceiling must hold at firm, got %s", ev.ConfidenceContribution)
		}
		if cands[0].Candidate.OracleName != "differential" {
			t.Fatalf("oracle must stay differential, got %q", cands[0].Candidate.OracleName)
		}
	})

	t.Run("rejected batch stays silent", func(t *testing.T) {
		env := &loader.JSEnv{
			Points: []loader.JSPoint{point},
			Send: func(p loader.JSPoint) (loader.JSResponse, error) {
				h := map[string]string{"Content-Type": "application/json"}
				return loader.JSResponse{Status: 200, Headers: h, Body: `{"errors":[{"message":"Batch queries are disabled"}]}`, URL: p.URL}, nil
			},
		}
		cands, err := loader.ExecuteJS(context.Background(), spec, src, env, 10*time.Second)
		if err != nil {
			t.Fatalf("execute: %v", err)
		}
		if len(cands) != 0 {
			t.Fatalf("a disabled batch must not confirm, got %d", len(cands))
		}
	})

	t.Run("non graphql points are skipped", func(t *testing.T) {
		var sends atomic.Int64
		env := &loader.JSEnv{
			Points: []loader.JSPoint{{URL: "http://example.com/api/search", Method: "GET", ParamName: "q", ParamLocation: "query"}},
			Send: func(p loader.JSPoint) (loader.JSResponse, error) {
				sends.Add(1)
				return loader.JSResponse{Status: 200, Body: "neutral", URL: p.URL}, nil
			},
		}
		cands, err := loader.ExecuteJS(context.Background(), spec, src, env, 10*time.Second)
		if err != nil {
			t.Fatalf("execute: %v", err)
		}
		if len(cands) != 0 || sends.Load() != 0 {
			t.Fatalf("non-graphql surface must not be probed: cands=%d sends=%d", len(cands), sends.Load())
		}
	})

	t.Run("send budget holds", func(t *testing.T) {
		points := make([]loader.JSPoint, 20)
		for i := range points {
			points[i] = loader.JSPoint{
				URL:           "http://example.com/graphql/" + itoaTest(i),
				Method:        "POST",
				ParamName:     "query",
				ParamLocation: "body",
			}
		}
		var sends atomic.Int64
		env := &loader.JSEnv{
			Points: points,
			Send: func(p loader.JSPoint) (loader.JSResponse, error) {
				sends.Add(1)
				return loader.JSResponse{Status: 200, Body: "neutral", URL: p.URL}, nil
			},
		}
		if _, err := loader.ExecuteJS(context.Background(), spec, src, env, 2*time.Second); err != nil {
			t.Fatalf("execute: %v", err)
		}
		if got := sends.Load(); got > 60 {
			t.Fatalf("send budget exceeded: got %d, want <= 60", got)
		}
	})

	t.Run("ceiling is declared once in oracle_params", func(t *testing.T) {
		lower := strings.ToLower(src)
		if !strings.Contains(lower, "oracle_params:") || !strings.Contains(lower, "confidence_ceiling: firm") {
			t.Fatal("ceiling must be declared in the frontmatter oracle_params block")
		}
		if !strings.Contains(lower, "host.oracles.differential(batchresps, singleresps, controlresp)") {
			t.Fatal("the differential call must not pass an inline ceiling: oracle_params is the single source")
		}
		assertOracleSurface(t, src,
			[]string{"host.oracles.differential"},
			[]string{"host.oracles.error", "host.oracles.timing", "host.oracles.reflection"})
	})
}

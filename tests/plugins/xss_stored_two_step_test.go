// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Module: github.com/Xmar1881/Gash

package plugins

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Xmar1881/Gash/internal/oracle"
	"github.com/Xmar1881/Gash/internal/plugin"
	"github.com/Xmar1881/Gash/internal/plugin/loader"
)

// TestXSSStoredTwoStepE2E proves the two-request store-plus-render flow.
// What: Executes xss-stored-two-step.js against a stateful store/render mock:
// request 1 stores through the form point, request 2 GETs the render page,
// and the pair is verified with the stored oracle (two exchanges plus
// clean control).
// Why: Tier 1 xss-stored-basic is a synchronous-render approximation; Tier 2
// must prove the real POST-store plus render-GET flow through the existing
// probe.send plus surface plus host.oracles bindings with no new transport.
func TestXSSStoredTwoStepE2E(t *testing.T) {
	root := repoRoot(t)
	path := filepath.Join(root, "plugins", "xss", "xss-stored-two-step.js")
	src, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	spec, err := loader.LoadTier2Frontmatter(path)
	if err != nil {
		t.Fatalf("frontmatter %s: %v", path, err)
	}

	t.Run("vulnerable store plus render confirms static evidence", func(t *testing.T) {
		const canary = "gash_store_e2e_1"
		var stored string
		env := &loader.JSEnv{
			Points: []loader.JSPoint{{URL: "http://example.com/comments", Method: "POST", ParamName: "comment", ParamLocation: "body"}},
			Canary: canary,
			Send: func(p loader.JSPoint) (loader.JSResponse, error) {
				h := map[string]string{"Content-Type": "text/html"}
				// Store request: form point with executable payload.
				if p.ParamName == "comment" && strings.Contains(p.Value, "alert("+canary+")") {
					stored = p.Value
					return loader.JSResponse{Status: 200, Headers: h, Body: "<html><body>stored</body></html>", URL: p.URL}, nil
				}
				// Render page GET (empty paramName, empty value).
				if p.ParamName == "" {
					if p.Value == "gash-control-neutral" {
						// Binding control fetch: clean page without the canary.
						return loader.JSResponse{Status: 200, Headers: h, Body: "<html><body><div class=\"comment\">nice post</div></body></html>", URL: p.URL}, nil
					}
					if stored != "" {
						return loader.JSResponse{Status: 200, Headers: h, Body: "<html><body><div class=\"comment\">" + stored + "</div></body></html>", URL: p.URL}, nil
					}
					return loader.JSResponse{Status: 200, Headers: h, Body: "<html><body><div class=\"comment\">nice post</div></body></html>", URL: p.URL}, nil
				}
				return loader.JSResponse{Status: 200, Headers: h, Body: "<html><body>neutral</body></html>", URL: p.URL}, nil
			},
		}
		cands, err := loader.ExecuteJS(context.Background(), spec, string(src), env, 10*time.Second)
		if err != nil {
			t.Fatalf("execute: %v", err)
		}
		if len(cands) != 1 {
			t.Fatalf("one stored candidate expected, got %d", len(cands))
		}
		ev := cands[0].Evidence
		if ev == nil || ev.Verdict != oracle.VerdictAccept {
			t.Fatalf("accepted evidence required: %+v", cands[0])
		}
		if ev.ConfidenceContribution != plugin.ConfidenceStaticExecution {
			t.Fatalf("static-execution-evidence required, got %s (%s)", ev.ConfidenceContribution, ev.Note)
		}
		if cands[0].Candidate.OracleName != "stored" {
			t.Fatalf("oracle must be stored, got %q", cands[0].Candidate.OracleName)
		}
		if ev.Artifacts["workflow"] != "store+render" {
			t.Fatalf("two-exchange workflow stamp required: %+v", ev.Artifacts)
		}
		lower := strings.ToLower(string(src))
		if !strings.Contains(lower, "host.oracles.stored") {
			t.Fatal("must use host.oracles.storedExecution")
		}
		if strings.Contains(lower, "host.oracles.reflection") {
			t.Fatal("single-exchange reflection must not bypass the stored workflow")
		}
		if strings.Contains(lower, "eval(") || strings.Contains(lower, "function(") {
			t.Fatal("no new sandbox surface: only probe.send plus surface plus host.oracles")
		}
	})

	t.Run("filtered store rejects", func(t *testing.T) {
		const canary = "gash_store_e2e_2"
		env := &loader.JSEnv{
			Points: []loader.JSPoint{{URL: "http://example.com/comments", Method: "POST", ParamName: "comment", ParamLocation: "body"}},
			Canary: canary,
			Send: func(p loader.JSPoint) (loader.JSResponse, error) {
				h := map[string]string{"Content-Type": "text/html"}
				if p.ParamName == "comment" {
					return loader.JSResponse{Status: 200, Headers: h, Body: "<html><body>stored</body></html>", URL: p.URL}, nil
				}
				// Render never reflects the canary (filtered).
				return loader.JSResponse{Status: 200, Headers: h, Body: "<html><body><div class=\"comment\">nice post</div></body></html>", URL: p.URL}, nil
			},
		}
		cands, err := loader.ExecuteJS(context.Background(), spec, string(src), env, 10*time.Second)
		if err != nil {
			t.Fatalf("execute: %v", err)
		}
		if len(cands) != 0 {
			t.Fatalf("filtered backend must not confirm, got %d", len(cands))
		}
	})
}

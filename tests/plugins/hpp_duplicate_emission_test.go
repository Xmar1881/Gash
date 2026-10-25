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

// TestHPPDuplicateEmissionE2E proves real duplicate-key emission end to end.
// What: Executes hpp-duplicate-emission.js against a mocked transport that
// distinguishes duplicate (id=1&id=2) from single (id=1) requests.
// Why: Tier 1 models pollution as value divergence (approximation); Tier 2 must
// prove native duplicated-key emission through the existing probe.send binding
// with no new sandbox surface, compared via the differential oracle.
func TestHPPDuplicateEmissionE2E(t *testing.T) {
	root := repoRoot(t)
	path := filepath.Join(root, "plugins", "hpp", "hpp-duplicate-emission.js")
	src, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	spec, err := loader.LoadTier2Frontmatter(path)
	if err != nil {
		t.Fatalf("frontmatter %s: %v", path, err)
	}
	if spec.ID != "hpp-duplicate-emission" {
		t.Fatalf("unexpected id %q", spec.ID)
	}

	isDuplicate := func(p loader.JSPoint) bool {
		if strings.Contains(p.URL, "id=1&id=2") || strings.Contains(p.URL, "id%3D1") {
			return true
		}
		if p.ParamName == "" && strings.Contains(p.Value, "id=1&id=2") {
			return true
		}
		if strings.Contains(p.Value, "id=1&id=2") {
			return true
		}
		// Generic: any URL carrying the same key twice.
		if p.ParamName == "" && strings.Count(p.URL, "id=") >= 2 {
			return true
		}
		return false
	}

	mkEnv := func(points []loader.JSPoint, polluted, single string) *loader.JSEnv {
		return &loader.JSEnv{
			Points: points,
			Send: func(p loader.JSPoint) (loader.JSResponse, error) {
				h := map[string]string{"Content-Type": "text/html"}
				if isDuplicate(p) {
					return loader.JSResponse{Status: 200, Headers: h, Body: polluted, URL: p.URL}, nil
				}
				if p.Value == "1" {
					return loader.JSResponse{Status: 200, Headers: h, Body: single, URL: p.URL}, nil
				}
				return loader.JSResponse{Status: 200, Headers: h, Body: "<html><body>neutral</body></html>", URL: p.URL}, nil
			},
		}
	}

	t.Run("query duplicate diverges", func(t *testing.T) {
		env := mkEnv(
			[]loader.JSPoint{{URL: "http://example.com/list", Method: "GET", ParamName: "id", ParamLocation: "query"}},
			"<ul><li>polluted-admin</li></ul>",
			"<ul><li>guest</li></ul>",
		)
		cands, err := loader.ExecuteJS(context.Background(), spec, string(src), env, 10*time.Second)
		if err != nil {
			t.Fatalf("execute: %v", err)
		}
		if len(cands) != 1 {
			t.Fatalf("one HPP candidate expected, got %d", len(cands))
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
		// No new sandbox surface: source must only use existing bindings.
		lower := strings.ToLower(string(src))
		if !strings.Contains(lower, "host.oracles.differential") {
			t.Fatal("must use host.oracles.differential")
		}
		if strings.Contains(lower, "host.oracles.hpp") || strings.Contains(lower, "probe.duplicate") {
			t.Fatal("new sandbox surface is forbidden")
		}
	})

	t.Run("body duplicate diverges", func(t *testing.T) {
		env := mkEnv(
			[]loader.JSPoint{{URL: "http://example.com/list", Method: "POST", ParamName: "id", ParamLocation: "body"}},
			"<ul><li>polluted-admin</li></ul>",
			"<ul><li>guest</li></ul>",
		)
		cands, err := loader.ExecuteJS(context.Background(), spec, string(src), env, 10*time.Second)
		if err != nil {
			t.Fatalf("execute: %v", err)
		}
		if len(cands) != 1 {
			t.Fatalf("one HPP candidate expected for body, got %d", len(cands))
		}
	})

	t.Run("last-value-wins rejects", func(t *testing.T) {
		env := mkEnv(
			[]loader.JSPoint{{URL: "http://example.com/list", Method: "GET", ParamName: "id", ParamLocation: "query"}},
			"<ul><li>guest</li></ul>",
			"<ul><li>guest</li></ul>",
		)
		cands, err := loader.ExecuteJS(context.Background(), spec, string(src), env, 10*time.Second)
		if err != nil {
			t.Fatalf("execute: %v", err)
		}
		if len(cands) != 0 {
			t.Fatalf("consistent backend must not confirm, got %d", len(cands))
		}
	})

	t.Run("large surfaces stay within send budget", func(t *testing.T) {
		points := make([]loader.JSPoint, 20)
		for i := range points {
			points[i] = loader.JSPoint{
				URL:           "http://example.com/page-" + string(rune('a'+i)),
				Method:        "GET",
				ParamName:     "id",
				ParamLocation: "query",
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
			t.Fatalf("HPP send budget exceeded: got %d, want <= 60", got)
		}
	})
}

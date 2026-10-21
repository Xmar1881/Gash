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

	"github.com/Xmar1881/Gash/internal/plugin"
	"github.com/Xmar1881/Gash/internal/plugin/loader"
)

// TestSQLiCorpusExecution proves the rewritten sqli-error-based.js loop:
// prioritized probes first, stop at the first error hit, control collision
// rejects, and the request budget stays inside the declared cap.
// What: Executes sqli-error-based.js against synthetic servers through the
// real binding and error oracle.
// Why: The metric fixtures are oracle-level; this test is the JS-side proof
// that the corpus loop and control semantics stay honest.
func TestSQLiCorpusExecution(t *testing.T) {
	root := repoRoot(t)
	path := filepath.Join(root, "plugins", "sqli", "sqli-error-based.js")
	src, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	spec, err := loader.LoadTier2Frontmatter(path)
	if err != nil {
		t.Fatalf("frontmatter %s: %v", path, err)
	}

	mysqlError := "ERROR 1105 (HY000): XPATH syntax error: '~5.7.44'"

	scenarios := []struct {
		name      string
		respond   func(v string) string
		wantCands int
		wantSends int
	}{
		{
			name: "error signature confirms after prefix probes miss",
			respond: func(v string) string {
				if v != "gash-control" && strings.Contains(v, "EXTRACTVALUE") {
					return "<html><body>" + mysqlError + "</body></html>"
				}
				return "<html><body>clean results</body></html>"
			},
			wantCands: 1,
			wantSends: 5, // control + three prefix probes + first EXTRACTVALUE probe
		},
		{
			name:      "clean server yields no candidate",
			respond:   func(string) string { return "<html><body>clean results</body></html>" },
			wantCands: 0,
			wantSends: 17, // control + all sixteen probes
		},
		{
			name:      "signature present in control rejects",
			respond:   func(string) string { return "<html><body>" + mysqlError + "</body></html>" },
			wantCands: 0,
			wantSends: 17,
		},
	}

	for _, sc := range scenarios {
		t.Run(sc.name, func(t *testing.T) {
			sends := 0
			env := &loader.JSEnv{
				Points: []loader.JSPoint{{URL: "http://example.com/item", Method: "GET", ParamName: "id", ParamLocation: "query"}},
				Canary: "gash_corpus_exec",
				Send: func(p loader.JSPoint) (loader.JSResponse, error) {
					sends++
					h := map[string]string{"Content-Type": "text/html"}
					return loader.JSResponse{Status: 200, Headers: h, Body: sc.respond(p.Value), URL: p.URL}, nil
				},
			}
			cands, err := loader.ExecuteJS(context.Background(), spec, string(src), env, 10*time.Second)
			if err != nil {
				t.Fatalf("execute: %v", err)
			}
			if len(cands) != sc.wantCands {
				t.Fatalf("candidates = %d, want %d (%+v)", len(cands), sc.wantCands, cands)
			}
			if sends != sc.wantSends {
				t.Fatalf("sends = %d, want %d", sends, sc.wantSends)
			}
			if sc.wantCands == 0 {
				return
			}
			c := cands[0]
			if c.Candidate.OracleName != "error" {
				t.Fatalf("oracle must be error, got %q", c.Candidate.OracleName)
			}
			if !strings.Contains(c.Candidate.InjectionPoint.Value, "EXTRACTVALUE") {
				t.Fatalf("payload must be the first error probe, got %q", c.Candidate.InjectionPoint.Value)
			}
			ev := c.Evidence
			if ev == nil || ev.ConfidenceContribution != plugin.ConfidenceConfirmed {
				t.Fatalf("confirmed evidence required: %+v", ev)
			}
		})
	}
}

// TestSQLiFairBudgetReachesTailPoints proves the round-robin budget: a quiet
// prefix of points can no longer starve a later point (the measured
// /sqli/error recall gap came from exactly that starvation).
// What: Five points, only the last one error-signatures on the first
// prioritized probe; the candidate must still be found and the send count
// stays at the declared cap.
// Why: Locks the fairness property that the old per-point loop violated by
// returning once fewer than 13 sends remained.
func TestSQLiFairBudgetReachesTailPoints(t *testing.T) {
	root := repoRoot(t)
	path := filepath.Join(root, "plugins", "sqli", "sqli-error-based.js")
	src, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	spec, err := loader.LoadTier2Frontmatter(path)
	if err != nil {
		t.Fatalf("frontmatter %s: %v", path, err)
	}

	mysqlError := "ERROR 1105 (HY000): XPATH syntax error: '~5.7.44'"
	points := []loader.JSPoint{
		{URL: "http://example.com/a", Method: "GET", ParamName: "q", ParamLocation: "query"},
		{URL: "http://example.com/b", Method: "GET", ParamName: "q", ParamLocation: "query"},
		{URL: "http://example.com/c", Method: "GET", ParamName: "q", ParamLocation: "query"},
		{URL: "http://example.com/d", Method: "GET", ParamName: "q", ParamLocation: "query"},
		{URL: "http://example.com/sqli/error", Method: "GET", ParamName: "id", ParamLocation: "query"},
	}
	sends := 0
	env := &loader.JSEnv{
		Points: points,
		Canary: "gash_fair_budget",
		Send: func(p loader.JSPoint) (loader.JSResponse, error) {
			sends++
			body := "<html><body>clean results</body></html>"
			if strings.HasSuffix(p.URL, "/sqli/error") && strings.Contains(p.Value, "'") {
				body = "<html><body>" + mysqlError + "</body></html>"
			}
			return loader.JSResponse{Status: 200, Headers: map[string]string{"Content-Type": "text/html"}, Body: body, URL: p.URL}, nil
		},
	}
	cands, err := loader.ExecuteJS(context.Background(), spec, string(src), env, 10*time.Second)
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	if len(cands) != 1 {
		t.Fatalf("tail point must be reached despite quiet prefix, candidates = %d", len(cands))
	}
	if got := cands[0].Candidate.InjectionPoint.URL; !strings.HasSuffix(got, "/sqli/error") {
		t.Fatalf("candidate must come from the tail point, got %q", got)
	}
	if got := cands[0].Candidate.InjectionPoint.Value; got != "1'" {
		t.Fatalf("first prioritized probe must confirm, got %q", got)
	}
	// 5 controls + round 0 (5 sends) + 45 sends over 4 live points up to the cap.
	if sends != 60 {
		t.Fatalf("sends = %d, want 60 (fair round-robin cap)", sends)
	}
}

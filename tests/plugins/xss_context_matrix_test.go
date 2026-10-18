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

// TestXSSContextMatrix proves the probe-first classifier picks the payload
// family that executes in each reflection context, and that escaped output
// never yields static-execution evidence.
// What: Executes xss-reflected-basic.js against synthetic per-context
// responses through the real binding and reflection oracle.
// Why: The metric fixtures are oracle-level; this test is the JS-side proof
// that the context classifier and payload sets stay honest.
func TestXSSContextMatrix(t *testing.T) {
	root := repoRoot(t)
	path := filepath.Join(root, "plugins", "xss", "xss-reflected-basic.js")
	src, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	spec, err := loader.LoadTier2Frontmatter(path)
	if err != nil {
		t.Fatalf("frontmatter %s: %v", path, err)
	}

	scenarios := []struct {
		name     string
		reflect  func(v string) string
		wantExec bool
	}{
		{
			name:     "html text accepts tag payload",
			reflect:  func(v string) string { return "<html><body><p>" + v + "</p></body></html>" },
			wantExec: true,
		},
		{
			name:     "double-quoted attribute accepts breakout",
			reflect:  func(v string) string { return `<html><body><input value="` + v + `"></body></html>` },
			wantExec: true,
		},
		{
			name:     "unquoted attribute accepts event handler",
			reflect:  func(v string) string { return "<html><body><input value=" + v + "></body></html>" },
			wantExec: true,
		},
		{
			name:     "script single-quoted string accepts breakout",
			reflect:  func(v string) string { return "<html><body><script>var q='" + v + "';</script></body></html>" },
			wantExec: true,
		},
		{
			name:     "href attribute accepts javascript URL",
			reflect:  func(v string) string { return `<html><body><a href="` + v + `">next</a></body></html>` },
			wantExec: true,
		},
		{
			name: "html-escaped output never confirms",
			reflect: func(v string) string {
				r := strings.NewReplacer("<", "&lt;", ">", "&gt;", `"`, "&quot;", "'", "&#39;")
				return "<html><body><p>" + r.Replace(v) + "</p></body></html>"
			},
			wantExec: false,
		},
	}

	for i, sc := range scenarios {
		t.Run(sc.name, func(t *testing.T) {
			env := &loader.JSEnv{
				Points: []loader.JSPoint{{URL: "http://example.com/search", Method: "GET", ParamName: "q", ParamLocation: "query"}},
				Canary: "gash_ctx_" + string(rune('a'+i)),
				Send: func(p loader.JSPoint) (loader.JSResponse, error) {
					h := map[string]string{"Content-Type": "text/html"}
					if p.Value == "gash-control-neutral" {
						return loader.JSResponse{Status: 200, Headers: h, Body: "<html><body><p>clean</p></body></html>", URL: p.URL}, nil
					}
					return loader.JSResponse{Status: 200, Headers: h, Body: sc.reflect(p.Value), URL: p.URL}, nil
				},
			}
			cands, err := loader.ExecuteJS(context.Background(), spec, string(src), env, 10*time.Second)
			if err != nil {
				t.Fatalf("execute: %v", err)
			}
			if !sc.wantExec {
				for _, c := range cands {
					switch c.Evidence.ConfidenceContribution {
					case plugin.ConfidenceStaticExecution, plugin.ConfidenceFirm, plugin.ConfidenceConfirmed:
						t.Fatalf("escaped output must not confirm: %+v", c.Evidence)
					}
				}
				return
			}
			if len(cands) != 1 {
				t.Fatalf("expected 1 candidate, got %d", len(cands))
			}
			c := cands[0]
			if c.Candidate.OracleName != "reflection" {
				t.Fatalf("oracle must be reflection, got %q", c.Candidate.OracleName)
			}
			ev := c.Evidence
			if ev == nil || ev.Verdict != oracle.VerdictAccept {
				t.Fatalf("accepted evidence required: %+v", ev)
			}
			if ev.ConfidenceContribution != plugin.ConfidenceStaticExecution {
				t.Fatalf("static-execution-evidence required, got %s (%s)", ev.ConfidenceContribution, ev.Note)
			}
			switch ev.Artifacts["context"] {
			case "attr-executable", "script", "url-executable", "html-text":
			default:
				t.Fatalf("unexpected artifact context: %+v", ev.Artifacts)
			}
		})
	}
}

// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Module: github.com/Xmar1881/Gash

package loader

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/Xmar1881/Gash/internal/oracle"
	"github.com/Xmar1881/Gash/internal/plugin"
)

// Tier 2 oracle parameters: a plugin may declare them once in frontmatter
// (`oracle_params`) and the binding applies them, so the fixture runner and a
// live scan share one source of truth. A per-call opts argument still wins.

const errorProbeSource = `
function run(probe, ctx) {
  const out = [];
  for (const p of ctx.injectionPoints()) {
    const resp = probe.send(p.withValue("../../../../etc/passwd"));
    const ctrl = probe.send(p.withValue("neutral"));
    const ev = host.oracles.error(resp, ctrl);
    if (ev) out.push(host.candidate(p, "error", ev));
  }
  return out;
}`

const differentialProbeSource = `
function run(probe, ctx) {
  const out = [];
  for (const p of ctx.injectionPoints()) {
    const t = [], f = [];
    for (let i = 0; i < 3; i++) {
      t.push(probe.send(p.withValue("batch")));
      f.push(probe.send(p.withValue("single")));
    }
    const ev = host.oracles.differential(t, f, probe.send(p.withValue("control")));
    if (ev) out.push(host.candidate(p, "differential", ev));
  }
  return out;
}`

const passwdBody = "<pre>root:x:0:0:root:/root:/bin/bash</pre>"
const cleanBody = "<html><body>file not available</body></html>"

func minimalSpec(id string, params map[string]any) *plugin.PluginSpec {
	return &plugin.PluginSpec{ID: id, OracleParams: params}
}

func pointEnv(url string, send func(JSPoint) (JSResponse, error)) *JSEnv {
	return &JSEnv{
		Points: []JSPoint{{URL: url, Method: "POST", ParamName: "file", ParamLocation: "body"}},
		Send:   send,
	}
}

// TestJSErrorModeFromOracleParams proves the mode default and the override.
func TestJSErrorModeFromOracleParams(t *testing.T) {
	// The traversal payload leaks file content; the neutral value does not.
	send := func(p JSPoint) (JSResponse, error) {
		body := cleanBody
		if strings.Contains(p.Value, "passwd") {
			body = passwdBody
		}
		return JSResponse{Status: 200, Headers: map[string]string{"Content-Type": "text/html"}, Body: body, URL: p.URL}, nil
	}

	t.Run("frontmatter mode path_traversal accepts", func(t *testing.T) {
		spec := minimalSpec("mode-from-params", map[string]any{"mode": "path_traversal"})
		cands, err := ExecuteJS(context.Background(), spec, errorProbeSource, pointEnv("http://example.com/api/export", send), 5*time.Second)
		if err != nil {
			t.Fatalf("execute: %v", err)
		}
		if len(cands) != 1 || cands[0].Evidence.ConfidenceContribution != plugin.ConfidenceConfirmed {
			t.Fatalf("one confirmed traversal candidate expected, got %+v", cands)
		}
	})

	t.Run("per-call mode argument wins", func(t *testing.T) {
		src := strings.Replace(errorProbeSource, "host.oracles.error(resp, ctrl)", `host.oracles.error(resp, ctrl, {mode: "path_traversal"})`, 1)
		spec := minimalSpec("mode-per-call", nil)
		cands, err := ExecuteJS(context.Background(), spec, src, pointEnv("http://example.com/api/export", send), 5*time.Second)
		if err != nil {
			t.Fatalf("execute: %v", err)
		}
		if len(cands) != 1 {
			t.Fatalf("per-call mode must accept the traversal proof, got %d", len(cands))
		}
	})

	t.Run("default mode stays sqli and rejects", func(t *testing.T) {
		spec := minimalSpec("mode-default", nil)
		cands, err := ExecuteJS(context.Background(), spec, errorProbeSource, pointEnv("http://example.com/api/export", send), 5*time.Second)
		if err != nil {
			t.Fatalf("execute: %v", err)
		}
		if len(cands) != 0 {
			t.Fatalf("a file signature is not a SQL signature: got %d candidates", len(cands))
		}
	})
}

// TestJSDifferentialCeilingFromOracleParams proves the ceiling default.
func TestJSDifferentialCeilingFromOracleParams(t *testing.T) {
	send := func(p JSPoint) (JSResponse, error) {
		body := "neutral page"
		switch p.Value {
		case "batch":
			body = `[{"data":{"__typename":"Query"}},{"data":{"__typename":"Query"}}]`
		case "single":
			body = `{"data":{"__typename":"Query"}}`
		}
		return JSResponse{Status: 200, Headers: map[string]string{"Content-Type": "application/json"}, Body: body, URL: p.URL}, nil
	}

	t.Run("frontmatter ceiling firm downgrades", func(t *testing.T) {
		spec := minimalSpec("ceiling-from-params", map[string]any{"confidence_ceiling": "firm"})
		cands, err := ExecuteJS(context.Background(), spec, differentialProbeSource, pointEnv("http://example.com/graphql", send), 5*time.Second)
		if err != nil {
			t.Fatalf("execute: %v", err)
		}
		if len(cands) != 1 {
			t.Fatalf("one differential candidate expected, got %d", len(cands))
		}
		if got := cands[0].Evidence.ConfidenceContribution; got != plugin.ConfidenceFirm {
			t.Fatalf("ceiling must hold at firm, got %s", got)
		}
		if cands[0].Evidence.Verdict != oracle.VerdictAccept {
			t.Fatalf("ceiling must not change the verdict: %+v", cands[0].Evidence)
		}
	})

	t.Run("without a ceiling the oracle confirms", func(t *testing.T) {
		spec := minimalSpec("ceiling-absent", nil)
		cands, err := ExecuteJS(context.Background(), spec, differentialProbeSource, pointEnv("http://example.com/graphql", send), 5*time.Second)
		if err != nil {
			t.Fatalf("execute: %v", err)
		}
		if len(cands) != 1 || cands[0].Evidence.ConfidenceContribution != plugin.ConfidenceConfirmed {
			t.Fatalf("no ceiling means confirmed, got %+v", cands)
		}
	})
}

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

// jsonSinkPoint is the discovered JSON body field every sink test drives.
// What: A POST body field named url.
// Why: Mirrors the shape the engine hands to a Tier 2 plugin.
func jsonSinkPoint() loader.JSPoint {
	return loader.JSPoint{URL: "http://example.com/api/hook", Method: "POST", ParamName: "url", ParamLocation: "body"}
}

// between extracts the text between two markers.
// What: Small helper for reading a canary out of an echoed payload.
// Why: The mock must echo the plugin's per-run canary, not a fixed one.
func between(s, open, close string) string {
	i := strings.Index(s, open)
	if i < 0 {
		return ""
	}
	rest := s[i+len(open):]
	j := strings.Index(rest, close)
	if j < 0 {
		return ""
	}
	return rest[:j]
}

// TestOpenRedirectJSONBodyE2E proves per-field JSON redirect testing.
// What: Executes open-redirect-json-body.js against a mocked JSON backend.
// Why: Tier 1 sends one static body, so a JSON API redirect field cannot be
// exercised field by field; the Location header plus a neutral-value control
// is what makes the finding honest.
func TestOpenRedirectJSONBodyE2E(t *testing.T) {
	spec, src := loadTier2(t, "plugins/redirect/open-redirect-json-body.js", "open-redirect-json-body")
	point := jsonSinkPoint()

	t.Run("json field redirects to the payload host", func(t *testing.T) {
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
				// Only an absolute http(s) value becomes an external target.
				target := between(p.Value, `"url":"`, `"`)
				if strings.HasPrefix(target, "https://") {
					h["Location"] = target + "/landing"
					return loader.JSResponse{Status: 302, Headers: h, Body: "<html>redirecting</html>", URL: p.URL}, nil
				}
				return loader.JSResponse{Status: 200, Headers: h, Body: "<html>registered</html>", URL: p.URL}, nil
			},
		}
		cands, err := loader.ExecuteJS(context.Background(), spec, src, env, 10*time.Second)
		if err != nil {
			t.Fatalf("execute: %v", err)
		}
		if len(cands) != 1 {
			t.Fatalf("one redirect candidate expected, got %d", len(cands))
		}
		ev := cands[0].Evidence
		if ev == nil || ev.Verdict != oracle.VerdictAccept || ev.ConfidenceContribution != plugin.ConfidenceConfirmed {
			t.Fatalf("confirmed evidence required: %+v", cands[0])
		}
		if cands[0].Candidate.OracleName != "redirect" {
			t.Fatalf("oracle must stay redirect, got %q", cands[0].Candidate.OracleName)
		}
		if !rawBody.Load() || !jsonContentType.Load() {
			t.Fatal("JSON field must be sent as a raw JSON body")
		}
	})

	t.Run("in-origin target rejects", func(t *testing.T) {
		env := &loader.JSEnv{
			Points: []loader.JSPoint{point},
			Send: func(p loader.JSPoint) (loader.JSResponse, error) {
				h := map[string]string{"Content-Type": "text/html", "Location": "/dashboard"}
				return loader.JSResponse{Status: 302, Headers: h, Body: "<html>redirecting</html>", URL: p.URL}, nil
			},
		}
		cands, err := loader.ExecuteJS(context.Background(), spec, src, env, 10*time.Second)
		if err != nil {
			t.Fatalf("execute: %v", err)
		}
		if len(cands) != 0 {
			t.Fatalf("in-origin redirect must not confirm, got %d", len(cands))
		}
	})

	t.Run("send budget holds", func(t *testing.T) {
		assertSendBudget(t, spec, src, 40, "POST", "body")
	})

	t.Run("no new sandbox surface", func(t *testing.T) {
		assertOracleSurface(t, src,
			[]string{"host.oracles.redirect"},
			[]string{"host.oracles.reflection", "host.oracles.stored", "host.oracles.differential"})
	})
}

// TestXSSReflectedJSONBodyE2E proves JSON field reflection reaches static proof.
// What: Executes xss-reflected-json-body.js against a mocked renderer.
// Why: The query-point reflection plugin replays body points as urlencoded
// forms, which a JSON API never parses, so the reflection is missed entirely.
func TestXSSReflectedJSONBodyE2E(t *testing.T) {
	spec, src := loadTier2(t, "plugins/xss/xss-reflected-json-body.js", "xss-reflected-json-body")
	point := jsonSinkPoint()

	t.Run("json field echoed into a script context", func(t *testing.T) {
		var jsonContentType atomic.Bool
		env := &loader.JSEnv{
			Points: []loader.JSPoint{point},
			Send: func(p loader.JSPoint) (loader.JSResponse, error) {
				h := map[string]string{"Content-Type": "text/html"}
				if strings.Contains(strings.ToLower(jsHeaderValue(p.Headers, "Content-Type")), "json") {
					jsonContentType.Store(true)
				}
				canary := between(p.Value, "alert(", ")")
				if canary != "" {
					// Echo the executing pattern into a script context.
					return loader.JSResponse{Status: 200, Headers: h, Body: "<html><body><script>alert(" + canary + ")</script></body></html>", URL: p.URL}, nil
				}
				return loader.JSResponse{Status: 200, Headers: h, Body: "<html><body><p>zzz</p></body></html>", URL: p.URL}, nil
			},
		}
		cands, err := loader.ExecuteJS(context.Background(), spec, src, env, 10*time.Second)
		if err != nil {
			t.Fatalf("execute: %v", err)
		}
		if len(cands) != 1 {
			t.Fatalf("one reflected XSS candidate expected, got %d", len(cands))
		}
		ev := cands[0].Evidence
		if ev == nil || ev.Verdict != oracle.VerdictAccept {
			t.Fatalf("accepted evidence required: %+v", cands[0])
		}
		if ev.ConfidenceContribution != plugin.ConfidenceStaticExecution {
			t.Fatalf("static-execution-evidence required, got %s", ev.ConfidenceContribution)
		}
		if cands[0].Candidate.OracleName != "reflection" {
			t.Fatalf("oracle must stay reflection, got %q", cands[0].Candidate.OracleName)
		}
		if !jsonContentType.Load() {
			t.Fatal("JSON body must be sent with an application/json content type")
		}
	})

	t.Run("inert text reflection rejects", func(t *testing.T) {
		env := &loader.JSEnv{
			Points: []loader.JSPoint{point},
			Send: func(p loader.JSPoint) (loader.JSResponse, error) {
				h := map[string]string{"Content-Type": "text/html"}
				canary := between(p.Value, "alert(", ")")
				if canary != "" {
					return loader.JSResponse{Status: 200, Headers: h, Body: "<html><body><p>" + canary + "</p></body></html>", URL: p.URL}, nil
				}
				return loader.JSResponse{Status: 200, Headers: h, Body: "<html><body><p>zzz</p></body></html>", URL: p.URL}, nil
			},
		}
		cands, err := loader.ExecuteJS(context.Background(), spec, src, env, 10*time.Second)
		if err != nil {
			t.Fatalf("execute: %v", err)
		}
		// Text-only reflection is tolerated as tentative noise but must never
		// reach static-execution-evidence.
		for _, c := range cands {
			if c.Evidence != nil && c.Evidence.ConfidenceContribution != plugin.ConfidenceTentative {
				t.Fatalf("inert reflection reached %s, want tentative at most", c.Evidence.ConfidenceContribution)
			}
		}
	})

	t.Run("send budget holds", func(t *testing.T) {
		assertSendBudget(t, spec, src, 60, "POST", "body")
	})

	t.Run("no new sandbox surface", func(t *testing.T) {
		assertOracleSurface(t, src,
			[]string{"host.oracles.reflection"},
			[]string{"host.oracles.stored", "host.oracles.differential", "host.oracles.error"})
	})
}

// TestSSRFJSONBodyOOBE2E proves the JSON-body OOB discipline.
// What: Executes ssrf-json-body-oob.js with OOB enabled and disabled.
// Why: A blind SSRF claim needs a matched callback token; without a server the
// plugin must send nothing rather than emit tentative noise.
func TestSSRFJSONBodyOOBE2E(t *testing.T) {
	spec, src := loadTier2(t, "plugins/ssrf/ssrf-json-body-oob.js", "ssrf-json-body-oob")
	point := jsonSinkPoint()

	t.Run("callback confirms the JSON field", func(t *testing.T) {
		var jsonContentType, bodyCarriedCallback atomic.Bool
		env := &loader.JSEnv{
			Points:         []loader.JSPoint{point},
			OOBEnabled:     true,
			OOBNamespace:   "scan_e2e",
			OOBCorrelation: "c_json_body",
			Send: func(p loader.JSPoint) (loader.JSResponse, error) {
				h := map[string]string{"Content-Type": "application/json"}
				if strings.Contains(strings.ToLower(jsHeaderValue(p.Headers, "Content-Type")), "json") {
					jsonContentType.Store(true)
				}
				if strings.Contains(p.Value, "c_json_body") || strings.Contains(p.Value, "oob.example") {
					bodyCarriedCallback.Store(true)
				}
				return loader.JSResponse{Status: 200, Headers: h, Body: `{"status":"queued"}`, URL: p.URL}, nil
			},
			OOBCallbackSeen: func(id string) bool { return id == "c_json_body" },
		}
		cands, err := loader.ExecuteJS(context.Background(), spec, src, env, 10*time.Second)
		if err != nil {
			t.Fatalf("execute: %v", err)
		}
		if len(cands) != 1 {
			t.Fatalf("one SSRF candidate expected, got %d", len(cands))
		}
		ev := cands[0].Evidence
		if ev == nil || ev.Verdict != oracle.VerdictAccept || ev.ConfidenceContribution != plugin.ConfidenceConfirmed {
			t.Fatalf("confirmed evidence required: %+v", cands[0])
		}
		if cands[0].Candidate.OracleName != "oob" {
			t.Fatalf("oracle must stay oob, got %q", cands[0].Candidate.OracleName)
		}
		if !jsonContentType.Load() || !bodyCarriedCallback.Load() {
			t.Fatal("the callback URL must be sent inside an application/json body")
		}
	})

	t.Run("without an OOB server nothing is sent", func(t *testing.T) {
		var sends atomic.Int64
		env := &loader.JSEnv{
			Points:     []loader.JSPoint{point},
			OOBEnabled: false,
			Send: func(p loader.JSPoint) (loader.JSResponse, error) {
				sends.Add(1)
				return loader.JSResponse{Status: 200, Body: "neutral", URL: p.URL}, nil
			},
		}
		cands, err := loader.ExecuteJS(context.Background(), spec, src, env, 10*time.Second)
		if err != nil {
			t.Fatalf("execute: %v", err)
		}
		if len(cands) != 0 {
			t.Fatalf("no OOB server means no finding, got %d", len(cands))
		}
		if sends.Load() != 0 {
			t.Fatalf("no OOB server means no request, got %d sends", sends.Load())
		}
	})

	t.Run("send budget holds", func(t *testing.T) {
		points := make([]loader.JSPoint, 60)
		for i := range points {
			points[i] = loader.JSPoint{
				URL:           "http://example.com/api/" + itoaTest(i),
				Method:        "POST",
				ParamName:     "url",
				ParamLocation: "body",
			}
		}
		var sends atomic.Int64
		env := &loader.JSEnv{
			Points:         points,
			OOBEnabled:     true,
			OOBNamespace:   "scan_e2e",
			OOBCorrelation: "c_json_body",
			Send: func(p loader.JSPoint) (loader.JSResponse, error) {
				sends.Add(1)
				return loader.JSResponse{Status: 200, Body: "neutral", URL: p.URL}, nil
			},
			OOBCallbackSeen: func(string) bool { return false },
		}
		if _, err := loader.ExecuteJS(context.Background(), spec, src, env, 2*time.Second); err != nil {
			t.Fatalf("execute: %v", err)
		}
		if got := sends.Load(); got > 40 {
			t.Fatalf("send budget exceeded: got %d, want <= 40", got)
		}
	})

	t.Run("no new sandbox surface", func(t *testing.T) {
		assertOracleSurface(t, src,
			[]string{"host.oob.generate", "host.oracles.oobAny"},
			[]string{"host.oracles.reflection", "host.oracles.differential", "host.oracles.timing"})
	})
}

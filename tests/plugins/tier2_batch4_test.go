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

// TestXSSReflectedURLContextE2E proves the javascript-scheme URL-sink discipline.
// What: Executes xss-reflected-url-context.js against a mocked renderer that
// reflects the value into an href sink.
// Why: A value landing inside href/src needs no markup, only a scheme; Tier 1
// sends one fixed markup payload per file, so it cannot pick the scheme payload
// for exactly the points whose response is a URL sink. The claim must stay with
// the reflection oracle (url-executable context plus a clean control).
func TestXSSReflectedURLContextE2E(t *testing.T) {
	spec, src := loadTier2(t, "plugins/xss/xss-reflected-url-context.js", "xss-reflected-url-context")
	point := loader.JSPoint{URL: "http://example.com/go", Method: "GET", ParamName: "next", ParamLocation: "query"}

	t.Run("javascript scheme inside an href confirms", func(t *testing.T) {
		var sawScheme atomic.Bool
		env := &loader.JSEnv{
			Points: []loader.JSPoint{point},
			Canary: "gash_url_e2e",
			Send: func(p loader.JSPoint) (loader.JSResponse, error) {
				h := map[string]string{"Content-Type": "text/html"}
				if strings.HasPrefix(p.Value, "javascript:") || strings.HasPrefix(p.Value, "JaVaScRiPt:") {
					sawScheme.Store(true)
					return loader.JSResponse{Status: 200, Headers: h, Body: "<html><body><a href=\"" + p.Value + "\">click</a></body></html>", URL: p.URL}, nil
				}
				return loader.JSResponse{Status: 200, Headers: h, Body: "<html><body><a href=\"#\">click</a></body></html>", URL: p.URL}, nil
			},
		}
		cands, err := loader.ExecuteJS(context.Background(), spec, src, env, 10*time.Second)
		if err != nil {
			t.Fatalf("execute: %v", err)
		}
		if len(cands) != 1 {
			t.Fatalf("one URL-sink reflected-XSS candidate expected, got %d", len(cands))
		}
		ev := cands[0].Evidence
		if ev == nil || ev.Verdict != oracle.VerdictAccept || ev.ConfidenceContribution != plugin.ConfidenceStaticExecution {
			t.Fatalf("static-execution-evidence required: %+v", cands[0])
		}
		if cands[0].Candidate.OracleName != "reflection" {
			t.Fatalf("oracle must stay reflection, got %q", cands[0].Candidate.OracleName)
		}
		if ev.Artifacts["context"] != "url-executable" {
			t.Fatalf("context must be url-executable, got %q", ev.Artifacts["context"])
		}
		if !sawScheme.Load() {
			t.Fatal("the probe must send a javascript: scheme payload")
		}
	})

	t.Run("fragment or text sink rejects", func(t *testing.T) {
		env := &loader.JSEnv{
			Points: []loader.JSPoint{point},
			Canary: "gash_url_e2e",
			Send: func(p loader.JSPoint) (loader.JSResponse, error) {
				h := map[string]string{"Content-Type": "text/html"}
				// The value is reflected as page text, never into a URL sink.
				return loader.JSResponse{Status: 200, Headers: h, Body: "<html><body><p>you searched for " + p.Value + "</p></body></html>", URL: p.URL}, nil
			},
		}
		cands, err := loader.ExecuteJS(context.Background(), spec, src, env, 10*time.Second)
		if err != nil {
			t.Fatalf("execute: %v", err)
		}
		if len(cands) != 0 {
			t.Fatalf("a non-URL sink must not confirm, got %d", len(cands))
		}
	})

	t.Run("send budget holds", func(t *testing.T) {
		assertSendBudget(t, spec, src, 40, "GET", "query")
	})

	t.Run("no new sandbox surface", func(t *testing.T) {
		assertOracleSurface(t, src,
			[]string{"host.oracles.reflection"},
			[]string{"host.oracles.error", "host.oracles.differential", "host.oracles.timing", "host.oracles.stored"})
	})
}

// TestXSSStoredHeaderTwoStepE2E proves the header-borne stored-XSS workflow.
// What: Executes xss-stored-header-two-step.js against a stateful store/render
// mock whose write channel is the Referer header.
// Why: Applications persist request metadata, so the write needs no form at
// all; the value travels as a point-level header and the render is re-read
// afterwards. A sibling page that never received the payload is the only clean
// control, and the claim stays with the stored oracle.
func TestXSSStoredHeaderTwoStepE2E(t *testing.T) {
	spec, src := loadTier2(t, "plugins/xss/xss-stored-header-two-step.js", "xss-stored-header-two-step")
	const (
		canary  = "gash_header_e2e"
		primary = "http://example.com/panel"
		sibling = "http://example.com/sibling"
	)
	points := []loader.JSPoint{
		{URL: primary, Method: "GET", ParamName: "q", ParamLocation: "query"},
		{URL: sibling, Method: "GET", ParamName: "q", ParamLocation: "query"},
	}

	t.Run("header-borne store renders executable", func(t *testing.T) {
		var refererSeen atomic.Bool
		stored := map[string]string{}
		env := &loader.JSEnv{
			Points: points,
			Canary: canary,
			Send: func(p loader.JSPoint) (loader.JSResponse, error) {
				h := map[string]string{"Content-Type": "text/html"}
				if ref := jsHeaderValue(p.Headers, "Referer"); ref != "" {
					refererSeen.Store(true)
					// Only the primary page persists the header.
					if p.URL == primary {
						stored[p.URL] = ref
					}
					return loader.JSResponse{Status: 200, Headers: h, Body: "<html><body>stored</body></html>", URL: p.URL}, nil
				}
				if payload, ok := stored[p.URL]; ok {
					return loader.JSResponse{Status: 200, Headers: h, Body: "<html><body><div class=\"referrer\">" + payload + "</div></body></html>", URL: p.URL}, nil
				}
				return loader.JSResponse{Status: 200, Headers: h, Body: "<html><body><div class=\"referrer\">direct</div></body></html>", URL: p.URL}, nil
			},
		}
		cands, err := loader.ExecuteJS(context.Background(), spec, src, env, 10*time.Second)
		if err != nil {
			t.Fatalf("execute: %v", err)
		}
		if len(cands) != 1 {
			t.Fatalf("one stored candidate expected, got %d", len(cands))
		}
		ev := cands[0].Evidence
		if ev == nil || ev.Verdict != oracle.VerdictAccept || ev.ConfidenceContribution != plugin.ConfidenceStaticExecution {
			t.Fatalf("static-execution-evidence required: %+v", cands[0])
		}
		if cands[0].Candidate.OracleName != "stored" {
			t.Fatalf("oracle must stay stored, got %q", cands[0].Candidate.OracleName)
		}
		if !refererSeen.Load() {
			t.Fatal("the write exchange must carry the Referer header")
		}
	})

	t.Run("unpersisted header rejects", func(t *testing.T) {
		env := &loader.JSEnv{
			Points: points,
			Canary: canary,
			Send: func(p loader.JSPoint) (loader.JSResponse, error) {
				h := map[string]string{"Content-Type": "text/html"}
				return loader.JSResponse{Status: 200, Headers: h, Body: "<html><body><div class=\"referrer\">direct</div></body></html>", URL: p.URL}, nil
			},
		}
		cands, err := loader.ExecuteJS(context.Background(), spec, src, env, 10*time.Second)
		if err != nil {
			t.Fatalf("execute: %v", err)
		}
		if len(cands) != 0 {
			t.Fatalf("a header that is not persisted must not confirm, got %d", len(cands))
		}
	})

	t.Run("send budget holds", func(t *testing.T) {
		assertSendBudget(t, spec, src, 60, "GET", "query")
	})

	t.Run("no new sandbox surface", func(t *testing.T) {
		assertOracleSurface(t, src,
			[]string{"host.oracles.storedExecution"},
			[]string{"host.oracles.reflection", "host.oracles.differential", "host.oracles.error"})
	})
}

// TestOpenRedirectUserinfoConfusionE2E proves the multi-variant redirect proof.
// What: Executes open-redirect-userinfo-confusion.js against a mocked redirector
// whose Location is decided by the injected host.
// Why: A single-payload Tier 1 file cannot reach protocol-relative, userinfo,
// suffix and fragment confusion shapes together, and the payload host is a
// per-run canary so a graded Location can only come from our own payload.
func TestOpenRedirectUserinfoConfusionE2E(t *testing.T) {
	spec, src := loadTier2(t, "plugins/redirect/open-redirect-userinfo-confusion.js", "open-redirect-userinfo-confusion")
	const canary = "gash_redirect_e2e"
	const evil = canary + ".gash-redirect.example"
	point := loader.JSPoint{URL: "http://example.com/go", Method: "GET", ParamName: "next", ParamLocation: "query"}

	t.Run("confusion hop to the payload host confirms", func(t *testing.T) {
		env := &loader.JSEnv{
			Points: []loader.JSPoint{point},
			Canary: canary,
			Send: func(p loader.JSPoint) (loader.JSResponse, error) {
				h := map[string]string{"Content-Type": "text/html"}
				if strings.Contains(p.Value, evil) {
					h["Location"] = "https://" + evil + "/landing"
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
	})

	t.Run("relative hop rejects", func(t *testing.T) {
		env := &loader.JSEnv{
			Points: []loader.JSPoint{point},
			Canary: canary,
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
			t.Fatalf("a relative hop must not confirm, got %d", len(cands))
		}
	})

	t.Run("send budget holds", func(t *testing.T) {
		assertSendBudget(t, spec, src, 40, "GET", "query")
	})

	t.Run("no new sandbox surface", func(t *testing.T) {
		assertOracleSurface(t, src,
			[]string{"host.oracles.redirect"},
			[]string{"host.oracles.reflection", "host.oracles.stored", "host.oracles.differential"})
	})
}

// TestPrototypePollutionJSONBodyE2E proves the nested-object merge gap.
// What: Executes prototype-pollution-json-body.js against a mocked JSON API
// that distinguishes a nested __proto__ member from a plain object.
// Why: The query-string check cannot reach a JSON field merged server-side; the
// dangerous shape is the discovered field sent as an object carrying a
// __proto__ member, which only a script can rebuild per field. An echoing body
// is reflection and must reject.
func TestPrototypePollutionJSONBodyE2E(t *testing.T) {
	spec, src := loadTier2(t, "plugins/prototype-pollution/prototype-pollution-json-body.js", "prototype-pollution-json-body")
	point := loader.JSPoint{URL: "http://example.com/api/profile", Method: "POST", ParamName: "profile", ParamLocation: "body"}

	t.Run("nested __proto__ object diverges", func(t *testing.T) {
		var jsonContentType atomic.Bool
		env := &loader.JSEnv{
			Points: []loader.JSPoint{point},
			Send: func(p loader.JSPoint) (loader.JSResponse, error) {
				if strings.Contains(strings.ToLower(jsHeaderValue(p.Headers, "Content-Type")), "json") {
					jsonContentType.Store(true)
				}
				h := map[string]string{"Content-Type": "application/json"}
				switch {
				case strings.Contains(p.Value, "__proto__"):
					return loader.JSResponse{Status: 200, Headers: h, Body: `{"updated":true,"polluted":true}`, URL: p.URL}, nil
				case strings.Contains(p.Value, "gashPolluted"):
					return loader.JSResponse{Status: 200, Headers: h, Body: `{"updated":true,"polluted":false}`, URL: p.URL}, nil
				default:
					return loader.JSResponse{Status: 200, Headers: h, Body: `{"updated":false,"error":"invalid body"}`, URL: p.URL}, nil
				}
			},
		}
		cands, err := loader.ExecuteJS(context.Background(), spec, src, env, 10*time.Second)
		if err != nil {
			t.Fatalf("execute: %v", err)
		}
		if len(cands) != 1 {
			t.Fatalf("one prototype-pollution candidate expected, got %d", len(cands))
		}
		ev := cands[0].Evidence
		if ev == nil || ev.Verdict != oracle.VerdictAccept || ev.ConfidenceContribution != plugin.ConfidenceConfirmed {
			t.Fatalf("confirmed evidence required: %+v", cands[0])
		}
		if cands[0].Candidate.OracleName != "differential" {
			t.Fatalf("oracle must stay differential, got %q", cands[0].Candidate.OracleName)
		}
		if !jsonContentType.Load() {
			t.Fatal("the object must be sent with a JSON content type")
		}
	})

	t.Run("echoed member is reflection, not a merge", func(t *testing.T) {
		env := &loader.JSEnv{
			Points: []loader.JSPoint{point},
			Send: func(p loader.JSPoint) (loader.JSResponse, error) {
				h := map[string]string{"Content-Type": "application/json"}
				return loader.JSResponse{Status: 200, Headers: h, Body: p.Value, URL: p.URL}, nil
			},
		}
		cands, err := loader.ExecuteJS(context.Background(), spec, src, env, 10*time.Second)
		if err != nil {
			t.Fatalf("execute: %v", err)
		}
		if len(cands) != 0 {
			t.Fatalf("an echoing backend must not confirm, got %d", len(cands))
		}
	})

	t.Run("identical merge rejects", func(t *testing.T) {
		env := &loader.JSEnv{
			Points: []loader.JSPoint{point},
			Send: func(p loader.JSPoint) (loader.JSResponse, error) {
				h := map[string]string{"Content-Type": "application/json"}
				return loader.JSResponse{Status: 200, Headers: h, Body: `{"updated":true}`, URL: p.URL}, nil
			},
		}
		cands, err := loader.ExecuteJS(context.Background(), spec, src, env, 10*time.Second)
		if err != nil {
			t.Fatalf("execute: %v", err)
		}
		if len(cands) != 0 {
			t.Fatalf("an identical merge must not confirm, got %d", len(cands))
		}
	})

	t.Run("send budget holds", func(t *testing.T) {
		assertSendBudget(t, spec, src, 60, "POST", "body")
	})

	t.Run("no new sandbox surface", func(t *testing.T) {
		assertOracleSurface(t, src,
			[]string{"host.oracles.differential"},
			[]string{"host.oracles.error", "host.oracles.timing", "host.oracles.reflection"})
	})
}

// TestHPPQueryArrayNotationE2E proves the bracket-array pollution proof.
// What: Executes hpp-query-array-notation.js against a mocked binder that is
// array-aware, rebuilding the raw query per point.
// Why: Bracket notation is a different parser path from duplicate keys; an
// array-aware binder hands one element to the logic as a scalar and two as a
// slice. Building that raw query per point is not expressible in Tier 1.
func TestHPPQueryArrayNotationE2E(t *testing.T) {
	spec, src := loadTier2(t, "plugins/hpp/hpp-query-array-notation.js", "hpp-query-array-notation")
	point := loader.JSPoint{URL: "http://example.com/search?lang=en", Method: "GET", ParamName: "filter", ParamLocation: "query"}

	t.Run("two array elements diverge from one", func(t *testing.T) {
		var otherParamSurvived atomic.Bool
		env := &loader.JSEnv{
			Points: []loader.JSPoint{point},
			Send: func(p loader.JSPoint) (loader.JSResponse, error) {
				if strings.Contains(p.URL, "lang=en") {
					otherParamSurvived.Store(true)
				}
				h := map[string]string{"Content-Type": "application/json"}
				switch {
				case strings.Contains(p.URL, "%5B%5D=2"):
					return loader.JSResponse{Status: 200, Headers: h, Body: `{"items":["1","2"]}`, URL: p.URL}, nil
				case strings.Contains(p.URL, "%5B%5D=1"):
					return loader.JSResponse{Status: 200, Headers: h, Body: `{"items":["1"]}`, URL: p.URL}, nil
				default:
					return loader.JSResponse{Status: 200, Headers: h, Body: `{"items":"gash-control-neutral"}`, URL: p.URL}, nil
				}
			},
		}
		cands, err := loader.ExecuteJS(context.Background(), spec, src, env, 10*time.Second)
		if err != nil {
			t.Fatalf("execute: %v", err)
		}
		if len(cands) != 1 {
			t.Fatalf("one HPP candidate expected, got %d", len(cands))
		}
		ev := cands[0].Evidence
		if ev == nil || ev.Verdict != oracle.VerdictAccept || ev.ConfidenceContribution != plugin.ConfidenceConfirmed {
			t.Fatalf("confirmed evidence required: %+v", cands[0])
		}
		if cands[0].Candidate.OracleName != "differential" {
			t.Fatalf("oracle must stay differential, got %q", cands[0].Candidate.OracleName)
		}
		if !otherParamSurvived.Load() {
			t.Fatal("the sibling query parameter must survive the rebuild")
		}
	})

	t.Run("identical responses reject", func(t *testing.T) {
		env := &loader.JSEnv{
			Points: []loader.JSPoint{point},
			Send: func(p loader.JSPoint) (loader.JSResponse, error) {
				h := map[string]string{"Content-Type": "application/json"}
				return loader.JSResponse{Status: 200, Headers: h, Body: `{"items":["1"]}`, URL: p.URL}, nil
			},
		}
		cands, err := loader.ExecuteJS(context.Background(), spec, src, env, 10*time.Second)
		if err != nil {
			t.Fatalf("execute: %v", err)
		}
		if len(cands) != 0 {
			t.Fatalf("an array-blind binder must not confirm, got %d", len(cands))
		}
	})

	t.Run("send budget holds", func(t *testing.T) {
		assertSendBudget(t, spec, src, 60, "GET", "query")
	})

	t.Run("no new sandbox surface", func(t *testing.T) {
		assertOracleSurface(t, src,
			[]string{"host.oracles.differential"},
			[]string{"host.oracles.error", "host.oracles.timing", "host.oracles.reflection"})
	})
}

// TestLDAPJSONBodyTimingE2E proves the JSON-body blind LDAP timing discipline.
// What: Executes ldap-injection-json-body-timing.js against a mocked directory
// that only the wide filter closure makes slow.
// Why: A directory that returns the same page and has no egress is invisible to
// the differential and OOB plugins; the filter-evaluation cost is observable
// in-band, and three repeats on both branches are required so one slow response
// can never confirm. The ceiling stays firm.
func TestLDAPJSONBodyTimingE2E(t *testing.T) {
	spec, src := loadTier2(t, "plugins/ldap/ldap-injection-json-body-timing.js", "ldap-injection-json-body-timing")
	point := loader.JSPoint{URL: "http://example.com/api/login", Method: "POST", ParamName: "user", ParamLocation: "body"}

	t.Run("filter closure delay confirms at firm", func(t *testing.T) {
		env := &loader.JSEnv{
			Points: []loader.JSPoint{point},
			Send: func(p loader.JSPoint) (loader.JSResponse, error) {
				h := map[string]string{"Content-Type": "application/json"}
				rtt := 120.0
				if strings.Contains(p.Value, "*)(cn=*") || strings.Contains(p.Value, "*)(uid=*") {
					rtt = 5500
				}
				return loader.JSResponse{Status: 200, Headers: h, Body: `{"error":"invalid credentials"}`, URL: p.URL, RTTMs: rtt}, nil
			},
		}
		cands, err := loader.ExecuteJS(context.Background(), spec, src, env, 10*time.Second)
		if err != nil {
			t.Fatalf("execute: %v", err)
		}
		if len(cands) != 1 {
			t.Fatalf("one timing candidate expected, got %d", len(cands))
		}
		ev := cands[0].Evidence
		if ev == nil || ev.Verdict != oracle.VerdictAccept || ev.ConfidenceContribution != plugin.ConfidenceFirm {
			t.Fatalf("firm evidence required: %+v", cands[0])
		}
		if cands[0].Candidate.OracleName != "timing" {
			t.Fatalf("oracle must stay timing, got %q", cands[0].Candidate.OracleName)
		}
	})

	t.Run("uniform latency rejects", func(t *testing.T) {
		env := &loader.JSEnv{
			Points: []loader.JSPoint{point},
			Send: func(p loader.JSPoint) (loader.JSResponse, error) {
				h := map[string]string{"Content-Type": "application/json"}
				return loader.JSResponse{Status: 200, Headers: h, Body: `{"error":"invalid credentials"}`, URL: p.URL, RTTMs: 120}, nil
			},
		}
		cands, err := loader.ExecuteJS(context.Background(), spec, src, env, 10*time.Second)
		if err != nil {
			t.Fatalf("execute: %v", err)
		}
		if len(cands) != 0 {
			t.Fatalf("uniform latency must not confirm, got %d", len(cands))
		}
	})

	t.Run("send budget holds", func(t *testing.T) {
		assertSendBudget(t, spec, src, 60, "POST", "body")
	})

	t.Run("mode is declared in oracle_params", func(t *testing.T) {
		lower := strings.ToLower(src)
		if !strings.Contains(lower, "min_delay_ms: 5000") || !strings.Contains(lower, "repeats: 3") {
			t.Fatal("min_delay_ms and repeats must be declared in the frontmatter oracle_params block")
		}
		if !strings.Contains(lower, "host.oracles.timing") {
			t.Fatal("must use host.oracles.timing")
		}
	})
}

// TestXXEJSONBodyErrorE2E proves the JSON-embedded error-based XXE discipline.
// What: Executes xxe-json-body-error.js against a mocked JSON importer whose
// parser fails only for the entity-bearing document.
// Why: A parser that resolves entities but has no egress still discloses the
// failure in-band, and that signature only appears for the entity document. The
// probe never points at a local path, so it proves resolution, not file read.
func TestXXEJSONBodyErrorE2E(t *testing.T) {
	spec, src := loadTier2(t, "plugins/xxe/xxe-json-body-error.js", "xxe-json-body-error")
	point := loader.JSPoint{URL: "http://example.com/api/import", Method: "POST", ParamName: "xml", ParamLocation: "body"}
	const signature = "<html><body>XML parser error: could not resolve external entity</body></html>"

	t.Run("entity-specific parser failure confirms at firm", func(t *testing.T) {
		var jsonContentType atomic.Bool
		env := &loader.JSEnv{
			Points: []loader.JSPoint{point},
			Send: func(p loader.JSPoint) (loader.JSResponse, error) {
				if strings.Contains(strings.ToLower(jsHeaderValue(p.Headers, "Content-Type")), "json") {
					jsonContentType.Store(true)
				}
				h := map[string]string{"Content-Type": "text/html"}
				if strings.Contains(p.Value, "gash-xxe-unresolvable.example") {
					return loader.JSResponse{Status: 500, Headers: h, Body: signature, URL: p.URL}, nil
				}
				return loader.JSResponse{Status: 200, Headers: map[string]string{"Content-Type": "application/json"}, Body: `{"parsed":true}`, URL: p.URL}, nil
			},
		}
		cands, err := loader.ExecuteJS(context.Background(), spec, src, env, 10*time.Second)
		if err != nil {
			t.Fatalf("execute: %v", err)
		}
		if len(cands) != 1 {
			t.Fatalf("one XXE candidate expected, got %d", len(cands))
		}
		ev := cands[0].Evidence
		if ev == nil || ev.Verdict != oracle.VerdictAccept || ev.ConfidenceContribution != plugin.ConfidenceFirm {
			t.Fatalf("firm evidence required: %+v", cands[0])
		}
		if cands[0].Candidate.OracleName != "error" {
			t.Fatalf("oracle must stay error, got %q", cands[0].Candidate.OracleName)
		}
		if !jsonContentType.Load() {
			t.Fatal("the document must be carried inside a JSON body")
		}
	})

	t.Run("universal parser failure rejects", func(t *testing.T) {
		env := &loader.JSEnv{
			Points: []loader.JSPoint{point},
			Send: func(p loader.JSPoint) (loader.JSResponse, error) {
				h := map[string]string{"Content-Type": "text/html"}
				return loader.JSResponse{Status: 500, Headers: h, Body: signature, URL: p.URL}, nil
			},
		}
		cands, err := loader.ExecuteJS(context.Background(), spec, src, env, 10*time.Second)
		if err != nil {
			t.Fatalf("execute: %v", err)
		}
		if len(cands) != 0 {
			t.Fatalf("a signature present for every document must not confirm, got %d", len(cands))
		}
	})

	t.Run("send budget holds", func(t *testing.T) {
		assertSendBudget(t, spec, src, 40, "POST", "body")
	})

	t.Run("mode is declared in oracle_params", func(t *testing.T) {
		lower := strings.ToLower(src)
		if !strings.Contains(lower, "mode: generic_error") {
			t.Fatal("the generic_error mode must be declared in oracle_params")
		}
		assertOracleSurface(t, src,
			[]string{"host.oracles.error"},
			[]string{"host.oracles.differential", "host.oracles.timing", "host.oracles.reflection"})
	})
}

// TestCommandInjectionJSONBodyErrorE2E proves the JSON-body error-based command
// injection discipline.
// What: Executes command-injection-json-body-error.js against a mocked converter
// whose shell complains only for a broken fragment.
// Why: An endpoint that shells out but has no egress and a small command budget
// is invisible to the OOB and timing plugins; a shell handed a broken fragment
// still reports its own syntax error in-band, and the payloads are inert
// fragments that provoke the complaint without running anything.
func TestCommandInjectionJSONBodyErrorE2E(t *testing.T) {
	spec, src := loadTier2(t, "plugins/command-injection/command-injection-json-body-error.js", "command-injection-json-body-error")
	point := loader.JSPoint{URL: "http://example.com/api/convert", Method: "POST", ParamName: "name", ParamLocation: "body"}
	fragments := []string{"$(", "; ;", "`", "| |", "&& (", "; if"}
	const signature = "<html><body>sh: 1: Syntax error: end of file unexpected</body></html>"
	hasFragment := func(v string) bool {
		for _, f := range fragments {
			if strings.Contains(v, f) {
				return true
			}
		}
		return false
	}

	t.Run("shell syntax failure confirms at firm", func(t *testing.T) {
		var jsonContentType atomic.Bool
		env := &loader.JSEnv{
			Points: []loader.JSPoint{point},
			Send: func(p loader.JSPoint) (loader.JSResponse, error) {
				if strings.Contains(strings.ToLower(jsHeaderValue(p.Headers, "Content-Type")), "json") {
					jsonContentType.Store(true)
				}
				h := map[string]string{"Content-Type": "text/html"}
				if hasFragment(p.Value) {
					return loader.JSResponse{Status: 500, Headers: h, Body: signature, URL: p.URL}, nil
				}
				return loader.JSResponse{Status: 200, Headers: map[string]string{"Content-Type": "application/json"}, Body: `{"status":"converted"}`, URL: p.URL}, nil
			},
		}
		cands, err := loader.ExecuteJS(context.Background(), spec, src, env, 10*time.Second)
		if err != nil {
			t.Fatalf("execute: %v", err)
		}
		if len(cands) != 1 {
			t.Fatalf("one command-injection candidate expected, got %d", len(cands))
		}
		ev := cands[0].Evidence
		if ev == nil || ev.Verdict != oracle.VerdictAccept || ev.ConfidenceContribution != plugin.ConfidenceFirm {
			t.Fatalf("firm evidence required: %+v", cands[0])
		}
		if cands[0].Candidate.OracleName != "error" {
			t.Fatalf("oracle must stay error, got %q", cands[0].Candidate.OracleName)
		}
		if !jsonContentType.Load() {
			t.Fatal("the fragment must be carried inside a JSON body")
		}
	})

	t.Run("universal failure rejects", func(t *testing.T) {
		env := &loader.JSEnv{
			Points: []loader.JSPoint{point},
			Send: func(p loader.JSPoint) (loader.JSResponse, error) {
				h := map[string]string{"Content-Type": "text/html"}
				return loader.JSResponse{Status: 500, Headers: h, Body: signature, URL: p.URL}, nil
			},
		}
		cands, err := loader.ExecuteJS(context.Background(), spec, src, env, 10*time.Second)
		if err != nil {
			t.Fatalf("execute: %v", err)
		}
		if len(cands) != 0 {
			t.Fatalf("a failure present for every value must not confirm, got %d", len(cands))
		}
	})

	t.Run("send budget holds", func(t *testing.T) {
		assertSendBudget(t, spec, src, 40, "POST", "body")
	})

	t.Run("mode is declared in oracle_params", func(t *testing.T) {
		lower := strings.ToLower(src)
		if !strings.Contains(lower, "mode: generic_error") {
			t.Fatal("the generic_error mode must be declared in oracle_params")
		}
		assertOracleSurface(t, src,
			[]string{"host.oracles.error"},
			[]string{"host.oracles.differential", "host.oracles.timing", "host.oracles.reflection"})
	})
}

// TestLog4ShellJSONBodyOOBE2E proves the JSON-body JNDI callback discipline.
// What: Executes log4shell-json-body-oob.js with OOB enabled and disabled.
// Why: The JNDI family is a request-channel problem and an API body is a third
// channel Tier 1 cannot rebuild; every variant carries its own token so a
// callback names the exact field, and without a server the plugin returns
// nothing rather than inventing a tentative finding.
func TestLog4ShellJSONBodyOOBE2E(t *testing.T) {
	spec, src := loadTier2(t, "plugins/command-injection/log4shell-json-body-oob.js", "log4shell-json-body-oob")
	point := loader.JSPoint{URL: "http://example.com/api/log", Method: "POST", ParamName: "message", ParamLocation: "body"}

	t.Run("jndi callback confirms", func(t *testing.T) {
		var jsonContentType, bodyCarriedCallback atomic.Bool
		env := &loader.JSEnv{
			Points:         []loader.JSPoint{point},
			OOBEnabled:     true,
			OOBNamespace:   "log4shell-json",
			OOBCorrelation: "c_l4j_e2e",
			Send: func(p loader.JSPoint) (loader.JSResponse, error) {
				if strings.Contains(strings.ToLower(jsHeaderValue(p.Headers, "Content-Type")), "json") {
					jsonContentType.Store(true)
				}
				if strings.Contains(p.Value, "oob.example") || strings.Contains(p.Value, "c_l4j_e2e") {
					bodyCarriedCallback.Store(true)
				}
				return loader.JSResponse{Status: 200, Headers: map[string]string{"Content-Type": "application/json"}, Body: `{"status":"queued"}`, URL: p.URL}, nil
			},
			OOBCallbackSeen: func(string) bool { return true },
		}
		cands, err := loader.ExecuteJS(context.Background(), spec, src, env, 10*time.Second)
		if err != nil {
			t.Fatalf("execute: %v", err)
		}
		if len(cands) != 1 {
			t.Fatalf("one Log4Shell candidate expected, got %d", len(cands))
		}
		ev := cands[0].Evidence
		if ev == nil || ev.Verdict != oracle.VerdictAccept || ev.ConfidenceContribution != plugin.ConfidenceConfirmed {
			t.Fatalf("confirmed evidence required: %+v", cands[0])
		}
		if cands[0].Candidate.OracleName != "oob" {
			t.Fatalf("oracle must stay oob, got %q", cands[0].Candidate.OracleName)
		}
		if !jsonContentType.Load() || !bodyCarriedCallback.Load() {
			t.Fatal("the callback must be carried inside a raw application/json body")
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
		if len(cands) != 0 || sends.Load() != 0 {
			t.Fatalf("no OOB server means no request and no finding: cands=%d sends=%d", len(cands), sends.Load())
		}
	})

	t.Run("send budget holds", func(t *testing.T) {
		points := make([]loader.JSPoint, 60)
		for i := range points {
			points[i] = loader.JSPoint{
				URL:           "http://example.com/api/" + itoaTest(i),
				Method:        "POST",
				ParamName:     "message",
				ParamLocation: "body",
			}
		}
		var sends atomic.Int64
		env := &loader.JSEnv{
			Points:          points,
			OOBEnabled:      true,
			OOBNamespace:    "log4shell-json",
			OOBCorrelation:  "c_l4j_e2e",
			OOBCallbackSeen: func(string) bool { return false },
			Send: func(p loader.JSPoint) (loader.JSResponse, error) {
				sends.Add(1)
				return loader.JSResponse{Status: 200, Body: "neutral", URL: p.URL}, nil
			},
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
			[]string{"host.oracles.error", "host.oracles.differential", "host.oracles.timing"})
	})
}

// TestFileUploadSniffingMismatchE2E proves the content-sniffing serve-back proof.
// What: Executes file-upload-sniffing-mismatch.js against a mocked upload plus
// static server whose served content type decides the verdict.
// Why: Declaration and extension are both inert here; only the served content
// type answers whether the server ignored them, which is exactly what the
// upload-served oracle grades. A sibling name never uploaded is the control.
func TestFileUploadSniffingMismatchE2E(t *testing.T) {
	spec, src := loadTier2(t, "plugins/file-upload/file-upload-sniffing-mismatch.js", "file-upload-sniffing-mismatch")
	point := loader.JSPoint{URL: "http://example.com/api/upload", Method: "POST", ParamName: "file", ParamLocation: "body"}
	const canary = "gash_sniff_e2e"
	const token = canary + ".txt"
	const payload = `<svg xmlns="http://www.w3.org/2000/svg" onload="alert(` + canary + `)"></svg>`

	mkEnv := func(fetchType string, uploadStatus int, publishURL, dirtyControl bool, inertNameSeen, inertDeclSeen *atomic.Bool) *loader.JSEnv {
		return &loader.JSEnv{
			Points: []loader.JSPoint{point},
			Canary: canary,
			Send: func(p loader.JSPoint) (loader.JSResponse, error) {
				if p.ParamName == "" && strings.Contains(p.Value, `filename="`) {
					if inertNameSeen != nil && strings.Contains(p.Value, `filename="`+token+`"`) {
						inertNameSeen.Store(true)
					}
					if inertDeclSeen != nil && strings.Contains(p.Value, "application/octet-stream") {
						inertDeclSeen.Store(true)
					}
					body := `{"stored":true}`
					if publishURL {
						body = `{"url":"/media/` + token + `"}`
					}
					return loader.JSResponse{Status: uploadStatus, Headers: map[string]string{"Content-Type": "application/json"}, Body: body, URL: p.URL}, nil
				}
				// Fetch or control exchange.
				if strings.Contains(p.URL, "_never") && !dirtyControl {
					return loader.JSResponse{Status: 404, Headers: map[string]string{"Content-Type": "text/html"}, Body: "<html><body>not found</body></html>", URL: p.URL}, nil
				}
				return loader.JSResponse{Status: 200, Headers: map[string]string{"Content-Type": fetchType}, Body: payload, URL: p.URL}, nil
			},
		}
	}

	t.Run("sniffing server confirms", func(t *testing.T) {
		var inertNameSeen, inertDeclSeen atomic.Bool
		env := mkEnv("text/html", 200, true, false, &inertNameSeen, &inertDeclSeen)
		cands, err := loader.ExecuteJS(context.Background(), spec, src, env, 10*time.Second)
		if err != nil {
			t.Fatalf("execute: %v", err)
		}
		if len(cands) != 1 {
			t.Fatalf("one upload candidate expected, got %d", len(cands))
		}
		ev := cands[0].Evidence
		if ev == nil || ev.Verdict != oracle.VerdictAccept || ev.ConfidenceContribution != plugin.ConfidenceConfirmed {
			t.Fatalf("confirmed evidence required: %+v", cands[0])
		}
		if cands[0].Candidate.OracleName != "upload-served" {
			t.Fatalf("oracle must be upload-served, got %q", cands[0].Candidate.OracleName)
		}
		if !inertNameSeen.Load() || !inertDeclSeen.Load() {
			t.Fatal("the part must carry the inert name and the inert declaration")
		}
	})

	t.Run("honouring server stays firm", func(t *testing.T) {
		env := mkEnv("application/octet-stream", 200, true, false, nil, nil)
		cands, err := loader.ExecuteJS(context.Background(), spec, src, env, 10*time.Second)
		if err != nil {
			t.Fatalf("execute: %v", err)
		}
		if len(cands) != 1 {
			t.Fatalf("one candidate expected, got %d", len(cands))
		}
		if got := cands[0].Evidence.ConfidenceContribution; got != plugin.ConfidenceFirm {
			t.Fatalf("an honouring server must stay firm, got %s", got)
		}
	})

	t.Run("dirty control rejects", func(t *testing.T) {
		env := mkEnv("text/html", 200, true, true, nil, nil)
		cands, err := loader.ExecuteJS(context.Background(), spec, src, env, 10*time.Second)
		if err != nil {
			t.Fatalf("execute: %v", err)
		}
		if len(cands) != 0 {
			t.Fatalf("a dirty control must not confirm, got %d", len(cands))
		}
	})

	t.Run("rejected upload stays silent", func(t *testing.T) {
		env := mkEnv("text/html", 415, false, false, nil, nil)
		cands, err := loader.ExecuteJS(context.Background(), spec, src, env, 10*time.Second)
		if err != nil {
			t.Fatalf("execute: %v", err)
		}
		if len(cands) != 0 {
			t.Fatalf("a rejected upload must not confirm, got %d", len(cands))
		}
	})

	t.Run("send budget holds", func(t *testing.T) {
		assertSendBudget(t, spec, src, 40, "POST", "body")
	})

	t.Run("no new sandbox surface", func(t *testing.T) {
		assertOracleSurface(t, src,
			[]string{"host.oracles.uploadServed"},
			[]string{"host.oracles.stored", "host.oracles.reflection", "host.oracles.differential"})
	})
}

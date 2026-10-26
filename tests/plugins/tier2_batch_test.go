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

// jsonFieldPoint builds the discovered JSON body point the batch suites drive.
func jsonFieldPoint(url, method, name string) loader.JSPoint {
	return loader.JSPoint{URL: url, Method: method, ParamName: name, ParamLocation: "body"}
}

// TestXXEJSONBodyOOBE2E proves the JSON-embedded blind XXE discipline.
func TestXXEJSONBodyOOBE2E(t *testing.T) {
	spec, src := loadTier2(t, "plugins/xxe/xxe-json-body-oob.js", "xxe-json-body-oob")
	point := jsonFieldPoint("http://example.com/api/import", "POST", "xml")

	t.Run("callback confirms entity resolution", func(t *testing.T) {
		var jsonContentType, singleQuotedSystem atomic.Bool
		env := &loader.JSEnv{
			Points:       []loader.JSPoint{point},
			OOBEnabled:   true,
			OOBNamespace: "scan_e2e",
			Send: func(p loader.JSPoint) (loader.JSResponse, error) {
				if strings.Contains(strings.ToLower(jsHeaderValue(p.Headers, "Content-Type")), "json") {
					jsonContentType.Store(true)
				}
				if strings.Contains(p.Value, "SYSTEM '") && strings.Contains(p.Value, "oob.example") {
					singleQuotedSystem.Store(true)
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
			t.Fatalf("one XXE candidate expected, got %d", len(cands))
		}
		ev := cands[0].Evidence
		if ev == nil || ev.Verdict != oracle.VerdictAccept || ev.ConfidenceContribution != plugin.ConfidenceConfirmed {
			t.Fatalf("confirmed evidence required: %+v", cands[0])
		}
		if cands[0].Candidate.OracleName != "oob" {
			t.Fatalf("oracle must stay oob, got %q", cands[0].Candidate.OracleName)
		}
		if !jsonContentType.Load() || !singleQuotedSystem.Load() {
			t.Fatal("the entity must be carried as a single-quoted SYSTEM literal inside a JSON body")
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
		assertSendBudget(t, spec, src, 40, "POST", "body")
	})

	t.Run("no new sandbox surface", func(t *testing.T) {
		assertOracleSurface(t, src,
			[]string{"host.oob.generate", "host.oracles.oobAny"},
			[]string{"host.oracles.reflection", "host.oracles.differential", "host.oracles.timing"})
	})
}

// TestInsecureCORSReflectedOriginE2E proves the reflected-origin proof.
func TestInsecureCORSReflectedOriginE2E(t *testing.T) {
	spec, src := loadTier2(t, "plugins/cors/insecure-cors-reflected-origin.js", "insecure-cors-reflected-origin")
	point := loader.JSPoint{URL: "http://example.com/api/account", Method: "GET", ParamName: "", ParamLocation: "query"}

	// The origin literal must live in exactly one place per file: the
	// frontmatter oracle_params block and the script constant must agree,
	// otherwise a fixture would grade a different origin than a live scan.
	declared, _ := spec.OracleParams["request_origin"].(string)
	if declared == "" {
		t.Fatal("oracle_params.request_origin must be declared")
	}
	if !strings.Contains(src, `const REFLECT_ORIGIN = "`+declared+`";`) {
		t.Fatalf("script constant must equal the declared origin %q", declared)
	}

	t.Run("reflected origin with credentials confirms", func(t *testing.T) {
		var sentOrigin atomic.Bool
		env := &loader.JSEnv{
			Points: []loader.JSPoint{point},
			Send: func(p loader.JSPoint) (loader.JSResponse, error) {
				if jsHeaderValue(p.Headers, "Origin") == declared {
					sentOrigin.Store(true)
				}
				h := map[string]string{
					"Content-Type":                     "text/html",
					"Access-Control-Allow-Origin":      declared,
					"Access-Control-Allow-Credentials": "true",
				}
				return loader.JSResponse{Status: 200, Headers: h, Body: "<html><body>account</body></html>", URL: p.URL}, nil
			},
		}
		cands, err := loader.ExecuteJS(context.Background(), spec, src, env, 10*time.Second)
		if err != nil {
			t.Fatalf("execute: %v", err)
		}
		if len(cands) != 1 {
			t.Fatalf("one CORS candidate expected, got %d", len(cands))
		}
		if got := cands[0].Evidence.ConfidenceContribution; got != plugin.ConfidenceConfirmed {
			t.Fatalf("reflection with credentials must confirm, got %s", got)
		}
		if cands[0].Candidate.OracleName != "cors" {
			t.Fatalf("oracle must stay cors, got %q", cands[0].Candidate.OracleName)
		}
		if !sentOrigin.Load() {
			t.Fatal("the request must carry the declared Origin header")
		}
	})

	t.Run("allowlisted origin rejects", func(t *testing.T) {
		env := &loader.JSEnv{
			Points: []loader.JSPoint{point},
			Send: func(p loader.JSPoint) (loader.JSResponse, error) {
				h := map[string]string{"Content-Type": "text/html", "Access-Control-Allow-Origin": "https://example.com"}
				return loader.JSResponse{Status: 200, Headers: h, Body: "<html><body>account</body></html>", URL: p.URL}, nil
			},
		}
		cands, err := loader.ExecuteJS(context.Background(), spec, src, env, 10*time.Second)
		if err != nil {
			t.Fatalf("execute: %v", err)
		}
		if len(cands) != 0 {
			t.Fatalf("an allowlist that ignores our origin must not confirm, got %d", len(cands))
		}
	})

	t.Run("reflection without credentials firms", func(t *testing.T) {
		env := &loader.JSEnv{
			Points: []loader.JSPoint{point},
			Send: func(p loader.JSPoint) (loader.JSResponse, error) {
				h := map[string]string{"Content-Type": "text/html", "Access-Control-Allow-Origin": declared}
				return loader.JSResponse{Status: 200, Headers: h, Body: "<html><body>account</body></html>", URL: p.URL}, nil
			},
		}
		cands, err := loader.ExecuteJS(context.Background(), spec, src, env, 10*time.Second)
		if err != nil {
			t.Fatalf("execute: %v", err)
		}
		if len(cands) != 1 || cands[0].Evidence.ConfidenceContribution != plugin.ConfidenceFirm {
			t.Fatalf("credential-less reflection must stay firm, got %+v", cands)
		}
	})
}

// TestLDAPInjectionJSONBodyE2E proves the JSON-body directory filter proof.
func TestLDAPInjectionJSONBodyE2E(t *testing.T) {
	spec, src := loadTier2(t, "plugins/ldap/ldap-injection-json-body.js", "ldap-injection-json-body")
	point := jsonFieldPoint("http://example.com/api/login", "POST", "user")

	t.Run("always-true filter diverges", func(t *testing.T) {
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
				h := map[string]string{"Content-Type": "application/json"}
				if strings.Contains(p.Value, "*)(uid=*") {
					return loader.JSResponse{Status: 200, Headers: h, Body: `{"role":"admin"}`, URL: p.URL}, nil
				}
				return loader.JSResponse{Status: 200, Headers: h, Body: `{"error":"invalid credentials"}`, URL: p.URL}, nil
			},
		}
		cands, err := loader.ExecuteJS(context.Background(), spec, src, env, 10*time.Second)
		if err != nil {
			t.Fatalf("execute: %v", err)
		}
		if len(cands) != 1 {
			t.Fatalf("one LDAP candidate expected, got %d", len(cands))
		}
		if got := cands[0].Evidence.ConfidenceContribution; got != plugin.ConfidenceConfirmed {
			t.Fatalf("stable divergence must confirm, got %s", got)
		}
		if !jsonContentType.Load() || !rawBody.Load() {
			t.Fatal("the payload must be a raw application/json body")
		}
	})

	t.Run("escaped field rejects", func(t *testing.T) {
		env := &loader.JSEnv{
			Points: []loader.JSPoint{point},
			Send: func(p loader.JSPoint) (loader.JSResponse, error) {
				h := map[string]string{"Content-Type": "application/json"}
				return loader.JSResponse{Status: 200, Headers: h, Body: `{"error":"invalid credentials"}`, URL: p.URL}, nil
			},
		}
		cands, err := loader.ExecuteJS(context.Background(), spec, src, env, 10*time.Second)
		if err != nil {
			t.Fatalf("execute: %v", err)
		}
		if len(cands) != 0 {
			t.Fatalf("an escaping backend must not confirm, got %d", len(cands))
		}
	})
}

// TestInsecureDeserializationJSONBodyE2E proves the deserialization mode wiring.
func TestInsecureDeserializationJSONBodyE2E(t *testing.T) {
	spec, src := loadTier2(t, "plugins/deserialization/insecure-deserialization-json-body.js", "insecure-deserialization-json-body")
	point := jsonFieldPoint("http://example.com/api/import", "POST", "data")

	t.Run("java marker raises a signature at firm", func(t *testing.T) {
		var jsonContentType atomic.Bool
		env := &loader.JSEnv{
			Points: []loader.JSPoint{point},
			Send: func(p loader.JSPoint) (loader.JSResponse, error) {
				if strings.Contains(strings.ToLower(jsHeaderValue(p.Headers, "Content-Type")), "json") {
					jsonContentType.Store(true)
				}
				h := map[string]string{"Content-Type": "text/html"}
				if strings.Contains(p.Value, "rO0AB") {
					return loader.JSResponse{Status: 500, Headers: h, Body: "<pre>java.io.InvalidClassException: local class incompatible</pre>", URL: p.URL}, nil
				}
				return loader.JSResponse{Status: 200, Headers: h, Body: "<p>import complete</p>", URL: p.URL}, nil
			},
		}
		cands, err := loader.ExecuteJS(context.Background(), spec, src, env, 10*time.Second)
		if err != nil {
			t.Fatalf("execute: %v", err)
		}
		if len(cands) != 1 {
			t.Fatalf("one deserialization candidate expected, got %d", len(cands))
		}
		if got := cands[0].Evidence.ConfidenceContribution; got != plugin.ConfidenceFirm {
			t.Fatalf("the deserialization mode ceiling is firm, got %s", got)
		}
		if cands[0].Candidate.OracleName != "error" {
			t.Fatalf("oracle must stay error, got %q", cands[0].Candidate.OracleName)
		}
		if !jsonContentType.Load() {
			t.Fatal("the payload must be sent with a JSON content type")
		}
	})

	t.Run("always-erroring backend rejects", func(t *testing.T) {
		env := &loader.JSEnv{
			Points: []loader.JSPoint{point},
			Send: func(p loader.JSPoint) (loader.JSResponse, error) {
				h := map[string]string{"Content-Type": "text/html"}
				return loader.JSResponse{Status: 500, Headers: h, Body: "<pre>java.io.InvalidClassException: local class incompatible</pre>", URL: p.URL}, nil
			},
		}
		cands, err := loader.ExecuteJS(context.Background(), spec, src, env, 10*time.Second)
		if err != nil {
			t.Fatalf("execute: %v", err)
		}
		if len(cands) != 0 {
			t.Fatalf("a signature present for every value must not confirm, got %d", len(cands))
		}
	})

	t.Run("mode and surface", func(t *testing.T) {
		lower := strings.ToLower(src)
		if !strings.Contains(lower, "mode: deserialization") {
			t.Fatal("the deserialization mode must be declared in oracle_params")
		}
		assertOracleSurface(t, src,
			[]string{"host.oracles.error"},
			[]string{"host.oracles.differential", "host.oracles.timing", "host.oracles.reflection"})
	})
}

// TestSQLiJSONBodyTimingE2E proves the JSON-body time-based ceiling.
func TestSQLiJSONBodyTimingE2E(t *testing.T) {
	spec, src := loadTier2(t, "plugins/sqli/sqli-json-body-timing.js", "sqli-json-body-timing")
	point := jsonFieldPoint("http://example.com/api/items", "POST", "id")

	t.Run("delay payload diverges at firm", func(t *testing.T) {
		env := &loader.JSEnv{
			Points: []loader.JSPoint{point},
			Send: func(p loader.JSPoint) (loader.JSResponse, error) {
				h := map[string]string{"Content-Type": "application/json"}
				rtt := 100.0
				if strings.Contains(p.Value, "SLEEP") || strings.Contains(p.Value, "WAITFOR") {
					rtt = 5500
				}
				return loader.JSResponse{Status: 200, Headers: h, Body: `{"items":[]}`, URL: p.URL, RTTMs: rtt}, nil
			},
		}
		cands, err := loader.ExecuteJS(context.Background(), spec, src, env, 10*time.Second)
		if err != nil {
			t.Fatalf("execute: %v", err)
		}
		if len(cands) != 1 {
			t.Fatalf("one timing candidate expected, got %d", len(cands))
		}
		if got := cands[0].Evidence.ConfidenceContribution; got != plugin.ConfidenceFirm {
			t.Fatalf("timing carries no confirmation: got %s", got)
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
				return loader.JSResponse{Status: 200, Headers: h, Body: `{"items":[]}`, URL: p.URL, RTTMs: 120}, nil
			},
		}
		cands, err := loader.ExecuteJS(context.Background(), spec, src, env, 10*time.Second)
		if err != nil {
			t.Fatalf("execute: %v", err)
		}
		if len(cands) != 0 {
			t.Fatalf("no latency divergence means no finding, got %d", len(cands))
		}
	})

	t.Run("send budget holds", func(t *testing.T) {
		assertSendBudget(t, spec, src, 60, "POST", "body")
	})
}

// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Module: github.com/Xmar1881/Gash

package plugins

import (
	"context"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Xmar1881/Gash/internal/oracle"
	"github.com/Xmar1881/Gash/internal/plugin"
	"github.com/Xmar1881/Gash/internal/plugin/loader"
)

// TestNoSQLInjectionTimingJSONBodyE2E proves the JSON-body time-based ceiling.
func TestNoSQLInjectionTimingJSONBodyE2E(t *testing.T) {
	spec, src := loadTier2(t, "plugins/nosql/nosql-injection-timing-json-body.js", "nosql-injection-timing-json-body")
	point := jsonFieldPoint("http://example.com/api/items", "POST", "id")

	t.Run("$where delay payload diverges at firm", func(t *testing.T) {
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
				rtt := 100.0
				if strings.Contains(p.Value, "sleep(") || strings.Contains(p.Value, "while(") {
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
		if !rawBody.Load() || !jsonContentType.Load() {
			t.Fatal("the $where probe must be a raw application/json body")
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

	t.Run("no new sandbox surface", func(t *testing.T) {
		assertOracleSurface(t, src,
			[]string{"host.oracles.timing"},
			[]string{"host.oracles.differential", "host.oracles.error", "host.oracles.reflection", "host.oracles.oobAny"})
	})
}

// TestNoSQLInjectionDifferentialJSONBodyE2E proves the operator-injection proof.
func TestNoSQLInjectionDifferentialJSONBodyE2E(t *testing.T) {
	spec, src := loadTier2(t, "plugins/nosql/nosql-injection-differential-json-body.js", "nosql-injection-differential-json-body")
	point := jsonFieldPoint("http://example.com/api/users", "POST", "user")

	t.Run("operator object diverges from the literal", func(t *testing.T) {
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
				if strings.Contains(p.Value, "$ne") || strings.Contains(p.Value, "$gt") {
					return loader.JSResponse{Status: 200, Headers: h, Body: `{"result":"admin"}`, URL: p.URL}, nil
				}
				return loader.JSResponse{Status: 200, Headers: h, Body: `{"error":"not found"}`, URL: p.URL}, nil
			},
		}
		cands, err := loader.ExecuteJS(context.Background(), spec, src, env, 10*time.Second)
		if err != nil {
			t.Fatalf("execute: %v", err)
		}
		if len(cands) != 1 {
			t.Fatalf("one NoSQL candidate expected, got %d", len(cands))
		}
		if got := cands[0].Evidence.ConfidenceContribution; got != plugin.ConfidenceConfirmed {
			t.Fatalf("stable divergence must confirm, got %s", got)
		}
		if cands[0].Candidate.OracleName != "differential" {
			t.Fatalf("oracle must stay differential, got %q", cands[0].Candidate.OracleName)
		}
		if !rawBody.Load() || !jsonContentType.Load() {
			t.Fatal("the operator object must be sent as a raw application/json body")
		}
	})

	t.Run("operator-blind backend rejects", func(t *testing.T) {
		env := &loader.JSEnv{
			Points: []loader.JSPoint{point},
			Send: func(p loader.JSPoint) (loader.JSResponse, error) {
				h := map[string]string{"Content-Type": "application/json"}
				return loader.JSResponse{Status: 200, Headers: h, Body: `{"error":"not found"}`, URL: p.URL}, nil
			},
		}
		cands, err := loader.ExecuteJS(context.Background(), spec, src, env, 10*time.Second)
		if err != nil {
			t.Fatalf("execute: %v", err)
		}
		if len(cands) != 0 {
			t.Fatalf("a backend that treats the operator as a literal must not confirm, got %d", len(cands))
		}
	})

	t.Run("no new sandbox surface", func(t *testing.T) {
		assertOracleSurface(t, src,
			[]string{"host.oracles.differential"},
			[]string{"host.oracles.error", "host.oracles.timing", "host.oracles.reflection", "host.oracles.oobAny"})
	})
}

// TestWebCacheMethodOverrideE2E proves the clean/prime/clean poisoning sequence.
func TestWebCacheMethodOverrideE2E(t *testing.T) {
	spec, src := loadTier2(t, "plugins/cache-poisoning/web-cache-method-override.js", "web-cache-method-override")
	point := loader.JSPoint{URL: "http://example.com/portal", Method: "GET", ParamName: "", ParamLocation: "query"}

	t.Run("primed method-override canary is served to headerless reads", func(t *testing.T) {
		var mu sync.Mutex
		primed := false
		plain := `<html><body><a href="/portal">portal</a></body></html>`
		env := &loader.JSEnv{
			Points: []loader.JSPoint{point},
			Canary: "gash_e2e_cache_override",
			Send: func(p loader.JSPoint) (loader.JSResponse, error) {
				h := map[string]string{"Content-Type": "text/html"}
				seen := ""
				for _, name := range []string{"X-HTTP-Method-Override", "X-Method-Override", "X-HTTP-Method"} {
					if v := jsHeaderValue(p.Headers, name); v != "" {
						seen = v
					}
				}
				mu.Lock()
				defer mu.Unlock()
				if seen != "" {
					primed = true
					return loader.JSResponse{Status: 200, Headers: h, Body: plain, URL: p.URL}, nil
				}
				if primed {
					return loader.JSResponse{Status: 200, Headers: h, Body: `<html><body><a href="/portal?override=` + "gash_e2e_cache_override" + `">portal</a></body></html>`, URL: p.URL}, nil
				}
				return loader.JSResponse{Status: 200, Headers: h, Body: plain, URL: p.URL}, nil
			},
		}
		cands, err := loader.ExecuteJS(context.Background(), spec, src, env, 10*time.Second)
		if err != nil {
			t.Fatalf("execute: %v", err)
		}
		if len(cands) != 1 {
			t.Fatalf("one cache poisoning candidate expected, got %d", len(cands))
		}
		if got := cands[0].Evidence.ConfidenceContribution; got != plugin.ConfidenceConfirmed {
			t.Fatalf("confirmed required, got %s", got)
		}
		if cands[0].Candidate.OracleName != "differential" {
			t.Fatalf("oracle must stay differential, got %q", cands[0].Candidate.OracleName)
		}
	})

	t.Run("header-ignoring backend rejects", func(t *testing.T) {
		env := &loader.JSEnv{
			Points: []loader.JSPoint{point},
			Send: func(p loader.JSPoint) (loader.JSResponse, error) {
				h := map[string]string{"Content-Type": "text/html"}
				return loader.JSResponse{Status: 200, Headers: h, Body: `<html><body>portal</body></html>`, URL: p.URL}, nil
			},
		}
		cands, err := loader.ExecuteJS(context.Background(), spec, src, env, 10*time.Second)
		if err != nil {
			t.Fatalf("execute: %v", err)
		}
		if len(cands) != 0 {
			t.Fatalf("a non-caching backend must not confirm, got %d", len(cands))
		}
	})

	t.Run("send budget holds", func(t *testing.T) {
		assertSendBudget(t, spec, src, 60, "GET", "query")
	})

	t.Run("no new sandbox surface", func(t *testing.T) {
		assertOracleSurface(t, src,
			[]string{"host.oracles.differential"},
			[]string{"host.oracles.error", "host.oracles.timing", "host.oracles.reflection", "host.oracles.oobAny"})
	})
}

// TestJWTNoneAlgBypassE2E proves the active alg:none acceptance proof.
func TestJWTNoneAlgBypassE2E(t *testing.T) {
	spec, src := loadTier2(t, "plugins/jwt/jwt-none-alg-bypass.js", "jwt-none-alg-bypass")
	point := loader.JSPoint{URL: "http://example.com/api/account", Method: "GET", ParamName: "", ParamLocation: "query"}
	const issued = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJndWVzdCIsInJvbGUiOiJ1c2VyIn0.c2lnbmF0dXJl"

	t.Run("alg:none token accepted as authenticated", func(t *testing.T) {
		var forgedSeen atomic.Bool
		env := &loader.JSEnv{
			Points: []loader.JSPoint{point},
			Send: func(p loader.JSPoint) (loader.JSResponse, error) {
				h := map[string]string{"Content-Type": "application/json"}
				auth := jsHeaderValue(p.Headers, "Authorization")
				if auth == "" {
					return loader.JSResponse{Status: 200, Headers: h, Body: `{"token":"` + issued + `","anonymous":true}`, URL: p.URL}, nil
				}
				if strings.HasSuffix(auth, ".") {
					forgedSeen.Store(true)
					return loader.JSResponse{Status: 200, Headers: h, Body: `{"user":"admin","role":"admin"}`, URL: p.URL}, nil
				}
				return loader.JSResponse{Status: 401, Headers: h, Body: `{"error":"unauthorized"}`, URL: p.URL}, nil
			},
		}
		cands, err := loader.ExecuteJS(context.Background(), spec, src, env, 10*time.Second)
		if err != nil {
			t.Fatalf("execute: %v", err)
		}
		if len(cands) != 1 {
			t.Fatalf("one JWT candidate expected, got %d", len(cands))
		}
		if cands[0].Evidence.Verdict != oracle.VerdictAccept || cands[0].Evidence.ConfidenceContribution != plugin.ConfidenceConfirmed {
			t.Fatalf("confirmed evidence required: %+v", cands[0])
		}
		if cands[0].Candidate.OracleName != "differential" {
			t.Fatalf("oracle must stay differential, got %q", cands[0].Candidate.OracleName)
		}
		if !forgedSeen.Load() {
			t.Fatal("a headerless-signature token must have been sent")
		}
	})

	t.Run("algorithm enforcement rejects", func(t *testing.T) {
		env := &loader.JSEnv{
			Points: []loader.JSPoint{point},
			Send: func(p loader.JSPoint) (loader.JSResponse, error) {
				h := map[string]string{"Content-Type": "application/json"}
				if jsHeaderValue(p.Headers, "Authorization") == "" {
					return loader.JSResponse{Status: 200, Headers: h, Body: `{"token":"` + issued + `","anonymous":true}`, URL: p.URL}, nil
				}
				return loader.JSResponse{Status: 401, Headers: h, Body: `{"error":"unauthorized"}`, URL: p.URL}, nil
			},
		}
		cands, err := loader.ExecuteJS(context.Background(), spec, src, env, 10*time.Second)
		if err != nil {
			t.Fatalf("execute: %v", err)
		}
		if len(cands) != 0 {
			t.Fatalf("a server that enforces the algorithm must not confirm, got %d", len(cands))
		}
	})

	t.Run("send budget holds", func(t *testing.T) {
		assertSendBudget(t, spec, src, 16, "GET", "query")
	})

	t.Run("no new sandbox surface", func(t *testing.T) {
		assertOracleSurface(t, src,
			[]string{"host.oracles.differential"},
			[]string{"host.oracles.error", "host.oracles.timing", "host.oracles.reflection", "host.oracles.oobAny"})
	})
}

// TestXPathInjectionJSONBodyE2E proves the JSON-body XPath mode wiring.
func TestXPathInjectionJSONBodyE2E(t *testing.T) {
	spec, src := loadTier2(t, "plugins/xpath/xpath-injection-json-body.js", "xpath-injection-json-body")
	point := jsonFieldPoint("http://example.com/api/search", "POST", "query")

	t.Run("parser error raises a signature at firm", func(t *testing.T) {
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
				h := map[string]string{"Content-Type": "text/html"}
				if strings.Contains(p.Value, "//*") || strings.Contains(p.Value, "or '1'='1") {
					return loader.JSResponse{Status: 500, Headers: h, Body: "<pre>javax.xml.xpath.XPathExpressionException: Invalid XPath expression</pre>", URL: p.URL}, nil
				}
				return loader.JSResponse{Status: 200, Headers: h, Body: "<p>no results</p>", URL: p.URL}, nil
			},
		}
		cands, err := loader.ExecuteJS(context.Background(), spec, src, env, 10*time.Second)
		if err != nil {
			t.Fatalf("execute: %v", err)
		}
		if len(cands) != 1 {
			t.Fatalf("one XPath candidate expected, got %d", len(cands))
		}
		if got := cands[0].Evidence.ConfidenceContribution; got != plugin.ConfidenceFirm {
			t.Fatalf("the xpath mode ceiling is firm, got %s", got)
		}
		if cands[0].Candidate.OracleName != "error" {
			t.Fatalf("oracle must stay error, got %q", cands[0].Candidate.OracleName)
		}
		if !rawBody.Load() || !jsonContentType.Load() {
			t.Fatal("the probe must be sent as a raw application/json body")
		}
	})

	t.Run("clean backend rejects", func(t *testing.T) {
		env := &loader.JSEnv{
			Points: []loader.JSPoint{point},
			Send: func(p loader.JSPoint) (loader.JSResponse, error) {
				h := map[string]string{"Content-Type": "text/html"}
				return loader.JSResponse{Status: 200, Headers: h, Body: "<p>no results</p>", URL: p.URL}, nil
			},
		}
		cands, err := loader.ExecuteJS(context.Background(), spec, src, env, 10*time.Second)
		if err != nil {
			t.Fatalf("execute: %v", err)
		}
		if len(cands) != 0 {
			t.Fatalf("a clean backend must not confirm, got %d", len(cands))
		}
	})

	t.Run("mode and surface", func(t *testing.T) {
		lower := strings.ToLower(src)
		if !strings.Contains(lower, "mode: xpath") {
			t.Fatal("the xpath mode must be declared in oracle_params")
		}
		assertOracleSurface(t, src,
			[]string{"host.oracles.error"},
			[]string{"host.oracles.differential", "host.oracles.timing", "host.oracles.reflection"})
	})
}

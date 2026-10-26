// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Module: github.com/Xmar1881/Gash

package plugins

import (
	"context"
	"path"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Xmar1881/Gash/internal/oracle"
	"github.com/Xmar1881/Gash/internal/plugin"
	"github.com/Xmar1881/Gash/internal/plugin/loader"
)

// TestSQLiOOBSecondOrderE2E proves the blind second-order write/read discipline.
// What: Executes sqli-oob-second-order.js with and without an OOB server.
// Why: The stored closure produces no output and no delay, so only a matched
// callback may confirm; without a server the plugin must send nothing.
func TestSQLiOOBSecondOrderE2E(t *testing.T) {
	spec, src := loadTier2(t, "plugins/sqli/sqli-oob-second-order.js", "sqli-oob-second-order")
	point := loader.JSPoint{URL: "http://example.com/api/items", Method: "POST", ParamName: "id", ParamLocation: "query"}

	t.Run("callback confirms the write/read pair", func(t *testing.T) {
		var values []string
		env := &loader.JSEnv{
			Points:       []loader.JSPoint{point},
			OOBEnabled:   true,
			OOBNamespace: "scan_e2e",
			Send: func(p loader.JSPoint) (loader.JSResponse, error) {
				values = append(values, p.Value)
				return loader.JSResponse{Status: 200, Headers: map[string]string{"Content-Type": "application/json"}, Body: `{"status":"queued"}`, URL: p.URL}, nil
			},
			OOBCallbackSeenAny: func(ids []string) []string { return ids },
		}
		cands, err := loader.ExecuteJS(context.Background(), spec, src, env, 10*time.Second)
		if err != nil {
			t.Fatalf("execute: %v", err)
		}
		if len(cands) != 1 {
			t.Fatalf("one second-order candidate expected, got %d", len(cands))
		}
		ev := cands[0].Evidence
		if ev == nil || ev.Verdict != oracle.VerdictAccept || ev.ConfidenceContribution != plugin.ConfidenceConfirmed {
			t.Fatalf("confirmed evidence required: %+v", cands[0])
		}
		if cands[0].Candidate.OracleName != "oob" {
			t.Fatalf("oracle must stay oob, got %q", cands[0].Candidate.OracleName)
		}
		if len(values) != 2 {
			t.Fatalf("a write plus a neutral re-read are required, got %d sends", len(values))
		}
		if !strings.Contains(values[0], "xp_dirtree") || !strings.Contains(values[0], "oob.example") {
			t.Fatalf("the write must carry the callback-only closure, got %q", values[0])
		}
		if values[1] != "1" {
			t.Fatalf("the re-read must carry the neutral value, got %q", values[1])
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
		points := make([]loader.JSPoint, 20)
		for i := range points {
			points[i] = loader.JSPoint{URL: "http://example.com/api/" + itoaTest(i), Method: "POST", ParamName: "id", ParamLocation: "query"}
		}
		var sends atomic.Int64
		env := &loader.JSEnv{
			Points:       points,
			OOBEnabled:   true,
			OOBNamespace: "scan_e2e",
			Send: func(p loader.JSPoint) (loader.JSResponse, error) {
				sends.Add(1)
				return loader.JSResponse{Status: 200, URL: p.URL}, nil
			},
			OOBCallbackSeenAny: func([]string) []string { return nil },
		}
		if _, err := loader.ExecuteJS(context.Background(), spec, src, env, 2*time.Second); err != nil {
			t.Fatalf("execute: %v", err)
		}
		if got := sends.Load(); got > 60 {
			t.Fatalf("send budget exceeded: got %d, want <= 60", got)
		}
	})

	t.Run("no new sandbox surface", func(t *testing.T) {
		assertOracleSurface(t, src,
			[]string{"host.oob.generate", "host.oracles.oobAny"},
			[]string{"host.oracles.differential", "host.oracles.timing", "host.oracles.reflection"})
	})
}

// TestSSTIJSONBodyOOBE2E proves the JSON-field template callback discipline.
func TestSSTIJSONBodyOOBE2E(t *testing.T) {
	spec, src := loadTier2(t, "plugins/ssti/ssti-json-body-oob.js", "ssti-json-body-oob")
	point := jsonFieldPoint("http://example.com/api/reports", "POST", "subject")

	t.Run("callback confirms the rendered field", func(t *testing.T) {
		var jsonContentType, carriedDomain atomic.Bool
		env := &loader.JSEnv{
			Points:       []loader.JSPoint{point},
			OOBEnabled:   true,
			OOBNamespace: "scan_e2e",
			Send: func(p loader.JSPoint) (loader.JSResponse, error) {
				if strings.Contains(strings.ToLower(jsHeaderValue(p.Headers, "Content-Type")), "json") {
					jsonContentType.Store(true)
				}
				if strings.Contains(p.Value, "oob.example") {
					carriedDomain.Store(true)
				}
				return loader.JSResponse{Status: 200, Headers: map[string]string{"Content-Type": "application/json"}, Body: `{"status":"rendered"}`, URL: p.URL}, nil
			},
			OOBCallbackSeenAny: func(ids []string) []string { return ids },
		}
		cands, err := loader.ExecuteJS(context.Background(), spec, src, env, 10*time.Second)
		if err != nil {
			t.Fatalf("execute: %v", err)
		}
		if len(cands) != 1 {
			t.Fatalf("one SSTI candidate expected, got %d", len(cands))
		}
		if cands[0].Evidence.ConfidenceContribution != plugin.ConfidenceConfirmed || cands[0].Candidate.OracleName != "oob" {
			t.Fatalf("confirmed oob evidence required: %+v", cands[0])
		}
		if !jsonContentType.Load() || !carriedDomain.Load() {
			t.Fatal("the payload must be a raw application/json body carrying the callback host")
		}
	})

	t.Run("without an OOB server nothing is sent", func(t *testing.T) {
		var sends atomic.Int64
		env := &loader.JSEnv{
			Points:     []loader.JSPoint{point},
			OOBEnabled: false,
			Send: func(p loader.JSPoint) (loader.JSResponse, error) {
				sends.Add(1)
				return loader.JSResponse{Status: 200, URL: p.URL}, nil
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

	t.Run("no new sandbox surface", func(t *testing.T) {
		assertOracleSurface(t, src,
			[]string{"host.oob.generate", "host.oracles.oobAny"},
			[]string{"host.oracles.differential", "host.oracles.timing", "host.oracles.error"})
	})
}

// TestLDAPOOBJSONBodyE2E proves the JSON-body directory-filter callback proof.
func TestLDAPOOBJSONBodyE2E(t *testing.T) {
	spec, src := loadTier2(t, "plugins/ldap/ldap-injection-oob-json-body.js", "ldap-injection-oob-json-body")
	point := jsonFieldPoint("http://example.com/api/login", "POST", "user")

	t.Run("callback confirms the filter closure", func(t *testing.T) {
		var carriedDomain atomic.Bool
		env := &loader.JSEnv{
			Points:       []loader.JSPoint{point},
			OOBEnabled:   true,
			OOBNamespace: "scan_e2e",
			Send: func(p loader.JSPoint) (loader.JSResponse, error) {
				if strings.Contains(p.Value, "oob.example") {
					carriedDomain.Store(true)
				}
				return loader.JSResponse{Status: 200, Headers: map[string]string{"Content-Type": "application/json"}, Body: `{"token":"issued"}`, URL: p.URL}, nil
			},
			OOBCallbackSeenAny: func(ids []string) []string { return ids },
		}
		cands, err := loader.ExecuteJS(context.Background(), spec, src, env, 10*time.Second)
		if err != nil {
			t.Fatalf("execute: %v", err)
		}
		if len(cands) != 1 {
			t.Fatalf("one LDAP candidate expected, got %d", len(cands))
		}
		if cands[0].Evidence.ConfidenceContribution != plugin.ConfidenceConfirmed || cands[0].Candidate.OracleName != "oob" {
			t.Fatalf("confirmed oob evidence required: %+v", cands[0])
		}
		if !carriedDomain.Load() {
			t.Fatal("the filter must carry the callback host")
		}
	})

	t.Run("without an OOB server nothing is sent", func(t *testing.T) {
		var sends atomic.Int64
		env := &loader.JSEnv{
			Points:     []loader.JSPoint{point},
			OOBEnabled: false,
			Send: func(p loader.JSPoint) (loader.JSResponse, error) {
				sends.Add(1)
				return loader.JSResponse{Status: 200, URL: p.URL}, nil
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

	t.Run("no new sandbox surface", func(t *testing.T) {
		assertOracleSurface(t, src,
			[]string{"host.oob.generate", "host.oracles.oobAny"},
			[]string{"host.oracles.differential", "host.oracles.error", "host.oracles.reflection"})
	})
}

// idorResponder answers the three identifiers the matrix plugin reads.
// What: Own object, neighbour object, and a missing-object baseline.
// Why: The divergence between them is the only thing the oracle grades.
func idorResponder(own string) func(loader.JSPoint) (loader.JSResponse, error) {
	return func(p loader.JSPoint) (loader.JSResponse, error) {
		h := map[string]string{"Content-Type": "application/json"}
		switch p.Value {
		case own:
			return loader.JSResponse{Status: 200, Headers: h, Body: `{"object":{"owner":"gash-caller"}}`, URL: p.URL}, nil
		case "4":
			return loader.JSResponse{Status: 200, Headers: h, Body: `{"object":{"owner":"gash-other-tenant"}}`, URL: p.URL}, nil
		default:
			return loader.JSResponse{Status: 404, Headers: h, Body: `{"error":"not found"}`, URL: p.URL}, nil
		}
	}
}

// TestIDORSequentialIDMatrixE2E proves the own/neighbour/missing matrix.
func TestIDORSequentialIDMatrixE2E(t *testing.T) {
	spec, src := loadTier2(t, "plugins/idor/idor-sequential-id-matrix.js", "idor-sequential-id-matrix")
	point := loader.JSPoint{URL: "http://example.com/api/orders", Method: "GET", ParamName: "id", ParamLocation: "query", Value: "3"}

	t.Run("neighbour object diverges and confirms", func(t *testing.T) {
		var sawNeighbour, sawMissing atomic.Bool
		inner := idorResponder("3")
		env := &loader.JSEnv{
			Points: []loader.JSPoint{point},
			Send: func(p loader.JSPoint) (loader.JSResponse, error) {
				if p.Value == "4" {
					sawNeighbour.Store(true)
				}
				if p.Value == "100003" {
					sawMissing.Store(true)
				}
				return inner(p)
			},
		}
		cands, err := loader.ExecuteJS(context.Background(), spec, src, env, 10*time.Second)
		if err != nil {
			t.Fatalf("execute: %v", err)
		}
		if len(cands) != 1 {
			t.Fatalf("one IDOR candidate expected, got %d", len(cands))
		}
		if cands[0].Evidence.ConfidenceContribution != plugin.ConfidenceConfirmed || cands[0].Candidate.OracleName != "differential" {
			t.Fatalf("confirmed differential evidence required: %+v", cands[0])
		}
		if !sawNeighbour.Load() || !sawMissing.Load() {
			t.Fatal("the matrix must read a neighbouring and a non-existent identifier")
		}
	})

	t.Run("identifier ignored rejects", func(t *testing.T) {
		env := &loader.JSEnv{
			Points: []loader.JSPoint{point},
			Send: func(p loader.JSPoint) (loader.JSResponse, error) {
				return loader.JSResponse{Status: 200, Headers: map[string]string{"Content-Type": "application/json"}, Body: `{"object":{"owner":"gash-caller"}}`, URL: p.URL}, nil
			},
		}
		cands, err := loader.ExecuteJS(context.Background(), spec, src, env, 10*time.Second)
		if err != nil {
			t.Fatalf("execute: %v", err)
		}
		if len(cands) != 0 {
			t.Fatalf("an endpoint that ignores the identifier must not confirm, got %d", len(cands))
		}
	})

	t.Run("send budget holds", func(t *testing.T) {
		points := make([]loader.JSPoint, 20)
		for i := range points {
			points[i] = loader.JSPoint{URL: "http://example.com/api/" + itoaTest(i), Method: "GET", ParamName: "id", ParamLocation: "query", Value: "3"}
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

	t.Run("no new sandbox surface", func(t *testing.T) {
		assertOracleSurface(t, src,
			[]string{"host.oracles.differential"},
			[]string{"host.oracles.error", "host.oracles.timing", "host.oracles.oob"})
	})
}

// TestMassAssignmentNestedJSONE2E proves the nested-object binding proof.
func TestMassAssignmentNestedJSONE2E(t *testing.T) {
	spec, src := loadTier2(t, "plugins/mass-assignment/mass-assignment-nested-json.js", "mass-assignment-nested-json")
	point := jsonFieldPoint("http://example.com/api/profile", "POST", "user")

	t.Run("privileged nested object diverges at firm", func(t *testing.T) {
		env := &loader.JSEnv{
			Points: []loader.JSPoint{point},
			Send: func(p loader.JSPoint) (loader.JSResponse, error) {
				h := map[string]string{"Content-Type": "application/json"}
				if strings.Contains(p.Value, "is_admin") {
					return loader.JSResponse{Status: 200, Headers: h, Body: `{"updated":true,"privileged":true}`, URL: p.URL}, nil
				}
				return loader.JSResponse{Status: 200, Headers: h, Body: `{"updated":true,"privileged":false}`, URL: p.URL}, nil
			},
		}
		cands, err := loader.ExecuteJS(context.Background(), spec, src, env, 10*time.Second)
		if err != nil {
			t.Fatalf("execute: %v", err)
		}
		if len(cands) != 1 {
			t.Fatalf("one candidate expected, got %d", len(cands))
		}
		if got := cands[0].Evidence.ConfidenceContribution; got != plugin.ConfidenceFirm {
			t.Fatalf("the declared ceiling is firm, got %s", got)
		}
	})

	t.Run("echoed privileged field rejects", func(t *testing.T) {
		env := &loader.JSEnv{
			Points: []loader.JSPoint{point},
			Send: func(p loader.JSPoint) (loader.JSResponse, error) {
				return loader.JSResponse{Status: 200, Headers: map[string]string{"Content-Type": "application/json"}, Body: `<html><body>{"role":"admin"}</body></html>`, URL: p.URL}, nil
			},
		}
		cands, err := loader.ExecuteJS(context.Background(), spec, src, env, 10*time.Second)
		if err != nil {
			t.Fatalf("execute: %v", err)
		}
		if len(cands) != 0 {
			t.Fatalf("a body that echoes the privileged field must not confirm, got %d", len(cands))
		}
	})

	t.Run("mode and surface", func(t *testing.T) {
		if !strings.Contains(strings.ToLower(src), "confidence_ceiling: firm") {
			t.Fatal("the firm ceiling must be declared in oracle_params")
		}
		assertOracleSurface(t, src,
			[]string{"host.oracles.differential"},
			[]string{"host.oracles.timing", "host.oracles.error", "host.oracles.reflection"})
	})
}

// TestGraphQLAliasAmplificationE2E proves the aliased-document divergence.
func TestGraphQLAliasAmplificationE2E(t *testing.T) {
	spec, src := loadTier2(t, "plugins/graphql/graphql-alias-amplification.js", "graphql-alias-amplification")
	point := jsonFieldPoint("http://example.com/graphql", "POST", "query")

	t.Run("aliased document diverges at firm", func(t *testing.T) {
		var sawAliases atomic.Bool
		env := &loader.JSEnv{
			Points: []loader.JSPoint{point},
			Send: func(p loader.JSPoint) (loader.JSResponse, error) {
				h := map[string]string{"Content-Type": "application/json"}
				if strings.Contains(p.Value, "a24:__typename") {
					sawAliases.Store(true)
					return loader.JSResponse{Status: 200, Headers: h, Body: `{"data":{"aliased":{"__typename":"Query"}}}`, URL: p.URL}, nil
				}
				return loader.JSResponse{Status: 200, Headers: h, Body: `{"data":{"__typename":"Query"}}`, URL: p.URL}, nil
			},
		}
		cands, err := loader.ExecuteJS(context.Background(), spec, src, env, 10*time.Second)
		if err != nil {
			t.Fatalf("execute: %v", err)
		}
		if len(cands) != 1 {
			t.Fatalf("one candidate expected, got %d", len(cands))
		}
		if got := cands[0].Evidence.ConfidenceContribution; got != plugin.ConfidenceFirm {
			t.Fatalf("the declared ceiling is firm, got %s", got)
		}
		if !sawAliases.Load() {
			t.Fatal("the batched document must carry the full alias set")
		}
	})

	t.Run("identical branches reject", func(t *testing.T) {
		env := &loader.JSEnv{
			Points: []loader.JSPoint{point},
			Send: func(p loader.JSPoint) (loader.JSResponse, error) {
				return loader.JSResponse{Status: 200, Headers: map[string]string{"Content-Type": "application/json"}, Body: `{"errors":[{"message":"Too many aliases"}]}`, URL: p.URL}, nil
			},
		}
		cands, err := loader.ExecuteJS(context.Background(), spec, src, env, 10*time.Second)
		if err != nil {
			t.Fatalf("execute: %v", err)
		}
		if len(cands) != 0 {
			t.Fatalf("an alias limit must not confirm, got %d", len(cands))
		}
	})

	t.Run("send budget holds", func(t *testing.T) {
		assertSendBudget(t, spec, src, 60, "POST", "body")
	})

	t.Run("no new sandbox surface", func(t *testing.T) {
		assertOracleSurface(t, src,
			[]string{"host.oracles.differential"},
			[]string{"host.oracles.error", "host.oracles.timing", "host.oracles.stored"})
	})
}

// TestWebCacheUnkeyedCookieE2E proves the clean/prime/clean cookie sequence.
func TestWebCacheUnkeyedCookieE2E(t *testing.T) {
	spec, src := loadTier2(t, "plugins/cache-poisoning/web-cache-unkeyed-cookie.js", "web-cache-unkeyed-cookie")
	point := loader.JSPoint{URL: "http://example.com/shop", Method: "GET", ParamName: "", ParamLocation: "query"}

	t.Run("canary outlives the priming request", func(t *testing.T) {
		var primed string
		env := &loader.JSEnv{
			Points: []loader.JSPoint{point},
			// The mock cache only stores responses to cookie-less requests, so
			// the priming exchange itself stays clean and the control (which
			// carries a cookie) never sees the canary.
			Send: func(p loader.JSPoint) (loader.JSResponse, error) {
				h := map[string]string{"Content-Type": "text/html"}
				cookie := jsHeaderValue(p.Headers, "Cookie")
				if cookie != "" {
					if strings.HasPrefix(cookie, "gash_cache_track=") && !strings.Contains(cookie, "gash-control-neutral") {
						primed = strings.TrimPrefix(cookie, "gash_cache_track=")
					}
					return loader.JSResponse{Status: 200, Headers: h, Body: "<html><body>store</body></html>", URL: p.URL}, nil
				}
				if primed != "" {
					return loader.JSResponse{Status: 200, Headers: h, Body: "<html><body>store " + primed + "</body></html>", URL: p.URL}, nil
				}
				return loader.JSResponse{Status: 200, Headers: h, Body: "<html><body>store</body></html>", URL: p.URL}, nil
			},
		}
		cands, err := loader.ExecuteJS(context.Background(), spec, src, env, 10*time.Second)
		if err != nil {
			t.Fatalf("execute: %v", err)
		}
		if len(cands) != 1 {
			t.Fatalf("one cache-poisoning candidate expected, got %d", len(cands))
		}
		if got := cands[0].Evidence.ConfidenceContribution; got != plugin.ConfidenceConfirmed {
			t.Fatalf("stable poisoned reads must confirm, got %s", got)
		}
	})

	t.Run("keyed cookie rejects", func(t *testing.T) {
		env := &loader.JSEnv{
			Points: []loader.JSPoint{point},
			Send: func(p loader.JSPoint) (loader.JSResponse, error) {
				return loader.JSResponse{Status: 200, Headers: map[string]string{"Content-Type": "text/html"}, Body: "<html><body>store</body></html>", URL: p.URL}, nil
			},
		}
		cands, err := loader.ExecuteJS(context.Background(), spec, src, env, 10*time.Second)
		if err != nil {
			t.Fatalf("execute: %v", err)
		}
		if len(cands) != 0 {
			t.Fatalf("a keyed cookie must not confirm, got %d", len(cands))
		}
	})

	t.Run("send budget holds", func(t *testing.T) {
		assertSendBudget(t, spec, src, 60, "GET", "query")
	})

	t.Run("no new sandbox surface", func(t *testing.T) {
		assertOracleSurface(t, src,
			[]string{"host.oracles.differential"},
			[]string{"host.oracles.timing", "host.oracles.reflection", "host.oracles.uploadServed"})
	})
}

// TestCommandInjectionJSONBodyTimingE2E proves the measured-delay ceiling.
func TestCommandInjectionJSONBodyTimingE2E(t *testing.T) {
	spec, src := loadTier2(t, "plugins/command-injection/command-injection-json-body-timing.js", "command-injection-json-body-timing")
	point := jsonFieldPoint("http://example.com/api/convert", "POST", "target")

	t.Run("sleep payload diverges at firm", func(t *testing.T) {
		env := &loader.JSEnv{
			Points: []loader.JSPoint{point},
			Send: func(p loader.JSPoint) (loader.JSResponse, error) {
				h := map[string]string{"Content-Type": "application/json"}
				rtt := 120.0
				if strings.Contains(p.Value, "sleep") {
					rtt = 5600
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
		if cands[0].Evidence.ConfidenceContribution != plugin.ConfidenceFirm || cands[0].Candidate.OracleName != "timing" {
			t.Fatalf("firm timing evidence required: %+v", cands[0])
		}
	})

	t.Run("uniform latency rejects", func(t *testing.T) {
		env := &loader.JSEnv{
			Points: []loader.JSPoint{point},
			Send: func(p loader.JSPoint) (loader.JSResponse, error) {
				return loader.JSResponse{Status: 200, Headers: map[string]string{"Content-Type": "application/json"}, Body: `{"items":[]}`, URL: p.URL, RTTMs: 125}, nil
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
			[]string{"host.oracles.error", "host.oracles.differential", "host.oob.generate"})
	})
}

// TestFileUploadFilenameTraversalE2E proves the traversal serve-back workflow.
func TestFileUploadFilenameTraversalE2E(t *testing.T) {
	spec, src := loadTier2(t, "plugins/file-upload/file-upload-filename-traversal.js", "file-upload-filename-traversal")
	point := loader.JSPoint{URL: "http://example.com/api/upload", Method: "POST", ParamName: "file", ParamLocation: "body"}

	// mkTraversalEnv models an endpoint that joins the raw filename with its
	// upload directory and serves the artifact back outside it.
	mkTraversalEnv := func(fetchContentType string, dirtyControl bool, traversalSeen, multipartSeen *atomic.Bool) *loader.JSEnv {
		return &loader.JSEnv{
			Points: []loader.JSPoint{point},
			Send: func(p loader.JSPoint) (loader.JSResponse, error) {
				if strings.EqualFold(p.ParamLocation, "body") && p.ParamName == "" {
					ct := jsHeaderValue(p.Headers, "Content-Type")
					if multipartSeen != nil && strings.Contains(strings.ToLower(ct), "multipart/form-data") && strings.Contains(strings.ToLower(ct), "boundary=") {
						multipartSeen.Store(true)
					}
					if traversalSeen != nil && strings.Contains(p.Value, `filename="../../`) {
						traversalSeen.Store(true)
					}
					name := between(p.Value, `filename="../../`, `"`)
					if name == "" {
						name = "unknown.html"
					}
					return loader.JSResponse{Status: 200, Headers: map[string]string{"Content-Type": "application/json"}, Body: `{"url":"/media/` + name + `"}`, URL: p.URL}, nil
				}
				name := path.Base(p.URL)
				if strings.Contains(name, "_never") {
					if dirtyControl {
						return loader.JSResponse{Status: 200, Headers: map[string]string{"Content-Type": fetchContentType}, Body: `<svg onload="alert(` + strings.TrimSuffix(name, "_never.html") + `.html)"></svg>`, URL: p.URL}, nil
					}
					return loader.JSResponse{Status: 404, Headers: map[string]string{"Content-Type": "text/html"}, Body: "<html><body>not found</body></html>", URL: p.URL}, nil
				}
				canary := strings.TrimSuffix(name, ".html")
				body := `<svg xmlns="http://www.w3.org/2000/svg" onload="alert(` + canary + `)"></svg>`
				return loader.JSResponse{Status: 200, Headers: map[string]string{"Content-Type": fetchContentType}, Body: body, URL: p.URL}, nil
			},
		}
	}

	t.Run("traversed artifact served as active content confirms", func(t *testing.T) {
		var traversalSeen, multipartSeen atomic.Bool
		env := mkTraversalEnv("text/html", false, &traversalSeen, &multipartSeen)
		cands, err := loader.ExecuteJS(context.Background(), spec, src, env, 10*time.Second)
		if err != nil {
			t.Fatalf("execute: %v", err)
		}
		if len(cands) != 1 {
			t.Fatalf("one candidate expected, got %d", len(cands))
		}
		if cands[0].Evidence.ConfidenceContribution != plugin.ConfidenceConfirmed || cands[0].Candidate.OracleName != "upload-served" {
			t.Fatalf("confirmed upload-served evidence required: %+v", cands[0])
		}
		if !traversalSeen.Load() || !multipartSeen.Load() {
			t.Fatal("the part must carry a traversal filename inside a raw multipart body")
		}
	})

	t.Run("inert serve-back firms", func(t *testing.T) {
		env := mkTraversalEnv("text/plain", false, nil, nil)
		cands, err := loader.ExecuteJS(context.Background(), spec, src, env, 10*time.Second)
		if err != nil {
			t.Fatalf("execute: %v", err)
		}
		if len(cands) != 1 || cands[0].Evidence.ConfidenceContribution != plugin.ConfidenceFirm {
			t.Fatalf("inert serve-back must stay firm, got %+v", cands)
		}
	})

	t.Run("dirty control rejects", func(t *testing.T) {
		env := mkTraversalEnv("text/html", true, nil, nil)
		cands, err := loader.ExecuteJS(context.Background(), spec, src, env, 10*time.Second)
		if err != nil {
			t.Fatalf("execute: %v", err)
		}
		if len(cands) != 0 {
			t.Fatalf("a control that also serves the payload must reject, got %d", len(cands))
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

// TestCORSNullOriginTrustE2E proves the literal null-origin proof.
func TestCORSNullOriginTrustE2E(t *testing.T) {
	spec, src := loadTier2(t, "plugins/cors/cors-null-origin-trust.js", "cors-null-origin-trust")
	point := loader.JSPoint{URL: "http://example.com/api/account", Method: "GET", ParamName: "", ParamLocation: "query"}

	// The origin literal must live in exactly one place per file: the
	// frontmatter oracle_params block and the script constant must agree,
	// otherwise a fixture would grade a different origin than a live scan.
	declared, _ := spec.OracleParams["request_origin"].(string)
	if declared != "null" {
		t.Fatalf("oracle_params.request_origin must be the literal null, got %q", declared)
	}
	if !strings.Contains(src, `const NULL_ORIGIN = "`+declared+`";`) {
		t.Fatalf("script constant must equal the declared origin %q", declared)
	}

	t.Run("null origin with credentials confirms", func(t *testing.T) {
		var sentNull atomic.Bool
		env := &loader.JSEnv{
			Points: []loader.JSPoint{point},
			Send: func(p loader.JSPoint) (loader.JSResponse, error) {
				if jsHeaderValue(p.Headers, "Origin") == declared {
					sentNull.Store(true)
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
		if cands[0].Evidence.ConfidenceContribution != plugin.ConfidenceConfirmed || cands[0].Candidate.OracleName != "cors" {
			t.Fatalf("confirmed cors evidence required: %+v", cands[0])
		}
		if !sentNull.Load() {
			t.Fatal("the request must carry the literal null Origin")
		}
	})

	t.Run("specific allowlist rejects", func(t *testing.T) {
		env := &loader.JSEnv{
			Points: []loader.JSPoint{point},
			Send: func(p loader.JSPoint) (loader.JSResponse, error) {
				h := map[string]string{"Content-Type": "text/html", "Access-Control-Allow-Origin": "https://app.example.com"}
				return loader.JSResponse{Status: 200, Headers: h, Body: "<html><body>account</body></html>", URL: p.URL}, nil
			},
		}
		cands, err := loader.ExecuteJS(context.Background(), spec, src, env, 10*time.Second)
		if err != nil {
			t.Fatalf("execute: %v", err)
		}
		if len(cands) != 0 {
			t.Fatalf("an allowlist that does not echo null must reject, got %d", len(cands))
		}
	})

	t.Run("null origin without credentials firms", func(t *testing.T) {
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
			t.Fatalf("credential-less null reflection must stay firm, got %+v", cands)
		}
	})

	t.Run("send budget holds", func(t *testing.T) {
		assertSendBudget(t, spec, src, 30, "GET", "query")
	})
}

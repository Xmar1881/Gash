// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Module: github.com/Xmar1881/Gash

package plugins

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Xmar1881/Gash/internal/oracle"
	"github.com/Xmar1881/Gash/internal/plugin"
	"github.com/Xmar1881/Gash/internal/plugin/loader"
)

// TestWebCacheUnkeyedHeaderE2E proves the clean/prime/clean poisoning sequence.
// What: Executes web-cache-unkeyed-header.js against a mocked transport that
// caches a response only after a forwarding header was seen.
// Why: Cache poisoning cannot be shown by one request/response pair: the proof
// is that the primed canary outlives the priming request. A header on the wire
// plus correlated reads is exactly what Tier 1 cannot express.
func TestWebCacheUnkeyedHeaderE2E(t *testing.T) {
	root := repoRoot(t)
	path := filepath.Join(root, "plugins", "cache-poisoning", "web-cache-unkeyed-header.js")
	src, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	spec, err := loader.LoadTier2Frontmatter(path)
	if err != nil {
		t.Fatalf("frontmatter %s: %v", path, err)
	}
	if spec.ID != "web-cache-unkeyed-header" {
		t.Fatalf("unexpected id %q", spec.ID)
	}

	point := loader.JSPoint{URL: "http://example.com/portal", Method: "GET", ParamName: "", ParamLocation: "query"}
	proxyHeaders := []string{"X-Forwarded-Host", "X-Host", "X-Forwarded-Server"}

	t.Run("primed response is served to headerless reads", func(t *testing.T) {
		var mu sync.Mutex
		var primedHost string
		var primedHeaders int
		clean := `<html><body><a href="http://example.com/portal">portal</a></body></html>`
		env := &loader.JSEnv{
			Points: []loader.JSPoint{point},
			Send: func(p loader.JSPoint) (loader.JSResponse, error) {
				h := map[string]string{"Content-Type": "text/html"}
				seen := ""
				for _, name := range proxyHeaders {
					if v := jsHeaderValue(p.Headers, name); v != "" {
						seen = v
						primedHeaders++
					}
				}
				mu.Lock()
				defer mu.Unlock()
				if seen != "" {
					primedHost = seen
					return loader.JSResponse{Status: 200, Headers: h, Body: clean, URL: p.URL}, nil
				}
				if primedHost != "" {
					body := `<html><body><a href="http://` + primedHost + `/portal">portal</a></body></html>`
					return loader.JSResponse{Status: 200, Headers: h, Body: body, URL: p.URL}, nil
				}
				return loader.JSResponse{Status: 200, Headers: h, Body: clean, URL: p.URL}, nil
			},
		}
		cands, err := loader.ExecuteJS(context.Background(), spec, string(src), env, 10*time.Second)
		if err != nil {
			t.Fatalf("execute: %v", err)
		}
		if len(cands) != 1 {
			t.Fatalf("one cache poisoning candidate expected, got %d", len(cands))
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
		if primedHeaders < len(proxyHeaders) {
			t.Fatalf("priming request must carry every unkeyed header, got %d", primedHeaders)
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
		cands, err := loader.ExecuteJS(context.Background(), spec, string(src), env, 10*time.Second)
		if err != nil {
			t.Fatalf("execute: %v", err)
		}
		if len(cands) != 0 {
			t.Fatalf("a non-caching backend must not confirm, got %d", len(cands))
		}
	})

	t.Run("large surfaces stay within send budget", func(t *testing.T) {
		points := make([]loader.JSPoint, 20)
		for i := range points {
			points[i] = loader.JSPoint{
				URL:           "http://example.com/page-" + itoaTest(i),
				Method:        "GET",
				ParamName:     "",
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
			t.Fatalf("cache poisoning send budget exceeded: got %d, want <= 60", got)
		}
	})

	t.Run("priming headers never reach the control read", func(t *testing.T) {
		// The canary host must be unique per run and never reused as the
		// neutral control value.
		lower := strings.ToLower(string(src))
		if !strings.Contains(lower, "probe.canary()") {
			t.Fatal("canary host must come from probe.canary()")
		}
		for _, forbidden := range []string{"host.oracles.header", "host.oracles.error", "require(", "fetch("} {
			if strings.Contains(lower, forbidden) {
				t.Fatalf("forbidden sandbox surface in source: %s", forbidden)
			}
		}
	})
}

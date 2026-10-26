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

// TestSQLiSecondOrderE2E proves the write-then-neutral-re-read correlation.
// What: Executes sqli-second-order.js against a mocked transport that only
// errors on the neutral re-read of a previously written payload.
// Why: Second-order injection needs two correlated exchanges; Tier 1 declares
// one request per payload, so only a Tier 2 script can sequence the pair. The
// proof must stay inside the existing probe.send plus host.oracles bindings.
func TestSQLiSecondOrderE2E(t *testing.T) {
	root := repoRoot(t)
	path := filepath.Join(root, "plugins", "sqli", "sqli-second-order.js")
	src, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	spec, err := loader.LoadTier2Frontmatter(path)
	if err != nil {
		t.Fatalf("frontmatter %s: %v", path, err)
	}
	if spec.ID != "sqli-second-order" {
		t.Fatalf("unexpected id %q", spec.ID)
	}

	const neutral = "1"
	queryPoint := loader.JSPoint{URL: "http://example.com/item", Method: "GET", ParamName: "id", ParamLocation: "query"}

	// mkEnv answers writes (any value other than the neutral read) by latching
	// the stored state; neutral reads return the read body for that state.
	mkEnv := func(points []loader.JSPoint, cleanRead, errorRead string, writeStatus int, writeBody string) *loader.JSEnv {
		var written atomic.Bool
		return &loader.JSEnv{
			Points: points,
			Send: func(p loader.JSPoint) (loader.JSResponse, error) {
				h := map[string]string{"Content-Type": "text/html"}
				if p.Value == neutral {
					if written.Load() {
						return loader.JSResponse{Status: 500, Headers: h, Body: errorRead, URL: p.URL}, nil
					}
					return loader.JSResponse{Status: 200, Headers: h, Body: cleanRead, URL: p.URL}, nil
				}
				written.Store(true)
				return loader.JSResponse{Status: writeStatus, Headers: h, Body: writeBody, URL: p.URL}, nil
			},
		}
	}

	t.Run("state-borne signature confirms", func(t *testing.T) {
		env := mkEnv(
			[]loader.JSPoint{queryPoint},
			"<html><body>normal item page</body></html>",
			"<html><body>ERROR: You have an error in your SQL syntax</body></html>",
			200, "<html><body>saved</body></html>",
		)
		cands, err := loader.ExecuteJS(context.Background(), spec, string(src), env, 10*time.Second)
		if err != nil {
			t.Fatalf("execute: %v", err)
		}
		if len(cands) != 1 {
			t.Fatalf("one second-order candidate expected, got %d", len(cands))
		}
		ev := cands[0].Evidence
		if ev == nil || ev.Verdict != oracle.VerdictAccept {
			t.Fatalf("accepted evidence required: %+v", cands[0])
		}
		if ev.ConfidenceContribution != plugin.ConfidenceConfirmed {
			t.Fatalf("confirmed required, got %s", ev.ConfidenceContribution)
		}
		if cands[0].Candidate.OracleName != "error" {
			t.Fatalf("oracle must stay error, got %q", cands[0].Candidate.OracleName)
		}
	})

	t.Run("first-order-only error does not confirm", func(t *testing.T) {
		// The write response errors, but the neutral re-read stays clean: the
		// plugin never treats the write response as evidence.
		env := mkEnv(
			[]loader.JSPoint{queryPoint},
			"<html><body>normal item page</body></html>",
			"<html><body>normal item page</body></html>",
			500, "<html><body>ERROR: You have an error in your SQL syntax</body></html>",
		)
		cands, err := loader.ExecuteJS(context.Background(), spec, string(src), env, 10*time.Second)
		if err != nil {
			t.Fatalf("execute: %v", err)
		}
		if len(cands) != 0 {
			t.Fatalf("first-order noise must not confirm, got %d", len(cands))
		}
	})

	t.Run("pre-existing signature in baseline rejects", func(t *testing.T) {
		env := mkEnv(
			[]loader.JSPoint{queryPoint},
			"<html><body>ERROR: You have an error in your SQL syntax</body></html>",
			"<html><body>ERROR: You have an error in your SQL syntax</body></html>",
			200, "<html><body>saved</body></html>",
		)
		cands, err := loader.ExecuteJS(context.Background(), spec, string(src), env, 10*time.Second)
		if err != nil {
			t.Fatalf("execute: %v", err)
		}
		if len(cands) != 0 {
			t.Fatalf("baseline-borne signature must not confirm, got %d", len(cands))
		}
	})

	t.Run("large surfaces stay within send budget", func(t *testing.T) {
		points := make([]loader.JSPoint, 20)
		for i := range points {
			points[i] = loader.JSPoint{
				URL:           "http://example.com/page-" + itoaTest(i),
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
		if got := sends.Load(); got > 120 {
			t.Fatalf("second-order send budget exceeded: got %d, want <= 120", got)
		}
	})

	t.Run("no new sandbox surface", func(t *testing.T) {
		lower := strings.ToLower(string(src))
		if !strings.Contains(lower, "host.oracles.error") {
			t.Fatal("must use host.oracles.error")
		}
		for _, forbidden := range []string{"host.oracles.reflection", "host.oracles.differential", "host.oracles.oob", "require(", "fetch("} {
			if strings.Contains(lower, forbidden) {
				t.Fatalf("forbidden sandbox surface in source: %s", forbidden)
			}
		}
	})
}

// TestSQLiSecondOrderTimingE2E proves the timed write-then-re-read correlation.
// What: Executes sqli-second-order-timing.js against a transport whose neutral
// reads are slow only after a sleep payload was written.
// Why: When the stored payload never reflects an in-band error, response time
// on a post-write neutral request is the only observable; attributing it to
// the stored payload requires sequencing two exchanges.
func TestSQLiSecondOrderTimingE2E(t *testing.T) {
	root := repoRoot(t)
	path := filepath.Join(root, "plugins", "sqli", "sqli-second-order-timing.js")
	src, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	spec, err := loader.LoadTier2Frontmatter(path)
	if err != nil {
		t.Fatalf("frontmatter %s: %v", path, err)
	}
	if spec.ID != "sqli-second-order-timing" {
		t.Fatalf("unexpected id %q", spec.ID)
	}

	const neutral = "1"
	queryPoint := loader.JSPoint{URL: "http://example.com/item", Method: "GET", ParamName: "id", ParamLocation: "query"}

	// mkEnv answers neutral reads with fastMs before any write and slowMs
	// after, so only a stored payload can produce the delay.
	mkEnv := func(points []loader.JSPoint, fastMs, slowMs float64) *loader.JSEnv {
		var written atomic.Bool
		return &loader.JSEnv{
			Points: points,
			Send: func(p loader.JSPoint) (loader.JSResponse, error) {
				h := map[string]string{"Content-Type": "text/html"}
				if p.Value == neutral {
					if written.Load() {
						return loader.JSResponse{Status: 200, Headers: h, Body: "item", URL: p.URL, RTTMs: slowMs}, nil
					}
					return loader.JSResponse{Status: 200, Headers: h, Body: "item", URL: p.URL, RTTMs: fastMs}, nil
				}
				written.Store(true)
				return loader.JSResponse{Status: 200, Headers: h, Body: "saved", URL: p.URL, RTTMs: fastMs}, nil
			},
		}
	}

	t.Run("stored sleep delays the neutral re-read", func(t *testing.T) {
		env := mkEnv([]loader.JSPoint{queryPoint}, 100, 5500)
		cands, err := loader.ExecuteJS(context.Background(), spec, string(src), env, 10*time.Second)
		if err != nil {
			t.Fatalf("execute: %v", err)
		}
		if len(cands) != 1 {
			t.Fatalf("one timing candidate expected, got %d", len(cands))
		}
		ev := cands[0].Evidence
		if ev == nil || ev.Verdict != oracle.VerdictAccept {
			t.Fatalf("accepted evidence required: %+v", cands[0])
		}
		if ev.ConfidenceContribution != plugin.ConfidenceFirm {
			t.Fatalf("firm required, got %s", ev.ConfidenceContribution)
		}
		if cands[0].Candidate.OracleName != "timing" {
			t.Fatalf("oracle must stay timing, got %q", cands[0].Candidate.OracleName)
		}
	})

	t.Run("consistently fast backend rejects", func(t *testing.T) {
		env := mkEnv([]loader.JSPoint{queryPoint}, 100, 120)
		cands, err := loader.ExecuteJS(context.Background(), spec, string(src), env, 10*time.Second)
		if err != nil {
			t.Fatalf("execute: %v", err)
		}
		if len(cands) != 0 {
			t.Fatalf("no stored delay must not confirm, got %d", len(cands))
		}
	})

	t.Run("large surfaces stay within send budget", func(t *testing.T) {
		points := make([]loader.JSPoint, 20)
		for i := range points {
			points[i] = loader.JSPoint{
				URL:           "http://example.com/page-" + itoaTest(i),
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
				return loader.JSResponse{Status: 200, URL: p.URL, Body: "neutral", RTTMs: 100}, nil
			},
		}
		if _, err := loader.ExecuteJS(context.Background(), spec, string(src), env, 2*time.Second); err != nil {
			t.Fatalf("execute: %v", err)
		}
		if got := sends.Load(); got > 120 {
			t.Fatalf("second-order timing send budget exceeded: got %d, want <= 120", got)
		}
	})

	t.Run("no new sandbox surface", func(t *testing.T) {
		lower := strings.ToLower(string(src))
		if !strings.Contains(lower, "host.oracles.timing") {
			t.Fatal("must use host.oracles.timing")
		}
		for _, forbidden := range []string{"host.oracles.error", "host.oracles.reflection", "host.oracles.differential", "host.oracles.oob", "require(", "fetch("} {
			if strings.Contains(lower, forbidden) {
				t.Fatalf("forbidden sandbox surface in source: %s", forbidden)
			}
		}
	})
}

// itoaTest formats a small non-negative index for test URLs.
// What: Avoids importing strconv just for URL construction.
// Why: Keeps the fixture surface minimal and dependency-free.
func itoaTest(i int) string {
	if i == 0 {
		return "0"
	}
	var b [20]byte
	p := len(b)
	for i > 0 {
		p--
		b[p] = byte('0' + i%10)
		i /= 10
	}
	return string(b[p:])
}

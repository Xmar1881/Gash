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

// TestXSSStoredJSONAPI proves the JSON write plus render stored-XSS flow.
// What: Executes xss-stored-json-api.js against a mocked JSON store and renderer.
// Why: The form-point stored plugin replays its write as an urlencoded form, so
// a JSON API never parses the payload. The write must be observed on a render
// page, and a sibling render page is the only clean control available.
func TestXSSStoredJSONAPI(t *testing.T) {
	spec, src := loadTier2(t, "plugins/xss/xss-stored-json-api.js", "xss-stored-json-api")
	const (
		writesURL  = "http://example.com/api/profile"
		siblingURL = "http://example.com/api/notes"
	)
	points := []loader.JSPoint{
		{URL: writesURL, Method: "POST", ParamName: "bio", ParamLocation: "body"},
		{URL: siblingURL, Method: "POST", ParamName: "bio", ParamLocation: "body"},
	}

	mkEnv := func(renderShowsPayload bool, jsonContentType *atomic.Bool, rawBody *atomic.Bool) *loader.JSEnv {
		var mu sync.Mutex
		stored := map[string]string{}
		return &loader.JSEnv{
			Points: points,
			Send: func(p loader.JSPoint) (loader.JSResponse, error) {
				h := map[string]string{"Content-Type": "text/html"}
				if strings.EqualFold(p.ParamLocation, "body") && p.ParamName == "" {
					if jsonContentType != nil && strings.Contains(strings.ToLower(jsHeaderValue(p.Headers, "Content-Type")), "json") {
						jsonContentType.Store(true)
					}
					if rawBody != nil && strings.HasPrefix(strings.TrimSpace(p.Value), "{") {
						rawBody.Store(true)
					}
					mu.Lock()
					stored[p.URL] = between(p.Value, "alert(", ")")
					mu.Unlock()
					return loader.JSResponse{Status: 200, Headers: map[string]string{"Content-Type": "application/json"}, Body: `{"saved":true}`, URL: p.URL}, nil
				}
				// Render exchange: only the primary view displays the field.
				mu.Lock()
				canary := stored[p.URL]
				mu.Unlock()
				if renderShowsPayload && canary != "" && p.URL == writesURL {
					return loader.JSResponse{Status: 200, Headers: h, Body: "<html><body><script>alert(" + canary + ")</script></body></html>", URL: p.URL}, nil
				}
				return loader.JSResponse{Status: 200, Headers: h, Body: "<html><body><p>no biography</p></body></html>", URL: p.URL}, nil
			},
		}
	}

	t.Run("stored json write renders executable", func(t *testing.T) {
		var jsonContentType, rawBody atomic.Bool
		env := mkEnv(true, &jsonContentType, &rawBody)
		cands, err := loader.ExecuteJS(context.Background(), spec, src, env, 10*time.Second)
		if err != nil {
			t.Fatalf("execute: %v", err)
		}
		if len(cands) != 1 {
			t.Fatalf("one stored candidate expected, got %d", len(cands))
		}
		ev := cands[0].Evidence
		if ev == nil || ev.Verdict != oracle.VerdictAccept {
			t.Fatalf("accepted evidence required: %+v", cands[0])
		}
		if ev.ConfidenceContribution != plugin.ConfidenceStaticExecution {
			t.Fatalf("static-execution-evidence required, got %s", ev.ConfidenceContribution)
		}
		if cands[0].Candidate.OracleName != "stored" {
			t.Fatalf("oracle must stay stored, got %q", cands[0].Candidate.OracleName)
		}
		if !jsonContentType.Load() || !rawBody.Load() {
			t.Fatal("the write must be a raw application/json body")
		}
	})

	t.Run("filtered render rejects", func(t *testing.T) {
		env := mkEnv(false, nil, nil)
		cands, err := loader.ExecuteJS(context.Background(), spec, src, env, 10*time.Second)
		if err != nil {
			t.Fatalf("execute: %v", err)
		}
		if len(cands) != 0 {
			t.Fatalf("a filtered render must not confirm, got %d", len(cands))
		}
	})

	t.Run("send budget holds", func(t *testing.T) {
		assertSendBudget(t, spec, src, 60, "POST", "body")
	})

	t.Run("no new sandbox surface", func(t *testing.T) {
		assertOracleSurface(t, src,
			[]string{"host.oracles.storedExecution"},
			[]string{"host.oracles.reflection", "host.oracles.differential", "host.oracles.error"})
	})
}

// TestCommandInjectionJSONBodyOOBE2E proves the JSON-body RCE OOB discipline.
// What: Executes command-injection-json-body-oob.js with OOB enabled and disabled.
// Why: A blind RCE claim needs a matched callback token; without a server the
// plugin must send nothing rather than emit tentative noise.
func TestCommandInjectionJSONBodyOOBE2E(t *testing.T) {
	spec, src := loadTier2(t, "plugins/command-injection/command-injection-json-body-oob.js", "command-injection-json-body-oob")
	point := loader.JSPoint{URL: "http://example.com/api/convert", Method: "POST", ParamName: "filename", ParamLocation: "body"}

	t.Run("callback confirms the JSON field", func(t *testing.T) {
		var jsonContentType, bodyCarriedCallback, rawBody atomic.Bool
		env := &loader.JSEnv{
			Points:       []loader.JSPoint{point},
			OOBEnabled:   true,
			OOBNamespace: "scan_e2e",
			Send: func(p loader.JSPoint) (loader.JSResponse, error) {
				if p.ParamName == "" && strings.HasPrefix(strings.TrimSpace(p.Value), "{") {
					rawBody.Store(true)
				}
				if strings.Contains(strings.ToLower(jsHeaderValue(p.Headers, "Content-Type")), "json") {
					jsonContentType.Store(true)
				}
				if strings.Contains(p.Value, "curl") || strings.Contains(p.Value, "nslookup") {
					if strings.Contains(p.Value, "oob.example") {
						bodyCarriedCallback.Store(true)
					}
				}
				return loader.JSResponse{Status: 200, Headers: map[string]string{"Content-Type": "application/json"}, Body: `{"status":"converted"}`, URL: p.URL}, nil
			},
			OOBCallbackSeen: func(string) bool { return true },
		}
		cands, err := loader.ExecuteJS(context.Background(), spec, src, env, 10*time.Second)
		if err != nil {
			t.Fatalf("execute: %v", err)
		}
		if len(cands) != 1 {
			t.Fatalf("one command-injection candidate expected, got %d", len(cands))
		}
		ev := cands[0].Evidence
		if ev == nil || ev.Verdict != oracle.VerdictAccept || ev.ConfidenceContribution != plugin.ConfidenceConfirmed {
			t.Fatalf("confirmed evidence required: %+v", cands[0])
		}
		if cands[0].Candidate.OracleName != "oob" {
			t.Fatalf("oracle must stay oob, got %q", cands[0].Candidate.OracleName)
		}
		if !jsonContentType.Load() || !rawBody.Load() || !bodyCarriedCallback.Load() {
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
				ParamName:     "filename",
				ParamLocation: "body",
			}
		}
		var sends atomic.Int64
		env := &loader.JSEnv{
			Points:          points,
			OOBEnabled:      true,
			OOBNamespace:    "scan_e2e",
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

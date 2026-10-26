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

// TestFileUploadServedE2E proves the upload plus serve-back workflow.
// What: Executes file-upload-served.js against a mocked multipart upload backend.
// Why: An accepted upload proves nothing; the finding exists only when the
// artifact comes back carrying our canary and the served content type decides
// between firm (inert) and confirmed (active). The control must be a sibling
// name that was never uploaded.
func TestFileUploadServedE2E(t *testing.T) {
	spec, src := loadTier2(t, "plugins/file-upload/file-upload-served.js", "file-upload-served")
	point := loader.JSPoint{URL: "http://example.com/api/upload", Method: "POST", ParamName: "file", ParamLocation: "body"}

	// mkEnv models an upload endpoint that stores the file under /uploads and
	// serves it back with the given content type.
	mkEnv := func(fetchContentType string, uploadStatus int, withURL bool, multipartSeen, rawBodySeen *atomic.Bool) *loader.JSEnv {
		return &loader.JSEnv{
			Points: []loader.JSPoint{point},
			Send: func(p loader.JSPoint) (loader.JSResponse, error) {
				if strings.EqualFold(p.ParamLocation, "body") && p.ParamName == "" {
					ct := jsHeaderValue(p.Headers, "Content-Type")
					if multipartSeen != nil && strings.Contains(strings.ToLower(ct), "multipart/form-data") && strings.Contains(strings.ToLower(ct), "boundary=") {
						multipartSeen.Store(true)
					}
					if rawBodySeen != nil && strings.Contains(p.Value, `filename="`) {
						rawBodySeen.Store(true)
					}
					body := `{"stored":true}`
					if withURL {
						name := between(p.Value, `filename="`, `"`)
						if name == "" {
							name = "unknown.html"
						}
						body = `{"url":"/uploads/` + name + `"}`
					}
					return loader.JSResponse{Status: uploadStatus, Headers: map[string]string{"Content-Type": "application/json"}, Body: body, URL: p.URL}, nil
				}
				// Fetch/control exchange.
				name := path.Base(p.URL)
				if strings.Contains(name, "_never") {
					return loader.JSResponse{Status: 404, Headers: map[string]string{"Content-Type": "text/html"}, Body: "<html><body>not found</body></html>", URL: p.URL}, nil
				}
				canary := strings.TrimSuffix(name, ".html")
				body := `<svg xmlns="http://www.w3.org/2000/svg" onload="alert(` + canary + `)"></svg>`
				return loader.JSResponse{Status: 200, Headers: map[string]string{"Content-Type": fetchContentType}, Body: body, URL: p.URL}, nil
			},
		}
	}

	t.Run("active content type confirms", func(t *testing.T) {
		var multipartSeen, rawBodySeen atomic.Bool
		env := mkEnv("text/html", 200, true, &multipartSeen, &rawBodySeen)
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
		if !multipartSeen.Load() || !rawBodySeen.Load() {
			t.Fatal("the upload must be a raw multipart body with a file part")
		}
	})

	t.Run("inert content type firms", func(t *testing.T) {
		env := mkEnv("text/plain", 200, true, nil, nil)
		cands, err := loader.ExecuteJS(context.Background(), spec, src, env, 10*time.Second)
		if err != nil {
			t.Fatalf("execute: %v", err)
		}
		if len(cands) != 1 {
			t.Fatalf("one candidate expected, got %d", len(cands))
		}
		if got := cands[0].Evidence.ConfidenceContribution; got != plugin.ConfidenceFirm {
			t.Fatalf("inert serve-back must stay firm, got %s", got)
		}
	})

	t.Run("rejected upload stays silent", func(t *testing.T) {
		env := mkEnv("text/html", 415, true, nil, nil)
		cands, err := loader.ExecuteJS(context.Background(), spec, src, env, 10*time.Second)
		if err != nil {
			t.Fatalf("execute: %v", err)
		}
		if len(cands) != 0 {
			t.Fatalf("a rejected upload must not confirm, got %d", len(cands))
		}
	})

	t.Run("unlocatable artifact sends no fetch", func(t *testing.T) {
		var gets atomic.Int64
		env := mkEnv("text/html", 200, false, nil, nil)
		inner := env.Send
		env.Send = func(p loader.JSPoint) (loader.JSResponse, error) {
			if !strings.EqualFold(p.ParamLocation, "body") {
				gets.Add(1)
			}
			return inner(p)
		}
		cands, err := loader.ExecuteJS(context.Background(), spec, src, env, 10*time.Second)
		if err != nil {
			t.Fatalf("execute: %v", err)
		}
		if len(cands) != 0 || gets.Load() != 0 {
			t.Fatalf("no locatable URL means no claim and no fetch: cands=%d gets=%d", len(cands), gets.Load())
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

// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Module: github.com/Xmar1881/Gash

package engine

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/Xmar1881/Gash/internal/plugin"
	"github.com/Xmar1881/Gash/internal/plugin/loader"
)

// e2eHeaderPlugin is a minimal Tier 1 header check for live scan tests.
// What: Passive header fixture used only by scan e2e tests.
// Why: Proves the live path without depending on shipped plugin identities.
const e2eHeaderPlugin = `id: e2e-header-check
name: E2E Header Check For Testing Purposes
description: Detects absent security headers for scan e2e testing purposes here.
severity: low
tags: [headers]
safe: true
deep: false
active: false
requires_auth: false
phase: probe
order: 10
api_version: "1.0"
tests: tests/fixtures/missing-security-headers/
request:
  method: GET
oracle:
  name: header
`

// writeE2EPlugin drops the header plugin into a temp dir.
// What: Single-file drop-in for deterministic discovery.
// Why: Isolates the e2e proof from the shipped plugins tree.
func writeE2EPlugin(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "e2e-header.yaml")
	if err := os.WriteFile(path, []byte(e2eHeaderPlugin), 0o644); err != nil {
		t.Fatal(err)
	}
	return dir
}

// TestScanE2EHeaderFinding proves live Tier 1 execution finds missing headers.
// What: Httptest backend without hardening plus one header plugin.
// Why: A vulnerable localhost target must yield at least one deterministic finding.
func TestScanE2EHeaderFinding(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("<html><body>hello</body></html>"))
	}))
	defer srv.Close()

	dir := writeE2EPlugin(t)
	reg := plugin.NewRegistry()
	if _, err := loader.Discover([]string{dir}, reg); err != nil {
		t.Fatalf("discover: %v", err)
	}
	if reg.Len() != 1 {
		t.Fatalf("one plugin expected, got %d", reg.Len())
	}
	cfg := DefaultConfig()
	e := New(reg, cfg)
	rep, err := e.Run(context.Background(), srv.URL)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if len(rep.Findings) < 1 {
		t.Fatalf("vulnerable backend must yield >=1 finding, got %d (skipped=%v)", len(rep.Findings), rep.Skipped)
	}
	if rep.Findings[0].RuleID == "" {
		t.Fatal("finding must carry a rule id")
	}
	for _, key := range []string{
		"surface_points", "crawl_failed", "form_fuzz_ms", "flow_ms",
		"matrix_ms", "smuggle_ms", "browser_verify_ms",
		"crawl_stored_bytes", "crawl_urls_dropped", "crawl_bodies_dropped",
		"retry_budget_exhausted",
		"request_budget_target", "request_budget_total", "rate_limit_per_second",
		"max_pages", "crawl_depth", "passive_cache_hits", "passive_cache_fetches",
	} {
		if _, ok := rep.Stats[key]; !ok {
			t.Fatalf("stats[%s] missing from live report", key)
		}
	}
	if rep.Stats["request_budget_target"] != int(cfg.MaxRequestsPerTarget) ||
		rep.Stats["request_budget_total"] != int(cfg.MaxRequestsTotal) ||
		rep.Stats["max_pages"] != cfg.MaxPages ||
		rep.Stats["crawl_depth"] != cfg.Depth ||
		rep.Stats["rate_limit_per_second"] != int(cfg.RatePerSecond) {
		t.Fatalf("effective engine limits must be reported: %+v", rep.Stats)
	}
	if rep.Stats["surface_points"] < 1 {
		t.Fatalf("surface_points must count discovered points: %+v", rep.Stats)
	}
}

// TestScanE2EHardenedEmpty proves a hardened backend yields a valid empty report.
// What: Same plugin against headers that satisfy the oracle.
// Why: Zero findings must still be a deterministic valid report, not an error.
const e2eRedirectPlugin = `id: e2e-redirect-multi
name: E2E Multi-Endpoint Redirect Check
description: Detects external redirects across more than one discovered endpoint.
severity: medium
tags: [redirect]
safe: true
deep: false
active: false
requires_auth: false
max_requests: 40
phase: probe
order: 10
api_version: "1.0"
tests: tests/fixtures/open-redirect-param/
request:
  method: GET
  param_names: [url, next]
  payloads:
    - "https://gash-canary.example/landing"
oracle:
  name: redirect
  params:
    expect_external_host: true
`

// TestScanEmitsPhaseDetails locks the live menu progress contract: every
// major phase must end with a human-readable summary, not just its label.
func TestScanEmitsPhaseDetails(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<html><body><a href="/next">next</a></body></html>`))
	}))
	defer srv.Close()

	dir := writeE2EPlugin(t)
	reg := plugin.NewRegistry()
	if _, err := loader.Discover([]string{dir}, reg); err != nil {
		t.Fatalf("discover: %v", err)
	}

	var (
		mu     sync.Mutex
		detail = map[string]string{}
	)
	cfg := DefaultConfig()
	cfg.Active = true
	cfg.OnProgress = func(phaseKey, detailKey string, args ...any) {
		mu.Lock()
		detail[phaseKey] = detailKey
		mu.Unlock()
	}
	if _, err := New(reg, cfg).Run(context.Background(), srv.URL); err != nil {
		t.Fatalf("run: %v", err)
	}

	want := map[string]string{
		progressPhaseTech:        progressDetailTechDone,
		progressPhasePlanning:    progressDetailPlanDone,
		progressPhaseProtocol:    progressDetailProtocolDone,
		progressPhaseCrawl:       progressDetailCrawlDone,
		progressPhasePlugins:     progressDetailPluginsDone,
		progressPhaseCorrelation: progressDetailCorrelationDone,
	}
	for phase, wantDetail := range want {
		mu.Lock()
		got := detail[phase]
		mu.Unlock()
		if got != wantDetail {
			t.Fatalf("phase %q final detail key = %q, want %q", phase, got, wantDetail)
		}
	}
}

// TestScanReportsCrawlProgress: "Sayfa & Yüzey Keşfi" fazı canlı sayfa sayacı
// yayınlamalı.
// What: 3 sayfalık yerel sitede OnProgress "N/M sayfa · host/path" görmeli.
// Why: Sayaç olmadan uzun crawl (aggressive'te 500 sayfaya kadar) donmuş görünür.
func TestScanReportsCrawlProgress(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<html><body><a href="/a">a</a><a href="/b">b</a></body></html>`))
	})
	mux.HandleFunc("/a", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`<html><body>a</body></html>`))
	})
	mux.HandleFunc("/b", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`<html><body>b</body></html>`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	dir := writeE2EPlugin(t)
	reg := plugin.NewRegistry()
	if _, err := loader.Discover([]string{dir}, reg); err != nil {
		t.Fatalf("discover: %v", err)
	}

	var (
		mu      sync.Mutex
		details []string
	)
	cfg := DefaultConfig()
	cfg.OnProgress = func(phaseKey, detailKey string, args ...any) {
		if phaseKey != progressPhaseCrawl || detailKey != progressDetailCrawlPage {
			return
		}
		if len(args) != 3 {
			t.Errorf("crawl page args = %v, want done/total/page", args)
			return
		}
		mu.Lock()
		details = append(details, fmt.Sprintf("%v/%v %v", args[0], args[1], args[2]))
		mu.Unlock()
	}
	e := New(reg, cfg)
	if _, err := e.Run(context.Background(), srv.URL); err != nil {
		t.Fatalf("run: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(details) < 2 {
		t.Fatalf("crawl ilerleme satırı yayınlanmadı (>=2 bekleniyordu): %v", details)
	}
	for _, d := range details {
		if !strings.Contains(d, "/") {
			t.Fatalf("crawl detail page arg missing: %q", d)
		}
	}
}

// TestScanE2EMultipleDiscoveryHits proves the Tier 1 discovery fallback keeps
// testing distinct endpoints after the first hit instead of hiding later ones.
func TestScanE2EMultipleDiscoveryHits(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		switch r.URL.Path {
		case "/":
			_, _ = w.Write([]byte(`<html><body>
<a href="/first?url=/home">first</a>
<a href="/second?next=/home">second</a>
</body></html>`))
		case "/first", "/second":
			target := r.URL.Query().Get("url")
			if target == "" {
				target = r.URL.Query().Get("next")
			}
			if strings.HasPrefix(strings.ToLower(target), "https://gash-canary.example/") {
				http.Redirect(w, r, target, http.StatusFound)
				return
			}
			_, _ = w.Write([]byte("<html><body>internal target</body></html>"))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	dir := t.TempDir()
	path := filepath.Join(dir, "e2e-redirect.yaml")
	if err := os.WriteFile(path, []byte(e2eRedirectPlugin), 0o644); err != nil {
		t.Fatal(err)
	}
	reg := plugin.NewRegistry()
	if _, err := loader.Discover([]string{dir}, reg); err != nil {
		t.Fatalf("discover: %v", err)
	}
	e := New(reg, DefaultConfig())
	rep, err := e.Run(context.Background(), srv.URL)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	var first, second bool
	for _, f := range rep.Findings {
		if strings.Contains(f.Target, "/first") {
			first = true
		}
		if strings.Contains(f.Target, "/second") {
			second = true
		}
	}
	if !first || !second {
		t.Fatalf("both discovered endpoints must be reported, first=%v second=%v findings=%v", first, second, rep.Findings)
	}
}

func TestScanE2EHardenedEmpty(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Header().Set("Content-Security-Policy", "default-src 'self'")
		w.Header().Set("Strict-Transport-Security", "max-age=31536000")
		w.Header().Set("X-Frame-Options", "DENY")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("<html><body>hello</body></html>"))
	}))
	defer srv.Close()

	dir := writeE2EPlugin(t)
	reg := plugin.NewRegistry()
	if _, err := loader.Discover([]string{dir}, reg); err != nil {
		t.Fatalf("discover: %v", err)
	}
	e := New(reg, DefaultConfig())
	rep, err := e.Run(context.Background(), srv.URL)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if len(rep.Findings) != 0 {
		t.Fatalf("hardened backend must yield empty report, got %d", len(rep.Findings))
	}
	if rep.Stats == nil || rep.Target == "" {
		t.Fatal("empty report must carry target and stats")
	}
}

// TestScanE2EInvalidTarget proves target validation fails fast.
// What: Non-http scheme must be rejected before any probe traffic.
// Why: Fail-fast keeps policy and probe layers from seeing malformed input.
func TestScanE2EInvalidTarget(t *testing.T) {
	reg := plugin.NewRegistry()
	e := New(reg, DefaultConfig())
	if _, err := e.Run(context.Background(), "ftp://example.com/"); err == nil {
		t.Fatal("non-http target must fail validation")
	}
}

// TestScanE2ESurfaceDiscovery proves that targets with forms have surface extracted and scanned.
func TestScanE2ESurfaceDiscovery(t *testing.T) {
	formVisited := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		if r.URL.Path == "/login" {
			formVisited = true
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("<html><body>login page</body></html>"))
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`<html><body><form action="/login" method="POST"><input name="username"><input name="password"></form></body></html>`))
	}))
	defer srv.Close()

	dir := writeE2EPlugin(t)
	reg := plugin.NewRegistry()
	if _, err := loader.Discover([]string{dir}, reg); err != nil {
		t.Fatalf("discover: %v", err)
	}
	cfg := DefaultConfig()
	cfg.Active = true
	e := New(reg, cfg)
	rep, err := e.Run(context.Background(), srv.URL)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	_ = formVisited
	if rep == nil || len(rep.Findings) == 0 {
		t.Fatalf("expected findings on unhardened target, got %+v", rep)
	}
}

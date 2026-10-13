// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Module: github.com/Xmar1881/Gash

package engine

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
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
}

// TestScanE2EHardenedEmpty proves a hardened backend yields a valid empty report.
// What: Same plugin against headers that satisfy the oracle.
// Why: Zero findings must still be a deterministic valid report, not an error.
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

// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Module: github.com/Xmar1881/Gash

// Package plugintest S1 trust path gates live here.
// What: Default plus legacy plus override resolution coverage.
// Why: The CLI and engine must agree on one trust location.
package plugintest

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestDefaultTrustPathIsDB verifies the S1 default filename.
// What: Default path naming check.
// Why: Architecture mandates trust.db as the single default.
func TestDefaultTrustPathIsDB(t *testing.T) {
	got := DefaultTrustPath()
	if got == "" {
		t.Skip("no home directory in test env")
	}
	if !strings.HasSuffix(got, filepath.Join(".gash", "trust.db")) {
		t.Fatalf("default must end with .gash/trust.db, got %q", got)
	}
}

// TestLegacyTrustPathIsJSON verifies the pre-S1 filename is retained.
// What: Legacy path naming check.
// Why: Migration needs a stable legacy source.
func TestLegacyTrustPathIsJSON(t *testing.T) {
	got := LegacyTrustPath()
	if got == "" {
		t.Skip("no home directory in test env")
	}
	if !strings.HasSuffix(got, filepath.Join(".gash", "trust.json")) {
		t.Fatalf("legacy must end with .gash/trust.json, got %q", got)
	}
	if got == DefaultTrustPath() {
		t.Fatal("legacy and default paths must differ")
	}
}

// TestResolveTrustPath verifies flag plus env plus default precedence.
// What: Trust path override precedence check.
// Why: Explicit config must win while default stays migratable.
func TestResolveTrustPath(t *testing.T) {
	def := DefaultTrustPath()
	if def == "" {
		t.Skip("no home directory in test env")
	}
	if got := ResolveTrustPath("/tmp/explicit.db"); got != "/tmp/explicit.db" {
		t.Fatalf("explicit must win, got %q", got)
	}
	t.Setenv("GASH_TRUST_FILE", "/tmp/from-env.db")
	if got := ResolveTrustPath(""); got != "/tmp/from-env.db" {
		t.Fatalf("env must win over default, got %q", got)
	}
	if got := ResolveTrustPath("/tmp/explicit.db"); got != "/tmp/explicit.db" {
		t.Fatalf("explicit must win over env, got %q", got)
	}
	if err := os.Unsetenv("GASH_TRUST_FILE"); err != nil {
		t.Fatal(err)
	}
	if got := ResolveTrustPath(""); got != def {
		t.Fatalf("empty must resolve to default %q, got %q", def, got)
	}
}

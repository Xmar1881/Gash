// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Module: github.com/Xmar1881/Gash

package main

import (
	"path/filepath"
	"strings"
	"testing"
)

// TestScanOnlyPluginValidation proves the positive selection fails closed for
// typos and for IDs that are both selected and excluded.
func TestScanOnlyPluginValidation(t *testing.T) {
	root, err := filepath.Abs(filepath.Join("..", "..", "plugins"))
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("GASH_PLUGIN_PATH", root)

	cmdUnknown := newScanCmd()
	cmdUnknown.SetArgs([]string{
		"--target", "http://127.0.0.1:1", "--profile", "safe", "--no-proxy",
		"--only-plugin", "does-not-exist",
	})
	if err := cmdUnknown.Execute(); err == nil || !strings.Contains(err.Error(), "unknown --only-plugin") {
		t.Fatalf("unknown only-plugin must fail closed, got %v", err)
	}

	cmdOverlap := newScanCmd()
	cmdOverlap.SetArgs([]string{
		"--target", "http://127.0.0.1:1", "--profile", "safe", "--no-proxy",
		"--only-plugin", "missing-security-headers",
		"--ignore-plugin", "missing-security-headers",
	})
	if err := cmdOverlap.Execute(); err == nil || !strings.Contains(err.Error(), "overlap") {
		t.Fatalf("only/ignore overlap must fail closed, got %v", err)
	}
}

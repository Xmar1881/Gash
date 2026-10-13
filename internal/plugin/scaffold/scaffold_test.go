// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Module: github.com/Xmar1881/Gash

package scaffold

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Xmar1881/Gash/internal/plugin/loader"
	"github.com/Xmar1881/Gash/internal/plugintest"
)

// TestGenerateYAMLWritesPassingSkeleton locks the Tier 1 happy path.
// What: Generates a YAML skeleton then validates plus tests it.
// Why: `plugins new` must produce output that clears both gates untouched.
func TestGenerateYAMLWritesPassingSkeleton(t *testing.T) {
	dir := t.TempDir()
	res, err := Generate(dir, "demo-starter", TierYAML, false)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	spec, file, err := loader.LoadTier1File(res.PluginPath)
	if err != nil {
		t.Fatalf("validate generated yaml: %v", err)
	}
	if spec.ID != "demo-starter" {
		t.Fatalf("id = %q", spec.ID)
	}
	sum, err := plugintest.Run(context.Background(), spec.ID, file.Oracle.Name, res.FixtureRoot, true)
	if err != nil {
		t.Fatalf("run fixtures: %v", err)
	}
	if !sum.Pass || sum.Precision < 0.99 {
		t.Fatalf("skeleton must pass gate: pass=%v precision=%.4f", sum.Pass, sum.Precision)
	}
}

// TestGenerateJSWritesPassingSkeleton locks the Tier 2 happy path.
// What: Generates a JS skeleton then checks frontmatter plus fixtures.
// Why: The JS oracle inference and the fixture set must agree on reflection.
func TestGenerateJSWritesPassingSkeleton(t *testing.T) {
	dir := t.TempDir()
	res, err := Generate(dir, "demo-js-starter", TierJS, false)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	spec, err := loader.LoadTier2Frontmatter(res.PluginPath)
	if err != nil {
		t.Fatalf("validate generated js: %v", err)
	}
	if spec.ID != "demo-js-starter" {
		t.Fatalf("id = %q", spec.ID)
	}
	data, err := os.ReadFile(res.PluginPath)
	if err != nil {
		t.Fatal(err)
	}
	if got := plugintest.InferJSOracle(string(data)); got != "reflection" {
		t.Fatalf("inferred oracle = %q, want reflection", got)
	}
	sum, err := plugintest.Run(context.Background(), spec.ID, "reflection", res.FixtureRoot, true)
	if err != nil {
		t.Fatalf("run fixtures: %v", err)
	}
	if !sum.Pass || sum.Precision < 0.99 {
		t.Fatalf("skeleton must pass gate: pass=%v precision=%.4f", sum.Pass, sum.Precision)
	}
}

// TestGenerateRejectsBadID proves fail-fast validation.
// What: Rejects empty and non-slug identifiers.
// Why: Bad names must never reach the registry or the filesystem.
func TestGenerateRejectsBadID(t *testing.T) {
	dir := t.TempDir()
	for _, bad := range []string{"", "Bad_Name", "UPPER", "has space"} {
		if _, err := Generate(dir, bad, TierYAML, false); err == nil {
			t.Fatalf("id %q must fail", bad)
		}
	}
}

// TestGenerateRefusesOverwriteWithoutForce proves safe defaults.
// What: Second generation without --force fails, with --force succeeds.
// Why: Scaffolding must never silently destroy contributor work.
func TestGenerateRefusesOverwriteWithoutForce(t *testing.T) {
	dir := t.TempDir()
	if _, err := Generate(dir, "dup-plugin", TierYAML, false); err != nil {
		t.Fatalf("first generate: %v", err)
	}
	if _, err := Generate(dir, "dup-plugin", TierYAML, false); err == nil {
		t.Fatal("second generate without force must fail")
	}
	if _, err := Generate(dir, "dup-plugin", TierYAML, true); err != nil {
		t.Fatalf("generate with force: %v", err)
	}
}

// TestParseTierAcceptsAliases checks flag normalization.
// What: yaml variants map to Tier 1, js to Tier 2, others fail.
// Why: CLI errors stay consistent for every caller of the flag.
func TestParseTierAcceptsAliases(t *testing.T) {
	for _, raw := range []string{"yaml", "yml", "json", "", "YAML"} {
		got, err := ParseTier(raw)
		if err != nil || got != TierYAML {
			t.Fatalf("tier %q = %v, %v", raw, got, err)
		}
	}
	got, err := ParseTier("js")
	if err != nil || got != TierJS {
		t.Fatalf("tier js = %v, %v", got, err)
	}
	if _, err := ParseTier("native"); err == nil {
		t.Fatal("native must fail for `new`")
	}
	if !strings.Contains(filepath.Base(t.TempDir()), "") {
		t.Fatal("unreachable")
	}
}

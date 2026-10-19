// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Module: github.com/Xmar1881/Gash

package bench

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// TestManualScanDebug is a development aid: it starts the fixture lab, scans
// it with a freshly built gash binary and dumps the raw scan report
// (dist/debug-scan.json). Skipped unless GASH_BENCH_DEBUG=1 is set.
func TestManualScanDebug(t *testing.T) {
	if os.Getenv("GASH_BENCH_DEBUG") != "1" {
		t.Skip("set GASH_BENCH_DEBUG=1 to run the manual fixture scan dump")
	}
	repo := repoRoot(t)
	name := "gash-debug"
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	bin := filepath.Join(t.TempDir(), name)
	build := exec.Command("go", "build", "-o", bin, "./cmd/gash")
	build.Dir = repo
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build: %v: %s", err, out)
	}
	lab, err := StartFixtureLab()
	if err != nil {
		t.Fatalf("lab: %v", err)
	}
	defer lab.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()
	rawPath := filepath.Join(repo, "dist", "debug-scan.json")
	target := lab.URL()
	if p := os.Getenv("GASH_BENCH_DEBUG_PATH"); p != "" {
		target += p
	}
	args := []string{
		"scan", "--target", target, "--format", "json", "--output", rawPath,
		"--show-tentative",
		"--profile", "standard", "--active", "--rate-limit", "80",
		"--plugin-timeout", "20s", "--request-timeout", "2s",
		"--max-requests-total", "6000", "--max-requests-per-target", "3000",
		"--scope", "127.0.0.1",
	}
	args = append(args, strings.Fields(os.Getenv("GASH_BENCH_DEBUG_ARGS"))...)
	cmd := exec.CommandContext(ctx, bin, args...)
	cmd.Dir = repo
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Logf("scan exit: %v", err)
	}
	if len(out) > 2000 {
		out = out[len(out)-2000:]
	}
	t.Logf("scan tail:\n%s", out)

	raw, err := os.ReadFile(rawPath)
	if err != nil {
		t.Fatalf("read raw report: %v", err)
	}
	var report struct {
		Findings []map[string]any `json:"findings"`
		Skipped  []map[string]any `json:"skipped"`
		Stats    map[string]any   `json:"stats"`
	}
	if err := json.Unmarshal(raw, &report); err != nil {
		t.Fatalf("parse raw report: %v", err)
	}
	t.Logf("raw findings=%d skipped=%d", len(report.Findings), len(report.Skipped))
	for _, s := range report.Skipped {
		t.Logf("  skipped %v: %v", s["plugin_id"], s["reason"])
	}
	for _, f := range report.Findings {
		ev, _ := json.Marshal(f["evidence"])
		if len(ev) > 220 {
			ev = ev[:220]
		}
		t.Logf("  finding %v | %v | %v | %s", f["plugin_id"], f["target"], f["confidence"], ev)
	}
	t.Logf("stats: %v", report.Stats)
}

func repoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 6; i++ {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		dir = filepath.Dir(dir)
	}
	t.Fatal("repo root not found")
	return ""
}

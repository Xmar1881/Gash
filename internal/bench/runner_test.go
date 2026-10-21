// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Module: github.com/Xmar1881/Gash

package bench

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

// TestRunnerEndToEndFixtures is the critical-detector gate: a real gash binary
// scans the real fixture lab through the full runner and the report must show
// zero false positives, no not-run outcomes, verified reflected-XSS detection,
// and clean trap behavior. Slow; skipped with -short.
func TestRunnerEndToEndFixtures(t *testing.T) {
	if testing.Short() {
		t.Skip("end-to-end benchmark run skipped in -short mode")
	}
	repo := repoRoot(t)
	name := "gash-e2e"
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	bin := filepath.Join(t.TempDir(), name)
	build := exec.Command("go", "build", "-o", bin, "./cmd/gash")
	build.Dir = repo
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build gash: %v: %s", err, out)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Minute)
	defer cancel()
	outDir := t.TempDir()
	runner := NewRunner(RunOptions{
		DatasetPath: filepath.Join(repo, "bench", "datasets", "fixtures.yaml"),
		OutDir:      outDir,
		RepoDir:     repo,
		GashBin:     bin,
		Tools:       []string{"gash"},
		Logf:        t.Logf,
	})
	rep, err := runner.Run(ctx)
	if err != nil {
		t.Fatalf("runner: %v", err)
	}

	gash := rep.Tools["gash"]
	if gash == nil || !gash.Available {
		t.Fatalf("gash must be available: %+v", gash)
	}
	if gash.Score.NotRun != 0 {
		t.Fatalf("no gash outcome may be not-run: %+v", gash.Score)
	}
	if gash.Score.FP != 0 {
		var fps []string
		for _, o := range rep.Outcomes["gash"] {
			if o.Status == StatusFP {
				fps = append(fps, o.Scenario)
			}
		}
		t.Fatalf("false positives on a non-vulnerable fixture: %v", fps)
	}

	for _, o := range rep.Outcomes["gash"] {
		if !o.Verification.Verified {
			continue
		}
		switch {
		case o.Category == "xss-reflected" && o.Expected == ExpectVulnerable:
			if o.Status != StatusTP {
				t.Fatalf("critical detector regression: %s is %s (expected tp)", o.Scenario, o.Status)
			}
		case o.Expected != ExpectVulnerable:
			if o.Status != StatusTN {
				t.Fatalf("trap scenario %s (%s) must stay tn, got %s", o.Scenario, o.Expected, o.Status)
			}
		}
	}

	// The fixtures dataset runs the standard profile, which intentionally does
	// not enable the execution detector. Browser-verified DOM detection is
	// covered by TestDeepVerifyXSSHashRoute and the native benchmark instead.
	if domOut := outcomeByID(rep.Outcomes["gash"], "xss-dom-hash-sink"); domOut != nil && domOut.Verification.Verified {
		t.Logf("DOM scenario verified with standard-profile scan: status=%s (detection is deep-profile only)", domOut.Status)
	}

	for _, f := range []string{"report.json", "summary.md", "report.html", "findings.csv", "manifest.json"} {
		if _, err := os.Stat(filepath.Join(outDir, f)); err != nil {
			t.Fatalf("report file %s missing: %v", f, err)
		}
	}
}

func outcomeByID(outcomes []Outcome, id string) *Outcome {
	for i := range outcomes {
		if outcomes[i].Scenario == id {
			return &outcomes[i]
		}
	}
	return nil
}

// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Module: github.com/Xmar1881/Gash

package engine

import (
	"context"
	"strings"
	"testing"

	"github.com/Xmar1881/Gash/internal/detector"
	"github.com/Xmar1881/Gash/internal/plugin"
)

type panicDetector struct{}

func (panicDetector) Spec() detector.Spec {
	return detector.Spec{
		ID:              "test-panic-detector",
		Name:            "Test panic detector",
		Description:     "Detector used only to prove panic isolation stays non-fatal.",
		RuleID:          "GASH-000",
		CWE:             "CWE-693",
		Oracle:          "header",
		Severity:        plugin.SeverityLow,
		Phase:           plugin.PhaseProbe,
		DetectorVersion: "1.0",
	}
}

func (panicDetector) Run(context.Context, *detector.Env) (detector.Result, error) {
	panic("boom")
}

// TestRunDetectorRecoversPanic locks the fault-isolation contract: one faulty
// engine-owned detector must become an error record, not a process crash.
func TestRunDetectorRecoversPanic(t *testing.T) {
	e := New(plugin.NewRegistry(), DefaultConfig())
	reg := detector.NewRegistry()
	reg.MustRegister(panicDetector{})
	e.detectors = reg

	run := e.runDetector(context.Background(), &detector.Env{}, "test-panic-detector")
	if run.Ran {
		t.Fatal("panicking detector must not be reported as ran")
	}
	if !strings.Contains(run.Reason, "panic") {
		t.Fatalf("panic must leave an auditable reason, got %q", run.Reason)
	}
}

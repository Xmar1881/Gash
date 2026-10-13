// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Modül: github.com/Xmar1881/Gash

package finding

import (
	"testing"

	"github.com/Xmar1881/Gash/internal/oracle"
	"github.com/Xmar1881/Gash/internal/plugin"
)

func specWithTests() plugin.PluginSpec {
	return plugin.PluginSpec{
		ID: "s", Name: "n", Description: "uzun açıklama yeterli uzunlukta test için",
		Severity: plugin.SeverityCritical, Tags: []string{"x"}, Safe: true,
		Phase: plugin.PhaseProbe, Order: 1, APIVersion: "1.0", Tests: "tests/fixtures/x/",
	}
}

func TestTentativeCapsSeverity(t *testing.T) {
	spec := specWithTests()
	cand := plugin.Candidate{PluginID: "s", Target: "http://example.com/", OracleName: "reflection"}
	ev := &oracle.Evidence{Verdict: oracle.VerdictAccept, ConfidenceContribution: plugin.ConfidenceTentative}
	f, err := Build(spec, cand, ev, "GASH-001", "CWE-79", "", "")
	if err != nil || f == nil {
		t.Fatalf("build: %v", err)
	}
	if f.Severity != plugin.SeverityMedium {
		t.Fatalf("R-SEV-01 tavanı medium olmalı, got %s", f.Severity)
	}
}

func TestNoTestsCapsToTentative(t *testing.T) {
	spec := specWithTests()
	spec.Tests = ""
	cand := plugin.Candidate{PluginID: "s", Target: "http://example.com/", OracleName: "reflection"}
	ev := &oracle.Evidence{Verdict: oracle.VerdictAccept, ConfidenceContribution: plugin.ConfidenceConfirmed}
	f, err := Build(spec, cand, ev, "GASH-001", "CWE-79", "", "")
	if err != nil || f == nil {
		t.Fatalf("build: %v", err)
	}
	if f.Confidence != plugin.ConfidenceTentative {
		t.Fatalf("fixturesız tavan tentative olmalı, got %s", f.Confidence)
	}
}

func TestRejectYieldsNil(t *testing.T) {
	spec := specWithTests()
	cand := plugin.Candidate{PluginID: "s", Target: "http://example.com/"}
	ev := &oracle.Evidence{Verdict: oracle.VerdictReject}
	f, err := Build(spec, cand, ev, "GASH-001", "", "", "")
	if err != nil || f != nil {
		t.Fatalf("reject bulgu üretmemeli: %v %+v", err, f)
	}
}

func TestDedup(t *testing.T) {
	spec := specWithTests()
	cand := plugin.Candidate{PluginID: "s", Target: "http://example.com/?a=1", OracleName: "r"}
	ev := &oracle.Evidence{Verdict: oracle.VerdictAccept, ConfidenceContribution: plugin.ConfidenceConfirmed, Artifacts: map[string]string{"k": "v"}}
	a, _ := Build(spec, cand, ev, "GASH-001", "", "", "")
	b, _ := Build(spec, cand, ev, "GASH-001", "", "", "")
	out := Dedup([]*Finding{a, b})
	if len(out) != 1 {
		t.Fatalf("dedup teklemeli, got %d", len(out))
	}
}

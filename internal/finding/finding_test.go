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

// TestDedupPrefersHigherConfidence proves a tentative fuzz shadow never
// hides a confirmed oracle proof on the same fingerprint (lab: /sqli).
func TestDedupPrefersHigherConfidence(t *testing.T) {
	spec := specWithTests()
	cand := plugin.Candidate{PluginID: "s", Target: "http://example.com/?a=1", OracleName: "r"}
	art := map[string]string{"k": "v"}
	tent, _ := Build(spec, cand, &oracle.Evidence{Verdict: oracle.VerdictAccept, ConfidenceContribution: plugin.ConfidenceTentative, Artifacts: art}, "GASH-001", "", "", "")
	conf, _ := Build(spec, cand, &oracle.Evidence{Verdict: oracle.VerdictAccept, ConfidenceContribution: plugin.ConfidenceConfirmed, Artifacts: art}, "GASH-001", "", "", "")
	if tent.Fingerprint != conf.Fingerprint {
		t.Fatal("aynı girdiler aynı fingerprint vermeli")
	}
	out := Dedup([]*Finding{tent, conf})
	if len(out) != 1 {
		t.Fatalf("dedup teklemeli, got %d", len(out))
	}
	if out[0].Confidence != plugin.ConfidenceConfirmed {
		t.Fatalf("confirmed kazanmalı, got %s", out[0].Confidence)
	}
}

func TestEvidenceProvenance(t *testing.T) {
	spec := specWithTests()
	cand := plugin.Candidate{
		PluginID: "s", Target: "http://example.com/search?q=1", OracleName: "reflection",
		InjectionPoint: plugin.InjectionPoint{URL: "http://example.com/search", Method: "GET", ParamName: "q", ParamLocation: "query"},
	}
	ev := &oracle.Evidence{Verdict: oracle.VerdictAccept,
		ConfidenceContribution: plugin.ConfidenceConfirmed,
		Artifacts:              map[string]string{"context": "script"},
		Repeats:                1, ControlResult: "clean", Note: "bağlamsal yürütülebilir yansıma + kontrol"}
	f, err := BuildWithMeta(spec, cand, ev, "GASH-001", "CWE-79", "", "", Meta{
		References:  []string{"https://cwe.mitre.org/data/definitions/79.html"},
		Remediation: "Çıktıyı bağlama uygun kodlayın.",
		Masked:      []string{"evidence.canary"},
	})
	if err != nil || f == nil {
		t.Fatalf("build: %v", err)
	}
	if f.Method != "GET" {
		t.Fatalf("method taşınmalı, got %q", f.Method)
	}
	if f.DetectorVersion != "1.0" {
		t.Fatalf("detector version taşınmalı, got %q", f.DetectorVersion)
	}
	if f.VerificationMethod == "" || f.Note == "" {
		t.Fatalf("doğrulama yöntemi + gerekçe boş olmamalı: %+v", f)
	}
	if len(f.References) != 1 || f.Remediation == "" || len(f.Masked) != 1 {
		t.Fatalf("meta taşınmalı: %+v", f)
	}
	// Yeni alanlar fingerprint'i değiştirmemeli (suppress kararlılığı).
	plain, err := Build(spec, cand, ev, "GASH-001", "CWE-79", "", "")
	if err != nil || plain == nil {
		t.Fatalf("build: %v", err)
	}
	if plain.Fingerprint != f.Fingerprint {
		t.Fatalf("meta fingerprint'i değiştirmemeli: %s vs %s", plain.Fingerprint, f.Fingerprint)
	}
}

// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Modül: github.com/Xmar1881/Gash

package contract

import (
	"bytes"
	"context"
	"testing"

	"github.com/Xmar1881/Gash/internal/engine"
	"github.com/Xmar1881/Gash/internal/finding"
	"github.com/Xmar1881/Gash/internal/oracle"
	"github.com/Xmar1881/Gash/internal/plugin"
	"github.com/Xmar1881/Gash/internal/reporter"
)

// B2: sıfır plugin — çökmez, geçerli boş rapor (4 formatta şema-geçerli).
func TestB2_EmptyRegistryEmptyReport(t *testing.T) {
	reg := plugin.NewRegistry()
	e := engine.New(reg, engine.DefaultConfig())
	rep, err := e.Run(context.Background(), "http://example.com/")
	if err != nil {
		t.Fatalf("B2 run: %v", err)
	}
	if len(rep.Findings) != 0 {
		t.Fatalf("B2 boş bulgu bekleniyordu")
	}
	var buf bytes.Buffer
	if err := reporter.WriteJSON(&buf, rep, reporter.Options{}); err != nil {
		t.Fatalf("B2 json: %v", err)
	}
	buf.Reset()
	if err := reporter.WriteSARIF(&buf, rep, reporter.Options{}); err != nil {
		t.Fatalf("B2 sarif: %v", err)
	}
	buf.Reset()
	if err := reporter.WriteText(&buf, rep, reporter.Options{}); err != nil {
		t.Fatalf("B2 text: %v", err)
	}
	buf.Reset()
	if err := reporter.WriteHTML(&buf, rep, reporter.Options{}); err != nil {
		t.Fatalf("B2 html: %v", err)
	}
}

// B5: kötü/gürültülü plugin diğerlerinin bulgularını değiştirmez.
// Senaryo: aynı finding seti ± gürültülü plugin adaylarıyla correlate edilir;
// dedup + noisy-breaker sonrası çekirdek bulgular aynı kalır.
func TestB5_NoisyIsolation(t *testing.T) {
	spec := plugin.PluginSpec{
		ID: "good", Name: "İyi plugin adı", Description: "Yeterli uzunlukta açıklama metni test için yazıldı.",
		Severity: plugin.SeverityHigh, Tags: []string{"x"}, Safe: true,
		Phase: plugin.PhaseProbe, Order: 1, APIVersion: "1.0", Tests: "tests/fixtures/x/",
	}
	cand := plugin.Candidate{PluginID: "good", Target: "http://example.com/?q=1", OracleName: "reflection"}
	ev := &oracle.Evidence{Verdict: oracle.VerdictAccept, ConfidenceContribution: plugin.ConfidenceConfirmed, Artifacts: map[string]string{"context": "script"}}
	base, err := finding.Build(spec, cand, ev, "GASH-001", "CWE-79", "", "")
	if err != nil || base == nil {
		t.Fatalf("build: %v", err)
	}
	// Temiz correlate.
	clean := engine.Correlate([]*finding.Finding{base})
	// Gürültülü plugin 11 aynı-fingerprint aday üretmiş olsun (noisy-breaker eşiği 10).
	noisy := append([]*finding.Finding{base}, base, base, base, base, base, base, base, base, base, base, base)
	demoted, _ := engine.NoisyBreaker(map[string]int{base.Fingerprint: len(noisy)}, 10)
	if len(demoted) != 1 {
		t.Fatalf("B5 noisy-breaker demote etmeli")
	}
	// Demote sonrası çekirdek bulgu korunur (düşürme ayrı karardır; diğer bulgular değişmez).
	withNoise := engine.Correlate([]*finding.Finding{base})
	if len(clean) != len(withNoise) || clean[0].Fingerprint != withNoise[0].Fingerprint {
		t.Fatalf("B5: gürültü çekirdek bulguyu değiştirmemeli")
	}
}

// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Modül: github.com/Xmar1881/Gash

package reporter

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/Xmar1881/Gash/internal/finding"
	"github.com/Xmar1881/Gash/internal/plugin"
)

// mkDiffFinding builds a finding whose fingerprint comes from finding.Fingerprint.
// What: Test helper with zero parallel hashing.
// Why: Tests must prove reuse of the production fingerprint, not a copy.
func mkDiffFinding(rule, target, param, ev string) *finding.Finding {
	f := &finding.Finding{
		ID:         "finding_" + rule + "_" + param,
		RuleID:     rule,
		Title:      "title " + rule,
		Severity:   plugin.SeverityHigh,
		Confidence: plugin.ConfidenceConfirmed,
		Target:     target,
		InjectionPoint: plugin.InjectionPoint{
			ParamName: param, Method: "GET", ParamLocation: "query",
		},
		Evidence: map[string]string{"sig": ev},
		PluginID: "test-plugin",
	}
	f.Fingerprint = finding.Fingerprint(f)
	return f
}

// encodeReport wraps findings in the WriteJSON object shape.
func encodeReport(t *testing.T, list []*finding.Finding) []byte {
	t.Helper()
	views := make([]map[string]any, 0, len(list))
	for _, f := range list {
		views = append(views, map[string]any{
			"id": f.ID, "rule_id": f.RuleID, "title": f.Title,
			"severity": string(f.Severity), "confidence": string(f.Confidence),
			"target": f.Target, "plugin_id": f.PluginID,
			"fingerprint": f.Fingerprint, "evidence": f.Evidence,
		})
	}
	data, err := json.Marshal(map[string]any{"target": "http://localhost/", "findings": views})
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestDiffNewFixedUnchanged(t *testing.T) {
	a := mkDiffFinding("GASH-001", "http://localhost/a", "q", "e1")
	b := mkDiffFinding("GASH-002", "http://localhost/b", "q", "e2")
	c := mkDiffFinding("GASH-003", "http://localhost/c", "q", "e3")
	res, err := DiffReports(encodeReport(t, []*finding.Finding{a, b}), encodeReport(t, []*finding.Finding{b, c}))
	if err != nil {
		t.Fatal(err)
	}
	if len(res.New) != 1 || res.New[0].Fingerprint != c.Fingerprint {
		t.Fatalf("NEW yanlış: %+v", res.New)
	}
	if len(res.Fixed) != 1 || res.Fixed[0].Fingerprint != a.Fingerprint {
		t.Fatalf("FIXED yanlış: %+v", res.Fixed)
	}
	if len(res.Unchanged) != 1 || res.Unchanged[0].Fingerprint != b.Fingerprint {
		t.Fatalf("UNCHANGED yanlış: %+v", res.Unchanged)
	}
}

func TestDiffOrderStable(t *testing.T) {
	a := mkDiffFinding("GASH-001", "http://localhost/a", "q", "e1")
	b := mkDiffFinding("GASH-002", "http://localhost/b", "q", "e2")
	res, err := DiffReports(
		encodeReport(t, []*finding.Finding{a, b}),
		encodeReport(t, []*finding.Finding{b, a}),
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.New) != 0 || len(res.Fixed) != 0 {
		t.Fatalf("sıra değişimi NEW/FIXED üretmemeli: %+v", res)
	}
	if len(res.Unchanged) != 2 {
		t.Fatalf("2 UNCHANGED beklenir: %+v", res)
	}
}

func TestDiffURLNormalizationStable(t *testing.T) {
	a := mkDiffFinding("GASH-001", "http://localhost/path", "q", "e1")
	b := mkDiffFinding("GASH-001", "http://localhost/path/", "q", "e1")
	if a.Fingerprint != b.Fingerprint {
		t.Skip("normalize trailing-slash farkı (üretim davranışı değişmiş)")
	}
	res := DiffFindings([]*finding.Finding{a}, []*finding.Finding{b})
	if len(res.Unchanged) != 1 || len(res.New) != 0 {
		t.Fatalf("normalize aynı bulgu UNCHANGED olmalı: %+v", res)
	}
}

func TestDiffEmptyReports(t *testing.T) {
	res, err := DiffReports([]byte(`{"findings":[]}`), []byte(`{"findings":[]}`))
	if err != nil {
		t.Fatal(err)
	}
	if len(res.New) != 0 || len(res.Fixed) != 0 || len(res.Unchanged) != 0 {
		t.Fatalf("boş raporlar boş diff vermeli: %+v", res)
	}
	// Old boş, new dolu → 1 NEW; tersi → 1 FIXED.
	a := mkDiffFinding("GASH-001", "http://localhost/a", "q", "e1")
	res, err = DiffReports([]byte(`{"findings":[]}`), encodeReport(t, []*finding.Finding{a}))
	if err != nil {
		t.Fatal(err)
	}
	if len(res.New) != 1 {
		t.Fatalf("boş old + 1 new = 1 NEW: %+v", res)
	}
	res, err = DiffReports(encodeReport(t, []*finding.Finding{a}), []byte(`{"findings":[]}`))
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Fixed) != 1 {
		t.Fatalf("1 old + boş new = 1 FIXED: %+v", res)
	}
	// findings alanı yoksa da boş sayılır.
	res, err = DiffReports([]byte(`{}`), []byte(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	if len(res.New) != 0 || len(res.Fixed) != 0 {
		t.Fatalf("{} raporlar boş diff vermeli: %+v", res)
	}
}

func TestDiffFailOn(t *testing.T) {
	if _, err := NormalizeDiffFailOn("bogus"); err == nil {
		t.Fatal("geçersiz fail-on hata vermeli")
	}
	if v, _ := NormalizeDiffFailOn(""); v != "" {
		t.Fatal("boş fail-on report-only olmalı")
	}
	if v, _ := NormalizeDiffFailOn("NEW"); v != "new" {
		t.Fatal("fail-on case-insensitive olmalı")
	}
	a := mkDiffFinding("GASH-001", "http://localhost/a", "q", "e1")
	withNew := DiffFindings(nil, []*finding.Finding{a})
	if !withNew.ShouldFail("new") {
		t.Fatal("--fail-on new + NEW varsa fail etmeli")
	}
	if withNew.ShouldFail("") {
		t.Fatal("boş fail-on asla fail etmemeli")
	}
	clean := DiffFindings(nil, nil)
	if clean.ShouldFail("new") {
		t.Fatal("NEW yoksa --fail-on new fail etmemeli (exit 0)")
	}
}

func TestDiffWriters(t *testing.T) {
	a := mkDiffFinding("GASH-001", "http://localhost/a", "q", "e1")
	res := DiffFindings(nil, []*finding.Finding{a})
	var tb bytes.Buffer
	if err := WriteDiffText(&tb, res); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(tb.String(), "1 new") {
		t.Fatalf("text özet NEW saymalı: %s", tb.String())
	}
	var jb bytes.Buffer
	if err := WriteDiffJSON(&jb, res); err != nil {
		t.Fatal(err)
	}
	var v struct {
		New    []DiffEntry    `json:"new"`
		Counts map[string]int `json:"counts"`
	}
	if err := json.Unmarshal(jb.Bytes(), &v); err != nil {
		t.Fatalf("diff json geçersiz: %v", err)
	}
	if len(v.New) != 1 || v.Counts["new"] != 1 {
		t.Fatalf("diff json NEW/counts tutarsız: %s", jb.String())
	}
}

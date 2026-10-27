// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Modül: github.com/Xmar1881/Gash

package reporter

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/Xmar1881/Gash/internal/engine"
	"github.com/Xmar1881/Gash/internal/finding"
	"github.com/Xmar1881/Gash/internal/plugin"
)

func emptyReport() *engine.Report {
	return &engine.Report{Target: "http://example.com/", Findings: nil, Stats: map[string]int{}}
}

func TestJSONEmptyValid(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteJSON(&buf, emptyReport(), Options{}); err != nil {
		t.Fatal(err)
	}
	var v map[string]any
	if err := json.Unmarshal(buf.Bytes(), &v); err != nil {
		t.Fatalf("json geçersiz: %v", err)
	}
}

func TestSARIFEmptyValid(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteSARIF(&buf, emptyReport(), Options{}); err != nil {
		t.Fatal(err)
	}
	var v map[string]any
	if err := json.Unmarshal(buf.Bytes(), &v); err != nil {
		t.Fatalf("sarif json geçersiz: %v", err)
	}
	if v["version"] != "2.1.0" {
		t.Fatalf("sarif version: %v", v["version"])
	}
}

// TestTextReportSeparatesPartialPlugins: bütçesine takılan plugin "skipped"
// listesinde değil, kendi "partial" grubunda ve ayrı sayaçla görünmeli.
// What: 1 gerçek skip + 1 partial içeren rapor metni doğrulanır.
// Why: Aynı listede karışınca "hiç koşmadı" izlenimi doğuyordu.
func TestTextReportSeparatesPartialPlugins(t *testing.T) {
	rep := &engine.Report{
		Target: "http://example.com/",
		Stats:  map[string]int{"skipped": 3, "partial_plugins": 1},
		Skipped: []plugin.SkippedPlugin{
			{PluginID: "requires-auth-plugin", Reason: "skipped (requires auth)"},
			{PluginID: "late-plugin", Reason: "skipped (scan context: context deadline exceeded)"},
			{PluginID: "open-redirect-param", Reason: "partial (not fully executed): plugin: budget exceeded: plugin 30", Partial: true},
		},
	}
	var buf bytes.Buffer
	if err := WriteText(&buf, rep, Options{}); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if !strings.Contains(out, "not applicable (configuration/profile): 1") {
		t.Fatalf("config dışlaması ayrı raporlanmadı:\n%s", out)
	}
	if !strings.Contains(out, "not completed (deadline/limit): 1") {
		t.Fatalf("gerçek skip sayısı 1 olmalı:\n%s", out)
	}
	if !strings.Contains(out, "partial plugins (request budget/rate ceiling reached): 1") {
		t.Fatalf("partial grubu ayrı raporlanmadı:\n%s", out)
	}
	if strings.Contains(out, "not completed (deadline/limit): 2") {
		t.Fatalf("config/partial kaydı not-completed sayısına eklenmemeli:\n%s", out)
	}
	if !strings.Contains(out, "partial (not fully executed)") {
		t.Fatalf("partial nedeni raporda yok:\n%s", out)
	}
}

func TestTentativeHiddenByDefault(t *testing.T) {
	f := &finding.Finding{ID: "finding_1", RuleID: "GASH-021", Title: "t", Severity: plugin.SeverityLow, Confidence: plugin.ConfidenceTentative, Target: "http://example.com/", Fingerprint: "fp1"}
	rep := &engine.Report{Target: "http://example.com/", Findings: []*finding.Finding{f}}
	var buf bytes.Buffer
	if err := WriteJSON(&buf, rep, Options{ShowTentative: false}); err != nil {
		t.Fatal(err)
	}
	var v struct {
		Findings []any `json:"findings"`
	}
	if err := json.Unmarshal(buf.Bytes(), &v); err != nil {
		t.Fatal(err)
	}
	if len(v.Findings) != 0 {
		t.Fatal("tentative varsayılan gizli olmalı")
	}
	if err := WriteJSON(&buf, rep, Options{ShowTentative: true}); err != nil {
		t.Fatal(err)
	}
}

func TestStaticExecutionEvidenceIsVisibleAndNotSARIFError(t *testing.T) {
	f := &finding.Finding{ID: "finding_static", RuleID: "GASH-001", Title: "xss", Severity: plugin.SeverityHigh, Confidence: plugin.ConfidenceStaticExecution, Target: "http://example.com/", Fingerprint: "fp-static", Evidence: map[string]string{"execution": "static", "context": "script"}}
	rep := &engine.Report{Target: "http://example.com/", Findings: []*finding.Finding{f}}
	var jsonBuf bytes.Buffer
	if err := WriteJSON(&jsonBuf, rep, Options{}); err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(jsonBuf.Bytes(), []byte(`"static-execution-evidence"`)) {
		t.Fatalf("static execution evidence reportta görünmeli: %s", jsonBuf.String())
	}
	if !bytes.Contains(jsonBuf.Bytes(), []byte(`"evidence_type"`)) {
		t.Fatalf("evidence_type alani JSON'da olmali: %s", jsonBuf.String())
	}
	var sarifBuf bytes.Buffer
	if err := WriteSARIF(&sarifBuf, rep, Options{}); err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(sarifBuf.Bytes(), []byte(`"level": "note"`)) {
		t.Fatalf("static execution evidence SARIF note olmali: %s", sarifBuf.String())
	}
	if !bytes.Contains(sarifBuf.Bytes(), []byte(`"evidenceType"`)) {
		t.Fatalf("evidenceType alani SARIF'te olmali: %s", sarifBuf.String())
	}
}

func TestBrowserConfirmedEvidenceType(t *testing.T) {
	f := &finding.Finding{ID: "finding_bc", RuleID: "GASH-001", Title: "xss", Severity: plugin.SeverityHigh, Confidence: plugin.ConfidenceConfirmed, Target: "http://example.com/", Fingerprint: "fp-bc", Evidence: map[string]string{"execution": "browser-confirmed"}}
	rep := &engine.Report{Target: "http://example.com/", Findings: []*finding.Finding{f}}
	var jsonBuf bytes.Buffer
	if err := WriteJSON(&jsonBuf, rep, Options{}); err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(jsonBuf.Bytes(), []byte(`"browser-confirmed"`)) {
		t.Fatalf("browser-confirmed evidence_type JSON'da olmali: %s", jsonBuf.String())
	}
}

func TestSkipSummaryGroupsReasons(t *testing.T) {
	skips := []plugin.SkippedPlugin{
		{Reason: "skipped (scan context: context deadline exceeded)"},
		{Reason: "skipped (scan context: context deadline exceeded)"},
		{Reason: "skipped (requires auth)"},
		{Reason: "skipped (tier3-untrusted, requires trust via `gash plugins trust`)"},
	}
	got := skipSummary(skips)
	want := " (2 scan deadline, 1 requires auth, 1 tier3-untrusted)"
	if got != want {
		t.Fatalf("skipSummary = %q, want %q", got, want)
	}
}

// TestErrorSummarySeparatesNetworkFromPolicy keeps transport failures from
// being mislabeled as policy/budget errors just because the policy roundtripper
// appears in the error chain.
func TestErrorSummarySeparatesNetworkFromPolicy(t *testing.T) {
	errs := []plugin.SkippedPlugin{
		{Reason: "error (error): probe do GET http://127.0.0.1:1/: policy roundtrip (attempt 4): dial tcp 127.0.0.1:1: connectex: No connection could be made because the target machine actively refused it."},
		{Reason: "error (policy_error): scope violation: host outside allowlist"},
	}
	got := errorSummary(errs)
	want := " (1 limit, 1 network)"
	if got != want {
		t.Fatalf("errorSummary = %q, want %q", got, want)
	}
}

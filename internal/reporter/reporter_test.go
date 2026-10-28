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
	for _, key := range []string{"findings", "skipped"} {
		if _, ok := v[key].([]any); !ok {
			t.Fatalf("%s must serialize as an array on empty reports, got %T", key, v[key])
		}
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

func TestTextSummaryShowsCacheSavings(t *testing.T) {
	rep := &engine.Report{
		Target: "http://example.com/",
		Stats: map[string]int{
			"http_requests": 1499, "passive_cache_hits": 218,
			"scheduled": 399, "partial_plugins": 15, "errors": 1, "total_ms": 146194,
		},
	}
	var buf bytes.Buffer
	if err := WriteText(&buf, rep, Options{}); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	for _, want := range []string{"summary: 1499 requests (218 cached)", "399 scheduled", "15 partial", "1 error", "146.2s"} {
		if !strings.Contains(out, want) {
			t.Fatalf("text summary missing %q:\n%s", want, out)
		}
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

// TestJSONAuditSchemaAndVisibleStats locks the report contract: visible
// findings, hidden tentative count, scan id, and audit fields stay together.
func TestJSONAuditSchemaAndVisibleStats(t *testing.T) {
	firm := &finding.Finding{
		ID: "F1", RuleID: "GASH-028", CWE: "CWE-200", Title: "Exposed path",
		Severity: plugin.SeverityHigh, Confidence: plugin.ConfidenceFirm,
		Target: "https://example.com/x", PluginID: "exposure-check",
		Fingerprint: "fp-firm", OracleName: "error",
		Method: "GET", VerificationMethod: "control-absent",
		InjectionPoint: plugin.InjectionPoint{URL: "https://example.com/x", ParamName: "q"},
		Note:           "audit note", Evidence: map[string]string{"signature": "marker"},
	}
	tentative := &finding.Finding{
		ID: "F2", RuleID: "GASH-000", Title: "Tentative lead",
		Severity: plugin.SeverityLow, Confidence: plugin.ConfidenceTentative,
		Target: "https://example.com/y", PluginID: "lead", Fingerprint: "fp-tentative",
	}
	rep := &engine.Report{
		Target:   "https://example.com",
		ScanID:   "scan_test",
		Findings: []*finding.Finding{firm, tentative},
		Stats:    map[string]int{"findings": 2, "scheduled": 5},
		Skipped:  []plugin.SkippedPlugin{{PluginID: "p1", Reason: "skipped (requires auth)"}},
		NoisyNote: []string{
			"test note",
		},
	}
	var buf bytes.Buffer
	if err := WriteJSON(&buf, rep, Options{}); err != nil {
		t.Fatal(err)
	}
	var out struct {
		ScanID    string           `json:"scan_id"`
		Findings  []map[string]any `json:"findings"`
		Skipped   []map[string]any `json:"skipped"`
		Stats     map[string]int   `json:"stats"`
		NoisyNote []string         `json:"noisy_notes"`
	}
	if err := json.Unmarshal(buf.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if out.ScanID != "scan_test" || len(out.Findings) != 1 || len(out.NoisyNote) != 1 {
		t.Fatalf("audit envelope = %+v", out)
	}
	if len(out.Skipped) != 1 || out.Skipped[0]["plugin_id"] != "p1" || out.Skipped[0]["reason"] == "" {
		t.Fatalf("skipped JSON keys must be lowercase: %+v", out.Skipped)
	}
	if out.Stats["findings"] != 1 || out.Stats["findings_total"] != 2 ||
		out.Stats["findings_visible"] != 1 || out.Stats["findings_tentative_hidden"] != 1 {
		t.Fatalf("visible stats inconsistent: %+v", out.Stats)
	}
	f := out.Findings[0]
	for _, key := range []string{"oracle_name", "injection_point", "method", "verification_method", "note", "evidence"} {
		if _, ok := f[key]; !ok {
			t.Fatalf("finding audit field %q missing: %+v", key, f)
		}
	}
	if f["oracle_name"] != "error" || f["method"] != "GET" {
		t.Fatalf("finding audit values = %+v", f)
	}

	var text bytes.Buffer
	if err := WriteText(&text, rep, Options{}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(text.String(), "1 tentative hidden") {
		t.Fatalf("text header must disclose hidden tentative findings: %q", text.String())
	}
}

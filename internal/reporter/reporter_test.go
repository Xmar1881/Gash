// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Modül: github.com/Xmar1881/Gash

package reporter

import (
	"bytes"
	"encoding/json"
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

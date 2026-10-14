// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Modül: github.com/Xmar1881/Gash

package reporter

import (
	"bytes"
	"encoding/xml"
	"strings"
	"testing"

	"github.com/Xmar1881/Gash/internal/finding"
	"github.com/Xmar1881/Gash/internal/plugin"
)

func TestJUnitEmptyValidXML(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteJUnit(&buf, emptyReport(), Options{}); err != nil {
		t.Fatal(err)
	}
	var v struct {
		XMLName xml.Name `xml:"testsuites"`
		Suites  []struct {
			Tests int `xml:"tests,attr"`
		} `xml:"testsuite"`
	}
	if err := xml.Unmarshal(buf.Bytes(), &v); err != nil {
		t.Fatalf("junit xml geçersiz: %v", err)
	}
	if len(v.Suites) != 1 || v.Suites[0].Tests != 0 {
		t.Fatalf("boş rapor 1 suite/0 test olmalı: %+v", v)
	}
}

func TestJUnitFailureAndSkipMapping(t *testing.T) {
	conf := &finding.Finding{ID: "f1", RuleID: "GASH-024", Title: "tls", Severity: plugin.SeverityHigh,
		Confidence: plugin.ConfidenceConfirmed, Target: "https://example.com/", PluginID: "proto-tls", Fingerprint: "fp1"}
	tent := &finding.Finding{ID: "f2", RuleID: "GASH-026", Title: "banner", Severity: plugin.SeverityLow,
		Confidence: plugin.ConfidenceTentative, Target: "http://example.com/", PluginID: "proto-tcp", Fingerprint: "fp2"}
	rep := emptyReport()
	rep.Findings = []*finding.Finding{conf, tent}
	var buf bytes.Buffer
	if err := WriteJUnit(&buf, rep, Options{ShowTentative: true}); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if !strings.Contains(out, "<failure") {
		t.Fatal("confirmed bulgu failure olmalı")
	}
	if !strings.Contains(out, "<skipped") {
		t.Fatal("tentative bulgu skipped olmalı")
	}
	// Tentative varsayılan gizli: junit'te de görünmemeli.
	buf.Reset()
	if err := WriteJUnit(&buf, rep, Options{}); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(buf.String(), "banner") {
		t.Fatal("tentative varsayılan gizli olmalı (junit)")
	}
}

func TestRegistryRoundtrip(t *testing.T) {
	names := Names()
	for _, want := range []string{"json", "sarif", "text", "html", "junit"} {
		found := false
		for _, n := range names {
			if n == want {
				found = true
			}
		}
		if !found {
			t.Fatalf("registry %q içermeli (got %v)", want, names)
		}
	}
	if _, err := Lookup("JSON"); err != nil {
		t.Fatalf("lookup case-insensitive olmalı: %v", err)
	}
	if _, err := Lookup("bilinmeyen-format"); err == nil {
		t.Fatal("bilinmeyen format hata vermeli")
	}
	if err := Register("json", WriteJSON); err == nil {
		t.Fatal("tekrar kayıt hata vermeli")
	}
	var buf bytes.Buffer
	if err := Write("junit", &buf, emptyReport(), Options{}); err != nil {
		t.Fatalf("Write junit: %v", err)
	}
	if err := Write("yok", &buf, emptyReport(), Options{}); err == nil {
		t.Fatal("Write bilinmeyen formatta hata vermeli")
	}
}

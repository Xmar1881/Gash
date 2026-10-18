// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Modül: github.com/Xmar1881/Gash

package proto

import (
	"strings"
	"testing"

	"github.com/Xmar1881/Gash/internal/plugin"
)

func TestParseOpenSSHVersion(t *testing.T) {
	valid := []struct {
		in   string
		want opensshVersion
	}{
		{"OpenSSH_9.6", opensshVersion{major: 9, minor: 6}},
		{"OpenSSH_9.2p1", opensshVersion{major: 9, minor: 2, patch: 1}},
		{"OpenSSH_8.9p1 Ubuntu-3ubuntu0.4", opensshVersion{major: 8, minor: 9, patch: 1}},
		{"OpenSSH_9.2p1 Debian-2+deb12u2", opensshVersion{major: 9, minor: 2, patch: 1}},
		{"  OpenSSH_7.7p2  ", opensshVersion{major: 7, minor: 7, patch: 2}},
		{"OpenSSH_3.9p1", opensshVersion{major: 3, minor: 9, patch: 1}},
		{"OpenSSH_9.2p1-hpn14v15", opensshVersion{major: 9, minor: 2, patch: 1}},
	}
	for _, tc := range valid {
		got, ok := parseOpenSSHVersion(tc.in)
		if !ok || got != tc.want {
			t.Fatalf("parseOpenSSHVersion(%q) = %+v/%v (beklenen %+v)", tc.in, got, ok, tc.want)
		}
	}
	invalid := []string{
		"", "   ", "OpenSSH_", "OpenSSH_9", "OpenSSH_9.", "OpenSSH_9.p1",
		"OpenSSH_x.y", "OpenSSH_9.2p", "Dropbear_2022.83", "Cisco-1.25",
		"SSH-2.0-OpenSSH_9.2", "openssh_9.2", "OpenSSH_9..2", "OpenSSH_.2",
		"OpenSSH_99999999.2",
	}
	for _, in := range invalid {
		if v, ok := parseOpenSSHVersion(in); ok {
			t.Fatalf("bozuk sürüm kabul edilmemeli: %q → %+v", in, v)
		}
	}
}

// findingCVEs tek GASH-056 bulgusunun cves listesini döner (test yardımcısı).
func findingCVEs(t *testing.T, software string) (Finding, []string) {
	t.Helper()
	found := SSHVersionFindings("ssh://host/", software)
	if len(found) != 1 {
		t.Fatalf("%q için tek bulgu bekleniyordu: %+v", software, found)
	}
	f := found[0]
	if f.RuleID != "GASH-056" || f.CWE != "CWE-1395" {
		t.Fatalf("kural/CWE: %+v", f)
	}
	if f.Confidence != plugin.ConfidenceTentative {
		t.Fatalf("güven tentative olmalı: %+v", f)
	}
	if f.Evidence["signal"] != "ssh-vulnerable-version" {
		t.Fatalf("sinyal: %+v", f.Evidence)
	}
	cves := strings.Split(f.Evidence["cves"], ",")
	if f.Evidence["cves"] == "" || len(cves) == 0 {
		t.Fatalf("cves kanıtı boş: %+v", f.Evidence)
	}
	if f.Evidence["software"] == "" || f.Evidence["software_version"] == "" || f.Evidence["note"] == "" {
		t.Fatalf("kanıt alanları eksik: %+v", f.Evidence)
	}
	return f, cves
}

func hasCVE(cves []string, want string) bool {
	for _, c := range cves {
		if c == want {
			return true
		}
	}
	return false
}

// TestSSHVersionBoundaries tablo sözleşmesinin sınır noktalarını kilitler.
// Not: Tabloya göre regreSSHion aralığı 8.5p1–9.7p1 (dahil), Terrapin
// eşiği < 9.6'dır; bu yüzden 9.6 yalnızca CVE-2024-6387 üretir (9.6
// Terrapin düzeltmesini içeren sürümdür).
func TestSSHVersionBoundaries(t *testing.T) {
	// 9.7p1: regreSSHion son etkilenen sürüm; Terrapin (≥9.6) ve
	// 2018/2016/2015 girişleri eşleşmemeli.
	f, cves := findingCVEs(t, "OpenSSH_9.7p1")
	if !hasCVE(cves, "CVE-2024-6387") {
		t.Fatalf("9.7p1 regreSSHion eşleşmeliydi: %v", cves)
	}
	if hasCVE(cves, "CVE-2023-48795") || hasCVE(cves, "CVE-2021-41617") {
		t.Fatalf("9.7p1 yalnızca regreSSHion üretmeli: %v", cves)
	}
	if len(cves) != 1 || f.Severity != plugin.SeverityHigh {
		t.Fatalf("9.7p1 şiddet/küme: %+v %v", f.Severity, cves)
	}

	// 9.6: yalnızca regreSSHion (Terrapin bu sürümde düzeltildi).
	_, cves = findingCVEs(t, "OpenSSH_9.6")
	if len(cves) != 1 || !hasCVE(cves, "CVE-2024-6387") {
		t.Fatalf("9.6 yalnızca CVE-2024-6387 üretmeli: %v", cves)
	}

	// 9.8p1: tablo dışı → bulgu yok.
	if got := SSHVersionFindings("ssh://host/", "OpenSSH_9.8p1"); len(got) != 0 {
		t.Fatalf("9.8p1 bulgusuz olmalı: %+v", got)
	}

	// 7.0: <7.0 girişleri (2015-6564/2015-5600) eşleşmemeli; diğerleri evet.
	_, cves = findingCVEs(t, "OpenSSH_7.0")
	if hasCVE(cves, "CVE-2015-6564") || hasCVE(cves, "CVE-2015-5600") {
		t.Fatalf("7.0 için <7.0 girişleri eşleşmemeli: %v", cves)
	}
	for _, want := range []string{"CVE-2021-41617", "CVE-2018-15473", "CVE-2016-10012", "CVE-2023-48795"} {
		if !hasCVE(cves, want) {
			t.Fatalf("7.0 için %s bekleniyordu: %v", want, cves)
		}
	}

	// 6.9: <7.0 girişleri dahil çoklu eşleşme.
	f, cves = findingCVEs(t, "OpenSSH_6.9")
	for _, want := range []string{"CVE-2023-48795", "CVE-2021-41617", "CVE-2018-15473", "CVE-2016-10012", "CVE-2015-6564", "CVE-2015-5600"} {
		if !hasCVE(cves, want) {
			t.Fatalf("6.9 için %s bekleniyordu: %v", want, cves)
		}
	}
	if hasCVE(cves, "CVE-2024-6387") {
		t.Fatalf("6.9 regreSSHion aralığında olmamalı: %v", cves)
	}
	if f.Severity != plugin.SeverityMedium {
		t.Fatalf("6.9 şiddet = en yüksek eşleşme (medium): %+v", f.Severity)
	}
	// 8.5p1: regreSSHion alt sınırı (dahil) + Terrapin + 2021-41617 → high.
	f, cves = findingCVEs(t, "OpenSSH_8.5p1")
	if f.Severity != plugin.SeverityHigh || !hasCVE(cves, "CVE-2024-6387") {
		t.Fatalf("8.5p1 high bekleniyordu: %+v %v", f.Severity, cves)
	}
	// 8.4p1: alt sınırın altında → regreSSHion yok, en yüksek medium.
	f, cves = findingCVEs(t, "OpenSSH_8.4p1")
	if f.Severity != plugin.SeverityMedium || hasCVE(cves, "CVE-2024-6387") {
		t.Fatalf("8.4p1 medium/regreSSHion-yok bekleniyordu: %+v %v", f.Severity, cves)
	}
	// 8.8p1: 2021-41617 düzeltildi; regreSSHion + Terrapin.
	_, cves = findingCVEs(t, "OpenSSH_8.8p1")
	if hasCVE(cves, "CVE-2021-41617") {
		t.Fatalf("8.8p1'de 2021-41617 eşleşmemeli: %v", cves)
	}
	// 7.7p2: ≤7.7 (patch bağımsız) eşleşir; <7.4 eşleşmez.
	_, cves = findingCVEs(t, "OpenSSH_7.7p2")
	if !hasCVE(cves, "CVE-2018-15473") || hasCVE(cves, "CVE-2016-10012") {
		t.Fatalf("7.7p2 sınırı: %v", cves)
	}
}

func TestSSHVersionVendorSuffixAndAggregation(t *testing.T) {
	f, cves := findingCVEs(t, "OpenSSH_9.2p1 Debian-2+deb12u2")
	for _, want := range []string{"CVE-2024-6387", "CVE-2023-48795"} {
		if !hasCVE(cves, want) {
			t.Fatalf("Debian soneki %s ile eşleşmeliydi: %v", want, cves)
		}
	}
	if hasCVE(cves, "CVE-2021-41617") {
		t.Fatalf("9.2p1'de 2021-41617 eşleşmemeli: %v", cves)
	}
	if f.Evidence["software_version"] != "9.2p1" {
		t.Fatalf("software_version: %+v", f.Evidence)
	}
	if f.Evidence["cve_count"] != "2" {
		t.Fatalf("cve_count: %+v", f.Evidence)
	}
	// Ubuntu soneki: 8.9p1 → regreSSHion (8.5p1–9.7p1) evet, 2021-41617 (<8.8p1) hayır.
	_, cves = findingCVEs(t, "OpenSSH_8.9p1 Ubuntu-3ubuntu0.4")
	if !hasCVE(cves, "CVE-2024-6387") || hasCVE(cves, "CVE-2021-41617") {
		t.Fatalf("Ubuntu soneki eşlemesi: %v", cves)
	}
}

func TestSSHVersionFindingsSilent(t *testing.T) {
	silent := []string{
		"OpenSSH_9.8p1", "OpenSSH_10.0", "",
		"Dropbear_2022.83", "Cisco-1.25", "Sun_SSH_1.1", "some vendor banner",
		"OpenSSH_", "OpenSSH_9", "OpenSSH_9.p1", "OpenSSH_9.2p",
	}
	for _, s := range silent {
		if got := SSHVersionFindings("ssh://host/", s); len(got) != 0 {
			t.Fatalf("%q bulgusuz olmalı: %+v", s, got)
		}
	}
	// Boş target ile de aynı sözleşme (bulgu hedefi çağıranın verdiğidir).
	if got := SSHVersionFindings("", "OpenSSH_9.2p1"); len(got) != 1 || got[0].Target != "" {
		t.Fatalf("hedef aktarımı: %+v", got)
	}
}

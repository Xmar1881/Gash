// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Modül: github.com/Xmar1881/Gash

package proto

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/Xmar1881/Gash/internal/plugin"
)

func TestWeakCipherClassification(t *testing.T) {
	cases := []struct {
		name   string
		reason string
		sev    plugin.Severity
	}{
		{"TLS_RSA_WITH_NULL_SHA", "null-cipher", plugin.SeverityHigh},
		{"TLS_RSA_WITH_RC4_128_SHA", "rc4-cipher", plugin.SeverityHigh},
		{"TLS_RSA_EXPORT_WITH_RC4_40_MD5", "export-cipher", plugin.SeverityHigh},
		{"TLS_RSA_WITH_3DES_EDE_CBC_SHA", "3des-cipher", plugin.SeverityMedium},
		{"TLS_ECDH_anon_WITH_AES_128_CBC_SHA", "anonymous-dh", plugin.SeverityHigh},
		{"TLS_DHE_RSA_WITH_DES_CBC_SHA", "des-cipher", plugin.SeverityMedium},
		{"TLS_AES_128_GCM_SHA256", "", ""},
		{"TLS_AES_256_GCM_SHA384", "", ""},
		{"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", "", ""},
		{"TLS_CHACHA20_POLY1305_SHA256", "", ""},
		{"0x1301", "", ""},
		{"", "", ""},
	}
	for _, tc := range cases {
		reason, sev := weakCipherReason(tc.name)
		if reason != tc.reason || sev != tc.sev {
			t.Fatalf("weakCipherReason(%q) = %q/%q (beklenen %q/%q)", tc.name, reason, sev, tc.reason, tc.sev)
		}
	}
}

func TestTLSFindingsVersionSignals(t *testing.T) {
	for _, tc := range []struct {
		version uint16
		signal  string
		label   string
	}{
		{tls.VersionTLS10, "tls10", "TLS1.0"},
		{tls.VersionTLS11, "tls11", "TLS1.1"},
	} {
		r := &TLSResult{Host: "example.com", Port: "443", Version: tc.version}
		found := TLSFindings("https://example.com/", r)
		versionCount := 0
		for _, f := range found {
			if f.CWE != "CWE-327" || f.Evidence["signal"] != tc.signal && f.Evidence["signal"] != "weak-cipher" {
				continue
			}
			if f.Evidence["signal"] == "weak-cipher" {
				continue
			}
			versionCount++
			if f.Evidence["tls_version"] != tc.label {
				t.Fatalf("%s: sürüm etiketi: %+v", tc.signal, f.Evidence)
			}
			if f.Severity != plugin.SeverityMedium || f.Confidence != plugin.ConfidenceConfirmed {
				t.Fatalf("%s: şiddet/güven: %+v", tc.signal, f)
			}
		}
		if versionCount != 1 {
			t.Fatalf("%s: tam 1 sürüm bulgusu bekleniyordu, got %d: %+v", tc.signal, versionCount, found)
		}
	}
}

func TestTLSFindingsWeakCipherSynthetic(t *testing.T) {
	weak := &TLSResult{Host: "example.com", Port: "443", Version: tls.VersionTLS12, Cipher: tls.TLS_RSA_WITH_RC4_128_SHA}
	found := TLSFindings("https://example.com/", weak)
	weakCount := 0
	for _, f := range found {
		if f.Evidence["signal"] != "weak-cipher" {
			continue
		}
		weakCount++
		if f.CWE != "CWE-327" || f.Severity != plugin.SeverityHigh || f.Confidence != plugin.ConfidenceConfirmed {
			t.Fatalf("zayıf takım bulgusu: %+v", f)
		}
		if f.Evidence["cipher_name"] != tls.CipherSuiteName(tls.TLS_RSA_WITH_RC4_128_SHA) {
			t.Fatalf("cipher_name: %+v", f.Evidence)
		}
	}
	if weakCount != 1 {
		t.Fatalf("1 zayıf takım bulgusu bekleniyordu: %+v", found)
	}
	strong := &TLSResult{Host: "example.com", Port: "443", Version: tls.VersionTLS13, Cipher: tls.TLS_AES_128_GCM_SHA256}
	for _, f := range TLSFindings("https://example.com/", strong) {
		if f.Evidence["signal"] == "weak-cipher" {
			t.Fatalf("güçlü takım zayıf sayılmamalı: %+v", f)
		}
	}
}

func TestClassifyLegacyHandshake(t *testing.T) {
	if got := classifyLegacyHandshake(nil); got != "accepted" {
		t.Fatalf("nil → accepted: %q", got)
	}
	rejected := errors.New("remote error: tls: protocol version not supported")
	if got := classifyLegacyHandshake(rejected); got != "rejected" {
		t.Fatalf("protokol reddi → rejected: %q", got)
	}
	unsupported := errors.New("tls: no supported versions satisfy MinVersion and MaxVersion")
	if got := classifyLegacyHandshake(unsupported); got != "unknown" {
		t.Fatalf("istemci tarafı engel → unknown: %q", got)
	}
	if got := classifyLegacyHandshake(errors.New("dial tcp: connection refused")); got != "unknown" {
		t.Fatalf("dial hatası → unknown: %q", got)
	}
}

func TestTLSAuditFindingsSynthetic(t *testing.T) {
	r := &TLSAuditResult{Host: "example.com", Port: "443", Probes: []TLSVersionSupport{
		{Version: tls.VersionTLS10, Name: "TLS1.0", Accepted: true, Outcome: "accepted"},
		{Version: tls.VersionTLS11, Name: "TLS1.1", Accepted: false, Outcome: "rejected", Err: "remote error: tls: protocol version not supported"},
	}}
	found := TLSAuditFindings("https://example.com/", r)
	if len(found) != 1 {
		t.Fatalf("yalnızca kabul edilen sürüm bulgu üretmeli: %+v", found)
	}
	f := found[0]
	if f.RuleID != "GASH-024" || f.CWE != "CWE-327" || f.Evidence["signal"] != "tls10-supported" {
		t.Fatalf("bulgu: %+v", f)
	}
	if f.Severity != plugin.SeverityMedium || f.Confidence != plugin.ConfidenceConfirmed {
		t.Fatalf("şiddet/güven: %+v", f)
	}
	if f.Evidence["tls_version"] != "TLS1.0" || f.Evidence["outcome"] != "accepted" {
		t.Fatalf("kanıt: %+v", f.Evidence)
	}
	if got := TLSAuditFindings("https://example.com/", nil); len(got) != 0 {
		t.Fatalf("nil sonuç bulgusuz: %+v", got)
	}
	unknownOnly := &TLSAuditResult{Host: "h", Port: "443", Probes: []TLSVersionSupport{
		{Version: tls.VersionTLS10, Name: "TLS1.0", Outcome: "unknown", Err: "timeout"},
	}}
	if got := TLSAuditFindings("https://h/", unknownOnly); len(got) != 0 {
		t.Fatalf("unknown sonuç bulgusuz: %+v", got)
	}
}

// startLegacyTLSServer TLS 1.0-only mock sunucusudur (RSA sertifika).
// What: MinVersion=MaxVersion=TLS10; istemci eski sürümü kabul ediyor mu gözlemi.
// Why: Derin denetim uçtan uca sınanır; ortam eski sürümü engelliyorsa test skip eder.
func startLegacyTLSServer(t *testing.T) string {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(7),
		Subject:      pkix.Name{CommonName: "127.0.0.1"},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(24 * time.Hour),
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}},
		MinVersion:   tls.VersionTLS10,
		MaxVersion:   tls.VersionTLS10,
		CipherSuites: []uint16{tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA, tls.TLS_RSA_WITH_AES_128_CBC_SHA},
	})
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer func() { _ = c.Close() }()
				if tc, ok := c.(*tls.Conn); ok {
					_ = tc.SetDeadline(time.Now().Add(3 * time.Second))
					_ = tc.Handshake()
				}
			}(c)
		}
	}()
	t.Cleanup(func() { _ = ln.Close() })
	return ln.Addr().String()
}

func TestCheckTLSVersionSupportMock(t *testing.T) {
	addr := startLegacyTLSServer(t)
	audit, err := CheckTLSVersionSupport(context.Background(), addr, Options{Allow: allowAll, Timeout: 3 * time.Second})
	if err != nil {
		t.Fatalf("audit: %v", err)
	}
	if len(audit.Probes) != 2 {
		t.Fatalf("2 prob bekleniyordu: %+v", audit.Probes)
	}
	var tls10, tls11 *TLSVersionSupport
	for i := range audit.Probes {
		switch audit.Probes[i].Version {
		case tls.VersionTLS10:
			tls10 = &audit.Probes[i]
		case tls.VersionTLS11:
			tls11 = &audit.Probes[i]
		}
	}
	if tls10 == nil || tls11 == nil {
		t.Fatalf("problar eksik: %+v", audit.Probes)
	}
	if !tls10.Accepted {
		t.Skipf("ortam TLS 1.0 kabulünü engelliyor (outcome=%s err=%s); sınıflandırma katmanı ayrı test edildi",
			tls10.Outcome, tls10.Err)
	}
	if tls11.Accepted {
		t.Fatalf("TLS 1.0-only sunucuya TLS 1.1 kabul edilmemeli: %+v", tls11)
	}
	found := TLSAuditFindings("https://"+addr+"/", audit)
	if len(found) != 1 || found[0].Evidence["signal"] != "tls10-supported" {
		t.Fatalf("tek tls10-supported bulgusu bekleniyordu: %+v", found)
	}
	// Kapsam: Allow nil → çalışmaz.
	if _, err := CheckTLSVersionSupport(context.Background(), addr, Options{}); err == nil {
		t.Fatal("Allow nil iken derin denetim kapalı kalmalı")
	}
}

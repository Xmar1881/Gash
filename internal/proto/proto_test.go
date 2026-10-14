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
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Xmar1881/Gash/internal/plugin"
)

func allowAll(string) bool { return true }

func TestScopeFailClosed(t *testing.T) {
	ctx := context.Background()
	if _, err := CheckTLS(ctx, "example.com:443", Options{}); err == nil {
		t.Fatal("Allow nil iken TLS kapalı kalır")
	}
	deny := Options{Allow: func(string) bool { return false }}
	if _, err := CheckTLS(ctx, "example.com:443", deny); err == nil {
		t.Fatal("kapsam-dışı TLS reddedilmeli")
	}
	if _, err := CheckDNS(ctx, "example.com", deny); err == nil {
		t.Fatal("kapsam-dışı DNS reddedilmeli")
	}
	if _, err := GrabBanner(ctx, "example.com:80", deny); err == nil {
		t.Fatal("kapsam-dışı TCP reddedilmeli")
	}
	if _, err := CheckTLS(ctx, "portsuz", Options{Allow: allowAll}); err == nil {
		t.Fatal("portsuz girdi kabul edilmez")
	}
	if _, err := CheckDNS(ctx, "  ", Options{Allow: allowAll}); err == nil {
		t.Fatal("boş host reddedilmeli")
	}
}

// leafCert test yaprağı üretir (süre + self-signed kontrolü).
func leafCert(t *testing.T, notAfter time.Time, host string) *x509.Certificate {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: host},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     notAfter,
		DNSNames:     []string{host},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

func TestBuildTLSResultAndFindings(t *testing.T) {
	now := time.Now()
	leaf := leafCert(t, now.Add(10*24*time.Hour+time.Hour), "example.com")
	st := &tls.ConnectionState{
		Version:          tls.VersionTLS13,
		CipherSuite:      tls.TLS_AES_128_GCM_SHA256,
		PeerCertificates: []*x509.Certificate{leaf},
	}
	r := buildTLSResult("example.com", "443", st, now)
	if r.DaysLeft != 10 {
		t.Fatalf("days: %d", r.DaysLeft)
	}
	if !r.SelfSigned {
		t.Fatal("öz-imzalı tek yaprak self-signed olmalı")
	}
	if r.HostnameErr != "" {
		t.Fatalf("hostname: %s", r.HostnameErr)
	}
	// Yanlış host → hostname bulgusu.
	r2 := buildTLSResult("baska.example.com", "443", st, now)
	if r2.HostnameErr == "" {
		t.Fatal("hostname uyumsuzluğu yakalanmalı")
	}
	found := TLSFindings("https://example.com/", r)
	signals := map[string]bool{}
	for _, f := range found {
		signals[f.Evidence["signal"]] = true
		if f.RuleID != "GASH-024" || f.Confidence != plugin.ConfidenceConfirmed {
			t.Fatalf("kural/güven: %+v", f)
		}
	}
	if !signals["expiring"] || !signals["self-signed"] {
		t.Fatalf("sinyaller: %v", signals)
	}
	if signals["expired"] || signals["old-version"] {
		t.Fatalf("yanlış sinyal: %v", signals)
	}
	// Süresi dolmuş + eski sürüm.
	old := buildTLSResult("example.com", "443", &tls.ConnectionState{
		Version:          tls.VersionTLS10,
		PeerCertificates: []*x509.Certificate{leafCert(t, now.Add(-time.Hour), "example.com")},
	}, now)
	found = TLSFindings("https://example.com/", old)
	signals = map[string]bool{}
	for _, f := range found {
		signals[f.Evidence["signal"]] = true
	}
	if !signals["expired"] || !signals["old-version"] {
		t.Fatalf("expired/old-version bekleniyordu: %v", signals)
	}
	// Sağlıklı sertifika → bulgu yok.
	caKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	caTmpl := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "Test CA"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(365 * 24 * time.Hour), IsCA: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature, BasicConstraintsValid: true}
	caDER, _ := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	ca, _ := x509.ParseCertificate(caDER)
	leafKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	leafTmpl := &x509.Certificate{SerialNumber: big.NewInt(3), Subject: pkix.Name{CommonName: "example.com"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(300 * 24 * time.Hour), DNSNames: []string{"example.com"}}
	leafDER, _ := x509.CreateCertificate(rand.Reader, leafTmpl, ca, &leafKey.PublicKey, caKey)
	good, _ := x509.ParseCertificate(leafDER)
	healthy := buildTLSResult("example.com", "443", &tls.ConnectionState{
		Version: tls.VersionTLS13, PeerCertificates: []*x509.Certificate{good, ca}}, now)
	if got := TLSFindings("https://example.com/", healthy); len(got) != 0 {
		t.Fatalf("sağlıklı zincir bulgusuz olmalı: %+v", got)
	}
}

func TestCheckTLSLive(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()
	addr := strings.TrimPrefix(srv.URL, "https://")
	r, err := CheckTLS(context.Background(), addr, Options{Allow: allowAll})
	if err != nil {
		t.Fatalf("canlı TLS: %v", err)
	}
	if r.DaysLeft <= 0 {
		t.Fatalf("test sertifikası geçerli olmalı: %+v", r)
	}
	if r.Version < tls.VersionTLS12 {
		t.Fatalf("test sunucusu modern TLS kullanmalı: %s", versionName(r.Version))
	}
}

func TestCheckDNSInjected(t *testing.T) {
	o := Options{
		Allow:   allowAll,
		Resolve: func(string) ([]net.IP, error) { return []net.IP{net.ParseIP("93.184.216.34")}, nil },
		LookupTXT: func(name string) ([]string, error) {
			if strings.HasPrefix(name, "_dmarc.") {
				return []string{"v=DMARC1; p=reject"}, nil
			}
			return []string{"v=spf1 -all"}, nil
		},
	}
	r, err := CheckDNS(context.Background(), "example.com", o)
	if err != nil {
		t.Fatalf("dns: %v", err)
	}
	if r.SPF == "" || r.DMARC == "" || len(r.IPs) != 1 {
		t.Fatalf("dns sonuç: %+v", r)
	}
	if got := DNSFindings("https://example.com/", r); len(got) != 0 {
		t.Fatalf("tam kayıt bulgusuz olmalı: %+v", got)
	}
	// Kayıtsız domain → 2 bulgu (spf/dmarc), tavan firm.
	empty, err := CheckDNS(context.Background(), "ornek.test", Options{
		Allow:     allowAll,
		Resolve:   o.Resolve,
		LookupTXT: func(string) ([]string, error) { return nil, nil },
	})
	if err != nil {
		t.Fatalf("dns: %v", err)
	}
	found := DNSFindings("https://ornek.test/", empty)
	if len(found) != 2 {
		t.Fatalf("2 bulgu bekleniyordu: %+v", found)
	}
	for _, f := range found {
		if f.RuleID != "GASH-025" || f.Confidence != plugin.ConfidenceFirm {
			t.Fatalf("kural/güven: %+v", f)
		}
	}
	// IP literal: bulgusuz, hatasız.
	ipRes, err := CheckDNS(context.Background(), "127.0.0.1", Options{Allow: allowAll})
	if err != nil {
		t.Fatalf("ip: %v", err)
	}
	if got := DNSFindings("http://127.0.0.1/", ipRes); len(got) != 0 {
		t.Fatalf("IP literal bulgusuz: %+v", got)
	}
}

func TestGrabBanner(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_, _ = c.Write([]byte("SSH-2.0-OpenSSH_9.2\r\n"))
			_ = c.Close()
		}
	}()
	r, err := GrabBanner(context.Background(), ln.Addr().String(), Options{Allow: allowAll})
	if err != nil {
		t.Fatalf("banner: %v", err)
	}
	if !strings.Contains(r.Banner, "SSH-2.0") {
		t.Fatalf("banner: %q", r.Banner)
	}
	found := BannerFindings("tcp://"+ln.Addr().String(), r)
	if len(found) != 1 || found[0].RuleID != "GASH-026" || found[0].Confidence != plugin.ConfidenceTentative {
		t.Fatalf("banner bulgu: %+v", found)
	}
	// Banner'sız sunucu → bulgu yok.
	ln2, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln2.Close() }()
	go func() {
		for {
			c, err := ln2.Accept()
			if err != nil {
				return
			}
			_ = c.Close() // veri yok
		}
	}()
	r2, err := GrabBanner(context.Background(), ln2.Addr().String(), Options{Allow: allowAll})
	if err != nil {
		t.Fatalf("boş banner: %v", err)
	}
	if got := BannerFindings("tcp://"+ln2.Addr().String(), r2); len(got) != 0 {
		t.Fatalf("boş banner bulgusuz: %+v", got)
	}
}

func TestToFindingFingerprintStable(t *testing.T) {
	mk := func() Finding {
		return Finding{RuleID: "GASH-024", CWE: "CWE-295", Title: "t", Desc: "d",
			Severity: plugin.SeverityHigh, Confidence: plugin.ConfidenceConfirmed,
			Target: "https://example.com/", PluginID: "proto-tls-cert", OracleName: "tls",
			Evidence: map[string]string{"signal": "expired"}, Note: "n", Tags: []string{"tls"}}
	}
	a, b := mk().ToFinding(), mk().ToFinding()
	if a.Fingerprint == "" || a.Fingerprint != b.Fingerprint {
		t.Fatalf("fingerprint deterministik olmalı: %q vs %q", a.Fingerprint, b.Fingerprint)
	}
}

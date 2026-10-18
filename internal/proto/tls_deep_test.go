// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Modül: github.com/Xmar1881/Gash

package proto

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
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

// --- Faz 2: saf sınıflandırma birim testleri ---

func TestWeakKeyReason(t *testing.T) {
	rsa1024, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	rsa2048, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name   string
		cert   *x509.Certificate
		reason string
		sev    plugin.Severity
	}{
		{"rsa1024", &x509.Certificate{PublicKeyAlgorithm: x509.RSA, PublicKey: &rsa1024.PublicKey}, "rsa-small", plugin.SeverityHigh},
		{"rsa2048", &x509.Certificate{PublicKeyAlgorithm: x509.RSA, PublicKey: &rsa2048.PublicKey}, "", ""},
		{"ecdsaP224", &x509.Certificate{PublicKeyAlgorithm: x509.ECDSA, PublicKey: &ecdsa.PublicKey{Curve: elliptic.P224()}}, "ecdsa-small", plugin.SeverityMedium},
		{"ecdsaP256", &x509.Certificate{PublicKeyAlgorithm: x509.ECDSA, PublicKey: &ecdsa.PublicKey{Curve: elliptic.P256()}}, "", ""},
		{"dsa", &x509.Certificate{PublicKeyAlgorithm: x509.DSA}, "dsa-key", plugin.SeverityHigh},
		{"bilinmeyen-bitsiz-rsa", &x509.Certificate{PublicKeyAlgorithm: x509.RSA}, "", ""},
		{"nil", nil, "", ""},
	}
	for _, tc := range cases {
		reason, sev := weakKeyReason(tc.cert)
		if reason != tc.reason || sev != tc.sev {
			t.Fatalf("weakKeyReason(%s) = %q/%q (beklenen %q/%q)", tc.name, reason, sev, tc.reason, tc.sev)
		}
	}
}

func TestWeakSignatureReason(t *testing.T) {
	cases := []struct {
		sig    x509.SignatureAlgorithm
		reason string
		sev    plugin.Severity
	}{
		{x509.MD2WithRSA, "md2-signature", plugin.SeverityMedium},
		{x509.MD5WithRSA, "md5-signature", plugin.SeverityMedium},
		{x509.SHA1WithRSA, "sha1-signature", plugin.SeverityMedium},
		{x509.DSAWithSHA1, "sha1-signature", plugin.SeverityMedium},
		{x509.ECDSAWithSHA1, "sha1-signature", plugin.SeverityMedium},
		{x509.SHA256WithRSA, "", ""},
		{x509.ECDSAWithSHA256, "", ""},
		{x509.PureEd25519, "", ""},
	}
	for _, tc := range cases {
		reason, sev := weakSignatureReason(&x509.Certificate{SignatureAlgorithm: tc.sig})
		if reason != tc.reason || sev != tc.sev {
			t.Fatalf("weakSignatureReason(%v) = %q/%q (beklenen %q/%q)", tc.sig, reason, sev, tc.reason, tc.sev)
		}
	}
	if reason, _ := weakSignatureReason(nil); reason != "" {
		t.Fatalf("nil imza sınıflandırılmamalı: %q", reason)
	}
}

func TestWildcardAndSANClassification(t *testing.T) {
	cert := &x509.Certificate{DNSNames: []string{"*.com", "*.example.com", "www.example.com", "*.co.uk", "*.", "*x.com"}}
	got := wildcardSANs(cert)
	want := []string{"*.com", "*.example.com", "*.co.uk", "*."}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("wildcardSANs = %v (beklenen %v)", got, want)
	}
	broad := broadWildcards(got)
	if len(broad) != 2 || broad[0] != "*.com" || broad[1] != "*." {
		t.Fatalf("broadWildcards = %v (*.com ve *. geniş olmalı)", broad)
	}
	if got := broadWildcards([]string{"*.example.com", "*.co.uk", "example.com", ""}); len(got) != 0 {
		t.Fatalf("çok etiketli joker geniş sayılmamalı: %v", got)
	}
	if !certHasSAN(&x509.Certificate{IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}}) {
		t.Fatal("IP SAN has_san sayılmalı")
	}
	if certHasSAN(&x509.Certificate{Subject: pkix.Name{CommonName: "x"}}) {
		t.Fatal("CN tek başına SAN değildir")
	}
}

func TestCertValidityDays(t *testing.T) {
	now := time.Now()
	cert := &x509.Certificate{NotBefore: now, NotAfter: now.Add(400 * 24 * time.Hour)}
	if got := certValidityDays(cert); got != 400 {
		t.Fatalf("validity days = %d (beklenen 400)", got)
	}
	if got := certValidityDays(nil); got != 0 {
		t.Fatalf("nil validity = %d", got)
	}
	if got := certValidityDays(&x509.Certificate{}); got != 0 {
		t.Fatalf("sıfır zaman validity = %d", got)
	}
}

// deepTestChain gerçek imzalı kök + yaprak üretir (saf sınıflandırma testi için).
func deepTestChain(t *testing.T, leafNotAfter time.Time) (leaf, root *x509.Certificate, rootKey *rsa.PrivateKey) {
	t.Helper()
	now := time.Now()
	rootKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	rootTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(100),
		Subject:               pkix.Name{CommonName: "Deep Test Root"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(3650 * 24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTmpl, rootTmpl, &rootKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	root, err = x509.ParseCertificate(rootDER)
	if err != nil {
		t.Fatal(err)
	}
	leafKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(101),
		Subject:      pkix.Name{CommonName: "deep.example.com"},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     leafNotAfter,
		DNSNames:     []string{"deep.example.com"},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, root, &leafKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err = x509.ParseCertificate(leafDER)
	if err != nil {
		t.Fatal(err)
	}
	return leaf, root, rootKey
}

func TestClassifyChainStatus(t *testing.T) {
	now := time.Now()
	leaf, root, _ := deepTestChain(t, now.Add(90*24*time.Hour))

	rootPool := x509.NewCertPool()
	rootPool.AddCert(root)
	if status, errText := classifyChainStatus(leaf, nil, rootPool, now); status != "verified" || errText != "" {
		t.Fatalf("güvenilen kök → verified: %q %q", status, errText)
	}
	// Ara sertifika sunulmuş ama kök güvenilmez → untrusted (eksik değil).
	untrusted := x509.NewCertPool()
	if status, _ := classifyChainStatus(leaf, []*x509.Certificate{root}, untrusted, now); status != "untrusted" {
		t.Fatalf("güvenilmeyen kök → untrusted: %q", status)
	}
	// Issuer zincirde yok → incomplete (eksik ara sertifika).
	if status, _ := classifyChainStatus(leaf, nil, untrusted, now); status != "incomplete" {
		t.Fatalf("eksik issuer → incomplete: %q", status)
	}
	// Öz-imzalı yaprak (issuer=yok) → untrusted.
	selfKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	selfTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(102), Subject: pkix.Name{CommonName: "self.example.com"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(90 * 24 * time.Hour),
		DNSNames: []string{"self.example.com"},
	}
	selfDER, err := x509.CreateCertificate(rand.Reader, selfTmpl, selfTmpl, &selfKey.PublicKey, selfKey)
	if err != nil {
		t.Fatal(err)
	}
	self, err := x509.ParseCertificate(selfDER)
	if err != nil {
		t.Fatal(err)
	}
	if status, _ := classifyChainStatus(self, nil, untrusted, now); status != "untrusted" {
		t.Fatalf("öz-imzalı → untrusted (incomplete değil): %q", status)
	}
	// Süresi dolmuş yaprak → invalid.
	expiredLeaf, _, _ := deepTestChain(t, now.Add(-time.Hour))
	if status, _ := classifyChainStatus(expiredLeaf, nil, rootPool, now); status != "invalid" {
		t.Fatalf("süresi dolmuş → invalid: %q", status)
	}
	if status, errText := classifyChainStatus(nil, nil, nil, now); status != "" || errText != "" {
		t.Fatalf("nil yaprak sessiz olmalı: %q %q", status, errText)
	}
}

// deepSyntheticResult tüm zayıf olguları taşıyan sentetik gözlem üretir.
func deepSyntheticResult() *TLSResult {
	now := time.Now()
	return &TLSResult{
		Host: "deep.example.com", Port: "443",
		Version: tls.VersionTLS12, Cipher: tls.TLS_AES_128_GCM_SHA256,
		LeafSubject: "CN=deep.example.com", LeafIssuer: "CN=Untrusted Root",
		LeafCN:    "deep.example.com",
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(500 * 24 * time.Hour),
		ValidityDays: 500, ChainLen: 1,
		ChainStatus: "incomplete",
		ChainErr:    "x509: certificate signed by unknown authority",
		LeafKeyAlgo: "RSA", LeafKeyBits: 1024,
		LeafSigAlgo: "SHA1-RSA", LeafIsCA: true,
		DNSNamesCount: 0, HasSAN: false,
		WildcardNames: []string{"*.com", "*.example.com"},
	}
}

func TestTLSDeepFindingsSynthetic(t *testing.T) {
	r := deepSyntheticResult()
	found := TLSDeepFindings("https://deep.example.com/", r)
	signals := map[string]Finding{}
	for _, f := range found {
		if f.RuleID != "GASH-024" || f.Confidence != plugin.ConfidenceConfirmed {
			t.Fatalf("kural/güven: %+v", f)
		}
		if f.PluginID != "proto-tls-deep" || f.OracleName != "tls" {
			t.Fatalf("plugin/oracle: %+v", f)
		}
		signals[f.Evidence["signal"]] = f
	}
	expect := []string{"tls-weak-key", "tls-weak-signature", "tls-leaf-is-ca", "tls-untrusted-chain", "tls-no-san", "tls-wildcard-broad", "tls-long-validity"}
	for _, sig := range expect {
		if _, ok := signals[sig]; !ok {
			t.Fatalf("sinyal eksik %q: %+v", sig, found)
		}
	}
	if got := len(found); got != len(expect) {
		t.Fatalf("fazladan/eksik bulgu: %d (%v)", got, found)
	}
	if f := signals["tls-weak-key"]; f.Severity != plugin.SeverityHigh || f.CWE != "CWE-326" {
		t.Fatalf("weak-key şiddet/CWE: %+v", f)
	}
	if f := signals["tls-leaf-is-ca"]; f.Severity != plugin.SeverityHigh {
		t.Fatalf("leaf-is-ca şiddet: %+v", f)
	}
	if f := signals["tls-untrusted-chain"]; f.Severity != plugin.SeverityMedium || f.Evidence["chain_status"] != "incomplete" || f.Evidence["chain_err"] == "" {
		t.Fatalf("untrusted-chain: %+v", f)
	}
	if f := signals["tls-no-san"]; f.Severity != plugin.SeverityLow || f.Evidence["leaf_cn"] != "deep.example.com" {
		t.Fatalf("no-san: %+v", f)
	}
	if f := signals["tls-wildcard-broad"]; f.Severity != plugin.SeverityLow || f.Evidence["broad_wildcards"] != "*.com" {
		t.Fatalf("wildcard-broad: %+v", f)
	}
	if f := signals["tls-long-validity"]; f.Severity != plugin.SeverityLow || f.Evidence["validity_days"] != "500" {
		t.Fatalf("long-validity: %+v", f)
	}
	// Mevcut GASH-024 sinyalleri tekrarlanmamalı.
	for _, dup := range []string{"expired", "expiring", "self-signed", "hostname-mismatch", "tls10", "tls11", "weak-cipher"} {
		if _, ok := signals[dup]; ok {
			t.Fatalf("mevcut sinyal tekrarlandı: %q", dup)
		}
	}
	if got := TLSDeepFindings("https://x/", nil); len(got) != 0 {
		t.Fatalf("nil sonuç bulgusuz: %+v", got)
	}
}

func TestTLSDeepFindingsSelfSignedNoUntrustedDuplicate(t *testing.T) {
	r := &TLSResult{
		Host: "self.example.com", Port: "443", Version: tls.VersionTLS13,
		LeafCN: "self.example.com", DNSNamesCount: 1, HasSAN: true,
		ChainLen: 1, SelfSigned: true,
		ChainStatus: "untrusted", ChainErr: "x509: certificate signed by unknown authority",
		LeafKeyAlgo: "RSA", LeafKeyBits: 2048, LeafSigAlgo: "SHA256-RSA",
		ValidityDays: 90, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(90 * 24 * time.Hour),
	}
	for _, f := range TLSDeepFindings("https://self.example.com/", r) {
		if f.Evidence["signal"] == "tls-untrusted-chain" {
			t.Fatalf("self-signed zincir untrusted olarak TEKRAR raporlanmamalı: %+v", f)
		}
	}
	// Sağlıklı gözlem (doğrulanmış zincir, güçlü anahtar/imza, SAN'lı, kısa ömür) sessiz.
	healthy := &TLSResult{
		Host: "healthy.example.com", Port: "443", Version: tls.VersionTLS13,
		LeafCN: "healthy.example.com", DNSNamesCount: 2, HasSAN: true,
		ChainLen: 2, ChainStatus: "verified",
		LeafKeyAlgo: "ECDSA", LeafKeyBits: 256, LeafSigAlgo: "ECDSA-SHA256",
		ValidityDays: 90, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(90 * 24 * time.Hour),
	}
	if got := TLSDeepFindings("https://healthy.example.com/", healthy); len(got) != 0 {
		t.Fatalf("sağlıklı sertifika bulgusuz olmalı: %+v", got)
	}
}

// --- Gerçek yerel TLS sunucusu: alan doldurma + bulgu tetikleme ---

// startDeepTestTLSServer loopback TLS sunucusudur (RSA bits, isCA).
// What: httptest.NewUnstartedServer + x509.CreateCertificate; dış ağ yok.
// Why: TLSResult alanlarının canlı el sıkışmadan dolduğu deterministik sınanır.
func startDeepTestTLSServer(t *testing.T, bits int, isCA bool) *httptest.Server {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(200),
		Subject:      pkix.Name{CommonName: "127.0.0.1"},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(200 * 24 * time.Hour),
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		IsCA:         isCA,
	}
	if isCA {
		tmpl.KeyUsage = x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature
		tmpl.BasicConstraintsValid = true
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv
}

func TestCheckTLSDeepLeafFieldsLive(t *testing.T) {
	srv := startDeepTestTLSServer(t, 1024, false)
	addr := strings.TrimPrefix(srv.URL, "https://")
	r, err := CheckTLS(context.Background(), addr, Options{Allow: allowAll, Timeout: 3 * time.Second})
	if err != nil {
		t.Fatalf("canlı TLS: %v", err)
	}
	if r.LeafKeyAlgo != "RSA" || r.LeafKeyBits != 1024 {
		t.Fatalf("anahtar alanları: %+v", r)
	}
	if r.LeafSigAlgo == "" || r.LeafIsCA {
		t.Fatalf("imza/CA alanları: %+v", r)
	}
	if !r.HasSAN || r.DNSNamesCount != 0 || !r.SelfSigned {
		t.Fatalf("SAN/self-signed alanları: %+v", r)
	}
	if r.ChainStatus != "untrusted" {
		t.Fatalf("öz-imzalı zincir untrusted bekleniyordu: %+v", r)
	}
	if r.ValidityDays < 199 || r.ValidityDays > 201 {
		t.Fatalf("geçerlilik günü: %d", r.ValidityDays)
	}
	found := TLSDeepFindings("https://"+addr+"/", r)
	signals := map[string]Finding{}
	for _, f := range found {
		signals[f.Evidence["signal"]] = f
	}
	weak, ok := signals["tls-weak-key"]
	if !ok || weak.Severity != plugin.SeverityHigh {
		t.Fatalf("RSA-1024 zayıf anahtar bulgusu: %+v", found)
	}
	if _, ok := signals["tls-untrusted-chain"]; ok {
		t.Fatalf("self-signed zincir untrusted olarak TEKRAR raporlanmamalı: %+v", found)
	}
}

func TestCheckTLSDeepLeafIsCALive(t *testing.T) {
	srv := startDeepTestTLSServer(t, 2048, true)
	addr := strings.TrimPrefix(srv.URL, "https://")
	r, err := CheckTLS(context.Background(), addr, Options{Allow: allowAll, Timeout: 3 * time.Second})
	if err != nil {
		t.Fatalf("canlı TLS: %v", err)
	}
	if !r.LeafIsCA {
		t.Fatalf("CA:TRUE alanı dolmalı: %+v", r)
	}
	signals := map[string]bool{}
	for _, f := range TLSDeepFindings("https://"+addr+"/", r) {
		signals[f.Evidence["signal"]] = true
	}
	if !signals["tls-leaf-is-ca"] {
		t.Fatalf("tls-leaf-is-ca bekleniyordu: %+v", signals)
	}
}

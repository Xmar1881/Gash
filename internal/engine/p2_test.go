// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Modül: github.com/Xmar1881/Gash

package engine

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Xmar1881/Gash/internal/auth"
	"github.com/Xmar1881/Gash/internal/plugin"
	"github.com/Xmar1881/Gash/internal/plugin/loader"
)

// startShortLivedTLSServer 5-gün ömürlü öz-imzalı sertifikalı yerel TLS sunucusudur.
// What: Deterministik "expiring" sinyali için kontrollü laboratuvar sunucusu.
// Why: httptest varsayılan sertifikası 2084'e kadar geçerli CA'dır (bulgusuz).
func startShortLivedTLSServer(t *testing.T) *httptest.Server {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(42),
		Subject:      pkix.Name{CommonName: "127.0.0.1"},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(5 * 24 * time.Hour),
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("hello"))
	}))
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{cert}}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv
}

// TestAuthContextOpensRequiresAuth proves P2.5 wiring (context → HasAuth → schedule).
func TestAuthContextOpensRequiresAuth(t *testing.T) {
	mkReg := func() *plugin.Registry {
		reg := plugin.NewRegistry()
		s := mkSpec("auth-needing", plugin.PhaseProbe, 1)
		s.Safe = true
		s.RequiresAuth = true
		reg.MustRegister(s, "mem", false)
		return reg
	}
	e := New(mkReg(), DefaultConfig())
	ordered, skipped, err := e.Schedule(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(ordered) != 0 {
		t.Fatal("auth yokken requires_auth atlanır")
	}
	found := false
	for _, sk := range skipped {
		if sk.PluginID == "auth-needing" && strings.Contains(sk.Reason, "requires auth") {
			found = true
		}
	}
	if !found {
		t.Fatalf("skip sebebi yok: %+v", skipped)
	}

	ac := auth.New()
	if err := ac.ParseAuthHeader("Authorization: Bearer test-token"); err != nil {
		t.Fatal(err)
	}
	cfg := DefaultConfig()
	cfg.Auth = ac
	e2 := New(mkReg(), cfg)
	ordered, _, err = e2.Schedule(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(ordered) != 1 {
		t.Fatalf("auth varken requires_auth koşmalı: %+v", ordered)
	}
}

// TestChainTechSchedule proves P2.3 wiring (RequiresTech gate via --tech).
func TestChainTechSchedule(t *testing.T) {
	mkReg := func() *plugin.Registry {
		reg := plugin.NewRegistry()
		s := mkSpec("wp-bridger", plugin.PhaseProbe, 1)
		s.Safe = true
		s.RequiresTech = []string{"wordpress"}
		reg.MustRegister(s, "mem", false)
		return reg
	}
	e := New(mkReg(), DefaultConfig())
	ordered, skipped, err := e.Schedule(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(ordered) != 0 {
		t.Fatal("teknoloji yokken kapılanmalı")
	}
	if len(skipped) != 1 || !strings.Contains(skipped[0].Reason, "requires tech") {
		t.Fatalf("chain skip: %+v", skipped)
	}
	cfg := DefaultConfig()
	cfg.Technologies = []string{"wordpress"}
	e2 := New(mkReg(), cfg)
	ordered, _, err = e2.Schedule(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(ordered) != 1 {
		t.Fatalf("teknoloji varken koşmalı: %+v", ordered)
	}
}

// TestChainMissingProviderSchedule proves fail-open (skip, not fatal).
func TestChainMissingProviderSchedule(t *testing.T) {
	reg := plugin.NewRegistry()
	s := mkSpec("yetim-tuketici", plugin.PhaseProbe, 1)
	s.Safe = true
	s.Requires = []string{"olmayan-yetenek"}
	reg.MustRegister(s, "mem", false)
	e := New(reg, DefaultConfig())
	ordered, skipped, err := e.Schedule(context.Background())
	if err != nil {
		t.Fatalf("eksik sağlayıcı fatal olmamalı: %v", err)
	}
	if len(ordered) != 0 || len(skipped) != 1 {
		t.Fatalf("ordered=%v skipped=%v", ordered, skipped)
	}
}

// TestProtoReconTLSLive proves engine TLS recon against a local TLS server.
// What: 5-gün ömürlü öz-imzalı sunucu → expiring (+self-signed) GASH-024 bulguları.
// Why: Safe-profile passive recon produces deterministic findings offline.
func TestProtoReconTLSLive(t *testing.T) {
	srv := startShortLivedTLSServer(t)
	e := New(plugin.NewRegistry(), DefaultConfig())
	found, skipped := e.runProtoRecon(context.Background(), srv.URL)
	if len(skipped) != 0 {
		t.Fatalf("skip beklenmiyor: %+v", skipped)
	}
	if len(found) != 2 {
		t.Fatalf("2 TLS bulgusu bekleniyordu (expiring+self-signed), got %d: %+v", len(found), found)
	}
	signals := map[string]bool{}
	for _, f := range found {
		if f.RuleID != "GASH-024" {
			t.Fatalf("kural: %s", f.RuleID)
		}
		if string(f.Confidence) != "confirmed" {
			t.Fatalf("TLS deterministik gözlem confirmed olmalı: %s", f.Confidence)
		}
		signals[f.Evidence["signal"]] = true
	}
	if !signals["expiring"] || !signals["self-signed"] {
		t.Fatalf("sinyaller: %v", signals)
	}
}

// TestProtoReconHTTPNoTLS proves plain-http targets skip TLS but stay fast.
func TestProtoReconHTTPNoTLS(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()
	e := New(plugin.NewRegistry(), DefaultConfig())
	found, _ := e.runProtoRecon(context.Background(), srv.URL)
	for _, f := range found {
		if f.RuleID == "GASH-024" {
			t.Fatalf("http hedefte TLS bulgusu olmamalı: %+v", f)
		}
	}
}

// TestProtoReconTCPActiveGate proves --active gating + scope for banner probes.
func TestProtoReconTCPActiveGate(t *testing.T) {
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
			_, _ = c.Write([]byte("SSH-2.0-Test\r\n"))
			_ = c.Close()
		}
	}()
	mkCfg := func(active bool) Config {
		cfg := DefaultConfig()
		cfg.Active = active
		cfg.TCPBanners = []string{ln.Addr().String()}
		return cfg
	}
	// Pasif: skip izi, bulgu yok.
	e := New(plugin.NewRegistry(), mkCfg(false))
	found, skipped := e.runProtoRecon(context.Background(), "http://127.0.0.1/")
	if len(found) != 0 {
		t.Fatalf("active'siz banner bulgusu olmamalı: %+v", found)
	}
	if len(skipped) != 1 || !strings.Contains(skipped[0].Reason, "requires --active") {
		t.Fatalf("active skip izi: %+v", skipped)
	}
	// Aktif: tentative banner bulgusu (aynı host → kapsam içi).
	e2 := New(plugin.NewRegistry(), mkCfg(true))
	found, skipped = e2.runProtoRecon(context.Background(), "http://127.0.0.1/")
	if len(skipped) != 0 {
		t.Fatalf("skip beklenmiyor: %+v", skipped)
	}
	if len(found) != 1 || found[0].RuleID != "GASH-026" {
		t.Fatalf("banner bulgusu: %+v", found)
	}
	// Kapsam-dışı banner: istek yok, bulgu yok.
	cfg := mkCfg(true)
	cfg.TCPBanners = []string{"93.184.216.34:80"}
	e3 := New(plugin.NewRegistry(), cfg)
	found, _ = e3.runProtoRecon(context.Background(), "http://127.0.0.1/")
	if len(found) != 0 {
		t.Fatalf("kapsam-dışı bannera dokunulmaz: %+v", found)
	}
}

// TestFullRunIncludesProtoFindings proves end-to-end proto wiring in Run.
func TestFullRunIncludesProtoFindings(t *testing.T) {
	srv := startShortLivedTLSServer(t)
	dir := writeE2EPlugin(t)
	reg := plugin.NewRegistry()
	if _, err := loader.Discover([]string{dir}, reg); err != nil {
		t.Fatalf("discover: %v", err)
	}
	e := New(reg, DefaultConfig())
	rep, err := e.Run(context.Background(), srv.URL)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	hasTLS := false
	for _, f := range rep.Findings {
		if f.RuleID == "GASH-024" {
			hasTLS = true
		}
	}
	if !hasTLS {
		t.Fatalf("Run raporu GASH-024 içermeli: %+v", rep.Findings)
	}
}

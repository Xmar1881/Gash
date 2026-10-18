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
	"encoding/binary"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Xmar1881/Gash/internal/config"
	"github.com/Xmar1881/Gash/internal/plugin"
)

// startInfraSSHMock loopback SSH banner mock'udur; kabul sayacı döner.
// What: Her bağlantıya sabit banner yazar ve kapatır (salt-okuma gözlem).
// Why: Kapsam kapılarının "soket açılmadı" iddiası deterministik sayılır.
func startInfraSSHMock(t *testing.T, banner string) (string, *int32) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var accepts int32
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			atomic.AddInt32(&accepts, 1)
			_, _ = c.Write([]byte(banner))
			_ = c.Close()
		}
	}()
	t.Cleanup(func() { _ = ln.Close() })
	return ln.Addr().String(), &accepts
}

// TestInfraReconSSHNoActiveGate proves --active gate with zero sockets.
func TestInfraReconSSHNoActiveGate(t *testing.T) {
	addr, accepts := startInfraSSHMock(t, "SSH-1.5-OpenSSH_3.9p1\r\n")
	cfg := DefaultConfig()
	cfg.Active = false
	cfg.SSHAudit = true
	cfg.InfraTargets = []string{addr}
	e := New(plugin.NewRegistry(), cfg)
	found, skipped, stats := e.runInfraRecon(context.Background(), "http://127.0.0.1/")
	if len(found) != 0 {
		t.Fatalf("active'siz bulgu olmamalı: %+v", found)
	}
	if len(skipped) != 1 || skipped[0].PluginID != "proto-ssh-banner" || !strings.Contains(skipped[0].Reason, "requires --active") {
		t.Fatalf("skip izi: %+v", skipped)
	}
	if atomic.LoadInt32(accepts) != 0 {
		t.Fatalf("active'siz soket açılmamalı (kabul=%d)", atomic.LoadInt32(accepts))
	}
	if stats["ssh_checks"] != 0 {
		t.Fatalf("stats: %+v", stats)
	}
}

// TestInfraReconSSHOutOfScope proves fail-closed scope with zero sockets.
func TestInfraReconSSHOutOfScope(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Active = true
	cfg.SSHAudit = true
	cfg.InfraTargets = []string{"198.51.100.7:22"} // TEST-NET-2: asla dial edilmez
	e := New(plugin.NewRegistry(), cfg)
	found, skipped, stats := e.runInfraRecon(context.Background(), "http://127.0.0.1/")
	if len(found) != 0 || stats["ssh_checks"] != 0 {
		t.Fatalf("kapsam-dışı: found=%+v stats=%+v", found, stats)
	}
	if len(skipped) != 1 || !strings.Contains(skipped[0].Reason, "outside scope, no socket opened") {
		t.Fatalf("kapsam skip izi: %+v", skipped)
	}
}

// TestInfraReconSSHSafeProfileGate proves detector gating by safe profile.
func TestInfraReconSSHSafeProfileGate(t *testing.T) {
	addr, accepts := startInfraSSHMock(t, "SSH-1.5-OpenSSH_3.9p1\r\n")
	cfg := DefaultConfig()
	cfg.Active = true
	cfg.SSHAudit = true
	cfg.Profile = config.ProfileSafe
	cfg.InfraTargets = []string{addr}
	e := New(plugin.NewRegistry(), cfg)
	_, skipped, stats := e.runInfraRecon(context.Background(), "http://127.0.0.1/")
	if len(skipped) != 1 || !strings.Contains(skipped[0].Reason, "detector ssh disabled by profile") {
		t.Fatalf("profil kapısı: %+v", skipped)
	}
	if atomic.LoadInt32(accepts) != 0 || stats["ssh_checks"] != 0 {
		t.Fatalf("safe profilde soket açılmamalı: kabul=%d stats=%+v", atomic.LoadInt32(accepts), stats)
	}
}

// TestInfraReconSSHLive proves the SSH finding pipeline over a live mock.
// Faz 2: eski sürüm eşlemesi (GASH-056) tetiklendiğinde jenerik
// ssh-old-software sinyali düşer; protokol 1.x bulgusu (GASH-052) korunur.
func TestInfraReconSSHLive(t *testing.T) {
	addr, accepts := startInfraSSHMock(t, "SSH-1.5-OpenSSH_3.9p1\r\n")
	cfg := DefaultConfig()
	cfg.Active = true
	cfg.SSHAudit = true
	cfg.InfraTargets = []string{addr}
	cfg.InfraRatePerSecond = 0 // test hızı: limitsiz
	e := New(plugin.NewRegistry(), cfg)
	found, skipped, stats := e.runInfraRecon(context.Background(), "http://127.0.0.1/")
	if len(skipped) != 0 {
		t.Fatalf("skip beklenmiyor: %+v", skipped)
	}
	if stats["ssh_checks"] != 1 {
		t.Fatalf("ssh_checks=1 bekleniyordu: %+v", stats)
	}
	if atomic.LoadInt32(accepts) != 1 {
		t.Fatalf("tek dial bekleniyordu: %d", atomic.LoadInt32(accepts))
	}
	signals := map[string]string{}
	for _, f := range found {
		if f.RuleID != "GASH-052" && f.RuleID != "GASH-056" {
			t.Fatalf("kural: %+v", f)
		}
		signals[f.Evidence["signal"]] = f.RuleID
	}
	if signals["ssh-proto-1"] != "GASH-052" {
		t.Fatalf("protokol 1.x GASH-052 korunmalı: %v", signals)
	}
	if _, ok := signals["ssh-old-software"]; ok {
		t.Fatalf("GASH-056 varken jenerik eski-yazılım sinyali düşürülmeli: %v", signals)
	}
	if signals["ssh-vulnerable-version"] != "GASH-056" {
		t.Fatalf("sürüm eşlemesi sinyali: %v", signals)
	}
}

// TestInfraReconSSHVersionAdvisoryDedup: modern protokolde eski OpenSSH
// yalnızca GASH-056 üretir; jenerik GASH-052 tamamen düşer.
func TestInfraReconSSHVersionAdvisoryDedup(t *testing.T) {
	addr, _ := startInfraSSHMock(t, "SSH-2.0-OpenSSH_8.4p1 Ubuntu-6ubuntu2.1\r\n")
	cfg := DefaultConfig()
	cfg.Active = true
	cfg.SSHAudit = true
	cfg.InfraTargets = []string{addr}
	cfg.InfraRatePerSecond = 0
	e := New(plugin.NewRegistry(), cfg)
	found, skipped, _ := e.runInfraRecon(context.Background(), "http://127.0.0.1/")
	if len(skipped) != 0 {
		t.Fatalf("skip beklenmiyor: %+v", skipped)
	}
	if len(found) != 1 {
		t.Fatalf("tek GASH-056 bekleniyordu: %+v", found)
	}
	f := found[0]
	if f.RuleID != "GASH-056" || f.CWE != "CWE-1395" || f.Confidence != plugin.ConfidenceTentative {
		t.Fatalf("bulgu nitelikleri: %+v", f)
	}
	if f.Evidence["signal"] != "ssh-vulnerable-version" || f.Evidence["software_version"] != "8.4p1" {
		t.Fatalf("kanıt: %+v", f.Evidence)
	}
}

// TestInfraReconDBPortsLive proves DB port inventory findings and stats.
func TestInfraReconDBPortsLive(t *testing.T) {
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
			// Postgres-style auth hatası selamlaması (salt-okuma tespit).
			_, _ = c.Write([]byte("E\x00\x00\x00\x4eSFATAL\x00C28000\x00Mno pg_hba.conf entry for host"))
			_ = c.Close()
		}
	}()
	_, portStr, err := net.SplitHostPort(ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatal(err)
	}
	cfg := DefaultConfig()
	cfg.Active = true
	cfg.DBPortScan = true
	cfg.DBPorts = []int{port}
	cfg.InfraRatePerSecond = 0
	e := New(plugin.NewRegistry(), cfg)
	found, skipped, stats := e.runInfraRecon(context.Background(), "http://127.0.0.1/")
	if len(skipped) != 0 {
		t.Fatalf("skip beklenmiyor: %+v", skipped)
	}
	if stats["db_ports_scanned"] != 1 || stats["db_open_ports"] != 1 {
		t.Fatalf("stats: %+v", stats)
	}
	if len(found) != 1 || found[0].RuleID != "GASH-053" || found[0].Evidence["signal"] != "db-port-open" {
		t.Fatalf("DB bulgusu: %+v", found)
	}
	if found[0].Evidence["service"] != "postgres" {
		t.Fatalf("servis tanıma: %+v", found[0].Evidence)
	}
}

// TestInfraReconFlagsOffZeroTraffic proves default scans stay untouched.
func TestInfraReconFlagsOffZeroTraffic(t *testing.T) {
	e := New(plugin.NewRegistry(), DefaultConfig())
	found, skipped, stats := e.runInfraRecon(context.Background(), "http://127.0.0.1/")
	if found != nil || skipped != nil {
		t.Fatalf("bayraklar kapalıyken hiçbir şey üretilmemeli: %+v %+v", found, skipped)
	}
	for k, v := range stats {
		if v != 0 {
			t.Fatalf("stats[%s]=%d", k, v)
		}
	}
}

// TestInfraReconFullRunWiring proves Run includes infra findings + stats.
func TestInfraReconFullRunWiring(t *testing.T) {
	addr, _ := startInfraSSHMock(t, "SSH-1.5-OpenSSH_3.9p1\r\n")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()
	cfg := DefaultConfig()
	cfg.Active = true
	cfg.SSHAudit = true
	cfg.InfraTargets = []string{addr}
	cfg.InfraRatePerSecond = 0
	cfg.MaxPages = 1
	cfg.Depth = 1
	// Boş registry Run'da erken döner (B2); canlı hattı açmak için no-op
	// plugin kaydedilir (yürütme hatası iz bırakır, infra bulguları korunur).
	reg := plugin.NewRegistry()
	reg.MustRegister(mkSpec("noop-infra", plugin.PhaseProbe, 1), "mem", false)
	e := New(reg, cfg)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	rep, err := e.Run(ctx, srv.URL)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	hasSSH := false
	for _, f := range rep.Findings {
		if f.RuleID == "GASH-052" {
			hasSSH = true
		}
	}
	if !hasSSH {
		t.Fatalf("Run raporu GASH-052 içermeli: %+v", rep.Findings)
	}
	if rep.Stats["ssh_checks"] != 1 {
		t.Fatalf("stats ssh_checks: %+v", rep.Stats)
	}
}

// --- Faz 1: KEXINIT denetimi + DB unauth motor testleri ---

// infraKexInitPacket KEXINIT çerçevesini elle kurar (RFC 4253).
// What: Motor testleri proto iç yardımcılarına erişemez; bayt biçimi burada
// yeniden üretilir (10 name-list + boolean + reserved, 8-bayt blok hizası).
// Why: Sahte sunucunun beyanı deterministik olmalı; gerçek çözümleyici proto'da.
func infraKexInitPacket(lists ...[]string) []byte {
	payload := []byte{20}
	payload = append(payload, make([]byte, 16)...)
	for i := 0; i < 10; i++ {
		var list []string
		if i < len(lists) {
			list = lists[i]
		}
		raw := strings.Join(list, ",")
		var l [4]byte
		binary.BigEndian.PutUint32(l[:], uint32(len(raw)))
		payload = append(payload, l[:]...)
		payload = append(payload, raw...)
	}
	payload = append(payload, 0, 0, 0, 0, 0)
	base := 4 + 1 + len(payload)
	pad := 8 - base%8
	if pad < 4 {
		pad += 8
	}
	out := make([]byte, 4+1+len(payload)+pad)
	binary.BigEndian.PutUint32(out[:4], uint32(1+len(payload)+pad))
	out[4] = byte(pad)
	copy(out[5:], payload)
	return out
}

// startInfraSSHHandshakeMock banner + KEXINIT yazıp kapatan sahte sunucudur.
func startInfraSSHHandshakeMock(t *testing.T, banner string, packet []byte) (string, *int32) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var accepts int32
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			atomic.AddInt32(&accepts, 1)
			_, _ = c.Write([]byte(banner))
			_, _ = c.Write(packet)
			_ = c.Close()
		}
	}()
	t.Cleanup(func() { _ = ln.Close() })
	return ln.Addr().String(), &accepts
}

// TestInfraReconSSHHandshakeNoActiveGate: --active yoksa sıfır soket + skip izi.
func TestInfraReconSSHHandshakeNoActiveGate(t *testing.T) {
	packet := infraKexInitPacket(
		[]string{"curve25519-sha256"},
		[]string{"ssh-ed25519"},
		[]string{"aes128-ctr"}, []string{"aes128-ctr"},
		[]string{"hmac-sha2-256"}, []string{"hmac-sha2-256"},
	)
	addr, accepts := startInfraSSHHandshakeMock(t, "SSH-2.0-OpenSSH_9.6\r\n", packet)
	cfg := DefaultConfig()
	cfg.Active = false
	cfg.SSHHandshakeAudit = true
	cfg.InfraTargets = []string{addr}
	e := New(plugin.NewRegistry(), cfg)
	found, skipped, stats := e.runInfraRecon(context.Background(), "http://127.0.0.1/")
	if len(found) != 0 {
		t.Fatalf("active'siz bulgu olmamalı: %+v", found)
	}
	if len(skipped) != 1 || skipped[0].PluginID != "proto-ssh-handshake" || !strings.Contains(skipped[0].Reason, "requires --active") {
		t.Fatalf("skip izi: %+v", skipped)
	}
	if atomic.LoadInt32(accepts) != 0 || stats["ssh_handshake_checks"] != 0 {
		t.Fatalf("active'siz soket açılmamalı: kabul=%d stats=%+v", atomic.LoadInt32(accepts), stats)
	}
}

// TestInfraReconSSHHandshakeSafeProfileGate: ssh dedektörü kapalı profilde dial yok.
func TestInfraReconSSHHandshakeSafeProfileGate(t *testing.T) {
	packet := infraKexInitPacket([]string{"curve25519-sha256"})
	addr, accepts := startInfraSSHHandshakeMock(t, "SSH-2.0-OpenSSH_9.6\r\n", packet)
	cfg := DefaultConfig()
	cfg.Active = true
	cfg.SSHHandshakeAudit = true
	cfg.Profile = config.ProfileSafe
	cfg.InfraTargets = []string{addr}
	e := New(plugin.NewRegistry(), cfg)
	_, skipped, stats := e.runInfraRecon(context.Background(), "http://127.0.0.1/")
	if len(skipped) != 1 || skipped[0].PluginID != "proto-ssh-handshake" ||
		!strings.Contains(skipped[0].Reason, "detector ssh disabled by profile") {
		t.Fatalf("profil kapısı: %+v", skipped)
	}
	if atomic.LoadInt32(accepts) != 0 || stats["ssh_handshake_checks"] != 0 {
		t.Fatalf("safe profilde soket açılmamalı: kabul=%d stats=%+v", atomic.LoadInt32(accepts), stats)
	}
}

// TestInfraReconSSHHandshakeLive: KEXINIT gözlemi GASH-054 bulgusu üretir.
func TestInfraReconSSHHandshakeLive(t *testing.T) {
	packet := infraKexInitPacket(
		[]string{"diffie-hellman-group1-sha1", "curve25519-sha256"},
		[]string{"ssh-rsa", "ssh-ed25519"},
		[]string{"aes128-ctr"}, []string{"aes128-ctr"},
		[]string{"hmac-sha2-256"}, []string{"hmac-sha2-256"},
		[]string{"none"}, []string{"none"},
	)
	addr, accepts := startInfraSSHHandshakeMock(t, "SSH-2.0-OpenSSH_7.4\r\n", packet)
	cfg := DefaultConfig()
	cfg.Active = true
	cfg.SSHHandshakeAudit = true
	cfg.InfraTargets = []string{addr}
	cfg.InfraRatePerSecond = 0
	e := New(plugin.NewRegistry(), cfg)
	found, skipped, stats := e.runInfraRecon(context.Background(), "http://127.0.0.1/")
	if len(skipped) != 0 {
		t.Fatalf("skip beklenmiyor: %+v", skipped)
	}
	if stats["ssh_handshake_checks"] != 1 {
		t.Fatalf("ssh_handshake_checks=1 bekleniyordu: %+v", stats)
	}
	if atomic.LoadInt32(accepts) != 1 {
		t.Fatalf("tek dial bekleniyordu: %d", atomic.LoadInt32(accepts))
	}
	signals := map[string]bool{}
	for _, f := range found {
		if f.RuleID != "GASH-054" || f.Confidence != plugin.ConfidenceFirm {
			t.Fatalf("kural/güven: %+v", f)
		}
		signals[f.Evidence["signal"]] = true
	}
	if !signals["ssh-weak-kex"] || !signals["ssh-weak-hostkey"] {
		t.Fatalf("sinyaller: %v", signals)
	}
}

// startInfraRedisMock 6379 loopback'inde PING→+PONG, INFO→sürüm yanıtı verir.
// What: Port doluysa test atlanır; dış ağa asla çıkılmaz.
// Why: CheckDBUnauth servis kimliğini port numarasından türetir (sözleşme).
func startInfraRedisMock(t *testing.T) *int32 {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:6379")
	if err != nil {
		t.Skipf("loopback :6379 bağlanamadı (yerel servis olabilir): %v", err)
	}
	var accepts int32
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			atomic.AddInt32(&accepts, 1)
			go func(c net.Conn) {
				defer func() { _ = c.Close() }()
				buf := make([]byte, 64)
				for i := 0; i < 2; i++ {
					n, err := c.Read(buf)
					if err != nil {
						return
					}
					cmd := strings.TrimSpace(string(buf[:n]))
					switch {
					case strings.HasPrefix(cmd, "PING"):
						_, _ = c.Write([]byte("+PONG\r\n"))
					case strings.HasPrefix(cmd, "INFO"):
						_, _ = c.Write([]byte("# Server\r\nredis_version:7.2.4\r\n"))
					}
				}
			}(c)
		}
	}()
	t.Cleanup(func() { _ = ln.Close() })
	return &accepts
}

// TestInfraReconDBUnauthNoActiveGate: --active yoksa sıfır soket + skip izi.
func TestInfraReconDBUnauthNoActiveGate(t *testing.T) {
	accepts := startInfraRedisMock(t)
	cfg := DefaultConfig()
	cfg.Active = false
	cfg.DBUnauth = true
	cfg.DBPorts = []int{6379}
	e := New(plugin.NewRegistry(), cfg)
	found, skipped, stats := e.runInfraRecon(context.Background(), "http://127.0.0.1/")
	if len(found) != 0 {
		t.Fatalf("active'siz bulgu olmamalı: %+v", found)
	}
	if len(skipped) != 1 || skipped[0].PluginID != "proto-db-unauth" || !strings.Contains(skipped[0].Reason, "requires --active") {
		t.Fatalf("skip izi: %+v", skipped)
	}
	if atomic.LoadInt32(accepts) != 0 || stats["db_unauth_checks"] != 0 {
		t.Fatalf("active'siz soket açılmamalı: kabul=%d stats=%+v", atomic.LoadInt32(accepts), stats)
	}
}

// TestInfraReconDBUnauthLive: Redis PONG kanıtı GASH-055 high/firm bulgusu üretir.
func TestInfraReconDBUnauthLive(t *testing.T) {
	accepts := startInfraRedisMock(t)
	cfg := DefaultConfig()
	cfg.Active = true
	cfg.DBUnauth = true
	cfg.DBPorts = []int{6379}
	cfg.InfraRatePerSecond = 0
	e := New(plugin.NewRegistry(), cfg)
	found, skipped, stats := e.runInfraRecon(context.Background(), "http://127.0.0.1/")
	if len(skipped) != 0 {
		t.Fatalf("skip beklenmiyor: %+v", skipped)
	}
	if stats["db_unauth_checks"] != 1 {
		t.Fatalf("db_unauth_checks=1 bekleniyordu: %+v", stats)
	}
	if atomic.LoadInt32(accepts) != 1 {
		t.Fatalf("tek dial bekleniyordu: %d", atomic.LoadInt32(accepts))
	}
	if len(found) != 1 {
		t.Fatalf("tek GASH-055 bekleniyordu: %+v", found)
	}
	f := found[0]
	if f.RuleID != "GASH-055" || f.CWE != "CWE-306" || f.Severity != plugin.SeverityHigh ||
		f.Confidence != plugin.ConfidenceFirm || f.PluginID != "proto-db-unauth" {
		t.Fatalf("bulgu nitelikleri: %+v", f)
	}
	if f.Evidence["signal"] != "db-unauth-redis" || f.Evidence["version"] != "7.2.4" {
		t.Fatalf("kanıt: %+v", f.Evidence)
	}
}

// --- Faz 2: derin TLS sertifika/zincir motor testleri ---

// startInfraWeakTLSServer zayıf/CA yaprak sertifikalı yerel TLS sunucusudur.
// What: RSA bits + isCA bayrağı çağırana bırakılır; dış ağa çıkılmaz.
// Why: GASH-024 Faz 2 sinyalleri canlı el sıkışmadan deterministik sınanır.
func startInfraWeakTLSServer(t *testing.T, bits int, isCA bool) *httptest.Server {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(301),
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

// TestInfraReconTLSDeepCertFindings: tls-audit-deep zayıf anahtarı
// GASH-024 high/confirmed olarak raporlar; öz-imzalı zincir tekrar edilmez.
func TestInfraReconTLSDeepCertFindings(t *testing.T) {
	srv := startInfraWeakTLSServer(t, 1024, false)
	cfg := DefaultConfig()
	cfg.TLSAuditDeep = true
	e := New(plugin.NewRegistry(), cfg)
	found, skipped, stats := e.runInfraRecon(context.Background(), srv.URL)
	if len(skipped) != 0 {
		t.Fatalf("skip beklenmiyor: %+v", skipped)
	}
	if stats["tls_deep_checks"] < 1 {
		t.Fatalf("tls_deep_checks: %+v", stats)
	}
	signals := map[string]plugin.Severity{}
	for _, f := range found {
		if f.RuleID != "GASH-024" || f.Confidence != plugin.ConfidenceConfirmed {
			t.Fatalf("kural/güven: %+v", f)
		}
		signals[f.Evidence["signal"]] = f.Severity
	}
	if signals["tls-weak-key"] != plugin.SeverityHigh {
		t.Fatalf("RSA-1024 high bekleniyordu: %+v", signals)
	}
	if _, ok := signals["tls-untrusted-chain"]; ok {
		t.Fatalf("öz-imzalı zincir untrusted olarak raporlanmamalı: %+v", signals)
	}
	if _, ok := signals["tls-no-san"]; ok {
		t.Fatalf("IP SAN'lı sertifika CN-only sayılmamalı: %+v", signals)
	}
}

// TestInfraReconTLSDeepLocalIsCA: CA:TRUE yaprak sertifikası GASH-024 ile bildirilir.
func TestInfraReconTLSDeepLocalIsCA(t *testing.T) {
	srv := startInfraWeakTLSServer(t, 2048, true)
	cfg := DefaultConfig()
	cfg.TLSAuditDeep = true
	e := New(plugin.NewRegistry(), cfg)
	found, _, _ := e.runInfraRecon(context.Background(), srv.URL)
	signals := map[string]bool{}
	for _, f := range found {
		signals[f.Evidence["signal"]] = true
	}
	if !signals["tls-leaf-is-ca"] {
		t.Fatalf("tls-leaf-is-ca bekleniyordu: %+v", signals)
	}
}

// TestInfraReconTLSDeepReusesObservation: runProtoReconTLS gözlemi ile
// sunucu kapalıyken de sertifika bulguları üretilir (ek dial gerekmez).
func TestInfraReconTLSDeepReusesObservation(t *testing.T) {
	srv := startInfraWeakTLSServer(t, 1024, false)
	e := New(plugin.NewRegistry(), DefaultConfig())
	found, _, obs := e.runProtoReconTLS(context.Background(), srv.URL)
	if obs == nil {
		t.Fatal("TLS gözlemi dönmeliydi")
	}
	weak := false
	for _, f := range found {
		if f.Evidence["signal"] == "self-signed" {
			weak = true
		}
	}
	if !weak {
		t.Fatalf("öz-imzalı gözlem bekleniyordu: %+v", found)
	}
	srv.Close() // sunucu kapandı: yeniden dial mümkün değil
	cfg := DefaultConfig()
	cfg.TLSAuditDeep = true
	e2 := New(plugin.NewRegistry(), cfg)
	found2, _, _ := e2.runInfraReconTLS(context.Background(), srv.URL, obs)
	signals := map[string]bool{}
	for _, f := range found2 {
		if f.RuleID != "GASH-024" {
			t.Fatalf("kural: %+v", f)
		}
		signals[f.Evidence["signal"]] = true
	}
	if !signals["tls-weak-key"] {
		t.Fatalf("gözlemden zayıf anahtar bulgusu bekleniyordu: %+v", signals)
	}
}

// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Modül: github.com/Xmar1881/Gash

package proto

import (
	"context"
	"encoding/binary"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Xmar1881/Gash/internal/plugin"
)

// startSSHMock loopback sahte SSH sunucusudur; kabul sayısını döndürür.
// What: Her bağlantıya verilen banner'ı yazar ve kapatır (yazma yok, salt-okuma testi).
// Why: Dış ağ YOK; dial/kabul kanıtı deterministik sayılır.
func startSSHMock(t *testing.T, banner string) (string, *int32) {
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
			if banner != "" {
				_, _ = c.Write([]byte(banner))
			}
			_ = c.Close()
		}
	}()
	t.Cleanup(func() { _ = ln.Close() })
	return ln.Addr().String(), &accepts
}

func TestParseSSHBannerTable(t *testing.T) {
	valid := []struct {
		line     string
		proto    string
		software string
		comment  string
	}{
		{"SSH-2.0-OpenSSH_9.6", "2.0", "OpenSSH_9.6", ""},
		{"SSH-2.0-OpenSSH_8.4p1 Ubuntu-6ubuntu2.1", "2.0", "OpenSSH_8.4p1", "Ubuntu-6ubuntu2.1"},
		{"SSH-1.5-OpenSSH_3.9p1", "1.5", "OpenSSH_3.9p1", ""},
		{"SSH-1.99-OpenSSH_3.4", "1.99", "OpenSSH_3.4", ""},
		{"SSH-2.0-Dropbear_2022.83", "2.0", "Dropbear_2022.83", ""},
	}
	for _, tc := range valid {
		protoVersion, software, comment, ok := parseSSHBanner(tc.line)
		if !ok {
			t.Fatalf("%q ayrıştırılmalıydı", tc.line)
		}
		if protoVersion != tc.proto || software != tc.software || comment != tc.comment {
			t.Fatalf("%q => %q/%q/%q (beklenen %q/%q/%q)",
				tc.line, protoVersion, software, comment, tc.proto, tc.software, tc.comment)
		}
	}
	malformed := []string{"", "HELLO", "SSH-2.0", "SSH--x", "SSH-x.y-z", "SSH-", "  "}
	for _, line := range malformed {
		if _, _, _, ok := parseSSHBanner(line); ok {
			t.Fatalf("bozuk satır kabul edilmemeli: %q", line)
		}
	}
}

func TestSSHFindingsProto1x(t *testing.T) {
	res := &SSHResult{
		Host: "127.0.0.1", Port: "22", Open: true,
		Banner: "SSH-1.5-OpenSSH_3.9p1", ProtocolVersion: "1.5", Software: "OpenSSH_3.9p1",
	}
	found := SSHFindings("ssh://127.0.0.1:22/", res)
	if len(found) != 2 {
		t.Fatalf("proto 1.x + eski yazılım → 2 bulgu: %+v", found)
	}
	signals := map[string]Finding{}
	for _, f := range found {
		signals[f.Evidence["signal"]] = f
		if f.RuleID != "GASH-052" || f.Confidence != plugin.ConfidenceTentative {
			t.Fatalf("kural/güven: %+v", f)
		}
	}
	p1, ok := signals["ssh-proto-1"]
	if !ok || p1.Severity != plugin.SeverityHigh || p1.CWE != "CWE-327" {
		t.Fatalf("proto-1 bulgusu: %+v", signals)
	}
	old, ok := signals["ssh-old-software"]
	if !ok || old.Severity != plugin.SeverityMedium {
		t.Fatalf("eski yazılım bulgusu: %+v", signals)
	}
	// 1.99 uyumluluk sürümü de 1.x sınıfındadır (RFC 4253).
	compat := &SSHResult{Host: "h", Port: "22", Open: true, ProtocolVersion: "1.99", Software: "OpenSSH_3.4"}
	fs := SSHFindings("ssh://h/", compat)
	if len(fs) != 2 {
		t.Fatalf("1.99 → proto-1 + eski yazılım: %+v", fs)
	}
}

func TestSSHFindingsModernSilent(t *testing.T) {
	modern := &SSHResult{
		Host: "h", Port: "22", Open: true,
		Banner: "SSH-2.0-OpenSSH_9.6", ProtocolVersion: "2.0", Software: "OpenSSH_9.6",
	}
	if got := SSHFindings("ssh://h/", modern); len(got) != 0 {
		t.Fatalf("modern banner bulgusuz olmalı: %+v", got)
	}
	// 8.5+ eski-yazılım tablosunda değildir (muhafazakâr tablo).
	newer := &SSHResult{Host: "h", Port: "22", Open: true, ProtocolVersion: "2.0", Software: "OpenSSH_8.5p1"}
	if got := SSHFindings("ssh://h/", newer); len(got) != 0 {
		t.Fatalf("OpenSSH_8.5 eski sayılmamalı: %+v", got)
	}
	// Boş banner/kapalı sonuç sessizdir.
	if got := SSHFindings("ssh://h/", &SSHResult{Open: false}); len(got) != 0 {
		t.Fatalf("kapalı sonuç bulgusuz: %+v", got)
	}
	if got := SSHFindings("ssh://h/", nil); len(got) != 0 {
		t.Fatalf("nil sonuç bulgusuz: %+v", got)
	}
}

func TestCheckSSHAllowNilNoDial(t *testing.T) {
	addr, accepts := startSSHMock(t, "SSH-2.0-OpenSSH_9.6\r\n")
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := CheckSSH(context.Background(), host, port, Options{}); err == nil {
		t.Fatal("Allow nil iken SSH kapalı kalmalı (fail-closed)")
	}
	deny := Options{Allow: func(string) bool { return false }}
	if _, err := CheckSSH(context.Background(), host, port, deny); err == nil {
		t.Fatal("kapsam-dışı SSH reddedilmeli")
	}
	if atomic.LoadInt32(accepts) != 0 {
		t.Fatalf("kapsam reddinde soket açılmamalı (kabul=%d)", atomic.LoadInt32(accepts))
	}
}

func TestCheckSSHLive(t *testing.T) {
	addr, accepts := startSSHMock(t, "SSH-2.0-OpenSSH_8.4p1 Ubuntu-6ubuntu2.1\r\n")
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatal(err)
	}
	res, err := CheckSSH(context.Background(), host, port, Options{Allow: allowAll, Timeout: 2 * time.Second})
	if err != nil {
		t.Fatalf("ssh: %v", err)
	}
	if !res.Open || res.ProtocolVersion != "2.0" || res.Software != "OpenSSH_8.4p1" || res.Comment != "Ubuntu-6ubuntu2.1" {
		t.Fatalf("sonuç: %+v", res)
	}
	if res.DurationMs < 0 {
		t.Fatalf("süre negatif olamaz: %d", res.DurationMs)
	}
	if !strings.Contains(res.Banner, "SSH-2.0") {
		t.Fatalf("banner: %q", res.Banner)
	}
	if got := atomic.LoadInt32(accepts); got != 1 {
		t.Fatalf("tek dial bekleniyordu: %d", got)
	}
	found := SSHFindings("ssh://"+addr+"/", res)
	if len(found) != 1 || found[0].Evidence["signal"] != "ssh-old-software" {
		t.Fatalf("eski yazılım bulgusu: %+v", found)
	}
}

func TestCheckSSHOversizedAndMalformedBanner(t *testing.T) {
	huge := "SSH-2.0-" + strings.Repeat("A", 400) + "\r\n"
	addr, _ := startSSHMock(t, huge)
	host, port, _ := net.SplitHostPort(addr)
	res, err := CheckSSH(context.Background(), host, port, Options{Allow: allowAll, Timeout: 2 * time.Second})
	if err != nil {
		t.Fatalf("ssh: %v", err)
	}
	if len(res.Banner) > sshBannerMax {
		t.Fatalf("banner %d bayt (tavan %d)", len(res.Banner), sshBannerMax)
	}
	if res.ProtocolVersion != "2.0" {
		t.Fatalf("taşan banner'da proto ayrışmalı: %+v", res)
	}
	// Bozuk satır: bağlantı kanıtı var, ayrıştırma sessiz.
	badAddr, _ := startSSHMock(t, "HELLO-THERE\r\n")
	bh, bp, _ := net.SplitHostPort(badAddr)
	bad, err := CheckSSH(context.Background(), bh, bp, Options{Allow: allowAll, Timeout: 2 * time.Second})
	if err != nil {
		t.Fatalf("bozuk banner: %v", err)
	}
	if !bad.Open || bad.ProtocolVersion != "" || bad.Software != "" {
		t.Fatalf("bozuk banner ayrıştırılmamalı: %+v", bad)
	}
	if got := SSHFindings("ssh://"+badAddr+"/", bad); len(got) != 0 {
		t.Fatalf("bozuk banner bulgusuz: %+v", got)
	}
}

func TestCheckSSHClosedPort(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	host, port, _ := net.SplitHostPort(addr)
	if _, err := CheckSSH(context.Background(), host, port, Options{Allow: allowAll, Timeout: time.Second}); err == nil {
		t.Fatal("kapalı portta hata bekleniyordu")
	}
	// Boş host reddedilir.
	if _, err := CheckSSH(context.Background(), "  ", "22", Options{Allow: allowAll}); err == nil {
		t.Fatal("boş host reddedilmeli")
	}
}

// --- Faz 1: SSH KEXINIT denetim testleri ---

// startSSHHandshakeMock loopback sahte SSH sunucusudur (banner + KEXINIT).
// What: waitClient=true ise istemcinin KEXINIT'ini bekler, sonra yanıt yazar.
// Why: Her iki akış (sunucu-initiated ve istemci-initiated) deterministik sınanır.
func startSSHHandshakeMock(t *testing.T, banner string, kex []byte, waitClient bool) (string, *int32) {
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
			go func(c net.Conn) {
				defer func() { _ = c.Close() }()
				if banner != "" {
					_, _ = c.Write([]byte(banner))
				}
				if waitClient {
					buf := make([]byte, 256)
					_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
					_, _ = c.Read(buf)
				}
				if len(kex) > 0 {
					_, _ = c.Write(kex)
				}
			}(c)
		}
	}()
	t.Cleanup(func() { _ = ln.Close() })
	return ln.Addr().String(), &accepts
}

// sshTestKexInitPacket 10 name-list'li geçerli KEXINIT paketi kurar (üretim çerçeveleyicisi).
func sshTestKexInitPacket(t *testing.T, lists [][]string) []byte {
	t.Helper()
	if len(lists) != 10 {
		t.Fatalf("10 name-list gerekir: %d", len(lists))
	}
	payload := []byte{20}
	payload = append(payload, make([]byte, 16)...)
	for _, list := range lists {
		raw := strings.Join(list, ",")
		var l [4]byte
		binary.BigEndian.PutUint32(l[:], uint32(len(raw)))
		payload = append(payload, l[:]...)
		payload = append(payload, raw...)
	}
	payload = append(payload, 0, 0, 0, 0, 0)
	return frameSSHPacket(payload)
}

// sshTestStrongLists yalnızca modern algoritmalar içeren 10 listelik settir.
func sshTestStrongLists() [][]string {
	return [][]string{
		{"curve25519-sha256", "sntrup761x25519-sha512@openssh.com", "ecdh-sha2-nistp256"},
		{"ssh-ed25519", "rsa-sha2-512", "rsa-sha2-256", "ecdsa-sha2-nistp256"},
		{"chacha20-poly1305@openssh.com", "aes256-gcm@openssh.com", "aes128-ctr"},
		{"chacha20-poly1305@openssh.com", "aes256-gcm@openssh.com", "aes128-ctr"},
		{"hmac-sha2-256-etm@openssh.com", "umac-128-etm@openssh.com"},
		{"hmac-sha2-256-etm@openssh.com", "umac-128-etm@openssh.com"},
		{"none", "zlib@openssh.com"},
		{"none", "zlib@openssh.com"},
		{"en-US", "tr-TR"}, // dil listeleri dolu: 10'lu çözümleme sırası doğrulanır
		{"en-US"},
	}
}

// sshTestWeakLists kırılgan sınıfların karışımını içerir.
func sshTestWeakLists() [][]string {
	return [][]string{
		{"diffie-hellman-group1-sha1", "curve25519-sha256"},
		{"ssh-rsa", "ssh-dss", "ssh-ed25519"},
		{"3des-cbc", "aes128-cbc", "aes128-ctr"},
		{"aes128-ctr", "arcfour256"},
		{"hmac-md5", "hmac-sha1", "hmac-sha2-256"},
		{"hmac-sha2-256", "umac-64@openssh.com"},
		{"none"},
		{"none"},
		{},
		{},
	}
}

func TestAuditSSHHandshakeLiveStrong(t *testing.T) {
	packet := sshTestKexInitPacket(t, sshTestStrongLists())
	addr, accepts := startSSHHandshakeMock(t, "SSH-2.0-OpenSSH_9.6\r\n", packet, false)
	host, port, _ := net.SplitHostPort(addr)
	res, err := AuditSSHHandshake(context.Background(), host, port, Options{Allow: allowAll, Timeout: 2 * time.Second})
	if err != nil {
		t.Fatalf("audit: %v", err)
	}
	if !strings.Contains(res.Banner, "OpenSSH_9.6") || res.ProtocolVersion != "2.0" || res.Software != "OpenSSH_9.6" {
		t.Fatalf("banner alanları: %+v", res)
	}
	if len(res.KexAlgorithms) != 3 || res.KexAlgorithms[0] != "curve25519-sha256" {
		t.Fatalf("kex listesi: %v", res.KexAlgorithms)
	}
	if len(res.HostKeyAlgorithms) != 4 || res.HostKeyAlgorithms[0] != "ssh-ed25519" {
		t.Fatalf("hostkey listesi: %v", res.HostKeyAlgorithms)
	}
	if len(res.CiphersClientToServer) != 3 || len(res.CiphersServerToClient) != 3 {
		t.Fatalf("cipher listeleri: c2s=%v s2c=%v", res.CiphersClientToServer, res.CiphersServerToClient)
	}
	if len(res.MACsClientToServer) != 2 || len(res.MACsServerToClient) != 2 {
		t.Fatalf("mac listeleri: c2s=%v s2c=%v", res.MACsClientToServer, res.MACsServerToClient)
	}
	// Dil listeleri (9./10.) dolu olsa da sıkıştırma listeleri doğru çözülür.
	if len(res.CompressionC2S) != 2 || res.CompressionC2S[0] != "none" || res.CompressionS2C[0] != "none" {
		t.Fatalf("compression listeleri: c2s=%v s2c=%v", res.CompressionC2S, res.CompressionS2C)
	}
	if res.DurationMs < 0 {
		t.Fatalf("süre negatif: %d", res.DurationMs)
	}
	if got := atomic.LoadInt32(accepts); got != 1 {
		t.Fatalf("tek dial bekleniyordu: %d", got)
	}
	if found := SSHHandshakeFindings("ssh://"+addr+"/", res); len(found) != 0 {
		t.Fatalf("modern algoritmalar bulgusuz olmalı: %+v", found)
	}
}

func TestAuditSSHHandshakeWeakFindings(t *testing.T) {
	packet := sshTestKexInitPacket(t, sshTestWeakLists())
	addr, _ := startSSHHandshakeMock(t, "SSH-2.0-OpenSSH_7.4\r\n", packet, false)
	host, port, _ := net.SplitHostPort(addr)
	res, err := AuditSSHHandshake(context.Background(), host, port, Options{Allow: allowAll, Timeout: 2 * time.Second})
	if err != nil {
		t.Fatalf("audit: %v", err)
	}
	found := SSHHandshakeFindings("ssh://"+addr+"/", res)
	if len(found) != 4 {
		t.Fatalf("4 sınıf bulgusu bekleniyordu: %+v", found)
	}
	bySignal := map[string]Finding{}
	for _, f := range found {
		if f.RuleID != "GASH-054" || f.CWE != "CWE-327" || f.Confidence != plugin.ConfidenceFirm {
			t.Fatalf("kural/CWE/güven: %+v", f)
		}
		if f.Evidence["ssh_version"] == "" || f.Evidence["weak_algorithms"] == "" {
			t.Fatalf("kanıt eksik: %+v", f.Evidence)
		}
		bySignal[f.Evidence["signal"]] = f
	}
	kex, ok := bySignal["ssh-weak-kex"]
	if !ok || kex.Severity != plugin.SeverityMedium {
		t.Fatalf("kex bulgusu: %+v", bySignal)
	}
	if !strings.Contains(kex.Evidence["weak_algorithms"], "diffie-hellman-group1-sha1") {
		t.Fatalf("kex zayıf liste: %+v", kex.Evidence)
	}
	hostkey, ok := bySignal["ssh-weak-hostkey"]
	if !ok || hostkey.Severity != plugin.SeverityMedium {
		t.Fatalf("hostkey bulgusu: %+v", bySignal)
	}
	if !strings.Contains(hostkey.Evidence["weak_algorithms"], "ssh-rsa") || !strings.Contains(hostkey.Evidence["weak_algorithms"], "ssh-dss") {
		t.Fatalf("hostkey zayıf liste: %+v", hostkey.Evidence)
	}
	cipher, ok := bySignal["ssh-weak-cipher"]
	if !ok || cipher.Severity != plugin.SeverityHigh {
		t.Fatalf("cipher bulgusu (3des/arcfour high): %+v", bySignal)
	}
	// c2s+s2c tek kanıt alanında birleşir.
	if !strings.Contains(cipher.Evidence["ciphers"], "c2s=[3des-cbc") || !strings.Contains(cipher.Evidence["ciphers"], "arcfour256") {
		t.Fatalf("cipher kanıtı: %+v", cipher.Evidence)
	}
	mac, ok := bySignal["ssh-weak-mac"]
	if !ok || mac.Severity != plugin.SeverityMedium {
		t.Fatalf("mac bulgusu: %+v", bySignal)
	}
	if !strings.Contains(mac.Evidence["weak_algorithms"], "hmac-md5") || !strings.Contains(mac.Evidence["weak_algorithms"], "umac-64@openssh.com") {
		t.Fatalf("mac zayıf liste: %+v", mac.Evidence)
	}

	// Plaintext "none" cipher → high.
	lists := sshTestStrongLists()
	lists[6] = []string{"none"}
	lists[7] = []string{"none"}
	nonePacket := sshTestKexInitPacket(t, lists)
	noneAddr, _ := startSSHHandshakeMock(t, "SSH-2.0-x\r\n", nonePacket, false)
	nh, np, _ := net.SplitHostPort(noneAddr)
	nres, err := AuditSSHHandshake(context.Background(), nh, np, Options{Allow: allowAll, Timeout: 2 * time.Second})
	if err != nil {
		t.Fatalf("none audit: %v", err)
	}
	nf := SSHHandshakeFindings("ssh://"+noneAddr+"/", nres)
	if len(nf) != 0 {
		t.Fatalf("sıkıştırma none bulgu üretmemeli (yalnızca cipher sınıfı): %+v", nf)
	}
	// Cipher listesine none eklenirse high bulgu.
	lists[2] = []string{"none"}
	nonePacket = sshTestKexInitPacket(t, lists)
	noneAddr2, _ := startSSHHandshakeMock(t, "SSH-2.0-x\r\n", nonePacket, false)
	nh2, np2, _ := net.SplitHostPort(noneAddr2)
	nres2, err := AuditSSHHandshake(context.Background(), nh2, np2, Options{Allow: allowAll, Timeout: 2 * time.Second})
	if err != nil {
		t.Fatalf("none cipher audit: %v", err)
	}
	nf2 := SSHHandshakeFindings("ssh://"+noneAddr2+"/", nres2)
	if len(nf2) != 1 || nf2[0].Severity != plugin.SeverityHigh || nf2[0].Evidence["weakness"] != "plaintext-none" {
		t.Fatalf("none cipher high bulgu bekleniyordu: %+v", nf2)
	}
}

func TestAuditSSHHandshakeClientInitiated(t *testing.T) {
	packet := sshTestKexInitPacket(t, sshTestStrongLists())
	addr, _ := startSSHHandshakeMock(t, "SSH-2.0-Dropbear_2022.83\r\n", packet, true)
	host, port, _ := net.SplitHostPort(addr)
	res, err := AuditSSHHandshake(context.Background(), host, port, Options{Allow: allowAll, Timeout: 3 * time.Second})
	if err != nil {
		t.Fatalf("istemci-initiated audit: %v", err)
	}
	if len(res.KexAlgorithms) == 0 || res.Software != "Dropbear_2022.83" {
		t.Fatalf("sonuç: %+v", res)
	}
}

func TestAuditSSHHandshakeMalformed(t *testing.T) {
	packet := sshTestKexInitPacket(t, sshTestStrongLists())
	// Kesik paket: gövde eksik → nazik hata.
	truncated := packet[:len(packet)-5]
	addr, _ := startSSHHandshakeMock(t, "SSH-2.0-x\r\n", truncated, false)
	host, port, _ := net.SplitHostPort(addr)
	if _, err := AuditSSHHandshake(context.Background(), host, port, Options{Allow: allowAll, Timeout: time.Second}); err == nil {
		t.Fatal("kesik paket hata vermeliydi")
	}
	// Aşırı büyük packet_length: gövde olmadan bile reddedilir.
	oversize := make([]byte, 4)
	binary.BigEndian.PutUint32(oversize, 1<<20)
	oversize = append(oversize, 0, 0, 0, 0)
	bigAddr, _ := startSSHHandshakeMock(t, "SSH-2.0-x\r\n", oversize, false)
	bh, bp, _ := net.SplitHostPort(bigAddr)
	if _, err := AuditSSHHandshake(context.Background(), bh, bp, Options{Allow: allowAll, Timeout: time.Second}); err == nil {
		t.Fatal("aşırı packet_length hata vermeliydi")
	}
	// Yanlış mesaj tipi (KEXINIT değil): çözümleme hatası.
	payload := []byte{21}
	payload = append(payload, make([]byte, 16+8)...)
	wrongAddr, _ := startSSHHandshakeMock(t, "SSH-2.0-x\r\n", frameSSHPacket(payload), false)
	wh, wp, _ := net.SplitHostPort(wrongAddr)
	if _, err := AuditSSHHandshake(context.Background(), wh, wp, Options{Allow: allowAll, Timeout: time.Second}); err == nil {
		t.Fatal("yanlış mesaj tipi hata vermeliydi")
	}
	// Hiç KEXINIT göndermeyen sunucu: kısa deadline sonunda hata (asılı kalmaz).
	silentAddr, _ := startSSHHandshakeMock(t, "SSH-2.0-x\r\n", nil, false)
	sh, sp, _ := net.SplitHostPort(silentAddr)
	if _, err := AuditSSHHandshake(context.Background(), sh, sp, Options{Allow: allowAll, Timeout: 900 * time.Millisecond}); err == nil {
		t.Fatal("KEXINIT gelmezse hata bekleniyordu")
	}
}

func TestAuditSSHHandshakeAllowNilNoDial(t *testing.T) {
	packet := sshTestKexInitPacket(t, sshTestWeakLists())
	addr, accepts := startSSHHandshakeMock(t, "SSH-2.0-x\r\n", packet, false)
	host, port, _ := net.SplitHostPort(addr)
	if _, err := AuditSSHHandshake(context.Background(), host, port, Options{}); err == nil {
		t.Fatal("Allow nil iken denetim kapalı kalmalı (fail-closed)")
	}
	deny := Options{Allow: func(string) bool { return false }}
	if _, err := AuditSSHHandshake(context.Background(), host, port, deny); err == nil {
		t.Fatal("kapsam-dışı denetim reddedilmeli")
	}
	if _, err := AuditSSHHandshake(context.Background(), "  ", "22", Options{Allow: allowAll}); err == nil {
		t.Fatal("boş host reddedilmeli")
	}
	if atomic.LoadInt32(accepts) != 0 {
		t.Fatalf("kapsam reddinde soket açılmamalı (kabul=%d)", atomic.LoadInt32(accepts))
	}
}

func TestSSHWeakAlgorithmClassification(t *testing.T) {
	cases := []struct {
		kind   string
		name   string
		reason string
		sev    plugin.Severity
	}{
		{"kex", "diffie-hellman-group1-sha1", "sha1-kex", plugin.SeverityMedium},
		{"kex", "diffie-hellman-group14-sha1", "sha1-kex", plugin.SeverityMedium},
		{"kex", "diffie-hellman-group-exchange-sha1", "sha1-kex", plugin.SeverityMedium},
		{"kex", "gss-group1-sha1-toWM5Slw5Ew8Mqkay+al2g==", "sha1-kex", plugin.SeverityMedium},
		{"kex", "curve25519-sha256", "", ""},
		{"kex", "sntrup761x25519-sha512@openssh.com", "", ""},
		{"kex", "ecdh-sha2-nistp256", "", ""},
		{"kex", "diffie-hellman-group16-sha512", "", ""},
		{"kex", "diffie-hellman-group14-sha256", "", ""},
		{"hostkey", "ssh-dss", "ssh-dss", plugin.SeverityMedium},
		{"hostkey", "ssh-rsa", "ssh-rsa-sha1", plugin.SeverityMedium},
		{"hostkey", "ssh-ed25519", "", ""},
		{"hostkey", "rsa-sha2-256", "", ""},
		{"hostkey", "ecdsa-sha2-nistp521", "", ""},
		{"cipher", "none", "plaintext-none", plugin.SeverityHigh},
		{"cipher", "arcfour128", "arcfour", plugin.SeverityHigh},
		{"cipher", "3des-cbc", "3des-cbc", plugin.SeverityHigh},
		{"cipher", "blowfish-cbc", "blowfish-cbc", plugin.SeverityHigh},
		{"cipher", "cast128-cbc", "cast128-cbc", plugin.SeverityHigh},
		{"cipher", "des-cbc", "single-des", plugin.SeverityHigh},
		{"cipher", "aes128-cbc", "cbc-mode", plugin.SeverityMedium},
		{"cipher", "aes256-gcm@openssh.com", "", ""},
		{"cipher", "chacha20-poly1305@openssh.com", "", ""},
		{"mac", "hmac-md5", "hmac-md5", plugin.SeverityMedium},
		{"mac", "hmac-md5-96", "hmac-md5", plugin.SeverityMedium},
		{"mac", "hmac-sha1", "hmac-sha1", plugin.SeverityMedium},
		{"mac", "hmac-sha1-96", "hmac-sha1", plugin.SeverityMedium},
		{"mac", "umac-64@openssh.com", "umac-64", plugin.SeverityMedium},
		{"mac", "hmac-ripemd160", "ripemd160", plugin.SeverityMedium},
		{"mac", "hmac-sha2-256-etm@openssh.com", "", ""},
		{"mac", "umac-128-etm@openssh.com", "", ""},
		{"", "hmac-md5", "", ""},
	}
	for _, tc := range cases {
		reason, sev := sshWeakAlgorithmReason(tc.kind, tc.name)
		if reason != tc.reason || sev != tc.sev {
			t.Fatalf("sshWeakAlgorithmReason(%q, %q) = %q/%q (beklenen %q/%q)",
				tc.kind, tc.name, reason, sev, tc.reason, tc.sev)
		}
	}
	if got := SSHHandshakeFindings("ssh://h/", nil); len(got) != 0 {
		t.Fatalf("nil sonuç bulgusuz: %+v", got)
	}
	if got := SSHHandshakeFindings("ssh://h/", &SSHHandshakeResult{Host: "h", Port: "22"}); len(got) != 0 {
		t.Fatalf("KEXINIT gözlemi yoksa bulgusuz: %+v", got)
	}
}

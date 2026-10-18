// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Modül: github.com/Xmar1881/Gash

package proto

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"math"
	"net"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Xmar1881/Gash/internal/plugin"
)

// startDBMock loopback sahte DB sunucusudur; kabul sayısını döndürür.
// What: greeting boşsa hiçbir veri yazmadan kapatır (sessiz açık port).
// Why: Dış ağ YOK; port/selamlama heuristiği deterministik doğrulanır.
func startDBMock(t *testing.T, greeting string) (int, *int32) {
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
			if greeting != "" {
				_, _ = c.Write([]byte(greeting))
			}
			_ = c.Close()
		}
	}()
	t.Cleanup(func() { _ = ln.Close() })
	_, portStr, err := net.SplitHostPort(ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatal(err)
	}
	return port, &accepts
}

func TestNormalizeDBPorts(t *testing.T) {
	got := normalizeDBPorts([]int{0, 70000, -1, 5432, 5432, 6379, 5432})
	want := []int{5432, 6379}
	if len(got) != len(want) {
		t.Fatalf("normalize: %v (beklenen %v)", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("normalize: %v (beklenen %v)", got, want)
		}
	}
	var many []int
	for i := 1; i <= 70; i++ {
		many = append(many, i)
	}
	if got := normalizeDBPorts(many); len(got) != dbMaxPorts {
		t.Fatalf("tavan %d olmalı: %d", dbMaxPorts, len(got))
	}
	if got := normalizeDBPorts(nil); len(got) != 0 {
		t.Fatalf("boş girdi boş dönmeli: %v", got)
	}
}

func TestIdentifyDBService(t *testing.T) {
	pgError := "E\x00\x00\x00\x4eSFATAL\x00C28000\x00Mno pg_hba.conf entry for host \"127.0.0.1\""
	mysqlHello := string([]byte{0x0a}) + "8.0.35\x00" + strings.Repeat("\x00", 8)
	cases := []struct {
		raw     string
		port    int
		service string
	}{
		{pgError, 5432, "postgres"},
		{"PostgreSQL 16.1 on x86_64", 9999, "postgres"},
		{mysqlHello, 3306, "mysql"},
		{"mysql_native_password", 9999, "mysql"},
		{"MongoDB server greeting", 27017, "mongodb"},
		{"memcached 1.6.21", 11211, "memcached"},
		{"CouchDB/3.3.2 (Erlang OTP/24)", 5984, "couchdb"},
		{"Cassandra native protocol", 9042, "cassandra"},
		{"", 5432, "postgres"}, // sessiz port → port eşlemesi
		{"", 6379, "redis"},    // sessiz port → port eşlemesi
		{"", 9200, "elasticsearch"},
		{"", 9999, "unknown"}, // ne selamlama ne eşleme
		{"random banner", 9999, "unknown"},
	}
	for _, tc := range cases {
		if got := identifyDBService(tc.raw, tc.port); got != tc.service {
			t.Fatalf("identify(%q, %d) = %q (beklenen %q)", tc.raw, tc.port, got, tc.service)
		}
	}
}

func TestScanDBPortsAllowNilNoDial(t *testing.T) {
	port, accepts := startDBMock(t, "")
	if _, err := ScanDBPorts(context.Background(), "127.0.0.1", []int{port}, Options{}); err == nil {
		t.Fatal("Allow nil iken DB taraması kapalı kalmalı (fail-closed)")
	}
	deny := Options{Allow: func(string) bool { return false }}
	if _, err := ScanDBPorts(context.Background(), "127.0.0.1", []int{port}, deny); err == nil {
		t.Fatal("kapsam-dışı DB taraması reddedilmeli")
	}
	if atomic.LoadInt32(accepts) != 0 {
		t.Fatalf("kapsam reddinde soket açılmamalı (kabul=%d)", atomic.LoadInt32(accepts))
	}
	if _, err := ScanDBPorts(context.Background(), "  ", []int{port}, Options{Allow: allowAll}); err == nil {
		t.Fatal("boş host reddedilmeli")
	}
}

func TestScanDBPortsLive(t *testing.T) {
	pgPort, _ := startDBMock(t, "E\x00\x00\x00\x4eSFATAL\x00C28000\x00Mno pg_hba.conf entry for host")
	silentPort, _ := startDBMock(t, "")
	unknownPort, _ := startDBMock(t, "")
	o := Options{Allow: allowAll, Timeout: 2 * time.Second}
	results, err := ScanDBPorts(context.Background(), "127.0.0.1", []int{pgPort, silentPort, unknownPort}, o)
	if err != nil {
		t.Fatalf("db: %v", err)
	}
	if len(results) != 3 {
		t.Fatalf("3 sonuç bekleniyordu: %+v", results)
	}
	byPort := map[int]DBPortResult{}
	for _, r := range results {
		byPort[r.Port] = r
		if !r.Open {
			t.Fatalf("loopback port açık olmalı: %+v", r)
		}
		if r.DurationMs < 0 {
			t.Fatalf("süre negatif: %+v", r)
		}
	}
	if got := byPort[pgPort].Service; got != "postgres" {
		t.Fatalf("selamlama postgres tanımalı: %q", got)
	}
	// Sessiz port: haritada yoksa "unknown" (rastgele ephemeral port haritada yer almaz).
	if got := byPort[silentPort].Service; got == "" {
		t.Fatalf("sessiz port servis alanı boş olmamalı")
	}
	if got := byPort[unknownPort].Service; got != "unknown" && !strings.Contains(got, "unknown") {
		// Ephemeral portlar bilinen DB portlarıyla çakışırsa (nadir) kabul edilir.
		if _, known := dbPortServices[unknownPort]; !known {
			t.Fatalf("eşlemesiz sessiz port unknown olmalı: %q", got)
		}
	}
	// Kapalı port: hata yok, Open=false.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	_, closedStr, err := net.SplitHostPort(ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	closedPort, err := strconv.Atoi(closedStr)
	if err != nil {
		t.Fatal(err)
	}
	_ = ln.Close()
	closed, err := ScanDBPorts(context.Background(), "127.0.0.1", []int{closedPort}, o)
	if err != nil {
		t.Fatalf("kapalı port hata döndürmemeli (gözlem): %v", err)
	}
	if len(closed) != 1 || closed[0].Open {
		t.Fatalf("kapalı port Open=false olmalı: %+v", closed)
	}
}

func TestDBPortFindingsOnlyOpen(t *testing.T) {
	results := []DBPortResult{
		{Host: "127.0.0.1", Port: 5432, Open: true, Service: "postgres", Banner: "PostgreSQL"},
		{Host: "127.0.0.1", Port: 3306, Open: false, Service: "mysql"},
	}
	found := DBPortFindings(results)
	if len(found) != 1 {
		t.Fatalf("yalnızca açık port bulgu üretmeli: %+v", found)
	}
	f := found[0]
	if f.RuleID != "GASH-053" || f.CWE != "CWE-200" {
		t.Fatalf("kural/CWE: %+v", f)
	}
	if f.Severity != plugin.SeverityMedium || f.Confidence != plugin.ConfidenceFirm {
		t.Fatalf("şiddet/güven: %+v", f)
	}
	if f.Evidence["signal"] != "db-port-open" || f.Evidence["port"] != "5432" || f.Evidence["service"] != "postgres" {
		t.Fatalf("kanıt: %+v", f.Evidence)
	}
	if f.Target != "127.0.0.1:5432" {
		t.Fatalf("hedef: %q", f.Target)
	}
	// Kanıt hijyeni: kontrol baytları kırpılır, uzunluk sınırlanır.
	dirty := []DBPortResult{{Host: "h", Port: 1234, Open: true, Service: "unknown",
		Banner: "\x01\x02" + strings.Repeat("B", 500)}}
	fs := DBPortFindings(dirty)
	if len(fs) != 1 {
		t.Fatalf("kirli banner bulgu üretmeli: %+v", fs)
	}
	if len(fs[0].Evidence["banner"]) > dbEvidenceMax || strings.ContainsAny(fs[0].Evidence["banner"], "\x01\x02") {
		t.Fatalf("banner arındırılmalı: %q", fs[0].Evidence["banner"])
	}
}

// --- Faz 1: DB unauth denetim testleri ---
//
// CheckDBUnauth servis kimliğini PORT numarasından türetir (üretim sözleşmesi);
// bu yüzden mock listener'lar gerçek servis portlarına bağlanır. Yerel makinede
// o port doluysa test atlanır (t.Skip) — dış ağa asla çıkılmaz.

// startDBProbeMockOnPort loopback'te belirtilen portta bağlanır ve her
// bağlantıya özel handler koşar; kabul sayacını döndürür.
func startDBProbeMockOnPort(t *testing.T, port int, handler func(net.Conn)) *int32 {
	t.Helper()
	ln, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
	if err != nil {
		t.Skipf("loopback :%d bağlanamadı (yerel servis olabilir): %v", port, err)
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
				handler(c)
			}(c)
		}
	}()
	t.Cleanup(func() { _ = ln.Close() })
	return &accepts
}

// redisMockHandler PING → +PONG, ardından tek INFO server yanıtı verir.
func redisMockHandler(c net.Conn) {
	br := bufio.NewReader(c)
	for i := 0; i < 2; i++ {
		line, err := br.ReadString('\n')
		if err != nil {
			return
		}
		switch strings.TrimSpace(line) {
		case "PING":
			_, _ = c.Write([]byte("+PONG\r\n"))
		case "INFO server":
			_, _ = c.Write([]byte("# Server\r\nredis_version:7.2.4\r\n"))
		}
	}
}

func TestCheckDBUnauthRedisLive(t *testing.T) {
	// 6379 doluysa gerçek bir Redis'e karşı deneme yapma riski: skip.
	accepts := startDBProbeMockOnPort(t, 6379, redisMockHandler)
	res, err := CheckDBUnauth(context.Background(), "127.0.0.1", 6379, Options{Allow: allowAll, Timeout: 2 * time.Second})
	if err != nil {
		t.Fatalf("redis unauth: %v", err)
	}
	if !res.Unauth || res.Version != "7.2.4" || res.Service != "redis" {
		t.Fatalf("redis sonucu: %+v", res)
	}
	if !strings.Contains(res.Note, "PING") {
		t.Fatalf("not: %q", res.Note)
	}
	if got := atomic.LoadInt32(accepts); got != 1 {
		t.Fatalf("tek dial bekleniyordu: %d", got)
	}
	found := DBUnauthFindings("redis://127.0.0.1:6379/", *res)
	if len(found) != 1 {
		t.Fatalf("tek GASH-055 bulgusu bekleniyordu: %+v", found)
	}
	f := found[0]
	if f.RuleID != "GASH-055" || f.CWE != "CWE-306" || f.Severity != plugin.SeverityHigh || f.Confidence != plugin.ConfidenceFirm {
		t.Fatalf("kural/CWE/şiddet/güven: %+v", f)
	}
	if f.Evidence["signal"] != "db-unauth-redis" || f.Evidence["service"] != "redis" || f.Evidence["version"] != "7.2.4" {
		t.Fatalf("kanıt: %+v", f.Evidence)
	}
	if f.PluginID != "proto-db-unauth" || f.OracleName != "db" {
		t.Fatalf("plugin/oracle: %+v", f)
	}
}

func TestCheckDBUnauthRedisAuthRequired(t *testing.T) {
	startDBProbeMockOnPort(t, 6379, func(c net.Conn) {
		br := bufio.NewReader(c)
		if _, err := br.ReadString('\n'); err != nil {
			return
		}
		_, _ = c.Write([]byte("-NOAUTH Authentication required.\r\n"))
	})
	res, err := CheckDBUnauth(context.Background(), "127.0.0.1", 6379, Options{Allow: allowAll, Timeout: 2 * time.Second})
	if err != nil {
		t.Fatalf("redis noauth: %v", err)
	}
	if res.Unauth || !res.AuthRequired || res.AuthMethod != "requirepass" {
		t.Fatalf("auth gerekli sonucu: %+v", res)
	}
	if found := DBUnauthFindings("redis://127.0.0.1:6379/", *res); len(found) != 0 {
		t.Fatalf("auth gerekliyse bulgu yok: %+v", found)
	}
}

func TestCheckDBUnauthMemcachedLive(t *testing.T) {
	startDBProbeMockOnPort(t, 11211, func(c net.Conn) {
		br := bufio.NewReader(c)
		if _, err := br.ReadString('\n'); err != nil {
			return
		}
		_, _ = c.Write([]byte("VERSION 1.6.21\r\n"))
	})
	res, err := CheckDBUnauth(context.Background(), "127.0.0.1", 11211, Options{Allow: allowAll, Timeout: 2 * time.Second})
	if err != nil {
		t.Fatalf("memcached unauth: %v", err)
	}
	if !res.Unauth || res.Version != "1.6.21" || res.Service != "memcached" {
		t.Fatalf("memcached sonucu: %+v", res)
	}
	if found := DBUnauthFindings("memcached://127.0.0.1:11211", *res); len(found) != 1 {
		t.Fatalf("GASH-055 bekleniyordu: %+v", found)
	}
}

// bsonTestDouble / bsonTestInt32 / bsonTestString minimal BSON elemanları.
func bsonTestDouble(name string, v float64) []byte {
	out := append([]byte{0x01}, []byte(name)...)
	out = append(out, 0)
	var b [8]byte
	binary.LittleEndian.PutUint64(b[:], math.Float64bits(v))
	return append(out, b[:]...)
}

func bsonTestInt32(name string, v int32) []byte {
	out := append([]byte{0x10}, []byte(name)...)
	out = append(out, 0)
	var b [4]byte
	binary.LittleEndian.PutUint32(b[:], uint32(v))
	return append(out, b[:]...)
}

func bsonTestString(name, v string) []byte {
	out := append([]byte{0x02}, []byte(name)...)
	out = append(out, 0)
	var b [4]byte
	binary.LittleEndian.PutUint32(b[:], uint32(len(v)+1))
	out = append(out, b[:]...)
	out = append(out, []byte(v)...)
	return append(out, 0)
}

func bsonTestDoc(elems ...[]byte) []byte {
	out := make([]byte, 4)
	for _, e := range elems {
		out = append(out, e...)
	}
	out = append(out, 0)
	binary.LittleEndian.PutUint32(out[:4], uint32(len(out)))
	return out
}

// mongoTestOpReply tek BSON belgeli OP_REPLY zarfı üretir.
func mongoTestOpReply(doc []byte) []byte {
	out := make([]byte, 36)
	binary.LittleEndian.PutUint32(out[0:], uint32(36+len(doc)))
	binary.LittleEndian.PutUint32(out[4:], 2)  // requestID
	binary.LittleEndian.PutUint32(out[8:], 1)  // responseTo
	binary.LittleEndian.PutUint32(out[12:], 1) // OP_REPLY
	binary.LittleEndian.PutUint32(out[32:], 1) // numberReturned
	return append(out, doc...)
}

// readMongoTestRequest istemci OP_QUERY paketini tüketir (içerik doğrulanır).
func readMongoTestRequest(t *testing.T, c net.Conn) {
	t.Helper()
	var hdr [16]byte
	if _, err := io.ReadFull(c, hdr[:]); err != nil {
		return
	}
	mlen := int(binary.LittleEndian.Uint32(hdr[:4]))
	if mlen < 16 || mlen > 4096 {
		return
	}
	body := make([]byte, mlen-16)
	_, _ = io.ReadFull(c, body)
	if op := binary.LittleEndian.Uint32(hdr[12:16]); op != 2004 {
		t.Errorf("OP_QUERY bekleniyordu: %d", op)
	}
	if !bytes.Contains(body, []byte("admin.$cmd\x00")) || !bytes.Contains(body, []byte("hello\x00")) {
		t.Errorf("hello komutu bekleniyordu: %q", body)
	}
}

func TestCheckDBUnauthMongoLive(t *testing.T) {
	startDBProbeMockOnPort(t, 27017, func(c net.Conn) {
		readMongoTestRequest(t, c)
		doc := bsonTestDoc(
			bsonTestDouble("ok", 1),
			bsonTestInt32("maxWireVersion", 13),
			bsonTestString("version", "7.0.5"),
		)
		_, _ = c.Write(mongoTestOpReply(doc))
	})
	res, err := CheckDBUnauth(context.Background(), "127.0.0.1", 27017, Options{Allow: allowAll, Timeout: 2 * time.Second})
	if err != nil {
		t.Fatalf("mongo unauth: %v", err)
	}
	if !res.Unauth || res.MaxWireVersion != 13 || res.Version != "7.0.5" || res.AuthRequired {
		t.Fatalf("mongo sonucu: %+v", res)
	}
	found := DBUnauthFindings("mongodb://127.0.0.1:27017", *res)
	if len(found) != 1 || found[0].Evidence["max_wire_version"] != "13" {
		t.Fatalf("mongo bulgusu: %+v", found)
	}
}

func TestCheckDBUnauthMongoAuthRequired(t *testing.T) {
	startDBProbeMockOnPort(t, 27017, func(c net.Conn) {
		readMongoTestRequest(t, c)
		doc := bsonTestDoc(
			bsonTestDouble("ok", 0),
			bsonTestString("errmsg", "command hello requires authentication"),
			bsonTestInt32("code", 13),
		)
		_, _ = c.Write(mongoTestOpReply(doc))
	})
	res, err := CheckDBUnauth(context.Background(), "127.0.0.1", 27017, Options{Allow: allowAll, Timeout: 2 * time.Second})
	if err != nil {
		t.Fatalf("mongo auth: %v", err)
	}
	if res.Unauth || !res.AuthRequired || res.AuthMethod != "SCRAM (code 13)" {
		t.Fatalf("auth gerekli sonucu: %+v", res)
	}
	if found := DBUnauthFindings("mongodb://127.0.0.1:27017", *res); len(found) != 0 {
		t.Fatalf("auth gerekliyse bulgu yok: %+v", found)
	}
}

// readPostgresTestStartup istemci StartupMessage'ını tüketir ve kimlik alanını doğrular.
func readPostgresTestStartup(t *testing.T, c net.Conn) {
	t.Helper()
	var lenb [4]byte
	if _, err := io.ReadFull(c, lenb[:]); err != nil {
		return
	}
	n := int(binary.BigEndian.Uint32(lenb[:]))
	if n < 8 || n > 4096 {
		return
	}
	buf := make([]byte, n-4)
	_, _ = io.ReadFull(c, buf)
	if proto := binary.BigEndian.Uint32(buf[:4]); proto != 196608 {
		t.Errorf("protokol 3.0 bekleniyordu: %d", proto)
	}
	if !bytes.Contains(buf, []byte("gash_probe\x00")) {
		t.Errorf("dummy kimlik bekleniyordu: %q", buf)
	}
}

func TestCheckDBUnauthPostgresTrust(t *testing.T) {
	startDBProbeMockOnPort(t, 5432, func(c net.Conn) {
		readPostgresTestStartup(t, c)
		_, _ = c.Write([]byte{'R', 0, 0, 0, 8, 0, 0, 0, 0}) // AuthenticationOk (trust)
		body := append([]byte("server_version\x00"), []byte("16.2\x00")...)
		msg := []byte{'S', 0, 0, 0, 0}
		binary.BigEndian.PutUint32(msg[1:], uint32(4+len(body)))
		_, _ = c.Write(append(msg, body...))
		_, _ = c.Write([]byte{'Z', 0, 0, 0, 5, 'I'}) // ReadyForQuery
	})
	res, err := CheckDBUnauth(context.Background(), "127.0.0.1", 5432, Options{Allow: allowAll, Timeout: 2 * time.Second})
	if err != nil {
		t.Fatalf("pg trust: %v", err)
	}
	if !res.Unauth || res.AuthRequired || res.AuthMethod != "trust" || res.Version != "16.2" {
		t.Fatalf("pg trust sonucu: %+v", res)
	}
	if found := DBUnauthFindings("postgres://127.0.0.1:5432", *res); len(found) != 1 {
		t.Fatalf("GASH-055 bekleniyordu: %+v", found)
	}
}

func TestCheckDBUnauthPostgresMD5(t *testing.T) {
	startDBProbeMockOnPort(t, 5432, func(c net.Conn) {
		readPostgresTestStartup(t, c)
		// R: length 12, auth type 5 (md5) + 4 bayt salt.
		_, _ = c.Write([]byte{'R', 0, 0, 0, 12, 0, 0, 0, 5, 1, 2, 3, 4})
	})
	res, err := CheckDBUnauth(context.Background(), "127.0.0.1", 5432, Options{Allow: allowAll, Timeout: 2 * time.Second})
	if err != nil {
		t.Fatalf("pg md5: %v", err)
	}
	if res.Unauth || !res.AuthRequired || res.AuthMethod != "md5-password" {
		t.Fatalf("pg md5 sonucu: %+v", res)
	}
	if found := DBUnauthFindings("postgres://127.0.0.1:5432", *res); len(found) != 0 {
		t.Fatalf("auth gerekliyse bulgu yok: %+v", found)
	}
}

// mysqlTestGreeting capability'lerinde CLIENT_PLUGIN_AUTH set olan selamlama üretir.
func mysqlTestGreeting() []byte {
	p := []byte{0x0a}
	p = append(p, []byte("8.0.35\x00")...)
	p = append(p, 1, 0, 0, 0)                    // connection id
	p = append(p, make([]byte, 8)...)            // auth-plugin-data-1
	p = append(p, 0x00)                          // filler
	p = append(p, 0x82, 0x8a)                    // capability lower
	p = append(p, 0x21)                          // charset
	p = append(p, 0x02, 0x00)                    // status
	p = append(p, 0x08, 0x00)                    // capability upper (CLIENT_PLUGIN_AUTH)
	p = append(p, 21)                            // auth-plugin-data len
	p = append(p, make([]byte, 10)...)           // reserved
	p = append(p, []byte("123456789012\x00")...) // auth-plugin-data-2 (13)
	p = append(p, []byte("mysql_native_password\x00")...)
	return p
}

func TestCheckDBUnauthMySQLMetadataOnly(t *testing.T) {
	startDBProbeMockOnPort(t, 3306, func(c net.Conn) {
		p := mysqlTestGreeting()
		hdr := []byte{byte(len(p)), byte(len(p) >> 8), byte(len(p) >> 16), 0}
		_, _ = c.Write(append(hdr, p...))
	})
	res, err := CheckDBUnauth(context.Background(), "127.0.0.1", 3306, Options{Allow: allowAll, Timeout: 2 * time.Second})
	if err != nil {
		t.Fatalf("mysql metadata: %v", err)
	}
	if res.Unauth || res.AuthRequired || res.Version != "8.0.35" || res.AuthMethod != "mysql_native_password" {
		t.Fatalf("mysql metadata sonucu: %+v", res)
	}
	if !strings.Contains(res.Note, "giriş DENENMEDİ") {
		t.Fatalf("not: %q", res.Note)
	}
	if found := DBUnauthFindings("mysql://127.0.0.1:3306", *res); len(found) != 0 {
		t.Fatalf("metadata-only bulgu üretmemeli: %+v", found)
	}
}

func TestCheckDBUnauthUnsupportedPortNoDial(t *testing.T) {
	res, err := CheckDBUnauth(context.Background(), "127.0.0.1", 27099, Options{Allow: allowAll, Timeout: time.Second})
	if err != nil {
		t.Fatalf("desteklenmeyen port hata değil not dönmeli: %v", err)
	}
	if res.Service != dbServiceUnknown || !strings.Contains(res.Note, "desteklenmiyor") {
		t.Fatalf("desteklenmeyen port sonucu: %+v", res)
	}
	if found := DBUnauthFindings("tcp://127.0.0.1:27099", *res); len(found) != 0 {
		t.Fatalf("kanıtsız sonuç bulgu üretmemeli: %+v", found)
	}
	// Geçersiz port ve boş host reddedilir.
	if _, err := CheckDBUnauth(context.Background(), "127.0.0.1", 0, Options{Allow: allowAll}); err == nil {
		t.Fatal("geçersiz port reddedilmeli")
	}
	if _, err := CheckDBUnauth(context.Background(), "  ", 6379, Options{Allow: allowAll}); err == nil {
		t.Fatal("boş host reddedilmeli")
	}
}

func TestCheckDBUnauthAllowNilNoDial(t *testing.T) {
	accepts := startDBProbeMockOnPort(t, 6379, redisMockHandler)
	if _, err := CheckDBUnauth(context.Background(), "127.0.0.1", 6379, Options{}); err == nil {
		t.Fatal("Allow nil iken denetim kapalı kalmalı (fail-closed)")
	}
	deny := Options{Allow: func(string) bool { return false }}
	if _, err := CheckDBUnauth(context.Background(), "127.0.0.1", 6379, deny); err == nil {
		t.Fatal("kapsam-dışı denetim reddedilmeli")
	}
	if atomic.LoadInt32(accepts) != 0 {
		t.Fatalf("kapsam reddinde soket açılmamalı (kabul=%d)", atomic.LoadInt32(accepts))
	}
}

func TestDBUnauthFindingsEmptyTargetFallback(t *testing.T) {
	found := DBUnauthFindings("", DBUnauthResult{Host: "127.0.0.1", Port: 6379, Service: "redis", Unauth: true})
	if len(found) != 1 || found[0].Target != "127.0.0.1:6379" {
		t.Fatalf("hedef geri düşüşü: %+v", found)
	}
	if len(DBUnauthFindings("t")) != 0 {
		t.Fatal("sonuç yoksa bulgu yok")
	}
}

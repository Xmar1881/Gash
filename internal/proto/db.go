// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Modül: github.com/Xmar1881/Gash

package proto

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"math"
	"net"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/Xmar1881/Gash/internal/plugin"
)

// DB gözlem sınırları (Faz 0: salt-okuma, auth/komut YOK).
const (
	dbMaxPorts       = 64  // dış savunma tavanı (motor ayrıca MaxInfraPorts uygular)
	dbBannerMax      = 256 // okunan selamlama bayt tavanı
	dbEvidenceMax    = 300 // kanıta taşınan selamlama karakter tavanı
	dbGreetingWait   = 500 * time.Millisecond
	dbServiceUnknown = "unknown"
)

// dbPortServices yaygın veritabanı port eşlemesidir (yalnızca ipucu;
// selamlama heuristiği port tahminini geçersiz kılabilir).
var dbPortServices = map[int]string{
	1433:  "mssql",
	1521:  "oracle",
	3306:  "mysql",
	5432:  "postgres",
	6379:  "redis",
	9200:  "elasticsearch",
	27017: "mongodb",
	11211: "memcached",
	5984:  "couchdb",
	9042:  "cassandra",
}

// DefaultDBPorts yaygın veritabanı portlarının sıralı kopyasıdır.
func DefaultDBPorts() []int {
	out := make([]int, 0, len(dbPortServices))
	for p := range dbPortServices {
		out = append(out, p)
	}
	sort.Ints(out)
	return out
}

// DBPortResult tek port gözlemidir. Open=false girdileri de döner (kanıt izi);
// bulgu yalnızca açık portlardan üretilir.
type DBPortResult struct {
	Host       string
	Port       int
	Open       bool
	Service    string
	Banner     string
	DurationMs int64
}

// ScanDBPorts portları sırayla yoklar; salt-okuma selamlama okur.
// What: Dial + kısa bounded okuma; veri GÖNDERMEZ, auth/komut/veri işlemi YOK.
// Bağlantı hemen kapatılır. Geçersiz portlar sessizce atılır, liste
// yinelenmez ve en fazla 64 port denenir.
// Why: Açık DB portu/yüzeyi envanterdir; hedefte hiçbir durum değiştirilmez
// ama bağlantı kurulumu aktif bir probdur (motor --active kapısına tabidir).
func ScanDBPorts(ctx context.Context, host string, ports []int, o Options) ([]DBPortResult, error) {
	h := strings.ToLower(strings.TrimSpace(host))
	if h == "" {
		return nil, fmt.Errorf("proto db: boş host")
	}
	if err := o.checkAllowed(h); err != nil {
		return nil, err
	}
	clean := normalizeDBPorts(ports)
	if len(clean) == 0 {
		return nil, nil
	}
	var out []DBPortResult
	for _, port := range clean {
		if ctx.Err() != nil {
			break // iptal: kalan portlar sessizce atlanır (hata yayılmaz)
		}
		out = append(out, scanOneDBPort(ctx, h, port, o))
	}
	return out, nil
}

// normalizeDBPorts geçersiz portları ayıklar, yinelenenleri teker ve listeyi
// dbMaxPorts ile sınırlar (1..65535, ilk görülme sırası korunur).
func normalizeDBPorts(ports []int) []int {
	seen := make(map[int]bool, len(ports))
	var out []int
	for _, p := range ports {
		if p < 1 || p > 65535 || seen[p] {
			continue
		}
		seen[p] = true
		out = append(out, p)
		if len(out) >= dbMaxPorts {
			break
		}
	}
	return out
}

// scanOneDBPort tek portu yoklar (dial + bounded selamlama okuması).
func scanOneDBPort(ctx context.Context, host string, port int, o Options) DBPortResult {
	start := time.Now()
	res := DBPortResult{Host: host, Port: port}
	cctx, cancel := context.WithTimeout(ctx, o.timeout())
	defer cancel()
	dialer := &net.Dialer{Timeout: o.timeout()}
	conn, err := dialer.DialContext(cctx, "tcp", net.JoinHostPort(host, strconv.Itoa(port)))
	if err != nil {
		res.DurationMs = time.Since(start).Milliseconds()
		return res
	}
	defer func() { _ = conn.Close() }()
	res.Open = true
	// Salt-okuma: kısa selamlama penceresi; veri gönderilmez, komut/auth YOK.
	wait := dbGreetingWait
	if t := o.timeout(); t < wait {
		wait = t
	}
	_ = conn.SetReadDeadline(time.Now().Add(wait))
	buf, _ := io.ReadAll(io.LimitReader(conn, dbBannerMax))
	raw := string(buf)
	res.Service = identifyDBService(raw, port)
	res.Banner = sanitizeProtoBanner(raw, dbEvidenceMax)
	res.DurationMs = time.Since(start).Milliseconds()
	return res
}

// identifyDBService ham selamlamadan servis adı çıkarır; eşleşme yoksa port
// eşlemesine, o da yoksa "unknown" değerine düşer (saf fonksiyon).
func identifyDBService(raw string, port int) string {
	lower := strings.ToLower(raw)
	switch {
	case strings.Contains(lower, "postgres"),
		strings.HasPrefix(raw, "E") && strings.Contains(lower, "fatal"):
		return "postgres"
	case strings.Contains(lower, "mysql"), mysqlHandshake(raw):
		return "mysql"
	case strings.Contains(lower, "mongo"):
		return "mongodb"
	case strings.Contains(lower, "memcached"):
		return "memcached"
	case strings.Contains(lower, "couchdb"):
		return "couchdb"
	case strings.Contains(lower, "cassandra"), strings.Contains(lower, "cql"):
		return "cassandra"
	}
	if svc, ok := dbPortServices[port]; ok {
		return svc
	}
	return dbServiceUnknown
}

// mysqlHandshake MySQL ilk paketini tanır: protokol baytı 0x0a + sürüm rakamı.
func mysqlHandshake(raw string) bool {
	if len(raw) < 2 || raw[0] != 0x0a {
		return false
	}
	return raw[1] >= '0' && raw[1] <= '9'
}

// DBPortFindings açık portlardan bulgu üretir (GASH-053, CWE-200).
// What: Her açık port için tek medium/firm bulgu; kapalı portlar bulgusuz.
// Selamlama kanıta kırpılmış/arındırılmış taşınır.
// Why: Açık port deterministik bir gözlemdir ama servis kimliği heuristik
// olduğundan tavan firm'dir (kimlik denemesi/auth YOK — kanıtlanmadı).
func DBPortFindings(results []DBPortResult) []Finding {
	var out []Finding
	for _, r := range results {
		if !r.Open {
			continue
		}
		port := strconv.Itoa(r.Port)
		out = append(out, Finding{
			RuleID: "GASH-053", CWE: "CWE-200",
			Title: "Açık veritabanı portu (" + r.Service + "/" + port + ")",
			Desc: "Hedefte " + r.Service + " servisi " + port + " numaralı port üzerinden erişilebilir; " +
				"yetkisiz erişim yüzeyi oluşur (yalnızca port/selamlama gözlemi, kimlik denemesi yapılmadı).",
			Severity: plugin.SeverityMedium, Confidence: plugin.ConfidenceFirm,
			Target: net.JoinHostPort(r.Host, port), PluginID: "proto-db-ports", OracleName: "db",
			Evidence: map[string]string{
				"host":    r.Host,
				"port":    port,
				"service": r.Service,
				"banner":  sanitizeProtoBanner(r.Banner, dbEvidenceMax),
				"signal":  "db-port-open",
			},
			Note: "salt-okuma port/selamlama gözlemi; auth/komut/veri işlemi yok, tavan firm",
			Tags: []string{"db", "exposure", "misconfig"},
		})
	}
	return out
}

// --- Faz 1: DB kimlik doğrulamasız erişim denetimi (GASH-055) ---
//
// Güvenlik sözleşmesi (pazarlıksız): servis başına TEK zararsız istek; sabit
// dummy kimlikler ("gash_probe"), parola DENEMESİ yok, veri okuma/komut yok.
// Kanıt yalnızca sunucunun kimlik istemeden yanıt vermesiyle üretilir.

// DB unauth denetim sınırları.
const (
	dbUnauthReadMax = 4096 // tek yanıt okuma bayt tavanı
	dbUnauthMsgMax  = 8    // PostgreSQL akışında azami mesaj sayısı
	dbDummyUser     = "gash_probe"
	dbDummyDatabase = "gash_probe"
)

// dbUnauthServices desteklenen unauth denetim portlarıdır (yalnızca bunlar dial edilir).
var dbUnauthServices = map[int]string{
	3306:  "mysql",
	5432:  "postgres",
	6379:  "redis",
	27017: "mongodb",
	11211: "memcached",
}

// DBUnauthResult tek servis unauth gözlemidir.
type DBUnauthResult struct {
	Host    string
	Port    int
	Service string
	Version string
	// MaxWireVersion MongoDB hello yanıtından çıkarılır (0 = bilinmiyor).
	MaxWireVersion int
	AuthRequired   bool
	Unauth         bool
	AuthMethod     string
	Note           string
	Banner         string
	DurationMs     int64
}

// CheckDBUnauth desteklenen veritabanlarında kimlik doğrulamasız erişimi gözler.
// What: Sabit dummy kimliklerle servis başına TEK zararsız istek:
//   - Redis (6379): PING; yalnızca +PONG kanıt sayılır. PONG gelirse tek
//     INFO server okumasıyla sürüm çıkarılır (salt-okuma, hemen kapatılır).
//   - Memcached (11211): version komutu (memcached auth sunmaz).
//   - MongoDB (27017): admin.$cmd üzerinde legacy OP_QUERY
//     {"hello":1,"helloOk":true}; ok:1 → unauth, code 13/unauthorized → auth.
//   - PostgreSQL (5432): StartupMessage (user/database=gash_probe); yalnızca
//     AuthenticationRequest gözlenir, PAROLA ASLA GÖNDERİLMEZ.
//   - MySQL (3306): sunucu selamlaması ayrıştırılır; giriş DENENMEZ (metadata).
//
// Desteklenmeyen port: dial YOK; Note ile döner, bulgu üretmez.
// Why: Unauth erişim yüksek etkili yanlış yapılandırmadır; kanıt veri okumadan,
// tek istek ve dummy kimlikle sınırlı tutulur (yıkıcı işlem yok).
func CheckDBUnauth(ctx context.Context, host string, port int, o Options) (*DBUnauthResult, error) {
	h := strings.ToLower(strings.TrimSpace(host))
	if h == "" {
		return nil, fmt.Errorf("proto db: boş host")
	}
	if port < 1 || port > 65535 {
		return nil, fmt.Errorf("proto db: geçersiz port %d", port)
	}
	if err := o.checkAllowed(h); err != nil {
		return nil, err
	}
	svc, supported := dbUnauthServices[port]
	if !supported {
		svc = identifyDBService("", port)
		return &DBUnauthResult{
			Host: h, Port: port, Service: svc,
			Note: "unauth denetimi bu servis için desteklenmiyor (yalnızca port/selamlama gözlemi; ek dial yok)",
		}, nil
	}
	start := time.Now()
	cctx, cancel := context.WithTimeout(ctx, o.timeout())
	defer cancel()
	dialer := &net.Dialer{Timeout: o.timeout()}
	conn, err := dialer.DialContext(cctx, "tcp", net.JoinHostPort(h, strconv.Itoa(port)))
	if err != nil {
		return nil, fmt.Errorf("proto db unauth %s:%d: %w", h, port, err)
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(o.timeout()))

	res := &DBUnauthResult{Host: h, Port: port, Service: svc}
	var perr error
	switch svc {
	case "redis":
		perr = probeRedisUnauth(conn, res)
	case "memcached":
		perr = probeMemcachedUnauth(conn, res)
	case "mongodb":
		perr = probeMongoUnauth(conn, res)
	case "postgres":
		perr = probePostgresUnauth(conn, res)
	case "mysql":
		perr = probeMySQLMetadata(conn, res)
	}
	res.DurationMs = time.Since(start).Milliseconds()
	if perr != nil && res.Note == "" {
		res.Note = "probe tamamlanamadı: " + perr.Error()
	}
	return res, nil
}

// readDBLineBounded bufio okuyucudan en fazla max baytlık satır okur.
func readDBLineBounded(br *bufio.Reader, max int) (string, error) {
	var sb strings.Builder
	for i := 0; i < max; i++ {
		b, err := br.ReadByte()
		if err != nil {
			if sb.Len() > 0 {
				return sb.String(), nil
			}
			return "", err
		}
		if b == '\n' {
			return sb.String(), nil
		}
		sb.WriteByte(b)
	}
	return sb.String(), nil
}

// readDBAllBounded kalan baytları tavan/deadline ile okur (tek pencere).
func readDBAllBounded(br *bufio.Reader, max int) string {
	var sb strings.Builder
	for sb.Len() < max {
		b, err := br.ReadByte()
		if err != nil {
			break
		}
		sb.WriteByte(b)
	}
	return sb.String()
}

// extractRedisVersion INFO server gövdesinden redis_version alanını çeker.
func extractRedisVersion(body string) string {
	for _, line := range strings.Split(body, "\n") {
		line = strings.TrimSpace(line)
		if len(line) >= len("redis_version:") && strings.EqualFold(line[:len("redis_version:")], "redis_version:") {
			return strings.TrimSpace(line[len("redis_version:"):])
		}
	}
	return ""
}

// probeRedisUnauth Redis'e tek PING gönderir (yazma/anahtar komutu YOK).
func probeRedisUnauth(conn net.Conn, res *DBUnauthResult) error {
	if _, err := conn.Write([]byte("PING\r\n")); err != nil {
		return err
	}
	br := bufio.NewReaderSize(conn, dbUnauthReadMax)
	line, err := readDBLineBounded(br, dbBannerMax)
	if err != nil {
		return err
	}
	res.Banner = sanitizeProtoBanner(line, dbEvidenceMax)
	upper := strings.ToUpper(strings.TrimSpace(line))
	switch {
	case strings.HasPrefix(upper, "+PONG"):
		// protected-mode PING'i engellemez; yalnızca PONG kanıt sayılır.
		res.Unauth = true
		res.Note = "PING yanıtlandı (protected-mode bu komutu engellemez); yalnızca PING kanıtı"
		// İsteğe bağlı tek INFO server okuması: sürüm çıkarımı, salt-okuma.
		_ = conn.SetReadDeadline(time.Now().Add(dbGreetingWait))
		if _, werr := conn.Write([]byte("INFO server\r\n")); werr == nil {
			body := readDBAllBounded(br, dbUnauthReadMax)
			if v := extractRedisVersion(body); v != "" {
				res.Version = v
			}
			if strings.TrimSpace(body) != "" {
				res.Banner = sanitizeProtoBanner(strings.TrimSpace(body), dbEvidenceMax)
			}
		}
	case strings.Contains(upper, "NOAUTH") || strings.Contains(upper, "WRONGPASS"):
		res.AuthRequired = true
		res.AuthMethod = "requirepass"
		res.Note = "AUTH gerekli (NOAUTH yanıtı); parola denenmedi"
	default:
		res.Note = "beklenmeyen PING yanıtı (kanıt yok)"
	}
	return nil
}

// probeMemcachedUnauth tek version komutu gönderir (memcached auth sunmaz).
func probeMemcachedUnauth(conn net.Conn, res *DBUnauthResult) error {
	if _, err := conn.Write([]byte("version\r\n")); err != nil {
		return err
	}
	br := bufio.NewReaderSize(conn, dbUnauthReadMax)
	line, err := readDBLineBounded(br, dbBannerMax)
	if err != nil {
		return err
	}
	res.Banner = sanitizeProtoBanner(line, dbEvidenceMax)
	fields := strings.Fields(strings.TrimSpace(line))
	if len(fields) >= 2 && strings.EqualFold(fields[0], "VERSION") {
		res.Unauth = true
		res.Version = sanitizeProtoBanner(fields[1], 64)
		res.Note = "version komutu yanıtlandı; memcached kimlik doğrulaması sunmaz (tek istek)"
		return nil
	}
	res.Note = "beklenmeyen version yanıtı (kanıt yok)"
	return nil
}

// buildMongoHelloQuery legacy OP_QUERY zarfında BSON {"hello":1,"helloOk":true} üretir.
// What: admin.$cmd koleksiyonu, numberToReturn=-1 (tek yanıt), zararsız hello komutu.
// Why: hello/isMaster el sıkışma komutudur; veri okumaz, durum değiştirmez.
func buildMongoHelloQuery() []byte {
	doc := make([]byte, 4)
	doc = append(doc, 0x10)
	doc = append(doc, []byte("hello\x00")...)
	var v [4]byte
	binary.LittleEndian.PutUint32(v[:], 1)
	doc = append(doc, v[:]...)
	doc = append(doc, 0x08)
	doc = append(doc, []byte("helloOk\x00")...)
	doc = append(doc, 1)
	doc = append(doc, 0)
	binary.LittleEndian.PutUint32(doc[:4], uint32(len(doc)))

	body := make([]byte, 4) // flags = 0
	body = append(body, []byte("admin.$cmd\x00")...)
	binary.LittleEndian.PutUint32(v[:], 0)
	body = append(body, v[:]...) // numberToSkip = 0
	binary.LittleEndian.PutUint32(v[:], 0xFFFFFFFF)
	body = append(body, v[:]...) // numberToReturn = -1
	body = append(body, doc...)

	msg := make([]byte, 16+len(body))
	binary.LittleEndian.PutUint32(msg[0:], uint32(len(msg))) // messageLength
	binary.LittleEndian.PutUint32(msg[4:], 1)                // requestID
	binary.LittleEndian.PutUint32(msg[8:], 0)                // responseTo
	binary.LittleEndian.PutUint32(msg[12:], 2004)            // OP_QUERY
	copy(msg[16:], body)
	return msg
}

// mongoReplyDocument yanıt zarfından ilk BSON belgesini çıkarır (OP_REPLY/OP_MSG).
func mongoReplyDocument(msg []byte) ([]byte, error) {
	if len(msg) < 16 {
		return nil, fmt.Errorf("mongo: yanıt kısa")
	}
	op := binary.LittleEndian.Uint32(msg[12:16])
	switch op {
	case 1: // OP_REPLY
		if len(msg) < 36 {
			return nil, fmt.Errorf("mongo: OP_REPLY kısa")
		}
		return msg[36:], nil
	case 2013: // OP_MSG (kind 0 tek belge)
		if len(msg) < 21 {
			return nil, fmt.Errorf("mongo: OP_MSG kısa")
		}
		if msg[20] != 0 {
			return nil, fmt.Errorf("mongo: OP_MSG bölüm 0 bekleniyordu")
		}
		return msg[21:], nil
	default:
		return nil, fmt.Errorf("mongo: beklenmeyen opcode %d", op)
	}
}

// parseBSONDocument minimal BSON çözümleyicidir (yalnızca gerekli tipler).
// What: ok/errmsg/code/codeName/maxWireVersion/version alanları için yeterli
// tip desteği; bilinmeyen tipte eldeki alanlarla döner (fail-open değil, kısmi).
// Why: Harici bağımlılık yok; yanıt sunucu kontrolündedir, bozuk veri Fp üretmez.
func parseBSONDocument(b []byte) (map[string]any, error) {
	if len(b) < 5 {
		return nil, fmt.Errorf("bson: belge kısa")
	}
	docLen := int(int32(binary.LittleEndian.Uint32(b[:4])))
	if docLen < 5 || docLen > len(b) {
		return nil, fmt.Errorf("bson: uzunluk %d geçersiz", docLen)
	}
	out := make(map[string]any)
	off := 4
	skipCString := func() (string, bool) {
		end := bytes.IndexByte(b[off:docLen], 0)
		if end < 0 {
			return "", false
		}
		s := string(b[off : off+end])
		off += end + 1
		return s, true
	}
	for off < docLen-1 {
		typ := b[off]
		off++
		name, ok := skipCString()
		if !ok {
			return out, fmt.Errorf("bson: alan adı bozuk")
		}
		var val any
		switch typ {
		case 0x01: // double
			if off+8 > docLen {
				return out, fmt.Errorf("bson: double kısa")
			}
			val = math.Float64frombits(binary.LittleEndian.Uint64(b[off:]))
			off += 8
		case 0x02: // string
			if off+5 > docLen {
				return out, fmt.Errorf("bson: string kısa")
			}
			sl := int(int32(binary.LittleEndian.Uint32(b[off:])))
			off += 4
			if sl < 1 || off+sl > docLen {
				return out, fmt.Errorf("bson: string uzunluk %d geçersiz", sl)
			}
			val = string(b[off : off+sl-1])
			off += sl
		case 0x03, 0x04: // embedded document / array
			if off+4 > docLen {
				return out, fmt.Errorf("bson: gömülü belge kısa")
			}
			sl := int(int32(binary.LittleEndian.Uint32(b[off:])))
			if sl < 5 || off+sl > docLen {
				return out, fmt.Errorf("bson: gömülü belge uzunluk %d geçersiz", sl)
			}
			off += sl
		case 0x05: // binary
			if off+5 > docLen {
				return out, fmt.Errorf("bson: binary kısa")
			}
			bl := int(int32(binary.LittleEndian.Uint32(b[off:])))
			off += 5 // uzunluk + alt tip
			if bl < 0 || off+bl > docLen {
				return out, fmt.Errorf("bson: binary uzunluk %d geçersiz", bl)
			}
			off += bl
		case 0x07: // objectid
			if off+12 > docLen {
				return out, fmt.Errorf("bson: objectid kısa")
			}
			off += 12
		case 0x08: // bool
			if off+1 > docLen {
				return out, fmt.Errorf("bson: bool kısa")
			}
			val = b[off] != 0
			off++
		case 0x09, 0x11, 0x12: // datetime / timestamp / int64
			if off+8 > docLen {
				return out, fmt.Errorf("bson: 64-bit alan kısa")
			}
			val = int64(binary.LittleEndian.Uint64(b[off:]))
			off += 8
		case 0x0A: // null
			val = nil
		case 0x10: // int32
			if off+4 > docLen {
				return out, fmt.Errorf("bson: int32 kısa")
			}
			val = int64(int32(binary.LittleEndian.Uint32(b[off:])))
			off += 4
		case 0x0B: // regex (iki cstring)
			if _, ok := skipCString(); !ok {
				return out, fmt.Errorf("bson: regex bozuk")
			}
			if _, ok := skipCString(); !ok {
				return out, fmt.Errorf("bson: regex seçenekleri bozuk")
			}
		case 0x0D, 0x0E: // javascript / symbol (string gibi)
			if off+5 > docLen {
				return out, fmt.Errorf("bson: kod alanı kısa")
			}
			sl := int(int32(binary.LittleEndian.Uint32(b[off:])))
			off += 4
			if sl < 1 || off+sl > docLen {
				return out, fmt.Errorf("bson: kod uzunluk %d geçersiz", sl)
			}
			off += sl
		case 0x0F: // code with scope
			if off+4 > docLen {
				return out, fmt.Errorf("bson: kod kapsamı kısa")
			}
			sl := int(int32(binary.LittleEndian.Uint32(b[off:])))
			if sl < 4 || off+sl > docLen {
				return out, fmt.Errorf("bson: kod kapsamı uzunluk %d geçersiz", sl)
			}
			off += sl
		default:
			return out, fmt.Errorf("bson: bilinmeyen tip 0x%02x", typ)
		}
		if name != "" {
			out[name] = val
		}
	}
	return out, nil
}

// mongoInt BSON sayısal değerini int64'e çevirir (int32/int64/double).
func mongoInt(v any) int64 {
	switch n := v.(type) {
	case int64:
		return n
	case float64:
		return int64(n)
	}
	return 0
}

// mongoFloat BSON ok alanını float64'e çevirir.
func mongoFloat(v any) (float64, bool) {
	switch n := v.(type) {
	case float64:
		return n, true
	case int64:
		return float64(n), true
	case bool:
		if n {
			return 1, true
		}
		return 0, true
	}
	return 0, false
}

// probeMongoUnauth tek hello komutu gönderir ve kimlik istemini sınıflar.
func probeMongoUnauth(conn net.Conn, res *DBUnauthResult) error {
	if _, err := conn.Write(buildMongoHelloQuery()); err != nil {
		return err
	}
	var hdr [16]byte
	if _, err := io.ReadFull(conn, hdr[:]); err != nil {
		return err
	}
	mlen := int(binary.LittleEndian.Uint32(hdr[:4]))
	if mlen < 16 || mlen > dbUnauthReadMax {
		return fmt.Errorf("mongo: messageLength %d geçersiz", mlen)
	}
	body := make([]byte, mlen-16)
	if _, err := io.ReadFull(conn, body); err != nil {
		return err
	}
	docBytes, err := mongoReplyDocument(append(hdr[:], body...))
	if err != nil {
		return err
	}
	doc, derr := parseBSONDocument(docBytes)
	if derr != nil && len(doc) == 0 {
		return derr
	}
	errmsg, _ := doc["errmsg"].(string)
	code := mongoInt(doc["code"])
	if code == 13 || strings.Contains(strings.ToLower(errmsg), "unauthorized") ||
		strings.Contains(strings.ToLower(errmsg), "authentication") {
		res.AuthRequired = true
		res.AuthMethod = "SCRAM (code 13)"
		res.Note = "sunucu yetkilendirme istedi (hello reddedildi); kimlik denenmedi"
		res.Banner = sanitizeProtoBanner("code=13 errmsg="+errmsg, dbEvidenceMax)
		return nil
	}
	if v, ok := mongoFloat(doc["ok"]); ok && v == 1 {
		res.Unauth = true
		res.Note = "hello komutu kimlik istemeden yanıtlandı (ok:1); gerçek yetki sınırı ayrıca doğrulanmalı"
		if s, ok := doc["version"].(string); ok {
			res.Version = sanitizeProtoBanner(s, 64)
		}
		res.MaxWireVersion = int(mongoInt(doc["maxWireVersion"]))
		res.Banner = sanitizeProtoBanner(fmt.Sprintf("ok=1 maxWireVersion=%d", res.MaxWireVersion), dbEvidenceMax)
		return nil
	}
	if derr != nil {
		return derr
	}
	res.Note = "hello yanıtı belirsiz (ok≠1); kanıt yok"
	return nil
}

// postgresAuthMethod kimlik istek kodunu okunabilir yönteme çevirir.
func postgresAuthMethod(t uint32) string {
	switch t {
	case 0:
		return "trust"
	case 2:
		return "kerberos-v5"
	case 3:
		return "cleartext-password"
	case 5:
		return "md5-password"
	case 6:
		return "scm-credential"
	case 7:
		return "gss"
	case 9:
		return "sspi"
	case 10:
		return "sasl-scram"
	case 11:
		return "gss-continue"
	case 12:
		return "sspi-continue"
	default:
		return fmt.Sprintf("type-%d", t)
	}
}

// postgresParameterStatus ParameterStatus gövdesinden anahtarı çeker (key\0value\0).
func postgresParameterStatus(body []byte, key string) string {
	parts := bytes.Split(body, []byte{0})
	for i := 0; i+1 < len(parts); i += 2 {
		if string(parts[i]) == key {
			return string(parts[i+1])
		}
	}
	return ""
}

// postgresErrorFields ErrorResponse gövdesinden ana mesajı ('M') çeker.
func postgresErrorFields(body []byte) string {
	off := 0
	for off < len(body) {
		typ := body[off]
		off++
		end := bytes.IndexByte(body[off:], 0)
		if end < 0 {
			break
		}
		val := string(body[off : off+end])
		off += end + 1
		if typ == 'M' {
			return val
		}
	}
	return ""
}

// probePostgresUnauth tek StartupMessage gönderir; yalnızca auth isteği gözlenir.
// What: protocol 3.0 + user/database=gash_probe; R(tip 0) → trust, R(3/5/10/...)
// → auth gerekli; 'S' server_version; 'E' hata notu. PAROLA ASLA GÖNDERİLMEZ.
// Why: Parola göndermeden kimlik isteminin varlığı/yokluğu kanıtlanabilir.
func probePostgresUnauth(conn net.Conn, res *DBUnauthResult) error {
	params := "user\x00" + dbDummyUser + "\x00database\x00" + dbDummyDatabase + "\x00\x00"
	msg := make([]byte, 8+len(params))
	binary.BigEndian.PutUint32(msg[0:], uint32(len(msg)))
	binary.BigEndian.PutUint32(msg[4:], 196608) // protocol 3.0
	copy(msg[8:], params)
	if _, err := conn.Write(msg); err != nil {
		return err
	}
	for i := 0; i < dbUnauthMsgMax; i++ {
		var hdr [5]byte
		if _, err := io.ReadFull(conn, hdr[:]); err != nil {
			if res.Unauth || res.AuthRequired {
				return nil // kanıt toplandı; kalan mesajlar şart değil
			}
			return err
		}
		mlen := int(binary.BigEndian.Uint32(hdr[1:])) - 4
		if mlen < 0 || mlen > dbUnauthReadMax {
			return fmt.Errorf("pg: mesaj boyu %d geçersiz", mlen)
		}
		body := make([]byte, mlen)
		if _, err := io.ReadFull(conn, body); err != nil {
			return err
		}
		switch hdr[0] {
		case 'R':
			if len(body) < 4 {
				return fmt.Errorf("pg: kısa auth isteği")
			}
			at := binary.BigEndian.Uint32(body[:4])
			res.AuthMethod = postgresAuthMethod(at)
			res.Banner = sanitizeProtoBanner("R/"+res.AuthMethod, dbEvidenceMax)
			if at == 0 {
				res.Unauth = true
				res.Note = "trust kimlik doğrulaması: parola istenmeden oturum açıldı (tek startup isteği)"
			} else {
				res.AuthRequired = true
				res.Note = "sunucu kimlik doğrulaması istedi (" + res.AuthMethod + "); parola gönderilmedi"
				return nil
			}
		case 'S':
			if v := postgresParameterStatus(body, "server_version"); v != "" && res.Version == "" {
				res.Version = sanitizeProtoBanner(v, 64)
			}
		case 'E':
			detail := postgresErrorFields(body)
			if res.Note == "" {
				res.Note = "sunucu hata yanıtı: " + sanitizeProtoBanner(detail, 120)
			}
			if res.Banner == "" {
				res.Banner = sanitizeProtoBanner("E/"+detail, dbEvidenceMax)
			}
		case 'Z': // ReadyForQuery: trust akışı tamam
			return nil
		}
	}
	return nil
}

// probeMySQLMetadata yalnızca sunucu selamlamasını ayrıştırır.
// What: protocol sürümü, server version ve auth plugin adı (capability parse
// edilebilirse) çıkarılır; hiçbir veri GÖNDERİLMEZ, giriş DENENMEZ.
// Why: MySQL'de unauth iddiası ancak el sıkışma/auth akışıyla kanıtlanır;
// o tamamlanmadığı için bu denetim metadata-only kalır (Unauth=false).
func probeMySQLMetadata(conn net.Conn, res *DBUnauthResult) error {
	br := bufio.NewReaderSize(conn, dbUnauthReadMax)
	var head [4]byte
	if _, err := io.ReadFull(br, head[:]); err != nil {
		return err
	}
	plen := int(head[0]) | int(head[1])<<8 | int(head[2])<<16
	if plen < 1 || plen > dbUnauthReadMax {
		return fmt.Errorf("mysql: paket boyu %d geçersiz", plen)
	}
	payload := make([]byte, plen)
	if _, err := io.ReadFull(br, payload); err != nil {
		return err
	}
	res.Banner = sanitizeProtoBanner(string(payload), dbEvidenceMax)
	if len(payload) < 2 || payload[0] != 0x0a {
		res.Note = "MySQL selamlaması ayrıştırılamadı (kanıt yok)"
		return nil
	}
	off := 1
	end := bytes.IndexByte(payload[off:], 0)
	if end < 0 {
		res.Note = "MySQL sürüm alanı bozuk (kanıt yok)"
		return nil
	}
	res.Version = sanitizeProtoBanner(string(payload[off:off+end]), 64)
	off += end + 1
	// connection id (4) + auth-plugin-data-1 (8) + filler (1) + capability lower (2)
	if off+15 <= len(payload) {
		off += 4 + 8 + 1
		lower := binary.LittleEndian.Uint16(payload[off:])
		off += 2
		if off+11 <= len(payload) {
			off += 1 + 2 // charset + status
			upper := binary.LittleEndian.Uint16(payload[off:])
			off += 2
			authLen := int(payload[off])
			off += 1
			off += 10 // reserved
			caps := uint32(lower) | uint32(upper)<<16
			if caps&0x00080000 != 0 { // CLIENT_PLUGIN_AUTH
				part2 := 13
				if authLen-8 > part2 {
					part2 = authLen - 8
				}
				if off+part2 <= len(payload) {
					off += part2
				}
				if off < len(payload) {
					if e := bytes.IndexByte(payload[off:], 0); e > 0 {
						res.AuthMethod = sanitizeProtoBanner(string(payload[off:off+e]), 64)
					}
				}
			}
		}
	}
	res.Note = "yalnızca selamlama metadatası; giriş DENENMEDİ (unauth iddiası yok)"
	return nil
}

// DBUnauthFindings yalnızca kanıtlı Unauth sonuçlarından bulgu üretir (GASH-055).
// What: Unauth=true → tek high/firm bulgu (CWE-306); AuthRequired veya belirsiz
// sonuçlar bulgu ÜRETMEZ (sağlıklı/kanıtsız gürültü yok).
// Why: Tek zararsız istek + dummy kimlik kanıtı deterministiktir (firm); veri
// okunmadığı/yazılmadığı için tavan confirmed'a çıkarılmaz.
func DBUnauthFindings(target string, results ...DBUnauthResult) []Finding {
	var out []Finding
	for i := range results {
		r := results[i]
		if !r.Unauth {
			continue
		}
		port := strconv.Itoa(r.Port)
		tgt := target
		if strings.TrimSpace(tgt) == "" {
			tgt = net.JoinHostPort(r.Host, port)
		}
		ev := map[string]string{
			"host":        r.Host,
			"port":        port,
			"service":     r.Service,
			"version":     r.Version,
			"auth_method": r.AuthMethod,
			"signal":      "db-unauth-" + r.Service,
			"banner":      sanitizeProtoBanner(r.Banner, dbEvidenceMax),
			"note":        r.Note,
		}
		if r.MaxWireVersion > 0 {
			ev["max_wire_version"] = strconv.Itoa(r.MaxWireVersion)
		}
		out = append(out, Finding{
			RuleID: "GASH-055", CWE: "CWE-306",
			Title: "Kimlik doğrulamasız veritabanı erişimi (" + r.Service + "/" + port + ")",
			Desc: r.Service + " servisi " + port + " portunda kimlik doğrulaması istemeden yanıt verdi; " +
				"yetkisiz okuma/yazma yüzeyi (yalnızca tek zararsız istek ile gözlendi; veri okunmadı).",
			Severity: plugin.SeverityHigh, Confidence: plugin.ConfidenceFirm,
			Target: tgt, PluginID: "proto-db-unauth", OracleName: "db",
			Evidence: ev,
			Note:     "tek zararsız istek (dummy kimlik " + dbDummyUser + "); veri okuma/komut/parola denemesi yok, tavan firm",
			Tags:     []string{"db", "auth", "misconfig"},
		})
	}
	return out
}

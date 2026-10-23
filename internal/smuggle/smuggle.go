// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Modül: github.com/Xmar1881/Gash

// Package smuggle ham-TCP CL.TE / TE.CL / TE.TE diferansiyel probudur
// (engine-recon, GASH-033, CWE-444).
//
// What: Aynı keep-alive bağlantısı üzerinde muğlak istek (Content-Length +
// Transfer-Encoding: chunked bir arada) + ardından birebir aynı zararsız
// takip isteği gönderir; kontrol çiftindeki (düz CL + aynı takip) yanıtla
// statü/gövde farkını (differential) ve takip yanıtı gecikmesini (timing)
// karşılaştırır. net/http BYPASS edilir: istemci chunk çerçevelemeyi
// denetlemez, ham soket şarttır.
//
// Why: Ön-uç/arka-uç CL-vs-TE yorum farkı (request smuggling) yalnızca ham
// baytlarla gözlenir; tek-kanallı sinyal (yalnızca gecikme veya yalnızca
// statü farkı) bulgu üretmez — çift kanıt zorunludur.
//
// Güvenlik sınırları (bilerek YOK / kapalı):
//   - Hedef: kullanıcının verdiği host (Nuclei/Burp smuggler modeli); lab-only
//     loopback kilidi YOK. Yazılımsal hedef-engeli bırakıldı; operatör
//     sorumluluğu geçerlidir (yalnızca yetkili sistemlerde koşun).
//   - Kapsam: AllowHost preflight yalnızca --scope verilmişse uygulanır
//     (nil Allow = open mod, blok yok); kapsam-dışı → ErrScopeViolation,
//     soket AÇILMADAN (fail-closed).
//   - Kapı: --active + agresif profil dışında ÇALIŞMAZ (safe/standard/deep
//     dahil); skip + raporda sebep, bulgu YOK.
//   - Hacim: en fazla MaxProbes (10) istek, prob başına 5s tavan; gövdeler
//     ZARARSIZ işaretleyicidir ("0\r\n\r\n" chunk sonlandırıcı, "x=1&y");
//     cache-poisoning/DOS etkisi YOK (zehirli gömülü istek gönderilmez,
//     takip isteği düz GET'tir).
//   - Kanıt tavanı: timing+differential çift kanıt → en fazla firm; tek
//     başına confirmed YOK (yeni seviye YOK).
//   - HTTPS: SNI + hostname doğrulamalı TLS (InsecureSkipVerify YOK);
//     ALPN http/1.1 dayatılır, h2 negotiate olursa prob skip (HTTP/2'de
//     smuggling geçersiz).
package smuggle

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/Xmar1881/Gash/internal/baseline"
	"github.com/Xmar1881/Gash/internal/finding"
	"github.com/Xmar1881/Gash/internal/oracle"
	"github.com/Xmar1881/Gash/internal/plugin"
)

// Kural kimliği (çakışma yok: GASH-032 son kullanımda; 033 boş).
const (
	RuleID          = "GASH-033"
	CWE             = "CWE-444"
	OracleName      = "smuggling-differential"
	PluginID        = "engine-smuggle-recon"
	DetectorVersion = "1.0"
)

// Sınırlar: düşük hacim + timeout'lu + çift-kanıt eşiği.
const (
	// MaxProbes toplam istek tavanıdır (kontrol dahil; tasarım 8'de durur).
	MaxProbes = 10
	// defaultTimeout prob başına soket tavanıdır (dial+okuma/yazma).
	defaultTimeout = 5 * time.Second
	// secondReadTimeout takip yanıtı okuma tavanıdır (gecikme gözlem penceresi).
	secondReadTimeout = 3 * time.Second
	// timingDeltaThreshold takip gecikmesinin kontrolden anlamlı sapmasıdır.
	timingDeltaThreshold = 500 * time.Millisecond
	// followupDelay muğlak istek ile takip isteği arası zararsız beklemedir.
	followupDelay = 200 * time.Millisecond
	// maxBody karşılaştırılan gövde üst sınırıdır.
	maxBody = 32 * 1024
)

// Prob türleri (diferansiyel eksenler).
const (
	KindCLTE = "CL.TE"
	KindTECL = "TE.CL"
	KindTETE = "TE.TE"
)

// ProbeKinds deneme sırasındaki türlerdir.
func ProbeKinds() []string { return []string{KindCLTE, KindTECL, KindTETE} }

// AllowHost kapsam kararıdır (host → izinli mi). Nil = --scope verilmemiş
// (open mod, blok yok; operatör sorumluluğu).
type AllowHost func(host string) bool

// Options prob sınırlarıdır.
type Options struct {
	// Timeout prob başına tavan (0 ise 5s).
	Timeout time.Duration
	// Allow kapsam kararı; nil ise --scope yok → open mod (fail-closed DEĞİL).
	Allow AllowHost
	// Active --active bayrağıdır.
	Active bool
	// Aggressive agresif profil onayıdır (--aggressive → active+profil).
	Aggressive bool
	// Dialer ham TCP dialer'ıdır (test enjeksiyonu: sahte dialer/sayaç);
	// nil ise net.DialTimeout kullanılır.
	Dialer func(ctx context.Context, network, address string) (net.Conn, error)
}

func (o Options) timeout() time.Duration {
	if o.Timeout <= 0 {
		return defaultTimeout
	}
	return o.Timeout
}

// gate --active + agresif profil kapısıdır (dışı → skip, soket yok).
func (o Options) gate() (string, bool) {
	if !o.Active || !o.Aggressive {
		return "skipped (smuggle-probe requires --active --aggressive)", false
	}
	return "", true
}

// checkAllowed kapsamı doğrular (fail-closed yalnızca --scope verilmişse;
// soket öncesi).
// What: Allow == nil → open mod, hiçbir host bloklanmaz; Allow dolu →
// deny kararı ErrScopeViolation üretir, soket açılmaz.
// Why: Kapsam opt-in sıkı moddur (Nuclei/Burp smuggler modeli).
func (o Options) checkAllowed(host string) error {
	h := strings.ToLower(strings.TrimSpace(host))
	if h == "" {
		return fmt.Errorf("smuggle: boş host: %w", plugin.ErrScopeViolation)
	}
	if o.Allow == nil {
		return nil // open mod: --scope yok, blok yok
	}
	if !o.Allow(h) {
		return fmt.Errorf("smuggle: host %s kapsam-dışı: %w", h, plugin.ErrScopeViolation)
	}
	return nil
}

// errHTTP2 h2 negotiate sentinelidir (smuggling geçersiz → skip).
var errHTTP2 = errors.New("smuggle: http/2 negotiate — smuggling geçersiz, skip")

// dialTarget ayrıştırılmış hedeftir.
type dialTarget struct {
	host   string
	port   string
	scheme string
	path   string
	useTLS bool
}

// parseTarget hedefi doğrular (yalnızca http/https; query taşınmaz).
func parseTarget(raw string) (dialTarget, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || strings.TrimSpace(u.Host) == "" {
		return dialTarget{}, fmt.Errorf("smuggle: geçersiz hedef %q", raw)
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme != "http" && scheme != "https" {
		return dialTarget{}, fmt.Errorf("smuggle: scheme http/https olmalı (got %q)", u.Scheme)
	}
	host := u.Hostname()
	port := u.Port()
	if port == "" {
		if scheme == "https" {
			port = "443"
		} else {
			port = "80"
		}
	}
	path := u.EscapedPath()
	if path == "" {
		path = "/"
	}
	return dialTarget{host: host, port: port, scheme: scheme, path: path, useTLS: scheme == "https"}, nil
}

// hostHeader Host başlığıdır (varsayılan port yazılmaz).
func hostHeader(dt dialTarget) string {
	if (dt.scheme == "http" && dt.port == "80") || (dt.scheme == "https" && dt.port == "443") {
		return dt.host
	}
	return net.JoinHostPort(dt.host, dt.port)
}

// dial ham soket açar (net/http BYPASS). SNI+hostname doğrulamalı TLS;
// h2 negotiate → skip (kapatıp sentinel döner).
func (o Options) dial(ctx context.Context, dt dialTarget) (net.Conn, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	addr := net.JoinHostPort(dt.host, dt.port)
	var conn net.Conn
	var err error
	if o.Dialer != nil {
		conn, err = o.Dialer(ctx, "tcp", addr)
	} else {
		conn, err = net.DialTimeout("tcp", addr, o.timeout())
	}
	if err != nil {
		return nil, fmt.Errorf("smuggle dial %s: %w", addr, err)
	}
	if !dt.useTLS {
		return conn, nil
	}
	tlsConn := tls.Client(conn, &tls.Config{
		ServerName: dt.host, // SNI + hostname doğrulaması (skip YOK)
		MinVersion: tls.VersionTLS12,
		NextProtos: []string{"http/1.1"}, // smuggling yalnızca http/1.1'de anlamlı
	})
	_ = tlsConn.SetDeadline(time.Now().Add(o.timeout()))
	if err := tlsConn.Handshake(); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("smuggle tls handshake: %w", err)
	}
	if proto := tlsConn.ConnectionState().NegotiatedProtocol; proto != "" && proto != "http/1.1" {
		_ = tlsConn.Close()
		return nil, errHTTP2
	}
	return tlsConn, nil
}

// respSummary tek yanıt özetidir (ham gövde sınıflandırma için saklanır).
type respSummary struct {
	status  int
	headers http.Header
	body    []byte
	rtt     time.Duration
	timeout bool
}

// bodyString karşılaştırma gövdesidir.
func (r respSummary) bodyString() string { return string(r.body) }

// pairOutcome aynı bağlantıdaki istek+takip çiftidir.
type pairOutcome struct {
	kind      string
	first     respSummary
	second    respSummary
	untrusted bool // ilk yanıt blok sayfasıysa bu tür kanıt olamaz
}

// ScanResult prob sonucudur (bulgu + denetim izi).
type ScanResult struct {
	Requests int
	Skipped  string
	Evidence *oracle.Evidence
	Finding  *finding.Finding
	Detail   map[string]string
}

// controlFirst zararsız kontrol isteğidir (düz CL, chunk YOK).
func controlFirst(dt dialTarget) string {
	h := hostHeader(dt)
	var b strings.Builder
	b.WriteString("POST " + dt.path + " HTTP/1.1\r\n")
	b.WriteString("Host: " + h + "\r\n")
	b.WriteString("Content-Type: application/x-www-form-urlencoded\r\n")
	b.WriteString("Content-Length: 5\r\n")
	b.WriteString("Connection: keep-alive\r\n")
	b.WriteString("User-Agent: gash-smuggle-probe/1.0\r\n\r\n")
	b.WriteString("x=1&y")
	return b.String()
}

// followup birebir aynı zararsız takip isteğidir (kontrol+prob'da AYNI bayt).
func followup(dt dialTarget) string {
	h := hostHeader(dt)
	return "GET " + dt.path + " HTTP/1.1\r\nHost: " + h + "\r\nConnection: keep-alive\r\nUser-Agent: gash-smuggle-probe/1.0\r\n\r\n"
}

// ambiguousFirst muğlak istektir (CL + chunked bir arada, gövde ZARARSIZ
// sonlandırıcıdan ibaret; gömülü zehirli istek YOK).
func ambiguousFirst(dt dialTarget, kind string) string {
	h := hostHeader(dt)
	var b strings.Builder
	b.WriteString("POST " + dt.path + " HTTP/1.1\r\n")
	b.WriteString("Host: " + h + "\r\n")
	b.WriteString("Content-Type: application/x-www-form-urlencoded\r\n")
	switch kind {
	case KindCLTE:
		b.WriteString("Content-Length: 4\r\nTransfer-Encoding: chunked\r\n")
	case KindTECL:
		b.WriteString("Content-Length: 6\r\nTransfer-Encoding: chunked\r\n")
	case KindTETE:
		b.WriteString("Content-Length: 5\r\nTransfer-Encoding: chunked\r\nTransfer-Encoding: chunked\r\n")
	default:
		b.WriteString("Content-Length: 4\r\nTransfer-Encoding: chunked\r\n")
	}
	b.WriteString("Connection: keep-alive\r\n")
	b.WriteString("User-Agent: gash-smuggle-probe/1.0\r\n\r\n")
	switch kind {
	case KindTECL:
		b.WriteString("0\r\n\r\nX")
	default:
		b.WriteString("0\r\n\r\n")
	}
	return b.String()
}

// readOne tek yanıt okur (CL + yanıt-chunked destekli, tavanlı).
func readOne(conn net.Conn, readTimeout time.Duration) respSummary {
	start := time.Now()
	out := respSummary{headers: make(http.Header)}
	_ = conn.SetDeadline(time.Now().Add(readTimeout))
	br := bufio.NewReader(conn)
	line, err := br.ReadString('\n')
	if err != nil {
		if ne, ok := err.(net.Error); ok && ne.Timeout() {
			out.timeout = true
		}
		out.rtt = time.Since(start)
		return out
	}
	parts := strings.SplitN(strings.TrimSpace(line), " ", 3)
	if len(parts) < 2 {
		out.rtt = time.Since(start)
		return out
	}
	if code, aerr := strconv.Atoi(parts[1]); aerr == nil {
		out.status = code
	}
	for {
		hline, herr := br.ReadString('\n')
		if herr != nil {
			out.rtt = time.Since(start)
			return out
		}
		hline = strings.TrimRight(hline, "\r\n")
		if hline == "" {
			break
		}
		if idx := strings.Index(hline, ":"); idx > 0 {
			out.headers.Add(strings.TrimSpace(hline[:idx]), strings.TrimSpace(hline[idx+1:]))
		}
	}
	// Gövde: CL öncelikli; yanıt-chunked desteklenir; uzunluksuzda kısa grace.
	body := readBody(br, conn, out.headers)
	out.body = body
	out.rtt = time.Since(start)
	return out
}

// readBody CL / yanıt-chunked / uzunluksuz gövdeyi tavanlı okur.
func readBody(br *bufio.Reader, conn net.Conn, h http.Header) []byte {
	if isChunkedResponse(h) {
		return readChunkedBody(br)
	}
	if cl := contentLength(h); cl > 0 {
		if cl > maxBody {
			cl = maxBody
		}
		buf := make([]byte, cl)
		n, _ := io.ReadFull(br, buf)
		return buf[:n]
	}
	// Uzunluksuz: bağlantı açık kalır (keep-alive) → kısa grace, fazlası yok.
	_ = conn.SetDeadline(time.Now().Add(150 * time.Millisecond))
	extra, _ := io.ReadAll(io.LimitReader(br, 4096))
	return extra
}

// readChunkedBody yanıt-chunked gövdeyi tavanlı çözer.
func readChunkedBody(br *bufio.Reader) []byte {
	var out []byte
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			return out
		}
		line = strings.TrimSpace(strings.SplitN(line, ";", 2)[0])
		n, err := strconv.ParseInt(line, 16, 64)
		if err != nil || n < 0 {
			return out
		}
		if n == 0 {
			// Fragman sonu + kapanış satırı tüketilir.
			_, _ = br.ReadString('\n')
			return out
		}
		if int64(len(out))+n > maxBody {
			n = int64(maxBody - len(out))
		}
		chunk := make([]byte, n)
		if _, err := io.ReadFull(br, chunk); err != nil {
			return append(out, chunk...)
		}
		out = append(out, chunk...)
		_, _ = br.ReadString('\n') // chunk kapanışı
		if len(out) >= maxBody {
			return out
		}
	}
}

func isChunkedResponse(h http.Header) bool {
	for _, v := range h.Values("Transfer-Encoding") {
		for _, tok := range strings.Split(strings.ToLower(v), ",") {
			if strings.TrimSpace(tok) == "chunked" {
				return true
			}
		}
	}
	return false
}

func contentLength(h http.Header) int {
	v := strings.TrimSpace(h.Get("Content-Length"))
	if v == "" {
		return 0
	}
	n, err := strconv.Atoi(strings.Split(v, ",")[0])
	if err != nil || n < 0 {
		return 0
	}
	return n
}

// runPair tek bağlantıda istek+takip çiftini koşar (2 istek sayar).
func (o Options) runPair(ctx context.Context, dt dialTarget, kind, first string) (pairOutcome, int, error) {
	out := pairOutcome{kind: kind}
	if err := ctx.Err(); err != nil {
		return out, 0, err
	}
	conn, err := o.dial(ctx, dt)
	if err != nil {
		return out, 0, err
	}
	defer func() { _ = conn.Close() }()
	sent := 0
	_ = conn.SetDeadline(time.Now().Add(o.timeout()))
	if _, werr := io.WriteString(conn, first); werr != nil {
		return out, sent, fmt.Errorf("smuggle write first: %w", werr)
	}
	sent++
	out.first = readOne(conn, o.timeout())
	if out.first.timeout || out.first.status == 0 {
		return out, sent, nil
	}
	// Blok sayfası kanıt olamaz (oracle guard disiplini).
	cls := baseline.ClassifyStatic(out.first.status, out.first.headers, out.first.body)
	out.untrusted = cls.Untrusted
	// Takip: kısa bekleme + aynı bayt (desync varsa kuyruğa takılır).
	select {
	case <-ctx.Done():
		return out, sent, ctx.Err()
	case <-time.After(followupDelay):
	}
	_ = conn.SetDeadline(time.Now().Add(o.timeout()))
	if _, werr := io.WriteString(conn, followup(dt)); werr != nil {
		return out, sent, nil // yazılamadı → ikinci yanıt yok (divergence adayı)
	}
	sent++
	out.second = readOne(conn, secondReadTimeout)
	return out, sent, nil
}

// decide çift-kanıt kararıdır: differential + timing BİRLİKTE → firm.
// Tek-kanal (yalnızca gecikme / yalnızca statü farkı) → reject (bulgu YOK).
// confirmed bu disiplinde ÜRETİLMEZ (tavan firm).
func decide(control pairOutcome, probes []pairOutcome) *oracle.Evidence {
	if control.second.timeout || control.second.status == 0 {
		return nil // kontrol bozuk → ölçüm yok
	}
	if control.second.status >= 500 {
		return nil // kararsız backend → ölçüm yok
	}
	var divergent []string
	art := map[string]string{
		"control_second_status": strconv.Itoa(control.second.status),
		"control_second_body":   truncate(control.second.bodyString(), 120),
		"control_second_rtt_ms": strconv.FormatInt(control.second.rtt.Milliseconds(), 10),
	}
	for _, p := range probes {
		if p.untrusted {
			continue // blok sayfası kanıt olamaz
		}
		diff := p.second.timeout ||
			p.second.status != control.second.status ||
			p.second.bodyString() != control.second.bodyString()
		var delta time.Duration
		if p.second.timeout {
			delta = secondReadTimeout
		} else {
			delta = p.second.rtt - control.second.rtt
			if delta < 0 {
				delta = 0
			}
		}
		timing := p.second.timeout || delta >= timingDeltaThreshold
		prefix := "probe_" + sanitizeKind(p.kind) + "_"
		art[prefix+"second_status"] = strconv.Itoa(p.second.status)
		art[prefix+"second_body"] = truncate(p.second.bodyString(), 120)
		art[prefix+"second_rtt_ms"] = strconv.FormatInt(p.second.rtt.Milliseconds(), 10)
		art[prefix+"timeout"] = strconv.FormatBool(p.second.timeout)
		if diff && timing {
			divergent = append(divergent, p.kind)
		}
	}
	if len(divergent) == 0 {
		return nil
	}
	art["divergent_kinds"] = strings.Join(divergent, ",")
	return &oracle.Evidence{
		Verdict:                oracle.VerdictAccept,
		ConfidenceContribution: plugin.ConfidenceFirm,
		Artifacts:              art,
		Repeats:                len(probes) + 1,
		ControlResult:          "diverged",
		Note:                   "CL.TE/TE.CL timing+differential çift kanıt → firm (tek başına confirmed YOK)",
	}
}

func sanitizeKind(k string) string {
	return strings.ToLower(strings.NewReplacer(".", "_", "/", "_").Replace(k))
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

// Scan hedefte smuggling diferansiyel taraması koşar.
// What: Kapı → kapsam preflight (yalnızca --scope verilmişse) → kontrol çifti
// + 3 tür probu (≤10 istek) → çift-kanıt kararı → en fazla firm bulgu.
// Why: Tek canlı döngü; open modda kullanıcı hedefine soket açılır (operatör
// sorumluluğu), --scope verilmişse kapsam-dışı istek YOK, yıkıcı gövde YOK.
func Scan(ctx context.Context, target string, opts Options) (*ScanResult, error) {
	res := &ScanResult{Detail: map[string]string{}}
	if reason, ok := opts.gate(); !ok {
		res.Skipped = reason
		return res, nil
	}
	dt, err := parseTarget(target)
	if err != nil {
		return nil, err
	}
	// Kapsam preflight: yalnızca --scope verilmişse (Allow != nil);
	// kapsam-dışı → ErrScopeViolation, SOKET AÇILMADAN.
	if err := opts.checkAllowed(dt.host); err != nil {
		return nil, err
	}
	control, n, err := opts.runPair(ctx, dt, "control", controlFirst(dt))
	if err != nil {
		if errors.Is(err, errHTTP2) {
			res.Requests = n
			res.Skipped = "skipped (http/2'de smuggling geçersiz)"
			return res, nil
		}
		return nil, err
	}
	res.Requests += n
	var probes []pairOutcome
	for _, kind := range ProbeKinds() {
		if res.Requests >= MaxProbes {
			break
		}
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		p, pn, perr := opts.runPair(ctx, dt, kind, ambiguousFirst(dt, kind))
		if perr != nil {
			if errors.Is(perr, errHTTP2) {
				res.Skipped = "skipped (http/2'de smuggling geçersiz)"
				return res, nil
			}
			// Tek tür hatası taramayı durdurmaz (ölçülemeyen eksen elenir).
			res.Detail["error_"+sanitizeKind(kind)] = perr.Error()
			continue
		}
		res.Requests += pn
		probes = append(probes, p)
	}
	res.Detail["kinds"] = strings.Join(ProbeKinds(), ",")
	ev := decide(control, probes)
	if ev == nil {
		res.Detail["decision"] = "reject: çift-kanıt (timing+differential) yok"
		return res, nil
	}
	res.Evidence = ev
	res.Finding = buildFinding(target, ev, res.Requests)
	res.Detail["decision"] = "accept: firm (tavan; confirmed YOK)"
	return res, nil
}

// buildFinding motor-içi bulgu kurar (engine-recon disiplini: finding.Build
// KULLANILMAZ — Build, Tests'siz spec'te confirmed'ı tentative'a indirir;
// engine-recon'un fixture-spec'i yoktur, kanıt disiplini buradadır;
// bkz. internal/discovery/content-discovery.go buildContentFinding).
func buildFinding(target string, ev *oracle.Evidence, requests int) *finding.Finding {
	f := &finding.Finding{
		ID:          newSmuggleID(),
		RuleID:      RuleID,
		CWE:         CWE,
		Title:       "HTTP request smuggling ayrışması (CL.TE/TE.CL)",
		Description: "Ham-TCP diferansiyel probunda muğlak CL+TE isteği sonrası takip yanıtı kontrol çiftinden ayrıştı (statü/gövde farkı + gecikme); ön-uç/arka-uç çerçeveleme yorumu tutarsız.",
		Severity:    plugin.SeverityHigh,
		Confidence:  plugin.ConfidenceFirm, // tavan: çift kanıt bile confirmed vermez
		Target:      target,
		InjectionPoint: plugin.InjectionPoint{
			URL:           target,
			Method:        "POST",
			ParamLocation: "header",
		},
		Evidence: map[string]string{},
		Reproducibility: map[string]string{
			"repeats": strconv.Itoa(ev.Repeats),
			"control": ev.ControlResult,
			"note":    ev.Note,
		},
		PluginID:           PluginID,
		OracleName:         OracleName,
		Tags:               []string{"smuggle", "request-smuggling", "recon", "differential"},
		Method:             "POST",
		VerificationMethod: "oracle smuggling-differential, repeats=" + strconv.Itoa(ev.Repeats) + ", control=dual(timing+differential)",
		Note:               ev.Note,
		DetectorVersion:    DetectorVersion,
	}
	for k, v := range ev.Artifacts {
		f.Evidence[k] = v
	}
	f.Evidence["requests"] = strconv.Itoa(requests)
	f.Evidence["signal"] = "cl-te-desync"
	f.Fingerprint = finding.Fingerprint(f)
	return f
}

func newSmuggleID() string {
	var b [6]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "finding_smuggle_fallback"
	}
	return "finding_smuggle_" + hex.EncodeToString(b[:])
}

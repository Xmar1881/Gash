// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Modül: github.com/Xmar1881/Gash

package proto

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	"github.com/Xmar1881/Gash/internal/plugin"
)

// SSH gözlem sınırları (RFC 4253: sunucu banner'ı bağlantıda gönderilir).
const (
	sshDefaultPort = "22"
	sshBannerMax   = 255 // RFC 4253 üst sınırı; kanıta taşınan bayt tavanı
	sshLineMax     = 4   // banner öncesi veri satırı toleransı (RFC 4253 MAY)
)

// SSHResult SSH banner gözlemidir. Bağlantıda HİÇBİR veri gönderilmez:
// sunucu banner'ı bağlantı kurulumunda kendiliğinden gelir (salt-okuma).
type SSHResult struct {
	Host            string
	Port            string
	Open            bool
	Banner          string
	ProtocolVersion string
	Software        string
	Comment         string
	DurationMs      int64
}

// CheckSSH hedefe bağlanıp SSH banner'ını okur, veri GÖNDERMEZ, hemen kapatır.
// What: Güvenli aktif prob: SYN→sunucu banner'ı→kapat; KEX/auth/KEX-init YOK,
// yazma YOK, banner ≤255 bayt, deadline'lı. Boş port → 22.
// Why: Sürüm/protokol ifşası sinyaldir ama tek başına zayıftır (tavan tentative);
// kapsam kararı fail-closed'dur (Allow nil → çalışmaz, soket açılmaz).
func CheckSSH(ctx context.Context, host, port string, o Options) (*SSHResult, error) {
	h := strings.ToLower(strings.TrimSpace(host))
	if h == "" {
		return nil, fmt.Errorf("proto ssh: boş host")
	}
	p := strings.TrimSpace(port)
	if p == "" {
		p = sshDefaultPort
	}
	if err := o.checkAllowed(h); err != nil {
		return nil, err
	}
	start := time.Now()
	ctx, cancel := context.WithTimeout(ctx, o.timeout())
	defer cancel()
	dialer := &net.Dialer{Timeout: o.timeout()}
	addr := net.JoinHostPort(h, p)
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("proto ssh %s: %w", addr, err)
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(o.timeout()))

	res := &SSHResult{Host: h, Port: p, Open: true}
	// Salt-okuma: sınırlı okuyucu; sunucu yeni satır göndermezse deadline keser.
	br := bufio.NewReaderSize(io.LimitReader(conn, int64(sshBannerMax)+1), sshBannerMax+1)
	firstLine := ""
	sshLine := ""
	for i := 0; i < sshLineMax; i++ {
		line, rerr := br.ReadString('\n')
		trimmed := strings.TrimRight(line, "\r\n")
		if firstLine == "" {
			firstLine = trimmed
		}
		if strings.HasPrefix(trimmed, "SSH-") {
			sshLine = trimmed
			break
		}
		if rerr != nil || line == "" {
			break
		}
	}
	if len(sshLine) > sshBannerMax {
		sshLine = sshLine[:sshBannerMax]
	}
	if len(firstLine) > sshBannerMax {
		firstLine = firstLine[:sshBannerMax]
	}
	if sshLine != "" {
		res.Banner = sanitizeProtoBanner(sshLine, sshBannerMax)
		if proto, software, comment, ok := parseSSHBanner(sshLine); ok {
			res.ProtocolVersion = proto
			res.Software = software
			res.Comment = comment
		}
	} else {
		// Kısmi/bozuk banner: bağlantı kanıtı korunur, ayrıştırma sessiz kalır.
		res.Banner = sanitizeProtoBanner(firstLine, sshBannerMax)
	}
	res.DurationMs = time.Since(start).Milliseconds()
	return res, nil
}

// parseSSHBanner RFC 4253 satırını ayrıştırır: SSH-<proto>-<software>[ <comment>].
// What: Gevşek ayrıştırma; proto boş veya rakam/nokta dışıysa ok=false.
// Why: Eksik/bozuk satır bulgu tavanını düşürür ama çökme veya sahte sürüm
// iddiası üretmemelidir (tolerant reader).
func parseSSHBanner(line string) (protoVersion, software, comment string, ok bool) {
	s := strings.TrimSpace(line)
	if !strings.HasPrefix(s, "SSH-") {
		return "", "", "", false
	}
	rest := s[len("SSH-"):]
	dash := strings.IndexByte(rest, '-')
	if dash <= 0 {
		return "", "", "", false
	}
	protoVersion = rest[:dash]
	for _, ch := range protoVersion {
		if (ch < '0' || ch > '9') && ch != '.' {
			return "", "", "", false
		}
	}
	rest = rest[dash+1:]
	if sp := strings.IndexByte(rest, ' '); sp >= 0 {
		software = rest[:sp]
		comment = strings.TrimSpace(rest[sp+1:])
	} else {
		software = rest
	}
	if len(software) > 64 {
		software = software[:64]
	}
	return protoVersion, software, comment, true
}

// outdatedSSHPrefixes bakımsız OpenSSH sürüm aileleridir (CVE iddiası YOK;
// genel "eski yazılım, satıcı bültenlerine bakın" notuyla kullanılır).
var outdatedSSHPrefixes = []string{
	"OpenSSH_1", "OpenSSH_2", "OpenSSH_3", "OpenSSH_4", "OpenSSH_5",
	"OpenSSH_6", "OpenSSH_7",
	"OpenSSH_8.0", "OpenSSH_8.1", "OpenSSH_8.2", "OpenSSH_8.3", "OpenSSH_8.4",
}

// oldSSHSoftware bilinen eski OpenSSH öneklerinden biriyle eşleşir mi.
func oldSSHSoftware(software string) bool {
	s := strings.TrimSpace(software)
	if s == "" {
		return false
	}
	for _, p := range outdatedSSHPrefixes {
		if strings.HasPrefix(s, p) {
			return true
		}
	}
	return false
}

// sshProto1x protokol sürümü 1.x ailesini (1.99 uyumluluk dahil) bildirir mi.
// What: "1.*" öneki 1.x kabulüdür; "1.99" sunucunun 1.5'i de kabul ettiğini
// bildirir (RFC 4253), bu yüzden aynı sınıfta işlenir.
// Why: 1.x zayıf/kırık protokoldür (CWE-327) ama gözlem tek başına tentativedir.
func sshProto1x(protoVersion string) bool {
	return strings.HasPrefix(strings.TrimSpace(protoVersion), "1.")
}

// SSHFindings gözlemden bulgu üretir (GASH-052, CWE-327).
// What: Proto 1.x → high/tentative; eski OpenSSH yazılımı → medium/tentative.
// Modern banner (2.0 + güncel yazılım) bulgu üretmez; boş banner sessizdir.
// Why: Banner beyanı davranışla doğrulanmadı (yalnızca sunucunun kendi iddiası),
// bu yüzden tavan tentative'dir (GASH-026 disiplini).
func SSHFindings(target string, res *SSHResult) []Finding {
	if res == nil || !res.Open {
		return nil
	}
	base := map[string]string{
		"host":             res.Host,
		"port":             res.Port,
		"banner":           sanitizeProtoBanner(res.Banner, sshBannerMax),
		"protocol_version": res.ProtocolVersion,
		"software":         res.Software,
	}
	mk := func(title, desc string, sev plugin.Severity, signal string) Finding {
		ev := make(map[string]string, len(base)+1)
		for k, v := range base {
			ev[k] = v
		}
		ev["signal"] = signal
		return Finding{
			RuleID: "GASH-052", CWE: "CWE-327", Title: title, Desc: desc,
			Severity: sev, Confidence: plugin.ConfidenceTentative,
			Target: target, PluginID: "proto-ssh-banner", OracleName: "ssh",
			Evidence: ev,
			Note:     "salt-okuma SSH banner gözlemi (KEX/auth yok); beyan doğrulanmadı, tavan tentative",
			Tags:     []string{"ssh", "protocol", "version-disclosure"},
		}
	}
	var out []Finding
	if sshProto1x(res.ProtocolVersion) {
		out = append(out, mk("SSH protokol 1.x desteği açık (SSH-"+res.ProtocolVersion+")",
			"Sunucu SSH protokol 1.x (veya 1.99 uyumluluk) bildiriyor; 1.x kırık kabul edilir (CWE-327).",
			plugin.SeverityHigh, "ssh-proto-1"))
	}
	if oldSSHSoftware(res.Software) {
		out = append(out, mk("SSH yazılımı eski (banner: "+res.Software+")",
			"Banner bakımsız OpenSSH ailesi bildiriyor; satıcı güvenlik bültenlerine göre doğrulayın ve güncelleyin.",
			plugin.SeverityMedium, "ssh-old-software"))
	}
	return out
}

// --- Faz 1: SSH el sıkışma algoritma denetimi (GASH-054) ---
//
// Kapsam sınırı (pazarlıksız): sürüm değişimi + SSH_MSG_KEXINIT algoritma
// gözlemi. Anahtar değişimi TAMAMLANMAZ, kimlik doğrulama DENENMEZ, parola
// gönderilmez, auth yöntemleri numaralandırılmaz. Sunucu KEXINIT'i
// gecikirse sabit (gizli anahtar gerektirmeyen) minimal istemci KEXINIT
// yazılır; bu yalnızca sunucunun listesini görmek içindir.

// SSH el sıkışma denetim sınırları (savunma tavanları).
const (
	sshKexInitMaxPacket = 256 * 1024             // packet_length tavanı (uint32 bayt)
	sshNameListMax      = 64 * 1024              // tek name-list bayt tavanı
	sshMaxNamesPerList  = 4096                   // tek name-list isim sayısı sanity tavanı
	sshMaxTotalNames    = 4 * sshMaxNamesPerList // tüm listeler toplamı sanity tavanı
	sshEvidenceMax      = 2048                   // kanıta taşınan algoritma listesi karakter tavanı
	sshKexInitWait      = 500 * time.Millisecond
	sshMsgKexInit       = 20
)

// sshClientCookie sabit istemci KEXINIT cookie'sidir (gözlem amaçlı; gizli değer yok).
var sshClientCookie = [16]byte{'g', 'a', 's', 'h', '-', 's', 's', 'h', '-', 'p', 'r', 'o', 'b', 'e', '1', 0}

// SSHHandshakeResult KEXINIT algoritma gözlemidir (kimlik doğrulama YOK).
type SSHHandshakeResult struct {
	Host                  string
	Port                  string
	Banner                string
	ProtocolVersion       string
	Software              string
	KexAlgorithms         []string
	HostKeyAlgorithms     []string
	CiphersClientToServer []string
	CiphersServerToClient []string
	MACsClientToServer    []string
	MACsServerToClient    []string
	CompressionC2S        []string
	CompressionS2C        []string
	DurationMs            int64
}

// AuditSSHHandshake sürüm değişimi + KEXINIT algoritma listelerini gözlemler.
// What: CheckSSH ile aynı fail-closed kapsam/dial disiplini; banner okunur,
// ardından sunucunun SSH_MSG_KEXINIT paketi (≤256KB, deadline'lı) çözümlenir.
// Sunucu kendiliğinden göndermezse sabit minimal istemci KEXINIT yazılır ve
// yanıt kalan sürede okunur. Bağlantı ayrıştırma sonrası hemen kapatılır.
// Why: KEXINIT beyanı deterministik bir gözlemdir (firm); anahtar değişimi
// tamamlanmadığı için auth yöntemi numaralandırması bu fazın DIŞINDADIR.
func AuditSSHHandshake(ctx context.Context, host, port string, o Options) (*SSHHandshakeResult, error) {
	h := strings.ToLower(strings.TrimSpace(host))
	if h == "" {
		return nil, fmt.Errorf("proto ssh: boş host")
	}
	p := strings.TrimSpace(port)
	if p == "" {
		p = sshDefaultPort
	}
	if err := o.checkAllowed(h); err != nil {
		return nil, err
	}
	start := time.Now()
	ctx, cancel := context.WithTimeout(ctx, o.timeout())
	defer cancel()
	dialer := &net.Dialer{Timeout: o.timeout()}
	addr := net.JoinHostPort(h, p)
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("proto ssh handshake %s: %w", addr, err)
	}
	defer func() { _ = conn.Close() }()
	deadline := time.Now().Add(o.timeout())
	_ = conn.SetDeadline(deadline)

	res := &SSHHandshakeResult{Host: h, Port: p}
	br := bufio.NewReaderSize(conn, 64*1024)
	first, sshLine := readSSHVersionLines(br, sshBannerMax)
	if sshLine != "" {
		res.Banner = sanitizeProtoBanner(sshLine, sshBannerMax)
		if pv, software, _, ok := parseSSHBanner(sshLine); ok {
			res.ProtocolVersion = pv
			res.Software = software
		}
	} else {
		res.Banner = sanitizeProtoBanner(first, sshBannerMax)
	}

	// Sunucu KEXINIT'i kendiliğinden gönderir (RFC 4253). Göndermezse kısa
	// bekleme sonunda sabit istemci teklifi yazılır (anahtar değişimi YOK).
	waitEnd := time.Now().Add(sshKexInitWait)
	if waitEnd.After(deadline) {
		waitEnd = deadline
	}
	_ = conn.SetReadDeadline(waitEnd)
	payload, rerr := readSSHPacketPayload(br, sshKexInitMaxPacket)
	if rerr != nil {
		var nerr net.Error
		if !errors.As(rerr, &nerr) || !nerr.Timeout() {
			return nil, fmt.Errorf("proto ssh handshake %s: kexinit okunamadı: %w", addr, rerr)
		}
		_ = conn.SetWriteDeadline(deadline)
		if _, werr := conn.Write(buildClientSSHKexInit()); werr != nil {
			return nil, fmt.Errorf("proto ssh handshake %s: istemci kexinit yazılamadı: %w", addr, werr)
		}
		_ = conn.SetReadDeadline(deadline)
		payload, rerr = readSSHPacketPayload(br, sshKexInitMaxPacket)
		if rerr != nil {
			return nil, fmt.Errorf("proto ssh handshake %s: kexinit okunamadı: %w", addr, rerr)
		}
	}
	if err := decodeSSHKexInit(res, payload); err != nil {
		return nil, fmt.Errorf("proto ssh handshake %s: %w", addr, err)
	}
	res.DurationMs = time.Since(start).Milliseconds()
	return res, nil
}

// readSSHLineLimited bufio okuyucudan en fazla max baytlık satır okur.
// What: Bayt bayt okuma (tavanda durur); complete=yeni satır görüldü.
// Why: ReadString sınırsız büyüyebilir; düşmanca banner bellek tüketmemelidir.
func readSSHLineLimited(br *bufio.Reader, max int) (line string, complete bool) {
	var sb strings.Builder
	for i := 0; i <= max; i++ {
		b, err := br.ReadByte()
		if err != nil {
			return sb.String(), false
		}
		if b == '\n' {
			return sb.String(), true
		}
		sb.WriteByte(b)
	}
	return sb.String(), false
}

// readSSHVersionLines RFC 4253 sürüm satırlarını sınırlı okur (≤4 satır).
// What: CheckSSH ile aynı tolerans: SSH- önekli ilk satır banner'dır.
// Why: Banner öncesi veri satırı RFC tarafından MAY; ayrıştırıcı paylaşılır.
func readSSHVersionLines(br *bufio.Reader, max int) (firstLine, sshLine string) {
	for i := 0; i < sshLineMax; i++ {
		line, complete := readSSHLineLimited(br, max)
		trimmed := strings.TrimRight(line, "\r\n")
		if firstLine == "" {
			firstLine = trimmed
		}
		if strings.HasPrefix(trimmed, "SSH-") {
			return firstLine, trimmed
		}
		if !complete || line == "" {
			break
		}
	}
	return firstLine, ""
}

// readSSHPacketPayload tek SSH transport paketinin payload'ını okur.
// What: uint32 packet_length (≤ tavan, 8'in katı hizalı) + padding_length
// doğrulaması; gövde deadline ile sınırlı okunur.
// Why: KEX öncesi blok boyu 8'dir (RFC 4253 §6); bozuk çerçeve sessiz yutulmaz.
func readSSHPacketPayload(br *bufio.Reader, maxPacket int) ([]byte, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(br, hdr[:]); err != nil {
		return nil, err
	}
	plen := binary.BigEndian.Uint32(hdr[:])
	if plen == 0 || plen > uint32(maxPacket) {
		return nil, fmt.Errorf("packet_length %d geçersiz (tavan %d)", plen, maxPacket)
	}
	if (plen+4)%8 != 0 {
		return nil, fmt.Errorf("packet_length %d blok hizasız (8'in katı olmalı)", plen)
	}
	buf := make([]byte, plen)
	if _, err := io.ReadFull(br, buf); err != nil {
		return nil, fmt.Errorf("paket gövdesi eksik: %w", err)
	}
	pad := int(buf[0])
	if pad < 4 || pad+1 > len(buf) {
		return nil, fmt.Errorf("padding_length %d geçersiz", pad)
	}
	return buf[1 : len(buf)-pad], nil
}

// decodeSSHKexInit KEXINIT payload'ından 10 name-list'i çözümleyip sonuca yazar.
// What: msg=20 + 16 bayt cookie + 10 name-list (dil listeleri boş olabilir) +
// boolean first_kex_packet_follows + uint32 reserved; hepsi sınırlı çözülür.
// Why: X25519 vb. modern algoritmalar dahil tüm liste beyanları okunur; bozuk
// veri hata döner, asla panik veya sahte dolu liste üretilmez.
func decodeSSHKexInit(res *SSHHandshakeResult, payload []byte) error {
	if len(payload) < 1+16 {
		return fmt.Errorf("kexinit payload kısa (%d bayt)", len(payload))
	}
	if payload[0] != sshMsgKexInit {
		return fmt.Errorf("kexinit bekleniyordu (msg=%d)", payload[0])
	}
	off := 1 + 16
	lists := make([][]string, 0, 10)
	total := 0
	for i := 0; i < 10; i++ {
		names, next, err := readSSHNameList(payload, off)
		if err != nil {
			return fmt.Errorf("name-list %d: %w", i+1, err)
		}
		total += len(names)
		if total > sshMaxTotalNames {
			return fmt.Errorf("name-list toplam isim tavanı aştı (%d)", total)
		}
		lists = append(lists, names)
		off = next
	}
	if off+5 > len(payload) {
		return fmt.Errorf("kexinit kuyruğu eksik (%d bayt)", len(payload)-off)
	}
	if payload[off] > 1 {
		return fmt.Errorf("first_kex_packet_follows geçersiz (%d)", payload[off])
	}
	res.KexAlgorithms = lists[0]
	res.HostKeyAlgorithms = lists[1]
	res.CiphersClientToServer = lists[2]
	res.CiphersServerToClient = lists[3]
	res.MACsClientToServer = lists[4]
	res.MACsServerToClient = lists[5]
	res.CompressionC2S = lists[6]
	res.CompressionS2C = lists[7]
	return nil
}

// readSSHNameList uint32 uzunluklu virgüllü name-list'i çözer.
// What: Bayt tavanı (64KB) + isim sayısı sanity tavanı; boş isimler atılır.
// Why: Sunucu kontrolündeki uzunluklar bellek/CPU tüketimine dönüşmemelidir.
func readSSHNameList(b []byte, off int) ([]string, int, error) {
	if off+4 > len(b) {
		return nil, off, fmt.Errorf("uzunluk alanı eksik")
	}
	n := int(binary.BigEndian.Uint32(b[off:]))
	off += 4
	if n < 0 || n > sshNameListMax || off+n > len(b) {
		return nil, off, fmt.Errorf("uzunluk %d geçersiz (tavan %d, kalan %d)", n, sshNameListMax, len(b)-off)
	}
	raw := string(b[off : off+n])
	off += n
	if n == 0 {
		return nil, off, nil
	}
	parts := strings.Split(raw, ",")
	if len(parts) > sshMaxNamesPerList {
		return nil, off, fmt.Errorf("isim sayısı %d tavanı aştı", len(parts))
	}
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		out = append(out, sanitizeProtoBanner(p, 64))
	}
	return out, off, nil
}

// buildClientSSHKexInit sabit minimal istemci KEXINIT paketi üretir.
// What: Yalnızca sunucunun listesini görmek için sabit teklif (gizli veri yok);
// frameSSHPacket ile RFC 4253 çerçevesine sarılır.
// Why: Anahtar değişimi tamamlanmaz; hiçbir durumda auth/parola gönderilmez.
func buildClientSSHKexInit() []byte {
	lists := [][]string{
		{"diffie-hellman-group14-sha256"},
		{"ssh-ed25519"},
		{"aes128-ctr"},
		{"aes128-ctr"},
		{"hmac-sha2-256"},
		{"hmac-sha2-256"},
		{"none"},
		{"none"},
		{},
		{},
	}
	payload := []byte{sshMsgKexInit}
	payload = append(payload, sshClientCookie[:]...)
	for _, list := range lists {
		raw := strings.Join(list, ",")
		var l [4]byte
		binary.BigEndian.PutUint32(l[:], uint32(len(raw)))
		payload = append(payload, l[:]...)
		payload = append(payload, raw...)
	}
	payload = append(payload, 0, 0, 0, 0, 0) // first_kex_packet_follows=false + reserved
	return frameSSHPacket(payload)
}

// frameSSHPacket payload'ı SSH transport çerçevesine sarar (KEX öncesi blok=8).
// What: packet_length + padding_length + payload + rastgele olmayan dolgu;
// toplam uzunluk 8'in katı, dolgu 4..255 bayt (RFC 4253 §6).
// Why: Testler de aynı çerçeveleyiciyi kullanır (tek kod yolu).
func frameSSHPacket(payload []byte) []byte {
	const block = 8
	base := 4 + 1 + len(payload)
	pad := block - base%block
	if pad < 4 {
		pad += block
	}
	out := make([]byte, 4+1+len(payload)+pad)
	binary.BigEndian.PutUint32(out[:4], uint32(1+len(payload)+pad))
	out[4] = byte(pad)
	copy(out[5:], payload)
	return out
}

// sshWeakAlgorithmReason algoritma adını zayıf sınıfa eşler (saf fonksiyon).
// What: kind = kex|hostkey|cipher|mac; kırılgan aile adı + şiddet döner.
//   - kex: SHA-1 tabanlı/1024-bit gruplar → medium (modern X25519/ECDH/group16+ sessiz)
//   - hostkey: ssh-dss ve SHA-1 ssh-rsa (cert dahil) → medium
//   - cipher: none/arcfour/3DES/blowfish/cast128/tek-DES → high; CBC modu → medium
//   - mac: MD5/umac-64/hmac-sha1/ripemd160 → medium (ETM-SHA2 sessiz)
//
// Why: CVE iddiası yok; yalnızca algoritma adındaki aile sinyali raporlanır.
func sshWeakAlgorithmReason(kind, name string) (string, plugin.Severity) {
	n := strings.ToLower(strings.TrimSpace(name))
	if n == "" {
		return "", ""
	}
	switch kind {
	case "kex":
		switch {
		case strings.Contains(n, "sha1"):
			return "sha1-kex", plugin.SeverityMedium
		case strings.Contains(n, "group1-"):
			return "dh-group1-1024", plugin.SeverityMedium
		}
		return "", ""
	case "hostkey":
		switch {
		case n == "ssh-dss":
			return "ssh-dss", plugin.SeverityMedium
		case strings.HasPrefix(n, "ssh-rsa"):
			return "ssh-rsa-sha1", plugin.SeverityMedium
		}
		return "", ""
	case "cipher":
		switch {
		case n == "none":
			return "plaintext-none", plugin.SeverityHigh
		case strings.Contains(n, "arcfour"):
			return "arcfour", plugin.SeverityHigh
		case strings.Contains(n, "3des"):
			return "3des-cbc", plugin.SeverityHigh
		case strings.Contains(n, "blowfish"):
			return "blowfish-cbc", plugin.SeverityHigh
		case strings.Contains(n, "cast128"):
			return "cast128-cbc", plugin.SeverityHigh
		case strings.Contains(n, "des"):
			return "single-des", plugin.SeverityHigh
		case strings.Contains(n, "-cbc"):
			return "cbc-mode", plugin.SeverityMedium
		}
		return "", ""
	case "mac":
		switch {
		case strings.Contains(n, "md5"):
			return "hmac-md5", plugin.SeverityMedium
		case strings.Contains(n, "umac-64"):
			return "umac-64", plugin.SeverityMedium
		case n == "hmac-sha1" || strings.HasPrefix(n, "hmac-sha1-"):
			return "hmac-sha1", plugin.SeverityMedium
		case strings.Contains(n, "ripemd160"):
			return "ripemd160", plugin.SeverityMedium
		}
		return "", ""
	}
	return "", ""
}

// collectSSHWeakList zayıf algoritmaları toplar (severity = en yüksek).
func collectSSHWeakList(kind string, lists ...[]string) ([]string, string, plugin.Severity) {
	var weak []string
	reason := ""
	var sev plugin.Severity
	for _, list := range lists {
		for _, name := range list {
			r, s := sshWeakAlgorithmReason(kind, name)
			if r == "" {
				continue
			}
			weak = append(weak, name)
			if sev == "" || sshSeverityRank(s) > sshSeverityRank(sev) {
				sev = s
				reason = r
			}
		}
	}
	return weak, reason, sev
}

// sshSeverityRank şiddetleri karşılaştırır (high > medium > low > "").
func sshSeverityRank(s plugin.Severity) int {
	switch s {
	case plugin.SeverityHigh:
		return 3
	case plugin.SeverityMedium:
		return 2
	case plugin.SeverityLow:
		return 1
	}
	return 0
}

// SSHHandshakeFindings KEXINIT gözleminden bulgu üretir (GASH-054, CWE-327).
// What: Sınıf başına TEK bulgu (kex, hostkey, cipher, mac); cipher/mac c2s+s2c
// birleşik kanıtla taşınır. Şiddet: cipher'da none/plaintext → high, diğerleri
// medium. Modern sunucu (yalnızca güçlü algoritmalar) bulgu üretmez.
// Why: KEXINIT sunucunun doğrudan beyanıdır ve gözlem deterministiktir → firm;
// auth yöntemi/parola denemesi olmadığı için tavan confirmed'a çıkmaz.
func SSHHandshakeFindings(target string, res *SSHHandshakeResult) []Finding {
	if res == nil {
		return nil
	}
	if len(res.KexAlgorithms)+len(res.HostKeyAlgorithms)+len(res.CiphersClientToServer)+
		len(res.CiphersServerToClient)+len(res.MACsClientToServer)+len(res.MACsServerToClient) == 0 {
		return nil // KEXINIT gözlemi yok → bulgu yok
	}
	version := strings.TrimSpace(res.Banner)
	if version == "" && res.ProtocolVersion != "" {
		version = "SSH-" + res.ProtocolVersion + "-" + res.Software
	}
	join := func(list []string) string { return strings.Join(list, ",") }
	base := map[string]string{
		"host":                res.Host,
		"port":                res.Port,
		"ssh_version":         sanitizeProtoBanner(version, sshBannerMax),
		"kex_algorithms":      sanitizeProtoBanner(join(res.KexAlgorithms), sshEvidenceMax),
		"host_key_algorithms": sanitizeProtoBanner(join(res.HostKeyAlgorithms), sshEvidenceMax),
		"ciphers":             sanitizeProtoBanner("c2s=["+join(res.CiphersClientToServer)+"], s2c=["+join(res.CiphersServerToClient)+"]", sshEvidenceMax),
		"macs":                sanitizeProtoBanner("c2s=["+join(res.MACsClientToServer)+"], s2c=["+join(res.MACsServerToClient)+"]", sshEvidenceMax),
		"compression":         sanitizeProtoBanner("c2s=["+join(res.CompressionC2S)+"], s2c=["+join(res.CompressionS2C)+"]", sshEvidenceMax),
	}
	mk := func(signal, title, desc string, sev plugin.Severity, weak []string, reason string) Finding {
		ev := make(map[string]string, len(base)+2)
		for k, v := range base {
			ev[k] = v
		}
		ev["signal"] = signal
		ev["weak_algorithms"] = sanitizeProtoBanner(strings.Join(weak, ","), sshEvidenceMax)
		ev["weakness"] = reason
		return Finding{
			RuleID: "GASH-054", CWE: "CWE-327", Title: title, Desc: desc,
			Severity: sev, Confidence: plugin.ConfidenceFirm,
			Target: target, PluginID: "proto-ssh-handshake", OracleName: "ssh",
			Evidence: ev,
			Note:     "KEXINIT algoritma gözlemi (sürüm değişimi + beyan); anahtar değişimi tamamlanmadı, kimlik doğrulama yok",
			Tags:     []string{"ssh", "crypto", "protocol"},
		}
	}
	var out []Finding
	if weak, reason, sev := collectSSHWeakList("kex", res.KexAlgorithms); len(weak) > 0 {
		out = append(out, mk("ssh-weak-kex", "SSH zayıf anahtar değişimi (KEX) algoritmaları",
			"Sunucu SHA-1/1024-bit tabanlı KEX algoritmaları öneriyor ("+reason+"); modern olanlar tercih edilmeli.",
			sev, weak, reason))
	}
	if weak, reason, sev := collectSSHWeakList("hostkey", res.HostKeyAlgorithms); len(weak) > 0 {
		out = append(out, mk("ssh-weak-hostkey", "SSH zayıf host key algoritmaları",
			"Sunucu ssh-dss/ssh-rsa (SHA-1) host key algoritmaları öneriyor ("+reason+"); ed25519/ecdsa/rsa-sha2 tercih edilmeli.",
			sev, weak, reason))
	}
	if weak, reason, sev := collectSSHWeakList("cipher", res.CiphersClientToServer, res.CiphersServerToClient); len(weak) > 0 {
		out = append(out, mk("ssh-weak-cipher", "SSH zayıf şifre algoritmaları",
			"Sunucu CBC/3DES/RC4/plaintext sınıfı şifreler öneriyor ("+reason+"); AES-CTR/GCM veya ChaCha20 tercih edilmeli.",
			sev, weak, reason))
	}
	if weak, reason, sev := collectSSHWeakList("mac", res.MACsClientToServer, res.MACsServerToClient); len(weak) > 0 {
		out = append(out, mk("ssh-weak-mac", "SSH zayıf MAC algoritmaları",
			"Sunucu MD5/SHA-1/umac-64 sınıfı MAC'ler öneriyor ("+reason+"); ETM-SHA2 ailesi tercih edilmeli.",
			sev, weak, reason))
	}
	return out
}

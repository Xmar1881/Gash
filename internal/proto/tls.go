// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Modül: github.com/Xmar1881/Gash

package proto

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Xmar1881/Gash/internal/plugin"
)

// TLSResult sertifika/zincir/protokol gözlemidir.
// Faz 2: sertifika/zincir olguları (anahtar, imza, SAN, zincir durumu) AYNI
// el sıkışmadan yerel olarak türetilir; ek dial YOKTUR. Yeni alanlar geriye
// dönük uyumludur (eski kurucular/testler çalışmaya devam eder).
type TLSResult struct {
	Host        string
	Port        string
	Version     uint16 // görüşülen TLS sürümü (örn. tls.VersionTLS13)
	Cipher      uint16
	LeafSubject string
	LeafIssuer  string
	LeafCN      string
	NotBefore   time.Time
	NotAfter    time.Time
	DaysLeft    int
	Expired     bool // notAfter geçmiş (kesin zaman karşılaştırması; gün kesmesi değil)
	Expiring    bool // dolmamış ama 30 gün içinde dolacak
	ChainLen    int
	SelfSigned  bool
	HostnameErr string // hostname doğrulama hatası (boşsa eşleşti)
	// Faz 2 sertifika olguları (yerel türetim; iptal kontrolü YOK).
	ValidityDays  int // notBefore..notAfter tam gün sayısı
	LeafKeyAlgo   string
	LeafKeyBits   int
	LeafSigAlgo   string
	LeafIsCA      bool
	DNSNamesCount int
	HasSAN        bool
	WildcardNames []string
	// ChainStatus: "verified" | "untrusted" | "incomplete" | "invalid" | "".
	// Sistem kökleri + sunucunun gönderdiği ara sertifikalarla yerel doğrulama.
	ChainStatus string
	ChainErr    string
}

// CheckTLS hedefe salt-gözlem TLS el sıkışması yapar (veri gönderilmez).
// What: tls.Dial + InsecureSkipVerify ile gözlem, ardından yerel doğrulama
// (süre/zincir/hostname/TLS sürümü). Bağlantı hemen kapatılır.
// Why: InsecureSkipVerify burada güvensizlik değil gözlem yöntemidir: zinciri
// reddetmek yerine inceler; karar yerel kurallarla verilir (süre matematiği deterministiktir).
func CheckTLS(ctx context.Context, addr string, o Options) (*TLSResult, error) {
	host, port, err := splitHostPort(addr)
	if err != nil {
		return nil, err
	}
	if err := o.checkAllowed(host); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, o.timeout())
	defer cancel()
	dialer := &net.Dialer{Timeout: o.timeout()}
	raw, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(host, port))
	if err != nil {
		return nil, fmt.Errorf("proto tls %s: %w", addr, err)
	}
	conn := tls.Client(raw, &tls.Config{
		InsecureSkipVerify: true, // gözlem amaçlı; doğrulama aşağıda yereldir
		ServerName:         host,
	})
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(o.timeout()))
	// Tek el sıkışma (tls.Dial denenmez — çift handshake renegotiation üretir).
	if err := conn.HandshakeContext(ctx); err != nil {
		return nil, fmt.Errorf("proto tls handshake %s: %w", addr, err)
	}
	st := conn.ConnectionState()
	return buildTLSResult(host, port, &st, o.now()), nil
}

// buildTLSResult ConnectionState'ten saf sonuç üretir (ağsız, test edilebilir).
func buildTLSResult(host, port string, st *tls.ConnectionState, now time.Time) *TLSResult {
	r := &TLSResult{Host: host, Port: port, Version: st.Version, Cipher: st.CipherSuite, ChainLen: len(st.PeerCertificates)}
	if len(st.PeerCertificates) > 0 {
		leaf := st.PeerCertificates[0]
		r.LeafSubject = leaf.Subject.String()
		r.LeafIssuer = leaf.Issuer.String()
		r.LeafCN = leaf.Subject.CommonName
		r.NotBefore = leaf.NotBefore
		r.NotAfter = leaf.NotAfter
		r.DaysLeft = int(leaf.NotAfter.Sub(now).Hours() / 24)
		r.Expired = now.After(leaf.NotAfter)
		r.Expiring = !r.Expired && leaf.NotAfter.Sub(now) <= 30*24*time.Hour
		r.SelfSigned = leaf.Subject.String() == leaf.Issuer.String() && len(st.PeerCertificates) == 1 && !leaf.IsCA
		if err := leaf.VerifyHostname(host); err != nil {
			r.HostnameErr = err.Error()
		}
		// Faz 2: sertifika/zincir olguları aynı el sıkışmadan yerel türetilir.
		r.ValidityDays = certValidityDays(leaf)
		r.LeafKeyAlgo = leaf.PublicKeyAlgorithm.String()
		r.LeafKeyBits = certKeyBits(leaf)
		r.LeafSigAlgo = leaf.SignatureAlgorithm.String()
		r.LeafIsCA = leaf.IsCA
		r.DNSNamesCount = len(leaf.DNSNames)
		r.HasSAN = certHasSAN(leaf)
		r.WildcardNames = wildcardSANs(leaf)
		r.ChainStatus, r.ChainErr = classifyChainStatus(leaf, st.PeerCertificates[1:], systemCertPool(), now)
	}
	return r
}

// --- Faz 2: TLS sertifika/zincir derin sınıflandırma (GASH-024) ---
//
// Sınır sözleşmesi: tüm sınıflandırma gözlenen el sıkışma üzerinde YEREL
// hesaplamadır (ek dial yok, veri gönderilmez). İptal kontrolü (OCSP/CRL)
// YAPILMAZ; "untrusted" sınıfı yalnızca yerel sistem kökleri + sunucunun
// gönderdiği ara sertifikalarla doğrulama sonucudur.

// tlsDeepEvidenceMax kanıta taşınan hata/dize tavanıdır.
const tlsDeepEvidenceMax = 300

// sistem kök deposu süreç başına bir kez yüklenir (deterministik önbellek).
var (
	systemRootsOnce sync.Once
	systemRoots     *x509.CertPool
)

// systemCertPool sistem köklerini döner (yüklenemezse nil → Verify sistem
// varsayılanını kullanır; çağıran asla panic görmez).
func systemCertPool() *x509.CertPool {
	systemRootsOnce.Do(func() { systemRoots, _ = x509.SystemCertPool() })
	return systemRoots
}

// certValidityDays notBefore..notAfter tam gün sayısıdır (saf).
func certValidityDays(cert *x509.Certificate) int {
	if cert == nil || cert.NotBefore.IsZero() || cert.NotAfter.IsZero() {
		return 0
	}
	return int(cert.NotAfter.Sub(cert.NotBefore).Hours() / 24)
}

// certKeyBits açık anahtar bit uzunluğunu döner (saf; bilinmiyorsa 0).
func certKeyBits(cert *x509.Certificate) int {
	if cert == nil || cert.PublicKey == nil {
		return 0
	}
	switch pub := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		if pub.N != nil {
			return pub.N.BitLen()
		}
	case *ecdsa.PublicKey:
		if pub.Curve != nil {
			return pub.Curve.Params().BitSize
		}
	case ed25519.PublicKey:
		return 256
	}
	return 0
}

// certHasSAN sertifikada herhangi bir SAN girişi var mı (saf).
func certHasSAN(cert *x509.Certificate) bool {
	if cert == nil {
		return false
	}
	return len(cert.DNSNames) > 0 || len(cert.IPAddresses) > 0 ||
		len(cert.EmailAddresses) > 0 || len(cert.URIs) > 0
}

// wildcardSANs yıldızlı DNS SAN adlarını döner (saf).
func wildcardSANs(cert *x509.Certificate) []string {
	if cert == nil {
		return nil
	}
	var out []string
	for _, n := range cert.DNSNames {
		if strings.HasPrefix(n, "*.") {
			out = append(out, n)
		}
	}
	return out
}

// broadWildcards TLD'yi veya *'dan sonra ≤1 etiketi kapsayan geniş
// joker adları döner (örn. *.com, *.io, bozuk *.). Çok etiketli jokerler
// ( *.example.com, *.co.uk ) bu kurala göre geniş SAYILMAZ (saf fonksiyon).
func broadWildcards(names []string) []string {
	var out []string
	for _, n := range names {
		suffix, ok := strings.CutPrefix(n, "*.")
		if !ok {
			continue
		}
		labels := 0
		for _, part := range strings.Split(suffix, ".") {
			if strings.TrimSpace(part) != "" {
				labels++
			}
		}
		if labels <= 1 {
			out = append(out, n)
		}
	}
	return out
}

// weakKeyReason açık anahtar algoritması/bit uzunluğunu sınıflandırır (saf).
// What: RSA < 2048 → high; ECDSA < 256 → medium; DSA (her boy) → high;
// Ed25519/RSA≥2048/ECDSA≥256/eksik bilgi → sessiz.
// Why: CVE iddiası yok; yalnızca anahtar gücü ailesi raporlanır. Bit
// uzunluğu bilinmiyorsa (0) asla zayıf VARSAYILMAZ (FP yok).
func weakKeyReason(cert *x509.Certificate) (string, plugin.Severity) {
	if cert == nil {
		return "", ""
	}
	switch cert.PublicKeyAlgorithm {
	case x509.RSA:
		if bits := certKeyBits(cert); bits > 0 && bits < 2048 {
			return "rsa-small", plugin.SeverityHigh
		}
	case x509.ECDSA:
		if bits := certKeyBits(cert); bits > 0 && bits < 256 {
			return "ecdsa-small", plugin.SeverityMedium
		}
	case x509.DSA:
		return "dsa-key", plugin.SeverityHigh
	}
	return "", ""
}

// weakSignatureReason MD5/SHA-1 imza algoritmalarını sınıflandırır (saf).
func weakSignatureReason(cert *x509.Certificate) (string, plugin.Severity) {
	if cert == nil {
		return "", ""
	}
	switch cert.SignatureAlgorithm {
	case x509.MD2WithRSA:
		return "md2-signature", plugin.SeverityMedium
	case x509.MD5WithRSA:
		return "md5-signature", plugin.SeverityMedium
	case x509.SHA1WithRSA, x509.DSAWithSHA1, x509.ECDSAWithSHA1:
		return "sha1-signature", plugin.SeverityMedium
	}
	return "", ""
}

// classifyChainStatus yaprak sertifikayı sistem kökleri + sunucunun
// gönderdiği ara sertifikalarla yerel doğrular (saf; ağsız).
// What: nil hata → "verified"; UnknownAuthorityError → zincirde ara
// sertifika eksikse "incomplete", aksi halde "untrusted";
// CertificateInvalidError ve diğer hatalar → "invalid".
// Why: Yerel doğrulama deterministiktir ama sistem kök deposuna bağlıdır;
// iptal (OCSP/CRL) kontrol edilmez, bu yüzden sınıf kanıtı ham hata metniyle
// birlikte taşınır (yorum değil olgu).
func classifyChainStatus(leaf *x509.Certificate, chain []*x509.Certificate, roots *x509.CertPool, now time.Time) (string, string) {
	if leaf == nil {
		return "", ""
	}
	intermediates := x509.NewCertPool()
	for _, c := range chain {
		if c != nil {
			intermediates.AddCert(c)
		}
	}
	_, err := leaf.Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		CurrentTime:   now,
	})
	if err == nil {
		return "verified", ""
	}
	var unknown x509.UnknownAuthorityError
	if errors.As(err, &unknown) {
		if chainMissingIssuer(leaf, chain) {
			return "incomplete", err.Error()
		}
		return "untrusted", err.Error()
	}
	return "invalid", err.Error()
}

// chainMissingIssuer yaprağın issuer'ını zincirde bulamıyorsa true döner
// (öz-imzalı hariç) — eksik ara sertifika göstergesidir (saf).
func chainMissingIssuer(leaf *x509.Certificate, chain []*x509.Certificate) bool {
	if leaf.Subject.String() == leaf.Issuer.String() {
		return false
	}
	for _, c := range chain {
		if c != nil && c.Subject.String() == leaf.Issuer.String() {
			return false
		}
	}
	return true
}

// weakKeyReasonName sınıflandırmayı TLSResult alanlarından yapar (saf sarmalayıcı).
func weakKeyReasonName(algo string, bits int) (string, plugin.Severity) {
	switch strings.ToUpper(strings.TrimSpace(algo)) {
	case "RSA":
		if bits > 0 && bits < 2048 {
			return "rsa-small", plugin.SeverityHigh
		}
	case "ECDSA":
		if bits > 0 && bits < 256 {
			return "ecdsa-small", plugin.SeverityMedium
		}
	case "DSA":
		return "dsa-key", plugin.SeverityHigh
	}
	return "", ""
}

// weakSignatureReasonName sınıflandırmayı imza etiketiyle yapar (saf sarmalayıcı).
func weakSignatureReasonName(algo string) (string, plugin.Severity) {
	n := strings.ToUpper(strings.TrimSpace(algo))
	switch {
	case strings.Contains(n, "MD2"):
		return "md2-signature", plugin.SeverityMedium
	case strings.Contains(n, "MD5"):
		return "md5-signature", plugin.SeverityMedium
	case strings.Contains(n, "SHA1"):
		return "sha1-signature", plugin.SeverityMedium
	}
	return "", ""
}

// TLSDeepFindings sertifika/zincir olgularından bulgu üretir (GASH-024).
// What: Yalnızca Faz 2 sinyalleri: zayıf anahtar/imza, yaprak CA, güvensiz/
// eksik zincir, CN-only (SAN yok), geniş joker, uzun geçerlilik. Mevcut
// GASH-024 bulguları (expired/expiring/self-signed/hostname/version/cipher)
// TEKRARLANMAZ; self-signed zincirde tls-untrusted-chain üretilmez.
// Why: Hepsi gözlenen sertifikanın yerel/deterministik olgusudur →
// confirmed; iptal kontrolü yoktur (OCSP/CRL), bu not kanıta taşınır.
func TLSDeepFindings(target string, r *TLSResult) []Finding {
	if r == nil {
		return nil
	}
	base := map[string]string{
		"host":           r.Host,
		"port":           r.Port,
		"tls_version":    versionName(r.Version),
		"cipher":         fmt.Sprintf("0x%04x", r.Cipher),
		"subject":        r.LeafSubject,
		"issuer":         r.LeafIssuer,
		"not_before":     r.NotBefore.UTC().Format(time.RFC3339),
		"not_after":      r.NotAfter.UTC().Format(time.RFC3339),
		"validity_days":  strconv.Itoa(r.ValidityDays),
		"chain_len":      strconv.Itoa(r.ChainLen),
		"chain_status":   r.ChainStatus,
		"self_signed":    strconv.FormatBool(r.SelfSigned),
		"key_algo":       r.LeafKeyAlgo,
		"key_bits":       strconv.Itoa(r.LeafKeyBits),
		"sig_algo":       r.LeafSigAlgo,
		"leaf_is_ca":     strconv.FormatBool(r.LeafIsCA),
		"dns_names":      strconv.Itoa(r.DNSNamesCount),
		"has_san":        strconv.FormatBool(r.HasSAN),
		"wildcard_names": sanitizeProtoBanner(strings.Join(r.WildcardNames, ","), tlsDeepEvidenceMax),
	}
	mk := func(signal, title, desc, cwe string, sev plugin.Severity, extra map[string]string) Finding {
		ev := make(map[string]string, len(base)+len(extra))
		for k, v := range base {
			ev[k] = v
		}
		for k, v := range extra {
			ev[k] = v
		}
		ev["signal"] = signal
		return Finding{
			RuleID: "GASH-024", CWE: cwe, Title: title, Desc: desc,
			Severity: sev, Confidence: plugin.ConfidenceConfirmed,
			Target: target, PluginID: "proto-tls-deep", OracleName: "tls",
			Evidence: ev,
			Note:     "yerel sertifika/zincir sınıflandırması (aynı el sıkışma); iptal (OCSP/CRL) kontrol edilmedi",
			Tags:     []string{"tls", "certificate", "crypto"},
		}
	}
	var out []Finding
	if reason, sev := weakKeyReasonName(r.LeafKeyAlgo, r.LeafKeyBits); reason != "" {
		out = append(out, mk("tls-weak-key",
			"TLS zayıf sertifika anahtarı ("+r.LeafKeyAlgo+" "+strconv.Itoa(r.LeafKeyBits)+" bit)",
			"Sertifika açık anahtarı kırılgan sınıfta ("+reason+"); en az RSA 2048 / ECDSA 256 bit kullanılmalı.",
			"CWE-326", sev, map[string]string{"weakness": reason}))
	}
	if reason, sev := weakSignatureReasonName(r.LeafSigAlgo); reason != "" {
		out = append(out, mk("tls-weak-signature",
			"TLS sertifikası zayıf imza algoritması ("+r.LeafSigAlgo+")",
			"Sertifika MD5/SHA-1 tabanlı imza kullanıyor ("+reason+"); çakışma saldırılarına açıktır (CWE-327).",
			"CWE-327", sev, map[string]string{"weakness": reason}))
	}
	if r.LeafIsCA {
		out = append(out, mk("tls-leaf-is-ca",
			"TLS yaprak sertifikası CA:TRUE",
			"Sunucunun yaprak sertifikası CA olarak işaretli; yanlış üretilmiş sertifika anahtarını imzalayabilir (CWE-295).",
			"CWE-295", plugin.SeverityHigh, nil))
	}
	if !r.SelfSigned && (r.ChainStatus == "untrusted" || r.ChainStatus == "incomplete") {
		out = append(out, mk("tls-untrusted-chain",
			"TLS sertifika zinciri doğrulanamadı ("+r.ChainStatus+")",
			"Zincir sistem kökleriyle doğrulanamadı (eksik ara sertifika veya güvenilmeyen kök); "+
				"istemciler bağlantıyı reddedebilir veya MITM riski oluşur (CWE-295).",
			"CWE-295", plugin.SeverityMedium, map[string]string{
				"chain_err": sanitizeProtoBanner(r.ChainErr, tlsDeepEvidenceMax),
			}))
	}
	if !r.HasSAN && strings.TrimSpace(r.LeafCN) != "" {
		out = append(out, mk("tls-no-san",
			"TLS sertifikasında SAN yok (yalnızca CN)",
			"Sertifika kimliğini SAN yerine CN ile taşıyor; RFC 6125 CN kullanımını kullanımdan kaldırmıştır.",
			"CWE-295", plugin.SeverityLow, map[string]string{"leaf_cn": sanitizeProtoBanner(r.LeafCN, 128)}))
	}
	if broad := broadWildcards(r.WildcardNames); len(broad) > 0 {
		out = append(out, mk("tls-wildcard-broad",
			"TLS sertifikasında geniş joker SAN ("+strings.Join(broad, ",")+")",
			"Joker SAN TLD'yi veya tek etiketi kapsıyor; neredeyse tüm alan adları için geçerli olur (CWE-295).",
			"CWE-295", plugin.SeverityLow, map[string]string{
				"broad_wildcards": sanitizeProtoBanner(strings.Join(broad, ","), tlsDeepEvidenceMax),
			}))
	}
	if r.ValidityDays > 398 {
		out = append(out, mk("tls-long-validity",
			"TLS sertifikası geçerlilik süresi 398 günden uzun ("+strconv.Itoa(r.ValidityDays)+" gün)",
			"Uzun geçerlilik süresi iptal/rotasyon disiplinini zayıflatır; tarayıcı politikası 398 günle sınırlar.",
			"CWE-295", plugin.SeverityLow, nil))
	}
	return out
}

// versionName TLS sürüm etiketi.
func versionName(v uint16) string {
	switch v {
	case tls.VersionTLS13:
		return "TLS1.3"
	case tls.VersionTLS12:
		return "TLS1.2"
	case tls.VersionTLS11:
		return "TLS1.1"
	case tls.VersionTLS10:
		return "TLS1.0"
	case 0x0300: // SSL3.0 (deprecated sembol yerine sayısal; kırık kabul edilir)
		return "SSL3.0"
	default:
		return fmt.Sprintf("unknown(0x%04x)", v)
	}
}

// versionSignal eski sürüm sinyal adıdır (tls10/tls11; diğerleri old-version).
// What: Sürüm bulgusu tekildir; sinyal ayrımı rapor/regresyon ağını netleştirir.
// Why: TLS 1.0 ve 1.1 ayrı sinyaller olarak izlenir; bilinmeyen/kırık
// sürümler (örn. SSL3.0) genel sinyale düşer (bulgu kaybolmaz).
func versionSignal(v uint16) string {
	switch v {
	case tls.VersionTLS10:
		return "tls10"
	case tls.VersionTLS11:
		return "tls11"
	default:
		return "old-version"
	}
}

// weakCipherReason görüşülen şifre takımını sınıflandırır (saf fonksiyon).
// What: NULL/anonim-DH/export/RC4 → high; 3DES/DES → medium; modern → boş.
// Why: Sınıflandırma ağsız test edilebilir; CVE iddiası yoktur, yalnızca
// takım adındaki kırılgan aile sinyali raporlanır.
func weakCipherReason(name string) (string, plugin.Severity) {
	n := strings.ToUpper(strings.TrimSpace(name))
	switch {
	case strings.Contains(n, "NULL"):
		return "null-cipher", plugin.SeverityHigh
	case strings.Contains(n, "ANON") || strings.Contains(n, "ADH") || strings.Contains(n, "AECDH"):
		return "anonymous-dh", plugin.SeverityHigh
	case strings.Contains(n, "EXPORT"):
		return "export-cipher", plugin.SeverityHigh
	case strings.Contains(n, "RC4"):
		return "rc4-cipher", plugin.SeverityHigh
	case strings.Contains(n, "3DES"):
		return "3des-cipher", plugin.SeverityMedium
	case strings.Contains(n, "DES"):
		return "des-cipher", plugin.SeverityMedium
	default:
		return "", ""
	}
}

// TLSFindings gözlemden bulgu üretir (GASH-024, CWE-295/327).
// What: expired → high/confirmed; ≤30 gün → medium/confirmed; self-signed veya
// hostname uyumsuzluğu → high/confirmed; TLS<1.2 → tek bulgu (tls10/tls11
// sinyali) medium/confirmed; zayıf şifre takımı → high/medium/confirmed.
// Why: Hepsi görüşülen/gözlenen deterministik olgudur (tek-kanal ama kesin).
func TLSFindings(target string, r *TLSResult) []Finding {
	base := map[string]string{
		"tls_version":  versionName(r.Version),
		"cipher":       fmt.Sprintf("0x%04x", r.Cipher),
		"subject":      r.LeafSubject,
		"issuer":       r.LeafIssuer,
		"not_after":    r.NotAfter.UTC().Format(time.RFC3339),
		"days_left":    fmt.Sprintf("%d", r.DaysLeft),
		"chain_len":    fmt.Sprintf("%d", r.ChainLen),
		"self_signed":  fmt.Sprintf("%v", r.SelfSigned),
		"hostname_err": r.HostnameErr,
	}
	mk := func(title, desc string, sev plugin.Severity, extra map[string]string) Finding {
		ev := make(map[string]string, len(base)+len(extra))
		for k, v := range base {
			ev[k] = v
		}
		for k, v := range extra {
			ev[k] = v
		}
		return Finding{
			RuleID: "GASH-024", CWE: "CWE-295", Title: title, Desc: desc,
			Severity: sev, Confidence: plugin.ConfidenceConfirmed,
			Target: target, PluginID: "proto-tls-cert", OracleName: "tls",
			Evidence: ev, Note: "pasif TLS gözlemi (el sıkışma); kontrol kanalı yok",
			Tags: []string{"tls", "certificate", "misconfig"},
		}
	}
	var out []Finding
	if r.Expired {
		out = append(out, mk("TLS sertifikası süresi dolmuş",
			"Sertifika notAfter tarihi geçmiş; istemciler bağlantıyı reddeder (DoS riski).",
			plugin.SeverityHigh, map[string]string{"signal": "expired"}))
	} else if r.Expiring {
		out = append(out, mk("TLS sertifikası 30 gün içinde doluyor",
			"Yenileme penceresi kritik; dolarsa kesinti olur.",
			plugin.SeverityMedium, map[string]string{"signal": "expiring"}))
	}
	if r.SelfSigned {
		out = append(out, mk("TLS self-signed sertifika",
			"Zincir tek eleman ve öz-imzalı; istemci güveni yok (MITM riski).",
			plugin.SeverityHigh, map[string]string{"signal": "self-signed"}))
	}
	if strings.TrimSpace(r.HostnameErr) != "" {
		out = append(out, mk("TLS hostname uyumsuzluğu",
			"Sertifika hedef host adını doğrulamıyor.",
			plugin.SeverityHigh, map[string]string{"signal": "hostname-mismatch"}))
	}
	if r.Version < tls.VersionTLS12 {
		// Tek sürüm bulgusu: TLS 1.0 → tls10, TLS 1.1 → tls11 (yinelenmez).
		f := mk("TLS eski protokol sürümü ("+versionName(r.Version)+")",
			"TLS 1.2 altı sürümler zayıf kabul edilir (CWE-327).",
			plugin.SeverityMedium, map[string]string{"signal": versionSignal(r.Version)})
		f.CWE = "CWE-327"
		out = append(out, f)
	}
	if name := tls.CipherSuiteName(r.Cipher); name != "" {
		if reason, sev := weakCipherReason(name); reason != "" {
			f := mk("TLS zayıf şifre takımı ("+name+")",
				"Görüşülen şifre takımı kırılgan sınıfta ("+reason+"); CWE-327.",
				sev, map[string]string{
					"signal":          "weak-cipher",
					"cipher_name":     name,
					"cipher_weakness": reason,
				})
			f.CWE = "CWE-327"
			out = append(out, f)
		}
	}
	return out
}

// TLSVersionSupport tek eski sürüm probunun sonucudur.
type TLSVersionSupport struct {
	Version  uint16
	Name     string
	Accepted bool
	// Outcome: "accepted" | "rejected" | "unknown" (istemci/sunucu ortamı
	// nedeniyle belirsiz kalan sonuçlar sessizce yutulmaz, "unknown" kalır).
	Outcome string
	Err     string
}

// TLSAuditResult eski sürüm kabul gözlemidir (TLS 1.0/1.1).
type TLSAuditResult struct {
	Host   string
	Port   string
	Probes []TLSVersionSupport
}

// classifyLegacyHandshake tek el sıkışma hatasını sınıflandırır (saf fonksiyon).
// What: nil → accepted; uzak "protocol version" reddi → rejected; diğer
// hatalar (istemci tarafı sürüm engeli, timeout, dial) → unknown.
// Why: Go bazı yapılandırmalarda eski istemci sürümünü kendisi reddedebilir;
// bu durum sunucu hakkında bilgi vermez ve yanlış bulguya dönüşmemelidir.
func classifyLegacyHandshake(err error) string {
	if err == nil {
		return "accepted"
	}
	msg := strings.ToLower(err.Error())
	if strings.Contains(msg, "protocol version") {
		return "rejected"
	}
	return "unknown"
}

// CheckTLSVersionSupport eski TLS sürümlerini tek tek yoklar (yalnızca gözlem).
// What: Her sürüm için ayrı dial + MinVersion=MaxVersion el sıkışması; veri
// gönderilmez, sertifika doğrulanmaz (gözlem yöntemi), bağlantı hemen kapanır.
// Why: Eski sürüm kabulü downgrade yüzeyidir; kabul deterministik bir el
// sıkışma olgusudur. İstemci/sunucu ortamı engellerse "unknown" kaydedilir —
// asla panic yok, asla sahte "rejected" yok.
func CheckTLSVersionSupport(ctx context.Context, addr string, o Options) (*TLSAuditResult, error) {
	host, port, err := splitHostPort(addr)
	if err != nil {
		return nil, err
	}
	if err := o.checkAllowed(host); err != nil {
		return nil, err
	}
	out := &TLSAuditResult{Host: host, Port: port}
	for _, v := range []uint16{tls.VersionTLS10, tls.VersionTLS11} {
		out.Probes = append(out.Probes, probeLegacyTLS(ctx, host, port, v, o))
	}
	return out, nil
}

// probeLegacyTLS tek eski sürümü yoklar; her hata yolu sınıflandırılmış döner.
func probeLegacyTLS(ctx context.Context, host, port string, v uint16, o Options) (res TLSVersionSupport) {
	res = TLSVersionSupport{Version: v, Name: versionName(v), Outcome: "unknown"}
	defer func() {
		// Teorik panic (gelecekteki stdlib değişimi): gözlem "unknown" kalır.
		if r := recover(); r != nil {
			res.Accepted = false
			res.Outcome = "unknown"
			res.Err = fmt.Sprintf("panic: %v", r)
		}
	}()
	cctx, cancel := context.WithTimeout(ctx, o.timeout())
	defer cancel()
	dialer := &net.Dialer{Timeout: o.timeout()}
	raw, err := dialer.DialContext(cctx, "tcp", net.JoinHostPort(host, port))
	if err != nil {
		res.Err = err.Error()
		res.Outcome = classifyLegacyHandshake(err)
		return res
	}
	conn := tls.Client(raw, &tls.Config{
		InsecureSkipVerify: true, // gözlem amaçlı; kabul/red kararı yerel kurallarla
		ServerName:         host,
		MinVersion:         v,
		MaxVersion:         v,
	})
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(o.timeout()))
	err = conn.HandshakeContext(cctx)
	res.Outcome = classifyLegacyHandshake(err)
	res.Accepted = err == nil
	if err != nil {
		res.Err = err.Error()
	}
	return res
}

// TLSAuditFindings derin sürüm denetiminden bulgu üretir (GASH-024, CWE-327).
// What: Kabul edilen her eski sürüm (TLS 1.0/1.1) için tek medium/confirmed bulgu.
// Why: El sıkışma kabulü deterministiktir (TLS disiplini → confirmed); red ve
// "unknown" sonuçlar bulgu üretmez (FP yok).
func TLSAuditFindings(target string, r *TLSAuditResult) []Finding {
	if r == nil {
		return nil
	}
	var out []Finding
	for _, p := range r.Probes {
		if !p.Accepted {
			continue
		}
		out = append(out, Finding{
			RuleID: "GASH-024", CWE: "CWE-327",
			Title:    "TLS eski sürüm desteği açık (" + p.Name + ")",
			Desc:     p.Name + " sunucu tarafından hala kabul ediliyor; istemciler bu sürüme düşürülebilir (downgrade).",
			Severity: plugin.SeverityMedium, Confidence: plugin.ConfidenceConfirmed,
			Target: target, PluginID: "proto-tls-deep", OracleName: "tls",
			Evidence: map[string]string{
				"host":        r.Host,
				"port":        r.Port,
				"tls_version": p.Name,
				"signal":      versionSignal(p.Version) + "-supported",
				"outcome":     p.Outcome,
			},
			Note: "aktif el sıkışma gözlemi (yalnızca eski sürüm kabulü); veri gönderilmedi",
			Tags: []string{"tls", "protocol", "misconfig"},
		})
	}
	return out
}

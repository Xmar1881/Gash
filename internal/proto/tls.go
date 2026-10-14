// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Modül: github.com/Xmar1881/Gash

package proto

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/Xmar1881/Gash/internal/plugin"
)

// TLSResult sertifika/zincir/protokol gözlemidir.
type TLSResult struct {
	Host        string
	Port        string
	Version     uint16 // görüşülen TLS sürümü (örn. tls.VersionTLS13)
	Cipher      uint16
	LeafSubject string
	LeafIssuer  string
	NotAfter    time.Time
	DaysLeft    int
	Expired     bool // notAfter geçmiş (kesin zaman karşılaştırması; gün kesmesi değil)
	Expiring    bool // dolmamış ama 30 gün içinde dolacak
	ChainLen    int
	SelfSigned  bool
	HostnameErr string // hostname doğrulama hatası (boşsa eşleşti)
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
		r.NotAfter = leaf.NotAfter
		r.DaysLeft = int(leaf.NotAfter.Sub(now).Hours() / 24)
		r.Expired = now.After(leaf.NotAfter)
		r.Expiring = !r.Expired && leaf.NotAfter.Sub(now) <= 30*24*time.Hour
		r.SelfSigned = leaf.Subject.String() == leaf.Issuer.String() && len(st.PeerCertificates) == 1 && !leaf.IsCA
		if err := leaf.VerifyHostname(host); err != nil {
			r.HostnameErr = err.Error()
		}
	}
	return r
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

// TLSFindings gözlemden bulgu üretir (GASH-024, CWE-295/327).
// What: expired → high/confirmed; ≤30 gün → medium/confirmed; self-signed veya
// hostname uyumsuzluğu → high/confirmed; TLS<1.2 → medium/confirmed.
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
		f := mk("TLS eski protokol sürümü ("+versionName(r.Version)+")",
			"TLS 1.2 altı sürümler zayıf kabul edilir (CWE-327).",
			plugin.SeverityMedium, map[string]string{"signal": "old-version"})
		f.CWE = "CWE-327"
		out = append(out, f)
	}
	return out
}

// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Modül: github.com/Xmar1881/Gash

// Package proto DNS/TLS/TCP protokol kontrolleridir (P2.1).
// What: Yalnızca pasif gözlem + güvenli aktif problar (okuma, el sıkışma, DNS sorgusu).
// Why: Safe profil pasif kalmalı; yıkıcı kontrol YOK, kapsam-dışı istek YOK.
//
// Güvenlik sınırları (bilerek YOK):
//   - DNS zone transfer (AXFR) denemesi YOK — yalnızca okuma sorguları (A/AAAA/TXT/CAA).
//   - Sertifika yazma/yenileme, veri gönderen TCP payload'u, banner-dışı etkileşim YOK.
//   - Her kontrol kapsam izni ister (AllowHost nil ise kapalı → fail-closed).
//   - Güven tavanı: TLS deterministik gözlem → confirmed; DNS çözümleyici-bağımlı → firm;
//     TCP banner tek başına zayıf sinyal → tentative.
package proto

import (
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/Xmar1881/Gash/internal/finding"
	"github.com/Xmar1881/Gash/internal/plugin"
)

// AllowHost kapsam kararıdır (host → izinli mi). Nil = kapalı (fail-closed).
type AllowHost func(host string) bool

// Options tüm protokol kontrollerinin ortak sınırıdır.
type Options struct {
	// Timeout her kontrolün üst sınırı (0 ise 10s).
	Timeout time.Duration
	// Allow kapsam kararı; nil ise kontrol çalışmaz (fail-closed).
	Allow AllowHost
	// Now saat enjeksiyonu (test determinizmi); nil ise time.Now.
	Now func() time.Time
	// Resolve DNS çözümleyici enjeksiyonu (test determinizmi); nil ise net.DefaultResolver.
	Resolve func(host string) ([]net.IP, error)
	// LookupTXT TXT kaydı enjeksiyonu (SPF/DMARC); nil ise net.LookupTXT.
	LookupTXT func(name string) ([]string, error)
	// LookupCAA CAA kaydı enjeksiyonu (test determinizmi); nil ise miekg/dns
	// ile wire sorgu (yalnızca okuma, TypeCAA; AXFR yok).
	LookupCAA func(host string) ([]CAARecord, error)
	// CAAServer CAA wire sorgusunun hedefi (host:port); boşsa sistem
	// çözümleyicisi (/etc/resolv.conf → GASH_DNS_SERVER → 8.8.8.8:53).
	CAAServer string
}

func (o Options) timeout() time.Duration {
	if o.Timeout <= 0 {
		return 10 * time.Second
	}
	return o.Timeout
}

func (o Options) now() time.Time {
	if o.Now != nil {
		return o.Now()
	}
	return time.Now()
}

// checkAllowed kapsamı doğrular (fail-closed).
func (o Options) checkAllowed(host string) error {
	h := strings.ToLower(strings.TrimSpace(host))
	if h == "" {
		return fmt.Errorf("proto: boş host: %w", plugin.ErrScopeViolation)
	}
	if o.Allow == nil {
		return fmt.Errorf("proto: kapsam kararı yok (fail-closed): %w", plugin.ErrScopeViolation)
	}
	if hostOnly(h) != "" {
		h = hostOnly(h)
	}
	if !o.Allow(h) {
		return fmt.Errorf("proto: host %s kapsam-dışı: %w", h, plugin.ErrScopeViolation)
	}
	return nil
}

// hostOnly "host:port" veya URL'den host çıkarır (saf dize işlemi).
func hostOnly(s string) string {
	if h, _, err := net.SplitHostPort(s); err == nil {
		return strings.ToLower(h)
	}
	return ""
}

// Finding protokol bulgusudur (motor finding.Finding'e dönüşür).
type Finding struct {
	RuleID     string
	CWE        string
	Title      string
	Desc       string
	Severity   plugin.Severity
	Confidence plugin.Confidence
	Target     string
	PluginID   string
	OracleName string
	Evidence   map[string]string
	Note       string
	Tags       []string
}

// ToFinding motor bulgusuna çevirir (fingerprint deterministik).
// What: finding.Fingerprint tek kaynağı kullanılır; ID rastgeledir.
// Why: Dedup/correlation hattı proto bulgularını da tekler.
func (f Finding) ToFinding() *finding.Finding {
	out := &finding.Finding{
		ID:                 "finding_proto",
		RuleID:             f.RuleID,
		CWE:                f.CWE,
		Title:              f.Title,
		Description:        f.Desc,
		Severity:           f.Severity,
		Confidence:         f.Confidence,
		Target:             f.Target,
		Evidence:           f.Evidence,
		Reproducibility:    map[string]string{"repeats": "1", "control": "n/a (pasif gözlem)", "note": f.Note},
		PluginID:           f.PluginID,
		OracleName:         f.OracleName,
		Tags:               append([]string{}, f.Tags...),
		Method:             "proto",
		VerificationMethod: "proto " + f.OracleName + ", repeats=1, control=n/a (pasif gözlem)",
		Note:               f.Note,
	}
	out.Fingerprint = finding.Fingerprint(out)
	return out
}

// splitHostPort host:port ayrıştırır (port yoksa TLS 443 / TCP 80 önerilmez — açık port şart).
func splitHostPort(addr string) (string, string, error) {
	h, p, err := net.SplitHostPort(addr)
	if err != nil {
		return "", "", fmt.Errorf("proto: host:port biçimi gerekli (got %q)", addr)
	}
	if strings.TrimSpace(h) == "" || strings.TrimSpace(p) == "" {
		return "", "", fmt.Errorf("proto: boş host/port (got %q)", addr)
	}
	return h, p, nil
}

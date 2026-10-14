// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Modül: github.com/Xmar1881/Gash

package proto

import (
	"context"
	"fmt"
	"net"
	"strings"

	"github.com/Xmar1881/Gash/internal/plugin"
)

// DNSResult pasif DNS gözlemidir. Zone transfer (AXFR) bilerek YOKTUR:
// bu paket yalnızca okuma sorguları yapar (A/AAAA/TXT).
type DNSResult struct {
	Host       string
	IPs        []net.IP
	SPF        string // v=spf1 kaydı (boşsa yok)
	DMARC      string // _dmarc TXT (boşsa yok)
	TXTRecords []string
}

// CheckDNS hedef domain için pasif DNS kontrolleri yapar.
// What: A/AAAA çözümleme + SPF/DMARC/CAA okuma. IP literal'lerde yalnızca
// çözümleme atlanır (e-posta kayıtları anlamsız) ve kayıt kontrolleri yapılmaz.
// Why: Hepsi okuma sorgusudur; hedefte durum değiştirmez, safe profilde çalışır.
func CheckDNS(ctx context.Context, host string, o Options) (*DNSResult, error) {
	h := strings.ToLower(strings.TrimSpace(host))
	if h == "" {
		return nil, fmt.Errorf("proto: boş host")
	}
	if h != "" && hostOnly(h) != "" {
		h = hostOnly(h)
	}
	if err := o.checkAllowed(h); err != nil {
		return nil, err
	}
	r := &DNSResult{Host: h}
	resolve := o.Resolve
	if resolve == nil {
		resolve = func(host string) ([]net.IP, error) { return net.DefaultResolver.LookupIP(ctx, "ip", host) }
	}
	lookupTXT := o.LookupTXT
	if lookupTXT == nil {
		lookupTXT = func(name string) ([]string, error) { return net.LookupTXT(name) }
	}
	if ip := net.ParseIP(h); ip == nil {
		ips, err := resolve(h)
		if err != nil {
			return nil, fmt.Errorf("proto dns %s: %w", h, err)
		}
		r.IPs = ips
		if txts, err := lookupTXT(h); err == nil {
			r.TXTRecords = txts
			for _, t := range txts {
				if strings.HasPrefix(strings.ToLower(strings.TrimSpace(t)), "v=spf1") {
					r.SPF = t
					break
				}
			}
		}
		if dmarc, err := lookupTXT("_dmarc." + h); err == nil {
			for _, t := range dmarc {
				if strings.HasPrefix(strings.ToLower(strings.TrimSpace(t)), "v=dmarc1") {
					r.DMARC = t
					break
				}
			}
		}
	}
	return r, nil
}

// DNSFindings gözlemden bulgu üretir (GASH-025, CWE-693).
// What: SPF yok → medium/firm; DMARC yok → low/firm.
// Why: Kayıt yokluğu deterministik gözlemdir ama çözümleyici/önbellek bağımlı
// olduğu için tavan firm'dir (confirmed yok).
func DNSFindings(target string, r *DNSResult) []Finding {
	mk := func(title, desc string, sev plugin.Severity, signal string) Finding {
		return Finding{
			RuleID: "GASH-025", CWE: "CWE-693", Title: title, Desc: desc,
			Severity: sev, Confidence: plugin.ConfidenceFirm,
			Target: target, PluginID: "proto-dns-records", OracleName: "dns",
			Evidence: map[string]string{
				"host": r.Host, "spf": r.SPF, "dmarc": r.DMARC, "signal": signal,
			},
			Note: "pasif DNS okuma (AXFR yok); çözümleyici-bağımlı, tavan firm",
			Tags: []string{"dns", "email-security", "misconfig"},
		}
	}
	var out []Finding
	if net.ParseIP(r.Host) != nil {
		return nil // IP literal: e-posta kaydı beklenmez
	}
	if strings.TrimSpace(r.SPF) == "" {
		out = append(out, mk("SPF kaydı yok",
			"Domain SPF yayınlamıyor; e-posta taklidi (spoofing) kolaylaşır.",
			plugin.SeverityMedium, "missing-spf"))
	}
	if strings.TrimSpace(r.DMARC) == "" {
		out = append(out, mk("DMARC kaydı yok",
			"_dmarc kaydı yok; kimlik doğrulama politikası uygulanamaz.",
			plugin.SeverityLow, "missing-dmarc"))
	}
	return out
}

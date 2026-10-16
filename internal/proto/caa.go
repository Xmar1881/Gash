// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Modül: github.com/Xmar1881/Gash

package proto

import (
	"context"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"github.com/Xmar1881/Gash/internal/plugin"
	"github.com/miekg/dns"
)

// CAARecord tek CAA kaydıdır (RFC 8659: flag/tag/value).
type CAARecord struct {
	Flag  uint8
	Tag   string
	Value string
}

// CAAResult CAA pasif gözlemidir. Zone transfer (AXFR) bilerek YOKTUR:
// bu dosya yalnızca TypeCAA okuma sorgusu yapar.
type CAAResult struct {
	Host    string
	Records []CAARecord
	Server  string // sorgulanan DNS sunucusu (kanıt/izlenebilirlik)
}

// caaTimeout CAA sorgusunun üst sınırıdır (en fazla 5s).
// What: Options.Timeout ne olursa olsun tavan 5s; daha küçük değer korunur.
// Why: Kırmızı çizgi — yalnızca-okuma ve timeout'lu; testler kısa deadline
// enjekte eder, üretimde 10s varsayılan 5s'e iner.
func caaTimeout(o Options) time.Duration {
	t := o.timeout()
	if t > 5*time.Second {
		return 5 * time.Second
	}
	return t
}

// caaServerAddr wire sorgunun hedefini seçer (okuma, kapsam-dışı yazma yok).
// What: Açık CAAServer → GASH_DNS_SERVER → /etc/resolv.conf ilk sunucu → 8.8.8.8:53.
// Why: Taşınabilir varsayılan; testler loopback sunucu enjekte eder (dış DNS yok).
func caaServerAddr(explicit string) string {
	if h := strings.TrimSpace(explicit); h != "" {
		if _, _, err := net.SplitHostPort(h); err == nil {
			return h
		}
		return net.JoinHostPort(h, "53")
	}
	if env := strings.TrimSpace(os.Getenv("GASH_DNS_SERVER")); env != "" {
		if _, _, err := net.SplitHostPort(env); err == nil {
			return env
		}
		return net.JoinHostPort(env, "53")
	}
	if cfg, err := dns.ClientConfigFromFile("/etc/resolv.conf"); err == nil && cfg != nil && len(cfg.Servers) > 0 {
		port := strings.TrimSpace(cfg.Port)
		if port == "" {
			port = "53"
		}
		return net.JoinHostPort(cfg.Servers[0], port)
	}
	return "8.8.8.8:53"
}

// CheckCAA hedef domain için CAA okuma sorgusu yapar.
// What: TypeCAA okuma; IP literal'de sorgusuz boş sonuç. NXDOMAIN/timeout/
// SERVFAIL gibi belirsizlikler hata döner (çağıran sessiz geçer, FP yok).
// Why: Hepsi okuma sorgusudur; hedefte durum değiştirmez, safe profilde çalışır.
func CheckCAA(ctx context.Context, host string, o Options) (*CAAResult, error) {
	h := strings.ToLower(strings.TrimSpace(host))
	if h != "" && hostOnly(h) != "" {
		h = hostOnly(h)
	}
	if h == "" {
		return nil, fmt.Errorf("proto: boş host")
	}
	if err := o.checkAllowed(h); err != nil {
		return nil, err
	}
	if net.ParseIP(h) != nil {
		return &CAAResult{Host: h}, nil // IP literal: CAA beklenmez
	}
	if o.LookupCAA != nil {
		recs, err := o.LookupCAA(h)
		if err != nil {
			return nil, fmt.Errorf("proto caa %s: %w", h, err)
		}
		return &CAAResult{Host: h, Records: recs}, nil
	}
	timeout := caaTimeout(o)
	cctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	server := caaServerAddr(o.CAAServer)
	client := &dns.Client{Timeout: timeout}
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(h), dns.TypeCAA)
	resp, _, err := client.ExchangeContext(cctx, msg, server)
	if err != nil {
		return nil, fmt.Errorf("proto caa %s: %w", h, err)
	}
	if resp == nil {
		return nil, fmt.Errorf("proto caa %s: boş yanıt (inconclusive)", h)
	}
	if resp.Truncated {
		tcp := &dns.Client{Net: "tcp", Timeout: timeout}
		resp, _, err = tcp.ExchangeContext(cctx, msg, server)
		if err != nil {
			return nil, fmt.Errorf("proto caa %s: %w", h, err)
		}
		if resp == nil {
			return nil, fmt.Errorf("proto caa %s: boş yanıt (inconclusive)", h)
		}
	}
	switch resp.Rcode {
	case dns.RcodeSuccess:
		// Kayıt varlığı/yokluğu aşağıda ayrışır (NODATA → missing bulgusu).
	default:
		if resp.Rcode == dns.RcodeNameError {
			return nil, fmt.Errorf("proto caa %s: NXDOMAIN (inconclusive)", h)
		}
		name := dns.RcodeToString[resp.Rcode]
		if name == "" {
			name = fmt.Sprintf("rcode=%d", resp.Rcode)
		}
		return nil, fmt.Errorf("proto caa %s: %s (inconclusive)", h, name)
	}
	out := &CAAResult{Host: h, Server: server}
	for _, rr := range resp.Answer {
		if caa, ok := rr.(*dns.CAA); ok {
			out.Records = append(out.Records, CAARecord{Flag: caa.Flag, Tag: caa.Tag, Value: caa.Value})
		}
	}
	return out, nil
}

// caaProblem tek kaydın RFC 8659 ihlalini döndürür (boşsa sağlıklı).
// What: Boş tag, tag'de [a-z0-9] dışı karakter, boş value, iodef'te
// mailto:/http(s): dışı şema → bozuk. Bilinmeyen tag'lere ve flag bitlerine
// dokunulmaz (ileriye-dönük FP yok).
// Why: Dar kural FP üretmez; gevşek yorum belirsizliği sessizliğe iter.
func caaProblem(tag, value string) string {
	t := strings.ToLower(strings.TrimSpace(tag))
	if t == "" {
		return "empty-tag"
	}
	for _, ch := range t {
		if (ch < 'a' || ch > 'z') && (ch < '0' || ch > '9') {
			return "bad-tag"
		}
	}
	v := strings.TrimSpace(value)
	if v == "" {
		return "empty-value"
	}
	if t == "iodef" {
		lv := strings.ToLower(v)
		if !(strings.HasPrefix(lv, "mailto:") || strings.HasPrefix(lv, "http://") || strings.HasPrefix(lv, "https://")) {
			return "bad-iodef"
		}
	}
	return ""
}

// caaSummary kayıtları kanıt dizesine indirir (≤300 karakter hijyeni).
func caaSummary(recs []CAARecord) string {
	parts := make([]string, 0, len(recs))
	for _, r := range recs {
		parts = append(parts, fmt.Sprintf("%d %s %q", r.Flag, strings.ToLower(strings.TrimSpace(r.Tag)), strings.TrimSpace(r.Value)))
	}
	s := strings.Join(parts, "; ")
	if len(s) > 300 {
		s = s[:300]
	}
	return s
}

// CAAFindings gözlemden bulgu üretir (GASH-027, CWE-295).
// What: Kayıt yok → medium/firm; bozuk kayıt → medium/firm; sağlıklı → sessiz.
// IP literal ve nil sonuç bulgusuzdur. NXDOMAIN/timeout buraya ulaşmaz
// (CheckCAA hata döner → çağıran sessiz geçer).
// Why: Kayıt yokluğu/bozukluğu gözlemdir ama çözümleyici-bağımlı olduğu için
// tavan firm'dir (confirmed yok; GASH-025 disiplini).
func CAAFindings(target string, r *CAAResult) []Finding {
	if r == nil {
		return nil
	}
	if net.ParseIP(strings.TrimSpace(r.Host)) != nil {
		return nil // IP literal: CAA beklenmez
	}
	mk := func(title, desc string, sev plugin.Severity, signal, detail string) Finding {
		return Finding{
			RuleID: "GASH-027", CWE: "CWE-295", Title: title, Desc: desc,
			Severity: sev, Confidence: plugin.ConfidenceFirm,
			Target: target, PluginID: "proto-dns-caa", OracleName: "dns",
			Evidence: map[string]string{
				"host": r.Host, "caa": caaSummary(r.Records), "signal": signal, "detail": detail,
			},
			Note: "pasif DNS okuma (CAA, AXFR yok); çözümleyici-bağımlı, tavan firm",
			Tags: []string{"dns", "caa", "certificate", "misconfig"},
		}
	}
	if len(r.Records) == 0 {
		return []Finding{mk("CAA kaydı yok",
			"Domain CAA yayınlamıyor; herhangi bir sertifika yetkilisi (CA) bu ad için sertifika düzenleyebilir.",
			plugin.SeverityMedium, "missing-caa", "no CAA records")}
	}
	var bad []string
	for i, rec := range r.Records {
		if p := caaProblem(rec.Tag, rec.Value); p != "" {
			bad = append(bad, fmt.Sprintf("kayıt %d: %s", i, p))
		}
	}
	if len(bad) > 0 {
		return []Finding{mk("CAA kaydı hatalı",
			"CAA kaydı RFC 8659 biçimini ihlal ediyor; yetkisiz sertifika düzenlenmesine karşı politika uygulanamayabilir.",
			plugin.SeverityMedium, "malformed-caa", strings.Join(bad, "; "))}
	}
	return nil
}

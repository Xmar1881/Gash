// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Modül: github.com/Xmar1881/Gash

package proto

import (
	"context"
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	"github.com/Xmar1881/Gash/internal/plugin"
)

// BannerResult TCP banner gözlemidir (salt-okuma).
type BannerResult struct {
	Host   string
	Port   string
	Banner string
	Empty  bool // bağlantı açıldı ama veri gelmedi
}

// GrabBanner hedefe bağlanıp ilk baytları okur, veri GÖNDERMEZ, hemen kapatır.
// What: Güvenli aktif prob: SYN→banner→kapat; yazma yok, 1KB üst sınır, deadline'lı.
// Why: Sürüm ifşası sinyaldir ama tek başına zayıftır (tavan tentative).
// Not: Yalnızca --active ile çalışır (safe profilde koşmaz); kapsam zorunludur.
func GrabBanner(ctx context.Context, addr string, o Options) (*BannerResult, error) {
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
	conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(host, port))
	if err != nil {
		return nil, fmt.Errorf("proto tcp %s: %w", addr, err)
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(o.timeout()))
	// Veri gönderilmez: yalnızca okuma (banner).
	buf, err := io.ReadAll(io.LimitReader(conn, 1024))
	if err != nil && len(buf) == 0 {
		// Zaman aşımı/boş banner: bağlantı kanıtı, veri yok.
		if ctx.Err() != nil {
			return nil, fmt.Errorf("proto tcp banner %s: %w", addr, ctx.Err())
		}
		return &BannerResult{Host: host, Port: port, Empty: true}, nil
	}
	return &BannerResult{Host: host, Port: port, Banner: string(buf)}, nil
}

// BannerFindings banner'dan bulgu üretir (GASH-026, CWE-200).
// What: Banner'da ürün/sürüm jetonu varsa tentative bulgu; boş banner bulgu üretmez.
// Why: Banner tek başına zayıf sinyaldir (sürüm iddiası davranışla doğrulanmadı).
func BannerFindings(target string, r *BannerResult) []Finding {
	banner := strings.TrimSpace(r.Banner)
	if banner == "" {
		return nil
	}
	// Yazdırılamayan baytları kırp (rapor hijyeni).
	clean := strings.Map(func(ch rune) rune {
		if ch < 32 && ch != '\n' && ch != '\t' {
			return -1
		}
		if ch > 0x10FFFF {
			return -1
		}
		return ch
	}, banner)
	if len(clean) > 300 {
		clean = clean[:300]
	}
	return []Finding{{
		RuleID: "GASH-026", CWE: "CWE-200", Title: "TCP servis banner'ı sürüm ifşa ediyor",
		Desc:     "Servis açılış banner'ında ürün/sürüm bilgisi var; hedef profilleme kolaylaşır.",
		Severity: plugin.SeverityLow, Confidence: plugin.ConfidenceTentative,
		Target: target, PluginID: "proto-tcp-banner", OracleName: "tcp",
		Evidence: map[string]string{
			"host": r.Host, "port": r.Port, "banner": clean, "signal": "version-banner",
		},
		Note: "salt-okuma banner probu; davranışla doğrulanmadı, tavan tentative",
		Tags: []string{"tcp", "banner", "version-disclosure"},
	}}
}

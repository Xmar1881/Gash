// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Modül: github.com/Xmar1881/Gash

// Login entegrasyonu (P2.6): CLI karmaşıklığını motordan uzak tutar.
// What: --login-url verildiyse auth.LoginFlow'u policy hattı üzerinden koşar,
// sonucu sayaç + skip izi + (başarıda) Auth bağlamı olarak döner.
// Why: Başarısızlık sessiz kalmaz, kimlik sızmaz; yalnızca kapsam/politika
// ihlali fail-closed'dur, diğer her hata oturumsuz taramayla devam eder.

package engine

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/Xmar1881/Gash/internal/auth"
	"github.com/Xmar1881/Gash/internal/plugin"
	"github.com/Xmar1881/Gash/internal/probe"
)

// loginMaxRequests login akışının policy bütçesidir.
// Deneme başına ~9 istek (GET+POST+verify+kontrol+redirect hop'ları);
// varsayılan 2 deneme + serving varyansı için emniyet payı.
const loginMaxRequests = 40

// loginOutcome login denemesinin rapor edilebilir sonucudur.
// What: Sayaçlar + kurulan oturum bağlamı + dürüst skip izi.
// Why: Kimlik değeri taşımaz; başarısızlık açık sebeplidir.
type loginOutcome struct {
	// attempted flow koştu mu (0/1).
	attempted int
	// succeeded doğrulanmış oturum kuruldu mu (0/1).
	succeeded int
	// cookies kurulan/ gözlenen cookie sayısıdır.
	cookies int
	// auth başarılı oturumun bağlamıdır (yalnızca başarıda dolu).
	auth *auth.Context
	// skipped başarısızlıkta tek bir "login" skip kaydı taşır.
	skipped []plugin.SkippedPlugin
}

// runLogin --login-url verildiyse policy hattı üzerinden oturum kurar.
// What: auth.LoginFlow'u probe.Client sender sarmalayıcısıyla koşar; sender
// plugin kimliği (login, safe=false), no-redirect ve no-WAF-bypass taşır.
// Why: Hata YALNIZCA fail-closed durumlarda (kapsam/politika ihlali) döner;
// mantıksal başarısızlık skip kaydı + oturumsuz taramayla devam eder.
func (e *Engine) runLogin(ctx context.Context, client *probe.Client) (loginOutcome, error) {
	var out loginOutcome
	opts := e.cfg.Login
	if opts == nil || strings.TrimSpace(opts.LoginURL) == "" || client == nil {
		return out, nil
	}
	out.attempted = 1

	requestTimeout := e.cfg.RequestTimeout
	if requestTimeout <= 0 {
		requestTimeout = 15 * time.Second
	}
	maxReq := loginMaxRequests
	sender := func(sctx context.Context, method, rawURL string, headers map[string]string, payload []byte) (int, http.Header, string, error) {
		sctx = plugin.WithPlugin(sctx, "login", false, &maxReq)
		// Redirect'ler akış tarafından manuel izlenir (Set-Cookie her hop'ta
		// görülür, downgrade kararı akışta); politika her hop'ta yine uygulanır.
		sctx = plugin.WithNoRedirect(sctx)
		// Kimlik bilgisi taşıyan istek asla WAF-bypass varyantıyla tekrarlanmaz.
		sctx = probe.WithNoWAFBypass(sctx)
		sctx, cancel := context.WithTimeout(sctx, requestTimeout)
		defer cancel()
		resp, err := client.Send(sctx, method, rawURL, headers, payload)
		if err != nil {
			return 0, nil, "", err
		}
		return resp.Status, resp.Headers, string(resp.Body), nil
	}

	res, err := auth.LoginFlow(ctx, sender, *opts)
	if err != nil {
		if e.loginFatal(err) {
			return out, fmt.Errorf("engine login: %w", err)
		}
		out.skipped = append(out.skipped, plugin.SkippedPlugin{
			PluginID: "login",
			Reason:   "skipped (login-error: " + scrubLoginSecrets(err, opts) + ")",
		})
		return out, nil
	}
	out.cookies = res.Cookies
	if res.Success && res.Context != nil {
		out.succeeded = 1
		out.auth = res.Context
		return out, nil
	}
	out.skipped = append(out.skipped, plugin.SkippedPlugin{
		PluginID: "login",
		Reason:   "skipped (login-failed: " + res.Reason + ")",
	})
	return out, nil
}

// loginFatal kapsam/politika ihlalini bildirir (fail-closed tek liste).
func (e *Engine) loginFatal(err error) bool {
	return errors.Is(err, plugin.ErrScopeViolation) || errors.Is(err, plugin.ErrPolicyViolation)
}

// scrubLoginSecrets hata metninden kullanıcı/parola değerlerini siler.
// What: Defense-in-depth (LoginFlow zaten değer taşımaz) + uzunluk tavanı.
// Why: Hata metinleri rapora girer; kimlik bilgisi asla sızmamalı.
func scrubLoginSecrets(err error, opts *auth.LoginOptions) string {
	if err == nil {
		return ""
	}
	msg := err.Error()
	if opts != nil {
		for _, secret := range []string{opts.Pass, opts.User} {
			if len(secret) >= 3 {
				msg = strings.ReplaceAll(msg, secret, "[redacted]")
			}
		}
	}
	const maxLen = 300
	if len(msg) > maxLen {
		msg = msg[:maxLen] + "..."
	}
	return msg
}

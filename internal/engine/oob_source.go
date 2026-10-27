// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Modül: github.com/Xmar1881/Gash

package engine

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/Xmar1881/Gash/internal/oob"
	"github.com/Xmar1881/Gash/internal/plugin/loader"
)

// engineOOBSource binds the self-hosted OOB provider to the loader's
// Tier1Options.OOBSource contract.
// What: Fresh single-use correlation token per payload; bounded callback wait.
// Why: OOBOracle only reaches confirmed through a real callback; the token
// lifetime never outlives the attempt so cross-candidate matches cannot occur.
type engineOOBSource struct {
	provider oob.Provider
	window   time.Duration
	polls    int
}

// oobSource returns the Tier 1 OOB source when --oob-server is configured.
// What: nil without a server (payloads stay inert, no finding is fabricated).
// "local" değeri dahili yerel dinleyici kullanır (sunucusuz).
func (e *Engine) oobSource() loader.OOBSource {
	if e == nil || strings.TrimSpace(e.cfg.OOBServer) == "" {
		return nil
	}
	provider, err := e.oobProvider()
	if err != nil || provider == nil || !provider.Enabled() {
		return nil
	}
	return &engineOOBSource{provider: provider}
}

// oobProvider builds (once) the configured OOB provider.
// What: local, interactsh (public/self-hosted), or the custom self-hosted API.
// Why: Interactsh registration must happen once per scan, not per detector or
// plugin; the cached provider also keeps the callback session stable.
func (e *Engine) oobProvider() (oob.Provider, error) {
	if e == nil {
		return nil, nil
	}
	e.oobOnce.Do(func() {
		server := strings.TrimSpace(e.cfg.OOBServer)
		switch {
		case server == "":
			return
		case strings.EqualFold(server, "local"):
			p, err := oob.NewLocalProvider("")
			e.oobProv, e.oobProvErr = p, err
		case isInteractshServer(server):
			p, err := oob.NewInteractshProvider(server, e.cfg.OOBToken)
			e.oobProv, e.oobProvErr = p, err
		default:
			e.oobProv = oob.NewSelfHostedProvider(server, e.cfg.OOBToken)
		}
	})
	return e.oobProv, e.oobProvErr
}

func isInteractshServer(s string) bool {
	l := strings.ToLower(strings.TrimSpace(s))
	return l == "interactsh" || strings.HasPrefix(l, "interactsh://") || strings.HasPrefix(l, "interactsh:")
}

// Generate mints a fresh correlation ID plus DNS domain and HTTP URL.
func (s *engineOOBSource) Generate() (string, string, string, error) {
	corr, err := oob.NewCorrelationID()
	if err != nil {
		return "", "", "", err
	}
	if s.provider == nil || !s.provider.Enabled() {
		return "", "", "", fmt.Errorf("oob provider disabled")
	}
	return corr, s.provider.DNSCallbackDomain(corr), s.provider.HTTPCallbackURL(corr), nil
}

// Wait performs the bounded multi-channel callback wait (dns or http).
func (s *engineOOBSource) Wait(ctx context.Context, correlationID string) bool {
	_, ok := oob.WaitForCallback(ctx, s.provider, correlationID, s.window, s.polls)
	return ok
}

// WaitAny performs the shared bounded wait over many tokens (one window).
func (s *engineOOBSource) WaitAny(ctx context.Context, correlationIDs []string) []string {
	return oob.WaitForCallbacks(ctx, s.provider, correlationIDs, s.window, s.polls)
}

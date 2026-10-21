//go:build !deep

// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Module: github.com/Xmar1881/Gash

package headless

import (
	"context"
	"fmt"
	"time"
)

// Supported reports whether this build carries a real browser driver.
// What: false in the default build; the engine uses it to decide whether
// browser verification can even be attempted (stub never links chromedp).
// Why: An honest capability flag beats probing a stub that always errors.
func Supported() bool { return false }

// VerifyDOM is the default-build stub: no browser driver is linked.
// What: Always errors, never fabricates a browser proof.
// Why: Default binary must not bloat with chromedp and must never emit a
// fake browser-confirmed verdict; confirmed requires `-tags deep`.
func VerifyDOM(ctx context.Context, payloadURL, controlURL, probeExpr string, timeout time.Duration) (Result, error) {
	_ = ctx
	_ = payloadURL
	_ = controlURL
	_ = probeExpr
	_ = timeout
	return Result{}, fmt.Errorf("headless: browser verification requires -tags deep (chromedp pinned, default build links no browser)")
}

// VerifyXSS is the default-build stub for the generic XSS browser proof.
// What: Always errors; no dialog/DOM/window canary observation is fabricated.
// Why: Reflected/stored XSS findings must keep their static tier in the
// default build; confirmed requires `-tags deep` plus a real Chrome run.
func VerifyXSS(ctx context.Context, payloadURL, controlURL string, timeout time.Duration) (Result, error) {
	return VerifyXSSWithAuth(ctx, payloadURL, controlURL, "", timeout)
}

// VerifyXSSWithAuth is the default-build stub for authenticated browser proof.
// What: Always errors; the auth header is never applied or reported.
// Why: The default build has no browser driver and must stay honestly
// unverified even when the scenario carries a session header.
func VerifyXSSWithAuth(ctx context.Context, payloadURL, controlURL, authHeader string, timeout time.Duration) (Result, error) {
	_ = ctx
	_ = payloadURL
	_ = controlURL
	_ = authHeader
	_ = timeout
	return Result{}, fmt.Errorf("headless: browser verification requires -tags deep (chromedp pinned, default build links no browser)")
}

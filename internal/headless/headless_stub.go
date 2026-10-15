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

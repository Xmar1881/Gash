//go:build deep

// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Module: github.com/Xmar1881/Gash

package headless

import (
	"context"
	"fmt"
	"time"

	"github.com/chromedp/chromedp"
)

// VerifyDOM runs a controlled headless-Chrome proof for DOM execution.
// What: Navigates to payloadURL then controlURL, evaluating probeExpr (a JS
// expression returning truthy when the payload executed) in each.
// Why: Real browser evidence only: Triggered+ControlClean feeds
// oracle.ExecutionParams{HeadlessEnabled:true} to reach confirmed. The
// chromedp dependency is pinned in go.mod and compiled only with -tags deep
// so the default binary stays light.
func VerifyDOM(ctx context.Context, payloadURL, controlURL, probeExpr string, timeout time.Duration) (Result, error) {
	if payloadURL == "" || controlURL == "" || probeExpr == "" {
		return Result{}, fmt.Errorf("headless: payload/control/probe required")
	}
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	chromePath := FindChrome()
	opts := append(chromedp.DefaultExecAllocatorOptions[:],
		chromedp.Flag("headless", true),
		chromedp.Flag("disable-gpu", true),
		chromedp.Flag("no-sandbox", true),
		chromedp.Flag("no-first-run", true),
		chromedp.Flag("no-default-browser-check", true),
	)
	if chromePath != "" {
		opts = append(opts, chromedp.ExecPath(chromePath))
	}
	allocCtx, allocCancel := chromedp.NewExecAllocator(ctx, opts...)
	defer allocCancel()
	browserCtx, browserCancel := chromedp.NewContext(allocCtx)
	defer browserCancel()

	var payloadHit, controlHit bool
	var err error
	if _, err = chromedp.Run(browserCtx, chromedp.Navigate(payloadURL)); err != nil {
		return Result{}, fmt.Errorf("headless: chromedp navigate payload: %w", err)
	}
	if _, err = chromedp.Run(browserCtx, chromedp.Sleep(500*time.Millisecond)); err != nil {
		return Result{}, fmt.Errorf("headless: chromedp sleep payload: %w", err)
	}
	if payloadHit, err = chromedp.Run(browserCtx, chromedp.Evaluate[bool](probeExpr)); err != nil {
		return Result{}, fmt.Errorf("headless: chromedp evaluate payload: %w", err)
	}
	// Ara boş sayfa: hash-only URL farkları reload tetiklemez; aynı sekmede
	// kalan JS durumu kontrolü kirletir. about:blank hop izolasyonu sağlar.
	if _, err = chromedp.Run(browserCtx, chromedp.Navigate("about:blank")); err != nil {
		return Result{}, fmt.Errorf("headless: chromedp navigate blank: %w", err)
	}
	if _, err = chromedp.Run(browserCtx, chromedp.Sleep(200*time.Millisecond)); err != nil {
		return Result{}, fmt.Errorf("headless: chromedp sleep blank: %w", err)
	}
	if _, err = chromedp.Run(browserCtx, chromedp.Navigate(controlURL)); err != nil {
		return Result{}, fmt.Errorf("headless: chromedp navigate control: %w", err)
	}
	if _, err = chromedp.Run(browserCtx, chromedp.Sleep(500*time.Millisecond)); err != nil {
		return Result{}, fmt.Errorf("headless: chromedp sleep control: %w", err)
	}
	if controlHit, err = chromedp.Run(browserCtx, chromedp.Evaluate[bool](probeExpr)); err != nil {
		return Result{}, fmt.Errorf("headless: chromedp evaluate control: %w", err)
	}
	return Result{Triggered: payloadHit, ControlClean: !controlHit}, nil
}

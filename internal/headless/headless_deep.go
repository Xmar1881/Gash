//go:build deep

// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Module: github.com/Xmar1881/Gash

package headless

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/chromedp/cdproto/cdp"
	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/cdproto/page"
	"github.com/chromedp/chromedp"
)

// Supported reports whether this build carries a real browser driver.
// What: true under -tags deep (chromedp linked); Chrome availability is a
// separate runtime check via Available().
// Why: The engine gates the generic browser-verify pass on this so the
// default build degrades honestly with an audit reason instead of errors.
func Supported() bool { return true }

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
		chromedp.Flag("disable-dev-shm-usage", true),
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

// xssCanaryProbe is the DOM/window canary observer. Dialog opening is observed
// separately through CDP events; this expression covers payload forms that
// mark execution by planting a canary node or a window flag instead of (or in
// addition to) a dialog. No external requests are ever made.
const xssCanaryProbe = `(function(){try{return (document.getElementById('__gash_canary')!==null)||(window.__gashCanary===true);}catch(e){return false;}})()`

// VerifyXSS runs the generic controlled browser proof for reflected/stored
// XSS findings.
// What: Loads payloadURL then controlURL in isolated browser contexts and
// reports Triggered when any of the three triggers is observed (dialog
// open, DOM canary node `__gash_canary`, `window.__gashCanary`), plus
// ControlClean when the neutral control shows none of them.
// Why: Only a real browser trigger plus a clean control may lift a static
// finding to confirmed. The payload and control run in separate contexts so
// no JS state can leak between them; any dialog is auto-dismissed (accepted)
// so the page keeps loading and the DOM probe still runs. No network egress
// beyond the two supplied URLs: payloads are expected to stay local/DOM-only.
func VerifyXSS(ctx context.Context, payloadURL, controlURL string, timeout time.Duration) (Result, error) {
	return VerifyXSSWithAuth(ctx, payloadURL, controlURL, "", timeout)
}

// VerifyXSSWithAuth runs the same controlled browser proof with one auth header
// applied to both the payload and control contexts.
// What: Parses "Name: value"; Cookie headers become CDP cookies, other headers
// are applied with Network.setExtraHTTPHeaders before navigation.
// Why: Authenticated scenarios (DVWA sessions) otherwise land on the login page
// and can never execute the payload, producing an unverified result.
func VerifyXSSWithAuth(ctx context.Context, payloadURL, controlURL, authHeader string, timeout time.Duration) (Result, error) {
	if payloadURL == "" || controlURL == "" {
		return Result{}, fmt.Errorf("headless: payload/control URLs required")
	}
	if payloadURL == controlURL {
		return Result{}, fmt.Errorf("headless: payload and control URLs must differ")
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
		chromedp.Flag("disable-dev-shm-usage", true),
		chromedp.Flag("no-first-run", true),
		chromedp.Flag("no-default-browser-check", true),
	)
	if chromePath != "" {
		opts = append(opts, chromedp.ExecPath(chromePath))
	}
	allocCtx, allocCancel := chromedp.NewExecAllocator(ctx, opts...)
	defer allocCancel()

	payloadHit, err := xssPhase(allocCtx, payloadURL, authHeader)
	if err != nil {
		return Result{}, fmt.Errorf("headless: xss payload phase: %w", err)
	}
	controlHit, err := xssPhase(allocCtx, controlURL, authHeader)
	if err != nil {
		return Result{}, fmt.Errorf("headless: xss control phase: %w", err)
	}
	return Result{Triggered: payloadHit, ControlClean: !controlHit}, nil
}

// authActions converts one auth header into CDP actions for a target URL.
// What: Cookie headers are split into Network.setCookies entries; any other
// header is applied as an extra HTTP header.
// Why: Chrome ignores an extra "Cookie" header in newer protocol versions, so
// session cookies need the cookie store rather than a header override.
func authActions(target, authHeader string) (chromedp.Action[chromedp.Void], error) {
	authHeader = strings.TrimSpace(authHeader)
	if authHeader == "" {
		return nil, nil
	}
	name, value, ok := strings.Cut(authHeader, ":")
	if !ok {
		return nil, fmt.Errorf("headless: auth header must be 'Name: value'")
	}
	name = strings.TrimSpace(name)
	value = strings.TrimSpace(value)
	if name == "" {
		return nil, fmt.Errorf("headless: auth header name is empty")
	}
	if !strings.EqualFold(name, "Cookie") {
		return chromedp.Func(func(ctx context.Context, t *chromedp.Target) error {
			_, err := cdp.Call(ctx, t, network.SetExtraHTTPHeaders, network.SetExtraHTTPHeadersParams{
				Headers: network.Headers{name: value},
			})
			return err
		}), nil
	}

	u, err := url.Parse(target)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return nil, fmt.Errorf("headless: auth target URL %q is not absolute", target)
	}
	cookieURL := u.Scheme + "://" + u.Host + "/"
	var cookies []*network.CookieParam
	for _, raw := range strings.Split(value, ";") {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		key, val, ok := strings.Cut(raw, "=")
		key = strings.TrimSpace(key)
		val = strings.TrimSpace(val)
		if !ok || key == "" {
			continue
		}
		cookies = append(cookies, &network.CookieParam{Name: key, Value: val, URL: cookieURL})
	}
	if len(cookies) == 0 {
		return nil, fmt.Errorf("headless: auth Cookie header contains no cookies")
	}
	return chromedp.Func(func(ctx context.Context, t *chromedp.Target) error {
		_, err := cdp.Call(ctx, t, network.SetCookies, network.SetCookiesParams{Cookies: cookies})
		return err
	}), nil
}

// xssPhase runs one navigation and observes the dialog/canary triggers.
// What: Per-phase browser context plus a protocol-event dialog observer plus
// the DOM canary probe.
// Why: Isolating the control in its own context keeps a payload's leftover
// DOM/canary state from tainting the clean-control determination. The
// observer uses the chromedp v0.21 event API (cdp.Events replaces the old
// ListenTarget) and accepts dialogs so the renderer keeps loading; a dialog
// observed is already a trigger even if accepting races the load.
func xssPhase(allocCtx context.Context, target, authHeader string) (bool, error) {
	browserCtx, cancel := chromedp.NewContext(allocCtx)
	defer cancel()

	authAction, err := authActions(target, authHeader)
	if err != nil {
		return false, err
	}
	if authAction != nil {
		if _, err := chromedp.Run(browserCtx, authAction); err != nil {
			return false, fmt.Errorf("chromedp auth setup %s: %w", target, err)
		}
	}

	hit, err := chromedp.Run(browserCtx, func(ctx context.Context, t *chromedp.Target) (bool, error) {
		var mu sync.Mutex
		dialogHit := false
		obsCtx, obsCancel := context.WithCancel(ctx)
		defer obsCancel()
		observerDone := make(chan struct{})
		go func() {
			defer close(observerDone)
			for _, err := range cdp.Events(obsCtx, t, page.JavascriptDialogOpening) {
				if err != nil {
					return
				}
				mu.Lock()
				dialogHit = true
				mu.Unlock()
				// A dialog blocks the renderer until it is handled; accepting
				// keeps the load (and the later DOM probe) moving. Best-effort:
				// the observed event is the trigger even if this call fails.
				_, _ = cdp.Call(obsCtx, t, page.HandleJavaScriptDialog, page.HandleJavaScriptDialogParams{Accept: true})
			}
		}()
		var stopOnce sync.Once
		stopObserver := func() {
			stopOnce.Do(func() {
				obsCancel()
				<-observerDone
			})
		}
		defer stopObserver()

		if _, err := chromedp.Navigate(target)(ctx, t); err != nil {
			return false, fmt.Errorf("chromedp navigate %s: %w", target, err)
		}
		if _, err := chromedp.Sleep(500*time.Millisecond)(ctx, t); err != nil {
			return false, fmt.Errorf("chromedp sleep %s: %w", target, err)
		}
		domHit, err := chromedp.Evaluate[bool](xssCanaryProbe)(ctx, t)
		if err != nil {
			return false, fmt.Errorf("chromedp evaluate %s: %w", target, err)
		}
		mu.Lock()
		d := dialogHit
		mu.Unlock()
		return d || domHit, nil
	})
	if err != nil {
		return false, err
	}
	return hit, nil
}

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

// canarySettle bounds the post-load wait for async DOM/SPA execution.
const canarySettle = 2 * time.Second

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

// VerifyXSS runs the generic controlled browser proof for reflected/stored
// XSS findings.
// What: Loads payloadURL then controlURL in isolated browser contexts and
// reports Triggered only when a unique per-run token is stamped by an actual
// JS side effect (alert() call or window.__gashCanary=true), plus ControlClean
// when the neutral control shows no such side effect.
// Why: Only a real browser trigger plus a clean control may lift a static
// finding to confirmed. The token prevents DOM insertion, a fixed page flag,
// or leftover state from a previous run from being counted as execution. The
// payload and control run in separate contexts so no JS state can leak
// between them; dialogs are auto-dismissed so the probe keeps running. No
// network egress beyond the two supplied URLs: payloads are expected to stay
// local/DOM-only.
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

	token, err := newCanaryToken()
	if err != nil {
		return Result{}, err
	}
	payload, err := xssPhase(allocCtx, payloadURL, authHeader, token)
	if err != nil {
		return Result{}, fmt.Errorf("headless: xss payload phase: %w", err)
	}
	control, err := xssPhase(allocCtx, controlURL, authHeader, token)
	if err != nil {
		return Result{}, fmt.Errorf("headless: xss control phase: %w", err)
	}
	return Result{
		Triggered:     payload.hit,
		ControlClean:  !control.hit,
		PayloadStatus: payload.status,
		ControlStatus: control.status,
	}, nil
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

// xssPhaseResult carries one navigation's trigger plus main-document status.
type xssPhaseResult struct {
	hit    bool
	status int
}

// xssPhase runs one navigation and observes the token-stamped triggers.
// What: Per-phase browser context plus dialog and response observers plus the
// token probe.
// Why: Isolating the control in its own context keeps payload state from
// tainting the clean-control determination. The dialog observer only keeps
// the renderer moving; the alert wrapper and window setter stamp the run
// token, so a dialog or DOM node alone is not execution evidence. The
// response observer records the final document status so auth/WAF/5xx pages
// are classified instead of being mistaken for a clean negative.
func xssPhase(allocCtx context.Context, target, authHeader, token string) (xssPhaseResult, error) {
	browserCtx, cancel := chromedp.NewContext(allocCtx)
	defer cancel()

	authAction, err := authActions(target, authHeader)
	if err != nil {
		return xssPhaseResult{}, err
	}
	if authAction != nil {
		if _, err := chromedp.Run(browserCtx, authAction); err != nil {
			return xssPhaseResult{}, fmt.Errorf("chromedp auth setup %s: %w", target, err)
		}
	}

	res, err := chromedp.Run(browserCtx, func(ctx context.Context, t *chromedp.Target) (xssPhaseResult, error) {
		tree, err := cdp.Call(ctx, t, page.GetFrameTree, cdp.Empty{})
		if err != nil {
			return xssPhaseResult{}, fmt.Errorf("chromedp frame tree %s: %w", target, err)
		}
		if tree.FrameTree == nil || tree.FrameTree.Frame == nil {
			return xssPhaseResult{}, fmt.Errorf("chromedp frame tree %s: empty main frame", target)
		}
		mainFrameID := tree.FrameTree.Frame.ID
		var mu sync.Mutex
		documentStatus := 0
		obsCtx, obsCancel := context.WithCancel(ctx)
		defer obsCancel()
		var observers sync.WaitGroup
		observers.Add(2)
		go func() {
			defer observers.Done()
			for _, err := range cdp.Events(obsCtx, t, page.JavascriptDialogOpening) {
				if err != nil {
					return
				}
				// A dialog blocks the renderer until it is handled; accepting
				// keeps the load (and the later token probe) moving. The
				// alert wrapper, not the dialog event alone, records execution.
				_, _ = cdp.Call(obsCtx, t, page.HandleJavaScriptDialog, page.HandleJavaScriptDialogParams{Accept: true})
			}
		}()
		go func() {
			defer observers.Done()
			for ev, err := range cdp.Events(obsCtx, t, network.ResponseReceived) {
				if err != nil {
					return
				}
				if ev.Type != network.ResourceTypeDocument || ev.Response == nil || ev.FrameID != mainFrameID {
					continue
				}
				mu.Lock()
				documentStatus = int(ev.Response.Status)
				mu.Unlock()
			}
		}()
		var stopOnce sync.Once
		stopObserver := func() {
			stopOnce.Do(func() {
				obsCancel()
				observers.Wait()
			})
		}
		defer stopObserver()

		if _, err := cdp.Call(ctx, t, page.AddScriptToEvaluateOnNewDocument,
			page.AddScriptToEvaluateOnNewDocumentParams{Source: xssCanaryBootstrap(token)}); err != nil {
			return xssPhaseResult{}, fmt.Errorf("chromedp canary bootstrap %s: %w", target, err)
		}
		if _, err := chromedp.Navigate(target)(ctx, t); err != nil {
			return xssPhaseResult{}, fmt.Errorf("chromedp navigate %s: %w", target, err)
		}
		hit, err := waitForCanary(ctx, t, token, canarySettle)
		if err != nil {
			return xssPhaseResult{}, fmt.Errorf("chromedp canary probe %s: %w", target, err)
		}
		mu.Lock()
		out := xssPhaseResult{hit: hit, status: documentStatus}
		mu.Unlock()
		return out, nil
	})
	if err != nil {
		return xssPhaseResult{}, err
	}
	return res, nil
}

// waitForCanary polls the token probe so async DOM/SPA handlers can run.
// What: Checks immediately, then every 100 ms up to the settle budget.
// Why: A single fixed sleep misses delayed sinks; a bounded poll still stops
// before the scan-level timeout.
func waitForCanary(ctx context.Context, t *chromedp.Target, token string, window time.Duration) (bool, error) {
	deadline := time.Now().Add(window)
	for {
		hit, err := chromedp.Evaluate[bool](xssCanaryProbe(token))(ctx, t)
		if err != nil {
			return false, err
		}
		if hit {
			return true, nil
		}
		if time.Now().After(deadline) {
			return false, nil
		}
		select {
		case <-ctx.Done():
			return false, ctx.Err()
		case <-time.After(100 * time.Millisecond):
		}
	}
}

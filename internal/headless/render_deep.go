//go:build deep

// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Module: github.com/Xmar1881/Gash

package headless

import (
	"context"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/chromedp/cdproto/cdp"
	"github.com/chromedp/cdproto/fetch"
	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/chromedp"
)

const (
	renderSettleQuiet = 500 * time.Millisecond
	renderSettleMax   = 3 * time.Second
	renderPollEvery   = 100 * time.Millisecond
)

// RenderPage loads one page in headless Chrome and returns its rendered DOM
// plus the request URLs observed while it settled.
// What: Seeds session cookies, optionally blocks every request outside
// AllowedURL through Fetch interception, navigates once (no clicking/typing),
// waits for document.readyState=complete plus a quiet network window, then
// captures location.href and outerHTML.
// Why: SPA surface exists only after scripts run; bounded settle plus request
// caps keep the pass deterministic, and the scope gate ensures the browser
// never produces third-party or out-of-scope traffic.
func RenderPage(ctx context.Context, pageURL string, opts RenderOptions) (RenderedPage, error) {
	target := NormalizeObservedURL(pageURL)
	if target == "" {
		return RenderedPage{}, fmt.Errorf("headless: render requires an absolute http(s) URL, got %q", pageURL)
	}
	if opts.Timeout <= 0 {
		opts.Timeout = DefaultTimeout
	}
	if opts.MaxNetworkURLs <= 0 {
		opts.MaxNetworkURLs = DefaultMaxNetworkURLs
	}
	if !Available() {
		return RenderedPage{}, fmt.Errorf("headless: render requires a Chrome binary (set CHROME_BIN or install Chrome)")
	}

	ctx, cancel := context.WithTimeout(ctx, opts.Timeout)
	defer cancel()

	chromePath := FindChrome()
	execOpts := append(chromedp.DefaultExecAllocatorOptions[:],
		chromedp.Flag("headless", true),
		chromedp.Flag("disable-gpu", true),
		chromedp.Flag("no-sandbox", true),
		chromedp.Flag("disable-dev-shm-usage", true),
		chromedp.Flag("no-first-run", true),
		chromedp.Flag("no-default-browser-check", true),
	)
	if chromePath != "" {
		execOpts = append(execOpts, chromedp.ExecPath(chromePath))
	}
	allocCtx, allocCancel := chromedp.NewExecAllocator(ctx, execOpts...)
	defer allocCancel()
	browserCtx, browserCancel := chromedp.NewContext(allocCtx)
	defer browserCancel()

	return chromedp.Run(browserCtx, func(ctx context.Context, t *chromedp.Target) (RenderedPage, error) {
		return renderTarget(ctx, t, target, opts)
	})
}

// renderTarget performs the bounded render inside one target.
func renderTarget(ctx context.Context, t *chromedp.Target, target string, opts RenderOptions) (RenderedPage, error) {
	collector := NewNetworkURLCollector(opts.MaxNetworkURLs)
	var activityMu sync.Mutex
	lastActivity := time.Now()
	noteActivity := func() {
		activityMu.Lock()
		lastActivity = time.Now()
		activityMu.Unlock()
	}

	obsCtx, obsCancel := context.WithCancel(ctx)
	var observers sync.WaitGroup
	observers.Add(1)
	go func() {
		defer observers.Done()
		for ev, err := range cdp.Events(obsCtx, t, network.RequestWillBeSent) {
			if err != nil {
				return
			}
			noteActivity()
			if ev.Request == nil || !renderMethodAllowed(ev.Request.Method) {
				continue
			}
			switch ev.Type {
			case network.ResourceTypeDocument, network.ResourceTypeXHR, network.ResourceTypeFetch:
				if opts.AllowedURL != nil && !opts.AllowedURL(ev.Request.URL) {
					continue
				}
				collector.Add(ev.Request.URL)
			}
		}
	}()
	observers.Add(1)
	go func() {
		defer observers.Done()
		for _, err := range cdp.Events(obsCtx, t, network.LoadingFinished) {
			if err != nil {
				return
			}
			noteActivity()
		}
	}()
	observers.Add(1)
	go func() {
		defer observers.Done()
		for _, err := range cdp.Events(obsCtx, t, network.LoadingFailed) {
			if err != nil {
				return
			}
			noteActivity()
		}
	}()
	if opts.AllowedURL != nil {
		observers.Add(1)
		go func() {
			defer observers.Done()
			for ev, err := range cdp.Events(obsCtx, t, fetch.RequestPaused) {
				if err != nil {
					return
				}
				noteActivity()
				if ev.Request != nil && (!renderMethodAllowed(ev.Request.Method) || !opts.AllowedURL(ev.Request.URL)) {
					_, _ = cdp.Call(obsCtx, t, fetch.FailRequest, fetch.FailRequestParams{
						RequestID:   ev.RequestID,
						ErrorReason: network.ErrorReasonBlockedByClient,
					})
					continue
				}
				_, _ = cdp.Call(obsCtx, t, fetch.ContinueRequest, fetch.ContinueRequestParams{
					RequestID: ev.RequestID,
				})
			}
		}()
	}
	var stopOnce sync.Once
	stopObservers := func() {
		stopOnce.Do(func() {
			obsCancel()
			observers.Wait()
		})
	}
	defer stopObservers()

	if _, err := cdp.Call(ctx, t, network.Enable, network.EnableParams{}); err != nil {
		return RenderedPage{}, fmt.Errorf("headless: render network enable: %w", err)
	}

	names := make([]string, 0, len(opts.Cookies))
	for name := range opts.Cookies {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		if _, err := cdp.Call(ctx, t, network.SetCookie, network.SetCookieParams{
			Name:  name,
			Value: opts.Cookies[name],
			URL:   target,
		}); err != nil {
			return RenderedPage{}, fmt.Errorf("headless: render seed cookie %q: %w", name, err)
		}
	}

	if opts.AllowedURL != nil {
		if _, err := cdp.Call(ctx, t, fetch.Enable, fetch.EnableParams{
			Patterns: []*fetch.RequestPattern{{URLPattern: "*"}},
		}); err != nil {
			return RenderedPage{}, fmt.Errorf("headless: render fetch enable: %w", err)
		}
	}

	if _, err := chromedp.Navigate(target)(ctx, t); err != nil {
		return RenderedPage{}, fmt.Errorf("headless: render navigate %s: %w", target, err)
	}

	deadline := time.Now().Add(renderSettleMax)
	for {
		if err := ctx.Err(); err != nil {
			return RenderedPage{}, fmt.Errorf("headless: render settle: %w", err)
		}
		state, err := chromedp.Evaluate[string]("document.readyState")(ctx, t)
		if err != nil {
			return RenderedPage{}, fmt.Errorf("headless: render readyState: %w", err)
		}
		activityMu.Lock()
		quiet := time.Since(lastActivity)
		activityMu.Unlock()
		if state == "complete" && quiet >= renderSettleQuiet {
			break
		}
		if time.Now().After(deadline) {
			break
		}
		if _, err := chromedp.Sleep(renderPollEvery)(ctx, t); err != nil {
			return RenderedPage{}, fmt.Errorf("headless: render settle sleep: %w", err)
		}
	}

	finalURL, err := chromedp.Location()(ctx, t)
	if err != nil {
		return RenderedPage{}, fmt.Errorf("headless: render location: %w", err)
	}
	html, err := chromedp.OuterHTML("html")(ctx, t)
	if err != nil {
		return RenderedPage{}, fmt.Errorf("headless: render outerHTML: %w", err)
	}
	stopObservers()
	if finalURL != "" {
		finalURL = NormalizeObservedURL(finalURL)
	}
	return RenderedPage{URL: finalURL, HTML: html, NetworkURLs: collector.URLs()}, nil
}

// renderMethodAllowed keeps the render pass GET/HEAD-only.
// What: Any non-idempotent request a page script attempts is failed before
// it leaves the browser.
// Why: --browser-crawl must not need --active, so rendering can never submit
// a state-changing request on the operator's behalf.
func renderMethodAllowed(method string) bool {
	return strings.EqualFold(method, http.MethodGet) || strings.EqualFold(method, http.MethodHead)
}

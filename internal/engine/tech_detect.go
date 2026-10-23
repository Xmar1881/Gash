// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Module: github.com/Xmar1881/Gash

package engine

import (
	"context"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/Xmar1881/Gash/internal/discovery"
)

// detectRuntimeTech targets one passive GET plus optional favicon fetch.
// What: Header, cookie-name, body-marker, and favicon-hash fingerprint.
// Why: Chain gating needs runtime context; both fetches are same-target,
// bounded (512KB/64KB), short-timeout, and best-effort (error yields empty).
func (e *Engine) detectRuntimeTech(ctx context.Context, target string) {
	e.detectedTech = map[string]bool{}
	e.detectedCaps = map[string]bool{}
	if e.sharedPolicy != nil && e.cfg.MaxRequestsTotal > 0 && e.sharedPolicy.TotalCount() >= e.cfg.MaxRequestsTotal {
		return
	}
	u, err := url.Parse(target)
	if err != nil || u.Host == "" {
		return
	}
	var tr = http.DefaultTransport
	if strings.TrimSpace(e.cfg.ProxyURL) != "" {
		if pu, err := url.Parse(strings.TrimSpace(e.cfg.ProxyURL)); err == nil {
			if defTr, ok := http.DefaultTransport.(*http.Transport); ok {
				t := defTr.Clone()
				t.Proxy = http.ProxyURL(pu)
				tr = t
			}
		}
	}
	client := &http.Client{Transport: tr, Timeout: 8 * time.Second}
	reqCtx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, target, nil)
	if err != nil {
		return
	}
	req.Header.Set("User-Agent", "Gash-techfp/1.0")
	resp, err := client.Do(req)
	if err != nil {
		return
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 512*1024))
	var cookies []*http.Cookie
	if resp.Cookies() != nil {
		cookies = resp.Cookies()
	}
	fp := discovery.FingerprintTech(resp.Header, cookies, string(body))
	for _, t := range fp.Tech {
		e.detectedTech[strings.ToLower(strings.TrimSpace(t))] = true
	}
	for c := range fp.Capabilities {
		e.detectedCaps[strings.ToLower(strings.TrimSpace(c))] = true
	}
	// Favicon: only when the page references it (one extra same-host GET).
	if strings.Contains(strings.ToLower(string(body)), "favicon") {
		favURL := (&url.URL{Scheme: u.Scheme, Host: u.Host, Path: "/favicon.ico"}).String()
		fctx, fcancel := context.WithTimeout(ctx, 5*time.Second)
		defer fcancel()
		freq, err := http.NewRequestWithContext(fctx, http.MethodGet, favURL, nil)
		if err != nil {
			return
		}
		fresp, err := client.Do(freq)
		if err != nil {
			return
		}
		defer func() { _ = fresp.Body.Close() }()
		fdata, _ := io.ReadAll(io.LimitReader(fresp.Body, 64*1024))
		if h := discovery.FaviconHash(fdata); h != "" {
			e.detectedCaps["favicon:"+h[:16]] = true
		}
	}
}

// mergeSurfaceTech folds the runLive surface response into the same sets.
// What: Same FingerprintTech over the already-fetched init response.
// Why: Run detection may have failed (timeout); the live fetch is a free
// second opinion without extra traffic.
func (e *Engine) mergeSurfaceTech(headers http.Header, cookies []*http.Cookie, body []byte) {
	fp := discovery.FingerprintTech(headers, cookies, string(body))
	if e.detectedTech == nil {
		e.detectedTech = map[string]bool{}
	}
	if e.detectedCaps == nil {
		e.detectedCaps = map[string]bool{}
	}
	for _, t := range fp.Tech {
		e.detectedTech[strings.ToLower(strings.TrimSpace(t))] = true
	}
	for c := range fp.Capabilities {
		e.detectedCaps[strings.ToLower(strings.TrimSpace(c))] = true
	}
}

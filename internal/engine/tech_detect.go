// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Module: github.com/Xmar1881/Gash

package engine

import (
	"context"
	"net/http"
	"net/url"
	"strings"

	"github.com/Xmar1881/Gash/internal/discovery"
	"github.com/Xmar1881/Gash/internal/plugin"
	"github.com/Xmar1881/Gash/internal/probe"
)

// detectRuntimeTech targets one passive GET plus optional favicon fetch.
// What: Header, cookie-name, body-marker, and favicon-hash fingerprint.
// Why: Chain gating needs runtime context; both fetches use the same policy,
// auth context, scope, budget, redirect, and outer scan deadline as plugins.
// The first GET doubles as the target preflight: a transport/scope failure is
// returned so Run can fail fast instead of scheduling every plugin against an
// unreachable target. A favicon failure is optional context and is ignored.
func (e *Engine) detectRuntimeTech(ctx context.Context, target string, client *probe.Client) error {
	e.detectedTech = map[string]bool{}
	e.detectedCaps = map[string]bool{}
	if client == nil {
		return nil
	}
	u, err := url.Parse(target)
	if err != nil || u.Host == "" {
		return nil
	}
	detectCtx := plugin.WithPlugin(ctx, "engine-tech-detect", true, nil)
	detectCtx = probe.WithNoWAFBypass(detectCtx)
	resp, err := client.Send(detectCtx, http.MethodGet, target, map[string]string{
		"User-Agent": "Gash-techfp/1.0",
	}, nil)
	if err != nil {
		return err
	}
	body := resp.Body
	if len(body) > 512*1024 {
		body = body[:512*1024]
	}
	cookies := (&http.Response{Header: resp.Headers}).Cookies()
	fp := discovery.FingerprintTech(resp.Headers, cookies, string(body))
	for _, t := range fp.Tech {
		e.detectedTech[strings.ToLower(strings.TrimSpace(t))] = true
	}
	for c := range fp.Capabilities {
		e.detectedCaps[strings.ToLower(strings.TrimSpace(c))] = true
	}
	// Favicon: only when the page references it (one extra same-host GET).
	if strings.Contains(strings.ToLower(string(body)), "favicon") {
		favURL := (&url.URL{Scheme: u.Scheme, Host: u.Host, Path: "/favicon.ico"}).String()
		fresp, ferr := client.Send(detectCtx, http.MethodGet, favURL, map[string]string{
			"User-Agent": "Gash-techfp/1.0",
		}, nil)
		if ferr != nil {
			return nil
		}
		fdata := fresp.Body
		if len(fdata) > 64*1024 {
			fdata = fdata[:64*1024]
		}
		if h := discovery.FaviconHash(fdata); h != "" {
			e.detectedCaps["favicon:"+h[:16]] = true
		}
	}
	return nil
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

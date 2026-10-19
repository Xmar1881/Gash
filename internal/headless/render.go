// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Module: github.com/Xmar1881/Gash

// Package headless: bounded SPA surface render seam.
// What: Shared render types plus pure URL normalization/collection helpers;
// the chromedp driver lives behind the `deep` build tag, the default build
// carries an honest "unavailable" stub.
// Why: SPA discovery must degrade with an audit reason in light builds, never
// fabricate rendered surface or link chromedp outside -tags deep.
package headless

import (
	"errors"
	"net/url"
	"strings"
	"time"
)

// ErrBrowserUnavailable is returned by the default-build renderer stub.
var ErrBrowserUnavailable = errors.New("headless: browser render requires -tags deep (chromedp pinned, default build links no browser)")

const (
	// DefaultMaxNetworkURLs bounds observed request URLs per rendered page.
	DefaultMaxNetworkURLs = 200
	// maxObservedURLLen bounds a single normalized observed URL.
	maxObservedURLLen = 2048
)

// RenderedPage is the renderer output consumed by discovery.HarvestRendered.
// What: Final document URL, post-script DOM HTML, and observed network URLs.
// Why: SPA forms/links exist only in the rendered DOM, and XHR/fetch endpoints
// exist only in the network stream; both feed the scan surface.
type RenderedPage struct {
	URL         string
	HTML        string
	NetworkURLs []string
}

// RenderOptions bounds one page render.
// What: Session cookies, wall-clock timeout, URL cap, and the scope gate for
// every browser request.
// Why: The renderer must carry the scan session but never widen scan scope;
// AllowedURL is invoked for each request (including subresources) and may run
// concurrently, so callbacks must be safe for concurrent use.
type RenderOptions struct {
	Cookies        map[string]string
	Timeout        time.Duration
	MaxNetworkURLs int
	AllowedURL     func(rawURL string) bool
}

// NormalizeObservedURL canonicalizes an observed request URL for surface use.
// What: Trims, accepts only absolute http(s) URLs, lowercases scheme/host,
// drops userinfo and fragment, and rejects empty hosts and overlong values.
// Why: Network streams repeat URLs with fragments/case variance; a single
// deterministic form keeps harvest dedupe stable and avoids leaking auth
// material embedded in userinfo.
func NormalizeObservedURL(raw string) string {
	s := strings.TrimSpace(raw)
	if s == "" || len(s) > maxObservedURLLen {
		return ""
	}
	u, err := url.Parse(s)
	if err != nil || u.Host == "" {
		return ""
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme != "http" && scheme != "https" {
		return ""
	}
	u.Scheme = scheme
	u.Host = strings.ToLower(u.Host)
	u.User = nil
	u.Fragment = ""
	return u.String()
}

// NetworkURLCollector accumulates deduplicated, capped observed URLs.
// What: Add normalizes and keeps the first occurrence until max is reached.
// Why: One page can emit thousands of asset requests; the surface only needs
// a bounded, deterministic HTTP URL list.
type NetworkURLCollector struct {
	seen map[string]struct{}
	urls []string
	max  int
}

// NewNetworkURLCollector returns a collector capped at max (<=0 -> default).
func NewNetworkURLCollector(max int) *NetworkURLCollector {
	if max <= 0 {
		max = DefaultMaxNetworkURLs
	}
	return &NetworkURLCollector{seen: make(map[string]struct{}), max: max}
}

// Add records raw once, in deterministic arrival order, until the cap.
func (c *NetworkURLCollector) Add(raw string) {
	if c == nil || len(c.urls) >= c.max {
		return
	}
	norm := NormalizeObservedURL(raw)
	if norm == "" {
		return
	}
	if _, ok := c.seen[norm]; ok {
		return
	}
	c.seen[norm] = struct{}{}
	c.urls = append(c.urls, norm)
}

// URLs returns a copy of the collected URLs.
func (c *NetworkURLCollector) URLs() []string {
	if c == nil {
		return nil
	}
	out := make([]string, len(c.urls))
	copy(out, c.urls)
	return out
}

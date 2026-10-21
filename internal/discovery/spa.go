// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Modül: github.com/Xmar1881/Gash
//
// File: internal/discovery/spa.go
// What: Render edilmiş SPA yüzeyinin saf hasadı (DOM form/link + ağ URL'leri).
// Why: Tarayıcı yalnızca ham veri üretir; form/injection point/endpoint
// kararları deterministik ve istisiz burada verilir. Kapsam kararı çağıran
// motordadır (prodüksiyon isteği üretilmez).

package discovery

import (
	"net/url"
	"sort"
	"strings"

	"github.com/Xmar1881/Gash/internal/headless"
)

// spaMaxEndpoints bounds follow-crawl candidates from one rendered page.
const spaMaxEndpoints = 200

// SPAHarvest is the scan-surface contribution of one rendered page.
// What: Replayable forms, injection points, and parameterless follow URLs.
// Why: Forms need full-field replay, query URLs are directly fuzzable, and
// parameterless URLs must be fetched once to expose their own surface.
type SPAHarvest struct {
	Forms     []Form
	Points    []InjectionPoint
	Endpoints []string
}

// HarvestRendered derives scan surface from one rendered page.
// What: Extracts forms and DOM-derived points from the post-script HTML,
// converts observed query URLs into GET injection points, and keeps
// parameterless observed URLs as bounded follow-crawl candidates.
// Why: SPA content exists only after scripts run; noise (assets, CDNs,
// non-http schemes) is filtered with the same rules as passive JS recon, and
// the synthetic CommonCandidateParams fallback is intentionally not applied.
func HarvestRendered(page headless.RenderedPage) SPAHarvest {
	var out SPAHarvest
	pageURL := headless.NormalizeRenderedURL(page.URL)
	body := []byte(page.HTML)
	if pageURL != "" && len(body) > 0 {
		out.Forms = ExtractForms(pageURL, body)
		out.Points = extractSurface(pageURL, body, false)
	}

	seenPoints := make(map[string]bool, len(out.Points))
	for _, p := range out.Points {
		seenPoints[spaPointKey(p)] = true
	}
	for _, p := range searchHashFallbackPoints(pageURL, body) {
		key := spaPointKey(p)
		if seenPoints[key] {
			continue
		}
		seenPoints[key] = true
		out.Points = append(out.Points, p)
	}
	seenEndpoints := make(map[string]bool)
	if pageURL != "" {
		seenEndpoints[pageURL] = true
	}

	for _, raw := range page.NetworkURLs {
		norm := headless.NormalizeObservedURL(raw)
		if norm == "" || len(norm) > maxEndpointLiteralLen || jsEndpointNoise(norm) {
			continue
		}
		u, err := url.Parse(norm)
		if err != nil || u.Host == "" || IsNoiseJSHost(u.Hostname()) {
			continue
		}
		query := u.Query()
		if len(query) > 0 {
			names := make([]string, 0, len(query))
			for name := range query {
				names = append(names, name)
			}
			sort.Strings(names)
			clean := *u
			clean.RawQuery = ""
			cleanURL := clean.String()
			for _, name := range names {
				point := InjectionPoint{
					URL:           cleanURL,
					Method:        "GET",
					ParamName:     name,
					ParamLocation: "query",
					Value:         query.Get(name),
				}
				key := spaPointKey(point)
				if seenPoints[key] {
					continue
				}
				seenPoints[key] = true
				out.Points = append(out.Points, point)
			}
			continue
		}
		if seenEndpoints[norm] || len(out.Endpoints) >= spaMaxEndpoints {
			continue
		}
		seenEndpoints[norm] = true
		out.Endpoints = append(out.Endpoints, norm)
	}
	return out
}

// spaPointKey mirrors the engine's point dedupe key.
func spaPointKey(p InjectionPoint) string {
	return strings.ToUpper(p.Method) + "|" + p.URL + "|" + p.ParamLocation + "|" + p.ParamName
}

const spaMaxSearchHashFallbackPoints = 12

// searchHashFallbackPoints derives a tiny query vocabulary for rendered
// search-like hash routes that expose no explicit query. Hash-routed SPAs
// often render nav links such as "#/search" without a term; a browser-only
// probe can safely try the conventional names because a finding is emitted
// only after a real execution and a clean control.
func searchHashFallbackPoints(pageURL string, body []byte) []InjectionPoint {
	base, err := url.Parse(pageURL)
	if err != nil || base.Host == "" {
		return nil
	}
	var out []InjectionPoint
	seen := map[string]bool{}
	add := func(raw *url.URL) {
		if raw == nil || !strings.EqualFold(raw.Hostname(), base.Hostname()) {
			return
		}
		route, rawQuery, hasQuery := strings.Cut(raw.Fragment, "?")
		if strings.TrimSpace(route) == "" || (hasQuery && strings.TrimSpace(rawQuery) != "") {
			return
		}
		if !searchLikeHashRoute(route) {
			return
		}
		clean := *raw
		clean.Fragment = route
		urlKey := clean.String()
		for _, name := range []string{"q", "query", "search"} {
			key := urlKey + "|" + name
			if seen[key] {
				continue
			}
			seen[key] = true
			out = append(out, InjectionPoint{
				URL:           urlKey,
				Method:        "GET",
				ParamName:     name,
				ParamLocation: "fragment",
			})
			if len(out) >= spaMaxSearchHashFallbackPoints {
				return
			}
		}
	}
	add(base)
	for _, href := range extractLinks(body) {
		ref, err := url.Parse(strings.TrimSpace(href))
		if err != nil {
			continue
		}
		add(base.ResolveReference(ref))
		if len(out) >= spaMaxSearchHashFallbackPoints {
			break
		}
	}
	return out
}

func searchLikeHashRoute(route string) bool {
	lower := strings.ToLower(strings.Trim(route, "/"))
	for _, marker := range []string{"search", "find", "query", "lookup"} {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	return false
}

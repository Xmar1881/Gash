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
	pageURL := headless.NormalizeObservedURL(page.URL)
	body := []byte(page.HTML)
	if pageURL != "" && len(body) > 0 {
		out.Forms = ExtractForms(pageURL, body)
		out.Points = extractSurface(pageURL, body, false)
	}

	seenPoints := make(map[string]bool, len(out.Points))
	for _, p := range out.Points {
		seenPoints[spaPointKey(p)] = true
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

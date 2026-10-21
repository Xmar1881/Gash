// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Modül: github.com/Xmar1881/Gash
//
// File: internal/engine/spa_crawl.go
// What: Sınırlı SPA render hattı: seçilmiş HTML sayfalarını gerçek tarayıcıda
// render edip DOM form/link + XHR/fetch yüzeyini tarama listesine ekler.
// Why: Statik crawl script'lerin ürettiği formları ve endpoint'leri göremez;
// render yalnızca açık --browser-crawl ile koşar, -tags deep + Chrome yoksa
// dürüst skip izi bırakır, sayfa hatalarında taramayı durdurmaz ve kapsam
// dışına istek üretmez (Fetch kapısı renderer içinde uygulanır).

package engine

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/Xmar1881/Gash/internal/auth"
	"github.com/Xmar1881/Gash/internal/discovery"
	"github.com/Xmar1881/Gash/internal/headless"
	"github.com/Xmar1881/Gash/internal/plugin"
	"github.com/Xmar1881/Gash/internal/plugin/loader"
	"github.com/Xmar1881/Gash/internal/probe"
	"golang.org/x/time/rate"
)

const (
	spaDefaultPages   = 5
	spaMaxPages       = 10
	spaMaxFollowPages = 25
	spaHintScanBytes  = 256 * 1024
	spaCrawlPluginID  = "browser-crawl"
	spaStubSkipReason = "skipped (browser-crawl requires a -tags deep build; default build links no browser)"
	spaNoChromeReason = "skipped (browser-crawl found no Chrome binary)"
	spaDefaultTimeout = 15 * time.Second
)

// runSPACrawl renders selected crawl pages and merges the harvested surface.
// What: Picks up to N in-scope HTML pages (script/SPA hints first), renders
// them with the scan session cookies, adds rendered forms/points, and follows
// a bounded number of newly observed parameterless endpoints once.
// Why: SPA-only surface must enter the same scan pipeline without widening
// scope, hanging the scan, or fabricating data when no browser exists.
func (e *Engine) runSPACrawl(ctx context.Context, target string, client *probe.Client, crawlRes *discovery.CrawlResult, existing []loader.JSPoint) ([]loader.JSPoint, []plugin.SkippedPlugin, map[string]int) {
	stats := map[string]int{
		"spa_pages_rendered": 0,
		"spa_forms":          0,
		"spa_endpoints":      0,
		"spa_skipped":        0,
	}
	if !e.cfg.BrowserCrawl || crawlRes == nil {
		return nil, nil, stats
	}

	render := e.cfg.BrowserCrawlFunc
	if render == nil {
		switch {
		case !headless.Supported():
			return nil, []plugin.SkippedPlugin{{PluginID: spaCrawlPluginID, Reason: spaStubSkipReason}}, stats
		case !headless.Available():
			return nil, []plugin.SkippedPlugin{{PluginID: spaCrawlPluginID, Reason: spaNoChromeReason}}, stats
		default:
			render = headless.RenderPage
		}
	}

	targetParsed, err := url.Parse(strings.TrimSpace(target))
	if err != nil || targetParsed.Host == "" {
		return nil, nil, stats
	}
	sm := NewScopeManager(e.cfg.Scope)
	sm.SetOriginalTarget(targetParsed.String())
	var allowedMu sync.Mutex
	allowed := func(raw string) bool {
		u, perr := url.Parse(raw)
		if perr != nil || u.Host == "" {
			return false
		}
		allowedMu.Lock()
		defer allowedMu.Unlock()
		return jsReconURLAllowed(targetParsed, u, e.cfg.Scope, sm)
	}

	timeout := e.cfg.RequestTimeout
	if timeout <= 0 {
		timeout = spaDefaultTimeout
	}
	var limiter *rate.Limiter
	if e.cfg.RatePerSecond > 0 {
		limiter = rate.NewLimiter(rate.Limit(e.cfg.RatePerSecond), 1)
	}
	cookies := spaSessionCookies(e.cfg.Auth)

	seenPoints := make(map[string]bool, len(existing))
	for _, p := range existing {
		seenPoints[spaPointKey(p.URL, p.Method, p.ParamLocation, p.ParamName)] = true
	}
	var newPoints []loader.JSPoint
	addPoint := func(p loader.JSPoint) {
		key := spaPointKey(p.URL, p.Method, p.ParamLocation, p.ParamName)
		if seenPoints[key] {
			return
		}
		seenPoints[key] = true
		newPoints = append(newPoints, p)
	}

	endpointSeen := make(map[string]bool)
	var endpoints []string
	var renderSkipped []plugin.SkippedPlugin
	for _, page := range spaRenderCandidates(crawlRes, e.spaPageLimit()) {
		if ctx.Err() != nil {
			break
		}
		if !allowed(page.URL) {
			stats["spa_skipped"]++
			continue
		}
		if limiter != nil {
			if werr := limiter.Wait(ctx); werr != nil {
				break
			}
		}
		res, rerr := render(ctx, page.URL, headless.RenderOptions{
			Cookies:        cookies,
			Timeout:        timeout,
			MaxNetworkURLs: headless.DefaultMaxNetworkURLs,
			AllowedURL:     allowed,
		})
		if rerr != nil {
			if errors.Is(rerr, headless.ErrBrowserUnavailable) {
				return newPoints, []plugin.SkippedPlugin{{PluginID: spaCrawlPluginID, Reason: spaStubSkipReason}}, stats
			}
			stats["spa_skipped"]++
			if len(renderSkipped) == 0 {
				renderSkipped = append(renderSkipped, plugin.SkippedPlugin{
					PluginID: spaCrawlPluginID,
					Reason:   spaRenderError(page.URL, rerr),
				})
			}
			continue
		}
		finalURL := headless.NormalizeRenderedURL(res.URL)
		if finalURL == "" {
			finalURL = headless.NormalizeRenderedURL(page.URL)
		}
		if finalURL == "" {
			stats["spa_skipped"]++
			continue
		}
		if u, uerr := url.Parse(finalURL); uerr != nil || !jsReconURLAllowed(targetParsed, u, e.cfg.Scope, sm) {
			stats["spa_skipped"]++
			continue
		}
		if e.cfg.MaxResponseBytes > 0 && int64(len(res.HTML)) > e.cfg.MaxResponseBytes {
			stats["spa_skipped"]++
			continue
		}
		harvest := discovery.HarvestRendered(headless.RenderedPage{
			URL:         finalURL,
			HTML:        res.HTML,
			NetworkURLs: res.NetworkURLs,
		})
		stats["spa_pages_rendered"]++
		stats["spa_forms"] += mergeSPAForms(crawlRes, harvest.Forms)
		for _, p := range harvest.Points {
			addPoint(loader.JSPoint{
				URL:           p.URL,
				Method:        p.Method,
				ParamName:     p.ParamName,
				ParamLocation: p.ParamLocation,
				Value:         p.Value,
				FormValues:    p.FormValues,
				FormEnctype:   p.FormEnctype,
			})
		}
		for _, ep := range harvest.Endpoints {
			norm := headless.NormalizeObservedURL(ep)
			if norm == "" || endpointSeen[norm] || !allowed(norm) {
				continue
			}
			endpointSeen[norm] = true
			endpoints = append(endpoints, norm)
		}
	}
	stats["spa_endpoints"] = len(endpoints)

	if client == nil || len(endpoints) == 0 || ctx.Err() != nil {
		return newPoints, renderSkipped, stats
	}
	crawled := make(map[string]bool, len(crawlRes.Pages))
	for _, p := range crawlRes.Pages {
		if norm := headless.NormalizeObservedURL(p.URL); norm != "" {
			crawled[norm] = true
		}
	}
	followed := 0
	for _, ep := range endpoints {
		if followed >= spaMaxFollowPages || ctx.Err() != nil {
			break
		}
		if crawled[ep] {
			continue
		}
		follow, ferr := discovery.Crawl(ctx, client, ep, discovery.CrawlOptions{
			MaxPages: 1, MaxDepth: 0, Scope: e.cfg.Scope,
			ReadRobots: false, ReadSitemap: false, SkipJSRecon: true,
		})
		if ferr != nil || follow == nil {
			continue
		}
		followed++
		stats["spa_forms"] += mergeSPAForms(crawlRes, follow.Forms)
		for _, ip := range follow.SurfacePoints {
			addPoint(loader.JSPoint{
				URL:           ip.URL,
				Method:        ip.Method,
				ParamName:     ip.ParamName,
				ParamLocation: ip.ParamLocation,
				Value:         ip.Value,
				FormValues:    ip.FormValues,
				FormEnctype:   ip.FormEnctype,
			})
		}
	}
	return newPoints, renderSkipped, stats
}

// spaPageLimit resolves the render-page cap (default 5, hard cap 10).
func (e *Engine) spaPageLimit() int {
	limit := e.cfg.BrowserCrawlPages
	if limit <= 0 {
		limit = spaDefaultPages
	}
	if limit > spaMaxPages {
		limit = spaMaxPages
	}
	return limit
}

// spaRenderCandidates selects in-scope HTML pages, preferring SPA hints.
func spaRenderCandidates(crawlRes *discovery.CrawlResult, limit int) []discovery.CrawlPage {
	if crawlRes == nil || limit <= 0 {
		return nil
	}
	type candidate struct {
		page  discovery.CrawlPage
		score int
	}
	seen := make(map[string]bool, len(crawlRes.Pages))
	cands := make([]candidate, 0, len(crawlRes.Pages))
	for _, page := range crawlRes.Pages {
		if page.Status < 200 || page.Status >= 300 || !spaHTMLPage(page) {
			continue
		}
		norm := headless.NormalizeObservedURL(page.URL)
		if norm == "" || seen[norm] {
			continue
		}
		seen[norm] = true
		cands = append(cands, candidate{page: page, score: spaHintScore(page.Body)})
	}
	sort.SliceStable(cands, func(i, j int) bool { return cands[i].score > cands[j].score })
	if len(cands) > limit {
		cands = cands[:limit]
	}
	out := make([]discovery.CrawlPage, len(cands))
	for i := range cands {
		out[i] = cands[i].page
	}
	return out
}

// spaHTMLPage reports whether a crawl page is an HTML document.
func spaHTMLPage(page discovery.CrawlPage) bool {
	ct := strings.ToLower(strings.TrimSpace(page.Headers.Get("Content-Type")))
	if ct == "" {
		ct = strings.ToLower(http.DetectContentType(page.Body))
	}
	return strings.Contains(ct, "text/html") || strings.Contains(ct, "application/xhtml+xml")
}

// spaHintScore counts script/SPA markers in a bounded body prefix.
func spaHintScore(body []byte) int {
	if len(body) > spaHintScanBytes {
		body = body[:spaHintScanBytes]
	}
	lower := bytes.ToLower(body)
	markers := [][]byte{
		[]byte("<script"), []byte("__next_data__"), []byte("data-reactroot"),
		[]byte("ng-app"), []byte("v-app"),
		[]byte(`id="root"`), []byte(`id='root'`),
		[]byte(`id="app"`), []byte(`id='app'`),
	}
	score := 0
	for _, marker := range markers {
		if bytes.Contains(lower, marker) {
			score++
		}
	}
	return score
}

// mergeSPAForms appends only forms not already known and returns the count.
func mergeSPAForms(crawlRes *discovery.CrawlResult, forms []discovery.Form) int {
	if crawlRes == nil || len(forms) == 0 {
		return 0
	}
	seen := make(map[string]bool, len(crawlRes.Forms)+len(forms))
	for _, f := range crawlRes.Forms {
		seen[spaFormKey(f)] = true
	}
	added := 0
	for _, f := range forms {
		key := spaFormKey(f)
		if seen[key] {
			continue
		}
		seen[key] = true
		crawlRes.Forms = append(crawlRes.Forms, f)
		added++
	}
	return added
}

// spaFormKey mirrors the crawler's method+action+field-name dedupe key.
func spaFormKey(f discovery.Form) string {
	names := make([]string, 0, len(f.Fields))
	for _, fld := range f.Fields {
		names = append(names, fld.Name)
	}
	sort.Strings(names)
	return f.Method + "|" + f.ActionURL + "|" + strings.Join(names, ",")
}

// spaPointKey mirrors the engine's surface-point dedupe key.
func spaPointKey(rawURL, method, location, param string) string {
	return strings.ToUpper(method) + "|" + rawURL + "|" + location + "|" + param
}

// spaSessionCookies builds the browser cookie seed from the scan auth context.
// What: Auth cookie map plus names parsed from explicit Cookie headers (explicit wins).
// Why: Login/--cookie sessions must survive into the renderer so authenticated
// SPA pages are rendered instead of a login wall; header values are never logged.
func spaSessionCookies(a *auth.Context) map[string]string {
	if a == nil || !a.HasAuth() {
		return nil
	}
	out := make(map[string]string, len(a.Cookies)+2)
	for name, value := range a.Cookies {
		if strings.TrimSpace(name) != "" {
			out[name] = value
		}
	}
	for name, value := range a.Headers {
		if !strings.EqualFold(name, "Cookie") {
			continue
		}
		for _, part := range strings.Split(value, ";") {
			n, v, ok := strings.Cut(strings.TrimSpace(part), "=")
			n = strings.TrimSpace(n)
			if !ok || n == "" {
				continue
			}
			if _, exists := out[n]; !exists {
				out[n] = strings.TrimSpace(v)
			}
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// spaRenderError formats a bounded render error for audit records.
func spaRenderError(pageURL string, err error) string {
	msg := fmt.Sprintf("skipped (render error: %s: %v)", pageURL, err)
	const maxLen = 300
	if len(msg) > maxLen {
		msg = msg[:maxLen] + "..."
	}
	return msg
}

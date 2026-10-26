// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Module: github.com/Xmar1881/Gash

package discovery

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"

	"github.com/Xmar1881/Gash/internal/plugin"
	"github.com/Xmar1881/Gash/internal/probe"
	"golang.org/x/net/html"
)

// CrawlPage represents an HTTP page fetched during discovery.
type CrawlPage struct {
	URL     string
	Status  int
	Headers http.Header
	Body    []byte
	Depth   int
}

// CrawlOptions controls breadth-first search discovery behavior.
type CrawlOptions struct {
	MaxPages    int      // Maximum pages to crawl. Default 50.
	MaxDepth    int      // Maximum BFS traversal depth from target. Default 3.
	Scope       []string // Scope allowlist (domains/CIDRs). Empty = open mod: yazılımsal host engeli yok.
	ReadRobots  bool     // Whether to read robots.txt for seed URLs.
	ReadSitemap bool     // Whether to read sitemap.xml for seed URLs.
	// SkipJSRecon JS kaynağı toplama/çekmeyi kapatır. Ana crawl false bırakır
	// (JS recon'u besler); mini/geri-besleme crawl'ları true kullanır (çift
	// analiz ve istek tekrarı olmaz).
	SkipJSRecon bool
	// OnPage her sayfa denemesinden sonra çağrılır: denenen sayfa sayısı, sayfa
	// bütçesi ve denenen URL. Canlı ilerleme göstergesi içindir; nil olabilir.
	// Why: Uzun crawl'larda çağıran taraf bekleyişin ilerlediğini gösterebilmeli.
	OnPage func(done, total int, pageURL string)
}

// DefaultCrawlOptions returns recommended default crawl parameters.
func DefaultCrawlOptions() CrawlOptions {
	return CrawlOptions{
		MaxPages:    50,
		MaxDepth:    3,
		ReadRobots:  true,
		ReadSitemap: true,
	}
}

// CrawlResult holds all crawled pages and discovered injection points.
type CrawlResult struct {
	Pages         []CrawlPage
	SurfacePoints []InjectionPoint
	// Forms holds deduplicated HTML forms for full-form replay fuzzing.
	Forms         []Form
	TotalRequests int
	SeedURLs      []string
	// JSSources pasif JS recon için toplanan gövdelerdir (harici + inline).
	JSSources []JSSource
	// JSFilesFetched çekilen harici JS dosyası sayısıdır (inline sayılmaz).
	JSFilesFetched int
}

type crawlItem struct {
	rawURL string
	depth  int
}

var sitemapLocRegex = regexp.MustCompile(`(?i)<loc>\s*([^<\s]+)\s*</loc>`)

// Crawl performs a BFS web crawl starting from targetURL, subject to scope
// allowlist and PolicySession budget / rate-limit constraints. It populates
// attack surface injection points from every crawled page.
func Crawl(ctx context.Context, client *probe.Client, targetURL string, opts CrawlOptions) (*CrawlResult, error) {
	if client == nil {
		return nil, fmt.Errorf("crawl: nil probe client")
	}
	targetParsed, err := url.Parse(strings.TrimSpace(targetURL))
	if err != nil || targetParsed.Host == "" {
		return nil, fmt.Errorf("crawl: invalid target URL %q: %w", targetURL, err)
	}

	if opts.MaxPages <= 0 {
		opts.MaxPages = 50
	}
	if opts.MaxDepth < 0 {
		opts.MaxDepth = 3
	}

	result := &CrawlResult{}
	visited := make(map[string]bool)
	seenParamSkeletons := make(map[string]bool)
	seenPoints := make(map[string]bool)
	seenForms := make(map[string]bool)

	normTarget := normalizeURL(targetParsed)
	visited[normTarget] = true
	visited[urlSkeleton(targetParsed)] = true

	queue := []crawlItem{
		{rawURL: normTarget, depth: 0},
	}
	result.SeedURLs = append(result.SeedURLs, normTarget)

	policy := client.Policy()

	rootURL := fmt.Sprintf("%s://%s", targetParsed.Scheme, targetParsed.Host)
	rootParsed, _ := url.Parse(rootURL)
	if rootParsed == nil {
		rootParsed = targetParsed
	}

	// 1. Fetch & parse robots.txt if enabled
	var sitemapCandidates []string
	if opts.ReadRobots && isURLInScope(ctx, rootParsed, targetParsed, policy, opts.Scope) {
		robotsURL := rootURL + "/robots.txt"
		reqCtx := plugin.WithPlugin(ctx, "crawler", true, nil)
		resp, rerr := client.Send(reqCtx, http.MethodGet, robotsURL, nil, nil)
		if rerr == nil {
			result.TotalRequests++
			if resp != nil && resp.Status == http.StatusOK && len(resp.Body) > 0 {
				paths, sitemaps := parseRobotsTxt(resp.Body)
				sitemapCandidates = append(sitemapCandidates, sitemaps...)
				for _, p := range paths {
					rel, perr := url.Parse(p)
					if perr != nil {
						continue
					}
					resolved := rootParsed.ResolveReference(rel)
					if isURLInScope(ctx, resolved, targetParsed, policy, opts.Scope) && !isSessionDestructiveURL(resolved.String()) {
						norm := normalizeURL(resolved)
						skel := urlSkeleton(resolved)
						if !visited[norm] && !seenParamSkeletons[skel] {
							visited[norm] = true
							seenParamSkeletons[skel] = true
							result.SeedURLs = append(result.SeedURLs, norm)
							queue = append(queue, crawlItem{rawURL: norm, depth: 1})
						}
					}
				}
			}
		}
	}

	// 2. Fetch & parse sitemap.xml if enabled
	if opts.ReadSitemap && isURLInScope(ctx, rootParsed, targetParsed, policy, opts.Scope) {
		sitemapURLs := []string{rootURL + "/sitemap.xml"}
		for _, s := range sitemapCandidates {
			if su, serr := url.Parse(s); serr == nil {
				resolved := rootParsed.ResolveReference(su)
				if isURLInScope(ctx, resolved, targetParsed, policy, opts.Scope) {
					sitemapURLs = append(sitemapURLs, resolved.String())
				}
			}
		}

		for _, smURL := range sitemapURLs {
			if ctx.Err() != nil {
				break
			}
			reqCtx := plugin.WithPlugin(ctx, "crawler", true, nil)
			resp, serr := client.Send(reqCtx, http.MethodGet, smURL, nil, nil)
			if serr == nil {
				result.TotalRequests++
				if resp != nil && resp.Status == http.StatusOK && len(resp.Body) > 0 {
					locs := parseSitemapXML(resp.Body)
					for _, loc := range locs {
						lu, lerr := url.Parse(loc)
						if lerr != nil {
							continue
						}
						resolved := rootParsed.ResolveReference(lu)
						if isURLInScope(ctx, resolved, targetParsed, policy, opts.Scope) && !isSessionDestructiveURL(resolved.String()) {
							norm := normalizeURL(resolved)
							skel := urlSkeleton(resolved)
							if !visited[norm] && !seenParamSkeletons[skel] {
								visited[norm] = true
								seenParamSkeletons[skel] = true
								result.SeedURLs = append(result.SeedURLs, norm)
								queue = append(queue, crawlItem{rawURL: norm, depth: 1})
							}
						}
					}
				}
			}
		}
	}

	// 3. BFS Traversal
	scriptQueue := make([]string, 0, 16)
	seenScripts := make(map[string]bool)
	inlineBudget := jsMaxInlineTotal
	fetched := 0
	for len(queue) > 0 && len(result.Pages) < opts.MaxPages {
		if ctx.Err() != nil {
			break
		}

		item := queue[0]
		queue = queue[1:]

		reqCtx := plugin.WithPlugin(ctx, "crawler", true, nil)
		resp, err := client.Send(reqCtx, http.MethodGet, item.rawURL, nil, nil)
		fetched++
		if opts.OnPage != nil {
			opts.OnPage(fetched, opts.MaxPages, item.rawURL)
		}
		if err != nil {
			if errors.Is(err, plugin.ErrBudgetExceeded) {
				// Budget exhausted: break immediately and return what was collected
				break
			}
			if errors.Is(err, plugin.ErrScopeViolation) {
				continue
			}
			// Transient network/timeout: skip to next item
			continue
		}
		result.TotalRequests++
		if resp == nil {
			continue
		}

		page := CrawlPage{
			URL:     item.rawURL,
			Status:  resp.Status,
			Headers: resp.Headers,
			Body:    resp.Body,
			Depth:   item.depth,
		}
		result.Pages = append(result.Pages, page)

		// Extract attack surface injection points from response. Synthetic
		// fallback params are added once by the engine when the whole surface
		// is empty; per-page fallback invented points on CSS/favicon URLs and
		// starved real points out of the plugin request budget.
		pts := extractSurface(item.rawURL, resp.Body, false)
		for _, pt := range pts {
			k := strings.ToUpper(pt.Method) + "|" + pt.URL + "|" + pt.ParamLocation + "|" + pt.ParamName
			if !seenPoints[k] {
				seenPoints[k] = true
				result.SurfacePoints = append(result.SurfacePoints, pt)
			}
		}

		// Full-form replay model: dedup by method+action+field-name set so the
		// same site-wide form (search box, newsletter) is fuzzed once.
		for _, f := range ExtractForms(item.rawURL, resp.Body) {
			names := make([]string, 0, len(f.Fields))
			for _, fld := range f.Fields {
				names = append(names, fld.Name)
			}
			sort.Strings(names)
			k := f.Method + "|" + f.ActionURL + "|" + strings.Join(names, ",")
			if !seenForms[k] {
				seenForms[k] = true
				result.Forms = append(result.Forms, f)
			}
		}

		// Pasif JS recon: inline gövdeler hemen toplanır, harici src'ler
		// same-origin/--scope kapısından geçerse kuyruğa girer (CDN asla).
		if !opts.SkipJSRecon && len(resp.Body) > 0 && inlineBudget > 0 {
			pageParsed, perr := url.Parse(item.rawURL)
			if perr == nil {
				srcs, inline := extractScriptSources(resp.Body, inlineBudget)
				for _, content := range inline {
					inlineBudget -= len(content)
					result.JSSources = append(result.JSSources, JSSource{
						URL: item.rawURL, Body: content, Inline: true,
					})
				}
				for _, s := range srcs {
					ref, rerr := url.Parse(s)
					if rerr != nil {
						continue
					}
					resolved := pageParsed.ResolveReference(ref)
					if !jsAssetFetchAllowed(ctx, targetParsed, resolved, policy, opts.Scope) {
						continue
					}
					key := normalizeURL(resolved)
					if seenScripts[key] {
						continue
					}
					if len(scriptQueue) >= jsMaxFilesPerCrawl {
						break
					}
					seenScripts[key] = true
					scriptQueue = append(scriptQueue, key)
				}
			}
		}

		// Expand links if under max depth
		if item.depth < opts.MaxDepth && len(resp.Body) > 0 {
			pageParsed, err := url.Parse(item.rawURL)
			if err != nil {
				continue
			}
			links := extractLinks(resp.Body)
			for _, l := range links {
				ref, err := url.Parse(l)
				if err != nil {
					continue
				}
				resolved := pageParsed.ResolveReference(ref)
				if !isURLInScope(ctx, resolved, targetParsed, policy, opts.Scope) {
					continue
				}
				if isSessionDestructiveURL(resolved.String()) {
					continue
				}
				if isStateTogglingURL(resolved.String()) {
					continue
				}
				norm := normalizeURL(resolved)
				skel := urlSkeleton(resolved)
				if !visited[norm] && !seenParamSkeletons[skel] {
					visited[norm] = true
					seenParamSkeletons[skel] = true
					queue = append(queue, crawlItem{rawURL: norm, depth: item.depth + 1})
				}
			}
		}
	}

	// 4. Harici JS çekimi (pasif recon): GET-only, same-origin/--scope kapılı,
	// dosya ve toplam boyut tavanlı; hata/bütçe sessiz düşer (tarama durmaz).
	if !opts.SkipJSRecon && ctx.Err() == nil {
		for _, su := range scriptQueue {
			if ctx.Err() != nil {
				break
			}
			reqCtx := plugin.WithPlugin(ctx, "crawler", true, nil)
			resp, serr := client.Send(reqCtx, http.MethodGet, su, nil, nil)
			if serr != nil {
				if errors.Is(serr, plugin.ErrBudgetExceeded) {
					break
				}
				continue
			}
			result.TotalRequests++
			result.JSFilesFetched++
			if resp == nil || len(resp.Body) == 0 {
				continue
			}
			result.JSSources = append(result.JSSources, JSSource{URL: su, Body: resp.Body})
		}
	}

	return result, nil
}

// isURLInScope checks whether candidate is permitted under the policy session
// or explicit scope constraints.
// What: policy session (or explicit entries) decides; neither configured =
// open mode: any http(s) host is crawlable, no host filtering.
// Why: Scope is opt-in (--scope); without it the operator owns authorization.
func isURLInScope(ctx context.Context, u *url.URL, target *url.URL, policy *plugin.PolicySession, explicitScope []string) bool {
	scheme := strings.ToLower(u.Scheme)
	if scheme != "http" && scheme != "https" {
		return false
	}
	if policy != nil {
		if err := policy.CheckScope(ctx, u); err != nil {
			return false
		}
		return true
	}
	if len(explicitScope) > 0 {
		host := strings.ToLower(u.Hostname())
		for _, s := range explicitScope {
			s = strings.TrimSpace(strings.ToLower(s))
			if s == "" {
				continue
			}
			if _, ipNet, err := net.ParseCIDR(s); err == nil {
				if ip := net.ParseIP(host); ip != nil && ipNet.Contains(ip) {
					return true
				}
				continue
			}
			if strings.HasPrefix(s, "http://") || strings.HasPrefix(s, "https://") {
				if su, err := url.Parse(s); err == nil {
					if strings.EqualFold(u.Hostname(), su.Hostname()) && strings.HasPrefix(strings.TrimSuffix(u.Path, "/"), strings.TrimSuffix(su.Path, "/")) {
						return true
					}
				}
				continue
			}
			if host == s || strings.HasSuffix(host, "."+s) {
				return true
			}
		}
		return false
	}
	// Open mode: no policy session and no --scope entries -> no host filtering.
	return true
}

// normalizeURL removes fragment and redundant trailing slash.
func normalizeURL(u *url.URL) string {
	clean := *u
	clean.Fragment = ""
	if len(clean.Path) > 1 && strings.HasSuffix(clean.Path, "/") {
		clean.Path = strings.TrimSuffix(clean.Path, "/")
	}
	return clean.String()
}

// urlSkeleton produces a deduplication key based on scheme, host, path, and sorted query parameter names.
// This prevents infinite pagination traps (e.g. /items?page=1, /items?page=2).
func urlSkeleton(u *url.URL) string {
	keys := make([]string, 0, len(u.Query()))
	for k := range u.Query() {
		keys = append(keys, strings.ToLower(k))
	}
	sort.Strings(keys)
	path := strings.TrimSuffix(u.Path, "/")
	return strings.ToLower(u.Scheme) + "://" + strings.ToLower(u.Host) + path + "?" + strings.Join(keys, "&")
}

// parseRobotsTxt extracts paths and sitemap URLs from robots.txt content.
func parseRobotsTxt(body []byte) (paths []string, sitemaps []string) {
	scanner := bufio.NewScanner(bytes.NewReader(body))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if idx := strings.Index(line, "#"); idx >= 0 {
			line = strings.TrimSpace(line[:idx])
		}
		if line == "" {
			continue
		}
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.ToLower(strings.TrimSpace(parts[0]))
		val := strings.TrimSpace(parts[1])
		switch key {
		case "disallow", "allow":
			if val != "" && val != "/" && !strings.Contains(val, "*") {
				paths = append(paths, val)
			}
		case "sitemap":
			if val != "" {
				sitemaps = append(sitemaps, val)
			}
		}
	}
	return paths, sitemaps
}

// parseSitemapXML extracts <loc> tags from sitemap XML content.
func parseSitemapXML(body []byte) []string {
	var urls []string
	matches := sitemapLocRegex.FindAllSubmatch(body, -1)
	for _, m := range matches {
		if len(m) > 1 {
			loc := strings.TrimSpace(string(m[1]))
			if loc != "" {
				urls = append(urls, loc)
			}
		}
	}
	return urls
}

var sessionDestructivePath = regexp.MustCompile(`(?i)(?:^|/)(?:log[-_]?out|sign[-_]?out|log[-_]?off)(?:\.[a-z0-9]+)?$`)

func isSessionDestructiveURL(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil {
		return false
	}
	return sessionDestructivePath.MatchString(strings.TrimRight(u.Path, "/"))
}

// stateToggleKeys/Values identify GET links that flip application state when
// merely visited (?phpids=on, ?debug=1, ?action=delete). Crawling or replaying
// them mutates the target (DVWA enabled PHPIDS mid-scan and blocked later SQLi
// probes), so they are never followed, surfaced, or form-replayed.
var stateToggleKeys = map[string]bool{
	"phpids": true, "php_ids": true, "ids": true, "debug": true,
	"enable": true, "disable": true, "enabled": true, "disabled": true,
	"logout": true, "action": true, "do": true, "confirm": true,
	"delete": true, "remove": true, "reset": true, "activate": true,
	"deactivate": true, "mode": true, "status": true, "state": true,
	"toggle": true, "security": true, "level": true,
}

var stateToggleValues = map[string]bool{
	"on": true, "off": true, "enable": true, "disable": true,
	"enabled": true, "disabled": true, "logout": true, "delete": true,
	"remove": true, "reset": true, "activate": true, "deactivate": true,
}

func isStateTogglingURL(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil {
		return false
	}
	for k, vals := range u.Query() {
		if stateToggleKeys[strings.ToLower(strings.TrimSpace(k))] {
			return true
		}
		for _, v := range vals {
			if stateToggleValues[strings.ToLower(strings.TrimSpace(v))] {
				return true
			}
		}
	}
	return false
}

// extractLinks parses HTML and returns all href, action, and src links.
func extractLinks(body []byte) []string {
	var links []string
	doc, err := html.Parse(bytes.NewReader(body))
	if err != nil {
		return nil
	}
	var walk func(*html.Node)
	walk = func(n *html.Node) {
		if n.Type == html.ElementNode {
			tag := strings.ToLower(n.Data)
			var attrName string
			switch tag {
			case "a", "link":
				attrName = "href"
			case "form":
				attrName = "action"
			case "iframe", "frame":
				attrName = "src"
			}
			if attrName != "" {
				for _, a := range n.Attr {
					if strings.EqualFold(a.Key, attrName) {
						val := strings.TrimSpace(a.Val)
						if val != "" && !strings.HasPrefix(val, "javascript:") && !strings.HasPrefix(val, "mailto:") && !strings.HasPrefix(val, "tel:") {
							links = append(links, val)
						}
					}
				}
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			walk(c)
		}
	}
	walk(doc)
	return links
}

// extractScriptSources HTML'den harici script src'lerini ve inline JS
// gövdelerini toplar.
// What: Yalnızca JS-tipi script'ler (boş/module/javascript/ecmascript);
// inline gövde script başına 256 KB ve çağrı bütçesiyle sınırlıdır.
// Why: JSON veri blokları (__NEXT_DATA__ vb.) pasif JS recon kapsamı dışıdır;
// tavanlar 2 MB'lık analiz limitine taşmadan besleme garantisidir.
func extractScriptSources(body []byte, inlineBudget int) (srcs []string, inline [][]byte) {
	doc, err := html.Parse(bytes.NewReader(body))
	if err != nil {
		return nil, nil
	}
	if inlineBudget < 0 {
		inlineBudget = 0
	}
	var walk func(*html.Node)
	walk = func(n *html.Node) {
		if n.Type == html.ElementNode && strings.EqualFold(n.Data, "script") {
			scriptType := ""
			var src string
			for _, a := range n.Attr {
				switch strings.ToLower(a.Key) {
				case "src":
					src = strings.TrimSpace(a.Val)
				case "type":
					scriptType = strings.ToLower(strings.TrimSpace(a.Val))
				}
			}
			if isJSScriptType(scriptType) {
				switch {
				case src != "":
					if len(srcs) < jsMaxSrcCandidates {
						srcs = append(srcs, src)
					}
				case n.FirstChild != nil && inlineBudget > 0:
					var sb strings.Builder
					for c := n.FirstChild; c != nil; c = c.NextSibling {
						if c.Type == html.TextNode {
							sb.WriteString(c.Data)
						}
					}
					content := []byte(sb.String())
					if len(content) > jsMaxInlinePerScript {
						content = content[:jsMaxInlinePerScript]
					}
					if len(content) > inlineBudget {
						content = content[:inlineBudget]
					}
					if len(content) > 0 {
						inline = append(inline, content)
						inlineBudget -= len(content)
					}
				}
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			walk(c)
		}
	}
	walk(doc)
	return srcs, inline
}

// sameOrigin şema + host (port dahil) birebir eşleşmesidir.
func sameOrigin(a, b *url.URL) bool {
	if a == nil || b == nil {
		return false
	}
	return strings.EqualFold(a.Scheme, b.Scheme) && strings.EqualFold(a.Host, b.Host)
}

// jsAssetFetchAllowed JS asset çekme kapısıdır.
// What: Yalnızca hedef origin VEYA explicit --scope içindeki host; CDN/analitik
// host'lar ve non-http(s) şemalar hiçbir koşulda çekilmez.
// Why: Pasif JS recon üçüncü taraf trafiği üretmez; kapsam disiplini crawl
// ile aynıdır (policy + explicit scope, fail-closed).
func jsAssetFetchAllowed(ctx context.Context, target, asset *url.URL, policy *plugin.PolicySession, scope []string) bool {
	scheme := strings.ToLower(asset.Scheme)
	if scheme != "http" && scheme != "https" {
		return false
	}
	if IsNoiseJSHost(asset.Hostname()) {
		return false
	}
	if !sameOrigin(target, asset) && len(scope) == 0 {
		return false
	}
	return isURLInScope(ctx, asset, target, policy, scope)
}

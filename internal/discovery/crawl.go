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
	TotalRequests int
	SeedURLs      []string
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

	normTarget := normalizeURL(targetParsed)
	visited[normTarget] = true
	visited[urlSkeleton(targetParsed)] = true

	queue := []crawlItem{
		{rawURL: normTarget, depth: 0},
	}
	result.SeedURLs = append(result.SeedURLs, normTarget)

	var policy *plugin.PolicySession
	policy = client.Policy()

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
					if isURLInScope(ctx, resolved, targetParsed, policy, opts.Scope) {
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
						if isURLInScope(ctx, resolved, targetParsed, policy, opts.Scope) {
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
	for len(queue) > 0 && len(result.Pages) < opts.MaxPages {
		if ctx.Err() != nil {
			break
		}

		item := queue[0]
		queue = queue[1:]

		reqCtx := plugin.WithPlugin(ctx, "crawler", true, nil)
		resp, err := client.Send(reqCtx, http.MethodGet, item.rawURL, nil, nil)
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

		// Extract attack surface injection points from response
		pts := ExtractSurface(item.rawURL, resp.Body)
		for _, pt := range pts {
			k := strings.ToUpper(pt.Method) + "|" + pt.URL + "|" + pt.ParamLocation + "|" + pt.ParamName
			if !seenPoints[k] {
				seenPoints[k] = true
				result.SurfacePoints = append(result.SurfacePoints, pt)
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

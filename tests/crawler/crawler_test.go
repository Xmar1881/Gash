// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Module: github.com/Xmar1881/Gash

package crawler_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Xmar1881/Gash/internal/discovery"
	"github.com/Xmar1881/Gash/internal/plugin"
	"github.com/Xmar1881/Gash/internal/probe"
)

// TestCrawler_ScopeAllowlistEnforcement ensures the crawler strictly adheres
// to the scope allowlist and never requests or indexes out-of-scope URLs.
func TestCrawler_ScopeAllowlistEnforcement(t *testing.T) {
	var outOfScopeHits atomic.Int64
	outOfScopeServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		outOfScopeHits.Add(1)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("<html><body>out of scope target</body></html>"))
	}))
	defer outOfScopeServer.Close()

	inScopeServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		switch r.URL.Path {
		case "/":
			fmt.Fprintf(w, `<html><body>
				<a href="/allowed-1">Allowed Page 1</a>
				<a href="%s/forbidden">Forbidden External</a>
				<a href="http://192.0.2.1/illegal">Forbidden IP</a>
			</body></html>`, outOfScopeServer.URL)
		case "/allowed-1":
			fmt.Fprintf(w, `<html><body>
				<form action="/allowed-form" method="POST">
					<input name="param1" value="val1" />
				</form>
				<a href="%s/forbidden-2">Forbidden External 2</a>
			</body></html>`, outOfScopeServer.URL)
		case "/allowed-form":
			fmt.Fprintf(w, `<html><body>ok</body></html>`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer inScopeServer.Close()

	u, err := url.Parse(inScopeServer.URL)
	if err != nil {
		t.Fatal(err)
	}

	policyCfg := plugin.DefaultPolicyConfig()
	policyCfg.Scope = []string{u.Host} // Strictly allow only inScopeServer
	policy := plugin.NewPolicySession(policyCfg, nil)
	policy.SetOriginalTarget(inScopeServer.URL)

	client := probe.NewClient(probe.Options{
		Policy:         policy,
		RequestTimeout: 5 * time.Second,
	})

	opts := discovery.CrawlOptions{
		MaxPages:    10,
		MaxDepth:    3,
		Scope:       []string{u.Host},
		ReadRobots:  false,
		ReadSitemap: false,
	}

	res, err := discovery.Crawl(context.Background(), client, inScopeServer.URL, opts)
	if err != nil {
		t.Fatalf("crawl error: %v", err)
	}

	if outOfScopeHits.Load() > 0 {
		t.Fatalf("scope violation: outOfScopeServer was requested %d times", outOfScopeHits.Load())
	}

	for _, p := range res.Pages {
		pu, perr := url.Parse(p.URL)
		if perr != nil {
			t.Fatalf("bad page url %q: %v", p.URL, perr)
		}
		if !strings.EqualFold(pu.Host, u.Host) {
			t.Fatalf("scope violation: crawler indexed page from forbidden host %q (expected %q)", pu.Host, u.Host)
		}
	}

	foundParam := false
	for _, pt := range res.SurfacePoints {
		if pt.ParamName == "param1" {
			foundParam = true
			break
		}
	}
	if !foundParam {
		t.Fatal("expected param1 from allowed-1 form to be in SurfacePoints")
	}
}

// TestCrawler_BudgetViolationHaltsGracefully ensures that when PolicySession's
// request budget is exhausted, the crawler halts cleanly without panic or crashing.
func TestCrawler_BudgetViolationHaltsGracefully(t *testing.T) {
	var totalServerRequests atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		totalServerRequests.Add(1)
		w.Header().Set("Content-Type", "text/html")
		n := strings.TrimPrefix(r.URL.Path, "/page-")
		fmt.Fprintf(w, `<html><body>
			<a href="/page-%s-next1">Next 1</a>
			<a href="/page-%s-next2">Next 2</a>
		</body></html>`, n, n)
	}))
	defer server.Close()

	const maxBudget = 4
	policyCfg := plugin.DefaultPolicyConfig()
	policyCfg.MaxRequestsTotal = maxBudget
	policy := plugin.NewPolicySession(policyCfg, nil)
	policy.SetOriginalTarget(server.URL)

	client := probe.NewClient(probe.Options{
		Policy:         policy,
		RequestTimeout: 5 * time.Second,
	})

	opts := discovery.CrawlOptions{
		MaxPages:    50, // request far more pages than budget allows
		MaxDepth:    10,
		ReadRobots:  false,
		ReadSitemap: false,
	}

	res, err := discovery.Crawl(context.Background(), client, server.URL+"/page-0", opts)
	if err != nil {
		t.Fatalf("crawler must not return fatal error when budget is hit: %v", err)
	}

	if policy.TotalCount() > maxBudget {
		t.Fatalf("budget exceeded: policy recorded %d requests (max allowed %d)", policy.TotalCount(), maxBudget)
	}
	if int64(res.TotalRequests) > maxBudget {
		t.Fatalf("crawler reported %d requests (max budget %d)", res.TotalRequests, maxBudget)
	}
	if len(res.Pages) > maxBudget {
		t.Fatalf("crawler returned %d pages, which exceeds budget %d", len(res.Pages), maxBudget)
	}
}

// TestCrawler_BFSDepthAndMaxPages verifies strict breadth-first depth and
// max-page limits.
func TestCrawler_BFSDepthAndMaxPages(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		switch r.URL.Path {
		case "/":
			fmt.Fprint(w, `<html><body><a href="/depth1-a">D1A</a><a href="/depth1-b">D1B</a></body></html>`)
		case "/depth1-a":
			fmt.Fprint(w, `<html><body><a href="/depth2-a">D2A</a></body></html>`)
		case "/depth1-b":
			fmt.Fprint(w, `<html><body><a href="/depth2-b">D2B</a></body></html>`)
		case "/depth2-a":
			fmt.Fprint(w, `<html><body><a href="/depth3-a">D3A</a></body></html>`)
		case "/depth2-b":
			fmt.Fprint(w, `<html><body><a href="/depth3-b">D3B</a></body></html>`)
		case "/depth3-a", "/depth3-b":
			fmt.Fprint(w, `<html><body>Leaf</body></html>`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	client := probe.NewClient(probe.Options{
		RequestTimeout: 5 * time.Second,
	})

	// Case 1: MaxDepth: 1 -> only root and depth1-* can be crawled
	optsDepth := discovery.CrawlOptions{
		MaxPages:    50,
		MaxDepth:    1,
		ReadRobots:  false,
		ReadSitemap: false,
	}
	resDepth, err := discovery.Crawl(context.Background(), client, server.URL+"/", optsDepth)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range resDepth.Pages {
		if strings.Contains(p.URL, "depth2") || strings.Contains(p.URL, "depth3") {
			t.Fatalf("depth limit violated: page %s crawled at depth limit 1", p.URL)
		}
	}

	// Case 2: MaxPages: 2 -> at most 2 pages crawled
	optsPages := discovery.CrawlOptions{
		MaxPages:    2,
		MaxDepth:    5,
		ReadRobots:  false,
		ReadSitemap: false,
	}
	resPages, err := discovery.Crawl(context.Background(), client, server.URL+"/", optsPages)
	if err != nil {
		t.Fatal(err)
	}
	if len(resPages.Pages) != 2 {
		t.Fatalf("expected exactly 2 pages, got %d", len(resPages.Pages))
	}
}

// TestCrawler_RobotsAndSitemapSeeds verifies that robots.txt disallow/allow paths
// and sitemap.xml <loc> entries are parsed and crawled as seed URLs.
func TestCrawler_RobotsAndSitemapSeeds(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/robots.txt":
			w.Header().Set("Content-Type", "text/plain")
			fmt.Fprint(w, "User-agent: *\nDisallow: /admin-panel\nAllow: /public-api\nSitemap: /custom-sitemap.xml\n")
		case "/custom-sitemap.xml", "/sitemap.xml":
			w.Header().Set("Content-Type", "application/xml")
			fmt.Fprint(w, `<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <url><loc>/sitemap-portal</loc></url>
</urlset>`)
		case "/":
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprint(w, `<html><body><a href="/index-link">Home</a></body></html>`)
		case "/admin-panel":
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprint(w, `<html><body>
				<form action="/login" method="POST">
					<input name="admin_user" />
					<input name="admin_pass" type="password" />
				</form>
			</body></html>`)
		case "/sitemap-portal":
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprint(w, `<html><body>
				<a href="/portal-dest?token=seed123">Portal</a>
			</body></html>`)
		default:
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprint(w, `<html><body>generic page</body></html>`)
		}
	}))
	defer server.Close()

	client := probe.NewClient(probe.Options{
		RequestTimeout: 5 * time.Second,
	})

	opts := discovery.CrawlOptions{
		MaxPages:    10,
		MaxDepth:    2,
		ReadRobots:  true,
		ReadSitemap: true,
	}

	res, err := discovery.Crawl(context.Background(), client, server.URL+"/", opts)
	if err != nil {
		t.Fatalf("crawl with robots and sitemap: %v", err)
	}

	foundAdmin := false
	foundPortal := false
	for _, p := range res.Pages {
		if strings.Contains(p.URL, "/admin-panel") {
			foundAdmin = true
		}
		if strings.Contains(p.URL, "/sitemap-portal") {
			foundPortal = true
		}
	}
	if !foundAdmin {
		t.Fatal("expected /admin-panel from robots.txt to be crawled")
	}
	if !foundPortal {
		t.Fatal("expected /sitemap-portal from sitemap.xml to be crawled")
	}

	foundAdminParam := false
	foundTokenParam := false
	for _, pt := range res.SurfacePoints {
		if pt.ParamName == "admin_user" {
			foundAdminParam = true
		}
		if pt.ParamName == "token" {
			foundTokenParam = true
		}
	}
	if !foundAdminParam {
		t.Fatal("expected admin_user from /admin-panel form in SurfacePoints")
	}
	if !foundTokenParam {
		t.Fatal("expected token query param from /sitemap-portal in SurfacePoints")
	}
}

// TestCrawler_CycleHandling verifies that circular link references do not cause
// infinite loops or duplicate page processing.
func TestCrawler_CycleHandling(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		switch r.URL.Path {
		case "/a":
			fmt.Fprint(w, `<html><body><a href="/b">Go to B</a></body></html>`)
		case "/b":
			fmt.Fprint(w, `<html><body><a href="/a">Go to A</a></body></html>`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	client := probe.NewClient(probe.Options{
		RequestTimeout: 5 * time.Second,
	})

	opts := discovery.CrawlOptions{
		MaxPages:    10,
		MaxDepth:    10,
		ReadRobots:  false,
		ReadSitemap: false,
	}

	done := make(chan struct{})
	go func() {
		res, err := discovery.Crawl(context.Background(), client, server.URL+"/a", opts)
		if err != nil {
			t.Errorf("crawl failed: %v", err)
		}
		if len(res.Pages) != 2 {
			t.Errorf("expected exactly 2 distinct pages (a and b), got %d", len(res.Pages))
		}
		close(done)
	}()

	select {
	case <-done:
		// Succeeded promptly
	case <-time.After(3 * time.Second):
		t.Fatal("crawler stuck in infinite loop on circular link graph")
	}
}

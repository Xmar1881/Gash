// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Module: github.com/Xmar1881/Gash

package engine

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/Xmar1881/Gash/internal/auth"
	"github.com/Xmar1881/Gash/internal/discovery"
	"github.com/Xmar1881/Gash/internal/headless"
	"github.com/Xmar1881/Gash/internal/plugin"
	"github.com/Xmar1881/Gash/internal/plugin/loader"
	"github.com/Xmar1881/Gash/internal/probe"
)

func spaTestClient() *probe.Client {
	policy := plugin.NewPolicySession(plugin.PolicyConfig{
		MaxRequestsPerTarget: 10000,
		MaxRequestsTotal:     10000,
		RatePerSecond:        0,
	}, nil)
	return probe.NewClient(probe.Options{Policy: policy})
}

func spaTestPage(url, body string) discovery.CrawlPage {
	return discovery.CrawlPage{
		URL:     url,
		Status:  http.StatusOK,
		Headers: http.Header{"Content-Type": []string{"text/html; charset=utf-8"}},
		Body:    []byte(body),
	}
}

func TestRunSPACrawlMergesSurfaceAndFollowsEndpoints(t *testing.T) {
	var mu sync.Mutex
	hits := map[string]int{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		hits[r.URL.Path]++
		mu.Unlock()
		w.Header().Set("Content-Type", "text/html")
		switch r.URL.Path {
		case "/api/list":
			_, _ = w.Write([]byte(`<html><body><form method="GET" action="/submit"><input name="term" value="x"></form></body></html>`))
		case "/app":
			_, _ = w.Write([]byte(`<html><body>app</body></html>`))
		default:
			_, _ = w.Write([]byte(`<html><body>plain</body></html>`))
		}
	}))
	defer srv.Close()

	outside := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("out-of-scope server must not be contacted: %s", r.URL)
		_, _ = w.Write([]byte("outside"))
	}))
	defer outside.Close()

	cfg := DefaultConfig()
	cfg.BrowserCrawl = true
	cfg.BrowserCrawlPages = 10
	cfg.RatePerSecond = 0
	cfg.Scope = []string{srv.URL}
	cfg.Auth = auth.New()
	if err := cfg.Auth.ParseCookie("session=abc; theme=dark"); err != nil {
		t.Fatal(err)
	}
	var rendered []string
	cfg.BrowserCrawlFunc = func(ctx context.Context, pageURL string, opts headless.RenderOptions) (headless.RenderedPage, error) {
		rendered = append(rendered, pageURL)
		if opts.Cookies["session"] != "abc" {
			t.Fatalf("renderer cookie seed = %v, want session=abc", opts.Cookies)
		}
		if opts.AllowedURL == nil || !opts.AllowedURL(srv.URL+"/api/list") {
			t.Fatal("in-scope endpoint must be allowed")
		}
		if opts.AllowedURL(outside.URL + "/leak") {
			t.Fatal("out-of-scope endpoint must be denied")
		}
		return headless.RenderedPage{
			URL:  pageURL,
			HTML: `<html><body><form method="GET" action="/search"><input name="q" value="1"></form></body></html>`,
			NetworkURLs: []string{
				srv.URL + "/api/list",
				srv.URL + "/api/items?q=1",
				srv.URL + "/static/app.js",
				outside.URL + "/leak",
			},
		}, nil
	}
	e := New(plugin.NewRegistry(), cfg)

	crawlRes := &discovery.CrawlResult{
		Pages: []discovery.CrawlPage{
			spaTestPage(srv.URL+"/app", `<html><body><div id="app"><script>boot()</script></div></body></html>`),
			spaTestPage(srv.URL+"/plain", `<html><body>plain</body></html>`),
			spaTestPage(outside.URL+"/out", `<html><body><script>leak()</script></body></html>`),
		},
	}
	points, skipped, stats := e.runSPACrawl(t.Context(), srv.URL, spaTestClient(), crawlRes, nil)
	if len(skipped) != 0 {
		t.Fatalf("unexpected skips: %+v", skipped)
	}
	for _, got := range rendered {
		if strings.HasPrefix(got, outside.URL) {
			t.Fatalf("out-of-scope page was rendered: %s", got)
		}
	}
	if len(rendered) != 2 {
		t.Fatalf("rendered pages = %v, want app+plain", rendered)
	}
	if stats["spa_pages_rendered"] != 2 {
		t.Fatalf("spa_pages_rendered = %d, want 2", stats["spa_pages_rendered"])
	}
	if stats["spa_endpoints"] != 1 {
		t.Fatalf("spa_endpoints = %d, want 1 (in-scope only)", stats["spa_endpoints"])
	}
	if stats["spa_forms"] != 2 {
		t.Fatalf("spa_forms = %d, want 2 (rendered + followed)", stats["spa_forms"])
	}
	if stats["spa_skipped"] != 1 {
		t.Fatalf("spa_skipped = %d, want 1 (out-of-scope page)", stats["spa_skipped"])
	}

	wantPoints := map[string]bool{
		spaPointKey(srv.URL+"/search", "GET", "query", "q"):    true,
		spaPointKey(srv.URL+"/api/items", "GET", "query", "q"): true,
		spaPointKey(srv.URL+"/submit", "GET", "query", "term"): true,
	}
	for _, p := range points {
		delete(wantPoints, spaPointKey(p.URL, p.Method, p.ParamLocation, p.ParamName))
	}
	if len(wantPoints) != 0 {
		t.Fatalf("missing points: %v (got %+v)", wantPoints, points)
	}
	if len(crawlRes.Forms) != 2 {
		t.Fatalf("forms = %d, want 2: %+v", len(crawlRes.Forms), crawlRes.Forms)
	}
	mu.Lock()
	listHits := hits["/api/list"]
	submitHits := hits["/submit"]
	mu.Unlock()
	if listHits != 1 {
		t.Fatalf("/api/list hits = %d, want 1", listHits)
	}
	if submitHits != 0 {
		t.Fatalf("form action must not be submitted during discovery, got %d", submitHits)
	}
}

func TestRunSPACrawlDedupesExistingPoints(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<html><body><script>app()</script></body></html>`))
	}))
	defer srv.Close()

	cfg := DefaultConfig()
	cfg.BrowserCrawl = true
	cfg.BrowserCrawlPages = 1
	cfg.RatePerSecond = 0
	cfg.BrowserCrawlFunc = func(ctx context.Context, pageURL string, opts headless.RenderOptions) (headless.RenderedPage, error) {
		return headless.RenderedPage{
			URL:  pageURL,
			HTML: `<html><body><form method="GET" action="/search"><input name="q" value="1"></form></body></html>`,
		}, nil
	}
	e := New(plugin.NewRegistry(), cfg)
	crawlRes := &discovery.CrawlResult{Pages: []discovery.CrawlPage{spaTestPage(srv.URL+"/", `<html><body>app</body></html>`)}}
	existing := []loader.JSPoint{{URL: srv.URL + "/search", Method: "GET", ParamName: "q", ParamLocation: "query", Value: "old"}}
	points, _, _ := e.runSPACrawl(t.Context(), srv.URL, nil, crawlRes, existing)
	if len(points) != 0 {
		t.Fatalf("existing point must not be duplicated: %+v", points)
	}
}

func TestRunSPACrawlRendererErrorIsNotFatal(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<html><body><script>app()</script></body></html>`))
	}))
	defer srv.Close()

	cfg := DefaultConfig()
	cfg.BrowserCrawl = true
	cfg.BrowserCrawlPages = 1
	cfg.RatePerSecond = 0
	cfg.BrowserCrawlFunc = func(ctx context.Context, pageURL string, opts headless.RenderOptions) (headless.RenderedPage, error) {
		return headless.RenderedPage{}, errors.New("navigation exploded")
	}
	e := New(plugin.NewRegistry(), cfg)
	crawlRes := &discovery.CrawlResult{Pages: []discovery.CrawlPage{spaTestPage(srv.URL+"/", `<html><body>app</body></html>`)}}
	points, skipped, stats := e.runSPACrawl(t.Context(), srv.URL, nil, crawlRes, nil)
	if len(points) != 0 {
		t.Fatalf("renderer error must not invent points: %+v", points)
	}
	if stats["spa_skipped"] != 1 {
		t.Fatalf("spa_skipped = %d, want 1", stats["spa_skipped"])
	}
	if len(skipped) != 1 || !strings.Contains(skipped[0].Reason, "render error") {
		t.Fatalf("renderer error must leave one audit record: %+v", skipped)
	}
}

func TestRunSPACrawlDisabled(t *testing.T) {
	e := New(plugin.NewRegistry(), DefaultConfig())
	points, skipped, stats := e.runSPACrawl(t.Context(), "http://127.0.0.1:1", nil, &discovery.CrawlResult{}, nil)
	if len(points) != 0 || len(skipped) != 0 || stats["spa_pages_rendered"] != 0 {
		t.Fatalf("disabled crawl must be inert: %v %v %v", points, skipped, stats)
	}
}

// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Module: github.com/Xmar1881/Gash

package discovery

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
)

// TestCrawlReportsPageProgress OnPage geri çağrısının her sayfa denemesinde
// artan sayaç ve sayfa bütçesiyle tetiklendiğini doğrular.
// What: 3 sayfalık bir sitede sayaç 1,2,3 ve bütçe 10 olmalı.
// Why: "Sayfa & Yüzey Keşfi" fazı canlı ilerleme göstergesini bu veriyle
// besler; sayaç akmazsa uzun crawl donmuş görünür.
func TestCrawlReportsPageProgress(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<html><body><a href="/a">a</a><a href="/b">b</a></body></html>`))
	})
	mux.HandleFunc("/a", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`<html><body>a</body></html>`))
	})
	mux.HandleFunc("/b", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`<html><body>b</body></html>`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	var (
		mu     sync.Mutex
		counts []int
		totals []int
		urls   []string
	)
	_, err := Crawl(context.Background(), testClient(t, srv.URL), srv.URL+"/", CrawlOptions{
		MaxPages: 10, MaxDepth: 2, ReadRobots: false, ReadSitemap: false,
		OnPage: func(done, total int, pageURL string) {
			mu.Lock()
			defer mu.Unlock()
			counts = append(counts, done)
			totals = append(totals, total)
			urls = append(urls, pageURL)
		},
	})
	if err != nil {
		t.Fatalf("crawl: %v", err)
	}
	if len(counts) != 3 {
		t.Fatalf("3 sayfa denemesi bekleniyordu, %d alındı: %v", len(counts), urls)
	}
	for i, c := range counts {
		if c != i+1 {
			t.Fatalf("sayaç artan olmalı, alınan: %v", counts)
		}
		if totals[i] != 10 {
			t.Fatalf("sayfa bütçesi 10 bildirilmeli, alınan: %v", totals)
		}
		if urls[i] == "" {
			t.Fatal("ilerleme URL'i boş olmamalı")
		}
	}
}

// TestCrawlUsesOnlyObservedSurfacePoints proves the crawler does not invent
// CommonCandidateParams for every page without parameters. Per-page fallback
// produced synthetic points on stylesheets/favicons and pushed real form
// points out of the per-plugin request budget (measured on DVWA).
func TestCrawlUsesOnlyObservedSurfacePoints(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<html><head><link rel="stylesheet" href="/style.css"></head><body>
			<a href="/about.php">About</a>
			<a href="/search?q=x">Search</a>
		</body></html>`))
	})
	mux.HandleFunc("/about.php", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`<html><body><p>about</p></body></html>`))
	})
	mux.HandleFunc("/search", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`<html><body><p>search</p></body></html>`))
	})
	mux.HandleFunc("/style.css", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/css")
		_, _ = w.Write([]byte(`body{color:#000}`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	client := testClient(t, srv.URL)
	res, err := Crawl(context.Background(), client, srv.URL+"/", CrawlOptions{
		MaxPages: 10, MaxDepth: 2, ReadRobots: false, ReadSitemap: false,
	})
	if err != nil {
		t.Fatalf("crawl: %v", err)
	}
	sawQuery := false
	for _, p := range res.SurfacePoints {
		if p.ParamName == "q" && p.ParamLocation == "query" {
			sawQuery = true
		}
		if p.ParamLocation == "query" && p.ParamName != "q" {
			t.Fatalf("crawler synthesized unobserved point: %+v", p)
		}
	}
	if !sawQuery {
		t.Fatal("observed link query parameter q was not captured")
	}
}

// TestCrawlSkipsStateTogglingLinks proves GET links that flip state
// (?phpids=on) are neither fetched nor turned into injection points. DVWA's
// security.php enables PHPIDS on GET; crawling it muted later SQLi probes.
func TestCrawlSkipsStateTogglingLinks(t *testing.T) {
	var toggled int
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<html><body>
			<a href="/security.php?phpids=on">Enable PHPIDS</a>
			<a href="/search?q=x">Search</a>
		</body></html>`))
	})
	mux.HandleFunc("/security.php", func(w http.ResponseWriter, r *http.Request) {
		toggled++
		_, _ = w.Write([]byte(`<html><body>security</body></html>`))
	})
	mux.HandleFunc("/search", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`<html><body>search</body></html>`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	client := testClient(t, srv.URL)
	res, err := Crawl(context.Background(), client, srv.URL+"/", CrawlOptions{
		MaxPages: 10, MaxDepth: 2, ReadRobots: false, ReadSitemap: false,
	})
	if err != nil {
		t.Fatalf("crawl: %v", err)
	}
	if toggled != 0 {
		t.Fatalf("state-toggling link was fetched %d times", toggled)
	}
	for _, p := range res.SurfacePoints {
		if p.ParamName == "phpids" {
			t.Fatalf("state-toggling point surfaced: %+v", p)
		}
	}
}

func TestIsStateTogglingURL(t *testing.T) {
	on := []string{
		"/security.php?phpids=on",
		"/admin?debug=1",
		"/user?action=delete",
		"/x?state=off",
	}
	for _, raw := range on {
		if !isStateTogglingURL(raw) {
			t.Fatalf("%s should be state-toggling", raw)
		}
	}
	off := []string{
		"/search?q=x",
		"/vulnerabilities/sqli/?id=1&Submit=Submit",
		"/page?page=2",
	}
	for _, raw := range off {
		if isStateTogglingURL(raw) {
			t.Fatalf("%s should not be state-toggling", raw)
		}
	}
}

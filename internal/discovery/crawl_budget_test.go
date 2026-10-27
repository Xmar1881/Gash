// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Module: github.com/Xmar1881/Gash

package discovery

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestCrawlStoredBodyBudget proves retained page bodies stay inside the memory
// budget while every page is still fetched and parsed.
func TestCrawlStoredBodyBudget(t *testing.T) {
	body := `<html><body>` + strings.Repeat("x", 2048) +
		`<a href="/a">a</a><a href="/b">b</a></body></html>`
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(body))
	})
	for _, path := range []string{"/a", "/b"} {
		p := path
		mux.HandleFunc(p, func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write([]byte(body))
		})
	}
	srv := httptest.NewServer(mux)
	defer srv.Close()

	res, err := Crawl(context.Background(), testClient(t, srv.URL), srv.URL+"/", CrawlOptions{
		MaxPages:           3,
		MaxDepth:           1,
		ReadRobots:         false,
		ReadSitemap:        false,
		SkipJSRecon:        true,
		MaxStoredBodyBytes: 2500,
	})
	if err != nil {
		t.Fatalf("crawl: %v", err)
	}
	if len(res.Pages) != 3 {
		t.Fatalf("all 3 pages must still be fetched, got %d", len(res.Pages))
	}
	if res.StoredBodyBytes > 2500 {
		t.Fatalf("stored bytes %d exceed budget 2500", res.StoredBodyBytes)
	}
	if res.BodiesDropped == 0 {
		t.Fatal("at least one body must be truncated or dropped")
	}
	var nilBodies int
	for _, p := range res.Pages {
		if len(p.Body) == 0 {
			nilBodies++
		}
	}
	if nilBodies == 0 {
		t.Fatalf("budget exhaustion must leave an empty retained body, pages=%d", len(res.Pages))
	}
}

// TestCrawlDiscoveredURLsAreCapped proves a link-heavy page cannot grow the
// frontier/visited maps without bound.
func TestCrawlDiscoveredURLsAreCapped(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		var b strings.Builder
		b.WriteString("<html><body>")
		for i := 0; i < 50; i++ {
			fmt.Fprintf(&b, `<a href="/p/%d">p%d</a>`, i, i)
		}
		b.WriteString("</body></html>")
		_, _ = w.Write([]byte(b.String()))
	})
	mux.HandleFunc("/p/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte("<html><body>ok</body></html>"))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	res, err := Crawl(context.Background(), testClient(t, srv.URL), srv.URL+"/", CrawlOptions{
		MaxPages:          50,
		MaxDepth:          2,
		ReadRobots:        false,
		ReadSitemap:       false,
		SkipJSRecon:       true,
		MaxDiscoveredURLs: 5,
	})
	if err != nil {
		t.Fatalf("crawl: %v", err)
	}
	if res.URLsDropped == 0 {
		t.Fatal("link-heavy page must report dropped URLs once the cap is reached")
	}
	if len(res.Pages) > 6 {
		t.Fatalf("discovery cap 5 must bound fetched pages, got %d", len(res.Pages))
	}
}

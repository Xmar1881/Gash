// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Module: github.com/Xmar1881/Gash

package discovery

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

func TestIsSessionDestructiveURL(t *testing.T) {
	cases := []struct {
		url  string
		want bool
	}{
		{"http://127.0.0.1:8081/logout.php", true},
		{"http://127.0.0.1:8081/logout.php?return=/index.php", true},
		{"http://127.0.0.1:8081/session/sign-out/", true},
		{"http://127.0.0.1:8081/account/logoff", true},
		{"http://127.0.0.1:8081/login.php", false},
		{"http://127.0.0.1:8081/logout-help", false},
		{"http://127.0.0.1:8081/logout/help", false},
	}
	for _, tc := range cases {
		if got := isSessionDestructiveURL(tc.url); got != tc.want {
			t.Errorf("isSessionDestructiveURL(%q) = %v, want %v", tc.url, got, tc.want)
		}
	}
}

func TestCrawlSkipsSessionDestructiveLinks(t *testing.T) {
	var logoutHits, aboutHits int32
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<html><body>
			<a href="/about.php">About</a>
			<a href="/logout.php">Logout</a>
		</body></html>`))
	})
	mux.HandleFunc("/about.php", func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&aboutHits, 1)
		_, _ = w.Write([]byte(`<html><body>about</body></html>`))
	})
	mux.HandleFunc("/logout.php", func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&logoutHits, 1)
		_, _ = w.Write([]byte(`<html><body>logged out</body></html>`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	client := testClient(t, srv.URL)
	res, err := Crawl(context.Background(), client, srv.URL+"/", CrawlOptions{
		MaxPages: 5, MaxDepth: 1, ReadRobots: false, ReadSitemap: false,
	})
	if err != nil {
		t.Fatalf("crawl: %v", err)
	}
	if atomic.LoadInt32(&logoutHits) != 0 {
		t.Fatalf("crawler followed a session-destructive logout link (%d hits)", logoutHits)
	}
	if atomic.LoadInt32(&aboutHits) != 1 {
		t.Fatalf("about.php hits = %d, want 1", aboutHits)
	}
	for _, p := range res.Pages {
		if isSessionDestructiveURL(p.URL) {
			t.Fatalf("crawl result contains session-destructive URL %q", p.URL)
		}
	}
}

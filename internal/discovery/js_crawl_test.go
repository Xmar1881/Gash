// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Modül: github.com/Xmar1881/Gash

package discovery

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

// TestCrawlCollectsSameOriginJSSources kanıtlar: inline + same-origin harici JS
// toplanır, üçüncü taraf script HİÇ çekilmez.
// What: Sayfa iki script taşır (same-origin src + inline) ve bir üçüncü taraf
// src trap'i; trap sunucusu sıfır isabet görmelidir.
// Why: Pasif recon üçüncü taraf trafiği üretmez (precision + kapsam disiplini).
func TestCrawlCollectsSameOriginJSSources(t *testing.T) {
	var thirdHits, appHits int32
	third := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&thirdHits, 1)
		w.Header().Set("Content-Type", "application/javascript")
		_, _ = w.Write([]byte(`fetch("/third?q=1");`))
	}))
	defer third.Close()

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<html><head>` +
			`<script src="/app.js"></script>` +
			`<script>var u = "/api/inline?q=1";</script>` +
			`<script src="` + third.URL + `/tracker.js"></script>` +
			`</head><body>ok</body></html>`))
	})
	mux.HandleFunc("/app.js", func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&appHits, 1)
		w.Header().Set("Content-Type", "application/javascript")
		_, _ = w.Write([]byte(`fetch("/api/app?x=2");`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	client := testClient(t, srv.URL)
	res, err := Crawl(context.Background(), client, srv.URL+"/", CrawlOptions{
		MaxPages: 3, MaxDepth: 1, ReadRobots: false, ReadSitemap: false,
	})
	if err != nil {
		t.Fatalf("crawl: %v", err)
	}
	if res.JSFilesFetched != 1 {
		t.Fatalf("JSFilesFetched %d, beklenen 1", res.JSFilesFetched)
	}
	if atomic.LoadInt32(&appHits) != 1 {
		t.Fatalf("app.js isabeti %d, beklenen 1", appHits)
	}
	var haveApp, haveInline bool
	for _, src := range res.JSSources {
		if !src.Inline && strings.HasSuffix(src.URL, "/app.js") {
			haveApp = true
		}
		if src.Inline && strings.Contains(string(src.Body), "/api/inline") {
			haveInline = true
		}
	}
	if !haveApp {
		t.Fatalf("harici app.js JSSources'ta yok: %+v", res.JSSources)
	}
	if !haveInline {
		t.Fatalf("inline script JSSources'ta yok: %+v", res.JSSources)
	}
	if got := atomic.LoadInt32(&thirdHits); got != 0 {
		t.Fatalf("üçüncü taraf JS çekildi: %d isabet", got)
	}

	// Toplanan gövdeler AnalyzeJS'e merkezi olarak beslenir (uçtan uca yol).
	rep := AnalyzeJS(srv.URL+"/", []byte(`var u = "/api/inline?q=1";`))
	if len(rep.Endpoints) != 1 || !strings.Contains(rep.Endpoints[0].Resolved, "/api/inline") {
		t.Fatalf("inline endpoint çıkarımı yanlış: %+v", rep.Endpoints)
	}
}

// TestCrawlSkipJSRecon mini/geri-besleme crawl'larının JS toplamadığını kanıtlar.
// What: SkipJSRecon=true ile ne src çekilir ne inline toplanır.
// Why: Aynı sayfa için çift analiz/çift istek oluşmamalıdır (ana crawl besler).
func TestCrawlSkipJSRecon(t *testing.T) {
	var appHits int32
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<html><head><script src="/app.js"></script>` +
			`<script>var u = "/api/inline?q=1";</script></head><body>ok</body></html>`))
	})
	mux.HandleFunc("/app.js", func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&appHits, 1)
		_, _ = w.Write([]byte(`fetch("/api/app?x=2");`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	client := testClient(t, srv.URL)
	res, err := Crawl(context.Background(), client, srv.URL+"/", CrawlOptions{
		MaxPages: 3, MaxDepth: 1, ReadRobots: false, ReadSitemap: false,
		SkipJSRecon: true,
	})
	if err != nil {
		t.Fatalf("crawl: %v", err)
	}
	if res.JSFilesFetched != 0 || len(res.JSSources) != 0 {
		t.Fatalf("SkipJSRecon ile JS toplanmamalı: fetched=%d sources=%d", res.JSFilesFetched, len(res.JSSources))
	}
	if atomic.LoadInt32(&appHits) != 0 {
		t.Fatalf("SkipJSRecon ile app.js çekildi: %d isabet", appHits)
	}
}

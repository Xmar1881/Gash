//go:build deep

// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Module: github.com/Xmar1881/Gash

package headless

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// TestDeepRenderCapturesSPASurface exercises the real browser renderer when
// Chrome exists: cookie seeding, script-created form/link, XHR capture, and
// out-of-scope request blocking.
func TestDeepRenderCapturesSPASurface(t *testing.T) {
	if !Available() {
		if os.Getenv("CI") != "" {
			t.Fatal("headless zorunlu: CI ortaminda chrome bulunamadi (no Chrome binary found in CI)")
		}
		t.Skip("headless yok: chrome bulunamadı, skip")
	}

	var trackerHits atomic.Int64
	tracker := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		trackerHits.Add(1)
		fmt.Fprint(w, "tracked")
	}))
	defer tracker.Close()

	var postHits atomic.Int64
	app := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/items":
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `{"items":[]}`)
		case "/mutate":
			postHits.Add(1)
			fmt.Fprint(w, "mutated")
		case "/":
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprintf(w, `<!doctype html><html><head><title>spa</title></head><body>
<div id="session"></div><div id="root"></div>
<script>
document.getElementById('session').textContent = document.cookie;
setTimeout(function(){
  var f = document.createElement('form');
  f.method = 'GET';
  f.action = '/search';
  var i = document.createElement('input');
  i.type = 'text';
  i.name = 'q';
  f.appendChild(i);
  document.getElementById('root').appendChild(f);
  var a = document.createElement('a');
  a.href = '/details?id=7';
  a.textContent = 'details';
  document.getElementById('root').appendChild(a);
}, 50);
fetch('/api/items?q=1').catch(function(){});
fetch('/mutate', {method: 'POST', body: 'x=1'}).catch(function(){});
fetch('%s/track?token=secret').catch(function(){});
</script></body></html>`, tracker.URL)
		default:
			fmt.Fprint(w, "ok")
		}
	}))
	defer app.Close()

	appURL, err := url.Parse(app.URL)
	if err != nil {
		t.Fatal(err)
	}
	page, err := RenderPage(t.Context(), app.URL+"/", RenderOptions{
		Cookies:        map[string]string{"session": "gash-session-1"},
		Timeout:        20 * time.Second,
		MaxNetworkURLs: 50,
		AllowedURL: func(raw string) bool {
			u, uerr := url.Parse(raw)
			return uerr == nil && strings.EqualFold(u.Host, appURL.Host)
		},
	})
	if err != nil {
		t.Fatalf("RenderPage error: %v", err)
	}
	if page.URL == "" || page.URL != app.URL+"/" {
		t.Fatalf("final URL = %q, want %q", page.URL, app.URL+"/")
	}
	if !strings.Contains(page.HTML, `name="q"`) {
		t.Fatalf("rendered HTML missing script-created form field: %s", page.HTML)
	}
	if !strings.Contains(page.HTML, `href="/details?id=7"`) {
		t.Fatalf("rendered HTML missing script-created link: %s", page.HTML)
	}
	if !strings.Contains(page.HTML, "gash-session-1") {
		t.Fatalf("rendered HTML missing seeded cookie: %s", page.HTML)
	}
	foundAPI := false
	for _, obs := range page.NetworkURLs {
		if strings.Contains(obs, "/api/items?q=1") {
			foundAPI = true
		}
		if strings.HasPrefix(obs, tracker.URL) {
			t.Fatalf("out-of-scope URL leaked into surface: %s", obs)
		}
	}
	if !foundAPI {
		t.Fatalf("XHR URL not captured: %v", page.NetworkURLs)
	}
	if got := trackerHits.Load(); got != 0 {
		t.Fatalf("out-of-scope tracker received %d requests, want 0", got)
	}
	if got := postHits.Load(); got != 0 {
		t.Fatalf("non-GET request reached the server %d times, want 0", got)
	}
}

//go:build deep

// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Module: github.com/Xmar1881/Gash

package headless

import (
	"context"
	"fmt"
	"html"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"testing"
	"time"
)

const domFixturePayload = `<img src=x onerror="window.__gashCanary=true">`

// TestDeepDOMFixtureOutcomeMatrix runs the local DOM fixture through the real
// browser and asserts every honest outcome: dangerous sinks confirm, safe
// sinks and reflection-only pages do not, and WAF/server errors never become
// "not vulnerable".
func TestDeepDOMFixtureOutcomeMatrix(t *testing.T) {
	if !Available() {
		if os.Getenv("CI") != "" {
			t.Fatal("headless zorunlu: CI ortaminda chrome bulunamadi (no Chrome binary found in CI)")
		}
		t.Skip("headless yok: chrome bulunamadi, skip")
	}
	srv := newDOMFixtureServer()
	defer srv.Close()

	tests := []struct {
		name     string
		path     string
		location string
		payload  string
		want     Outcome
	}{
		{
			name:     "dangerous hash innerHTML",
			path:     "/danger-hash",
			location: "fragment",
			want:     OutcomeConfirmed,
		},
		{
			name:     "dangerous async hash innerHTML",
			path:     "/danger-hash-async",
			location: "fragment",
			want:     OutcomeConfirmed,
		},
		{
			name:     "dangerous delayed async innerHTML",
			path:     "/danger-hash-delayed",
			location: "fragment",
			want:     OutcomeConfirmed,
		},
		{
			name:     "SPA pushState plus delayed innerHTML",
			path:     "/danger-spa",
			location: "fragment",
			want:     OutcomeConfirmed,
		},
		{
			name:     "dialog-only execution",
			path:     "/danger-hash",
			location: "fragment",
			payload:  `<img src=x onerror="alert(1)">`,
			want:     OutcomeConfirmed,
		},
		{
			name:     "same-origin iframe execution",
			path:     "/danger-iframe",
			location: "fragment",
			want:     OutcomeConfirmed,
		},
		{
			name:     "canary node insertion is not execution",
			path:     "/danger-hash",
			location: "fragment",
			payload:  `<div id="__gash_canary">not execution</div>`,
			want:     OutcomeNotVulnerable,
		},
		{
			name:     "dangerous URLSearchParams innerHTML",
			path:     "/danger-search",
			location: "query",
			want:     OutcomeConfirmed,
		},
		{
			name:     "safe textContent",
			path:     "/safe-text",
			location: "fragment",
			want:     OutcomeNotVulnerable,
		},
		{
			name:     "safe sanitized innerHTML",
			path:     "/safe-sanitized",
			location: "fragment",
			want:     OutcomeNotVulnerable,
		},
		{
			name:     "reflection only",
			path:     "/reflect-only",
			location: "query",
			want:     OutcomeNotVulnerable,
		},
		{
			name:     "waf blocked",
			path:     "/blocked",
			location: "none",
			want:     OutcomeBlocked,
		},
		{
			name:     "server error",
			path:     "/error",
			location: "none",
			want:     OutcomeError,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			payload := tc.payload
			if payload == "" {
				payload = domFixturePayload
			}
			payloadURL, controlURL := domFixtureURLs(srv.URL, tc.path, tc.location, payload)
			res, err := VerifyXSS(context.Background(), payloadURL, controlURL, 20*time.Second)
			if err != nil {
				t.Fatalf("VerifyXSS(%s): %v", tc.name, err)
			}
			if got := res.Outcome(); got != tc.want {
				t.Fatalf("Outcome() = %s, want %s (payload=%d control=%d triggered=%v clean=%v)",
					got, tc.want, res.PayloadStatus, res.ControlStatus, res.Triggered, res.ControlClean)
			}
		})
	}
}

func TestDeepDOMFixtureNavigationError(t *testing.T) {
	if !Available() {
		if os.Getenv("CI") != "" {
			t.Fatal("headless zorunlu: CI ortaminda chrome bulunamadi (no Chrome binary found in CI)")
		}
		t.Skip("headless yok: chrome bulunamadi, skip")
	}
	srv := newDOMFixtureServer()
	base := srv.URL
	srv.Close()

	_, err := VerifyXSS(context.Background(), base+"/#payload", base+"/#control", 10*time.Second)
	if err == nil {
		t.Fatal("closed local server must produce a navigation error, not a clean negative")
	}
}

func domFixtureURLs(base, path, location, payload string) (string, string) {
	switch location {
	case "fragment":
		return base + path + "#" + url.PathEscape(payload), base + path + "#gash-control-neutral"
	case "query":
		return base + path + "?q=" + url.QueryEscape(payload), base + path + "?q=gash-control-neutral"
	default:
		return base + path, base + path + "?control=1"
	}
}

func newDOMFixtureServer() *httptest.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("/danger-hash", domPage(`
var h = decodeURIComponent(location.hash.slice(1));
document.getElementById('sink').innerHTML = h;`))
	mux.HandleFunc("/danger-hash-async", domPage(`
var h = decodeURIComponent(location.hash.slice(1));
setTimeout(function(){ document.getElementById('sink').innerHTML = h; }, 50);`))
	mux.HandleFunc("/danger-hash-delayed", domPage(`
var h = decodeURIComponent(location.hash.slice(1));
setTimeout(function(){ document.getElementById('sink').innerHTML = h; }, 900);`))
	mux.HandleFunc("/danger-spa", domPage(`
var h = decodeURIComponent(location.hash.slice(1));
history.pushState({}, '', location.pathname + '?spa=1' + location.hash);
setTimeout(function(){ document.getElementById('sink').innerHTML = h; }, 600);`))
	mux.HandleFunc("/danger-iframe", domPage(`
var h = decodeURIComponent(location.hash.slice(1));
var f = document.createElement('iframe');
f.srcdoc = '<html><body>' + h + '</body></html>';
document.body.appendChild(f);`))
	mux.HandleFunc("/danger-search", domPage(`
var q = new URLSearchParams(location.search).get('q') || '';
document.getElementById('sink').innerHTML = q;`))
	mux.HandleFunc("/safe-text", domPage(`
var h = decodeURIComponent(location.hash.slice(1));
document.getElementById('sink').textContent = h;`))
	mux.HandleFunc("/safe-sanitized", domPage(`
var h = decodeURIComponent(location.hash.slice(1)).replace(/[<>]/g, '');
document.getElementById('sink').innerHTML = h;`))
	mux.HandleFunc("/reflect-only", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprintf(w, `<html><body><div id="out">%s</div></body></html>`,
			html.EscapeString(r.URL.Query().Get("q")))
	})
	mux.HandleFunc("/blocked", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		fmt.Fprint(w, "blocked by local WAF")
	})
	mux.HandleFunc("/error", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprint(w, "local fixture error")
	})
	return httptest.NewServer(mux)
}

func domPage(script string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprintf(w, `<!doctype html><html><body><div id="sink"></div><script>%s</script></body></html>`, script)
	}
}

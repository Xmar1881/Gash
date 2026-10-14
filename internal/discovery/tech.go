// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Module: github.com/Xmar1881/Gash

package discovery

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"strings"
)

// TechFingerprint is the passive runtime fingerprint of one response.
// What: Technology set plus capability set derived without extra probing.
// Why: Chain gating (requires_tech / requires) needs runtime context, not
// just user-declared --tech; all signals here are passive header, cookie,
// body-marker, and favicon-hash observations.
type TechFingerprint struct {
	// Tech lists normalized technology slugs (wordpress, nginx, ...).
	Tech []string
	// Capabilities lists runtime abilities (login-form, graphql-endpoint, ...).
	Capabilities map[string]bool
	// FaviconHash is the sha256 of the favicon bytes when fetched (empty if not).
	FaviconHash string
}

// FingerprintTech derives tech + capabilities from one passive response.
// What: Header, cookie-name, body-marker, and generator-meta scan.
// Why: Single function serves engine pre-schedule detection and offline tests
// without network; known-path probing stays in the engine (bounded, scoped).
func FingerprintTech(headers http.Header, cookies []*http.Cookie, body string) TechFingerprint {
	out := TechFingerprint{Capabilities: map[string]bool{}}
	seen := map[string]bool{}
	addTech := func(t string) {
		t = strings.ToLower(strings.TrimSpace(t))
		if t == "" || seen[t] {
			return
		}
		seen[t] = true
		out.Tech = append(out.Tech, t)
	}
	addCap := func(c string) {
		out.Capabilities[strings.ToLower(strings.TrimSpace(c))] = true
	}

	srv := ""
	if headers != nil {
		srv = strings.ToLower(headers.Get("Server") + " " + headers.Get("X-Powered-By") + " " + headers.Get("X-AspNet-Version") + " " + headers.Get("X-Generator") + " " + headers.Get("Via"))
	}
	lowerBody := strings.ToLower(body)

	// Server / powered-by signals.
	switch {
	case strings.Contains(srv, "wordpress") || strings.Contains(lowerBody, "wp-content") || strings.Contains(lowerBody, "wp-json") || strings.Contains(lowerBody, "wp-includes"):
		addTech("wordpress")
	}
	if strings.Contains(srv, "nginx") {
		addTech("nginx")
	}
	if strings.Contains(srv, "apache") {
		addTech("apache")
	}
	if strings.Contains(srv, "express") || strings.Contains(lowerBody, "express") && strings.Contains(srv, "node") {
		addTech("express")
	}
	if strings.Contains(srv, "microsoft-iis") || strings.Contains(srv, "iis/") {
		addTech("iis")
	}
	if strings.Contains(srv, "asp.net") || strings.Contains(lowerBody, "__viewstate") {
		addTech("aspnet")
	}
	if strings.Contains(srv, "django") || strings.Contains(lowerBody, "csrftoken") {
		addTech("django")
	}
	if strings.Contains(srv, "rails") || strings.Contains(srv, "phusion") {
		addTech("rails")
	}
	if strings.Contains(srv, "laravel") {
		addTech("laravel")
	}
	if strings.Contains(srv, "cloudflare") {
		addTech("cloudflare")
	}
	if headers != nil && (headers.Get("Cf-Ray") != "" || headerHasCookie(headers, "__cf_bm")) {
		addTech("cloudflare")
	}
	if strings.Contains(srv, "php") {
		addTech("php")
	}

	// Cookie-name signals (passive, no extra request).
	for _, c := range cookies {
		if c == nil {
			continue
		}
		n := strings.ToLower(c.Name)
		switch {
		case strings.Contains(n, "phpsessid"):
			addTech("php")
		case strings.Contains(n, "jsessionid"):
			addTech("java")
		case strings.Contains(n, "asp.net_sessionid") || strings.Contains(n, "aspnet"):
			addTech("aspnet")
		case strings.Contains(n, "csrftoken"):
			addTech("django")
		case strings.Contains(n, "laravel_session") || strings.Contains(n, "xsrf-token"):
			addTech("laravel")
		case strings.Contains(n, "next-auth") || strings.Contains(n, "__next"):
			addTech("nextjs")
		}
	}

	// Body markers.
	if strings.Contains(lowerBody, "_next/") || strings.Contains(lowerBody, "__next_data__") {
		addTech("nextjs")
	}
	if strings.Contains(lowerBody, "graphql") || strings.Contains(lowerBody, "/graphql") || strings.Contains(lowerBody, "__typename") {
		addTech("graphql")
	}
	if strings.Contains(lowerBody, "swagger") || strings.Contains(lowerBody, "openapi") {
		addTech("openapi")
	}
	if strings.Contains(lowerBody, "drupal") {
		addTech("drupal")
	}
	if strings.Contains(lowerBody, "joomla") {
		addTech("joomla")
	}
	if strings.Contains(lowerBody, "generator") && strings.Contains(lowerBody, "wordpress") {
		addTech("wordpress")
	}

	// Capabilities (chain provider vocabulary, passive only).
	if strings.Contains(lowerBody, `type="password"`) || strings.Contains(lowerBody, "type='password'") || strings.Contains(lowerBody, "/login") {
		addCap("login-form")
	}
	if strings.Contains(lowerBody, "/graphql") || strings.Contains(lowerBody, "graphql") {
		addCap("graphql-endpoint")
	}
	if strings.Contains(lowerBody, `type="file"`) || strings.Contains(lowerBody, "type='file'") {
		addCap("upload-form")
	}
	if strings.Contains(lowerBody, "/api/") {
		addCap("rest-api")
	}
	if strings.Contains(lowerBody, "swagger") || strings.Contains(lowerBody, "openapi.json") || strings.Contains(lowerBody, "openapi.yaml") {
		addCap("openapi-spec")
	}
	if strings.Contains(lowerBody, "<form") {
		addCap("html-form")
	}
	return out
}

// FaviconHash hashes favicon bytes for technology matching.
// What: sha256 of /favicon.ico bytes (empty input yields empty hash).
// Why: Framework favicons are stable; the hash is a passive tech hint that
// never leaves the target host (same-origin fetch only).
func FaviconHash(data []byte) string {
	if len(data) == 0 {
		return ""
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func headerHasCookie(h http.Header, name string) bool {
	for _, c := range h["Set-Cookie"] {
		if strings.Contains(strings.ToLower(c), strings.ToLower(name)) {
			return true
		}
	}
	for _, c := range h["Cookie"] {
		if strings.Contains(strings.ToLower(c), strings.ToLower(name)) {
			return true
		}
	}
	return false
}

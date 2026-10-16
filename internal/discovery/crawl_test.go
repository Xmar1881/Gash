// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Module: github.com/Xmar1881/Gash

package discovery

import (
	"net/url"
	"testing"
)

func TestParseRobotsTxt(t *testing.T) {
	robotsContent := []byte(`
# Robots file for testing
User-agent: *
Disallow: /admin
Disallow: /api/private/
Allow: /public/
Sitemap: http://example.com/sitemap.xml
Sitemap: https://example.com/sitemap2.xml
Disallow: /*.pdf
`)
	paths, sitemaps := parseRobotsTxt(robotsContent)
	if len(paths) != 3 {
		t.Fatalf("expected 3 valid paths (/admin, /api/private/, /public/), got %d: %v", len(paths), paths)
	}
	if len(sitemaps) != 2 {
		t.Fatalf("expected 2 sitemaps, got %d: %v", len(sitemaps), sitemaps)
	}
	if sitemaps[0] != "http://example.com/sitemap.xml" {
		t.Errorf("unexpected sitemap: %s", sitemaps[0])
	}
}

func TestParseSitemapXML(t *testing.T) {
	xmlContent := []byte(`<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <url>
    <loc>https://example.com/home</loc>
    <lastmod>2026-01-01</lastmod>
  </url>
  <url>
    <loc>   https://example.com/about   </loc>
  </url>
  <url>
    <loc>https://example.com/contact?src=web</loc>
  </url>
</urlset>`)
	locs := parseSitemapXML(xmlContent)
	if len(locs) != 3 {
		t.Fatalf("expected 3 loc URLs, got %d: %v", len(locs), locs)
	}
	if locs[0] != "https://example.com/home" {
		t.Errorf("unexpected loc: %s", locs[0])
	}
	if locs[1] != "https://example.com/about" {
		t.Errorf("unexpected loc: %s", locs[1])
	}
	if locs[2] != "https://example.com/contact?src=web" {
		t.Errorf("unexpected loc: %s", locs[2])
	}
}

func TestUrlSkeleton(t *testing.T) {
	u1, _ := url.Parse("http://example.com/search?q=foo&page=1")
	u2, _ := url.Parse("http://example.com/search?page=2&q=bar")
	u3, _ := url.Parse("http://example.com/search?q=foo")

	skel1 := urlSkeleton(u1)
	skel2 := urlSkeleton(u2)
	skel3 := urlSkeleton(u3)

	if skel1 != skel2 {
		t.Fatalf("expected identical skeleton for same query keys: %q vs %q", skel1, skel2)
	}
	if skel1 == skel3 {
		t.Fatalf("expected different skeleton for different query keys: %q vs %q", skel1, skel3)
	}
}

func TestExtractLinks(t *testing.T) {
	htmlContent := []byte(`
<html>
<head>
	<link href="/styles.css" rel="stylesheet" />
</head>
<body>
	<a href="/about-us">About</a>
	<a href="javascript:void(0)">Noop</a>
	<a href="mailto:test@example.com">Email</a>
	<form action="/login-post" method="POST">
		<input name="user" />
	</form>
	<iframe src="/embedded-view"></iframe>
</body>
</html>`)
	links := extractLinks(htmlContent)
	expected := map[string]bool{
		"/styles.css":    true,
		"/about-us":      true,
		"/login-post":    true,
		"/embedded-view": true,
	}
	if len(links) != len(expected) {
		t.Fatalf("expected %d links, got %d: %v", len(expected), len(links), links)
	}
	for _, l := range links {
		if !expected[l] {
			t.Errorf("unexpected link found: %s", l)
		}
	}
}

func TestNormalizeURL(t *testing.T) {
	u1, _ := url.Parse("http://example.com/path/#frag")
	u2, _ := url.Parse("http://example.com/path")

	n1 := normalizeURL(u1)
	n2 := normalizeURL(u2)

	if n1 != n2 {
		t.Fatalf("expected normalized URLs to match: %q vs %q", n1, n2)
	}
}

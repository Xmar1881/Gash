// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Modül: github.com/Xmar1881/Gash

package auth

import (
	"net/http"
	"strings"
	"testing"
)

func TestParseAuthHeaderRoundtrip(t *testing.T) {
	c := New()
	if err := c.ParseAuthHeader("Authorization: Bearer token123"); err != nil {
		t.Fatalf("parse: %v", err)
	}
	if !c.HasAuth() {
		t.Fatal("HasAuth true olmalı")
	}
	if got := c.Headers["Authorization"]; got != "Bearer token123" {
		t.Fatalf("header değer: %q", got)
	}
}

func TestParseAuthHeaderRejectsCRLF(t *testing.T) {
	c := New()
	for _, bad := range []string{
		"X-A: a\r\nInjected: 1",
		"X-B: a\nb",
		": boş-ad",
		"X-C: ",
		"not-a-header",
		"Ad With Space: v",
	} {
		if err := c.ParseAuthHeader(bad); err == nil {
			t.Fatalf("reddedilmeli: %q", bad)
		}
	}
	if c.HasAuth() {
		t.Fatal("hatalı parse sonrası HasAuth false kalmalı")
	}
}

func TestParseCookieVariants(t *testing.T) {
	c := New()
	if err := c.ParseCookie("session=abc; theme=dark"); err != nil {
		t.Fatalf("cookie: %v", err)
	}
	if c.Cookies["session"] != "abc" || c.Cookies["theme"] != "dark" {
		t.Fatalf("cookie map: %v", c.Cookies)
	}
	if err := c.ParseCookie("kötü"); err == nil {
		t.Fatal("eşittirsiz cookie reddedilmeli")
	}
	if err := c.ParseCookie("a=b\r\nc=d"); err == nil {
		t.Fatal("CRLF cookie reddedilmeli")
	}
}

func TestParseBasicAuth(t *testing.T) {
	c := New()
	if err := c.ParseBasicAuth("admin:s3cret"); err != nil {
		t.Fatalf("basic: %v", err)
	}
	m := c.HeaderMap()
	if !strings.HasPrefix(m["Authorization"], "Basic ") {
		t.Fatalf("basic header: %v", m)
	}
	bad := New()
	if err := bad.ParseBasicAuth("sadece-kullanıcı"); err == nil {
		t.Fatal("ayraçsız basic reddedilmeli")
	}
	if bad.HasAuth() {
		t.Fatal("hatalı basic sonrası HasAuth false kalmalı")
	}
}

func TestApplyToRequestPreservesExplicit(t *testing.T) {
	c := New()
	if err := c.ParseAuthHeader("X-Token: from-ctx"); err != nil {
		t.Fatal(err)
	}
	if err := c.ParseCookie("s=1"); err != nil {
		t.Fatal(err)
	}
	req, _ := http.NewRequest("GET", "http://example.com/", nil)
	req.Header.Set("X-Token", "explicit")
	c.ApplyToRequest(req)
	if got := req.Header.Get("X-Token"); got != "explicit" {
		t.Fatalf("açık header korunmalı: %q", got)
	}
	if got := req.Header.Get("Cookie"); got != "s=1" {
		t.Fatalf("cookie: %q", got)
	}
}

func TestRedactedLeaksNothing(t *testing.T) {
	c := New()
	_ = c.ParseAuthHeader("Authorization: Bearer süper-gizli")
	_ = c.ParseCookie("session=süper-gizli-oturum")
	_ = c.ParseBasicAuth("admin:süper-gizli-parola")
	red := c.Redacted()
	for _, secret := range []string{"süper-gizli", "Bearer", "Basic "} {
		if strings.Contains(red, secret) {
			t.Fatalf("redacted sızıntı: %q", red)
		}
	}
	if !strings.Contains(red, "Authorization") || !strings.Contains(red, "session") || !strings.Contains(red, "basic=yes") {
		t.Fatalf("redacted adları göstermeli: %q", red)
	}
	if New().Redacted() != "auth: none" {
		t.Fatal("boş bağlam auth: none olmalı")
	}
	var nilCtx *Context
	if nilCtx.HasAuth() || nilCtx.Redacted() != "auth: none" || nilCtx.HeaderMap() != nil {
		t.Fatal("nil bağlam güvenli olmalı")
	}
}

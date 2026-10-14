// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Module: github.com/Xmar1881/Gash

package discovery

import (
	"net/http"
	"testing"
)

func TestFingerprintWordPress(t *testing.T) {
	h := http.Header{}
	h.Set("Server", "nginx")
	body := `<html><meta name="generator" content="WordPress 6.5"><link href="/wp-content/style.css"><form><input type="password" name="p"></form></html>`
	fp := FingerprintTech(h, nil, body)
	has := func(want string) bool {
		for _, g := range fp.Tech {
			if g == want {
				return true
			}
		}
		return false
	}
	if !has("wordpress") || !has("nginx") {
		t.Fatalf("tech: %v", fp.Tech)
	}
	if !fp.Capabilities["login-form"] || !fp.Capabilities["html-form"] {
		t.Fatalf("caps: %v", fp.Capabilities)
	}
}

func TestFingerprintCookiesAndGraphQL(t *testing.T) {
	h := http.Header{}
	cookies := []*http.Cookie{{Name: "csrftoken", Value: "x"}}
	body := `{"data":{"__typename":"Query"}} fetch("/graphql") <form><input type="file"></form> /api/users`
	fp := FingerprintTech(h, cookies, body)
	has := func(want string) bool {
		for _, g := range fp.Tech {
			if g == want {
				return true
			}
		}
		return false
	}
	if !has("django") || !has("graphql") {
		t.Fatalf("tech: %v", fp.Tech)
	}
	for _, c := range []string{"graphql-endpoint", "upload-form", "rest-api", "html-form"} {
		if !fp.Capabilities[c] {
			t.Fatalf("cap %s yok: %v", c, fp.Capabilities)
		}
	}
}

func TestFaviconHashEmpty(t *testing.T) {
	if FaviconHash(nil) != "" {
		t.Fatal("boş favicon hash üretmemeli")
	}
	if FaviconHash([]byte("x")) == "" {
		t.Fatal("hash boş olmamalı")
	}
}

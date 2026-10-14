// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Module: github.com/Xmar1881/Gash

package discovery

import (
	"testing"
)

func TestExtractSurface_URLParams(t *testing.T) {
	u := "http://example.com/search?q=test&cat=books"
	points := ExtractSurface(u, nil)
	if len(points) != 2 {
		t.Fatalf("expected 2 points, got %d", len(points))
	}
	foundQ, foundCat := false, false
	for _, p := range points {
		if p.ParamName == "q" && p.Value == "test" && p.ParamLocation == "query" {
			foundQ = true
		}
		if p.ParamName == "cat" && p.Value == "books" && p.ParamLocation == "query" {
			foundCat = true
		}
	}
	if !foundQ || !foundCat {
		t.Fatalf("expected to find q and cat params, got %+v", points)
	}
}

func TestExtractSurface_HTMLForm(t *testing.T) {
	u := "http://example.com/app"
	htmlDoc := []byte(`
<!DOCTYPE html>
<html>
<body>
  <form action="/login" method="POST">
    <input type="text" name="username" value="admin">
    <input type="password" name="password">
    <input type="submit" value="Log In">
  </form>
  <a href="/profile?user_id=42">Profile</a>
</body>
</html>
`)
	points := ExtractSurface(u, htmlDoc)
	foundUser, foundPass, foundLink := false, false, false
	for _, p := range points {
		if p.ParamName == "username" && p.Method == "POST" && p.ParamLocation == "body" && p.URL == "http://example.com/login" {
			foundUser = true
		}
		if p.ParamName == "password" && p.Method == "POST" && p.ParamLocation == "body" {
			foundPass = true
		}
		if p.ParamName == "user_id" && p.Method == "GET" && p.ParamLocation == "query" {
			foundLink = true
		}
	}
	if !foundUser || !foundPass || !foundLink {
		t.Fatalf("expected to extract form and link inputs, got %+v", points)
	}
}

func TestExtractSurface_Fallback(t *testing.T) {
	u := "http://example.com/"
	points := ExtractSurface(u, []byte("<html><body>Hello world</body></html>"))
	if len(points) != len(CommonCandidateParams) {
		t.Fatalf("expected fallback candidate params (%d), got %d", len(CommonCandidateParams), len(points))
	}
}

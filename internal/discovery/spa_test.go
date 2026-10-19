// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Module: github.com/Xmar1881/Gash

package discovery

import (
	"fmt"
	"reflect"
	"testing"

	"github.com/Xmar1881/Gash/internal/headless"
)

func TestHarvestRenderedDOMAndNetwork(t *testing.T) {
	page := headless.RenderedPage{
		URL: "https://example.com/app",
		HTML: `<html><body>
<form method="GET" action="/search"><input type="text" name="q" value="hello"></form>
<a href="/item?id=5">item</a>
</body></html>`,
		NetworkURLs: []string{
			"https://example.com/api/items?q=1",
			"https://example.com/api/items",
			"https://example.com/api/items",
			"https://example.com/app#section",
			"https://cdn.jsdelivr.net/lib.js",
			"https://example.com/static/app.js",
			"https://example.com/logo.png",
			"data:text/html,x",
			"https://other.example/api/v1/thing",
		},
	}
	got := HarvestRendered(page)

	if len(got.Forms) != 1 {
		t.Fatalf("forms = %d, want 1: %+v", len(got.Forms), got.Forms)
	}
	if got.Forms[0].ActionURL != "https://example.com/search" || got.Forms[0].Method != "GET" {
		t.Fatalf("unexpected form: %+v", got.Forms[0])
	}
	if len(got.Forms[0].Fields) != 1 || got.Forms[0].Fields[0].Name != "q" {
		t.Fatalf("unexpected form fields: %+v", got.Forms[0].Fields)
	}

	wantPoints := []InjectionPoint{
		{URL: "https://example.com/search", Method: "GET", ParamName: "q", ParamLocation: "query", Value: "hello"},
		{URL: "https://example.com/item", Method: "GET", ParamName: "id", ParamLocation: "query", Value: "5"},
		{URL: "https://example.com/api/items", Method: "GET", ParamName: "q", ParamLocation: "query", Value: "1"},
	}
	if !reflect.DeepEqual(got.Points, wantPoints) {
		t.Fatalf("points = %+v, want %+v", got.Points, wantPoints)
	}

	wantEndpoints := []string{
		"https://example.com/api/items",
		"https://other.example/api/v1/thing",
	}
	if !reflect.DeepEqual(got.Endpoints, wantEndpoints) {
		t.Fatalf("endpoints = %v, want %v", got.Endpoints, wantEndpoints)
	}
}

func TestHarvestRenderedDisablesSyntheticFallback(t *testing.T) {
	got := HarvestRendered(headless.RenderedPage{
		URL:  "https://example.com/plain",
		HTML: "<html><body>no surface here</body></html>",
	})
	if len(got.Points) != 0 {
		t.Fatalf("rendered harvest must not synthesize fallback points: %+v", got.Points)
	}
}

func TestHarvestRenderedCapsEndpoints(t *testing.T) {
	page := headless.RenderedPage{URL: "https://example.com/"}
	for i := 0; i < spaMaxEndpoints+10; i++ {
		page.NetworkURLs = append(page.NetworkURLs, fmt.Sprintf("https://example.com/p%d", i))
	}
	got := HarvestRendered(page)
	if len(got.Endpoints) != spaMaxEndpoints {
		t.Fatalf("endpoints = %d, want cap %d", len(got.Endpoints), spaMaxEndpoints)
	}
}

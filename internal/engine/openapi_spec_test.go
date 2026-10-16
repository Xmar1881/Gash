// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Modül: github.com/Xmar1881/Gash

package engine

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/Xmar1881/Gash/internal/discovery"
	"github.com/Xmar1881/Gash/internal/plugin"
	"github.com/Xmar1881/Gash/internal/plugin/loader"
)

// mockOpenAPISpec 2 GET + 1 POST endpoint + parametreli mock spec'tir.
const mockOpenAPISpec = `{
  "openapi": "3.0.0",
  "info": {"title": "Mock", "version": "1.0"},
  "servers": [{"url": "https://api.example.com/v1"}],
  "paths": {
    "/api/items": {
      "get": {
        "operationId": "listItems",
        "parameters": [{"name": "q", "in": "query"}]
      }
    },
    "/api/users/{id}": {
      "get": {
        "operationId": "getUser",
        "parameters": [{"name": "id", "in": "path", "required": true}, {"name": "verbose", "in": "query"}]
      }
    },
    "/api/login": {
      "post": {
        "operationId": "login",
        "parameters": [{"name": "X-Req", "in": "header"}],
        "requestBody": {"content": {"application/json": {}}}
      }
    }
  }
}`

// writeMockSpec mock spec'i temp dosyaya yazar.
func writeMockSpec(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "openapi.json")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

// TestOpenAPISurfacePointsAdded mock spec endpoint+parametrelerinin yüzeye eklendiğini kanıtlar.
func TestOpenAPISurfacePointsAdded(t *testing.T) {
	plan, err := discovery.ParseSpec([]byte(mockOpenAPISpec))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(plan.Endpoints) != 3 {
		t.Fatalf("3 endpoint bekleniyordu, got %d", len(plan.Endpoints))
	}
	target := "http://127.0.0.1:8080"
	points := openAPISurfacePoints(plan, target, nil)
	if len(points) < 4 {
		t.Fatalf("en az 4 nokta bekleniyordu (1+2+2), got %d: %+v", len(points), points)
	}
	hasQuery := false
	hasPath := false
	hasBody := false
	for _, p := range points {
		if !strings.HasPrefix(p.URL, target) {
			t.Fatalf("nokta hedef bazlı olmalı: %q", p.URL)
		}
		switch {
		case p.ParamName == "q" && p.ParamLocation == "query":
			hasQuery = true
		case p.ParamName == "id" && p.ParamLocation == "path":
			hasPath = true
		case p.ParamName == "(body)" && p.ParamLocation == "body":
			hasBody = true
		}
		if strings.Contains(p.URL, "{") || strings.Contains(p.URL, "}") {
			t.Fatalf("path şablonu somutlaşmalı: %q", p.URL)
		}
	}
	if !hasQuery || !hasPath || !hasBody {
		t.Fatalf("parametre kapsama eksik q=%v id=%v body=%v: %+v", hasQuery, hasPath, hasBody, points)
	}
}

// TestOpenAPISurfaceSkipsOutOfScope hedef-host dışı + kapsam-dışı path atlamayı kanıtlar.
func TestOpenAPISurfaceSkipsOutOfScope(t *testing.T) {
	plan, err := discovery.ParseSpec([]byte(mockOpenAPISpec))
	if err != nil {
		t.Fatal(err)
	}
	// Mutlak yabancı URL'li endpoint hedef host ile eşleşmez → atlanır.
	plan.Endpoints = append(plan.Endpoints, discovery.Endpoint{Method: "GET", Path: "https://evil.example.com/steal"})
	target := "http://127.0.0.1:8080"
	points := openAPISurfacePoints(plan, target, nil)
	for _, p := range points {
		if strings.Contains(p.URL, "evil.example.com") {
			t.Fatalf("yabancı host probalanmaz: %+v", p)
		}
	}

	// URL-prefix scope: /api altı izinli, /admin dışı → atlanır (portsuz host, saf URL hesabı).
	scopedTarget := "http://localhost/api"
	scope := []string{"http://localhost/api"}
	scopedPlan := &discovery.Plan{
		Title: "scoped", Version: "1",
		Endpoints: []discovery.Endpoint{
			{Method: "GET", Path: "/api/items", Params: []discovery.Param{{Name: "q", In: "query"}}},
			{Method: "GET", Path: "/admin", Params: []discovery.Param{{Name: "x", In: "query"}}},
		},
	}
	got := openAPISurfacePoints(scopedPlan, scopedTarget, scope)
	if len(got) != 1 {
		t.Fatalf("/admin atlanmalı, /api/items kalmalı: %+v", got)
	}
	if !strings.HasSuffix(got[0].URL, "/api/items") {
		t.Fatalf("yanlış nokta kaldı: %+v", got[0])
	}
}

// TestOpenAPILoadMissingFile dosya-bulunamadı hatasını kanıtlar.
func TestOpenAPILoadMissingFile(t *testing.T) {
	cfg := DefaultConfig()
	cfg.OpenAPISpec = filepath.Join(t.TempDir(), "yok-openapi.json")
	e := New(plugin.NewRegistry(), cfg)
	if _, err := e.loadOpenAPISurface(context.Background(), "http://127.0.0.1:8080"); err == nil {
		t.Fatal("olmayan spec dosyası hata vermeli")
	}
}

// TestOpenAPILoadFileSuccess dosya spec'inin yüzeye eklendiğini kanıtlar.
func TestOpenAPILoadFileSuccess(t *testing.T) {
	path := writeMockSpec(t, mockOpenAPISpec)
	cfg := DefaultConfig()
	cfg.OpenAPISpec = path
	e := New(plugin.NewRegistry(), cfg)
	points, err := e.loadOpenAPISurface(context.Background(), "http://127.0.0.1:8080")
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(points) < 4 {
		t.Fatalf("dosya spec yüzeye eklenmeli: %+v", points)
	}
}

// TestOpenAPISpecURLScopeGate kapsam-dışı URL fetch yasağını kanıtlar (fetch YOK, hata VAR).
func TestOpenAPISpecURLScopeGate(t *testing.T) {
	// Kapsam-dışı dış URL: ağa çıkmadan reddedilmeli.
	cfg := DefaultConfig()
	cfg.OpenAPISpec = "http://93.184.216.34/spec.json"
	e := New(plugin.NewRegistry(), cfg)
	if _, err := e.loadOpenAPISurface(context.Background(), "http://127.0.0.1:8080"); err == nil {
		t.Fatal("kapsam-dışı spec URL reddedilmeli")
	} else if !strings.Contains(err.Error(), "kapsam-dışı") {
		t.Fatalf("hata kapsam-dışı demeli: %v", err)
	}

	// Loopback URL: kapıdan geçer (fetch denenir; hedef yoksa fetch hatası — kapı hatası değil).
	specSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(mockOpenAPISpec))
	}))
	defer specSrv.Close()
	cfg2 := DefaultConfig()
	cfg2.OpenAPISpec = specSrv.URL + "/openapi.json"
	e2 := New(plugin.NewRegistry(), cfg2)
	points, err := e2.loadOpenAPISurface(context.Background(), specSrv.URL)
	if err != nil {
		t.Fatalf("loopback spec çekilmeli: %v", err)
	}
	if len(points) == 0 {
		t.Fatal("loopback spec nokta üretmeli")
	}
}

// sweepPlugin her yüzeyi tek istekle süpüren safe Tier2 plugin'dir (E2E kanıtı).
const sweepPlugin = `/* ---
id: sweep-surface
name: Sweep Surface For Testing Purposes Here
description: Sweeps every injection point once to prove OpenAPI surface expansion in tests.
severity: low
tags: [sweep]
safe: true
deep: false
active: false
requires_auth: false
phase: probe
order: 10
api_version: "1.0"
--- */
function run(probe, ctx) {
  const points = ctx.injectionPoints();
  for (const point of points) {
    try {
      probe.send(point.withValue("1"));
    } catch (e) {}
  }
  return [];
}
`

// TestScanE2EOpenAPISpec E2E: spec'teki ek endpointlerin tarandığını kanıtlar.
func TestScanE2EOpenAPISpec(t *testing.T) {
	var mu sync.Mutex
	var seen []string
	targetSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen = append(seen, r.URL.Path)
		mu.Unlock()
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("<html><body>hello</body></html>"))
	}))
	defer targetSrv.Close()

	specPath := writeMockSpec(t, `{
  "openapi": "3.0.0",
  "info": {"title": "E2E", "version": "1"},
  "paths": {
    "/api/extra": {"get": {"parameters": [{"name": "q", "in": "query"}]}},
    "/api/other": {"get": {"parameters": [{"name": "id", "in": "query"}]}}
  }
}`)

	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "sweep.js"), []byte(sweepPlugin), 0o644); err != nil {
		t.Fatal(err)
	}
	reg := plugin.NewRegistry()
	if _, err := loader.Discover([]string{dir}, reg); err != nil {
		t.Fatalf("discover: %v", err)
	}
	if reg.Len() != 1 {
		t.Fatalf("sweep plugin bulunmalı, got %d", reg.Len())
	}
	cfg := DefaultConfig()
	cfg.OpenAPISpec = specPath
	e := New(reg, cfg)
	if _, err := e.Run(context.Background(), targetSrv.URL); err != nil {
		t.Fatalf("run: %v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	hit := map[string]bool{}
	for _, p := range seen {
		hit[p] = true
	}
	if !hit["/api/extra"] || !hit["/api/other"] {
		t.Fatalf("spec endpointleri taranmalı (extra=%v other=%v, görülen=%v)", hit["/api/extra"], hit["/api/other"], seen)
	}
}

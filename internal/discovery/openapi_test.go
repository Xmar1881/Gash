// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Modül: github.com/Xmar1881/Gash

package discovery

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const openAPI3 = `{
  "openapi": "3.0.0",
  "info": {"title": "Demo", "version": "1.2.3"},
  "servers": [{"url": "https://api.example.com/v1"}],
  "paths": {
    "/users/{id}": {
      "parameters": [{"name": "id", "in": "path", "required": true}],
      "get": {
        "operationId": "getUser",
        "parameters": [{"name": "verbose", "in": "query"}]
      },
      "delete": {"operationId": "delUser"}
    },
    "/login": {
      "post": {
        "requestBody": {"content": {"application/json": {}}},
        "parameters": [{"name": "X-Req", "in": "header"}]
      }
    }
  }
}`

const swagger2 = `
swagger: "2.0"
info: {title: Legacy, version: "0.9"}
host: legacy.example.com
basePath: /api
schemes: [https]
paths:
  /search:
    get:
      parameters:
        - {name: q, in: query, required: true}
`

func TestParseOpenAPI3(t *testing.T) {
	p, err := ParseSpec([]byte(openAPI3))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if p.Title != "Demo" || p.Version != "1.2.3" {
		t.Fatalf("info: %+v", p)
	}
	if len(p.Servers) != 1 || p.Servers[0] != "https://api.example.com/v1" {
		t.Fatalf("servers: %v", p.Servers)
	}
	if len(p.Endpoints) != 3 {
		t.Fatalf("endpoint sayısı 3 olmalı: %+v", p.Endpoints)
	}
	// Deterministik sıra: path alfabetik.
	if p.Endpoints[0].Path != "/login" || p.Endpoints[0].Method != "POST" {
		t.Fatalf("sıra: %+v", p.Endpoints[0])
	}
	get := p.Endpoints[1]
	if get.Method != "GET" || len(get.Params) != 2 {
		t.Fatalf("get param birleşimi: %+v", get)
	}
	del := p.Endpoints[2]
	if del.Method != "DELETE" || len(del.Params) != 1 || del.Params[0].Name != "id" {
		t.Fatalf("shared param: %+v", del)
	}
	post := p.Endpoints[0]
	if len(post.Params) != 2 || post.Params[1].Name != "(body)" {
		t.Fatalf("body sinyali: %+v", post.Params)
	}
	targets := p.Targets("")
	if targets[0] != "POST https://api.example.com/v1/login" {
		t.Fatalf("targets: %v", targets)
	}
	if got := p.Targets("https://other.test/base"); !strings.HasPrefix(got[0], "POST https://other.test/base/login") {
		t.Fatalf("base override: %v", got)
	}
}

func TestParseSwagger2AndYAML(t *testing.T) {
	p, err := ParseSpec([]byte(swagger2))
	if err != nil {
		t.Fatalf("swagger2: %v", err)
	}
	if len(p.Servers) != 1 || p.Servers[0] != "https://legacy.example.com/api" {
		t.Fatalf("servers: %v", p.Servers)
	}
	if len(p.Endpoints) != 1 || p.Endpoints[0].Params[0].Name != "q" {
		t.Fatalf("endpoints: %+v", p.Endpoints)
	}
	// YAML olarak JSON da ayrışmalı.
	if _, err := ParseSpec([]byte(openAPI3)); err != nil {
		t.Fatalf("json-as-yaml: %v", err)
	}
}

func TestParseRejects(t *testing.T) {
	for _, tc := range []struct {
		name string
		data string
	}{
		{"boş", ""},
		{"pathsız", `{"openapi":"3.0.0","info":{},"paths":{}}`},
		{"operasyonsuz", `{"openapi":"3.0.0","info":{},"paths":{"/x":{}}}`},
		{"bozuk", "{geçersiz"},
	} {
		if _, err := ParseSpec([]byte(tc.data)); err == nil {
			t.Fatalf("%s reddedilmeli", tc.name)
		}
	}
	if _, err := ParseSpec(make([]byte, 11*1024*1024)); err == nil {
		t.Fatal("10MB sınırı aşılmalı")
	}
}

func TestLoadAndFetch(t *testing.T) {
	path := filepath.Join(t.TempDir(), "spec.json")
	if err := os.WriteFile(path, []byte(openAPI3), 0o644); err != nil {
		t.Fatal(err)
	}
	p, err := LoadSpecFile(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(p.Endpoints) != 3 {
		t.Fatalf("endpoints: %d", len(p.Endpoints))
	}
	if _, err := LoadSpecFile(filepath.Join(t.TempDir(), "yok.json")); err == nil {
		t.Fatal("olmayan dosya hata vermeli")
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(openAPI3))
	}))
	defer srv.Close()
	got, err := FetchSpec(context.Background(), srv.URL, 0)
	if err != nil {
		t.Fatalf("fetch: %v", err)
	}
	if len(got.Endpoints) != 3 {
		t.Fatalf("fetch endpoints: %d", len(got.Endpoints))
	}
	for _, bad := range []string{"", "ftp://x/y", "http://x/%zz", "gopher://x"} {
		if _, err := FetchSpec(context.Background(), bad, 0); err == nil {
			t.Fatalf("fetch reddetmeli: %q", bad)
		}
	}
	redir := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, srv.URL, http.StatusFound)
	}))
	defer redir.Close()
	if _, err := FetchSpec(context.Background(), redir.URL, 0); err == nil {
		t.Fatal("redirect izlenmemeli")
	}
}

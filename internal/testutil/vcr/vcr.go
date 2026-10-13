// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Modül: github.com/Xmar1881/Gash

// Package vcr kayıt-tekrar (record/replay) test harness'ıdır.
// Go net/http/httptest tabanlı; plugin'ler HTTP fixture'larıyla çevrimdışı test edilir.
package vcr

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
)

// Route tek fixture rotasıdır.
type Route struct {
	Method  string
	Path    string
	Status  int
	Headers map[string]string
	Body    string
	Hits    int
}

// VCR httptest replay harness'ıdır.
type VCR struct {
	mu     sync.Mutex
	routes map[string]*Route // method + " " + path
	server *httptest.Server
}

// New boş VCR + httptest server kurar.
func New() *VCR {
	v := &VCR{routes: make(map[string]*Route)}
	v.server = httptest.NewServer(http.HandlerFunc(v.serve))
	return v
}

func (v *VCR) serve(w http.ResponseWriter, r *http.Request) {
	key := r.Method + " " + r.URL.Path
	v.mu.Lock()
	rt, ok := v.routes[key]
	if ok {
		rt.Hits++
	}
	v.mu.Unlock()
	if !ok {
		// SPA catch-all varsayılanı: 200 + aynı body (soft-404 testleri için override edilir).
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprint(w, "<html><body>app</body></html>")
		return
	}
	for k, val := range rt.Headers {
		w.Header().Set(k, val)
	}
	w.WriteHeader(rt.Status)
	_, _ = fmt.Fprint(w, rt.Body)
}

// AddRoute fixture rotası ekler.
func (v *VCR) AddRoute(method, path string, status int, headers map[string]string, body string) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.routes[method+" "+path] = &Route{Method: method, Path: path, Status: status, Headers: headers, Body: body}
}

// URL server köküdür.
func (v *VCR) URL() string { return v.server.URL }

// Close server'ı kapatır.
func (v *VCR) Close() { v.server.Close() }

// Hits rota isabet sayısı (bütçe/policy testleri için).
func (v *VCR) Hits(method, path string) int {
	v.mu.Lock()
	defer v.mu.Unlock()
	if rt, ok := v.routes[method+" "+path]; ok {
		return rt.Hits
	}
	return 0
}

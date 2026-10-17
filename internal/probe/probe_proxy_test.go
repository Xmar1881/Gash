// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Module: github.com/Xmar1881/Gash

package probe

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/Xmar1881/Gash/internal/plugin"
)

func TestProbeClientProxyConfiguration(t *testing.T) {
	proxyURL, err := url.Parse("http://127.0.0.1:8080")
	if err != nil {
		t.Fatalf("parse proxy URL: %v", err)
	}

	opts := Options{
		ProxyURL: proxyURL,
	}
	client := NewClient(opts)

	if client.ProxyURL() == nil || client.ProxyURL().String() != "http://127.0.0.1:8080" {
		t.Fatalf("expected client.ProxyURL() to be http://127.0.0.1:8080, got %v", client.ProxyURL())
	}

	tr := client.Transport()
	if tr == nil {
		t.Fatalf("expected non-nil transport on client")
	}

	dummyReq, _ := http.NewRequest(http.MethodGet, "http://example.com/", nil)
	gotProxy, err := tr.Proxy(dummyReq)
	if err != nil {
		t.Fatalf("tr.Proxy failed: %v", err)
	}
	if gotProxy == nil || gotProxy.String() != "http://127.0.0.1:8080" {
		t.Fatalf("expected transport proxy http://127.0.0.1:8080, got %v", gotProxy)
	}
}

func TestProbeProxyScopeEnforcement(t *testing.T) {
	var mu sync.Mutex
	var receivedHosts []string

	// Local HTTP proxy server simulation
	proxyServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		receivedHosts = append(receivedHosts, r.Host)
		mu.Unlock()

		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"proxy": "ok"}`))
	}))
	defer proxyServer.Close()

	proxyURL, err := url.Parse(proxyServer.URL)
	if err != nil {
		t.Fatalf("parse proxy url: %v", err)
	}

	// PolicySession configured with strict scope allowlist
	policyCfg := plugin.PolicyConfig{
		MaxRequestsPerTarget: 100,
		MaxRequestsTotal:     100,
		Scope:                []string{"allowed.target.local"},
		RatePerSecond:        0,
		MaxResponseBytes:     1024 * 1024,
	}
	policy := plugin.NewPolicySession(policyCfg, nil)

	// Probe client configured with policy and upstream proxy
	client := NewClient(Options{
		Policy:         policy,
		RequestTimeout: 5 * time.Second,
		ProxyURL:       proxyURL,
	})

	ctx := plugin.WithPlugin(context.Background(), "test-plugin", true, nil)

	// 1. In-scope request: http://allowed.target.local/api
	// Should pass scope check and be received by the proxy
	resp, err := client.Send(ctx, http.MethodGet, "http://allowed.target.local/api", nil, nil)
	if err != nil {
		t.Fatalf("expected in-scope request through proxy to succeed, got: %v", err)
	}
	if resp.Status != http.StatusOK {
		t.Errorf("expected 200 OK from proxy, got %d", resp.Status)
	}

	mu.Lock()
	if len(receivedHosts) != 1 || receivedHosts[0] != "allowed.target.local" {
		t.Errorf("expected proxy to receive 1 request for allowed.target.local, got: %v", receivedHosts)
	}
	mu.Unlock()

	// 2. Out-of-scope request: http://forbidden.target.local/secret
	// MUST fail with ErrScopeViolation, and NEVER reach the proxy
	_, err = client.Send(ctx, http.MethodGet, "http://forbidden.target.local/secret", nil, nil)
	if err == nil {
		t.Fatalf("expected out-of-scope request through proxy to be blocked by scope policy")
	}
	if !errors.Is(err, plugin.ErrScopeViolation) {
		t.Errorf("expected ErrScopeViolation, got: %v", err)
	}

	// Verify that the proxy never received the forbidden request
	mu.Lock()
	if len(receivedHosts) != 1 {
		t.Errorf("expected proxy to still only have 1 request, got %d: %v", len(receivedHosts), receivedHosts)
	}
	mu.Unlock()
}

// TestProbeOpenModeNoScopeAllowsCrossHost proxy preflight --scope yokken
// (open mod) hiçbir host'u bloklamaz; cross-host istek proxy'e ulaşır.
func TestProbeOpenModeNoScopeAllowsCrossHost(t *testing.T) {
	var mu sync.Mutex
	var receivedHosts []string

	proxyServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		receivedHosts = append(receivedHosts, r.Host)
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"proxy": "ok"}`))
	}))
	defer proxyServer.Close()

	proxyURL, err := url.Parse(proxyServer.URL)
	if err != nil {
		t.Fatalf("parse proxy url: %v", err)
	}

	// Scope YOK → open mod (operatör sorumluluğu; yazılımsal host engeli yok).
	policyCfg := plugin.PolicyConfig{
		MaxRequestsPerTarget: 100,
		MaxRequestsTotal:     100,
		RatePerSecond:        0,
		MaxResponseBytes:     1024 * 1024,
	}
	policy := plugin.NewPolicySession(policyCfg, nil)

	client := NewClient(Options{
		Policy:         policy,
		RequestTimeout: 5 * time.Second,
		ProxyURL:       proxyURL,
	})

	ctx := plugin.WithPlugin(context.Background(), "test-plugin", true, nil)
	resp, err := client.Send(ctx, http.MethodGet, "http://cross.host.local/api", nil, nil)
	if err != nil {
		t.Fatalf("open modda cross-host istek bloklanmamalı (proxy'e ulaşmalı): %v", err)
	}
	if resp.Status != http.StatusOK {
		t.Errorf("expected 200 OK from proxy, got %d", resp.Status)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(receivedHosts) != 1 || receivedHosts[0] != "cross.host.local" {
		t.Errorf("expected proxy to receive 1 request for cross.host.local, got: %v", receivedHosts)
	}
}

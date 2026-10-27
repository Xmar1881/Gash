// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Module: github.com/Xmar1881/Gash

package probe

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/Xmar1881/Gash/internal/plugin"
	"github.com/Xmar1881/Gash/internal/proxypool"
)

func newFailoverClient(t *testing.T, proxies []*httptest.Server, timeout time.Duration) *Client {
	t.Helper()
	urls := make([]*url.URL, 0, len(proxies))
	for _, srv := range proxies {
		u, err := url.Parse(srv.URL)
		if err != nil {
			t.Fatalf("parse proxy URL: %v", err)
		}
		urls = append(urls, u)
	}

	pcfg := plugin.DefaultPolicyConfig()
	pcfg.ProxyURLs = urls
	pcfg.ProxyRotate = proxypool.PerHost
	pcfg.ProxyCooldown = time.Minute
	pcfg.RetryConfig.MaxRetries = 2
	pcfg.RetryConfig.BaseDelay = time.Millisecond
	pcfg.RetryConfig.MaxDelay = 5 * time.Millisecond
	policy := plugin.NewPolicySession(pcfg, nil)

	return NewClient(Options{Policy: policy, RequestTimeout: timeout})
}

// TestProxyFailoverOnTimeoutReplaysBody: the first proxy hangs, the policy
// abandons it on the per-attempt deadline and replays the POST body through the
// second proxy. This is the timeout/plugin-skip path the pool exists for.
func TestProxyFailoverOnTimeoutReplaysBody(t *testing.T) {
	release := make(chan struct{})
	slow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-release:
		case <-time.After(5 * time.Second):
		}
	}))
	defer slow.Close()
	defer close(release)

	var mu sync.Mutex
	var gotBody string
	fast := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		mu.Lock()
		gotBody = string(body)
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	defer fast.Close()

	client := newFailoverClient(t, []*httptest.Server{slow, fast}, 250*time.Millisecond)
	ctx := plugin.WithPlugin(context.Background(), "proxy-failover", false, nil)

	resp, err := client.Send(ctx, http.MethodPost, "http://target.invalid/submit", nil, []byte("payload"))
	if err != nil {
		t.Fatalf("expected failover through second proxy, got: %v", err)
	}
	if resp.Status != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.Status)
	}

	mu.Lock()
	defer mu.Unlock()
	if gotBody != "payload" {
		t.Fatalf("second proxy received body %q, want %q (body replay failed)", gotBody, "payload")
	}

	if pool := client.ProxyPool(); pool != nil {
		if st := pool.Stats(); st.Rotations == 0 || st.Failures == 0 {
			t.Fatalf("expected rotation and failure stats, got %+v", st)
		}
	}
}

// TestProxyFailoverOnBlockStatus: a 403 from the target through one source IP
// rotates to the next proxy instead of ending as evidence.
func TestProxyFailoverOnBlockStatus(t *testing.T) {
	blocked := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer blocked.Close()

	ok := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	defer ok.Close()

	client := newFailoverClient(t, []*httptest.Server{blocked, ok}, time.Second)
	ctx := plugin.WithPlugin(context.Background(), "proxy-block", true, nil)

	resp, err := client.Send(ctx, http.MethodGet, "http://target.invalid/", nil, nil)
	if err != nil {
		t.Fatalf("expected block failover, got: %v", err)
	}
	if resp.Status != http.StatusOK {
		t.Fatalf("expected 200 after rotating away from 403, got %d", resp.Status)
	}
}

// TestExplicitAttemptTimeoutSurvivesClientSetup: an engine-level per-attempt
// timeout must not be replaced by the request timeout during client setup.
func TestExplicitAttemptTimeoutSurvivesClientSetup(t *testing.T) {
	u1, err := url.Parse("http://127.0.0.1:9001")
	if err != nil {
		t.Fatal(err)
	}
	u2, err := url.Parse("http://127.0.0.1:9002")
	if err != nil {
		t.Fatal(err)
	}
	pcfg := plugin.DefaultPolicyConfig()
	pcfg.ProxyURLs = []*url.URL{u1, u2}
	pcfg.AttemptTimeout = 3 * time.Second
	policy := plugin.NewPolicySession(pcfg, nil)
	_ = NewClient(Options{Policy: policy, RequestTimeout: 15 * time.Second})
	if got := policy.AttemptTimeout(); got != 3*time.Second {
		t.Fatalf("attempt timeout = %s, want 3s", got)
	}
}

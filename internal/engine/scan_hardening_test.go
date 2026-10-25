// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Module: github.com/Xmar1881/Gash

package engine

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/Xmar1881/Gash/internal/plugin"
)

type enginePolicyRoundTripper struct {
	mu       sync.Mutex
	requests []string
	finalTry int
}

func (rt *enginePolicyRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	rt.mu.Lock()
	rt.requests = append(rt.requests, req.URL.String())
	if req.URL.Path == "/final" {
		rt.finalTry++
	}
	finalTry := rt.finalTry
	rt.mu.Unlock()

	switch req.URL.Path {
	case "/":
		return &http.Response{
			StatusCode: http.StatusFound,
			Header:     http.Header{"Location": []string{"/final"}},
			Body:       http.NoBody,
			Request:    req,
		}, nil
	case "/final":
		if finalTry == 1 {
			return &http.Response{StatusCode: http.StatusServiceUnavailable, Header: http.Header{}, Body: http.NoBody, Request: req}, nil
		}
		return &http.Response{StatusCode: http.StatusOK, Header: http.Header{}, Body: http.NoBody, Request: req}, nil
	default:
		return &http.Response{StatusCode: http.StatusNotFound, Header: http.Header{}, Body: http.NoBody, Request: req}, nil
	}
}

func (rt *enginePolicyRoundTripper) seen() []string {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	return append([]string(nil), rt.requests...)
}

func TestNewScanClientKeepsPolicyDefaults(t *testing.T) {
	e := New(plugin.NewRegistry(), DefaultConfig())
	policy, _, err := e.newScanClient("http://127.0.0.1/")
	if err != nil {
		t.Fatalf("new scan client: %v", err)
	}
	rt := &enginePolicyRoundTripper{}
	policy.SetBase(rt)
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://127.0.0.1/", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := policy.RoundTripWithRetry(req)
	if err != nil {
		t.Fatalf("policy request: %v", err)
	}
	resp.Body.Close()
	want := []string{"http://127.0.0.1/", "http://127.0.0.1/final", "http://127.0.0.1/final"}
	got := rt.seen()
	if len(got) != len(want) {
		t.Fatalf("request chain = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("request %d = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestAcquireContextSlotHonorsCancellation(t *testing.T) {
	sem := make(chan struct{}, 1)
	sem <- struct{}{}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if acquireContextSlot(ctx, sem) {
		t.Fatal("cancelled scan must not acquire an occupied worker slot")
	}
}

func TestRunScanTimeoutBoundsRuntimeDetection(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-time.After(time.Second):
			w.WriteHeader(http.StatusOK)
		case <-r.Context().Done():
		}
	}))
	defer srv.Close()

	cfg := DefaultConfig()
	cfg.ScanTimeout = 50 * time.Millisecond
	cfg.RequestTimeout = 2 * time.Second
	e := New(plugin.NewRegistry(), cfg)
	start := time.Now()
	rep, err := e.Run(context.Background(), srv.URL)
	if err != nil {
		t.Fatalf("run with bounded scan timeout: %v", err)
	}
	if rep == nil {
		t.Fatal("bounded scan must still return an auditable empty report")
	}
	if elapsed := time.Since(start); elapsed > 500*time.Millisecond {
		t.Fatalf("scan timeout was not enforced by the engine: %v", elapsed)
	}
}

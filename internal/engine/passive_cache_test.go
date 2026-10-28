// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Module: github.com/Xmar1881/Gash

package engine

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Xmar1881/Gash/internal/plugin/loader"
	"github.com/Xmar1881/Gash/internal/probe"
)

func testCacheResponse() *probe.Response {
	return &probe.Response{
		Status:  200,
		Headers: http.Header{"X-Test": {"one"}},
		Body:    []byte("shared-body"),
	}
}

func TestPassiveCacheCoalescesConcurrentFetches(t *testing.T) {
	c := newPassiveResponseCache(time.Minute, 8, 1<<20)
	var fetches atomic.Int64
	entered := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once
	fetch := func() (*probe.Response, error) {
		fetches.Add(1)
		once.Do(func() { close(entered) })
		<-release
		return testCacheResponse(), nil
	}
	const workers = 8
	var wg sync.WaitGroup
	results := make(chan *probe.Response, workers)
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			resp, err := c.GetOrFetch(context.Background(), "GET http://example.com/", fetch)
			if err != nil {
				t.Errorf("cache fetch: %v", err)
				return
			}
			results <- resp
		}()
	}
	<-entered
	close(release)
	wg.Wait()
	close(results)
	if got := fetches.Load(); got != 1 {
		t.Fatalf("one network fetch expected, got %d", got)
	}
	for resp := range results {
		if resp == nil || resp.Status != 200 || string(resp.Body) != "shared-body" {
			t.Fatalf("shared response mismatch: %+v", resp)
		}
	}
	hits, fetchesStat := c.Stats()
	if hits != workers-1 || fetchesStat != 1 {
		t.Fatalf("cache stats hits=%d fetches=%d", hits, fetchesStat)
	}
}

func TestPassiveCachePanicDoesNotHangWaiters(t *testing.T) {
	c := newPassiveResponseCache(time.Minute, 4, 1<<20)
	_, err := c.GetOrFetch(context.Background(), "GET http://example.com/", func() (*probe.Response, error) {
		panic("boom")
	})
	if err == nil || !strings.Contains(err.Error(), "panic") {
		t.Fatalf("panic must surface as an error, got %v", err)
	}
	// The failed entry must be removed so the key can be fetched again.
	resp, err := c.GetOrFetch(context.Background(), "GET http://example.com/", func() (*probe.Response, error) {
		return testCacheResponse(), nil
	})
	if err != nil || resp == nil || resp.Status != 200 {
		t.Fatalf("panic entry must not poison later fetches: resp=%+v err=%v", resp, err)
	}
}

func TestPassiveCacheDoesNotRetainErrors(t *testing.T) {
	c := newPassiveResponseCache(time.Minute, 4, 1<<20)
	calls := 0
	fetch := func() (*probe.Response, error) {
		calls++
		if calls == 1 {
			return nil, errors.New("transient")
		}
		return testCacheResponse(), nil
	}
	if _, err := c.GetOrFetch(context.Background(), "GET http://example.com/", fetch); err == nil {
		t.Fatal("first fetch must surface the error")
	}
	resp, err := c.GetOrFetch(context.Background(), "GET http://example.com/", fetch)
	if err != nil || resp == nil || resp.Status != 200 {
		t.Fatalf("retry after error must fetch fresh: resp=%+v err=%v", resp, err)
	}
	if calls != 2 {
		t.Fatalf("failed response must not be cached, calls=%d", calls)
	}
	hits, _ := c.Stats()
	if hits != 0 {
		t.Fatalf("errors must not count as hits, got %d", hits)
	}
}

func TestPassiveCacheExpires(t *testing.T) {
	c := newPassiveResponseCache(10*time.Millisecond, 4, 1<<20)
	var fetches atomic.Int64
	fetch := func() (*probe.Response, error) {
		fetches.Add(1)
		return testCacheResponse(), nil
	}
	if _, err := c.GetOrFetch(context.Background(), "GET http://example.com/", fetch); err != nil {
		t.Fatal(err)
	}
	time.Sleep(25 * time.Millisecond)
	if _, err := c.GetOrFetch(context.Background(), "GET http://example.com/", fetch); err != nil {
		t.Fatal(err)
	}
	if got := fetches.Load(); got != 2 {
		t.Fatalf("expired entry must refetch, got %d fetches", got)
	}
}

func TestPassiveCacheHeadersAreIndependent(t *testing.T) {
	c := newPassiveResponseCache(time.Minute, 4, 1<<20)
	fetch := func() (*probe.Response, error) { return testCacheResponse(), nil }
	first, err := c.GetOrFetch(context.Background(), "GET http://example.com/", fetch)
	if err != nil {
		t.Fatal(err)
	}
	first.Headers.Set("X-Test", "mutated")
	second, err := c.GetOrFetch(context.Background(), "GET http://example.com/", fetch)
	if err != nil {
		t.Fatal(err)
	}
	if got := second.Headers.Get("X-Test"); got != "one" {
		t.Fatalf("cached header map mutated through a caller: %q", got)
	}
}

func TestPassiveCacheKey(t *testing.T) {
	cases := []struct {
		method  string
		headers map[string]string
		body    []byte
		ok      bool
	}{
		{http.MethodGet, nil, nil, true},
		{http.MethodHead, nil, nil, true},
		{http.MethodPost, nil, nil, false},
		{http.MethodGet, map[string]string{"Host": "x"}, nil, false},
		{http.MethodGet, nil, []byte("body"), false},
	}
	for _, tc := range cases {
		if _, ok := passiveCacheKey(tc.method, "http://example.com/", tc.headers, tc.body); ok != tc.ok {
			t.Fatalf("passiveCacheKey(%s, headers=%v, body=%d) = %v, want %v", tc.method, tc.headers, len(tc.body), ok, tc.ok)
		}
	}
}

func TestTier1PassiveCacheEligibility(t *testing.T) {
	cases := []struct {
		name string
		file *loader.Tier1File
		want bool
	}{
		{"nil", nil, false},
		{"header policy", &loader.Tier1File{Oracle: loader.Tier1Oracle{Name: "header", Params: map[string]any{"mode": "policy"}}}, true},
		{"header default", &loader.Tier1File{Oracle: loader.Tier1Oracle{Name: "header"}}, true},
		{"header ratelimit", &loader.Tier1File{Oracle: loader.Tier1Oracle{Name: "header", Params: map[string]any{"mode": "ratelimit"}}}, false},
		{"header host", &loader.Tier1File{Oracle: loader.Tier1Oracle{Name: "header", Params: map[string]any{"mode": "host_header"}}}, false},
		{"version", &loader.Tier1File{Oracle: loader.Tier1Oracle{Name: "version"}}, true},
		{"cookie", &loader.Tier1File{Oracle: loader.Tier1Oracle{Name: "cookie"}}, true},
		{"cors", &loader.Tier1File{Oracle: loader.Tier1Oracle{Name: "cors"}}, true},
		{"error exposure", &loader.Tier1File{Oracle: loader.Tier1Oracle{Name: "error"}}, true},
		{"redirect", &loader.Tier1File{Oracle: loader.Tier1Oracle{Name: "redirect"}}, false},
		{"reflection", &loader.Tier1File{Oracle: loader.Tier1Oracle{Name: "reflection"}}, false},
		{"timing", &loader.Tier1File{Oracle: loader.Tier1Oracle{Name: "timing"}}, false},
	}
	for _, tc := range cases {
		if got := tier1PassiveCacheEligible(tc.file); got != tc.want {
			t.Fatalf("%s: eligible=%v, want %v", tc.name, got, tc.want)
		}
	}
}

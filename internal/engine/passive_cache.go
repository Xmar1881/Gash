// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Module: github.com/Xmar1881/Gash

package engine

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/Xmar1881/Gash/internal/plugin/loader"
	"github.com/Xmar1881/Gash/internal/probe"
)

// passiveResponseCache coalesces identical passive GET/HEAD requests inside
// one scan. What: TTL cache plus singleflight so concurrent header/version
// plugins share one network response. Why: the Tier 1 expansion pack made the
// same root URL the most requested object in a scan; sharing it cuts both
// request budget and wall-clock time without letting a plugin decide evidence.
type passiveResponseCache struct {
	mu         sync.Mutex
	entries    map[string]*passiveCacheEntry
	ttl        time.Duration
	maxEntries int
	maxBytes   int
	curBytes   int
	hits       int64
	fetches    int64
}

type passiveCacheEntry struct {
	ready   chan struct{}
	resp    *probe.Response
	err     error
	expires time.Time
}

func newPassiveResponseCache(ttl time.Duration, maxEntries, maxBytes int) *passiveResponseCache {
	if ttl <= 0 {
		ttl = 60 * time.Second
	}
	if maxEntries <= 0 {
		maxEntries = 512
	}
	if maxBytes <= 0 {
		maxBytes = 32 << 20
	}
	return &passiveResponseCache{
		entries:    make(map[string]*passiveCacheEntry, 64),
		ttl:        ttl,
		maxEntries: maxEntries,
		maxBytes:   maxBytes,
	}
}

// Stats returns served-without-network hits and actual fetch attempts.
func (c *passiveResponseCache) Stats() (hits, fetches int64) {
	if c == nil {
		return 0, 0
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.hits, c.fetches
}

// GetOrFetch serves key from cache or performs one shared fetch.
// What: Singleflight per key with a TTL and bounded retention.
// Why: Parallel passive plugins ask for the same URL at the same moment; a
// plain cache would still send every first request.
func (c *passiveResponseCache) GetOrFetch(ctx context.Context, key string, fetch func() (*probe.Response, error)) (*probe.Response, error) {
	if c == nil {
		return fetch()
	}
	now := time.Now()
	c.mu.Lock()
	if e, ok := c.entries[key]; ok {
		if e.expires.IsZero() || now.Before(e.expires) {
			c.hits++
			c.mu.Unlock()
			select {
			case <-e.ready:
				return cloneProbeResponse(e.resp), e.err
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}
		c.removeLocked(key, e)
	}
	if len(c.entries) >= c.maxEntries {
		c.evictFinishedLocked(now)
	}
	if len(c.entries) >= c.maxEntries {
		c.mu.Unlock()
		return fetch()
	}
	entry := &passiveCacheEntry{ready: make(chan struct{})}
	c.entries[key] = entry
	c.mu.Unlock()

	resp, err := safePassiveFetch(fetch)
	c.mu.Lock()
	c.fetches++
	if err != nil {
		entry.err = err
		delete(c.entries, key)
		close(entry.ready)
		c.mu.Unlock()
		return nil, err
	}
	if resp == nil {
		entry.err = context.Canceled
		delete(c.entries, key)
		close(entry.ready)
		c.mu.Unlock()
		return nil, context.Canceled
	}
	entry.resp = resp
	entry.expires = time.Now().Add(c.ttl)
	if c.curBytes+len(resp.Body) > c.maxBytes {
		// Memory pressure: return the response but do not retain it. Waiters
		// already holding the entry still see the fetched response.
		delete(c.entries, key)
		close(entry.ready)
		c.mu.Unlock()
		return resp, nil
	}
	c.curBytes += len(resp.Body)
	close(entry.ready)
	c.mu.Unlock()
	return cloneProbeResponse(resp), nil
}

// safePassiveFetch keeps one panicking fetch from leaving an unclosed entry
// that would block every later waiter for the same key.
func safePassiveFetch(fetch func() (*probe.Response, error)) (resp *probe.Response, err error) {
	defer func() {
		if p := recover(); p != nil {
			resp, err = nil, fmt.Errorf("passive cache fetch panic: %v", p)
		}
	}()
	return fetch()
}

func (c *passiveResponseCache) removeLocked(key string, e *passiveCacheEntry) {
	if e == nil {
		return
	}
	delete(c.entries, key)
	if e.resp != nil {
		c.curBytes -= len(e.resp.Body)
		if c.curBytes < 0 {
			c.curBytes = 0
		}
	}
}

// evictFinishedLocked drops expired finished entries, then oldest finished
// entries when the table is still full. In-flight entries are never evicted.
func (c *passiveResponseCache) evictFinishedLocked(now time.Time) {
	for k, e := range c.entries {
		select {
		case <-e.ready:
			if now.After(e.expires) || len(c.entries) >= c.maxEntries {
				c.removeLocked(k, e)
			}
		default:
		}
		if len(c.entries) < c.maxEntries {
			return
		}
	}
}

// cloneProbeResponse gives every caller an independent header map while
// sharing the immutable body bytes. The engine sender and oracles only read.
func cloneProbeResponse(r *probe.Response) *probe.Response {
	if r == nil {
		return nil
	}
	cp := *r
	if r.Headers != nil {
		cp.Headers = r.Headers.Clone()
	}
	return &cp
}

// passiveCacheKey accepts only static GET/HEAD requests. Plugin-declared
// headers or bodies can change the response, so those requests bypass the
// cache entirely.
func passiveCacheKey(method, rawURL string, reqHeaders map[string]string, reqBody []byte) (string, bool) {
	if len(reqHeaders) != 0 || len(reqBody) != 0 {
		return "", false
	}
	switch strings.ToUpper(strings.TrimSpace(method)) {
	case http.MethodGet, http.MethodHead:
		return strings.ToUpper(strings.TrimSpace(method)) + " " + rawURL, true
	default:
		return "", false
	}
}

// tier1PassiveCacheEligible limits sharing to read-only oracles. Timing,
// differential, OOB, redirect, reflection, burst, and host-header flows need
// independent exchanges, so they always fetch their own response.
func tier1PassiveCacheEligible(file *loader.Tier1File) bool {
	if file == nil {
		return false
	}
	switch strings.ToLower(strings.TrimSpace(file.Oracle.Name)) {
	case "header":
		mode := strings.ToLower(oracleParamString(file.Oracle.Params, "mode", "security"))
		return mode != "ratelimit" && mode != "host_header"
	case "version", "cookie", "cors", "error":
		return true
	default:
		return false
	}
}

func oracleParamString(params map[string]any, key, fallback string) string {
	if params == nil {
		return fallback
	}
	if v, ok := params[key]; ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return fallback
}

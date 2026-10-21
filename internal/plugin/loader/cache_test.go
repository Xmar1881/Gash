// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Module: github.com/Xmar1881/Gash

package loader

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestCacheKeyMatrix(t *testing.T) {
	base := time.Date(2026, 10, 21, 12, 0, 0, 123456789, time.UTC)
	a := CacheKey("/plugins/a.js", base, "1.0")
	b := CacheKey("/plugins/a.js", base, "1.0")
	if a != b {
		t.Fatalf("stable key mismatch: %q != %q", a, b)
	}
	if len(a) != 64 {
		t.Fatalf("key length = %d, want 64", len(a))
	}
	tests := []struct {
		name string
		path string
		when time.Time
		api  string
	}{
		{"path", "/plugins/b.js", base, "1.0"},
		{"mtime", "/plugins/a.js", base.Add(time.Nanosecond), "1.0"},
		{"api", "/plugins/a.js", base, "2.0"},
	}
	for _, tc := range tests {
		if got := CacheKey(tc.path, tc.when, tc.api); got == a {
			t.Fatalf("%s change did not alter key", tc.name)
		}
	}
	zone := time.FixedZone("plus2", 2*60*60)
	if got := CacheKey("/plugins/a.js", base.In(zone), "1.0"); got != a {
		t.Fatalf("timezone must not alter key: %q != %q", got, a)
	}
}

func TestFileKeyAndMissingPath(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "plugin.js")
	if err := os.WriteFile(path, []byte("// plugin"), 0o600); err != nil {
		t.Fatal(err)
	}
	when := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	if err := os.Chtimes(path, when, when); err != nil {
		t.Fatal(err)
	}
	key, err := FileKey(path)
	if err != nil {
		t.Fatal(err)
	}
	if want := CacheKey(path, when, "1.0"); key != want {
		t.Fatalf("FileKey = %q, want %q", key, want)
	}
	if _, err := FileKey(filepath.Join(dir, "missing.js")); err == nil || !strings.Contains(err.Error(), "cache stat") {
		t.Fatalf("missing file err = %v", err)
	}
}

func TestCacheRoundTripAndPersistence(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cache.db")
	c, err := OpenCache(path)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := c.Get("missing"); err != nil || got != nil {
		t.Fatalf("missing get = %q, %v", got, err)
	}
	if err := c.Put("k", []byte("v1")); err != nil {
		t.Fatal(err)
	}
	if err := c.Put("k", []byte("v2")); err != nil {
		t.Fatal(err)
	}
	got, err := c.Get("k")
	if err != nil || string(got) != "v2" {
		t.Fatalf("get = %q, %v", got, err)
	}
	got[0] = 'X'
	again, _ := c.Get("k")
	if string(again) != "v2" {
		t.Fatal("Get must return a defensive copy")
	}
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	if err := c.Close(); err != nil {
		t.Fatal("second Close must be safe")
	}

	c2, err := OpenCache(path)
	if err != nil {
		t.Fatal(err)
	}
	defer c2.Close()
	got, err = c2.Get("k")
	if err != nil || string(got) != "v2" {
		t.Fatalf("persisted get = %q, %v", got, err)
	}
}

func TestOpenCacheErrorsAndNilClose(t *testing.T) {
	var nilCache *Cache
	if err := nilCache.Close(); err != nil {
		t.Fatalf("nil close = %v", err)
	}
	if err := (&Cache{}).Close(); err != nil {
		t.Fatalf("empty close = %v", err)
	}
	if _, err := OpenCache(t.TempDir()); err == nil || !strings.Contains(err.Error(), "cache open") {
		t.Fatalf("directory open err = %v", err)
	}
}

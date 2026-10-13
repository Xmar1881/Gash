// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Modül: github.com/Xmar1881/Gash

// Package bench warm-keşif bütçesi regresyonudur (B8: ≤150ms).
package bench

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/Xmar1881/Gash/internal/plugin"
	"github.com/Xmar1881/Gash/internal/plugin/loader"
)

const benchTier1 = `id: %s
name: Bench plugin for warm discovery testing purposes here
description: Warm discovery benchmark plugin with sufficiently long description text here.
severity: low
tags: [bench]
safe: true
deep: false
active: false
requires_auth: false
phase: probe
order: 10
api_version: "1.0"
request:
  method: GET
  param_names: [q]
  payload: "x"
oracle:
  name: reflection
  params: {}
`

func BenchmarkWarmDiscovery(b *testing.B) {
	dir := b.TempDir()
	for i := 0; i < 100; i++ {
		id := fmt.Sprintf("bench-%03d", i)
		content := fmt.Sprintf(benchTier1, id)
		if err := os.WriteFile(filepath.Join(dir, id+".yaml"), []byte(content), 0o644); err != nil {
			b.Fatal(err)
		}
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		reg := plugin.NewRegistry()
		if _, err := loader.Discover([]string{dir}, reg); err != nil {
			b.Fatalf("discover: %v", err)
		}
		if reg.Len() != 100 {
			b.Fatalf("100 plugin bekleniyordu, got %d", reg.Len())
		}
	}
}

// TestWarmDiscoveryBudget bench'i tek-seferlik test olarak da kilitler (CI fail eşiği).
func TestWarmDiscoveryBudget(t *testing.T) {
	if testing.Short() {
		t.Skip("short modda bench bütçesi atlanır")
	}
	res := testing.Benchmark(BenchmarkWarmDiscovery)
	// testing.BenchmarkResult: NsPerOp nanosaniye; 100 plugin warm keşif ≤150ms.
	perOp := res.NsPerOp()
	t.Logf("warm discovery 100 plugin: %d ns/op (%d iter)", perOp, res.N)
	if perOp > 150_000_000 {
		t.Fatalf("B8: warm keşif 150ms aşıldı: %d ns", perOp)
	}
}

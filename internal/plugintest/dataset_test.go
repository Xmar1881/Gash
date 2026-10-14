// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Modül: github.com/Xmar1881/Gash

package plugintest

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

// TestDatasetHashStable pins the fixture dataset version (P0.3).
// What: Same bytes produce the same hash; any added file changes it.
// Why: Precision claims must name the dataset they were measured on.
func TestDatasetHashStable(t *testing.T) {
	dir := t.TempDir()
	write := func(rel, body string) {
		p := filepath.Join(dir, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("positive/a.json", `{"name":"a"}`)
	write("negative/b.json", `{"name":"b"}`)
	h1, n1, err := hashDataset(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(h1) != 64 || n1 != 2 {
		t.Fatalf("hash hex64 + 2 files bekleniyordu: %q %d", h1, n1)
	}
	h2, _, err := hashDataset(dir)
	if err != nil {
		t.Fatal(err)
	}
	if h1 != h2 {
		t.Fatal("aynı veri aynı hash üretmeli (determinizm)")
	}
	// Sessiz fixture ekleme hash'i değiştirmeli (benchmark şişirme görünür).
	write("positive/c.json", `{"name":"c"}`)
	h3, n3, err := hashDataset(dir)
	if err != nil {
		t.Fatal(err)
	}
	if h3 == h1 || n3 != 3 {
		t.Fatalf("yeni fixture hash'i değiştirmeli: %q vs %q (%d)", h1, h3, n3)
	}
}

// TestRunRecordsDataset pins Summary dataset provenance (P0.3).
func TestRunRecordsDataset(t *testing.T) {
	dir := t.TempDir()
	pos := filepath.Join(dir, "positive")
	neg := filepath.Join(dir, "negative")
	if err := os.MkdirAll(pos, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(neg, 0o755); err != nil {
		t.Fatal(err)
	}
	posFixture := `{"name":"ok","status":200,"headers":{"Content-Type":"text/html"},` +
		`"body":"<p>gash_a1b2c3d4</p>","control_body":"<p>zzz</p>",` +
		`"canary":"gash_a1b2c3d4","expected_verdict":"accept","expected_confidence":"tentative"}`
	negFixture := `{"name":"clean","status":200,"headers":{"Content-Type":"text/html"},` +
		`"body":"<p>nothing</p>","control_body":"<p>zzz</p>",` +
		`"canary":"gash_a1b2c3d4","expected_verdict":"reject"}`
	if err := os.WriteFile(filepath.Join(pos, "p.json"), []byte(posFixture), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(neg, "n.json"), []byte(negFixture), 0o644); err != nil {
		t.Fatal(err)
	}
	sum, err := Run(context.Background(), "probe", "reflection", dir, true, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !sum.Pass {
		t.Fatalf("fixture seti geçmeli: %+v", sum.Cases)
	}
	if sum.Dataset != dir || len(sum.DatasetHash) != 64 || sum.FixtureFiles != 2 {
		t.Fatalf("dataset provenance eksik: %+v", sum)
	}
}

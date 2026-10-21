// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Module: github.com/Xmar1881/Gash

package engine

import (
	"testing"

	"github.com/Xmar1881/Gash/internal/plugin/loader"
)

// TestTier1DiscoveryPointsMatching proves declared parameters match discovered
// injection points so Tier 1 plugins can reach multi-endpoint surfaces.
func TestTier1DiscoveryPointsMatching(t *testing.T) {
	target := "http://127.0.0.1:9099"
	points := []loader.JSPoint{
		{URL: "http://127.0.0.1:9099/traversal?file=readme.txt", Method: "GET", ParamName: "file", ParamLocation: "query", Value: "readme.txt"},
		{URL: "http://127.0.0.1:9099/xss/reflect?q=hello", Method: "GET", ParamName: "q", ParamLocation: "query", Value: "hello"},
		{URL: "http://127.0.0.1:9099/post", Method: "POST", ParamName: "file"},
		{URL: "http://127.0.0.1:9099/cookie-borne", Method: "GET", ParamName: "file", ParamLocation: "cookie"},
		{URL: "http://other.example/traversal?file=x", Method: "GET", ParamName: "file", ParamLocation: "query"},
	}
	got := tier1DiscoveryPoints(target, []string{"file", "path"}, points)
	if len(got) != 1 || got[0].URL != "http://127.0.0.1:9099/traversal?file=readme.txt" || got[0].Param != "file" {
		t.Fatalf("param-matched in-scope GET point only: %v", got)
	}
}

func TestTier1DiscoveryPointsNoParams(t *testing.T) {
	points := []loader.JSPoint{{URL: "http://127.0.0.1:9099/a?file=x", ParamName: "file"}}
	if got := tier1DiscoveryPoints("http://127.0.0.1:9099", nil, points); got != nil {
		t.Fatalf("plugins without declared params must not get feedback: %v", got)
	}
}

func TestTier1DiscoveryPointsCap(t *testing.T) {
	target := "http://127.0.0.1:9099"
	var points []loader.JSPoint
	for i := 0; i < tier1DiscoveryPointCap+5; i++ {
		points = append(points, loader.JSPoint{
			URL: "http://127.0.0.1:9099/p?file=" + string(rune('a'+i)), Method: "GET",
			ParamName: "file", ParamLocation: "query",
		})
	}
	got := tier1DiscoveryPoints(target, []string{"file"}, points)
	if len(got) != tier1DiscoveryPointCap {
		t.Fatalf("feedback must be capped at %d, got %d", tier1DiscoveryPointCap, len(got))
	}
}

func TestTier1DiscoveryPointsDedupesURL(t *testing.T) {
	target := "http://127.0.0.1:9099"
	points := []loader.JSPoint{
		{URL: "http://127.0.0.1:9099/redirect", Method: "GET", ParamName: "next", ParamLocation: "query"},
		{URL: "http://127.0.0.1:9099/redirect", Method: "GET", ParamName: "url", ParamLocation: "query"},
	}
	got := tier1DiscoveryPoints(target, []string{"redirect", "url", "next"}, points)
	if len(got) != 1 || got[0].Param != "next" {
		t.Fatalf("one attempt per discovered URL keeps fallback bounded: %v", got)
	}
}

func TestTier1DiscoveryPointsSkipsTargetItself(t *testing.T) {
	target := "http://127.0.0.1:9099/?file=x"
	points := []loader.JSPoint{
		{URL: target, Method: "GET", ParamName: "file", ParamLocation: "query"},
		{URL: "http://127.0.0.1:9099/other?file=y", Method: "GET", ParamName: "file", ParamLocation: "query"},
	}
	got := tier1DiscoveryPoints(target, []string{"file"}, points)
	if len(got) != 1 || got[0].URL != "http://127.0.0.1:9099/other?file=y" {
		t.Fatalf("target itself must be skipped: %v", got)
	}
}

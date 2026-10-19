//go:build !deep

// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Module: github.com/Xmar1881/Gash

package engine

import (
	"strings"
	"testing"

	"github.com/Xmar1881/Gash/internal/discovery"
	"github.com/Xmar1881/Gash/internal/plugin"
)

// TestRunSPACrawlStubSkipsHonestly locks the default-build contract: no
// browser driver means one explicit skip record, never fabricated surface.
func TestRunSPACrawlStubSkipsHonestly(t *testing.T) {
	cfg := DefaultConfig()
	cfg.BrowserCrawl = true
	e := New(plugin.NewRegistry(), cfg)
	crawlRes := &discovery.CrawlResult{Pages: []discovery.CrawlPage{{
		URL: "http://127.0.0.1:1/", Status: 200,
	}}}
	points, skipped, stats := e.runSPACrawl(t.Context(), "http://127.0.0.1:1", nil, crawlRes, nil)
	if len(points) != 0 {
		t.Fatalf("stub build must not produce points: %+v", points)
	}
	if stats["spa_pages_rendered"] != 0 {
		t.Fatalf("stub build must not count renders: %v", stats)
	}
	if len(skipped) != 1 || skipped[0].PluginID != "browser-crawl" ||
		!strings.Contains(strings.ToLower(skipped[0].Reason), "deep") {
		t.Fatalf("stub build must leave one honest skip: %+v", skipped)
	}
}

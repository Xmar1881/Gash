// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Module: github.com/Xmar1881/Gash

package engine

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Xmar1881/Gash/internal/config"
	"github.com/Xmar1881/Gash/internal/plugin"
	"github.com/Xmar1881/Gash/internal/plugin/loader"
)

// wafAggressiveBackend bypass başlığı yoksa 403+WAF işareti, varsa çıplak
// 200 döner (header oracle bulgu üretir).
func wafAggressiveBackend() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		if r.Header.Get("X-Forwarded-For") != "127.0.0.1" {
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte("<html>request blocked by waf</html>"))
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("<html><body>hello</body></html>"))
	}))
}

func wafAggressiveEngine(t *testing.T, profile config.ProfileName) *Engine {
	t.Helper()
	dir := writeE2EPlugin(t)
	reg := plugin.NewRegistry()
	if _, err := loader.Discover([]string{dir}, reg); err != nil {
		t.Fatalf("discover: %v", err)
	}
	cfg := DefaultConfig()
	cfg.Profile = profile
	return New(reg, cfg)
}

// TestAggressiveBypassesWAF proves the aggressive profile turns a WAF block
// into a bypassed live response (finding + waf stats) instead of a drop.
func TestAggressiveBypassesWAF(t *testing.T) {
	srv := wafAggressiveBackend()
	defer srv.Close()
	e := wafAggressiveEngine(t, config.ProfileAggressive)
	rep, err := e.Run(context.Background(), srv.URL)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if len(rep.Findings) < 1 {
		t.Fatalf("bypass sonrası bulgu beklenir, got %d (skipped=%v)", len(rep.Findings), rep.Skipped)
	}
	if rep.Stats["waf_detected"] < 1 {
		t.Fatalf("waf_detected işlenmeli: %+v", rep.Stats)
	}
	if rep.Stats["waf_bypassed"] < 1 {
		t.Fatalf("waf_bypassed işlenmeli: %+v", rep.Stats)
	}
}

// TestStandardKeepsWAFBlock proves the default profile never stealth-retries:
// the block page stays evidence-free (guard reject) but is still counted.
func TestStandardKeepsWAFBlock(t *testing.T) {
	srv := wafAggressiveBackend()
	defer srv.Close()
	e := wafAggressiveEngine(t, config.ProfileStandard)
	rep, err := e.Run(context.Background(), srv.URL)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if len(rep.Findings) != 0 {
		t.Fatalf("blok sayfa kanıt olamaz, got %d bulgu", len(rep.Findings))
	}
	if rep.Stats["waf_detected"] < 1 {
		t.Fatalf("standart modda da waf_detected sayılmalı: %+v", rep.Stats)
	}
	if rep.Stats["waf_bypassed"] != 0 {
		t.Fatalf("standart modda bypass YOK: %+v", rep.Stats)
	}
}

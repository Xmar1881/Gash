// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Modül: github.com/Xmar1881/Gash

package engine

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Xmar1881/Gash/internal/config"
	"github.com/Xmar1881/Gash/internal/plugin"
	"github.com/Xmar1881/Gash/internal/plugin/loader"
	"github.com/Xmar1881/Gash/internal/smuggle"
)

// TestSmuggleGateMatrix kapı matrisini kilitler: yalnızca
// --active + agresif profil koşar, diğerleri skip (soket yok).
func TestSmuggleGateMatrix(t *testing.T) {
	mk := func(active bool, profile config.ProfileName) *Engine {
		cfg := DefaultConfig()
		cfg.Active = active
		cfg.Profile = profile
		return New(plugin.NewRegistry(), cfg)
	}
	if !smuggleGateOK(mk(true, config.ProfileAggressive)) {
		t.Fatalf("active+aggressive → kapı açık olmalı")
	}
	for _, tc := range []struct {
		name    string
		active  bool
		profile config.ProfileName
	}{
		{"safe", false, config.ProfileSafe},
		{"standard", true, config.ProfileStandard},
		{"standard-passive", false, config.ProfileStandard},
		{"deep-active", true, config.ProfileDeep},
		{"aggressive-passive", false, config.ProfileAggressive},
		{"empty", false, ""},
	} {
		if smuggleGateOK(mk(tc.active, tc.profile)) {
			t.Fatalf("%s → kapı kapalı olmalı", tc.name)
		}
	}
}

// TestSmuggleSkipReported kapı dışının raporda denetim izi bıraktığını kanıtlar.
func TestSmuggleSkipReported(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()
	dir := writeE2EPlugin(t)
	reg := plugin.NewRegistry()
	if _, err := loader.Discover([]string{dir}, reg); err != nil {
		t.Fatalf("discover: %v", err)
	}
	e := New(reg, DefaultConfig()) // safe: Active=false
	rep, err := e.Run(context.Background(), srv.URL)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	found := false
	for _, s := range rep.Skipped {
		if s.PluginID == smuggle.PluginID && strings.Contains(s.Reason, "--active --aggressive") {
			found = true
		}
	}
	if !found {
		t.Fatalf("smuggle skip izi raporda olmalı: %+v", rep.Skipped)
	}
	for _, f := range rep.Findings {
		if f.RuleID == smuggle.RuleID {
			t.Fatalf("kapı dışı GASH-033 bulgusu olmamalı")
		}
	}
}

// TestSmuggleAggressiveConsistentNoFinding agresif profilde tutarlı
// localhost backend'in bulgusuz (TN) kaldığını kanıtlar.
func TestSmuggleAggressiveConsistentNoFinding(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("OK-clean"))
	}))
	defer srv.Close()
	dir := writeE2EPlugin(t)
	reg := plugin.NewRegistry()
	if _, err := loader.Discover([]string{dir}, reg); err != nil {
		t.Fatalf("discover: %v", err)
	}
	cfg := DefaultConfig()
	cfg.Active = true
	cfg.Profile = config.ProfileAggressive
	e := New(reg, cfg)
	rep, err := e.Run(context.Background(), srv.URL)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	for _, f := range rep.Findings {
		if f.RuleID == smuggle.RuleID {
			t.Fatalf("tutarlı backend'de GASH-033 olmamalı: %+v", f)
		}
	}
	if n, ok := rep.Stats["smuggle_requests"]; !ok || n <= 0 {
		t.Fatalf("agresif taramada smuggle_requests ölçülmeli: %+v", rep.Stats)
	}
}

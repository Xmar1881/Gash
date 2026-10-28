// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Modül: github.com/Xmar1881/Gash

package engine

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/Xmar1881/Gash/internal/config"
	"github.com/Xmar1881/Gash/internal/plugin"
)

func mkSpec(id string, phase plugin.Phase, order int) plugin.PluginSpec {
	return plugin.PluginSpec{
		ID: id, Name: "Test plugin adı", Description: "Yeterli uzunlukta açıklama metni test için yazıldı.",
		Severity: plugin.SeverityMedium, Tags: []string{"t"}, Safe: true,
		Phase: phase, Order: order, APIVersion: "1.0",
	}
}

func TestEmptyRegistryEmptyReport(t *testing.T) {
	reg := plugin.NewRegistry()
	e := New(reg, DefaultConfig())
	rep, err := e.Run(context.Background(), "http://example.com/")
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if len(rep.Findings) != 0 {
		t.Fatalf("boş rapor bekleniyordu")
	}
}

// TestTargetPreflightFailsFast locks the early abort for unreachable targets.
// What: A non-empty schedule against a closed port must return a preflight
// error instead of burning every per-plugin timeout.
// Why: The runtime tech GET doubles as the reachability check.
func TestTargetPreflightFailsFast(t *testing.T) {
	reg := plugin.NewRegistry()
	reg.MustRegister(mkSpec("passive-p", plugin.PhaseProbe, 1), "mem", false)
	cfg := DefaultConfig()
	cfg.ScanTimeout = 5 * time.Second
	cfg.RequestTimeout = 2 * time.Second
	_, err := New(reg, cfg).Run(context.Background(), "http://127.0.0.1:1/")
	if err == nil {
		t.Fatal("unreachable target must fail the preflight")
	}
	if !strings.Contains(err.Error(), "target preflight failed") {
		t.Fatalf("preflight error must name the phase: %v", err)
	}
}

// TestPreflightIgnoredWhenScheduleEmpty keeps the empty-result contract: when
// profile gates skip every plugin, an unreachable target is irrelevant and the
// run still returns a valid empty report.
func TestPreflightIgnoredWhenScheduleEmpty(t *testing.T) {
	reg := plugin.NewRegistry()
	active := mkSpec("active-p", plugin.PhaseProbe, 1)
	active.Active = true
	active.Safe = false
	reg.MustRegister(active, "mem", false)
	cfg := DefaultConfig()
	cfg.ScanTimeout = 5 * time.Second
	cfg.RequestTimeout = 2 * time.Second
	rep, err := New(reg, cfg).Run(context.Background(), "http://127.0.0.1:1/")
	if err != nil {
		t.Fatalf("empty schedule must not surface preflight: %v", err)
	}
	if len(rep.Findings) != 0 || len(rep.Skipped) == 0 {
		t.Fatalf("expected empty report with skips, got %+v", rep)
	}
}

func TestOOBRequiredSkipped(t *testing.T) {
	reg := plugin.NewRegistry()
	s := mkSpec("blind-ssrf", plugin.PhaseProbe, 1)
	s.Safe = false
	s.Active = true
	s.OOB = plugin.OOBRequired
	reg.MustRegister(s, "mem", false)
	cfg := DefaultConfig()
	cfg.Active = true  // active kapısı açık; OOB kapısı test edilir (B9)
	e := New(reg, cfg) // OOBServer boş
	ordered, skipped, err := e.Schedule(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(ordered) != 0 {
		t.Fatalf("oob:required çalışmamalı, got %v", ordered) //nolint:misspell // Türkçe olumsuz gelecek zaman eki, İngilizce yazım denetimine tabi değildir
	}
	found := false
	for _, sk := range skipped {
		if sk.PluginID == "blind-ssrf" && contains(sk.Reason, "oob-not-configured") {
			found = true
		}
	}
	if !found {
		t.Fatalf("oob skip sebebi yok: %+v", skipped)
	}
}

func TestTier3UntrustedSkipped(t *testing.T) {
	reg := plugin.NewRegistry()
	s := mkSpec("native-x", plugin.PhaseDeep, 1)
	s.Tier = plugin.TierNative
	s.Safe = false
	s.Active = true
	reg.MustRegister(s, "mem", false)
	e := New(reg, DefaultConfig())
	e.cfg.Active = true
	e.cfg.Deep = true
	ordered, skipped, _ := e.Schedule(context.Background())
	if len(ordered) != 0 {
		t.Fatalf("trust'suz native çalışmamalı") //nolint:misspell // Türkçe olumsuz gelecek zaman eki
	}
	_ = skipped
}

func TestNoisyBreaker(t *testing.T) {
	dem, note := NoisyBreaker(map[string]int{"fp1": 11, "fp2": 2}, 10)
	if len(dem) != 1 || dem[0] != "fp1" {
		t.Fatalf("demote: %v %s", dem, note)
	}
}

// TestSkippedReasonFormat locks the user-visible skip messages.
// What: Exact match for active/deep gates plus substring checks for OOB,
// trust, auth, and ignore reasons.
// Why: The CLI prints these verbatim; a malformed flag name such as
// "active-requires---active" must never regress.
func TestSkippedReasonFormat(t *testing.T) {
	e := New(plugin.NewRegistry(), DefaultConfig())

	activeSpec := mkSpec("active-p", plugin.PhaseProbe, 1)
	activeSpec.Active = true
	if reason, ok := e.filterReason(activeSpec); ok || reason != "skipped (requires --active)" {
		t.Fatalf("active skip mismatch: ok=%v reason=%q", ok, reason)
	}

	deepSpec := mkSpec("deep-p", plugin.PhaseProbe, 2)
	deepSpec.Deep = true
	if reason, ok := e.filterReason(deepSpec); ok || reason != "skipped (requires --deep)" {
		t.Fatalf("deep skip mismatch: ok=%v reason=%q", ok, reason)
	}

	authSpec := mkSpec("auth-p", plugin.PhaseProbe, 3)
	authSpec.RequiresAuth = true
	if reason, ok := e.filterReason(authSpec); ok || reason != "skipped (requires auth)" {
		t.Fatalf("auth skip mismatch: ok=%v reason=%q", ok, reason)
	}

	oobSpec := mkSpec("oob-p", plugin.PhaseProbe, 4)
	oobSpec.Active = true
	oobSpec.OOB = plugin.OOBRequired
	eActive := New(plugin.NewRegistry(), func() Config {
		c := DefaultConfig()
		c.Active = true
		return c
	}())
	if reason, ok := eActive.filterReason(oobSpec); ok || !strings.Contains(reason, "oob-not-configured") || !strings.Contains(reason, "--oob-server") {
		t.Fatalf("oob skip must name oob-not-configured and --oob-server: ok=%v reason=%q", ok, reason)
	}

	nativeSpec := mkSpec("native-p", plugin.PhaseProbe, 5)
	nativeSpec.Tier = plugin.TierNative
	if reason, ok := e.filterReason(nativeSpec); ok || !strings.Contains(reason, "tier3-untrusted") {
		t.Fatalf("tier3 skip must name tier3-untrusted: ok=%v reason=%q", ok, reason)
	}

	// Ignore-list reason keeps the flag name and the skipped prefix.
	reg := plugin.NewRegistry()
	reg.MustRegister(mkSpec("ignored-p", plugin.PhaseProbe, 6), "mem", false)
	cfg := DefaultConfig()
	cfg.IgnorePlugins = map[string]bool{"ignored-p": true}
	eIgnored := New(reg, cfg)
	_, skipped, err := eIgnored.Schedule(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, sk := range skipped {
		if sk.PluginID == "ignored-p" {
			found = true
			if !strings.HasPrefix(sk.Reason, "skipped (") || !strings.Contains(sk.Reason, "--ignore-plugin") {
				t.Fatalf("ignore skip format mismatch: %q", sk.Reason)
			}
		}
	}
	if !found {
		t.Fatalf("ignored plugin must appear in skipped: %+v", skipped)
	}

	// Global invariant: no scheduler reason may contain the malformed triple-dash flag.
	for _, s := range []plugin.PluginSpec{activeSpec, deepSpec, authSpec, oobSpec, nativeSpec} {
		var eng *Engine
		if s.ID == "oob-p" {
			eng = eActive
		} else {
			eng = e
		}
		reason, ok := eng.filterReason(s)
		if ok {
			continue
		}
		if strings.Contains(reason, "---") {
			t.Fatalf("skip reason contains malformed flag %q for %s", reason, s.ID)
		}
		if !strings.HasPrefix(reason, "skipped (") || !strings.HasSuffix(reason, ")") {
			t.Fatalf("skip reason must use consistent skipped (...) format: %q", reason)
		}
	}
}

// TestOnlyPluginsRestrictsSchedule locks positive selection semantics:
// unselected plugins disappear from the schedule without skip-wall entries.
func TestOnlyPluginsRestrictsSchedule(t *testing.T) {
	reg := plugin.NewRegistry()
	reg.MustRegister(mkSpec("keep-plugin", plugin.PhaseProbe, 1), "mem", false)
	reg.MustRegister(mkSpec("drop-plugin", plugin.PhaseProbe, 2), "mem", false)
	cfg := DefaultConfig()
	cfg.OnlyPlugins = map[string]bool{"keep-plugin": true}
	ordered, skipped, err := New(reg, cfg).Schedule(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(ordered) != 1 || ordered[0].ID != "keep-plugin" {
		t.Fatalf("only-plugin schedule = %+v", ordered)
	}
	if len(skipped) != 0 {
		t.Fatalf("positive selection must not create skip entries: %+v", skipped)
	}
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (func() bool {
		for i := 0; i+len(sub) <= len(s); i++ {
			if s[i:i+len(sub)] == sub {
				return true
			}
		}
		return false
	})()
}

// TestProfileGateUsesRegistryOracle locks discovery-recorded oracle gating.
// What: A product-tagged plugin whose tags never name "error" must still be
// filtered by the safe profile when discovery recorded the error oracle.
// Why: This is the starvation path that made hundreds of exposure plugins run
// in passive profiles and exhaust the request budget before header checks.
func TestProfileGateUsesRegistryOracle(t *testing.T) {
	reg := plugin.NewRegistry()
	spec := mkSpec("product-tagged-exposure", plugin.PhaseDiscovery, 1)
	spec.Safe = false
	spec.Tags = []string{"adminer", "database"}
	reg.MustRegister(spec, "mem", false)
	reg.SetOracleName(spec.ID, "error")

	cfg := DefaultConfig()
	cfg.Profile = config.ProfileSafe
	ordered, skipped, err := New(reg, cfg).Schedule(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(ordered) != 0 {
		t.Fatalf("safe profile must not schedule an error-oracle plugin: %v", ordered)
	}
	if len(skipped) != 1 || !strings.Contains(skipped[0].Reason, `oracle "error" disabled by profile safe`) {
		t.Fatalf("profile skip reason must name the recorded oracle: %+v", skipped)
	}
}

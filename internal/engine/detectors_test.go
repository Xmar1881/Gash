// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Module: github.com/Xmar1881/Gash

package engine

import (
	"testing"

	"github.com/Xmar1881/Gash/internal/config"
	"github.com/Xmar1881/Gash/internal/discovery"
	"github.com/Xmar1881/Gash/internal/plugin"
	"github.com/Xmar1881/Gash/internal/proto"
	"github.com/Xmar1881/Gash/internal/recon"
	"github.com/Xmar1881/Gash/internal/smuggle"
)

// TestDetectorRegistryIsComplete proves the engine-owned unit inventory.
// What: Every engine-owned finding producer is registered, with its rule id,
// and the registry order follows the scan pipeline.
// Why: Before the port these units were if-chains; the registry is now the only
// place that answers "which engine-owned detectors exist", so the inventory must
// be asserted instead of assumed.
func TestDetectorRegistryIsComplete(t *testing.T) {
	e := New(plugin.NewRegistry(), DefaultConfig())
	specs := e.DetectorSpecs()
	want := map[string]string{
		recon.PluginIDJSRecon:              recon.RuleIDJSSecret,
		recon.PluginIDSPAState:             recon.RuleIDSPAState,
		recon.PluginIDDevBuild:             recon.RuleIDDevBuild,
		discovery.PluginIDContentDiscovery: discovery.RuleIDExposedPath,
		smuggle.PluginID:                   smuggle.RuleID,
		proto.PluginIDTLSCert:              "GASH-024",
		proto.PluginIDTLSDeep:              "GASH-024",
		proto.PluginIDDNS:                  "GASH-025",
		proto.PluginIDTCPBanner:            "GASH-026",
		proto.PluginIDSSHBanner:            "GASH-052",
		proto.PluginIDSSHHandshake:         "GASH-054",
		proto.PluginIDDBPorts:              "GASH-053",
		proto.PluginIDDBUnauth:             "GASH-055",
	}
	if len(specs) != len(want) {
		t.Fatalf("want %d registered detectors, got %d: %+v", len(want), len(specs), specs)
	}
	for _, spec := range specs {
		rule, ok := want[spec.ID]
		if !ok {
			t.Fatalf("unexpected detector %q", spec.ID)
		}
		if spec.RuleID != rule {
			t.Fatalf("detector %q rule=%q want %q", spec.ID, spec.RuleID, rule)
		}
		if spec.CWE == "" || spec.Oracle == "" || spec.DetectorVersion == "" {
			t.Fatalf("detector %q lost its traceability fields: %+v", spec.ID, spec)
		}
	}
	wantOrder := []string{
		recon.PluginIDJSRecon,
		recon.PluginIDSPAState,
		recon.PluginIDDevBuild,
		discovery.PluginIDContentDiscovery,
		proto.PluginIDTLSCert,
		proto.PluginIDDNS,
		proto.PluginIDTCPBanner,
		proto.PluginIDSSHBanner,
		proto.PluginIDSSHHandshake,
		proto.PluginIDDBPorts,
		proto.PluginIDDBUnauth,
		proto.PluginIDTLSDeep,
		smuggle.PluginID,
	}
	for i, id := range wantOrder {
		if specs[i].ID != id {
			t.Fatalf("registry order[%d]=%q want %q", i, specs[i].ID, id)
		}
	}
}

// TestDetectorGatesFollowTheProfile proves the engine-owned gate contract.
// What: Discovery units stay ungated, discovery needs --active, and the raw-TCP
// probe needs --active plus the aggressive profile.
// Why: The gate wording and order are the audit trail; a drift here would let an
// invasive unit run in a profile that forbids it (or silently drop a safe one).
func TestDetectorGatesFollowTheProfile(t *testing.T) {
	cases := []struct {
		name    string
		profile config.ProfileName
		active  bool
		// allow lists the detectors the policy must admit.
		allow []string
		// deny maps a refused detector to the exact audit reason.
		deny map[string]string
	}{
		{
			name:    "safe profile without active",
			profile: config.ProfileSafe,
			allow:   []string{recon.PluginIDJSRecon, recon.PluginIDSPAState, recon.PluginIDDevBuild, proto.PluginIDTLSCert, proto.PluginIDDNS, proto.PluginIDTLSDeep},
			deny: map[string]string{
				discovery.PluginIDContentDiscovery: "skipped (requires --active)",
				proto.PluginIDTCPBanner:            "skipped (tcp-banner requires --active)",
				proto.PluginIDSSHBanner:            "skipped (requires --active)",
				proto.PluginIDSSHHandshake:         "skipped (requires --active)",
				proto.PluginIDDBPorts:              "skipped (requires --active)",
				proto.PluginIDDBUnauth:             "skipped (requires --active)",
				smuggle.PluginID:                   "skipped (smuggle-probe requires --active --aggressive)",
			},
		},
		{
			name:    "safe profile with active proves the profile gate",
			profile: config.ProfileSafe,
			active:  true,
			allow:   []string{recon.PluginIDJSRecon, recon.PluginIDSPAState, recon.PluginIDDevBuild, discovery.PluginIDContentDiscovery, proto.PluginIDTLSCert, proto.PluginIDDNS, proto.PluginIDTLSDeep},
			deny: map[string]string{
				proto.PluginIDTCPBanner:    "skipped (detector tcp disabled by profile safe)",
				proto.PluginIDSSHBanner:    "skipped (detector ssh disabled by profile safe)",
				proto.PluginIDSSHHandshake: "skipped (detector ssh disabled by profile safe)",
				proto.PluginIDDBPorts:      "skipped (detector db disabled by profile safe)",
				proto.PluginIDDBUnauth:     "skipped (detector db disabled by profile safe)",
				smuggle.PluginID:           "skipped (smuggle-probe requires --aggressive)",
			},
		},
		{
			name:    "standard profile with active",
			profile: config.ProfileStandard,
			active:  true,
			allow: []string{
				recon.PluginIDJSRecon, recon.PluginIDSPAState, recon.PluginIDDevBuild,
				discovery.PluginIDContentDiscovery, proto.PluginIDTLSCert, proto.PluginIDDNS,
				proto.PluginIDTCPBanner, proto.PluginIDSSHBanner, proto.PluginIDSSHHandshake,
				proto.PluginIDDBPorts, proto.PluginIDDBUnauth, proto.PluginIDTLSDeep,
			},
			deny: map[string]string{
				smuggle.PluginID: "skipped (smuggle-probe requires --aggressive)",
			},
		},
		{
			name:    "aggressive profile without active",
			profile: config.ProfileAggressive,
			allow:   []string{recon.PluginIDJSRecon, recon.PluginIDSPAState, recon.PluginIDDevBuild, proto.PluginIDTLSCert, proto.PluginIDDNS, proto.PluginIDTLSDeep},
			deny: map[string]string{
				discovery.PluginIDContentDiscovery: "skipped (requires --active)",
				proto.PluginIDTCPBanner:            "skipped (tcp-banner requires --active)",
				proto.PluginIDSSHBanner:            "skipped (requires --active)",
				proto.PluginIDSSHHandshake:         "skipped (requires --active)",
				proto.PluginIDDBPorts:              "skipped (requires --active)",
				proto.PluginIDDBUnauth:             "skipped (requires --active)",
				smuggle.PluginID:                   "skipped (smuggle-probe requires --active)",
			},
		},
		{
			name:    "aggressive profile with active",
			profile: config.ProfileAggressive,
			active:  true,
			allow: []string{
				recon.PluginIDJSRecon, recon.PluginIDSPAState, recon.PluginIDDevBuild,
				discovery.PluginIDContentDiscovery, proto.PluginIDTLSCert, proto.PluginIDDNS,
				proto.PluginIDTCPBanner, proto.PluginIDSSHBanner, proto.PluginIDSSHHandshake,
				proto.PluginIDDBPorts, proto.PluginIDDBUnauth, proto.PluginIDTLSDeep,
				smuggle.PluginID,
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := DefaultConfig()
			cfg.Profile = tc.profile
			cfg.Active = tc.active
			e := New(plugin.NewRegistry(), cfg)
			policy := e.detectorPolicy()
			specs := e.DetectorSpecs()

			allowed := map[string]bool{}
			for _, spec := range specs {
				ok, reason := spec.Evaluate(policy)
				if ok {
					allowed[spec.ID] = true
					continue
				}
				want, declared := tc.deny[spec.ID]
				if !declared {
					t.Fatalf("%s unexpectedly refused: %s", spec.ID, reason)
				}
				if reason != want {
					t.Fatalf("%s reason=%q want %q", spec.ID, reason, want)
				}
			}
			for _, id := range tc.allow {
				if !allowed[id] {
					t.Fatalf("%s must run in %s", id, tc.name)
				}
			}
			// Every registered detector must be accounted for, either admitted
			// or refused with a declared reason; a new unit cannot slip in
			// ungated without this test noticing.
			if len(tc.allow)+len(tc.deny) != len(specs) {
				t.Fatalf("policy table covers %d detectors, registry has %d", len(tc.allow)+len(tc.deny), len(specs))
			}
		})
	}

	t.Run("smuggle gate wrapper mirrors the registry", func(t *testing.T) {
		cfg := DefaultConfig()
		cfg.Profile = config.ProfileAggressive
		cfg.Active = true
		if !smuggleGateOK(New(plugin.NewRegistry(), cfg)) {
			t.Fatal("aggressive + active must open the smuggling gate")
		}
		cfg.Active = false
		if smuggleGateOK(New(plugin.NewRegistry(), cfg)) {
			t.Fatal("without --active the smuggling gate must stay closed")
		}
	})
}

// TestDetectorScopeIsFailClosed proves the raw-TCP scope decision.
// What: No --scope means open mode; a configured scope denies foreign hosts.
// Why: The smuggling probe dials hosts directly, so its scope preflight is the
// only thing standing between a misconfigured scan and a third-party target.
func TestDetectorScopeIsFailClosed(t *testing.T) {
	e := New(plugin.NewRegistry(), DefaultConfig())
	if scope := e.detectorScope("http://example.com/"); scope != nil {
		t.Fatal("without --scope the decision must stay nil (open mode)")
	}
	e.cfg.Scope = []string{"example.com"}
	scope := e.detectorScope("http://example.com/")
	if scope == nil {
		t.Fatal("with --scope a decision must exist")
	}
	if !scope("example.com") {
		t.Fatal("the scoped host must stay reachable")
	}
	if scope("evil.test") {
		t.Fatal("a foreign host must be denied")
	}

	t.Run("unparseable target fails closed", func(t *testing.T) {
		e.cfg.Scope = []string{"example.com"}
		scope := e.detectorScope("://not a url")
		if scope == nil || scope("example.com") {
			t.Fatal("an unparseable target must deny every host")
		}
	})
}

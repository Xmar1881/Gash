// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Module: github.com/Xmar1881/Gash

package detector

import (
	"context"
	"strings"
	"testing"

	"github.com/Xmar1881/Gash/internal/plugin"
)

// stubDetector is a minimal detector for registry and gate tests.
// What: Deterministic spec plus an optional run record.
// Why: The port must be testable without pulling in a real scan unit.
type stubDetector struct {
	spec    Spec
	ranWith string
}

func (s *stubDetector) Spec() Spec { return s.spec }

func (s *stubDetector) Run(_ context.Context, env *Env) (Result, error) {
	if env != nil {
		s.ranWith = env.Target
	}
	return Result{Stats: map[string]int{"stub_runs": 1}}, nil
}

// baseSpec is a complete, valid spec used as the mutation base.
func baseSpec(id string) Spec {
	return Spec{
		ID: id, Name: "Stub detector", Description: "stub",
		RuleID: "GASH-900", CWE: "CWE-000", Oracle: "stub",
		Severity: plugin.SeverityLow, Phase: plugin.PhaseProbe, Order: 10,
		DetectorVersion: "1.0",
	}
}

// TestRegistryRejectsIncompleteSpecs proves the traceability contract.
// What: Every identity field a finding needs must be declared.
// Why: A detector without rule/CWE/oracle/version produces an unauditable
// finding, which is exactly what the plugin gate refuses for plugins.
func TestRegistryRejectsIncompleteSpecs(t *testing.T) {
	mutate := map[string]func(*Spec){
		"empty id":        func(s *Spec) { s.ID = "" },
		"non slug id":     func(s *Spec) { s.ID = "engine" },
		"empty name":      func(s *Spec) { s.Name = "" },
		"empty desc":      func(s *Spec) { s.Description = "" },
		"empty rule":      func(s *Spec) { s.RuleID = "" },
		"empty cwe":       func(s *Spec) { s.CWE = "" },
		"empty oracle":    func(s *Spec) { s.Oracle = "" },
		"empty version":   func(s *Spec) { s.DetectorVersion = "" },
		"bad severity":    func(s *Spec) { s.Severity = "urgent" },
		"bad phase":       func(s *Spec) { s.Phase = "crawl" },
		"negative budget": func(s *Spec) { s.MaxRequests = -1 },
	}
	for name, fn := range mutate {
		t.Run(name, func(t *testing.T) {
			spec := baseSpec("engine-stub-detector")
			fn(&spec)
			reg := NewRegistry()
			if err := reg.Register(&stubDetector{spec: spec}); err == nil {
				t.Fatal("incomplete spec must be rejected")
			}
		})
	}

	t.Run("valid spec registers", func(t *testing.T) {
		reg := NewRegistry()
		if err := reg.Register(&stubDetector{spec: baseSpec("engine-stub-detector")}); err != nil {
			t.Fatalf("valid spec rejected: %v", err)
		}
		if reg.Len() != 1 {
			t.Fatalf("want 1 detector, got %d", reg.Len())
		}
	})

	t.Run("duplicate id rejected", func(t *testing.T) {
		reg := NewRegistry()
		reg.MustRegister(&stubDetector{spec: baseSpec("engine-stub-detector")})
		if err := reg.Register(&stubDetector{spec: baseSpec("engine-stub-detector")}); err == nil {
			t.Fatal("duplicate id must be rejected")
		}
	})
}

// TestRegistryOrderingIsDeterministic proves stable enumeration.
// What: Order, then ID.
// Why: Reports and docs must not reorder between builds or map iterations.
func TestRegistryOrderingIsDeterministic(t *testing.T) {
	reg := NewRegistry()
	for _, id := range []string{"engine-zeta", "engine-alpha", "engine-middle"} {
		reg.MustRegister(&stubDetector{spec: baseSpec(id)})
	}
	specs := reg.Specs()
	if len(specs) != 3 {
		t.Fatalf("want 3 specs, got %d", len(specs))
	}
	if specs[0].ID != "engine-alpha" || specs[1].ID != "engine-middle" || specs[2].ID != "engine-zeta" {
		t.Fatalf("unexpected order: %s, %s, %s", specs[0].ID, specs[1].ID, specs[2].ID)
	}

	ordered := NewRegistry()
	first := baseSpec("engine-late")
	first.Order = 90
	second := baseSpec("engine-early")
	second.Order = 5
	ordered.MustRegister(&stubDetector{spec: first})
	ordered.MustRegister(&stubDetector{spec: second})
	got := ordered.Specs()
	if got[0].ID != "engine-early" || got[1].ID != "engine-late" {
		t.Fatalf("order field must sort first: %s, %s", got[0].ID, got[1].ID)
	}
}

// TestGateReasonsMatchTheAuditContract proves the canonical skip wording.
// What: Flag requirements first, then the profile gate.
// Why: The report and the contract tests quote these strings verbatim; the port
// must not silently reword an audit trail.
func TestGateReasonsMatchTheAuditContract(t *testing.T) {
	smuggleLike := baseSpec("engine-smuggle-recon")
	smuggleLike.Gate = "smuggle"
	smuggleLike.RequiresActive = true
	smuggleLike.RequiresAggressive = true
	smuggleLike.SkipSubject = "smuggle-probe"

	protoLike := baseSpec("proto-ssh-banner")
	protoLike.Gate = "ssh"
	protoLike.RequiresActive = true

	deepLike := baseSpec("engine-deep-unit")
	deepLike.RequiresDeep = true

	cases := []struct {
		name   string
		spec   Spec
		policy Policy
		ok     bool
		reason string
	}{
		{
			name:   "smuggle without flags",
			spec:   smuggleLike,
			policy: Policy{Flags: Flags{Profile: "standard"}, Enabled: map[string]bool{"smuggle": true}},
			ok:     false,
			reason: "skipped (smuggle-probe requires --active --aggressive)",
		},
		{
			name:   "smuggle with active but not aggressive",
			spec:   smuggleLike,
			policy: Policy{Flags: Flags{Active: true, Profile: "deep"}, Enabled: map[string]bool{"smuggle": true}},
			ok:     false,
			reason: "skipped (smuggle-probe requires --aggressive)",
		},
		{
			name:   "smuggle profile disabled",
			spec:   smuggleLike,
			policy: Policy{Flags: Flags{Active: true, Aggressive: true, Profile: "aggressive"}, Enabled: map[string]bool{}},
			ok:     false,
			reason: "skipped (detector smuggle disabled by profile aggressive)",
		},
		{
			name:   "smuggle enabled",
			spec:   smuggleLike,
			policy: Policy{Flags: Flags{Active: true, Aggressive: true, Profile: "aggressive"}, Enabled: map[string]bool{"smuggle": true}},
			ok:     true,
		},
		{
			name:   "proto without active",
			spec:   protoLike,
			policy: Policy{Flags: Flags{Profile: "standard"}, Enabled: map[string]bool{"ssh": true}},
			ok:     false,
			reason: "skipped (requires --active)",
		},
		{
			name:   "proto profile disabled",
			spec:   protoLike,
			policy: Policy{Flags: Flags{Active: true, Profile: "safe"}, Enabled: map[string]bool{}},
			ok:     false,
			reason: "skipped (detector ssh disabled by profile safe)",
		},
		{
			name:   "deep unit without deep",
			spec:   deepLike,
			policy: Policy{Flags: Flags{Active: true, Profile: "standard"}, Enabled: map[string]bool{}},
			ok:     false,
			reason: "skipped (requires --deep)",
		},
		{
			name:   "unknown profile renders",
			spec:   protoLike,
			policy: Policy{Flags: Flags{Active: true}, Enabled: map[string]bool{}},
			ok:     false,
			reason: "skipped (detector ssh disabled by profile unknown)",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ok, reason := tc.spec.Evaluate(tc.policy)
			if ok != tc.ok {
				t.Fatalf("gate ok=%v want %v", ok, tc.ok)
			}
			if reason != tc.reason {
				t.Fatalf("reason=%q want %q", reason, tc.reason)
			}
		})
	}
}

// TestSpecRequirementRendering proves the declared requirement string.
// What: Canonical flag order for docs and audit reasons.
// Why: The inventory documentation is generated from these fields.
func TestSpecRequirementRendering(t *testing.T) {
	s := baseSpec("engine-combo")
	s.RequiresActive = true
	s.RequiresAggressive = true
	s.RequiresDeep = true
	if got := s.Requirement(); got != "--active --deep --aggressive" {
		t.Fatalf("requirement=%q", got)
	}
	if got := baseSpec("engine-plain").Requirement(); got != "" {
		t.Fatalf("plain detector must declare no requirement, got %q", got)
	}
	if got := baseSpec("engine-plain").ProfileGate(); got != "none" {
		t.Fatalf("profile gate summary=%q", got)
	}
}

// TestPagesForScanSkipsInlineScripts proves the shared page selection rule.
// What: HTML pages plus external JS, never inline scripts.
// Why: Inline scripts are already part of the page body; scanning both would
// duplicate GASH-071/072 findings.
func TestPagesForScanSkipsInlineScripts(t *testing.T) {
	env := &Env{Pages: []Page{
		{URL: "http://t/", Body: []byte("<html>")},
		{URL: "http://t/app.js", Body: []byte("var x=1"), JS: true},
		{URL: "http://t/", Body: []byte("inline"), JS: true, Inline: true},
	}}
	got := env.PagesForScan()
	if len(got) != 2 {
		t.Fatalf("want 2 scannable pages, got %d", len(got))
	}
	for _, p := range got {
		if p.Inline {
			t.Fatal("inline script must not be scanned twice")
		}
	}
	var nilEnv *Env
	if nilEnv.PagesForScan() != nil {
		t.Fatal("nil env must return no pages")
	}
}

// TestLogHelpersAreNilSafe proves detector logging cannot panic.
// What: Detectors run on paths where no logger is wired.
// Why: A nil logger must degrade to silence, not to a scan abort.
func TestLogHelpersAreNilSafe(t *testing.T) {
	var env *Env
	env.LogInfo("no logger")
	env.LogWarn("no logger")
	var seen []string
	withLog := &Env{Log: func(level, msg string) { seen = append(seen, level+":"+msg) }}
	withLog.LogInfo("hello")
	if len(seen) != 1 || !strings.HasPrefix(seen[0], "info:") {
		t.Fatalf("logger not called: %v", seen)
	}
}

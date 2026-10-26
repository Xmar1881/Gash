// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Module: github.com/Xmar1881/Gash
//
// File: internal/detector/policy.go
// What: Gate evaluation for engine-owned detectors (flags plus profile).
// Why: Every engine-owned unit previously repeated its own if-chain and its own
// skip wording, so the audit trail drifted between detectors. One evaluator
// keeps the reason strings canonical, and one place answers "why did this
// detector not run?".

package detector

import (
	"fmt"
	"strings"
)

// Policy is the effective gate input for detector evaluation.
// What: Activation flags plus the profile's enabled detector set.
// Why: Detectors must be gated by exactly the same data the plugin scheduler
// uses, so an engine-owned unit can never run in a profile that forbids it.
type Policy struct {
	// Flags is the effective scan policy.
	Flags Flags
	// Enabled is the profile's enabled detector set (config.ActiveDetectors).
	Enabled map[string]bool
}

// Profile returns the profile name used in skip reasons.
// What: Falls back to "unknown" when the engine reported no profile.
// Why: A skip reason must never end in an empty profile name.
func (p Policy) Profile() string {
	if strings.TrimSpace(p.Flags.Profile) == "" {
		return "unknown"
	}
	return p.Flags.Profile
}

// Requirement renders the flag list the detector needs.
// What: Canonical order "--active --deep --aggressive", empty when unflagged.
// Why: Skip reasons and documentation must quote the identical requirement.
func (s Spec) Requirement() string {
	var parts []string
	if s.RequiresActive {
		parts = append(parts, "--active")
	}
	if s.RequiresDeep {
		parts = append(parts, "--deep")
	}
	if s.RequiresAggressive {
		parts = append(parts, "--aggressive")
	}
	return strings.Join(parts, " ")
}

// unmetFlags lists the declared flag requirements the policy does not satisfy.
// What: Flag check used by Gate and by the registry tests.
// Why: Keeping the check in one function keeps "requires --active --aggressive"
// honest for detectors that need both.
func (s Spec) unmetFlags(f Flags) []string {
	var unmet []string
	if s.RequiresActive && !f.Active {
		unmet = append(unmet, "--active")
	}
	if s.RequiresDeep && !f.Deep {
		unmet = append(unmet, "--deep")
	}
	if s.RequiresAggressive && !f.Aggressive {
		unmet = append(unmet, "--aggressive")
	}
	return unmet
}

// Evaluate reports whether the detector may run and why not.
// What: Flag requirements first, then the profile detector gate.
// Why: The order (and the wording) matches the audit-trail contract the report
// and the contract tests already rely on:
//
//	"skipped (requires --active)"
//	"skipped (smuggle-probe requires --active --aggressive)"
//	"skipped (detector smuggle disabled by profile standard)"
func (s Spec) Evaluate(p Policy) (bool, string) {
	if unmet := s.unmetFlags(p.Flags); len(unmet) > 0 {
		req := strings.Join(unmet, " ")
		if strings.TrimSpace(s.SkipSubject) == "" {
			return false, fmt.Sprintf("skipped (requires %s)", req)
		}
		return false, fmt.Sprintf("skipped (%s requires %s)", s.SkipSubject, req)
	}
	if s.Gate != "" && !p.Enabled[strings.ToLower(s.Gate)] {
		return false, fmt.Sprintf("skipped (detector %s disabled by profile %s)", s.Gate, p.Profile())
	}
	return true, ""
}

// ProfileGate describes the profile requirement in documentation terms.
// What: Human-readable gate summary for inventory and test output.
// Why: New detectors must document why they are gated where they are.
func (s Spec) ProfileGate() string {
	if s.Gate == "" {
		return "none"
	}
	return s.Gate
}

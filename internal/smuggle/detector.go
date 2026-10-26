// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Module: github.com/Xmar1881/Gash
//
// File: internal/smuggle/detector.go
// What: Raw-TCP smuggling probe exposed through the engine detector port.
// Why: GASH-033 cannot live in YAML (net/http is bypassed on purpose) or in the
// JS sandbox (no raw sockets), so it stayed an if-chain inside the engine. The
// port keeps the engine as carrier/budget/decider while this package owns the
// identity, gates, payload table, telemetry key, and skip wording.

package smuggle

import (
	"context"
	"errors"
	"time"

	"github.com/Xmar1881/Gash/internal/detector"
	"github.com/Xmar1881/Gash/internal/plugin"
)

// ScopeViolationReason is the audit-trailed skip when the target is out of
// scope. What: No socket is opened for an out-of-scope host.
// Why: The reason string is asserted by the scan report and the gate tests, so
// it has one definition instead of one per call site.
const ScopeViolationReason = "skipped (smuggle-probe scope violation, no socket opened)"

// Detector adapts the smuggling probe to the engine detector port.
// What: Spec plus a Run that maps the probe result onto the port result.
// Why: One place converts transport outcomes (scope violation, HTTP/2 refusal,
// measured requests) into the engine's uniform finding/counter/skip shape.
type Detector struct{}

// Spec describes the smuggling detector.
// What: Identity, taxonomy, gates, and request budget.
// Why: The registry and the coverage documentation read this struct; nothing
// about the detector may exist only in engine control flow.
func (Detector) Spec() detector.Spec {
	return detector.Spec{
		ID:          PluginID,
		Name:        "HTTP request smuggling (raw-TCP differential)",
		Description: "Sends an ambiguous CL+TE request and an identical follow-up on one keep-alive connection, then compares status/body divergence and follow-up latency against a plain control pair; dual evidence only, ceiling firm.",
		RuleID:      RuleID,
		CWE:         CWE,
		Oracle:      OracleName,
		Severity:    plugin.SeverityHigh,
		Phase:       plugin.PhaseProbe,
		Order:       200,
		Gate:        "smuggle",
		// Invasive: raw bytes on a live connection, aggressive volume.
		RequiresActive:     true,
		RequiresAggressive: true,
		SkipSubject:        "smuggle-probe",
		MaxRequests:        MaxProbes,
		Docs:               "docs/metrics/smuggle-differential.md",
		DetectorVersion:    DetectorVersion,
	}
}

// Run executes the smuggling probe under the engine's policy envelope.
// What: Builds transport options from the brokered environment.
// Why: The detector must never invent its own policy: scope and activation come
// from the env, so a scan flag can never be bypassed by detector code.
func (Detector) Run(ctx context.Context, env *detector.Env) (detector.Result, error) {
	if env == nil {
		return detector.Result{}, errors.New("smuggle: nil detector env")
	}
	var allow AllowHost
	if env.Scope != nil {
		allow = AllowHost(env.Scope)
	}
	res, err := Scan(ctx, env.Target, Options{
		Timeout:    5 * time.Second,
		Allow:      allow,
		Active:     env.Flags.Active,
		Aggressive: env.Flags.Aggressive,
	})
	if err != nil {
		if errors.Is(err, plugin.ErrScopeViolation) {
			// Fail-closed: no socket was opened, so this is an audited skip,
			// not a detector failure.
			env.LogWarn("smuggle: target out of scope, no socket opened")
			return detector.Result{Skips: []plugin.SkippedPlugin{{PluginID: PluginID, Reason: ScopeViolationReason}}}, nil
		}
		return detector.Result{}, err
	}
	if res == nil {
		return detector.Result{}, nil
	}
	out := detector.Result{
		Stats:    map[string]int{"smuggle_requests": res.Requests},
		Requests: res.Requests,
	}
	if res.Skipped != "" {
		out.Skips = append(out.Skips, plugin.SkippedPlugin{PluginID: PluginID, Reason: res.Skipped})
	}
	if res.Finding != nil {
		out.Findings = append(out.Findings, res.Finding)
	}
	return out, nil
}

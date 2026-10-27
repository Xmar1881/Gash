// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Module: github.com/Xmar1881/Gash
//
// File: internal/discovery/detector.go
// What: Wordlist content discovery exposed through the engine detector port.
// Why: GASH-028 stayed an engine if-chain with its identity, budget, and stat
// keys hardcoded in scan_exec.go. The port puts the identity next to the
// detector, and the wordlists were already data (wordlists/*.txt).

package discovery

import (
	"context"

	"github.com/Xmar1881/Gash/internal/detector"
	"github.com/Xmar1881/Gash/internal/plugin"
)

// ContentDetector exposes wordlist content discovery to the engine.
// What: GASH-028 detector over the shared PolicySession probe client.
// Why: Discovery is invasive (many requests), so it declares --active and a
// request ceiling instead of relying on the engine to remember them.
type ContentDetector struct{}

// Spec describes the content-discovery detector.
// What: Identity, taxonomy, phase, and the --active requirement.
// Why: The profile gate is intentionally empty because discovery is driven by
// --active today; naming that explicitly keeps the gate auditable.
func (ContentDetector) Spec() detector.Spec {
	return detector.Spec{
		ID:              PluginIDContentDiscovery,
		Name:            "Wordlist content discovery",
		Description:     "Technology-pinned wordlist probing on the shared policy session; soft-404 baseline plus a deterministic content signal produces GASH-028 exposed-path findings and feeds discovered paths back to the scan surface.",
		RuleID:          RuleIDExposedPath,
		CWE:             CWEExposedPath,
		Oracle:          OracleContentExposure,
		Severity:        plugin.SeverityMedium,
		Phase:           plugin.PhaseDiscovery,
		Order:           30,
		RequiresActive:  true,
		MaxRequests:     80,
		Docs:            "docs/metrics/content-discovery-2026-10-16.md",
		DetectorVersion: DetectorVersionContentDiscovery,
	}
}

// Run probes the wordlists and returns findings, counters, and paths.
// What: Thin adapter over DiscoverContent with the env's tech fingerprint.
// Why: The detector owns its probing; the engine keeps the follow-up crawl
// decision for the paths it reports (surface orchestration stays in the engine).
func (ContentDetector) Run(ctx context.Context, env *detector.Env) (detector.Result, error) {
	if env == nil || env.Probe == nil {
		return detector.Result{}, nil
	}
	fpTech := TechFingerprint{Capabilities: map[string]bool{}}
	fpTech.Tech = append(fpTech.Tech, env.Tech...)
	opts := DefaultContentOptions()
	if env.Progress != nil {
		opts.OnProgress = env.Progress
	}
	res, err := DiscoverContent(ctx, env.Probe, env.Target, fpTech, nil, opts)
	if err != nil {
		return detector.Result{}, err
	}
	if res == nil {
		return detector.Result{}, nil
	}
	budget := 0
	if res.BudgetExhausted {
		budget = 1
	}
	return detector.Result{
		Findings: res.Findings,
		Stats: map[string]int{
			"content_requests":         res.Requests,
			"content_findings":         len(res.Findings),
			"content_budget_exhausted": budget,
		},
		Requests: res.Requests,
		Paths:    res.DiscoveredPaths,
	}, nil
}

// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Module: github.com/Xmar1881/Gash
//
// File: internal/recon/recon.go
// What: Byte-analysis recon detectors: GASH-071 (secrets in framework-embedded
// state) and GASH-072 (development build artifacts).
// Why: Both are deterministic content observations on bytes the crawler already
// fetched, so they need neither a plugin fixture spec nor extra requests. They
// used to be unexported functions inside the engine; they now implement the
// detector port so their identity, rule mapping, gates, and stat keys are data
// instead of engine control flow.

package recon

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/http"
	"sort"
	"strings"

	"github.com/Xmar1881/Gash/internal/detector"
	"github.com/Xmar1881/Gash/internal/discovery"
	"github.com/Xmar1881/Gash/internal/finding"
	"github.com/Xmar1881/Gash/internal/plugin"
)

const (
	// RuleIDSPAState is the embedded SPA state secret rule (GASH-068 used by
	// multi-step flow; 069/070 belong to the Next.js plugins).
	RuleIDSPAState = "GASH-071"
	// CWESPAStateCredential is hardcoded credential exposure in state.
	CWESPAStateCredential = "CWE-798"
	// CWESPAStateExposure is token/session data exposure in state.
	CWESPAStateExposure = "CWE-200"
	// PluginIDSPAState is the PolicySession identity (GET/static only).
	PluginIDSPAState = "engine-spa-state"
	// OracleSPAState names the deterministic content observation.
	OracleSPAState = "embedded-state-secret"
	// DetectorVersionSPAState is the detector version for traceability.
	DetectorVersionSPAState = "1.0.0"

	// RuleIDDevBuild is the development build artifact rule.
	RuleIDDevBuild = "GASH-072"
	// CWEDevBuild is exposure of debug/development artifacts.
	CWEDevBuild = "CWE-489"
	// PluginIDDevBuild is the PolicySession identity (GET/static only).
	PluginIDDevBuild = "engine-devbuild"
	// OracleDevBuild names the deterministic content observation.
	OracleDevBuild = "dev-build-marker"
	// DetectorVersionDevBuild is the detector version for traceability.
	DetectorVersionDevBuild = "1.0.0"
)

// SPAState finds secrets in framework-embedded state.
// What: GASH-071 detector over already-fetched page and external JS bodies.
// Why: Serialized state (__NEXT_DATA__, __INITIAL_STATE__) leaks credentials
// without any injection; the observation is deterministic, so the ceiling is
// static-execution-evidence, never confirmed.
type SPAState struct{}

// Spec describes the embedded-state detector.
// What: Identity, taxonomy, and phase; no flag or profile gate.
// Why: The scan runs it whenever the crawler produced bodies, exactly like
// before the port existed.
func (SPAState) Spec() detector.Spec {
	return detector.Spec{
		ID:              PluginIDSPAState,
		Name:            "Secrets in SPA embedded state",
		Description:     "Deterministic pass over already-fetched page and external JS bodies for framework-serialized state containing credentials or session tokens; values are masked in the report.",
		RuleID:          RuleIDSPAState,
		CWE:             CWESPAStateCredential,
		Oracle:          OracleSPAState,
		Severity:        plugin.SeverityHigh,
		Phase:           plugin.PhaseDiscovery,
		Order:           10,
		Docs:            "docs/detector-inventory.md",
		DetectorVersion: DetectorVersionSPAState,
	}
}

// Run scans the crawler-provided bodies.
// What: One pass, no requests.
// Why: The crawl is the only owner of fetched bytes; a re-fetch would duplicate
// work and could observe different content than the pages plugins were given.
func (SPAState) Run(ctx context.Context, env *detector.Env) (detector.Result, error) {
	findings, stats := ScanSPAState(ctx, env.PagesForScan())
	return detector.Result{Findings: findings, Stats: stats}, nil
}

// DevBuild finds genuinely development-only build artifacts.
// What: GASH-072 detector over already-fetched page and external JS bodies.
// Why: Debug builds widen the attack surface (devtools hooks, unminified
// internals); one aggregated finding per source keeps the report readable.
type DevBuild struct{}

// Spec describes the dev-build detector.
// What: Identity, taxonomy, and phase; no flag or profile gate.
// Why: Same "runs whenever the crawler produced bodies" contract as GASH-071.
func (DevBuild) Spec() detector.Spec {
	return detector.Spec{
		ID:              PluginIDDevBuild,
		Name:            "Development build artifacts served",
		Description:     "Deterministic marker scan of already-fetched page and external JS bodies for development-only build artifacts (dev framework bundles, devtools hooks); env-gated markers and generic warnings are deliberately excluded.",
		RuleID:          RuleIDDevBuild,
		CWE:             CWEDevBuild,
		Oracle:          OracleDevBuild,
		Severity:        plugin.SeverityLow,
		Phase:           plugin.PhaseDiscovery,
		Order:           20,
		Docs:            "docs/detector-inventory.md",
		DetectorVersion: DetectorVersionDevBuild,
	}
}

// Run scans the crawler-provided bodies.
// What: One pass, no requests.
// Why: Identical discipline to GASH-071: observe exactly the bytes the crawl
// already paid for.
func (DevBuild) Run(ctx context.Context, env *detector.Env) (detector.Result, error) {
	findings, stats := ScanDevBuild(ctx, env.PagesForScan())
	return detector.Result{Findings: findings, Stats: stats}, nil
}

// ScanSPAState finds secrets in framework-embedded state on page and JS bodies.
// What: One deterministic pass over the given pages plus external JS sources;
// inline sources are skipped because they are already part of page bodies.
// Why: Exported so the engine parity test can assert the exact same findings
// the detector produces, and so the rule's unit tests stay next to the rule.
func ScanSPAState(ctx context.Context, pages []detector.Page) ([]*finding.Finding, map[string]int) {
	stats := map[string]int{"spa_state_pages": 0, "spa_state_secrets": 0}
	var out []*finding.Finding
	scanPages(ctx, pages, func(p detector.Page, countPage bool) {
		rep := discovery.AnalyzeSPAState(p.Body, p.URL)
		if countPage && len(rep.Containers) > 0 {
			stats["spa_state_pages"]++
		}
		for _, s := range rep.Secrets {
			out = append(out, buildSPAStateFinding(s))
		}
	})
	stats["spa_state_secrets"] = len(out)
	return out, stats
}

// ScanDevBuild finds genuinely development-only build artifacts.
// What: One aggregated finding per fetched page/asset, with all marker names.
// Why: Numeric marker count in stats reflects distinct marker hits, while a
// single finding per source keeps the report readable.
func ScanDevBuild(ctx context.Context, pages []detector.Page) ([]*finding.Finding, map[string]int) {
	stats := map[string]int{"devbuild_markers": 0}
	var out []*finding.Finding
	scanPages(ctx, pages, func(p detector.Page, _ bool) {
		markers := discovery.DetectDevBuildMarkers(p.Body)
		if len(markers) == 0 {
			return
		}
		stats["devbuild_markers"] += len(markers)
		out = append(out, buildDevBuildFinding(p.URL, markers))
	})
	return out, stats
}

// scanPages visits every scannable page once, in order.
// What: Shared URL-dedup plus cancellation check.
// Why: Both detectors must agree on what "one source" means, and neither may
// keep working after the scan context is cancelled.
func scanPages(ctx context.Context, pages []detector.Page, fn func(p detector.Page, countPage bool)) {
	seen := make(map[string]bool, len(pages))
	for _, p := range pages {
		if ctx != nil && ctx.Err() != nil {
			return
		}
		if p.URL == "" || len(p.Body) == 0 || p.Inline || seen[p.URL] {
			continue
		}
		seen[p.URL] = true
		fn(p, !p.JS)
	}
}

// buildSPAStateFinding builds one masked GASH-071 finding.
func buildSPAStateFinding(s discovery.SPAStateSecret) *finding.Finding {
	cwe := CWESPAStateCredential
	if s.Secret.Type == "jwt" {
		cwe = CWESPAStateExposure
	}
	evidence := map[string]string{
		"page_url":     s.Secret.Location,
		"framework":    s.Framework,
		"container":    s.Container,
		"secret_type":  s.Secret.Type,
		"masked_value": s.Secret.Masked,
		"note":         "full value intentionally not reported (masked first4...last4); remove the value from serialized state and rotate the credential",
	}
	if s.Secret.VarName != "" {
		evidence["var_name"] = s.Secret.VarName
	}
	if s.Secret.Context != "" {
		evidence["context"] = s.Secret.Context
	}
	f := &finding.Finding{
		ID:          newContentFindingID("spa"),
		RuleID:      RuleIDSPAState,
		CWE:         cwe,
		Title:       "Secret in SPA embedded state: " + s.Secret.Type,
		Description: fmt.Sprintf("%s state (%s) serialized into %s contains a %s match; values are masked in this report", s.Framework, s.Container, s.Secret.Location, s.Secret.Type),
		Severity:    s.Secret.Severity,
		Confidence:  plugin.ConfidenceStaticExecution,
		Target:      s.Secret.Location,
		InjectionPoint: plugin.InjectionPoint{
			URL:           s.Secret.Location,
			Method:        http.MethodGet,
			ParamLocation: "path",
		},
		Evidence: evidence,
		Reproducibility: map[string]string{
			"repeats": "1",
			"control": "not-applicable (static page/asset observation)",
			"note":    "state container observed in fetched bytes; no request replay or credential validation",
		},
		PluginID:           PluginIDSPAState,
		OracleName:         OracleSPAState,
		Tags:               []string{"recon", "secrets", "spa", "embedded-state", s.Framework},
		Method:             http.MethodGet,
		VerificationMethod: "static embedded-state scan (rule " + s.Secret.RuleName + "), repeats=1, no live credential check",
		Note:               "static-execution-evidence ceiling: literal observed in serialized state, not a validated live credential",
		DetectorVersion:    DetectorVersionSPAState,
		Masked:             []string{"masked_value", "context"},
	}
	f.Fingerprint = finding.Fingerprint(f)
	return f
}

// buildDevBuildFinding aggregates markers for one source into one finding.
func buildDevBuildFinding(url string, markers []discovery.DevBuildMarker) *finding.Finding {
	frameworkSet := make(map[string]bool)
	markerSet := make(map[string]bool)
	var names, frameworks []string
	var snippets []string
	for _, m := range markers {
		if !markerSet[m.Marker] {
			markerSet[m.Marker] = true
			names = append(names, m.Marker)
		}
		if !frameworkSet[m.Framework] {
			frameworkSet[m.Framework] = true
			frameworks = append(frameworks, m.Framework)
		}
		if len(snippets) < 3 && m.Snippet != "" {
			snippets = append(snippets, m.Snippet)
		}
	}
	sort.Strings(frameworks)
	sort.Strings(names)
	snippet := strings.Join(snippets, " | ")
	if len(snippet) > 320 {
		snippet = snippet[:320]
	}
	f := &finding.Finding{
		ID:          newContentFindingID("devbuild"),
		RuleID:      RuleIDDevBuild,
		CWE:         CWEDevBuild,
		Title:       "Development build artifacts served",
		Description: fmt.Sprintf("development-only %s markers are present in %s (%s); debug builds often expose internals and disable production optimizations", strings.Join(frameworks, "/"), url, strings.Join(names, ", ")),
		Severity:    plugin.SeverityLow,
		Confidence:  plugin.ConfidenceFirm,
		Target:      url,
		InjectionPoint: plugin.InjectionPoint{
			URL:           url,
			Method:        http.MethodGet,
			ParamLocation: "path",
		},
		Evidence: map[string]string{
			"location":  url,
			"framework": strings.Join(frameworks, ","),
			"markers":   strings.Join(names, ","),
			"snippet":   snippet,
			"note":      "development-only artifact observed in fetched bytes; devtools hooks and generic warnings are deliberately not markers",
		},
		Reproducibility: map[string]string{
			"repeats": "1",
			"control": "not-applicable (static page/asset observation)",
			"note":    "marker observed in fetched bytes; deployment configuration should be reviewed",
		},
		PluginID:           PluginIDDevBuild,
		OracleName:         OracleDevBuild,
		Tags:               append([]string{"recon", "dev-build", "debug"}, frameworks...),
		Method:             http.MethodGet,
		VerificationMethod: "static build-artifact marker scan, repeats=1, no request replay",
		Note:               "firm ceiling: development-only artifact observed, exploitability not assessed",
		DetectorVersion:    DetectorVersionDevBuild,
		Masked:             []string{"snippet"},
	}
	f.Fingerprint = finding.Fingerprint(f)
	return f
}

// newContentFindingID generates a deterministic-prefix random finding ID.
// What: Per-finding identity for engine-recon output.
// Why: Findings must be individually addressable in SARIF/JSON without
// re-deriving identity from the evidence map.
func newContentFindingID(prefix string) string {
	var b [6]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "finding_" + prefix + "_fallback"
	}
	return "finding_" + prefix + "_" + hex.EncodeToString(b[:])
}

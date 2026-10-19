// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Module: github.com/Xmar1881/Gash
//
// File: internal/engine/embedded_state.go
// What: Engine-owned GASH-071 (SPA embedded-state secrets) and GASH-072
// (development build artifacts) scans over already-crawled bodies.
// Why: Both are deterministic content observations on bytes the crawler
// already fetched; they need no extra requests, no plugin, and no validator.
// Values are masked and evidence is bounded exactly like GASH-067.

package engine

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/http"
	"sort"
	"strings"

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

// scanSPAState finds secrets in framework-embedded state on page and JS bodies.
// What: One deterministic pass over CrawlResult pages plus external JS sources;
// page inline sources are skipped because they are already part of page bodies.
// Why: The crawl is the only owner of fetched bytes; this scan makes no
// requests and reports masked evidence only.
func scanSPAState(crawl *discovery.CrawlResult) ([]*finding.Finding, map[string]int) {
	stats := map[string]int{"spa_state_pages": 0, "spa_state_secrets": 0}
	if crawl == nil {
		return nil, stats
	}
	var out []*finding.Finding
	seenSources := make(map[string]bool)
	scan := func(url string, body []byte, countPage bool) {
		if url == "" || len(body) == 0 || seenSources[url] {
			return
		}
		seenSources[url] = true
		rep := discovery.AnalyzeSPAState(body, url)
		if countPage && len(rep.Containers) > 0 {
			stats["spa_state_pages"]++
		}
		for _, s := range rep.Secrets {
			out = append(out, buildSPAStateFinding(s))
		}
	}
	for _, page := range crawl.Pages {
		scan(page.URL, page.Body, true)
	}
	for _, src := range crawl.JSSources {
		if src.Inline {
			continue
		}
		scan(src.URL, src.Body, false)
	}
	stats["spa_state_secrets"] = len(out)
	return out, stats
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

// scanDevBuild finds genuinely development-only build artifacts.
// What: One aggregated finding per fetched page/asset, with all marker names.
// Why: Numeric marker count in stats reflects distinct marker hits, while a
// single finding per source keeps the report readable.
func scanDevBuild(crawl *discovery.CrawlResult) ([]*finding.Finding, map[string]int) {
	stats := map[string]int{"devbuild_markers": 0}
	if crawl == nil {
		return nil, stats
	}
	var out []*finding.Finding
	seenSources := make(map[string]bool)
	scan := func(url string, body []byte) {
		if url == "" || len(body) == 0 || seenSources[url] {
			return
		}
		seenSources[url] = true
		markers := discovery.DetectDevBuildMarkers(body)
		if len(markers) == 0 {
			return
		}
		stats["devbuild_markers"] += len(markers)
		out = append(out, buildDevBuildFinding(url, markers))
	}
	for _, page := range crawl.Pages {
		scan(page.URL, page.Body)
	}
	for _, src := range crawl.JSSources {
		if src.Inline {
			continue
		}
		scan(src.URL, src.Body)
	}
	return out, stats
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
func newContentFindingID(prefix string) string {
	var b [6]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "finding_" + prefix + "_fallback"
	}
	return "finding_" + prefix + "_" + hex.EncodeToString(b[:])
}

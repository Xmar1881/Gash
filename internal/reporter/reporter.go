// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Modül: github.com/Xmar1881/Gash

// Package reporter json/sarif/text/html üretir (A-20). SARIF birincil sözleşmedir.
package reporter

import (
	"encoding/json"
	"fmt"
	"html"
	"io"
	"sort"
	"strings"

	"github.com/Xmar1881/Gash/internal/engine"
	"github.com/Xmar1881/Gash/internal/finding"
	"github.com/Xmar1881/Gash/internal/plugin"
)

// Options rapor politikasıdır (tentative/suppress).
type Options struct {
	ShowTentative bool
	Suppressed    map[string]bool // fingerprint → bastırılmış
	Target        string
}

// filter tentative + suppress uygular.
func filter(rep *engine.Report, opts Options) (visible []*findingView, suppressed int) {
	for _, f := range rep.Findings {
		if f.Confidence == plugin.ConfidenceTentative && !opts.ShowTentative {
			continue
		}
		if opts.Suppressed[f.Fingerprint] {
			suppressed++
			continue
		}
		visible = append(visible, &findingView{
			ID: f.ID, RuleID: f.RuleID, CWE: f.CWE, Title: f.Title,
			Severity: string(f.Severity), Confidence: string(f.Confidence),
			Target: f.Target, PluginID: f.PluginID, Fingerprint: f.Fingerprint,
			EvidenceType: evidenceTypeFor(f), Evidence: f.Evidence,
		})
	}
	sort.Slice(visible, func(i, j int) bool {
		if visible[i].RuleID != visible[j].RuleID {
			return visible[i].RuleID < visible[j].RuleID
		}
		return visible[i].Fingerprint < visible[j].Fingerprint
	})
	return visible, suppressed
}

type findingView struct {
	ID          string `json:"id"`
	RuleID      string `json:"rule_id"`
	CWE         string `json:"cwe,omitempty"`
	Title       string `json:"title"`
	Severity    string `json:"severity"`
	Confidence  string `json:"confidence"`
	Target      string `json:"target"`
	PluginID    string `json:"plugin_id"`
	Fingerprint string `json:"fingerprint"`
	// EvidenceType is the §8 evidence discriminator: static-execution-evidence
	// for parser-recognized payloads without a browser run, browser-confirmed
	// only after a controlled headless execution, otherwise the confidence.
	EvidenceType string            `json:"evidence_type,omitempty"`
	Evidence     map[string]string `json:"evidence,omitempty"`
}

// evidenceTypeFor derives the report-level evidence discriminator from the
// stored artifacts. The execution artifact is authoritative when present:
// "static" maps to static-execution-evidence, "browser-confirmed" stays as is.
func evidenceTypeFor(f *finding.Finding) string {
	if f == nil {
		return ""
	}
	if f.Evidence != nil {
		switch f.Evidence["execution"] {
		case "static":
			return "static-execution-evidence"
		case "browser-confirmed":
			return "browser-confirmed"
		}
	}
	return string(f.Confidence)
}

// WriteJSON tam Finding[] + scan_meta + skipped + stats (deterministik sıralı).
func WriteJSON(w io.Writer, rep *engine.Report, opts Options) error {
	vis, supp := filter(rep, opts)
	out := map[string]any{
		"target":     rep.Target,
		"findings":   vis,
		"skipped":    rep.Skipped,
		"suppressed": supp,
		"stats":      rep.Stats,
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(true)
	if err := enc.Encode(out); err != nil {
		return fmt.Errorf("reporter json: %w", err)
	}
	return nil
}

// WriteText insan-okunur terminal çıktısıdır (tentative gizli).
func WriteText(w io.Writer, rep *engine.Report, opts Options) error {
	vis, supp := filter(rep, opts)
	if _, err := fmt.Fprintf(w, "GASH scan: %s — %d findings (%d suppressed)\n", rep.Target, len(vis), supp); err != nil {
		return fmt.Errorf("reporter text: %w", err)
	}
	for _, f := range vis {
		if _, err := fmt.Fprintf(w, "- [%s/%s] %s (%s) %s\n", f.Severity, f.Confidence, f.Title, f.RuleID, f.Target); err != nil {
			return fmt.Errorf("reporter text: %w", err)
		}
	}
	// Kanıt disiplini: "koşmadı" (skipped) ile "bütçesine takıldı, yarım kaldı"
	// (partial) ayrı raporlanır; ikisi aynı listede karışmaz.
	var partials, rest, failures []plugin.SkippedPlugin
	var notApplicable []plugin.SkippedPlugin
	for _, s := range rep.Skipped {
		if s.Partial {
			partials = append(partials, s)
			continue
		}
		if notApplicableReason(s.Reason) {
			notApplicable = append(notApplicable, s)
			continue
		}
		if errorReason(s.Reason) {
			failures = append(failures, s)
			continue
		}
		rest = append(rest, s)
	}
	if len(notApplicable) > 0 {
		if _, err := fmt.Fprintf(w, "not applicable (configuration/profile): %d\n", len(notApplicable)); err != nil {
			return fmt.Errorf("reporter text: %w", err)
		}
		printSkippedDetails(w, notApplicable)
	}
	if len(failures) > 0 {
		if _, err := fmt.Fprintf(w, "runtime errors: %d%s\n", len(failures), errorSummary(failures)); err != nil {
			return fmt.Errorf("reporter text: %w", err)
		}
		printSkippedDetails(w, failures)
	}
	if len(rest) > 0 {
		if _, err := fmt.Fprintf(w, "not completed (deadline/limit): %d%s\n", len(rest), skipSummary(rest)); err != nil {
			return fmt.Errorf("reporter text: %w", err)
		}
		printSkippedDetails(w, rest)
	}
	if len(partials) > 0 {
		if _, err := fmt.Fprintf(w, "partial plugins (request budget/rate ceiling reached): %d\n", len(partials)); err != nil {
			return fmt.Errorf("reporter text: %w", err)
		}
		printSkippedDetails(w, partials)
	}
	return nil
}

func printSkippedDetails(w io.Writer, skips []plugin.SkippedPlugin) {
	const detailCap = 20
	for i, s := range skips {
		if i >= detailCap {
			_, _ = fmt.Fprintf(w, "  ... and %d more (see JSON report)\n", len(skips)-detailCap)
			return
		}
		_, _ = fmt.Fprintf(w, "  - %s: %s\n", s.PluginID, displayReason(s.Reason))
	}
}

// displayReason strips the internal "skipped (...)" wrapper from the text
// report; JSON keeps the full auditable reason.
func displayReason(reason string) string {
	const prefix = "skipped ("
	if strings.HasPrefix(reason, prefix) && strings.HasSuffix(reason, ")") {
		return reason[len(prefix) : len(reason)-1]
	}
	return reason
}

// errorReason separates runtime failures from configuration exclusions and
// genuine skips in the text report.
func errorReason(reason string) bool {
	r := strings.ToLower(reason)
	if strings.HasPrefix(r, "error (") || strings.Contains(r, "render error:") {
		return true
	}
	for _, marker := range []string{"panic:", "tls: failed", "context deadline exceeded while"} {
		if strings.Contains(r, marker) {
			return true
		}
	}
	return false
}

func errorSummary(errs []plugin.SkippedPlugin) string {
	counts := map[string]int{}
	for _, s := range errs {
		r := strings.ToLower(s.Reason)
		switch {
		case strings.Contains(r, "timeout"):
			counts["timeout"]++
		case strings.Contains(r, "tls"), strings.Contains(r, "certificate"):
			counts["tls"]++
		case strings.Contains(r, "proxyconnect"), strings.Contains(r, "proxy connect"):
			counts["proxy"]++
		case strings.Contains(r, "policy violation"), strings.Contains(r, "scope"),
			strings.Contains(r, "budget"), strings.Contains(r, "rate limit"),
			strings.Contains(r, "rate-limited"), strings.Contains(r, "backpressure"):
			counts["limit"]++
		case strings.Contains(r, "connection refused"), strings.Contains(r, "dial tcp"),
			strings.Contains(r, "no such host"), strings.Contains(r, "connection reset"),
			strings.Contains(r, "network is unreachable"):
			counts["network"]++
		default:
			counts["other"]++
		}
	}
	var parts []string
	for _, key := range []string{"timeout", "tls", "proxy", "limit", "network", "other"} {
		if counts[key] > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", counts[key], key))
		}
	}
	if len(parts) == 0 {
		return ""
	}
	return " (" + strings.Join(parts, ", ") + ")"
}

// notApplicableReason separates configuration/profile exclusions from real
// skips (timeouts, deadlines, errors) in the text report.
func notApplicableReason(reason string) bool {
	r := strings.ToLower(reason)
	for _, marker := range []string{
		"requires --active", "requires --deep", "requires auth",
		"oob-not-configured", "tier3-untrusted", "requires trust",
		"disabled by profile", "smuggle-probe requires",
	} {
		if strings.Contains(r, marker) {
			return true
		}
	}
	return false
}

// skipSummary groups skip reasons so a 300-plugin report says why the plugins
// did not run instead of only listing them.
func skipSummary(skips []plugin.SkippedPlugin) string {
	counts := map[string]int{}
	for _, s := range skips {
		r := strings.ToLower(s.Reason)
		switch {
		case strings.Contains(r, "deadline exceeded"):
			counts["scan deadline"]++
		case strings.Contains(r, "requires auth"):
			counts["requires auth"]++
		case strings.Contains(r, "tier3-untrusted"):
			counts["tier3-untrusted"]++
		case strings.Contains(r, "scan context"):
			counts["scan context"]++
		default:
			counts["other"]++
		}
	}
	var parts []string
	for _, key := range []string{"scan deadline", "requires auth", "tier3-untrusted", "scan context", "other"} {
		if counts[key] > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", counts[key], key))
		}
	}
	if len(parts) == 0 {
		return ""
	}
	return " (" + strings.Join(parts, ", ") + ")"
}

// WriteSARIF SARIF v2.1.0 minimal-geçerli çıktıdır (CI kapısı).
// Eşleme: confirmed→error, firm→warning, tentative→note (yalnızca --show-tentative).
func WriteSARIF(w io.Writer, rep *engine.Report, opts Options) error {
	vis, _ := filter(rep, opts)
	type sarifRule struct {
		ID               string `json:"id"`
		Name             string `json:"name"`
		ShortDescription struct {
			Text string `json:"text"`
		} `json:"shortDescription"`
	}
	type sarifResult struct {
		RuleID    string `json:"ruleId"`
		RuleIndex int    `json:"ruleIndex"`
		Level     string `json:"level"`
		Message   struct {
			Text string `json:"text"`
		} `json:"message"`
		Locations    []any             `json:"locations"`
		Fingerprints map[string]string `json:"fingerprints,omitempty"`
		Properties   map[string]string `json:"properties,omitempty"`
	}
	ruleIdx := make(map[string]int)
	var rules []sarifRule
	var results []sarifResult
	for _, f := range vis {
		idx, ok := ruleIdx[f.RuleID]
		if !ok {
			idx = len(rules)
			ruleIdx[f.RuleID] = idx
			r := sarifRule{ID: f.RuleID, Name: f.Title}
			r.ShortDescription.Text = f.Title
			rules = append(rules, r)
		}
		level := ""
		switch f.Confidence {
		case string(plugin.ConfidenceConfirmed):
			level = "error"
		case string(plugin.ConfidenceFirm):
			level = "warning"
		default:
			level = "note"
		}
		res := sarifResult{RuleID: f.RuleID, RuleIndex: idx, Level: level}
		res.Message.Text = fmt.Sprintf("%s [%s] (%s)", f.Title, f.Fingerprint, f.EvidenceType)
		res.Locations = []any{map[string]any{"physicalLocation": map[string]any{"artifactLocation": map[string]any{"uri": f.Target}}}}
		res.Fingerprints = map[string]string{"gash/v1": f.Fingerprint}
		res.Properties = map[string]string{"evidenceType": f.EvidenceType, "confidence": f.Confidence}
		results = append(results, res)
	}
	if results == nil {
		results = []sarifResult{}
	}
	if rules == nil {
		rules = []sarifRule{}
	}
	doc := map[string]any{
		"$schema": "https://json.schemastore.org/sarif-2.1.0.json",
		"version": "2.1.0",
		"runs": []any{map[string]any{
			"tool":    map[string]any{"driver": map[string]any{"name": "gash", "rules": rules}},
			"results": results,
		}},
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(doc); err != nil {
		return fmt.Errorf("reporter sarif: %w", err)
	}
	return nil
}

// WriteHTML tek-dosya inline-CSS paydaş raporudur (PII-redact'li evidence özeti).
func WriteHTML(w io.Writer, rep *engine.Report, opts Options) error {
	vis, supp := filter(rep, opts)
	var sb strings.Builder
	sb.WriteString("<!doctype html><html><head><meta charset=\"utf-8\"><title>Gash report</title>")
	sb.WriteString("<style>body{font-family:sans-serif;margin:2em}table{border-collapse:collapse}td,th{border:1px solid #ccc;padding:.4em}</style></head><body>")
	sb.WriteString("<h1>Gash report</h1>")
	sb.WriteString("<p>Target: " + html.EscapeString(rep.Target) + "</p>")
	_, _ = fmt.Fprintf(&sb, "<p>%d findings (%d suppressed)</p>", len(vis), supp)
	sb.WriteString("<table><tr><th>Severity</th><th>Confidence</th><th>Title</th><th>Rule</th><th>Target</th></tr>")
	for _, f := range vis {
		sb.WriteString("<tr><td>" + html.EscapeString(f.Severity) + "</td><td>" + html.EscapeString(f.Confidence) +
			"</td><td>" + html.EscapeString(f.Title) + "</td><td>" + html.EscapeString(f.RuleID) +
			"</td><td>" + html.EscapeString(f.Target) + "</td></tr>")
	}
	sb.WriteString("</table></body></html>")
	if _, err := io.WriteString(w, sb.String()); err != nil {
		return fmt.Errorf("reporter html: %w", err)
	}
	return nil
}

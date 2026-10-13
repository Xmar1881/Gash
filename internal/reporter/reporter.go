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
	if len(rep.Skipped) > 0 {
		if _, err := fmt.Fprintf(w, "skipped plugins: %d\n", len(rep.Skipped)); err != nil {
			return fmt.Errorf("reporter text: %w", err)
		}
		for _, s := range rep.Skipped {
			if _, err := fmt.Fprintf(w, "  - %s: %s\n", s.PluginID, s.Reason); err != nil {
				return fmt.Errorf("reporter text: %w", err)
			}
		}
	}
	return nil
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
		level := "warning"
		switch f.Confidence {
		case string(plugin.ConfidenceConfirmed):
			level = "error"
		case string(plugin.ConfidenceFirm):
			level = "warning"
		default:
			level = "note"
		}
		res := sarifResult{RuleID: f.RuleID, RuleIndex: idx, Level: level}
		res.Message.Text = fmt.Sprintf("%s [%s]", f.Title, f.Fingerprint)
		res.Locations = []any{map[string]any{"physicalLocation": map[string]any{"artifactLocation": map[string]any{"uri": f.Target}}}}
		res.Fingerprints = map[string]string{"gash/v1": f.Fingerprint}
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
	sb.WriteString("<!doctype html><html><head><meta charset=\"utf-8\"><title>GASH report</title>")
	sb.WriteString("<style>body{font-family:sans-serif;margin:2em}table{border-collapse:collapse}td,th{border:1px solid #ccc;padding:.4em}</style></head><body>")
	sb.WriteString("<h1>GASH report</h1>")
	sb.WriteString("<p>Target: " + html.EscapeString(rep.Target) + "</p>")
	sb.WriteString(fmt.Sprintf("<p>%d findings (%d suppressed)</p>", len(vis), supp))
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

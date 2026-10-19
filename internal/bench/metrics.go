// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Module: github.com/Xmar1881/Gash

package bench

import (
	"sort"
	"strings"
)

// Score aggregates scenario-level binary classification for one tool.
type Score struct {
	TP         int      `json:"tp"`
	FP         int      `json:"fp"`
	TN         int      `json:"tn"`
	FN         int      `json:"fn"`
	Weak       int      `json:"weak_evidence"`
	Unverified int      `json:"unverified"`
	NotRun     int      `json:"not_run"`
	Confirmed  int      `json:"confirmed_tp"`
	Precision  *float64 `json:"precision"`
	Recall     *float64 `json:"recall"`
	F1         *float64 `json:"f1"`
}

// Outcome is the scored result of one scenario under one tool.
type Outcome struct {
	Scenario     string       `json:"scenario"`
	Category     string       `json:"category"`
	Subcategory  string       `json:"subcategory,omitempty"`
	Expected     string       `json:"expected"`
	Status       string       `json:"status"`
	Detectors    []string     `json:"detectors,omitempty"`
	EvidenceType string       `json:"evidence_type,omitempty"`
	Verification Verification `json:"verification"`
	Notes        []string     `json:"notes,omitempty"`
}

// CrossRow compares both tools on one verified scenario.
type CrossRow struct {
	Scenario string `json:"scenario"`
	Category string `json:"category"`
	Expected string `json:"expected"`
	Gash     string `json:"gash"`
	Nuclei   string `json:"nuclei,omitempty"`
	Verdict  string `json:"verdict"`
}

func scenarioPath(sc *Scenario) string {
	raw := sc.Path
	if raw == "" {
		raw = sc.URL
	}
	return normalizePath(raw)
}

// matchFinding reports whether a finding claims the scenario's path and class.
func matchFinding(f NormalizedFinding, sc *Scenario, tool string) bool {
	if normalizePath(f.Path) != scenarioPath(sc) {
		return false
	}
	switch tool {
	case "gash":
		if len(sc.Match.PluginIDs) == 0 && len(sc.Match.RuleIDs) == 0 {
			return true
		}
		for _, id := range sc.Match.PluginIDs {
			if f.PluginID == id {
				return true
			}
		}
		for _, id := range sc.Match.RuleIDs {
			if f.RuleID == id {
				return true
			}
		}
		return false
	default:
		if len(sc.Match.NucleiTags) == 0 {
			return true
		}
		for _, want := range sc.Match.NucleiTags {
			for _, tag := range f.Tags {
				if strings.EqualFold(want, tag) {
					return true
				}
			}
		}
		return false
	}
}

// BuildOutcomes matches findings against scenarios and scores the outcomes.
// It returns outcomes plus the findings that matched no scenario, split into
// unexplained (unmatched) and explicitly excluded-by-dataset noise.
func BuildOutcomes(ds *Dataset, tool string, available bool, findings []NormalizedFinding, verifications map[string]Verification) ([]Outcome, []NormalizedFinding, []NormalizedFinding) {
	excludedPlugins := map[string]bool{}
	for _, p := range ds.UnscoredPlugins {
		excludedPlugins[p] = true
	}
	excludedRules := map[string]bool{}
	for _, r := range ds.UnscoredRules {
		excludedRules[r] = true
	}

	var outcomes []Outcome
	matchedFindings := map[int]bool{}
	for i := range ds.Scenarios {
		sc := &ds.Scenarios[i]
		out := Outcome{
			Scenario: sc.ID, Category: sc.Category, Subcategory: sc.Subcategory,
			Expected: sc.Expected, Verification: verifications[sc.ID],
		}
		switch {
		case !available:
			out.Status = StatusNotRun
			outcomes = append(outcomes, out)
			continue
		case !out.Verification.Verified:
			out.Status = StatusUnverified
			if out.Verification.Error != "" {
				out.Notes = append(out.Notes, "verification: "+out.Verification.Error)
			}
			outcomes = append(outcomes, out)
			continue
		}
		var matched []NormalizedFinding
		var idx []int
		for i, f := range findings {
			if matchFinding(f, sc, tool) {
				matched = append(matched, f)
				idx = append(idx, i)
			}
		}
		for _, i := range idx {
			matchedFindings[i] = true
		}
		out.Detectors = detectorNames(matched)
		if len(matched) > 0 {
			out.EvidenceType = matched[0].EvidenceType
		}
		switch sc.Expected {
		case ExpectVulnerable:
			switch {
			case len(matched) == 0:
				out.Status = StatusFN
			case sc.XSS != nil && sc.XSS.ExecutionRequired && !browserConfirmed(matched):
				out.Status = StatusWeak
				out.Notes = append(out.Notes, "detected, but evidence is not browser-confirmed; not counted as confirmed XSS")
			default:
				out.Status = StatusTP
			}
		default:
			if len(matched) > 0 {
				out.Status = StatusFP
				out.Notes = append(out.Notes, "finding reported on a non-vulnerable scenario")
			} else {
				out.Status = StatusTN
			}
		}
		outcomes = append(outcomes, out)
	}

	var unmatched, excludedOut []NormalizedFinding
	for i, f := range findings {
		if matchedFindings[i] {
			continue
		}
		if (f.PluginID != "" && excludedPlugins[f.PluginID]) || (f.RuleID != "" && excludedRules[f.RuleID]) {
			excludedOut = append(excludedOut, f)
			continue
		}
		unmatched = append(unmatched, f)
	}
	return outcomes, unmatched, excludedOut
}

func detectorNames(findings []NormalizedFinding) []string {
	seen := map[string]bool{}
	var out []string
	for _, f := range findings {
		name := f.PluginID
		if name == "" {
			name = f.TemplateID
		}
		if name == "" {
			name = f.RuleID
		}
		if name != "" && !seen[name] {
			seen[name] = true
			out = append(out, name)
		}
	}
	return out
}

func browserConfirmed(findings []NormalizedFinding) bool {
	for _, f := range findings {
		if f.EvidenceType == "browser-confirmed" {
			return true
		}
	}
	return false
}

// ScoreOutcomes computes per-tool metrics from outcomes.
func ScoreOutcomes(outcomes []Outcome) Score {
	var s Score
	for _, o := range outcomes {
		switch o.Status {
		case StatusTP:
			s.TP++
			if o.EvidenceType == "browser-confirmed" {
				s.Confirmed++
			}
		case StatusFP:
			s.FP++
		case StatusTN:
			s.TN++
		case StatusFN:
			s.FN++
		case StatusWeak:
			s.Weak++
		case StatusUnverified:
			s.Unverified++
		case StatusNotRun:
			s.NotRun++
		}
	}
	s.Precision = ratio(s.TP, s.TP+s.FP)
	s.Recall = ratio(s.TP, s.TP+s.FN+s.Weak)
	if s.Precision != nil && s.Recall != nil && *s.Precision+*s.Recall > 0 {
		f1 := 2 * *s.Precision * *s.Recall / (*s.Precision + *s.Recall)
		s.F1 = &f1
	}
	return s
}

// ScoreByCategory groups outcomes by category and computes a score per group.
func ScoreByCategory(outcomes []Outcome) map[string]Score {
	groups := map[string][]Outcome{}
	for _, o := range outcomes {
		groups[o.Category] = append(groups[o.Category], o)
	}
	out := map[string]Score{}
	for cat, group := range groups {
		out[cat] = ScoreOutcomes(group)
	}
	return out
}

// ScoreXSS groups XSS outcomes by kind and by kind/context.
func ScoreXSS(ds *Dataset, outcomes []Outcome) map[string]Score {
	kinds := map[string][]Outcome{}
	contexts := map[string][]Outcome{}
	for _, o := range outcomes {
		sc := findScenario(ds, o.Scenario)
		if sc == nil || sc.XSS == nil {
			continue
		}
		kinds[sc.XSS.Kind] = append(kinds[sc.XSS.Kind], o)
		contexts[sc.XSS.Kind+"/"+sc.XSS.Context] = append(contexts[sc.XSS.Kind+"/"+sc.XSS.Context], o)
	}
	out := map[string]Score{}
	for k, v := range kinds {
		out[k] = ScoreOutcomes(v)
	}
	for k, v := range contexts {
		out[k] = ScoreOutcomes(v)
	}
	return out
}

func findScenario(ds *Dataset, id string) *Scenario {
	for i := range ds.Scenarios {
		if ds.Scenarios[i].ID == id {
			return &ds.Scenarios[i]
		}
	}
	return nil
}

// BuildCrossTool compares both tools per verified scenario.
func BuildCrossTool(outcomes map[string][]Outcome) []CrossRow {
	byScenario := map[string]map[string]Outcome{}
	for tool, list := range outcomes {
		for _, o := range list {
			if byScenario[o.Scenario] == nil {
				byScenario[o.Scenario] = map[string]Outcome{}
			}
			byScenario[o.Scenario][tool] = o
		}
	}
	rows := make([]CrossRow, 0, len(byScenario))
	for id, tools := range byScenario {
		gash, hasGash := tools["gash"]
		nuclei, hasNuclei := tools["nuclei"]
		if !hasGash {
			continue
		}
		if gash.Status == StatusUnverified || gash.Status == StatusNotRun {
			continue
		}
		row := CrossRow{Scenario: id, Category: gash.Category, Expected: gash.Expected, Gash: gash.Status}
		if !hasNuclei || nuclei.Status == StatusUnverified || nuclei.Status == StatusNotRun {
			row.Verdict = "single-tool"
			rows = append(rows, row)
			continue
		}
		row.Nuclei = nuclei.Status
		gashPos := gash.Status == StatusTP || gash.Status == StatusWeak
		nucleiPos := nuclei.Status == StatusTP || nuclei.Status == StatusWeak
		switch {
		case gashPos && nucleiPos:
			row.Verdict = "both"
		case gashPos && !nucleiPos:
			row.Verdict = "gash-only"
		case !gashPos && nucleiPos:
			row.Verdict = "nuclei-only"
		default:
			row.Verdict = "neither"
		}
		rows = append(rows, row)
	}
	sortCrossRows(rows)
	return rows
}

func sortCrossRows(rows []CrossRow) {
	sort.Slice(rows, func(i, j int) bool { return rows[i].Scenario < rows[j].Scenario })
}

func ratio(num, den int) *float64 {
	if den == 0 {
		return nil
	}
	v := float64(num) / float64(den)
	return &v
}

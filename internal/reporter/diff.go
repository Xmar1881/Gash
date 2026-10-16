// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Modül: github.com/Xmar1881/Gash

package reporter

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/Xmar1881/Gash/internal/finding"
)

// DiffEntry is the stable diff view of one finding (fingerprint-keyed).
type DiffEntry struct {
	Fingerprint string `json:"fingerprint"`
	RuleID      string `json:"rule_id"`
	Title       string `json:"title,omitempty"`
	Severity    string `json:"severity,omitempty"`
	Confidence  string `json:"confidence,omitempty"`
	Target      string `json:"target,omitempty"`
	PluginID    string `json:"plugin_id,omitempty"`
}

// DiffResult groups fingerprints into NEW / FIXED / UNCHANGED.
type DiffResult struct {
	New       []DiffEntry `json:"new"`
	Fixed     []DiffEntry `json:"fixed"`
	Unchanged []DiffEntry `json:"unchanged"`
}

// Counts reports list lengths (CI-friendly, no new severity level).
func (r DiffResult) Counts() (int, int, int) {
	return len(r.New), len(r.Fixed), len(r.Unchanged)
}

// toDiffEntry converts one finding to its diff view.
// What: Field copy without recomputing any hash.
// Why: Display must never fork the fingerprint source of truth.
func toDiffEntry(f *finding.Finding) DiffEntry {
	return DiffEntry{
		Fingerprint: f.Fingerprint,
		RuleID:      f.RuleID,
		Title:       f.Title,
		Severity:    string(f.Severity),
		Confidence:  string(f.Confidence),
		Target:      f.Target,
		PluginID:    f.PluginID,
	}
}

// sortDiffEntries orders a diff list deterministically.
// What: RuleID then fingerprint ordering (same tie-break as reporter filter).
// Why: Text/JSON output must be stable across runs for CI diffing.
func sortDiffEntries(in []DiffEntry) {
	sort.Slice(in, func(i, j int) bool {
		if in[i].RuleID != in[j].RuleID {
			return in[i].RuleID < in[j].RuleID
		}
		if in[i].Fingerprint != in[j].Fingerprint {
			return in[i].Fingerprint < in[j].Fingerprint
		}
		return in[i].Target < in[j].Target
	})
}

// ParseReportFindings decodes one WriteJSON report into findings.
// What: Accepts the {"findings": [...]} object (or a bare [...] array).
// Why: Diff inputs are stored scan reports; both shapes stay parseable.
func ParseReportFindings(data []byte) ([]*finding.Finding, error) {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 {
		return nil, fmt.Errorf("reporter diff: empty report")
	}
	if bytes.HasPrefix(trimmed, []byte("[")) {
		var arr []*finding.Finding
		if err := json.Unmarshal(trimmed, &arr); err != nil {
			return nil, fmt.Errorf("reporter diff: decode array: %w", err)
		}
		out := make([]*finding.Finding, 0, len(arr))
		for _, f := range arr {
			if f != nil {
				out = append(out, f)
			}
		}
		return out, nil
	}
	var obj struct {
		Findings []*finding.Finding `json:"findings"`
	}
	if err := json.Unmarshal(trimmed, &obj); err != nil {
		return nil, fmt.Errorf("reporter diff: decode report: %w", err)
	}
	if obj.Findings == nil {
		return []*finding.Finding{}, nil
	}
	out := make([]*finding.Finding, 0, len(obj.Findings))
	for _, f := range obj.Findings {
		if f != nil {
			out = append(out, f)
		}
	}
	return out, nil
}

// DiffFindings compares two finding sets by stored fingerprint.
// What: Map lookup on f.Fingerprint (set at build time by finding.Fingerprint).
// Why: Fingerprint is URL+evidence based (never line-based); diff reuses that
// exact value with zero parallel hashing so baseline matching stays identical
// to engine dedup/suppress semantics.
func DiffFindings(old, new []*finding.Finding) DiffResult {
	oldMap := make(map[string]*finding.Finding, len(old))
	for _, f := range old {
		if f == nil {
			continue
		}
		if strings.TrimSpace(f.Fingerprint) == "" {
			continue
		}
		if _, dup := oldMap[f.Fingerprint]; !dup {
			oldMap[f.Fingerprint] = f
		}
	}
	newMap := make(map[string]*finding.Finding, len(new))
	for _, f := range new {
		if f == nil {
			continue
		}
		if strings.TrimSpace(f.Fingerprint) == "" {
			continue
		}
		if _, dup := newMap[f.Fingerprint]; !dup {
			newMap[f.Fingerprint] = f
		}
	}
	res := DiffResult{New: []DiffEntry{}, Fixed: []DiffEntry{}, Unchanged: []DiffEntry{}}
	for fp, nf := range newMap {
		if _, ok := oldMap[fp]; ok {
			res.Unchanged = append(res.Unchanged, toDiffEntry(nf))
		} else {
			res.New = append(res.New, toDiffEntry(nf))
		}
	}
	for fp, of := range oldMap {
		if _, ok := newMap[fp]; !ok {
			res.Fixed = append(res.Fixed, toDiffEntry(of))
		}
	}
	sortDiffEntries(res.New)
	sortDiffEntries(res.Fixed)
	sortDiffEntries(res.Unchanged)
	return res
}

// DiffReports parses two JSON reports and diffs them by fingerprint.
// What: ParseReportFindings plus DiffFindings in one call.
// Why: CLI and tests share one parse-and-compare path (no drift).
func DiffReports(oldJSON, newJSON []byte) (DiffResult, error) {
	oldF, err := ParseReportFindings(oldJSON)
	if err != nil {
		return DiffResult{}, fmt.Errorf("reporter diff old: %w", err)
	}
	newF, err := ParseReportFindings(newJSON)
	if err != nil {
		return DiffResult{}, fmt.Errorf("reporter diff new: %w", err)
	}
	return DiffFindings(oldF, newF), nil
}

// NormalizeDiffFailOn validates the diff CI gate.
// What: Empty (report only) plus "new" allowlist.
// Why: Unknown levels would make the baseline gate silently meaningless;
// "new" is a set-membership gate, not a confidence/severity level (no new level).
func NormalizeDiffFailOn(level string) (string, error) {
	trimmed := strings.ToLower(strings.TrimSpace(level))
	if trimmed == "" {
		return "", nil
	}
	if trimmed == "new" {
		return "new", nil
	}
	return "", fmt.Errorf("diff: --fail-on %q invalid (new or empty)", level)
}

// ShouldFail reports whether the diff result trips the CI gate.
// What: "new" fails iff at least one NEW fingerprint exists; empty never fails.
// Why: Mirrors scan --fail-on discipline (0 clean, 1 gate triggered) without
// touching existing findings — only genuinely new ones fail the build.
func (r DiffResult) ShouldFail(failOn string) bool {
	switch strings.ToLower(strings.TrimSpace(failOn)) {
	case "new":
		return len(r.New) > 0
	default:
		return false
	}
}

// WriteDiffText renders a human-readable diff summary.
// What: One summary line plus new/fixed/unchanged sections (deterministic order).
// Why: Terminal output stays greppable while JSON stays machine-readable.
func WriteDiffText(w io.Writer, r DiffResult) error {
	if _, err := fmt.Fprintf(w, "diff: %d new, %d fixed, %d unchanged\n", len(r.New), len(r.Fixed), len(r.Unchanged)); err != nil {
		return fmt.Errorf("reporter diff text: %w", err)
	}
	sections := []struct {
		name string
		list []DiffEntry
	}{
		{"new", r.New},
		{"fixed", r.Fixed},
		{"unchanged", r.Unchanged},
	}
	for _, s := range sections {
		if _, err := fmt.Fprintf(w, "%s (%d):\n", s.name, len(s.list)); err != nil {
			return fmt.Errorf("reporter diff text: %w", err)
		}
		for _, e := range s.list {
			if _, err := fmt.Fprintf(w, "- [%s/%s] %s (%s) %s fp=%s\n",
				e.Severity, e.Confidence, e.Title, e.RuleID, e.Target, e.Fingerprint); err != nil {
				return fmt.Errorf("reporter diff text: %w", err)
			}
		}
	}
	return nil
}

// WriteDiffJSON renders the machine-readable diff (CI contract).
// What: {"new": [...], "fixed": [...], "unchanged": [...], "counts": {...}}.
// Why: Pipelines parse counts without scraping terminal text.
func WriteDiffJSON(w io.Writer, r DiffResult) error {
	if r.New == nil {
		r.New = []DiffEntry{}
	}
	if r.Fixed == nil {
		r.Fixed = []DiffEntry{}
	}
	if r.Unchanged == nil {
		r.Unchanged = []DiffEntry{}
	}
	doc := map[string]any{
		"new":       r.New,
		"fixed":     r.Fixed,
		"unchanged": r.Unchanged,
		"counts": map[string]int{
			"new":       len(r.New),
			"fixed":     len(r.Fixed),
			"unchanged": len(r.Unchanged),
		},
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(true)
	if err := enc.Encode(doc); err != nil {
		return fmt.Errorf("reporter diff json: %w", err)
	}
	return nil
}

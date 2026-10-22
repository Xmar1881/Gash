// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Module: github.com/Xmar1881/Gash

package bench

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"html"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const ReportSchemaVersion = "bench-report/1"

// LabManifest records the fixture lab request counters observed during the run.
type LabManifest struct {
	Kind          string           `json:"kind"`
	URL           string           `json:"url,omitempty"`
	TotalObserved int64            `json:"total_observed"`
	PerPath       map[string]int64 `json:"per_path,omitempty"`
}

// Manifest is the reproducibility manifest: versions, environment, commands.
type Manifest struct {
	StartedAt     string            `json:"started_at"`
	FinishedAt    string            `json:"finished_at"`
	GitCommit     string            `json:"git_commit,omitempty"`
	GitDirty      bool              `json:"git_dirty"`
	GOOS          string            `json:"goos"`
	GOARCH        string            `json:"goarch"`
	GoVersion     string            `json:"go_version"`
	DatasetPath   string            `json:"dataset_path"`
	DatasetSHA256 string            `json:"dataset_sha256"`
	GashBin       string            `json:"gash_bin"`
	GashVersion   string            `json:"gash_version,omitempty"`
	GashSHA256    string            `json:"gash_sha256,omitempty"`
	NucleiBin     string            `json:"nuclei_bin,omitempty"`
	NucleiVersion string            `json:"nuclei_version,omitempty"`
	FixtureLab    *LabManifest      `json:"fixture_lab,omitempty"`
	Conditions    []string          `json:"conditions,omitempty"`
	Environment   map[string]string `json:"environment,omitempty"`
}

// ToolResult aggregates every run of one tool plus its score.
type ToolResult struct {
	Available        bool             `json:"available"`
	Reason           string           `json:"reason,omitempty"`
	Version          string           `json:"version,omitempty"`
	Runs             []ToolRun        `json:"runs"`
	Findings         int              `json:"findings"`
	TentativeTotal   int              `json:"tentative_total,omitempty"`
	Score            Score            `json:"score"`
	ByCategory       map[string]Score `json:"by_category"`
	XSS              map[string]Score `json:"xss,omitempty"`
	Unmatched        int              `json:"unmatched"`
	Excluded         int              `json:"excluded"`
	DurationMS       int64            `json:"duration_ms"`
	ReportedRequests *int64           `json:"reported_requests,omitempty"`
	ObservedRequests *int64           `json:"observed_requests,omitempty"`
	CPUTimeMS        *int64           `json:"cpu_time_ms,omitempty"`
	MaxRSSKB         *int64           `json:"max_rss_kb,omitempty"`
}

// MissedRow is one failed or missed scenario entry for the failure list.
type MissedRow struct {
	Tool      string `json:"tool"`
	Scenario  string `json:"scenario"`
	Category  string `json:"category"`
	Expected  string `json:"expected"`
	Status    string `json:"status"`
	Detectors string `json:"detectors,omitempty"`
	Note      string `json:"note,omitempty"`
}

// UnverifiedRow records a scenario that could not be independently verified.
type UnverifiedRow struct {
	Scenario string `json:"scenario"`
	Kind     string `json:"kind"`
	Reason   string `json:"reason,omitempty"`
}

// DatasetSummary is the report-facing dataset description.
type DatasetSummary struct {
	Name          string `json:"name"`
	Kind          string `json:"kind"`
	Path          string `json:"path"`
	SHA256        string `json:"sha256"`
	ScenarioCount int    `json:"scenario_count"`
	TargetCount   int    `json:"target_count"`
}

// Report is the complete, reproducible benchmark output.
type Report struct {
	SchemaVersion     string                 `json:"schema_version"`
	GeneratedAt       string                 `json:"generated_at"`
	Dataset           DatasetSummary         `json:"dataset"`
	Manifest          Manifest               `json:"manifest"`
	Tools             map[string]*ToolResult `json:"tools"`
	Outcomes          map[string][]Outcome   `json:"outcomes"`
	CrossTool         []CrossRow             `json:"cross_tool"`
	Missed            []MissedRow            `json:"missed"`
	Unverified        []UnverifiedRow        `json:"unverified_scenarios,omitempty"`
	UnmatchedFindings []NormalizedFinding    `json:"unmatched_findings,omitempty"`
	ExcludedFindings  []NormalizedFinding    `json:"excluded_findings,omitempty"`
	Limitations       []string               `json:"limitations,omitempty"`
	Gate              *GateResult            `json:"gate,omitempty"`
}

// BuildMissed derives the failed/missed list from outcomes.
func (r *Report) BuildMissed() {
	for _, tool := range sortedToolNames(r.Tools) {
		res := r.Tools[tool]
		if res == nil || !res.Available {
			continue
		}
		for _, o := range r.Outcomes[tool] {
			switch o.Status {
			case StatusFN, StatusWeak, StatusFP:
				note := ""
				if len(o.Notes) > 0 {
					note = strings.Join(o.Notes, "; ")
				}
				r.Missed = append(r.Missed, MissedRow{
					Tool: tool, Scenario: o.Scenario, Category: o.Category,
					Expected: o.Expected, Status: o.Status,
					Detectors: strings.Join(o.Detectors, ","), Note: note,
				})
			}
		}
	}
	sort.Slice(r.Missed, func(i, j int) bool {
		if r.Missed[i].Tool != r.Missed[j].Tool {
			return r.Missed[i].Tool < r.Missed[j].Tool
		}
		return r.Missed[i].Scenario < r.Missed[j].Scenario
	})
}

func sortedToolNames(tools map[string]*ToolResult) []string {
	names := make([]string, 0, len(tools))
	for name := range tools {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// WriteDir writes report.json, summary.md, report.html, findings.csv and
// manifest.json into dir and returns the written file paths.
func (r *Report) WriteDir(dir string) (map[string]string, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("bench report: mkdir %s: %w", dir, err)
	}
	files := map[string]string{}
	write := func(name string, fn func(*os.File) error) error {
		path := filepath.Join(dir, name)
		f, err := os.Create(path)
		if err != nil {
			return err
		}
		defer f.Close()
		if err := fn(f); err != nil {
			return fmt.Errorf("%s: %w", path, err)
		}
		files[name] = path
		return nil
	}
	if err := write("report.json", func(f *os.File) error {
		enc := json.NewEncoder(f)
		enc.SetIndent("", "  ")
		return enc.Encode(r)
	}); err != nil {
		return files, err
	}
	if err := write("manifest.json", func(f *os.File) error {
		enc := json.NewEncoder(f)
		enc.SetIndent("", "  ")
		return enc.Encode(r.Manifest)
	}); err != nil {
		return files, err
	}
	if err := write("summary.md", func(f *os.File) error {
		_, err := f.WriteString(r.SummaryMarkdown())
		return err
	}); err != nil {
		return files, err
	}
	if err := write("report.html", func(f *os.File) error {
		_, err := f.WriteString(r.HTMLReport())
		return err
	}); err != nil {
		return files, err
	}
	if err := write("findings.csv", func(f *os.File) error {
		return r.writeFindingsCSV(f)
	}); err != nil {
		return files, err
	}
	return files, nil
}

func (r *Report) writeFindingsCSV(f *os.File) error {
	w := csv.NewWriter(f)
	header := []string{"tool", "scenario", "status", "category", "expected", "detectors", "evidence_type", "note"}
	if err := w.Write(header); err != nil {
		return err
	}
	for _, tool := range sortedToolNames(r.Tools) {
		for _, o := range r.Outcomes[tool] {
			row := []string{tool, o.Scenario, o.Status, o.Category, o.Expected,
				strings.Join(o.Detectors, ","), o.EvidenceType, strings.Join(o.Notes, "; ")}
			if err := w.Write(row); err != nil {
				return err
			}
		}
	}
	for _, m := range r.Missed {
		row := []string{m.Tool, m.Scenario, m.Status, m.Category, m.Expected, m.Detectors, "", m.Note}
		if err := w.Write(row); err != nil {
			return err
		}
	}
	w.Flush()
	return w.Error()
}

func fmtRatio(v *float64) string {
	if v == nil {
		return "N/A"
	}
	return fmt.Sprintf("%.3f", *v)
}

func fmtScore(s Score) string {
	return fmt.Sprintf("TP=%d (static=%d browser=%d) FP=%d TN=%d FN=%d weak=%d blocked=%d error=%d prec=%s recall=%s F1=%s",
		s.TP, s.StaticActiveTP, s.BrowserConfirmedTP, s.FP, s.TN, s.FN, s.Weak,
		s.Blocked, s.Error, fmtRatio(s.Precision), fmtRatio(s.Recall), fmtRatio(s.F1))
}

// SummaryMarkdown renders the human-readable report.
func (r *Report) SummaryMarkdown() string {
	var b strings.Builder
	fmt.Fprintf(&b, "# Gash benchmark report\n\n")
	fmt.Fprintf(&b, "- generated: %s\n", r.GeneratedAt)
	fmt.Fprintf(&b, "- dataset: %s (%s, sha256 %s)\n", r.Dataset.Name, r.Dataset.Kind, shortSHA(r.Dataset.SHA256))
	fmt.Fprintf(&b, "- scenarios: %d, targets: %d\n", r.Dataset.ScenarioCount, r.Dataset.TargetCount)
	fmt.Fprintf(&b, "- git commit: %s (dirty=%v), go %s %s/%s\n\n", r.Manifest.GitCommit, r.Manifest.GitDirty, r.Manifest.GoVersion, r.Manifest.GOOS, r.Manifest.GOARCH)

	fmt.Fprintf(&b, "## Tool metrics\n\n")
	fmt.Fprintf(&b, "| tool | available | findings | tentative | TP | static TP | browser TP | FP | TN | FN | weak | unverified | blocked | error | not-run | precision | recall | F1 | duration | requests (reported/observed) |\n")
	fmt.Fprintf(&b, "|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|\n")
	for _, tool := range sortedToolNames(r.Tools) {
		res := r.Tools[tool]
		if res == nil {
			continue
		}
		req := "N/A"
		if res.ReportedRequests != nil || res.ObservedRequests != nil {
			req = fmt.Sprintf("%s / %s", fmtInt(res.ReportedRequests), fmtInt(res.ObservedRequests))
		}
		fmt.Fprintf(&b, "| %s | %v | %d | %d | %d | %d | %d | %d | %d | %d | %d | %d | %d | %d | %d | %s | %s | %s | %s | %s |\n",
			tool, res.Available, res.Findings, res.TentativeTotal, res.Score.TP,
			res.Score.StaticActiveTP, res.Score.BrowserConfirmedTP,
			res.Score.FP, res.Score.TN, res.Score.FN,
			res.Score.Weak, res.Score.Unverified, res.Score.Blocked, res.Score.Error, res.Score.NotRun,
			fmtRatio(res.Score.Precision), fmtRatio(res.Score.Recall), fmtRatio(res.Score.F1),
			time.Duration(res.DurationMS)*time.Millisecond, req)
		if !res.Available && res.Reason != "" {
			fmt.Fprintf(&b, "\n%s unavailable: %s\n", tool, res.Reason)
		}
	}
	fmt.Fprintf(&b, "\nPrecision/recall denominators exclude unverified and not-run scenarios (reported separately). `static TP` is non-browser-confirmed static/active evidence; `browser TP` is the browser-confirmed subset. They are disjoint, sum to TP, and are never conflated: static TP must not be read as browser-confirmed XSS. Execution-required XSS without browser proof remains weak, not static TP. Weak evidence (execution-required XSS without browser proof) counts as recall loss, never as confirmed XSS. Blocked and error counts are subsets of unverified and are excluded from denominators, not scored as negatives. Scoring counts the tools' normal report visibility: tentative candidates are listed in the tentative column but never scored (add --show-tentative to the dataset args to opt in).\n\n")

	for _, tool := range sortedToolNames(r.Tools) {
		res := r.Tools[tool]
		if res == nil || len(res.ByCategory) == 0 {
			continue
		}
		fmt.Fprintf(&b, "## %s per category\n\n", tool)
		fmt.Fprintf(&b, "| category | %s |\n|---|---|\n", "score")
		for _, cat := range sortedScoreKeys(res.ByCategory) {
			fmt.Fprintf(&b, "| %s | %s |\n", cat, fmtScore(res.ByCategory[cat]))
		}
		fmt.Fprintf(&b, "\n")
	}

	for _, tool := range sortedToolNames(r.Tools) {
		res := r.Tools[tool]
		if res == nil || len(res.XSS) == 0 {
			continue
		}
		fmt.Fprintf(&b, "## %s XSS breakdown\n\n", tool)
		fmt.Fprintf(&b, "| kind/context | %s |\n|---|---|\n", "score")
		for _, key := range sortedScoreKeys(res.XSS) {
			fmt.Fprintf(&b, "| %s | %s |\n", key, fmtScore(res.XSS[key]))
		}
		fmt.Fprintf(&b, "\n")
	}

	if len(r.CrossTool) > 0 {
		fmt.Fprintf(&b, "## Cross-tool (verified scenarios)\n\n")
		fmt.Fprintf(&b, "| scenario | category | expected | gash | nuclei | verdict |\n|---|---|---|---|---|---|\n")
		for _, row := range r.CrossTool {
			nuclei := row.Nuclei
			if nuclei == "" {
				nuclei = "n/a"
			}
			fmt.Fprintf(&b, "| %s | %s | %s | %s | %s | %s |\n", row.Scenario, row.Category, row.Expected, row.Gash, nuclei, row.Verdict)
		}
		fmt.Fprintf(&b, "\n")
	}

	if len(r.Missed) > 0 {
		fmt.Fprintf(&b, "## Failed and missed scenarios\n\n")
		fmt.Fprintf(&b, "| tool | scenario | category | expected | status | detectors | note |\n|---|---|---|---|---|---|---|\n")
		for _, m := range r.Missed {
			fmt.Fprintf(&b, "| %s | %s | %s | %s | %s | %s | %s |\n", m.Tool, m.Scenario, m.Category, m.Expected, m.Status, m.Detectors, m.Note)
		}
		fmt.Fprintf(&b, "\n")
	} else {
		fmt.Fprintf(&b, "## Failed and missed scenarios\n\nnone\n\n")
	}

	if len(r.Unverified) > 0 {
		fmt.Fprintf(&b, "## Unverified scenarios (excluded from scoring)\n\n")
		fmt.Fprintf(&b, "| scenario | verify kind | reason |\n|---|---|---|\n")
		for _, u := range r.Unverified {
			fmt.Fprintf(&b, "| %s | %s | %s |\n", u.Scenario, u.Kind, u.Reason)
		}
		fmt.Fprintf(&b, "\n")
	}

	if len(r.ExcludedFindings) > 0 {
		fmt.Fprintf(&b, "## Excluded findings (out of benchmark scope, listed for transparency)\n\n")
		fmt.Fprintf(&b, "| tool | path | plugin/template/rules | title |\n|---|---|---|---|\n")
		for _, f := range r.ExcludedFindings {
			fmt.Fprintf(&b, "| %s | %s | %s | %s |\n", f.Tool, f.Path, firstNonEmpty(f.PluginID, f.TemplateID, f.RuleID), f.Title)
		}
		fmt.Fprintf(&b, "\n")
	}
	if len(r.UnmatchedFindings) > 0 {
		fmt.Fprintf(&b, "## Unmatched findings (no scenario claimed them)\n\n")
		fmt.Fprintf(&b, "| tool | path | plugin/template/rules | severity | title |\n|---|---|---|---|---|\n")
		for _, f := range r.UnmatchedFindings {
			fmt.Fprintf(&b, "| %s | %s | %s | %s | %s |\n", f.Tool, f.Path, firstNonEmpty(f.PluginID, f.TemplateID, f.RuleID), f.Severity, f.Title)
		}
		fmt.Fprintf(&b, "\n")
	}

	fmt.Fprintf(&b, "## Conditions and environment\n\n")
	for _, c := range r.Manifest.Conditions {
		fmt.Fprintf(&b, "- %s\n", c)
	}
	for _, k := range sortedKeys(r.Manifest.Environment) {
		fmt.Fprintf(&b, "- env %s=%s\n", k, r.Manifest.Environment[k])
	}
	for _, tool := range sortedToolNames(r.Tools) {
		res := r.Tools[tool]
		if res == nil {
			continue
		}
		for i, run := range res.Runs {
			fmt.Fprintf(&b, "- run %s[%d] target=%s auth=%s command=%q duration=%s requests(reported=%s observed=%s)\n",
				tool, i, run.Target, run.Auth, strings.Join(run.Command, " "),
				time.Duration(run.DurationMS)*time.Millisecond, fmtInt(run.ReportedRequests), fmtInt(run.ObservedRequests))
		}
	}
	fmt.Fprintf(&b, "\n")

	if len(r.Limitations) > 0 {
		fmt.Fprintf(&b, "## Limitations\n\n")
		for _, l := range r.Limitations {
			fmt.Fprintf(&b, "- %s\n", l)
		}
		fmt.Fprintf(&b, "\n")
	}

	if r.Gate != nil {
		fmt.Fprintf(&b, "## Regression gate\n\n")
		fmt.Fprintf(&b, "- passed: %v\n", r.Gate.Passed)
		for _, reason := range r.Gate.Reasons {
			fmt.Fprintf(&b, "- %s\n", reason)
		}
		for _, d := range r.Gate.Deltas {
			fmt.Fprintf(&b, "- delta %s: %s -> %s\n", d.Metric, d.Before, d.After)
		}
		fmt.Fprintf(&b, "\n")
	}
	return b.String()
}

// HTMLReport renders a self-contained HTML report.
func (r *Report) HTMLReport() string {
	var b strings.Builder
	b.WriteString("<!doctype html><html><head><meta charset=\"utf-8\"><title>Gash benchmark report</title><style>")
	b.WriteString("body{font-family:system-ui,Segoe UI,Arial,sans-serif;margin:24px;color:#1c2530}h1,h2{color:#123}table{border-collapse:collapse;margin:12px 0 24px;width:100%}th,td{border:1px solid #c8d2dc;padding:6px 8px;text-align:left;font-size:14px}th{background:#eef3f8}.tp{color:#0a7d32;font-weight:600}.fp,.fn,.weak-evidence{color:#b3261e;font-weight:600}.tn{color:#57606a}pre{background:#f4f6f8;padding:10px;overflow:auto;font-size:12px}")
	b.WriteString("</style></head><body>")
	fmt.Fprintf(&b, "<h1>Gash benchmark report</h1><p>generated %s &middot; dataset %s (sha256 %s) &middot; git %s</p>",
		html.EscapeString(r.GeneratedAt), html.EscapeString(r.Dataset.Name), html.EscapeString(shortSHA(r.Dataset.SHA256)), html.EscapeString(r.Manifest.GitCommit))

	b.WriteString("<h2>Tool metrics</h2><table><tr><th>tool</th><th>available</th><th>findings</th><th>tentative</th><th>TP</th><th>static TP</th><th>browser TP</th><th>FP</th><th>TN</th><th>FN</th><th>weak</th><th>unverified</th><th>blocked</th><th>error</th><th>not-run</th><th>precision</th><th>recall</th><th>F1</th><th>duration</th><th>requests</th></tr>")
	for _, tool := range sortedToolNames(r.Tools) {
		res := r.Tools[tool]
		if res == nil {
			continue
		}
		req := "N/A"
		if res.ReportedRequests != nil || res.ObservedRequests != nil {
			req = fmt.Sprintf("%s / %s", fmtInt(res.ReportedRequests), fmtInt(res.ObservedRequests))
		}
		fmt.Fprintf(&b, "<tr><td>%s</td><td>%v</td><td>%d</td><td>%d</td><td class=\"tp\">%d</td><td>%d</td><td>%d</td><td class=\"fp\">%d</td><td class=\"tn\">%d</td><td class=\"fn\">%d</td><td class=\"weak-evidence\">%d</td><td>%d</td><td>%d</td><td>%d</td><td>%d</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>",
			html.EscapeString(tool), res.Available, res.Findings, res.TentativeTotal, res.Score.TP,
			res.Score.StaticActiveTP, res.Score.BrowserConfirmedTP,
			res.Score.FP, res.Score.TN, res.Score.FN,
			res.Score.Weak, res.Score.Unverified, res.Score.Blocked, res.Score.Error, res.Score.NotRun,
			fmtRatio(res.Score.Precision), fmtRatio(res.Score.Recall), fmtRatio(res.Score.F1),
			time.Duration(res.DurationMS)*time.Millisecond, req)
	}
	b.WriteString("</table><p>Precision/recall exclude unverified and not-run scenarios; weak evidence counts as recall loss and never as confirmed XSS. Static TP and browser TP are disjoint and sum to TP; static TP is not browser-confirmed evidence. Blocked and error are subsets of unverified and stay out of denominators. Tentative candidates are reported but unscored unless the dataset opts in with --show-tentative.</p>")

	for _, tool := range sortedToolNames(r.Tools) {
		res := r.Tools[tool]
		if res == nil || len(res.ByCategory) == 0 {
			continue
		}
		fmt.Fprintf(&b, "<h2>%s per category</h2><table><tr><th>category</th><th>TP</th><th>FP</th><th>TN</th><th>FN</th><th>weak</th><th>precision</th><th>recall</th><th>F1</th></tr>", html.EscapeString(tool))
		for _, cat := range sortedScoreKeys(res.ByCategory) {
			s := res.ByCategory[cat]
			fmt.Fprintf(&b, "<tr><td>%s</td><td>%d</td><td>%d</td><td>%d</td><td>%d</td><td>%d</td><td>%s</td><td>%s</td><td>%s</td></tr>",
				html.EscapeString(cat), s.TP, s.FP, s.TN, s.FN, s.Weak, fmtRatio(s.Precision), fmtRatio(s.Recall), fmtRatio(s.F1))
		}
		b.WriteString("</table>")
	}

	if len(r.Missed) > 0 {
		b.WriteString("<h2>Failed and missed scenarios</h2><table><tr><th>tool</th><th>scenario</th><th>category</th><th>expected</th><th>status</th><th>detectors</th><th>note</th></tr>")
		for _, m := range r.Missed {
			fmt.Fprintf(&b, "<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td class=\"%s\">%s</td><td>%s</td><td>%s</td></tr>",
				html.EscapeString(m.Tool), html.EscapeString(m.Scenario), html.EscapeString(m.Category),
				html.EscapeString(m.Expected), html.EscapeString(m.Status), html.EscapeString(m.Status),
				html.EscapeString(m.Detectors), html.EscapeString(m.Note))
		}
		b.WriteString("</table>")
	}

	if len(r.Unverified) > 0 {
		b.WriteString("<h2>Unverified scenarios</h2><table><tr><th>scenario</th><th>verify kind</th><th>reason</th></tr>")
		for _, u := range r.Unverified {
			fmt.Fprintf(&b, "<tr><td>%s</td><td>%s</td><td>%s</td></tr>", html.EscapeString(u.Scenario), html.EscapeString(u.Kind), html.EscapeString(u.Reason))
		}
		b.WriteString("</table>")
	}

	if len(r.Limitations) > 0 {
		b.WriteString("<h2>Limitations</h2><ul>")
		for _, l := range r.Limitations {
			fmt.Fprintf(&b, "<li>%s</li>", html.EscapeString(l))
		}
		b.WriteString("</ul>")
	}

	b.WriteString("<h2>Conditions</h2><ul>")
	for _, c := range r.Manifest.Conditions {
		fmt.Fprintf(&b, "<li>%s</li>", html.EscapeString(c))
	}
	b.WriteString("</ul><h2>Executed commands</h2><pre>")
	for _, tool := range sortedToolNames(r.Tools) {
		res := r.Tools[tool]
		if res == nil {
			continue
		}
		for _, run := range res.Runs {
			b.WriteString(html.EscapeString(strings.Join(run.Command, " ")) + "\n")
		}
	}
	b.WriteString("</pre></body></html>")
	return b.String()
}

func shortSHA(v string) string {
	if len(v) > 12 {
		return v[:12]
	}
	return v
}

func fmtInt(v *int64) string {
	if v == nil {
		return "N/A"
	}
	return fmt.Sprintf("%d", *v)
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func sortedScoreKeys(m map[string]Score) []string { return sortedKeys(m) }

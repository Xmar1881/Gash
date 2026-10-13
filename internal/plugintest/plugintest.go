// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Module: github.com/Xmar1881/Gash

// Package plugintest provides offline fixture execution for reference plugins.
// What: Loads JSON fixtures and evaluates them through engine-owned oracles.
// Why: Lets `gash plugins test` verify precision without network access while
// keeping the confidence decision inside the oracles, never in the plugin.
package plugintest

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/Xmar1881/Gash/internal/baseline"
	"github.com/Xmar1881/Gash/internal/oracle"
	"github.com/Xmar1881/Gash/internal/plugin"
)

// Fixture describes one canned HTTP exchange plus the expected oracle outcome.
// What: Serializable positive/negative case consumed by the test runner.
// Why: A single schema covers every oracle so fixtures stay reviewable.
type Fixture struct {
	// Name is a human-readable case label used in failure messages.
	Name string `json:"name"`
	// Target is the request URL the case applies to.
	Target string `json:"target"`
	// Status is the probe response status code.
	Status int `json:"status"`
	// Headers is the probe response header set.
	Headers map[string]string `json:"headers"`
	// Body is the probe response body.
	Body string `json:"body"`
	// ControlStatus is the control response status code.
	ControlStatus int `json:"control_status"`
	// ControlHeaders is the control response header set.
	ControlHeaders map[string]string `json:"control_headers"`
	// ControlBody is the neutral-payload response body.
	ControlBody string `json:"control_body"`
	// TrueBodies and FalseBodies carry differential repeats.
	TrueBodies []string `json:"true_bodies"`
	// FalseBodies carries the false-branch repeats.
	FalseBodies []string `json:"false_bodies"`
	// PayloadHost is the expected redirect payload host.
	PayloadHost string `json:"payload_host"`
	// OOBCallback simulates a seen OOB interaction.
	OOBCallback bool `json:"oob_callback"`
	// Canary overrides the default reflection canary.
	Canary string `json:"canary"`
	// ExpectedVerdict is the oracle verdict the runner requires.
	ExpectedVerdict string `json:"expected_verdict"`
	// ExpectedConfidence is the confidence the runner requires on accept.
	ExpectedConfidence string `json:"expected_confidence"`
}

// DefaultCanary is the deterministic canary used when a fixture omits one.
// What: Stable fallback canary for offline evaluation.
// Why: Determinism keeps fixture runs reproducible across machines.
const DefaultCanary = "gash_a1b2c3d4"

// LoadDir reads all *.json fixtures from a directory, sorted by file name.
// What: Directory loader for positive/negative fixture sets.
// Why: Sorted loading guarantees deterministic test order.
func LoadDir(dir string) ([]Fixture, []string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, nil, fmt.Errorf("plugintest load dir %s: %w", dir, err)
	}
	var names []string
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(strings.ToLower(e.Name()), ".json") {
			continue
		}
		names = append(names, e.Name())
	}
	sort.Strings(names)
	var out []Fixture
	var files []string
	for _, n := range names {
		p := filepath.Join(dir, n)
		data, err := os.ReadFile(p)
		if err != nil {
			return nil, nil, fmt.Errorf("plugintest read %s: %w", p, err)
		}
		var f Fixture
		if err := json.Unmarshal(data, &f); err != nil {
			return nil, nil, fmt.Errorf("plugintest decode %s: %w", p, err)
		}
		if f.Name == "" {
			f.Name = strings.TrimSuffix(n, ".json")
		}
		out = append(out, f)
		files = append(files, p)
	}
	return out, files, nil
}

// CaseResult records the outcome of a single fixture evaluation.
// What: Per-fixture pass/fail detail for CLI and gate tests.
// Why: Structured results let reporters show exactly which case failed.
type CaseResult struct {
	// File is the fixture file path.
	File string
	// Name is the fixture case label.
	Name string
	// Positive marks positive (must-accept) versus negative (must-not-confirm) cases.
	Positive bool
	// Verdict is the oracle verdict observed.
	Verdict oracle.Verdict
	// Confidence is the confidence observed on accept.
	Confidence plugin.Confidence
	// Pass states whether expectations held.
	Pass bool
	// Detail explains failures.
	Detail string
}

// Summary aggregates a full `gash plugins test` run.
// What: Totals plus precision/recall for one plugin.
// Why: The metrics gate consumes these numbers instead of trusting prose.
type Summary struct {
	// PluginID is the plugin under test.
	PluginID string
	// Cases holds per-fixture results in execution order.
	Cases []CaseResult
	// TruePositives counts positive fixtures accepted at expected confidence.
	TruePositives int
	// FalseNegatives counts positive fixtures missed.
	FalseNegatives int
	// FalsePositives counts negative fixtures that reached firm or confirmed.
	FalsePositives int
	// TrueNegatives counts correctly rejected negatives.
	TrueNegatives int
	// Precision is TP/(TP+FP), 1.0 when no positive claims exist.
	Precision float64
	// Recall is TP/(TP+FN), 1.0 when no positives exist.
	Recall float64
	// Pass is true when every case met expectations.
	Pass bool
}

// Evaluate runs one fixture through the named oracle.
// What: Oracle dispatcher shared by the CLI and Go gate tests.
// Why: A single dispatcher prevents per-plugin test logic from drifting.
func Evaluate(ctx context.Context, oracleName string, f Fixture, oobEnabled bool) (*oracle.Evidence, error) {
	cls := baseline.ClassifyStatic(f.Status, toHeader(f.Headers), []byte(f.Body))
	canary := f.Canary
	if canary == "" {
		canary = DefaultCanary
	}
	switch strings.ToLower(oracleName) {
	case "header":
		var o oracle.HeaderOracle
		return o.Verify(ctx, cls, false, oracle.HeaderParams{Headers: toHeader(f.Headers)})
	case "redirect":
		var o oracle.RedirectOracle
		loc := ""
		for k, v := range f.Headers {
			if strings.EqualFold(k, "Location") {
				loc = v
				break
			}
		}
		controlClean := f.ControlBody != "" || f.ControlStatus != 0
		if f.ControlBody == "" && f.ControlStatus == 0 {
			controlClean = false
		}
		// A control that itself redirects externally is not a clean control.
		if cl := controlLocation(f.ControlHeaders); cl != "" && isAbsoluteURL(cl) {
			controlClean = false
		}
		return o.Verify(ctx, cls, false, oracle.RedirectParams{
			Location: loc, PayloadHost: f.PayloadHost,
			ControlNoRedir: controlClean, ResolveDNS: false,
		})
	case "reflection":
		var o oracle.ReflectionOracle
		ctrl := f.ControlBody
		return o.Verify(ctx, f.Body, toHeader(f.Headers), cls, false, oracle.ReflectionParams{
			Canary: canary, Contexts: []string{"html", "attr", "script"},
			RequireExecutableContext: true, ControlBody: ctrl,
		})
	case "error":
		var o oracle.ErrorSignatureOracle
		return o.Verify(ctx, cls, false, oracle.ErrorSignatureParams{
			Body: f.Body, ControlBody: f.ControlBody,
		})
	case "differential":
		var o oracle.DifferentialOracle
		return o.Verify(ctx, cls, false, oracle.DifferentialParams{
			TrueBodies: f.TrueBodies, FalseBodies: f.FalseBodies,
			ControlBody: f.ControlBody, Repeats: 3,
		})
	case "oob":
		o := oracle.OOBOracle{Enabled: oobEnabled}
		return o.Verify(ctx, cls, false, oracle.OOBParams{
			CorrelationID: "c_fixture", Namespace: "scan_fixture",
			CallbackSeen: f.OOBCallback,
		})
	case "version":
		var o oracle.VersionOracle
		return o.Verify(ctx, cls, false, oracle.VersionParams{Banner: f.Body})
	default:
		return nil, fmt.Errorf("plugintest: unknown oracle %q", oracleName)
	}
}

// CheckPositive asserts a positive fixture accepted at the expected confidence.
// What: Positive-case assertion used by the runner.
// Why: Exact-confidence matching locks the documented evidence ladder.
func CheckPositive(ev *oracle.Evidence, f Fixture) (bool, string) {
	if ev == nil {
		return false, "nil evidence"
	}
	if ev.Verdict != oracle.VerdictAccept {
		return false, fmt.Sprintf("expected accept, got %s (%s)", ev.Verdict, ev.Note)
	}
	if f.ExpectedConfidence != "" && string(ev.ConfidenceContribution) != f.ExpectedConfidence {
		return false, fmt.Sprintf("expected confidence %s, got %s", f.ExpectedConfidence, ev.ConfidenceContribution)
	}
	return true, ""
}

// CheckNegative asserts a negative fixture never reaches firm or confirmed.
// What: Negative-case assertion enforcing the zero-FP corpus discipline.
// Why: Tentative is tolerable noise; firm-plus is a gate failure.
func CheckNegative(ev *oracle.Evidence) (bool, string) {
	if ev == nil {
		return true, ""
	}
	if ev.Verdict != oracle.VerdictAccept {
		return true, ""
	}
	switch ev.ConfidenceContribution {
	case plugin.ConfidenceFirm, plugin.ConfidenceConfirmed:
		return false, fmt.Sprintf("false positive: %s (%s)", ev.ConfidenceContribution, ev.Note)
	default:
		return true, ""
	}
}

// Run executes positive/ and negative/ fixture sets for one oracle.
// What: Full per-plugin fixture run returning a precision/recall summary.
// Why: One entry point serves the CLI, the docs generator, and the CI gate.
func Run(ctx context.Context, pluginID, oracleName, fixtureRoot string, oobEnabled bool) (*Summary, error) {
	pos, posFiles, err := LoadDir(filepath.Join(fixtureRoot, "positive"))
	if err != nil {
		return nil, err
	}
	neg, negFiles, err := LoadDir(filepath.Join(fixtureRoot, "negative"))
	if err != nil {
		return nil, err
	}
	sum := &Summary{PluginID: pluginID, Pass: true}
	for i, f := range pos {
		ev, err := Evaluate(ctx, oracleName, f, oobEnabled)
		if err != nil {
			sum.Cases = append(sum.Cases, CaseResult{File: posFiles[i], Name: f.Name, Positive: true, Pass: false, Detail: err.Error()})
			sum.FalseNegatives++
			sum.Pass = false
			continue
		}
		ok, detail := CheckPositive(ev, f)
		cr := CaseResult{File: posFiles[i], Name: f.Name, Positive: true, Pass: ok, Detail: detail}
		if ev != nil {
			cr.Verdict = ev.Verdict
			cr.Confidence = ev.ConfidenceContribution
		}
		sum.Cases = append(sum.Cases, cr)
		if ok {
			sum.TruePositives++
		} else {
			sum.FalseNegatives++
			sum.Pass = false
		}
	}
	for i, f := range neg {
		// Negative OOB fixtures run with the mock enabled so a missing
		// callback must reject; the disabled-server skip is covered by B9.
		ev, err := Evaluate(ctx, oracleName, f, true)
		if err != nil {
			sum.Cases = append(sum.Cases, CaseResult{File: negFiles[i], Name: f.Name, Pass: false, Detail: err.Error()})
			sum.FalsePositives++
			sum.Pass = false
			continue
		}
		ok, detail := CheckNegative(ev)
		cr := CaseResult{File: negFiles[i], Name: f.Name, Pass: ok, Detail: detail}
		if ev != nil {
			cr.Verdict = ev.Verdict
			cr.Confidence = ev.ConfidenceContribution
		}
		sum.Cases = append(sum.Cases, cr)
		if ok {
			sum.TrueNegatives++
		} else {
			sum.FalsePositives++
			sum.Pass = false
		}
	}
	tp := float64(sum.TruePositives)
	fp := float64(sum.FalsePositives)
	fn := float64(sum.FalseNegatives)
	if tp+fp > 0 {
		sum.Precision = tp / (tp + fp)
	} else {
		sum.Precision = 1
	}
	if tp+fn > 0 {
		sum.Recall = tp / (tp + fn)
	} else {
		sum.Recall = 1
	}
	return sum, nil
}

func toHeader(m map[string]string) http.Header {
	h := make(http.Header)
	for k, v := range m {
		h.Set(k, v)
	}
	return h
}

func controlLocation(m map[string]string) string {
	for k, v := range m {
		if strings.EqualFold(k, "Location") {
			return v
		}
	}
	return ""
}

func isAbsoluteURL(s string) bool {
	return strings.HasPrefix(strings.ToLower(s), "http://") || strings.HasPrefix(strings.ToLower(s), "https://")
}

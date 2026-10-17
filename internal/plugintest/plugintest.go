// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Module: github.com/Xmar1881/Gash

// Package plugintest provides offline fixture execution for reference plugins.
// What: Loads JSON fixtures and evaluates them through engine-owned oracles.
// Why: Lets `gash plugins test` verify precision without network access while
// keeping the confidence decision inside the oracles, never in the plugin.
package plugintest

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
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
	// OOBCorrelationID and OOBNamespace for OOB fixtures.
	OOBCorrelationID string `json:"oob_correlation_id"`
	OOBNamespace     string `json:"oob_namespace"`
	// DelaySamples and ControlSamples carry timing measurements (ms).
	DelaySamples   []float64 `json:"delay_samples"`
	ControlSamples []float64 `json:"control_samples"`
	BaselineStddev float64   `json:"baseline_stddev"`
	// Canary overrides the default reflection canary.
	Canary string `json:"canary"`
	// StoreStatus and StoreBody model the write exchange of a stored
	// workflow (POST store). Render is Body/Headers/Status. Missing store
	// fields default to an accepted write for backward compatibility.
	StoreStatus int    `json:"store_status"`
	StoreBody   string `json:"store_body"`
	// Origin carries the request Origin for CORS fixtures (empty = passive only).
	Origin string `json:"origin"`
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
	// Dataset is the fixture root this summary was computed from.
	Dataset string
	// DatasetHash pins the exact fixture bytes (sha256 over sorted
	// relpath+content of every *.json under Dataset). Metrics reports
	// quote this hash so numbers stay reproducible and silent fixture
	// edits cannot inflate precision without updating the report.
	DatasetHash string
	// FixtureFiles counts the *.json files hashed into DatasetHash.
	FixtureFiles int
}

// Evaluate runs one fixture through the named oracle.
// What: Oracle dispatcher shared by the CLI and Go gate tests.
// Why: A single dispatcher prevents per-plugin test logic from drifting.
func Evaluate(ctx context.Context, oracleName string, f Fixture, oobEnabled bool, oracleParams map[string]any) (*oracle.Evidence, error) {
	cls := baseline.ClassifyStatic(f.Status, toHeader(f.Headers), []byte(f.Body))
	canary := f.Canary
	if canary == "" {
		canary = DefaultCanary
	}
	switch strings.ToLower(oracleName) {
	case "header":
		var o oracle.HeaderOracle
		mode := getStringParam(oracleParams, "mode", "security")
		var reqHeaders http.Header
		if rh, ok := oracleParams["request_headers"]; ok {
			if rhMap, ok := rh.(map[string]any); ok {
				reqHeaders = make(http.Header)
				for k, v := range rhMap {
					if vs, ok := v.([]any); ok {
						for _, vi := range vs {
							reqHeaders.Add(k, fmt.Sprintf("%v", vi))
						}
					} else {
						reqHeaders.Set(k, fmt.Sprintf("%v", v))
					}
				}
			}
		}
		return o.Verify(ctx, cls, false, oracle.HeaderParams{
			Headers:        toHeader(f.Headers),
			Mode:           mode,
			RequestHeaders: reqHeaders,
			Body:           f.Body,
			Status:         f.Status,
		})
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
		contexts := getStringSliceParam(oracleParams, "contexts")
		if len(contexts) == 0 {
			contexts = []string{"html", "attr", "attr-executable", "script", "url", "url-executable"}
		}
		requireExecutable := true
		if v, ok := oracleParams["require_executable_context"].(bool); ok {
			requireExecutable = v
		}
		return o.Verify(ctx, f.Body, toHeader(f.Headers), cls, false, oracle.ReflectionParams{
			Canary: canary, Contexts: contexts,
			RequireExecutableContext: requireExecutable, ControlBody: ctrl,
		})
	case "error":
		var o oracle.ErrorSignatureOracle
		mode := getStringParam(oracleParams, "mode", "sqli")
		signatureSet := getStringSliceParam(oracleParams, "signature_set")
		return o.Verify(ctx, cls, false, oracle.ErrorSignatureParams{
			Body:         f.Body,
			ControlBody:  f.ControlBody,
			SignatureSet: signatureSet,
			Mode:         mode,
		})
	case "differential":
		var o oracle.DifferentialOracle
		return o.Verify(ctx, cls, false, oracle.DifferentialParams{
			TrueBodies: f.TrueBodies, FalseBodies: f.FalseBodies,
			ControlBody: f.ControlBody, Repeats: 3,
			ConfidenceCeiling: getStringParam(oracleParams, "confidence_ceiling", ""),
		})
	case "oob":
		o := oracle.OOBOracle{Enabled: oobEnabled}
		corrID := f.OOBCorrelationID
		if corrID == "" {
			corrID = "c_fixture"
		}
		ns := f.OOBNamespace
		if ns == "" {
			ns = "scan_fixture"
		}
		return o.Verify(ctx, cls, false, oracle.OOBParams{
			CorrelationID: corrID, Namespace: ns,
			CallbackSeen: f.OOBCallback,
		})
	case "version":
		var o oracle.VersionOracle
		mode := getStringParam(oracleParams, "mode", "banner")
		bannerRegex := getStringParam(oracleParams, "banner_regex", "")
		// For banner mode, include headers in the banner for version detection
		banner := f.Body
		if mode == "banner" {
			var headerParts []string
			for k, v := range f.Headers {
				headerParts = append(headerParts, k+": "+v)
			}
			if len(headerParts) > 0 {
				banner = strings.Join(headerParts, "\n") + "\n\n" + f.Body
			}
		}
		return o.Verify(ctx, cls, false, oracle.VersionParams{
			Banner:      banner,
			BannerRegex: bannerRegex,
			Mode:        mode,
		})
	case "timing":
		var o oracle.TimingOracle
		minDelayMs := getFloat64Param(oracleParams, "min_delay_ms", 5000)
		repeats := getIntParam(oracleParams, "repeats", 3)
		strategy := getStringParam(oracleParams, "strategy", "mann-whitney-u")
		return o.Verify(ctx, cls, false, oracle.TimingParams{
			DelaySamples:   f.DelaySamples,
			ControlSamples: f.ControlSamples,
			BaselineStddev: f.BaselineStddev,
			MinDelayMs:     minDelayMs,
			Repeats:        repeats,
			Strategy:       strategy,
		})
	case "cookie":
		var o oracle.CookieOracle
		return o.Verify(ctx, cls, false, oracle.CookieParams{Headers: toHeader(f.Headers), Target: f.Target})
	case "cors":
		var o oracle.CORSOracle
		requestOrigin := getStringParam(oracleParams, "request_origin", "")
		return o.Verify(ctx, cls, false, oracle.CORSParams{Headers: toHeader(f.Headers), RequestOrigin: requestOrigin})
	case "execution":
		var o oracle.ExecutionOracle
		sink := detectFixtureSink(f.Body)
		if sink == "" {
			return o.Verify(ctx, cls, false, oracle.ExecutionParams{})
		}
		return o.Verify(ctx, cls, false, oracle.ExecutionParams{
			Sink: sink, Source: detectFixtureSource(f.Body),
			HeadlessEnabled: false,
		})
	case "stored", "storedexecution", "stored-execution", "stored_execution":
		var o oracle.StoredOracle
		contexts := getStringSliceParam(oracleParams, "contexts")
		if len(contexts) == 0 {
			contexts = []string{"html", "attr-executable", "script", "url", "url-executable"}
		}
		requireExecutable := true
		if v, ok := oracleParams["require_executable_context"].(bool); ok {
			requireExecutable = v
		}
		storeStatus := f.StoreStatus
		storeBody := f.StoreBody
		if storeStatus == 0 && storeBody == "" {
			storeStatus = 200
			storeBody = "<html><body>stored</body></html>"
		}
		return o.Verify(ctx, cls, false, oracle.StoredParams{
			Canary: canary, Contexts: contexts,
			RequireExecutableContext: requireExecutable,
			StoreStatus:              storeStatus, StoreBody: storeBody,
			RenderBody: f.Body, RenderHeaders: toHeader(f.Headers),
			ControlBody: f.ControlBody,
		})
	default:
		return nil, fmt.Errorf("plugintest: unknown oracle %q", oracleName)
	}
}

func getStringParam(params map[string]any, key, defaultVal string) string {
	if params == nil {
		return defaultVal
	}
	if v, ok := params[key]; ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return defaultVal
}

func getStringSliceParam(params map[string]any, key string) []string {
	if params == nil {
		return nil
	}
	if v, ok := params[key]; ok {
		if arr, ok := v.([]any); ok {
			out := make([]string, len(arr))
			for i, vi := range arr {
				out[i] = fmt.Sprintf("%v", vi)
			}
			return out
		}
	}
	return nil
}

func getFloat64Param(params map[string]any, key string, defaultVal float64) float64 {
	if params == nil {
		return defaultVal
	}
	if v, ok := params[key]; ok {
		switch val := v.(type) {
		case float64:
			return val
		case int:
			return float64(val)
		case int64:
			return float64(val)
		}
	}
	return defaultVal
}

func getIntParam(params map[string]any, key string, defaultVal int) int {
	if params == nil {
		return defaultVal
	}
	if v, ok := params[key]; ok {
		switch val := v.(type) {
		case int:
			return val
		case int64:
			return int(val)
		case float64:
			return int(val)
		}
	}
	return defaultVal
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

// CheckNegative asserts a negative fixture never reaches static evidence or above.
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
	case plugin.ConfidenceStaticExecution, plugin.ConfidenceFirm, plugin.ConfidenceConfirmed:
		return false, fmt.Sprintf("false positive: %s (%s)", ev.ConfidenceContribution, ev.Note)
	default:
		return true, ""
	}
}

// Run executes positive/ and negative/ fixture sets for one oracle.
// What: Full per-plugin fixture run returning a precision/recall summary.
// Why: One entry point serves the CLI, the docs generator, and the CI gate.
func Run(ctx context.Context, pluginID, oracleName, fixtureRoot string, oobEnabled bool, oracleParams map[string]any) (*Summary, error) {
	pos, posFiles, err := LoadDir(filepath.Join(fixtureRoot, "positive"))
	if err != nil {
		return nil, err
	}
	neg, negFiles, err := LoadDir(filepath.Join(fixtureRoot, "negative"))
	if err != nil {
		return nil, err
	}
	sum := &Summary{PluginID: pluginID, Pass: true}
	sum.Dataset = fixtureRoot
	hash, nfiles, herr := hashDataset(fixtureRoot)
	if herr != nil {
		return nil, herr
	}
	sum.DatasetHash = hash
	sum.FixtureFiles = nfiles
	for i, f := range pos {
		ev, err := Evaluate(ctx, oracleName, f, oobEnabled, oracleParams)
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
		ev, err := Evaluate(ctx, oracleName, f, true, oracleParams)
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

// detectFixtureSink mirrors the Tier 2 static sink vocabulary for fixtures.
// What: Same substring list as loader.detectDOMSink (headless-free).
// Why: Fixture evaluation must use the identical static claim as live scans.
func detectFixtureSink(body string) string {
	lower := strings.ToLower(body)
	for _, s := range []string{"innerhtml", "outerhtml", "document.write", "document.writeln", "eval(", "settimeout(", "setinterval(", "location.hash", "postmessage"} {
		if strings.Contains(lower, s) {
			return s
		}
	}
	return ""
}

// detectFixtureSource mirrors the Tier 2 static source vocabulary.
func detectFixtureSource(body string) string {
	lower := strings.ToLower(body)
	for _, s := range []string{"location.hash", "location.search", "location.href", "document.url", "window.name", "postmessage"} {
		if strings.Contains(lower, s) {
			return s
		}
	}
	return ""
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

// hashDataset pins the fixture dataset version (P0.3).
// What: sha256 over sorted relpath+NUL+content of every *.json file.
// Why: Precision/recall numbers are meaningless without the dataset they
// were measured on; the hash makes silent benchmark inflation visible.
func hashDataset(root string) (string, int, error) {
	var rels []string
	err := filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(strings.ToLower(d.Name()), ".json") {
			return nil
		}
		rel, err := filepath.Rel(root, p)
		if err != nil {
			return fmt.Errorf("plugintest rel %s: %w", p, err)
		}
		rels = append(rels, filepath.ToSlash(rel))
		return nil
	})
	if err != nil {
		return "", 0, fmt.Errorf("plugintest hash dataset %s: %w", root, err)
	}
	sort.Strings(rels)
	h := sha256.New()
	for _, rel := range rels {
		data, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(rel)))
		if err != nil {
			return "", 0, fmt.Errorf("plugintest hash read %s: %w", rel, err)
		}
		data = bytes.ReplaceAll(data, []byte("\r\n"), []byte("\n"))
		h.Write([]byte(rel))
		h.Write([]byte{0})
		h.Write(data)
		h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil)), len(rels), nil
}

// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Module: github.com/Xmar1881/Gash

package bench

import (
	"math"
	"testing"
)

func testDataset() *Dataset {
	return &Dataset{
		Name: "test",
		UnscoredPlugins: []string{
			"web-cache-poisoning-basic",
		},
		Targets: []Target{{ID: "x", BaseURL: "http://x"}},
		Scenarios: []Scenario{
			{
				ID: "xss-reflect", Category: "xss-reflected", Expected: ExpectVulnerable,
				Path: "/xss/reflect", XSS: &XSSSpec{Kind: "reflected", Context: "html", ExecutionRequired: true},
				Match: MatchSpec{PluginIDs: []string{"xss-reflected-basic"}},
			},
			{
				ID: "sqli-error", Category: "sqli", Expected: ExpectVulnerable,
				Path: "/sqli/error", Match: MatchSpec{PluginIDs: []string{"sqli-error-based"}},
			},
			{
				ID: "clean-page", Category: "clean", Expected: ExpectClean,
				Path: "/clean",
			},
			{
				ID: "denied-secret", Category: "auth", Expected: ExpectDenied,
				Path: "/auth/secret",
			},
		},
	}
}

func verifiedAll(ds *Dataset) map[string]Verification {
	v := map[string]Verification{}
	for _, sc := range ds.Scenarios {
		v[sc.ID] = Verification{Kind: sc.Verify.Kind, Verified: true}
	}
	return v
}

func TestBuildOutcomesScoring(t *testing.T) {
	ds := testDataset()
	findings := []NormalizedFinding{
		{PluginID: "xss-reflected-basic", Target: "http://x/y", Path: "/xss/reflect", EvidenceType: "static-execution-evidence"},
		{PluginID: "sqli-error-based", Target: "http://x/y", Path: "/sqli/error", EvidenceType: "firm"},
		{PluginID: "web-cache-poisoning-basic", Target: "http://x/y", Path: "/xss/reflect"},
		{PluginID: "clickjacking", Target: "http://x/y", Path: "/somewhere-else"},
	}
	outcomes, unmatched, excluded := BuildOutcomes(ds, "gash", true, findings, verifiedAll(ds))

	byID := map[string]Outcome{}
	for _, o := range outcomes {
		byID[o.Scenario] = o
	}
	if got := byID["xss-reflect"].Status; got != StatusWeak {
		t.Fatalf("xss without browser confirmation must be weak, got %s", got)
	}
	if got := byID["sqli-error"].Status; got != StatusTP {
		t.Fatalf("sqli must be tp, got %s", got)
	}
	if got := byID["clean-page"].Status; got != StatusTN {
		t.Fatalf("clean must be tn, got %s", got)
	}
	if got := byID["denied-secret"].Status; got != StatusTN {
		t.Fatalf("denied must be tn, got %s", got)
	}
	if len(unmatched) != 1 || unmatched[0].PluginID != "clickjacking" {
		t.Fatalf("unmatched wrong: %+v", unmatched)
	}
	if len(excluded) != 1 || excluded[0].PluginID != "web-cache-poisoning-basic" {
		t.Fatalf("excluded wrong: %+v", excluded)
	}

	score := ScoreOutcomes(outcomes)
	if score.TP != 1 || score.Weak != 1 || score.TN != 2 || score.FP != 0 || score.FN != 0 {
		t.Fatalf("score wrong: %+v", score)
	}
	if score.Precision == nil || *score.Precision != 1 {
		t.Fatalf("precision wrong: %v", score.Precision)
	}
	if score.Recall == nil || math.Abs(*score.Recall-0.5) > 1e-9 {
		t.Fatalf("weak evidence must count against recall: %v", score.Recall)
	}
}

func TestBrowserConfirmedUpgradesXSS(t *testing.T) {
	ds := testDataset()
	findings := []NormalizedFinding{
		{PluginID: "xss-reflected-basic", Path: "/xss/reflect", EvidenceType: "browser-confirmed"},
	}
	outcomes, _, _ := BuildOutcomes(ds, "gash", true, findings, verifiedAll(ds))
	score := ScoreOutcomes(outcomes)
	if score.TP != 1 || score.Confirmed != 1 || score.Weak != 0 {
		t.Fatalf("browser-confirmed must be confirmed tp: %+v", score)
	}
}

func TestUnavailableToolIsNotRun(t *testing.T) {
	ds := testDataset()
	outcomes, _, _ := BuildOutcomes(ds, "nuclei", false, nil, verifiedAll(ds))
	score := ScoreOutcomes(outcomes)
	if score.NotRun != len(ds.Scenarios) || score.TP != 0 {
		t.Fatalf("unavailable tool must be not-run, got %+v", score)
	}
	if score.Precision != nil || score.Recall != nil {
		t.Fatal("not-run tool must not fabricate precision/recall")
	}
}

func TestUnverifiedScenarioIsExcludedFromScoring(t *testing.T) {
	ds := testDataset()
	v := verifiedAll(ds)
	v["clean-page"] = Verification{Verified: false, Error: "lab unreachable"}
	outcomes, _, _ := BuildOutcomes(ds, "gash", true, nil, v)
	score := ScoreOutcomes(outcomes)
	if score.Unverified != 1 {
		t.Fatalf("unverified scenario must be tracked: %+v", score)
	}
	if score.TN != 1 {
		t.Fatalf("only the verified clean scenario may count as tn: %+v", score)
	}
}

func TestBlockedErrorAndUnverifiedStayOutOfDenominators(t *testing.T) {
	ds := testDataset()
	v := verifiedAll(ds)
	v["sqli-error"] = Verification{Verified: false, Error: "browser verification blocked: reason=payload_forbidden"}
	v["clean-page"] = Verification{Verified: false, Error: "browser verification error: reason=payload_server_error"}
	v["denied-secret"] = Verification{Verified: false, Error: "lab unreachable"}
	findings := []NormalizedFinding{
		{PluginID: "sqli-error-based", Path: "/sqli/error", EvidenceType: "firm"},
		{PluginID: "xss-reflected-basic", Path: "/xss/reflect", EvidenceType: "browser-confirmed"},
	}
	outcomes, _, _ := BuildOutcomes(ds, "gash", true, findings, v)
	score := ScoreOutcomes(outcomes)
	if score.TP != 1 || score.Confirmed != 1 {
		t.Fatalf("only the verified confirmed XSS may score: %+v", score)
	}
	if score.FN != 0 || score.TN != 0 || score.FP != 0 || score.Weak != 0 {
		t.Fatalf("blocked/error/unverified must not become FN/TN/FP/Weak: %+v", score)
	}
	if score.Unverified != 3 {
		t.Fatalf("all three blocked/error/unverified scenarios must be tracked: %+v", score)
	}
	if score.Recall == nil || *score.Recall != 1 {
		t.Fatalf("recall denominator must contain only the scored vulnerable scenario: %v", score.Recall)
	}
	if score.Precision == nil || *score.Precision != 1 {
		t.Fatalf("precision denominator must not include unverified findings: %v", score.Precision)
	}
}

func TestNormalizePathHashRoute(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{in: "http://juice/#/search?q=apple", want: "/search"},
		{in: "http://juice/#/search", want: "/search"},
		{in: "http://juice/#/", want: "/"},
		{in: "http://juice/app#/search?q=apple", want: "/app/search"},
		{in: "http://juice/app#section", want: "/app"},
		{in: "http://juice/app?x=1", want: "/app"},
	}
	for _, tc := range tests {
		if got := normalizePath(tc.in); got != tc.want {
			t.Fatalf("normalizePath(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestDedupeNormalizedFindingsKeepsStrongest(t *testing.T) {
	in := []NormalizedFinding{
		{Tool: "gash", Target: "http://x", Path: "/a", Auth: "a", PluginID: "p", Fingerprint: "fp", Confidence: "tentative"},
		{Tool: "gash", Target: "http://x", Path: "/a", Auth: "b", PluginID: "p", Fingerprint: "fp", Confidence: "confirmed"},
		{Tool: "gash", Target: "http://x", Path: "/a", Auth: "b", PluginID: "other", Fingerprint: "fp2", Confidence: "firm"},
	}
	got := DedupeNormalizedFindings(in)
	if len(got) != 2 {
		t.Fatalf("dedupe = %d findings, want 2: %+v", len(got), got)
	}
	if got[0].Confidence != "confirmed" {
		t.Fatalf("strongest duplicate must win: %+v", got[0])
	}
	if got[1].PluginID != "other" {
		t.Fatalf("different plugin must remain distinct: %+v", got[1])
	}
}

func TestMatchFindingTags(t *testing.T) {
	ds := testDataset()
	ds.Scenarios[0].Match = MatchSpec{NucleiTags: []string{"xss", "reflected"}}
	sc := &ds.Scenarios[0]
	if !matchFinding(ds, NormalizedFinding{Path: "/xss/reflect", Tags: []string{"reflected"}}, sc, "nuclei") {
		t.Fatal("nuclei tag match failed")
	}
	if matchFinding(ds, NormalizedFinding{Path: "/xss/reflect", Tags: []string{"sqli"}}, sc, "nuclei") {
		t.Fatal("nuclei wrong tag must not match")
	}
	if !matchFinding(ds, NormalizedFinding{Path: "/xss/reflect", PluginID: "xss-reflected-basic"}, sc, "gash") {
		t.Fatal("gash plugin match failed")
	}
}

func TestBuildCrossToolVerdicts(t *testing.T) {
	outcomes := map[string][]Outcome{
		"gash": {
			{Scenario: "a", Category: "x", Expected: ExpectVulnerable, Status: StatusTP},
			{Scenario: "b", Category: "x", Expected: ExpectVulnerable, Status: StatusFN},
			{Scenario: "c", Category: "x", Expected: ExpectClean, Status: StatusTN},
		},
		"nuclei": {
			{Scenario: "a", Category: "x", Expected: ExpectVulnerable, Status: StatusFN},
			{Scenario: "b", Category: "x", Expected: ExpectVulnerable, Status: StatusTP},
			{Scenario: "c", Category: "x", Expected: ExpectClean, Status: StatusFP},
		},
	}
	rows := BuildCrossTool(outcomes)
	got := map[string]string{}
	for _, r := range rows {
		got[r.Scenario] = r.Verdict
	}
	if got["a"] != "gash-only" || got["b"] != "nuclei-only" || got["c"] != "neither" {
		t.Fatalf("cross verdicts wrong: %+v", got)
	}
}

func TestCrossToolSingleTool(t *testing.T) {
	outcomes := map[string][]Outcome{
		"gash":   {{Scenario: "a", Category: "x", Expected: ExpectVulnerable, Status: StatusTP}},
		"nuclei": {{Scenario: "a", Category: "x", Expected: ExpectVulnerable, Status: StatusNotRun}},
	}
	rows := BuildCrossTool(outcomes)
	if len(rows) != 1 || rows[0].Verdict != "single-tool" {
		t.Fatalf("unavailable nuclei must yield single-tool: %+v", rows)
	}
}

func TestMatchFindingRejectsOtherOrigin(t *testing.T) {
	ds := testDataset()
	ds.Targets = []Target{
		{ID: "dvwa", BaseURL: "http://127.0.0.1:8081"},
		{ID: "juice", BaseURL: "http://127.0.0.1:8082"},
	}
	ds.Scenarios = []Scenario{{
		ID: "juice-phpinfo", TargetID: "juice", Path: "/phpinfo.php", Expected: ExpectClean,
	}}
	sc := &ds.Scenarios[0]
	if matchFinding(ds, NormalizedFinding{Target: "http://127.0.0.1:8081/phpinfo.php", Path: "/phpinfo.php"}, sc, "gash") {
		t.Fatal("finding from another target origin must not match")
	}
	if !matchFinding(ds, NormalizedFinding{Target: "http://127.0.0.1:8082/phpinfo.php", Path: "/phpinfo.php"}, sc, "gash") {
		t.Fatal("finding on the scenario origin must match")
	}
}

func TestMatchFindingTrailingSlash(t *testing.T) {
	ds := testDataset()
	ds.Scenarios[0].Path = "/vulnerabilities/sqli/?id=1&Submit=Submit"
	ds.Scenarios[0].Match = MatchSpec{PluginIDs: []string{"sqli-error-based"}}
	sc := &ds.Scenarios[0]
	if !matchFinding(ds, NormalizedFinding{Path: "/vulnerabilities/sqli", PluginID: "sqli-error-based"}, sc, "gash") {
		t.Fatal("trailing-slash path mismatch must not hide a finding")
	}
	if got := normalizePath("http://127.0.0.1:8081/vulnerabilities/xss_r/?name=hello"); got != "/vulnerabilities/xss_r" {
		t.Fatalf("normalizePath = %q", got)
	}
	if got := normalizePath("http://127.0.0.1:8081/"); got != "/" {
		t.Fatalf("root normalizePath = %q", got)
	}
}

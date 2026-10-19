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

func TestMatchFindingTags(t *testing.T) {
	ds := testDataset()
	ds.Scenarios[0].Match = MatchSpec{NucleiTags: []string{"xss", "reflected"}}
	sc := &ds.Scenarios[0]
	if !matchFinding(NormalizedFinding{Path: "/xss/reflect", Tags: []string{"reflected"}}, sc, "nuclei") {
		t.Fatal("nuclei tag match failed")
	}
	if matchFinding(NormalizedFinding{Path: "/xss/reflect", Tags: []string{"sqli"}}, sc, "nuclei") {
		t.Fatal("nuclei wrong tag must not match")
	}
	if !matchFinding(NormalizedFinding{Path: "/xss/reflect", PluginID: "xss-reflected-basic"}, sc, "gash") {
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

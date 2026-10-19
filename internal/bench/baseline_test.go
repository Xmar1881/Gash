// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Module: github.com/Xmar1881/Gash

package bench

import (
	"testing"
)

func f64(v float64) *float64 { return &v }
func i64(v int64) *int64     { return &v }

func baseBaseline() *Baseline {
	return &Baseline{
		SchemaVersion: ReportSchemaVersion,
		Tool:          "gash",
		Dataset:       "fixtures",
		DatasetSHA256: "abc",
		Score:         Score{TP: 10, FP: 0, TN: 8, FN: 2, Precision: f64(1.0), Recall: f64(10.0 / 12.0)},
		ByCategory: map[string]Score{
			"xss-reflected": {TP: 5, Precision: f64(1.0), Recall: f64(1.0)},
		},
		Requests:   i64(4000),
		DurationMS: 100000,
	}
}

func TestCompareBaselineCleanPass(t *testing.T) {
	base := baseBaseline()
	cur := baseBaseline()
	cur.Score = Score{TP: 10, FP: 0, TN: 8, FN: 2, Precision: f64(1.0), Recall: f64(10.0 / 12.0)}
	res := CompareBaseline(base, cur, DefaultGateThresholds())
	if !res.Passed {
		t.Fatalf("identical run must pass: %+v", res.Reasons)
	}
}

func TestCompareBaselinePrecisionDropFails(t *testing.T) {
	base := baseBaseline()
	cur := baseBaseline()
	cur.Score = Score{TP: 10, FP: 3, TN: 8, FN: 2, Precision: f64(10.0 / 13.0), Recall: f64(10.0 / 12.0)}
	res := CompareBaseline(base, cur, DefaultGateThresholds())
	if res.Passed {
		t.Fatal("precision drop must fail the gate")
	}
}

func TestCompareBaselineRecallDropFails(t *testing.T) {
	base := baseBaseline()
	cur := baseBaseline()
	cur.Score = Score{TP: 9, FP: 0, TN: 8, FN: 3, Precision: f64(1.0), Recall: f64(9.0 / 12.0)}
	res := CompareBaseline(base, cur, DefaultGateThresholds())
	if res.Passed {
		t.Fatal("recall drop must fail the gate")
	}
}

func TestCompareBaselineCategoryRecallDropFails(t *testing.T) {
	base := baseBaseline()
	cur := baseBaseline()
	cur.ByCategory = map[string]Score{
		"xss-reflected": {TP: 4, Precision: f64(1.0), Recall: f64(0.8)},
	}
	res := CompareBaseline(base, cur, DefaultGateThresholds())
	if res.Passed {
		t.Fatal("category recall drop must fail the gate")
	}
}

func TestCompareBaselineRequestAndDurationBudgets(t *testing.T) {
	base := baseBaseline()
	cur := baseBaseline()
	cur.Requests = i64(6000)
	res := CompareBaseline(base, cur, DefaultGateThresholds())
	if res.Passed {
		t.Fatal("+50% requests must fail the gate")
	}
	cur = baseBaseline()
	cur.DurationMS = 200000
	res = CompareBaseline(base, cur, DefaultGateThresholds())
	if res.Passed {
		t.Fatal("+100% duration must fail the gate")
	}
	cur = baseBaseline()
	cur.Requests = i64(4500)
	cur.DurationMS = 140000
	res = CompareBaseline(base, cur, DefaultGateThresholds())
	if !res.Passed {
		t.Fatalf("within-budget drift must pass: %+v", res.Reasons)
	}
}

func TestCompareBaselineDatasetChangeIsReported(t *testing.T) {
	base := baseBaseline()
	cur := baseBaseline()
	cur.DatasetSHA256 = "different"
	res := CompareBaseline(base, cur, DefaultGateThresholds())
	if res.Passed {
		t.Fatal("dataset change must fail comparability")
	}
}

func TestCompareBaselineRecallComputabilityChange(t *testing.T) {
	base := baseBaseline()
	cur := baseBaseline()
	cur.Score.Recall = nil
	res := CompareBaseline(base, cur, DefaultGateThresholds())
	if res.Passed {
		t.Fatal("recall becoming unmeasurable is a regression")
	}
}

func TestBaselineRoundTripThroughReport(t *testing.T) {
	rep := &Report{
		SchemaVersion: ReportSchemaVersion,
		Dataset:       DatasetSummary{Name: "fixtures", SHA256: "abc"},
		GeneratedAt:   "2026-01-01T00:00:00Z",
		Tools: map[string]*ToolResult{
			"gash": {
				Available: true,
				Score:     Score{TP: 5, FP: 0, Precision: f64(1.0), Recall: f64(0.5)},
			},
		},
	}
	b, err := BaselineFromReport(rep, "gash")
	if err != nil {
		t.Fatal(err)
	}
	if b.Dataset != "fixtures" || b.Score.TP != 5 {
		t.Fatalf("baseline extraction wrong: %+v", b)
	}
	if _, err := BaselineFromReport(rep, "nuclei"); err == nil {
		t.Fatal("missing tool must be an error")
	}
}

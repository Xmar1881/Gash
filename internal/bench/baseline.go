// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Module: github.com/Xmar1881/Gash

package bench

import (
	"encoding/json"
	"fmt"
	"os"
)

// Baseline is the compact regression reference persisted between runs.
type Baseline struct {
	SchemaVersion string           `json:"schema_version"`
	Tool          string           `json:"tool"`
	Dataset       string           `json:"dataset"`
	DatasetSHA256 string           `json:"dataset_sha256"`
	GeneratedAt   string           `json:"generated_at"`
	Score         Score            `json:"score"`
	ByCategory    map[string]Score `json:"by_category,omitempty"`
	Requests      *int64           `json:"requests,omitempty"`
	DurationMS    int64            `json:"duration_ms"`
}

// GateThresholds controls the regression gate.
type GateThresholds struct {
	MinPrecision        float64
	MaxRecallDrop       float64
	MaxRequestIncrease  float64
	MaxDurationIncrease float64
}

// DefaultGateThresholds is the CI gate: no critical recall loss, no precision
// drop below 0.99, at most +25% requests and +50% wall-clock.
func DefaultGateThresholds() GateThresholds {
	return GateThresholds{MinPrecision: 0.99, MaxRecallDrop: 0, MaxRequestIncrease: 0.25, MaxDurationIncrease: 0.5}
}

// GateDelta is one before/after metric comparison.
type GateDelta struct {
	Metric string `json:"metric"`
	Before string `json:"before"`
	After  string `json:"after"`
}

// GateResult is the regression gate verdict.
type GateResult struct {
	Passed  bool        `json:"passed"`
	Reasons []string    `json:"reasons,omitempty"`
	Deltas  []GateDelta `json:"deltas,omitempty"`
}

// BaselineFromReport extracts a baseline for one tool from a full report.
func BaselineFromReport(r *Report, tool string) (*Baseline, error) {
	res, ok := r.Tools[tool]
	if !ok || res == nil {
		return nil, fmt.Errorf("bench baseline: report has no tool %q", tool)
	}
	if !res.Available {
		return nil, fmt.Errorf("bench baseline: tool %q was unavailable (%s)", tool, res.Reason)
	}
	return &Baseline{
		SchemaVersion: ReportSchemaVersion,
		Tool:          tool,
		Dataset:       r.Dataset.Name,
		DatasetSHA256: r.Dataset.SHA256,
		GeneratedAt:   r.GeneratedAt,
		Score:         res.Score,
		ByCategory:    res.ByCategory,
		Requests:      res.ReportedRequests,
		DurationMS:    res.DurationMS,
	}, nil
}

// LoadBaseline loads a baseline file; a full report.json is also accepted and
// reduced to its gash tool section.
func LoadBaseline(path string) (*Baseline, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("bench baseline: read %s: %w", path, err)
	}
	var b Baseline
	if err := json.Unmarshal(raw, &b); err == nil && b.SchemaVersion == ReportSchemaVersion && b.Tool != "" {
		return &b, nil
	}
	var rep Report
	if err := json.Unmarshal(raw, &rep); err != nil {
		return nil, fmt.Errorf("bench baseline: %s is neither a baseline nor a report: %w", path, err)
	}
	return BaselineFromReport(&rep, "gash")
}

// CompareBaseline evaluates the regression gate.
func CompareBaseline(base, cur *Baseline, th GateThresholds) GateResult {
	var res GateResult
	if base == nil || cur == nil {
		res.Passed = false
		res.Reasons = append(res.Reasons, "missing baseline or current result")
		return res
	}
	if base.DatasetSHA256 != "" && cur.DatasetSHA256 != "" && base.DatasetSHA256 != cur.DatasetSHA256 {
		res.Reasons = append(res.Reasons, "dataset changed between baseline and current run; deltas are not comparable")
	}

	prec := 1.0
	if cur.Score.Precision != nil {
		prec = *cur.Score.Precision
	}
	res.Deltas = append(res.Deltas, GateDelta{Metric: "precision", Before: fmtRatio(base.Score.Precision), After: fmtRatio(cur.Score.Precision)})
	if cur.Score.Precision != nil && prec < th.MinPrecision {
		res.Reasons = append(res.Reasons, fmt.Sprintf("precision %.3f below minimum %.3f (more false positives)", prec, th.MinPrecision))
	}

	recallDelta := 0.0
	if base.Score.Recall != nil && cur.Score.Recall != nil {
		recallDelta = *cur.Score.Recall - *base.Score.Recall
	} else if base.Score.Recall == nil && cur.Score.Recall != nil {
		recallDelta = *cur.Score.Recall
	} else if base.Score.Recall != nil && cur.Score.Recall == nil {
		recallDelta = -*base.Score.Recall
	}
	res.Deltas = append(res.Deltas, GateDelta{Metric: "recall", Before: fmtRatio(base.Score.Recall), After: fmtRatio(cur.Score.Recall)})
	if base.Score.Recall != nil && cur.Score.Recall == nil {
		res.Reasons = append(res.Reasons, "recall is no longer measurable (no scored positive scenarios); treated as a regression")
	} else if base.Score.Recall != nil && cur.Score.Recall != nil && recallDelta < -th.MaxRecallDrop {
		res.Reasons = append(res.Reasons, fmt.Sprintf("recall dropped by %.3f (critical detector regression)", -recallDelta))
	}
	for _, cat := range sortedScoreKeys(base.ByCategory) {
		b, c := base.ByCategory[cat], cur.ByCategory[cat]
		if b.Recall != nil && c.Recall != nil && *c.Recall < *b.Recall {
			res.Reasons = append(res.Reasons, fmt.Sprintf("category %s recall dropped %.3f -> %.3f", cat, *b.Recall, *c.Recall))
		}
	}

	if base.Requests != nil && cur.Requests != nil && *base.Requests > 0 {
		increase := float64(*cur.Requests-*base.Requests) / float64(*base.Requests)
		res.Deltas = append(res.Deltas, GateDelta{Metric: "requests", Before: fmt.Sprintf("%d", *base.Requests), After: fmt.Sprintf("%d", *cur.Requests)})
		if increase > th.MaxRequestIncrease {
			res.Reasons = append(res.Reasons, fmt.Sprintf("HTTP request count increased %.0f%% (budget drift)", increase*100))
		}
	}
	if base.DurationMS > 0 {
		increase := float64(cur.DurationMS-base.DurationMS) / float64(base.DurationMS)
		res.Deltas = append(res.Deltas, GateDelta{Metric: "duration_ms", Before: fmt.Sprintf("%d", base.DurationMS), After: fmt.Sprintf("%d", cur.DurationMS)})
		if increase > th.MaxDurationIncrease {
			res.Reasons = append(res.Reasons, fmt.Sprintf("scan duration increased %.0f%%", increase*100))
		}
	}
	res.Passed = len(res.Reasons) == 0
	if res.Passed {
		res.Reasons = append(res.Reasons, "no regression detected against baseline")
	}
	return res
}

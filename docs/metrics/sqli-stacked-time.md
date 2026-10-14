<!--
SPDX-License-Identifier: AGPL-3.0-only
Copyright (C) 2026 Xmar1881 / GASH contributors
Module: github.com/Xmar1881/Gash

File: docs/metrics/sqli-stacked-time.md
What: Precision and recall report for the stacked-query time-based SQLi plugin.
Why: Proves a second-statement WAITFOR DELAY is distinguished from jitter by
the same Mann-Whitney U discipline as single-query time-based SQLi.
-->

# Metrics: sqli-stacked-time

## Overview

Tier 1 active plugin. Oracle `timing`. Payload stacks a second statement
(`1; WAITFOR DELAY '0:0:6'--`, MSSQL). Statistical delay analysis via
Mann-Whitney U with baseline jitter control. Maximum confidence `firm`
(no `confirmed` without OOB). Tier 1 is used deliberately: the JS sandbox
exposes no timing binding, so YAML is the audited path.

## Evidence Standard

Rule GASH-006/010. Requires N≥3 repeats, median delay ≥ 5s (configurable),
and statistical significance (z > 1.645). Baseline jitter must not explain
divergence (median diff > 3×stddev). WAF/block pages classify `Untrusted`
and always reject.

## Fixtures

- Positive: 2 of 2 accepted (`firm`: 5s and 6s stacked delays, low jitter).
- Negative: 2 of 2 rejected (no delay, delay explained by control jitter).
- Command: `go run ./cmd/gash plugins test plugins/sqli/sqli-stacked-time.yaml`

## Corpus Result

Oracle `timing` evaluated against clean, SPA, WAF, encoded, and dynamic
bodies. `firm` plus findings: 0. WAF body correctly rejects as untrusted.

## Lab Result

Procedure: serve a stacked-query vulnerable endpoint, scan with
`--active --deep`, expect one high severity finding at `firm`.
Status: pending manual run (see `docs/metrics/lab-aggressive-*.md` when the
localhost lab lands). Expected Precision 100 percent on this vulnerability class.

## Precision

True positives 2, false positives 0. Precision 1.00.

## Recall

True positives 2, false negatives 0. Recall 1.00.

## Gate Verdict

PASS. Precision 1.00 is above the 0.99 gate. Corpus holds 0 `firm` plus.

## Dataset

- Dataset hash: `3efd96d975794406592353f95e12313b20bb7c688698891f82ea5efe8d48b373`
  (sha256 over all 4 fixture files under `tests/fixtures/sqli-stacked-time/`).
- Samples: TP=2, FP=0, TN=2, FN=0. Fixture-only measurement; lab pending above.
  `TestMetricGate` fails the build if this hash drifts from the fixtures.

<!--
SPDX-License-Identifier: AGPL-3.0-only
Copyright (C) 2026 Xmar1881 / GASH contributors
Module: github.com/Xmar1881/Gash

File: docs/metrics/sqli-time-based.md
What: Precision and recall report for the time-based SQLi reference plugin.
Why: Proves Tier 1 timing oracle meets statistical rigor (Mann-Whitney U + baseline control).
-->

# Metrics: sqli-time-based

## Overview

Tier 1 active plugin. Oracle `timing`. Statistical delay analysis via Mann-Whitney U test
with baseline standard deviation control. Maximum confidence `firm` (no `confirmed` without OOB).

## Evidence Standard

Rule GASH-006/010. Requires N≥3 repeats, median delay ≥ 5s (configurable), and
statistical significance (z > 1.645). Baseline jitter must not explain divergence
(median diff > 3×stddev). WAF/block pages classify `Untrusted` and always reject.

## Fixtures

- Positive: 2 of 2 accepted (`firm`).
- Negative: 2 of 2 rejected (no delay, high control jitter).
- Command: `go run ./cmd/gash plugins test plugins/sqli-time-based/sqli-time-based.yaml`

## Corpus Result

Oracle `timing` evaluated against clean, SPA, WAF, encoded, and dynamic bodies.
`firm` plus findings: 0. WAF body correctly rejects as untrusted.

## Lab Result

Procedure: serve a time-based SQLi vulnerable endpoint, scan with payload
`1' WAITFOR DELAY '0:0:6'--`, expect one high severity finding at `firm`.
Status: pending manual run. Expected Precision 100 percent on this vulnerability class.

## Precision

True positives 2, false positives 0. Precision 1.00.

## Recall

True positives 2, false negatives 0. Recall 1.00.

## Gate Verdict

PASS. Precision 1.00 is above the 0.99 gate. Corpus holds 0 `firm` plus.

## Dataset

- Dataset hash: `f9e39e28fe73b6009906f4809cde0476542c8a1c60a892e3aca16745790efb1d`
  (sha256 over all 4 fixture files under `tests/fixtures/sqli-time-based/`).
- Samples: TP=2, FP=0, TN=2, FN=0. Fixture-only measurement; lab pending above.
  `TestMetricGate` fails the build if this hash drifts from the fixtures.

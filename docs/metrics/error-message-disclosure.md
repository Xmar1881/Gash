<!--
SPDX-License-Identifier: AGPL-3.0-only
Copyright (C) 2026 Xmar1881 / GASH contributors
Module: github.com/Xmar1881/Gash

File: docs/metrics/error-message-disclosure.md
What: Precision and recall report for the error message disclosure reference plugin.
Why: Proves Tier 1 passive error disclosure detection meets the 99 percent precision gate.
-->

# Metrics: error-message-disclosure

## Overview

Tier 1 passive plugin. Oracle `error` (mode: `generic_error`). Detects verbose error messages and stack traces in HTTP responses.

## Evidence Standard

Rule GASH-004 extended. Generic error signatures without control yield `firm`. With control absence, `confirmed`.

## Fixtures

- Positive: 2 of 2 accepted (1 `firm`, 1 `confirmed` with control).
- Negative: 2 of 2 rejected.
- Command: `go run ./cmd/gash plugins test plugins/error-disclosure/error-message-disclosure.yaml`

## Corpus Result

Oracle `error` (generic_error mode) evaluated against clean, SPA, WAF, encoded, and dynamic bodies.
`firm` plus findings: 0. WAF body correctly rejects as untrusted.

## Lab Result

Procedure: serve a test target with debug error page, scan, expect one medium severity finding.
Status: pending manual run. Expected Precision 100 percent on this page class.

## Precision

True positives 2, false positives 0. Precision 1.00.

## Recall

True positives 2, false negatives 0. Recall 1.00.

## Gate Verdict

PASS. Precision 1.00 is above the 0.99 gate. Corpus holds 0 `firm` plus.

## Dataset

- Dataset hash: `65b4bd0047d10d128f0fe86f5e791ee7aa1de4b73dbb6ec1d499afcccdfeb352`
  (sha256 over all 4 fixture files under `tests/fixtures/error-message-disclosure/`).
- Samples: TP=2, FP=0, TN=2, FN=0. Fixture-only measurement; lab pending above.
  `TestMetricGate` fails the build if this hash drifts from the fixtures.

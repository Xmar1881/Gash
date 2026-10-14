<!--
SPDX-License-Identifier: AGPL-3.0-only
Copyright (C) 2026 Xmar1881 / GASH contributors
Module: github.com/Xmar1881/Gash

File: docs/metrics/jwt-token-exposure.md
What: Precision and recall report for the JWT token exposure reference plugin.
Why: Proves Tier 1 passive JWT detection meets the 99 percent precision gate.
-->

# Metrics: jwt-token-exposure

## Overview

Tier 1 passive plugin. Oracle `header` (mode: `jwt`). Detects JWT tokens in HTTP response headers and cookies.

## Evidence Standard

Rule GASH-019 extended. JWT detection is logic based, needs no control request, never emits `tentative`.

## Fixtures

- Positive: 2 of 2 accepted (`confirmed`).
- Negative: 2 of 2 rejected.
- Command: `go run ./cmd/gash plugins test plugins/jwt-exposure/jwt-token-exposure.yaml`

## Corpus Result

Oracle `header` (jwt mode) evaluated against clean, SPA, WAF, encoded, and dynamic bodies.
`firm` plus findings: 0. WAF body correctly rejects as untrusted.

## Lab Result

Procedure: serve a test target with JWT in headers, scan, expect one high severity finding.
Status: pending manual run. Expected Precision 100 percent on this page class.

## Precision

True positives 2, false positives 0. Precision 1.00.

## Recall

True positives 2, false negatives 0. Recall 1.00.

## Gate Verdict

PASS. Precision 1.00 is above the 0.99 gate. Corpus holds 0 `firm` plus.

## Dataset

- Dataset hash: `b2e72eaf9a8cfa360f8ff0ba5c2d8b3b8b2306a57f61af4923c851ff3833dd35`
  (sha256 over all 4 fixture files under `tests/fixtures/jwt-token-exposure/`).
- Samples: TP=2, FP=0, TN=2, FN=0. Fixture-only measurement; lab pending above.
  `TestMetricGate` fails the build if this hash drifts from the fixtures.

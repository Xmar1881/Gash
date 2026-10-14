<!--
SPDX-License-Identifier: AGPL-3.0-only
Copyright (C) 2026 Xmar1881 / GASH contributors
Module: github.com/Xmar1881/Gash

File: docs/metrics/crlf-header-injection.md
What: Precision and recall report for the CRLF header injection reference plugin.
Why: Proves Tier 1 passive CRLF detection meets the 99 percent precision gate.
-->

# Metrics: crlf-header-injection

## Overview

Tier 1 passive plugin. Oracle `header` (mode: `crlf`). Detects CRLF injection in HTTP response headers.

## Evidence Standard

Rule GASH-019 extended. Header checks are logic based, need no control request. CRLF mode detects CR/LF control characters in response headers.

## Fixtures

- Positive: 2 of 2 accepted (`confirmed`).
- Negative: 2 of 2 rejected.
- Command: `go run ./cmd/gash plugins test plugins/crlf/crlf-header-injection.yaml`

## Corpus Result

Oracle `header` (crlf mode) evaluated against clean, SPA, WAF, encoded, and dynamic bodies.
`firm` plus findings: 0. WAF body correctly rejects as untrusted.

## Lab Result

Procedure: serve a test target with CRLF in headers, scan, expect one medium severity finding.
Status: pending manual run. Expected Precision 100 percent on this page class.

## Precision

True positives 2, false positives 0. Precision 1.00.

## Recall

True positives 2, false negatives 0. Recall 1.00.

## Gate Verdict

PASS. Precision 1.00 is above the 0.99 gate. Corpus holds 0 `firm` plus.

## Dataset

- Dataset hash: `5dd689ff9c5abd7ff0ff07791621008567bc375271f96fb3ad0989f6321db658`
  (sha256 over all 4 fixture files under `tests/fixtures/crlf-header-injection/`).
- Samples: TP=2, FP=0, TN=2, FN=0. Fixture-only measurement; lab pending above.
  `TestMetricGate` fails the build if this hash drifts from the fixtures.

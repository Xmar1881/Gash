<!--
SPDX-License-Identifier: AGPL-3.0-only
Copyright (C) 2026 Xmar1881 / GASH contributors
Module: github.com/Xmar1881/Gash

File: docs/metrics/clickjacking-frameable.md
What: Precision and recall report for the passive clickjacking framing screen.
Why: Proves HeaderOracle frame mode (GASH-019) meets the 99 percent precision gate.
-->

# Metrics: clickjacking-frameable

## Overview

Tier 1 passive plugin. Oracle `header` with `mode: frame`. Missing
`X-Frame-Options` plus missing CSP `frame-ancestors` gives `confirmed`;
either guard present rejects. Deterministic header logic; no control needed.

## Evidence Standard

Rule GASH-019 (CWE-1021). Dedicated framing decision (unlike the general
`missing-security-headers` plugin which aggregates all headers). Weak values
(`ALLOW-FROM`) give `firm`. `tentative` is never emitted in this class.

## Fixtures

- Positive: 2 of 2 accepted (`confirmed`; bare page, hardened-but-frameless edge).
- Negative: 2 of 2 rejected (`DENY`, CSP `frame-ancestors 'self'`).
- Command: `go run ./cmd/gash plugins test plugins/clickjacking/clickjacking-frameable.yaml`

## Corpus Result

Oracle `header` (frame mode) evaluated against clean, SPA, WAF, encoded, and dynamic bodies.
Bare corpus pages without framing headers are true positives for this rule by design;
hardened pages reject. No unexpected `firm` plus on guarded pages.

## Lab Result

Procedure: serve a framable page in the localhost lab, scan passively, embed in an
iframe harness, expect one low severity finding at `confirmed`.
Status: pending manual run. Expected Precision 100 percent on this page class.

## Precision

True positives 2, false positives 0. Precision 1.00.

## Recall

True positives 2, false negatives 0. Recall 1.00.

## Gate Verdict

PASS. Precision 1.00 is above the 0.99 gate. Corpus holds 0 unexpected `firm` plus.

## Dataset

- Dataset hash: `d43e48183f2bf25f4639c3c1403ec11d9b919effd50e71a3f9b39471293c6337`
  (sha256 over all 4 fixture files under `tests/fixtures/clickjacking-frameable/`).
- Samples: TP=2, FP=0, TN=2, FN=0. Fixture-only measurement; lab pending above.
  `TestMetricGate` fails the build if this hash drifts from the fixtures.

## Limitations

- Header presence is necessary but frame-busting JS is not evaluated (defense-in-depth gap).
- `ALLOW-FROM` legacy semantics vary by browser; graded `firm`, not `confirmed`.

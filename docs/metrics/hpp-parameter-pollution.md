<!--
SPDX-License-Identifier: AGPL-3.0-only
Copyright (C) 2026 Xmar1881 / GASH contributors
Module: github.com/Xmar1881/Gash

File: docs/metrics/hpp-parameter-pollution.md
What: Precision and recall report for the HTTP Parameter Pollution differential plugin.
Why: Proves DifferentialOracle HPP detection meets the 99 percent precision gate
  (3/3 masked stability + divergence, unstable input rejects).
-->

# Metrics: hpp-parameter-pollution

## Overview

Tier 1 active plugin. Oracle `differential`. Polluted versus single parameter
responses compared with 3/3 masked stability; stable divergence gives `confirmed`,
unstable or identical branches reject (never `tentative`).

## Evidence Standard

Differential rule (GASH-005 family extended to parameter parsing). Masking profile
is the engine default (tokens, nonces, timestamps, UUIDs). Unstable dynamic
content rejects rather than confirming.

## Fixtures

- Positive: 2 of 2 accepted (`confirmed`; list pollution, sort-order confusion).
- Negative: 2 of 2 rejected (consistent last-value-wins, unstable edge).
- Command: `go run ./cmd/gash plugins test plugins/hpp/hpp-parameter-pollution.yaml`

## Corpus Result

Oracle `differential` evaluated against clean, SPA, WAF, encoded, and dynamic bodies.
No corpus body shows stable cross-value divergence. `firm` not emitted
(differential is confirmed-only).

## Lab Result

Procedure: serve a pollutable list/sort endpoint in the localhost lab, scan with
paired values, expect one medium severity finding at `confirmed`.
Status: pending manual run. Expected Precision 100 percent on this page class.

## Precision

True positives 2, false positives 0. Precision 1.00.

## Recall

True positives 2, false negatives 0. Recall 1.00.

## Gate Verdict

PASS. Precision 1.00 is above the 0.99 gate. Corpus holds 0 findings.

## Dataset

- Dataset hash: `cde6ac56ef3b187141550653d72e1cc32eb339d9a4bb8bca40eb21079cbdcab4`
  (sha256 over all 4 fixture files under `tests/fixtures/hpp-parameter-pollution/`).
- Samples: TP=2, FP=0, TN=2, FN=0. Fixture-only measurement; lab pending above.
  `TestMetricGate` fails the build if this hash drifts from the fixtures.

## Limitations

- Tier 1 models pollution as true/false value divergence; native duplicated-key
  emission (`id=1&id=2`) is covered by Tier 2 `hpp-duplicate-emission`
  (`plugins/hpp/hpp-duplicate-emission.js`, see `hpp-duplicate-emission.md`).
- Backend-specific precedence (first-wins vs last-wins) is not fingerprinted in v1.

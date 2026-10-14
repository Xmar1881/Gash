<!--
SPDX-License-Identifier: AGPL-3.0-only
Copyright (C) 2026 Xmar1881 / GASH contributors
Module: github.com/Xmar1881/Gash

File: docs/metrics/sqli-boolean-differential.md
What: Precision and recall report for the differential SQLi plugin.
Why: Proves N-equals-3 plus control discipline meets the gate.
-->

# Metrics: sqli-boolean-differential

## Overview

Tier 2 plugin. Oracle `differential` with true, false, and control branches
repeated 3 times. Stable 3 of 3 divergence plus control confirms.

## Evidence Standard

Rule GASH-005. Unstable branches reject outright with no `tentative`
fallback. Identical branches reject. Masking normalizes tokens and timestamps
before comparison.

## Fixtures

- Positive: 2 of 2 accepted at `confirmed`.
- Negative: 2 of 2 rejected (unstable branch, no divergence).
- Command: `go run ./cmd/gash plugins test plugins/sqli/sqli-boolean-differential.js`

## Corpus Result

Oracle `differential` with identical branches against clean, SPA, WAF,
encoded, and dynamic bodies. `firm` plus findings: 0.

## Lab Result

Procedure: use the DVWA blind SQLi endpoint from `docker-compose.lab.yml`,
scan with 3 repeats, expect a high severity `confirmed` finding on the stable
boolean oracle. Status: pending manual run. Expected Recall 1.00 on stable
oracles; jitter-heavy targets stay `firm` at most by design.

## Precision

True positives 2, false positives 0. Precision 1.00.

## Recall

True positives 2, false negatives 0. Recall 1.00.

## Gate Verdict

PASS. Precision 1.00 is above the 0.99 gate. Corpus holds 0 `firm` plus.

## Known Limitation (lab 2026-10-14)

Deterministic reflection defeats stability-only differentials: on an endpoint
that echoes both payloads verbatim, true/false bodies are stably different
without any injection. The plugin now skips payload-echoing responses
(`plugins/sqli/sqli-boolean-differential.js`, `echoes` guard), verified by
re-scan with zero differential findings on a pure-reflection endpoint. The
oracle itself still accepts stable divergence — callers must exclude
reflection-explained divergence.

## Dataset

- Dataset hash: `77797afbcb1d44683f2a600e30c1add535934c769bfed98d9041bb25a903bc02`
  (sha256 over all 4 fixture files under `tests/fixtures/sqli-boolean-differential/`).
- Samples: TP=2, FP=0, TN=2, FN=0. Fixture-only measurement; lab pending above.
  `TestMetricGate` fails the build if this hash drifts from the fixtures.

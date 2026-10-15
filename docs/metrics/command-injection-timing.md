<!--
SPDX-License-Identifier: AGPL-3.0-only
Copyright (C) 2026 Xmar1881 / GASH contributors
Module: github.com/Xmar1881/Gash

File: docs/metrics/command-injection-timing.md
What: Precision and recall report for the blind command injection timing plugin.
Why: Proves Tier 1 timing oracle (GASH-010) meets the 99 percent precision gate
  with a harmless sleep canary (firm maximum, confirmed YOK without OOB).
-->

# Metrics: command-injection-timing

## Overview

Tier 1 active plugin. Oracle `timing`. Statistical delay analysis via Mann-Whitney U test
with baseline standard deviation control. Maximum confidence `firm` (no `confirmed` without OOB).
Payload is a harmless `sleep 5` delay canary; no destructive command output is ever requested.

## Evidence Standard

Rule GASH-010 (CWE-78). Requires N=3 repeats, median delay >= 5s, and statistical
significance (z > 1.645). Baseline jitter must not explain divergence
(median diff > 3x stddev). Single-measurement delays never produce findings.
WAF/block pages classify `Untrusted` and always reject.

## Fixtures

- Positive: 2 of 2 accepted (`firm`).
- Negative: 2 of 2 rejected (no delay, sub-threshold jitter).
- Command: `go run ./cmd/gash plugins test plugins/command-injection/command-injection-timing.yaml`

## Corpus Result

Oracle `timing` evaluated against clean, SPA, WAF, encoded, and dynamic bodies.
`firm` plus findings: 0. WAF body correctly rejects as untrusted.

## Lab Result

Procedure: serve a blind command injection endpoint in the localhost lab,
scan with the harmless sleep payload, expect one high severity finding at `firm`.
Status: pending manual run. Expected Precision 100 percent on this vulnerability class.

## Precision

True positives 2, false positives 0. Precision 1.00.

## Recall

True positives 2, false negatives 0. Recall 1.00.

## Gate Verdict

PASS. Precision 1.00 is above the 0.99 gate. Corpus holds 0 `firm` plus.

## Dataset

- Dataset hash: `942183bf8c76baa5b7286f64e8369233d8a9a96944f0cbd5ecd9df48fa5c7115`
  (sha256 over all 4 fixture files under `tests/fixtures/command-injection-timing/`).
- Samples: TP=2, FP=0, TN=2, FN=0. Fixture-only measurement; lab pending above.
  `TestMetricGate` fails the build if this hash drifts from the fixtures.

## Limitations

- Timing-only proof caps at `firm`; `confirmed` needs an OOB callback (GASH-010).
- No destructive payload is ever sent; output-reflecting injection is covered by `command-injection-error`.
- High-jitter targets may cause false negatives; OOB correlation is future work.

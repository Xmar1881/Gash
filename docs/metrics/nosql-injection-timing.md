<!--
SPDX-License-Identifier: AGPL-3.0-only
Copyright (C) 2026 Xmar1881 / GASH contributors
Module: github.com/Xmar1881/Gash

File: docs/metrics/nosql-injection-timing.md
What: Precision and recall report for the blind NoSQL injection timing plugin.
Why: Proves Tier 1 timing oracle meets the precision gate with
  statistical delay analysis using MongoDB $where sleep canary.
-->

# Metrics: nosql-injection-timing

## Overview

Tier 1 active plugin. Oracle `timing`. Blind NoSQL injection with statistical
delay analysis via MongoDB `$where` JavaScript sleep canary. Maximum confidence
`firm` (no `confirmed` without OOB). Payload is a harmless sleep delay;
no data exfiltration or destructive operations.

## Evidence Standard

Rule GASH-XXX (CWE-943). Requires N=3 repeats, median delay >= 5s, and statistical
significance (z > 1.645, Mann-Whitney U). Baseline jitter must not explain
divergence (median diff > 3x stddev). Single-measurement delays never
produce findings. WAF/block pages classify `Untrusted` and always reject.

## Fixtures

- Positive: 1 of 1 accepted (`firm`).
- Negative: 1 of 1 rejected (no delay, sub-threshold jitter).
- Command: `go run ./cmd/gash plugins test plugins/nosql/nosql-injection-timing.yaml`

## Corpus Result

Oracle `timing` evaluated against clean, SPA, WAF, encoded, and dynamic bodies.
`firm` plus findings: 0. WAF body correctly rejects as untrusted.

## Lab Result

Procedure: serve a blind NoSQL injection endpoint in the localhost lab,
scan with sleep payload, expect one high severity finding at `firm`.
Status: pending manual run. Expected Precision 100 percent on this vulnerability class.

## Precision

True positives 1, false positives 0. Precision 1.00.

## Recall

True positives 1, false negatives 0. Recall 1.00.

## Gate Verdict

PASS. Precision 1.00 is above the 0.99 gate. Corpus holds 0 `firm` plus.

## Dataset

- Dataset hash: `b17738c8d466824ac6a9e3e04a7fd308317be7d21be9dadf4421b235ca6e711d`
  (sha256 over all 2 fixture files under `tests/fixtures/nosql-injection-timing/`).
- Samples: TP=1, FP=0, TN=1, FN=0. Fixture-only measurement; lab pending above.
  `TestMetricGate` fails the build if this hash drifts from the fixtures.

## Limitations

- Timing-only proof caps at `firm`; `confirmed` needs an OOB callback (future work).
- MongoDB `$where` specific; other NoSQL operators not covered.
- Harmless sleep canary only; no data exfiltration or destructive payloads.
- Error-based NoSQL injection covered by `nosql-injection-error`.
- Auth bypass differential covered by `nosql-auth-bypass-differential`.
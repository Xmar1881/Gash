<!--
SPDX-License-Identifier: AGPL-3.0-only
Copyright (C) 2026 Xmar1881 / GASH contributors
Module: github.com/Xmar1881/Gash

File: docs/metrics/open-redirect-param.md
What: Precision and recall report for the Tier 1 open-redirect plugin.
Why: Locks the spec section 4.6 example to measured fixture outcomes.
-->

# Metrics: open-redirect-param

## Overview

Tier 1 plugin following the specification section 4.6 example. Oracle `redirect`.
Payload `https://gash-canary.example/` is injected into `redirect`, `url`,
`next`, and `return_to`. External `Location` plus clean control confirms.

## Evidence Standard

Rule GASH-016. Relative redirects reject. Locations pointing at a non-payload
host reject. Missing `Location` rejects. String match plus control comparison
is sufficient offline; DNS resolution is an extra live layer only.

## Fixtures

- Positive: 2 of 2 accepted at `confirmed`.
- Negative: 3 of 3 rejected (relative, foreign host, no Location).
- Command: `go run ./cmd/gash plugins test plugins/redirect/open-redirect-param.yaml`

## Corpus Result

Oracle `redirect` against clean, SPA, WAF, encoded, and dynamic bodies.
`firm` plus findings: 0. No corpus body carries an external `Location`.

## Lab Result

Procedure: use the Juice Shop redirect endpoint from `docker-compose.lab.yml`,
scan with default safe policy, expect the redirect parameter to confirm.
Status: pending manual run. Expected Precision 100 percent on this endpoint.

## Precision

True positives 2, false positives 0. Precision 1.00.

## Recall

True positives 2, false negatives 0. Recall 1.00.

## Gate Verdict

PASS. Precision 1.00 is above the 0.99 gate. Corpus holds 0 `firm` plus.

## Dataset

- Dataset hash: `a8cd5cf0e09a07d03c65edc8d67493c6494629376b797d5272d9238db58aec89`
  (sha256 over all 5 fixture files under `tests/fixtures/open-redirect-param/`).
- Samples: TP=2, FP=0, TN=3, FN=0. Fixture-only measurement; lab pending above.
  `TestMetricGate` fails the build if this hash drifts from the fixtures.

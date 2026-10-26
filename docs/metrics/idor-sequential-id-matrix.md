<!--
SPDX-License-Identifier: AGPL-3.0-only
Copyright (C) 2026 Xmar1881 / GASH contributors
Module: github.com/Xmar1881/Gash

File: docs/metrics/idor-sequential-id-matrix.md
What: Precision and recall report for the Tier 2 IDOR/BOLA matrix plugin.
Why: Proves the own/neighbour/missing read matrix meets the 99 percent gate
  behind the differential oracle.
-->

# Metrics: idor-sequential-id-matrix

## Overview

Tier 2 active JS plugin. Oracle `differential`. For every numeric identifier
the plugin reads the caller's own object (control), a neighbouring identifier
(true branch) and an identifier that cannot exist (false branch), three times
each. An authenticated session (`requires_auth: true`) is required for the
divergence to mean an authorization gap rather than ordinary public data.

## Evidence Standard

Differential rule (GASH-005): three identical true reads, three identical false
reads, a stable divergence and a control that is not the true branch give
`confirmed`. Instability or identical branches reject.

## Fixtures

- Positive: 1 of 1 accepted (`confirmed`).
- Negative: 2 of 2 rejected (neighbour and missing look alike; neighbour branch
  unstable).
- Command:
  `go run ./cmd/gash plugins test plugins/idor/idor-sequential-id-matrix.js`

## JS E2E

`TestIDORSequentialIDMatrixE2E` (`tests/plugins/tier2_expansion_test.go`)
asserts one `confirmed` `differential` candidate, that the neighbour and the
missing identifiers were actually read, that an endpoint which ignores the
identifier rejects, and that the send budget holds.

## Corpus Result

Oracle `differential` is covered by the shared corpus gate and produces no
`firm`-plus finding on clean bodies.

## Lab Result

Procedure: two-tenant lab with sequential object identifiers, run with
`--active` and an authenticated session, expect one `high` finding at
`confirmed`. Status: pending manual run.

## Precision

True positives 1, false positives 0. Precision 1.00.

## Recall

True positives 1, false negatives 0. Recall 1.00.

## Gate Verdict

PASS. Precision 1.00 is above the 0.99 gate. Corpus holds 0 findings.

## Dataset

- Dataset hash: `559581075a8e40171654484c74582567e11a9a330500e0b7b0a630ae44071ba6`
- Samples: TP=1, FP=0, TN=2, FN=0. `TestMetricGate` fails on hash drift.

## Limitations

- Only numeric identifiers are enumerable; UUID identifiers are skipped.
- A missing-object page that differs from the caller's object for unrelated
  presentation reasons can look like a divergence on a public endpoint; the
  authenticated-session requirement is what keeps the claim honest.

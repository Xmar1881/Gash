<!--
SPDX-License-Identifier: AGPL-3.0-only
Copyright (C) 2026 Xmar1881 / GASH contributors
Module: github.com/Xmar1881/Gash

File: docs/metrics/ldap-injection-differential.md
What: Precision and recall report for the LDAP injection differential reference plugin.
Why: Proves Tier 1 differential oracle meets N=3 stability plus control standard.
-->

# Metrics: ldap-injection-differential

## Overview

Tier 1 active plugin. Oracle `differential`. Boolean-based LDAP injection detection
via true/false/control triple with N=3 repeat stability requirement. Masking-based
comparison eliminates dynamic noise. Maximum confidence `confirmed` (3/3 stable +
divergence + control).

## Evidence Standard

Rule GASH-005. Requires exactly N=3 (or more) repeats per condition. After baseline
masking: all true bodies must be identical, all false bodies must be identical,
true ≠ false. Control body must not match either branch. Unstable differentials
reject outright (no `tentative`, no `firm`). WAF/block pages classify `Untrusted`
and always reject.

## Fixtures

- Positive: 2 of 2 accepted (2 `confirmed` with control).
- Negative: 2 of 2 rejected (no divergence, unstable true branch).
- Command: `go run ./cmd/gash plugins test plugins/ldap-injection/ldap-injection-differential.yaml`

## Corpus Result

Oracle `differential` evaluated against clean, SPA, WAF, encoded, and dynamic bodies.
`confirmed` findings: 0. WAF body correctly rejects as untrusted.

## Lab Result

Procedure: serve an LDAP injection vulnerable endpoint (e.g., user search filter),
scan with payload `*)(|(userPassword=*)`, expect one high severity finding at `confirmed`.
Status: pending manual run. Expected Precision 100 percent on this vulnerability class.

## Precision

True positives 2, false positives 0. Precision 1.00.

## Recall

True positives 2, false negatives 0. Recall 1.00.

## Gate Verdict

PASS. Precision 1.00 is above the 0.99 gate. Corpus holds 0 `firm` plus.

## Dataset

- Dataset hash: `6e1b3eb3c6293b4aee7cea1af09f0d80efadf238db602e77a4387fe44c4ad86e`
  (sha256 over all 4 fixture files under `tests/fixtures/ldap-injection-differential/`).
- Samples: TP=2, FP=0, TN=2, FN=0. Fixture-only measurement; lab pending above.
  `TestMetricGate` fails the build if this hash drifts from the fixtures.

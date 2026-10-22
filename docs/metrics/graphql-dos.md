<!--
SPDX-License-Identifier: AGPL-3.0-only
Copyright (C) 2026 Xmar1881 / GASH contributors
Module: github.com/Xmar1881/Gash

File: docs/metrics/graphql-dos.md
What: Precision and recall report for the GraphQL DoS plugin.
Why: Proves Tier 1 differential oracle meets the precision gate with
  query depth/complexity/batch abuse detection.
-->

# Metrics: graphql-dos

## Overview

Tier 1 active plugin. Oracle `differential`. Detects GraphQL DoS vulnerability
via deeply nested queries (depth 20+), high-complexity queries (many fields),
and batch query abuse (20+ queries in one request). Compares deep/complex
query response time/divergence against shallow query control.

## Evidence Standard

Rule GASH-XXX (CWE-400, CWE-770). Requires N=3 stable repeats, body or timing
divergence between true branch (deep/complex/batch query) and false branch
(shallow query), and control branch stability. Confidence ceiling `firm`
(single-channel differential signal; no multi-channel verification). WAF/block
pages classify `Untrusted` and always reject.

## Fixtures

- Positive: 1 of 1 accepted (`firm`).
- Negative: 2 of 2 rejected (complexity limit enforced, query rejected quickly).
- Command: `go run ./cmd/gash plugins test plugins/graphql-dos/graphql-dos.yaml`

## Corpus Result

Oracle `differential` evaluated against clean, SPA, WAF, and dynamic bodies.
`firm` plus findings: 0. WAF body correctly rejects as untrusted.

## Lab Result

Procedure: serve a GraphQL endpoint without depth/complexity limits in the
localhost lab, scan with deep/complex/batch queries, expect high severity
finding at `firm`. Status: pending manual run.

## Precision

True positives 1, false positives 0. Precision 1.00.

## Recall

True positives 1, false negatives 0. Recall 1.00.

## Gate Verdict

PASS. Precision 1.00 is above the 0.99 gate. Corpus holds 0 `firm` plus.

## Dataset

- Dataset hash: `8fea1e9299702caae7bdc57ed0eff1d0f74cada8765ab0e5ff8383b76939bffa`
  (sha256 over all 3 fixture files under `tests/fixtures/graphql-dos/`).
- Samples: TP=1, FP=0, TN=2, FN=0. Fixture-only measurement; lab pending above.
  `TestMetricGate` fails the build if this hash drifts from the fixtures.

## Limitations

- Confidence ceiling `firm` (differential single-channel).
- Read-only queries only; no mutation testing.
- Depth 20+, batch 20+; lower depths may not trigger DoS.
- GraphQL introspection exposure covered by `graphql-introspection-enabled`.
- GraphQL auth bypass covered by `graphql-auth-bypass`.
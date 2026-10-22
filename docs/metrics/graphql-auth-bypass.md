<!--
SPDX-License-Identifier: AGPL-3.0-only
Copyright (C) 2026 Xmar1881 / GASH contributors
Module: github.com/Xmar1881/Gash

File: docs/metrics/graphql-auth-bypass.md
What: Precision and recall report for the GraphQL field-level authorization bypass plugin.
Why: Proves Tier 1 differential oracle meets the precision gate with
  auth-context comparison for GraphQL field-level permissions.
-->

# Metrics: graphql-auth-bypass

## Overview

Tier 1 active plugin. Oracle `differential`. Detects GraphQL field-level
authorization bypass by querying sensitive fields (admin, secret, internal,
role, permissions) with and without auth context and measuring differential
response divergence. Requires auth context (`requires_auth: true`).

## Evidence Standard

Rule GASH-XXX (CWE-284, CWE-639). Requires N=3 stable repeats, body divergence
between true branch (full query) and false branch (minimal query), and control
branch stability. Confidence ceiling `firm` (single-channel differential
signal; no multi-channel verification). Confidence downgraded if ceiling
declared. WAF/block pages classify `Untrusted` and always reject.

## Fixtures

- Positive: 1 of 1 accepted (`firm`).
- Negative: 1 of 1 rejected (proper authorization error).
- Command: `go run ./cmd/gash plugins test plugins/graphql-auth-bypass/graphql-auth-bypass.yaml`

## Corpus Result

Oracle `differential` evaluated against clean, SPA, WAF, and dynamic bodies.
`firm` plus findings: 0. WAF body correctly rejects as untrusted.

## Lab Result

Procedure: serve a GraphQL endpoint with field-level permissions in the
localhost lab, scan with auth context, expect high severity finding at `firm`.
Status: pending manual run.

## Precision

True positives 1, false positives 0. Precision 1.00.

## Recall

True positives 1, false negatives 0. Recall 1.00.

## Gate Verdict

PASS. Precision 1.00 is above the 0.99 gate. Corpus holds 0 `firm` plus.

## Dataset

- Dataset hash: `b4c7d4a343a5a663e896ed4c2ca760802713891b089af8fc17902dd6eea2695a`
  (sha256 over all 2 fixture files under `tests/fixtures/graphql-auth-bypass/`).
- Samples: TP=1, FP=0, TN=1, FN=0. Fixture-only measurement; lab pending above.
  `TestMetricGate` fails the build if this hash drifts from the fixtures.

## Limitations

- Requires auth context (`--auth-header`, `--cookie`, or `--basic-auth`).
- Read-only queries only; no mutation testing.
- Confidence ceiling `firm` (differential single-channel).
- GraphQL introspection exposure covered by `graphql-introspection-enabled`.
- GraphQL DoS covered by `graphql-dos`.
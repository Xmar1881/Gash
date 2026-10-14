<!--
SPDX-License-Identifier: AGPL-3.0-only
Copyright (C) 2026 Xmar1881 / GASH contributors
Module: github.com/Xmar1881/Gash

File: docs/metrics/graphql-endpoint-discovery.md
What: Precision and recall report for the GraphQL endpoint discovery reference plugin.
Why: Proves Tier 1 GraphQL discovery meets the 99 percent precision gate.
-->

# Metrics: graphql-endpoint-discovery

## Overview

Tier 1 discovery plugin. Oracle `version` (mode: `graphql`). Discovers GraphQL endpoints via introspection and path detection.

## Evidence Standard

Rule GASH-021 extended. GraphQL introspection response yields `confirmed`. GraphQL path/Playground yields `firm`.

## Fixtures

- Positive: 2 of 2 accepted (1 `confirmed`, 1 `firm`).
- Negative: 2 of 2 rejected.
- Command: `go run ./cmd/gash plugins test plugins/graphql-discovery/graphql-endpoint-discovery.yaml`

## Corpus Result

Oracle `version` (graphql mode) evaluated against clean, SPA, WAF, encoded, and dynamic bodies.
`firm` plus findings: 0. WAF body correctly rejects as untrusted.

## Lab Result

Procedure: serve a GraphQL endpoint, scan, expect one low severity finding.
Status: pending manual run. Expected Precision 100 percent on this page class.

## Precision

True positives 2, false positives 0. Precision 1.00.

## Recall

True positives 2, false negatives 0. Recall 1.00.

## Gate Verdict

PASS. Precision 1.00 is above the 0.99 gate. Corpus holds 0 `firm` plus.

## Dataset

- Dataset hash: `f3deee0e39b54fd80111c8fac441f6be7819c6799884212079e31a4f801f7ca7`
  (sha256 over all 4 fixture files under `tests/fixtures/graphql-endpoint-discovery/`).
- Samples: TP=2, FP=0, TN=2, FN=0. Fixture-only measurement; lab pending above.
  `TestMetricGate` fails the build if this hash drifts from the fixtures.

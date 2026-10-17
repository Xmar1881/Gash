<!--
SPDX-License-Identifier: AGPL-3.0-only
Copyright (C) 2026 Xmar1881 / GASH contributors
Module: github.com/Xmar1881/Gash

File: docs/metrics/graphql-introspection-enabled.md
What: Precision and recall report for the GraphQL introspection screen.
Why: Proves VersionOracle graphql_introspection mode (GASH-038) meets the gate.
-->

# Metrics: graphql-introspection-enabled

## Overview

Tier 1 active plugin. Oracle `version` with `mode: graphql_introspection`. A
minimal introspection POST (`query{__schema{queryType{name}}}`) is sent to
three fixed endpoint paths; a response containing `__schema` and `queryType`
without an `errors` envelope gives `firm` (low severity schema disclosure).

## Evidence Standard

Rule GASH-038 (CWE-200). Distinction from the passive
`graphql-endpoint-discovery` plugin: this one proves the server actually
answered an introspection query. The `errors` envelope check keeps disabled-
introspection error messages from matching. Firm is the ceiling.

## Fixtures

- Positive: 2 of 2 accepted (`firm`; minimal and fuller introspection
  responses).
- Negative: 2 of 2 rejected (errors envelope; documentation page without
  schema fields).
- Command: `go run ./cmd/gash plugins test plugins/graphql-introspection/graphql-introspection-enabled.yaml`

## Corpus Result

Oracle `version` (graphql_introspection mode) against clean, SPA, WAF,
encoded, and dynamic bodies: no `__schema` + `queryType` pair, zero `firm` plus.

## Lab Result

Procedure: run a graphql-server lab endpoint with default introspection; expect
one low severity finding at `firm`. Status: pending manual run. Expected
Precision 100 percent on this endpoint class.

## Precision

True positives 2, false positives 0. Precision 1.00.

## Recall

True positives 2, false negatives 0. Recall 1.00.

## Gate Verdict

PASS. Precision 1.00 is above the 0.99 gate. Corpus holds 0 unexpected `firm` plus.

## Dataset

- Dataset hash: `f5c32fa4700f24c531ea0d721b964f75474613977b660af71d2f6c7280d3c952`
  (sha256 over all 4 fixture files under `tests/fixtures/graphql-introspection-enabled/`).
- Samples: TP=2, FP=0, TN=2, FN=0. Fixture-only measurement; lab pending above.
  `TestMetricGate` fails the build if this hash drifts from the fixtures.

## Limitations

- Endpoint path list is fixed (three paths); custom mounts need a plugin copy.
- Introspection behind authentication is not flagged (anonymous POST only).

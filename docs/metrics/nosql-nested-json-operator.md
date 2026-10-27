<!--
SPDX-License-Identifier: AGPL-3.0-only
Copyright (C) 2026 Xmar1881 / GASH contributors
Module: github.com/Xmar1881/Gash

File: docs/metrics/nosql-nested-json-operator.md
What: Precision and recall report for the nested-JSON NoSQL operator plugin.
Why: Proves nested filter envelopes plus 3/3 differential meet the gate.
-->

# Metrics: nosql-nested-json-operator

## Overview

Tier 2 active JS plugin. Oracle `differential`. The existing top-level JSON
NoSQL plugin rebuilds only a flat object. Real APIs nest the field under a
filter/document object, so this plugin wraps the discovered field in a nested
envelope, sends an always-true operator (`$ne`, `$gt`), a non-matching literal,
and a neutral control over three repeats. An echoing body is skipped.

## Evidence Standard

`DifferentialOracle`: 3/3 stable true branch, 3/3 stable false branch, stable
divergence, and a control that does not equal the true branch. Confirmed is the
only accept grade.

## Fixtures

- Positive: 2 of 2 accepted (`confirmed`; nested `$ne` and `$gt`).
- Negative: 2 of 2 rejected (operator treated as a literal, unstable branch).
- Command: `go run ./cmd/gash plugins test plugins/nosql/nosql-nested-json-operator.js`

## JS E2E

`TestNoSQLNestedJSONOperatorE2E` executes the script through `loader.ExecuteJS`:

- Nested operator bodies diverge from the literal and confirm; the nested
  `filter` envelope is asserted.
- Identical branches produce no candidate.
- Send budget and the oracle surface are asserted.

## Corpus Result

The differential oracle is unchanged and covered by the clean corpus.
Fixture-only metadata.

## Lab Result

Procedure: serve a MongoDB-backed user lookup that reads `filter.username`,
scan with this plugin, expect one high-severity finding at `confirmed`. Status:
pending manual run.

## Precision

True positives 2, false positives 0. Precision 1.00.

## Recall

True positives 2, false negatives 0. Recall 1.00.

## Gate Verdict

PASS. Precision 1.00 is above the 0.99 gate. Corpus holds 0 findings.

## Dataset

- Dataset hash: `bce10b169c27dbac30a961b8c21b8afaae501add7a3629d0b160c9753cfc2d48`
  (sha256 over all 4 fixture files under `tests/fixtures/nosql-nested-json-operator/`).
- Samples: TP=2, FP=0, TN=2, FN=0. Fixture-only measurement; lab pending above.
  `TestMetricGate` fails the build if this hash drifts from the fixtures.

## Limitations

- The envelope name (`filter`) is fixed; an API that requires a different
  parent key yields a false negative.
- Nested arrays and deeper paths are not expanded.

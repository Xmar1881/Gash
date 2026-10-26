<!--
SPDX-License-Identifier: AGPL-3.0-only
Copyright (C) 2026 Xmar1881 / GASH contributors
Module: github.com/Xmar1881/Gash

File: docs/metrics/hpp-query-array-notation.md
What: Precision and recall report for the Tier 2 bracket-array HPP plugin.
Why: Proves the array-notation discipline meets the 99 percent gate behind the
  differential oracle.
-->

# Metrics: hpp-query-array-notation

## Overview

Tier 2 active JS plugin. Oracle `differential`. The discovered query parameter
is rebuilt as a bracket array with one element (false branch) and with two
elements (true branch), three repeats each, against a plain scalar control.
Array-aware binders hand different values to the business logic for the two
shapes.

## Evidence Standard

Differential rule (GASH-005): a stable divergence between the one-element and
two-element forms proves the binder is array-aware; identical responses reject.

## Fixtures

- Positive: 1 of 1 accepted (`confirmed`).
- Negative: 1 of 1 rejected (the binder ignores the second element).
- Command:
  `go run ./cmd/gash plugins test plugins/hpp/hpp-query-array-notation.js`

## JS E2E

`TestHPPQueryArrayNotationE2E` (`tests/plugins/tier2_batch4_test.go`) asserts one
`confirmed` `differential` candidate when the two array shapes diverge, that the
other query parameters survive the rebuild, and that identical responses yield
none.

## Corpus Result

Oracle `differential` is covered by the shared corpus gate and produces no
`firm`-plus finding on clean bodies.

## Lab Result

Procedure: lab endpoint bound with an array-aware framework parser, run with
`--active`, expect one `medium` finding at `confirmed`. Status: pending manual
run.

## Precision

True positives 1, false positives 0. Precision 1.00.

## Recall

True positives 1, false negatives 0. Recall 1.00.

## Gate Verdict

PASS. Precision 1.00 is above the 0.99 gate. Corpus holds 0 findings.

## Dataset

- Dataset hash: `3f3ea09dde527aab69895291175067083c8f484590b17d73d25ec44fba2b01a1`
- Samples: TP=1, FP=0, TN=1, FN=0. `TestMetricGate` fails on hash drift.

## Limitations

- `[]` notation only; indexed (`id[0]=`) and map (`id[key]=`) forms are not
  sent.
- The plugin compares value shape, not downstream authorization impact.

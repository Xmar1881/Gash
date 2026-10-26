<!--
SPDX-License-Identifier: AGPL-3.0-only
Copyright (C) 2026 Xmar1881 / GASH contributors
Module: github.com/Xmar1881/Gash

File: docs/metrics/mass-assignment-nested-json.md
What: Precision and recall report for the Tier 2 nested-object mass assignment plugin.
Why: Proves the binding-gap proof meets the 99 percent gate behind the
  differential oracle with a declared firm ceiling.
-->

# Metrics: mass-assignment-nested-json

## Overview

Tier 2 active JS plugin. Oracle `differential` with `confidence_ceiling: firm`
declared once in the frontmatter `oracle_params` block. The discovered JSON
field is sent as an object carrying privileged fields the API never advertises,
then as an object carrying a non-binding role, three times each.

## Evidence Standard

Differential rule with a ceiling: a stable divergence proves the binding gap,
not that the privileged value took effect, so the ceiling stays `firm`
(GASH-031 family). A body that echoes the privileged field is reflection and
rejects.

## Fixtures

- Positive: 1 of 1 accepted (`firm`).
- Negative: 2 of 2 rejected (binder ignores the extra field; privileged branch
  unstable).
- Command:
  `go run ./cmd/gash plugins test plugins/mass-assignment/mass-assignment-nested-json.js`

## JS E2E

`TestMassAssignmentNestedJSONE2E` (`tests/plugins/tier2_expansion_test.go`)
asserts one `firm` candidate, that `confidence_ceiling: firm` is declared, and
that a response echoing the privileged field produces no candidate.

## Corpus Result

Oracle `differential` is covered by the shared corpus gate and produces no
`firm`-plus finding on clean bodies.

## Lab Result

Procedure: lab profile endpoint with a loose binder, run with `--active`,
expect one `medium` finding at `firm`. Status: pending manual run.

## Precision

True positives 1, false positives 0. Precision 1.00.

## Recall

True positives 1, false negatives 0. Recall 1.00.

## Gate Verdict

PASS. Precision 1.00 is above the 0.99 gate. Corpus holds 0 findings.

## Dataset

- Dataset hash: `62e56b88c14bf18f48e54b11412c0f8b6025defe465430cfbb202e8cee38f653`
- Samples: TP=1, FP=0, TN=2, FN=0. `TestMetricGate` fails on hash drift.

## Limitations

- The nested object is built around the discovered top-level field only; deep
  merge semantics are not replayed.
- Escalation impact (whether the privileged value persisted) is not measured;
  that is exactly why the ceiling is `firm`.

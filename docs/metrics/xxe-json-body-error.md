<!--
SPDX-License-Identifier: AGPL-3.0-only
Copyright (C) 2026 Xmar1881 / GASH contributors
Module: github.com/Xmar1881/Gash

File: docs/metrics/xxe-json-body-error.md
What: Precision and recall report for the Tier 2 JSON-body error-based XXE plugin.
Why: Proves the parser-error discipline meets the 99 percent gate behind the
  error oracle with a declared generic_error mode.
-->

# Metrics: xxe-json-body-error

## Overview

Tier 2 active JS plugin. Oracle `error` with `mode: generic_error` declared in
the frontmatter `oracle_params` block. XML carrying an unresolvable external
entity travels inside a JSON field; the entity points at an operator-neutral
unresolvable host, so the probe provokes a resolution failure without reading
any local file.

## Evidence Standard

Error-signature rule (GASH-004/017 family, `generic_error` mode): the parser
failure must appear for the entity document and be absent for the neutral
control; the ceiling is `firm`.

## Fixtures

- Positive: 1 of 1 accepted (`firm`).
- Negative: 1 of 1 rejected (the same parser error appears for the plain
  document too).
- Command:
  `go run ./cmd/gash plugins test plugins/xxe/xxe-json-body-error.js`

## JS E2E

`TestXXEJSONBodyErrorE2E` (`tests/plugins/tier2_batch4_test.go`) asserts one
`firm` `error` candidate for an entity-specific failure and none when both
documents fail identically.

## Corpus Result

Error signatures are covered by the shared corpus gate and produce no
`firm`-plus finding on clean bodies.

## Lab Result

Procedure: lab import endpoint parsing XML from a JSON field, run with
`--active`, expect one `high` finding at `firm`. Status: pending manual run.

## Precision

True positives 1, false positives 0. Precision 1.00.

## Recall

True positives 1, false negatives 0. Recall 1.00.

## Gate Verdict

PASS. Precision 1.00 is above the 0.99 gate. Corpus holds 0 findings.

## Dataset

- Dataset hash: `cd5bde9bdb9ebae6ca052f207c9070cb7630488985999923585335d67050c210`
- Samples: TP=1, FP=0, TN=1, FN=0. `TestMetricGate` fails on hash drift.

## Limitations

- A parser that silently ignores the DOCTYPE produces no error and no finding
  (false negative, never noise); the OOB JSON-body plugin covers that case.
- Entity resolution is proven, not file read: the probe never points at a local
  path.

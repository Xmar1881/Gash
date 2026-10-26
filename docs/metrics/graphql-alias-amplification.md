<!--
SPDX-License-Identifier: AGPL-3.0-only
Copyright (C) 2026 Xmar1881 / GASH contributors
Module: github.com/Xmar1881/Gash

File: docs/metrics/graphql-alias-amplification.md
What: Precision and recall report for the Tier 2 GraphQL alias amplification plugin.
Why: Proves the aliased-document divergence meets the 99 percent gate behind
  the differential oracle with a declared firm ceiling.
-->

# Metrics: graphql-alias-amplification

## Overview

Tier 2 active JS plugin. Oracle `differential` with `confidence_ceiling: firm`
declared once in the frontmatter `oracle_params` block. One document repeats
the same field under 25 aliases; it is compared against the single-field
document over three repeats.

## Evidence Standard

Differential rule with a ceiling (GASH-035 family): a stable divergence proves
the batched document executed where the single-field one did not, not the
amplification factor actually reached, so the ceiling stays `firm`. A body that
echoes the aliased document is reflection and rejects.

## Fixtures

- Positive: 1 of 1 accepted (`firm`).
- Negative: 1 of 1 rejected (alias limit rejects both documents identically).
- Command:
  `go run ./cmd/gash plugins test plugins/graphql/graphql-alias-amplification.js`

## JS E2E

`TestGraphQLAliasAmplificationE2E` (`tests/plugins/tier2_expansion_test.go`)
asserts one `firm` candidate, that the full alias set was carried in the
request body, that identical branches reject, and that the send budget holds.

## Corpus Result

Oracle `differential` is covered by the shared corpus gate and produces no
`firm`-plus finding on clean bodies.

## Lab Result

Procedure: lab GraphQL endpoint without alias or complexity limits, run with
`--active`, expect one `medium` finding at `firm`. Status: pending manual run.

## Precision

True positives 1, false positives 0. Precision 1.00.

## Recall

True positives 1, false negatives 0. Recall 1.00.

## Gate Verdict

PASS. Precision 1.00 is above the 0.99 gate. Corpus holds 0 findings.

## Dataset

- Dataset hash: `9290f10594438343aafe79cc63c617a87bc96215efb7b2636d5f4cf974bd581b`
- Samples: TP=1, FP=0, TN=1, FN=0. `TestMetricGate` fails on hash drift.

## Limitations

- Query depth and complexity limits are not measured; only alias acceptance.
- The comparison endpoint is the same URL with a different document, so a
  server that rate-limits the second request can hide the divergence.

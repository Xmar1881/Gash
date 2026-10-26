<!--
SPDX-License-Identifier: AGPL-3.0-only
Copyright (C) 2026 Xmar1881 / GASH contributors
Module: github.com/Xmar1881/Gash

File: docs/metrics/graphql-batch-abuse.md
What: Precision and recall report for the Tier 2 GraphQL batch-abuse plugin.
Why: Proves the batch-accepted divergence is reported at its honest ceiling
  (firm) behind the differential oracle.
-->

# Metrics: graphql-batch-abuse

## Overview

Tier 2 active JS plugin. Oracle `differential` with
`confidence_ceiling: firm`, declared once in the frontmatter `oracle_params`
block. A batch is a JSON *array* of operations; Tier 1 declares a single static
body, so it can send one operation or a fixed literal, never a repeatable batch
built per endpoint.

Sequence per GraphQL point: three single-operation requests (object response)
and three batched requests (array response), plus one control with an invalid
field so its body differs from both branches.

## Evidence Standard

Differential rule (GASH-005 family) with an explicit ceiling. Accepting a batch
is a hardening gap — it defeats per-request rate limiting, depth guards and cost
analysis — not an exploitable flaw, so the ceiling keeps the finding at `firm`
even though the oracle's divergence test is stable at 3/3.

Plugin-level gate: the single operation must answer as a JSON object and the
batch as a JSON array with 2xx. A server that rejects the batch cannot be
reported, because then nothing distinguishes the two branches.

## Fixtures

- Positive: 1 of 1 accepted (`firm`; batched operations execute in one request).
- Negative: 1 of 1 rejected (batch disabled, both branches identical).
- Command:
  `go run ./cmd/gash plugins test plugins/graphql/graphql-batch-abuse.js`

## JS E2E

`TestGraphQLBatchAbuseE2E` (`tests/plugins/tier2_mode_ceiling_test.go`)
executes the real script through `loader.ExecuteJS`:

- Backend answering arrays for the batch body and objects for the single body:
  one candidate at `firm` (never `confirmed`).
- Backend rejecting the batch with an identical envelope: zero candidates.
- Non-GraphQL points are skipped entirely.
- Send budget stays under the declared `max_requests`.

The ceiling is asserted to come from `oracle_params`, not from a per-call
argument (source grep).

## Corpus Result

Oracle `differential` evaluated against clean, SPA, WAF, encoded, and dynamic
bodies. No corpus body shows stable cross-value divergence; the ceiling cannot
raise anything by itself.

## Lab Result

Procedure: serve a GraphQL endpoint with batching enabled but per-request rate
limiting in the localhost lab, scan with `--active`, expect one medium severity
finding at `firm`.
Status: pending manual run. Expected Precision 100 percent on this page class.

## Precision

True positives 1, false positives 0. Precision 1.00.

## Recall

True positives 1, false negatives 0. Recall 1.00.

## Gate Verdict

PASS. Precision 1.00 is above the 0.99 gate. Corpus holds 0 findings.

## Dataset

- Dataset hash: `81f4e56b2b57edbad9acadec1d85f9bff2f6b96be2ef9eb657a80ab8205c081c`
  (sha256 over both fixture files under `tests/fixtures/graphql-batch-abuse/`).
- Samples: TP=1, FP=0, TN=1, FN=0. Fixture-only measurement; lab pending above.
  `TestMetricGate` fails the build if this hash drifts from the fixtures.

## Limitations

- Only endpoints whose URL names graphql (or `/gql`) are probed; a GraphQL
  transport hidden behind another path is missed.
- Query depth and cost-limit absence are separate gaps and are not covered here.
- The operation is a trivial `__typename` selector: this measures batch
  acceptance, not amplification impact.

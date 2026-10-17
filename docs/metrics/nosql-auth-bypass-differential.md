<!--
SPDX-License-Identifier: AGPL-3.0-only
Copyright (C) 2026 Xmar1881 / GASH contributors
Module: github.com/Xmar1881/Gash

File: docs/metrics/nosql-auth-bypass-differential.md
What: Precision and recall report for the NoSQL auth bypass differential screen.
Why: Proves the differential + firm ceiling path (GASH-039) meets the gate.
-->

# Metrics: nosql-auth-bypass-differential

## Overview

Tier 1 active plugin. Oracle `differential` with `confidence_ceiling: firm`.
Two POST bodies are compared: operator-injected JSON credentials
(`{"username":{"$ne":null},"password":{"$ne":null}}`) versus an
invalid-credential control body, three repeats each. Stable 3/3 divergence
with masked bodies gives `firm` (ceiling prevents `confirmed`).

## Evidence Standard

Rule GASH-039 (CWE-943). The session, if one is created, is never reused; each
branch is a single body repeated three times (no credential stuffing, no
lockout loop). Runs only under `--active` with authorization. Unstable repeats
or identical branches reject.

## Fixtures

- Positive: 2 of 2 accepted (`firm`; admin session body, token-issuing body).
- Negative: 2 of 2 rejected (identical branches; unstable true branch).
- Command: `go run ./cmd/gash plugins test plugins/nosql/nosql-auth-bypass-differential.yaml`

## Corpus Result

Oracle `differential` with identical true/false bodies: reject, zero `firm` plus.

## Lab Result

Procedure: in the localhost lab, run a MongoDB-backed login that passes
operator objects through to the query; expect one critical severity finding at
`firm`. Status: pending manual run. Expected Precision 100 percent on this
endpoint class.

## Precision

True positives 2, false positives 0. Precision 1.00.

## Recall

True positives 2, false negatives 0. Recall 1.00.

## Gate Verdict

PASS. Precision 1.00 is above the 0.99 gate. Corpus holds 0 unexpected `firm` plus.

## Dataset

- Dataset hash: `4abbc0758508c9876638a506cfa03db8df00227956ba70e2103f72cad86756e3`
  (sha256 over all 4 fixture files under `tests/fixtures/nosql-auth-bypass-differential/`).
- Samples: TP=2, FP=0, TN=2, FN=0. Fixture-only measurement; lab pending above.
  `TestMetricGate` fails the build if this hash drifts from the fixtures.

## Limitations

- Query-string (non-JSON) NoSQL auth bypass variants are not covered by this
  body-based plugin.
- Account lockout policies in front of the login can mask the divergence; the
  plugin stops at the first accepted variant and never loops credentials.

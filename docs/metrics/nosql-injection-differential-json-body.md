<!--
SPDX-License-Identifier: AGPL-3.0-only
Copyright (C) 2026 Xmar1881 / GASH contributors
Module: github.com/Xmar1881/Gash

File: docs/metrics/nosql-injection-differential-json-body.md
What: Precision and recall report for the Tier 2 JSON-body NoSQL operator injection plugin.
Why: Proves the true/false divergence meets the 99 percent precision gate.
-->

# Metrics: nosql-injection-differential-json-body

## Overview

Tier 2 active JS plugin. Oracle `differential` (3/3 true/false stability plus a
clean control). The query-point NoSQL plugins cannot reach a JSON API: an
operator object has to be built into the request object around the discovered
field and sent as `application/json`.

Two always-true operator objects (`$ne` with an unlikely value, `$gt` with an
empty bound) are each compared against one non-matching literal across three
repeats. A body that echoes our operator or value is discarded as noise.

## Evidence Standard

Differential rule (GASH-005). Three stable repeats per branch that diverge,
with a control that does not match the true branch, are `confirmed`; any
instability rejects.

## Fixtures

- Positive: 1 of 1 accepted (`confirmed`; operator object matches every record
  while the literal matches none).
- Negative: 1 of 1 rejected (operator object treated as a literal, both
  branches identical).
- Command:
  `go run ./cmd/gash plugins test plugins/nosql/nosql-injection-differential-json-body.js`

## JS E2E

`TestNoSQLInjectionDifferentialJSONBodyE2E`
(`tests/plugins/tier2_nosql_jwt_xpath_test.go`) executes the real script through
`loader.ExecuteJS`: an operator-aware backend yields one `confirmed` candidate
that carries the raw `application/json` body; an operator-blind backend yields
none.

## Corpus Result

The differential oracle rejects identical true/false branches, so the static
corpus gate produces no finding for this plugin.

## Lab Result

Procedure: serve a JSON query endpoint that passes the body straight into a
document-store query in the localhost lab, scan with `--active`, expect one
high severity finding at `confirmed`.
Status: pending manual run.

## Precision

True positives 1, false positives 0. Precision 1.00.

## Recall

True positives 1, false negatives 0. Recall 1.00.

## Gate Verdict

PASS. Precision 1.00 is above the 0.99 gate. Corpus holds 0 findings.

## Dataset

- Dataset hash: `87eae7354c1567505e0ad988eab7c4d5f5b58af0236a342ab3ba29966f03d12a`
  (sha256 over both fixture files under `tests/fixtures/nosql-injection-differential-json-body/`).
- Samples: TP=1, FP=0, TN=1, FN=0. `TestMetricGate` fails on hash drift.

## Limitations

- Only two operator families are probed; nested paths inside the JSON object
  are not expanded.
- A backend that normalizes or rejects operator objects returns identical
  branches and rejects honestly.
- Authentication bypass via NoSQL operators stays with
  `nosql-auth-bypass-differential`.

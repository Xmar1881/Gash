<!--
SPDX-License-Identifier: AGPL-3.0-only
Copyright (C) 2026 Xmar1881 / GASH contributors
Module: github.com/Xmar1881/Gash

File: docs/metrics/nosql-injection-error.md
What: Precision and recall report for the NoSQL injection error-based reference plugin.
Why: Proves Tier 1 error oracle (generic_error mode) meets signature-plus-control standard
  for MongoDB-style $ne/$where probes at the firm ceiling.
-->

# Metrics: nosql-injection-error

## Overview

Tier 1 active plugin. Oracle `error` with `mode: generic_error`. MongoDB-style
error signature match (`MongoError`, `BSONTypeError`, `Exception`, `stack trace`,
`Fatal error`) plus absent-in-control proof. Maximum confidence `firm` with or
without control (generic error disclosure is informational, never `confirmed`).
Probe payload is a harmless `{"$ne": null}` operator value; no destructive
operator (`$where` JS execution is documented only as a signature, never sent
as an active RCE probe).

## Evidence Standard

Rule GASH-004 extended to NoSQL. `generic_error` signatures: stack trace,
exception, traceback, fatal error, internal server error, syntax error, plus
`error:` substring which covers `MongoError:` and `BSONTypeError:` forms.
Control response must not contain the same signature. WAF/block pages classify
`Untrusted` and always reject. Firm ceiling is intentional: a DB error string
alone does not prove exploitable injection, only a reproducible error oracle.

## Fixtures

- Positive: 2 of 2 accepted (2 `firm` with control; `$ne` CastError, `$where` BSON error).
- Negative: 2 of 2 rejected (no error, same error in control).
- Command: `go run ./cmd/gash plugins test plugins/nosql/nosql-injection-error.yaml`

## Corpus Result

Oracle `error` (generic_error) evaluated against clean, SPA, WAF, encoded, and dynamic
bodies. `firm` plus findings: 0. WAF body correctly rejects as untrusted.

## Lab Result

Procedure: serve a MongoDB-backed login/search endpoint that renders DB errors,
scan the `username`/`search` parameter with the `$ne` probe, expect one high
severity finding at `firm` and no claim on the hardened control.
Status: pending manual run. Expected Precision 100 percent on this page class.

## Precision

True positives 2, false positives 0. Precision 1.00.

## Recall

True positives 2, false negatives 0. Recall 1.00.

## Gate Verdict

PASS. Precision 1.00 is above the 0.99 gate. Corpus holds 0 `firm` plus.

## Dataset

- Dataset hash: `5dcae85a83cdd1e12b9636d1704a54389a2059482c52b6b222b263c3b4127df3`
  (sha256 over all 4 fixture files under `tests/fixtures/nosql-injection-error/`).
- Samples: TP=2, FP=0, TN=2, FN=0. Fixture-only measurement; lab pending above.
  `TestMetricGate` fails the build if this hash drifts from the fixtures.

## Limitations

- Generic error strings cannot distinguish MongoDB from other backends; triage
  must confirm the backend before claiming NoSQL injection.
- Blind NoSQL (boolean/time/OOB) is out of scope; this plugin covers error oracle only.
- `$where` JS payloads are never sent; only the error signature is matched.

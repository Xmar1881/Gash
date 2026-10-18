<!--
SPDX-License-Identifier: AGPL-3.0-only
Copyright (C) 2026 Xmar1881 / GASH contributors
Module: github.com/Xmar1881/Gash

File: docs/metrics/sqli-error-based.md
What: Precision and recall report for the error-based SQLi plugin.
Why: Proves signature plus absent-in-control evidence meets the gate.
-->

# Metrics: sqli-error-based

## Overview

Tier 2 plugin. Oracle `error` with the MySQL, Postgres, MSSQL, Oracle, and
SQLite signature set. Signature plus clean control confirms.

## Evidence Standard

Rule GASH-004. A signature that also appears in the control response rejects.
Generic wording without a known signature stays `tentative` at most. Clean
pages reject.

## Fixtures

- Positive: 6 of 6 accepted at `confirmed` (MSSQL conversion, MySQL
  syntax, Postgres `invalid input syntax`, Oracle `ORA-`, SQLite,
  MySQL XPATH from `EXTRACTVALUE`/`UPDATEXML`).
- Negative: 4 of 4 clean (control collision rejects, clean page rejects,
  generic wording stays `tentative`, XPATH signature in control rejects).
- Command: `go run ./cmd/gash plugins test plugins/sqli/sqli-error-based.js`

## Corpus Result

Oracle `error` against clean, SPA, WAF, encoded, and dynamic bodies.
`firm` plus findings: 0. The live probe corpus mirrors
`internal/fuzz/sqli_corpus.go` (boolean pair plus ten DBMS error probes:
EXTRACTVALUE/UPDATEXML, CONVERT, CAST, case-mixing, double-encoding, tab and
MySQL versioned-comment variants) and a sync test locks both in lockstep.

## Lab Result

Procedure: use the DVWA SQLi page from `docker-compose.lab.yml`, scan the id
parameter, expect a high severity `confirmed` finding on the error endpoint.
Status: pending manual run. Expected Precision 100 percent on error endpoints.

## Precision

True positives 6, false positives 0. Precision 1.00.

## Recall

True positives 6, false negatives 0. Recall 1.00.

## Gate Verdict

PASS. Precision 1.00 is above the 0.99 gate. Corpus holds 0 `firm` plus.

## Dataset

- Dataset hash: `894ae2858cd86e30ba97c83475f8b99f815f5e50efe3ddd3384cdf406dfa7ebb`
  (sha256 over all 10 fixture files under `tests/fixtures/sqli-error-based/`).
- Samples: TP=6, FP=0, TN=4, FN=0. Fixture-only measurement; lab pending above.
  `TestMetricGate` fails the build if this hash drifts from the fixtures.

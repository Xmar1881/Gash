<!--
SPDX-License-Identifier: AGPL-3.0-only
Copyright (C) 2026 Xmar1881 / GASH contributors
Module: github.com/Xmar1881/Gash

File: docs/metrics/sqli-auth-bypass.md
What: Precision and recall report for the login-form SQLi auth-bypass plugin.
Why: Proves credential-field error signatures confirm only with a clean control.
-->

# Metrics: sqli-auth-bypass

## Overview

Tier 1 active plugin. Oracle `error` (mode `sqli`). Targets login and
credential parameters (`username`, `user`, `login`, `email`, `password`,
`passwd`) with a classic auth-bypass payload. Maximum confidence `confirmed`
(DB signature plus absent-in-control proof). No login is performed and no
state changes.

## Evidence Standard

Rule GASH-004 (CWE-89). Requires a MySQL/PostgreSQL/MSSQL/Oracle/SQLite
error signature in the payload response plus its absence in the neutral
control response. WAF/block pages classify `Untrusted` and always reject.

## Fixtures

- Positive: 2 of 2 accepted (`confirmed`: MySQL syntax error, MSSQL conversion).
- Negative: 2 of 2 rejected (hardened login, signature also in control).
- Command: `go run ./cmd/gash plugins test plugins/sqli/sqli-auth-bypass.yaml`

## Corpus Result

Oracle `error` is covered by `TestB4CorpusZeroFirmPlus`: 0 `firm` plus
findings on clean, SPA, WAF, encoded, and dynamic bodies. A WAF block body
correctly rejects as untrusted.

## Lab Result

Procedure: serve a login form concatenating credentials into SQL, scan with
`--active`, expect one critical finding at `confirmed`.
Status: pending manual run (see `docs/metrics/lab-aggressive-*.md` when the
localhost lab lands). Expected Precision 100 percent on this vulnerability class.

## Precision

True positives 2, false positives 0. Precision 1.00.

## Recall

True positives 2, false negatives 0. Recall 1.00.

## Gate Verdict

PASS. Precision 1.00 is above the 0.99 gate. Corpus holds 0 `firm` plus.

## Dataset

- Dataset hash: `d51e40179022ea30316c9a2568aa29067f54c0bff65be2cfacad89777e163fca`
  (sha256 over all 4 fixture files under `tests/fixtures/sqli-auth-bypass/`).
- Samples: TP=2, FP=0, TN=2, FN=0. Fixture-only measurement; lab pending above.
  `TestMetricGate` fails the build if this hash drifts from the fixtures.

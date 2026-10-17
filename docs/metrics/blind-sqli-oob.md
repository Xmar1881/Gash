<!--
SPDX-License-Identifier: AGPL-3.0-only
Copyright (C) 2026 Xmar1881 / GASH contributors
Module: github.com/Xmar1881/Gash

File: docs/metrics/blind-sqli-oob.md
What: Precision and recall report for the blind SQLi OOB reference plugin.
Why: Proves Tier 1 OOB oracle meets single-callback confirmed standard.
-->

# Metrics: blind-sqli-oob

## Overview

Tier 1 active plugin. Oracle `oob` (requires `--oob-server`). Blind SQL injection
detection via out-of-band DNS/HTTP callback (e.g., `xp_dirtree`, `LOAD_FILE`,
`UTL_INADDR.GET_HOST_ADDRESS`). Single cryptographically-random callback match
yields `confirmed`. Without OOB server, plugin is skipped (not an error).

## Live Path (dialect corpus, deferred shared window)

The live corpus sends callback-only functions per dialect: MSSQL
`xp_dirtree`/`xp_fileexist` (UNC and HTTP path forms), MySQL `LOAD_FILE` with
UNC path (backslash and forward-slash variants), Oracle
`UTL_INADDR.GET_HOST_ADDRESS` and `UTL_HTTP.REQUEST`, each with its own
single-use `{{CORRELATION}}` token under the operator's real
`{{OOB_DOMAIN}}`/`{{OOB_URL}}` (server-pinned expansion; previously a broken
literal placeholder). All tokens are verified in ONE shared bounded window
(`oob.WaitForCallbacks`, 10 s / 2 polls); unmatched tokens yield no finding.
PostgreSQL is deliberately absent: it has no callback-only blind primitive
short of `COPY ... TO PROGRAM` / `dblink`, both outside the no-command-execution
scope — recorded as a gap in `known-limits.md`.

## Evidence Standard

Rule GASH-008/010/012/013. Correlation ID is cryptographically random (128-bit).
Namespace isolates scan context. Callback match (DNS A/AAAA or HTTP) is sufficient.
Control request not required (OOB channel is independent). WAF/block pages classify
`Untrusted` and always reject.

## Fixtures

- Positive: 2 of 2 accepted (2 `confirmed` with callback).
- Negative: 2 of 2 rejected (no callback, OOB not configured).
- Command: `go run ./cmd/gash plugins test plugins/blind-sqli-oob/blind-sqli-oob.yaml`

## Corpus Result

Oracle `oob` evaluated against clean, SPA, WAF, encoded, and dynamic bodies.
`confirmed` findings: 0 (OOB not configured in corpus). WAF body correctly rejects
as untrusted.

## Lab Result

Procedure: configure `--oob-server https://oob.example`, serve blind SQLi vulnerable
endpoint, scan with payload, expect one critical severity finding at `confirmed`.
Status: pending manual run. Expected Precision 100 percent on this vulnerability class.

## Precision

True positives 2, false positives 0. Precision 1.00.

## Recall

True positives 2, false negatives 0. Recall 1.00.

## Gate Verdict

PASS. Precision 1.00 is above the 0.99 gate. Corpus holds 0 `firm` plus.

## Dataset

- Dataset hash: `e61015851c60167c40fc3df9de23d0e7c20247fa1b0d4e2eca7a54992d7371fb`
  (sha256 over all 4 fixture files under `tests/fixtures/blind-sqli-oob/`).
- Samples: TP=2, FP=0, TN=2, FN=0. Fixture-only measurement; lab pending above.
  `TestMetricGate` fails the build if this hash drifts from the fixtures.

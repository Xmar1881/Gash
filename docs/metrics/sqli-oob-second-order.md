<!--
SPDX-License-Identifier: AGPL-3.0-only
Copyright (C) 2026 Xmar1881 / GASH contributors
Module: github.com/Xmar1881/Gash

File: docs/metrics/sqli-oob-second-order.md
What: Precision and recall report for the Tier 2 blind second-order SQLi plugin.
Why: Proves the write/neutral-re-read discipline meets the 99 percent gate
  behind the oob oracle.
-->

# Metrics: sqli-oob-second-order

## Overview

Tier 2 active JS plugin. Oracle `oob` (required). The payload is a
callback-only database closure: it reads no table, writes no row and executes
no command, so the resolver hit is the whole signal. The plugin stores the
closure at an injection point and re-reads the same point with a neutral
value, which is what makes the finding second-order rather than first-order.

## Evidence Standard

OOB rule (GASH-008 family): a single-use correlation token matching a real
callback is `confirmed`. No callback, an unconfigured server, or a token that
never appears rejects. There is no timing or error fallback.

## Fixtures

- Positive: 1 of 1 accepted (`confirmed` on a matched callback).
- Negative: 2 of 2 rejected (no callback observed; server rejected the stored
  value).
- Command:
  `go run ./cmd/gash plugins test plugins/sqli/sqli-oob-second-order.js`

## JS E2E

`TestSQLiOOBSecondOrderE2E` (`tests/plugins/tier2_expansion_test.go`) executes
the real script through `loader.ExecuteJS`: a matched callback yields one
`confirmed` `oob` candidate and the two sends are asserted to be the
callback-carrying write followed by the neutral re-read. Without an OOB server
the plugin sends nothing. A separate subtest holds the declared send budget.

## Corpus Result

Oracle `oob` is disabled for the shared corpus gate, so clean bodies produce no
`firm`-plus finding.

## Lab Result

Procedure: point the plugin at a lab endpoint that stores the value and layers
it into a later query, run with `--active --oob-server`, expect one `critical`
finding at `confirmed`. Status: pending manual run.

## Precision

True positives 1, false positives 0. Precision 1.00.

## Recall

True positives 1, false negatives 0. Recall 1.00.

## Gate Verdict

PASS. Precision 1.00 is above the 0.99 gate. Corpus holds 0 findings.

## Dataset

- Dataset hash: `bd6392e323f0eba8c7fe3b983111cd0752db1f8059dcbaf18b8080c362579f94`
- Samples: TP=1, FP=0, TN=2, FN=0. `TestMetricGate` fails on hash drift.

## Limitations

- PostgreSQL has no callback-only primitive short of `COPY ... TO PROGRAM`
  (documented in `docs/known-limits.md`), so the payload set is MSSQL-flavoured
  and PostgreSQL second-order blind stays untested here.
- The engine discovers the write and the re-read at the same point; a separate
  downstream render endpoint is not discovered.

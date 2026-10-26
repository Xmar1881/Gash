<!--
SPDX-License-Identifier: AGPL-3.0-only
Copyright (C) 2026 Xmar1881 / GASH contributors
Module: github.com/Xmar1881/Gash

File: docs/metrics/sqli-json-body-timing.md
What: Precision and recall report for the Tier 2 JSON-body time-based SQLi plugin.
Why: Proves the latency divergence meets the 99 percent precision gate at its
  honest firm ceiling behind the statistical timing oracle.
-->

# Metrics: sqli-json-body-timing

## Overview

Tier 2 active JS plugin. Oracle `timing` (Mann-Whitney U over Go-measured
`rttMs`, ceiling `firm`). The error and boolean JSON plugins need an in-band
signal; when the endpoint answers identically regardless of the payload, only
the latency of the injected request differs.

Three neutral-value baseline requests are measured first, then three requests
per delay payload (`SLEEP(5)` and `WAITFOR DELAY`). Measuring the baseline first
keeps a genuinely slow endpoint from being read as an injected delay.

## Evidence Standard

Timing rule (GASH-006 family extended to JSON bodies). Median divergence must
clear `min_delay_ms` (5000) and the statistical test; the ceiling stays `firm`
because timing carries no confirmation.

## Fixtures

- Positive: 1 of 1 accepted (`firm`; injected request far slower than the
  baseline).
- Negative: 1 of 1 rejected (payload latency matches the baseline).
- Command:
  `go run ./cmd/gash plugins test plugins/sqli/sqli-json-body-timing.js`

## JS E2E

`TestSQLiJSONBodyTimingE2E` (`tests/plugins/tier2_batch_test.go`) executes the
real script through `loader.ExecuteJS` with a transport reporting `rttMs`: a
backend slow only for the delay payload yields one `firm` candidate (never
`confirmed`); a uniformly fast backend yields none.

## Corpus Result

Oracle `timing` needs a measured sample series, so the static corpus gate
produces no finding for this plugin.

## Lab Result

Procedure: serve a JSON query endpoint with a naive SQL concatenation in the
localhost lab, scan with `--active`, expect one high severity finding at `firm`.
Status: pending manual run.

## Precision

True positives 1, false positives 0. Precision 1.00.

## Recall

True positives 1, false negatives 0. Recall 1.00.

## Gate Verdict

PASS. Precision 1.00 is above the 0.99 gate. Corpus holds 0 findings.

## Dataset

- Dataset hash: `ffb0032ff8650cc1e5d7d568c7c827579c23d624907f1b50f34ed9ac311e8a08`
  (sha256 over both fixture files under `tests/fixtures/sqli-json-body-timing/`).
- Samples: TP=1, FP=0, TN=1, FN=0. `TestMetricGate` fails on hash drift.

## Limitations

- Jittered networks can suppress the signal; `baseline_stddev` is not derived
  from the live baseline in v1.
- Database-specific delay functions beyond SLEEP/WAITFOR are not included.
- Second-order JSON timing is covered by `sqli-second-order-timing`.

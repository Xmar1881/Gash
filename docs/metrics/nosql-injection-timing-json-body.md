<!--
SPDX-License-Identifier: AGPL-3.0-only
Copyright (C) 2026 Xmar1881 / GASH contributors
Module: github.com/Xmar1881/Gash

File: docs/metrics/nosql-injection-timing-json-body.md
What: Precision and recall report for the Tier 2 JSON-body time-based NoSQL plugin.
Why: Proves the latency divergence meets the 99 percent precision gate at its
  honest firm ceiling behind the statistical timing oracle.
-->

# Metrics: nosql-injection-timing-json-body

## Overview

Tier 2 active JS plugin. Oracle `timing` (Mann-Whitney U over Go-measured
`rttMs`, ceiling `firm`). The query-string `nosql-injection-timing` plugin
cannot reach a JSON API: a `$where` operator has to sit at the top level of
the request object, so the body is rebuilt and sent with an explicit
`application/json` content type.

Three neutral `$where` (`"false"`) baseline requests are measured first, then
three requests per delay payload (`sleep(5000)` and a `Date`-based busy loop).
Measuring the baseline first keeps a genuinely slow endpoint from being read as
an injected delay.

## Evidence Standard

Timing rule (GASH-006 family extended to JSON bodies). Median divergence must
clear `min_delay_ms` (5000) and the statistical test; the ceiling stays `firm`
because timing carries no confirmation.

## Fixtures

- Positive: 1 of 1 accepted (`firm`; injected request far slower than the
  baseline).
- Negative: 1 of 1 rejected (payload latency matches the baseline).
- Command:
  `go run ./cmd/gash plugins test plugins/nosql/nosql-injection-timing-json-body.js`

## JS E2E

`TestNoSQLInjectionTimingJSONBodyE2E` (`tests/plugins/tier2_nosql_jwt_xpath_test.go`)
executes the real script through `loader.ExecuteJS` with a transport reporting
`rttMs`: a backend slow only for the delay payload yields one `firm` candidate
(never `confirmed`); a uniformly fast backend yields none.

## Corpus Result

Oracle `timing` needs a measured sample series, so the static corpus gate
produces no finding for this plugin.

## Lab Result

Procedure: serve a JSON query endpoint backed by MongoDB with a naive
`$where` passthrough in the localhost lab, scan with `--active`, expect one
high severity finding at `firm`.
Status: pending manual run.

## Precision

True positives 1, false positives 0. Precision 1.00.

## Recall

True positives 1, false negatives 0. Recall 1.00.

## Gate Verdict

PASS. Precision 1.00 is above the 0.99 gate. Corpus holds 0 findings.

## Dataset

- Dataset hash: `6080328cab161e14fd209c9b49aafc8b9e8b283d2c4764e6a4c8495b46fe4a91`
  (sha256 over both fixture files under `tests/fixtures/nosql-injection-timing-json-body/`).
- Samples: TP=1, FP=0, TN=1, FN=0. `TestMetricGate` fails on hash drift.

## Limitations

- Jittered networks can suppress the signal; `baseline_stddev` is not derived
  from the live baseline in v1.
- `sleep()` availability depends on the server-side JavaScript engine a
  document store exposes; the busy-loop variant only differs in syntax.
- Second-order variants beyond the same request object are out of scope.

<!--
SPDX-License-Identifier: AGPL-3.0-only
Copyright (C) 2026 Xmar1881 / GASH contributors
Module: github.com/Xmar1881/Gash

File: docs/metrics/sqli-second-order.md
What: Precision and recall report for the Tier 2 second-order SQLi plugin.
Why: Proves the write-then-neutral-re-read correlation meets the 99 percent
  precision gate while keeping every claim inside the engine error oracle.
-->

# Metrics: sqli-second-order

## Overview

Tier 2 active JS plugin. Oracle `error` (database signature mode). Tier 1
declares one request per payload, so it can only prove first-order injection.
This plugin sequences two correlated exchanges: it writes an error-prone
closure at an injection point, then re-reads the same point with a neutral
value and compares the read-back body against a pre-write baseline read.

Only a signature the baseline never showed can survive as evidence, so a
pre-existing error page cannot confirm. The write response itself is never
used as evidence: first-order reflection is a different class.

## Evidence Standard

Error-signature rule (GASH-004 family extended to state-borne injection).
Control is the pre-write baseline read of the same point; the oracle rejects
when the signature is present in the control. WAF/untrusted baselines reject
through the shared guard.

## Fixtures

- Positive: 2 of 2 accepted (`confirmed`; mysql and mssql signatures that
  appear only on the neutral re-read).
- Negative: 2 of 2 rejected (signature already in the baseline; no signature
  anywhere).
- Command: `go run ./cmd/gash plugins test plugins/sqli/sqli-second-order.js`

## JS E2E

`TestSQLiSecondOrderE2E` (`tests/plugins/sqli_second_order_test.go`) executes
the real script through `loader.ExecuteJS` with a mocked transport:

- Backend that persists the closure and errors only on the neutral re-read:
  one `confirmed` error candidate.
- Backend that errors on the write response but stays clean on the neutral
  re-read: zero candidates (first-order noise is not second-order proof).
- Send budget stays under the declared `max_requests` on a wide surface.

No new `host.oracles.*` binding is introduced (source grep asserts only
`host.oracles.error`).

## Corpus Result

Oracle `error` evaluated against clean, SPA, WAF, encoded, and dynamic bodies
in the shared corpus gate. No corpus body carries a database signature, so no
`firm`-plus finding is produced.

## Lab Result

Procedure: serve a stored-then-rendered item endpoint in the localhost lab
(write stores the field, a later neutral read renders it into a backend
query), scan with `--active`, expect one high severity finding at `confirmed`.
Status: pending manual run. Expected Precision 100 percent on this page class.

## Precision

True positives 2, false positives 0. Precision 1.00.

## Recall

True positives 2, false negatives 0. Recall 1.00.

## Gate Verdict

PASS. Precision 1.00 is above the 0.99 gate. Corpus holds 0 findings.

## Dataset

- Dataset hash: `cddae6351ac6cedaf0d8a3eebd9b7e5242aa67d1ac6448e8df58f2a9c281442f`
  (sha256 over all 4 fixture files under `tests/fixtures/sqli-second-order/`).
- Samples: TP=2, FP=0, TN=2, FN=0. Fixture-only measurement; lab pending above.
  `TestMetricGate` fails the build if this hash drifts from the fixtures.

## Limitations

- The second exchange is modelled as a neutral re-read of the same point; a
  separate downstream render endpoint is not discovered in v1.
- Delay variants for back-ends without in-band errors are covered by the
  companion `sqli-second-order-timing` plugin.
- Real-target recall (ORM and caching layers that defer the query) is
  unmeasured.

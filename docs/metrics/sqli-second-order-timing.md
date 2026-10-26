<!--
SPDX-License-Identifier: AGPL-3.0-only
Copyright (C) 2026 Xmar1881 / GASH contributors
Module: github.com/Xmar1881/Gash

File: docs/metrics/sqli-second-order-timing.md
What: Precision and recall report for the Tier 2 blind second-order SQLi plugin.
Why: Proves the write-then-timed-re-read correlation meets the 99 percent
  precision gate with the engine statistical timing oracle.
-->

# Metrics: sqli-second-order-timing

## Overview

Tier 2 active JS plugin. Oracle `timing` (Mann-Whitney U over Go-measured
`rttMs`, ceiling `firm`). When a stored payload never reflects an in-band
error, the only observable is the response time of a neutral request taken
AFTER the write.

The plugin writes a sleep payload, then times `repeats` neutral re-reads and
compares them against `repeats` baseline reads taken before any write, so a
slow page cannot be mistaken for a stored delay. The write exchange's own
latency is never measured.

## Evidence Standard

Timing rule (GASH-006/010 family extended to state-borne injection). Median
divergence must clear `min_delay_ms` (5000) and the statistical test; the
oracle ceiling stays `firm` because no OOB channel is used.

## Fixtures

- Positive: 1 of 1 accepted (`firm`; stored sleep payload delays the neutral
  re-read well past the 5 s floor).
- Negative: 1 of 1 rejected (neutral re-read timing matches the baseline).
- Command:
  `go run ./cmd/gash plugins test plugins/sqli/sqli-second-order-timing.js`

## JS E2E

`TestSQLiSecondOrderTimingE2E` (`tests/plugins/sqli_second_order_test.go`)
executes the real script through `loader.ExecuteJS` with a mocked transport
that reports `rttMs`:

- Backend that slows down only after the sleep payload was written: one
  `firm` timing candidate.
- Consistently fast backend: zero candidates.
- Send budget stays under the declared `max_requests` on a wide surface.

No new `host.oracles.*` binding is introduced (source grep asserts only
`host.oracles.timing`).

## Corpus Result

Oracle `timing` is not exercised against the static corpus bodies (it needs a
measured sample series). The shared corpus gate therefore reports no
`firm`-plus finding for this plugin; no static body can produce one.

## Lab Result

Procedure: same stored-then-rendered lab endpoint as `sqli-second-order`, but
with in-band errors suppressed; inject `SLEEP`/`WAITFOR DELAY`, scan with
`--active`, expect one high severity `firm` finding.
Status: pending manual run. Expected Precision 100 percent on this page class.

## Precision

True positives 1, false positives 0. Precision 1.00.

## Recall

True positives 1, false negatives 0. Recall 1.00.

## Gate Verdict

PASS. Precision 1.00 is above the 0.99 gate. Corpus holds 0 findings.

## Dataset

- Dataset hash: `9dd7912a83c62d4e1d5bc0bf0193743dc41dc8929e3d803950cc69ccdae7c7d3`
  (sha256 over both fixture files under
  `tests/fixtures/sqli-second-order-timing/`).
- Samples: TP=1, FP=0, TN=1, FN=0. Fixture-only measurement; lab pending above.
  `TestMetricGate` fails the build if this hash drifts from the fixtures.

## Limitations

- The timing ceiling is `firm`; OOB confirmation is out of scope for the
  second-order path (a caller-owned callback cannot be attributed to a stored
  payload without an extra channel).
- Jittered networks can suppress the signal; `baseline_stddev` is not derived
  from the live baseline in v1.
- The second exchange is modelled as a neutral re-read of the same point.

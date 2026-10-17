<!--
SPDX-License-Identifier: AGPL-3.0-only
Copyright (C) 2026 Xmar1881 / GASH contributors
Module: github.com/Xmar1881/Gash

File: docs/metrics/missing-rate-limit.md
What: Precision and recall report for the missing rate limit screen.
Why: Proves Tier 1 header oracle (ratelimit mode) with a budgeted burst
  reports missing rate limiting at the observational tentative ceiling and
  rejects protected endpoints.
-->

# Metrics: missing-rate-limit

## Overview

Tier 1 active plugin (`--active`, aggressive profile recommended,
`--scope`-gated). Oracle `header` with `mode: ratelimit` and `burst: 20`
(GASH-032, CWE-770). The runner sends a budgeted anonymous GET burst (default
20, hard cap 50, `max_requests: 30`, profile budget plus `RatePerSecond`
enforced by the policy session) to the bare endpoint. No 429, no lockout
headers (`Retry-After`, `RateLimit-*`, `X-RateLimit-*`), no rate-limit body
text yields a `tentative` missing-rate-limit finding. Any 429 in the burst,
or rate-limit headers/text, rejects (protected). No credential stuffing:
anonymous empty probes only, no login lockout risk.

## Evidence Standard

GASH-032 is an observational screen, not a policy proof. Accept requires the
full burst with zero 429 and zero rate-limit signals. Confidence is
`tentative` by ceiling: signal absence cannot prove server-side policy
absence, and the finding stays hidden unless `--show-tentative` is passed.
429 responses classify `Untrusted` at the baseline and reject before the mode
logic. Burst actually sent is pinned in the `burst` artifact; interrupted
bursts (budget/scope cut) report the collected count, never fabricated data.

## Fixtures

- Positive: 2 of 2 accepted (2 `tentative`; login page and JSON API with no signals).
- Negative: 2 of 2 rejected (429 lockout with `Retry-After`, 200 with `X-RateLimit-*` headers).
- Command: `go run ./cmd/gash plugins test plugins/rate-limit/missing-rate-limit.yaml`

## Corpus Result

Oracle `header` (ratelimit mode) evaluated against clean, SPA, WAF, encoded,
and dynamic bodies. No corpus body carries rate-limit signals, and none
reaches `firm` plus (tentative at most on clean pages). Covered by
`TestRateLimitMode` in `internal/oracle/new_detectors_test.go`; burst
aggregation (request count, early 429) by `TestTier1RateLimitBurst` in
`internal/plugin/loader/tier1_burst_test.go`.

## Lab Result

Procedure: serve a lab login/API endpoint with no throttling, scan with
`--profile aggressive --active --scope <lab>`, expect one medium severity
finding at `tentative` with `burst: 20`; enable throttling (429 after N) and
expect rejection. Status: pending manual run. Expected Precision 100 percent
on this page class.

## Precision

True positives 2, false positives 0. Precision 1.00.

## Recall

True positives 2, false negatives 0. Recall 1.00.

## Gate Verdict

PASS. Precision 1.00 is above the 0.99 gate. Corpus holds 0 `firm` plus.

## Dataset

- Dataset hash: `2fccb6956e894a988c72fc024ba3b0582e609e19484c8137e71cce24d6c9b1ba`
  (sha256 over all 4 fixture files under `tests/fixtures/missing-rate-limit/`).
- Samples: TP=2, FP=0, TN=2, FN=0. Fixture-only measurement; lab pending above.
  `TestMetricGate` fails the build if this hash drifts from the fixtures.

## Limitations

- Fixtures pin the single-probe floor; burst aggregation is covered by unit tests, live burst confirmation by the lab procedure above.
- `tentative` findings are hidden by default (`--show-tentative` required).
- Distributed/behavioral throttling (WAF-side, account-side) is out of scope; only endpoint 429/header signals are observed.

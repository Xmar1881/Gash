<!--
SPDX-License-Identifier: AGPL-3.0-only
Copyright (C) 2026 Xmar1881 / GASH contributors
Module: github.com/Xmar1881/Gash

File: docs/metrics/web-cache-poisoning-basic.md
What: Precision and recall report for the web cache poisoning differential plugin.
Why: Proves DifferentialOracle cache-buster versus normal detection meets the 99 percent
  precision gate (3/3 masked stability + divergence, unstable input rejects).
-->

# Metrics: web-cache-poisoning-basic

## Overview

Tier 1 active plugin. Oracle `differential`. Cache-buster (`gash-cache-poison`)
versus normal (`gash-cache-normal`) values compared with 3/3 masked stability;
stable divergence with unkeyed-input reflection gives `confirmed`, unstable or
identical branches reject (never `tentative`, never `firm`; differential is
confirmed-only per GASH-005). Only harmless marker values are sent; no cache
purge or destructive request.

## Evidence Standard

Differential rule (GASH-005 family extended to cache parsing). Masking profile
is the engine default (tokens, nonces, timestamps, UUIDs). True branch is the
poison marker repeated 3x, false branch is the normal marker repeated 3x, plus a
neutral control. After masking: all true identical, all false identical,
true != false. Unstable dynamic content rejects rather than confirming. WAF/block
pages classify `Untrusted` and always reject.

## Fixtures

- Positive: 2 of 2 accepted (2 `confirmed`; utm_source reflection with X-Cache HIT, JSON poisoned versus normal).
- Negative: 2 of 2 rejected (correctly keyed cache with no divergence, unstable edge).
- Command: `go run ./cmd/gash plugins test plugins/web-cache/web-cache-poisoning-basic.yaml`

## Corpus Result

Oracle `differential` evaluated against clean, SPA, WAF, encoded, and dynamic bodies.
No corpus body shows stable cross-value divergence. `firm` not emitted
(differential is confirmed-only).

## Lab Result

Procedure: serve a cache-fronted endpoint that reflects `utm_source` and caches
by key without it, scan with paired poison/normal values, expect one medium
severity finding at `confirmed`.
Status: pending manual run. Expected Precision 100 percent on this page class.

## Precision

True positives 2, false positives 0. Precision 1.00.

## Recall

True positives 2, false negatives 0. Recall 1.00.

## Gate Verdict

PASS. Precision 1.00 is above the 0.99 gate. Corpus holds 0 findings.

## Dataset

- Dataset hash: `05cbcd2cfbd55f97ac50b3d9b467c14332ae9dc0293302076a9bd3701e1a0205`
  (sha256 over all 4 fixture files under `tests/fixtures/web-cache-poisoning-basic/`).
- Samples: TP=2, FP=0, TN=2, FN=0. Fixture-only measurement; lab pending above.
  `TestMetricGate` fails the build if this hash drifts from the fixtures.

## Limitations

- Tier 1 models poisoning as true/false query-value divergence; header-based
  unkeyed inputs (X-Forwarded-Host) need Tier 2 with header injection points (future work).
- Cache HIT/MISS header semantics are not asserted; only body divergence is proof in v1.
- Time-based cache timing or Web Cache Deception path-confusion variants are out of scope.

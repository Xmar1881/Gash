<!--
SPDX-License-Identifier: AGPL-3.0-only
Copyright (C) 2026 Xmar1881 / GASH contributors
Module: github.com/Xmar1881/Gash

File: docs/metrics/web-cache-method-override.md
What: Precision and recall report for the Tier 2 method-override cache-poisoning plugin.
Why: Proves the primed canary survival meets the 99 percent precision gate.
-->

# Metrics: web-cache-method-override

## Overview

Tier 2 active JS plugin. Oracle `differential` (3/3 stability plus a clean
control). Cache poisoning is a three-beat sequence (clean read, prime, clean
read); the only proof is that the canary outlives the priming request. This
plugin covers the unkeyed method-override header family
(`X-HTTP-Method-Override`, `X-Method-Override`, `X-HTTP-Method`), which the
forwarded-host plugin does not.

Only `GET` leaves the scanner: the override header is a forwarding hint, so no
destructive method is ever dispatched even when a proxy honours it.

## Evidence Standard

Differential rule (GASH-005). The canary must be absent in the three pre-prime
reads and present in all three post-prime reads; the differential oracle then
enforces 3/3 stability and the clean control.

## Fixtures

- Positive: 1 of 1 accepted (`confirmed`; primed response served to headerless
  reads).
- Negative: 1 of 1 rejected (canary does not survive the priming request).
- Command:
  `go run ./cmd/gash plugins test plugins/cache-poisoning/web-cache-method-override.js`

## JS E2E

`TestWebCacheMethodOverrideE2E` (`tests/plugins/tier2_nosql_jwt_xpath_test.go`)
executes the real script through `loader.ExecuteJS`: a caching backend that
re-serves the primed body to headerless reads yields one `confirmed` candidate;
a backend that always serves the origin body yields none.

## Corpus Result

The differential oracle rejects identical true/false branches, so the static
corpus gate produces no finding for this plugin.

## Lab Result

Procedure: front a localhost app with a caching reverse proxy in the lab, scan
with `--active`, expect one high severity finding at `confirmed`.
Status: pending manual run.

## Precision

True positives 1, false positives 0. Precision 1.00.

## Recall

True positives 1, false negatives 0. Recall 1.00.

## Gate Verdict

PASS. Precision 1.00 is above the 0.99 gate. Corpus holds 0 findings.

## Dataset

- Dataset hash: `f054e14c6c4be8949c2b07c40ea833211fcf696d407db661945acd7c17a7f2f4`
  (sha256 over both fixture files under `tests/fixtures/web-cache-method-override/`).
- Samples: TP=1, FP=0, TN=1, FN=0. `TestMetricGate` fails on hash drift.

## Limitations

- The canary must be reflected into the response for the sequence to prove
  caching; a proxy that keys the header, or an app that never reflects the
  override value, rejects honestly (zero recall, no false positives).
- Forwarded-host unkeyed headers stay with `web-cache-unkeyed-header`; `Vary`
  and path-override headers are not primed yet.

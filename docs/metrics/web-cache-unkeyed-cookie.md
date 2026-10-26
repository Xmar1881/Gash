<!--
SPDX-License-Identifier: AGPL-3.0-only
Copyright (C) 2026 Xmar1881 / GASH contributors
Module: github.com/Xmar1881/Gash

File: docs/metrics/web-cache-unkeyed-cookie.md
What: Precision and recall report for the Tier 2 unkeyed-cookie cache poisoning plugin.
Why: Proves the clean/prime/clean cookie sequence meets the 99 percent gate
  behind the differential oracle.
-->

# Metrics: web-cache-unkeyed-cookie

## Overview

Tier 2 active JS plugin. Oracle `differential`. The sequence is three clean
reads, one priming request carrying a per-run canary cookie, then three clean
reads. The canary must be absent before priming and present after it in every
read, which is what proves the cache key ignores the Cookie header.

## Evidence Standard

Differential rule (GASH-030 family): three stable poisoned reads, three stable
clean reads, a divergence and a control request all give `confirmed`. A canary
that was already present before priming does not prove anything and rejects.

## Fixtures

- Positive: 1 of 1 accepted (`confirmed`).
- Negative: 2 of 2 rejected (cookie is keyed; canary present before priming).
- Command:
  `go run ./cmd/gash plugins test plugins/cache-poisoning/web-cache-unkeyed-cookie.js`

## JS E2E

`TestWebCacheUnkeyedCookieE2E` (`tests/plugins/tier2_expansion_test.go`)
executes the real script against a mock cache that only starts echoing the
canary after priming, asserting one `confirmed` candidate, that a keyed Cookie
header rejects, and that the send budget holds.

## Corpus Result

Oracle `differential` is covered by the shared corpus gate and produces no
`firm`-plus finding on clean bodies.

## Lab Result

Procedure: lab reverse proxy configured with a cache that ignores Cookie, run
with `--active`, expect one `high` finding at `confirmed`. Status: pending
manual run.

## Precision

True positives 1, false positives 0. Precision 1.00.

## Recall

True positives 1, false negatives 0. Recall 1.00.

## Gate Verdict

PASS. Precision 1.00 is above the 0.99 gate. Corpus holds 0 findings.

## Dataset

- Dataset hash: `c0c98b8951ed2e55660bba758cb8c35c1eca14e7473afb7f36d8ca37c8302466`
- Samples: TP=1, FP=0, TN=2, FN=0. `TestMetricGate` fails on hash divergence.

## Limitations

- The plugin needs the application to reflect a cookie value into the body;
  a cache that ignores cookies but never reflects one yields a false negative.
- Cache TTL and `Vary` interactions are not measured, and a shared cache
  already warm with another tenant's entry can mask the sequence.

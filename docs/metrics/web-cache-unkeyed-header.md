<!--
SPDX-License-Identifier: AGPL-3.0-only
Copyright (C) 2026 Xmar1881 / GASH contributors
Module: github.com/Xmar1881/Gash

File: docs/metrics/web-cache-unkeyed-header.md
What: Precision and recall report for the Tier 2 unkeyed-header cache poisoning plugin.
Why: Proves the clean/prime/clean sequence meets the 99 percent precision gate
  behind the differential oracle.
-->

# Metrics: web-cache-unkeyed-header

## Overview

Tier 2 active JS plugin. Oracle `differential`. Tier 1 host-header checks send
one probe and read one response; cache poisoning is a three-beat sequence and
the only proof is that the canary OUTLIVES the priming request.

Sequence per URL: three clean reads (`false` branch and baseline), one priming
request carrying `X-Forwarded-Host`, `X-Host` and `X-Forwarded-Server` set to a
per-run canary host, then three clean reads (`true` branch). The plugin
pre-gates on the canary being absent before priming and present in every read
after it, then the differential oracle enforces 3/3 masked stability.

## Evidence Standard

Differential rule (GASH-005 family extended to cache-key behaviour). The
canary host is unique per run, so a poisoned response cannot be confused with
pre-existing content. A canary already present before priming invalidates the
sequence instead of confirming it.

## Fixtures

- Positive: 1 of 1 accepted (`confirmed`; primed response served to headerless
  reads).
- Negative: 1 of 1 rejected (canary does not survive the priming request).
- Command:
  `go run ./cmd/gash plugins test plugins/cache-poisoning/web-cache-unkeyed-header.js`

## JS E2E

`TestWebCacheUnkeyedHeaderE2E`
(`tests/plugins/web_cache_unkeyed_header_test.go`) executes the real script
through `loader.ExecuteJS` with a mocked transport that caches only after a
priming header was seen:

- Backend that stores the primed body and serves it to headerless reads: one
  `confirmed` candidate; the priming request is asserted to carry the
  forwarding headers.
- Backend that ignores the header (never poisons): zero candidates.
- Backend already poisoned before priming: zero candidates.
- Send budget stays under the declared `max_requests`.

No new `host.oracles.*` binding is introduced (source grep asserts only
`host.oracles.differential`).

## Corpus Result

Oracle `differential` evaluated against clean, SPA, WAF, encoded, and dynamic
bodies. No corpus body shows stable cross-value divergence. `firm` is not
emitted (differential is confirmed-only).

## Lab Result

Procedure: put a caching reverse proxy in front of the localhost lab, forward
the unkeyed host headers to the origin, scan with `--active`, expect one high
severity finding at `confirmed` (the proxy must echo the host into the body).
Status: pending manual run. Requires the proxy layer, so the lab is separate
from the fixture measurement.

## Precision

True positives 1, false positives 0. Precision 1.00.

## Recall

True positives 1, false negatives 0. Recall 1.00.

## Gate Verdict

PASS. Precision 1.00 is above the 0.99 gate. Corpus holds 0 findings.

## Dataset

- Dataset hash: `05842118e41277c1b1683a2ab434b2ee225f06c5a2004c15caf4c59961e67d36`
  (sha256 over both fixture files under
  `tests/fixtures/web-cache-unkeyed-header/`).
- Samples: TP=1, FP=0, TN=1, FN=0. Fixture-only measurement; lab pending above.
  `TestMetricGate` fails the build if this hash drifts from the fixtures.

## Limitations

- Only the forwarded-host header family is primed; further unkeyed headers
  (X-Forwarded-Scheme, X-Original-URL) are not covered in v1.
- A realistically configured cache requires the three reads to land inside the
  cache TTL; short TTLs can cause false negatives.
- CDN-level normalisation of the forwarding headers is unmeasured.

<!--
SPDX-License-Identifier: AGPL-3.0-only
Copyright (C) 2026 Xmar1881 / GASH contributors
Module: github.com/Xmar1881/Gash

File: docs/metrics/jwt-alg-confusion.md
What: Precision and recall report for the Tier 1 JWT algorithm confusion plugin.
Why: Proves header oracle JWT alg confusion detection meets the 99 percent precision gate.
-->

# Metrics: jwt-alg-confusion

## Overview

Tier 1 passive plugin. Oracle `header` with mode `jwt_alg`. Inspects response headers (Authorization, WWW-Authenticate, custom debug headers) for JWT algorithm confusion indicators: `none` algorithm tokens, HS256/RS256 key confusion debug output, algorithm validation error details.

## Evidence Standard

Rule GASH-019 extended (CWE-347, CWE-287). JWT algorithm confusion occurs when server accepts `alg: none`, or uses HS256 key to verify RS256 token (or vice versa). Header oracle detects: (1) `none` algorithm in presented tokens, (2) debug headers exposing key/algorithm mismatch, (3) verbose algorithm validation errors. Confidence: `confirmed` (logic-based, no control needed). WAF/block pages classify `Untrusted` and reject.

## Fixtures

- Positive: 2 of 2 accepted (1 `none` algorithm token, 1 HS256/RS256 confusion debug header).
- Negative: 2 of 2 rejected (valid RS256 token, proper invalid token rejection).
- Command: `go run ./cmd/gash plugins test plugins/jwt-alg-confusion/jwt-alg-confusion.yaml`

## Corpus Result

Oracle `header` (jwt_alg mode) evaluated against clean, SPA, WAF, encoded, and dynamic bodies. `firm` plus findings: 0. Corpus bodies do not carry JWT algorithm confusion indicators in headers.

## Lab Result

Procedure: serve an API endpoint with JWT alg confusion from `docker-compose.lab.yml`, scan the endpoint, expect one high severity JWT finding and no other claims.
Status: pending manual run. Expected Precision 100 percent on this page class.

## Precision

True positives 2, false positives 0. Precision 1.00.

## Recall

True positives 2, false negatives 0. Recall 1.00.

## Gate Verdict

PASS. Precision 1.00 is above the 0.99 gate. Corpus holds 0 `firm` plus.

## Dataset

- Dataset hash: `124271b01acac11380f4343b28b9ff9ef0da5822c7f7bbf021fb560dd5c9376c` (sha256 over all 4 fixture files under `tests/fixtures/jwt-alg-confusion/`).
- Samples: TP=2, FP=0, TN=2, FN=0. Fixture-only measurement; lab pending above.
  `TestMetricGate` fails the build if this hash drifts from the fixtures.

## Limitations

- v1 is passive-only: does not actively send forged tokens; detects only server-exposed indicators.
- `none` algorithm detection requires token in response headers (rare); active probing is future work.
- Key confusion via JWKS endpoint not tested.
- Does not test `kid` header injection or `jku`/`x5u` header manipulation.
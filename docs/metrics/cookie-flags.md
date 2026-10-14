<!--
SPDX-License-Identifier: AGPL-3.0-only
Copyright (C) 2026 Xmar1881 / GASH contributors
Module: github.com/Xmar1881/Gash

File: docs/metrics/cookie-flags.md
What: Precision and recall report for the Tier 1 cookie-flags plugin.
Why: Proves passive Set-Cookie grading meets the 99 percent precision gate.
-->

# Metrics: cookie-flags

## Overview

Tier 1 passive plugin. Oracle `cookie`. Inspects `Set-Cookie` response headers
for `Secure`, `HttpOnly`, and `SameSite`. Missing `HttpOnly` confirms at
`confirmed`; `SameSite=None` without `Secure` confirms; missing `Secure` on
https confirms and on http firms; missing `SameSite` alone firms.

## Evidence Standard

Rule GASH-022 (CWE-614). Cookie checks are logic based, need no control
request, and never emit `tentative`. WAF or block pages classify `Untrusted`
and always reject. No `Set-Cookie` rejects.

## Fixtures

- Positive: 2 of 2 accepted (1 `confirmed` bare cookie, 1 `firm` missing SameSite only).
- Negative: 2 of 2 rejected (hardened cookie, no cookies).
- Command: `go run ./cmd/gash plugins test plugins/cookies/cookie-flags.yaml`

## Corpus Result

Oracle `cookie` evaluated against clean, SPA, WAF, encoded, and dynamic bodies.
`firm` plus findings: 0. No corpus body carries a `Set-Cookie` header.

## Lab Result

Procedure: serve a login endpoint that sets a session cookie from
`docker-compose.lab.yml`, scan the landing page, expect one medium severity
cookie finding and no other claims.
Status: pending manual run. Expected Precision 100 percent on this page class.

## Precision

True positives 2, false positives 0. Precision 1.00.

## Recall

True positives 2, false negatives 0. Recall 1.00.

## Gate Verdict

PASS. Precision 1.00 is above the 0.99 gate. Corpus holds 0 `firm` plus.

## Dataset

- Dataset hash: `90faf13b79d601a03dc117ca2d033420407618d172779ba63ca793bfc18eafae`
  (sha256 over all 4 fixture files under `tests/fixtures/cookie-flags/`).
- Samples: TP=2, FP=0, TN=2, FN=0. Fixture-only measurement; lab pending above.
  `TestMetricGate` fails the build if this hash drifts from the fixtures.

## Limitations

- `Secure` grading uses the target scheme; unknown scheme defaults to https.
- Multiple cookies in one fixture value are joined with newline; live servers
  send separate `Set-Cookie` headers.
- Cookie prefixes (`__Secure-`, `__Host-`) are not separately graded in v1.

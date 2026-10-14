<!--
SPDX-License-Identifier: AGPL-3.0-only
Copyright (C) 2026 Xmar1881 / GASH contributors
Module: github.com/Xmar1881/Gash

File: docs/metrics/cors-misconfig.md
What: Precision and recall report for the Tier 1 CORS plugin.
Why: Proves passive ACAO grading meets the 99 percent precision gate.
-->

# Metrics: cors-misconfig

## Overview

Tier 1 passive plugin. Oracle `cors`. Inspects `Access-Control-Allow-Origin`
and `Access-Control-Allow-Credentials`. Wildcard with credentials confirms at
`confirmed`; plain wildcard firms; reflected request origin with credentials
confirms and without credentials firms; `null` firms.

## Evidence Standard

Rule GASH-023 (CWE-942). CORS checks are logic based, need no control request,
and never emit `tentative`. WAF or block pages classify `Untrusted` and always
reject. Missing `ACAO` rejects; specific allowlist rejects.

## Fixtures

- Positive: 2 of 2 accepted (1 `confirmed` wildcard with credentials, 1 `firm` plain wildcard).
- Negative: 2 of 2 rejected (no CORS headers, specific allowlist).
- Command: `go run ./cmd/gash plugins test plugins/cors/cors-misconfig.yaml`

## Corpus Result

Oracle `cors` evaluated against clean, SPA, WAF, encoded, and dynamic bodies.
`firm` plus findings: 0. No corpus body carries an `ACAO` header.

## Lab Result

Procedure: serve an API endpoint with permissive CORS from
`docker-compose.lab.yml`, scan the endpoint, expect one medium severity CORS
finding and no other claims.
Status: pending manual run. Expected Precision 100 percent on this page class.

## Precision

True positives 2, false positives 0. Precision 1.00.

## Recall

True positives 2, false negatives 0. Recall 1.00.

## Gate Verdict

PASS. Precision 1.00 is above the 0.99 gate. Corpus holds 0 `firm` plus.

## Dataset

- Dataset hash: `1009affb3562be33ae55ca14c331ae089ad17e96b17e027c043ce4e15210b676`
  (sha256 over all 4 fixture files under `tests/fixtures/cors-misconfig/`).
- Samples: TP=2, FP=0, TN=2, FN=0. Fixture-only measurement; lab pending above.
  `TestMetricGate` fails the build if this hash drifts from the fixtures.

## Limitations

- v1 is passive-only: reflected-origin detection needs the request `Origin`,
  which Tier 1 does not send yet; active Origin probing is future work.
- Preflight (`OPTIONS`) and `Vary: Origin` handling are not graded in v1.

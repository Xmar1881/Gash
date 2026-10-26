<!--
SPDX-License-Identifier: AGPL-3.0-only
Copyright (C) 2026 Xmar1881 / GASH contributors
Module: github.com/Xmar1881/Gash

File: docs/metrics/insecure-cors-reflected-origin.md
What: Precision and recall report for the Tier 2 reflected-origin CORS plugin.
Why: Proves the origin-reflection proof meets the 99 percent precision gate
  behind the cors oracle with a declared request origin.
-->

# Metrics: insecure-cors-reflected-origin

## Overview

Tier 2 active JS plugin. Oracle `cors` with `request_origin` declared once in
the frontmatter `oracle_params` block. The wildcard case is a single passive
read; the dangerous case is an allowlist that echoes whatever Origin it is
given, which needs the request to actually carry our Origin (a point-level
header).

The origin literal is declared in the frontmatter and asserted equal to the
script constant by the plugin test, so the fixture runner and a live scan send
and grade the same value.

## Evidence Standard

CORS rule (GASH-023 family extended to origin reflection): response
`Access-Control-Allow-Origin` equal to our origin plus
`Access-Control-Allow-Credentials: true` is `confirmed`; reflection without
credentials is `firm`; an allowlist that returns another origin is rejected.

## Fixtures

- Positive: 2 of 2 accepted (`confirmed` with credentials, `firm` without).
- Negative: 1 of 1 rejected (allowlisted origin; ours is not echoed).
- Command:
  `go run ./cmd/gash plugins test plugins/cors/insecure-cors-reflected-origin.js`

## JS E2E

`TestInsecureCORSReflectedOriginE2E` (`tests/plugins/tier2_batch_test.go`)
executes the real script through `loader.ExecuteJS`: a reflecting backend with
credentials yields one `confirmed` candidate and the request is asserted to
carry the declared `Origin`; an allowlisting backend yields none. The test also
asserts the frontmatter origin equals the script constant.

## Corpus Result

Oracle `cors` is logic-based: the shared corpus gate produces no `firm`-plus
finding because clean bodies carry no ACAO header.

## Lab Result

Procedure: serve a localhost lab endpoint with a naive ACAO echo plus
credentials, scan with `--active`, expect one high severity finding at
`confirmed`. Status: pending manual run.

## Precision

True positives 2, false positives 0. Precision 1.00.

## Recall

True positives 2, false negatives 0. Recall 1.00.

## Gate Verdict

PASS. Precision 1.00 is above the 0.99 gate. Corpus holds 0 findings.

## Dataset

- Dataset hash: `efd7ad723c94bd3905f4035dd28075a8babc08305b1c2b76a62b9d9531ed8eb9`
  (sha256 over all 3 fixture files under
  `tests/fixtures/insecure-cors-reflected-origin/`).
- Samples: TP=2, FP=0, TN=1, FN=0. `TestMetricGate` fails on hash drift.

## Limitations

- One origin probe per URL; subdomain-wildcard acceptance of a *different*
  subdomain than the canary is not enumerated.
- Preflight cache poisoning and Vary-header interactions are out of scope.

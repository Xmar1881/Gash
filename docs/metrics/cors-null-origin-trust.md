<!--
SPDX-License-Identifier: AGPL-3.0-only
Copyright (C) 2026 Xmar1881 / GASH contributors
Module: github.com/Xmar1881/Gash

File: docs/metrics/cors-null-origin-trust.md
What: Precision and recall report for the Tier 2 null-origin CORS plugin.
Why: Proves the literal null-origin proof meets the 99 percent gate behind the
  cors oracle with a declared request origin.
-->

# Metrics: cors-null-origin-trust

## Overview

Tier 2 active JS plugin. Oracle `cors` with `request_origin: "null"` declared
once in the frontmatter `oracle_params` block. The literal `null` is the
origin a sandboxed iframe or a `data:` URL sends and cannot be allowlisted
safely, so a policy that echoes it is a real bypass even when arbitrary origins
are rejected.

The origin literal is declared in the frontmatter and asserted equal to the
script constant by the plugin test, so the fixture runner and a live scan send
and grade the same value.

## Evidence Standard

CORS rule (GASH-023 family extended to the null origin): an echoed `null` with
`Access-Control-Allow-Credentials: true` is `confirmed`; an echoed `null`
without credentials is `firm`; a specific allowlist that does not echo our
origin rejects.

## Fixtures

- Positive: 2 of 2 accepted (`confirmed` with credentials, `firm` without).
- Negative: 2 of 2 rejected (specific allowlist; no CORS headers at all).
- Command:
  `go run ./cmd/gash plugins test plugins/cors/cors-null-origin-trust.js`

## JS E2E

`TestCORSNullOriginTrustE2E` (`tests/plugins/tier2_expansion_test.go`) executes
the real script through `loader.ExecuteJS`: a backend echoing the literal null
with credentials yields one `confirmed` candidate and the request is asserted
to carry the null `Origin`; a specific allowlist yields none. The test also
asserts the frontmatter origin equals the script constant.

## Corpus Result

Oracle `cors` is logic-based: the shared corpus gate produces no `firm`-plus
finding because clean bodies carry no ACAO header.

## Lab Result

Procedure: serve a localhost lab endpoint that special-cases the null origin,
scan with `--active`, expect one `high` finding at `confirmed`. Status: pending
manual run.

## Precision

True positives 2, false positives 0. Precision 1.00.

## Recall

True positives 2, false negatives 0. Recall 1.00.

## Gate Verdict

PASS. Precision 1.00 is above the 0.99 gate. Corpus holds 0 findings.

## Dataset

- Dataset hash: `e01d2a37e09c76bca1430a37797e4167b31b151cb621cd4062e54587accccebc`
- Samples: TP=2, FP=0, TN=2, FN=0. `TestMetricGate` fails on hash drift.

## Limitations

- One origin probe per URL; subdomain-wildcard policies that do not echo the
  literal null are not enumerated (they belong to `insecure-cors-reflected-origin`).
- Preflight cache poisoning and `Vary` interactions are out of scope.

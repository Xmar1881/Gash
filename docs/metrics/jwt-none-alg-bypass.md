<!--
SPDX-License-Identifier: AGPL-3.0-only
Copyright (C) 2026 Xmar1881 / GASH contributors
Module: github.com/Xmar1881/Gash

File: docs/metrics/jwt-none-alg-bypass.md
What: Precision and recall report for the Tier 2 active JWT alg:none plugin.
Why: Proves the forged/invalid/anonymous divergence meets the 99 percent gate.
-->

# Metrics: jwt-none-alg-bypass

## Overview

Tier 2 active JS plugin. Oracle `differential` (3/3 stability plus a clean
control). The passive JWT plugins read a token and grade its header; only an
active request proves the server accepts an unsigned token. The plugin
discovers a token from a read, rewrites the header segment to
`{"alg":"none","typ":"JWT"}` while keeping the original claims, drops the
signature, and replays it. It never needs a signing key and never decodes the
claims.

`Authorization: Bearer` is the transport the plugin assumes; a backend that
authenticates by another channel answers every branch identically and rejects.

## Evidence Standard

Differential rule (GASH-005). A forged token that yields authenticated content
while an invalid token is denied, over three stable repeats each and with an
anonymous control that differs from the forged branch, is `confirmed`.

## Fixtures

- Positive: 1 of 1 accepted (`confirmed`; alg:none token accepted as
  authenticated while an invalid token is rejected).
- Negative: 1 of 1 rejected (algorithm enforced, forged and invalid tokens
  both rejected).
- Command:
  `go run ./cmd/gash plugins test plugins/jwt/jwt-none-alg-bypass.js`

## JS E2E

`TestJWTNoneAlgBypassE2E` (`tests/plugins/tier2_nosql_jwt_xpath_test.go`)
executes the real script through `loader.ExecuteJS`: a backend that accepts the
rewritten token yields one `confirmed` candidate; a backend that rejects it
yields none.

## Corpus Result

The differential oracle rejects identical true/false branches, so the static
corpus gate produces no finding for this plugin.

## Lab Result

Procedure: serve a localhost API that validates a `Bearer` JWT with a
permissive library in the lab, scan with `--active`, expect one critical
severity finding at `confirmed`.
Status: pending manual run.

## Precision

True positives 1, false positives 0. Precision 1.00.

## Recall

True positives 1, false negatives 0. Recall 1.00.

## Gate Verdict

PASS. Precision 1.00 is above the 0.99 gate. Corpus holds 0 findings.

## Dataset

- Dataset hash: `310f4be1c4c12d71f8622d11461f611bb9ee6bf0b320bdfe31b20eb3f37ce372`
  (sha256 over both fixture files under `tests/fixtures/jwt-none-alg-bypass/`).
- Samples: TP=1, FP=0, TN=1, FN=0. `TestMetricGate` fails on hash drift.

## Limitations

- The endpoint must hand out a JWT to the discovery read and authenticate via
  the `Authorization: Bearer` header; otherwise the plugin returns no
  candidate instead of guessing.
- Only the `alg:none` case is proven; key-confusion (HS256 signed with a public
  key) needs the public key and stays with the passive `jwt-alg-confusion`
  family.

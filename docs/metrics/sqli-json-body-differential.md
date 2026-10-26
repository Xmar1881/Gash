<!--
SPDX-License-Identifier: AGPL-3.0-only
Copyright (C) 2026 Xmar1881 / GASH contributors
Module: github.com/Xmar1881/Gash

File: docs/metrics/sqli-json-body-differential.md
What: Precision and recall report for the Tier 2 JSON-body boolean SQLi plugin.
Why: Proves per-field JSON true/false injection meets the 99 percent precision
  gate behind the differential oracle (3/3 masked stability).
-->

# Metrics: sqli-json-body-differential

## Overview

Tier 2 active JS plugin. Oracle `differential`. The query-point differential
plugin replays a body point through the urlencoded form builder, so a JSON API
never parses the payload. This plugin injects the true/false closures into the
discovered JSON field, sends the rebuilt object as `application/json`, and lets
the oracle enforce 3/3 masked stability plus divergence.

Reflected payloads are treated as noise: if either branch echoes the payload
verbatim the point is skipped, matching the query-point plugin's discipline.

## Evidence Standard

Differential rule (GASH-005 family extended to JSON APIs). Unstable dynamic
content rejects rather than confirming; the neutral-value control must differ
from the true branch.

## Fixtures

- Positive: 2 of 2 accepted (`confirmed`; row-count divergence and an auth
  outcome change).
- Negative: 2 of 2 rejected (parameterised endpoint; unstable true branch).
- Command:
  `go run ./cmd/gash plugins test plugins/sqli/sqli-json-body-differential.js`

## JS E2E

`TestSQLiJSONBodyDifferentialE2E`
(`tests/plugins/tier2_json_multipart_test.go`) executes the real script through
`loader.ExecuteJS`:

- Backend answering the true closure with a populated list and the false
  closure with an empty list: one `confirmed` candidate, JSON content type
  asserted.
- Backend echoing the payload verbatim: zero candidates.
- Send budget stays under the declared `max_requests`.

No new `host.oracles.*` binding is introduced (source grep asserts only
`host.oracles.differential`).

## Corpus Result

Oracle `differential` evaluated against clean, SPA, WAF, encoded, and dynamic
bodies. No corpus body shows stable cross-value divergence. `firm` is not
emitted (differential is confirmed-only).

## Lab Result

Procedure: serve a JSON API endpoint with a boolean-observable query in the
localhost lab, scan with `--active`, expect one high severity finding at
`confirmed`.
Status: pending manual run. Expected Precision 100 percent on this page class.

## Precision

True positives 2, false positives 0. Precision 1.00.

## Recall

True positives 2, false negatives 0. Recall 1.00.

## Gate Verdict

PASS. Precision 1.00 is above the 0.99 gate. Corpus holds 0 findings.

## Dataset

- Dataset hash: `2cced0fc24ea28bf01c40504f29953d94939828e7af0d157ed3f64cf6f241d58`
  (sha256 over all 4 fixture files under
  `tests/fixtures/sqli-json-body-differential/`).
- Samples: TP=2, FP=0, TN=2, FN=0. Fixture-only measurement; lab pending above.
  `TestMetricGate` fails the build if this hash drifts from the fixtures.

## Limitations

- Only the discovered field is sent; sibling fields are not replayed.
- Time-based JSON confirmation is out of scope (the timing oracle needs
  measured samples on a neutral re-read, which is the second-order path).
- Nested JSON paths are not expanded in v1.

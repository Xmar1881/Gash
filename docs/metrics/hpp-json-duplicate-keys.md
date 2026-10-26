<!--
SPDX-License-Identifier: AGPL-3.0-only
Copyright (C) 2026 Xmar1881 / GASH contributors
Module: github.com/Xmar1881/Gash

File: docs/metrics/hpp-json-duplicate-keys.md
What: Precision and recall report for the Tier 2 JSON duplicate-key HPP plugin.
Why: Proves duplicated JSON key emission with an explicit JSON content type
  meets the 99 percent precision gate behind the differential oracle.
-->

# Metrics: hpp-json-duplicate-keys

## Overview

Tier 2 active JS plugin. Oracle `differential`. Tier 1 declares one body
payload per parameter and its form builder emits a single key; a duplicated
JSON key needs a raw body plus an explicit `application/json` content type,
which only a point-level header can carry.

The plugin sends three single-key bodies, three duplicate-key bodies
(`{"id":1,"id":2}`) and one neutral control, all with `Content-Type:
application/json`, and lets the differential oracle enforce 3/3 masked
stability plus divergence.

## Evidence Standard

Differential rule (GASH-005 family extended to JSON parsing). Plugin-level
guard: BOTH branches must be 2xx before the oracle is consulted, so a strict
parser that simply rejects the duplicate key (400/422) is never reported as
pollution. Unstable content rejects rather than confirming.

## Fixtures

- Positive: 2 of 2 accepted (`confirmed`; role elevation and query-filter
  confusion via duplicated JSON keys).
- Negative: 2 of 2 rejected (first-key-wins parser; unstable duplicate
  branch).
- Command:
  `go run ./cmd/gash plugins test plugins/hpp/hpp-json-duplicate-keys.js`

## JS E2E

`TestHPPJSONDuplicateKeysE2E` (`tests/plugins/hpp_json_duplicate_keys_test.go`)
executes the real script through `loader.ExecuteJS` with a mocked transport
that inspects the point headers:

- JSON body with a duplicated key returns the elevated body, the single-key
  body returns the guest body: one `confirmed` candidate, and the request
  carries `Content-Type: application/json`.
- Strict parser answering 400 to the duplicate body: zero candidates.
- Send budget stays under the declared `max_requests`.

No new `host.oracles.*` binding is introduced (source grep asserts only
`host.oracles.differential`).

## Corpus Result

Oracle `differential` evaluated against clean, SPA, WAF, encoded, and dynamic
bodies. No corpus body shows stable cross-value divergence. `firm` is not
emitted (differential is confirmed-only).

## Lab Result

Procedure: serve a JSON endpoint whose parser is last-key-wins in the
localhost lab, scan with `--active`, expect one medium severity finding at
`confirmed`.
Status: pending manual run. Expected Precision 100 percent on this page class.

## Precision

True positives 2, false positives 0. Precision 1.00.

## Recall

True positives 2, false negatives 0. Recall 1.00.

## Gate Verdict

PASS. Precision 1.00 is above the 0.99 gate. Corpus holds 0 findings.

## Dataset

- Dataset hash: `d79ceef9e1d83b8a1e8ba83b142ca4387ce98e344628126b86ff2661ee64fa08`
  (sha256 over all 4 fixture files under
  `tests/fixtures/hpp-json-duplicate-keys/`).
- Samples: TP=2, FP=0, TN=2, FN=0. Fixture-only measurement; lab pending above.
  `TestMetricGate` fails the build if this hash drifts from the fixtures.

## Limitations

- JSON body points only; urlencoded duplicates stay with
  `hpp-duplicate-emission` and multipart duplicates are out of scope.
- Backend precedence (first-wins vs last-wins) is not fingerprinted in v1.
- Strict-parser rejection is treated as "not pollution" by design; that is a
  deliberate false-negative trade, never a finding.

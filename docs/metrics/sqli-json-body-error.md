<!--
SPDX-License-Identifier: AGPL-3.0-only
Copyright (C) 2026 Xmar1881 / GASH contributors
Module: github.com/Xmar1881/Gash

File: docs/metrics/sqli-json-body-error.md
What: Precision and recall report for the Tier 2 JSON-body error SQLi plugin.
Why: Proves per-field JSON injection meets the 99 percent precision gate behind
  the engine error oracle with a neutral-value control.
-->

# Metrics: sqli-json-body-error

## Overview

Tier 2 active JS plugin. Oracle `error` (database signature mode). Tier 1
declares one static body per file, so it can only test a hardcoded JSON shape.
This plugin takes each discovered body point, rebuilds the JSON object around
that exact field name, and sends it with an explicit `application/json`
content type.

For every payload it also sends the same field with a neutral value as the
control, so the oracle rejects whenever the signature is not caused by the
payload. JSON-string-safe closures (`'`, `1'`, `' OR '1'='1`) are used because
a bare double quote would break the object.

## Evidence Standard

Error-signature rule (GASH-004 family extended to JSON APIs). Control is the
neutral-value request on the same field; the oracle rejects when the signature
is present there too. WAF/untrusted baselines reject through the shared guard.

## Fixtures

- Positive: 2 of 2 accepted (`confirmed`; mysql and mssql signatures, control
  clean).
- Negative: 2 of 2 rejected (signature also in the control; parameterised
  endpoint).
- Command:
  `go run ./cmd/gash plugins test plugins/sqli/sqli-json-body-error.js`

## JS E2E

`TestSQLiJSONBodyErrorE2E` (`tests/plugins/tier2_json_multipart_test.go`)
executes the real script through `loader.ExecuteJS` with a mocked transport
that inspects the point headers:

- Backend that errors only for the closure payload: one `confirmed` candidate,
  and the request carries `Content-Type: application/json` with an empty
  `paramName` (raw body).
- Backend that errors for every value: zero candidates.
- Send budget stays under the declared `max_requests`.

No new `host.oracles.*` binding is introduced (source grep asserts only
`host.oracles.error`).

## Corpus Result

Oracle `error` evaluated against clean, SPA, WAF, encoded, and dynamic bodies
in the shared corpus gate. No corpus body carries a database signature, so no
`firm`-plus finding is produced.

## Lab Result

Procedure: serve a JSON API endpoint in the localhost lab whose handler
concatenates a field into SQL; scan with `--active`, expect one high severity
finding at `confirmed`.
Status: pending manual run. Expected Precision 100 percent on this page class.

## Precision

True positives 2, false positives 0. Precision 1.00.

## Recall

True positives 2, false negatives 0. Recall 1.00.

## Gate Verdict

PASS. Precision 1.00 is above the 0.99 gate. Corpus holds 0 findings.

## Dataset

- Dataset hash: `563b4a3c1c7457336991c6cf96b19388f3898b7ed58253c200ab880ce0b694c6`
  (sha256 over all 4 fixture files under
  `tests/fixtures/sqli-json-body-error/`).
- Samples: TP=2, FP=0, TN=2, FN=0. Fixture-only measurement; lab pending above.
  `TestMetricGate` fails the build if this hash drifts from the fixtures.

## Limitations

- Only the discovered field is sent; sibling fields from the original request
  are not replayed, so handlers that require them can cause false negatives.
- Nested JSON paths (`user.name`) are not expanded in v1.
- Query-point injection stays with `sqli-error-based`.

<!--
SPDX-License-Identifier: AGPL-3.0-only
Copyright (C) 2026 Xmar1881 / GASH contributors
Module: github.com/Xmar1881/Gash

File: docs/metrics/open-redirect-json-body.md
What: Precision and recall report for the Tier 2 JSON-body open redirect plugin.
Why: Proves per-field JSON redirect testing meets the 99 percent precision gate
  behind the engine redirect oracle with a neutral-value control.
-->

# Metrics: open-redirect-json-body

## Overview

Tier 2 active JS plugin. Oracle `redirect`. Tier 1 declares one static body per
file, so a JSON API field that feeds a redirect target cannot be exercised
field by field. This plugin rebuilds the object around the discovered field,
sends it with an explicit `application/json` content type, and parses the real
`Location` header.

The payload host is a per-run canary host (`probe.canary()`), so a server that
redirects to a fixed external target never matches it.

## Evidence Standard

Redirect rule (GASH-016 family extended to JSON APIs). Plugin-level control
discipline: the neutral-value request must not produce a `Location` containing
the payload host before the oracle is consulted. Relative and in-origin
locations reject.

## Fixtures

- Positive: 2 of 2 accepted (`confirmed`; 302 and 301 external targets driven
  by the JSON field).
- Negative: 2 of 2 rejected (relative target; fixed in-origin target).
- Command:
  `go run ./cmd/gash plugins test plugins/redirect/open-redirect-json-body.js`

## JS E2E

`TestOpenRedirectJSONBodyE2E` (`tests/plugins/tier2_json_sinks_test.go`)
executes the real script through `loader.ExecuteJS`:

- Backend that sets `Location` to the canary host only for the payload value:
  one `confirmed` candidate; JSON content type and raw body asserted.
- Backend redirecting to a fixed in-origin path for every value: zero
  candidates.
- Send budget stays under the declared `max_requests`.

No new `host.oracles.*` binding is introduced (source grep asserts only
`host.oracles.redirect`).

## Corpus Result

Oracle `redirect` evaluated against clean, SPA, WAF, encoded, and dynamic
bodies in the shared corpus gate. None carries an external `Location`, so no
`firm`-plus finding is produced.

## Lab Result

Procedure: serve a JSON API endpoint whose handler passes a field into the
redirect target in the localhost lab, scan with `--active`, expect one medium
severity finding at `confirmed`.
Status: pending manual run. Expected Precision 100 percent on this page class.

## Precision

True positives 2, false positives 0. Precision 1.00.

## Recall

True positives 2, false negatives 0. Recall 1.00.

## Gate Verdict

PASS. Precision 1.00 is above the 0.99 gate. Corpus holds 0 findings.

## Dataset

- Dataset hash: `e2802680f1dd135e391026669d89fc58d59c0ccbff4e24bc9e945e2f08d3a515`
  (sha256 over all 4 fixture files under
  `tests/fixtures/open-redirect-json-body/`).
- Samples: TP=2, FP=0, TN=2, FN=0. Fixture-only measurement; lab pending above.
  `TestMetricGate` fails the build if this hash drifts from the fixtures.

## Limitations

- Only the discovered field is sent; sibling fields are not replayed.
- Nested JSON paths are not expanded in v1.
- A redirect performed client-side (JavaScript `location.href`) is out of
  scope: no `Location` header exists to parse.

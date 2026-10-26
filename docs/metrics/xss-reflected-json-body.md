<!--
SPDX-License-Identifier: AGPL-3.0-only
Copyright (C) 2026 Xmar1881 / GASH contributors
Module: github.com/Xmar1881/Gash

File: docs/metrics/xss-reflected-json-body.md
What: Precision and recall report for the Tier 2 JSON-body reflected XSS plugin.
Why: Proves per-field JSON injection reaches static-execution-evidence behind
  the engine reflection oracle with a clean control.
-->

# Metrics: xss-reflected-json-body

## Overview

Tier 2 active JS plugin. Oracle `reflection`. The query-point reflection plugin
replays a body point through the urlencoded form builder, so a JSON API never
parses the payload and the reflection is missed. This plugin rebuilds the
object around the discovered field, sends it as `application/json`, and lets
the engine decide the context.

The payload is an executing pattern (`<img src=x onerror=alert(CANARY)>`) and
is JSON-string safe, so the object stays parseable while the value is still
executable HTML. The evidence ladder stays engine-owned; the ceiling is
`static-execution-evidence` without a controlled browser run.

## Evidence Standard

Reflection rule (GASH-001 family extended to JSON APIs). The engine requires a
parser-recognized execution payload plus a clean control; text-only or
HTML-encoded reflections stay at `tentative` and never become a finding here.

## Fixtures

- Positive: 2 of 2 accepted (`static-execution-evidence`; script context and
  executable event handler).
- Negative: 2 of 2 rejected (text-only reflection; HTML-encoded form).
- Command:
  `go run ./cmd/gash plugins test plugins/xss/xss-reflected-json-body.js`

## JS E2E

`TestXSSReflectedJSONBodyE2E` (`tests/plugins/tier2_json_sinks_test.go`)
executes the real script through `loader.ExecuteJS`:

- Backend echoing the value into a script context: one
  `static-execution-evidence` candidate; JSON content type asserted.
- Backend echoing the value as inert text: zero candidates.
- Send budget stays under the declared `max_requests`.

No new `host.oracles.*` binding is introduced (source grep asserts only
`host.oracles.reflection`).

## Corpus Result

Oracle `reflection` evaluated against clean, SPA, WAF, encoded, and dynamic
bodies in the shared corpus gate. Encoded and text-only bodies do not reach
`static-execution-evidence`.

## Lab Result

Procedure: serve a JSON API endpoint that renders a field into HTML in the
localhost lab, scan with `--active`, expect one high severity finding at
`static-execution-evidence`.
Status: pending manual run. Expected Precision 100 percent on this page class.

## Precision

True positives 2, false positives 0. Precision 1.00.

## Recall

True positives 2, false negatives 0. Recall 1.00.

## Gate Verdict

PASS. Precision 1.00 is above the 0.99 gate. Corpus holds 0 findings.

## Dataset

- Dataset hash: `702c0da8e76bd985b079ecd400493e604644e1a21191ae6ae5a9fecd21cac199`
  (sha256 over all 4 fixture files under
  `tests/fixtures/xss-reflected-json-body/`).
- Samples: TP=2, FP=0, TN=2, FN=0. Fixture-only measurement; lab pending above.
  `TestMetricGate` fails the build if this hash drifts from the fixtures.

## Limitations

- Only the discovered field is sent; sibling fields are not replayed.
- `--browser-verify` confirmation applies to GET/query points only, so this
  plugin's ceiling stays `static-execution-evidence`.
- DOM sinks reached after client-side rendering are out of scope.

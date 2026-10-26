<!--
SPDX-License-Identifier: AGPL-3.0-only
Copyright (C) 2026 Xmar1881 / GASH contributors
Module: github.com/Xmar1881/Gash

File: docs/metrics/xss-stored-json-api.md
What: Precision and recall report for the Tier 2 JSON API stored XSS plugin.
Why: Proves the JSON write/render flow reaches static-execution-evidence behind
  the engine stored oracle with a clean sibling control.
-->

# Metrics: xss-stored-json-api

## Overview

Tier 2 active JS plugin. Oracle `stored`. The form-point stored plugin replays
its write through the urlencoded form builder, so a JSON API never parses the
payload and the value never lands in the store. This plugin rebuilds the object
around the discovered field, sends it as `application/json`, and then observes
the write on a render page — the second exchange is what makes the finding
stored rather than reflected.

Bases are walked round-robin so every write endpoint gets one attempt before
any endpoint gets a second one, and the whole run stays inside the send budget.
When a second base exists it is passed as the control URL; a neutralized
re-fetch of a genuinely stored value stays dirty and would reject, so a
single-base target yields no candidate rather than a false positive.

## Evidence Standard

Stored rule (GASH-002 family extended to JSON APIs). The engine requires the
store exchange to be accepted, a parser-recognized execution payload in the
render, and a clean control. Without a controlled browser run the ceiling is
`static-execution-evidence`; `--browser-verify` can lift an eligible
store/render pair to `confirmed`.

## Fixtures

- Positive: 2 of 2 accepted (`static-execution-evidence`; script context and
  executable event handler in the render).
- Negative: 2 of 2 rejected (render never shows the payload; payload
  HTML-encoded on render).
- Command:
  `go run ./cmd/gash plugins test plugins/xss/xss-stored-json-api.js`

## JS E2E

`TestXSSStoredJSONAPI` (`tests/plugins/tier2_json_stored_oob_test.go`) executes
the real script through `loader.ExecuteJS` with a mocked store:

- Two write endpoints; only the first renders the field. The write is asserted
  to carry `Content-Type: application/json` with a raw body, and the render
  exchange yields one `static-execution-evidence` candidate.
- Store endpoint whose render filters the payload: zero candidates.
- Send budget stays under the declared `max_requests`.

No new `host.oracles.*` binding is introduced (source grep asserts only
`host.oracles.storedExecution`).

## Corpus Result

Oracle `stored` evaluated against clean, SPA, WAF, encoded, and dynamic bodies
in the shared corpus gate. Encoded or absent payloads never reach
`static-execution-evidence`.

## Lab Result

Procedure: serve a JSON API profile endpoint plus its HTML view in the
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

- Dataset hash: `9ee860a7d0d9229c750f7c4c1b6aa2a02d7d4e16047e8674a0c2e44460863d81`
  (sha256 over all 4 fixture files under `tests/fixtures/xss-stored-json-api/`).
- Samples: TP=2, FP=0, TN=2, FN=0. Fixture-only measurement; lab pending above.
  `TestMetricGate` fails the build if this hash drifts from the fixtures.

## Limitations

- A single-base target yields no candidate (no clean control exists); pairs
  with a sibling render page are required in v1.
- Only the discovered field is written; sibling fields are not replayed.
- Persisted state is left behind by design; the payload is a canary-only
  `onerror=alert()` pattern, never a data-destroying value.

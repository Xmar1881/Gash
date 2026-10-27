<!--
SPDX-License-Identifier: AGPL-3.0-only
Copyright (C) 2026 Xmar1881 / GASH contributors
Module: github.com/Xmar1881/Gash

File: docs/metrics/xss-path-segment.md
What: Precision and recall report for the path-segment reflected XSS plugin.
Why: Proves encoded path reflection plus a clean base control meets the gate.
-->

# Metrics: xss-path-segment

## Overview

Tier 2 active JS plugin. Oracle `reflection`. The engine's injection surface
carries query, body, cookie and fragment points, not paths. The plugin appends a
percent-encoded executable payload as a path segment and grades the response
with the reflection oracle. The control is the unmodified base page: the
binding re-fetches the URL supplied in the response object, so a canary that
survives there blocks the claim.

## Evidence Standard

`ReflectionOracle` with executable contexts (`html`, `attr-executable`,
`script`, `url`, `url-executable`), a canary match, and a clean control. Static
execution evidence is the ceiling without a browser.

## Fixtures

- Positive: 2 of 2 accepted (`static-execution-evidence`; svg handler, event
  handler attribute).
- Negative: 2 of 2 rejected (no reflection, comment reflection).
- Command: `go run ./cmd/gash plugins test plugins/xss/xss-path-segment.js`

## JS E2E

`TestXSSPathSegmentE2E` executes the script through `loader.ExecuteJS`:

- The encoded path segment is reflected as an executable svg handler, the base
  page is fetched as the clean control, and one candidate is produced.
- A path that is never reflected produces none.
- Send budget and the oracle surface are asserted.

## Corpus Result

The reflection oracle is unchanged and covered by the clean corpus.
Fixture-only measurement.

## Lab Result

Procedure: serve a file browser that echoes the path in a 404 page, scan with
this plugin, expect one high-severity finding at `static-execution-evidence`
(or `confirmed` in a deep build with browser verification). Status: pending
manual run.

## Precision

True positives 2, false positives 0. Precision 1.00.

## Recall

True positives 2, false negatives 0. Recall 1.00.

## Gate Verdict

PASS. Precision 1.00 is above the 0.99 gate. Corpus holds 0 findings.

## Dataset

- Dataset hash: `c277c3ec70eaacd7488144fb34d4289809feac4f444e692f16a41f45c3c1b5f5`
  (sha256 over all 4 fixture files under `tests/fixtures/xss-path-segment/`).
- Samples: TP=2, FP=0, TN=2, FN=0. Fixture-only measurement; lab pending above.
  `TestMetricGate` fails the build if this hash drifts from the fixtures.

## Limitations

- Frameworks that never decode path segments yield a false negative.
- One path shape per base; multi-segment routing is not enumerated.

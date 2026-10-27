<!--
SPDX-License-Identifier: AGPL-3.0-only
Copyright (C) 2026 Xmar1881 / GASH contributors
Module: github.com/Xmar1881/Gash

File: docs/metrics/xss-reflected-header.md
What: Precision and recall report for the header-borne reflected XSS plugin.
Why: Proves UA/Referer reflection plus a header-less control meets the gate.
-->

# Metrics: xss-reflected-header

## Overview

Tier 2 active JS plugin. Oracle `reflection`. The discovered surface never
contains header points, yet error pages and access-log panels echo User-Agent
and Referer into HTML. The plugin attaches the payload as a request header and
grades the response with the reflection oracle; the binding re-fetches the same
URL without the header as the clean control.

## Evidence Standard

`ReflectionOracle` with executable contexts, canary match, and a header-less
control. Static execution evidence is the ceiling without a browser.

## Fixtures

- Positive: 2 of 2 accepted (`static-execution-evidence`; User-Agent svg,
  Referer event handler).
- Negative: 3 of 3 rejected (no reflection, WAF block page, comment reflection).
- Command: `go run ./cmd/gash plugins test plugins/xss/xss-reflected-header.js`

## JS E2E

`TestXSSReflectedHeaderE2E` executes the script through `loader.ExecuteJS`:

- A User-Agent reflection confirms and the header-less control request is
  asserted.
- Comment-only reflection rejects.
- Send budget and the oracle surface are asserted.

## Corpus Result

The reflection oracle is unchanged. Fixture-only measurement.

## Lab Result

Procedure: serve a page that prints the User-Agent into an HTML panel, scan with
this plugin, expect one medium-severity finding at
`static-execution-evidence`. Status: pending manual run.

## Precision

True positives 2, false positives 0. Precision 1.00.

## Recall

True positives 2, false negatives 0. Recall 1.00.

## Gate Verdict

PASS. Precision 1.00 is above the 0.99 gate. Corpus holds 0 findings.

## Dataset

- Dataset hash: `fde2d4ebd54b5d53b7d3e87d7e9f8679cf1461d3b3a230a807bccc4f8d8ae6ea`
  (sha256 over all 5 fixture files under `tests/fixtures/xss-reflected-header/`).
- Samples: TP=2, FP=0, TN=3, FN=0. Fixture-only measurement; lab pending above.
  `TestMetricGate` fails the build if this hash drifts from the fixtures.

## Limitations

- Only User-Agent and Referer are exercised; custom application headers are
  not enumerated.
- Servers that ignore client-supplied headers yield a false negative.

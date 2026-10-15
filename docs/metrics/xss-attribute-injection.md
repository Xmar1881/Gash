<!--
SPDX-License-Identifier: AGPL-3.0-only
Copyright (C) 2026 Xmar1881 / GASH contributors
Module: github.com/Xmar1881/Gash

File: docs/metrics/xss-attribute-injection.md
What: Precision and recall report for the attribute-breakout XSS plugin.
Why: Proves event-handler breakout confirms only in an executable context
with a clean control; encoded and comment reflections never confirm.
-->

# Metrics: xss-attribute-injection

## Overview

Tier 1 active plugin. Oracle `reflection` with canary `alert(1)`. Payload
breaks out of a value attribute into an event handler
(`" onfocus="alert(1)`). Maximum confidence `static-execution-evidence`
(parser-recognized executable attribute context plus absent-in-control proof;
browser confirmation is separate).

## Evidence Standard

Rule GASH-001 (CWE-79). Requires the canary inside an `on*` event-handler
attribute plus its absence in the neutral control response. Text-only,
encoded, or comment reflections never reach `static-execution-evidence`.
WAF/block pages
classify `Untrusted` and always reject.

## Fixtures

- Positive: 2 of 2 accepted (`static-execution-evidence`: onfocus breakout, onmouseover breakout).
- Negative: 2 of 2 rejected (no reflection, canary only in HTML comment).
- Command: `go run ./cmd/gash plugins test plugins/xss/xss-attribute-injection.yaml`

## Corpus Result

Oracle `reflection` is covered by `TestB4CorpusZeroFirmPlus`: 0 `firm` plus
findings on clean, SPA, WAF, encoded, and dynamic bodies. A WAF block body
correctly rejects as untrusted.

## Lab Result

Procedure: serve a search field reflecting into a value attribute, scan with
`--active`, expect one high finding at `static-execution-evidence` unless a
browser-backed verifier is enabled.
Status: pending manual run (see `docs/metrics/lab-aggressive-*.md` when the
localhost lab lands). Expected Precision 100 percent on this vulnerability class.

## Precision

True positives 2, false positives 0. Precision 1.00.

## Recall

True positives 2, false negatives 0. Recall 1.00.

## Gate Verdict

PASS. Precision 1.00 is above the 0.99 gate. Corpus holds 0 `firm` plus.

## Dataset

- Dataset hash: `4f752a8bf2ad6ff0c3d9b012255fb7a81d82fddd2ce326c2f09ed22896b478ef`
  (sha256 over all 4 fixture files under `tests/fixtures/xss-attribute-injection/`).
- Samples: TP=2, FP=0, TN=2, FN=0. Fixture-only measurement; lab pending above.
  `TestMetricGate` fails the build if this hash drifts from the fixtures.

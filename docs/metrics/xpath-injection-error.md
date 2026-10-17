<!--
SPDX-License-Identifier: AGPL-3.0-only
Copyright (C) 2026 Xmar1881 / GASH contributors
Module: github.com/Xmar1881/Gash

File: docs/metrics/xpath-injection-error.md
What: Precision and recall report for the XPath injection error-signature screen.
Why: Proves ErrorSignatureOracle xpath mode (GASH-034) meets the 99 percent gate.
-->

# Metrics: xpath-injection-error

## Overview

Tier 1 active plugin. Oracle `error` with `mode: xpath`. An XPath parser or
compiler error signature in the probe response, absent from the neutral
control, gives `firm`; the single-channel signal never reaches `confirmed`.

## Evidence Standard

Rule GASH-034 (CWE-643). Probe payload closes an XPath predicate and
deliberately produces a syntax error (`x'] | //* | a['`); second payload is a
boolean tautology. No file read, no data extraction, no denial payload.

## Fixtures

- Positive: 2 of 2 accepted (`firm`; Java XPathExpressionException with clean
  control, PHP DOMXPath error without control).
- Negative: 2 of 2 rejected (clean no-results page; signature also present in
  the control).
- Command: `go run ./cmd/gash plugins test plugins/xpath/xpath-injection-error.yaml`

## Corpus Result

Oracle `error` (xpath signature set) evaluated against clean, SPA, WAF,
encoded, and dynamic bodies: no signature match, zero `firm` plus.

## Lab Result

Procedure: point the plugin at a lab endpoint that concatenates a query
parameter into an XPath expression; expect one high severity finding at
`firm`. Status: pending manual run. Expected Precision 100 percent on this
endpoint class.

## Precision

True positives 2, false positives 0. Precision 1.00.

## Recall

True positives 2, false negatives 0. Recall 1.00.

## Gate Verdict

PASS. Precision 1.00 is above the 0.99 gate. Corpus holds 0 unexpected `firm` plus.

## Dataset

- Dataset hash: `8a3e57ae18043755be6647ab63402f10b8a38d9f7833315641e11d1a23697741`
  (sha256 over all 4 fixture files under `tests/fixtures/xpath-injection-error/`).
- Samples: TP=2, FP=0, TN=2, FN=0. Fixture-only measurement; lab pending above.
  `TestMetricGate` fails the build if this hash drifts from the fixtures.

## Limitations

- Reflection-based XPath sinks without parser errors stay invisible (no
  differential variant ships in this plugin).
- Error text localization can hide the signature; the set is English-centric.

<!--
SPDX-License-Identifier: AGPL-3.0-only
Copyright (C) 2026 Xmar1881 / Gash contributors
Module: github.com/Xmar1881/Gash

File: docs/metrics/dom-sink-basic.md
What: Precision and recall report for the static DOM sink plugin.
Why: Proves sink/source static analysis caps at firm without a browser;
confirmed requires headless execution (documented BLOCKED without deps).
-->

# Metrics: dom-sink-basic

## Overview

Tier 2 passive plugin. Oracle `execution` without a browser. The script sends
one probe value and calls `host.oracles.execution(resp)`; the Go binding
detects a static sink (`innerHTML`, `document.write`, ...) plus a
URL-controlled source (`location.hash`, `location.search`, ...). Maximum
confidence `firm` (headless absent). Headless `confirmed` path stays
BLOCKED (no browser dependency in this build; see Lab).

## Evidence Standard

Rule GASH-003 (CWE-79). Sink required; sink plus source yields `firm`;
sink without source yields `tentative`; no sink rejects. WAF/block pages
classify `Untrusted` and always reject. Browser-executed confirmation
(`Triggered` plus `ControlClean`) is the only `confirmed` path and needs the
headless build.

## Fixtures

- Positive: 2 of 2 accepted (`firm`: innerHTML plus location.hash, document.write plus location.search).
- Negative: 2 of 2 rejected (no sink, plain text).
- Command: `go run ./cmd/gash plugins test plugins/xss/dom-sink-basic.js`

## Corpus Result

Oracle `execution` returns reject on sink-free bodies; the clean, SPA, and
encoded corpus shapes carry no listed sink and stay silent. WAF block bodies
reject as untrusted before sink analysis.

## Lab Result

Synthetic localhost lab does not render JavaScript, so DOM execution is not
lab-measured. Browser confirmation (headless `Triggered` plus `ControlClean`)
is BLOCKED in this environment: no headless dependency is vendored, and no
`chromedp` pin exists. The static `firm` ceiling is the honest lab claim.

## Precision

True positives 2, false positives 0. Precision 1.00.

## Recall

True positives 2, false negatives 0. Recall 1.00.

## Gate Verdict

PASS. Precision 1.00 is above the 0.99 gate. Corpus holds 0 `firm` plus on
sink-free shapes; browser-confirmed recall remains unmeasured.

## Dataset

- Dataset hash: `8a12a2f9c78dace7e65fdd2004068948009c0d03e7a11881a8bbd7bcddde2e9b`
  (sha256 over all 4 fixture files under `tests/fixtures/dom-sink-basic/`).
- Samples: TP=2, FP=0, TN=2, FN=0. Fixture-only measurement; browser lab BLOCKED above.
  `TestMetricGate` fails the build if this hash drifts from the fixtures.

<!--
SPDX-License-Identifier: AGPL-3.0-only
Copyright (C) 2026 Xmar1881 / GASH contributors
Module: github.com/Xmar1881/Gash

File: docs/metrics/xss-stored-basic.md
What: Precision and recall report for the stored XSS synchronous-render plugin.
Why: Proves Tier 1 reflection oracle (GASH-002) meets the 99 percent precision gate
  with static-execution-evidence (browser-confirmed needs a controlled headless run).
-->

# Metrics: xss-stored-basic

## Overview

Tier 1 active plugin. Oracle `reflection` with `attr-executable` context and
`require_executable_context: true`. Parser-recognized execution payload
(`alert(1)` event handler) plus clean control gives `static-execution-evidence`;
this is static parser proof, not browser execution.

## Evidence Standard

Rule GASH-002 (CWE-79). Tier 1 evaluates the synchronous render body offline;
the two-request store+render flow is a lab procedure. Text-only or encoded
reflection never exceeds `tentative`. Control rendering the same executable
context rejects (indistinguishable).

## Fixtures

- Positive: 2 of 2 accepted (`static-execution-evidence`).
- Negative: 2 of 2 rejected (filtered content, control-indistinguishable render).
- Command: `go run ./cmd/gash plugins test plugins/xss/xss-stored-basic.yaml`

## Corpus Result

Oracle `reflection` evaluated against clean, SPA, WAF, encoded, and dynamic bodies.
`static-execution-evidence` plus findings: 0. WAF body correctly rejects as untrusted.

## Lab Result

Procedure: serve a comment/review board persisting input in the localhost lab,
store the payload, scan the render page, expect one high severity finding at
`static-execution-evidence` (headless run would lift to `confirmed`).
Status: pending manual run. Expected Precision 100 percent on this vulnerability class.

## Precision

True positives 2, false positives 0. Precision 1.00.

## Recall

True positives 2, false negatives 0. Recall 1.00.

## Gate Verdict

PASS. Precision 1.00 is above the 0.99 gate. Corpus holds 0 `firm` plus.

## Dataset

- Dataset hash: `aeff7a050d5f8d13af6e865faf7b2069a3f1245b22915fe16a3b259092b652fd`
  (sha256 over all 4 fixture files under `tests/fixtures/xss-stored-basic/`).
- Samples: TP=2, FP=0, TN=2, FN=0. Fixture-only measurement; lab pending above.
  `TestMetricGate` fails the build if this hash drifts from the fixtures.

## Limitations

- Synchronous-render approximation; the real two-request store+render flow is
  covered by Tier 2 `xss-stored-two-step` (`plugins/xss/xss-stored-two-step.js`,
  see `xss-stored-two-step.md`).
- `confirmed` requires a controlled headless run (`browser-confirmed`), not measured here.
- Real-target recall (multi-user render flows) is unmeasured.

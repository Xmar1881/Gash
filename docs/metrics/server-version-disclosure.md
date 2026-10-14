<!--
SPDX-License-Identifier: AGPL-3.0-only
Copyright (C) 2026 Xmar1881 / GASH contributors
Module: github.com/Xmar1881/Gash

File: docs/metrics/server-version-disclosure.md
What: Precision and recall report for the server version disclosure reference plugin.
Why: Proves Tier 1 passive version oracle (banner mode) meets disclosure detection standard.
-->

# Metrics: server-version-disclosure

## Overview

Tier 1 passive plugin. Oracle `version` with `mode: banner`. Passive banner/header
analysis for server version leakage (Server, X-Powered-By, X-AspNet-Version headers).
Confidence `tentative` (banner-only), `firm` with behavioral verification. No `confirmed`.

## Evidence Standard

Rule GASH-021. Regex match on version pattern in headers. Cloudflare/CDN responses
reject (origin hidden). Behavioral verification (e.g., version-specific behavior)
elevates to `firm`. WAF/block pages classify `Untrusted` and always reject.

## Fixtures

- Positive: 2 of 2 accepted (2 `tentative`).
- Negative: 2 of 2 rejected (no version in header, CDN).
- Command: `go run ./cmd/gash plugins test plugins/version-disclosure/server-version-disclosure.yaml`

## Corpus Result

Oracle `version` (banner) evaluated against clean, SPA, WAF, encoded, and dynamic bodies.
`firm` plus findings: 0. WAF body correctly rejects as untrusted.

## Lab Result

Procedure: serve a target with version-disclosing headers, scan landing page,
expect one low severity finding at `tentative`.
Status: pending manual run. Expected Precision 100 percent on this disclosure class.

## Precision

True positives 2, false positives 0. Precision 1.00.

## Recall

True positives 2, false negatives 0. Recall 1.00.

## Gate Verdict

PASS. Precision 1.00 is above the 0.99 gate. Corpus holds 0 `firm` plus.

## Dataset

- Dataset hash: `506d8ce14c1c79ff967e47cb2a5302a111c6f4730f759af5872eb2aa1332ad2a`
  (sha256 over all 4 fixture files under `tests/fixtures/server-version-disclosure/`).
- Samples: TP=2, FP=0, TN=2, FN=0. Fixture-only measurement; lab pending above.
  `TestMetricGate` fails the build if this hash drifts from the fixtures.

<!--
SPDX-License-Identifier: AGPL-3.0-only
Copyright (C) 2026 Xmar1881 / GASH contributors
Module: github.com/Xmar1881/Gash

File: docs/metrics/csrf-token-absence.md
What: Precision and recall report for the passive CSRF token-absence screen.
Why: Proves HeaderOracle csrf mode (GASH-020) meets the 99 percent precision gate
  with zero state-changing requests.
-->

# Metrics: csrf-token-absence

## Overview

Tier 1 passive plugin. Oracle `header` with `mode: csrf`. A state-changing POST
form without an anti-CSRF token and without `SameSite=Strict` gives `confirmed`;
token present, GET-only, or formless pages reject. No state-changing request is
ever sent (passive observation only).

## Evidence Standard

Rule GASH-020 (CWE-352). Deterministic logic finding; control request not needed
(passive screen). Token present or `SameSite=Strict` hardening downgrades to
`firm`/reject per the oracle ladder. `tentative` is never emitted in this class.

## Fixtures

- Positive: 2 of 2 accepted (`confirmed`; tokenless POST, Lax-cookie POST).
- Negative: 2 of 2 rejected (token-protected form, GET-only edge).
- Command: `go run ./cmd/gash plugins test plugins/csrf/csrf-token-absence.yaml`

## Corpus Result

Oracle `header` (csrf mode) evaluated against clean, SPA, WAF, encoded, and dynamic bodies.
`firm` plus findings: 0 (corpus pages carry no unprotected POST form).

## Lab Result

Procedure: serve a tokenless transfer form in the localhost lab, scan passively,
expect one medium severity finding at `confirmed` and no request side effects.
Status: pending manual run. Expected Precision 100 percent on this page class.

## Precision

True positives 2, false positives 0. Precision 1.00.

## Recall

True positives 2, false negatives 0. Recall 1.00.

## Gate Verdict

PASS. Precision 1.00 is above the 0.99 gate. Corpus holds 0 `firm` plus.

## Dataset

- Dataset hash: `bbca7dd36f79e6ba713b956f1d7ab7506c02715b050ed76d718c33dcf5165c8d`
  (sha256 over all 4 fixture files under `tests/fixtures/csrf-token-absence/`).
- Samples: TP=2, FP=0, TN=2, FN=0. Fixture-only measurement; lab pending above.
  `TestMetricGate` fails the build if this hash drifts from the fixtures.

## Limitations

- Passive screen only; live state-change differential confirmation is future work.
- Custom header-based CSRF schemes (non-form APIs) are out of scope for v1.
- Double-submit cookie patterns keyed on non-standard names may miss (recall gap, documented).

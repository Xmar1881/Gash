<!--
SPDX-License-Identifier: AGPL-3.0-only
Copyright (C) 2026 Xmar1881 / GASH contributors
Module: github.com/Xmar1881/Gash

File: docs/metrics/xss-stored-header-two-step.md
What: Precision and recall report for the Tier 2 header-borne stored-XSS plugin.
Why: Proves the header write-channel discipline meets the 99 percent gate behind
  the stored oracle.
-->

# Metrics: xss-stored-header-two-step

## Overview

Tier 2 active JS plugin. Oracle `stored`. The write channel is a request header
(`Referer`) rather than a form field: the payload travels with a GET to the page
base, the render is re-read afterwards, and a sibling page that never received
the payload is the clean control.

## Evidence Standard

Stored rule (GASH-002): the store exchange must be accepted and the render must
carry the canary in an executable context with a clean sibling control, which
gives `static-execution-evidence` (browser `confirmed` with the headless build).

## Fixtures

- Positive: 1 of 1 accepted (`static-execution-evidence`).
- Negative: 1 of 1 rejected (the header is not persisted into the render).
- Command:
  `go run ./cmd/gash plugins test plugins/xss/xss-stored-header-two-step.js`

## JS E2E

`TestXSSStoredHeaderTwoStepE2E` (`tests/plugins/tier2_batch4_test.go`) asserts
one candidate when the render shows the header-borne payload in an executable
context, that the write exchange actually carried the `Referer` header, and that
a request which never echoes it yields none.

## Corpus Result

Oracle `stored` is covered by the shared corpus gate and produces no `firm`-plus
finding on clean bodies.

## Lab Result

Procedure: lab panel rendering the Referer of the last visit, run with
`--active`, expect one `high` finding at `static-execution-evidence`. Status:
pending manual run.

## Precision

True positives 1, false positives 0. Precision 1.00.

## Recall

True positives 1, false negatives 0. Recall 1.00.

## Gate Verdict

PASS. Precision 1.00 is above the 0.99 gate. Corpus holds 0 findings.

## Dataset

- Dataset hash: `8a21a756457502cb28075ae5e3578c0cec76fa5a54e148f2d26014d66ac0a30d`
- Samples: TP=1, FP=0, TN=1, FN=0. `TestMetricGate` fails on hash drift.

## Limitations

- Only the `Referer` header is used as the write channel; other persisted
  headers (user agent, forwarding headers) are not yet enumerated.
- The render must be reachable without authentication context switching.

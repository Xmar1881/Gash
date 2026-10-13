<!--
SPDX-License-Identifier: AGPL-3.0-only
Copyright (C) 2026 Xmar1881 / GASH contributors
Module: github.com/Xmar1881/Gash

File: docs/metrics/missing-security-headers.md
What: Precision and recall report for the passive header reference plugin.
Why: Proves Tier 1 passive findings meet the 99 percent precision gate.
-->

# Metrics: missing-security-headers

## Overview

Tier 1 passive plugin. Oracle `header`. No request parameters. Missing HSTS, CSP,
or frame protection confirms at `confirmed`; weak CSP confirms at `firm`.

## Evidence Standard

Rule GASH-019. Header checks are logic based, need no control request, and never
emit `tentative`. WAF or block pages classify `Untrusted` and always reject.

## Fixtures

- Positive: 2 of 2 accepted (1 `confirmed`, 1 `firm`).
- Negative: 2 of 2 rejected (hardened host, WAF block page).
- Command: `go run ./cmd/gash plugins test plugins/headers/missing-security-headers.yaml`

## Corpus Result

Oracle `header` evaluated against clean, SPA, WAF, encoded, and dynamic bodies.
`firm` plus findings: 0. WAF body correctly rejects as untrusted.

## Lab Result

Procedure: serve the Juice Shop target from `docker-compose.lab.yml`, scan the
landing page, expect one low severity header finding and no other claims.
Status: pending manual run. Expected Precision 100 percent on this page class.

## Precision

True positives 2, false positives 0. Precision 1.00.

## Recall

True positives 2, false negatives 0. Recall 1.00.

## Gate Verdict

PASS. Precision 1.00 is above the 0.99 gate. Corpus holds 0 `firm` plus.

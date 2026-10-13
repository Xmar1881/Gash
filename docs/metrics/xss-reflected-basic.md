<!--
SPDX-License-Identifier: AGPL-3.0-only
Copyright (C) 2026 Xmar1881 / GASH contributors
Module: github.com/Xmar1881/Gash

File: docs/metrics/xss-reflected-basic.md
What: Precision and recall report for the Tier 2 reflected-XSS plugin.
Why: Proves the spec section 4.6 JS example meets the gate with controls.
-->

# Metrics: xss-reflected-basic

## Overview

Tier 2 plugin following the specification section 4.6 JavaScript example.
Oracle `reflection` over `html`, `attr`, and `script` contexts. Executable
reflection plus clean control confirms; text or encoded reflection stays
`tentative`.

## Evidence Standard

Rule GASH-001. Control payloads that render executable reject the candidate.
WAF block pages are untrusted and always reject. Missing reflection rejects.

## Fixtures

- Positive: 2 of 2 accepted at `confirmed` (script block, event handler).
- Negative: 4 of 4 clean (text stays `tentative`, encoded at most `tentative`,
  WAF rejects, absent reflection rejects).
- Command: `go run ./cmd/gash plugins test plugins/xss/xss-reflected-basic.js`

## Corpus Result

Oracle `reflection` with a never-present canary against clean, SPA, WAF,
encoded, and dynamic bodies. `firm` plus findings: 0.

## Lab Result

Procedure: use the DVWA reflected-XSS page at low security from
`docker-compose.lab.yml`, scan the query input, expect a high severity
`confirmed` finding. Status: pending manual run. Expected Recall 1.00 on the
basic contexts covered here; exotic contexts stay out of scope.

## Precision

True positives 2, false positives 0. Precision 1.00.

## Recall

True positives 2, false negatives 0. Recall 1.00.

## Gate Verdict

PASS. Precision 1.00 is above the 0.99 gate. Corpus holds 0 `firm` plus.

## Note

The event-handler fixture uses a `div` tag because the oracle classifies
`src` or `href` neighbours as URL context first; this documents oracle
behaviour, not a plugin weakness.

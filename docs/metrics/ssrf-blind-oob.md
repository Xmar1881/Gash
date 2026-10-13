<!--
SPDX-License-Identifier: AGPL-3.0-only
Copyright (C) 2026 Xmar1881 / GASH contributors
Module: github.com/Xmar1881/Gash

File: docs/metrics/ssrf-blind-oob.md
What: Precision and recall report for the blind-SSRF mandatory-OOB plugin.
Why: Proves the required-OOB discipline with honest skip and no fake tentative.
-->

# Metrics: ssrf-blind-oob

## Overview

Tier 2 plugin with `oob: required`, `safe: false`, `active: true`. Oracle `oob`.
A callback matching correlation plus namespace confirms. Without an OOB
server the scheduler skips the plugin and no `tentative` is produced.

## Evidence Standard

Rule GASH-008. Blind SSRF has no in-band confirmation path. Missing callback
means no finding. Timing hints alone are never evidence.

## Fixtures

- Positive: 2 of 2 accepted at `confirmed` with mocked callbacks.
- Negative: 2 of 2 rejected (no callback, timing hint only).
- Command: `go run ./cmd/gash plugins test plugins/ssrf/ssrf-blind-oob.js`
- Skip proof: `TestB9RealOOBSkip` schedules nothing without a server and
  reports `skipped (oob-not-configured)`.

## Corpus Result

Oracle `oob` with no callback against clean, SPA, WAF, encoded, and dynamic
bodies. `firm` plus findings: 0.

## Lab Result

Procedure: deploy the self-hosted OOB server beside the lab network from
`docker-compose.lab.yml`, scan the webhook endpoint with `--oob-server` and
`--active`, expect one high severity `confirmed` finding after the callback.
Without `--oob-server` expect a documented skip. Status: pending manual run.

## Precision

True positives 2, false positives 0. Precision 1.00.

## Recall

True positives 2, false negatives 0 on the mocked callback path. Recall 1.00.

## Gate Verdict

PASS. Precision 1.00 is above the 0.99 gate. Corpus holds 0 `firm` plus.

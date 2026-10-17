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

## Live Path (multi-variant corpus, shared window)

The live script ships a bounded corpus per injection point (≤60 requests):
absolute/alternate schemes (`http`, `https`, scheme-relative, `gopher://`,
`ftp://`, `dns://`), parser-confusion forms (userinfo `@`, raw/encoded `#`,
backslash), redirect-echo forms against the target origin, and — only for
dotted-quad callback domains — numeric-notation hosts (decimal, dotted-octal,
hex, IPv4-mapped IPv6). Every variant carries its own single-use correlation
token in the hostname, so a callback can only match the exact request that
caused it. All tokens are verified in ONE shared bounded window
(`oob.WaitForCallbacks`, 10 s / 2 polls) via `host.oracles.oobAny`; a token
that never fires produces no finding. Numeric-notation hosts carry the token
only in the path, so they can confirm solely when the operator's server
indexes path tokens — best-effort coverage, documented in `known-limits.md`.

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

## Dataset

- Dataset hash: `88b7f12f2ec8e683929475bcf3f50812775bb560fb1f00f8728132a405a497db`
  (sha256 over all 4 fixture files under `tests/fixtures/ssrf-blind-oob/`).
- Samples: TP=2, FP=0, TN=2, FN=0 on the mocked callback path.
  Fixture-only measurement; lab pending above. `TestMetricGate` fails the
  build if this hash drifts from the fixtures.

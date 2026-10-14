<!--
SPDX-License-Identifier: AGPL-3.0-only
Copyright (C) 2026 Xmar1881 / GASH contributors
Module: github.com/Xmar1881/Gash

File: docs/metrics/command-injection-error.md
What: Precision and recall report for the command injection error-based reference plugin.
Why: Proves Tier 1 error oracle (generic_error mode) meets signature-plus-control standard.
-->

# Metrics: command-injection-error

## Overview

Tier 1 active plugin. Oracle `error` with `mode: generic_error`. Shell error signature
match (stack trace, exception, traceback, runtime error) plus absent-in-control proof.
Maximum confidence `confirmed` with control; `firm` without.

## Evidence Standard

Rule GASH-004 extended. `generic_error` signatures: stack trace, exception, traceback,
runtime error, fatal error, internal server error, syntax error, null pointer, division
by zero. Control response must not contain the same signature. WAF/block pages classify
`Untrusted` and always reject.

## Fixtures

- Positive: 2 of 2 accepted (2 `confirmed` with control).
- Negative: 2 of 2 rejected (no error, same error in control).
- Command: `go run ./cmd/gash plugins test plugins/command-injection/command-injection-error.yaml`

## Corpus Result

Oracle `error` (generic_error) evaluated against clean, SPA, WAF, encoded, and dynamic
bodies. `firm` plus findings: 0. WAF body correctly rejects as untrusted.

## Lab Result

Procedure: serve a command injection vulnerable endpoint (e.g., `; cat /etc/passwd`),
scan with payload, expect one critical severity finding at `confirmed`.
Status: pending manual run. Expected Precision 100 percent on this vulnerability class.

## Precision

True positives 2, false positives 0. Precision 1.00.

## Recall

True positives 2, false negatives 0. Recall 1.00.

## Gate Verdict

PASS. Precision 1.00 is above the 0.99 gate. Corpus holds 0 `firm` plus.

## Dataset

- Dataset hash: `d6342c272f875bcf25f8dbfdcbf6c3493dcbba181779bdb9e81f34b369b842af`
  (sha256 over all 4 fixture files under `tests/fixtures/command-injection-error/`).
- Samples: TP=2, FP=0, TN=2, FN=0. Fixture-only measurement; lab pending above.
  `TestMetricGate` fails the build if this hash drifts from the fixtures.
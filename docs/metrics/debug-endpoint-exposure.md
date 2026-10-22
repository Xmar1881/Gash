<!--
SPDX-License-Identifier: AGPL-3.0-only
Copyright (C) 2026 Xmar1881 / GASH contributors
Module: github.com/Xmar1881/Gash

File: docs/metrics/debug-endpoint-exposure.md
What: Precision and recall report for the debug endpoint exposure plugin.
Why: Proves Tier 1 error oracle (generic_error + management_endpoint modes)
  meets the precision gate with extended debug endpoint coverage.
-->

# Metrics: debug-endpoint-exposure

## Overview

Tier 1 active plugin. Oracle `error` with modes `generic_error` and
`management_endpoint`. Detects exposed debug and diagnostic endpoints across
frameworks (Django, Flask, Express, Rails, Laravel, PHP, GraphQL, Swagger,
Kubernetes, Docker, Jenkins, GitLab, Prometheus, Elasticsearch) by matching
debug/error markers on fixed paths with soft-404 control absence.

## Evidence Standard

Rule GASH-XXX (CWE-200, CWE-497). Requires a canonical debug/error marker
(stack trace, exception, actuator marker, debugger PIN, etc.) in the response
body AND absent from the soft-404 control of the same path. A bare 200 is
never enough. Fixed bounded path list; no directory brute force.

## Fixtures

- Positive: 2 of 2 accepted (`firm`).
- Negative: 2 of 2 rejected (no marker, SPA catch-all).
- Command: `go run ./cmd/gash plugins test plugins/debug-endpoint-exposure/debug-endpoint-exposure.yaml`

## Corpus Result

Oracle `error` evaluated against clean, SPA, WAF, and dynamic bodies.
`firm` plus findings: 0. WAF body correctly rejects as untrusted. SPA catch-all
correctly rejected via soft-404 control.

## Lab Result

Procedure: serve debug endpoints in the localhost lab, scan with active mode,
expect medium severity findings at `firm`. Status: pending manual run.

## Precision

True positives 2, false positives 0. Precision 1.00.

## Recall

True positives 2, false negatives 0. Recall 1.00.

## Gate Verdict

PASS. Precision 1.00 is above the 0.99 gate. Corpus holds 0 `firm` plus.

## Dataset

- Dataset hash: `44e533dff158f02fe56e263a6aaa2a20713dd04c6ecc0fd493df14eae0ce102e`
  (sha256 over all 4 fixture files under `tests/fixtures/debug-endpoint-exposure/`).
- Samples: TP=2, FP=0, TN=2, FN=0. Fixture-only measurement; lab pending above.
  `TestMetricGate` fails the build if this hash drifts from the fixtures.

## Limitations

- Fixed path list; custom/renamed debug endpoints not detected.
- Soft-404 control required; may miss endpoints on servers without consistent 404s.
- No authentication bypass testing; only anonymous exposure.
- Management endpoints (Spring Actuator) also covered by `management-endpoint-exposure`.
- GraphQL introspection covered by `graphql-introspection-enabled`.
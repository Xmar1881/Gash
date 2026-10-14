<!--
SPDX-License-Identifier: AGPL-3.0-only
Copyright (C) 2026 Xmar1881 / GASH contributors
Module: github.com/Xmar1881/Gash

File: docs/metrics/path-traversal-error.md
What: Precision and recall report for the path traversal error reference plugin.
Why: Proves Tier 1 active path traversal detection meets the 99 percent precision gate.
-->

# Metrics: path-traversal-error

## Overview

Tier 1 active plugin. Oracle `error` (mode: `path_traversal`). Detects path traversal via file access error signatures.

## Evidence Standard

Rule GASH-004 extended. Error signature checks require control request for `confirmed`. Path traversal signatures without control yield `firm`.

## Fixtures

- Positive: 2 of 2 accepted (`confirmed` with control).
- Negative: 2 of 2 rejected.
- Command: `go run ./cmd/gash plugins test plugins/path-traversal/path-traversal-error.yaml`

## Corpus Result

Oracle `error` (path_traversal mode) evaluated against clean, SPA, WAF, encoded, and dynamic bodies.
`firm` plus findings: 0. WAF body correctly rejects as untrusted.

## Lab Result

Procedure: serve a test target with path traversal vulnerability, scan, expect one high severity finding.
Status: pending manual run. Expected Precision 100 percent on this page class.

## Precision

True positives 2, false positives 0. Precision 1.00.

## Recall

True positives 2, false negatives 0. Recall 1.00.

## Gate Verdict

PASS. Precision 1.00 is above the 0.99 gate. Corpus holds 0 `firm` plus.

## Dataset

- Dataset hash: `b1e16e54bfe5cea2091de39ee5a3d00edf00c46b81936f6cc8ca32978c1f7ac2`
  (sha256 over all 4 fixture files under `tests/fixtures/path-traversal-error/`).
- Samples: TP=2, FP=0, TN=2, FN=0. Fixture-only measurement; lab pending above.
  `TestMetricGate` fails the build if this hash drifts from the fixtures.

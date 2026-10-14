<!--
SPDX-License-Identifier: AGPL-3.0-only
Copyright (C) 2026 Xmar1881 / GASH contributors
Module: github.com/Xmar1881/Gash

File: docs/metrics/file-upload-unrestricted.md
What: Precision and recall report for the Tier 1 file upload plugin.
Why: Proves generic error signature detection meets the 99 percent precision gate.
-->

# Metrics: file-upload-unrestricted

## Overview

Tier 1 active plugin. Oracle `error` with mode `generic_error`. Inspects file upload responses for stack traces, exceptions, and filesystem errors that indicate unrestricted file upload with error disclosure.

## Evidence Standard

Rule GASH-004 extended (CWE-434, CWE-209). File upload endpoints that return stack traces, permission errors, or internal server errors on malformed uploads leak filesystem structure and application internals. Requires control request (clean upload) to confirm the error is payload-induced. Confidence: `confirmed` with control, `firm` without.

## Fixtures

- Positive: 2 of 2 accepted (1 Java stack trace, 1 PHP fatal error).
- Negative: 2 of 2 rejected (successful upload, validation error without stack trace).
- Command: `go run ./cmd/gash plugins test plugins/file-upload/file-upload-unrestricted.yaml`

## Corpus Result

Oracle `error` (generic_error mode) evaluated against clean, SPA, WAF, encoded, and dynamic bodies. `firm` plus findings: 0. Corpus bodies do not carry upload error signatures.

## Lab Result

Procedure: serve a file upload endpoint that returns stack traces on invalid uploads from `docker-compose.lab.yml`, scan the endpoint, expect one high severity file upload finding and no other claims.
Status: pending manual run. Expected Precision 100 percent on this page class.

## Precision

True positives 2, false positives 0. Precision 1.00.

## Recall

True positives 2, false negatives 0. Recall 1.00.

## Gate Verdict

PASS. Precision 1.00 is above the 0.99 gate. Corpus holds 0 `firm` plus.

## Dataset

- Dataset hash: `b1e64595eff7dd1198a0f6938e0b398d0685e0c42b2e060f791f403d103112e4` (sha256 over all 4 fixture files under `tests/fixtures/file-upload-unrestricted/`).
- Samples: TP=2, FP=0, TN=2, FN=0. Fixture-only measurement; lab pending above.
  `TestMetricGate` fails the build if this hash drifts from the fixtures.

## Limitations

- v1 detects error disclosure on upload; does not verify actual file write/execution.
- Requires control request (clean upload) for `confirmed`; without control caps at `firm`.
- Multipart/form-data boundary variations not fuzzed in v1.

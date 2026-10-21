<!--
SPDX-License-Identifier: AGPL-3.0-only
Copyright (C) 2026 Xmar1881 / GASH contributors
Module: github.com/Xmar1881/Gash

File: docs/metrics/path-traversal-error.md
What: Precision and recall report for the path traversal file-content reference plugin.
Why: Proves Tier 1 active path traversal detection meets the 99 percent precision gate.
-->

# Metrics: path-traversal-error

## Overview

Tier 1 active plugin. Oracle `error` (mode: `path_traversal`). Detects path traversal through successful target-file content (`/etc/passwd`, `C:\Windows\win.ini`).

## Evidence Standard

Rule GASH-017 / CWE-22. Content signatures require control request for `confirmed`; without a control they stay `firm`. Generic include warnings do not qualify: DVWA emits the same warning for the neutral control, so only successful file content proves the traversal.

## Fixtures

- Positive: 4 of 4 accepted (`confirmed` with control).
- Negative: 4 of 4 rejected.
- Command: `go run ./cmd/gash plugins test plugins/path-traversal/path-traversal-error.yaml`

## Corpus Result

Oracle `error` (path_traversal mode with content signatures) evaluated against clean, SPA, WAF, encoded, reflection-only, and dynamic bodies.
`firm` plus findings: 0. WAF body correctly rejects as untrusted. Reflected traversal text and include warnings alone reject.

## Lab Result

Procedure: scan DVWA `/vulnerabilities/fi/?page=include.php` with the admin session and the native-lab scan flags.
Status: measured in the 2026-10-20 native lab. DVWA `/vulnerabilities/fi/` was independently verified, and both Gash standard and deep scored it TP with one high `GASH-017`/`CWE-22` `path-traversal-error` finding at `confirmed` confidence and `windows_ini` evidence. Nuclei also scored it TP. See `native-lab-2026-10-20.md`.

## Precision

True positives 4, false positives 0. Precision 1.00.

## Recall

True positives 4, false negatives 0. Recall 1.00.

## Gate Verdict

PASS. Precision 1.00 is above the 0.99 gate. Corpus holds 0 `firm` plus.

## Dataset

- Dataset hash: `e067e6e22717d161a45676c9e96f379b087eaf578e54c286b40ab4a2b1935a06`
  (sha256 over all 8 fixture files under `tests/fixtures/path-traversal-error/`).
- Samples: TP=4, FP=0, TN=4, FN=0. Fixture-only measurement; lab verification above.
  `TestMetricGate` fails the build if this hash drifts from the fixtures.

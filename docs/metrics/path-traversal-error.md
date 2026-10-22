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

Tier 1 active plugin. Oracle `error` (mode: `path_traversal`). Detects path traversal through successful target-file content (`/etc/passwd`, `C:\Windows\win.ini`) or a file-open error that is absent from the neutral-parameter control.

## Evidence Standard

Rule GASH-017 / CWE-22. Content signatures and `include_error` require a control request for `confirmed`; without a control they stay `firm`. Raw traversal text or a warning present in both attack and control never qualifies. Generic missing-file text without a file-open error also rejects.

## Fixtures

- Positive: 5 of 5 accepted (`confirmed` with control).
- Negative: 5 of 5 rejected.
- Command: `go run ./cmd/gash plugins test plugins/path-traversal/path-traversal-error.yaml`

## Corpus Result

Oracle `error` (path_traversal mode with content and controlled include-error signatures) evaluated against clean, SPA, WAF, encoded, reflection-only, and dynamic bodies.
`firm` plus findings: 0. WAF body correctly rejects as untrusted. Reflected traversal text and control-equal include warnings reject.

## Lab Result

Procedure: scan DVWA `/vulnerabilities/fi/?page=include.php` with the admin session and the native-lab scan flags.
Status: measured in the 2026-10-20 native lab. DVWA `/vulnerabilities/fi/` was independently verified, and both Gash standard and deep scored it TP with one high `GASH-017`/`CWE-22` `path-traversal-error` finding at `confirmed` confidence and `windows_ini` evidence. Nuclei also scored it TP. See `native-lab-2026-10-20.md`.

## Precision

True positives 5, false positives 0. Precision 1.00.

## Recall

True positives 5, false negatives 0. Recall 1.00.

## Gate Verdict

PASS. Precision 1.00 is above the 0.99 gate. Corpus holds 0 `firm` plus.

## Dataset

- Dataset hash: `bdf533ccdf9d1ac4964f87e38a09d05f99e61a62496233b5cc8cbc9c770e0f80`
  (sha256 over all 10 fixture files under `tests/fixtures/path-traversal-error/`).
- Samples: TP=5, FP=0, TN=5, FN=0. Fixture-only measurement; lab verification above.
  `TestMetricGate` fails the build if this hash drifts from the fixtures.

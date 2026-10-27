<!--
SPDX-License-Identifier: AGPL-3.0-only
Copyright (C) 2026 Xmar1881 / GASH contributors
Module: github.com/Xmar1881/Gash

File: docs/metrics/path-traversal-encoding-bypass.md
What: Precision and recall report for the encoded path-traversal plugin.
Why: Proves the encoded payload family plus neutral control meets the gate.
-->

# Metrics: path-traversal-encoding-bypass

## Overview

Tier 2 active JS plugin. Oracle `error` with `mode: path_traversal` declared in
`oracle_params`. Tier 1 sends one literal traversal payload per file; naive
filters strip `../` once, so single-encoded, double-encoded, backslash,
overlong-style and dot-collapsed forms can still reach the filesystem. The
payloads are pre-encoded inside the raw URL or body so the engine's form
encoder cannot add or remove a layer. A response that only echoes the payload
is skipped.

## Evidence Standard

`ErrorSignatureOracle` path_traversal set (`path_traversal`, `unix_passwd`,
`windows_ini`): a file-access error or file-content marker in the attack
response, absent from the neutral-value control.

## Fixtures

- Positive: 2 of 2 accepted (`confirmed`; file-access error, passwd content).
- Negative: 2 of 2 rejected (error in control, neutral value served normally).
- Command: `go run ./cmd/gash plugins test plugins/path-traversal/path-traversal-encoding-bypass.js`

## JS E2E

`TestPathTraversalEncodingBypassE2E` executes the script through `loader.ExecuteJS`:

- Only the double-encoded variant reaches the filesystem in the mock; the
  plugin tries the single-encoded form first, then confirms on the
  double-encoded one: one `confirmed` candidate; both encodings are asserted.
- A reflected payload without an access error rejects.
- Send budget and the oracle surface are asserted.

## Corpus Result

The `path_traversal` mode is part of the existing error oracle and has no new
signatures. Fixture-only measurement.

## Lab Result

Procedure: serve a download handler that strips `../` once before opening the
file, scan with this plugin, expect one high-severity finding at `confirmed` on
the double-encoded variant. Status: pending manual run.

## Precision

True positives 2, false positives 0. Precision 1.00.

## Recall

True positives 2, false negatives 0. Recall 1.00.

## Gate Verdict

PASS. Precision 1.00 is above the 0.99 gate. Corpus holds 0 findings.

## Dataset

- Dataset hash: `0dad2d4680397189489c8fefe116eaa4146ac7f7195a2f1766cc22c8af70911b`
  (sha256 over all 4 fixture files under `tests/fixtures/path-traversal-encoding-bypass/`).
- Samples: TP=2, FP=0, TN=2, FN=0. Fixture-only measurement; lab pending above.
  `TestMetricGate` fails the build if this hash drifts from the fixtures.

## Limitations

- Server-specific decoding orders are not fingerprinted; a normalizing proxy
  can neutralize every variant.
- Echo-suppression may hide an error page that quotes the payload verbatim
  alongside a genuine access error.

<!--
SPDX-License-Identifier: AGPL-3.0-only
Copyright (C) 2026 Xmar1881 / GASH contributors
Module: github.com/Xmar1881/Gash

File: docs/metrics/command-injection-oob.md
What: Precision and recall report for the blind command injection OOB plugin.
Why: Proves Tier 1 OOB oracle (GASH-010) meets the precision gate with
  out-of-band callback confirmation. Requires self-hosted --oob-server.
-->

# Metrics: command-injection-oob

## Overview

Tier 1 active plugin. Oracle `oob`. Blind OS command injection with out-of-band
DNS/HTTP callback confirmation. Requires self-hosted `--oob-server`; without
it the plugin skips honestly (`oob-not-configured`). Payloads use harmless
callbacks (`curl`, `wget`, `nslookup`, `dig`); no destructive commands.
Confidence ceiling `confirmed` (callback match only).

## Evidence Standard

Rule GASH-010 (CWE-78). Requires a matching OOB callback with the correct
single-use correlation token and namespace. Without `--oob-server` the plugin
does not run (scheduler skip). A callback proves the command executed and
reached the operator's server. No timing fallback; no callback = no finding.

## Fixtures

- Positive: 1 of 1 accepted (`confirmed`).
- Negative: 1 of 1 rejected (no callback).
- Command: `go run ./cmd/gash plugins test plugins/command-injection/command-injection-oob.yaml`

## Corpus Result

Oracle `oob` evaluated against clean, SPA, WAF, and dynamic bodies.
`confirmed` plus findings: 0. WAF body correctly rejects as untrusted.

## Lab Result

Procedure: serve a blind command injection endpoint in the localhost lab,
scan with OOB payloads, expect one critical severity finding at `confirmed`.
Status: pending manual run. Expected Precision 100 percent on this vulnerability class.

## Precision

True positives 1, false positives 0. Precision 1.00.

## Recall

True positives 1, false negatives 0. Recall 1.00.

## Gate Verdict

PASS. Precision 1.00 is above the 0.99 gate. Corpus holds 0 `firm` plus.

## Dataset

- Dataset hash: `d5299c73310f5a2aa4140ce64fa2b47a9a216749d8bea63de89180410b3c9abe`
  (sha256 over all 2 fixture files under `tests/fixtures/command-injection-oob/`).
- Samples: TP=1, FP=0, TN=1, FN=0. Fixture-only measurement; lab pending above.
  `TestMetricGate` fails the build if this hash drifts from the fixtures.

## Limitations

- Requires self-hosted OOB server (`--oob-server`); no public interactsh default.
- Only harmless callback payloads; no output reflection or destructive commands.
- OOB-only proof; no timing fallback. Output-reflecting injection covered by `command-injection-error`.
- Blind timing-only injection covered by `command-injection-timing` (firm ceiling).
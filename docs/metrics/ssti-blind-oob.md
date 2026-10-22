<!--
SPDX-License-Identifier: AGPL-3.0-only
Copyright (C) 2026 Xmar1881 / GASH contributors
Module: github.com/Xmar1881/Gash

File: docs/metrics/ssti-blind-oob.md
What: Precision and recall report for the blind SSTI OOB plugin.
Why: Proves Tier 1 OOB oracle meets the precision gate with
  out-of-band callback confirmation. Requires self-hosted --oob-server.
-->

# Metrics: ssti-blind-oob

## Overview

Tier 1 active plugin. Oracle `oob`. Blind server-side template injection with
out-of-band DNS/HTTP callback confirmation. Requires self-hosted `--oob-server`;
without it the plugin skips honestly (`oob-not-configured`). Payloads use
template-engine-specific constructs (Jinja2, Twig, Freemarker, Velocity, Mako)
to trigger callbacks. Confidence ceiling `confirmed` (callback match only).

## Evidence Standard

Rule GASH-015 (CWE-1336). Requires a matching OOB callback with the correct
single-use correlation token and namespace. Without `--oob-server` the plugin
does not run (scheduler skip). A callback proves the template executed and
reached the operator's server. No timing fallback; no callback = no finding.

## Fixtures

- Positive: 1 of 1 accepted (`confirmed`).
- Negative: 1 of 1 rejected (no callback).
- Command: `go run ./cmd/gash plugins test plugins/ssti/ssti-blind-oob.yaml`

## Corpus Result

Oracle `oob` evaluated against clean, SPA, WAF, and dynamic bodies.
`confirmed` plus findings: 0. WAF body correctly rejects as untrusted.

## Lab Result

Procedure: serve a blind SSTI endpoint in the localhost lab,
scan with OOB payloads, expect one critical severity finding at `confirmed`.
Status: pending manual run. Expected Precision 100 percent on this vulnerability class.

## Precision

True positives 1, false positives 0. Precision 1.00.

## Recall

True positives 1, false negatives 0. Recall 1.00.

## Gate Verdict

PASS. Precision 1.00 is above the 0.99 gate. Corpus holds 0 `firm` plus.

## Dataset

- Dataset hash: `a26fb995011f789941bd0d6c5d660f3d8654d067689ccfb48517616b2cd9bf92`
  (sha256 over all 2 fixture files under `tests/fixtures/ssti-blind-oob/`).
- Samples: TP=1, FP=0, TN=1, FN=0. Fixture-only measurement; lab pending above.
  `TestMetricGate` fails the build if this hash drifts from the fixtures.

## Limitations

- Requires self-hosted OOB server (`--oob-server`); no public interactsh default.
- Template-engine-specific payloads; sandboxed engines may block callbacks.
- No timing fallback; blind timing-based SSTI covered by `ssti-blind-timing` (firm ceiling).
- Reflected SSTI with arithmetic proof covered by `template-injection-reflection` and `expression-language-injection`.
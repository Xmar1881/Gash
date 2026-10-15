<!--
SPDX-License-Identifier: AGPL-3.0-only
Copyright (C) 2026 Xmar1881 / GASH contributors
Module: github.com/Xmar1881/Gash

File: docs/metrics/hpp-duplicate-emission.md
What: Precision and recall report for the Tier 2 HPP duplicate-key emission plugin.
Why: Proves native id=1&id=2 emission plus differential comparison meets the 99
  percent precision gate (3/3 masked stability + divergence, unstable rejects).
-->

# Metrics: hpp-duplicate-emission

## Overview

Tier 2 active JS plugin. Oracle `differential`. Tier 1 `hpp-parameter-pollution`
models pollution as true/false value divergence (approximation); this plugin
emits a real duplicated key (`id=1&id=2`) and compares duplicate versus single
responses with 3/3 masked stability; stable divergence gives `confirmed`,
unstable or identical branches reject (never `tentative`).

No new sandbox surface: only `probe.send` plus `ctx` surface plus
`host.oracles.differential` plus `host.candidate`. Query duplicates are built
as `?id=1&id=2` URLs sent with an empty `paramName` so the engine uses the URL
as-is; form duplicates are built as `id=1&id=2` bodies on the same path.
Header/path/cookie points are skipped (duplicate keys do not apply).

## Evidence Standard

Differential rule (GASH-005 family extended to parameter parsing). Masking
profile is the engine default (tokens, nonces, timestamps, UUIDs). Unstable
dynamic content rejects rather than confirming.

## Fixtures

- Positive: 2 of 2 accepted (`confirmed`; list pollution, sort-order confusion).
- Negative: 2 of 2 rejected (consistent last-value-wins, unstable edge).
- Command: `go run ./cmd/gash plugins test plugins/hpp/hpp-duplicate-emission.js`

## JS E2E

`TestHPPDuplicateEmissionE2E` (`tests/plugins/hpp_duplicate_emission_test.go`)
executes the real script through `loader.ExecuteJS` with a mocked transport:

- Query `id` point, duplicate URL returns polluted body, single `1` returns
  guest body, control neutral: one `confirmed` differential candidate.
- POST body `id` point with `id=1&id=2` form body: one `confirmed` candidate.
- Last-value-wins backend (duplicate and single both guest): zero candidates.

No new `host.oracles.*` binding is introduced (source grep asserts only
`host.oracles.differential`).

## Corpus Result

Oracle `differential` evaluated against clean, SPA, WAF, encoded, and dynamic
bodies. No corpus body shows stable cross-value divergence. `firm` not emitted
(differential is confirmed-only).

## Lab Result

Procedure: serve a pollutable list/sort endpoint in the localhost lab, scan
with duplicate emission, expect one medium severity finding at `confirmed`.
Status: pending manual run. Expected Precision 100 percent on this page class.

## Precision

True positives 2, false positives 0. Precision 1.00.

## Recall

True positives 2, false negatives 0. Recall 1.00.

## Gate Verdict

PASS. Precision 1.00 is above the 0.99 gate. Corpus holds 0 findings.

## Dataset

- Dataset hash: `97460a36a79fa58440fd58ba488001c58ca50eaa74a2a30447a267b58a997a1c`
  (sha256 over all 4 fixture files under `tests/fixtures/hpp-duplicate-emission/`).
- Samples: TP=2, FP=0, TN=2, FN=0. Fixture-only measurement; lab pending above.
  `TestMetricGate` fails the build if this hash drifts from the fixtures.

## Limitations

- Backend-specific precedence (first-wins vs last-wins) is not fingerprinted in v1.
- Header/path/cookie pollution is out of scope (query/body only).
- Real-target recall (framework-specific parsers) is unmeasured.

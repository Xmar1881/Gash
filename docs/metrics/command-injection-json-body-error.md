<!--
SPDX-License-Identifier: AGPL-3.0-only
Copyright (C) 2026 Xmar1881 / GASH contributors
Module: github.com/Xmar1881/Gash

File: docs/metrics/command-injection-json-body-error.md
What: Precision and recall report for the Tier 2 JSON-body error-based command-injection plugin.
Why: Proves the interpreter-error discipline meets the 99 percent gate behind
  the error oracle with a declared generic_error mode.
-->

# Metrics: command-injection-json-body-error

## Overview

Tier 2 active JS plugin. Oracle `error` with `mode: generic_error` declared in
the frontmatter `oracle_params` block. Six inert shell fragments (unterminated
substitution, incomplete operator) are sent per JSON field; they provoke the
interpreter's own complaint without executing anything.

## Evidence Standard

Error-signature rule (GASH-004 family): the interpreter error must appear for
the broken fragment and be absent for the neutral value; the ceiling is `firm`.

## Fixtures

- Positive: 1 of 1 accepted (`firm`).
- Negative: 1 of 1 rejected (the endpoint fails for every value).
- Command:
  `go run ./cmd/gash plugins test plugins/command-injection/command-injection-json-body-error.js`

## JS E2E

`TestCommandInjectionJSONBodyErrorE2E` (`tests/plugins/tier2_batch4_test.go`)
asserts one `firm` `error` candidate for a shell-syntax failure that only the
payload produces, and none when the failure is universal.

## Corpus Result

Error signatures are covered by the shared corpus gate and produce no
`firm`-plus finding on clean bodies.

## Lab Result

Procedure: lab converter shelling out to a helper, run with `--active`, expect
one `high` finding at `firm`. Status: pending manual run.

## Precision

True positives 1, false positives 0. Precision 1.00.

## Recall

True positives 1, false negatives 0. Recall 1.00.

## Gate Verdict

PASS. Precision 1.00 is above the 0.99 gate. Corpus holds 0 findings.

## Dataset

- Dataset hash: `b56750ecb5c7bb08cfd24f6ecdf4aa45413b1d6a0fe6c0fba40738bb5186aeb3`
- Samples: TP=1, FP=0, TN=1, FN=0. `TestMetricGate` fails on hash drift.

## Limitations

- A backend that swallows stderr produces no signature: the OOB and timing
  JSON-body plugins cover the other two axes.
- Fragments are unix-shell oriented; no Windows command interpreter payloads.

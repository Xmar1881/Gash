<!--
SPDX-License-Identifier: AGPL-3.0-only
Copyright (C) 2026 Xmar1881 / GASH contributors
Module: github.com/Xmar1881/Gash

File: docs/metrics/command-injection-json-body-timing.md
What: Precision and recall report for the Tier 2 JSON-body command-injection timing plugin.
Why: Proves the measured-delay discipline meets the 99 percent gate behind the
  timing oracle with a declared firm ceiling.
-->

# Metrics: command-injection-json-body-timing

## Overview

Tier 2 active JS plugin. Oracle `timing` with `min_delay_ms: 5000` and
`repeats: 3` declared in the frontmatter `oracle_params` block. Five shell
separator variants carry a pure `sleep`; one neutral baseline block of three
samples serves every payload of the point.

## Evidence Standard

Timing rule (GASH-010 family): the median delay must exceed the control by at
least 0.8x the declared minimum and pass the statistical test, and the ceiling
is `firm` because no callback is involved. A single measurement never confirms.

## Fixtures

- Positive: 1 of 1 accepted (`firm`).
- Negative: 1 of 1 rejected (uniform latency across payload and baseline).
- Command:
  `go run ./cmd/gash plugins test plugins/command-injection/command-injection-json-body-timing.js`

## JS E2E

`TestCommandInjectionJSONBodyTimingE2E` (`tests/plugins/tier2_expansion_test.go`)
asserts one `firm` `timing` candidate when the injected field alone is slow,
that uniform latency rejects, and that the send budget holds.

## Corpus Result

The timing oracle rejects clean corpus bodies because only one uniform series
exists, so no `firm`-plus finding is produced.

## Lab Result

Procedure: lab endpoint that passes a JSON field to a shell helper, run with
`--active`, expect one `high` finding at `firm`. Status: pending manual run.

## Precision

True positives 1, false positives 0. Precision 1.00.

## Recall

True positives 1, false negatives 0. Recall 1.00.

## Gate Verdict

PASS. Precision 1.00 is above the 0.99 gate. Corpus holds 0 findings.

## Dataset

- Dataset hash: `91f6a38de3f452a4f0e780b279cfd81a1594a9a831d77dc69fbd5531797e435d`
- Samples: TP=1, FP=0, TN=1, FN=0. `TestMetricGate` fails on hash drift.

## Limitations

- A backend under heavy jitter or an intermediary that buffers the response can
  hide a real delay; the result is a false negative, never a false positive.
- The sleep budget is fixed at six seconds; four-second delays are documented
  as out of scope for this variant.

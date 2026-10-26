<!--
SPDX-License-Identifier: AGPL-3.0-only
Copyright (C) 2026 Xmar1881 / GASH contributors
Module: github.com/Xmar1881/Gash

File: docs/metrics/prototype-pollution-json-body.md
What: Precision and recall report for the Tier 2 JSON-body prototype-pollution plugin.
Why: Proves the nested-object discipline meets the 99 percent gate behind the
  differential oracle.
-->

# Metrics: prototype-pollution-json-body

## Overview

Tier 2 active JS plugin. Oracle `differential`. The discovered JSON field is
sent as an OBJECT carrying a `__proto__` member and compared against an object
with the same member count but no prototype key, three repeats each. A stable
divergence proves the server merged the nested object without a key allowlist.

## Evidence Standard

Differential rule (GASH-041 family): three stable true reads, three stable false
reads, a divergence and a control that is not the true branch give `confirmed`.
A body echoing the injected member is reflection and rejects.

## Fixtures

- Positive: 1 of 1 accepted (`confirmed`).
- Negative: 2 of 2 rejected (both objects merge identically; polluted branch
  unstable).
- Command:
  `go run ./cmd/gash plugins test plugins/prototype-pollution/prototype-pollution-json-body.js`

## JS E2E

`TestPrototypePollutionJSONBodyE2E` (`tests/plugins/tier2_batch4_test.go`)
asserts one `confirmed` `differential` candidate for a merging backend, none for
one that echoes the member, and that the request carries `application/json`.

## Corpus Result

Oracle `differential` is covered by the shared corpus gate and produces no
`firm`-plus finding on clean bodies.

## Lab Result

Procedure: lab API profile endpoint using an unguarded deep merge, run with
`--active`, expect one `high` finding at `confirmed`. Status: pending manual run.

## Precision

True positives 1, false positives 0. Precision 1.00.

## Recall

True positives 1, false negatives 0. Recall 1.00.

## Gate Verdict

PASS. Precision 1.00 is above the 0.99 gate. Corpus holds 0 findings.

## Dataset

- Dataset hash: `0b6b3e3fe7126b8561a1625fc434284eecc4e0296dfda4183f5c1d708b4429d0`
- Samples: TP=1, FP=0, TN=2, FN=0. `TestMetricGate` fails on hash drift.

## Limitations

- Top-level field only: nested JSON paths and `constructor.prototype` chains are
  not expanded.
- Pollution *impact* (whether a gadget was reached) is not measured; the
  divergence proves the merge gap.

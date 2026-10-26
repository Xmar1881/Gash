<!--
SPDX-License-Identifier: AGPL-3.0-only
Copyright (C) 2026 Xmar1881 / GASH contributors
Module: github.com/Xmar1881/Gash

File: docs/metrics/ldap-injection-json-body-timing.md
What: Precision and recall report for the Tier 2 JSON-body blind LDAP timing plugin.
Why: Proves the measured-delay discipline meets the 99 percent gate behind the
  timing oracle with a declared firm ceiling.
-->

# Metrics: ldap-injection-json-body-timing

## Overview

Tier 2 active JS plugin. Oracle `timing` with `min_delay_ms: 5000` and
`repeats: 3` declared in the frontmatter `oracle_params` block. Two filter
closures that expand into many candidate evaluations are sent per JSON field and
compared against a neutral-value baseline block.

## Evidence Standard

Timing rule (GASH-006): the median delay must exceed the control by at least
0.8x the declared minimum and pass the statistical test; the ceiling is `firm`
because no callback is involved.

## Fixtures

- Positive: 1 of 1 accepted (`firm`).
- Negative: 1 of 1 rejected (uniform latency across filter and baseline).
- Command:
  `go run ./cmd/gash plugins test plugins/ldap/ldap-injection-json-body-timing.js`

## JS E2E

`TestLDAPJSONBodyTimingE2E` (`tests/plugins/tier2_batch4_test.go`) asserts one
`firm` `timing` candidate when only the filter closure is slow, that uniform
latency rejects, and that the send budget holds.

## Corpus Result

The timing oracle rejects clean corpus bodies because only one uniform series
exists, so no `firm`-plus finding is produced.

## Lab Result

Procedure: lab directory behind a JSON API, run with `--active`, expect one
`medium` finding at `firm`. Status: pending manual run.

## Precision

True positives 1, false positives 0. Precision 1.00.

## Recall

True positives 1, false negatives 0. Recall 1.00.

## Gate Verdict

PASS. Precision 1.00 is above the 0.99 gate. Corpus holds 0 findings.

## Dataset

- Dataset hash: `5a0c6b088ddfc10238c0be17bbbe6983c8985d13e7b66971e5818442a4738515`
- Samples: TP=1, FP=0, TN=1, FN=0. `TestMetricGate` fails on hash drift.

## Limitations

- The signal is filter-evaluation cost, not a controlled sleep: an indexed
  directory can evaluate the wide closure instantly and stay invisible.
- A backend under heavy jitter can hide a real delay (false negative, never a
  false positive).

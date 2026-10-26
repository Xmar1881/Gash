<!--
SPDX-License-Identifier: AGPL-3.0-only
Copyright (C) 2026 Xmar1881 / GASH contributors
Module: github.com/Xmar1881/Gash

File: docs/metrics/xss-reflected-url-context.md
What: Precision and recall report for the Tier 2 URL-sink reflected-XSS plugin.
Why: Proves the javascript:-scheme discipline meets the 99 percent gate behind
  the reflection oracle with a declared context set.
-->

# Metrics: xss-reflected-url-context

## Overview

Tier 2 active JS plugin. Oracle `reflection` with `contexts: [url-executable]`
and `require_executable_context: true` declared once in the frontmatter
`oracle_params` block. The injected value lands in a URL sink (href/src/action),
where markup is unnecessary: only a `javascript:` scheme executes there.

## Evidence Standard

Reflection rule (GASH-001): a parser-recognized executable URL call plus a clean
control gives `static-execution-evidence`; browser `confirmed` needs the
separate headless verifier. Text-only or fragment-only reflection rejects.

## Fixtures

- Positive: 2 of 2 accepted (`static-execution-evidence`, lowercase and
  mixed-case scheme).
- Negative: 2 of 2 rejected (scheme text in page text; fragment-only sink).
- Command:
  `go run ./cmd/gash plugins test plugins/xss/xss-reflected-url-context.js`

## JS E2E

`TestXSSReflectedURLContextE2E` (`tests/plugins/tier2_batch4_test.go`) executes
the real script through `loader.ExecuteJS`: a javascript: value inside an href
yields one candidate at `static-execution-evidence`; an inert fragment sink
yields none.

## Corpus Result

Oracle `reflection` is covered by the shared corpus gate and produces no
`firm`-plus finding on clean bodies.

## Lab Result

Procedure: lab page echoing a query value into href, run with `--active`, expect
one `high` finding at `static-execution-evidence` (`confirmed` with a browser
build). Status: pending manual run.

## Precision

True positives 2, false positives 0. Precision 1.00.

## Recall

True positives 2, false negatives 0. Recall 1.00.

## Gate Verdict

PASS. Precision 1.00 is above the 0.99 gate. Corpus holds 0 findings.

## Dataset

- Dataset hash: `b96d4710333fd3088bf3f84034eaba3452b5b89364841c43cca7a573cccbb97f`
- Samples: TP=2, FP=0, TN=2, FN=0. `TestMetricGate` fails on hash drift.

## Limitations

- Only the `javascript:` scheme is sent; `data:` and `vbscript:` sinks are not
  enumerated.
- Sinks behind a client-side router (fragment routes) stay with the DOM-sink
  plugin and need the headless build for `confirmed`.

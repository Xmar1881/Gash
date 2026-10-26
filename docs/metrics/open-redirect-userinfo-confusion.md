<!--
SPDX-License-Identifier: AGPL-3.0-only
Copyright (C) 2026 Xmar1881 / GASH contributors
Module: github.com/Xmar1881/Gash

File: docs/metrics/open-redirect-userinfo-confusion.md
What: Precision and recall report for the Tier 2 URL-parser-confusion redirect plugin.
Why: Proves the multi-variant redirect discipline meets the 99 percent gate
  behind the redirect oracle.
-->

# Metrics: open-redirect-userinfo-confusion

## Overview

Tier 2 active JS plugin. Oracle `redirect`. Four variants per point target the
allowlist checks that a single-payload file cannot reach together:
protocol-relative (`//host`), userinfo (`https://trusted@evil`), suffix
(`https://trusted.evil`) and fragment (`https://evil#trusted`) confusion. The
payload host is a per-run canary, so a graded Location can only come from our
own payload.

## Evidence Standard

Redirect rule (GASH-016): the Location host must equal the payload host with a
clean (non-redirecting) control for `confirmed`. A hop that stays on the target
host rejects.

## Fixtures

- Positive: 2 of 2 accepted (`confirmed`).
- Negative: 2 of 2 rejected (relative hop; allowlist redirect to its own host).
- Command:
  `go run ./cmd/gash plugins test plugins/redirect/open-redirect-userinfo-confusion.js`

## JS E2E

`TestOpenRedirectUserinfoConfusionE2E` (`tests/plugins/tier2_batch4_test.go`)
asserts one `confirmed` candidate for a userinfo-form Location and none when the
response hops relatively.

## Corpus Result

Oracle `redirect` is covered by the shared corpus gate and produces no
`firm`-plus finding on clean bodies.

## Lab Result

Procedure: lab redirector validating with `contains(host)`, run with `--active`,
expect one `medium` finding at `confirmed`. Status: pending manual run.

## Precision

True positives 2, false positives 0. Precision 1.00.

## Recall

True positives 2, false negatives 0. Recall 1.00.

## Gate Verdict

PASS. Precision 1.00 is above the 0.99 gate. Corpus holds 0 findings.

## Dataset

- Dataset hash: `ee263cf33a476479dc761b5693a66c5ec3744bda13acfcbfa2b7041a5c3b492f`
- Samples: TP=2, FP=0, TN=2, FN=0. `TestMetricGate` fails on hash drift.

## Limitations

- Four confusion shapes only; backslash and double-encoding variants are not
  enumerated.
- The DNS double-check stays disabled for this plugin (no external resolver
  dependency); the payload canary is the attribution mechanism instead.

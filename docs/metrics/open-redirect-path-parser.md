<!--
SPDX-License-Identifier: AGPL-3.0-only
Copyright (C) 2026 Xmar1881 / GASH contributors
Module: github.com/Xmar1881/Gash

File: docs/metrics/open-redirect-path-parser.md
What: Precision and recall report for the path parser-confusion redirect plugin.
Why: Proves a neutral-path control and exact payload-host match meet the gate.
-->

# Metrics: open-redirect-path-parser

## Overview

Tier 2 active JS plugin. Oracle `redirect`. Routers that normalize a path before
using it as a login redirect treat `//host`, `/\host` and encoded-slash forms
differently. The plugin synthesizes those path shapes, fetches a neutral-path
control first, and calls the redirect oracle with a per-run payload host. A
Location that resolves anywhere else is rejected by the oracle.

## Evidence Standard

`RedirectOracle`: absolute Location, exact payload-host match, and a clean
control. Confirmed requires the control hop to stay internal or absent.

## Fixtures

- Positive: 2 of 2 accepted (`confirmed`; protocol-relative and encoded-slash
  locations pointing at the payload host).
- Negative: 3 of 3 rejected (relative Location, no Location, different host).
- Command: `go run ./cmd/gash plugins test plugins/redirect/open-redirect-path-parser.js`

## JS E2E

`TestOpenRedirectPathParserE2E` executes the script through `loader.ExecuteJS`:

- A path confusion hop to the payload host confirms, and the neutral-path
  control request is asserted.
- A relative hop rejects.
- Send budget and the oracle surface are asserted.

## Corpus Result

The redirect oracle is unchanged. Fixture-only measurement.

## Lab Result

Procedure: serve a login flow that redirects to a path-derived target, scan with
this plugin, expect one medium-severity finding at `confirmed`. Status: pending
manual run.

## Precision

True positives 2, false positives 0. Precision 1.00.

## Recall

True positives 2, false negatives 0. Recall 1.00.

## Gate Verdict

PASS. Precision 1.00 is above the 0.99 gate. Corpus holds 0 findings.

## Dataset

- Dataset hash: `8197bd345f6a1b95cd78c986c4c680538f2aa57555a3bdad337a6fa0df63add6`
  (sha256 over all 5 fixture files under `tests/fixtures/open-redirect-path-parser/`).
- Samples: TP=2, FP=0, TN=3, FN=0. Fixture-only measurement; lab pending above.
  `TestMetricGate` fails the build if this hash drifts from the fixtures.

## Limitations

- Frameworks that reject backslashes and double slashes outright yield a false
  negative.
- The oracle grades the Location header; the HTTP client's redirect policy is
  outside the plugin.

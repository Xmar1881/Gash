<!--
SPDX-License-Identifier: AGPL-3.0-only
Copyright (C) 2026 Xmar1881 / GASH contributors
Module: github.com/Xmar1881/Gash

File: docs/metrics/xss-stored-two-step.md
What: Precision and recall report for the Tier 2 stored-XSS two-request plugin.
Why: Proves the real POST-store plus render-GET flow via the reflection oracle
  meets the 99 percent precision gate with static-execution-evidence
  (browser-confirmed needs a controlled headless run).
-->

# Metrics: xss-stored-two-step

## Overview

Tier 2 active JS plugin. Oracle `reflection` with executable contexts
(`attr-executable`, `script`, `url-executable`). Flow: request 1 stores
`<img src=x onerror=alert(canary)>` through the surface form point
(`probe.send(point.withValue(payload))`, POST preserved); request 2 GETs the
render page (base URL, empty `paramName`) and checks it with
`host.oracles.reflection`. Parser-recognized execution payload plus clean
control gives `static-execution-evidence`; this is static parser proof, not
browser execution.

No new sandbox surface: only `probe.send` plus `ctx.injectionPoints` surface
(form extraction via `discovery.ExtractSurface`) plus `host.oracles.reflection`
plus `host.candidate`.

## Evidence Standard

Rule GASH-002 (CWE-79). Text-only or encoded reflection never exceeds
`tentative`. Control rendering the same executable context rejects
(indistinguishable). `confirmed` requires a controlled headless run
(`browser-confirmed`), not measured here.

## Fixtures

- Positive: 2 of 2 accepted (`static-execution-evidence`: event-handler render, script render).
- Negative: 2 of 2 rejected (filtered render, encoded render at most `tentative`).
- Command: `go run ./cmd/gash plugins test plugins/xss/xss-stored-two-step.js`

## JS E2E

`TestXSSStoredTwoStepE2E` (`tests/plugins/xss_stored_two_step_test.go`)
executes the real script through `loader.ExecuteJS` with a stateful
store/render mock:

- POST `comment` with `alert(canary)` stores; render GET returns the stored
  executable payload; binding control GET (`gash-control-neutral`) returns the
  clean page: one `static-execution-evidence` reflection candidate.
- Filtered backend (render never reflects): zero candidates.

## Corpus Result

Oracle `reflection` evaluated against clean, SPA, WAF, encoded, and dynamic
bodies. `static-execution-evidence` plus findings: 0. WAF body correctly
rejects as untrusted.

## Lab Result

Procedure: serve a comment/review board persisting input in the localhost lab,
run the two-step plugin with `--active` plus `--scope 127.0.0.1`, expect one
high severity finding at `static-execution-evidence` (headless run would lift
to `confirmed`). Requires a fresh lab (control must be pre-store clean;
append-only boards need reset between runs, see Limitations).
Status: pending manual run. Expected Precision 100 percent on this
vulnerability class.

## Precision

True positives 2, false positives 0. Precision 1.00.

## Recall

True positives 2, false negatives 0. Recall 1.00.

## Gate Verdict

PASS. Precision 1.00 is above the 0.99 gate. Corpus holds 0 `firm` plus.

## Dataset

- Dataset hash: `13e7003ed0f1b4df811690132d631efb4c284ab9df13603d46829972e4ec1193`
  (sha256 over all 4 fixture files under `tests/fixtures/xss-stored-two-step/`).
- Samples: TP=2, FP=0, TN=2, FN=0. Fixture-only measurement; lab pending above.
  `TestMetricGate` fails the build if this hash drifts from the fixtures.

## Limitations

- Binding control is fetched post-store; append-only render boards return the
  just-stored canary on the control fetch and reject (indistinguishable).
  Lab must reset or isolate per canary so the control stays pre-store clean.
- `confirmed` requires a controlled headless run (`browser-confirmed`), not measured here.
- Real-target recall (multi-user render flows, async polling) is unmeasured.

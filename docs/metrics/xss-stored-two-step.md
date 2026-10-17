<!--
SPDX-License-Identifier: AGPL-3.0-only
Copyright (C) 2026 Xmar1881 / GASH contributors
Module: github.com/Xmar1881/Gash

File: docs/metrics/xss-stored-two-step.md
What: Precision and recall report for the Tier 2 stored-XSS two-request plugin.
Why: Proves the real POST-store plus render-GET flow via the stored oracle
  meets the 99 percent precision gate with static-execution-evidence
  (browser-confirmed needs a controlled headless run).
-->

# Metrics: xss-stored-two-step

## Overview

Tier 2 active JS plugin. Oracle `stored` (`StoredOracle`, two separate HTTP
exchanges) with executable contexts (`attr-executable`, `script`,
`url-executable`). Flow: request 1 stores `<img src=x
onerror=alert(canary)>` through the surface form point
(`probe.send(point.withValue(payload))`, POST preserved); request 2 GETs the
render page (base URL, empty `paramName`) and verifies the pair with
`host.oracles.storedExecution(storeResp, renderResp, canary, [...])`.
The store exchange proves the write was accepted (never itself XSS proof);
the render exchange is checked with the reflection discipline plus a clean
control. Parser-recognized execution payload plus clean control gives
`static-execution-evidence`; this is static parser proof, not browser
execution.

No new sandbox surface: only `probe.send` plus `ctx.injectionPoints` surface
(form extraction via `discovery.ExtractSurface`) plus `host.oracles.storedExecution`
plus `host.candidate`. Tier 1 `oracle: stored` (`loader.ExecuteTier1`) and
offline `plugintest` evaluation (`Evaluate("stored", ...)`) share the same
`StoredOracle`, so Candidate→Oracle→Evidence→Finding stays engine-owned.

## Evidence Standard

Rule GASH-002 (CWE-79). Text-only or encoded reflection never exceeds
`tentative`. Control rendering the same executable context rejects
(indistinguishable). `confirmed` requires a controlled headless run
(`browser-confirmed`), not measured here.

## Fixtures

- Positive: 3 of 3 accepted (`static-execution-evidence`: event-handler render, script render, javascript-URL render).
- Negative: 5 of 5 pass (filtered render, store-accepted/render-clean, encoded render at most `tentative` x2, dirty control rejects).
- Command: `go run ./cmd/gash plugins test plugins/xss/xss-stored-two-step.js`

## JS E2E

`TestXSSStoredTwoStepE2E` (`tests/plugins/xss_stored_two_step_test.go`)
executes the real script through `loader.ExecuteJS` with a stateful
store/render mock:

- POST `comment` with `alert(canary)` stores; render GET returns the stored
  executable payload; binding control GET (`gash-control-neutral`) returns the
  clean page: one `static-execution-evidence` stored candidate (`workflow=store+render`).
- Filtered backend (render never reflects): zero candidates.

## Corpus Result

Oracle `stored` evaluated against clean, SPA, WAF, encoded, and dynamic
bodies (render without canary, control clean). `static-execution-evidence`
plus findings: 0. WAF body correctly rejects as untrusted.

## Lab Result

Procedure: serve a comment/review board persisting input in the localhost lab,
run the two-step plugin with `--active` plus `--scope 127.0.0.1`, expect one
high severity finding at `static-execution-evidence` (headless run would lift
to `confirmed`). Requires a fresh lab (control must be pre-store clean;
append-only boards need reset between runs, see Limitations).
Status: pending manual run. Expected Precision 100 percent on this
vulnerability class.

## Precision

True positives 3, false positives 0. Precision 1.00.

## Recall

True positives 3, false negatives 0. Recall 1.00.

## Gate Verdict

PASS. Precision 1.00 is above the 0.99 gate. Corpus holds 0 `firm` plus.

## Dataset

- Dataset hash: `87d365a486c00d24533f87b921cbcf0289b1358965c2ab5fc9cddf7886bed9ea`
  (sha256 over all 8 fixture files under `tests/fixtures/xss-stored-two-step/`).
- Samples: TP=3, FP=0, TN=5, FN=0. Fixture-only measurement; lab pending above.
  `TestMetricGate` fails the build if this hash drifts from the fixtures.

## Limitations

- Binding control is fetched post-store; append-only render boards return the
  just-stored canary on the control fetch and reject (indistinguishable).
  Lab must reset or isolate per canary so the control stays pre-store clean.
- `confirmed` requires a controlled headless run (`browser-confirmed`). The
  stored binding now supports it: the script passes a sibling-page
  `controlUrl` per context and (with `--browser-verify`, `-tags deep`, Chrome
  present) the engine only marks the candidate browser-verified when the real
  render URL triggers and the sibling control stays clean. Without browser
  evidence the ceiling remains `static-execution-evidence`; not measured here.
- Real-target recall (multi-user render flows, async polling) is unmeasured.

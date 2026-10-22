<!--
SPDX-License-Identifier: AGPL-3.0-only
Copyright (C) 2026 Xmar1881 / Gash contributors
Module: github.com/Xmar1881/Gash

File: docs/metrics/dom-sink-basic.md
What: Precision and recall report for the static DOM sink plugin.
Why: Records the firm static ceiling and the opt-in headless execution path
for query and fragment/hash injection points.
-->

# Metrics: dom-sink-basic

## Overview

Tier 2 plugin. For server-reachable query/form/header points it sends the
benign XSS probe and calls `host.oracles.execution(resp)`; the Go binding
detects a static sink (`innerHTML`, `outerHTML`, `insertAdjacentHTML`,
`document.write`/`writeln`, `eval(`, `setTimeout(`/`setInterval(` with string
args, jQuery `.html(`, `new Function(`, `location.hash` assignment,
`postMessage(`) plus a URL-controlled source (`location.hash`/`search`,
`document.location`, `document.URL`, `document.referrer`, `URLSearchParams`,
`window.name`, `postMessage`). Static evidence caps at `firm`. Fragment/hash
points never reach the server, so they use `host.oracles.browserExecution`
directly. The opt-in deep build (`--browser-verify`) can upgrade a point to
`confirmed` only when the browser triggers and the neutral control stays
clean; the standard build links no browser and keeps the static ceiling.

## Evidence Standard

Rule GASH-003 (CWE-79). Sink required; sink plus source yields `firm`;
sink without source yields `tentative`; no sink rejects. WAF/block pages
classify `Untrusted` and always reject. Browser-executed confirmation
(`Triggered` plus `ControlClean`) is the only `confirmed` path and needs the
headless build. The deep driver now returns an explicit outcome:
`confirmed` (token trigger + clean control with usable statuses), `candidate`
(trigger + dirty control),
`not_vulnerable` (clean control, no trigger for the tested payload/control
pair only), `blocked` (401/403/407/429/451), `error` (408, 5xx, or navigation
failure), and `unverified` (indistinguishable pages). `blocked` and `error`
are surfaced as verifier skips, never as a clean negative or a false
negative. Block reasons are stable codes (`auth_required`, `forbidden`,
`proxy_auth_required`, `rate_limited`, `legal_block`, `request_timeout`,
`server_error`) prefixed with `payload_` or `control_`; a 403 is not
automatically labeled WAF. Confirmation requires a unique per-run token
stamped by an actual JS side effect (`alert`/`confirm`/`prompt` call or
`window.__gashCanary=true`); inserting a `__gash_canary` node is not
execution. The token bootstrap runs before page scripts, the probe covers
same-origin frames, and it polls for up to 2 s for async/SPA handlers.

## Fixtures

- Positive: 2 of 2 accepted (`firm`: innerHTML plus location.hash, document.write plus location.search).
- Negative: 2 of 2 rejected (no sink, plain text).
- Command: `go run ./cmd/gash plugins test plugins/xss/dom-sink-basic.js`

## Corpus Result

Oracle `execution` returns reject on sink-free bodies; the clean, SPA, and
encoded corpus shapes carry no listed sink and stay silent. WAF block bodies
reject as untrusted before sink analysis.

## Lab Result

Synthetic localhost lab does not render JavaScript, so DOM execution is not
lab-measured. Browser confirmation (headless `Triggered` plus `ControlClean`)
is implemented in `internal/headless` with `chromedp v0.21.0` behind `-tags
deep` (default build still links no browser). `TestDeepVerifiesDOMExecution`
covers a query-style DOM payload and `TestDeepVerifyXSSHashRoute` covers the
`#/search?q=` fragment route with a real Chrome 155 headless browser; both
require a clean control. `TestDeepDOMFixtureOutcomeMatrix` extends this to a
local fixture matrix: hash `innerHTML`, async and delayed-async `innerHTML`,
SPA `history.pushState` plus delayed `innerHTML`, `URLSearchParams`
`innerHTML`, dialog-only execution, same-origin iframe execution,
node-insertion-only non-execution, safe `textContent`, sanitized
`innerHTML`, reflection-only, 403-blocked, and 500-error pages.
`TestDeepBrowserVerifyDOMFinding` exercises
the same path through the engine, and `TestDeepDOMFixtureNavigationError`
proves a closed server is an error, not a clean negative. The 2026-10-20
native-lab report still has `confirmed_tp=0`, so browser-confirmed recall
remains unmeasured in the benchmark. Fixture and corpus claims stay at the
static `firm` ceiling.

## Precision

True positives 2, false positives 0. Precision 1.00.

## Recall

True positives 2, false negatives 0. Recall 1.00.

## Gate Verdict

PASS. Precision 1.00 is above the 0.99 gate. Corpus holds 0 `firm` plus on
sink-free shapes; browser-confirmed recall remains unmeasured.

## Dataset

- Dataset hash: `8a12a2f9c78dace7e65fdd2004068948009c0d03e7a11881a8bbd7bcddde2e9b`
  (sha256 over all 4 fixture files under `tests/fixtures/dom-sink-basic/`).
- Samples: TP=2, FP=0, TN=2, FN=0. Fixture-only static measurement; the
  browser path is covered by the deep-build tests above and has no separate
  precision/recall table. `TestMetricGate` fails the build if this hash drifts
  from the fixtures.

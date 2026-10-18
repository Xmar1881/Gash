<!--
SPDX-License-Identifier: AGPL-3.0-only
Copyright (C) 2026 Xmar1881 / GASH contributors
Module: github.com/Xmar1881/Gash

File: docs/metrics/xss-reflected-basic.md
What: Precision and recall report for the Tier 2 reflected-XSS plugin.
Why: Proves the spec section 4.6 JS example meets the gate with controls.
-->

# Metrics: xss-reflected-basic

## Overview

Tier 2 active plugin following the specification section 4.6 JavaScript
example. The probe sends `alert(canary)`: a random canary reflection alone is
not an XSS proof. Oracle `reflection` separates HTML, attributes, executable
attributes, URLs, JavaScript code, strings/comments, and inert JSON blocks.
Executable payload plus clean control produces `static-execution-evidence`;
text or encoded reflection stays `tentative`.

## Live Path (payload corpus, browser-verify pass)

The live script ships a probe-first classifier plus a bounded payload corpus
(≤60 requests): one bare-canary request per point classifies the reflection
context (HTML text, attribute with quote style, event-handler attribute,
script string with quote style, URL, escaped/unknown), then only the matching
alert-based payload family is sent (tag breakouts, quote breakouts,
`javascript:` URLs, script-string breakouts), so a wrong client-side guess
costs one probe and never a false claim. Each attempt uses a fresh canary and
`point.withValue(payload)`, so per-candidate reflection evidence stays exact.
Browser `confirmed` is no longer reserved unconditionally: with
`--browser-verify` (requires `--active` plus the `-tags deep` build and a
Chrome binary) the engine re-fetches each `static-execution-evidence`
GET/query finding as payload URL plus a neutral-control URL through
`headless.VerifyXSS`; only a real trigger (dialog or DOM canary) with a clean
control upgrades the finding to `confirmed`
(`Evidence["execution"]="browser-confirmed"`). Non-eligible findings, dirty
controls, and no-trigger runs stay unchanged and are noted honestly in the
finding's note. The fixture measurements below are unchanged: no fixture is
browser-executed here.

## Evidence Standard

Rule GASH-001. Control payloads that render executable reject the candidate.
WAF block pages are untrusted and always reject. Missing reflection rejects.
Entity-encoded and JavaScript-escaped reflections stay `tentative` or reject.

## Fixtures

- Positive: 5 of 5 accepted at `static-execution-evidence` (script block,
  event handler, unquoted attribute breakout, `javascript:` URL attribute,
  script-string breakout).
- Negative: 10 of 10 clean (text stays `tentative`, encoded at most
  `tentative`, WAF rejects, absent reflection rejects, comment reflection
  rejects, style context at most `tentative`, JavaScript strings and JSON
  reject, entity-encoded tag stays `tentative`, JS unicode escape rejects).
- Command: `go run ./cmd/gash plugins test plugins/xss/xss-reflected-basic.js`

## Corpus Result

Oracle `reflection` with a never-present canary against clean, SPA, WAF,
encoded, and dynamic bodies. `firm` plus findings: 0. Static execution
evidence remains below `firm` for CI gating and above `tentative` for reporting.

## Lab Result

Procedure: use the DVWA reflected-XSS page at low security from
`docker-compose.lab.yml`, scan the query input, expect a high severity
`static-execution-evidence` finding unless a browser-backed verifier is used.
Status: pending manual run. Expected Recall 1.00 on the
basic contexts covered here; exotic contexts stay out of scope.

## Precision

True positives 5, false positives 0. Precision 1.00.

## Recall

True positives 5, false negatives 0. Recall 1.00.

## Gate Verdict

PASS. Precision 1.00 is above the 0.99 gate. Corpus holds 0 `firm` plus.

## Note

The event-handler fixture uses a `div` tag because the oracle classifies
`src` or `href` neighbours as URL context first; this documents oracle
behaviour, not a plugin weakness.

## Dataset

- Dataset hash: `e8c262ba6162ac29bfabcd5bb49c411fa4e11922083bf531929c0e0924098a2d`
  (sha256 over all 15 fixture files under `tests/fixtures/xss-reflected-basic/`).
- Samples: TP=5, FP=0, TN=10, FN=0. Fixture-only measurement; lab pending above.
- Scope: script/attr-executable/text/encoded/comment/style/URL contexts,
  JavaScript strings/comments, JSON script blocks, unquoted-attribute and
  script-string breakouts, `javascript:` URL attributes, entity-encoded tags,
  and JS unicode escapes. Multi-layer encoding, stored XSS, and
  browser-executed DOM XSS are NOT covered.
  `TestMetricGate` fails the build if this hash drifts from the fixtures.

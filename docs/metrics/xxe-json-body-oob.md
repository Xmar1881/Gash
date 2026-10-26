<!--
SPDX-License-Identifier: AGPL-3.0-only
Copyright (C) 2026 Xmar1881 / GASH contributors
Module: github.com/Xmar1881/Gash

File: docs/metrics/xxe-json-body-oob.md
What: Precision and recall report for the Tier 2 JSON-embedded blind XXE plugin.
Why: Proves entity-resolution callbacks meet the 99 percent precision gate and
  skip honestly without an OOB server.
-->

# Metrics: xxe-json-body-oob

## Overview

Tier 2 active JS plugin. Oracle `oob` (`oob: required`). JSON APIs routinely
take an XML document inside one field (import/export/reporting); the external
parameter entity is resolved by the XML parser, so a callback proves entity
resolution without reading any real file.

Three payload variants per field (callback URL, DNS over http, DNS over https),
each with its own single-use token, verified in one shared bounded window
(`oobAny`, 10 s / 2 polls).

## Evidence Standard

OOB rule (GASH-011/012 family extended to JSON bodies). `confirmed` requires a
matched callback token; no file content is ever requested or asserted, and no
tentative noise is produced.

## Fixtures

- Positive: 1 of 1 accepted (`confirmed`; callback observed).
- Negative: 1 of 1 rejected (no callback).
- Command: `go run ./cmd/gash plugins test plugins/xxe/xxe-json-body-oob.js`

## JS E2E

`TestXXEJSONBodyOOBE2E` (`tests/plugins/tier2_batch_test.go`) executes the real
script through `loader.ExecuteJS`: OOB enabled plus a matching callback yields
one `confirmed` candidate and the request is asserted to carry a single-quoted
SYSTEM literal inside an `application/json` body; OOB disabled sends nothing.

## Corpus Result

Oracle `oob` is callback-gated, so the shared corpus gate rejects the negative
OOB fixture and no `firm`-plus finding can be produced from static bodies.

## Lab Result

Procedure: serve a JSON import endpoint that parses XML in the localhost lab,
point `--oob-server` at the self-hosted callback server, scan with `--active`,
expect one high severity finding at `confirmed`.
Status: pending manual run.

## Precision

True positives 1, false positives 0. Precision 1.00.

## Recall

True positives 1, false negatives 0. Recall 1.00.

## Gate Verdict

PASS. Precision 1.00 is above the 0.99 gate. Corpus holds 0 findings.

## Dataset

- Dataset hash: `cf6af6cd1b2dec97e03188a4cd7fdcecdb1f362480817c9797bf607aa89582eb`
  (sha256 over both fixture files under `tests/fixtures/xxe-json-body-oob/`).
- Samples: TP=1, FP=0, TN=1, FN=0. `TestMetricGate` fails on hash drift.

## Limitations

- Only the discovered field is sent; sibling fields are not replayed.
- Parameter entities only: a general-entity-only parser variant is out of scope.
- Egress-filtered targets produce no callback (false negative by design).

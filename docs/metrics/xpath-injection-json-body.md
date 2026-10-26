<!--
SPDX-License-Identifier: AGPL-3.0-only
Copyright (C) 2026 Xmar1881 / GASH contributors
Module: github.com/Xmar1881/Gash

File: docs/metrics/xpath-injection-json-body.md
What: Precision and recall report for the Tier 2 JSON-body XPath injection plugin.
Why: Proves the parser-signature match meets the 99 percent precision gate at firm.
-->

# Metrics: xpath-injection-json-body

## Overview

Tier 2 active JS plugin. Oracle `error` (signature match plus absent-in-control
proof, mode `xpath` declared once in `oracle_params`, ceiling `firm`). The
query-point `xpath-injection-error` plugin declares one static query string; a
JSON API needs the syntax probe built into the object around the discovered
field and sent as `application/json`.

The probe is a harmless predicate-closing attempt (`x'] | //* | a['` and
`1' or '1'='1`); it reads no files and runs no denial-of-service loop.

## Evidence Standard

Error-signature rule (GASH-034). The XPath parser signature must appear in the
probe response and be absent in the neutral-value control; the ceiling stays
`firm` because a parser error string alone is not injection proof.

## Fixtures

- Positive: 1 of 1 accepted (`firm`; parser error raised for the injected
  field).
- Negative: 1 of 1 rejected (no XPath parser signature in the response).
- Command:
  `go run ./cmd/gash plugins test plugins/xpath/xpath-injection-json-body.js`

## JS E2E

`TestXPathInjectionJSONBodyE2E` (`tests/plugins/tier2_nosql_jwt_xpath_test.go`)
executes the real script through `loader.ExecuteJS`: a backend that raises an
XPath parser error only for the payload yields one `firm` candidate carrying a
raw `application/json` body; a backend that always answers cleanly yields none.

## Corpus Result

The static corpus holds no XPath parser signature, so it produces no finding
for this plugin.

## Lab Result

Procedure: serve a JSON search endpoint backed by an XML store with a naive
XPath concatenation in the localhost lab, scan with `--active`, expect one
high severity finding at `firm`.
Status: pending manual run.

## Precision

True positives 1, false positives 0. Precision 1.00.

## Recall

True positives 1, false negatives 0. Recall 1.00.

## Gate Verdict

PASS. Precision 1.00 is above the 0.99 gate. Corpus holds 0 findings.

## Dataset

- Dataset hash: `136fcc736cfc99aca17e3f35d40195b99dd11af413e2390ab278bce01eae23dd`
  (sha256 over both fixture files under `tests/fixtures/xpath-injection-json-body/`).
- Samples: TP=1, FP=0, TN=1, FN=0. `TestMetricGate` fails on hash drift.

## Limitations

- The signature family is engine-specific; a backend that suppresses parser
  errors rejects honestly.
- Only two syntax probes are sent; blind (error-free) XPath injection is out of
  scope and stays named as a gap in the coverage matrix.

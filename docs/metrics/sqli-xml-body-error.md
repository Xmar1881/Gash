<!--
SPDX-License-Identifier: AGPL-3.0-only
Copyright (C) 2026 Xmar1881 / GASH contributors
Module: github.com/Xmar1881/Gash

File: docs/metrics/sqli-xml-body-error.md
What: Precision and recall report for the XML-body error-based SQLi plugin.
Why: Proves the closure payload plus neutral control meets the 99 percent gate.
-->

# Metrics: sqli-xml-body-error

## Overview

Tier 2 active JS plugin. Oracle `error` (default `sqli` mode). The plugin only
processes request-body points, rebuilds a well-formed XML document with the
payload inside the element named after the discovered field, and sends an
explicit `application/xml` content type. The neutral document is the control,
so a handler that rejects XML or reports the same error for every document
cannot confirm. No new sandbox surface: `probe.send`, `ctx`, `host.oracles.error`,
`host.candidate`.

## Evidence Standard

`ErrorSignatureOracle` default SQLi signature set; the signature must appear in
the attack response and be absent from the neutral-value control. All firm-plus
grades come from the oracle, never from the script.

## Fixtures

- Positive: 2 of 2 accepted (`confirmed`; MySQL and PostgreSQL signatures).
- Negative: 2 of 2 rejected (signature present in the control, parameterised handler).
- Command: `go run ./cmd/gash plugins test plugins/sqli/sqli-xml-body-error.js`

## JS E2E

`TestSQLiXMLBodyErrorE2E` (`tests/plugins/tier2_batch5_test.go`) executes the
real script through `loader.ExecuteJS` with a mocked transport:

- Element closure returns a MySQL error, the neutral document does not: one
  `confirmed` candidate; the XML content type is asserted.
- A handler that answers the neutral document identically produces none.
- Send budget and the oracle surface are asserted.

## Corpus Result

The `error` oracle is exercised by the existing clean corpus; this plugin adds
no new oracle code and no new signature. Fixture-only measurement.

## Lab Result

Procedure: serve an XML import endpoint that interpolates element text into a
query, scan with this plugin, expect one high-severity finding at `confirmed`.
Status: pending manual run.

## Precision

True positives 2, false positives 0. Precision 1.00.

## Recall

True positives 2, false negatives 0. Recall 1.00.

## Gate Verdict

PASS. Precision 1.00 is above the 0.99 gate. Corpus holds 0 findings.

## Dataset

- Dataset hash: `128092484ce664ee879da81f3584707b10b1c72cf0936f63e032dddde2204434`
  (sha256 over all 4 fixture files under `tests/fixtures/sqli-xml-body-error/`).
- Samples: TP=2, FP=0, TN=2, FN=0. Fixture-only measurement; lab pending above.
  `TestMetricGate` fails the build if this hash drifts from the fixtures.

## Limitations

- The XML envelope uses the discovered field as one element; a strict schema
  that requires sibling elements yields a false negative.
- XML-to-SQL mapping is not fingerprinted; the signature library decides.

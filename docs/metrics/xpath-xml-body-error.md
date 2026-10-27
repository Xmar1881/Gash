<!--
SPDX-License-Identifier: AGPL-3.0-only
Copyright (C) 2026 Xmar1881 / GASH contributors
Module: github.com/Xmar1881/Gash

File: docs/metrics/xpath-xml-body-error.md
What: Precision and recall report for the XML-body XPath injection plugin.
Why: Proves the XPath parser-error evidence and firm ceiling meet the gate.
-->

# Metrics: xpath-xml-body-error

## Overview

Tier 2 active JS plugin. Oracle `error` with `mode: xpath` declared in
`oracle_params`. XPath injection is XML-native, so the payload is placed inside
the element named after the discovered body field and sent as
`application/xml`. The error oracle caps this mode at `firm`: a parser message
proves the expression reached the evaluator, not that data was extracted. No
new sandbox surface.

## Evidence Standard

`ErrorSignatureOracle` XPath signature set (`XPathExpressionException`,
`DOMXPath`, `xmlXPathEval`, compile/parse errors). The signature must be absent
from the neutral-value control. The `firm` ceiling is owned by the oracle.

## Fixtures

- Positive: 2 of 2 accepted (`firm`; Java XPathExpressionException, DOMXPath).
- Negative: 2 of 2 rejected (signature in control, neutral documents).
- Command: `go run ./cmd/gash plugins test plugins/xpath/xpath-xml-body-error.js`

## JS E2E

`TestXPathXMLBodyErrorE2E` executes the script through `loader.ExecuteJS`:

- Closure payload provokes an XPath parser error, the neutral document does
  not: one `firm` candidate; `oracle_params.mode` is asserted.
- A universal parser error rejects.
- Send budget and the oracle surface are asserted.

## Corpus Result

The `xpath` mode is part of the existing error oracle and has no new
signatures. Fixture-only measurement.

## Lab Result

Procedure: serve an XML search endpoint that evaluates an XPath expression built
from element text, scan with this plugin, expect one medium-severity finding at
`firm`. Status: pending manual run.

## Precision

True positives 2, false positives 0. Precision 1.00.

## Recall

True positives 2, false negatives 0. Recall 1.00.

## Gate Verdict

PASS. Precision 1.00 is above the 0.99 gate. Corpus holds 0 findings.

## Dataset

- Dataset hash: `abb4a27acf813027fb753a8f3251c388c57b6e636da110c72e647bdd66bcc725`
  (sha256 over all 4 fixture files under `tests/fixtures/xpath-xml-body-error/`).
- Samples: TP=2, FP=0, TN=2, FN=0. Fixture-only measurement; lab pending above.
  `TestMetricGate` fails the build if this hash drifts from the fixtures.

## Limitations

- Only one element per document is shaped; strict XML schemas yield a false
  negative.
- The firm ceiling is deliberate: parser errors are single-channel evidence.

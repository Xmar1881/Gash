<!--
SPDX-License-Identifier: AGPL-3.0-only
Copyright (C) 2026 Xmar1881 / GASH contributors
Module: github.com/Xmar1881/Gash

File: docs/metrics/ssti-json-body-oob.md
What: Precision and recall report for the Tier 2 JSON-body blind SSTI plugin.
Why: Proves the template-callback discipline meets the 99 percent gate behind
  the oob oracle.
-->

# Metrics: ssti-json-body-oob

## Overview

Tier 2 active JS plugin. Oracle `oob` (required). Four engine-specific payload
builders (Jinja2/Flask, Mako, Twig, Velocity) are carried inside a raw
`application/json` body around the discovered field. Every variant gets its
own single-use token, so a callback names the exact field and variant.

## Evidence Standard

OOB rule (GASH-013 family): a matched correlation token is `confirmed`.
Without a configured server the plugin returns an empty set and sends nothing.

## Fixtures

- Positive: 1 of 1 accepted (`confirmed`).
- Negative: 2 of 2 rejected (field treated as a plain string; payload echoed
  verbatim instead of evaluated).
- Command:
  `go run ./cmd/gash plugins test plugins/ssti/ssti-json-body-oob.js`

## JS E2E

`TestSSTIJSONBodyOOBE2E` (`tests/plugins/tier2_expansion_test.go`) asserts one
`confirmed` candidate, that the request carries `application/json`, that the
body carries the callback host, and that no request leaves the client when the
OOB server is unconfigured.

## Corpus Result

Oracle `oob` is disabled for the shared corpus gate; clean bodies produce no
`firm`-plus finding.

## Lab Result

Procedure: lab endpoint that renders a JSON field through a template engine,
run with `--active --oob-server`, expect one `critical` finding at `confirmed`.
Status: pending manual run.

## Precision

True positives 1, false positives 0. Precision 1.00.

## Recall

True positives 1, false negatives 0. Recall 1.00.

## Gate Verdict

PASS. Precision 1.00 is above the 0.99 gate. Corpus holds 0 findings.

## Dataset

- Dataset hash: `271ef7b11f45d188767b2661f89259253c446dfed7772c392ca006b69fa3ac99`
- Samples: TP=1, FP=0, TN=2, FN=0. `TestMetricGate` fails on hash drift.

## Limitations

- Only four engine families are covered; Ruby ERB, Handlebars and Smarty
  builders are not shipped.
- Non-HTML rendering contexts (email bodies, generated documents) are not
  enumerated; the plugin only sees the JSON field it was given.

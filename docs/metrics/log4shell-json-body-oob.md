<!--
SPDX-License-Identifier: AGPL-3.0-only
Copyright (C) 2026 Xmar1881 / GASH contributors
Module: github.com/Xmar1881/Gash

File: docs/metrics/log4shell-json-body-oob.md
What: Precision and recall report for the Tier 2 JSON-body Log4Shell plugin.
Why: Proves the JNDI-callback discipline meets the 99 percent gate behind the
  oob oracle.
-->

# Metrics: log4shell-json-body-oob

## Overview

Tier 2 active JS plugin. Oracle `oob` (required). Five lookup forms (ldap, rmi,
dns plus two `${lower:}` nesting tricks) are carried inside a raw
`application/json` body around the discovered field, each with its own
single-use token.

## Evidence Standard

OOB rule (GASH-008 family): a matched correlation token is `confirmed`. Without
a configured server the plugin returns nothing and sends nothing.

## Fixtures

- Positive: 1 of 1 accepted (`confirmed`).
- Negative: 1 of 1 rejected (the field is logged literally).
- Command:
  `go run ./cmd/gash plugins test plugins/command-injection/log4shell-json-body-oob.js`

## JS E2E

`TestLog4ShellJSONBodyOOBE2E` (`tests/plugins/tier2_batch4_test.go`) asserts one
`confirmed` `oob` candidate, that the body carries the callback host with a JSON
content type, and that no request leaves the client without an OOB server.

## Corpus Result

Oracle `oob` is disabled for the shared corpus gate, so clean bodies produce no
`firm`-plus finding.

## Lab Result

Procedure: lab service logging a JSON field through a vulnerable logging
library, run with `--active --oob-server`, expect one `critical` finding at
`confirmed`. Status: pending manual run.

## Precision

True positives 1, false positives 0. Precision 1.00.

## Recall

True positives 1, false negatives 0. Recall 1.00.

## Gate Verdict

PASS. Precision 1.00 is above the 0.99 gate. Corpus holds 0 findings.

## Dataset

- Dataset hash: `762b52d9a4a32e1e9edece5e2a28411eef93e10f209dd5b5848deff1dccdec1f`
- Samples: TP=1, FP=0, TN=1, FN=0. `TestMetricGate` fails on hash drift.

## Limitations

- Query-string and header vectors stay with the Tier 1 `log4shell-jndi` plugin;
  this file covers the API body channel only.
- A logger that redacts `${...}` patterns produces a false negative, never a
  false positive.

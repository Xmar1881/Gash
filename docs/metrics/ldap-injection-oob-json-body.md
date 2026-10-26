<!--
SPDX-License-Identifier: AGPL-3.0-only
Copyright (C) 2026 Xmar1881 / GASH contributors
Module: github.com/Xmar1881/Gash

File: docs/metrics/ldap-injection-oob-json-body.md
What: Precision and recall report for the Tier 2 JSON-body blind LDAP plugin.
Why: Proves the directory-callback discipline meets the 99 percent gate behind
  the oob oracle.
-->

# Metrics: ldap-injection-oob-json-body

## Overview

Tier 2 active JS plugin. Oracle `oob` (required). Three filter closures are
sent inside a raw `application/json` body around the discovered field. Each
closure terminates the injected expression and makes the directory resolve the
operator hostname; no attribute is read back.

## Evidence Standard

OOB rule (GASH-012 family): a matched correlation token is `confirmed`.
Without a configured server the plugin returns an empty set and sends nothing.

## Fixtures

- Positive: 1 of 1 accepted (`confirmed`).
- Negative: 2 of 2 rejected (escaped field never reaches the directory as a
  filter; closure rejected before any lookup).
- Command:
  `go run ./cmd/gash plugins test plugins/ldap/ldap-injection-oob-json-body.js`

## JS E2E

`TestLDAPOOBJSONBodyE2E` (`tests/plugins/tier2_expansion_test.go`) asserts one
`confirmed` `oob` candidate, that the JSON body carries the callback host, and
that nothing is sent when no OOB server is configured.

## Corpus Result

Oracle `oob` is disabled for the shared corpus gate; clean bodies produce no
`firm`-plus finding.

## Lab Result

Procedure: lab endpoint that splices a JSON field into an LDAP filter, run with
`--active --oob-server`, expect one `high` finding at `confirmed`. Status:
pending manual run.

## Precision

True positives 1, false positives 0. Precision 1.00.

## Recall

True positives 1, false negatives 0. Recall 1.00.

## Gate Verdict

PASS. Precision 1.00 is above the 0.99 gate. Corpus holds 0 findings.

## Dataset

- Dataset hash: `e80907a9ecbea4fa20e8a04c3fa09997696bc298acd142a75424438dec2db035`
- Samples: TP=1, FP=0, TN=2, FN=0. `TestMetricGate` fails on hash drift.

## Limitations

- Referral-based callbacks are environment-specific: a directory that refuses
  outbound resolution produces a false negative, never noise.
- Nested JSON paths are not expanded; only the discovered top-level field is
  rebuilt.

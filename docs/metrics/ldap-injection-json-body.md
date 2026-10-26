<!--
SPDX-License-Identifier: AGPL-3.0-only
Copyright (C) 2026 Xmar1881 / GASH contributors
Module: github.com/Xmar1881/Gash

File: docs/metrics/ldap-injection-json-body.md
What: Precision and recall report for the Tier 2 JSON-body LDAP injection plugin.
Why: Proves the always-true filter divergence meets the 99 percent precision
  gate behind the differential oracle.
-->

# Metrics: ldap-injection-json-body

## Overview

Tier 2 active JS plugin. Oracle `differential`. The query-point LDAP plugin
cannot reach a JSON API: the payload has to be built into the object around the
discovered field and sent as `application/json`.

Three always-true filter requests (`*)(uid=*))(|(uid=*`), three requests with a
value that cannot exist, and one neutral control are compared; an echo guard
drops points that reflect the payload verbatim.

## Evidence Standard

Differential rule (GASH-005 family extended to directory queries): 3/3 masked
stability plus true/false divergence, control distinct from the true branch.
Unstable content rejects instead of confirming.

## Fixtures

- Positive: 2 of 2 accepted (`confirmed`; auth bypass and widened search).
- Negative: 1 of 1 rejected (escaped field; both branches match).
- Command:
  `go run ./cmd/gash plugins test plugins/ldap/ldap-injection-json-body.js`

## JS E2E

`TestLDAPInjectionJSONBodyE2E` (`tests/plugins/tier2_batch_test.go`) executes
the real script through `loader.ExecuteJS`: a directory that returns an admin
page for the closure and an invalid-user page otherwise yields one `confirmed`
candidate with the JSON content type asserted; an escaping backend yields none.

## Corpus Result

Oracle `differential` evaluated against clean, SPA, WAF, encoded, and dynamic
bodies: no corpus body shows stable cross-value divergence.

## Lab Result

Procedure: serve a JSON login endpoint backed by a naive directory filter in
the localhost lab, scan with `--active`, expect one high severity finding at
`confirmed`. Status: pending manual run.

## Precision

True positives 2, false positives 0. Precision 1.00.

## Recall

True positives 2, false negatives 0. Recall 1.00.

## Gate Verdict

PASS. Precision 1.00 is above the 0.99 gate. Corpus holds 0 findings.

## Dataset

- Dataset hash: `b682350b49f817467bc35e02bffb1a4c18d741fb805b14613b6d2bf5c1612802`
  (sha256 over all 3 fixture files under
  `tests/fixtures/ldap-injection-json-body/`).
- Samples: TP=2, FP=0, TN=1, FN=0. `TestMetricGate` fails on hash drift.

## Limitations

- Only the discovered field is sent; sibling fields are not replayed.
- Blind LDAP (timing/OOB) in JSON bodies is not covered here.
- Attribute-name injection (as opposed to filter injection) is out of scope.

<!--
SPDX-License-Identifier: AGPL-3.0-only
Copyright (C) 2026 Xmar1881 / GASH contributors
Module: github.com/Xmar1881/Gash

File: docs/metrics/ldap-injection-oob.md
What: Precision and recall report for the blind LDAP injection OOB plugin.
Why: Proves Tier 1 OOB oracle meets the precision gate with
  out-of-band callback confirmation. Requires self-hosted --oob-server.
-->

# Metrics: ldap-injection-oob

## Overview

Tier 1 active plugin. Oracle `oob`. Blind LDAP injection with out-of-band
DNS/HTTP callback confirmation. Requires self-hosted `--oob-server`; without
it the plugin skips honestly (`oob-not-configured`). Payloads attempt to
trigger LDAP referrals or external lookups. Confidence ceiling `confirmed`
(callback match only).

## Evidence Standard

Rule GASH-XXX (CWE-90). Requires a matching OOB callback with the correct
single-use correlation token and namespace. Without `--oob-server` the plugin
does not run (scheduler skip). A callback proves the LDAP injection executed
and reached the operator's server. No timing fallback; no callback = no finding.

## Fixtures

- Positive: 1 of 1 accepted (`confirmed`).
- Negative: 1 of 1 rejected (no callback).
- Command: `go run ./cmd/gash plugins test plugins/ldap-blind/ldap-injection-oob.yaml`

## Corpus Result

Oracle `oob` evaluated against clean, SPA, WAF, and dynamic bodies.
`confirmed` plus findings: 0. WAF body correctly rejects as untrusted.

## Lab Result

Procedure: serve a blind LDAP injection endpoint in the localhost lab,
scan with OOB payloads, expect one high severity finding at `confirmed`.
Status: pending manual run. Expected Precision 100 percent on this vulnerability class.

## Precision

True positives 1, false positives 0. Precision 1.00.

## Recall

True positives 1, false negatives 0. Recall 1.00.

## Gate Verdict

PASS. Precision 1.00 is above the 0.99 gate. Corpus holds 0 `firm` plus.

## Dataset

- Dataset hash: `4b59749ae01c838432c54c08ff73883411e12f258d4a991ea691640a4f14c020`
  (sha256 over all 2 fixture files under `tests/fixtures/ldap-injection-oob/`).
- Samples: TP=1, FP=0, TN=1, FN=0. Fixture-only measurement; lab pending above.
  `TestMetricGate` fails the build if this hash drifts from the fixtures.

## Limitations

- Requires self-hosted OOB server (`--oob-server`); no public interactsh default.
- LDAP OOB exfiltration is environment-specific (referrals, external lookups).
- No timing fallback; boolean differential LDAP covered by `ldap-injection-differential`.
- Blind timing-based LDAP covered by `ldap-injection-blind` (firm ceiling).
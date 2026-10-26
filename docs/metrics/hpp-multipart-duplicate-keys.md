<!--
SPDX-License-Identifier: AGPL-3.0-only
Copyright (C) 2026 Xmar1881 / GASH contributors
Module: github.com/Xmar1881/Gash

File: docs/metrics/hpp-multipart-duplicate-keys.md
What: Precision and recall report for the Tier 2 multipart duplicate-field HPP plugin.
Why: Proves self-built multipart emission with a duplicated field name meets
  the 99 percent precision gate behind the differential oracle.
-->

# Metrics: hpp-multipart-duplicate-keys

## Overview

Tier 2 active JS plugin. Oracle `differential`. The engine form builder writes
exactly one part per field name, so a duplicated multipart name cannot be
expressed declaratively. This plugin builds the multipart body, its boundary
and the matching `Content-Type` itself, and sends it as a raw body.

Three single-part requests, three duplicate-part requests (`name=1` plus
`name=2`) and one neutral control are compared by the differential oracle
(3/3 masked stability plus divergence).

## Evidence Standard

Differential rule (GASH-005 family extended to multipart parsing). Plugin-level
guard: BOTH branches must be 2xx before the oracle is consulted, so a server
that rejects the malformed duplicate is never reported as pollution. Unstable
content rejects rather than confirming.

## Fixtures

- Positive: 2 of 2 accepted (`confirmed`; list pollution and role escalation).
- Negative: 2 of 2 rejected (first-part-wins parser; unstable duplicate
  branch).
- Command:
  `go run ./cmd/gash plugins test plugins/hpp/hpp-multipart-duplicate-keys.js`

## JS E2E

`TestHPPMultipartDuplicateKeysE2E`
(`tests/plugins/tier2_json_multipart_test.go`) executes the real script through
`loader.ExecuteJS`:

- Backend distinguishing the duplicated part returns the polluted body: one
  `confirmed` candidate; the request is asserted to carry a
  `multipart/form-data` content type with a boundary and both parts.
- Backend answering 400 to the duplicate part: zero candidates.
- Send budget stays under the declared `max_requests`.

No new `host.oracles.*` binding is introduced (source grep asserts only
`host.oracles.differential`).

## Corpus Result

Oracle `differential` evaluated against clean, SPA, WAF, encoded, and dynamic
bodies. No corpus body shows stable cross-value divergence. `firm` is not
emitted (differential is confirmed-only).

## Lab Result

Procedure: serve a multipart-accepting endpoint whose parser is last-part-wins
in the localhost lab, scan with `--active`, expect one medium severity finding
at `confirmed`.
Status: pending manual run. Expected Precision 100 percent on this page class.

## Precision

True positives 2, false positives 0. Precision 1.00.

## Recall

True positives 2, false negatives 0. Recall 1.00.

## Gate Verdict

PASS. Precision 1.00 is above the 0.99 gate. Corpus holds 0 findings.

## Dataset

- Dataset hash: `cf341be539a7dd628448dc8f7620c5418fd1826ca6ec9fb65ba635e7fbcabee7`
  (sha256 over all 4 fixture files under
  `tests/fixtures/hpp-multipart-duplicate-keys/`).
- Samples: TP=2, FP=0, TN=2, FN=0. Fixture-only measurement; lab pending above.
  `TestMetricGate` fails the build if this hash drifts from the fixtures.

## Limitations

- File parts are never emitted; both parts are plain text fields.
- The boundary is fixed, so a target that normalises unusual boundaries could
  reject the request (false negative, never a false positive).
- Part ordering beyond first/last duplicates is not varied in v1.

<!--
SPDX-License-Identifier: AGPL-3.0-only
Copyright (C) 2026 Xmar1881 / GASH contributors
Module: github.com/Xmar1881/Gash

File: docs/metrics/idor-differential.md
What: Precision and recall report for the Tier 1 IDOR plugin.
Why: Proves differential oracle IDOR detection meets the 99 percent precision gate.
-->

# Metrics: idor-differential

## Overview

Tier 1 active plugin. Oracle `differential`. Sends paired requests with different object identifiers (e.g., `/api/users/1` vs `/api/users/2`) and compares responses. Requires 3/3 masked stability + divergence for `confirmed`. Requires authentication (`requires_auth: true`).

## Evidence Standard

Rule GASH-005 extended (CWE-639, CWE-284). IDOR confirmed when: (1) authenticated user accesses another user's object, (2) response differs meaningfully from own object, (3) 3/3 repeated probes show stable divergence. Confidence: `confirmed` only (N=3 stability). WAF/block pages classify `Untrusted` and reject. Tainted responses reject.

## Fixtures

- Positive: 2 of 2 accepted (user data divergence, order data divergence; both 3/3 stable).
- Negative: 2 of 2 rejected (401 unauthorized, same response for different IDs).
- Command: `go run ./cmd/gash plugins test plugins/idor/idor-differential.yaml`

## Corpus Result

Oracle `differential` evaluated against clean, SPA, WAF, encoded, and dynamic bodies. No corpus body shows stable cross-ID divergence. `firm` not emitted (differential is confirmed-only).

## Lab Result

Procedure: serve a multi-user API with IDOR from `docker-compose.lab.yml`, scan with valid auth, expect one high severity IDOR finding and no other claims.
Status: pending manual run. Expected Precision 100 percent on this page class.

## Precision

True positives 2, false positives 0. Precision 1.00.

## Recall

True positives 2, false negatives 0. Recall 1.00.

## Gate Verdict

PASS. Precision 1.00 is above the 0.99 gate. Corpus holds 0 findings.

## Dataset

- Dataset hash: `26e742461f24fb1776c57a6379be814bd89f80b860967a6216cd293a89614556` (sha256 over all 4 fixture files under `tests/fixtures/idor-differential/`).
- Samples: TP=2, FP=0, TN=2, FN=0. Fixture-only measurement; lab pending above.
  `TestMetricGate` fails the build if this hash drifts from the fixtures.

## Limitations

- Requires valid authentication (`requires_auth: true`); unauthenticated scans skip.
- v1 tests only numeric ID parameters; UUID, slug, and composite keys are future work.
- Does not test horizontal vs vertical privilege escalation distinction.
- Rate limiting may cause false negatives; budget-aware probing is future work.

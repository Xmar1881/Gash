<!--
SPDX-License-Identifier: AGPL-3.0-only
Copyright (C) 2026 Xmar1881 / GASH contributors
Module: github.com/Xmar1881/Gash

File: docs/metrics/verb-tampering-bypass.md
What: Precision and recall report for the HTTP verb tampering auth bypass screen.
Why: Proves VerbTamperOracle (GASH-036) meets the 99 percent precision gate.
-->

# Metrics: verb-tampering-bypass

## Overview

Tier 1 active plugin. Oracle `verb-tamper`. When the baseline GET returns 401
or 403 on a declared path, HEAD, OPTIONS, X-HTTP-Method-Override,
X-Original-URL, and X-Rewrite-URL variants are attempted; a 2xx variant with a
meaningful body that differs from the baseline gives `firm`.

## Evidence Standard

Rule GASH-036 (CWE-650). Only idempotent read variants are sent (no PUT/DELETE/
PATCH). Empty or token bodies (HEAD, bare OPTIONS) and masked-equal bodies are
rejected, which kills protocol-shaped false positives. Firm is the ceiling.

## Fixtures

- Positive: 2 of 2 accepted (`firm`; 401 baseline with HEAD content, 403
  baseline with override-header JSON).
- Negative: 2 of 2 rejected (baseline not protected; status changed but body
  identical to baseline).
- Command: `go run ./cmd/gash plugins test plugins/verb-tampering/verb-tampering-bypass.yaml`

## Corpus Result

Oracle `verb-tamper` with protected-baseline bodies and empty/identical
variants: no accept, zero `firm` plus.

## Lab Result

Procedure: in the localhost lab, protect one path with Basic auth but leave
OPTIONS/HEAD unauthenticated; run with `--active` and a standard-or-deeper
profile; expect one high severity finding at `firm`. Status: pending manual
run. Expected Precision 100 percent on this endpoint class.

## Precision

True positives 2, false positives 0. Precision 1.00.

## Recall

True positives 2, false negatives 0. Recall 1.00.

## Gate Verdict

PASS. Precision 1.00 is above the 0.99 gate. Corpus holds 0 unexpected `firm` plus.

## Dataset

- Dataset hash: `a5c5004e1fa1c8dcb9164eaa5253f4be89afac875c0ce2f7ab1bbf19036d9b93`
  (sha256 over all 4 fixture files under `tests/fixtures/verb-tampering-bypass/`).
- Samples: TP=2, FP=0, TN=2, FN=0. Fixture-only measurement; lab pending above.
  `TestMetricGate` fails the build if this hash drifts from the fixtures.

## Limitations

- Path list is fixed (`/admin`, `/api/admin`); other protected routes need a
  plugin copy with its own `paths` block.
- Login redirects (302 to a login page) are not bypass evidence by design, so
  session-auth apps that never answer bare 401/403 stay unflagged.

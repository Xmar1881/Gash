<!--
SPDX-License-Identifier: AGPL-3.0-only
Copyright (C) 2026 Xmar1881 / GASH contributors
Module: github.com/Xmar1881/Gash

File: docs/metrics/mass-assignment-basic.md
What: Precision and recall report for the mass assignment differential plugin.
Why: Proves DifferentialOracle extra-field detection with a declared firm
  ceiling meets the 99 percent precision gate (3/3 masked stability +
  divergence, unstable input rejects).
-->

# Metrics: mass-assignment-basic

## Overview

Tier 1 active plugin (`--active`, lab-scoped). Oracle `differential` with
`confidence_ceiling: firm` (GASH-031, CWE-915). Extra harmless fields
(`role`, `is_admin`, `isAdmin`, `admin`, `debug`) are appended with
non-escalating values (true branch `0`, false branch inert marker, neutral
control); stable divergence proves the field was bound instead of filtered.
No privilege-escalation value (`admin`/`true`/`1`) is ever sent: only the
filtering difference (binding/reflection) is evidence.

## Evidence Standard

GASH-031 extends the GASH-005 differential family with a declared ceiling.
Masking profile is the engine default. True branch is the extra-field probe
repeated 3x, false branch is the inert-marker value repeated 3x, plus a
neutral control. After masking: all true identical, all false identical,
true != false. The oracle would emit `confirmed`; `confidence_ceiling: firm`
downgrades it because binding alone does not prove exploited privilege.
Unstable or identical branches reject (never `tentative`). WAF/block pages
classify `Untrusted` and always reject.

## Fixtures

- Positive: 2 of 2 accepted (2 `firm` after ceiling; `role` binding, `is_admin` binding with non-escalating `0`).
- Negative: 2 of 2 rejected (field ignored with no divergence, unstable dynamic responses).
- Command: `go run ./cmd/gash plugins test plugins/mass-assignment/mass-assignment-basic.yaml`

## Corpus Result

Oracle `differential` (with ceiling) evaluated against clean, SPA, WAF,
encoded, and dynamic bodies. No corpus body shows stable cross-value
divergence. Covered by `TestDifferentialCeiling` in
`internal/oracle/new_detectors_test.go` plus the Tier 1 ceiling
end-to-end in `internal/plugin/loader/tier1_burst_test.go`.

## Lab Result

Procedure: serve a lab profile/API endpoint that binds query fields to the
user object, scan with `--active --scope <lab>` on the aggressive profile,
expect one high severity finding at `firm` for the unfiltered field and no
claim on the allowlisted control endpoint. Status: pending manual run.
Expected Precision 100 percent on this page class.

## Precision

True positives 2, false positives 0. Precision 1.00.

## Recall

True positives 2, false negatives 0. Recall 1.00.

## Gate Verdict

PASS. Precision 1.00 is above the 0.99 gate. Corpus holds 0 findings.

## Dataset

- Dataset hash: `87ac5353764993ac19bc52fe174d6662a694d85acd8165a927a05d11b122b596`
  (sha256 over all 4 fixture files under `tests/fixtures/mass-assignment-basic/`).
- Samples: TP=2, FP=0, TN=2, FN=0. Fixture-only measurement; lab pending above.
  `TestMetricGate` fails the build if this hash drifts from the fixtures.

## Limitations

- Tier 1 models binding as query-param divergence; JSON-body mass assignment needs Tier 2 with body injection points (future work).
- Reflection versus true object-binding ambiguity: a reflected-but-unbound field also diverges; triage must confirm persistence/side effects.
- Ceiling downgrades `confirmed` to `firm` by design; the raw divergence is preserved in the `ceiling` artifact for audit.

<!--
SPDX-License-Identifier: AGPL-3.0-only
Copyright (C) 2026 Xmar1881 / GASH contributors
Module: github.com/Xmar1881/Gash

File: docs/metrics/sqli-multipart-error.md
What: Precision and recall report for the multipart-form SQLi plugin.
Why: Proves full-form replay plus a neutral control meets the 99 percent gate.
-->

# Metrics: sqli-multipart-error

## Overview

Tier 2 active JS plugin. Oracle `error` (default `sqli` mode). The plugin only
processes `multipart/form-data` body points, rebuilds the whole form with a
self-chosen boundary, replays every sibling field (CSRF tokens included), and
replaces only the discovered field with the closure payload. The neutral value
in the same field is the control. Tier 1 injects through the urlencoded form
builder, so multipart forms are otherwise untested.

## Evidence Standard

`ErrorSignatureOracle` SQLi signatures; present in the attack response, absent
from the neutral-value control. All confidence comes from the oracle.

## Fixtures

- Positive: 2 of 2 accepted (`confirmed`; MySQL and MSSQL signatures).
- Negative: 2 of 2 rejected (signature in control, parameterised handler).
- Command: `go run ./cmd/gash plugins test plugins/sqli/sqli-multipart-error.js`

## JS E2E

`TestSQLiMultipartErrorE2E` executes the script through `loader.ExecuteJS`:

- A multipart closure triggers a signature; the multipart content type and the
  replayed sibling field are asserted: one `confirmed` candidate.
- A urlencoded point is skipped without sending anything.
- Send budget and the oracle surface are asserted.

## Corpus Result

The `error` oracle is unchanged. Fixture-only measurement.

## Lab Result

Procedure: serve a multipart item-creation form that interpolates the title into
a query, scan with this plugin, expect one high-severity finding at `confirmed`.
Status: pending manual run.

## Precision

True positives 2, false positives 0. Precision 1.00.

## Recall

True positives 2, false negatives 0. Recall 1.00.

## Gate Verdict

PASS. Precision 1.00 is above the 0.99 gate. Corpus holds 0 findings.

## Dataset

- Dataset hash: `a6721c7b03491abebc558ebdc1c71380d222a117ad7fada638be178866f8f2d9`
  (sha256 over all 4 fixture files under `tests/fixtures/sqli-multipart-error/`).
- Samples: TP=2, FP=0, TN=2, FN=0. Fixture-only measurement; lab pending above.
  `TestMetricGate` fails the build if this hash drifts from the fixtures.

## Limitations

- File inputs are never replayed (no fabricated upload); forms whose handler
  requires a file part yield a false negative.
- Multipart forms that do not declare their enctype are skipped.

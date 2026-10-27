<!--
SPDX-License-Identifier: AGPL-3.0-only
Copyright (C) 2026 Xmar1881 / GASH contributors
Module: github.com/Xmar1881/Gash

File: docs/metrics/xxe-svg-upload-oob.md
What: Precision and recall report for the SVG-upload blind XXE plugin.
Why: Proves server-side parse callbacks, not upload acceptance, meet the gate.
-->

# Metrics: xxe-svg-upload-oob

## Overview

Tier 2 active JS plugin. Oracle `oob` (`oob: required`). The plugin builds a
multipart upload whose file part is an SVG carrying an external parameter
entity, replays sibling form fields, and confirms only when the operator's
self-hosted server observes a callback. An accepted upload is never evidence:
only the parser resolving the entity counts.

## Evidence Standard

`OOBOracle` with a unique correlation token per upload and one shared bounded
wait window. Upload status is not graded.

## Fixtures

- Positive: 1 of 1 accepted (`confirmed`; simulated callback).
- Negative: 1 of 1 rejected (accepted upload, no callback).
- Command: `go run ./cmd/gash plugins test plugins/xxe/xxe-svg-upload-oob.js`

## JS E2E

`TestXXESVGUploadOOBE2E` executes the script through `loader.ExecuteJS`:

- A callback yields one `confirmed` candidate; the multipart file part,
  `image/svg+xml` type, SYSTEM literal and sibling replay are asserted.
- An accepted upload without a callback produces no candidate.
- Without `OOBEnabled` the plugin performs zero sends.
- Send budget and the oracle surface are asserted.

## Corpus Result

The OOB oracle is unchanged. Fixture-only measurement.

## Lab Result

Procedure: serve an avatar upload that generates thumbnails server-side with an
XML parser, run with `--oob-server`, expect one high-severity finding at
`confirmed` after the callback. Status: pending manual run.

## Precision

True positives 1, false positives 0. Precision 1.00.

## Recall

True positives 1, false negatives 0. Recall 1.00.

## Gate Verdict

PASS. Precision 1.00 is above the 0.99 gate. Corpus holds 0 findings.

## Dataset

- Dataset hash: `befe066f6252f44802d085159c11d44bbb55d426c2f205933f10da6dcf5ceb69`
  (sha256 over all 2 fixture files under `tests/fixtures/xxe-svg-upload-oob/`).
- Samples: TP=1, FP=0, TN=1, FN=0. Fixture-only measurement; lab pending above.
  `TestMetricGate` fails the build if this hash drifts from the fixtures.

## Limitations

- Uploads that are stored but never parsed server-side yield a false negative.
- Image processors with entity resolution disabled or sandboxed yield no
  callback.

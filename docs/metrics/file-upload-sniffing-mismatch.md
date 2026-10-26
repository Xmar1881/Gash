<!--
SPDX-License-Identifier: AGPL-3.0-only
Copyright (C) 2026 Xmar1881 / GASH contributors
Module: github.com/Xmar1881/Gash

File: docs/metrics/file-upload-sniffing-mismatch.md
What: Precision and recall report for the Tier 2 content-sniffing upload plugin.
Why: Proves the sniffing serve-back workflow meets the 99 percent gate behind
  the upload-served oracle.
-->

# Metrics: file-upload-sniffing-mismatch

## Overview

Tier 2 active JS plugin. Oracle `upload-served`. The part is uploaded with an
inert name (`.txt`) and an inert declaration (`application/octet-stream`) while
the bytes are active content; the artifact is fetched back and a sibling name
that never received an upload is the control. The served content type decides
`confirmed` (active) or `firm` (inert).

## Evidence Standard

Upload-served rule (GASH-038): accepted upload, canary present in the fetched
artifact, clean control. Active served type is `confirmed`, inert or unknown is
`firm`; a rejected upload or a dirty control rejects.

## Fixtures

- Positive: 2 of 2 accepted (`confirmed` when the server sniffs, `firm` when it
  honours the declaration).
- Negative: 2 of 2 rejected (dirty control; upload rejected).
- Command:
  `go run ./cmd/gash plugins test plugins/file-upload/file-upload-sniffing-mismatch.js`

## JS E2E

`TestFileUploadSniffingMismatchE2E` (`tests/plugins/tier2_batch4_test.go`)
asserts one `confirmed` `upload-served` candidate for a sniffing server, that
the part really carried the inert name and declaration, that an honouring server
stays `firm`, and that a dirty control rejects.

## Corpus Result

Oracle `upload-served` rejects clean corpus bodies because no upload exchange
exists, so no `firm`-plus finding is produced.

## Lab Result

Procedure: lab upload endpoint with a sniffing static file server, run with
`--active`, expect one `medium` finding at `confirmed`. Status: pending manual
run.

## Precision

True positives 2, false positives 0. Precision 1.00.

## Recall

True positives 2, false negatives 0. Recall 1.00.

## Gate Verdict

PASS. Precision 1.00 is above the 0.99 gate. Corpus holds 0 findings.

## Dataset

- Dataset hash: `1d2ca421bd2ad05c9ad6214080f57e525094f59ddc352a149be17c7f7bca346d`
- Samples: TP=2, FP=0, TN=2, FN=0. `TestMetricGate` fails on hash drift.

## Limitations

- Only the `.txt` extension with an octet-stream declaration is sent; other inert
  pairs (`.log`, `.dat`) are not enumerated.
- When the server publishes no artifact URL the plugin claims nothing, which is
  a deliberate false negative.

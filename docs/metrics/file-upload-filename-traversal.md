<!--
SPDX-License-Identifier: AGPL-3.0-only
Copyright (C) 2026 Xmar1881 / GASH contributors
Module: github.com/Xmar1881/Gash

File: docs/metrics/file-upload-filename-traversal.md
What: Precision and recall report for the Tier 2 filename-traversal upload plugin.
Why: Proves the traversal serve-back workflow meets the 99 percent gate behind
  the upload-served oracle.
-->

# Metrics: file-upload-filename-traversal

## Overview

Tier 2 active JS plugin. Oracle `upload-served`. A multipart part is uploaded
with a traversal filename (`../../<canary>.html`); the artifact URL the server
hands out is fetched back, and a sibling name that was never uploaded is the
control. The served content type decides `confirmed` (active) or `firm`
(inert).

## Evidence Standard

Upload-served rule (GASH-038): the upload must be accepted, the fetched
artifact must carry our canary, and the control URL must stay clean. Active
content type is `confirmed`; inert or unknown is `firm`; a missing artifact, a
rejected upload or a dirty control rejects.

## Fixtures

- Positive: 2 of 2 accepted (`confirmed` on active serve-back, `firm` on inert
  serve-back).
- Negative: 2 of 2 rejected (control URL carries the payload too; upload
  rejected by the server).
- Command:
  `go run ./cmd/gash plugins test plugins/file-upload/file-upload-filename-traversal.js`

## JS E2E

`TestFileUploadFilenameTraversalE2E` (`tests/plugins/tier2_expansion_test.go`)
asserts one `confirmed` `upload-served` candidate, that the part actually
carried the traversal filename inside a raw multipart body, that an inert
serve-back stays `firm`, that a dirty control rejects, and that the declared
send budget holds.

## Corpus Result

Oracle `upload-served` rejects clean corpus bodies because no upload exchange
exists, so no `firm`-plus finding is produced.

## Lab Result

Procedure: lab upload endpoint that joins the raw filename with its storage
directory, run with `--active`, expect one `high` finding at `confirmed`.
Status: pending manual run.

## Precision

True positives 2, false positives 0. Precision 1.00.

## Recall

True positives 2, false negatives 0. Recall 1.00.

## Gate Verdict

PASS. Precision 1.00 is above the 0.99 gate. Corpus holds 0 findings.

## Dataset

- Dataset hash: `e1a336a3a81169c1cccffc3eec82693b57496f860153063b655336668a4d6571`
- Samples: TP=2, FP=0, TN=2, FN=0. `TestMetricGate` fails on hash drift.

## Limitations

- Only the `../` filename form is sent; Windows separators (`..\`) and
  double-encoded variants are not enumerated.
- Archive-based traversal (zip slip, tar slip) is out of scope: the plugin
  uploads a plain part, never a container.
- When the server does not disclose an artifact URL the plugin claims nothing,
  which is a deliberate false negative.

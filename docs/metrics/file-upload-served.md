<!--
SPDX-License-Identifier: AGPL-3.0-only
Copyright (C) 2026 Xmar1881 / GASH contributors
Module: github.com/Xmar1881/Gash

File: docs/metrics/file-upload-served.md
What: Precision and recall report for the Tier 2 upload validation-bypass plugin.
Why: Proves the upload serve-back workflow meets the 99 percent precision gate
  with a dedicated engine oracle (GASH-038).
-->

# Metrics: file-upload-served

## Overview

Tier 2 active JS plugin. Oracle `upload-served` (new, engine-owned, GASH-038).
The plugin uploads a multipart artifact whose declared part type deliberately
mismatches its extension (`image/png` with an `.html` filename) and whose body
is an executable canary payload, then locates the URL the server handed out and
fetches that artifact back.

An accepted upload proves nothing on its own, and the reflection oracle reasons
about a page's HTML context rather than the content type an artifact is served
with — an executable payload inside `text/plain` never runs. That is why the
serve-back behaviour needed its own oracle rather than reuse of `stored`.

## Evidence Standard

Upload rule (GASH-038 family). The ladder is reject / firm / confirmed:

- **reject**: upload missing or >= 400; artifact not retrievable (status 0 or
  >= 400); served body without the canary; or a control URL that also serves the
  payload (attribution lost).
- **firm**: upload accepted and the artifact comes back with our canary, but the
  served content type is inert or unknown — a validation bypass without
  execution.
- **confirmed**: the same, served with an active content type (`text/html`,
  `application/xhtml+xml`, `image/svg+xml`, `application/xml`, `text/xml`,
  `application/javascript`, `text/javascript`, `application/x-javascript`).

The control is a sibling filename that was never uploaded, so a pre-existing
file that merely happens to match cannot confirm.

## Fixtures

- Positive: 3 of 3 accepted (`confirmed` for `text/html` and `image/svg+xml`;
  `firm` for `text/plain`).
- Negative: 4 of 4 rejected (upload 415; artifact 404; served body without the
  payload; dirty control).
- Command: `go run ./cmd/gash plugins test plugins/file-upload/file-upload-served.js`

## JS E2E

`TestFileUploadServedE2E` (`tests/plugins/tier2_upload_test.go`) executes the
real script through `loader.ExecuteJS` with a mocked upload backend:

- Backend echoing `{"url":"/uploads/<canary>.html"}` and serving that path as
  `text/html`: one `confirmed` candidate; the request is asserted to be a raw
  multipart body with a boundary and a file part carrying the mismatched type.
- Backend serving the artifact as `text/plain`: one candidate at `firm`.
- Upload rejected: zero candidates.
- Upload response without a locatable URL: zero candidates and no fetch.
- Send budget stays under the declared `max_requests`.

## Corpus Result

Oracle `upload-served` is workflow-gated: nothing accepts without an accepted
upload, a retrievable artifact carrying the canary, and a clean control. The
shared corpus gate evaluates the oracle's negative fixture with the mock
enabled, so no `firm`-plus finding can be produced from static bodies.

## Lab Result

Procedure: serve a localhost lab upload endpoint that stores the file under a
public directory and serves it with `text/html` in the localhost lab, scan with
`--active`, expect one high severity finding at `confirmed`.
Status: pending manual run. Expected Precision 100 percent on this page class.

## Precision

True positives 3, false positives 0. Precision 1.00.

## Recall

True positives 3, false negatives 0. Recall 1.00.

## Gate Verdict

PASS. Precision 1.00 is above the 0.99 gate. Corpus holds 0 findings.

## Dataset

- Dataset hash: `503a22c626836757f3c1007aff76bd59c3ef099ac8b2d1d99091e55226d5b82b`
  (sha256 over all 7 fixture files under `tests/fixtures/file-upload-served/`).
- Samples: TP=3, FP=0, TN=4, FN=0. Fixture-only measurement; lab pending above.
  `TestMetricGate` fails the build if this hash drifts from the fixtures.

## Limitations

- The artifact URL must be discoverable in the upload response body; a response
  that hides it yields no finding (deliberate false negative).
- Server-side code execution (PHP/JSP) is out of scope: the proof is serve-back
  content type, not interpreter execution.
- Zip slip and archive traversal are separate gaps and are not covered here.
- `Content-Type` sniffing by the browser without a declared type stays at
  `firm`; only a declared active type confirms.

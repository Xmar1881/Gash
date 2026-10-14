<!--
SPDX-License-Identifier: AGPL-3.0-only
Copyright (C) 2026 Xmar1881 / GASH contributors
Module: github.com/Xmar1881/Gash

File: docs/metrics/ssrf-cloud-metadata.md
What: Precision and recall report for the cloud-metadata SSRF screen.
Why: Proves metadata-token reflection reports at most tentative without a
control-confirmed executable context (no over-claiming on text reflection).
-->

# Metrics: ssrf-cloud-metadata

## Overview

Tier 1 active plugin. Oracle `reflection` with canary `ami-id`. Sends the
link-local metadata URL (`http://169.254.169.254/latest/meta-data/`) to
URL-like parameters and looks for the metadata token in the response.
Maximum confidence `tentative` on text reflection (executable context is not
provable statically); runs only with `--active` on explicitly permitted
targets.

## Evidence Standard

Rule GASH-008 (CWE-918, engine label override for the SSRF class; the oracle
is shared with reflection). Requires the `ami-id` token in the payload
response. Comment-only or encoded occurrences never confirm. WAF/block pages
classify `Untrusted` and always reject.

## Fixtures

- Positive: 2 of 2 accepted (`tentative`: AWS token line, key-value pair).
- Negative: 2 of 2 rejected (no token anywhere, token only in HTML comment).
- Command: `go run ./cmd/gash plugins test plugins/ssrf/ssrf-cloud-metadata.yaml`

## Corpus Result

Oracle `reflection` is covered by `TestB4CorpusZeroFirmPlus`: 0 `firm` plus
findings on clean, SPA, WAF, encoded, and dynamic bodies. A WAF block body
correctly rejects as untrusted.

## Lab Result

Procedure: serve a fetch-URL endpoint performing server-side requests, scan
with `--active` against the localhost lab, expect one high finding at
`tentative` (manual verification required: confirm the target host fetched
the metadata address).
Status: pending manual run (see `docs/metrics/lab-aggressive-*.md` when the
localhost lab lands). Expected Precision 100 percent on this vulnerability class.

## Precision

True positives 2, false positives 0. Precision 1.00.

## Recall

True positives 2, false negatives 0. Recall 1.00.

## Gate Verdict

PASS. Precision 1.00 is above the 0.99 gate. Corpus holds 0 `firm` plus.

## Dataset

- Dataset hash: `881d9f495fe06a45062a95cedc24408b7685be9fa971a91f0f6a0ea09a9bf061`
  (sha256 over all 4 fixture files under `tests/fixtures/ssrf-cloud-metadata/`).
- Samples: TP=2, FP=0, TN=2, FN=0. Fixture-only measurement; lab pending above.
  `TestMetricGate` fails the build if this hash drifts from the fixtures.

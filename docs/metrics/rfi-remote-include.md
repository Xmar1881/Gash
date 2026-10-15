<!--
SPDX-License-Identifier: AGPL-3.0-only
Copyright (C) 2026 Xmar1881 / GASH contributors
Module: github.com/Xmar1881/Gash

File: docs/metrics/rfi-remote-include.md
What: Precision and recall report for the remote file include reflection screen.
Why: Proves Tier 1 reflection oracle (loopback URL canary) meets the 99 percent
  precision gate with tentative max (no remote fetch, no execution claim).
-->

# Metrics: rfi-remote-include

## Overview

Tier 1 active plugin. Oracle `reflection` with loopback canary
`http://127.0.0.1:9/gash-rfi-canary.txt` and contexts `[html, attr, url]`.
LFI is covered by `path-traversal-error` (error oracle); this plugin covers the
remote-include reflection gap. A reflected loopback URL is at most `tentative`
(text/attribute reflection is not inclusion or execution proof). No external
request is ever performed: the oracle only matches the canary string in the
response body. Live use is lab/loopback plus scope-gated only
(`--scope 127.0.0.1`, dis URL'ye gercek istek YOK).

## Evidence Standard

Rule GASH-008 family (CWE-98, engine label override for the RFI class; the
oracle is shared with reflection). Requires the loopback canary in an allowed
context (`html-text`, `attr`, `url`). Comment-only or encoded occurrences
reject. Control containing the same canary in the same context rejects
(indistinguishable). WAF/block pages classify `Untrusted` and always reject.

## Fixtures

- Positive: 2 of 2 accepted (`tentative`: text reflection, URL-attribute reflection).
- Negative: 2 of 2 rejected (clean page, comment-only canary).
- Command: `go run ./cmd/gash plugins test plugins/rfi/rfi-remote-include.yaml`

## Corpus Result

Oracle `reflection` is covered by `TestB4CorpusZeroFirmPlus`: 0 `firm` plus
findings on clean, SPA, WAF, encoded, and dynamic bodies. The loopback canary
never occurs in corpus bodies, so all corpus evaluations reject.

## Lab Result

Procedure: serve a local include endpoint (`?file=`, `?page=`, `?include=`)
reflecting the parameter in the localhost lab, scan with `--active` plus
`--scope 127.0.0.1`, expect one high finding at `tentative` (manual
verification required: confirm server-side include semantics; this screen alone
is not fetch proof).
Status: pending manual run. Expected Precision 100 percent on this page class.

## Precision

True positives 2, false positives 0. Precision 1.00.

## Recall

True positives 2, false negatives 0. Recall 1.00.

## Gate Verdict

PASS. Precision 1.00 is above the 0.99 gate. Corpus holds 0 `firm` plus.

## Dataset

- Dataset hash: `d594948e922ff480c1915ca4c6125c51ce09dc4fef3dfe06d477608897921141`
  (sha256 over all 4 fixture files under `tests/fixtures/rfi-remote-include/`).
- Samples: TP=2, FP=0, TN=2, FN=0. Fixture-only measurement; lab pending above.
  `TestMetricGate` fails the build if this hash drifts from the fixtures.

## Limitations

- Reflection-only screen; remote fetch or local/remote content inclusion is not
  proven (tentative ceiling, confirmed YOK).
- Dis URL'ye gercek istek YOK: payload is loopback-only by design; live runs
  require explicit scope plus localhost lab (kirmizi cizgi).
- Backend-specific include semantics (allow_url_include off, wrappers) are not
  fingerprinted in v1.

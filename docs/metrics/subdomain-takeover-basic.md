<!--
SPDX-License-Identifier: AGPL-3.0-only
Copyright (C) 2026 Xmar1881 / GASH contributors
Module: github.com/Xmar1881/Gash

File: docs/metrics/subdomain-takeover-basic.md
What: Precision and recall report for the subdomain takeover screen.
Why: Proves Tier 1 error oracle (takeover mode) meets unclaimed-service
  signature-plus-control standard at the DNS-dependent firm ceiling with
  passive in-scope requests only.
-->

# Metrics: subdomain-takeover-basic

## Overview

Tier 1 passive plugin (`safe: true`, GET-only). Oracle `error` with
`mode: takeover` and `signature_set: ["takeover"]` (GASH-030, CWE-693).
Unclaimed-service body signatures (S3 `NoSuchBucket`, GitHub Pages
`There isn't a GitHub Pages site here`, Heroku `No such app`, Shopify,
Tumblr) plus absent-in-control proof. Maximum confidence `firm`: the HTTP
signature is only half the proof; DNS CNAME confirmation (proto-dns recon or
`dig CNAME`, scope-checked) is a documented lab precondition, mocked in
fixtures. No request ever leaves the scope: bare-target GET, no parameter
injection, no third-party fetch.

## Evidence Standard

GASH-030 extends the GASH-004 error-signature family. Accept requires an
unclaimed-service signature in the bare-target body plus absence in the
control. WAF/block pages classify `Untrusted` and always reject. Firm ceiling
is intentional and DNS-dependent: without CNAME evidence the body alone is a
strong but single-channel signal. Claiming takeover without DNS confirmation
is a report-level violation, not a plugin finding.

## Fixtures

- Positive: 2 of 2 accepted (2 `firm` with control; S3 `NoSuchBucket`, GitHub Pages marker).
- Negative: 2 of 2 rejected (parked page without signature, same signature in control).
- Command: `go run ./cmd/gash plugins test plugins/takeover/subdomain-takeover-basic.yaml`

## Corpus Result

Oracle `error` (takeover mode) evaluated against clean, SPA, WAF, encoded,
and dynamic bodies. `firm` plus findings: 0. Covered by
`TestTakeoverSignature` in `internal/oracle/new_detectors_test.go`.

## Lab Result

Procedure: point a lab subdomain CNAME at an unclaimed S3 bucket or Pages
site (then confirm with `dig CNAME`), scan the bare subdomain with
`--scope <lab-domain>`, expect one high severity finding at `firm`; reclaim
the service and expect rejection. Status: pending manual run. Expected
Precision 100 percent on this page class.

## Precision

True positives 2, false positives 0. Precision 1.00.

## Recall

True positives 2, false negatives 0. Recall 1.00.

## Gate Verdict

PASS. Precision 1.00 is above the 0.99 gate. Corpus holds 0 `firm` plus.

## Dataset

- Dataset hash: `076de1553649189059876327db4f538099e90cd8db070fa3c1060f90508c7752`
  (sha256 over all 4 fixture files under `tests/fixtures/subdomain-takeover-basic/`).
- Samples: TP=2, FP=0, TN=2, FN=0. Fixture-only measurement; lab pending above.
  `TestMetricGate` fails the build if this hash drifts from the fixtures.

## Limitations

- Fixtures mock the DNS half; live runs without CNAME confirmation must stay `firm` and must not be reported as confirmed takeover.
- Signature list covers S3, GitHub Pages, Heroku, Shopify, Tumblr; Azure, Pantheon, and niche providers are future work.
- WAF-blocked or `AccessDenied`-style bodies classify `Untrusted` and reject by design (no finding rather than a noisy one).

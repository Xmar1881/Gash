<!--
SPDX-License-Identifier: AGPL-3.0-only
Copyright (C) 2026 Xmar1881 / GASH contributors
Module: github.com/Xmar1881/Gash

File: docs/metrics/host-header-injection.md
What: Precision and recall report for the Host header reflection screen.
Why: Proves HeaderOracle host_header mode (GASH-035) meets the 99 percent gate.
-->

# Metrics: host-header-injection

## Overview

Tier 1 active plugin. Oracle `header` with `mode: host_header`. A reserved
canary host (`.example`, never routable) injected via Host, X-Forwarded-Host,
or Forwarded that appears in the response body while absent from the
header-free control gives `firm`; reflection in the control rejects.

## Evidence Standard

Rule GASH-035 (CWE-644). GET only. The absolute-URI request-line variant is not
sendable with Go's standard transport and is out of scope; the three header
vectors above are the honest coverage. Cache-poisoning impact is not claimed
(no cache probing happens).

## Fixtures

- Positive: 2 of 2 accepted (`firm`; body link reflection, script-src
  reflection with clean controls).
- Negative: 2 of 2 rejected (no reflection; canary already present in control).
- Command: `go run ./cmd/gash plugins test plugins/host-header/host-header-injection.yaml`

## Corpus Result

Oracle `header` (host_header mode) with clean bodies that lack the canary host:
no accept, zero `firm` plus.

## Lab Result

Procedure: run a lab app that builds absolute URLs from the request Host
header; expect one medium severity finding at `firm`. Status: pending manual
run. Expected Precision 100 percent on this endpoint class.

## Precision

True positives 2, false positives 0. Precision 1.00.

## Recall

True positives 2, false negatives 0. Recall 1.00.

## Gate Verdict

PASS. Precision 1.00 is above the 0.99 gate. Corpus holds 0 unexpected `firm` plus.

## Dataset

- Dataset hash: `cff679d74fe0c575c1b9cacd749ad4177f98240a51acfccaf9c4e78d28bfbe34`
  (sha256 over all 4 fixture files under `tests/fixtures/host-header-injection/`).
- Samples: TP=2, FP=0, TN=2, FN=0. Fixture-only measurement; lab pending above.
  `TestMetricGate` fails the build if this hash drifts from the fixtures.

## Limitations

- Absolute-URI request line and duplicate Host header smuggling are not sent
  (std transport); documented, not implied as covered.
- Header-only reflection without body echo (e.g. Location only) is not flagged
  by this plugin.

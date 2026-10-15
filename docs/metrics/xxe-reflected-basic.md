<!--
SPDX-License-Identifier: AGPL-3.0-only
Copyright (C) 2026 Xmar1881 / GASH contributors
Module: github.com/Xmar1881/Gash

File: docs/metrics/xxe-reflected-basic.md
What: Precision and recall report for the in-band XXE content-reflection plugin.
Why: Proves Tier 1 reflection oracle (GASH-011) meets the 99 percent precision gate
  with a lab-controlled harmless canary entity (no file:// read of real files).
-->

# Metrics: xxe-reflected-basic

## Overview

Tier 1 active plugin. Oracle `reflection` with a harmless lab canary entity
(`GASH_XXE_CANARY`). Entity content reflected in-band plus absent-in-control
reasoning gives `firm`. No `file:///etc/passwd` read or OOB exfiltration is
ever requested or asserted; blind XXE stays with `xxe-oob`.

## Evidence Standard

Rule GASH-011 (CWE-611). Reflected entity content is the in-band proof channel.
Parse errors without content disclosure reject (not XXE proof). WAF/block pages
classify `Untrusted` and always reject.

## Fixtures

- Positive: 2 of 2 accepted (`firm`).
- Negative: 2 of 2 rejected (entities blocked, parse-error-only edge).
- Command: `go run ./cmd/gash plugins test plugins/xxe/xxe-reflected-basic.yaml`

## Corpus Result

Oracle `reflection` evaluated against clean, SPA, WAF, encoded, and dynamic bodies.
`firm` plus findings: 0. WAF body correctly rejects as untrusted.

## Lab Result

Procedure: serve an XML endpoint expanding a lab-controlled test entity in the
localhost lab, scan with the canary DTD payload, expect one high severity
finding at `firm` and no file disclosure.
Status: pending manual run. Expected Precision 100 percent on this vulnerability class.

## Precision

True positives 2, false positives 0. Precision 1.00.

## Recall

True positives 2, false negatives 0. Recall 1.00.

## Gate Verdict

PASS. Precision 1.00 is above the 0.99 gate. Corpus holds 0 `firm` plus.

## Dataset

- Dataset hash: `6a8b8e6709b7866cca1165fb81362fb062425518b213d3469723a4a3dc4e8144`
  (sha256 over all 4 fixture files under `tests/fixtures/xxe-reflected-basic/`).
- Samples: TP=2, FP=0, TN=2, FN=0. Fixture-only measurement; lab pending above.
  `TestMetricGate` fails the build if this hash drifts from the fixtures.

## Limitations

- In-band only; blind XXE without reflection is covered by `xxe-oob` (OOB required).
- Single canary-entity variant; DTD obfuscation and CDATA shapes are future work.
- Real file disclosure is never tested (safety boundary).

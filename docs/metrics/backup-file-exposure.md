<!--
SPDX-License-Identifier: AGPL-3.0-only
Copyright (C) 2026 Xmar1881 / GASH contributors
Module: github.com/Xmar1881/Gash

File: docs/metrics/backup-file-exposure.md
What: Precision and recall report for the backup and state file exposure screen.
Why: Proves ErrorSignatureOracle backup_file mode (GASH-037) meets the gate.
-->

# Metrics: backup-file-exposure

## Overview

Tier 1 active plugin. Oracle `error` with `mode: backup_file`. Twelve fixed
well-known paths are probed with GET; a canonical backup/state marker
(`APP_KEY=`, git `ref: refs/`, svn `<wc-entries`, dump banners, SQLite/zip
magic, etc.) plus an absent soft-404 control gives `firm`.

## Evidence Standard

Rule GASH-037 (CWE-538). Fixed 12-path list, no directory brute force, no
recursive discovery. The soft-404 control request (path suffix
`.gash-soft404-check`) keeps catch-all pages from producing evidence. Firm is
the ceiling: content markers prove file exposure but not exploitability.

## Fixtures

- Positive: 2 of 2 accepted (`firm`; dotenv with soft-404 control, git HEAD
  without control).
- Negative: 2 of 2 rejected (custom 404 catch-all; marker also present in the
  soft-404 control).
- Command: `go run ./cmd/gash plugins test plugins/backup-file/backup-file-exposure.yaml`

## Corpus Result

Oracle `error` (backup_file signature set) against clean, SPA, WAF, encoded,
and dynamic bodies: no marker match, zero `firm` plus.

## Lab Result

Procedure: serve a lab docroot containing `.env` and `www.zip`; expect two
medium severity findings at `firm`, one per file. Status: pending manual run.
Expected Precision 100 percent on this path class.

## Precision

True positives 2, false positives 0. Precision 1.00.

## Recall

True positives 2, false negatives 0. Recall 1.00.

## Gate Verdict

PASS. Precision 1.00 is above the 0.99 gate. Corpus holds 0 unexpected `firm` plus.

## Dataset

- Dataset hash: `cf128672ac54999f3c3f2c50c0d63d441ffdba80208742270b64f7cbea068d83`
  (sha256 over all 4 fixture files under `tests/fixtures/backup-file-exposure/`).
- Samples: TP=2, FP=0, TN=2, FN=0. Fixture-only measurement; lab pending above.
  `TestMetricGate` fails the build if this hash drifts from the fixtures.

## Limitations

- Path list is a fixed 12-entry top list, not a wordlist; unlisted backup names
  are out of scope.
- Marker-based detection can miss minified/custom dump formats without the
  canonical banners.
- Overlaps GASH-028 content discovery by design; this plugin pins marker-level
  proof with its own fixture gate.

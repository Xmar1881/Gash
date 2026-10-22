<!--
SPDX-License-Identifier: AGPL-3.0-only
Copyright (C) 2026 Xmar1881 / GASH contributors
Module: github.com/Xmar1881/Gash

File: docs/metrics/sensitive-file-exposure.md
What: Precision and recall report for the extended sensitive file exposure plugin.
Why: Proves Tier 1 error oracle (backup_file mode) meets the precision gate
  with an expanded fixed path list covering git, env, config, ssh, cloud, db, logs.
-->

# Metrics: sensitive-file-exposure

## Overview

Tier 1 active plugin. Oracle `error` with mode `backup_file`. Detects exposed
sensitive files (Git, SVN, Mercurial, environment files, config files, Docker,
Kubernetes, SSH keys, AWS/Azure/GCP credentials, IDE settings, logs, databases,
archives) via canonical content marker match plus soft-404 control absence on
an extended fixed path list (70+ paths). GET only, no directory brute force.

## Evidence Standard

Rule GASH-XXX (CWE-538, CWE-200, CWE-522). Requires a canonical file content
marker (repositoryformatversion, APP_KEY=, [core], id_rsa, etc.) in the response
body AND absent from the soft-404 control of the same path. A bare 200 is never
enough. Fixed bounded path list; overlap with GASH-028 content discovery is
documented.

## Fixtures

- Positive: 2 of 2 accepted (`firm`).
- Negative: 2 of 2 rejected (no marker, SPA catch-all).
- Command: `go run ./cmd/gash plugins test plugins/sensitive-file-exposure/sensitive-file-exposure.yaml`

## Corpus Result

Oracle `error` (backup_file mode) evaluated against clean, SPA, WAF, and dynamic
bodies. `firm` plus findings: 0. WAF body correctly rejects as untrusted. SPA
catch-all correctly rejected via soft-404 control.

## Lab Result

Procedure: serve sensitive files in the localhost lab, scan with active mode,
expect medium severity findings at `firm`. Status: pending manual run.

## Precision

True positives 2, false positives 0. Precision 1.00.

## Recall

True positives 2, false negatives 0. Recall 1.00.

## Gate Verdict

PASS. Precision 1.00 is above the 0.99 gate. Corpus holds 0 `firm` plus.

## Dataset

- Dataset hash: `fadff75105e5d7247902310fcddb3990cf6a5fe58513764cc96381d61e9a1d63`
  (sha256 over all 4 fixture files under `tests/fixtures/sensitive-file-exposure/`).
- Samples: TP=2, FP=0, TN=2, FN=0. Fixture-only measurement; lab pending above.
  `TestMetricGate` fails the build if this hash drifts from the fixtures.

## Limitations

- Fixed path list; custom/renamed sensitive files not detected.
- Soft-404 control required; may miss files on servers without consistent 404s.
- No authentication bypass testing; only anonymous exposure.
- Basic backup files (12-path list) covered by `backup-file-exposure`.
- Git exposure limited to HEAD/config; no full repo enumeration.
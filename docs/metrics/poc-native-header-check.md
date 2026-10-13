<!--
SPDX-License-Identifier: AGPL-3.0-only
Copyright (C) 2026 Xmar1881 / GASH contributors
Module: github.com/Xmar1881/Gash

File: docs/metrics/poc-native-header-check.md
What: Precision and recall report for the Tier 3 native reference plugin.
Why: Proves trust plus digest plus spawn and kill without weakening evidence.
-->

# Metrics: poc-native-header-check

## Overview

Tier 3 proof-of-concept binary plus manifest. The binary returns header-oracle
candidates over loopback gRPC; the engine verifies them like any other
candidate. Trust plus sha256 pin is mandatory before any spawn.

## Evidence Standard

Rule GASH-019 through the `header` oracle. Missing headers confirm; hardened
hosts reject.

## Fixtures

- Positive: 1 of 1 accepted at `confirmed`.
- Negative: 1 of 1 rejected.
- Command: `go run ./cmd/gash plugins test plugins/native/poc-native-header-check.gashplugin.yaml`

## Trust and Lifecycle

- Trust refusal without approval and digest mismatch both fail closed.
- Handshake checks identity plus `api_version 1.0` plus health.
- Per-call timeout bounds hung work; close always kills the process.
- Proof: `TestTier3TrustSpawnKill` in `tests/plugins`.

## Corpus Result

Oracle `header` against clean, SPA, WAF, encoded, and dynamic bodies.
`firm` plus findings: 0.

## Lab Result

Procedure: point the POC at the Juice Shop landing page inside
`docker-compose.lab.yml` with `--deep --active`, expect one low severity
header candidate verified to `confirmed`. Status: pending manual run.

## Precision

True positives 1, false positives 0. Precision 1.00.

## Recall

True positives 1, false negatives 0. Recall 1.00.

## Gate Verdict

PASS. Precision 1.00 is above the 0.99 gate. Corpus holds 0 `firm` plus.

## Deviation from Phase 0/1

The POC dials direct loopback gRPC with generic messages instead of the
hashicorp broker plus generated `plugin.proto` stubs. Trust, digest,
handshake, loopback-only binding, per-call timeout, and kill semantics are
preserved; broker adoption stays future work. The manifest pin belongs to the
reference build and must be re-pinned per platform via `gash plugins trust`.

<!--
SPDX-License-Identifier: AGPL-3.0-only
Copyright (C) 2026 Xmar1881 / GASH contributors
Module: github.com/Xmar1881/Gash

File: docs/native-plugin-spec.md
What: Tier 3 native process plugin specification.
Why: Documents the manifest, trust, and gRPC contract for advanced plugins.
-->

# Native Plugin Spec

## Purpose

Tier 3 covers native speed or special libraries (custom crypto, protocol
parsers) that cannot live in YAML or sandboxed JS. Each plugin is a compiled
binary plus a manifest. Binaries run in a separate OS process over gRPC and
never run on discovery alone.

## Trust Model

Tier 3 is untrusted by default. No automatic discovery executes code:

1. Pin the digest in the manifest (`sha256`).
2. Approve it explicitly: `gash plugins trust <manifest>`.
3. The engine checks digest plus platform before every spawn (B10).
4. `--strict-plugins` restricts scans to trusted binaries only.

Trust records live outside the repository (`~/.gash/trust.db` by default,
overridable with `--trust-file` or `GASH_TRUST_FILE`) and include the host
platform. A digest proven on one platform does not authorize a rebuild on
another; re-pin per platform after rebuilding.

### Trust File Migration

Legacy installs keep approvals in `~/.gash/trust.json`. On first use of the
default path the engine reads that legacy file when present and copies its
records into `~/.gash/trust.db` without modifying or deleting the legacy
file. Explicit `--trust-file` and `GASH_TRUST_FILE` values never trigger
migration; only the default path migrates.

## Manifest Format

Manifests use `.gashplugin.yaml` and are the only Tier 3 files discovered:

```yaml
id: poc-native-header-check
name: POC Native Header Check
description: Minimal Tier 3 reference plugin that asks the engine to verify security headers.
author: GASH contributors
severity: low
tags: [native, poc, headers]
safe: false
deep: true
active: true
requires_auth: false
phase: deep
order: 70
api_version: "1.0"
tests: tests/fixtures/poc-native-header-check/
binary: ./poc-check/poc-check
protocol: grpc
oracle: header
sha256: "3d0bdedb93fc44d9485df5f8100c619f2ccacbe17ec0298285ec3a5975cbd5cf"
```

Rules:

- All `PluginSpec` fields apply; `tier` is set by the loader.
- `binary`: path relative to the manifest (`.exe` fallback on Windows) or
  absolute. The binary itself is never read during discovery.
- `protocol`: exactly `grpc`. `net/rpc` is forbidden.
- `sha256`: lowercase hex digest of the exact binary. Mismatch fails closed.
- `oracle`: primary oracle for offline fixture tests (`header` default).
- `oob: required` needs `active: true, safe: false`, same as other tiers.

## gRPC Contract

The contract is `proto/gash/v1/plugin.proto` (package `gash.v1`):

- `PluginRunner` (host to plugin): `GetMetadata`, `Run`, `HealthCheck`.
  `Run` returns candidates only; the message has no finding, confidence, or
  severity fields (B3 at the protocol level).
- `HostCapabilities` (plugin to host, brokered): `SendProbe`,
  `VerifyOracle`, `GetBaseline`, `Log`. All network and oracle access flows
  through these calls, so `PolicySession` budgets, scope, and rate limits
  apply to native code as well.
- Handshake: `api_version "1.0"` plus plugin id plus sha256 pin. Mismatch
  means no spawn and a skipped-plugin reason in the report.
- Lifecycle: lazy spawn on first call, long-lived multiplexed process,
  per-call timeout, `SIGTERM` to grace to `SIGKILL` plus `Client.Kill` on
  every path. Hung binaries time out without stalling the scan.

The public SDK (`pkg/gashsdk`, Go-first, same AGPL-3.0-only license) wraps
this contract. Stdout writing is forbidden (it breaks the handshake); log
through `HostCapabilities.Log`.

## Safe Active Deep OOB Rules

Native plugins follow the same scheduler gates: `safe`, `deep`, `active`,
`requires_auth`, `requires_tech`, scope, and OOB discipline. An OOB-native
plugin declares `oob: required` and skips with `oob-not-configured` when no
`--oob-server` is set. `--oob-server` without `--active` is a CLI error.

## Fixtures

Tier 3 fixtures reuse the Tier 1 JSON shape against the manifest `oracle`:

```sh
go run ./cmd/gash plugins test plugins/native/poc-native-header-check.gashplugin.yaml
```

`test` verifies the manifest, checks the binary digest without executing
it, then runs positive plus negative fixtures through the real oracle. The
committed pin belongs to the reference build; contributors rebuild per
platform and re-pin via `trust`.

## Validation and Trust

```sh
go run ./cmd/gash plugins validate plugins/native/poc-native-header-check.gashplugin.yaml
go run ./cmd/gash plugins trust plugins/native/poc-native-header-check.gashplugin.yaml
go run ./cmd/gash plugins info poc-native-header-check
```

`validate` checks metadata, protocol, pin presence, and fixture presence.
`trust` verifies the digest and records `{id, sha256, platform}`. `info`
shows the approval state. Without approval the plugin lists as
`trusted=no` and the scheduler skips it as `tier3-untrusted`.

## Examples

- Reference manifest: `plugins/native/poc-native-header-check.gashplugin.yaml`.
- Reference server: `plugins/native/poc-check/main.go` (loopback-only gRPC).
- Metrics: `docs/metrics/poc-native-header-check.md`.
- Spawn plus kill coverage: `TestTier3TrustSpawnKill` in `tests/plugins`.

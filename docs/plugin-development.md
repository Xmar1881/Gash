<!--
SPDX-License-Identifier: AGPL-3.0-only
Copyright (C) 2026 Xmar1881 / GASH contributors
Module: github.com/Xmar1881/Gash

File: docs/plugin-development.md
What: Tier-independent author guide for community plugins.
Why: One place for the Candidate discipline, gates, and CLI workflow.
-->

# Plugin Development

## Purpose

This guide explains how to write a community plugin that passes review on
the first attempt. It is tier-independent; tier specifics live in
`docs/yaml-plugin-spec.md`, `docs/js-plugin-spec.md`, and
`docs/native-plugin-spec.md`.

## Core Model

Plugins never produce findings. They return **candidates**; engine-owned
oracles verify each candidate and the engine builds the finding
(Candidate to Verify to Finding). Confidence (`confirmed`, `firm`,
`tentative`) and final severity come from evidence, never from plugin
declarations. A plugin without evidence caps at `tentative`, and tentative
stays hidden unless `--show-tentative` is passed.

## Choosing a Tier

| Tier | Format | Code | Discovery | Audience |
|---|---|---|---|---|
| Tier 1 | `.yaml`/`.yml`/`.json` | No | Automatic | Everyone, widest community |
| Tier 2 | `.js` (goja VM) | Yes, sandboxed | Automatic | Complex logic |
| Tier 3 | Binary plus `.gashplugin.yaml` | Yes, native | Explicit trust only | Advanced, official extensions |

Start with Tier 1. Move to Tier 2 when branching, loops, or multi-step
correlation are needed. Tier 3 is reserved for native speed or special
libraries and needs `gash plugins trust` plus sha256 pinning; it is not a
community drop-in.

## Common Metadata

All tiers compile to the same `PluginSpec` IR. Required fields are `id`,
`name`, `description`, `severity`, `tags`, `safe`, `deep`, `active`,
`requires_auth`, `phase`, `order`, `api_version`. See `CONTRIBUTING.md` for
the full rule table (R-01 to R-12, R-SEV-01, R-OOB-01/02).

Key policy fields:

- `safe`: `true` means GET/HEAD/OPTIONS only, enforced by the proxy.
- `deep`: `true` runs only with `--deep`.
- `active`: `true` runs only with `--active` (state-changing or invasive).
- `oob`: `""`, `optional`, or `required`. Required plus no `--oob-server`
  means the plugin never runs (honest skip, no fake tentative).
- `requires_tech`: skips the plugin when baseline tech disagrees.
- `tests`: fixture directory; empty caps findings at `tentative`.

## Safe Active Deep OOB Rules

- Default scans stay `safe`. Request `--deep` or `--active` explicitly.
- `safe=true && active=true` is rejected at load time.
- OOB plugins must set `active: true, safe: false`.
- `--oob-server` without `--active` is a CLI error.
- `oob: required` plugins skip with `oob-not-configured` when no server is
  set; `oob: optional` plugins degrade to the in-band ceiling.

## Oracle API Overview

| Oracle | Tier 1 `oracle.name` | Tier 2 `host.oracles.*` | Tier 3 `VerifyOracle` |
|---|---|---|---|
| Reflection | `reflection` | `reflection(resp, canary, contexts)` | `reflection` |
| Differential | `differential` | `differential(true, false, control)` | `differential` |
| Error signature | `error` | `error(resp, control)` | `error` |
| Header | `header` | `header(resp)` | `header` |
| Redirect | `redirect` | `redirect(resp, host)` | `redirect` |
| OOB | `oob` | `oob(correlationId, namespace)` | `oob` |
| Version | `version` | n/a (Tier 1 only) | `version` |

Tier 1 declares the oracle by name; Tier 2 calls it and passes the returned
evidence to `host.candidate(point, ref, ev)`; Tier 3 calls `VerifyOracle`
over gRPC. Evidence objects are opaque: `null` means reject, non-null means
the engine accepted the proof. Never forge evidence; only oracle returns
count.

`host.oob.generate(channel)` returns `null` when OOB is disabled; skip
honestly instead of fabricating a callback. `host.candidate` returns `null`
for rejected evidence; only non-null results belong in the returned array.

## Candidate Contract

A candidate carries `plugin_id`, target, injection point, oracle name, and
an evidence reference. It carries no confidence and no severity. Returning a
wrong type, throwing outside `run`, or panicking marks the plugin as failed
without stopping the scan (B7). Keep `max_requests` small and let the engine
enforce budgets.

## Fixtures and Metrics

Each plugin needs `tests/fixtures/<id>/positive/*.json` plus
`tests/fixtures/<id>/negative/*.json`. The fastest start is the generator:

```sh
go run ./cmd/gash plugins new my-check --tier yaml
go run ./cmd/gash plugins validate my-check.yaml
go run ./cmd/gash plugins test my-check.yaml
```

Fixtures run offline through real oracles. Precision below 0.99 fails both
the CLI and `TestMetricGate`. The negative corpus (`tests/corpus/`) must
stay at zero `firm` plus. Every plugin also ships `docs/metrics/<id>.md`
with Precision, Recall, Corpus, Lab, and Gate Verdict sections.

## CLI Workflow

```sh
go run ./cmd/gash plugins list
go run ./cmd/gash plugins validate <file>
go run ./cmd/gash plugins test <file>
go run ./cmd/gash plugins info <id>
go run ./cmd/gash plugins trust <manifest>   # Tier 3 only
```

`list` and `info` never execute code. `validate` applies schema plus rules.
`test` enforces fixtures plus precision. `trust` pins a Tier 3 digest with
the current platform; without it the native binary never spawns (B10).

## Submission Checklist

- Metadata warning-free; fixtures positive plus negative; precision >= 0.99.
- Metrics report added; corpus gate green; `go test ./...` green.
- Responsible-use note: authorized targets only, scope allowlist, OOB
  opt-in, safe default. See `docs/SECURITY.md`.

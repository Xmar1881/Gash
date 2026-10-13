<!--
SPDX-License-Identifier: AGPL-3.0-only
Copyright (C) 2026 Xmar1881 / GASH contributors
Module: github.com/Xmar1881/Gash

File: docs/yaml-plugin-spec.md
What: Tier 1 declarative plugin specification.
Why: Gives YAML authors the exact schema, oracle blocks, and policy rules.
-->

# YAML Plugin Spec

## Purpose

Tier 1 is the declarative format for the widest community. No code runs;
the engine sends the declared request and verifies the response with the
declared oracle. Files use `.yaml`, `.yml`, or `.json` and are discovered
automatically.

## File Layout

```yaml
id: open-redirect-param
name: Open Redirect via Query Parameter
description: Detects unvalidated redirect targets in common redirect parameters.
author: GASH contributors
severity: medium
tags: [redirect, client]
safe: true
deep: false
active: false
requires_auth: false
phase: probe
order: 30
api_version: "1.0"
tests: tests/fixtures/open-redirect-param/
request:
  method: GET
  param_names: [redirect, url, next, return_to]
  payload: "https://gash-canary.example/"
oracle:
  name: redirect
  params:
    expect_external_host: true
```

All `PluginSpec` fields apply (see `docs/plugin-development.md`). Tier-only
blocks are `request` and `oracle`. Unknown top-level keys fail validation;
`script`, `code`, `eval`, `exec`, `run`, `function`, `require`, and `import`
keys are forbidden (code blocks are never accepted in Tier 1).

## Request Block

| Key | Required | Notes |
|---|---|---|
| `method` | No (default GET) | `safe: true` allows only GET/HEAD/OPTIONS |
| `param_names` | No | Empty means one request against the bare target |
| `payload` | No | Injected value per listed parameter |

The engine issues one request per `param_names` entry with `payload` as the
value, then verifies each response. Keep `payload` a canary host or marker
owned by the scan; never point it at third-party infrastructure.

## Oracle Block

```yaml
oracle:
  name: header      # reflection|differential|error|header|redirect|oob|version
  params: {}        # oracle-specific, see below
```

Supported oracles and their params:

- `header` (`mode: absent|weak|malformed`): passive security-header check.
  Logic-based, needs no control, never emits tentative. Example:
  `plugins/headers/missing-security-headers.yaml`.
- `redirect` (`expect_external_host: true`): parses the real `Location`
  header and compares hosts, with a neutral control request. Example:
  `plugins/redirect/open-redirect-param.yaml`.
- `reflection`, `differential`, `error`: Tier 1 executes only `header` and
  `redirect` live; other names validate but need Tier 2 for execution.
  Declare them only when the fixture oracle matches and execution stays in
  Tier 2.
- `oob`: declare `oob: required|optional` in metadata; without
  `--oob-server` the plugin skips (`required`) or degrades (`optional`).
- `version`: banner check; without behavioral proof the finding stays
  `tentative` plus `banner-based`.

Oracle names outside the whitelist fail `CheckOOBOracle` when combined with
`oob: required` on OOB-invalid classes.

## Safe Active Deep OOB Rules

- `safe: true` restricts methods to GET/HEAD/OPTIONS at the proxy.
- `deep: true` needs `--deep`; `active: true` needs `--active`.
- `oob: required` needs `active: true, safe: false`; otherwise load fails.
- World-writable files or directories are skipped with a warning.

## Fixtures

Point `tests` at `tests/fixtures/<id>/` with at least one `positive/*.json`
and one `negative/*.json`. Each JSON case carries `name`, `target`,
`status`, `headers`, `body`, plus control fields and
`expected_verdict`/`expected_confidence` for positives. The generator
produces a passing pair:

```sh
go run ./cmd/gash plugins new my-header --tier yaml
go run ./cmd/gash plugins test my-header.yaml
```

## Validation

```sh
go run ./cmd/gash plugins validate plugins/headers/missing-security-headers.yaml
```

Validation checks the JSON Schema shape (generated from `rules.go`), the
R-01 to R-12 consistency rules, the OOB discipline, and fixture presence
(warning when the directory is missing). Warning-free plus fixtures is the
reference bar.

## Examples

- Passive header: `plugins/headers/missing-security-headers.yaml` with
  `docs/metrics/missing-security-headers.md`.
- Open redirect: `plugins/redirect/open-redirect-param.yaml` with
  `docs/metrics/open-redirect-param.md`.
- Starter template: `templates/template.yaml` plus
  `templates/tests/fixtures/template-yaml/`.

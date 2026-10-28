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
| `payloads` | No | Extra ordered payloads tried per parameter; the first accepted evidence stops that parameter early (short-circuit) |
| `paths` | No | Payload-free path probes (e.g. `/admin`); runs once per path instead of query injection |
| `headers` | No | Static request headers sent with the probe (used by host-header style checks) |
| `body` | No | Raw request body for POST probes (e.g. JSON login bodies) |
| `query` | No | Static query values merged into the probe URL (OOB placeholders expanded); companion parameters that are not injection targets, e.g. `w`/`q` for `/_next/image` (GASH-070) |

The engine issues one request per `param_names` entry with `payload` as the
value, then retries the remaining `payloads` until one produces evidence,
then verifies each response. Keep every payload a canary host or marker
owned by the scan; never point it at third-party infrastructure.

## Oracle Block

```yaml
oracle:
  name: header      # reflection|differential|error|header|redirect|oob|version|timing|stored|verb-tamper|cookie|cors|middleware-bypass
  params: {}        # oracle-specific, see below
```

Supported oracles and their params:

- `header` (`mode: absent|weak|malformed|policy|crlf|jwt|jwt_alg|ratelimit|csrf|frame|host_header`):
  header logic checks; passive modes need no control, mode-specific params
  mirror the engine oracle (e.g. `ratelimit` burst budget, `host_header`
  canary). `policy` additionally accepts `header_name`, `policy` (`missing`,
  `required`, `forbidden`, `forbidden_tokens`), `required_tokens`, and
  `forbidden_tokens`; set `skip_if_header_missing: true` so a directive check
  only evaluates when the header exists and does not duplicate the dedicated
  missing-header finding. Examples: `plugins/headers/missing-security-headers.yaml`,
  `plugins/host-header/host-header-injection.yaml`.
- `redirect` (`expect_external_host: true`): parses the real `Location`
  header and compares hosts, with a neutral control request. Example:
  `plugins/redirect/open-redirect-param.yaml`.
- `reflection`, `differential`, `error`, `timing`, `stored`, `verb-tamper`,
  `cookie`, `cors`, `version`: Tier 1 executes these engine oracles directly
  through the shared runner; params mirror the engine oracle params
  (`contexts`, `canary_by_payload`, `false_body`, `mode`, `repeats`,
  `confidence_ceiling`, ...). See `docs/detector-inventory.md` for the full
  oracle matrix.
- The `error` oracle also accepts `mode: critical_exposure` for bounded,
  marker-based control-plane and secret exposure checks. This mode caps
  confidence at `firm`; it is not browser, authentication, or RCE proof.
- `oob`: declare `oob: required|optional` in metadata; without
  `--oob-server` the plugin skips (`required`) or degrades (`optional`).
- `middleware-bypass` (`header`, `header_values`): the declarative request is
  the access-denied control; each header value is replayed on the same path
  and must produce a 2xx, materially different masked body (GASH-069). Example:
  `plugins/nextjs-middleware-bypass/nextjs-middleware-bypass.yaml`.
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

// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Xmar1881 / GASH contributors
// Module: github.com/Xmar1881/Gash

// File: plugins/README.md
// What: Index of official Phase 3 reference plugins.
// Why: Shows tier layout, testing, and the metric gate in one place.

# Reference Plugins

## Purpose

Official built-in plugins covering Tier 1, Tier 2, and Tier 3. Each plugin
ships positive plus negative fixtures and a precision report. The engine
discovers this tree automatically; no enable flag exists.

## Layout

| Plugin | Tier | Oracle | File |
|---|---|---|---|
| missing-security-headers | Tier 1 | header | `headers/missing-security-headers.yaml` |
| open-redirect-param | Tier 1 | redirect | `redirect/open-redirect-param.yaml` |
| xss-reflected-basic | Tier 2 | reflection | `xss/xss-reflected-basic.js` |
| sqli-error-based | Tier 2 | error | `sqli/sqli-error-based.js` |
| sqli-boolean-differential | Tier 2 | differential | `sqli/sqli-boolean-differential.js` |
| ssrf-blind-oob | Tier 2 | oob (required) | `ssrf/ssrf-blind-oob.js` |
| poc-native-header-check | Tier 3 | header | `native/poc-native-header-check.gashplugin.yaml` |

## Testing

```sh
go run ./cmd/gash plugins test plugins/headers/missing-security-headers.yaml
go run ./cmd/gash plugins test plugins/xss/xss-reflected-basic.js
go test ./tests/plugins/ -v
```

## Adding a Plugin

1. Drop one file under the matching category directory.
2. Point `tests` at `tests/fixtures/<id>/` with `positive` and `negative` cases.
3. Add `docs/metrics/<id>.md` following `docs/metrics/README.md`.
4. `TestMetricGate` fails the build until precision reaches 0.99.

## Tier 3 Trust

Native binaries never run on discovery alone. Pin the digest in the manifest,
approve it with `gash plugins trust`, and keep the approval in `~/.gash/trust.db`
(legacy `~/.gash/trust.json` is auto-migrated on first default use).
The reference pin belongs to the reference build; rebuilds re-pin per platform.


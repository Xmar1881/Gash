<!--
SPDX-License-Identifier: AGPL-3.0-only
Copyright (C) 2026 Xmar1881 / GASH contributors
Module: github.com/Xmar1881/Gash

File: docs/metrics/README.md
What: Index of per-plugin precision and recall reports.
Why: Keeps the 99 percent precision gate auditable in one place.
-->

# Metrics Reports

## Purpose

Each reference plugin ships a precision and recall report under this directory.
A plugin lands only when its fixtures pass and precision stays at or above 99 percent.
The gate is enforced by `TestMetricGate` in `tests/plugins`, not by review convention.

## Contents

| Plugin | Report |
|---|---|
| missing-security-headers | [missing-security-headers.md](missing-security-headers.md) |
| open-redirect-param | [open-redirect-param.md](open-redirect-param.md) |
| xss-reflected-basic | [xss-reflected-basic.md](xss-reflected-basic.md) |
| sqli-error-based | [sqli-error-based.md](sqli-error-based.md) |
| sqli-boolean-differential | [sqli-boolean-differential.md](sqli-boolean-differential.md) |
| ssrf-blind-oob | [ssrf-blind-oob.md](ssrf-blind-oob.md) |
| poc-native-header-check | [poc-native-header-check.md](poc-native-header-check.md) |

## How to Reproduce

```sh
go test ./tests/plugins/ -run TestMetricGate -v
go run ./cmd/gash plugins test plugins/<category>/<file>
```

## Gate Rule

Precision below 0.99 fails the build. Corpus `firm` plus findings fail the build.
Lab runs are manual and follow the procedure inside each report.

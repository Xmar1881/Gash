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
| cookie-flags | [cookie-flags.md](cookie-flags.md) |
| cors-misconfig | [cors-misconfig.md](cors-misconfig.md) |
| open-redirect-param | [open-redirect-param.md](open-redirect-param.md) |
| xss-reflected-basic | [xss-reflected-basic.md](xss-reflected-basic.md) |
| sqli-error-based | [sqli-error-based.md](sqli-error-based.md) |
| sqli-boolean-differential | [sqli-boolean-differential.md](sqli-boolean-differential.md) |
| ssrf-blind-oob | [ssrf-blind-oob.md](ssrf-blind-oob.md) |
| poc-native-header-check | [poc-native-header-check.md](poc-native-header-check.md) |
| sqli-auth-bypass | [sqli-auth-bypass.md](sqli-auth-bypass.md) |
| sqli-stacked-time | [sqli-stacked-time.md](sqli-stacked-time.md) |
| ssrf-cloud-metadata | [ssrf-cloud-metadata.md](ssrf-cloud-metadata.md) |
| xss-attribute-injection | [xss-attribute-injection.md](xss-attribute-injection.md) |
| dom-sink-basic | [dom-sink-basic.md](dom-sink-basic.md) |

## Lab Reports

| Lab | Report |
|---|---|
| aggressive recall, localhost synthetic lab (2026-10-14) | [lab-aggressive-local-2026-10-14.md](lab-aggressive-local-2026-10-14.md) |
| compose lab DVWA/Juice Shop (2026-10-14, BLOCKED: no docker) | [lab-compose-dvwa-juiceshop-2026-10-14.md](lab-compose-dvwa-juiceshop-2026-10-14.md) |
| Nuclei comparison (2026-10-14, not compared: no harness) | [nuclei-comparison-2026-10-14.md](nuclei-comparison-2026-10-14.md) |

## How to Reproduce

```sh
go test ./tests/plugins/ -run TestMetricGate -v
go run ./cmd/gash plugins test plugins/<category>/<file>
```

## Gate Rule

The reflected-XSS dataset is currently 10 fixtures (TP=2, FP=0, TN=8,
FN=0), pinned by its report hash. Fixture counts are not real-target recall.

Precision below 0.99 fails the build. Corpus `firm` plus findings fail the build.
Lab runs are manual and follow the procedure inside each report.

## Dataset Honesty (P0.3)

All precision/recall numbers are fixture-scoped: small labelled sets (1–6 cases
per side), never real-world measurements. Each report pins its fixture bytes
under `## Dataset` (`Dataset hash`). `TestMetricGate` recomputes the hash from
`tests/fixtures/<id>/` on every run and fails when the report drifts — silent
fixture edits cannot inflate precision. The first measured (non-fixture)
recall is the localhost synthetic lab above; the docker compose lab
(DVWA/Juice Shop) is still pending where no docker runtime exists. Untested areas (multi-layer
encoding, browser-executed DOM, timing under jitter, blind classes without OOB)
are named in the per-plugin report, never implied as covered.

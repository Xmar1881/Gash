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
| command-injection-timing | [command-injection-timing.md](command-injection-timing.md) |
| xss-stored-basic | [xss-stored-basic.md](xss-stored-basic.md) |
| xxe-reflected-basic | [xxe-reflected-basic.md](xxe-reflected-basic.md) |
| csrf-token-absence | [csrf-token-absence.md](csrf-token-absence.md) |
| clickjacking-frameable | [clickjacking-frameable.md](clickjacking-frameable.md) |
| hpp-parameter-pollution | [hpp-parameter-pollution.md](hpp-parameter-pollution.md) |
| hpp-duplicate-emission | [hpp-duplicate-emission.md](hpp-duplicate-emission.md) |
| xss-stored-two-step | [xss-stored-two-step.md](xss-stored-two-step.md) |
| rfi-remote-include | [rfi-remote-include.md](rfi-remote-include.md) |
| cve-dependency-scan | [cve-dependency-scan.md](cve-dependency-scan.md) |
| crlf-header-injection | [crlf-header-injection.md](crlf-header-injection.md) |
| path-traversal-error | [path-traversal-error.md](path-traversal-error.md) |
| error-message-disclosure | [error-message-disclosure.md](error-message-disclosure.md) |
| jwt-token-exposure | [jwt-token-exposure.md](jwt-token-exposure.md) |
| jwt-alg-confusion | [jwt-alg-confusion.md](jwt-alg-confusion.md) |
| graphql-endpoint-discovery | [graphql-endpoint-discovery.md](graphql-endpoint-discovery.md) |
| file-upload-unrestricted | [file-upload-unrestricted.md](file-upload-unrestricted.md) |
| template-injection-reflection | [template-injection-reflection.md](template-injection-reflection.md) |
| xxe-oob | [xxe-oob.md](xxe-oob.md) |
| blind-sqli-oob | [blind-sqli-oob.md](blind-sqli-oob.md) |
| idor-differential | [idor-differential.md](idor-differential.md) |
| ldap-injection-differential | [ldap-injection-differential.md](ldap-injection-differential.md) |
| command-injection-error | [command-injection-error.md](command-injection-error.md) |
| server-version-disclosure | [server-version-disclosure.md](server-version-disclosure.md) |
| sqli-time-based | [sqli-time-based.md](sqli-time-based.md) |
| nosql-injection-error | [nosql-injection-error.md](nosql-injection-error.md) |
| web-cache-poisoning-basic | [web-cache-poisoning-basic.md](web-cache-poisoning-basic.md) |
| insecure-deserialization-error | [insecure-deserialization-error.md](insecure-deserialization-error.md) |
| subdomain-takeover-basic | [subdomain-takeover-basic.md](subdomain-takeover-basic.md) |
| mass-assignment-basic | [mass-assignment-basic.md](mass-assignment-basic.md) |
| missing-rate-limit | [missing-rate-limit.md](missing-rate-limit.md) |
| caa-dns-check (proto GASH-027, unit-scoped) | [caa-dns-check.md](caa-dns-check.md) |
| content-discovery (engine-recon GASH-028, mock-fixture scoped) | [content-discovery-2026-10-16.md](content-discovery-2026-10-16.md) |
| smuggle-differential (engine-recon GASH-033, mock-fixture scoped) | [smuggle-differential.md](smuggle-differential.md) |

## Lab Reports

| Lab | Report |
|---|---|
| aggressive recall, localhost synthetic lab (2026-10-14) | [lab-aggressive-local-2026-10-14.md](lab-aggressive-local-2026-10-14.md) |
| compose lab DVWA/Juice Shop (2026-10-14, BLOCKED: no docker) | [lab-compose-dvwa-juiceshop-2026-10-14.md](lab-compose-dvwa-juiceshop-2026-10-14.md) |
| compose lab DVWA/Juice Shop/WebGoat (2026-10-15, BLOCKED: no docker) | [lab-compose-2026-10-15.md](lab-compose-2026-10-15.md) |
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

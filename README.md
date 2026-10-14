<!--
SPDX-License-Identifier: AGPL-3.0-only
Copyright (C) 2026 Xmar1881 / Gash contributors
Module: github.com/Xmar1881/Gash

File: README.md
What: Repository entry point for operators and contributors.
Why: One page for purpose, model, quickstart, docs, metrics, and license.
-->

# Gash

[![License: AGPL v3](https://img.shields.io/badge/License-AGPL_v3-blue.svg)](https://www.gnu.org/licenses/agpl-3.0)
[![Go](https://img.shields.io/badge/Go-1.26.8-00ADD8?logo=go)](go.mod)
[![CI](https://img.shields.io/badge/CI-plugin--ci-passing-green)](.github/workflows/plugin-ci.yml)
[![Release](https://img.shields.io/badge/release-v0.1.0--dev-orange)](CHANGELOG.md)

> Badges above are placeholders until the first GitHub release is published;
> CI status becomes live after push (see `.github/workflows/plugin-ci.yml`).

## Purpose

Gash is a Go-core, hybrid-plugin security scanner engine. Community plugins
drop in as single files; engine-owned oracles decide what becomes a finding.
The scanner runs with zero plugins and still emits a valid empty report.

Module `github.com/Xmar1881/Gash`, toolchain `go1.26.8`, license
`AGPL-3.0-only`. Scan only targets you own or have explicit written
permission to test; `--scope` keeps the allowlist tight.

## Key Features

- **Frictionless drop-in plugins:** drop one `.yaml` or `.js` file under
  `~/.gash/plugins/` (or `GASH_PLUGIN_PATH`) and it is discovered
  automatically. No `--load-plugin` or `--enable` flags exist.
- **Accuracy independent of authorship:** every tier compiles to the same
  `PluginSpec` IR and flows through the same Candidate to Verify to Finding
  pipeline. Plugins return candidates only; engine-owned oracles verify; the
  engine builds findings with `confirmed`, `firm`, or `tentative` confidence.
- **Three-tier hybrid:** Tier 1 declarative YAML (no code), Tier 2 sandboxed
  JS via goja (no I/O, no `require`, timeouts), Tier 3 native gRPC process
  (explicit `trust` plus sha256 pin, never auto-executed).
- **Tier 2 timing and DOM bindings:** `host.oracles.timing` verifies
  Go-measured `rttMs` series (ceiling `firm`, no new network primitive);
  `host.oracles.execution` reports static DOM sinks with URL-controlled
  sources (ceiling `firm`; browser `confirmed` needs the headless build).
- **Runtime tech fingerprint:** passive header, cookie-name, body-marker,
  and favicon signals feed the `requires_tech` and capability chain
  (`login-form`, `graphql-endpoint`, ...) without extra probing.
- **Scan profiles:** `safe` (passive, low budget), `standard` (controlled
  active), `deep` (browser/OOB, explicit opt-in), `aggressive` (full
  offensive: all detectors, all methods, 50k req/target, 100 req/s).
- **WAF-aware, not stealthy:** WAF blocks become `WAFDetected` stats, never
  silent drops. Aggressive mode retries at most 5 scoped variants
  (header/HPP/encode/comment/case); block pages never count as evidence.
- **Protocol recon:** TLS observation (`confirmed`), SPF/DMARC reads
  (`firm`), explicit TCP banners (`tentative`, `--active` only), all
  scope-checked. CAA and chunked-TE are documented gaps, not silent.
- **OOB opt-in:** out-of-band verification stays disabled unless
  `--oob-server` points at a self-hosted interaction server you control.
  `oob: required` plugins skip honestly (`oob-not-configured`) instead of
  emitting fake low-confidence findings.
- **Safe-by-default:** default scans stay `safe` (GET/HEAD/OPTIONS only).
  `--deep` and `--active` are explicit opt-ins; `PolicySession` enforces
  methods, budgets, scope allowlist, and rate limits at the proxy layer.
- **Evidence standard:** reflection, differential, timing, error-signature,
  OOB, header, redirect, version, cookie, CORS, and execution oracles with
  baseline gating (soft-404, WAF, dynamic masking) and control plus repeat
  rules.
- **Machine reports:** SARIF 2.1.0 primary (CI code scanning), plus JSON,
  text, HTML, and JUnit. Tentative stays hidden unless `--show-tentative`.

## How It Differs

Honest comparison — Gash is experimental (`v0.1.0-dev`, 29 reference
plugins) and competes on verification discipline, not on maturity or library
size. No Gash-versus-Nuclei benchmark has been run; see
`docs/metrics/nuclei-comparison-2026-10-14.md`.

| Capability | Gash | Nuclei | OWASP ZAP | Burp Suite |
|---|---|---|---|---|
| Primary use | Engine + oracle-gated plugin runner (CI/CLI scans) | Fast template-based scanner with huge library | Full proxy, spider, passive + active scanner | Manual-first intercepting proxy + scanner |
| Plugin model | Drop-in single file (YAML/JS auto, native explicit trust) | YAML templates, large community registry | Add-ons / scripts / automation framework | BApp extensions, manual workflows |
| Who decides a finding | Engine-owned oracles only; plugins emit candidates | Template matchers + severity declarations | Scan rules + alert confidence | Scanner checks + analyst review |
| False-positive discipline | Corpus gate (`firm+` = build fail), precision >= 0.99 gate, control + repeat rules | Severity/filtering conventions, community QA | Alert risk/confidence taxonomy | Manual verification workflow |
| Blind / OOB | Self-hosted OOB only, explicit opt-in, honest skip | Interactsh integration (incl. public server option) | OOB via add-ons / callback channels | Burp Collaborator (built-in, SaaS-backed) |
| Maturity | Early, small reference set, lab recall manual | Mature, thousands of templates, wide adoption | Mature, OWASP flagship, broad protocol support | Industry standard for manual pentest (commercial) |
| License / cost | AGPL-3.0-only, free and open | Open (Nuclei + templates), free | Open (Apache 2.0), free | Commercial (Community free tier) |

Use Nuclei for template breadth, ZAP for proxy/crawl coverage, Burp for
manual depth. Use Gash when you want a small, auditable core where no plugin
— however sloppy — can mint a finding without engine-grade evidence.

## Quickstart

Prerequisite: Go 1.26.8+ on `PATH`. All commands run from the repo root.
Scan only targets you own or have explicit written permission to test.

Linux / macOS (`sh`) — 4 commands:

```sh
go run ./cmd/gash plugins list
go run ./cmd/gash plugins validate plugins/headers/missing-security-headers.yaml
go run ./cmd/gash plugins test plugins/headers/missing-security-headers.yaml
go run ./cmd/gash scan --target http://localhost:8080 --scope localhost
```

Windows (`PowerShell`) — same 4 commands:

```powershell
go run ./cmd/gash plugins list
go run ./cmd/gash plugins validate plugins/headers/missing-security-headers.yaml
go run ./cmd/gash plugins test plugins/headers/missing-security-headers.yaml
go run ./cmd/gash scan --target http://localhost:8080 --scope localhost
```

Aggressive lab scan (permitted target only):

```powershell
go run ./cmd/gash scan --target http://127.0.0.1:8081 --scope 127.0.0.1 --aggressive --format json
```

Scaffold a new check, then validate and test it offline:

```sh
go run ./cmd/gash plugins new my-check --tier yaml
go run ./cmd/gash plugins validate my-check.yaml
go run ./cmd/gash plugins test my-check.yaml
```

Drop-in example (Tier 1 header check, safe by default):

```yaml
id: my-check
name: My Check
description: Detects absent security headers via passive response analysis.
severity: low
tags: [headers, misconfig]
safe: true
deep: false
active: false
requires_auth: false
phase: probe
order: 50
api_version: "1.0"
tests: tests/fixtures/my-check/
request:
  method: GET
oracle:
  name: header
  params:
    mode: absent
```

Tier 2 timing example (Go-measured RTT, ceiling `firm`):

```js
function run(probe, ctx) {
  const points = ctx.injectionPoints();
  const out = [];
  for (const point of points) {
    const delay = [], control = [];
    for (let i = 0; i < 3; i++) {
      delay.push(probe.send(point.withValue("1'; WAITFOR DELAY '0:0:5'--")));
      control.push(probe.send(point.withValue("1")));
    }
    const ev = host.oracles.timing(delay, control, {min_delay_ms: 5000});
    if (ev) out.push(host.candidate(point, "timing", ev));
  }
  return out;
}
```

Static builds only (`CGO_ENABLED=0`); artifacts land under `dist/` and are
never committed:

```sh
CGO_ENABLED=0 go build ./...
VER=$(git describe --tags --always 2>/dev/null || echo v0.1.0-dev)
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o dist/gash-$VER-linux-amd64 ./cmd/gash
CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -o dist/gash-$VER-windows-amd64.exe ./cmd/gash
```

Windows note: `gash-*-windows-amd64.exe` is a console tool. Double-clicking
only shows help and waits for `Enter`; run it from a terminal instead:

```powershell
.\dist\gash-v0.1.0-dev-windows-amd64.exe --help
.\dist\gash-v0.1.0-dev-windows-amd64.exe scan --help
.\dist\gash-v0.1.0-dev-windows-amd64.exe plugins list
```

## Docs Index

| Document | Audience |
|---|---|
| `CONTRIBUTING.md` | Contribution flow, gates, checklist |
| `docs/plugin-development.md` | Tier-independent author guide |
| `docs/yaml-plugin-spec.md` | Tier 1 YAML reference |
| `docs/js-plugin-spec.md` | Tier 2 JS reference (timing + execution bindings) |
| `docs/native-plugin-spec.md` | Tier 3 native reference |
| `docs/architecture.md` | Full engine design (Phase 1) |
| `docs/evidence-standard.md` | Per-class proof rules (GASH-001 to GASH-021) |
| `docs/design/00-scope.md` | Phase 0 scope decisions |
| `docs/SECURITY.md` | Responsible use and reporting |
| `docs/user-guide-tr.md` | Turkish beginner guide (Türkçe, profiles + aggressive) |
| `docs/auth.md` | Auth contexts and dual-user BOLA matrix |
| `docs/api-discovery.md` | OpenAPI test-plan flow |
| `docs/proto-checks.md` | DNS/TLS/TCP checks and CAA gap |
| `docs/known-limits.md` | BLOCKED register (chunked-TE, CAA, headless, benchmark) |
| `docs/report-formats.md` | JSON/SARIF/text/HTML/JUnit contracts |
| `docs/ci-integration.md` | CI gates (`--fail-on`, corpus, bench) |
| `docs/detector-inventory.md` | Oracle and plugin catalog |
| `docs/metrics/README.md` | Precision and recall index |
| `templates/README.md` | Copy-rename starters |
| `plugins/README.md` | Reference plugin index |
| `CHANGELOG.md` | Release history |

## Metrics

Each reference plugin ships `docs/metrics/<id>.md` with Precision, Recall,
Corpus, Lab, and Gate Verdict sections. The gates are tests, not prose:

```sh
go test ./tests/plugins/ -run TestMetricGate -v
go test ./tests/corpus/ -run TestNoFalsePositives -v
go test ./tests/bench/ -run TestWarmDiscoveryBudget -v
```

Precision below 0.99 fails the build. Any `firm+` finding on the clean
corpus fails the build. Warm discovery of 100 plugins must stay under
150 ms. Lab procedures (`docker-compose.lab.yml`: DVWA 2.0, Juice Shop
17.1.0, WebGoat 2023.8) are manual and recorded per report. The first
measured recall is the localhost synthetic lab
(`docs/metrics/lab-aggressive-local-2026-10-14.md`); the compose lab is
BLOCKED without docker
(`docs/metrics/lab-compose-dvwa-juiceshop-2026-10-14.md`); Nuclei comparison
is explicitly not compared
(`docs/metrics/nuclei-comparison-2026-10-14.md`).

## Responsible Use

Scan only targets with explicit written permission. Keep `--scope` tight,
leave OOB disabled unless you run the interaction server, and stay on the
`safe` default in CI and production. Never point active probes, timing loops,
or OOB payloads at third-party systems. Aggressive mode is lab-only unless
you hold written authorization. See `docs/SECURITY.md` for the full
policy (authorized target, scope allowlist, OOB opt-in, safe default);
review rejects any change that encourages unauthorized scanning.

## License

`AGPL-3.0-only`. Full text in `LICENSE`; see `COPYING` for the file layout
plus third-party attribution plan. All new code and docs carry SPDX headers;
Tier 3 SDK uses the same license.

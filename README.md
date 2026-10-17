<!--
SPDX-License-Identifier: AGPL-3.0-only
Copyright (C) 2026 Xmar1881 / Gash contributors
Module: github.com/Xmar1881/Gash

File: README.md
What: Repository entry point for operators and contributors.
Why: One page for purpose, model, quickstart, docs, metrics, and license.
-->

# Gash

```text
  ____           _
 / ___|__ _ ___| |__
| |  _ / _` / __| '_ \
| |_| | (_| \__ \ | | |
 \____|\__,_|___/_| |_|
```

[![License: AGPL v3](https://img.shields.io/badge/License-AGPL_v3-blue.svg)](https://www.gnu.org/licenses/agpl-3.0)
[![Go](https://img.shields.io/badge/Go-1.26-00ADD8?logo=go)](go.mod)
[![Toolchain](https://img.shields.io/badge/toolchain-go1.27.2-00ADD8)](go.mod)
[![CI](https://github.com/Xmar1881/Gash/actions/workflows/plugin-ci.yml/badge.svg)](https://github.com/Xmar1881/Gash/actions/workflows/plugin-ci.yml)

> Evidence first. Plugins everywhere. Findings you can defend.

Gash is a Go-native, plugin-driven web security scanner for teams that care
about signal, explainability, and controlled execution. Plugins propose
candidates; engine-owned oracles decide whether those candidates deserve to
become findings.

Module `github.com/Xmar1881/Gash`, toolchain `go1.27.2`, license
`AGPL-3.0-only`. Scan only targets you own or have explicit written
permission to test (`--scope` opts into a strict allowlist; see Legal).

## Why Gash

- **Engine-owned oracles decide.** Every plugin compiles to the same
  `PluginSpec` IR and flows through `Candidate -> Oracle -> Evidence ->
  Finding`. A plugin can suggest a lead; it cannot mint proof.
- **Drop-in plugins.** Drop one `.yaml` or `.js` file under
  `~/.gash/plugins/` (or `GASH_PLUGIN_PATH`) and it is discovered
  automatically. No `--load-plugin` or `--enable` flags exist.
- **Safe by default.** Default scans stay `safe` (GET/HEAD/OPTIONS only).
  `deep`, `active`, `aggressive`, and OOB behavior are explicit opt-ins;
  `PolicySession` enforces methods, budgets, and rate limits (plus scope
  when `--scope` is set).
- **Evidence levels you can audit.** Findings carry `tentative`, `firm`,
  `static-execution-evidence`, or `confirmed` confidence with control plus
  repeat rules, baseline gating (soft-404, WAF, dynamic masking), and a
  per-plugin fixture report under `docs/metrics/`.

## What's New / Highlights

- **51 detectors** — verify with `go run ./cmd/gash plugins list`
  (37 YAML, 7 sandboxed JS, 1 native PoC; see Detector Summary below).
- **Request-smuggling probe (GASH-033)** — raw-TCP CL.TE/TE.CL/TE.TE
  differential with dual-channel proof (follow-up divergence *and* delay),
  `firm` ceiling, aggressive-gated, bounded to 10 requests on one keep-alive
  connection.
- **Operator-responsibility scope (Nuclei/ZAP-style)** — scans run open by
  default with a one-line authorization notice; `--scope` opts into a strict
  allowlist with DNS-rebinding pinning and upgrade-only http→https.
- **Fleet and surface tooling** — bulk `--target-file`/`--resume` runs with
  shared budgets, BFS crawler (`--max-pages`, `--depth`), content discovery
  with soft-404 learning, `gash diff` regression tracking, and `--proxy` for
  Burp/ZAP integration.
- **Aggressive profile** — full offensive opt-in: all detectors, all
  methods, 50k req/target, 100 req/s. Use only with written authorization.
- **WAF-aware, not stealthy** — WAF blocks become `WAFDetected` stats, never
  silent drops. Aggressive mode retries at most 5 scoped variants
  (header/HPP/encode/comment/case); block pages never count as evidence.
- **Fuzzing support** — `internal/fuzz` mutation helpers plus corpus-driven
  tests feed injection points without changing the evidence pipeline.
- **OOB, honestly gated** — out-of-band verification stays disabled unless
  `--oob-server` points at a self-hosted interaction server you control.
  `oob: required` plugins skip honestly (`oob-not-configured`).
- **Headless-deep path** — static DOM sinks report up to `firm` today;
  browser `confirmed` requires the headless build (`internal/headless`,
  `deep` build path) plus a clean control.
- **JUnit + SARIF** — SARIF 2.1.0 primary for CI code scanning, plus JSON,
  text, HTML, and JUnit. Tentative stays hidden unless `--show-tentative`.
- **Supply-chain + static gates in CI** — `govulncheck` dependency CVE scan
  and pinned `gosec` static scan run on every PR, alongside `go vet`,
  corpus, metric, contract, and bench gates.

## At a Glance

| Core | Plugins | Proof | Output |
|---|---|---|---|
| Go 1.26, toolchain go1.27.2 | YAML, sandboxed JS, trusted native gRPC | Control, repeat, baseline, context | SARIF, JSON, text, HTML, JUnit |

`safe` is the default. `deep`, `active`, `aggressive`, and OOB behavior are
explicit opt-ins. Scan only systems you own or have written permission to test.

## Reality Check

The current fixture corpus is measured and reproducible: the reflected XSS
dataset reports `TP=2 FP=0 TN=8 FN=0` at `static-execution-evidence`. That is a
corpus result, not a claim of real-world recall across every framework,
browser, WAF, or application shape.
Headless execution is implemented behind `-tags deep` (chromedp, verified
against real Chrome); a compose-lab recall run and a Nuclei comparison
remain tracked work in [`docs/known-limits.md`](docs/known-limits.md).

## How It Differs

Honest comparison — Gash is experimental (`v0.1.0-dev`, 51 reference
plugins) and competes on verification discipline, not on maturity or library
size. No Gash-versus-Nuclei benchmark has been run (not compared); see
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

## Try It in 60 Seconds

Prerequisite: Go 1.26+ (toolchain go1.27.2) on `PATH`. All commands run from
the repo root. Scan only targets you own or have explicit written permission
to test.

```sh
go run ./cmd/gash plugins list
go test ./...
go run ./cmd/gash plugins test plugins/xss/xss-reflected-basic.js
go run ./cmd/gash scan --target http://localhost:8080 --scope localhost
```

The last command is intentionally scoped to localhost. Replace it only with a
target you are authorized to test.

## Quickstart

Linux / macOS (`sh`) — copy-paste:

```sh
go run ./cmd/gash plugins list
go run ./cmd/gash plugins validate plugins/headers/missing-security-headers.yaml
go run ./cmd/gash plugins test plugins/headers/missing-security-headers.yaml
go run ./cmd/gash scan --target http://localhost:8080 --scope localhost
```

Windows (`PowerShell`) — copy-paste:

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

## Detector Summary

51 detectors via `go run ./cmd/gash plugins list`
(43 Tier 1 YAML, 7 Tier 2 sandboxed JS, 1 Tier 3 native PoC).
Full oracle/plugin catalog: `docs/detector-inventory.md`.

| Class | Count | Examples |
|---|---:|---|
| Cross-site scripting (reflected, stored, DOM) | 5 | `xss-reflected-basic`, `xss-attribute-injection`, `xss-stored-basic`, `xss-stored-two-step`, `dom-sink-basic` |
| SQL injection (error, boolean, time, stacked, auth-bypass, OOB) | 6 | `sqli-error-based`, `sqli-boolean-differential`, `sqli-time-based`, `sqli-stacked-time`, `sqli-auth-bypass`, `blind-sqli-oob` |
| XPath injection (error) | 1 | `xpath-injection-error` |
| NoSQL injection (error, auth-bypass differential) | 2 | `nosql-injection-error`, `nosql-auth-bypass-differential` |
| Command injection (error, timing) | 2 | `command-injection-error`, `command-injection-timing` |
| SSRF (blind OOB, cloud metadata) | 2 | `ssrf-blind-oob`, `ssrf-cloud-metadata` |
| XXE (OOB, reflected) | 2 | `xxe-oob`, `xxe-reflected-basic` |
| Template injection (SSTI) | 1 | `template-injection-reflection` |
| File / path (RFI, traversal, upload, backup exposure) | 4 | `rfi-remote-include`, `path-traversal-error`, `file-upload-unrestricted`, `backup-file-exposure` |
| Access control and logic (IDOR, LDAP, HPP x2, mass assignment, verb tampering) | 6 | `idor-differential`, `ldap-injection-differential`, `hpp-parameter-pollution`, `hpp-duplicate-emission`, `mass-assignment-basic`, `verb-tampering-bypass` |
| Misconfig and headers (security headers, cookie, CORS, CRLF, CSRF, clickjacking, JWT x2, version, GraphQL, host header, error disclosure, redirect, CVE, cache poisoning, rate limit) | 17 | `missing-security-headers`, `cookie-flags`, `cors-misconfig`, `crlf-header-injection`, `csrf-token-absence`, `clickjacking-frameable`, `jwt-token-exposure`, `jwt-alg-confusion`, `server-version-disclosure`, `graphql-endpoint-discovery`, `graphql-introspection-enabled`, `host-header-injection`, `error-message-disclosure`, `open-redirect-param`, `cve-dependency-scan`, `web-cache-poisoning-basic`, `missing-rate-limit` |
| Insecure deserialization (error signature) | 1 | `insecure-deserialization-error` |
| Subdomain takeover (unclaimed-service bodies) | 1 | `subdomain-takeover-basic` |
| Native PoC (Tier 3, explicit trust) | 1 | `poc-native-header-check` |
| **Total** | **51** | `go run ./cmd/gash plugins list` |

Engine-recon probes ship outside the plugin set: request smuggling
(GASH-033, `internal/smuggle`) and content discovery (GASH-028,
`internal/discovery`).

Evidence ladder: `tentative` -> `firm` / `static-execution-evidence` ->
`confirmed`. Timing caps at `firm`; browser `confirmed` needs the headless
build plus a clean control. OOB findings require a self-hosted callback
match. Counts above are plugin inventory, not real-target recall.

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
| `docs/known-limits.md` | BLOCKED and gap register (lab recall, benchmark, browser limits) |
| `docs/technical-audit-2026-10-14.md` | Latest technical audit, priorities, and measured status |
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

Scope enforcement is opt-in (Nuclei/ZAP-style operator responsibility).
Without `--scope` the scan runs in open mode: nothing is blocked and
cross-host and cross-scheme redirects and crawl links are followed, so only
scan systems you own or have explicit written permission to test. Pass
`--scope <cidr/domain,...>` to lock a strict allowlist (redirect
re-validation, upgrade-only http→https, downgrade never, DNS-rebinding
pinning). Leave OOB disabled unless you run the interaction server, and
stay on the `safe` default in CI and production. Never point active
probes, timing loops, or OOB payloads at third-party systems. Aggressive
mode requires written authorization. See `docs/SECURITY.md` for the full
policy (authorized target, scope allowlist, OOB opt-in, safe default);
review rejects any change that encourages unauthorized scanning.

## Legal

Gash is a testing tool for authorized security assessments only. You are
solely responsible for the targets you select and the payloads you enable;
using Gash against systems without prior written authorization may violate
computer-misuse laws (e.g. CFAA, UK CMA, TCK 243/244) and is prohibited by
this project. The authors accept no liability for misuse or damage.

## Credits

Developed by [@Xmar1881](https://github.com/Xmar1881).

Contributors: see the
[contributors page](https://github.com/Xmar1881/Gash/graphs/contributors) —
names are added here only with the contributor's consent (open a PR to add
yourself). No automated or placeholder names are listed.

## License

`AGPL-3.0-only`. Full text in `LICENSE`; see `COPYING` for the file layout
plus third-party attribution plan. All new code and docs carry SPDX headers;
Tier 3 SDK uses the same license.

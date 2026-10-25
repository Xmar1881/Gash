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
[![Go](https://img.shields.io/badge/Go-1.27-00ADD8?logo=go)](go.mod)
[![Toolchain](https://img.shields.io/badge/toolchain-go1.27.3-00ADD8)](go.mod)
[![CI](https://github.com/Xmar1881/Gash/actions/workflows/plugin-ci.yml/badge.svg?branch=main)](https://github.com/Xmar1881/Gash/actions/workflows/plugin-ci.yml)

> Evidence first. Plugins everywhere. Findings you can defend.

**Menu:** [Quickstart](#quickstart) · [Install](#installation) · [Detectors](#detector-summary) · [Docs](docs/README.md) · [Plugins](plugins/README.md) · [Contributing](CONTRIBUTING.md) · [Support](SUPPORT.md)

Gash is a Go-native, plugin-driven web security scanner for teams that care
about signal, explainability, and controlled execution. Plugins propose
candidates; engine-owned oracles decide whether those candidates deserve to
become findings.

Module `github.com/Xmar1881/Gash`, toolchain `go1.27.3`, license
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

## Current Status

| Area | Current state |
|---|---|
| Reference catalog | 183 plugins: 174 YAML, 7 sandboxed JavaScript, 1 native PoC, and 1 native Tier 2 check |
| Evidence model | Candidate -> oracle -> evidence -> finding; browser execution is required for browser-confirmed XSS |
| Scan engine | Shared retry, redirect, scope, rate, request-budget, response-size, cancellation, and scan-deadline controls |
| Discovery | BFS crawl, surface extraction, OpenAPI input, content discovery, passive JavaScript recon, SPA state/build scans, and optional browser crawl |
| Out-of-band checks | Disabled by default; self-hosted server or the bounded local provider must be explicitly selected |
| CI quality gates | Build, vet, vulnerability scan, static security scan, full tests, race tests, lint, fixture precision, corpus, contract, and benchmark gates |
| Local output | Scan reports stay under `reports/` and are intentionally ignored by Git |

This repository is in active development. The catalog and measurements are
auditable, but the project is not presented as a drop-in replacement for a
mature proxy or a broad commercial scanner. See [Known Limits](docs/known-limits.md)
and the [benchmark reports](docs/metrics/README.md) before interpreting recall
or comparison numbers.

## What's New / Highlights

- **183 detectors** — verify with `go run ./cmd/gash plugins list`
  (174 Tier 1 YAML, 7 sandboxed JS, 1 Tier 3 native PoC, 1 Tier 2 native;
  see Detector Summary below).
- **Framework-specific detectors (GASH-069..072)** — Next.js middleware
  authorization bypass (CVE-2025-29927) via a control-vs-bypass differential,
  Next.js image optimizer blind SSRF via OOB callback, secrets serialized into
  SPA state (Next/Nuxt/Redux/Apollo/Angular), and development-only build
  artifact markers. Secret values remain masked; no extra requests are made
  for the two engine-owned content scans.
- **Lab batch 2 (GASH-057..066)** — phpinfo/management-endpoint/directory-listing/
  source-map/SSI error signatures, Log4Shell JNDI OOB (header + query vectors),
  expression-language arithmetic canary, JSONP callback reflection, OAuth open
  redirect, and read-only WebDAV OPTIONS validation; Tier 1 YAML gained `paths`
  combined with parameter/payload injection and OOB token expansion in request
  headers and bodies.
- **Request-smuggling probe (GASH-033)** — raw-TCP CL.TE/TE.CL/TE.TE
  differential with dual-channel proof (follow-up divergence *and* delay),
  `firm` ceiling, aggressive-gated, bounded to 10 requests on one keep-alive
  connection.
- **Modern coverage pack** — 20 GET-only checks for browser-isolation headers,
  CSP/HSTS hardening, runtime disclosure, API consoles, monitoring endpoints,
  debug tooling, Git/env files, and Docker Compose exposure. Endpoint banners
  remain explicitly `tentative` until stronger behavioral proof exists.
- **Critical exposure pack** — 30 GET-only checks for cloud credentials,
  CI/CD secrets, orchestration APIs, admin consoles, debug pages, heap dumps,
  and control-plane endpoints. These use the `critical_exposure` oracle mode:
  a marker can produce at most `firm` confidence until stronger verification
  exists.
- **Rare platform pack** — 50 additional GET-only checks for cloud/provider
  keys, package-manager credentials, proxy admin APIs, service-mesh debug
  surfaces, CI/CD control planes, artifact registries, and identity metadata.
- **Login automation** — `--login-url` plus one credential set
  (`--login-pass-env` preferred) establishes a real form session through the
  policy pipeline; success requires an anonymous-control diff with no password
  field, failures become honest skip records (2FA/CAPTCHA never retries), and
  credentials never appear in reports or logs.
- **Multi-step workflow replay** — `--flow-seed` discovers a same-origin form
  workflow, replays it with fresh CSRF tokens, mutates one field, and checks
  downstream error/reflection/divergence plus an unauthenticated direct-access
  screen (GASH-068); every flow finding stays `tentative` and the flow feature
  adds no plugin of its own.
- **Operator-responsibility scope (Nuclei/ZAP-style)** — scans run open by
  default with a one-line authorization notice; `--scope` opts into a strict
  allowlist with DNS-rebinding pinning and upgrade-only http→https.
- **Fleet and surface tooling** — bulk `--target-file`/`--resume` runs with
  shared budgets, BFS crawler (`--max-pages`, `--depth`), content discovery
  with soft-404 learning, `gash diff` regression tracking, and `--proxy` for
  Burp/ZAP integration.
- **SPA-rendered surface discovery** — `--browser-crawl` (deep build + Chrome)
  renders crawled HTML app shells through the bounded headless browser,
  harvests script-created forms/links and observed XHR/Fetch endpoints, and
  feeds the normal injection surface. Cookie-only session seeding, GET/HEAD-only
  browser traffic, out-of-scope blocking, hard page/endpoint caps, and an honest
  skip when the build or browser is unavailable.
- **Aggressive profile** — full offensive opt-in: all detectors, all
  methods, 50k req/target, 100 req/s. Use only with written authorization.
- **WAF-aware, not stealthy** — WAF blocks become `WAFDetected` stats, never
  silent drops. Aggressive mode retries at most 5 scoped variants
  (header/HPP/encode/comment/case); block pages never count as evidence.
- **Fuzzing support** — `internal/fuzz` mutation helpers plus corpus-driven
  tests feed injection points without changing the evidence pipeline.
- **OOB, honestly gated** — out-of-band verification stays disabled unless
  `--oob-server` points at a self-hosted interaction server you control.
  `oob: required` plugins skip honestly (`oob-not-configured`). Multi-variant
  corpora use single-use tokens verified in one shared bounded window; no
  callback means no finding.
- **Headless-deep path** — static DOM sinks report up to `firm`; browser
  `confirmed` requires the headless build (`internal/headless`, `deep` build
  path) plus a clean control. Fragment/hash routes (`#/route?q=...`) are
  discovered from links, rendered SPA surfaces, and JS string literals, then
  exercised through `--browser-verify`; `dom-sink-basic` collapses duplicate
  per-route sink evidence. `--browser-verify` (needs `--active`) also
  re-checks eligible reflected-XSS findings and upgrades to `confirmed` only
  on trigger with clean control.
- **JUnit + SARIF** — SARIF 2.1.0 primary for CI code scanning, plus JSON,
  text, HTML, and JUnit. Tentative stays hidden unless `--show-tentative`.
- **Supply-chain + static gates in CI** — `govulncheck` dependency CVE scan
  and pinned `gosec` static scan run on every PR, alongside `go vet`,
  corpus, metric, contract, and bench gates.

## At a Glance

| Core | Plugins | Proof | Output |
|---|---|---|---|
| Go 1.27, toolchain go1.27.3 | YAML, sandboxed JS, trusted native gRPC | Control, repeat, baseline, context | SARIF, JSON, text, HTML, JUnit |

`safe` is the default. `deep`, `active`, `aggressive`, and OOB behavior are
explicit opt-ins. Scan only systems you own or have written permission to test.

## Reality Check

The current fixture corpus is measured and reproducible: the reflected XSS
dataset reports `TP=2 FP=0 TN=8 FN=0` at `static-execution-evidence`. That is a
corpus result, not a claim of real-world recall across every framework,
browser, WAF, or application shape.
Headless execution is implemented behind `-tags deep` (chromedp, verified
against real Chrome). The 2026-10-20 native lab (Juice Shop, DVWA, WebGoat)
measured all 22 independently verified scenarios: Gash standard
`TP=11 FP=0 TN=9 FN=2` (P=1.000, R=0.846), Gash deep `TP=12 FP=0 TN=9 FN=1`
(P=1.000, R=0.923), and Nuclei `TP=5 FP=0 TN=9 FN=8` (P=1.000, R=0.385).
Those are lab-scoped numbers, not a general superiority claim. They predate
the 2026-10-21 hash-route/browser-probe and benchmark-dedupe changes, so they
must be re-measured before being quoted as the current result; see
[`docs/metrics/native-lab-2026-10-20.md`](docs/metrics/native-lab-2026-10-20.md).

## How It Differs

Honest comparison — Gash is experimental (`v0.1.0-dev`, 183 reference
plugins) and competes on verification discipline, not on maturity or library
size. A same-target Gash-versus-Nuclei measurement now exists on the native
lab and fixture lab; it is small and lab-scoped, not a general parity claim.
See `docs/metrics/native-lab-2026-10-20.md` and
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

## Installation

| Method | Command |
|--------|---------|
| **Go install** (latest) | `go install github.com/Xmar1881/Gash/cmd/gash@latest` |
| **From source** | See [Building from Source](#building-from-source) below |

> Homebrew, Scoop, and Docker packages are not published yet. Use `go install`
> or build from source until those packaging paths are available.

### Building from Source

Prerequisite: Go 1.27+ (toolchain go1.27.3) on `PATH`.

```sh
# Clone and build
git clone https://github.com/Xmar1881/Gash.git
cd Gash
go test ./...
go build -o gash ./cmd/gash
./gash --help
```

Static builds only (`CGO_ENABLED=0`); artifacts land under `dist/` and are
never committed:

```sh
CGO_ENABLED=0 go build ./...
VER=$(git describe --tags --always 2>/dev/null || echo v0.1.0-dev)
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o dist/gash-$VER-linux-amd64 ./cmd/gash
CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -o dist/gash-$VER-windows-amd64.exe ./cmd/gash
CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 go build -o dist/gash-$VER-darwin-amd64 ./cmd/gash
CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go build -o dist/gash-$VER-darwin-arm64 ./cmd/gash
```

Windows note: `gash-*-windows-amd64.exe` is a console tool. Double-clicking
opens the interactive menu; use a terminal for command output or automation:

```powershell
.\dist\gash-v0.1.0-dev-windows-amd64.exe --help
.\dist\gash-v0.1.0-dev-windows-amd64.exe scan --help
.\dist\gash-v0.1.0-dev-windows-amd64.exe plugins list
```

## Quickstart

Interactive menu and command console (scan, plugins, bench, diff, suppress):

```sh
go run ./cmd/gash menu
# or run the binary with no arguments in a terminal
```

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

## Detector Summary

183 detectors via `go run ./cmd/gash plugins list`
(174 Tier 1 YAML, 7 Tier 2 sandboxed JS, 1 Tier 3 native PoC, 1 Tier 2 native).
Full oracle/plugin catalog: `docs/detector-inventory.md`.

| Class | Count | Examples |
|---|---:|---|
| Cross-site scripting (reflected, stored, DOM) | 6 | `xss-reflected-basic`, `xss-attribute-injection`, `xss-stored-basic`, `xss-stored-two-step`, `dom-sink-basic`, `xpath-injection-error` |
| SQL injection (error, boolean, time, stacked, auth-bypass, OOB) | 6 | `sqli-error-based`, `sqli-boolean-differential`, `sqli-time-based`, `sqli-stacked-time`, `sqli-auth-bypass`, `blind-sqli-oob` |
| XPath injection (error) | 1 | `xpath-injection-error` |
| NoSQL injection (error, auth-bypass differential, timing) | 3 | `nosql-injection-error`, `nosql-auth-bypass-differential`, `nosql-injection-timing` |
| Command injection (error, timing, **OOB**) | 3 | `command-injection-error`, `command-injection-timing`, `command-injection-oob` |
| SSRF (blind OOB, cloud metadata, internal port scan) | 3 | `ssrf-blind-oob`, `ssrf-cloud-metadata`, `ssrf-internal-port-scan` |
| XXE (OOB, blind OOB, reflected) | 4 | `xxe-oob`, `xxe-reflected-basic`, `xxe-blind-oob`, `xml-external-entity-blind` |
| Template injection (SSTI: reflection, blind timing, **OOB**) | 3 | `template-injection-reflection`, `ssti-blind-timing`, `ssti-blind-oob` |
| File / path (RFI, traversal, upload, backup, listing, source maps, **sensitive files**) | 8 | `rfi-remote-include`, `path-traversal-error`, `file-upload-unrestricted`, `backup-file-exposure`, `directory-listing`, `source-map-exposure`, `file-inclusion-rfi`, `sensitive-file-exposure` |
| Access control and logic (IDOR, LDAP x3, HPP x2, mass assignment, verb tampering, **GraphQL auth/DOS**) | 10 | `idor-differential`, `ldap-injection-differential`, `ldap-injection-blind`, `ldap-injection-oob`, `hpp-parameter-pollution`, `hpp-duplicate-emission`, `mass-assignment-basic`, `verb-tampering-bypass`, `graphql-auth-bypass`, `graphql-dos` |
| Misconfig and headers (security headers, cookie, CORS x2, CRLF, response splitting, CSRF, clickjacking, JWT x3, version, GraphQL x2, host header, method override, error disclosure, redirect x2, management endpoints, phpinfo, WebDAV, CVE, rate limit, **debug endpoints**) | 37 | `missing-security-headers`, `permissions-policy-missing`, `hsts-hardening`, `csp-unsafe-directives`, `cookie-flags`, `cors-misconfig`, `insecure-cors-preflight`, `server-header-disclosure`, `powered-by-disclosure` |
| Modern API and deployment exposure | 10 | `openapi-spec-exposure`, `swagger-ui-exposure`, `graphql-playground-exposure`, `prometheus-metrics-exposure`, `debug-toolbar-exposure`, `actuator-index-exposure`, `security-txt-exposure`, `git-config-exposure`, `environment-file-exposure`, `docker-compose-exposure` |
| Critical control-plane and secret exposure | 80 | `aws-credentials-exposure`, `azure-credentials-exposure`, `gcp-service-account-exposure`, `kubernetes-config-exposure`, `vault-api-exposure`, `docker-api-exposure`, `argo-cd-api-exposure`, `keycloak-admin-exposure`, `registry-catalog-exposure` |
| Insecure deserialization (error signature) | 1 | `insecure-deserialization-error` |
| Subdomain takeover (unclaimed-service bodies) | 1 | `subdomain-takeover-basic` |
| Web cache poisoning | 2 | `web-cache-poisoning-basic`, `cache-poisoning-host-header` |
| Injection (JNDI, expression language, SSI, JSONP, prototype pollution) | 5 | `log4shell-jndi`, `expression-language-injection`, `ssi-injection`, `jsonp-callback-injection`, `prototype-pollution-differential` |
| Framework-specific (Next.js middleware bypass, image optimizer SSRF) | 2 | `nextjs-middleware-bypass`, `nextjs-image-optimizer-ssrf` |
| Native PoC (Tier 3, explicit trust) | 1 | `poc-native-header-check` |
| **Total** | **183** | `go run ./cmd/gash plugins list` |

Engine-recon probes ship outside the plugin set: request smuggling
(GASH-033, `internal/smuggle`), content discovery (GASH-028,
`internal/discovery`), passive JavaScript reconnaissance (GASH-067,
`internal/discovery` + `internal/engine`; endpoint feeding plus masked
hardcoded-secret findings), SPA embedded-state secrets (GASH-071), and
development build markers (GASH-072).

Evidence ladder: `tentative` -> `firm` / `static-execution-evidence` ->
`confirmed`. Timing caps at `firm`; browser `confirmed` needs the headless
build plus a clean control. OOB findings require a self-hosted callback
match. Counts above are plugin inventory, not real-target recall.

## Docs Index

| Document | Audience |
|---|---|
| [docs/README.md](docs/README.md) | Categorized documentation index |
| [CONTRIBUTING.md](CONTRIBUTING.md) | Contribution flow, gates, checklist |
| [docs/plugin-development.md](docs/plugin-development.md) | Tier-independent author guide |
| [docs/yaml-plugin-spec.md](docs/yaml-plugin-spec.md) | Tier 1 YAML reference |
| [docs/js-plugin-spec.md](docs/js-plugin-spec.md) | Tier 2 JS reference (timing + execution bindings) |
| [docs/native-plugin-spec.md](docs/native-plugin-spec.md) | Tier 3 native reference |
| [docs/architecture.md](docs/architecture.md) | Full engine design (Phase 1) |
| [docs/evidence-standard.md](docs/evidence-standard.md) | Per-class proof rules (Faz 1 detail GASH-001..021; inventory through GASH-072) |
| [docs/design/00-scope.md](docs/design/00-scope.md) | Phase 0 scope decisions |
| [docs/SECURITY.md](docs/SECURITY.md) | Responsible use and reporting |
| [docs/user-guide-tr.md](docs/user-guide-tr.md) | Turkish beginner guide (Türkçe, profiles + aggressive) |
| [docs/getting-started.md](docs/getting-started.md) | Narrative tutorial for new users |
| [docs/faq.md](docs/faq.md) | Frequently asked questions |
| [docs/auth.md](docs/auth.md) | Auth contexts, dual-user BOLA matrix, and form login automation |
| [docs/api-discovery.md](docs/api-discovery.md) | OpenAPI test-plan flow |
| [docs/proto-checks.md](docs/proto-checks.md) | DNS/TLS/TCP checks and CAA gap |
| [docs/known-limits.md](docs/known-limits.md) | BLOCKED and gap register (lab recall, benchmark, browser limits) |
| [docs/technical-audit-2026-10-14.md](docs/technical-audit-2026-10-14.md) | Historical technical audit, priorities, and measured status |
| [docs/report-formats.md](docs/report-formats.md) | JSON/SARIF/text/HTML/JUnit contracts |
| [docs/benchmark.md](docs/benchmark.md) | Benchmark harness: datasets, verification, scoring, gates |
| [docs/ci-integration.md](docs/ci-integration.md) | CI gates (`--fail-on`, corpus, bench) |
| [docs/detector-inventory.md](docs/detector-inventory.md) | Oracle and plugin catalog |
| [docs/metrics/README.md](docs/metrics/README.md) | Precision and recall index |
| [templates/README.md](templates/README.md) | Copy-rename starters |
| [plugins/README.md](plugins/README.md) | Reference plugin index |
| [CHANGELOG.md](CHANGELOG.md) | Release history |

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
150 ms. The `gash bench` harness measures end-to-end TP/FP/TN/FN with
independently verified ground truth, cross-checks HTTP request counts, and
gates regressions against `bench/baselines/fixtures.json`
(`docs/benchmark.md`; first measured runs:
`docs/metrics/benchmark-fixtures-2026-10-19.md`). Lab procedures
(`docker-compose.lab.yml`: DVWA 2.0, Juice Shop 17.1.0, WebGoat 2023.8) are
manual and recorded per report. The first measured recall is the localhost
synthetic lab (`docs/metrics/lab-aggressive-local-2026-10-14.md`). The full
native lab is now measured (`docs/metrics/native-lab-2026-10-20.md`); Docker
compose reproduction remains unavailable in this environment
(`docs/metrics/lab-compose-2026-10-15.md`). Nuclei was compared on both the
native and fixture labs (`docs/metrics/nuclei-comparison-2026-10-14.md`).

## Community & Support

- **Issues**: [Bug reports & feature requests](https://github.com/Xmar1881/Gash/issues)
- **Support guide**: [SUPPORT.md](SUPPORT.md) — setup help, bug report checklist, version policy
- **Security**: [Private vulnerability reporting](https://github.com/Xmar1881/Gash/security/advisories/new)

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

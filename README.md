<!--
SPDX-License-Identifier: AGPL-3.0-only
Copyright (C) 2026 Xmar1881 / GASH contributors
Module: github.com/Xmar1881/Gash

File: README.md
What: GitHub landing page for operators, plugin authors, and contributors.
Why: One coherent entry point: product, menu, install, quickstart, evidence
     model, coverage, reports, limits, and license.
-->

<h1 align="center">Gash</h1>

<p align="center">
  <b>Evidence-first web security scanning</b><br>
  <sub>Plugins propose. Engine-owned oracles decide. Findings you can defend.</sub>
</p>

<p align="center">
  <a href="https://github.com/Xmar1881/Gash/actions/workflows/ci.yml"><img alt="CI" src="https://github.com/Xmar1881/Gash/actions/workflows/ci.yml/badge.svg?branch=main"></a>
  <a href="https://github.com/Xmar1881/Gash/actions/workflows/plugin-ci.yml"><img alt="Plugin CI" src="https://github.com/Xmar1881/Gash/actions/workflows/plugin-ci.yml/badge.svg?branch=main"></a>
  <img alt="Go 1.26+" src="https://img.shields.io/badge/Go-1.26%2B-00ADD8?logo=go">
  <img alt="Toolchain go1.27.3" src="https://img.shields.io/badge/toolchain-go1.27.3-00ADD8">
  <a href="LICENSE"><img alt="License: AGPL-3.0-only" src="https://img.shields.io/badge/license-AGPL--3.0--only-blue"></a>
</p>

<p align="center">
  A Go-native, oracle-gated web security scanner for CI pipelines, authorized
  assessments, and teams that need auditable evidence instead of alert volume.
</p>

<p align="center">
  <a href="#interactive-menu">Menu</a> ·
  <a href="#installation">Install</a> ·
  <a href="#quickstart">Quickstart</a> ·
  <a href="#scan-profiles">Profiles</a> ·
  <a href="#coverage">Coverage</a> ·
  <a href="docs/README.md">Docs</a> ·
  <a href="plugins/README.md">Plugins</a> ·
  <a href="CONTRIBUTING.md">Contributing</a>
</p>

> [!NOTE]
> Gash is experimental (`v0.1.0-dev`). Scan only systems you own or have
> explicit written permission to test. The default scope stays on the target's
> registrable domain; OOB is disabled until you configure it.

Gash is built around one rule: **a plugin can never mint a finding**. Every
check emits a candidate, and an engine-owned oracle compares it against a
control, a baseline, or a callback before confidence is assigned. The result is
a smaller set of findings you can explain line by line.

- **Reference catalog**: 438 plugins — 375 Tier 1 YAML, 62 sandboxed Tier 2
  JavaScript, 1 trusted Tier 3 native PoC — plus 13 engine-owned detectors.
- **Evidence first**: `Candidate → Oracle → Evidence → Finding`, with explicit
  `tentative`, `firm`, `static-execution-evidence`, and `confirmed` levels.
- **Safe operation**: same-site scope by default, budget and rate ceilings,
  honest skips, explicit deep/OOB opt-ins, and secret redaction in the UI.
  Use `--profile safe` for a strictly passive run.
- **Drop-in plugins**: one `.yaml` or `.js` file under `~/.gash/plugins/` or
  `GASH_PLUGIN_PATH`; no registry edits or enable flags.

## Interactive menu

The menu is the primary operator experience — the CLI is still the source of
truth, and every menu action maps to documented flags.

```sh
gash menu          # or run gash with no arguments in a terminal
gash menu --lang en
```

```text
  GASH › ◎ Scan                                        EN · 1/6
  ─────────────────────────────────────────────────────────────
   1 Scan   2 Plugins   3 Tools   4 Console   5 Status   6 Help
  ╭─ ◎ Scan ───────────────────────────────────────────────────╮
  │ Profiles: safe · standard · deep · aggressive · EVERYTHING │
  ╰────────────────────────────────────────────────────────────╯
  [1-6] tab · Enter open · n/< move · l language · :command · h help · q quit
  gash menu ❯
```

The interface starts in Turkish by default. Use `--lang en`, `GASH_LANG=en`,
or press `l` to switch; the tab table below shows the English surface.

| Tab | Key | Purpose |
|---|---|---|
| Scan | `s` / `1` | Target or bulk target file, profile, scope, proxy, auth, OOB, output |
| Plugins | `p` / `2` | List, inspect, validate, test, scaffold, trust, select, and configure plugins |
| Tools | `t` / `3` | Benchmark, OpenAPI plan, report diff, and suppressions; `b` `o` `d` `x` jump straight in |
| Console | `c` / `4` | Run any Gash command with history and `!!` replay |
| Status | `u` / `5` | Build, Chrome, Go, catalog count, proxy list, latest reports |
| Help | `h` / `6` | Shortcuts and the live command list |

Highlights that are menu-only conveniences:

- **Bulk targets**: point the target field at a file; each line becomes a
  target with its own same-site scope, plus `--output-dir` and `--resume`.
- **Proxy modes**: auto healthy list, direct (`--no-proxy`), one pinned proxy,
  or the full pool with per-request rotation.
- **Auth modes**: cookie, header, or real form login. Login upgrades the
  profile and adds `--active` automatically; the password is read from an
  environment variable.
- **Repeat and inspect**: `r` replays the last command; status `v` opens the
  latest report; secrets are masked in the command preview and history.
- **Live phase detail**: during a scan, each completed phase keeps its final
  summary and duration while the active phase updates in place (pages,
  endpoints, requests, findings, plugin counts); skipped phases state why, and
  every label/detail follows the TR/EN selection.

Full walkthrough: [docs/menu.md](docs/menu.md).

## Installation

| Method | Command |
|---|---|
| Go install | `go install github.com/Xmar1881/Gash/cmd/gash@latest` |
| From source | `git clone https://github.com/Xmar1881/Gash.git && cd Gash && go build -o gash ./cmd/gash` |
| Headless build | `go build -tags deep -o gash ./cmd/gash` (CGO + Chrome) |

Requires Go 1.26+ (toolchain pinned to `go1.27.3`). Standard builds are static
and browser-free. The `deep` build links chromedp and enables browser crawl and
browser verification when a Chrome/Chromium binary is available.

Homebrew, Scoop, and Docker packages are not published yet. CI builds and
cross-platform artifacts are produced from source; see
[`.github/workflows/release.yml`](.github/workflows/release.yml).

On Windows, double-clicking `gash.exe` opens the interactive menu. Use
PowerShell or Windows Terminal for scripted commands and machine-readable
output.

## Quickstart

```sh
# 1. See what is installed and what it expects
gash plugins list
gash plugins info xss-reflected-basic

# 2. Validate and test a plugin offline
gash plugins test plugins/headers/missing-security-headers.yaml

# 3. Scan a local target (authorized only)
gash scan --target http://localhost:8080 --profile safe

# 4. Open the guided menu
gash menu
```

A first authorized scan with explicit scope and reports:

```sh
gash scan \
  --target https://app.example.com \
  --scope app.example.com \
  --profile standard \
  --format json --format text \
  --output-dir reports
```

Aggressive mode is a deliberate opt-in and requires written authorization:

```sh
gash scan --target http://127.0.0.1:8081 --scope 127.0.0.1 \
  --profile aggressive --active --format json
```

## Scan profiles

The CLI default is `standard` (controlled active checks). Select `safe` for a
strictly passive run; `deep` and `aggressive` are explicit offensive modes.

| Profile | Active | Budget / target | Rate | Methods | Crawl |
|---|---|---:|---:|---|---|
| `safe` | no | 250 | 5 rps | GET/HEAD/OPTIONS | 20 pages, depth 2 |
| `standard` | yes | 2,000 | 10 rps | + POST | 50 pages, depth 3 |
| `deep` | yes + browser | 8,000 | 20 rps | + PUT/DELETE/PATCH | 200 pages, depth 5 |
| `aggressive` | full offensive | 50,000 | 100 rps | all methods | 500 pages, depth 10 |

Profiles set defaults; explicit flags win. Scope is independent of the profile:
without `--scope`, Gash derives the target's registrable domain (eTLD+1) and
does not follow external links. Use `--allow-external` to restore open mode or
`--scope` to pin a CIDR/domain allowlist.

## How evidence works

Every plugin compiles to the same `PluginSpec` IR and runs through one pipeline:

```text
Plugin → Candidate → Oracle → Evidence → Finding
                 ↑
       control / baseline / callback / differential
```

| Level | Meaning |
|---|---|
| `tentative` | A lead with weak or single-shot evidence; hidden unless `--show-tentative` |
| `firm` | Control-and-repeat evidence from the owning oracle |
| `static-execution-evidence` | Static sink/source proof; not browser-confirmed |
| `confirmed` | Strongest proof available for that class (browser trigger + clean control, verified OOB callback, or an oracle-specific proof) |

Confidence rules live in `internal/oracle`, not in plugins. A plugin that
returns a match without oracle proof is rejected. The same discipline applies
to fixture gates: precision must stay ≥ 0.99, and any `firm`-or-higher finding
on the clean corpus fails the build.

## Coverage

| Area | Examples |
|---|---|
| XSS | reflected, stored two-step, DOM sinks, attribute/path/header contexts |
| Injection | SQLi error/boolean/time/stacked/OOB, XPath, NoSQL, command, SSTI, Log4Shell |
| File and request | XXE, path traversal, RFI/LFI, upload, backup/source maps, request smuggling |
| Access control | IDOR/BOLA matrix, LDAP, HPP, mass assignment, verb tampering, GraphQL auth |
| Exposure | credentials, CI/CD and control planes, admin consoles, debug endpoints, Git/env/Docker files |
| Protocol and config | TLS/DNS/SSH/DB recon, security headers, cookies, CORS, JWT, host header |
| API and SPA | OpenAPI-driven surface, GraphQL, SPA state secrets, dev-build markers, browser crawl |

438 reference plugins and 13 engine detectors ship today. The full, auditable
list is in [docs/detector-inventory.md](docs/detector-inventory.md) and
[plugins/README.md](plugins/README.md). Run `gash plugins list` for the live
count in your checkout.

### Plugin tiers

| Tier | Format | Discovery | Trust |
|---|---|---|---|
| 1 | YAML, single request | automatic | reviewed source, no runtime |
| 2 | JavaScript, goja sandbox | automatic | no sockets or filesystem; host bindings only |
| 3 | native gRPC PoC | explicit | SHA-256 pinned per platform via `gash plugins trust` |

Scaffold a new check with `gash plugins new <id> --tier yaml|js`, add positive
and negative fixtures, and run the metric gate before opening a PR. See
[docs/plugin-development.md](docs/plugin-development.md).

## Reports, CI, and scale

- **Formats**: JSON, SARIF 2.1.0, text, HTML, and JUnit.
- **CI gate**: `--fail-on firm|confirmed`; SARIF integrates with GitHub code
  scanning. See [docs/ci-integration.md](docs/ci-integration.md).
- **Bulk scans**: `--target-file`, `--resume`, shared request budgets, and one
  aggregated summary.
- **Regression tracking**: `gash diff old.json new.json` and local
  `gash suppress` entries.
- **Proxy pools**: `--proxy`, `--proxy-file`, per-host or per-request rotation,
  cooldown, and automatic `.gash/proxies/alive.txt` discovery (`--no-proxy` to
  disable).
- **Auth**: cookie/header/basic, verified form login, and dual-user BOLA
  matrix. See [docs/auth.md](docs/auth.md).
- **OOB**: local listener, self-hosted API/interactsh, or explicitly selected
  public interactsh. No callback means no finding.

## Project status and limits

Gash is `v0.1.0-dev`. The catalog, fixtures, and measurements are auditable,
but the project is not a drop-in replacement for a mature proxy or a broad
commercial scanner. Measurements under `docs/metrics/` are lab- or
corpus-scoped and must not be read as general real-world recall. Known gaps,
browser constraints, and the benchmark scope are tracked in
[docs/known-limits.md](docs/known-limits.md).

## Documentation

| Document | Contents |
|---|---|
| [docs/README.md](docs/README.md) | Full documentation index |
| [docs/menu.md](docs/menu.md) | Interactive menu, tabs, console, status panel |
| [docs/getting-started.md](docs/getting-started.md) | Narrative CLI tutorial |
| [docs/plugin-development.md](docs/plugin-development.md) | Tier-independent plugin authoring |
| [docs/evidence-standard.md](docs/evidence-standard.md) | Per-class proof rules |
| [docs/architecture.md](docs/architecture.md) | Engine design and current implementation status |
| [docs/report-formats.md](docs/report-formats.md) | JSON/SARIF/text/HTML/JUnit contracts |
| [docs/known-limits.md](docs/known-limits.md) | Gaps, limits, and measurement scope |
| [docs/user-guide-tr.md](docs/user-guide-tr.md) | Turkish-language operator guide |
| [CHANGELOG.md](CHANGELOG.md) | Release history |

For AI agents and answer engines: [llms.txt](llms.txt) is the curated map,
[llms-full.txt](llms-full.txt) is the single-fetch digest, and
[AGENTS.md](AGENTS.md) documents the repository layout and mandatory gates.

## Community and security

- **Issues**: [bug reports and feature requests](https://github.com/Xmar1881/Gash/issues)
- **Support**: [SUPPORT.md](SUPPORT.md)
- **Vulnerability reporting**: [private security advisory](https://github.com/Xmar1881/Gash/security/advisories/new)
- **Contributing**: [CONTRIBUTING.md](CONTRIBUTING.md)

## Responsible use

Gash is for authorized security testing only. Without `--scope`, the scan is
limited to the target's registrable domain but is still an operator-responsibility
mode: you must have permission for every target and payload you enable. Do not
point active probes, timing loops, or OOB payloads at third-party systems.
Leave OOB disabled unless you operate the interaction server or deliberately
choose a third-party one. Aggressive mode requires written authorization. See
[docs/SECURITY.md](docs/SECURITY.md) and [docs/known-limits.md](docs/known-limits.md).

## License

AGPL-3.0-only. See [LICENSE](LICENSE) and [COPYING](COPYING). All source and
documentation files carry SPDX headers.

Developed by [@Xmar1881](https://github.com/Xmar1881). Contributor names are
added only with consent; see the
[contributors page](https://github.com/Xmar1881/Gash/graphs/contributors).

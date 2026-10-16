<!--
SPDX-License-Identifier: AGPL-3.0-only
Copyright (C) 2026 Xmar1881 / GASH contributors
Module: github.com/Xmar1881/Gash

File: CHANGELOG.md
What: Release history for the public repository.
Why: One place for what changed per version (Keep a Changelog style).
-->

# Changelog

All notable changes to GASH are documented here.
Format follows Keep a Changelog; versioning follows SemVer.
Dates are UTC.

## [Unreleased]

### Added

- Context-aware XSS reflection evidence: JavaScript strings/comments and inert
  JSON blocks no longer look executable; allowed contexts, execution payloads,
  clean controls, and CSP are enforced.
- WAF statistics now distinguish detection from verified bypass. Aggressive
  bypass counts require stable application responses and exclude auth,
  soft-404, challenge, error, and dynamic responses.
- BFS Web Crawler (`internal/discovery/crawl.go`): automated link following with
  robots.txt/sitemap.xml parsing, `--max-pages`, and `--depth` control.
- Multi-target bulk scanning (`cmd/gash/bulk.go`): `--target-file`, `--resume`,
  `--output-dir`, and aggregated `bulk_summary.json` reporting with strictly
  shared global request budgets.
- Upstream HTTP interception proxy support (`--proxy <url>`): full Burp Suite /
  OWASP ZAP integration wired to `probe.Client.Transport` with fail-closed
  preflight `--scope` firewall enforcement.
- Stored XSS two-step verification oracle (`internal/oracle/stored.go`) with
  isolated injection and rendering phases.
- Smart Content & Directory Discovery (`internal/discovery/content-discovery.go`):
  soft-404 baseline learning, embedded technology wordlists, and sensitive HEAD checks.
- Scan report diffing engine (`internal/reporter/diff.go`) for tracking regressions,
  fixed findings, and new vulnerabilities across recurring runs.
- Headless Chrome Deep XSS automated testing (`-tags deep`) wired into CI.
- New vulnerability detectors: CAA DNS verification, NoSQL injection error-based,
  and Web Cache Poisoning basic checks.

## [v0.1.0-dev] - 2026-10-13

### Added

- Phase 0: scope decisions (`docs/design/00-scope.md`, Go 1.26.8, cobra, goja).
- Phase 1: engine design (`docs/architecture.md`), evidence standard
  (`docs/evidence-standard.md`), Tier 3 gRPC contract (`proto/gash/v1/plugin.proto`).
- Phase 2: core infrastructure (schema/loader/registry, `PolicySession`,
  executor, baseline model, oracle library, replay harness, negative corpus,
  recall lab, OOB client). No vulnerability plugins yet at this gate.
- Phase 3: reference plugins (passive header, reflected XSS, error/boolean
  SQLi, open redirect, blind SSRF with mandatory OOB, one native Tier 3 POC),
  each with fixtures plus precision/recall reports under `docs/metrics/`.
- Phase 4: community surface (`CONTRIBUTING.md`, `gash plugins
  validate|test|list|info|new|trust`, `plugin-ci.yml`, docs, responsible-use
  policy). AI prompts excluded from the public tree (local `.ai-prompts/` only).

### Gates

- `go test ./...` green; `go vet ./...` clean.
- Corpus gate: zero `firm+` findings on the clean corpus (B4).
- Metric gate: reference-plugin precision >= 0.99.
- Warm discovery budget: 100 plugins under 150 ms (B8).

[v0.1.0-dev]: https://github.com/Xmar1881/Gash/releases/tag/v0.1.0-dev

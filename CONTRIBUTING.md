<!--
SPDX-License-Identifier: AGPL-3.0-only
Copyright (C) 2026 Xmar1881 / GASH contributors
Module: github.com/Xmar1881/Gash

File: CONTRIBUTING.md
What: Contributor guide for community plugins.
Why: Locks the plugin flow, metric gates, and style rules in one checklist.
-->

# Contributing to GASH

## Purpose

This guide covers community plugin contributions. Core engine changes follow
the same gates but need maintainer review. Plugin authors only need Tier 1
or Tier 2; Tier 3 stays maintainer-gated.

## Responsible Use

Scan only authorized targets. You must have written permission for every
host, network, and application in scope. Never point OOB payloads, active
probes, or timing loops at third-party systems. See `docs/SECURITY.md` for
the full policy; violations are rejected in review regardless of code quality.

## Plugin Contribution Flow

1. Scaffold a skeleton:
   ```sh
   go run ./cmd/gash plugins new my-check --tier yaml
   go run ./cmd/gash plugins new my-xss --tier js
   ```
   The generator writes the plugin file plus
   `tests/fixtures/<id>/positive/` and `tests/fixtures/<id>/negative/`.
2. Edit metadata and logic following `docs/plugin-development.md` plus the
   tier guide (`docs/yaml-plugin-spec.md`, `docs/js-plugin-spec.md`).
3. Validate offline:
   ```sh
   go run ./cmd/gash plugins validate <file>
   go run ./cmd/gash plugins test <file>
   ```
4. Add `docs/metrics/<id>.md` following `docs/metrics/README.md`
   (Precision, Recall, Corpus, Lab, Gate Verdict sections are mandatory).
5. Run the gates:
   ```sh
   go test ./...
   go vet ./...
   go test ./tests/corpus/ -run TestNoFalsePositives -v
   go test ./tests/plugins/ -run TestMetricGate -v
   ```
6. Open a pull request. `plugin-ci.yml` repeats every gate above plus
   schema sync, B11 grep, and the bench budget.

## PluginSpec Rules

The single source of truth is `internal/plugin/rules.go` (spec §4.1,
architecture §7.1). `schemas/plugin.schema.json` is generated from it;
never edit the schema by hand.

### Required Fields

`id`, `name`, `description`, `severity`, `tags`, `safe`, `deep`, `active`,
`requires_auth`, `phase`, `order`, `api_version`. Tier is set by the loader,
never by the author.

### Field Constraints

- `id`: slug `^[a-z0-9]+(-[a-z0-9]+)*$`, max 64. File name does not matter.
- `name`: 3-120 chars. `description`: 10-2000 chars, must state OOB needs.
- `severity`: `info|low|medium|high|critical` (advisory; the engine caps it).
- `tags`: at least one lowercase slug. `dom-xss` enables ExecutionOracle.
- `phase`: `recon|discovery|probe|deep`. `order`: 0-1000, low runs first.
- `max_requests`: 1-10000 when set. `api_version`: exactly `"1.0"`.

### Consistency Rules

- `safe=true && active=true` is invalid (R-01).
- `oob=required` needs `active=true` and `safe=false` (R-02, R-03).
- `oob=required` on an OOB-invalid oracle (`reflection`, `header`,
  `redirect`, `version`, `execution`) is invalid (G-03).
- Unknown `requires` entries (R-09), unknown `overrides` targets (R-08),
  and `api_version != "1.0"` (R-10) fail closed.
- Warnings (not errors): `deep` without `phase: deep` (R-04), `critical`
  with `safe: true` (R-05), `tests: ""` (R-06), `phase: deep` with
  `deep: false` (R-12).

### Policy Notes

`safe`, `deep`, `active`, `requires_auth`, `requires_tech`, `oob`, and scope
are enforced by the engine (`PolicySession` plus scheduler). Declarations
are hints, never guarantees. `safe: true` plugins can only send
GET/HEAD/OPTIONS; violations return `ErrPolicyViolation` without stopping
the scan.

## Fixture Requirement

Every plugin ships `positive/` (must accept) and `negative/` (must not reach
`firm` or above) JSON fixtures under the `tests` directory named in metadata.
Empty `tests` limits all findings to `tentative` (R-06); the reference gate
(`TestMetricGate`) additionally requires warning-free metadata plus a metrics
report, so fixtures are effectively mandatory for contributed plugins.

- Positive cases pin `expected_verdict: accept` and the expected confidence.
- Negative cases must cover the nearest miss: encoded reflection, text-only
  context, WAF block page, SPA catch-all, hardened headers, clean control.
- `gash plugins test` runs both sets offline through engine-owned oracles
  and prints per-case PASS/FAIL plus precision and recall.

## Precision Gate

Precision must stay at or above **0.99**. The gate is a test, not a review
convention:

```sh
go test ./tests/plugins/ -run TestMetricGate -v
go run ./cmd/gash plugins test plugins/<category>/<file>
```

`TestMetricGate` validates the spec, requires zero warnings, runs fixtures,
checks precision, and requires `docs/metrics/<id>.md` with Precision,
Recall, Corpus, Lab, and Gate Verdict sections. Below 0.99 fails the build.

## Corpus Gate

The global negative corpus (`tests/corpus/`) must yield zero `firm` or above:

```sh
go test ./tests/corpus/ -run TestNoFalsePositives -v
```

The rule covers clean apps, SPA catch-all, WAF blocks, encoding apps, and
dynamic pages. Any `firm+` finding fails the build (B4). Design fixtures so
the same oracle that confirms your positive rejects every corpus shape.

## Code Style

- Every `context.Context` is threaded for deadline and cancel; no blocking
  call without it.
- Wrap errors with `fmt.Errorf("...: %w", err)`; match with `errors.Is/As`.
- New Go code and docs use English headers plus `What:`/`Why:` doc comments.
- `golangci-lint` and `go vet` must pass:
  ```sh
  go vet ./...
  golangci-lint run ./...
  ```
- No hardcoded check counts or names in `internal/`, `cmd/`, or `pkg/`
  (B11; enforced by grep in CI).
- Do not commit AI prompts or local scanner state (`.ai-prompts/`, `.gash/`,
  and `dist/` are gitignored and never part of a pull request).

## Tier 3 Trust File

Tier 3 approvals live in `~/.gash/trust.db` by default, overridable with
`--trust-file` or `GASH_TRUST_FILE`. Legacy `~/.gash/trust.json` files are
read automatically on first default-path use and copied to `trust.db`
without modifying the legacy file. Explicit overrides never migrate.

## Pull Request Checklist

- [ ] `validate` passes; `test` passes with precision >= 0.99.
- [ ] Positive plus negative fixtures present; metrics report added.
- [ ] `go test ./...` green; `go vet ./...` clean.
- [ ] No world-writable files; Tier 3 changes include trust notes.
- [ ] Responsible-use statement (authorized target only) in the PR body.

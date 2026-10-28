<!--
SPDX-License-Identifier: AGPL-3.0-only
Copyright (C) 2026 Xmar1881 / GASH contributors
Module: github.com/Xmar1881/Gash

File: docs/ci-integration.md
What: CI/CD contract for `gash scan` (exit codes, fail-on, JUnit/SARIF).
Why: Automation needs a stable machine contract, not terminal text.
-->

# CI Integration

## Exit codes

| Code | Meaning |
|---|---|
| `0` | Scan completed; `--fail-on` gate (if set) not triggered. |
| `1` | CLI/validation error, **or** `--fail-on` gate triggered. |
| other | Tool/runtime failure (network, timeout, crash). |

`--fail-on` maps to confidence, not severity:

`static-execution-evidence` is intentionally below `firm`: it is reportable
static evidence, but it does not trigger either CI threshold until a stronger
verification path exists.

| `--fail-on` | Triggers on |
|---|---|
| `firm` | Any `firm` **or** `confirmed` finding. |
| `confirmed` | Only `confirmed` findings. |
| unset | Never fails the build (report only). |

`tentative` findings never trigger the gate (and are hidden unless
`--show-tentative` is passed).

## Recommended invocations

```sh
# Blocking gate on verified findings, SARIF for code scanning:
gash scan --target https://app.example.com --scope app.example.com \
  --format sarif --output gash.sarif --fail-on confirmed

# JUnit for test-style CI views (Jenkins/GitLab/ADO):
gash scan --target https://app.example.com --scope app.example.com \
  --format junit --output gash-junit.xml --fail-on firm
```

Multiple `--format` values print to stdout; `--output` requires exactly one
`--format` (machine-readable files stay parseable).

## JUnit mapping (`--format junit`)

- One `<testsuite name="gash <target>">` per scan.
- Each visible finding is a `<testcase classname="gash.<rule>">`:
  - `firm`/`confirmed` → `<failure type="vulnerability">` (fails the suite).
  - `tentative` → `<skipped>` (weak signal, review with `--show-tentative`).
- Each skipped plugin is a `<skipped>` testcase with the scheduler reason
  (audit trail: nothing is silently dropped).

## SARIF mapping (`--format sarif`)

SARIF v2.1.0, one `run` with tool `gash`:

- `confirmed` → `error`, `firm` → `warning`, `tentative` → `note`
  (tentative only with `--show-tentative`).
- `fingerprints: {"gash/v1": "<fp>"}` enables baseline/diff workflows.
- `properties: {"evidenceType": "<static-execution-evidence|browser-confirmed|...>",
  "confidence": "<confidence>"}` records the §8 evidence discriminator
  (static parser proof vs controlled browser execution).

## GitHub Actions example

```yaml
- name: GASH scan
  run: |
    go run ./cmd/gash scan --target https://app.example.com \
      --scope app.example.com --profile standard \
      --format sarif --output gash.sarif --fail-on confirmed
- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: gash.sarif
```

The repository's own workflow (`.github/workflows/plugin-ci.yml`) runs the
fixture/metric gates; use the snippet above for *target* scanning in your
pipeline.

## GitLab example

```yaml
gash-scan:
  script:
    - go run ./cmd/gash scan --target https://app.example.com
        --scope app.example.com --format junit
        --output report.xml --fail-on firm
  artifacts:
    reports:
      junit: report.xml
```

## Baseline diff (fail only on new findings)

Leave existing findings alone, fail only when a *new* fingerprint appears:

- Matching key is the stored `fingerprint` (`finding.Fingerprint`:
  URL + evidence based, never line-based). Reordered reports stay
  `UNCHANGED`; suppress entries keep working because they use the same key.
- `gash diff` exit codes mirror `scan --fail-on`: `0` = no NEW (or no gate),
  `1` = `--fail-on new` triggered or CLI/validation error.

```sh
# 1. Scan current commit (JSON keeps fingerprints):
gash scan --target https://app.example.com --scope app.example.com \
  --format json --output current.json

# 2. Compare against the checked-in baseline (do not touch old findings):
gash diff --old baseline.json --new current.json --format text --fail-on new

# Machine-readable form for artifact upload:
gash diff --old baseline.json --new current.json --format json > diff.json
```

GitHub Actions example (baseline stored as an artifact):

```yaml
- name: GASH scan (current)
  run: |
    go run ./cmd/gash scan --target https://app.example.com \
      --scope app.example.com --profile standard \
      --format json --output current.json
- name: Download baseline
  uses: actions/download-artifact@v4
  with:
    name: gash-baseline
    path: .
- name: Fail only on new findings
  run: |
    go run ./cmd/gash diff --old baseline.json \
      --new current.json --format text --fail-on new
```

Triage loop: fix what you can, then promote `current.json` to
`baseline.json` only after review — never auto-overwrite the baseline on
green builds.

## Safety notes for CI

- Always pass `--scope` for non-local targets; external targets without
  scope only warn (they still scan — scope is your allowlist proof).
- Keep `--profile safe` (passive-only) unless the pipeline explicitly approves
  active payloads. The CLI default is `standard` (controlled active);
  `--active`/`--deep`/`--oob-server` remain explicit opt-ins.
- Authenticated scans need `--auth-header`/`--cookie`/`--basic-auth`
  (see `docs/auth.md`); secrets must come from CI secret storage, never
  from the repository. Values never appear in reports (redacted summaries only).

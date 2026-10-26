<!--
SPDX-License-Identifier: AGPL-3.0-only
Copyright (C) 2026 Xmar1881 / GASH contributors
Module: github.com/Xmar1881/Gash

File: AGENTS.md
What: Repository instructions for AI coding agents.
Why: One factual orientation file so agents change Gash without breaking its gates.
-->

# AGENTS.md

Operating instructions for AI coding agents working in the Gash repository.
Read this before editing. It states what the project is, where things live, and
which gates a change must clear.

## Project in one paragraph

Gash is a Go-native, plugin-driven web security scanner. Plugins propose
candidates; engine-owned oracles decide findings. Nothing in this repository may
allow a plugin to mint a finding on its own. The pipeline is
`Candidate -> Oracle -> Evidence -> Finding`. License: AGPL-3.0-only. Status:
experimental `v0.1.0-dev`. Human-facing overview: `README.md`; documentation
index: `docs/README.md`; LLM map: `llms.txt`.

## Layout

| Path | Contents |
|---|---|
| `cmd/gash` | CLI entry point (Cobra commands: `scan`, `plugins`, `bench`, `menu`, `diff`, `suppress`) |
| `internal/engine` | Scan orchestration, budgets, detector registry wiring, report output |
| `internal/detector` | Detector port: `Spec`, `Detector`, `Registry`, `Env`, policy/gating |
| `internal/oracle` | Engine-owned oracles that decide confidence (`reflection`, `stored`, `error`, `differential`, `timing`, `oob`, `header`, `cookie`, `cors`, `redirect`, `version`, `execution`, `upload-served`, ...) |
| `internal/plugin` | Plugin IR (`PluginSpec`), validation, registry |
| `internal/plugin/loader` | Tier 1 YAML loader, Tier 2 goja sandbox + host bindings, Tier 3 gRPC client |
| `plugins/` | Reference plugin catalog (YAML, JS, native manifest) |
| `tests/fixtures/` | Per-plugin positive/negative fixture JSON |
| `tests/plugins/` | Fixture/`TestMetricGate` and Tier 2 end-to-end tests |
| `tests/corpus/` | Zero-false-positive corpus gate |
| `tests/contract/` | Contract tests, including detector-inventory parity |
| `docs/` | Plain-Markdown documentation (no site build) |
| `docs/metrics/` | Per-plugin precision/recall reports (dataset hash pinned) |

## Commands

```sh
go build ./...                                  # standard build (no CGO)
go build -tags deep ./cmd/gash                  # headless-browser build (CGO + Chrome)
go test -short ./...                            # fast test set (used by CI)
go test -count=1 ./...                          # full test set
go vet ./...
gofmt -l internal cmd tests plugins templates proto   # formatting gate
go test ./tests/plugins/ -run TestMetricGate     # per-plugin fixture + precision gate
go test ./tests/corpus/ -run TestNoFalsePositives
go run ./cmd/gash plugins list                   # live catalog (prints the plugin count)
go run ./cmd/gash plugins test <plugin-file>     # run one plugin's fixtures
```

## Non-negotiable rules

1. **Evidence discipline.** A plugin never decides a verdict. It emits a
   candidate with an oracle reference; confidence comes from the oracle. Do not
   add code that lets a plugin (or a detector) self-confirm.
2. **Nothing hardcoded in the engine.** Scanning logic lives in plugins or in
   engine detectors behind the `internal/detector` port. Do not add
   vulnerability-specific rules to `internal/engine` or `internal/oracle`
   outside an oracle's documented proof rules.
3. **Detector-inventory parity.** The detector registry and
   `docs/detector-inventory.md` must stay in sync; `tests/contract` enforces it.
4. **Every plugin ships fixtures and metrics.** A new plugin needs
   `tests/fixtures/<id>/{positive,negative}/*.json`, a `docs/metrics/<id>.md`
   report, and an entry in `plugins/README.md` and
   `docs/plugin-coverage-matrix.md`. `TestMetricGate` fails without them.
5. **Precision gate.** Fixture precision must be ≥ 0.99 and no `firm`-or-higher
   false positive may appear on the clean corpus.
6. **Tier rules.** Tier 1 YAML is single-step only. Multi-step or correlated
   logic belongs in Tier 2 JS and must declare its parameters in the frontmatter
   `oracle_params` block. Tier 3 native plugins are SHA-256 pinned and never run
   on discovery alone; they have no raw-socket access.
7. **Defaults stay safe.** The `safe` profile is passive. New checks that send
   attack traffic are `active`, and OOB-dependent checks must skip honestly
   (`oob-not-configured`) when no self-hosted server is configured.
8. **Headers.** Every Go and Markdown file carries the SPDX header used across
   the repository (`SPDX-License-Identifier: AGPL-3.0-only`).
9. **Verification is mandatory.** Before finishing: `gofmt`, `go vet ./...`,
   `go build ./...`, and `go test -count=1 ./...` must be clean.

## Adding a plugin

1. Scaffold: `go run ./cmd/gash plugins new <id> --tier yaml` (or `--tier js`).
2. Implement the check; pick the oracle that matches the evidence you can
   actually collect.
3. Add `positive/` and `negative/` fixtures.
4. Add `docs/metrics/<id>.md`; pin the dataset hash by running the metric gate
   with `UPDATE_METRICS=1`.
5. Update `plugins/README.md` and `docs/plugin-coverage-matrix.md`.
6. Run the metric gate for the new plugin and the full test set.

## Do not

- Do not invent benchmark or recall numbers. Quote `docs/metrics/` and state the
  lab/corpus scope; the project deliberately keeps those claims small.
- Do not add a runtime dependency for something the standard library or an
  existing dependency already covers.
- Do not reword the license or remove SPDX headers.
- Do not commit secrets, generated reports (`reports/`), or build artifacts.

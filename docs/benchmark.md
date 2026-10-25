<!--
SPDX-License-Identifier: AGPL-3.0-only
Copyright (C) 2026 Xmar1881 / GASH contributors
Module: github.com/Xmar1881/Gash

File: docs/benchmark.md
What: How the automated benchmark works: datasets, independent verification,
  equal-conditions runs, scoring, reports, baselines, and CI.
Why: The benchmark refuses self-reported success; every scenario must verify
  independently before it can be scored, and every number must be reproducible.
-->

# Benchmark

`gash bench` is the repository's measurement harness: YAML ground-truth
datasets, an independent verifier that never consumes scanner output, an
equal-conditions Gash/Nuclei comparison, deterministic metrics
(TP/FP/TN/FN, precision/recall/F1, duration, HTTP requests), honest reports,
and a baseline regression gate. It refuses non-loopback targets by default.

## Datasets

| Dataset | Target | Notes |
|---|---|---|
| `bench/datasets/fixtures.yaml` | In-process fixture lab (127.0.0.1, no docker) | 50 scenarios: reflected/stored/DOM XSS, SQLi, traversal, CMDi, redirect, clean, denied, soft-404, WAF, timeout, auth matrix, exposure artifacts |
| `bench/datasets/fixtures-deep.yaml` | Same lab | 50 scenarios with `--profile deep --deep --browser-verify` and larger budgets |
| `bench/datasets/compose-lab.yaml` | Docker compose lab (DVWA 8081, Juice Shop 8082, WebGoat 8083) | Requires docker; runtime ground truth unverified where docker is absent |
| `bench/datasets/native-lab.yaml` | Native Windows lab (same three applications, no docker) | 22 scenarios; placeholder DVWA sessions; independent verification requires `-tags deep` + Chrome for DOM |

Validate any dataset without scanning:

```sh
gash bench validate bench/datasets/fixtures.yaml
```

Validation enforces strict schema (unknown fields rejected), unique scenario
ids, known verify kinds, lab-only base URLs (`--allow-non-lab` is an explicit
unsafe opt-in), and records the dataset SHA-256 used by the gate.

## Running

```sh
# standard fixture benchmark, gash only
gash bench run --dataset bench/datasets/fixtures.yaml --tool gash --out dist/bench

# deep build with real headless-Chrome browser verification
go build -tags deep -o dist/gash-deep.exe ./cmd/gash
dist/gash-deep.exe bench run --dataset bench/datasets/fixtures-deep.yaml --tool gash --out dist/bench-deep

# comparison (requires nuclei in PATH; reported as N/A with a reason otherwise)
gash bench run --dataset bench/datasets/fixtures.yaml --tool gash,nuclei --out dist/bench-cmp

# regression gate against a committed baseline
gash bench run --dataset bench/datasets/fixtures.yaml --tool gash \
  --baseline bench/baselines/fixtures.json --fail-on-regression

# extract a compact baseline from a report
gash bench baseline --report dist/bench/report.json --tool gash --out bench/baselines/fixtures.json

# compare two reports without scanning
gash bench compare --baseline bench/baselines/fixtures.json --current dist/bench/report.json
```

The compose lab lifecycle (docker required) is `gash bench lab up|down|reset|status`.

## Independent verification

Every scenario carries a `verify:` procedure that the harness runs against the
lab **before** scoring, with a unique per-run marker: `http-reflection`
(marker echo), `http-error` (attack-only signature), `http-stored` (two-request
store+render), `http-json-raw`, `http-clean` (no raw marker), `http-denied`,
`http-soft404`, `http-waf` (attack 403 vs benign 200), `http-timeout`,
`http-redirect` (external Location), and `browser-exec` (controlled headless
Chrome canary trigger plus a neutral control that must stay clean). Scenarios
that fail verification are listed under `unverified_scenarios` and are
**excluded from scoring** — never counted as passes or failures.

## Scoring rules

- **Firm-only by default.** Tentative candidates are never scored; when a
  dataset opts in with `--show-tentative`, tentative findings are listed in a
  separate `tentative` column and remain unscored.
- **TP/FP/TN/FN per scenario**, matched by normalized path plus declared
  `plugin_ids`/`rule_ids` (Gash) or `nuclei_tags` (Nuclei). A finding on any
  non-vulnerable scenario is an FP; a finding matching no scenario is listed
  under `unmatched_findings` (or `excluded_findings` when the dataset declares
  the plugin/rule out of scope).
- **XSS is judged by evidence tier.** A scenario with
  `xss.execution_required: true` counts as TP only with a `browser-confirmed`
  finding; static-execution evidence is scored `weak-evidence` (counts against
  recall, is never reported as confirmed). The harness's own `browser-exec`
  verification and the engine's `--browser-verify` upgrade are independent.
- **Static/active TP and browser-confirmed TP are separate.** Every TP is
  assigned exactly one of `static_active_tp` (non-browser-confirmed) or
  `browser_confirmed_tp` (a matched `browser-confirmed` finding). The legacy
  `confirmed_tp` field remains as an alias for `browser_confirmed_tp`.
  Therefore `static_active_tp + browser_confirmed_tp = tp`, and
  `static_active_tp` never means "browser-confirmed". Weak candidates are
  counted in both `weak_evidence` and `candidate_weak`.
- **Blocked, error, and unverified stay out of denominators.** `blocked` and
  `error` are subsets of `unverified`; they are reported for audit and are
  never converted to FP/FN/TN. Precision is `TP/(TP+FP)`, recall is
  `TP/(TP+FN+weak_evidence)`, and F1 is the harmonic mean of the two when both
  are defined.
- **Not-run beats fabricated.** An unavailable tool produces `not_run`
  outcomes and `null` precision/recall with a written reason (N/A), never zero.
- Requests are cross-checked: tool-reported (`stats.http_requests`) versus
  lab-observed counters.

## Reports

`bench run` writes a report directory (default `bench/results/<timestamp>/`):
`report.json` (full machine-readable), `summary.md`, `report.html`,
`findings.csv`, `manifest.json` (versions, dataset hash, git commit, lab
request counters, equal-conditions notes), plus unverified and missed lists
inside the JSON. Failed and missed scenarios are always listed with their
verification detail.

## Baseline gate

`bench/baselines/fixtures.json` is the committed reference for the standard
fixture run (extracted with `bench baseline` from a real measured run).
`bench compare`/`--baseline` enforce: precision ≥ 0.99, no recall drop
(overall or per category), at most +25% HTTP requests, at most +50% wall-clock.
A dataset hash mismatch fails comparability instead of comparing apples to
oranges. Recall becoming unmeasurable (no scored positives) is treated as a
regression.

## CI

- **PR gate (`plugin-ci.yml`)**: bench unit tests plus the end-to-end
  critical-detector test (`go test ./internal/bench/`), which runs a real gash
  binary against the fixture lab and fails on any false positive, any
  not-run outcome, or a reflected-XSS detection regression.
- **Nightly (`bench-nightly.yml`)**: baseline-gated standard run, deep run
  with real Chrome browser verification, and a Gash/Nuclei comparison run
  (nuclei installed upstream with templates; install failure fails the job
  rather than silently dropping the comparison). Artifacts uploaded.
  The compose-lab dataset is opt-in via `workflow_dispatch`.

## Known measured limits (honest, not bugs to hide)

These were observed with the current engine and are reported by the benchmark,
not worked around by the harness:

- DOM XSS findings from the engine are static source-to-sink evidence; the
  benchmark keeps them `weak-evidence` unless a real browser confirms
  execution. `dom-sink-basic` now keeps query (`?q=`), raw-hash (`#payload`),
  and hash-route (`#/route?q=`) points as independent tests, correlates a
  source and sink only when they share one inline script, and records the
  evidence stages (`source_observed`, `sink_observed`, `source_sink_linked`,
  `execution_confirmed`, `control_result`). Node insertion alone is not
  execution. The deep build's `--browser-verify` pass checks GASH-003 DOM
  findings (including fragment/hash points) and `dom-sink-basic` collapses
  duplicate per-route sink/source evidence. The standard profile disables the
  execution detector, so `dom-sink-basic` is skipped there; even a deep build
  without `--browser-verify` has no browser proof and stays weak.
- The stored two-step browser proof runs only for attempts that already
  accept static evidence, so a static reject is never browser-retried.
- Equalization with Nuclei is wall-clock plus rate limit; Nuclei cannot cap
  total requests upstream.

The three engine limits measured on 2026-10-19 (Tier 1 endpoint discovery,
Tier 2 send-budget ordering, stored two-step timeout/control) were fixed the
same day and re-measured: standard recall 0.500 -> 1.000, deep recall
0.455 -> 0.909 (only the DOM weak outcome remains). Before/after evidence:
`docs/metrics/benchmark-fixtures-2026-10-19.md`.

## Measured results

- `docs/metrics/native-lab-2026-10-20.md`: full 22-scenario native lab on
  Juice Shop, DVWA, and WebGoat. Gash standard `TP=11 FP=0 TN=9 FN=2`, deep
  `TP=12 FP=0 TN=9 FN=1`, Nuclei `TP=5 FP=0 TN=9 FN=8`; all 22 scenarios
  independently verified in both runs.
- `docs/metrics/benchmark-fixtures-2026-10-19.md`: initial measured runs,
  the control-request bug they surfaced, the three recall fixes with
  before/after numbers, and the final standard/deep results.
- `docs/metrics/nuclei-comparison-2026-10-14.md`: the measured Gash/Nuclei
  comparison on the fixture lab (cross-tool verdicts, per category).
- Pre-fix fixture comparison (standard profile, 2026-10-22 run): Gash
  `TP=24 FP=0 TN=23 FN=2` precision=1.000 recall=0.923 F1=0.960;
  Nuclei `TP=1 FP=0 TN=23 FN=25` precision=1.000 recall=0.038 F1=0.074;
  cross-tool verdicts and per-category breakdown were recorded in the run
  output; no standalone report was committed.
- `dist/bench-std-final/` and `dist/bench-deep-final/`: final fixture runs
  with open-redirect-next and path-traversal-file-access fixes.
  Standard: `TP=26 FP=0 TN=23 FN=0` (1 unverified `xss-dom-hash-sink`),
  `P=R=F1=1.000`, 1m29s, 5922/5929 requests.
  Deep: `TP=27 FP=0 TN=23 FN=0`, `P=R=F1=1.000`, 6m54s, 7328/7556 requests.
- `bench/baselines/fixtures.json`: committed regression baseline, refreshed
  from the final standard run (TP=26, recall 1.000).

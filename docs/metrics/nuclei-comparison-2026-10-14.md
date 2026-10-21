<!--
SPDX-License-Identifier: AGPL-3.0-only
Copyright (C) 2026 Xmar1881 / Gash contributors
Module: github.com/Xmar1881/Gash

File: docs/metrics/nuclei-comparison-2026-10-14.md
What: Honest Nuclei comparison: status plus the first measured comparison.
Why: Early parity claims were unmeasured; the measurement now exists and is
filed with numbers and the remaining BLOCKED limits.
-->

# Nuclei Comparison (status 2026-10-14; measured 2026-10-19 and 2026-10-20)

## Status (historical, pre-harness)

Not compared at that date. No controlled benchmark between Gash and Nuclei had
been run in this repository then: no shared target set, no fixed network and
request budget, no equivalent template selection, and no precision/recall
harness spanning both tools. Any parity claim would have been unmeasured and
is therefore absent from the README, the detector inventory, and this report.

## Update (2026-10-19): the harness exists; the comparison is now measured locally

The required harness below has been built (`gash bench`, see
`docs/benchmark.md`): same-target same-scope runs, pinned request budgets,
lab-observed request counters, per-scenario verification, cross-tool verdicts,
and a regression gate. It produced first measured Gash-only runs
(`benchmark-fixtures-2026-10-19.md`).

Nuclei v3.11.1 was installed with the default template set (14,102 YAML
templates) and the comparison ran locally on the same fixture lab with both
tools; the measured tables are in "Measured (2026-10-19)" below. What remains
unmeasured is the Docker compose dataset, because docker is absent in this
environment -- that stays BLOCKED, never a fabricated number. The same three
applications were later measured natively (Juice Shop, DVWA, WebGoat) in
`native-lab-2026-10-20.md`; the compose procedure itself remains unexecuted.
The nightly CI workflow (`bench-nightly.yml`) still files the automated
fixture comparison artifact.

## What Exists Instead

- Honest capability table in `README.md` (`How It Differs`): engine plus
  oracle-gated plugin runner versus template breadth, proxy coverage, and
  manual depth. Maturity and library size are marked as Nuclei/ZAP/Burp
  strengths, not Gash strengths.
- Fixture-scoped precision per plugin (`docs/metrics/<id>.md`, gate 0.99)
  and one measured localhost synthetic recall
  (`lab-aggressive-local-2026-10-14.md`). Both are Gash-only; neither
  compares tools.
- Reproduction commands for the Gash side only:
  `go test ./tests/plugins/ -run TestMetricGate -v`,
  `go test ./tests/corpus/ -run TestNoFalsePositives -v`.

## Required Harness Before Any Claim

1. Same target set (localhost lab plus pinned compose images), same scope
   allowlist, same per-target and total request budget, same time window.
2. Equivalent test selection per tool (only classes both tools claim).
3. Labelled expectations with TP/FP/TN/FN per class, plus CPU, memory,
   duration, and total HTTP requests.
4. Results filed here with procedure and artifacts; regressions fail CI.

## Measured (2026-10-19)

### Conditions

- Same fixture lab (`internal/bench/lab.go`), dataset
  `bench/datasets/fixtures.yaml` (SHA-256 `17b2ef81cd4d...`), 23 scenarios,
  3 sequential runs per tool (auth groups none / user-a / user-b), same base
  URLs and auth headers.
- Gash: `dist/gash-bench.exe` (standard profile, `--no-browser-verify`):
  `--profile standard --active --rate-limit 80 --plugin-timeout 20s
  --request-timeout 2s --max-requests-total 6000
  --max-requests-per-target 3000`.
- Nuclei v3.11.1, default templates (14,102 YAML files, downloaded):
  `-jsonl -silent -no-color -disable-update-check -rate-limit 80 -timeout 10
  -tags xss,sqli,lfi,rce,redirect,exposure`. Nuclei has no total-request cap
  (upstream limitation); equalized by wall-clock timeout (6m) plus rate limit
  (80 req/s). Each run finished in ~2m15-18s, well under the cap -- the run
  was not killed mid-way.
- Official classes only (the tagged classes both tools claim). Tentative
  candidates are unscored; `xss-dom-hash-sink` is excluded as unverified in
  this browser-less build.

### Tool metrics

| tool | findings | tentative | TP | FP | TN | FN | P | R | F1 | duration | requests (reported/observed) |
|---|---|---|---|---|---|---|---|---|---|---|---|
| gash | 59 | 26 | 10 | 0 | 12 | 0 | 1.000 | 1.000 | 1.000 | 1m51.9s | 4927 / 4935 |
| nuclei | 0 | 0 | 0 | 0 | 12 | 10 | N/A | 0.000 | N/A | 6m49.3s | N/A / 28968 |

### Per category

| category | gash | nuclei |
|---|---|---|
| command-injection | TP=1 FN=0 | TP=0 FN=1 |
| open-redirect | TP=1 FN=0 | TP=0 FN=1 |
| path-traversal | TP=1 FN=0 | TP=0 FN=1 |
| sqli | TP=1 FN=0 | TP=0 FN=1 |
| xss-reflected | TP=5 FP=0 TN=2 FN=0 | TP=0 FP=0 TN=2 FN=5 |
| xss-stored | TP=1 FN=0 | TP=0 FN=1 |
| auth (4) | TN=4 | TN=4 |
| clean (2) | TN=2 | TN=2 |
| traps: waf/soft404/timeout/denied | TN=4 | TN=4 |

### Cross-tool verdicts

All 10 scored vulnerable scenarios: `gash-only`. All 12 expected-clean /
denied / trap / timeout scenarios: `neither` flagged them (both TN). No
`nuclei-only` scenario and no cross-tool disagreement on negatives.

### Reading the result honestly

- The fixture lab is a custom application. Nuclei's strength is breadth of
  signature/known-product templates; it does not enumerate discovered
  parameters or build per-target behavioural oracles, so 0/10 here is the
  expected shape of its design, not a claim that nuclei "cannot find" these
  classes on real products. No general superiority is claimed; this is one
  same-target, same-budget measurement.
- Request cost differs by an order of magnitude: nuclei probed 28,968 times
  (9,656 per run, all template traffic) versus Gash's 4,935 (1,645 per run,
  including verification controls). Both stayed within their pinned rate
  limit (80 req/s).
- Both tools kept every trap and clean look-alike clean (no false positives),
  so the comparison also holds on the negative side.
- Remaining unmeasured: compose-lab recall on real applications
  (BLOCKED, docker absent locally) -- filed, not fabricated. The nightly CI
  workflow reruns this comparison automatically.
- Native-lab update (2026-10-20): Juice Shop 17.1.0, DVWA, and WebGoat were
  served natively and all 22 scenarios were independently verified. Gash
  standard scored `TP=11 FP=0 TN=9 FN=2` (P=1.000, R=0.846), Gash deep
  `TP=12 FP=0 TN=9 FN=1` (P=1.000, R=0.923), and Nuclei
  `TP=5 FP=0 TN=9 FN=8` (P=1.000, R=0.385). Nuclei received explicit seeds,
  so this does not measure its discovery ability. Full conditions and
  limitations: `native-lab-2026-10-20.md`.

### Artifacts

`dist/bench-compare/{report.json,summary.md,findings.csv,manifest.json}`
(local, gitignored; the harness validates the dataset hash and scenario
labels). Reproduce with:

```
gash bench run --dataset bench/datasets/fixtures.yaml --tool gash,nuclei \
  --nuclei-bin "$(go env GOPATH)/bin/nuclei.exe" \
  --out dist/bench-compare --no-browser-verify
```

## Gate Verdict

Comparison measured on the fixture lab and the 22-scenario native lab; no
regression (the separate Gash baseline was refreshed from the final standard
fixture run, `bench/baselines/fixtures.json`, TP=10). Docker compose remains
BLOCKED pending a Docker-capable environment; the native run does not replace
that procedure.

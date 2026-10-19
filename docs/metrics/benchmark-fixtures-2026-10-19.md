<!--
SPDX-License-Identifier: AGPL-3.0-only
Copyright (C) 2026 Xmar1881 / GASH contributors
Module: github.com/Xmar1881/Gash

File: docs/metrics/benchmark-fixtures-2026-10-19.md
What: First measured benchmark runs on the fixture dataset (standard and deep),
  including the engine bug the benchmark surfaced.
Why: Numbers here are measured, reproducible, and include the honest misses;
  nothing is rounded up and no unmeasured class is claimed.
-->

# Benchmark: Fixtures (2026-10-19, first measured runs)

## Environment

- Windows, Go 1.27.2; gash built from the working tree at this date.
- Docker: absent (compose-lab scenarios not run). Nuclei: absent (comparison
  not run; reported N/A by the harness, never as zero success).
- Dataset: `bench/datasets/fixtures.yaml`, SHA-256
  `17b2ef81cd4de93cd30d4a8399dbe91f788cfa5f2b3d2177f5fcd866af43d6af`
  (23 scenarios, 1 fixture-lab target, auth groups none/user-a/user-b).
- Verification: 23/23 scenarios independently verified (22 HTTP kinds plus
  `browser-exec`, which is unverified in the default build — honestly excluded
  from scoring there — and verified with real headless Chrome in the deep run).

## Measured runs

| Run | Build | TP | FP | TN | FN | weak | P | R | F1 | requests (reported/observed) | wall clock |
|---|---|---|---|---|---|---|---|---|---|---|---|
| 1. First smoke (pre-fix, tentative scored) | default | 1 | 2 | 10 | 9 | 0 | 0.333 | 0.100 | 0.154 | 4333/4343 | 1m35s |
| 2. Post-fix, firm-only scoring | default | 5 | 0 | 12 | 5 | 0 | 1.000 | 0.500 | 0.667 | 4309/4318 | 1m28s |
| 3. Deep profile + browser verify | `-tags deep` | 5 | 0 | 12 | 5 | 1 | 1.000 | 0.455 | 0.625 | 5847/6094 | 3m42s |

Tentative candidates (unscored by design): 27 in run 2, 24 in run 3; they are
listed in the reports' tentative columns only.

Commands: `gash bench run --dataset bench/datasets/fixtures.yaml --tool gash`
and the same with `bench/datasets/fixtures-deep.yaml` from a
`go build -tags deep` binary (reports archived under `dist/bench-*` locally).

## The bug run 1 surfaced (fixed)

The first run scored tentative candidates, and firm reflected-XSS findings
never appeared in live scans at all. Root cause: `internal/plugin/loader/tier2_exec.go`
`controlFor` rebuilt the control request from the payload-bearing response URL
(`controlFor(JSPoint{URL: resp.URL})`) when `env.ControlSend` was nil, so the
"control" replayed the payload; the oracle saw a dirty control and rejected
every executable reflection evidence. Fixed by neutralizing all query values to
`gash-control-neutral` for the control request; regression test:
`internal/bench/plugin_live_test.go` (`TestReflectedXSSPluginAgainstFixtureLab`).
Reflected XSS then scored 5 TP / 0 FP with two clean look-alikes TN.

## Precision

Standard: 1.000 (5 TP, 0 FP; two clean scenarios stayed clean, all six traps
stayed TN). Deep: 1.000 (36 findings, 0 FP). Gate floor 0.99: PASS.

## Recall

Standard: 0.500 (5/10 positives; xss-dom unverified in the default build and
excluded). Deep: 0.455 (xss-dom detected with static evidence only, scored
weak; counted against recall). Remaining FNs, all reproduced and attributed to
engine behavior, not harness faults:

- `path-traversal-file-access`, `open-redirect-param`,
  `command-injection-error`: Tier 1 plugins probe the target root and declared
  parameters only; the vulnerable endpoints are discovered but not probed by
  these plugins. Direct scans of the exact paths confirm the engine detects
  them.
- `sqli-error-based`: Tier 2 plugin exhausts its per-plugin send budget on the
  first injection points in document order before reaching `/sqli/error`;
  direct scan of that path confirms detection.
- `xss-stored-render`: stored two-step plugin timed out under the standard
  profile's plugin timeout (deep dataset raises the timeout; still FN).

## Corpus

N/A (benchmark dataset, not the plugin corpus gate).

## Lab

In-process fixture lab (no docker), request counts cross-checked by the lab's
own counter against the scanner's `stats.http_requests` (agreement within the
same run; run 3's delta is the bench-side browser verification traffic).

## Gate Verdict

PASS on precision (1.000 ≥ 0.99) for both runs; recall misses above are
reported as measured limits in `docs/benchmark.md`, not hidden. The committed
baseline `bench/baselines/fixtures.json` (run 2) arms the nightly regression
gate.

<!--
SPDX-License-Identifier: AGPL-3.0-only
Copyright (C) 2026 Xmar1881 / Gash contributors
Module: github.com/Xmar1881/Gash

File: docs/metrics/nuclei-comparison-2026-10-14.md
What: Honest Nuclei comparison status without a measurement harness.
Why: No same-target, same-budget, same-scope benchmark has run; claiming
parity would be fabrication, so the gap is filed explicitly.
-->

# Nuclei Comparison (2026-10-14, not compared)

## Status

Not compared. No controlled benchmark between Gash and Nuclei has been run
in this repository: no shared target set, no fixed network and request
budget, no equivalent template selection, and no precision/recall harness
spanning both tools. Any parity claim would be unmeasured and is therefore
absent from the README, the detector inventory, and this report.

## Update (2026-10-19): the harness now exists, the comparison still does not

The required harness below has been built (`gash bench`, see
`docs/benchmark.md`): same-target same-scope runs, pinned request budgets,
lab-observed request counters, per-scenario verification, cross-tool verdicts,
and a regression gate. It has been measured for Gash alone
(`benchmark-fixtures-2026-10-19.md`). The Gash/Nuclei comparison itself is
still unmeasured **in this repository**, because nuclei is not installed in
the environment where those runs were made; the harness reports it as N/A
with a reason rather than zero success. The nightly CI workflow
(`bench-nightly.yml`) installs nuclei with templates and will file the first
real comparison run; until that artifact exists, the numbers below stay
unmeasured and no claim is made.

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

## Precision

Unmeasured for comparison purposes.

## Recall

Unmeasured for comparison purposes.

## Corpus

N/A.

## Lab

N/A.

## Gate Verdict

Not compared. No benchmark number is reported and none is implied.

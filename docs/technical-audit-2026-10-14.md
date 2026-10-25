<!--
SPDX-License-Identifier: AGPL-3.0-only
Copyright (C) 2026 Xmar1881 / Gash contributors
Module: github.com/Xmar1881/Gash

File: docs/technical-audit-2026-10-14.md
What: Evidence-backed priority audit for XSS reflection, WAF measurement,
and fixture reliability.
-->

# Technical Audit: Priority Findings (Historical Baseline)

## Scope

This report records the priority work requested during the 2026-10-14 audit
cycle and was last refreshed on 2026-10-18. Its measurements and findings are
historical; they are not a snapshot of the current checkout. It does not turn
design-document claims into implementation claims. The current catalog is
documented in `docs/detector-inventory.md` and the unresolved limits remain in
`docs/known-limits.md`.

## Current Repository Reference

As of 2026-10-25, the repository contains 283 reference plugins (275 Tier 1
YAML, 7 sandboxed JavaScript, and 1 Tier 3 native PoC). Current
engine behavior and verification status are summarized in the root README and
the benchmark/metrics index; the historical measurements below are preserved
for traceability and are not silently re-labeled as current results.

## Findings And Fixes

| Priority | Finding | Status | Fix / regression proof |
|---|---|---|---|
| P0 | `ReflectionParams.Contexts` was accepted but ignored. | Fixed | `internal/oracle/reflection.go` enforces canonical contexts; `TestReflectionContextsAreEnforced` covers a disallowed event handler. |
| P0 | HTML tokenizer state treated every script text occurrence as executable. | Fixed | JS lexical states distinguish code, strings, comments, executable MIME types, and JSON; `TestReflectionNonExecutableScriptFormsReject` covers string/comment/JSON. |
| P0 | A random canary in a script/event attribute could become `confirmed`. | Fixed | Parser-recognized execution call plus clean control now yields `static-execution-evidence`; `confirmed` requires browser evidence. Regression tests cover both paths. |
| P0 | CSP was not part of reflection grading. | Fixed | Blocking inline CSP downgrades the evidence to `tentative`; `TestReflectionCSPDowngradesInlineExecution` covers it. |
| P0 | Any non-blocking WAF variant was counted as bypass. | Fixed | `probe.Client` replays the exact variant and requires two stable application responses; probe and WAF tests cover auth, soft-404, dynamic, and generic 403 cases. |
| P1 | Fixture metrics could drift from fixture bytes. | Existing gate, updated | XSS dataset now has 10 pinned fixtures and reports TP=2, FP=0, TN=8, FN=0. `TestMetricGate` recomputes the hash. |

## Priority Classification

| Vulnerability / behavior | Current status | Honest boundary |
|---|---|---|
| Reflected XSS, basic HTML/JS contexts | partial | Static response proof only; active payload, control, CSP, and context rules are implemented. Findings are `static-execution-evidence`; browser execution is not performed. |
| Stored XSS | supported (two-step oracle) | `internal/oracle/stored.go` implements write-then-render with control; static-execution-evidence max without headless, browser-confirmed with controlled run. |
| DOM XSS | supported (static firm + browser-confirmed) | Static source-sink caps at firm; `internal/headless` (chromedp v0.21.0, `-tags deep`) lifts to confirmed on trigger + clean control. |
| WAF detection | implemented | Baseline markers and block classification are separate from evidence. |
| WAF bypass measurement | partial | Only opt-in, scope-checked, bounded, stable-response verification is implemented. No real-WAF general rate is measured. |
| Fixture TP/FP/TN/FN accounting | implemented | `plugintest.Summary` computes fixed fixture-set metrics; fixture results are not lab recall. |
| DVWA/Juice Shop/WebGoat recall | blocked / unmeasured | Docker lab procedure exists but was not run in this environment. |
| Nuclei comparison | unmeasured | No same-target, same-budget, same-scope harness run exists. |

## Measured Results

The initial `go test ./...` run was green before the priority changes. The
post-change run is also green. The relevant fixture results are:

| Dataset | TP | FP | TN | FN | Precision | Recall |
|---|---:|---:|---:|---:|---:|---:|
| xss-reflected-basic | 2 | 0 | 8 | 0 | 1.00 | 1.00 |
| xss-attribute-injection | 2 | 0 | 2 | 0 | 1.00 | 1.00 |
| template-injection-reflection | 2 | 0 | 2 | 0 | 1.00 | 1.00 |
| ssrf-cloud-metadata | 2 | 0 | 2 | 0 | 1.00 | 1.00 |

These are labelled fixture measurements only. They are not claims about
real-world prevalence, browser execution, or WAF bypass rates.

## Source References

The primary implementation points are `internal/oracle/reflection.go:21-25`
(allowed-context contract), `internal/oracle/reflection.go:42-57`
(context tokenization), `internal/oracle/reflection.go:317-372` (evidence
ladder), `internal/probe/probe.go:167-204` (WAF attempt flow), and
`internal/wafbypass/wafbypass.go:81-121` (WAF/app-response separation).
Regression tests are in `internal/oracle/oracle_test.go`,
`internal/probe/probe_waf_test.go`, and `internal/wafbypass/wafbypass_test.go`.

## Verification Commands

```text
go test ./...
go vet ./...
go test -race ./internal/oracle ./internal/probe ./internal/wafbypass ./tests/plugins
go build ./...
```

`go vet ./...` and `go build ./...` passed. The requested race command was
attempted with `CGO_ENABLED=1` but this Windows environment has no `gcc`; the
race result is therefore `blocked`, not silently treated as passed.

## Remaining Work

Stored-XSS two-request orchestration and browser-backed DOM confirmation are now implemented (`internal/oracle/stored.go`, `internal/headless`, `--browser-verify`). Real authorized WAF lab measurements, pinned compose-lab recall, and a parity Nuclei benchmark remain open and must stay `unmeasured` until their required test harnesses actually run.

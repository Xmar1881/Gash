<!--
SPDX-License-Identifier: AGPL-3.0-only
Copyright (C) 2026 Xmar1881 / Gash contributors
Module: github.com/Xmar1881/Gash

File: docs/known-limits.md
What: Honest BLOCKED and gap register (transport, DNS, browser, benchmark).
Why: Unimplemented paths stay documented with reasons instead of silent gaps.
-->

# Known Limits (BLOCKED and Gaps)

This file records what Gash deliberately does not do, with the technical
reason for each. Nothing here is implied as covered elsewhere.

## Reflected XSS execution proof: static-only boundary

The reflection oracle separates HTML text, ordinary attributes, URL
attributes, event-handler attributes, executable JavaScript, JavaScript
strings/comments, and inert JSON script blocks. A random canary reflection is
at most `tentative`; `confirmed` requires a recognizable execution payload,
a clean control response, and no inline-execution-blocking CSP. This is not a
browser proof. Stored-XSS write/render workflows and DOM source-to-sink
browser execution remain `unsupported`/`blocked`; see the DOM metric report.

The current reflected-XSS fixture result is TP=2, FP=0, TN=8, FN=0. The two
positive cases are reported as `static-execution-evidence`, not `confirmed`,
because no browser executed them. It must not be generalized to real-target
recall.

## Chunked Transfer-Encoding bypass: BLOCKED (transport)

WAF bypass mutations cover header bypass, HPP duplication, double URL
encoding, SQL comment injection, and mixed-case (`internal/wafbypass`).
Chunked Transfer-Encoding Kali-style body splitting is absent: Go `net/http`
owns framing and exposes no manual chunk-size control, so a raw-TCP transport
would be needed. WAF evasion therefore never relies on chunking, and no
chunked claim appears in reports. See `internal/wafbypass/wafbypass.go`.

## WAF bypass success rate: unmeasured outside controlled tests

The scanner records WAF observation separately from bypass verification.
Aggressive mode is opt-in, scope-checked, and bounded to five mutations. A
non-block status alone is never a bypass: the same mutation must produce two
stable application responses and must not look like authentication rejection,
soft-404, challenge, error, or dynamic noise. The repository has hermetic
regression tests for these cases, but no real-WAF success rate is claimed.

## CAA DNS checks: absent (stdlib gap)

Protocol checks cover TLS observation (GASH-024), SPF/DMARC reads (GASH-025),
and explicit TCP banners (GASH-026). CAA is absent: the standard library
offers no generic DNS query type, and no extra dependency is pulled in for
v1. SPF/DMARC plus resolution is the honest scope. See
`internal/proto/proto.go` and `docs/proto-checks.md`.

## Headless DOM confirmation: decided (chromedp, `-tags deep`)

Static DOM sink/source analysis (`host.oracles.execution`, plugin
`dom-sink-basic`, oracle `execution`) caps at `firm` in the default build.
The `confirmed` path (`Triggered` plus `ControlClean` via a headless browser)
is implemented in `internal/headless` with `chromedp v0.21.0` pinned in
`go.mod`, compiled only with `-tags deep` so the default binary stays light
(no browser linked). `ExecutionParams` is frozen (2026-10-15); default-build
`VerifyDOM` always errors and never fabricates `browser-confirmed`. See
`docs/metrics/dom-sink-basic.md`.

2026-10-15: decision implemented — chromedp v0.21.0 + build tag `deep` +
`internal/headless` (stub `!deep`, driver `deep`). Verified with real Chrome
155.0.8059.41 headless (`--dump-dom` + `TestDeepVerifiesDOMExecution`:
httptest payload triggers, control clean, oracle `confirmed`; negative
control rejects). Default `go test ./...` runs the stub contract
(`TestStubNeverConfirms`); `go test -tags deep ./...` runs the real browser
proof (skips only when no Chrome binary is found). Reflected-XSS `confirmed`
likewise requires supplied
`BrowserVerified`/`BrowserTriggered`/`BrowserControlClean` evidence; static
findings stay `static-execution-evidence` and never claim `browser-confirmed`.

## Compose-lab recall: BLOCKED where docker is absent

DVWA/Juice Shop/WebGoat recall (`docker-compose.lab.yml`) runs only where a
docker runtime exists. Without docker the status is BLOCKED with a filed
procedure, never a number. See
`docs/metrics/lab-compose-dvwa-juiceshop-2026-10-14.md` and
`docs/metrics/lab-compose-2026-10-15.md` (2026-10-15: docker absent,
procedure updated for DVWA 2.0 / Juice Shop 17.1.0 / WebGoat 2023.8 with
`--aggressive --scope 127.0.0.1`, no fake result).

## Nuclei benchmark: not compared (no harness)

No same-target, same-budget, same-scope Gash-versus-Nuclei benchmark has run.
The README compares capabilities honestly without parity claims. See
`docs/metrics/nuclei-comparison-2026-10-14.md`.

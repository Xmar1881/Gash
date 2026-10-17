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

## Out-of-band (OOB) blind detectors: self-hosted only, shared bounded window

OOB plugins (`ssrf-blind-oob`, `blind-sqli-oob`, `xxe-oob`) run only with a
self-hosted `--oob-server` (no public interactsh default) and require
`--active`; without a server the scheduler skips them honestly
(`oob-not-configured`). Callback proof discipline: every payload variant
carries its own single-use correlation token, so an incoming callback can
only confirm the exact request that caused it. Token verification is
deferred: Tier 1 sends the whole corpus first and then verifies all tokens
in ONE shared bounded window (`oob.WaitForCallbacks`, 10 s / 2 polls);
JS plugins call `host.oracles.oobAny(ids)` for the same shared window.
Per-payload waiting was rejected because N payloads x 10 s overflows the
plugin timeout budget. Consequences (documented tradeoffs):

- `oobAny` returns only the FIRST matched token; with several matching
  variants a run reports one confirmed finding for that plugin/point.
- Numeric-notation SSRF hosts (decimal/octal/hex, IPv4-mapped) can only
  carry the token in the path; they confirm solely when the operator's
  server indexes path tokens. Best-effort, never fake.
- PostgreSQL blind SQLi has no callback-only primitive short of
  `COPY ... TO PROGRAM` / `dblink`, both outside the no-command-execution
  scope. PostgreSQL is therefore absent from the corpus; this is a
  deliberate gap, not coverage.
- DNS-only exfil works wherever the operator's server sees the A/AAAA
  query for `<token>.<domain>`; HTTP callbacks must reach `/cb/<token>`.
  Network segmentation can cause false negatives.
- The window is a scan-time optimization; final `--oob-wait` (default 60 s)
  still applies at scan end for late callbacks.

## Reflected XSS execution proof: static-only boundary



The reflection oracle separates HTML text, ordinary attributes, URL
attributes, event-handler attributes, executable JavaScript, JavaScript
strings/comments, and inert JSON script blocks. A random canary reflection is
at most `tentative`; `confirmed` requires a recognizable execution payload,
a clean control response, and no inline-execution-blocking CSP. This is not a
browser proof by itself. The opt-in browser-verify pass
(`--browser-verify`, requires `--active` plus the `-tags deep` build and a
Chrome binary) re-fetches each eligible GET/query `static-execution-evidence`
finding as payload URL plus a neutral-control URL through
`headless.VerifyXSS` and upgrades to `confirmed` only on a real trigger
(dialog or DOM canary) with a clean control; otherwise the finding is left
unchanged and annotated honestly. DOM source-to-sink browser execution
remains gated behind `-tags deep` (see below); see the DOM metric report.

Stored-XSS write/render is `supported` via `StoredOracle`
(`internal/oracle/stored.go`, oracle `stored`,
`host.oracles.storedExecution`, Tier 1 `oracle: stored`): request 1 (POST
store, canary payload) plus request 2 (GET render page, reflection-checked)
plus a clean control render. The store exchange proves the write was accepted
and is never itself XSS proof; the render exchange carries the claim.
Limitations: `static-execution-evidence` ceiling without a controlled
headless run (`confirmed` needs `BrowserVerified`+`Triggered`+`ControlClean`);
binding control is fetched post-store so append-only boards need reset/isolate
per canary or they reject as indistinguishable; JSON/data blocks, encoded
renders (at most `tentative`), missing render canary, failed stores, and
dirty controls reject; async polling/multi-user render flows are unmeasured.

The current reflected-XSS fixture result is TP=2, FP=0, TN=8, FN=0. The two
positive cases are reported as `static-execution-evidence`, not `confirmed`,
because no browser executed them. It must not be generalized to real-target
recall.

## Chunked Transfer-Encoding / request smuggling: supported (raw-TCP, written authorization required)

WAF bypass mutations cover header bypass, HPP duplication, double URL
encoding, SQL comment injection, and mixed-case (`internal/wafbypass`).
Chunk framing itself stays out of `net/http` (it owns framing and exposes
no manual chunk-size control), so CL.TE / TE.CL / TE.TE desync detection
lives in a dedicated raw-TCP transport: `internal/smuggle` (engine-recon,
GASH-033, CWE-444, oracle `smuggling-differential`). The probe sends an
ambiguous CL+TE request plus a byte-identical harmless follow-up on the
same keep-alive connection and requires dual-channel proof (follow-up
status/body divergence AND delay/timeout) for at most a `firm` finding;
single-channel signals reject, `confirmed` never fires. Limits: the probe
dials the user-supplied target (operator responsibility; only with written
authorization), `--active` + `--aggressive` gate (safe/standard/deep skip
with reason), `AllowHost` preflight only when `--scope` is set (scope
violation → `ErrScopeViolation`, zero sockets), max 10 requests with a 5 s
cap, harmless terminator/marker bodies only (no cache-poisoning/DOS
impact). HTTPS verifies SNI/hostname (no skip); ALPN forces http/1.1 and a
negotiated HTTP/2 yields a skip (smuggling is invalid over h2). See
`docs/metrics/smuggle-differential.md`.

## WAF bypass success rate: unmeasured outside controlled tests

The scanner records WAF observation separately from bypass verification.
Aggressive mode is opt-in, scope-checked, and bounded to five mutations. A
non-block status alone is never a bypass: the same mutation must produce two
stable application responses and must not look like authentication rejection,
soft-404, challenge, error, or dynamic noise. The repository has hermetic
regression tests for these cases, but no real-WAF success rate is claimed.

## Lab-batch detectors (GASH-034..039): honest boundaries

- Host header injection (GASH-035): only Host, X-Forwarded-Host, and Forwarded
  header vectors are sent. The absolute-URI request-line variant cannot be
  emitted through Go's `net/http` (the transport rewrites the request line
  from parsed URL fields); it is out of scope, not covered. Cache-poisoning
  impact is never claimed (no cache probing).
- CRLF header injection stays passive: response-header and reflected-request-
  header checks only, no CRLF payload is injected into query parameters.
  Header-values containing raw CR/LF are rare precisely because Go's client
  and server both sanitize them; the check keeps a documented, honest ceiling
  instead of a blind-split claim.
- Backup file exposure (GASH-037) uses a fixed 12-path list, not a wordlist,
  and can therefore collide with engine content discovery (GASH-028) on the
  same paths; both pin their own gates, but an operator running `--active`
  content discovery may see both findings for one file.
- Verb tampering (GASH-036) sends only idempotent read variants (HEAD, OPTIONS,
  X-HTTP-Method-Override, X-Original-URL, X-Rewrite-URL) and only against the
  plugin's `paths` list (`/admin`, `/api/admin` by default). PUT/DELETE/PATCH
  are never sent (destructive-method red line), and login-redirect responses
  are not bypass evidence by design.
- GraphQL introspection (GASH-038) probes three fixed endpoint paths
  anonymously; introspection behind authentication is out of scope.
- NoSQL auth bypass (GASH-039) sends two JSON bodies three times each and
  never reuses a session; query-string (non-JSON) NoSQL bypass variants and
  lockout-protected logins are out of scope.

## CAA DNS checks: supported (miekg/dns, pinned)

Protocol checks cover TLS observation (GASH-024), SPF/DMARC reads (GASH-025),
CAA reads (GASH-027, CWE-295), and explicit TCP banners (GASH-026).
2026-10-16: the stdlib gap is closed with pinned `miekg/dns v1.1.73`
(`internal/proto/caa.go`): read-only TypeCAA query, 5 s cap, safe-profile
passive. NXDOMAIN/timeout/SERVFAIL stay silent (no finding, no FP);
missing CAA → medium/`firm`, malformed CAA → medium/`firm`, healthy or
IP-literal → silent. See `docs/proto-checks.md` and
`docs/metrics/caa-dns-check.md`.

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

2026-10-17: the deep driver was ported to the chromedp v0.21.0 generic API
(`cdp.Events` iterators and `cdp.Call` command values; the old
`ListenTarget`/`HandleJavaScriptDialog` helpers are gone) and
`headless.VerifyXSS` was added with a default-build stub that never confirms.
The engine consumes it through the opt-in browser-verify pass
(`--browser-verify`, `--active` required) for eligible reflected-XSS
findings and through the stored binding's `controlUrl` option for the
two-step plugin; without browser evidence both ceilings stay unchanged.

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

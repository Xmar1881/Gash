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

## Out-of-band (OOB) blind detectors: opt-in providers, shared bounded window

OOB plugins (`ssrf-blind-oob`, `blind-sqli-oob`, `xxe-oob`,
`nextjs-image-optimizer-ssrf`) run only with an explicitly selected
`--oob-server` and require `--active`; without a server the scheduler skips
them honestly (`oob-not-configured`). Providers: `local` (built-in listener),
a self-hosted API URL, a self-hosted interactsh server
(`interactsh://host`), or the public interactsh fleet (`interactsh`, an
explicit third-party opt-in; never the default). Callback proof discipline:
every payload variant carries its own single-use correlation token, so an
incoming callback can only confirm the exact request that caused it. Token verification is
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
`headless.VerifyXSS` and upgrades to `confirmed` only when a unique per-run
token is stamped by actual JS execution (an `alert`/`confirm`/`prompt` call or
`window.__gashCanary=true`) and the control stays clean; a DOM node insertion
alone is not a trigger. The probe covers same-origin frames and polls for up
to 2 s for async handlers. `not_vulnerable` is scoped to the tested
payload/control pair, never a page-wide safety claim. Blocked/error proofs
carry reason codes (`payload_forbidden`, `control_rate_limited`,
`payload_server_error`, etc.) and are excluded from benchmark scoring.
Otherwise the finding is left unchanged and annotated honestly. DOM
source-to-sink browser execution
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

The current reflected-XSS fixture result is TP=5, FP=0, TN=10, FN=0. The
positive cases are reported as `static-execution-evidence`, not `confirmed`,
because no browser executed them. It must not be generalized to real-target
recall.

## Full-form replay fuzzing: supported (`--active` only)

Body injection points discovered inside HTML forms carry the other form
fields (`FormValues`) so the engine replays the complete form — urlencoded or
multipart — with only the target field replaced; hidden fields and CSRF
tokens are preserved verbatim and token fields are never fuzzed, only
refreshed from the source page (at most 2 refreshes per form, one retry on
403/419/422 with token-wording match). Rejection pages are never treated as
signal. Limits: at most 5 forms, 10 non-token fields per form, and 12 SQLi
probes per field per scan; only POST/PUT/PATCH forms with same-origin actions
run; `text/plain` forms stay single-field; file inputs are never replayed;
GET forms are skipped by the form fuzzer (their query points are covered by
the regular active fuzz). Findings are always `tentative` (`form-fuzz-anomaly`,
RuleID GASH-004/GASH-000) because the mutation corpus is not oracle-specific;
per-request token rotation beyond the refresh cap may leave later probes
rejected and therefore unmeasured (false negatives by design). New engine
stat: `form_requests`.

## Multi-step workflow replay (`--flow-seed`): supported (`--active` only)

`--flow-seed` starts a form-driven workflow discovery: every step page is
re-fetched, its first eligible form (POST preferred; GET allowed;
urlencoded/multipart; at least one injectable field) is submitted with clean
values, and redirects are followed manually (max 5 hops; https->http
downgrade and non-http(s) schemes abort). Only same-origin form actions are
submitted, and the seed must share the target's scope (fail-closed preflight:
an out-of-scope seed sends zero requests). Replays use a fresh run-local
cookie jar, re-GET every step page to refresh CSRF tokens, mutate exactly one
non-token, non-password, non-file field at one step, and complete downstream
steps cleanly; a deviation is reported as `Stopped`, never as a finding.
Evaluation starts at the mutation step: error signatures (GASH-004),
executable-context reflections (GASH-001), and N=1 material body divergence
(GASH-005) are possible; the differential is only emitted when no stronger
signal exists. The session-bypass screen (GASH-068, CWE-841) requires >=2
steps, a fresh jar without seed cookies, a 2xx response, no password form,
and >=0.95 normalized similarity to the authenticated final page. Every flow
finding is `tentative` (synthetic `flow-replay` spec without fixtures, R-06)
and severity is capped at medium. Limits: one seed per scan, at most 6 steps
(default 4), at most 10 SQLi probes per step (default 6) plus three XSS
canaries, 120 requests per flow including discovery, replay, and bypass; v1
mutates only the first injectable field per step; forms built by JavaScript,
multi-origin wizards, JSON/token APIs, file uploads, and MFA/CAPTCHA steps
are out of scope. Discovery failure produces one honest `flow` skip record.
New engine stats: `flow_seed`, `flow_steps`, `flow_replays`, `flow_findings`,
`flow_bypass_checked`, `flow_requests`.

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

## Passive JavaScript reconnaissance (GASH-067): observe-only boundaries

The crawler fetches same-origin `<script src>` assets and captures inline
`<script>` bodies (JS types only; JSON data blocks are out of scope). Only
same-origin URLs are fetched — never third-party/CDN hosts; with `--scope`,
in-scope hosts are additionally allowed. Caps: 50 external files per crawl,
256 KB per inline script and 1 MB of inline JS per crawl, 200 endpoint
literals per file, 2 MB per asset (larger bodies are skipped and counted).
Endpoints extracted from `fetch`/`axios`/jQuery/`XMLHttpRequest` calls,
`url:` config objects, route-like string literals, and absolute URLs feed
the surface: endpoints with query parameters become direct injection points
(no extra request at discovery time) and parameterless endpoints get a
one-page, depth-0 follow crawl (at most 25 per scan). Relative URLs are
resolved against the asset URL and `${...}` template expressions are
normalized to `1`. WebSocket (`ws(s)://`) endpoints, asset extensions, and
CDN hosts are ignored. The follow crawl and source-map fetches share a 90s
budget; when it expires the detector stops and reports
`js_recon_budget_exhausted`, so a slow proxy pool cannot consume the scan
deadline. Phase timings are reported as `js_recon_ms` and `total_ms`.

Hardcoded-secret findings (GASH-067, CWE-798) are static-content matches
(AWS/GitHub/GitLab/Slack/Google/Stripe/SendGrid/Twilio/PEM/JWT plus a
generic key-name + Shannon-entropy rule). The confidence ceiling is
`static-execution-evidence`: the literal is observed in an asset, never
validated against the live credential. Evidence is masked (`first4…last4`)
plus a ±20-char masked context; full values are never reported, and matched
values are scrubbed from endpoint outputs. Placeholder/example values,
publishable keys, and low-entropy values are filtered (false negatives by
design). `sourceMappingURL` maps are fetched only same-origin/in-scope (at
most 5 per scan) and only their `sourcesContent` is scanned for secrets —
endpoints are not extracted from maps.

## Content discovery: bounded parallel probing
Wordlist discovery probes at most 80 paths per scan with 8 concurrent
requests; the shared policy session still enforces scope, rate, and request
budgets. The wordlist phase has a 90s time cap (`content_budget_exhausted`)
and the follow-up mini-crawl of discovered directories has a 60s cap
(`content_follow_budget_exhausted`). Wordlists remain technology-pinned
(`common` plus at most one framework list), not a giant brute-force corpus.
The live spinner reports `N/80` progress and the report carries
`content_discovery_ms`. The preceding BFS crawl has a `--crawl-timeout` budget
(5m default; menu everything 10m); when it expires, partial crawl results are
kept and the report sets `crawl_budget_exhausted` / `crawl_incomplete`. A crawl
that returns no result for any other reason sets `crawl_failed`, and plugins
then only see the root page. The crawler stores at most 64 MiB of page/JS
bodies (`crawl_stored_bytes`; excess is counted in `crawl_bodies_dropped`), and
its frontier is capped at `max(1000, 20 × MaxPages)` discovered URLs
(`crawl_urls_dropped`); parsing still uses the full fetched body, so these are
retention bounds, not detection bounds. Phase timings are reported per stage
(`crawl_ms`, `js_recon_ms`, `spa_crawl_ms`, `content_discovery_ms`, `fuzz_ms`,
`form_fuzz_ms`, `flow_ms`, `matrix_ms`, `smuggle_ms`, `browser_verify_ms`,
`plugins_ms`, `total_ms`).

## WAF bypass success rate: unmeasured outside controlled tests

The scanner records WAF observation separately from bypass verification.
Aggressive mode is opt-in, scope-checked, and bounded to twenty-four mutations:
header-only, HPP including benign-first/last-wins differentials, double
encoding, mixed case, class-aware SQLi/XSS/shell/path/URL semantic variants
(for example `/**/` and versioned MySQL comments, symbolic `||`/`&&`,
`0x31`/`CHAR(49)`/`CHR(49)`, percent/GBK quote and
`%0b`/`%0c`/`%0d`/`%a0` whitespace differentials, modern SVG/MathML/Media XSS
tags, backtick/computed `alert` calls plus entity/Unicode forms that preserve
the canary, `${IFS}` shell separators, and encoded traversal families),
content-type switching (JSON under `text/plain`/vendor types, form under
multipart, and a body with no `Content-Type`), parser differentials (JSON
duplicate keys, `\uXXXX` value escapes and escaped key names, malformed
multipart field names, multipart duplicate fields), 8 KiB inspection-window
padding, path-normalization confusion (`//`, `/./`, `..;/`, `;`),
decimal/hex/octal/IPv6 IP spellings, and IP-spoofing header families. A
non-block status
alone is never a bypass: the same mutation must produce two stable application
responses and must not look like authentication rejection, soft-404, challenge,
error, or dynamic noise. Modern challenge pages (Cloudflare, Akamai, Imperva,
DataDome, PerimeterX, AWS WAF, Sucuri, F5, Kasada) are detected as untrusted
and counted as `waf_challenges`; they do not trigger a host-wide plugin skip.
Headless Chrome checks challenge markers before and after the canary probe and
returns `blocked` (`payload_waf_challenge` / `control_waf_challenge`) instead
of treating a challenge DOM as target evidence. The repository has hermetic
regression tests
for these cases, but no real-WAF success rate is claimed; anti-bot stealth is
out of scope.

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

## Infrastructure recon (Faz 0: SSH/DB/TLS-deep): read-only boundaries

- SSH (`--ssh-audit`, GASH-052): the only data read is the RFC 4253 server
  banner (≤255 bytes, deadline-bounded). No `SSH_MSG_KEXINIT`, no algorithm
  enumeration, no auth attempt, no write. The banner is the server's own
  declaration, so findings stay `tentative`; the outdated-software table
  (`OpenSSH_1`..`OpenSSH_7`, `OpenSSH_8.0`–`8.4`) is a maintenance-hygiene
  signal with no CVE claims, and non-OpenSSH banners that carry no version
  mapping produce nothing.
- DB port inventory (`--db-port-scan`, GASH-053): connect + bounded greeting
  read (≤256 bytes, ≤500 ms) + close. No login, no commands, no key or
  database enumeration. Service identity is a greeting heuristic with a
  port-map fallback, so a non-DB service listening on a known DB port is
  reported with that port's conventional name, and unmapped silent ports are
  reported as `unknown`; the finding ceiling is `firm` (the open port is the
  fact, the name is not proven).
- TLS legacy-version audit (`--tls-audit-deep`, GASH-024): two separate
  handshake probes (TLS 1.0, TLS 1.1) against the https target only. A
  client/environment that cannot attempt legacy versions, a timeout, or any
  non-protocol error is recorded as `unknown` and never becomes a finding;
  only an accepted handshake fires (`<tls10|tls11>-supported`). The audit
  does not enumerate ciphers (the single observed suite is still reported by
  the regular TLS recon when the endpoint negotiates it).
- Gating and fan-out: `--ssh-audit`/`--db-port-scan` require `--active`;
  every flag needs its detector enabled by the profile (Safe skips all
  three). `--max-infra-ports` truncates the DB list, `--infra-rate-limit`
  (5/s default) and `--infra-parallelism` (4 default) bound the fan-out, and
  out-of-scope targets become skips with zero sockets. IPv6 literal
  handling inherits `net.SplitHostPort` semantics from the CLI validation.

## Infrastructure recon (Faz 1: SSH KEXINIT / DB unauth): observation boundaries

- SSH KEXINIT audit (`--ssh-handshake-audit`, GASH-054): the server banner
  plus exactly one `SSH_MSG_KEXINIT` packet (≤256 KB, deadline-bounded) are
  read. Key exchange is never completed, no auth method is attempted, and
  no channel is opened. Servers that do not send KEXINIT unprompted (some
  proxies/honeypots) get one fixed minimal client proposal purely to elicit
  the server's own declaration; the KEXINIT lists are the server's claim and
  the finding ceiling is `firm` (deterministic observation, CVE claims never
  made). Algorithm classification is name-family analysis only: unknown or
  future algorithm names stay silent, and a name containing `sha1` in a
  KEX is flagged even when the construction is arguably acceptable
  (`diffie-hellman-group14-sha1`), while `group16-sha512` is explicitly not
  flagged (`group1-` match). `ssh-rsa` host keys still required by legacy
  clients will be reported — that is intent, not a false positive.
- DB unauth (`--db-unauth`, GASH-055): exactly one harmless request per
  service, always with the fixed dummy identity `gash_probe`; no password
  is ever transmitted and no data is read or written. Consequences: MongoDB
  `hello` may answer `ok:1` even when auth is enabled (the command itself is
  unauthenticated; collection access is not proven), so the finding states
  what was observed, not actual data access. Redis `PING` is answered even
  in protected-mode defaults for loopback clients, so `+PONG` proves command
  reachability, not full data access; the optional `INFO server` read is the
  only extra request. PostgreSQL trust detection needs a reachable startup
  path; `pg_hba` rejections produce a note, never a finding. MySQL login is
  never attempted by design, so MySQL cannot produce a GASH-055 finding.
  Unsupported ports (anything outside 3306/5432/6379/27017/11211) return a
  note with zero dials. Service identity is port-keyed, so a non-DB service
  on a known DB port yields a failed/indeterminate probe, never a finding.
  TLS-wrapped database ports (e.g. PostgreSQL `sslmode=require` middleware)
  are not probed in this phase.

## Infrastructure recon (Faz 2: SSH version advisories / TLS certificate depth): heuristic limits

- SSH version→advisory map (`--ssh-audit`, GASH-056): the only input is the
  same RFC 4253 banner read as GASH-052 (no extra socket, no KEX, no auth).
  OpenSSH version parsing ignores vendor suffixes (`Debian-2+deb12u2`,
  `-hpn14v15`); the curated table is deliberately tiny: CVE-2024-6387
  (OpenSSH 8.5p1–9.7p1 inclusive), CVE-2023-48795 (<9.6), CVE-2021-41617
  (<8.8p1), CVE-2018-15473 (≤7.7), CVE-2016-10012 (<7.4), CVE-2015-6564
  (<7.0), CVE-2015-5600 (<7.0). Consequences: vendor backports are invisible
  to a banner, so a patched distro version still matches (a false positive
  by design) and a backported fix is indistinguishable from vulnerable;
  banners are also spoofable by honeypots/proxies. Findings are aggregated
  per host, capped at `tentative`, and no exploit, version-specific probe, or
  CVE severity beyond the table is claimed. When GASH-056 fires, the generic
  `ssh-old-software` signal from GASH-052 is dropped for that banner;
  protocol 1.x reporting (GASH-052) is unaffected. Only `OpenSSH_` banners
  are parsed — Dropbear/Cisco/etc. produce nothing here.
- TLS certificate/chain depth (`--tls-audit-deep`, GASH-024): every fact is
  derived locally from an observed handshake (reused from TLS recon when it
  already ran, otherwise one extra local handshake per scan; the two
  legacy-version probes are unchanged). "untrusted"/"incomplete" chain
  status comes from verifying the leaf against the host's **local system
  root store** plus only the intermediates the server sent: environments
  with custom/private roots may see `tls-untrusted-chain` on certificates
  their own clients trust, and a skipped AIA intermediate still reads as
  `incomplete`. No OCSP/CRL/revocation lookup is performed, no certificate
  is stored, and `InsecureSkipVerify` stays observation-only. Weak-key
  classification fires only when algorithm and bit length are observable
  (unknown sizes stay silent); DSA is flagged as a class without claiming
  exploitability. Broad-wildcard classification flags only TLD-level or
  single-label wildcards (`*.com`, `*.`), not multi-label (`*.example.com`,
  `*.co.uk`). The >398-day validity signal follows the browser policy as
  hygiene, not a compliance verdict.

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

2026-10-22: the deep driver records the final main-document HTTP status and
returns an explicit outcome (`confirmed`, `candidate`, `not_vulnerable`,
`blocked`, `error`, `unverified`). Confirmation requires a unique per-run
token stamped by actual JS execution; DOM-node insertion alone is not a
trigger. The probe covers same-origin frames and polls up to 2 s for
async/SPA handlers. `not_vulnerable` is scoped to the tested payload/control
pair only. Auth/throttle statuses (401/403/407/429/451), timeout (408), and
5xx or navigation failures are reported as verifier skips with reason codes
(`payload_forbidden`, `control_rate_limited`, `payload_server_error`, ...),
so they cannot be scored as a clean negative or false negative. Benchmark
precision/recall denominators exclude unverified, blocked, error, and
not-run scenarios. `TestDeepDOMFixtureOutcomeMatrix` covers
hash/async/delayed-async/SPA-pushState/URLSearchParams sinks, dialog-only and
iframe execution, node-insertion-only non-execution, safe `textContent`,
sanitized
output, reflection-only, blocked, and error pages against a real local
Chrome; `TestDeepBrowserVerifyDOMFinding` exercises the engine path.
Default-build behavior is unchanged.

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

2026-10-21: fragment/hash routes joined the same evidence path. Hash-route
query points discovered from links, rendered SPA fallbacks, or JS string
literals are sent to `host.oracles.browserExecution` only; static
`host.oracles.execution` cannot prove a fragment because it never reaches the
server. `browserEligible` also accepts GASH-003 findings, the deep browser
probe requires `Triggered` plus `ControlClean`, and `dom-sink-basic` emits one
finding per route/sink/source instead of one per query parameter. Without the
deep build or `--browser-verify`, fragment points are not turned into guesses.

## SPA-rendered surface discovery (`--browser-crawl`): bounded, GET-only

SPA surface discovery is engine-owned recon (no new detector, oracle, or rule
ID; this feature adds no plugin). It renders crawled HTML app shells through
`internal/headless` (`headless.RenderPage`) and harvests the resulting DOM plus
observed Document/XHR/Fetch URLs (`discovery.HarvestRendered`). Deliberate
limits:

- Requires the `-tags deep` build and a Chrome binary. The default build and a
  host without Chrome each emit one honest `browser-crawl` skip; no synthetic
  rendered surface is fabricated.
- At most `--browser-crawl-pages` pages are rendered (default 5, hard cap 10).
  Candidates are crawl results with a 2xx HTML response, deduplicated and
  ranked by SPA hints; the crawler's page budget still applies.
- Each render is one navigation with a bounded settle (readyState complete plus
  500 ms quiet, 3 s maximum). Click/type/navigation replay is not performed, so
  routes that require user interaction, arbitrary hash-router conventions, and
  lazy content that appears after the settle window are out of scope v1.
- Fragment/hash routes are discovered separately: links with `#/route?param=`
  become `fragment` injection points, rendered SPA search routes get bounded
  `q`/`query`/`search` fallback points, and JS string/backtick literals add
  explicit hash-route parameters (cap 20 per file). A hash route never reaches
  the server, so it can only be confirmed through a real browser probe
  (`--browser-verify`, deep build + Chrome); without that pass it stays
  undetected rather than guessed.
- Only auth-context cookies are seeded into the browser. `Authorization` and
  basic-auth headers are not forwarded, so apps that rely on header auth may
  render an anonymous surface.
- Browser traffic is GET/HEAD only. The engine always supplies a scope filter,
  and Fetch interception fails every non-GET/HEAD request before it leaves the
  browser; out-of-scope requests are likewise blocked. This is why the pass
  does not require `--active`.
- Harvest caps: 200 observed network URLs per page, 200 endpoints per page,
  and at most 25 parameterless endpoints followed with a one-page crawl.
  Endpoints are scope-filtered before they enter the injection surface; forms
  merge into the existing crawl surface. The HTML body is capped by the scan's
  response-size limit.
- Renderer errors are non-fatal: the scan continues and the first error becomes
  one `browser-crawl` skip record. The pass never upgrades confidence or creates
  findings by itself.

## Lab batch 2 detectors (GASH-057..066): honest boundaries

- phpinfo exposure (GASH-057): signature-only proof (PHP configuration marker
  plus a second phpinfo marker; soft-404 control of the same path must stay
  clean). A custom or stripped-down PHP landing page without the marker never
  matches; no PHP version, `disable_functions`, or secret value is claimed.
- Management endpoint exposure (GASH-058): fixed actuator/console path list
  (`/actuator/*`, `/server-status`, `/h2-console`). Consoles on non-listed
  paths, behind authentication, or renamed are not seen; the finding reports
  the exposed marker, not the environment contents, and no actuator endpoint
  is harvested.
- Directory listing (GASH-059): fixed path list; server-generated indexes
  (Apache/nginx/IIS title variants) only. Custom listing UIs or web servers
  with `<h1>`-less indexes stay unseen; file entries are never downloaded.
- Log4Shell JNDI (GASH-060): OOB-required; a callback proves a JNDI lookup
  attempt reached the operator's server, not RCE or a log4j version. Header
  vectors are limited to `User-Agent` and `X-Api-Version`; log4j versions that
  never evaluate (`1.x`) or WAF-blocked payloads produce no callback
  (false negatives remain). Without `--oob-server` the plugin skips honestly
  (`oob-not-configured`).
- Expression language injection (GASH-061): proof is the arithmetic result
  `1337*1337 = 1787569` appearing where the expression was injected; string
  reflection of `${...}` / `#{...}` / `*{...}` / `%{...}` without evaluation
  never confirms. Sandboxed EL implementations that block arithmetic are
  invisible, and contexts outside HTML text/attribute are not exercised.
- JSONP callback injection (GASH-062): proof is the deterministic canary
  callback name reflected into a JSON/JavaScript wrapper with the expected
  media type shape; browser execution is not attempted and endpoints that
  reflect arbitrary callback strings without JSONP context are rejected.
- OAuth open redirect (GASH-063): tested on fixed authorize paths with
  `redirect_uri`-family parameters; external Location plus DNS double-check
  and clean control (same discipline as GASH-016). IdPs that enforce exact
  redirect-URI allowlists produce no finding; this is not an OAuth flow
  analysis (no token, client, or scope checks).
- SSI injection (GASH-064): proof is a two-marker server-side include
  signature pair (`GATEWAY_INTERFACE` plus one of `SERVER_SOFTWARE`,
  `DOCUMENT_ROOT`, `SCRIPT_FILENAME`) that is absent in the control; the only
  payload is a printenv-style directive, no OS command or file include is
  attempted, and servers that suppress SSI error output stay silent (false
  negatives).
- WebDAV enabled (GASH-065): read-only `OPTIONS` only — write verbs are never
  sent. Proof is `Allow` advertising write methods (PUT/DELETE/MOVE/COPY/
  MKCOL/PROPPATCH); a missing or scrubbed `Allow` header rejects even when
  WebDAV is enabled (false negative by design). No lock, property, or
  directory-write behavior is claimed.
- Source map exposure (GASH-066): fixed bundle path list; proof is
  `"version": 3` plus one of `sources`/`mappings`/`names`/`sourcesContent`
  with a clean soft-404 control. Maps referenced only through `//# sourceMappingURL`
  comments on paths not in the list, or served behind auth, are not fetched.

## Framework-specific detectors (GASH-069..072): honest boundaries

- Next.js middleware bypass (GASH-069, CVE-2025-29927): fixed five-path list
  (`/admin`, `/dashboard`, `/api/user`, `/account`, `/settings`) and four
  `x-middleware-subrequest` values. A finding requires an access-denied
  control (401/403 or a login/session redirect) and a 2xx, materially
  different masked body. Public endpoints (200-to-200), patched builds,
  header echo without status change, WAF pages, and apps without Next.js
  middleware produce no finding. The proof is an authorization-boundary
  bypass on a read-only GET; no authenticated data access or impact beyond
  the observed divergence is claimed.
- Next.js image optimizer SSRF (GASH-070): only the default
  `/_next/image` route with `url={{OOB_URL}}` plus `w`/`q`; proof is a single
  OOB callback. Internal, metadata, and cloud-metadata targets are never
  attempted; a callback confirms an outbound fetch, not internal reachability.
  Custom image loaders, upstream allowlists, signed URLs, or disabled
  optimization produce no callback (false negatives). Without
  `--oob-server` the plugin skips honestly (`oob-not-configured`).
- SPA embedded-state secrets (GASH-071): static parse of known containers
  (`__NEXT_DATA__`, `__NUXT__`/`__NUXT_DATA__`, `__INITIAL_STATE__`,
  `__PRELOADED_STATE__`, `__APOLLO_STATE__`, `ng-state`,
  `self.__next_f.push`). State fetched or assembled at runtime after the
  initial HTML, custom serializations, and the plain-JS-object Nuxt form are
  not parsed. Values are masked and never validated against the live
  credential; placeholder/env references are filtered (false negatives by
  design). No extra requests are made: only crawled page bodies and already
  fetched external JS are scanned, and inline JS is deduplicated.
- Development build markers (GASH-072): the marker table is intentionally
  narrow (`react-dom.development.js`, `react.development.js`, `jsxDEV(`,
  `vue.global.js` but not `.prod.js`, `ng.probe(`, `ng.getComponent(`).
  Devtools hooks (`__REACT_DEVTOOLS_GLOBAL_HOOK__`,
  `__VUE_DEVTOOLS_GLOBAL_HOOK__`), `isDevMode()`, and generic warnings are
  rejected because production bundles commonly retain them. Renamed or
  minified builds can hide markers (false negatives); a marker is an
  informational build-hygiene fact, not proof of an exploitable debug
  endpoint, and severity stays low.

## Login automation (`--login-*`): honest boundaries

Form-based login (`internal/auth/login.go`, engine `runLogin`) handles one
classic HTML login form only. The following are deliberate gaps, not coverage:

- No OAuth/OIDC/SAML/SSO flows, no JS-rendered or CAPTCHA-protected widgets,
  no multi-page wizards (username page → password page), and no JSON/token
  login APIs. A page whose form is built by JavaScript yields
  `no-password-form` and the scan continues unauthenticated.
- One credential set only, at most 2 POST attempts by default (hard cap 3).
  There is no password guessing, spraying, or credential stuffing. `2FA`
  (`OTP`/`TOTP`/`MFA`/`CAPTCHA` fields) is detected and the flow gives up
  immediately — solving or bypassing MFA is out of scope.
- No re-login: sessions are established once before the scan; a session that
  expires mid-scan is not refreshed (plugins then see whatever the target
  returns for expired cookies).
- Success verification is heuristic: no password field **plus** a difference
  from an anonymous control fetch (token-like `value="..."` contents
  normalized). A site that renders login and post-login variants of the same
  URL indistinguishably (identical markup for anonymous users, cosmetic
  dynamic content that survives normalization) can therefore be declared
  `unverified-session` or `login-failed` even when a session exists — pick
  `--login-verify-url` carefully for such sites. Conversely, a failed login
  on a target whose anonymous page changes structurally between two fetches
  could be misread as success; verify URLs that are stable when logged out
  are the safe choice.
- Cookies are replayed only to the exact host that set them (`Domain`
  attribute sharing across sibling hosts is not honored), an `https → http`
  redirect downgrade aborts the flow (`redirect-downgrade-blocked`), and
  credential-bearing requests are never replayed through WAF-bypass
  mutations.
- In `--target-file` bulk scans the login flow runs once per target engine
  against the same explicit `--login-url`; there is no bulk-specific
  credential mapping.

## Native-lab recall: full 22-scenario run measured; Docker compose still BLOCKED

The 2026-10-20 native lab ran Juice Shop 17.1.0, DVWA, and WebGoat 2023.8 as
native Windows services (no Docker). All 22 scenarios were independently
verified before scoring (`unverified=0`). Gash standard scored
`TP=11 FP=0 TN=9 FN=2` (P=1.000, R=0.846); Gash deep scored
`TP=12 FP=0 TN=9 FN=1` (P=1.000, R=0.923); Nuclei v3.11.1 scored
`TP=5 FP=0 TN=9 FN=8` (P=1.000, R=0.385). At that time the only deep Gash miss
was the Juice Shop hash-route DOM XSS; the standard build also missed DVWA DOM
XSS. Hash-route/fragment discovery and browser probing were implemented after
that run and have not yet been re-measured, so those numbers are the last
measured state, not current behavior. Nuclei missed all 6 exposure scenarios
and both DOM scenarios. These are lab-scoped results, not general superiority
claims. Conditions, hashes, and limitations:
`docs/metrics/native-lab-2026-10-20.md`.

The compose procedure (`docker-compose.lab.yml`) remains reproducible only
where Docker exists; this environment still has no Docker runtime. The native
run does not replace the compose procedure, and both are reported separately:
`docs/metrics/lab-compose-2026-10-15.md`.

## Nuclei benchmark: measured on the fixture and native labs

A same-target, same-budget, same-scope Gash-versus-Nuclei comparison ran
locally on the fixture lab (nuclei v3.11.1, 14,102 templates): Gash scored
TP=10 FP=0 FN=0 (P=R=1.000) versus Nuclei TP=0 FP=0 FN=10 (recall 0.000)
across the classes both tools claim, with no disagreements on the negative
side. That is one synthetic-app measurement, not a general superiority claim;
Nuclei's template breadth targets known products. Full tables and conditions:
`docs/metrics/nuclei-comparison-2026-10-14.md`. The native-lab comparison is
in `docs/metrics/native-lab-2026-10-20.md`; it seeded Nuclei explicitly, so
it does not measure Nuclei's discovery ability. The nightly workflow
(`bench-nightly.yml`) reruns the fixture comparison automatically.

## Benchmark-measured engine limits (reported, not hidden)

The fixture benchmark measured three engine limits on 2026-10-19; all three
were fixed the same day and re-measured (standard recall 0.500 -> 1.000, deep
0.455 -> 0.909): Tier 1 endpoint discovery now feeds accepted URL rules back
through a bounded per-parameter probe; Tier 2 JS plugins use a lazy-control
round-robin send budget so tail injection points are reached; the stored
two-step plugin groups by base, uses a clean sibling page as control, and runs
the browser proof only after a static accept. The DOM XSS weak-evidence
boundary above remains. Details and before/after numbers:
`docs/metrics/benchmark-fixtures-2026-10-19.md`.

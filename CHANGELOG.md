<!--
SPDX-License-Identifier: AGPL-3.0-only
Copyright (C) 2026 Xmar1881 / GASH contributors
Module: github.com/Xmar1881/Gash

File: CHANGELOG.md
What: Release history for the public repository.
Why: One place for what changed per version (Keep a Changelog style).
-->

# Changelog

All notable changes to GASH are documented here.
Format follows Keep a Changelog; versioning follows SemVer.
Dates are UTC.

## [Unreleased]

### Added

- Context-aware XSS reflection evidence: JavaScript strings/comments and inert
  JSON blocks no longer look executable; allowed contexts, execution payloads,
  clean controls, and CSP are enforced.
- WAF statistics now distinguish detection from verified bypass. Aggressive
  bypass counts require stable application responses and exclude auth,
  soft-404, challenge, error, and dynamic responses.
- BFS Web Crawler (`internal/discovery/crawl.go`): automated link following with
  robots.txt/sitemap.xml parsing, `--max-pages`, and `--depth` control.
- Multi-target bulk scanning (`cmd/gash/bulk.go`): `--target-file`, `--resume`,
  `--output-dir`, and aggregated `bulk_summary.json` reporting with strictly
  shared global request budgets.
- Upstream HTTP interception proxy support (`--proxy <url>`): full Burp Suite /
  OWASP ZAP integration wired to `probe.Client.Transport` with fail-closed
  preflight `--scope` firewall enforcement.
- Stored XSS two-step verification oracle (`internal/oracle/stored.go`) with
  isolated injection and rendering phases.
- Smart Content & Directory Discovery (`internal/discovery/content-discovery.go`):
  soft-404 baseline learning, embedded technology wordlists, and sensitive HEAD checks.
- Scan report diffing engine (`internal/reporter/diff.go`) for tracking regressions,
  fixed findings, and new vulnerabilities across recurring runs.
- Headless Chrome Deep XSS automated testing (`-tags deep`) wired into CI.
- New vulnerability detectors: CAA DNS verification, NoSQL injection error-based,
  and Web Cache Poisoning basic checks.
- New vulnerability detectors: insecure deserialization (GASH-029), subdomain
  takeover (GASH-030), mass assignment (GASH-031), and missing rate limit
  (GASH-032), each with fixtures and metric reports.
- Request-smuggling differential probe (GASH-033, CWE-444): raw-TCP CL.TE/
  TE.CL/TE.TE engine recon with dual-channel proof (divergence + delay) and
  a `firm` ceiling (`internal/smuggle`).
- New vulnerability detectors: XPath injection error-based (GASH-034, CWE-643),
  host header injection reflection (GASH-035, CWE-644), verb tampering auth
  bypass (GASH-036, CWE-650, new `verb-tamper` oracle), backup and state file
  exposure (GASH-037, CWE-538, fixed 12-path list with soft-404 control),
  GraphQL introspection enabled (GASH-038, CWE-200), and NoSQL auth bypass
  differential (GASH-039, CWE-943, `firm` ceiling, session never reused).
- New Tier 1 detectors (GASH-057..066): phpinfo exposure (GASH-057, CWE-200),
  management endpoint exposure (GASH-058, CWE-200), directory listing
  (GASH-059, CWE-548), Log4Shell JNDI OOB (GASH-060, CWE-917, header and query
  vectors), expression language injection (GASH-061, CWE-917), JSONP callback
  injection (GASH-062, CWE-79), OAuth open redirect (GASH-063, CWE-601), SSI
  injection (GASH-064, CWE-97), WebDAV enabled (GASH-065, CWE-650, read-only
  OPTIONS Allow-header check), and JavaScript source map exposure (GASH-066,
  CWE-540), each with fixtures and metric reports.
- Passive JavaScript reconnaissance (GASH-067, CWE-798): the crawler collects
  same-origin `<script src>` and inline JS bodies (JS types only) and parses
  endpoints (`fetch`/axios/jQuery/XHR, `url:` configs, route-like literals,
  absolute URLs, `${...}` normalized to `1`) plus `sourceMappingURL` maps.
  Parameterized endpoints feed the injection surface directly; parameterless
  endpoints get a one-page follow crawl (<=25). Hardcoded-secret findings use
  AWS/GitHub/GitLab/Slack/Google/Stripe/SendGrid/Twilio/PEM/JWT plus a generic
  key-name + Shannon-entropy rule, stay `static-execution-evidence`, and report
  masked evidence only (`first4…last4` + masked context) with values scrubbed
  from endpoint outputs. Third-party/CDN assets are never fetched; source maps
  are fetched same-origin/in-scope (<=5) and only their `sourcesContent` is
  scanned. New engine stats: `js_files_fetched`, `js_endpoints_found`,
  `js_secrets_found`, `js_maps_fetched`.
- SPA-rendered surface discovery (`--browser-crawl`, `-tags deep` + Chrome):
  renders up to 5 crawled 2xx HTML pages (`--browser-crawl-pages`, hard cap 10),
  harvests rendered forms/injection points plus in-scope Document/XHR/Fetch
  URLs (<=200 per page, 200 endpoints per page), follows parameterless
  endpoints with <=25 one-page crawls, and merges results into the existing
  crawl surface. Browser traffic is GET/HEAD only (other methods are failed
  before send), out-of-scope requests are blocked, only auth-context cookies
  are seeded (`Authorization` headers are not forwarded), and render errors are
  non-fatal. Default builds and hosts without Chrome emit one honest
  `browser-crawl` skip and never synthesize rendered surface. New engine stats:
  `spa_pages_rendered`, `spa_forms`, `spa_endpoints`, `spa_skipped`. No new
  detectors (plugin count unchanged).
- Tier 1 YAML gained `paths` combined with parameter/payload injection and OOB
  token expansion in request headers and bodies; the error oracle gained
  `phpinfo`, `management_endpoint`, `directory_listing`, `source_map`, and
  `ssi` signature sets; the header oracle gained a read-only `webdav` mode.
- Full-form replay fuzzing: HTML forms are parsed into a replay model
  (`discovery.ExtractForms`) that keeps hidden and CSRF token fields, and
  body injection points carry the other fields' values (`FormValues` /
  `FormEnctype`) so the engine replays the complete form — urlencoded or
  multipart — instead of a single-field body. Active scans run a bounded
  full-form fuzz (<=5 forms, <=10 non-token fields per form, 12 probes per
  field) with CSRF token refresh from the source page (<=2 per form, one
  retry on 403/419/422 plus token-wording match), same-origin action gate,
  and tentative findings only. New engine stat: `form_requests`.
- Payload quality upgrade: a shared SQLi corpus (`internal/fuzz/sqli_corpus.go`)
  with a boolean pair plus ten DBMS error probes (EXTRACTVALUE/UPDATEXML,
  CONVERT, CAST, case-mixing, double-encoding, tab and MySQL versioned-comment
  WAF-bypass variants) now drives both the live engine and
  `sqli-error-based.js` (locked by a sync test); the MySQL signature set gained
  `XPATH syntax error` and Postgres `invalid input syntax`. The reflected-XSS
  plugin now classifies the reflection context first (bare-canary marker, one
  request) and sends only the matching alert-based payload family (HTML tag,
  quoted/unquoted attribute, event handler, script string, `javascript:` URL)
  with new oracle fixtures for unquoted attributes, `javascript:` URLs,
  script-string breakouts, entity-encoded tags, and JS unicode escapes.
- Tier 1 YAML requests gained `payloads` (ordered list with per-param
  short-circuit), `paths` (payload-free path probes), `headers`, and `body`
  support; the reflection oracle gained `canary_by_payload` and the
  differential oracle gained `false_body`.
- Error signature library extended: MariaDB/MySqlException, PG::/psql:,
  mssql syntax/quoting/column errors, OCI-/DPI-, SQLite.Exception, plus new
  `access`, `firebird`, `hql`, `xpath`, and `backup_file` sets; deserialization
  set gained .NET BinaryFormatter, Python pickle protocol, Ruby Marshal, and
  Psych::SyntaxError markers.
- Query payload variants added to path-traversal-error, command-injection-error,
  open-redirect-param, ldap-injection-differential, xss-attribute-injection,
  and reflected XSS (JS templates); ssrf-cloud-metadata now covers AWS (IMDSv1),
  Alibaba Cloud, and Azure IMDS payloads with per-payload canaries.
- OOB blind detectors now ship multi-variant corpora with single-use tokens:
  SSRF (schemes, parser-confusion forms, redirect-echo, best-effort
  numeric-notation hosts), blind SQLi (MSSQL/MySQL/Oracle callback-only
  functions; PostgreSQL deliberately omitted), and XXE (external DTD
  SYSTEM/PUBLIC, parameter-entity and nested forms). Templating is pinned to
  the operator's real provider bindings (`{{OOB_DOMAIN}}`/`{{OOB_URL}}`/
  `{{CORRELATION}}`); the previous inert placeholder is fixed.
- Deferred batch OOB verification: tokens are checked in one shared bounded
  window (`oob.WaitForCallbacks`, 10 s / 2 polls) instead of per-payload
  waits; Tier 1 gains this via the new `OOBSource.WaitAny` seam and JS plugins
  via the new `host.oracles.oobAny` binding. `oob.generate` in JS now returns
  correlations under the self-hosted server's domain instead of a fixture
  host.
- Browser-verify pass (`--browser-verify`, `--active` required): eligible GET
  query `static-execution-evidence` XSS findings are re-fetched as payload
  plus neutral-control URLs through `headless.VerifyXSS` in the `-tags deep`
  build and upgraded to `confirmed` only on real trigger with clean control;
  the stored two-step binding gained a `controlUrl` option that wires the same
  evidence path. Default-build stub never confirms.
- `internal/headless` ported to the chromedp v0.21.0 generic API
  (`cdp.Events` iterators, `cdp.Call` command values) and `VerifyXSS`
  (dialog or DOM-canary trigger channel, control-checked).
- DOM sink/source vocabulary expanded (`outerHTML`, `insertAdjacentHTML`,
  `eval(`, string-arg timers, jQuery `.html(`, `new Function(`, `postMessage`,
  `URLSearchParams`, `window.name`) with the fixture mirror kept in sync.
- Login/session automation (`--login-url`, `--login-user`, `--login-pass` /
  `--login-pass-env`, `--login-user-field`, `--login-pass-field`,
  `--login-verify-url`; `internal/auth/login.go` + engine `runLogin`): forms
  are fetched and POSTed through the same policy pipeline as every other
  request, redirects are followed manually with per-host cookies and
  https→http downgrade refusal, and success is declared only when the verify
  page has no password field and differs from an anonymous control fetch.
  Failures never stop the scan: one honest `login` skip record
  (`login-failed: <reason>`, `2fa-detected` never retries) plus new stats
  `login_attempted`/`login_succeeded`/`login_cookies`. Explicit
  `--auth-header`/`--cookie` values win per name; credentials never appear in
  reports, skip reasons, or logs (redacted stderr summary only); scope or
  policy violations during login fail closed before any plugin traffic.
- Multi-step workflow replay (`--flow-seed`, `--flow-max-steps`,
  `--flow-probes`; `internal/flow` + engine `runFlowFuzz`): discovers a
  same-origin form workflow from the seed, replays it in a fresh cookie jar
  while re-fetching every step page to refresh CSRF tokens, mutates exactly
  one non-token/non-password field, and continues downstream clean. Mutated
  replays are evaluated from the mutation step onward with the existing error
  (GASH-004), reflection (GASH-001), and N=1 differential (GASH-005) oracles.
  A session-bypass screen (>=2 steps, fresh jar without seed cookies, 2xx,
  no login form, normalized similarity >=0.95) emits GASH-068 (CWE-841)
  tentative. All flow findings stay `tentative` (synthetic `flow-replay`
  spec has no fixtures, R-06) and never add a plugin of their own. Gates:
  `--active` required, one seed, seed scope preflight fail-closed, <=6 steps,
  <=120 requests/flow, manual redirects (max 5, no https->http downgrade),
  cross-origin actions never submitted. New engine stats: `flow_seed`,
  `flow_steps`, `flow_replays`, `flow_findings`, `flow_bypass_checked`,
  `flow_requests`; discovery failure emits one honest `flow` skip record.
- Next.js middleware authorization bypass detector (GASH-069, CWE-288,
  CVE-2025-29927): GET control-versus-`x-middleware-subrequest` differential
  across five admin/dashboard/API paths, four bounded header values, clean
  denied control required, 2xx masked-body divergence required, WAF pages and
  public-route 200-to-200 comparisons rejected, `firm` ceiling.
- Next.js image optimizer blind SSRF detector (GASH-070, CWE-918):
  `/_next/image` with an OOB `url` plus static `w`/`q`, callback-only proof,
  no internal/metadata target probing.
- Tier 1 YAML gained an optional static `query` object on request templates,
  applied after OOB placeholder expansion (used by GASH-070).
- SPA embedded-state secret detector (GASH-071, CWE-798/200): parses
  Next/Nuxt/Redux/Apollo/Angular state containers plus `self.__next_f.push`,
  reuses JS secret rules with sensitive key matching, masks values, and makes
  no extra requests (page and external JS bodies already fetched).
- Development build artifact detector (GASH-072, CWE-489): low/firm,
  aggregated per source, marker table for React/Vue/Angular dev builds, with
  devtools hooks and generic warnings rejected as production noise.
- Engine report stats: `spa_state_pages`, `spa_state_secrets`,
  `devbuild_markers`.
- Automated benchmark harness (`gash bench`): YAML ground-truth datasets with
  strict validation and a lab-only safety guard, an independent verifier
  (HTTP reflection/error/stored/clean/denied/soft-404/WAF/timeout/redirect and
  controlled headless-Chrome browser execution) that excludes unverified
  scenarios from scoring, an equal-conditions Gash/Nuclei comparison with
  cross-checked HTTP request counters, TP/FP/TN/FN plus precision/recall/F1
  and per-category/XSS-context metrics, `report.json`/`summary.md`/
  `report.html`/`findings.csv`/`manifest.json` reports, a baseline regression
  gate (`gash bench compare`, `gash bench baseline`), an in-process fixture
  lab, compose-lab lifecycle commands, and a nightly CI workflow
  (`bench-nightly.yml`). Tentative candidates are unscored by default.
- Bench datasets and baselines: `bench/datasets/fixtures.yaml` (23 verified
  scenarios), `fixtures-deep.yaml` (deep profile + browser verification),
  `compose-lab.yaml` (DVWA/Juice Shop/WebGoat), `bench/baselines/fixtures.json`.
- Bench tests: unit suites plus an end-to-end critical-detector gate that runs
  a real gash binary against the fixture lab and fails on false positives,
  not-run outcomes, or reflected-XSS regressions.

### Fixed

- Tier 2 execution control requests replayed the payload when
  `env.ControlSend` was unset: `controlFor` rebuilt the control from the
  payload-bearing response URL, the oracle saw a dirty control, and every
  executable reflection/error/redirect evidence was rejected — live scans
  produced no firm reflected-XSS findings at all. Controls now neutralize all
  query values to `gash-control-neutral`; regression test
  `internal/bench/plugin_live_test.go`.

### Changed

- Scope enforcement is now opt-in (Nuclei/ZAP-style operator responsibility).
  Without `--scope` the scan runs in open mode: no host is blocked, cross-host
  and cross-scheme redirects (including https→http) are followed, crawl links
  on any host are attempted, and DNS decides (no rebinding pinning). A startup
  notice on stderr states this. With `--scope`, the previous strict behavior
  is unchanged (allowlist, DNS-rebinding pinning, upgrade-only http→https,
  https→http never). The request-smuggling probe (GASH-033) now targets the
  user-supplied host instead of refusing non-loopback targets; its scope
  preflight applies only when `--scope` is set, and the `--active`
  `--aggressive` gate plus the 10-request/5s caps are unchanged.

## [v0.1.0-dev] - 2026-10-13

### Added

- Phase 0: scope decisions (`docs/design/00-scope.md`, Go 1.26.8, cobra, goja).
- Phase 1: engine design (`docs/architecture.md`), evidence standard
  (`docs/evidence-standard.md`), Tier 3 gRPC contract (`proto/gash/v1/plugin.proto`).
- Phase 2: core infrastructure (schema/loader/registry, `PolicySession`,
  executor, baseline model, oracle library, replay harness, negative corpus,
  recall lab, OOB client). No vulnerability plugins yet at this gate.
- Phase 3: reference plugins (passive header, reflected XSS, error/boolean
  SQLi, open redirect, blind SSRF with mandatory OOB, one native Tier 3 POC),
  each with fixtures plus precision/recall reports under `docs/metrics/`.
- Phase 4: community surface (`CONTRIBUTING.md`, `gash plugins
  validate|test|list|info|new|trust`, `plugin-ci.yml`, docs, responsible-use
  policy). AI prompts excluded from the public tree (local `.ai-prompts/` only).

### Gates

- `go test ./...` green; `go vet ./...` clean.
- Corpus gate: zero `firm+` findings on the clean corpus (B4).
- Metric gate: reference-plugin precision >= 0.99.
- Warm discovery budget: 100 plugins under 150 ms (B8).

[v0.1.0-dev]: https://github.com/Xmar1881/Gash/releases/tag/v0.1.0-dev

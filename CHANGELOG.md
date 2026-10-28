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

- Plugin selection and persistent menu customization. The Plugins tab now has
  a selection editor (`s`) for an **only** list and an **excluded** list:
  adding to one removes the ID from the other, IDs are validated against the
  discovered catalog, and lists persist in `.gash/menu-settings.json`
  (`GASH_MENU_SETTINGS` overrides the path). Scans prompt to apply the saved
  set and emit `--only-plugin` / `--ignore-plugin`; the summary shows the
  counts and reports expose `plugin_selection` / `plugin_exclusions`.
  `--only-plugin` itself is a new validated CLI flag (unknown IDs and overlap
  with `--ignore-plugin` fail closed), and unselected plugins are omitted
  without skip-wall entries. A Settings screen (`g`) persists the default
  profile, logo visibility, and default proxy mode (`auto`/`off`/`all`). All
  new menu copy is TR/EN locale-keyed.
- Tier 1 expansion pack: 100 new YAML plugins (catalog 338 → 438; Tier 1 275 →
  375). Twenty-eight passive header-policy/hardening checks cover CSP
  directives, HSTS preload, referrer policy, permissions policy, legacy
  X-Frame-Options/X-XSS-Protection, isolation values, and version/debug
  disclosure headers. Seventy-two banner-only product fingerprints cover CMS,
  wiki, helpdesk, CRM/ERP, CI/CD, observability, auth, storage, data-UI, and
  ML/admin stacks. Every plugin ships positive/negative fixtures and an
  individual metrics report; fingerprints stay tentative and header policies
  stay firm/confirmed. The header oracle gained a generic
  `skip_if_header_missing` policy parameter so directive checks complement the
  dedicated presence checks instead of duplicating their findings.
- Profile detector gating now uses the oracle a plugin actually pins
  (recorded at discovery), not tag-name heuristics. Product-tagged exposure
  plugins no longer run in passive profiles that disable their oracle; a local
  safe-profile smoke target dropped from 219 scheduled/146 partial plugins to
  133 scheduled/2 partial at the same 400-request budget (186 requests used).
  JSON reports now serialize empty `findings` and `skipped` as arrays instead
  of null, so consumers never special-case the empty scan.
- Profile budgets raised for the 438-plugin catalog: `safe` 100 → 250,
  `standard` 500 → 2,000, and `deep` 4,000 → 8,000 requests per target
  (totals 2,000 / 15,000 / 40,000). A local standard smoke target needed about
  1,650 requests to finish 399 scheduled plugins (12 findings); at 500 it
  stopped with 220 partial plugins and zero findings. Explicit flags still win,
  and the menu's budget line reads the same profile values.
- Shared passive response cache: identical static GET/HEAD requests for
  read-only Tier 1 oracles are coalesced with singleflight, a 60 s TTL, 512
  entries, and a 32 MiB body cap. Active, timing, differential, OOB, redirect,
  reflection, rate-limit, and host-header flows keep their own exchange.
  Cached hits skip network and budget accounting; reports expose
  `passive_cache_hits` / `passive_cache_fetches`, and text reports end with a
  compact `summary:` line (requests, cache hits, scheduled/partial/error
  counts, duration). A local standard smoke run served 218 requests from cache
  (1,499 network requests vs 1,642 before) with the same 12 findings.
- Interactive menu overhaul (`gash menu`): new `status` tab (build tags,
  headless/Chrome, Go runtime, catalog count, auto proxy list, latest reports
  with open/view actions), bulk target-file scans with per-target same-site
  scope and resume/output-directory prompts, explicit proxy modes
  (`auto`/`off`/`single`/`all`), auth modes (`cookie`/`header`/`login` with
  profile upgrade), `--allow-external` toggle, secret redaction in the command
  preview/history, and `r` to repeat the last scan. Non-http(s) targets and
  header injection are validated before running.
- Menu information architecture simplified from nine tabs to six (Scan,
  Plugins, Tools, Console, Status, Help). Benchmark, OpenAPI, diff, and
  suppress now live under Tools while `b`/`o`/`d`/`x` still jump directly into
  the requested tool. Also removed unused color constants, resolved the proxy
  health-check path against the repo root, made the status viewer prefer text
  reports instead of dumping HTML/JSON, asked for OOB tokens on all custom
  providers, and added a confirmation before removing a suppression.
- Main menu opens with a six-line ANSI Shadow GASH wordmark painted with a
  purple-to-cyan gradient. Interactive color terminals play a short two-pass
  highlight sweep and settle on the static mark; piped output, `NO_COLOR`,
  `TERM=dumb`, and `GASH_NO_ANIMATION=1` stay static. The version/meta line
  keeps the literal brand name, and operator copy remains locale-keyed.
- Menu chrome modernized: compact brand/version header, persistent breadcrumb
  with language and tab position, numbered segmented tabs with an active pill,
  keycap action hints, aligned footer, and a prompt that turns green/red with
  the last command result. The six-line ASCII banner and boxed legal notice
  were replaced by a compact hero and a wrapped warning line; all new chrome
  stays on the TR/EN locale keys and the width-aware plain-text fallback.
- Documentation landing page rewritten around the actual operator experience:
  a clean text masthead, a first-class interactive-menu section with the
  tab/shortcut table (English sample), a dedicated `docs/menu.md`, a compact
  coverage section, and corrected default-profile/scope statements (CLI default
  is `standard`; `safe` is the passive profile, and same-site scope is the
  default). The generated SVG banner was removed, and the Turkish operator
  guide moved to a separate “Localized Guides” section instead of sitting
  beside the English menu entry.
- Live phase detail in menus and CLI: each completed scan phase now keeps its
  final summary and duration while the active phase updates in place. The
  engine reports crawl pages/surface/requests, JS files/endpoints/secrets, SPA
  state/dev-build counts, content requests/findings, fuzz points/requests,
  plugin completed/partial/error counts, browser-verify upgrades, and
  deduplicated finding totals; skipped phases include their reason. Progress is
  fully keyed and localized: the engine emits stable `progress.*` keys plus
  arguments, and the TR/EN menu catalogs render every phase, detail, hint, and
  completion line. The text report now classifies connection failures as
  `network` instead of `policy`.
- Core hardening batch: removed the unused probe response store that retained
  every body until the scan ended; made the scope DNS cache thread-safe;
  isolated engine-owned detector and plugin-dispatch panics so one faulty unit
  cannot kill a scan; capped crawl body retention (64 MiB) and discovered URLs
  (`max(1000, 20 × MaxPages)`) with `crawl_stored_bytes`,
  `crawl_urls_dropped`, and `crawl_bodies_dropped` report stats; bounded
  response headers at 1 MiB; and serialized `Engine.Run` per instance to keep
  per-target auth/tech state from racing.
- Engine per-run state isolation: bulk scans that reuse one engine no longer
  carry login-derived cookies or the `requires_auth` gate into the next target;
  the declared auth context is cloned for the run and restored afterwards.
- Report phase timings now cover form fuzz, flow replay, BOLA matrix, request
  smuggling, and browser verification (`form_fuzz_ms`, `flow_ms`, `matrix_ms`,
  `smuggle_ms`, `browser_verify_ms`). New `surface_points` and `crawl_failed`
  stats plus a crawl-failure note make limited plugin surfaces explicit instead
  of silently probing only the root page.
- Report taxonomy and audit fixes: error-oracle evidence modes now keep their
  documented rule IDs (path traversal GASH-017, XPath GASH-034, backup
  GASH-037, phpinfo/management/directory/source-map/SSI, and critical exposure
  GASH-028) instead of all collapsing to the SQLi GASH-004 rule. JSON stats
  now agree with the visible findings array (`findings`, `findings_total`,
  `findings_visible`, `findings_tentative_hidden`, `findings_suppressed`), and
  the JSON envelope gained `scan_id`, `noisy_notes`, oracle/method/injection
  point/verification/remediation fields, plus lowercase `skipped` keys.
- Scan reliability tuning to reduce skipped/timeout plugins: the HTTP transport
  keeps 32 idle connections per host (instead of the stdlib default of two),
  retries are globally budgeted at 20% of observed responses (minimum 32) to
  stop correlated-failure amplification, ambiguous 5xx responses are no longer
  replayed for POST/PATCH, `Retry-After` is honored up to the configured
  backoff ceiling, and the deep profile budget rises from 2,000 to 4,000
  requests/target so a 334-plugin run does not exhaust its host budget before
  the exposure checks finish. Reports expose `retry_budget_exhausted`.
- Target preflight and self-describing limits: the runtime tech GET now doubles
  as a reachability check, so an unreachable target, blocked scope, exhausted
  budget, or dead proxy pool aborts the run with one actionable error before
  every plugin timeout is spent (an all-skipped schedule still returns a valid
  empty report). The same GET supplies the TLS certificate verdict, removing
  the previous duplicate HTTPS preflight request while keeping the
  `SkipTLSFailFast` seam. JSON stats record the effective
  `request_budget_target`, `request_budget_total`, `rate_limit_per_second`,
  `max_pages`, and `crawl_depth`. The menu reads the same `internal/config`
  profiles to show the selected profile's budget in the pre-scan summary and an
  Engine row in the status tab.
- Modern WAF bypass pack (aggressive-only, 28 bounded variants): benign-first
  HPP differentials, JSON escaped keys (`\u0069d`) alongside duplicate keys,
  JSON bodies with no `Content-Type`, malformed multipart field names (NUL
  suffix/filename), 8 KiB inspection-window padding, `..;/` path confusion,
  payload-bearing header/cookie mutations, gzip-compressed bodies
  (`Content-Encoding`), the legacy `$Version` cookie parser differential,
  decimal/hex/octal/IPv6 payload-IP spellings, symbolic SQL boolean operators,
  and modern SVG/MathML/media XSS tags plus backtick/computed `alert` calls.
  Every variant still needs two stable application responses; no stealth claim.
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
- Rotating proxy pools for timeout/IP-block failover: `--proxy-file` (one URL
  per line), `--proxy-rotate per-host|per-request`, and `--proxy-cooldown`.
  Timeouts and 403/407/429 responses retry through the next healthy proxy,
  failing proxies cool down, and a per-attempt request timeout keeps one hanging
  proxy from consuming the whole plugin budget. Request bodies are replayed on
  retry.
- Ten new Tier 2 reference plugins: XML/SOAP SQLi (`sqli-xml-body-error`),
  multipart-form SQLi (`sqli-multipart-error`), XML-body XPath injection
  (`xpath-xml-body-error`), raw XML/SOAP XXE (`xxe-xml-body-oob`), SVG-upload
  XXE (`xxe-svg-upload-oob`), path-segment XSS (`xss-path-segment`), reflected
  header XSS (`xss-reflected-header`), path parser-confusion open redirect
  (`open-redirect-path-parser`), nested-JSON NoSQL operator injection
  (`nosql-nested-json-operator`), and encoded path traversal
  (`path-traversal-encoding-bypass`). Each ships fixtures, a metrics report,
  an E2E test, and no new sandbox surface.
- Automatic local proxy discovery: with no `--proxy`/`--proxy-file`, scans load
  `.gash/proxies/alive.txt` (then `all.txt`) or `GASH_PROXY_FILE`; `--no-proxy`
  disables it. The menu's "everything" preset now adds the detected pool with
  `per-request` rotation and a 45s cooldown.
- Same-site scans by default: without `--scope`, the target's registrable
  domain (eTLD+1) becomes the allowlist, so crawls no longer follow external
  links (Google, CDNs, social embeds) until the deadline. `--allow-external`
  restores open mode. New `--scan-timeout` (30m, menu everything 45m) and
  `--proxy-timeout` (8s per proxy attempt) keep 338-plugin scans from ending in
  "context deadline exceeded" skips.
- JS recon is capped at 90s of follow-up crawl/source-map time
  (`js_recon_budget_exhausted` stat) so a slow proxy pool cannot spend the scan
  deadline there. The report now carries phase timings (`crawl_ms`,
  `js_recon_ms`, `spa_crawl_ms`, `content_discovery_ms`, `fuzz_ms`,
  `plugins_ms`, `total_ms`) and per-phase progress labels, so a long scan shows
  exactly where the time went.
- Content discovery probes now run 8-way parallel instead of one-by-one, with a
  90s wordlist cap and a 60s cap on the follow-up mini-crawl. The spinner shows
  `N/80` progress, and the report exposes `content_budget_exhausted` /
  `content_follow_budget_exhausted` so a dead proxy pool no longer leaves the
  phase hanging.
- Discovery gets a `--crawl-timeout` budget (5m default, menu everything 10m) so
  a slow proxy pool cannot consume the scan deadline; partial crawl results are
  kept (`crawl_budget_exhausted`, `crawl_incomplete`). After six consecutive
  proxy failures for one host the pool switches that host to direct traffic
  (`proxy_direct_fallbacks`). Configuration/profile exclusions (auth, OOB not
  configured, untrusted Tier 3, profile-disabled detectors) are grouped as
  "not applicable" instead of "skipped" in the text report.
- HTTPS scans now fail fast once on an unverifiable target certificate instead
  of emitting the same TLS error for every plugin; install the issuing CA via
  `SSL_CERT_FILE` or fix the certificate. Runtime errors are grouped separately
  from skipped/not-applicable entries in the text report.
- Plug-and-play OOB via a stdlib interactsh client: `--oob-server interactsh`
  (public fleet, explicit third-party opt-in), `interactsh://host`
  (self-hosted), `--oob-token` / `GASH_OOB_TOKEN`, one session per scan. The
  local listener and custom self-hosted API keep working; no public service is
  ever selected by default.
- Modern WAF handling: Cloudflare/Akamai/Imperva/DataDome/PerimeterX/AWS
  WAF/Sucuri/F5/Kasada challenge pages are classified as untrusted even on
  200. Aggressive mode now tries up to 16 class-aware variants (SQLi comments
  and HEX/CHAR/CHR closures, percent/GBK quote and whitespace differentials,
  alternative XSS tags plus entity/Unicode forms that preserve the canary,
  shell `${IFS}`, encoded traversal, parser-confusion URLs), content-type
  switching (JSON under text/plain/vendor types, form under multipart),
  JSON/multipart parser differentials (duplicate keys, `\uXXXX` escapes,
  multipart duplicate fields), path-normalization confusion, and IP-spoofing
  headers, and requires two stable application responses. Challenge/429
  responses are counted as `waf_challenges` without a host-wide plugin skip;
  headless Chrome returns `payload_waf_challenge` / `control_waf_challenge`
  instead of treating challenge DOM as target evidence.
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
  with a boolean pair plus fourteen DBMS error probes (EXTRACTVALUE/UPDATEXML,
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
  `compose-lab.yaml` (DVWA/Juice Shop/WebGoat), `native-lab.yaml` (22 verified
  native scenarios), `bench/baselines/fixtures.json`.
- Pre-fix native-lab benchmark on Juice Shop 17.1.0, DVWA, and WebGoat 2023.8,
  all 22 scenarios independently verified: Gash standard
  `TP=11 FP=0 TN=9 FN=2` (P=1.000, R=0.846), Gash deep
  `TP=12 FP=0 TN=9 FN=1` (P=1.000, R=0.923), Nuclei v3.11.1
  `TP=5 FP=0 TN=9 FN=8` (P=1.000, R=0.385). Report:
  `docs/metrics/native-lab-2026-10-20.md`. These numbers predate the
  hash-route/dedupe changes and require re-measurement.
- Fragment/hash-route DOM discovery: links with `#/route?param=` become
  `fragment` injection points, rendered SPA search routes get bounded
  `q`/`query`/`search` fallbacks, and JS string/backtick literals add explicit
  hash-route parameters. Rendered URLs preserve the hash; fragment points are
  never sent to the server and are skipped by active fuzz/IDOR matrices.
- Browser execution probe: `host.oracles.browserExecution(point, payload[, opts])`
  requires `--browser-verify` and the deep build; it returns evidence only when
  the browser triggers and the neutral control stays clean. `ExecutionOracle`
  accepts browser-only confirmation without inventing a static sink, and
  `browserEligible` now covers GASH-003 firm/tentative findings.
- Benchmark finding dedupe: exact normalized fingerprint (or Nuclei
  path/title/template fallback) keeps the strongest-confidence row per tool,
  and hash-aware path normalization makes `#/search?q=` match `/search`.
- `dom-sink-basic` now uses the executable XSS payload, browser-probes
  fragment points, and emits one finding per route/sink/source instead of one
  per query parameter.
- Tests for rendered hash normalization, surface/SPA/JS hash-route extraction,
  fragment URL building, browser-only execution, browser execution binding,
  hash-aware bench paths/dedupe, and a real-Chrome `#/search?q=` deep test.
- Bench tests: unit suites plus an end-to-end critical-detector gate that runs
  a real gash binary against the fixture lab and fails on false positives,
  not-run outcomes, or reflected-XSS regressions.
- The manual `lab-recall` GitHub workflow now runs the compose-lab Gash/Nuclei
  benchmark with deep browser verification and uploads the report alongside the
  raw recall scans.
- Interactive menu is now keyboard-shortcut driven (each tab, submenu item, and
  choice has a single-key shortcut) and localized: TR/EN catalogs live in
  `cmd/gash/locales/{tr,en}.json` (embedded), with `--lang`, `GASH_LANG`, and a
  live `l` toggle in the menu.
- Live crawl progress: the `Sayfa & Yüzey Keşfi` phase now reports
  `done/total sayfa · host/path` for every crawl attempt, so a long crawl
  (aggressive profile allows up to 500 pages) no longer looks frozen.
- Honest plugin-status reporting: a plugin that stopped at its declared
  `max_requests`/rate ceiling is reported as `partial` (`StatusPartial`) with a
  separate `partial plugins` group and `partial_plugins` stat instead of being
  merged into `skipped`, which made it look like the plugin never ran.

### Fixed

- Removed the `csp-object-src-missing` finding: `object-src` falls back to
  `default-src`, so the check duplicated `csp-default-src-missing` and flagged
  compliant policies. Replaced by `permissions-policy-payment-missing`; the
  header pack stays at 28 plugins and the catalog at 438.
- Flarum and NodeBB fingerprints no longer match generic `/assets/...` paths;
  they require product-specific runtime markers, reducing tentative false
  positives.
- A panic inside a shared passive-cache fetch now closes the entry with an
  error instead of leaving waiters blocked and the key poisoned; the next
  caller can retry.
- CLI budget flag defaults now match the standard profile (2,000 per target /
  15,000 total) instead of advertising the stale 1,000/10,000 while profiles
  overrode them. Explicit flags still win.
- Text report summaries propagate writer errors and use singular "1 error".
- Interactive scan flow now honours its own "empty = automatic" report label:
  leaving the report field empty writes `reports/<target>.json` and `.text`
  (with the terminal summary kept), instead of producing no file at all. The
  menu also passes the new `--report-stamp`, so repeated scans of one target
  keep their own timestamped report instead of overwriting the previous one;
  the flag stays opt-in on the CLI to keep deterministic names for CI diffing.
- Benchmark `injectParam` fallback was nondeterministic because it selected the
  first key from a Go map; keys are now sorted, fixing the flaky
  `TestInjectParamFallbacks`.
- The deep fixture runner no longer asserts DOM detection under the standard
  dataset profile (which intentionally disables the execution detector); the
  browser hash-route proof remains covered by the deep headless tests.
- Tier 2 execution control requests replayed the payload when
  `env.ControlSend` was unset: `controlFor` rebuilt the control from the
  payload-bearing response URL, the oracle saw a dirty control, and every
  executable reflection/error/redirect evidence was rejected — live scans
  produced no firm reflected-XSS findings at all. Controls now neutralize all
  query values to `gash-control-neutral`; regression test
  `internal/bench/plugin_live_test.go`.
- Tier 1 endpoint-discovery feedback discarded its own results: probing four
  declared parameters exhausted the per-plugin request budget inside
  `ExecuteTier1WithOptions`, which returned an error and no candidates, so
  discovered endpoints (e.g. `/redirect?return_to=`) were never re-probed.
  The feedback loop now probes one deduplicated `(URL, param)` pair per
  cloned request (cap 6) and keeps results; fixture recall 0.500 -> 0.800
  (bench-fix1-redesign).
- Tier 2 send-budget starvation: `sqli-error-based.js` spent its 60-send
  budget on the first points in document order and never reached
  `/sqli/error` (point 9 of 79). Lazy per-point controls plus round-robin
  probing with a tail-trigger regression test; recall 0.800 -> 0.900
  (bench-fix2b).
- Stored XSS two-step missed findings in real runs: the plugin issued 158
  requests (79 points x store+render) and hit the plugin timeout, and its
  binding fetched the control from the same render URL so the persisted
  canary tainted the control. Base-grouped round-robin (60 sends), clean
  sibling-page control, and browser proof gated to static-accept attempts
  (ungated Chrome launches also timed out deep runs); standard recall
  0.900 -> 1.000, deep stored finding now `browser-confirmed`
  (bench-fix3 / bench-deep-fixes2).
- Refreshed `bench/baselines/fixtures.json` from the final standard run
  (TP=10, FP=0, precision=recall=1.000); `gash bench compare` passes.
- Compose-lab verification definitions corrected against a live Juice Shop
  v17.1.0 (official node22 release served natively, no docker): `q='` alone
  returns 200, so the SQLi `http-error` payload now carries the value prefix
  (`apple'`) and matches the real `SQLITE_ERROR ... syntax error` signature;
  the DOM `browser-exec` payload uses the documented alert form because the
  previous marker was set inside the iframe while the verifier probes the top
  window. The final native lab supersedes the earlier two-scenario subset and
  measures all three applications (`docs/metrics/native-lab-2026-10-20.md`).
- RFI live evidence ceiling: `file-inclusion-rfi` and
  `rfi-remote-include` now set `require_executable_context: true`, so loopback
  URL reflection is capped at `tentative` instead of claiming inclusion.
  Positive fixtures expect the same ceiling; live DVWA reflection with
  `allow_url_include=Off` is no longer presented as firm proof.
- Tier 2 SQLi corpus regression tests realigned with the prioritized
  prefix-preserving probes; full `go test ./...` passes.

### Changed

- The Gash/Nuclei fixture comparison is now measured (same target, pinned
  budgets, three auth runs): TP=10/FP=0/FN=0 vs TP=0/FP=0/FN=10, no negative
  disagreements; per-category tables filed in
  `docs/metrics/nuclei-comparison-2026-10-14.md`. The 22-scenario native
  comparison is also measured in `docs/metrics/native-lab-2026-10-20.md`.
  Docker compose recall stays BLOCKED without docker.
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

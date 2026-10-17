# Detector Inventory

This document catalogs all detectors (oracles + plugins) in GASH, their test coverage, and confidence characteristics.

## Oracles (Engine-Owned)

`reflection` now enforces the requested context set. It distinguishes HTML
text, ordinary attributes, URL attributes, event-handler attributes,
executable JavaScript, JavaScript strings/comments, and inert JSON script
blocks. A random canary is not execution proof; static XSS evidence requires a
parser-recognized execution payload, a clean control, and no blocking inline CSP.
Browser-confirmed XSS additionally requires controlled headless execution.
execution, Stored XSS write/render flows, and real-target recall remain
unmeasured or blocked as noted below.

For the `reflection` oracle, the ladder is `tentative` ->
`static-execution-evidence` -> `confirmed`. The middle state requires a
parser-recognized execution call and clean control; `confirmed` is reserved
for a controlled headless browser result.

| Oracle | Plugin(s) Using | Tier | Confidence Ladder | Requires Control | Active Probing | OOB | Notes |
|--------|-----------------|------|-------------------|------------------|----------------|-----|-------|
| `reflection` | XSS plugins, `xss-stored-basic`, `xxe-reflected-basic`, `rfi-remote-include` | 1/2/3 | tentative → firm → confirmed | Yes (for confirmed) | Yes (canary injection) | No | HTML tokenizer + context analysis; GASH-001/002/007/009/011/014/017; deep-research: stored-XSS sync-render (static-execution-evidence max) + in-band XXE canary-entity (firm, file:// YOK); RFI loopback-canary reflection (tentative max, dis fetch YOK) |
| `stored` | `xss-stored-two-step` | 1/2 | tentative → static-execution-evidence → confirmed | Yes | Yes (write+render canary) | No | GASH-002 two-exchange write/render plus clean control; render checked with reflection discipline; static-execution-evidence max without headless, browser-confirmed with controlled run |
| `header` | `missing-security-headers`, `crlf-header-injection`, `jwt-token-exposure`, `csrf-token-absence`, `clickjacking-frameable`, `missing-rate-limit`, `host-header-injection` | 1 | confirmed only, except `ratelimit` mode (tentative ceiling) and `host_header` mode (firm ceiling) | No (deterministic) | No (passive) except `ratelimit` burst and `host_header` canary probes | No | GASH-019: logic-based header absence/weakness; P1.4: CRLF/JWT modes; deep-research: csrf (GASH-020 POST-form token screen) + frame (GASH-019 clickjacking) modes; lab-batch: ratelimit (GASH-032 missing-rate-limit, budgeted anonymous burst, tentative ceiling, 429/headers reject); lab-batch: host_header (GASH-035 Host/X-Forwarded-Host/Forwarded canary reflection, GET-only, absolute-URI variant out of scope) |
| `redirect` | `open-redirect-param` | 1 | firm → confirmed | Yes | Yes (payload) | No | GASH-016: Location parse + host compare + DNS double-check; payload variants (bare host, path, encoded slash) added in lab batch |
| `error` | SQLi plugins, `path-traversal-error`, `error-message-disclosure`, `command-injection-error`, `insecure-deserialization-error`, `subdomain-takeover-basic`, `xpath-injection-error`, `backup-file-exposure` | 1/2 | firm → confirmed (deserialization/takeover/xpath/backup modes: firm ceiling) | Yes | Yes (payload) | No | GASH-004: DB signature library + control absence; P1.4: path_traversal/generic_error modes; lab-batch: deserialization (GASH-029 Java/Python/PHP, firm, gadget YOK) + takeover (GASH-030 unclaimed-service bodies, DNS-dependent firm, out-of-scope fetch YOK); lab-batch: xpath (GASH-034 parser error signatures, firm) + backup_file (GASH-037 fixed 12-path marker set with soft-404 control, firm) |
| `differential` | Boolean/blind SQLi, `idor-differential`, `ldap-injection-differential`, `hpp-parameter-pollution`, `hpp-duplicate-emission`, `mass-assignment-basic`, `nosql-auth-bypass-differential` | 1/2 | confirmed only (N=3); declared `confidence_ceiling` may downgrade (mass-assignment: firm; nosql-auth-bypass: firm) | Yes | Yes (true/false) | No | GASH-005: 3/3 masked stability + divergence; P1.4: IDOR/LDAP modes; deep-research: HPP polluted-vs-single divergence; Tier 2 HPP native duplicate-key (`id=1&id=2`) emission; content-exposure modu (GASH-028: baseline-negatif + içerik sinyali, N=1 deterministik, yeni oracle YOK); lab-batch: mass-assignment (GASH-031 extra-field binding, non-escalating values, firm ceiling, never upgrades); lab-batch: nosql-auth-bypass (GASH-039 operator-injected JSON body vs invalid-credential control, `false_body` support, 3 repeats, session never reused, firm ceiling) |
| `timing` | Time-based SQLi, `sqli-time-based`, `command-injection-timing` | 1/2 | firm max (no confirmed) | Yes | Yes (delay payloads) | No | GASH-006/010: statistical Mann-Whitney U + baseline stddev; P1.4: timing mode; Tier 2 `host.oracles.timing` (rttMs); deep-research: blind OS-command timing with harmless sleep canary (firm ceiling, confirmed YOK) |
| `smuggling-differential` | (engine smuggle recon: `engine-smuggle-recon`, no plugin file) | recon | firm max (dual-channel only, no confirmed) | Yes (paired control) | Yes (raw-TCP CL.TE/TE.CL/TE.TE, `--active` + `--aggressive` only) | No | GASH-033 (CWE-444): ambiguous CL+TE + identical harmless follow-up on one keep-alive conn; follow-up divergence AND delay/timeout required; single-channel rejects; user-supplied target dialed, scope preflight only with `--scope` (out-of-scope target = zero sockets), <=10 requests, 5 s cap |
| `verb-tamper` | `verb-tampering-bypass` | 1 | firm max (no confirmed) | Yes (401/403 baseline) | Yes (HEAD/OPTIONS + method-override headers) | No | GASH-036 (CWE-650): protected baseline required; variant must be 2xx with >=24-byte body differing from masked baseline; empty/identical bodies reject; only idempotent read variants are sent (no PUT/DELETE/PATCH) |
| `execution` | DOM XSS `dom-sink-basic` (static) | 2 | tentative → firm (headless `confirmed` BLOCKED) | No | No (passive body scan) | No | GASH-003 static sink/source; `host.oracles.execution`; browser path needs headless build |
| `version` | Version disclosure, `graphql-endpoint-discovery`, `server-version-disclosure`, `cve-dependency-scan`, `graphql-introspection-enabled` | 1 | tentative → firm | No | No (passive banner), except `graphql_introspection` mode (anonymous introspection POST) | No | GASH-021: banner + optional behavior verified; P1.4: graphql mode; deep-research: vulnerable-dependency screen (banner-only tentative, confirmed YOK); lab-batch: graphql_introspection (GASH-038 `__schema`+`queryType` without `errors` envelope, firm) |
| `cookie` | `cookie-flags` | 1 | firm → confirmed | No (deterministic) | No (passive) | No | GASH-022: Secure/HttpOnly/SameSite logic grading |
| `cors` | `cors-misconfig` | 1 | firm → confirmed | No (deterministic) | No (passive) | No | GASH-023: ACAO wildcard/reflection + credentials |
| `error` | `file-upload-unrestricted` | 1 | firm → confirmed | Yes | Yes (payload) | No | P1.4: generic_error mode |
| `reflection` | `template-injection-reflection` | 1 | tentative → firm → confirmed | Yes | Yes (canary) | No | P1.4: SSTI payload reflection |
| `oob` | `xxe-oob`, `blind-sqli-oob` | 1 | confirmed only | No | Yes (OOB payload) | **Required** | P1.4: blind XXE/SQLi via OOB |
| `tls` | (engine proto recon: `proto-tls-cert`) | recon | confirmed only (observed fact) | No (handshake observation) | No (no payload sent) | No | P2.1: GASH-024 expiry/chain/hostname/version; safe-profile |
| `dns` | (engine proto recon: `proto-dns-records`, `proto-dns-caa`) | recon | firm max (resolver-dependent) | No (read queries) | No (DNS reads only, AXFR yok) | No | P2.1: GASH-025 SPF/DMARC + GASH-027 CAA (miekg/dns pinned); safe-profile |
| `tcp` | (engine proto recon: `proto-tcp-banner`, explicit `--tcp-banner`) | recon | tentative only (unverified banner) | No | Yes (connect+read, no write; `--active` şart) | No | P2.1: GASH-026 banner; scope-checked |
| `header` | `jwt-alg-confusion` | 1 | confirmed only | No (deterministic) | No (passive) | No | P1.4: jwt_alg mode |
| `differential` | `idor-differential` | 1 | confirmed only (N=3) | Yes | Yes (true/false) | No | P1.4: IDOR via differential |
| `execution` | DOM XSS (Deep) | 3 | tentative → firm → confirmed | Yes (for confirmed) | Yes (headless) | No | GASH-003: headless-enabled build-tag `deep` |
| `oob` | Blind SSRF/SQLi/RCE | 1/2/3 | confirmed only | No | Yes (OOB payload) | **Required** | GASH-008/010/012/013: single cryptographically-random callback match |

## Reference Plugins (Tier 2 JS)

| Plugin ID | Oracle | Phase | Safe | Active | Deep | Severity | Tags | Fixture Path |
|-----------|--------|-------|------|--------|------|----------|------|--------------|
| `xss-reflected-basic` | reflection | probe | false | true | false | high | xss, client | `tests/fixtures/xss-reflected-basic/` |
| `sqli-error-based` | error | probe | true | false | false | high | sqli, injection | `tests/fixtures/sqli-error-based/` |
| `sqli-boolean-differential` | differential | probe | true | false | false | high | sqli, injection | `tests/fixtures/sqli-boolean-differential/` |
| `ssrf-blind-oob` | oob | probe | false | true | false | critical | ssrf, blind, oob | `tests/fixtures/ssrf-blind-oob/` |
| `dom-sink-basic` | execution | probe | true | false | false | medium | xss, dom, client | `tests/fixtures/dom-sink-basic/` |
| `hpp-duplicate-emission` | differential | probe | false | true | false | medium | hpp, parameter-pollution, injection, differential | `tests/fixtures/hpp-duplicate-emission/` |
| `xss-stored-two-step` | stored | probe | false | true | false | high | xss, stored-xss, injection, reflection | `tests/fixtures/xss-stored-two-step/` |

## Reference Plugins (Tier 1 YAML)

| Plugin ID | Oracle | Phase | Safe | Active | Deep | Severity | Tags | Fixture Path |
|-----------|--------|-------|------|--------|------|----------|------|--------------|
| `missing-security-headers` | header | probe | true | false | false | low | headers, misconfig | `tests/fixtures/missing-security-headers/` |
| `open-redirect-param` | redirect | probe | true | false | false | medium | redirect, client | `tests/fixtures/open-redirect-param/` |
| `cors-misconfig` | cors | probe | true | false | false | medium | cors, misconfig | `tests/fixtures/cors-misconfig/` |
| `cookie-flags` | cookie | probe | true | false | false | medium | cookies, misconfig | `tests/fixtures/cookie-flags/` |
| `crlf-header-injection` | header | probe | true | false | false | medium | crlf, http-splitting, header-injection, misconfig | `tests/fixtures/crlf-header-injection/` |
| `path-traversal-error` | error | probe | true | true | false | high | path-traversal, file-access, lfi, error-signature | `tests/fixtures/path-traversal-error/` |
| `error-message-disclosure` | error | probe | true | false | false | medium | error-disclosure, information-leakage, debug, stack-trace | `tests/fixtures/error-message-disclosure/` |
| `jwt-token-exposure` | header | probe | true | false | false | high | jwt, token-exposure, authentication, information-leakage | `tests/fixtures/jwt-token-exposure/` |
| `graphql-endpoint-discovery` | version | discovery | true | false | false | low | graphql, api-discovery, endpoint-enumeration, reconnaissance | `tests/fixtures/graphql-endpoint-discovery/` |
| `file-upload-unrestricted` | error | probe | false | true | false | high | file-upload, unrestricted, rce, error-disclosure, information-leakage | `tests/fixtures/file-upload-unrestricted/` |
| `template-injection-reflection` | reflection | probe | false | true | false | critical | ssti, template-injection, injection, rce, reflection | `tests/fixtures/template-injection-reflection/` |
| `xxe-oob` | oob | probe | false | true | false | critical | xxe, blind-xxe, oob, xml, injection, ssrf | `tests/fixtures/xxe-oob/` |
| `jwt-alg-confusion` | header | probe | true | false | false | high | jwt, algorithm-confusion, authentication, crypto, token-forgery | `tests/fixtures/jwt-alg-confusion/` |
| `idor-differential` | differential | probe | true | true | false | high | idor, authorization, broken-access-control, differential, boolean | `tests/fixtures/idor-differential/` |
| `sqli-time-based` | timing | probe | false | true | false | high | sqli, injection, blind, timing | `tests/fixtures/sqli-time-based/` |
| `command-injection-error` | error | probe | false | true | false | critical | command-injection, injection, rce, error-signature | `tests/fixtures/command-injection-error/` |
| `server-version-disclosure` | version | probe | true | false | false | low | version, information-disclosure, reconnaissance, banner | `tests/fixtures/server-version-disclosure/` |
| `blind-sqli-oob` | oob | probe | false | true | false | critical | sqli, blind, oob, injection, data-exfiltration | `tests/fixtures/blind-sqli-oob/` |
| `ldap-injection-differential` | differential | probe | false | true | false | high | ldap, injection, differential, boolean, authorization | `tests/fixtures/ldap-injection-differential/` |
| `command-injection-timing` | timing | probe | false | true | false | high | command-injection, injection, blind, timing | `tests/fixtures/command-injection-timing/` |
| `xss-stored-basic` | reflection | probe | false | true | false | high | xss, stored-xss, injection, reflection | `tests/fixtures/xss-stored-basic/` |
| `xxe-reflected-basic` | reflection | probe | false | true | false | high | xxe, xml, injection, reflection | `tests/fixtures/xxe-reflected-basic/` |
| `csrf-token-absence` | header | probe | true | false | false | medium | csrf, authentication, misconfig | `tests/fixtures/csrf-token-absence/` |
| `clickjacking-frameable` | header | probe | true | false | false | low | clickjacking, headers, misconfig | `tests/fixtures/clickjacking-frameable/` |
| `hpp-parameter-pollution` | differential | probe | false | true | false | medium | hpp, parameter-pollution, injection, differential | `tests/fixtures/hpp-parameter-pollution/` |
| `cve-dependency-scan` | version | probe | true | false | false | medium | cve, dependencies, version, supply-chain | `tests/fixtures/cve-dependency-scan/` |
| `rfi-remote-include` | reflection | probe | false | true | false | high | rfi, file-include, lfi, injection, reflection, ssrf | `tests/fixtures/rfi-remote-include/` |
| `sqli-auth-bypass` | error | probe | false | true | false | critical | sqli, injection, auth-bypass, error | `tests/fixtures/sqli-auth-bypass/` |
| `sqli-stacked-time` | timing | probe | false | true | false | high | sqli, injection, stacked, timing | `tests/fixtures/sqli-stacked-time/` |
| `ssrf-cloud-metadata` | reflection | probe | false | true | false | high | ssrf, cloud, metadata, reflection | `tests/fixtures/ssrf-cloud-metadata/` |
| `xss-attribute-injection` | reflection | probe | false | true | false | high | xss, injection, reflection | `tests/fixtures/xss-attribute-injection/` |
| `nosql-injection-error` | error | probe | false | true | false | high | nosql, injection, error-signature | `tests/fixtures/nosql-injection-error/` |
| `web-cache-poisoning-basic` | differential | probe | false | true | false | medium | cache-poisoning, web-cache, differential | `tests/fixtures/web-cache-poisoning-basic/` |
| `insecure-deserialization-error` | error | probe | false | true | false | high | deserialization, injection, error-signature | `tests/fixtures/insecure-deserialization-error/` |
| `subdomain-takeover-basic` | error | probe | true | false | false | high | takeover, subdomain, misconfig | `tests/fixtures/subdomain-takeover-basic/` |
| `mass-assignment-basic` | differential | probe | false | true | false | high | mass-assignment, authorization, differential | `tests/fixtures/mass-assignment-basic/` |
| `missing-rate-limit` | header | probe | false | true | false | medium | rate-limit, brute-force, misconfig | `tests/fixtures/missing-rate-limit/` |
| `xpath-injection-error` | error | probe | false | true | false | high | xpath, injection, error-signature | `tests/fixtures/xpath-injection-error/` |
| `host-header-injection` | header | probe | false | true | false | medium | host-header, injection, reflection | `tests/fixtures/host-header-injection/` |
| `verb-tampering-bypass` | verb-tamper | probe | false | true | false | high | verb-tampering, access-control, authorization | `tests/fixtures/verb-tampering-bypass/` |
| `backup-file-exposure` | error | probe | false | true | false | medium | backup-file, information-disclosure, file-access | `tests/fixtures/backup-file-exposure/` |
| `graphql-introspection-enabled` | version | probe | false | true | false | low | graphql, introspection, information-disclosure | `tests/fixtures/graphql-introspection-enabled/` |
| `nosql-auth-bypass-differential` | differential | probe | false | true | false | critical | nosql, authentication, differential, auth-bypass | `tests/fixtures/nosql-auth-bypass-differential/` |

## Reference Plugins (Tier 3 Native)

| Plugin ID | Oracle | Phase | Safe | Active | Deep | Severity | Tags | Manifest |
|-----------|--------|-------|------|--------|------|----------|------|----------|
| `poc-native-header-check` | header | probe | true | false | false | low | headers, native | `plugins/native/poc-native-header-check.gashplugin.yaml` |

## Confidence Ladder Summary

| Confidence | Meaning | Oracle Sources |
|------------|---------|----------------|
| `tentative` | Signal present but weak/unverified | reflection (encoded), version (banner-only), execution (static only), header/ratelimit (signal absence) |
| `static-execution-evidence` | Parser-recognized client execution shape with clean control; browser not run | reflection (executable payload + control) |
| `firm` | Strong signal, single-channel, reproducible | reflection (text), redirect (no control), differential (partial), timing, cookie (Secure on http), cors (wildcard no creds), header (CSP unsafe-inline), error (path_traversal/generic_error no control), version (graphql path), header (host_header canary reflection), verb-tamper (protected baseline + 2xx variant), error (xpath/backup_file), differential (nosql-auth-bypass, firm ceiling), version (graphql_introspection) |
| `confirmed` | Multi-channel verified, control pass, reproducible | reflection (headless execution + control), header (missing, crlf, jwt), redirect (control), error (control), differential (3/3), cookie (HttpOnly/Secure on https), cors (wildcard+creds/reflection+creds), oob (callback), execution (headless+control), version (graphql body) |

## Fixture Coverage

Each oracle has positive/negative fixture sets under `tests/fixtures/<plugin-id>/positive/` and `negative/`. The `plugintest.Run` evaluates precision/recall against these.

The reflected-XSS fixture set currently measures TP=2, FP=0, TN=8, FN=0 at
`static-execution-evidence` (dataset hash `27bba26a7f282df1de7486a433f53ce926eb74fe2a5c765cac163cae49fbd0c5`).
The set includes executable payloads, text/encoded/comment/style reflections,
JavaScript strings, and `application/json` script data. This is a fixture
measurement, not browser execution or real-target recall.

## WAF Measurement Boundary

`probe.Client` separates `waf_detected` from `waf_bypassed`. Aggressive mode
tries at most five scoped mutations, and increments `waf_bypassed` only after
two equivalent non-blocking application responses. Auth rejection, soft-404,
challenge/error pages, and unstable dynamic bodies do not count. No real WAF
or external lab bypass rate is measured in this repository; such results stay
`unmeasured` until an authorized, pinned lab run is recorded.

## Gap Analysis (P1.2 Profile Impact)

| Profile | Active Detectors | Request Types | Budget |
|---------|------------------|---------------|--------|
| Safe | header, redirect, cors, cookie, version, tls, dns, crlf-header-injection, error-message-disclosure, jwt-token-exposure, graphql-endpoint-discovery, jwt-alg-confusion, csrf-token-absence, clickjacking-frameable, cve-dependency-scan | GET/HEAD/OPTIONS only | Low (100 req/target) |
| Standard | Safe + tcp, reflection, error, differential, path-traversal-error, file-upload-unrestricted, template-injection-reflection, idor-differential, xss-stored-basic, xxe-reflected-basic, hpp-parameter-pollution, insecure-deserialization-error, subdomain-takeover-basic, mass-assignment-basic, missing-rate-limit | GET/POST + params | Medium (500 req/target) |
| Deep | Standard + execution (headless), timing, oob, xxe-oob, command-injection-timing | All + browser | High (2000 req/target) |

## P2 Capabilities (engine-owned, no plugin file)

| Capability | Entry | Notes |
|---|---|---|
| Proto recon (TLS/DNS) | `engine.runProtoRecon` | Safe-profile passive; findings GASH-024/025/027; see `docs/proto-checks.md` |
| TCP banner (explicit) | `engine.runProtoRecon` + `--tcp-banner` | `--active` required; GASH-026 tentative; scope-checked |
| Content discovery (wordlist) | `discovery.DiscoverContent` via `engine.runLive` | `--active` gated engine-recon (no plugin file); GASH-028 tentative/confirmed; tech-pinned wordlists (`internal/discovery/wordlists/`, <=50 lines each); baseline-negatif + içerik sinyali, çıplak 200 tentative max; `.git`-class HEAD-only (tentative max); smart-recurse backup suffixes (depth <=2); hits feed crawler surface + bounded dir mini-crawl; see `docs/metrics/content-discovery-2026-10-16.md` |
| Request smuggling (CL.TE/TE.CL/TE.TE) | `smuggle.Scan` via `engine.runLive` | `--active` + `--aggressive` gated engine-recon (no plugin file); GASH-033 (CWE-444) firm max (dual-channel only, confirmed never); raw-TCP keep-alive pairs, user-supplied target (operator responsibility / written authorization), scope preflight only with `--scope` (out-of-scope = zero sockets), <=10 requests, 5 s cap, harmless bodies; HTTPS SNI/hostname verified, h2 = skip; see `docs/metrics/smuggle-differential.md` |
| Conditional chain | `plugin.ResolveChain` | requires_tech (`--tech`) + provider cascade; see `docs/plugin-development.md` |
| Auth context | `auth.Context` + probe `ExtraHeaders` | `--auth-header`/`--cookie`/`--basic-auth`; see `docs/auth.md` |
| OpenAPI test plan | `discovery.ParseSpec` + `gash openapi` | Offline; see `docs/api-discovery.md` |
| JUnit + reporter registry | `reporter.Register/Write` | `junit` built-in; see `docs/report-formats.md`, `docs/ci-integration.md` |

# Detector Inventory

This document catalogs all detectors (oracles + plugins) in GASH, their test coverage, and confidence characteristics.

## Oracles (Engine-Owned)

| Oracle | Plugin(s) Using | Tier | Confidence Ladder | Requires Control | Active Probing | OOB | Notes |
|--------|-----------------|------|-------------------|------------------|----------------|-----|-------|
| `reflection` | XSS plugins | 1/2/3 | tentative → firm → confirmed | Yes (for confirmed) | Yes (canary injection) | No | HTML tokenizer + context analysis; GASH-001/002/007/009/011/014/017 |
| `header` | `missing-security-headers`, `crlf-header-injection`, `jwt-token-exposure` | 1 | confirmed only (no tentative) | No (deterministic) | No (passive) | No | GASH-019: logic-based header absence/weakness; P1.4: CRLF/JWT modes |
| `redirect` | `open-redirect-param` | 1 | firm → confirmed | Yes | Yes (payload) | No | GASH-016: Location parse + host compare + DNS double-check |
| `error` | SQLi plugins, `path-traversal-error`, `error-message-disclosure`, `command-injection-error` | 1/2 | firm → confirmed | Yes | Yes (payload) | No | GASH-004: DB signature library + control absence; P1.4: path_traversal/generic_error modes |
| `differential` | Boolean/blind SQLi, `idor-differential`, `ldap-injection-differential` | 1/2 | confirmed only (N=3) | Yes | Yes (true/false) | No | GASH-005: 3/3 masked stability + divergence; P1.4: IDOR/LDAP modes |
| `timing` | Time-based SQLi, `sqli-time-based` | 1/2 | firm max (no confirmed) | Yes | Yes (delay payloads) | No | GASH-006/010: statistical Mann-Whitney U + baseline stddev; P1.4: timing mode; Tier 2 `host.oracles.timing` (rttMs) |
| `execution` | DOM XSS `dom-sink-basic` (static) | 2 | tentative → firm (headless `confirmed` BLOCKED) | No | No (passive body scan) | No | GASH-003 static sink/source; `host.oracles.execution`; browser path needs headless build |
| `version` | Version disclosure, `graphql-endpoint-discovery`, `server-version-disclosure` | 1 | tentative → firm | No | No (passive banner) | No | GASH-021: banner + optional behavior verified; P1.4: graphql mode |
| `cookie` | `cookie-flags` | 1 | firm → confirmed | No (deterministic) | No (passive) | No | GASH-022: Secure/HttpOnly/SameSite logic grading |
| `cors` | `cors-misconfig` | 1 | firm → confirmed | No (deterministic) | No (passive) | No | GASH-023: ACAO wildcard/reflection + credentials |
| `error` | `file-upload-unrestricted` | 1 | firm → confirmed | Yes | Yes (payload) | No | P1.4: generic_error mode |
| `reflection` | `template-injection-reflection` | 1 | tentative → firm → confirmed | Yes | Yes (canary) | No | P1.4: SSTI payload reflection |
| `oob` | `xxe-oob`, `blind-sqli-oob` | 1 | confirmed only | No | Yes (OOB payload) | **Required** | P1.4: blind XXE/SQLi via OOB |
| `tls` | (engine proto recon: `proto-tls-cert`) | recon | confirmed only (observed fact) | No (handshake observation) | No (no payload sent) | No | P2.1: GASH-024 expiry/chain/hostname/version; safe-profile |
| `dns` | (engine proto recon: `proto-dns-records`) | recon | firm max (resolver-dependent) | No (read queries) | No (DNS reads only, AXFR yok) | No | P2.1: GASH-025 SPF/DMARC; safe-profile; CAA yok (stdlib gap) |
| `tcp` | (engine proto recon: `proto-tcp-banner`, explicit `--tcp-banner`) | recon | tentative only (unverified banner) | No | Yes (connect+read, no write; `--active` şart) | No | P2.1: GASH-026 banner; scope-checked |
| `header` | `jwt-alg-confusion` | 1 | confirmed only | No (deterministic) | No (passive) | No | P1.4: jwt_alg mode |
| `differential` | `idor-differential` | 1 | confirmed only (N=3) | Yes | Yes (true/false) | No | P1.4: IDOR via differential |
| `execution` | DOM XSS (Deep) | 3 | tentative → firm → confirmed | Yes (for confirmed) | Yes (headless) | No | GASH-003: headless-enabled build-tag `deep` |
| `oob` | Blind SSRF/SQLi/RCE | 1/2/3 | confirmed only | No | Yes (OOB payload) | **Required** | GASH-008/010/012/013: single cryptographically-random callback match |

## Reference Plugins (Tier 2 JS)

| Plugin ID | Oracle | Phase | Safe | Active | Deep | Severity | Tags | Fixture Path |
|-----------|--------|-------|------|--------|------|----------|------|--------------|
| `xss-reflected-basic` | reflection | probe | true | false | false | high | xss, client | `tests/fixtures/xss-reflected-basic/` |
| `sqli-error-based` | error | probe | true | false | false | high | sqli, injection | `tests/fixtures/sqli-error-based/` |
| `sqli-boolean-differential` | differential | probe | true | false | false | high | sqli, injection | `tests/fixtures/sqli-boolean-differential/` |
| `ssrf-blind-oob` | oob | probe | false | true | false | critical | ssrf, blind, oob | `tests/fixtures/ssrf-blind-oob/` |
| `dom-sink-basic` | execution | probe | true | false | false | medium | xss, dom, client | `tests/fixtures/dom-sink-basic/` |

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

## Reference Plugins (Tier 3 Native)

| Plugin ID | Oracle | Phase | Safe | Active | Deep | Severity | Tags | Manifest |
|-----------|--------|-------|------|--------|------|----------|------|----------|
| `poc-native-header-check` | header | probe | true | false | false | low | headers, native | `plugins/native/poc-native-header-check.gashplugin.yaml` |

## Confidence Ladder Summary

| Confidence | Meaning | Oracle Sources |
|------------|---------|----------------|
| `tentative` | Signal present but weak/unverified | reflection (encoded), version (banner-only), execution (static only) |
| `firm` | Strong signal, single-channel, reproducible | reflection (text), redirect (no control), differential (partial), timing, cookie (Secure on http), cors (wildcard no creds), header (CSP unsafe-inline), error (path_traversal/generic_error no control), version (graphql path) |
| `confirmed` | Multi-channel verified, control pass, reproducible | reflection (executable+control), header (missing, crlf, jwt), redirect (control), error (control), differential (3/3), cookie (HttpOnly/Secure on https), cors (wildcard+creds/reflection+creds), oob (callback), execution (headless+control), version (graphql body) |

## Fixture Coverage

Each oracle has positive/negative fixture sets under `tests/fixtures/<plugin-id>/positive/` and `negative/`. The `plugintest.Run` evaluates precision/recall against these.

## Gap Analysis (P1.2 Profile Impact)

| Profile | Active Detectors | Request Types | Budget |
|---------|------------------|---------------|--------|
| Safe | header, redirect, cors, cookie, version, tls, dns, crlf-header-injection, error-message-disclosure, jwt-token-exposure, graphql-endpoint-discovery, jwt-alg-confusion | GET/HEAD/OPTIONS only | Low (100 req/target) |
| Standard | Safe + tcp, reflection, error, differential, path-traversal-error, file-upload-unrestricted, template-injection-reflection, idor-differential | GET/POST + params | Medium (500 req/target) |
| Deep | Standard + execution (headless), timing, oob, xxe-oob | All + browser | High (2000 req/target) |

## P2 Capabilities (engine-owned, no plugin file)

| Capability | Entry | Notes |
|---|---|---|
| Proto recon (TLS/DNS) | `engine.runProtoRecon` | Safe-profile passive; findings GASH-024/025; see `docs/proto-checks.md` |
| TCP banner (explicit) | `engine.runProtoRecon` + `--tcp-banner` | `--active` required; GASH-026 tentative; scope-checked |
| Conditional chain | `plugin.ResolveChain` | requires_tech (`--tech`) + provider cascade; see `docs/plugin-development.md` |
| Auth context | `auth.Context` + probe `ExtraHeaders` | `--auth-header`/`--cookie`/`--basic-auth`; see `docs/auth.md` |
| OpenAPI test plan | `discovery.ParseSpec` + `gash openapi` | Offline; see `docs/api-discovery.md` |
| JUnit + reporter registry | `reporter.Register/Write` | `junit` built-in; see `docs/report-formats.md`, `docs/ci-integration.md` |
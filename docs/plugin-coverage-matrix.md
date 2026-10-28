# Plugin Coverage Matrix

This document catalogs all detectors/plugins in Gash, organized by security class, with their current coverage status, supported techniques, evidence types, and gaps.

## Legend

- **Status**: `Complete` (fully implemented with fixtures, proper evidence ladder), `Partial` (implemented but missing some techniques/evidence), `Gap` (not implemented)
- **Oracle**: Engine-owned oracle used
- **Tier**: YAML (Tier 1), JS (Tier 2), Native (Tier 3)
- **Confidence Ceiling**: Maximum confidence this plugin can emit
- **OOB**: `required` / `optional` / `none`

---

## 1. Cross-Site Scripting (XSS)

| Plugin ID | Tier | Oracle | Phase | Safe | Active | Confidence Ceiling | OOB | Fixtures | Status | Notes |
|-----------|------|--------|-------|------|--------|-------------------|-----|----------|--------|-------|
| `xss-reflected-basic` | JS | reflection | probe | false | true | confirmed (with browser-verify) | none | ✓ | Complete | HTML tokenizer + context analysis; static-execution-evidence without browser |
| `xss-attribute-injection` | YAML | reflection | probe | false | true | confirmed (with browser-verify) | none | ✓ | Complete | Attribute injection via reflection oracle |
| `xss-stored-basic` | YAML | reflection | probe | false | true | static-execution-evidence | none | ✓ | Partial | Single-request stored XSS reflection; no write/render flow |
| `xss-stored-two-step` | JS | stored | probe | false | true | confirmed (with browser-verify) | none | ✓ | Complete | Two-exchange write/render with clean control |
| `dom-sink-basic` | JS | execution | probe | true | false | firm (confirmed with deep+browser) | none | ✓ | Complete | Static sink/source analysis; headless for confirmed |
| `xss-reflected-json-body` | JS | reflection | probe | false | true | static-execution-evidence | none | ✓ | Complete | Per-field JSON body injection with `application/json`; executing pattern echoed into HTML |
| `xss-stored-json-api` | JS | stored | probe | false | true | static-execution-evidence | none | ✓ | Complete | JSON write plus render flow; sibling render page is the clean control |
| `xss-reflected-url-context` | JS | reflection | probe | false | true | static-execution-evidence | none | ✓ | Complete | `javascript:`-scheme payload into a URL sink (`href`/`src`); `contexts: [url-executable]` + clean control, lowercase and mixed-case |
| `xss-stored-header-two-step` | JS | stored | probe | false | true | static-execution-evidence | none | ✓ | Complete | Header-borne write (`Referer`) plus re-read render; a sibling page that never saw the payload is the clean control |
| `xss-path-segment` | JS | reflection | probe | false | true | static-execution-evidence | none | ✓ | Complete | Encoded executable payload appended as a path segment; the unmodified base page is the clean control |
| `xss-reflected-header` | JS | reflection | probe | false | true | static-execution-evidence | none | ✓ | Complete | User-Agent/Referer reflected into executable HTML; the header-less re-fetch is the clean control |

**Gaps:**
- No DOM XSS plugin for fragment/hash routes without deep build (engine-owned `browserExecution` oracle exists but no Tier 1/2 plugin)
- No mutation XSS (mXSS) detection
- No XSS via `postMessage` / cross-origin messaging
- No XSS in WebSocket messages
- JSON body reflection and JSON API stored flows are covered; a single render base without a sibling page yields no candidate (no clean control)
- Path-segment and request-header reflection are covered by `xss-path-segment` and `xss-reflected-header`; custom application headers are not enumerated

---

## 2. SQL Injection

| Plugin ID | Tier | Oracle | Phase | Safe | Active | Confidence Ceiling | OOB | Fixtures | Status | Notes |
|-----------|------|--------|-------|------|--------|-------------------|-----|----------|--------|-------|
| `sqli-error-based` | JS | error | probe | true | false | confirmed | none | ✓ | Complete | DB signature library + control absence |
| `sqli-boolean-differential` | JS | differential | probe | true | false | confirmed | optional | ✓ | Complete | 3/3 stability + control |
| `sqli-time-based` | YAML | timing | probe | false | true | firm | optional | ✓ | Complete | Mann-Whitney U + baseline stddev |
| `sqli-stacked-time` | YAML | timing | probe | false | true | firm | optional | ✓ | Complete | Stacked query timing |
| `sqli-auth-bypass` | YAML | error | probe | false | true | confirmed | none | ✓ | Complete | Auth bypass via error signatures |
| `blind-sqli-oob` | YAML | oob | probe | false | true | confirmed | required | ✓ | Complete | OOB callback required; MSSQL/MySQL/Oracle payloads |
| `sqli-second-order` | JS | error | probe | false | true | confirmed | none | ✓ | Complete | Write + neutral re-read correlation; pre-write baseline is the control (state-borne signature only) |
| `sqli-second-order-timing` | JS | timing | probe | false | true | firm | none | ✓ | Complete | Write + timed neutral re-reads vs pre-write baseline; statistical timing ceiling stays firm |
| `sqli-json-body-error` | JS | error | probe | false | true | confirmed | none | ✓ | Complete | Per-field JSON body injection with explicit `application/json`; neutral-value control per payload |
| `sqli-json-body-differential` | JS | differential | probe | false | true | confirmed | none | ✓ | Complete | JSON body true/false closures into the discovered field; echo guard + 3/3 stability |
| `sqli-json-body-timing` | JS | timing | probe | false | true | firm | none | ✓ | Complete | JSON body delay payloads measured against a neutral baseline; timing ceiling stays firm |
| `sqli-oob-second-order` | JS | oob | probe | false | true | confirmed | required | ✓ | Complete | Write plus neutral re-read at the same point with a callback-only closure (no output, no delay) |
| `sqli-xml-body-error` | JS | error | probe | false | true | confirmed | none | ✓ | Complete | XML/SOAP body element injection with an explicit `application/xml` document; neutral-document control |
| `sqli-multipart-error` | JS | error | probe | false | true | confirmed | none | ✓ | Complete | Multipart form rebuilt with a self-chosen boundary; sibling fields (CSRF included) replayed; neutral-field control |

**Gaps:**
- **PostgreSQL blind SQLi OOB**: No callback-only primitive short of `COPY ... TO PROGRAM` / `dblink` (documented in known-limits.md)
- No time-based blind with alternative payloads (e.g., heavy queries)
- Second-order SQLi is covered in-band (`sqli-second-order`), blind with timing (`sqli-second-order-timing`) and blind with a callback (`sqli-oob-second-order`) only for a neutral re-read of the same point; a separate downstream render endpoint is not discovered
- JSON body injection sends only the discovered field; sibling fields are not replayed, and nested JSON paths are not expanded
- No NoSQL injection coverage beyond auth bypass (see section 5)

---

## 3. Command Injection

| Plugin ID | Tier | Oracle | Phase | Safe | Active | Confidence Ceiling | OOB | Fixtures | Status | Notes |
|-----------|------|--------|-------|------|--------|-------------------|-----|----------|--------|-------|
| `command-injection-error` | YAML | error | probe | false | true | confirmed | none | ✓ | Complete | Command output reflection + differential (calculation) |
| `command-injection-timing` | YAML | timing | probe | false | true | firm | optional | ✓ | Complete | Sleep-based timing with statistical test |
| `command-injection-json-body-oob` | JS | oob | probe | false | true | confirmed | required | ✓ | Complete | Per-field JSON body shell payloads; unique token per variant, no timing fallback |
| `command-injection-json-body-timing` | JS | timing | probe | false | true | firm | none | ✓ | Complete | JSON field sleep payloads (five separator variants) against a neutral baseline; timing ceiling stays firm |
| `command-injection-json-body-error` | JS | error | probe | false | true | firm | none | ✓ | Complete | Inert shell fragments (six) provoke the interpreter's own syntax error in-band, absent for the neutral value; `mode: generic_error`, firm ceiling |
| `log4shell-json-body-oob` | JS | oob | probe | false | true | confirmed | required | ✓ | Complete | Five JNDI lookup forms (`ldap`/`rmi`/`dns` plus `${lower:}` nesting) in a JSON field; one shared token window, honest skip without a server |

**Gaps:**
- OOB command injection exists for query points (`command-injection-oob`) and JSON body fields (`command-injection-json-body-oob`); JSON body fields on segments without egress are covered by `command-injection-json-body-timing` (delay) and `command-injection-json-body-error` (in-band interpreter error), and logged JSON fields by `log4shell-json-body-oob`
- No command injection via template engines (covered by SSTI)
- No Windows-specific command injection vectors (the JSON corpus uses unix separators only)

---

## 4. Server-Side Request Forgery (SSRF)

| Plugin ID | Tier | Oracle | Phase | Safe | Active | Confidence Ceiling | OOB | Fixtures | Status | Notes |
|-----------|------|--------|-------|------|--------|-------------------|-----|----------|--------|-------|
| `ssrf-cloud-metadata` | YAML | reflection | probe | false | true | confirmed | none | ✓ | Complete | Cloud metadata endpoint reflection (169.254.169.254, 100.100.100.200) |
| `ssrf-blind-oob` | JS | oob | probe | false | true | confirmed | required | ✓ | Complete | Blind SSRF with OOB callback; scheme/parser-confusion/redirect-echo/numeric-host variants |
| `nextjs-image-optimizer-ssrf` | YAML | oob | probe | false | true | confirmed | required | ✓ | Complete | Next.js `/_next/image` with `url={{OOB_URL}}` |
| `ssrf-internal-port-scan` | YAML | reflection/error | probe | false | true | firm | none | ✓ | Partial | Internal port scan via SSRF; reflection/error based |
| `ssrf-json-body-oob` | JS | oob | probe | false | true | confirmed | required | ✓ | Complete | Per-field JSON body OOB payload; unique token per field, honest skip without a server |

**Gaps:**
- **No SSRF via PDF generation / document conversion** (wkhtmltopdf, puppeteer, etc.)
- **No SSRF via XML external entity** (covered by XXE plugins)
- **No SSRF via DNS rebinding detection**
- **No SSRF via cloud provider metadata variants beyond AWS/Azure** (GCP, DigitalOcean, etc.)
- **No SSRF via redirect chains with internal targets**
- JSON body fields are covered by `ssrf-json-body-oob`; header-borne SSRF stays with the Tier 1 plugins

---

## 5. NoSQL Injection

| Plugin ID | Tier | Oracle | Phase | Safe | Active | Confidence Ceiling | OOB | Fixtures | Status | Notes |
|-----------|------|--------|-------|------|--------|-------------------|-----|----------|--------|-------|
| `nosql-injection-error` | YAML | error | probe | false | true | confirmed | none | ✓ | Complete | Error signature-based NoSQL injection |
| `nosql-auth-bypass-differential` | YAML | differential | probe | false | true | firm | none | ✓ | Complete | Operator-injected JSON body vs invalid-credential control |
| `nosql-injection-timing-json-body` | JS | timing | probe | false | true | firm | none | ✓ | Complete | `$where` sleep/busy-loop at the top of a JSON body vs a neutral `$where` baseline; timing ceiling stays firm |
| `nosql-injection-differential-json-body` | JS | differential | probe | false | true | confirmed | none | ✓ | Complete | Always-true operator object (`$ne`, `$gt`) vs a non-matching literal in a JSON field; echo guard + 3/3 stability |
| `nosql-nested-json-operator` | JS | differential | probe | false | true | confirmed | none | ✓ | Complete | Operator object nested under a `filter` envelope; three repeats per branch, echo guard, neutral control |

**Gaps:**
- **No blind NoSQL injection with OOB** (exfiltration via DNS/HTTP); timing and operator differential are now covered
- **No query-string (non-JSON) NoSQL bypass variants beyond `nosql-injection-timing`** (documented as out of scope in known-limits.md)
- **Nested filter envelopes** are covered by `nosql-nested-json-operator`; deeper paths and array elements are not expanded

---

## 6. LDAP Injection

| Plugin ID | Tier | Oracle | Phase | Safe | Active | Confidence Ceiling | OOB | Fixtures | Status | Notes |
|-----------|------|--------|-------|------|--------|-------------------|-----|----------|--------|-------|
| `ldap-injection-differential` | YAML | differential | probe | false | true | confirmed | none | ✓ | Complete | Boolean differential LDAP injection |
| `ldap-injection-blind` | YAML | timing/oob | probe | false | true | firm/confirmed | optional | ✓ | Partial | Blind LDAP with timing/OOB |
| `ldap-injection-json-body` | JS | differential | probe | false | true | confirmed | none | ✓ | Complete | Always-true filter closure vs non-matching value in a JSON field; echo guard + 3/3 stability |
| `ldap-injection-oob-json-body` | JS | oob | probe | false | true | confirmed | required | ✓ | Complete | Filter closure carrying the operator hostname in a JSON field; callback only, no attribute read back |
| `ldap-injection-json-body-timing` | JS | timing | probe | false | true | firm | none | ✓ | Complete | Wide filter closures in a JSON field vs a neutral baseline; `min_delay_ms: 5000`, three repeats, firm ceiling |

**Gaps:**
- LDAP injection with OOB exfiltration is covered for query points (Tier 1 `ldap-injection-oob`) and for JSON body fields (`ldap-injection-oob-json-body`); a directory that refuses outbound resolution yields a false negative
- **No LDAP injection via filter manipulation beyond boolean and closure**

---

## 7. XXE (XML External Entity)

| Plugin ID | Tier | Oracle | Phase | Safe | Active | Confidence Ceiling | OOB | Fixtures | Status | Notes |
|-----------|------|--------|-------|------|--------|-------------------|-----|----------|--------|-------|
| `xxe-reflected-basic` | YAML | reflection | probe | false | true | confirmed | none | ✓ | Complete | In-band XXE with file:// entity reflection |
| `xxe-oob` | YAML | oob | probe | false | true | confirmed | required | ✓ | Complete | Blind XXE via OOB (DTD fetch callback) |
| `xxe-blind-oob` | YAML | oob | probe | false | true | confirmed | required | ✓ | Complete | Alternative blind XXE OOB plugin |
| `xml-external-entity-blind` | YAML | oob | probe | false | true | confirmed | required | ✓ | Partial | Duplicate of xxe-oob/xxe-blind-oob? |
| `xxe-json-body-oob` | JS | oob | probe | false | true | confirmed | required | ✓ | Complete | XML carried in a JSON field; external parameter entity callback (single-quoted SYSTEM literal) |
| `xxe-json-body-error` | JS | error | probe | false | true | firm | none | ✓ | Complete | XML with an unresolvable external entity carried in a JSON field; parser failure absent for the neutral document, `mode: generic_error`, firm ceiling |
| `xxe-xml-body-oob` | JS | oob | probe | false | true | confirmed | required | ✓ | Complete | Raw XML and SOAP bodies with an external parameter entity; one shared callback window |
| `xxe-svg-upload-oob` | JS | oob | probe | false | true | confirmed | required | ✓ | Complete | SVG multipart upload parsed server-side; confirmed only on an entity callback |

**Gaps:**
- **Duplicate plugins**: `xxe-oob`, `xxe-blind-oob`, `xml-external-entity-blind` appear to overlap
- **SAML-specific attribute vectors** remain untested; direct XML/SOAP bodies and SVG uploads are covered
- Parameter-entity exfiltration is covered for JSON-carried XML by `xxe-json-body-oob` (callback only, no file read)

---

## 8. SSTI (Server-Side Template Injection)

| Plugin ID | Tier | Oracle | Phase | Safe | Active | Confidence Ceiling | OOB | Fixtures | Status | Notes |
|-----------|------|--------|-------|------|--------|-------------------|-----|----------|--------|-------|
| `template-injection-reflection` | YAML | reflection | probe | false | true | confirmed | none | ✓ | Complete | Arithmetic proof (1337*1337=1787569) via reflection |
| `expression-language-injection` | YAML | reflection | probe | false | true | firm | none | ✓ | Complete | EL injection with arithmetic canary |
| `ssti-blind-timing` | YAML | timing | probe | false | true | firm | optional | ✓ | Partial | Blind SSTI with sleep timing |
| `ssti-json-body-oob` | JS | oob | probe | false | true | confirmed | required | ✓ | Complete | Engine-specific payloads carried in a JSON field; callback only |

**Gaps:**
- Blind SSTI with OOB exfiltration is covered for query points (Tier 1 `ssti-blind-oob`) and for JSON body fields (`ssti-json-body-oob`)
- **No SSTI via specific template engines** (Jinja2, Twig, Freemarker, Velocity, Thymeleaf specific payloads)
- **No SSTI in non-HTML contexts** (email templates, PDF generation, etc.)

---

## 9. Path Traversal / File Inclusion

| Plugin ID | Tier | Oracle | Phase | Safe | Active | Confidence Ceiling | OOB | Fixtures | Status | Notes |
|-----------|------|--------|-------|------|--------|-------------------|-----|----------|--------|-------|
| `path-traversal-error` | YAML | error | probe | true | true | confirmed | none | ✓ | Complete | File content signatures (root:x:, [fonts], etc.) + soft-404 control |
| `file-inclusion-rfi` | YAML | reflection | probe | false | true | confirmed | none | ✓ | Complete | RFI via reflection oracle (loopback canary) |
| `rfi-remote-include` | YAML | reflection | probe | false | true | confirmed | none | ✓ | Complete | Remote file include via reflection |
| `lfi-json-body` | JS | error | probe | false | true | confirmed | none | ✓ | Complete | Per-field JSON body payloads with `mode: path_traversal` from `oracle_params`; real file-content signatures |
| `path-traversal-encoding-bypass` | JS | error | probe | false | true | confirmed | none | ✓ | Complete | Single/double-encoded, backslash, overlong-style and dot-collapsed traversal families; echo guard + neutral control |

**Gaps:**
- **No blind path traversal** (documented as undetectable in known-limits.md - GASH-018)
- **No path traversal via archive upload** (zip slip, tar slip)
- **Encoding bypass families** are covered by `path-traversal-encoding-bypass`; server-specific decoding order remains unmeasured
- JSON body fields are covered by `lfi-json-body`; query-string traversal stays with `path-traversal-error`

---

## 10. Open Redirect

| Plugin ID | Tier | Oracle | Phase | Safe | Active | Confidence Ceiling | OOB | Fixtures | Status | Notes |
|-----------|------|--------|-------|------|--------|-------------------|-----|----------|--------|-------|
| `open-redirect-param` | YAML | redirect | probe | true | false | confirmed | none | ✓ | Complete | Location parse + host compare + DNS double-check |
| `oauth-open-redirect` | YAML | redirect | probe | true | false | confirmed | none | ✓ | Complete | OAuth authorize paths with redirect_uri params |
| `open-redirect-json-body` | JS | redirect | probe | false | true | confirmed | none | ✓ | Complete | Per-field JSON body injection; neutral-value control gate before the oracle |
| `open-redirect-userinfo-confusion` | JS | redirect | probe | false | true | confirmed | none | ✓ | Complete | Four parser-confusion variants per point (protocol-relative, userinfo, suffix, fragment); per-run canary payload host |
| `open-redirect-path-parser` | JS | redirect | probe | false | true | confirmed | none | ✓ | Complete | Path-borne protocol-relative, backslash and encoded-slash variants; neutral-path control before the oracle |

**Gaps:**
- **No open redirect via JavaScript** (DOM-based `location.href`, `window.open`)
- **No open redirect via header injection** (Location header via CRLF)
- Path parser-confusion variants are covered by `open-redirect-path-parser`; POST/JSON body redirects by `open-redirect-json-body` (client-side navigation is out of scope)

---

## 11. CORS Misconfiguration

| Plugin ID | Tier | Oracle | Phase | Safe | Active | Confidence Ceiling | OOB | Fixtures | Status | Notes |
|-----------|------|--------|-------|------|--------|-------------------|-----|----------|--------|-------|
| `cors-misconfig` | YAML | cors | probe | true | false | confirmed | none | ✓ | Complete | ACAO wildcard/reflection + credentials |
| `insecure-cors-preflight` | YAML | cors | probe | true | false | confirmed | none | ✓ | Complete | Preflight-specific CORS checks |
| `insecure-cors-reflected-origin` | JS | cors | probe | false | true | confirmed | none | ✓ | Complete | Sends a canary `Origin` header; echo plus credentials confirms, echo without credentials firms |
| `cors-null-origin-trust` | JS | cors | probe | false | true | confirmed | none | ✓ | Complete | Sends the literal `null` Origin; echo plus credentials confirms, echo without credentials firms |

**Gaps:**
- The null origin is covered by `cors-null-origin-trust` (a sandboxed iframe or `data:` origin)
- Origin reflection is covered by `insecure-cors-reflected-origin`; arbitrary subdomain enumeration is not
- **No CORS with preflight cache poisoning**

---

## 12. Cookie / Session Security

| Plugin ID | Tier | Oracle | Phase | Safe | Active | Confidence Ceiling | OOB | Fixtures | Status | Notes |
|-----------|------|--------|-------|------|--------|-------------------|-----|----------|--------|-------|
| `cookie-flags` | YAML | cookie | probe | true | false | confirmed | none | ✓ | Complete | Secure/HttpOnly/SameSite logic grading |
| `csrf-token-absence` | YAML | header | probe | true | false | confirmed | none | ✓ | Complete | POST form token absence + SameSite analysis |
| `clickjacking-frameable` | YAML | header | probe | true | false | confirmed | none | ✓ | Complete | X-Frame-Options + CSP frame-ancestors |

**Gaps:**
- **No cookie prefix validation** (`__Secure-`, `__Host-`)
- **No session fixation detection**
- **No session timeout / rotation analysis**
- **No JWT token validation in cookies** (covered partially by jwt-token-exposure)
- **No CSRF via SameSite=Lax bypass** (recent browser changes)

---

## 13. Authentication / Authorization

| Plugin ID | Tier | Oracle | Phase | Safe | Active | Confidence Ceiling | OOB | Fixtures | Status | Notes |
|-----------|------|--------|-------|------|--------|-------------------|-----|----------|--------|-------|
| `idor-differential` | YAML | differential | probe | true | true | confirmed | none | ✓ | Complete | IDOR via differential response analysis (3/3) |
| `mass-assignment-basic` | YAML | differential | probe | false | true | firm | none | ✓ | Complete | Extra-field binding, non-escalating values |
| `mass-assignment-nested-json` | JS | differential | probe | false | true | firm | none | ✓ | Complete | Privileged nested object vs a non-binding role in a JSON field; ceiling stays firm |
| `idor-sequential-id-matrix` | JS | differential | probe | false | true | confirmed | none | ✓ | Complete | Own/neighbour/missing identifier matrix over three repeats; authenticated session required |
| `jwt-token-exposure` | YAML | header | probe | true | false | confirmed | none | ✓ | Complete | JWT in headers/cookies |
| `jwt-alg-confusion` | YAML | header | probe | true | false | confirmed | none | ✓ | Complete | JWT algorithm confusion (none, HS256/RS256 switch) |
| `jwt-none-alg-confusion` | YAML | header | probe | true | false | confirmed | none | ✓ | Partial | Duplicate of jwt-alg-confusion? |
| `jwt-none-alg-bypass` | JS | differential | probe | false | true | confirmed | none | ✓ | Complete | Active proof: a discovered token re-headed to `alg:none` with an empty signature is replayed; forged vs invalid vs anonymous divergence confirms |
| `nextjs-middleware-bypass` | YAML | middleware-bypass | probe | false | true | firm | none | ✓ | Complete | CVE-2025-29927 middleware bypass |

**Gaps:**
- **BOLA (Broken Object Level Authorization)** beyond IDOR: `idor-sequential-id-matrix` probes the horizontal, sequential-identifier case with an authenticated session; role-based (vertical) escalation and API authorization matrices remain uncovered
- **No API authorization matrix testing** (different roles accessing different endpoints)
- **No broken function level authorization** (admin endpoints accessible to users)
- **No authentication bypass via password reset / 2FA / OAuth flows**; JWT `alg:none` acceptance now has an active proof (`jwt-none-alg-bypass`)
- **No session management flaws** (session fixation, concurrent sessions, logout)
- **Duplicate**: `jwt-alg-confusion` and `jwt-none-alg-confusion` appear to overlap

---

## 14. Injection - Other

| Plugin ID | Tier | Oracle | Phase | Safe | Active | Confidence Ceiling | OOB | Fixtures | Status | Notes |
|-----------|------|--------|-------|------|--------|-------------------|-----|----------|--------|-------|
| `xpath-injection-error` | YAML | error | probe | false | true | firm | none | ✓ | Complete | XPath parser error signatures |
| `xpath-injection-json-body` | JS | error | probe | false | true | firm | none | ✓ | Complete | Per-field JSON body syntax probes with `mode: xpath` from `oracle_params`; parser signatures, firm ceiling |
| `xpath-xml-body-error` | JS | error | probe | false | true | firm | none | ✓ | Complete | XML body element injection with `mode: xpath`; parser signatures absent from the neutral document, firm ceiling |
| `ssi-injection` | YAML | error | probe | false | true | firm | none | ✓ | Complete | SSI printenv two-marker pair |
| `prototype-pollution-differential` | YAML | differential | probe | false | true | confirmed | none | ✓ | Complete | Prototype pollution via differential |
| `prototype-pollution-json-body` | JS | differential | probe | false | true | confirmed | none | ✓ | Complete | Nested `__proto__` member sent as a JSON field value vs a plain object over three repeats; echo guard + 3/3 stability |
| `jsonp-callback-injection` | YAML | reflection | probe | false | true | firm | none | ✓ | Complete | JSONP callback reflection |
| `crlf-header-injection` | YAML | header | probe | true | false | confirmed | none | ✓ | Complete | CRLF in response/request headers |
| `http-response-splitting` | YAML | header/reflection | probe | true | false | confirmed | none | ✓ | Complete | HTTP response splitting via CRLF |
| `http-method-override-abuse` | YAML | header | probe | true | false | firm | none | ✓ | Complete | Method override header abuse |
| `insecure-deserialization-error` | YAML | error | probe | false | true | firm | none | ✓ | Complete | Deserialization error signatures (Java/Python/PHP) |
| `log4shell-jndi` | YAML | oob | probe | false | true | confirmed | required | ✓ | Complete | Log4Shell JNDI via OOB |

**Gaps:**
- **No HTTP request smuggling plugin** (engine-owned `smuggling-differential` oracle exists, no plugin file)
- **No header injection via Host/X-Forwarded-Host** (covered by `host-header-injection` but limited)
- **No cache poisoning via header manipulation** (covered by `web-cache-poisoning-basic` and `cache-poisoning-host-header`)
- **No WebSocket injection/hijacking**

---

## 15. Information Disclosure / Misconfiguration

| Plugin ID | Tier | Oracle | Phase | Safe | Active | Confidence Ceiling | OOB | Fixtures | Status | Notes |
|-----------|------|--------|-------|------|--------|-------------------|-----|----------|--------|-------|
| `missing-security-headers` | YAML | header | probe | true | false | confirmed | none | ✓ | Complete | HSTS, CSP, XFO, etc. |
| `error-message-disclosure` | YAML | error | probe | true | false | confirmed | none | ✓ | Complete | Stack traces, debug info |
| `server-version-disclosure` | YAML | version | probe | true | false | tentative/firm | none | ✓ | Complete | Banner + behavior verification |
| `backup-file-exposure` | YAML | error | probe | false | true | firm | none | ✓ | Complete | 12-path fixed list + soft-404 control |
| `phpinfo-exposure` | YAML | error | probe | false | true | firm | none | ✓ | Complete | PHP configuration markers |
| `management-endpoint-exposure` | YAML | error | probe | false | true | firm | none | ✓ | Complete | Actuator/console paths |
| `directory-listing` | YAML | error | probe | false | true | firm | none | ✓ | Complete | Server-generated index pages |
| `source-map-exposure` | YAML | error | probe | false | true | firm | none | ✓ | Complete | Source map wrapper (version 3 + mappings) |
| `webdav-enabled` | YAML | header | probe | true | false | confirmed | none | ✓ | Complete | OPTIONS Allow write verbs (read-only) |
| `version-disclosure` | YAML | version | probe | true | false | tentative/firm | none | ✓ | Complete | Technology fingerprinting |
| `cve-dependency-scan` | YAML | version | probe | true | false | tentative/firm | none | ✓ | Complete | Banner-based vulnerable dependency screen |

**Gaps:**
- **No debug endpoint enumeration** beyond actuator/console (e.g., `/debug`, `/health`, `/metrics`, `/trace`, GraphQL voyager, Swagger UI)
- **No sensitive file exposure beyond backup files** (`.git`, `.env`, `docker-compose.yml`, `kubeconfig`, SSH keys, etc.)
- **No API documentation exposure** (OpenAPI/Swagger/GraphQL introspection in non-standard paths)
- **No cloud credential exposure in metadata** (beyond SSRF cloud metadata)

---

## 16. File Upload

| Plugin ID | Tier | Oracle | Phase | Safe | Active | Confidence Ceiling | OOB | Fixtures | Status | Notes |
|-----------|------|--------|-------|------|--------|-------------------|-----|----------|--------|-------|
| `file-upload-unrestricted` | YAML | error | probe | false | true | confirmed | none | ✓ | Complete | Unrestricted file upload with error disclosure |
| `file-upload-served` | JS | upload-served | probe | false | true | confirmed | none | ✓ | Complete | Mismatched-type artifact uploaded, then fetched back; active serve-back type confirms, inert firms |
| `file-upload-filename-traversal` | JS | upload-served | probe | false | true | confirmed | none | ✓ | Complete | Traversal filename (`../../<canary>.html`) uploaded, artifact located outside the upload directory and fetched back |
| `file-upload-sniffing-mismatch` | JS | upload-served | probe | false | true | confirmed | none | ✓ | Complete | Inert `.txt` name and `application/octet-stream` declaration with active bytes; served content type confirms (active) or firms (inert), sibling name is the control |

**Gaps:**
- File upload validation bypass is covered by `file-upload-served` (serve-back content type only); filename traversal is covered by `file-upload-filename-traversal`
- **No file upload via archive (zip slip)**
- **No file upload RCE via polyglot files**

---

## 17. Deserialization

| Plugin ID | Tier | Oracle | Phase | Safe | Active | Confidence Ceiling | OOB | Fixtures | Status | Notes |
|-----------|------|--------|-------|------|--------|-------------------|-----|----------|--------|-------|
| `insecure-deserialization-error` | YAML | error | probe | false | true | firm | none | ✓ | Complete | Error signatures only; no gadget chain |
| `insecure-deserialization-json-body` | JS | error | probe | false | true | firm | none | ✓ | Complete | Serialization markers injected into a JSON field; `mode: deserialization` from `oracle_params`, firm ceiling |

**Gaps:**
- JSON body fields are covered by `insecure-deserialization-json-body` (marker signatures, no gadget chain)
- **No deserialization with OOB** (gadget chain triggering DNS/HTTP callback)
- **No .NET deserialization** (ViewState, BinaryFormatter, JSON.NET)
- **No Java deserialization with specific gadget chains** (ysoserial payloads)
- **No PHP deserialization** (__wakeup, __destruct, __unserialize)

---

## 18. Subdomain Takeover

| Plugin ID | Tier | Oracle | Phase | Safe | Active | Confidence Ceiling | OOB | Fixtures | Status | Notes |
|-----------|------|--------|-------|------|--------|-------------------|-----|----------|--------|-------|
| `subdomain-takeover-basic` | YAML | error | probe | true | false | firm | none | ✓ | Complete | Unclaimed service body signatures; DNS preflight external |

**Gaps:**
- **No DNS CNAME verification plugin** (engine-owned DNS oracle exists, no plugin)
- **No cloud provider specific takeover signatures** beyond basic set

---

## 19. Rate Limiting / DoS

| Plugin ID | Tier | Oracle | Phase | Safe | Active | Confidence Ceiling | OOB | Fixtures | Status | Notes |
|-----------|------|--------|-------|------|--------|-------------------|-----|----------|--------|-------|
| `missing-rate-limit` | YAML | header | probe | false | true | tentative | none | ✓ | Complete | Burst GET requests, 429/headers absence → tentative |

**Gaps:**
- **No rate limit bypass testing** (IP rotation, header manipulation)
- **No API rate limit enumeration** (per-endpoint, per-user limits)
- **No DoS via resource exhaustion** (large payloads, recursive entities)

---

## 20. GraphQL

| Plugin ID | Tier | Oracle | Phase | Safe | Active | Confidence Ceiling | OOB | Fixtures | Status | Notes |
|-----------|------|--------|-------|------|--------|-------------------|-----|----------|--------|-------|
| `graphql-endpoint-discovery` | YAML | version | discovery | true | false | confirmed | none | ✓ | Complete | GraphQL endpoint detection |
| `graphql-introspection-enabled` | YAML | version | probe | false | true | firm | none | ✓ | Complete | Introspection query without errors envelope |
| `graphql-batch-abuse` | JS | differential | probe | false | true | firm | none | ✓ | Complete | Batched operation array accepted in one request; `confidence_ceiling: firm` from `oracle_params` |
| `graphql-alias-amplification` | JS | differential | probe | false | true | firm | none | ✓ | Complete | One operation with 25 aliases vs the single-field document; `confidence_ceiling: firm` from `oracle_params` |

**Gaps:**
- **No GraphQL query depth/complexity DoS**
- **No GraphQL field suggestion / introspection abuse**
- Batch abuse is covered by `graphql-batch-abuse` and alias amplification by `graphql-alias-amplification` (acceptance only; amplification impact is not measured)
- **No GraphQL authorization bypass** (field-level permissions)

---

## 21. Web Cache Poisoning

| Plugin ID | Tier | Oracle | Phase | Safe | Active | Confidence Ceiling | OOB | Fixtures | Status | Notes |
|-----------|------|--------|-------|------|--------|-------------------|-----|----------|--------|-------|
| `web-cache-poisoning-basic` | YAML | differential | probe | false | true | confirmed | none | ✓ | Complete | Cache poisoning via differential |
| `cache-poisoning-host-header` | YAML | differential | probe | false | true | confirmed | none | ✓ | Complete | Host header cache poisoning |
| `web-cache-unkeyed-header` | JS | differential | probe | false | true | confirmed | none | ✓ | Complete | Clean/prime/clean sequence; canary must outlive the priming request |
| `web-cache-method-override` | JS | differential | probe | false | true | confirmed | none | ✓ | Complete | Clean/prime/clean over the unkeyed method-override header family (`X-HTTP-Method-Override`, `X-Method-Override`, `X-HTTP-Method`); GET-only |
| `web-cache-unkeyed-cookie` | JS | differential | probe | false | true | confirmed | none | ✓ | Complete | Clean/prime/clean with an unkeyed canary cookie; the canary must outlive the priming request |

**Gaps:**
- **No cache poisoning via Vary header manipulation**
- Unkeyed headers beyond the forwarded-host and method-override families (`X-Forwarded-Scheme`, `X-Original-URL`) are not primed yet; unkeyed cookies are covered by `web-cache-unkeyed-cookie`

---

## 22. HPP (HTTP Parameter Pollution)

| Plugin ID | Tier | Oracle | Phase | Safe | Active | Confidence Ceiling | OOB | Fixtures | Status | Notes |
|-----------|------|--------|-------|------|--------|-------------------|-----|----------|--------|-------|
| `hpp-parameter-pollution` | YAML | differential | probe | false | true | confirmed | none | ✓ | Complete | Parameter pollution via differential |
| `hpp-duplicate-emission` | JS | differential | probe | false | true | confirmed | none | ✓ | Complete | Native duplicate-key emission (`id=1&id=2`) |
| `hpp-json-duplicate-keys` | JS | differential | probe | false | true | confirmed | none | ✓ | Complete | Duplicate JSON key emission with explicit `application/json`; both branches must be 2xx |
| `hpp-multipart-duplicate-keys` | JS | differential | probe | false | true | confirmed | none | ✓ | Complete | Self-built multipart body with a duplicated field part; both branches must be 2xx |
| `hpp-query-array-notation` | JS | differential | probe | false | true | confirmed | none | ✓ | Complete | Bracket-array notation (`id[]=`) with one vs two elements in a rebuilt query, sibling parameters preserved; control is a plain scalar |

**Gaps:**
- HPP in JSON body is covered by `hpp-json-duplicate-keys` (duplicated key, not duplicate-key rejection)
- HPP in multipart/form-data is covered by `hpp-multipart-duplicate-keys` (text parts only, fixed boundary)

---

## 23. Infrastructure / Recon (Engine-Owned, No Plugin File)

These capabilities are engine-owned on purpose: their transport or input cannot
be expressed in YAML or the JS sandbox. Every finding producer among them
(`engine-smuggle-recon`, `engine-content-discovery`, `engine-spa-state`,
`engine-devbuild`, `engine-js-recon`, and the `proto-*` protocol units) runs
behind the detector port with a declared `Spec` (rule, CWE, oracle, phase, gate,
budget) registered in `internal/engine`, so their identity and gates are data
instead of control flow — see `docs/design/01-detector-port.md` and the registry
section of `docs/detector-inventory.md`.

| Capability | Oracle | Phase | Notes |
|------------|--------|-------|-------|
| TLS certificate/chain | `tls` | recon | Safe-profile passive; `--tls-audit-deep` for cert depth |
| DNS SPF/DMARC/CAA | `dns` | recon | miekg/dns pinned; safe-profile |
| TCP banner | `tcp` | recon | `--active` + `--tcp-banner` |
| SSH banner/audit | `ssh` | recon | `--ssh-audit` + `--ssh-handshake-audit` |
| DB port inventory/unauth | `db` | recon | `--db-port-scan` + `--db-unauth` |
| Request smuggling | `smuggling-differential` | recon | `--active` + `--aggressive`, raw-TCP |
| Content discovery | N/A | recon | Wordlist-based, tech-pinned |
| Passive JS recon | N/A | recon | Same-origin only |
| SPA surface discovery | N/A | recon | `--browser-crawl`, deep build |
| Hardcoded JS secrets | N/A | recon | GASH-067, static-execution-evidence |
| SPA embedded-state secrets | N/A | recon | GASH-071, static-execution-evidence |
| Dev build markers | N/A | recon | GASH-072, firm |
| Multi-step workflow replay | N/A | recon | `--flow-seed`, tentative ceiling |

---

## 24. Tier 1 Expansion Pack (100)

Passive expansion batch: 28 header hardening/policy checks and 72 banner-only
product fingerprints. All are safe, GET-only, fixture-backed, and verified by
`TestMetricGate`; fingerprints stay tentative and header policies stay
firm/confirmed. Files live under `plugins/tier1-expansion/`.

| Plugin ID | Tier | Oracle | Phase | Safe | Active | Confidence Ceiling | OOB | Fixtures | Status | Notes |
|-----------|------|--------|-------|------|--------|-------------------|-----|----------|--------|-------|
| `coep-unsafe-none` | YAML | header (policy) | probe | true | false | firm/confirmed (policy) | none | ✓ | Complete | Detects an explicit Cross-Origin-Embedder-Policy unsafe-none that disables embedder isolation. |
| `coop-unsafe-none` | YAML | header (policy) | probe | true | false | firm/confirmed (policy) | none | ✓ | Complete | Detects an explicit Cross-Origin-Opener-Policy unsafe-none that disables cross-origin isolation. |
| `csp-base-uri-missing` | YAML | header (policy) | probe | true | false | firm/confirmed (policy) | none | ✓ | Complete | Detects an existing Content-Security-Policy that omits base-uri, leaving relative URL resolution unconstrained. |
| `csp-default-src-missing` | YAML | header (policy) | probe | true | false | firm/confirmed (policy) | none | ✓ | Complete | Detects an existing Content-Security-Policy that omits the default-src fallback directive, leaving unlisted fetch directives unrestricted. |
| `csp-form-action-missing` | YAML | header (policy) | probe | true | false | firm/confirmed (policy) | none | ✓ | Complete | Detects an existing Content-Security-Policy that omits form-action, allowing form submissions to any origin. |
| `permissions-policy-payment-missing` | YAML | header (policy) | probe | true | false | firm/confirmed (policy) | none | ✓ | Complete | Detects an existing Permissions-Policy that does not restrict the Payment Request API. |
| `csp-require-trusted-types-missing` | YAML | header (policy) | probe | true | false | firm/confirmed (policy) | none | ✓ | Complete | Detects an existing Content-Security-Policy that omits require-trusted-types-for, leaving DOM sink hardening disabled. |
| `csp-upgrade-insecure-requests-missing` | YAML | header (policy) | probe | true | false | firm/confirmed (policy) | none | ✓ | Complete | Detects an existing Content-Security-Policy that omits upgrade-insecure-requests, leaving mixed-content fetches possible. |
| `feature-policy-deprecated` | YAML | header (policy) | probe | true | false | firm/confirmed (policy) | none | ✓ | Complete | Detects the deprecated Feature-Policy response header that is superseded by Permissions-Policy. |
| `hsts-preload-missing` | YAML | header (policy) | probe | true | false | firm/confirmed (policy) | none | ✓ | Complete | Detects an existing Strict-Transport-Security policy that omits the preload directive. |
| `permissions-policy-camera-missing` | YAML | header (policy) | probe | true | false | firm/confirmed (policy) | none | ✓ | Complete | Detects an existing Permissions-Policy that does not restrict camera access. |
| `permissions-policy-geolocation-missing` | YAML | header (policy) | probe | true | false | firm/confirmed (policy) | none | ✓ | Complete | Detects an existing Permissions-Policy that does not restrict geolocation access. |
| `permissions-policy-microphone-missing` | YAML | header (policy) | probe | true | false | firm/confirmed (policy) | none | ✓ | Complete | Detects an existing Permissions-Policy that does not restrict microphone access. |
| `referrer-policy-no-referrer-when-downgrade` | YAML | header (policy) | probe | true | false | firm/confirmed (policy) | none | ✓ | Complete | Detects the legacy no-referrer-when-downgrade Referrer-Policy, which sends full URLs on same-scheme requests. |
| `referrer-policy-unsafe-url` | YAML | header (policy) | probe | true | false | firm/confirmed (policy) | none | ✓ | Complete | Detects a Referrer-Policy set to unsafe-url, which leaks full URLs to cross-origin destinations. |
| `x-application-context-disclosure` | YAML | header (policy) | probe | true | false | firm/confirmed (policy) | none | ✓ | Complete | Detects a Spring Boot X-Application-Context header exposing the application name and active profile. |
| `x-aspnet-version-disclosure` | YAML | header (policy) | probe | true | false | firm/confirmed (policy) | none | ✓ | Complete | Detects the X-AspNet-Version response header exposing the ASP.NET runtime version. |
| `x-aspnetmvc-version-disclosure` | YAML | header (policy) | probe | true | false | firm/confirmed (policy) | none | ✓ | Complete | Detects the X-AspNetMvc-Version response header exposing the ASP.NET MVC version. |
| `x-debug-token-disclosure` | YAML | header (policy) | probe | true | false | firm/confirmed (policy) | none | ✓ | Complete | Detects an X-Debug-Token response header used by Symfony profiler debug tooling. |
| `x-debug-token-link-disclosure` | YAML | header (policy) | probe | true | false | firm/confirmed (policy) | none | ✓ | Complete | Detects an X-Debug-Token-Link response header pointing at a profiler endpoint. |
| `x-download-options-missing` | YAML | header (policy) | probe | true | false | firm/confirmed (policy) | none | ✓ | Complete | Detects a missing X-Download-Options header that prevents legacy Internet Explorer from opening downloads in-site. |
| `x-frame-options-allow-from` | YAML | header (policy) | probe | true | false | firm/confirmed (policy) | none | ✓ | Complete | Detects the obsolete X-Frame-Options ALLOW-FROM directive that modern browsers ignore. |
| `x-generator-disclosure` | YAML | header (policy) | probe | true | false | firm/confirmed (policy) | none | ✓ | Complete | Detects an X-Generator response header that fingerprints the CMS or site generator. |
| `x-permitted-cross-domain-policies-missing` | YAML | header (policy) | probe | true | false | firm/confirmed (policy) | none | ✓ | Complete | Detects a missing X-Permitted-Cross-Domain-Policies header that lets legacy Adobe clients load cross-domain policy files. |
| `x-rack-cache-disclosure` | YAML | header (policy) | probe | true | false | firm/confirmed (policy) | none | ✓ | Complete | Detects an X-Rack-Cache response header exposing Rails cache behavior. |
| `x-runtime-disclosure` | YAML | header (policy) | probe | true | false | firm/confirmed (policy) | none | ✓ | Complete | Detects an X-Runtime response header exposing per-request execution timing. |
| `x-varnish-disclosure` | YAML | header (policy) | probe | true | false | firm/confirmed (policy) | none | ✓ | Complete | Detects an X-Varnish response header exposing Varnish cache transaction IDs. |
| `x-xss-protection-enabled` | YAML | header (policy) | probe | true | false | firm/confirmed (policy) | none | ✓ | Complete | Detects the legacy X-XSS-Protection filter enabled, which can introduce side-channel and content-injection risks. |

| Plugin ID | Tier | Oracle | Phase | Safe | Active | Confidence Ceiling | OOB | Fixtures | Status | Notes |
|-----------|------|--------|-------|------|--------|-------------------|-----|----------|--------|-------|
| `alertmanager-version-disclosure` | YAML | version (banner) | discovery | true | false | tentative (banner) | none | ✓ | Complete | Detects the Alertmanager versionInfo field on the public status API; banner-only fingerprint, tentative confidence. |
| `arangodb-version-disclosure` | YAML | version (banner) | probe | true | false | tentative (banner) | none | ✓ | Complete | Detects ArangoDB markers or system database paths; banner-only fingerprint, tentative confidence. |
| `authelia-version-disclosure` | YAML | version (banner) | probe | true | false | tentative (banner) | none | ✓ | Complete | Detects Authelia markers on public login pages; banner-only fingerprint, tentative confidence. |
| `authentik-version-disclosure` | YAML | version (banner) | probe | true | false | tentative (banner) | none | ✓ | Complete | Detects authentik markers on public login pages; banner-only fingerprint, tentative confidence. |
| `bitrix-version-disclosure` | YAML | version (banner) | probe | true | false | tentative (banner) | none | ✓ | Complete | Detects Bitrix markers or core asset paths; banner-only fingerprint, tentative confidence. |
| `bookstack-version-disclosure` | YAML | version (banner) | probe | true | false | tentative (banner) | none | ✓ | Complete | Detects BookStack markers in public responses; banner-only fingerprint, tentative confidence. |
| `bugzilla-version-disclosure` | YAML | version (banner) | probe | true | false | tentative (banner) | none | ✓ | Complete | Detects Bugzilla markers or buglist.cgi endpoints; banner-only fingerprint, tentative confidence. |
| `casdoor-version-disclosure` | YAML | version (banner) | probe | true | false | tentative (banner) | none | ✓ | Complete | Detects Casdoor markers on public login pages; banner-only fingerprint, tentative confidence. |
| `cgit-version-disclosure` | YAML | version (banner) | probe | true | false | tentative (banner) | none | ✓ | Complete | Detects cgit version footers or cgit stylesheet markers; banner-only fingerprint, tentative confidence. |
| `cloudbeaver-version-disclosure` | YAML | version (banner) | probe | true | false | tentative (banner) | none | ✓ | Complete | Detects CloudBeaver markers or DBeaver asset paths; banner-only fingerprint, tentative confidence. |
| `cloudreve-version-disclosure` | YAML | version (banner) | probe | true | false | tentative (banner) | none | ✓ | Complete | Detects Cloudreve markers or site-config API paths; banner-only fingerprint, tentative confidence. |
| `concourse-version-disclosure` | YAML | version (banner) | discovery | true | false | tentative (banner) | none | ✓ | Complete | Detects the Concourse worker_version field on the public info API; banner-only fingerprint, tentative confidence. |
| `confluence-version-disclosure` | YAML | version (banner) | probe | true | false | tentative (banner) | none | ✓ | Complete | Detects the Confluence ajs-version-number metadata field; banner-only fingerprint, tentative confidence. |
| `craft-cms-version-disclosure` | YAML | version (banner) | probe | true | false | tentative (banner) | none | ✓ | Complete | Detects Craft CMS response headers or body markers; banner-only fingerprint, tentative confidence. |
| `dokuwiki-version-disclosure` | YAML | version (banner) | probe | true | false | tentative (banner) | none | ✓ | Complete | Detects DokuWiki markers or lib/exe asset paths; banner-only fingerprint, tentative confidence. |
| `dolibarr-version-disclosure` | YAML | version (banner) | probe | true | false | tentative (banner) | none | ✓ | Complete | Detects Dolibarr markers or theme asset paths; banner-only fingerprint, tentative confidence. |
| `druid-version-disclosure` | YAML | version (banner) | probe | true | false | tentative (banner) | none | ✓ | Complete | Detects Apache Druid markers or unified-console paths; banner-only fingerprint, tentative confidence. |
| `drupal-version-disclosure` | YAML | version (banner) | probe | true | false | tentative (banner) | none | ✓ | Complete | Detects Drupal script settings or core asset paths in public responses; banner-only fingerprint, tentative confidence. |
| `erpnext-version-disclosure` | YAML | version (banner) | probe | true | false | tentative (banner) | none | ✓ | Complete | Detects Frappe/ERPNext asset paths or markers; banner-only fingerprint, tentative confidence. |
| `espocrm-version-disclosure` | YAML | version (banner) | probe | true | false | tentative (banner) | none | ✓ | Complete | Detects EspoCRM markers or client library paths; banner-only fingerprint, tentative confidence. |
| `flarum-version-disclosure` | YAML | version (banner) | probe | true | false | tentative (banner) | none | ✓ | Complete | Detects Flarum forum asset markers; banner-only fingerprint, tentative confidence. |
| `flink-ui-version-disclosure` | YAML | version (banner) | probe | true | false | tentative (banner) | none | ✓ | Complete | Detects Apache Flink dashboard markers; banner-only fingerprint, tentative confidence. |
| `focalboard-version-disclosure` | YAML | version (banner) | probe | true | false | tentative (banner) | none | ✓ | Complete | Detects Focalboard markers or workspace API paths; banner-only fingerprint, tentative confidence. |
| `gerrit-version-disclosure` | YAML | version (banner) | probe | true | false | tentative (banner) | none | ✓ | Complete | Detects Gerrit Code Review markers or /gerrit/ paths; banner-only fingerprint, tentative confidence. |
| `gitlab-version-disclosure` | YAML | version (banner) | probe | true | false | tentative (banner) | none | ✓ | Complete | Detects GitLab markers on public login pages; banner-only fingerprint, tentative confidence. |
| `glpi-version-disclosure` | YAML | version (banner) | discovery | true | false | tentative (banner) | none | ✓ | Complete | Detects GLPI markers or front-controller paths; banner-only fingerprint, tentative confidence. |
| `gocd-version-disclosure` | YAML | version (banner) | discovery | true | false | tentative (banner) | none | ✓ | Complete | Detects the GoCD build_number field on the public version API; banner-only fingerprint, tentative confidence. |
| `invision-community-version-disclosure` | YAML | version (banner) | probe | true | false | tentative (banner) | none | ✓ | Complete | Detects Invision Community Suite markers or interface asset paths; banner-only fingerprint, tentative confidence. |
| `jenkins-version-disclosure` | YAML | version (banner) | probe | true | false | tentative (banner) | none | ✓ | Complete | Detects the Jenkins version response header on public Jenkins roots; banner-only fingerprint, tentative confidence. |
| `jira-version-disclosure` | YAML | version (banner) | discovery | true | false | tentative (banner) | none | ✓ | Complete | Detects the Jira serverInfo response marker; banner-only fingerprint, tentative confidence. |
| `joomla-version-disclosure` | YAML | version (banner) | probe | true | false | tentative (banner) | none | ✓ | Complete | Detects Joomla generator metadata or core asset paths; banner-only fingerprint, tentative confidence. |
| `kanboard-version-disclosure` | YAML | version (banner) | probe | true | false | tentative (banner) | none | ✓ | Complete | Detects Kanboard markers or app asset paths; banner-only fingerprint, tentative confidence. |
| `kodbox-version-disclosure` | YAML | version (banner) | probe | true | false | tentative (banner) | none | ✓ | Complete | Detects KodBox/KodExplorer markers or user route paths; banner-only fingerprint, tentative confidence. |
| `magento-version-disclosure` | YAML | version (banner) | discovery | true | false | tentative (banner) | none | ✓ | Complete | Detects the Magento version endpoint or static version asset paths; banner-only fingerprint, tentative confidence. |
| `matomo-version-disclosure` | YAML | version (banner) | probe | true | false | tentative (banner) | none | ✓ | Complete | Detects Matomo markers or tracking script paths; banner-only fingerprint, tentative confidence. |
| `mediawiki-version-disclosure` | YAML | version (banner) | probe | true | false | tentative (banner) | none | ✓ | Complete | Detects MediaWiki generator metadata or load.php module paths; banner-only fingerprint, tentative confidence. |
| `meilisearch-version-disclosure` | YAML | version (banner) | discovery | true | false | tentative (banner) | none | ✓ | Complete | Detects the Meilisearch pkgVersion field on the public version API; banner-only fingerprint, tentative confidence. |
| `mongo-express-version-disclosure` | YAML | version (banner) | probe | true | false | tentative (banner) | none | ✓ | Complete | Detects Mongo Express markers on the admin UI; banner-only fingerprint, tentative confidence. |
| `mybb-version-disclosure` | YAML | version (banner) | probe | true | false | tentative (banner) | none | ✓ | Complete | Detects MyBB footer or jscripts asset paths; banner-only fingerprint, tentative confidence. |
| `nats-version-disclosure` | YAML | version (banner) | discovery | true | false | tentative (banner) | none | ✓ | Complete | Detects the NATS server_name field on the monitoring varz endpoint; banner-only fingerprint, tentative confidence. |
| `nodebb-version-disclosure` | YAML | version (banner) | probe | true | false | tentative (banner) | none | ✓ | Complete | Detects NodeBB client asset markers; banner-only fingerprint, tentative confidence. |
| `odoo-version-disclosure` | YAML | version (banner) | discovery | true | false | tentative (banner) | none | ✓ | Complete | Detects the Odoo version_info server_version field; banner-only fingerprint, tentative confidence. |
| `opencart-version-disclosure` | YAML | version (banner) | probe | true | false | tentative (banner) | none | ✓ | Complete | Detects OpenCart route parameters or theme asset paths; banner-only fingerprint, tentative confidence. |
| `opensearch-version-disclosure` | YAML | version (banner) | discovery | true | false | tentative (banner) | none | ✓ | Complete | Detects the OpenSearch distribution field on the public root API; banner-only fingerprint, tentative confidence. |
| `opentsdb-version-disclosure` | YAML | version (banner) | discovery | true | false | tentative (banner) | none | ✓ | Complete | Detects the OpenTSDB short_revision field on the public version API; banner-only fingerprint, tentative confidence. |
| `orientdb-version-disclosure` | YAML | version (banner) | probe | true | false | tentative (banner) | none | ✓ | Complete | Detects OrientDB markers or studio paths; banner-only fingerprint, tentative confidence. |
| `osticket-version-disclosure` | YAML | version (banner) | discovery | true | false | tentative (banner) | none | ✓ | Complete | Detects osTicket markers on the staff login path; banner-only fingerprint, tentative confidence. |
| `phpbb-version-disclosure` | YAML | version (banner) | probe | true | false | tentative (banner) | none | ✓ | Complete | Detects phpBB footer or core stylesheet markers; banner-only fingerprint, tentative confidence. |
| `phpldapadmin-version-disclosure` | YAML | version (banner) | probe | true | false | tentative (banner) | none | ✓ | Complete | Detects phpLDAPadmin markers or template asset paths; banner-only fingerprint, tentative confidence. |
| `prestashop-version-disclosure` | YAML | version (banner) | probe | true | false | tentative (banner) | none | ✓ | Complete | Detects PrestaShop generator metadata in public responses; banner-only fingerprint, tentative confidence. |
| `pydio-version-disclosure` | YAML | version (banner) | probe | true | false | tentative (banner) | none | ✓ | Complete | Detects Pydio markers or /pydio/ paths; banner-only fingerprint, tentative confidence. |
| `redis-commander-version-disclosure` | YAML | version (banner) | probe | true | false | tentative (banner) | none | ✓ | Complete | Detects Redis Commander markers on the admin UI; banner-only fingerprint, tentative confidence. |
| `shopware-version-disclosure` | YAML | version (banner) | probe | true | false | tentative (banner) | none | ✓ | Complete | Detects Shopware markers or shopware asset paths; banner-only fingerprint, tentative confidence. |
| `sitecore-version-disclosure` | YAML | version (banner) | discovery | true | false | tentative (banner) | none | ✓ | Complete | Detects Sitecore paths or analytics cookie markers; banner-only fingerprint, tentative confidence. |
| `spark-ui-version-disclosure` | YAML | version (banner) | probe | true | false | tentative (banner) | none | ✓ | Complete | Detects Spark Master/UI markers on the public dashboard; banner-only fingerprint, tentative confidence. |
| `storm-ui-version-disclosure` | YAML | version (banner) | probe | true | false | tentative (banner) | none | ✓ | Complete | Detects Storm UI markers or cluster-summary API paths; banner-only fingerprint, tentative confidence. |
| `suitecrm-version-disclosure` | YAML | version (banner) | probe | true | false | tentative (banner) | none | ✓ | Complete | Detects SuiteCRM markers or theme cache paths; banner-only fingerprint, tentative confidence. |
| `thanos-version-disclosure` | YAML | version (banner) | discovery | true | false | tentative (banner) | none | ✓ | Complete | Detects the Thanos buildUser field on the public buildinfo API; banner-only fingerprint, tentative confidence. |
| `trac-version-disclosure` | YAML | version (banner) | probe | true | false | tentative (banner) | none | ✓ | Complete | Detects Trac generator metadata or /trac/ paths; banner-only fingerprint, tentative confidence. |
| `typo3-version-disclosure` | YAML | version (banner) | probe | true | false | tentative (banner) | none | ✓ | Complete | Detects TYPO3 generator metadata or typo3temp/typo3conf asset paths; banner-only fingerprint, tentative confidence. |
| `umbraco-version-disclosure` | YAML | version (banner) | discovery | true | false | tentative (banner) | none | ✓ | Complete | Detects Umbraco admin paths or XSRF cookie markers; banner-only fingerprint, tentative confidence. |
| `uptime-kuma-version-disclosure` | YAML | version (banner) | probe | true | false | tentative (banner) | none | ✓ | Complete | Detects Uptime Kuma markers or application asset paths; banner-only fingerprint, tentative confidence. |
| `vbulletin-version-disclosure` | YAML | version (banner) | probe | true | false | tentative (banner) | none | ✓ | Complete | Detects vBulletin client-script asset paths; banner-only fingerprint, tentative confidence. |
| `vikunja-version-disclosure` | YAML | version (banner) | discovery | true | false | tentative (banner) | none | ✓ | Complete | Detects the Vikunja frontend_url field on the public info API; banner-only fingerprint, tentative confidence. |
| `vtiger-version-disclosure` | YAML | version (banner) | probe | true | false | tentative (banner) | none | ✓ | Complete | Detects Vtiger markers or vlayout asset paths; banner-only fingerprint, tentative confidence. |
| `wekan-version-disclosure` | YAML | version (banner) | probe | true | false | tentative (banner) | none | ✓ | Complete | Detects Wekan markers or board asset paths; banner-only fingerprint, tentative confidence. |
| `wikijs-version-disclosure` | YAML | version (banner) | probe | true | false | tentative (banner) | none | ✓ | Complete | Detects Wiki.js markers in public responses; banner-only fingerprint, tentative confidence. |
| `woocommerce-version-disclosure` | YAML | version (banner) | probe | true | false | tentative (banner) | none | ✓ | Complete | Detects WooCommerce asset paths or WC-AJAX endpoints; banner-only fingerprint, tentative confidence. |
| `wordpress-version-disclosure` | YAML | version (banner) | probe | true | false | tentative (banner) | none | ✓ | Complete | Detects WordPress asset paths (wp-content themes/plugins or wp-includes) in public responses; banner-only fingerprint, tentative confidence. |
| `xenforo-version-disclosure` | YAML | version (banner) | probe | true | false | tentative (banner) | none | ✓ | Complete | Detects XenForo script assets or data-xf attributes; banner-only fingerprint, tentative confidence. |
| `xwiki-version-disclosure` | YAML | version (banner) | probe | true | false | tentative (banner) | none | ✓ | Complete | Detects XWiki markers or /xwiki/bin/ paths; banner-only fingerprint, tentative confidence. |
| `zammad-version-disclosure` | YAML | version (banner) | probe | true | false | tentative (banner) | none | ✓ | Complete | Detects Zammad markers or client asset paths; banner-only fingerprint, tentative confidence. |

---

## Duplicate / Overlapping Plugins

| Plugin Group | Issue |
|--------------|-------|
| `xxe-oob`, `xxe-blind-oob`, `xml-external-entity-blind` | Three plugins for blind XXE OOB; likely duplicate functionality |
| `jwt-alg-confusion`, `jwt-none-alg-confusion` | Both detect JWT algorithm confusion; check for overlap |
| `cors-misconfig`, `insecure-cors-preflight` | Both CORS; verify if preflight adds unique coverage |

---

## Summary: Coverage by Security Class

| Security Class | Plugins | Complete | Partial | Gaps Identified |
|----------------|---------|----------|---------|-----------------|
| XSS | 11 | 10 | 1 | DOM fragment/hash, mXSS, postMessage, WebSocket (path/header reflection covered) |
| SQL Injection | 12 | 11 | 1 | PostgreSQL blind OOB, time-based variants (XML/multipart covered) |
| Command Injection | 6 | 6 | 0 | Windows vectors |
| SSRF | 5 | 4 | 1 | PDF generation, DNS rebinding, GCP/DO metadata, redirect chains |
| NoSQL Injection | 5 | 4 | 1 | Blind OOB, query-string bypass, deeper JSON paths |
| LDAP Injection | 5 | 4 | 1 | OOB exfiltration (JSON body covered), filter manipulation |
| XXE | 8 | 7 | 1 | Duplicate plugins, SAML attributes (SOAP/XML body and SVG upload covered) |
| SSTI | 4 | 3 | 1 | Engine-specific, non-HTML contexts (JSON body OOB covered) |
| Path Traversal | 5 | 5 | 0 | Blind (undetectable), archive upload, server decoding order |
| Open Redirect | 5 | 5 | 0 | JS-based, header-based |
| CORS | 4 | 4 | 0 | Preflight cache poisoning, subdomain enumeration |
| Cookie/Session | 3 | 3 | 0 | Cookie prefixes, session fixation, timeout, CSRF Lax bypass |
| Auth/Authorization | 9 | 7 | 2 | Role-based/vertical escalation, function-level, auth bypass flows, session mgmt, duplicates |
| Other Injection | 13 | 13 | 0 | Request smuggling plugin, WebSocket |
| Info Disclosure | 11 | 11 | 0 | Debug endpoints, sensitive files, API docs, cloud creds |
| File Upload | 4 | 4 | 0 | zip slip, polyglot |
| Deserialization | 2 | 1 | 1 | OOB gadget chains, .NET, Java ysoserial, PHP |
| Subdomain Takeover | 1 | 1 | 0 | DNS CNAME verification, cloud-specific |
| Rate Limiting | 1 | 1 | 0 | Bypass testing, API enumeration, DoS |
| GraphQL | 4 | 4 | 0 | Depth/complexity DoS, field suggestions, auth bypass |
| Cache Poisoning | 5 | 5 | 0 | Vary header, further unkeyed headers |
| HPP | 5 | 5 | 0 | — |
| Infrastructure | N/A | N/A | N/A | Engine-owned, no plugins needed |
| Header Hardening (expansion) | 28 | 28 | 0 | Directive policies; presence checks stay separate |
| Product Fingerprints (expansion) | 72 | 72 | 0 | Banner-only, tentative by design |

**Reference catalog**: 438 plugins (375 Tier 1 YAML, 62 Tier 2 JS, 1 Tier 3 native). This page enumerates the class-level detector subset; the 180 critical/control-plane and rare-product exposure plugins plus this 100-plugin Tier 1 expansion pack are indexed in `plugins/README.md` and `docs/detector-inventory.md`, so the row counts below are not the full catalog.
**Listed rows**: class-level plugins only; complete/partial counts apply only to those rows.
**Significant Gaps**: 15+ classes with missing coverage

---

## Priority Gaps for Phase 2-3 Implementation

Based on the architecture support (oracles, engine capabilities) and real-world impact:

### High Priority (Architecture Supports, High Impact)
1. **OOB Command Injection** - Uses existing `oob` + `timing` oracles; blind RCE is critical
2. **Blind NoSQL Injection (OOB)** - Uses the existing `oob` oracle; timing (`nosql-injection-timing-json-body`) and operator differential (`nosql-injection-differential-json-body`) now ship
3. **Blind LDAP Injection (OOB)** - Uses existing `oob` oracle; now ships for JSON body fields (`ldap-injection-oob-json-body`), query points stay with Tier 1
4. **Blind SSTI (OOB)** - Uses existing `oob` oracle; now ships for JSON body fields (`ssti-json-body-oob`), query points stay with Tier 1
5. **BOLA / Role-Based Authorization Testing** - Uses existing `differential` oracle with auth context; sequential-identifier matrix (`idor-sequential-id-matrix`) now ships, role-based matrices remain
6. **Debug Endpoint Enumeration** - Uses existing `error`/`version` oracles; passive/active
7. **Sensitive File Exposure (Extended)** - Uses existing `error` oracle; expanded path list

### Medium Priority (Architecture Supports, Moderate Impact)
8. **GraphQL Authorization/DoS Plugins** - Uses existing `version`/`differential` oracles
9. **Cache Poisoning Variants** - Uses existing `differential` oracle; method-override family now ships (`web-cache-method-override`), `Vary` remains
10. **HPP in JSON/Multipart** - Uses existing `differential` oracle
11. **WebSocket Security** - New oracle may be needed
12. **Request Smuggling Plugin** - Engine oracle exists, needs plugin wrapper

### Lower Priority (Requires New Oracle or Significant Work)
13. **Deserialization with OOB Gadget Chains** - Needs gadget library + OOB
14. **Session Management Flaws** - Needs auth context + flow replay
15. **PDF/Document SSRF** - New vectors, may need new oracle
16. **DNS Rebinding Detection** - Complex, requires controlled DNS

---

## Next Steps

1. **Phase 2**: Validate architecture support for high-priority gaps (confirm oracles, engine capabilities)
2. **Phase 3**: Implement first batch of high-priority plugins with fixtures
3. **Phase 4**: Update documentation and coverage matrix
4. **Phase 5**: Run validation tests and deliver report
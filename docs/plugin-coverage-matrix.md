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

**Gaps:**
- No DOM XSS plugin for fragment/hash routes without deep build (engine-owned `browserExecution` oracle exists but no Tier 1/2 plugin)
- No mutation XSS (mXSS) detection
- No XSS via `postMessage` / cross-origin messaging
- No XSS in WebSocket messages

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

**Gaps:**
- **PostgreSQL blind SQLi OOB**: No callback-only primitive short of `COPY ... TO PROGRAM` / `dblink` (documented in known-limits.md)
- No time-based blind with alternative payloads (e.g., heavy queries)
- No second-order SQLi detection
- No NoSQL injection coverage beyond auth bypass (see section 5)

---

## 3. Command Injection

| Plugin ID | Tier | Oracle | Phase | Safe | Active | Confidence Ceiling | OOB | Fixtures | Status | Notes |
|-----------|------|--------|-------|------|--------|-------------------|-----|----------|--------|-------|
| `command-injection-error` | YAML | error | probe | false | true | confirmed | none | ✓ | Complete | Command output reflection + differential (calculation) |
| `command-injection-timing` | YAML | timing | probe | false | true | firm | optional | ✓ | Complete | Sleep-based timing with statistical test |

**Gaps:**
- **No OOB command injection plugin**: Blind command injection with OOB callback (DNS/HTTP exfil) — `oob=required` plugin missing
- No command injection via template engines (covered by SSTI)
- No Windows-specific command injection vectors

---

## 4. Server-Side Request Forgery (SSRF)

| Plugin ID | Tier | Oracle | Phase | Safe | Active | Confidence Ceiling | OOB | Fixtures | Status | Notes |
|-----------|------|--------|-------|------|--------|-------------------|-----|----------|--------|-------|
| `ssrf-cloud-metadata` | YAML | reflection | probe | false | true | confirmed | none | ✓ | Complete | Cloud metadata endpoint reflection (169.254.169.254, 100.100.100.200) |
| `ssrf-blind-oob` | JS | oob | probe | false | true | confirmed | required | ✓ | Complete | Blind SSRF with OOB callback; scheme/parser-confusion/redirect-echo/numeric-host variants |
| `nextjs-image-optimizer-ssrf` | YAML | oob | probe | false | true | confirmed | required | ✓ | Complete | Next.js `/_next/image` with `url={{OOB_URL}}` |
| `ssrf-internal-port-scan` | YAML | reflection/error | probe | false | true | firm | none | ✓ | Partial | Internal port scan via SSRF; reflection/error based |

**Gaps:**
- **No SSRF via PDF generation / document conversion** (wkhtmltopdf, puppeteer, etc.)
- **No SSRF via XML external entity** (covered by XXE plugins)
- **No SSRF via DNS rebinding detection**
- **No SSRF via cloud provider metadata variants beyond AWS/Azure** (GCP, DigitalOcean, etc.)
- **No SSRF via redirect chains with internal targets**

---

## 5. NoSQL Injection

| Plugin ID | Tier | Oracle | Phase | Safe | Active | Confidence Ceiling | OOB | Fixtures | Status | Notes |
|-----------|------|--------|-------|------|--------|-------------------|-----|----------|--------|-------|
| `nosql-injection-error` | YAML | error | probe | false | true | confirmed | none | ✓ | Complete | Error signature-based NoSQL injection |
| `nosql-auth-bypass-differential` | YAML | differential | probe | false | true | firm | none | ✓ | Complete | Operator-injected JSON body vs invalid-credential control |

**Gaps:**
- **No blind NoSQL injection with timing** (e.g., `$where` with sleep)
- **No blind NoSQL injection with OOB** (exfiltration via DNS/HTTP)
- **No query-string (non-JSON) NoSQL bypass variants** (documented as out of scope in known-limits.md)
- **No MongoDB `$where` / JavaScript injection detection**

---

## 6. LDAP Injection

| Plugin ID | Tier | Oracle | Phase | Safe | Active | Confidence Ceiling | OOB | Fixtures | Status | Notes |
|-----------|------|--------|-------|------|--------|-------------------|-----|----------|--------|-------|
| `ldap-injection-differential` | YAML | differential | probe | false | true | confirmed | none | ✓ | Complete | Boolean differential LDAP injection |
| `ldap-injection-blind` | YAML | timing/oob | probe | false | true | firm/confirmed | optional | ✓ | Partial | Blind LDAP with timing/OOB |

**Gaps:**
- **No LDAP injection with OOB exfiltration** (blind LDAP with DNS callback)
- **No LDAP injection via filter manipulation beyond boolean**

---

## 7. XXE (XML External Entity)

| Plugin ID | Tier | Oracle | Phase | Safe | Active | Confidence Ceiling | OOB | Fixtures | Status | Notes |
|-----------|------|--------|-------|------|--------|-------------------|-----|----------|--------|-------|
| `xxe-reflected-basic` | YAML | reflection | probe | false | true | confirmed | none | ✓ | Complete | In-band XXE with file:// entity reflection |
| `xxe-oob` | YAML | oob | probe | false | true | confirmed | required | ✓ | Complete | Blind XXE via OOB (DTD fetch callback) |
| `xxe-blind-oob` | YAML | oob | probe | false | true | confirmed | required | ✓ | Complete | Alternative blind XXE OOB plugin |
| `xml-external-entity-blind` | YAML | oob | probe | false | true | confirmed | required | ✓ | Partial | Duplicate of xxe-oob/xxe-blind-oob? |

**Gaps:**
- **Duplicate plugins**: `xxe-oob`, `xxe-blind-oob`, `xml-external-entity-blind` appear to overlap
- No XXE via SOAP/SAML specific vectors
- No XXE with parameter entities for internal file read without OOB

---

## 8. SSTI (Server-Side Template Injection)

| Plugin ID | Tier | Oracle | Phase | Safe | Active | Confidence Ceiling | OOB | Fixtures | Status | Notes |
|-----------|------|--------|-------|------|--------|-------------------|-----|----------|--------|-------|
| `template-injection-reflection` | YAML | reflection | probe | false | true | confirmed | none | ✓ | Complete | Arithmetic proof (1337*1337=1787569) via reflection |
| `expression-language-injection` | YAML | reflection | probe | false | true | firm | none | ✓ | Complete | EL injection with arithmetic canary |
| `ssti-blind-timing` | YAML | timing | probe | false | true | firm | optional | ✓ | Partial | Blind SSTI with sleep timing |

**Gaps:**
- **No blind SSTI with OOB exfiltration** (template function DNS callback)
- **No SSTI via specific template engines** (Jinja2, Twig, Freemarker, Velocity, Thymeleaf specific payloads)
- **No SSTI in non-HTML contexts** (email templates, PDF generation, etc.)

---

## 9. Path Traversal / File Inclusion

| Plugin ID | Tier | Oracle | Phase | Safe | Active | Confidence Ceiling | OOB | Fixtures | Status | Notes |
|-----------|------|--------|-------|------|--------|-------------------|-----|----------|--------|-------|
| `path-traversal-error` | YAML | error | probe | true | true | confirmed | none | ✓ | Complete | File content signatures (root:x:, [fonts], etc.) + soft-404 control |
| `file-inclusion-rfi` | YAML | reflection | probe | false | true | confirmed | none | ✓ | Complete | RFI via reflection oracle (loopback canary) |
| `rfi-remote-include` | YAML | reflection | probe | false | true | confirmed | none | ✓ | Complete | Remote file include via reflection |

**Gaps:**
- **No blind path traversal** (documented as undetectable in known-limits.md - GASH-018)
- **No path traversal via archive upload** (zip slip, tar slip)
- **No path traversal via Unicode/encoding bypasses** (double encoding, UTF-7, etc.)

---

## 10. Open Redirect

| Plugin ID | Tier | Oracle | Phase | Safe | Active | Confidence Ceiling | OOB | Fixtures | Status | Notes |
|-----------|------|--------|-------|------|--------|-------------------|-----|----------|--------|-------|
| `open-redirect-param` | YAML | redirect | probe | true | false | confirmed | none | ✓ | Complete | Location parse + host compare + DNS double-check |
| `oauth-open-redirect` | YAML | redirect | probe | true | false | confirmed | none | ✓ | Complete | OAuth authorize paths with redirect_uri params |

**Gaps:**
- **No open redirect via JavaScript** (DOM-based `location.href`, `window.open`)
- **No open redirect via header injection** (Location header via CRLF)
- **No open redirect in POST body parameters**

---

## 11. CORS Misconfiguration

| Plugin ID | Tier | Oracle | Phase | Safe | Active | Confidence Ceiling | OOB | Fixtures | Status | Notes |
|-----------|------|--------|-------|------|--------|-------------------|-----|----------|--------|-------|
| `cors-misconfig` | YAML | cors | probe | true | false | confirmed | none | ✓ | Complete | ACAO wildcard/reflection + credentials |
| `insecure-cors-preflight` | YAML | cors | probe | true | false | confirmed | none | ✓ | Complete | Preflight-specific CORS checks |

**Gaps:**
- **No CORS with null origin** exploitation
- **No CORS with subdomain wildcard** (`*.example.com`) validation
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
| `jwt-token-exposure` | YAML | header | probe | true | false | confirmed | none | ✓ | Complete | JWT in headers/cookies |
| `jwt-alg-confusion` | YAML | header | probe | true | false | confirmed | none | ✓ | Complete | JWT algorithm confusion (none, HS256/RS256 switch) |
| `jwt-none-alg-confusion` | YAML | header | probe | true | false | confirmed | none | ✓ | Partial | Duplicate of jwt-alg-confusion? |
| `nextjs-middleware-bypass` | YAML | middleware-bypass | probe | false | true | firm | none | ✓ | Complete | CVE-2025-29927 middleware bypass |

**Gaps:**
- **BOLA (Broken Object Level Authorization)** beyond IDOR: No role-based access control testing, no horizontal/vertical privilege escalation flows
- **No API authorization matrix testing** (different roles accessing different endpoints)
- **No broken function level authorization** (admin endpoints accessible to users)
- **No authentication bypass via password reset / 2FA / OAuth flows**
- **No session management flaws** (session fixation, concurrent sessions, logout)
- **Duplicate**: `jwt-alg-confusion` and `jwt-none-alg-confusion` appear to overlap

---

## 14. Injection - Other

| Plugin ID | Tier | Oracle | Phase | Safe | Active | Confidence Ceiling | OOB | Fixtures | Status | Notes |
|-----------|------|--------|-------|------|--------|-------------------|-----|----------|--------|-------|
| `xpath-injection-error` | YAML | error | probe | false | true | firm | none | ✓ | Complete | XPath parser error signatures |
| `ssi-injection` | YAML | error | probe | false | true | firm | none | ✓ | Complete | SSI printenv two-marker pair |
| `prototype-pollution-differential` | YAML | differential | probe | false | true | confirmed | none | ✓ | Complete | Prototype pollution via differential |
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

**Gaps:**
- **No file upload validation bypass** (MIME type, extension, magic bytes, content-type)
- **No file upload via archive (zip slip)**
- **No file upload RCE via polyglot files**
- **No file upload path traversal in filename**

---

## 17. Deserialization

| Plugin ID | Tier | Oracle | Phase | Safe | Active | Confidence Ceiling | OOB | Fixtures | Status | Notes |
|-----------|------|--------|-------|------|--------|-------------------|-----|----------|--------|-------|
| `insecure-deserialization-error` | YAML | error | probe | false | true | firm | none | ✓ | Complete | Error signatures only; no gadget chain |

**Gaps:**
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

**Gaps:**
- **No GraphQL query depth/complexity DoS**
- **No GraphQL field suggestion / introspection abuse**
- **No GraphQL batch query abuse**
- **No GraphQL authorization bypass** (field-level permissions)

---

## 21. Web Cache Poisoning

| Plugin ID | Tier | Oracle | Phase | Safe | Active | Confidence Ceiling | OOB | Fixtures | Status | Notes |
|-----------|------|--------|-------|------|--------|-------------------|-----|----------|--------|-------|
| `web-cache-poisoning-basic` | YAML | differential | probe | false | true | confirmed | none | ✓ | Complete | Cache poisoning via differential |
| `cache-poisoning-host-header` | YAML | differential | probe | false | true | confirmed | none | ✓ | Complete | Host header cache poisoning |

**Gaps:**
- **No cache poisoning via HTTP method override**
- **No cache poisoning via Vary header manipulation**
- **No cache poisoning with unkeyed headers** (beyond Host)

---

## 22. HPP (HTTP Parameter Pollution)

| Plugin ID | Tier | Oracle | Phase | Safe | Active | Confidence Ceiling | OOB | Fixtures | Status | Notes |
|-----------|------|--------|-------|------|--------|-------------------|-----|----------|--------|-------|
| `hpp-parameter-pollution` | YAML | differential | probe | false | true | confirmed | none | ✓ | Complete | Parameter pollution via differential |
| `hpp-duplicate-emission` | JS | differential | probe | false | true | confirmed | none | ✓ | Complete | Native duplicate-key emission (`id=1&id=2`) |

**Gaps:**
- **No HPP in JSON body** (duplicate keys in JSON)
- **No HPP in multipart/form-data**

---

## 23. Infrastructure / Recon (Engine-Owned, No Plugin File)

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
| XSS | 5 | 4 | 1 | DOM fragment/hash, mXSS, postMessage, WebSocket |
| SQL Injection | 6 | 5 | 1 | PostgreSQL blind OOB, second-order, time-based variants |
| Command Injection | 2 | 2 | 0 | OOB command injection, Windows vectors |
| SSRF | 4 | 3 | 1 | PDF generation, DNS rebinding, GCP/DO metadata, redirect chains |
| NoSQL Injection | 2 | 1 | 1 | Blind timing/OOB, query-string bypass, $where JS injection |
| LDAP Injection | 2 | 1 | 1 | OOB exfiltration |
| XXE | 4 | 3 | 1 | Duplicate plugins, SOAP/SAML, parameter entities |
| SSTI | 3 | 2 | 1 | Blind OOB, engine-specific, non-HTML contexts |
| Path Traversal | 3 | 3 | 0 | Blind (undetectable), archive upload, encoding bypasses |
| Open Redirect | 2 | 2 | 0 | JS-based, header-based, POST body |
| CORS | 2 | 2 | 0 | Null origin, subdomain wildcard, preflight cache poisoning |
| Cookie/Session | 3 | 3 | 0 | Cookie prefixes, session fixation, timeout, CSRF Lax bypass |
| Auth/Authorization | 6 | 4 | 2 | BOLA/role-based, function-level, auth bypass flows, session mgmt, duplicates |
| Other Injection | 10 | 10 | 0 | Request smuggling plugin, WebSocket, HPP JSON/multipart |
| Info Disclosure | 11 | 11 | 0 | Debug endpoints, sensitive files, API docs, cloud creds |
| File Upload | 1 | 1 | 0 | Validation bypass, zip slip, polyglot, path traversal |
| Deserialization | 1 | 0 | 1 | OOB gadget chains, .NET, Java ysoserial, PHP |
| Subdomain Takeover | 1 | 1 | 0 | DNS CNAME verification, cloud-specific |
| Rate Limiting | 1 | 1 | 0 | Bypass testing, API enumeration, DoS |
| GraphQL | 2 | 2 | 0 | DoS, field suggestions, batch abuse, auth bypass |
| Cache Poisoning | 2 | 2 | 0 | Method override, Vary header, unkeyed headers |
| HPP | 2 | 2 | 0 | JSON body, multipart |
| Infrastructure | N/A | N/A | N/A | Engine-owned, no plugins needed |

**Total Plugins**: ~70 (excluding engine-owned recon)
**Complete**: ~55
**Partial**: ~10
**Significant Gaps**: 15+ classes with missing coverage

---

## Priority Gaps for Phase 2-3 Implementation

Based on the architecture support (oracles, engine capabilities) and real-world impact:

### High Priority (Architecture Supports, High Impact)
1. **OOB Command Injection** - Uses existing `oob` + `timing` oracles; blind RCE is critical
2. **Blind NoSQL Injection (Timing + OOB)** - Uses existing `timing` + `oob` oracles
3. **Blind LDAP Injection (OOB)** - Uses existing `oob` oracle
4. **Blind SSTI (OOB)** - Uses existing `oob` oracle; template DNS exfiltration
5. **BOLA / Role-Based Authorization Testing** - Uses existing `differential` oracle with auth context
6. **Debug Endpoint Enumeration** - Uses existing `error`/`version` oracles; passive/active
7. **Sensitive File Exposure (Extended)** - Uses existing `error` oracle; expanded path list

### Medium Priority (Architecture Supports, Moderate Impact)
8. **GraphQL Authorization/DoS Plugins** - Uses existing `version`/`differential` oracles
9. **Cache Poisoning Variants** - Uses existing `differential` oracle
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
"""Finding knowledge base — CWE / OWASP Top 10 / estimated CVSS / remediation.

CVSS scores are static templates (estimates, environment-dependent), marked
as estimated in reports. Remediation notes are short and action-oriented.
"""

from __future__ import annotations

# title (prefix match) -> info. Order does not matter, startswith is used.
KB: list[tuple[str, dict]] = [
    ("Possible SQL Injection", dict(
        cwe="CWE-89", owasp="A03:2021 – Injection",
        cvss="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H (9.8)",
        remediation="Use parameterized queries / prepared statements; never "
                    "concatenate input into SQL, avoid the ORM's raw-query mode; "
                    "restrict DB user privileges; don't expose error messages.")),
    ("Possible Blind SQL Injection", dict(
        cwe="CWE-89", owasp="A03:2021 – Injection",
        cvss="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H (9.8)",
        remediation="Boolean/time-based has the same root cause: dynamic SQL. "
                    "Prepared statements + least privilege + generic error pages. "
                    "A WAF alone is not a fix.")),
    ("Possible Time-Based Blind SQLi", dict(
        cwe="CWE-89", owasp="A03:2021 – Injection",
        cvss="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H (9.8)",
        remediation="Slow responses to time functions prove injection. Remove "
                    "dynamic SQL, enforce allowlist + prepared statements.")),
    ("Possible SQLi WAF Bypass", dict(
        cwe="CWE-89", owasp="A03:2021 – Injection",
        cvss="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H (9.8)",
        remediation="The filter was bypassed: don't trust it, fix the root cause "
                    "(dynamic SQL); update the WAF rule set (CRS).")),
    ("Possible Stored XSS", dict(
        cwe="CWE-79", owasp="A03:2021 – Injection",
        cvss="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N (6.1)",
        remediation="Encode output for its context (HTML/JS/attribute), enforce CSP "
                    "(script-src, Trusted Types), sanitize stored content with an "
                    "allowlist HTML sanitizer (DOMPurify).")),
    ("Stored reflection", dict(
        cwe="CWE-79", owasp="A03:2021 – Injection",
        cvss="no estimate",
        remediation="Unconfirmed persistence: the value is stored and "
                     "re-rendered but no script breaker was observed. Confirm "
                     "the render context (and browser execution) before "
                     "calling it Stored XSS; encode stored output + CSP.")),
    ("Possible Reflected XSS", dict(
        cwe="CWE-79", owasp="A03:2021 – Injection",
        cvss="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N (6.1)",
        remediation="Context-aware encode reflected input; CSP + HttpOnly/SameSite "
                    "cookies limit the impact.")),
    ("Header reflection", dict(
        cwe="CWE-79", owasp="A03:2021 – Injection",
        cvss="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N (6.1)",
        remediation="Don't print request data (URL/headers) raw on error pages; "
                    "encode it or use a static template.")),
    ("Partially encoded reflection", dict(
        cwe="CWE-79", owasp="A03:2021 – Injection",
        cvss="CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:C/C:L/I:L/A:N (5.4)",
        remediation="Partial encoding can be bypassed per context (URI/event "
                     "handlers). Bind every output to one encoding policy, add CSP.")),
    ("Reflected input", dict(
        cwe="CWE-79", owasp="A03:2021 – Injection",
        cvss="no estimate",
        remediation="Unconfirmed reflection: the marker echoes but breaker "
                     "characters were not observed. Confirm per context "
                     "(attribute/JS) before calling it XSS; add "
                     "context-aware encoding + CSP.")),
    ("Blind XSS canary", dict(
        cwe="CWE-79", owasp="A03:2021 – Injection",
        cvss="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N (6.1)",
        remediation="Confirm via the external listener (callback); if it fires, "
                    "apply the Stored XSS procedure.")),
    ("Blind XSS (confirmed via OOB)", dict(
        cwe="CWE-79", owasp="A03:2021 – Injection",
        cvss="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N (8.2)",
        remediation="Proven script execution in another user's browser: apply "
                    "the Stored XSS procedure urgently, then find how the "
                    "payload reached the victim (stored source).")),
    ("SQLi (confirmed via OOB)", dict(
        cwe="CWE-89", owasp="A03:2021 – Injection",
        cvss="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H (9.8)",
        remediation="Proven: the database resolved our callback domain. Treat "
                    "as fully injectable — prepared statements, least "
                    "privilege, no dynamic SQL.")),
    ("Login username enumeration", dict(
        cwe="CWE-204", owasp="A07:2021 – Identification and Authentication Failures",
        cvss="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N (5.3)",
        remediation="Return identical errors for bad-user vs bad-password; "
                    "add login throttling and CAPTCHA.")),
    ("Possible LDAP injection (auth bypass)", dict(
        cwe="CWE-90", owasp="A03:2021 – Injection",
        cvss="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N (9.1)",
        remediation="Escape LDAP filters (or bind with parameterized APIs); "
                    "never concatenate usernames into search filters.")),
    ("Reflected redirect target", dict(
        cwe="CWE-601", owasp="A01:2021 – Broken Access Control",
        cvss="CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:N/I:L/A:N (3.1)",
        remediation="Informational: a redirect parameter echoes in the page; "
                    "check JS sinks before calling it open redirect.")),
    ("Cache poisoning surface", dict(
        cwe="CWE-444", owasp="A08:2021 – Software and Data Integrity Failures",
        cvss="CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:N (3.7)",
        remediation="Informational: confirm with two fetches (poison, then "
                    "victim request); key caches on Host, fix origin "
                    "validation.")),
    ("SSRF (confirmed via OOB)", dict(
        cwe="CWE-918", owasp="A10:2021 – SSRF",
        cvss="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H (9.8)",
        remediation="Proven server-side fetch: allowlist the parameter, block "
                    "internal/metadata egress, never mirror fetched content.")),
    ("Password reset poisoning", dict(
        cwe="CWE-640", owasp="A07:2021 – Identification and Authentication Failures",
        cvss="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N (8.1)",
        remediation="Build reset links from configured app URLs, never from "
                    "the Host header; reject unknown hosts at the edge.")),
    ("Possible SSTI", dict(
        cwe="CWE-1336", owasp="A03:2021 – Injection",
        cvss="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H (9.8)",
        remediation="Don't concatenate user input into templates; use logic-less "
                    "templates, keep the engine sandboxed and isolated.")),
    ("Possible SSRF", dict(
        cwe="CWE-918", owasp="A10:2021 – SSRF",
        cvss="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:L (8.6)",
        remediation="Bind URL parameters to an allowlist; block internal/metadata "
                    "addresses (incl. 169.254.169.254) at egress; don't mirror the "
                    "response back to the user.")),
    ("Possible IDOR", dict(
        cwe="CWE-639", owasp="A01:2021 – Broken Access Control",
        cvss="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N (8.1)",
        remediation="Check ownership/permission server-side on every object access "
                    "(object-level, not just function-level); prefer unguessable "
                    "references (UUID) over sequential IDs.")),
    ("Confirmed IDOR", dict(
        cwe="CWE-639", owasp="A01:2021 – Broken Access Control",
        cvss="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N (8.1)",
        remediation="PROVEN: a second user reads another user's object. Enforce "
                    "object-level authorization immediately, audit access logs "
                    "for exploitation, prefer unguessable references.")),
    ("Missing authentication on object endpoint", dict(
        cwe="CWE-306", owasp="A01:2021 – Broken Access Control",
        cvss="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N (7.5)",
        remediation="PROVEN: no session needed. Require authentication on "
                    "every object endpoint, then add object-level checks; "
                    "audit logs for anonymous reads.")),
    ("Direct object reference reachable anonymously", dict(
        cwe="CWE-639", owasp="A01:2021 – Broken Access Control",
        cvss="CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N (6.8)",
        remediation="Unguessable IDs are not access control: gate the object "
                    "behind session + ownership checks even when the URL "
                    "cannot be guessed.")),
    ("Possible missing authorization (admin surface)", dict(
        cwe="CWE-862", owasp="A01:2021 – Broken Access Control",
        cvss="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N (4.3)",
        remediation="Unproven boundary: replay the request as anonymous and "
                    "as a low-privilege user; enforce role checks server-side "
                    "on every admin path, not just by hiding links.")),
    ("Possible SQLi Auth Bypass", dict(
        cwe="CWE-89", owasp="A03:2021 – Injection",
        cvss="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N (9.1)",
        remediation="Move the login query to prepared statements; make success and "
                    "failure responses indistinguishable; add brute-force protection "
                    "+ CAPTCHA + lockout; enforce MFA.")),
    ("Possible Unrestricted File Upload", dict(
        cwe="CWE-434", owasp="A08:2021 – Integrity Failures",
        cvss="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H (9.8)",
        remediation="Validate extension + MIME + magic bytes together; store uploads "
                    "outside the web root in a non-executable dir; rename files "
                    "(UUID), reject double extensions/null bytes.")),
    ("Upload Filter Bypass", dict(
        cwe="CWE-434", owasp="A08:2021 – Integrity Failures",
        cvss="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H (9.8)",
        remediation="The filter was bypassed: allowlist (.png/.jpg…) instead of "
                    "blocklist, content validation + non-executable storage.")),
    ("Stored file via JSON upload", dict(
        cwe="CWE-434", owasp="A08:2021 – Integrity Failures",
        cvss="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N (9.1)",
        remediation="Base64/file fields are decoded and served: validate "
                    "content server-side, store outside the web root, serve "
                    "with safe Content-Type/Disposition.")),
    ("Upload content-type not validated", dict(
        cwe="CWE-436", owasp="A08:2021 – Integrity Failures",
        cvss="no estimate",
        remediation="Hygiene note: extension and Content-Type disagree yet "
                    "both pass. Validate magic bytes + allowlisted "
                    "extensions together.")),
    ("Upload filename handling", dict(
        cwe="CWE-22", owasp="A01:2021 – Broken Access Control",
        cvss="no estimate",
        remediation="Reflection only, not a write proof: sanitize filenames "
                    "(basename, allowlist charset), store under UUIDs, never "
                    "concatenate user names into paths.")),
    ("Admin Panel", dict(
        cwe="CWE-552", owasp="A05:2021 – Security Misconfiguration",
        cvss="no estimate",
        remediation="Discovery note, not a vulnerability: verify the panel is "
                    "intentional, behind VPN/IP allowlist, with MFA and lockout.")),
    ("Upload form detected", dict(
        cwe="CWE-434", owasp="A08:2021 – Integrity Failures",
        cvss="no estimate",
        remediation="Discovery note: a file input exists. Only a --deep upload "
                    "test (accepted executable) makes this a finding.")),
    ("Restricted Area", dict(
        cwe="CWE-552", owasp="A05:2021 – Security Misconfiguration",
        cvss="no estimate",
        remediation="Discovery note: the path exists but access is controlled "
                    "(401/403). Confirm the control is intentional.")),
    ("General Page", dict(
        cwe="CWE-?", owasp="—",
        cvss="no estimate",
        remediation="Discovery note: an ordinary reachable page. No action.")),
    ("Redirect", dict(
        cwe="CWE-?", owasp="—",
        cvss="no estimate",
        remediation="Discovery note: the path redirects elsewhere. No action.")),
    ("Critical File Exposure", dict(
        cwe="CWE-538", owasp="A05:2021 – Security Misconfiguration",
        cvss="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N (7.5)",
        remediation="Move sensitive files (.env, backups, .git) out of the web root; "
                    "add secret scanning to the deploy pipeline; ROTATE any leaked "
                    "keys immediately.")),
    ("Sensitive File (unverified", dict(
        cwe="CWE-538", owasp="A05:2021 – Security Misconfiguration",
        cvss="no estimate",
        remediation="A secret-looking path answers HTTP 200 but its content "
                    "doesn't validate — fetch it manually before calling it "
                    "an exposure.")),
    ("Sensitive Directory", dict(
        cwe="CWE-538", owasp="A05:2021 – Security Misconfiguration",
        cvss="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N (5.3)",
        remediation="Close unneeded directories / disable listing, remove defaults.")),
    ("robots.txt", dict(
        cwe="CWE-538", owasp="A05:2021 – Security Misconfiguration",
        cvss="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N (5.3)",
        remediation="robots.txt is not access control; authorize Disallow'ed paths "
                    "anyway, don't list sensitive paths there.")),
    ("SSRF surface", dict(
        cwe="CWE-918", owasp="A10:2021 – SSRF",
        cvss="CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N (3.7)",
        remediation="Inventory URL-accepting parameters, apply allowlist + egress.")),
    ("DOM XSS (confirmed", dict(
        cwe="CWE-79", owasp="A03:2021 – Injection",
        cvss="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N (8.2)",
        remediation="Headless-confirmed DOM XSS: don't flow location/hash/postMessage "
                    "sources into innerHTML/eval/document.write sinks; use "
                    "textContent + DOMPurify + Trusted Types + CSP.")),
    ("DOM XSS (suspected", dict(
        cwe="CWE-79", owasp="A03:2021 – Injection",
        cvss="no estimate",
        remediation="Controllable sink but no executable content observed: "
                     "craft a context PoC (event/js-url for the sink) before "
                     "calling it DOM XSS; route the source through "
                     "textContent/DOMPurify.")),
    ("JS DOM write", dict(
        cwe="CWE-79", owasp="A03:2021 – Injection",
        cvss="CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:C/C:L/I:L/A:N (5.4)",
        remediation="Review JS-to-DOM sinks (innerHTML, outerHTML, "
                    "insertAdjacentHTML); sanitize user input before sinking.")),
    ("WAF detected", dict(
        cwe="CWE-?", owasp="—",
        cvss="no estimate",
        remediation="Informational: results behind a WAF may be incomplete; check WAF "
                    "logs too, deepen bypass testing manually if needed.")),
    ("Weak cookie flags", dict(
        cwe="CWE-614", owasp="A05:2021 – Security Misconfiguration",
        cvss="CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N (3.1)",
        remediation="Add HttpOnly + Secure + SameSite=Lax/Strict to session cookies.")),
    ("Missing Security Header", dict(
        cwe="CWE-693", owasp="A05:2021 – Security Misconfiguration",
        cvss="no estimate",
        remediation="Emit the header; start with a report-only CSP, then enforce. "
                    "HSTS needs max-age + includeSubDomains.")),
    ("Weak CSP", dict(
        cwe="CWE-693", owasp="A05:2021 – Security Misconfiguration",
        cvss="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N (5.4)",
        remediation="Remove 'unsafe-inline'/'unsafe-eval' and wildcards from "
                    "script-src; use nonces or hashes for inline scripts.")),
    ("Weak HSTS", dict(
        cwe="CWE-693", owasp="A05:2021 – Security Misconfiguration",
        cvss="no estimate",
        remediation="Raise max-age to at least a year (31536000) with "
                    "includeSubDomains; consider preload.")),
    ("Possible Open Redirect", dict(
        cwe="CWE-601", owasp="A01:2021 – Broken Access Control",
        cvss="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N (6.1)",
        remediation="Never redirect to user input; keep an allowlist of paths, "
                    "reject absolute URLs.")),
    ("Possible Path Traversal", dict(
        cwe="CWE-22", owasp="A01:2021 – Broken Access Control",
        cvss="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N (7.5)",
        remediation="Map user input to an allowlist (no raw paths); canonicalize "
                    "and jail reads inside one directory.")),
    ("Permissive CORS", dict(
        cwe="CWE-942", owasp="A01:2021 – Broken Access Control",
        cvss="CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:N (5.4)",
        remediation="Reflect only trusted origins, never * with credentials; "
                    "Vary: Origin.")),
    ("Risky HTTP method", dict(
        cwe="CWE-693", owasp="A05:2021 – Security Misconfiguration",
        cvss="no estimate",
        remediation="Advertised only: confirm TRACE/PUT/DELETE actually work, "
                    "then disable TRACE (XST surface) and gate PUT/DELETE "
                    "behind auth.")),
    ("Exposed secret", dict(
        cwe="CWE-798", owasp="A07:2021 – Identification and Authentication Failures",
        cvss="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N (9.1)",
        remediation="ROTATE the key immediately; move secrets server-side "
                    "(env/BFF), scan the repo history too.")),
    ("JWT using alg:none", dict(
        cwe="CWE-327", owasp="A02:2021 – Cryptographic Failures",
        cvss="no estimate",
        remediation="Sighted, not proven: replay the token with alg:none and "
                    "a voided signature against a protected endpoint. Only an "
                    "accepted replay is a vulnerability; otherwise delete the "
                    "token from client-visible code.")),
    ("GraphQL introspection", dict(
        cwe="CWE-200", owasp="A01:2021 – Broken Access Control",
        cvss="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N (5.3)",
        remediation="Disable introspection in production; gate the endpoint "
                    "behind auth and depth/complexity limits.")),
    ("GraphQL mutations exposed", dict(
        cwe="CWE-?", owasp="—",
        cvss="no estimate",
        remediation="Informational surface map (never executed): review every "
                    "mutation's input validation and auth; hide admin-only "
                    "mutations behind roles.")),
    ("GraphQL weak input contract", dict(
        cwe="CWE-915", owasp="A08:2021 – Software and Data Integrity Failures",
        cvss="no estimate",
        remediation="Static schema note: a sensitive mutation input is "
                    "nullable client-side. Enforce allowlists + non-null + "
                    "server-side authorization regardless of the schema.")),
    ("Missing authorization on admin endpoint", dict(
        cwe="CWE-862", owasp="A01:2021 – Broken Access Control",
        cvss="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N (6.5)",
        remediation="PROVEN with an admin session: a normal user reads the "
                    "same admin content. Add role checks on every admin path "
                    "and audit who already read what.")),
    ("Exposed sensitive GraphQL field", dict(
        cwe="CWE-200", owasp="A01:2021 – Broken Access Control",
        cvss="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N (7.5)",
        remediation="Field-level auth is missing: require ownership/role "
                    "checks per field, stop returning secrets (hashes, "
                    "tokens) to low-privilege callers.")),
    ("Host header reflected", dict(
        cwe="CWE-640", owasp="A01:2021 – Broken Access Control",
        cvss="CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:N (5.4)",
        remediation="Never build links/keys from the Host header; allowlist "
                    "hosts, use relative URLs in emails.")),
    ("security.txt missing", dict(
        cwe="CWE-?", owasp="—",
        cvss="no estimate",
        remediation="Informational: publish /.well-known/security.txt with a "
                    "Contact field (RFC 9116).")),
    ("Possible OS Command Injection", dict(
        cwe="CWE-78", owasp="A03:2021 – Injection",
        cvss="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H (9.8)",
        remediation="Never pass user input to a shell; use argument arrays, "
                    "allowlists, and locked-down service users.")),
    ("Possible CRLF Injection", dict(
        cwe="CWE-113", owasp="A03:2021 – Injection",
        cvss="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N (6.1)",
        remediation="Strip CR/LF from reflected input; set headers from "
                    "constants, never from request data.")),
    ("Missing anti-CSRF controls", dict(
        cwe="CWE-352", owasp="A01:2021 – Broken Access Control",
        cvss="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N (8.8)",
        remediation="Add per-session CSRF tokens to state-changing forms, "
                    "SameSite=Lax/Strict cookies, and re-check auth server-side.")),
    ("Open Firebase database", dict(
        cwe="CWE-200", owasp="A01:2021 – Broken Access Control",
        cvss="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N (9.1)",
        remediation="Lock RTDB rules to authenticated owners immediately; "
                    "audit what was read, rotate exposed data.")),
    ("Exposed Supabase table", dict(
        cwe="CWE-639", owasp="A01:2021 – Broken Access Control",
        cvss="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N (8.1)",
        remediation="Enable RLS on every table with ownership checks "
                    "(auth.uid() = owner); deny anon by default, then open "
                    "only what is truly public.")),
    ("Next.js middleware bypass", dict(
        cwe="CWE-287", owasp="A01:2021 – Broken Access Control",
        cvss="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N (9.1)",
        remediation="Upgrade Next.js past the middleware-authorization fixes; "
                    "enforce auth in layouts/server components too, not only "
                    "in middleware.")),
    ("WordPress username disclosure", dict(
        cwe="CWE-200", owasp="A07:2021 – Identification and Authentication Failures",
        cvss="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N (5.3)",
        remediation="Restrict /wp-json/wp/v2/users to authenticated roles; "
                    "enforce strong passwords + login throttling + MFA.")),
    ("API docs exposed", dict(
        cwe="CWE-200", owasp="—",
        cvss="no estimate",
        remediation="Informational: gate Swagger/OpenAPI behind auth or IP "
                    "allowlist if the API is not public.")),
    ("Client-controllable role field", dict(
        cwe="CWE-915", owasp="A08:2021 – Software and Data Integrity Failures",
        cvss="no estimate",
        remediation="Informational: never trust role fields from the client; "
                    "assign roles server-side only.")),
    ("Prototype Pollution", dict(
        cwe="CWE-1321", owasp="A08:2021 – Integrity Failures",
        cvss="CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:N/I:L/A:N (3.1)",
        remediation="Block __proto__/constructor keys in merges, upgrade to a safe "
                    "library version, use Object.freeze / Map.")),
    ("TLS certificate expired", dict(
        cwe="CWE-298", owasp="A02:2021 – Cryptographic Failures",
        cvss="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N (7.5)",
        remediation="Expired trust is broken trust: renew from a public CA "
                    "immediately, automate renewal (ACME), monitor expiry.")),
    ("TLS hostname mismatch", dict(
        cwe="CWE-297", owasp="A02:2021 – Cryptographic Failures",
        cvss="CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:N (8.1)",
        remediation="Serve the certificate whose SAN covers this hostname "
                    "(or add the SAN); never train users to click through "
                    "name warnings.")),
    ("Self-signed TLS certificate", dict(
        cwe="CWE-296", owasp="A02:2021 – Cryptographic Failures",
        cvss="CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:N (5.4)",
        remediation="Fine for loopback labs; on any real host, terminate TLS "
                    "with a publicly trusted certificate.")),
    ("TLS certificate expires soon", dict(
        cwe="CWE-298", owasp="A02:2021 – Cryptographic Failures",
        cvss="no estimate",
        remediation="Informational: rotation due within 30 days — renew now, "
                    "then automate it.")),
    ("TLS certificate not yet valid", dict(
        cwe="CWE-298", owasp="A02:2021 – Cryptographic Failures",
        cvss="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N (3.7)",
        remediation="Check the server clock (NTP) and the deployment window; "
                    "the certificate is from the future.")),
    ("Weak TLS protocol enabled", dict(
        cwe="CWE-326", owasp="A02:2021 – Cryptographic Failures",
        cvss="CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N (5.9)",
        remediation="Set the TLS minimum to 1.2 (1.3 preferred) on the "
                    "terminator and re-test; old clients must upgrade.")),
    ("Weak TLS cipher negotiated", dict(
        cwe="CWE-327", owasp="A02:2021 – Cryptographic Failures",
        cvss="CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N (5.9)",
        remediation="Prefer AES-GCM/ChaCha20-Poly1305, drop RC4/3DES/MD5/ "
                    "export suites in the cipher string.")),
    ("Known vulnerable component", dict(
        cwe="CWE-1104", owasp="A06:2021 – Vulnerable and Outdated Components",
        cvss="varies by CVE (see detail for the NVD link)",
        remediation="Upgrade to the fixed release immediately; enable "
                    "dependabot/renovate so N-days don't linger.")),
    ("End-of-life component", dict(
        cwe="CWE-1104", owasp="A06:2021 – Vulnerable and Outdated Components",
        cvss="no estimate",
        remediation="EOL means every future CVE stays open: migrate to a "
                    "supported branch, there is no patch coming.")),
    ("Exposed development server", dict(
        cwe="CWE-668", owasp="A05:2021 – Security Misconfiguration",
        cvss="CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N (5.4)",
        remediation="Dev servers bind to 127.0.0.1 only (or gate with auth/"
                    "VPN); 0.0.0.0 publishes HMR/debug endpoints to the LAN.")),
    ("Local development server", dict(
        cwe="CWE-?", owasp="—",
        cvss="no estimate",
        remediation="Informational: correctly loopback-bound, no action.")),
    ("Local listeners inventory", dict(
        cwe="CWE-?", owasp="—",
        cvss="no estimate",
        remediation="Informational inventory of local listeners with "
                    "process attribution; triage exposed ones first.")),
    ("Local UDP service", dict(
        cwe="CWE-?", owasp="—",
        cvss="no estimate",
        remediation="Informational: loopback UDP service, port-classified "
                    "(only DNS gets one benign query); no action.")),
    ("LAN-visible UDP service", dict(
        cwe="CWE-668", owasp="A05:2021 – Security Misconfiguration",
        cvss="no estimate",
        remediation="UDP answers off-host: confirm the service must be "
                    "LAN-reachable; bind to loopback or firewall it.")),
    ("Overly broad secret file permissions", dict(
        cwe="CWE-732", owasp="A01:2021 – Broken Access Control",
        cvss="CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N (5.5)",
        remediation="chmod 0600 secret files (.env, keys, cloud credentials); "
                    "content was not read, fix the bits.")),
    ("Secret file present", dict(
        cwe="CWE-?", owasp="—",
        cvss="no estimate",
        remediation="Informational: exists with sane permissions; content "
                    "was not read.")),
    ("Host firewall disabled", dict(
        cwe="CWE-693", owasp="A05:2021 – Security Misconfiguration",
        cvss="no estimate",
        remediation="Informational posture note: re-enable the host firewall "
                    "or document why this host runs without one.")),
    ("Container/VM network present", dict(
        cwe="CWE-?", owasp="—",
        cvss="no estimate",
        remediation="Informational: virtual interfaces exist; audit "
                    "container/WSL guests separately.")),
    ("Container published port", dict(
        cwe="CWE-668", owasp="A05:2021 – Security Misconfiguration",
        cvss="no estimate",
        remediation="Host->container port mapping: confirm the published "
                    "port must be reachable at its exposure class; unpublish "
                    "or bind to 127.0.0.1 otherwise.")),
    ("WSL port forwarding", dict(
        cwe="CWE-?", owasp="—",
        cvss="no estimate",
        remediation="Informational: portproxy forwards into WSL guests; "
                    "audit the guest side separately.")),
]


def lookup(title: str) -> dict:
    """Prefix-match the title against the KB; defaults when nothing hits."""
    for prefix, info in KB:
        if title.startswith(prefix):
            return info
    return {"cwe": "CWE-?", "owasp": "—",
            "cvss": "no estimate",
            "remediation": "Manual review advised."}


def enrich(finding) -> None:
    """Fill empty cwe/owasp/cvss/remediation fields on a Finding."""
    info = lookup(finding.title)
    for k, v in info.items():
        if not getattr(finding, k, None):
            setattr(finding, k, v)

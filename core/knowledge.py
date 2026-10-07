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
    ("SSRF (confirmed via OOB)", dict(
        cwe="CWE-918", owasp="A10:2021 – SSRF",
        cvss="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H (9.8)",
        remediation="Proven server-side fetch: allowlist the parameter, block "
                    "internal/metadata egress, never mirror fetched content.")),
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

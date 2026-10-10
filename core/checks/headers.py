"""Header/policy checks: security headers, CORS, HTTP methods,
host/cache surfaces, security.txt and CSRF posture."""
from __future__ import annotations

import re
from urllib.parse import urlparse, urlunparse

from core.checks._shared import EVIL_HOST, EVIL_ORIGIN, _same_host
from core.colors import warn
from core.diff import looks_authenticated
from core.net import ScanBudgetExceeded, pace
from core.registry import check as register_check
from core.scanner import Finding, _get, _raw_reflected

REQUIRED_HEADERS = [
    "Content-Security-Policy",
    "Strict-Transport-Security",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Permissions-Policy",
]
# ---------- 1. security headers ----------

@register_check("security-headers", "Missing/weak security headers (passive)", order=11)
def test_security_headers(headers: dict, base: str,
                           verbose: bool = False) -> list[Finding]:
    """No requests: reads the base-page headers the scan already fetched."""
    out: list[Finding] = []
    for h in REQUIRED_HEADERS:
        if h not in (headers or {}):
            out.append(Finding(
                title=f"Missing Security Header: {h}", severity="LOW",
                url=base + "/",
                detail=f"Response lacks {h}; browsers lose a protection layer",
                evidence=h,
                confidence="High",
            ))
            if verbose:
                print(warn(f"    [!] Header missing: {h}"))
    out += _audit_csp(headers or {}, base, verbose)
    out += _audit_hsts(headers or {}, base, verbose)
    return out


def _header_ci(headers: dict, name: str) -> str:
    """Case-insensitive header lookup (HTTP/2 loves lowercase)."""
    low = name.lower()
    for k, v in (headers or {}).items():
        if str(k).lower() == low:
            return str(v or "")
    return ""


def parse_csp(value: str) -> dict[str, list[str]]:
    """Parse CSP directives without dropping modern tokens."""
    out: dict[str, list[str]] = {}
    for part in (value or "").split(";"):
        bits = part.strip().split()
        if bits:
            out.setdefault(bits[0].lower(), []).extend(
                token.lower() for token in bits[1:])
    return out


def _audit_csp(headers: dict, base: str, verbose: bool = False) -> list[Finding]:
    """A present-but-toothless CSP is worse than none: it looks protected
    while waving injections through. unsafe-inline kills XSS defense."""
    out: list[Finding] = []
    csp = _header_ci(headers, "Content-Security-Policy")
    if not csp:
        return out  # missing-header finding already covers it
    parsed = parse_csp(csp)
    directives = {name: " ".join(values)
                  for name, values in parsed.items()}
    script = directives.get("script-src", directives.get("default-src", ""))
    script_attr = directives.get("script-src-attr", "")
    if "'unsafe-inline'" in script:
        out.append(Finding(
            title="Weak CSP (unsafe-inline)", severity="MEDIUM",
            url=base + "/",
            detail="script-src allows 'unsafe-inline': any injected inline "
                   "script executes, CSP gives no XSS containment",
            evidence="unsafe-inline",
            confidence="High",
        ))
        if verbose:
            print(warn("    [!] CSP allows unsafe-inline"))
    if "'unsafe-eval'" in script:
        out.append(Finding(
            title="Weak CSP (unsafe-eval)", severity="MEDIUM",
            url=base + "/",
            detail="script-src allows 'unsafe-eval': string-to-code execution "
                   "stays available to injected scripts",
            evidence="unsafe-eval",
            confidence="High",
        ))
        if verbose:
            print(warn("    [!] CSP allows unsafe-eval"))
    wild = [w for w in ("*", "http:", "https:", "data:") if w in script.split()]
    if wild:
        out.append(Finding(
            title="Weak CSP (wildcard sources)", severity="MEDIUM",
            url=base + "/",
            detail=f"script-src trusts broad sources ({', '.join(wild)}); "
                   "attacker-hosted scripts may load",
            evidence=",".join(wild),
            confidence="High",
        ))
        if verbose:
            print(warn("    [!] CSP wildcard sources"))
    if "'unsafe-inline'" in script_attr:
        out.append(Finding(
            title="Weak CSP (unsafe-inline script attributes)", severity="MEDIUM",
            url=base + "/",
            detail="script-src-attr allows 'unsafe-inline'; event-handler "
                   "injection is not contained by CSP",
            evidence="script-src-attr 'unsafe-inline'",
            confidence="High",
        ))
        if verbose:
            print(warn("    [!] CSP allows inline script attributes"))
    tt = parsed.get("trusted-types", [])
    require_tt = "'script'" in parsed.get("require-trusted-types-for", [])
    if "*" in tt:
        out.append(Finding(
            title="Weak Trusted Types policy (wildcard)", severity="MEDIUM",
            url=base + "/",
            detail="trusted-types * permits arbitrary policy names; enforce a "
                   "small named policy allowlist",
            evidence="trusted-types *",
            confidence="High",
        ))
    elif require_tt and not tt:
        out.append(Finding(
            title="Trusted Types enforcement (policy not declared)", severity="INFO",
            url=base + "/",
            detail="require-trusted-types-for 'script' is active without a "
                   "trusted-types allowlist; policy creation remains an app concern",
            evidence="require-trusted-types-for 'script'",
            confidence="High",
        ))
    strict = "'strict-dynamic'" in script
    nonce_or_hash = any(token.startswith("'nonce-") or
                        token.startswith("'sha256-") or
                        token.startswith("'sha384-") or
                        token.startswith("'sha512-") for token in script.split())
    if strict and not nonce_or_hash:
        out.append(Finding(
            title="Weak CSP (strict-dynamic without nonce/hash)", severity="LOW",
            url=base + "/",
            detail="strict-dynamic has no nonce/hash root trust anchor; modern "
                   "browsers may ignore the intended script trust chain",
            evidence="strict-dynamic",
            confidence="Medium",
        ))
    return out


def _audit_hsts(headers: dict, base: str, verbose: bool = False) -> list[Finding]:
    """HSTS with a short max-age barely protects; note it once."""
    out: list[Finding] = []
    hsts = _header_ci(headers, "Strict-Transport-Security")
    if not hsts:
        return out  # missing-header finding already covers it
    m = re.search(r"max-age\s*=\s*(\d+)", hsts, re.I)
    if m and int(m.group(1)) < 31536000:
        out.append(Finding(
            title="Weak HSTS (short max-age)", severity="LOW",
            url=base + "/",
            detail=f"max-age={m.group(1)} is under a year; short-lived "
                   "protection against sslstrip-style downgrades",
            evidence=m.group(0),
            confidence="High",
        ))
        if verbose:
            print(warn("    [!] HSTS short max-age"))
    return out


# ---------- 4. CORS ----------

@register_check("cors", "Permissive CORS policy (evil origin probe)", order=11)
def test_cors(session, base: str, timeout: int,
              verbose: bool = False) -> list[Finding]:
    """One request with a fake Origin. Reflecting it back is the bug."""
    pace()
    try:
        r = session.get(base + "/", timeout=timeout,
                        headers={"Origin": EVIL_ORIGIN})
    except ScanBudgetExceeded:
        raise
    except Exception:
        return []
    try:
        headers = r.headers or {}
    except Exception:
        return []
    acao = headers.get("Access-Control-Allow-Origin", "")
    acac = headers.get("Access-Control-Allow-Credentials", "")
    if EVIL_HOST in acao:
        detail = f"Site trusts {acao}"
        if str(acac).lower() == "true":
            detail += " WITH credentials — session riding possible"
        if verbose:
            print(warn(f"    [!] CORS reflects evil origin: {base}/"))
        return [Finding(
            title="Permissive CORS (origin reflected)", severity="MEDIUM",
            url=base + "/",
            detail=detail,
            evidence=acao[:120],
            confidence="High",
        )]
    if acao.strip() == "*":
        if verbose:
            print(warn(f"    [!] CORS wildcard: {base}/"))
        return [Finding(
            title="Permissive CORS (wildcard)", severity="LOW",
            url=base + "/",
            detail="Access-Control-Allow-Origin: * exposes responses cross-origin",
            evidence="*",
            confidence="High",
        )]
    # null origin: browsers really send "null" (sandboxed iframes, data:
    # URLs, redirects) — trusting it is a classic CORS bug.
    pace()
    try:
        rn = session.get(base + "/", timeout=timeout,
                         headers={"Origin": "null"})
    except ScanBudgetExceeded:
        raise
    except Exception:
        rn = None
    try:
        nheaders = rn.headers or {} if rn else {}
    except Exception:
        nheaders = {}
    if nheaders.get("Access-Control-Allow-Origin", "").strip().lower() == "null":
        if verbose:
            print(warn(f"    [!] CORS trusts null origin: {base}/"))
        return [Finding(
            title="Permissive CORS (null origin trusted)", severity="MEDIUM",
            url=base + "/",
            detail="Access-Control-Allow-Origin echoes 'null'; sandboxed "
                   "contexts can read responses cross-origin",
            evidence="null",
            confidence="High",
        )]
    # preflight: does the server bless arbitrary methods for evil origins?
    pace()
    try:
        r = session.options(base + "/", timeout=timeout,
                            headers={"Origin": EVIL_ORIGIN,
                                     "Access-Control-Request-Method": "PUT"})
    except ScanBudgetExceeded:
        raise
    except Exception:
        return []
    try:
        headers = r.headers or {}
    except Exception:
        return []
    if EVIL_HOST in headers.get("Access-Control-Allow-Origin", ""):
        allowed = headers.get("Access-Control-Allow-Methods", "")
        if "PUT" in allowed.upper():
            if verbose:
                print(warn(f"    [!] CORS preflight blesses PUT: {base}/"))
            return [Finding(
                title="Permissive CORS (methods reflected)", severity="MEDIUM",
                url=base + "/",
                detail="Preflight reflects the evil origin and blesses PUT; "
                       "cross-site writes may be possible",
                evidence=allowed[:120],
                confidence="High",
            )]
    return []


# ---------- 5. HTTP methods ----------

@register_check("http-methods", "Risky HTTP methods (TRACE/PUT/DELETE)", order=11)
def test_http_methods(session, base: str, timeout: int,
                      verbose: bool = False) -> list[Finding]:
    """OPTIONS tells the truth most of the time. TRACE enables XST probing,
    PUT/DELETE mean the server might accept writes."""
    pace()
    try:
        r = session.options(base + "/", timeout=timeout)
    except ScanBudgetExceeded:
        raise
    except Exception:
        return []
    try:
        allow = (r.headers or {}).get("Allow", "")
    except Exception:
        return []
    methods = {m.strip().upper() for m in allow.split(",") if m.strip()}
    if not methods:
        return []
    out: list[Finding] = []
    notes = {"TRACE": "TRACE enables Cross-Site Tracing probe (XST surface)",
             "PUT": "PUT may allow file writes (verify manually)",
             "DELETE": "DELETE may allow object removal (verify manually)"}
    for m, detail in notes.items():
        if m not in methods:
            continue
        confirmed = ""
        if m == "TRACE":
            # advertised is cheap talk: send one and see it echo back.
            pace()
            try:
                tr = session.request("TRACE", base + "/", timeout=timeout)
                echoed = tr is not None and getattr(tr, "status_code", 0) == 200 \
                    and "TRACE" in (tr.text or "").upper()
            except ScanBudgetExceeded:
                raise
            except Exception:
                echoed = False
            if echoed:
                confirmed = " (live: TRACE echoed)"
                detail = ("TRACE is enabled and echoes requests: "
                          "Cross-Site Tracing works")
        out.append(Finding(
            title=f"Risky HTTP method advertised: {m}", severity="LOW",
            url=base + "/",
            detail=f"OPTIONS advertises {m}: {detail} (advertised only — "
                   "verify it really works before treating this as a vuln)"
            if not confirmed else
            f"OPTIONS advertises {m}{confirmed}: {detail}",
            evidence=allow[:120],
            confidence="High",
        ))
        if verbose:
            print(warn(f"    [!] HTTP method: {m} on {base}/"))
    return out[:3]


# ---------- 9. Host header reflection ----------

CACHE_HINT_HEADERS = ("x-cache", "x-cache-status", "cf-cache-status",
                      "x-served-by", "via", "x-cdn", "cdn-cache",
                      "x-cache-hits")

RESET_HINT = re.compile(r"forgot|reset|recover|remind", re.I)


def _reset_poison_probe(session, base: str, pages: dict | None, timeout: int,
                        verbose: bool, oob) -> list[Finding]:
    """Password reset poisoning: submit a reset flow with an evil Host.

    Uses a random nonexistent address, so no real user gets mail. Without
    OOB this stays silent (a reflection alone was already reported above);
    with OOB a callback proves token theft and reports CRITICAL.
    """
    from urllib.parse import urljoin
    if oob is None:
        return []
    target = None
    for html in list((pages or {}).values())[:6]:
        for m in re.finditer(r'href=["\']([^"\']+)["\']', html or "", re.I):
            if RESET_HINT.search(m.group(1)) and _same_host(
                    urljoin(base + "/", m.group(1)), base):
                target = urljoin(base + "/", m.group(1))
                break
        if target:
            break
    if not target:
        return []
    from core.oob import new_token
    token = new_token()
    evil = f"{token}.{oob.session_domain}"
    try:
        pace()
        r = session.post(target, timeout=timeout,
                         headers={"Host": evil},
                         data={"email": f"gashnouser{token}@example.com"})
    except ScanBudgetExceeded:
        raise
    except Exception:
        return []
    if r is None:
        return []
    oob.pending.append({"kind": "reset", "target": target, "token": token})
    if verbose:
        print(warn(f"    [!] Reset poisoning probe sent: {target}"))
    return []


@register_check("host-header", "Host header reflected (cache-poison surface)", order=11)
def test_host_header(session, base: str, timeout: int,
                     verbose: bool = False, pages: dict | None = None,
                     oob=None) -> list[Finding]:
    """Sends Host: evil-gash.test. A reflection means password-reset links,
    cache keys or analytics can be poisoned downstream. Falls back to
    X-Forwarded-Host (WSTG method), then tries reset-poisoning proof."""
    for header in ({"Host": "evil-gash.test"},
                   {"Host": urlparse(base).hostname or "x",
                    "X-Forwarded-Host": "evil-gash.test"}):
        got = _get(session, base + "/", timeout, headers=header)
        if not got:
            continue
        body = got[1] or ""
        if _raw_reflected(body, "evil-gash"):
            if verbose:
                via = "X-Forwarded-Host" if "X-Forwarded-Host" in header \
                    else "Host"
                print(warn(f"    [!] Host header reflected ({via}): {base}/"))
            out = [Finding(
                title="Host header reflected", severity="LOW",
                url=base + "/",
                detail="The Host header is reflected in the response; check "
                       "password-reset and cache behavior manually",
                evidence="evil-gash",
                confidence="High",
            )]
            out += _reset_poison_probe(session, base, pages, timeout,
                                       verbose, oob)
            return out
    return []


@register_check("cache-poisoning", "Cache poisoning via Host reflection", order=11)
def test_cache_poisoning(session, base: str, timeout: int,
                         verbose: bool = False) -> list[Finding]:
    """Evil Host reflected AND the response looks cached (Age, HIT, CDN).
    A poisoned entry would serve to everyone — but proving it takes a
    victim fetch, so this stays a surface note."""
    pace()
    try:
        r = session.get(base + "/", timeout=timeout,
                        headers={"Host": "evil-gash.test"})
    except ScanBudgetExceeded:
        raise
    except Exception:
        return []
    try:
        body, headers = r.text or "", r.headers or {}
    except Exception:
        return []
    if not _raw_reflected(body, "evil-gash"):
        return []
    low = {str(k).lower(): v for k, v in headers.items()}
    cached = [h for h in CACHE_HINT_HEADERS if h in low]
    try:
        age = int(str(low.get("age", "0")).split(",")[0].strip() or 0)
    except Exception:
        age = 0
    if not cached and age <= 0:
        return []
    return [Finding(
        title="Cache poisoning surface", severity="LOW",
        url=base + "/",
        detail="Evil Host reflects and the response looks cached "
               f"({', '.join(cached) or f'Age: {age}'}); fetch twice to "
               "confirm a stored poisoned entry",
        evidence="evil-gash",
        confidence="Medium",
    )]


# ---------- 9b. cache deception (deep-only, authenticated GET only) ----------

_AUTH_PAGE_HINTS = re.compile(
    r"logout|sign[ -]?out|dashboard|account|profile|settings|private|welcome",
    re.I)
_AUTH_GATE_HINTS = re.compile(
    r"sign[ -]?in|log[ -]?in|login|forgot password|unauthori[sz]ed",
    re.I)
_CACHE_DECEPTION_PATHS = re.compile(
    r"/(?:account|admin|dashboard|profile|settings|private|user|users|me|api)(?:/|$)",
    re.I)


def _has_auth_material(session) -> bool:
    headers = getattr(session, "headers", {}) or {}
    if any(str(k).lower() in {"authorization", "cookie"} and str(v).strip()
           for k, v in headers.items()) if hasattr(headers, "items") else False:
        return True
    try:
        return bool(list(getattr(session, "cookies", None) or []))
    except Exception:
        return False


def _auth_page_body(response) -> bool:
    return looks_authenticated(response, positive=_AUTH_PAGE_HINTS.pattern,
                               negative=_AUTH_GATE_HINTS.pattern)


def _auth_body_text(status: int, body: str) -> bool:
    return 200 <= status < 300 and bool(_AUTH_PAGE_HINTS.search(body)) \
        and not _AUTH_GATE_HINTS.search(body)


def _cache_evidence(response) -> list[str]:
    raw = getattr(response, "headers", {}) or {}
    low = {str(k).lower(): str(v) for k, v in raw.items()}
    hits = []
    cc = low.get("cache-control", "").lower()
    if re.search(r"\bpublic\b|\bs-maxage\s*=\s*\d+|\bmax-age\s*=\s*[1-9]", cc):
        hits.append(f"Cache-Control: {low.get('cache-control', '')[:70]}")
    for name in ("age", "x-cache", "x-cache-status", "cf-cache-status",
                 "cdn-cache-control", "via"):
        if name in low and low[name].strip():
            hits.append(f"{name}: {low[name][:50]}")
    return hits[:3]


def _cache_deception_get(session, url: str, timeout: int):
    try:
        pace()
        return session.get(url, timeout=timeout, allow_redirects=False)
    except ScanBudgetExceeded:
        raise
    except Exception:
        return None


@register_check("cache-deception",
                "Authenticated cache deception via suffix/normalization",
                deep_only=True, order=11, active=True, requires_auth=True,
                max_requests=6)
def test_cache_deception(session, base: str, pages: dict, timeout: int,
                         verbose: bool = False) -> list[Finding]:
    """GET-only check. It requires authenticated-looking content in both the
    clean and suffixed path plus an explicit cache signal; status alone is
    deliberately insufficient."""
    if not _has_auth_material(session):
        return []
    targets: list[str] = []
    for url, html in list((pages or {}).items())[:8]:
        parsed = urlparse(str(url))
        if parsed.scheme not in ("http", "https") or not _same_host(str(url), base):
            continue
        if _CACHE_DECEPTION_PATHS.search(parsed.path or "/") \
                or _auth_body_text(200, html or ""):
            targets.append(str(url))
    if not targets:
        targets = [base.rstrip("/") + "/"]
    for target in targets[:3]:
        original = _cache_deception_get(session, target, timeout)
        if not _auth_page_body(original):
            continue
        p = urlparse(target)
        path = (p.path or "/").rstrip("/") or "/"
        probes = [path + "/gash-cache.css", path + ".css",
                  path + "//gash-cache.css"]
        for probe_path in probes:
            probe = urlunparse((p.scheme, p.netloc, probe_path, "", "", ""))
            response = _cache_deception_get(session, probe, timeout)
            cache = _cache_evidence(response) if response else []
            if not cache or not _auth_page_body(response):
                continue
            marker = next((m.group(0).lower() for m in
                           _AUTH_PAGE_HINTS.finditer(
                               str(getattr(response, "text", "") or ""))),
                          "protected-content")
            out = [Finding(
                title="Authenticated cache deception",
                severity="MEDIUM", url=probe,
                detail="A suffix/normalization variant returned authenticated-"
                       "looking content while response headers advertised a "
                       f"cacheable or cached response ({'; '.join(cache)}).",
                evidence=f"{cache[0]}; marker={marker}", confidence="High",
                method="GET", location="path", param="path",
                auth_context="user", confirm="auth-content+cache-header")]
            if verbose:
                print(warn(f"    [!] Cache deception evidence: {probe}"))
            return out
    return []


# ---------- 10. security.txt ----------

@register_check("security-txt", "security.txt presence (RFC 9116)", order=11)
def test_security_txt(session, base: str, timeout: int,
                      verbose: bool = False) -> list[Finding]:
    """Best practice, not a vulnerability: a missing security.txt just
    means researchers can't find where to report."""
    got = _get(session, base + "/.well-known/security.txt", timeout)
    if got and got[0] == 200 and "contact" in (got[1] or "").lower():
        return []
    return [Finding(
        title="security.txt missing", severity="INFO",
        url=base + "/.well-known/security.txt",
        detail="No RFC 9116 security.txt; add one with a Contact field",
        evidence="404/missing",
        confidence="High",
    )]


# ---------- 13. CSRF surface ----------

def _session_cookie_exposed(session) -> bool:
    """True when a session-looking cookie lacks SameSite=Lax/Strict and no
    dedicated anti-CSRF cookie exists. A Lax tracking cookie does NOT make
    a SameSite=None session safe — only the session cookie itself counts."""
    try:
        jar = getattr(session, "cookies", None)
        cookies = list(jar) if jar else []
    except Exception:
        return False  # can't tell, don't claim
    if not cookies:
        return False
    names = [getattr(c, "name", "") or "" for c in cookies]
    if any(re.search(r"csrf|xsrf|authenticity", n, re.I) for n in names):
        return False  # framework CSRF cookie present, likely protected
    for c in cookies:
        name = getattr(c, "name", "") or ""
        if not SESSION_COOKIE_RE.search(name):
            continue
        try:
            rest = {k.lower(): v for k, v in
                    (getattr(c, "_rest", None) or {}).items()}
        except Exception:
            continue
        if str(rest.get("samesite", "")).lower() not in ("lax", "strict"):
            return True
    return False


TOKEN_NAME_RE = re.compile(r"token|csrf|nonce|authenticity|xsrf", re.I)
SESSION_COOKIE_RE = re.compile(
    r"session|sess|auth|jwt|sid|phpsessid|jsessionid|aspsession|"
    r"laravel_session|remember", re.I)


@register_check("csrf-surface", "POST forms without anti-CSRF controls", order=11)
def test_csrf_surface(session, pages: dict, base: str, timeout: int,
                      verbose: bool = False) -> list[Finding]:
    """A POST form with no token-like hidden field, on a session whose own
    cookie lacks SameSite, is rideable cross-site. No requests at all."""
    from core.advanced import _forms
    if not _session_cookie_exposed(session):
        return []
    out: list[Finding] = []
    for purl, html in list((pages or {}).items())[:6]:
        try:
            forms = _forms(html, purl.rsplit("/", 1)[0] if "/" in purl else base)
        except Exception:
            continue
        for f in forms:
            if f.get("method") != "POST":
                continue
            fields = f.get("fields", {})
            # a hidden field is only evidence when it LOOKS like a token:
            # <input type=hidden name=user_id> protects nothing.
            if any(t == "hidden" and TOKEN_NAME_RE.search(n or "")
                   for n, t in fields.items()):
                continue
            out.append(Finding(
                title="Missing anti-CSRF controls", severity="LOW",
                url=f.get("action", ""),
                detail="POST form has no hidden token field and session cookies "
                       "lack SameSite=Lax/Strict",
                evidence="no-token",
                confidence="Medium",
            ))
            if verbose:
                print(warn(f"    [!] CSRF surface: {f.get('action')}"))
            if len(out) >= 3:
                return out
    return out

__all__ = [
    "REQUIRED_HEADERS",
    "test_security_headers",
    "_header_ci",
    "_audit_csp",
    "_audit_hsts",
    "test_cors",
    "test_http_methods",
    "CACHE_HINT_HEADERS",
    "RESET_HINT",
    "_reset_poison_probe",
    "test_host_header",
    "test_cache_poisoning",
    "test_security_txt",
    "_session_cookie_exposed",
    "TOKEN_NAME_RE",
    "SESSION_COOKIE_RE",
    "test_csrf_surface",
]

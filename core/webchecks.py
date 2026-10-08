"""Modern web misconfiguration checks — the stuff AI-built sites ship with.

All low-risk: passive header reads, single GET probes, benign content.
Nothing here writes state or runs code on the target.
"""

from __future__ import annotations

import re
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

from core.colors import warn
from core.net import ScanBudgetExceeded, pace
from core.registry import check as register_check
from core.scanner import Finding, _get, _inject, _post, _post_form_targets, _raw_reflected

EVIL_ORIGIN = "https://evil-gash.test"
EVIL_HOST = "evil-gash.test"

REQUIRED_HEADERS = [
    "Content-Security-Policy",
    "Strict-Transport-Security",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Permissions-Policy",
]

REDIRECT_KEYS = {"next", "redirect", "return", "url", "u", "dest",
                 "destination", "continue", "ref", "target", "r",
                 "redirect_uri", "redirect_url", "return_url", "continue_url",
                 "callback", "callback_url", "forward", "goto", "to", "next_url"}

TRAVERSAL_KEYS = {"file", "path", "page", "include", "template", "dir",
                  "folder", "doc", "document", "filename", "pg"}
TRAVERSAL_SETS = [
    (["../../../../etc/passwd", "....//....//etc/passwd"], ["root:x:0:0"]),
    (["..\\..\\windows\\win.ini", "..//..//windows//win.ini"], ["[fonts]"]),
]
TRAVERSAL_CONFIRM = ("../../../../etc/hosts", "localhost")

SECRET_RES = [
    # (kind, pattern, severity, why-this-level)
    ("AWS access key", re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
     "CRITICAL", "account-level credential"),
    ("Stripe live key", re.compile(r"\bsk-live-[0-9A-Za-z]{16,}\b"),
     "CRITICAL", "live money-moving key"),
    ("Slack token", re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,}\b"),
     "CRITICAL", "workspace credential"),
    ("GitHub token", re.compile(r"\bghp_[A-Za-z0-9]{20,}\b"),
     "CRITICAL", "account/repo credential"),
    ("OpenAI key", re.compile(r"\bsk-[A-Za-z0-9]{20,}\b"),
     "CRITICAL", "billable API credential"),
    ("Anthropic key", re.compile(r"\bsk-ant-[A-Za-z0-9_-]{20,}\b"),
     "CRITICAL", "billable API credential"),
    ("Google API key", re.compile(r"\bAIza[0-9A-Za-z_-]{30,}\b"),
     "MEDIUM", "impact depends on Cloud Console API restrictions — verify"),
    ("Private key", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
     "CRITICAL", "raw private key material"),
]
PLACEHOLDER_HINT = re.compile(
    r"example|test|xxx+|your[_-]?key|1234|abcd|placeholder|dummy|sample", re.I)


def _same_host(url: str, base: str) -> bool:
    try:
        return urlparse(url).hostname == urlparse(base).hostname
    except Exception:
        return False


def _mask(secret: str) -> str:
    """Never put a full secret in a report: AKIA...12 style."""
    s = secret.strip()
    if len(s) <= 8:
        return s[:2] + "..."
    return s[:4] + "..." + s[-2:]


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


def _audit_csp(headers: dict, base: str, verbose: bool = False) -> list[Finding]:
    """A present-but-toothless CSP is worse than none: it looks protected
    while waving injections through. unsafe-inline kills XSS defense."""
    out: list[Finding] = []
    csp = _header_ci(headers, "Content-Security-Policy")
    if not csp:
        return out  # missing-header finding already covers it
    directives: dict[str, str] = {}
    for part in csp.split(";"):
        part = part.strip()
        if not part:
            continue
        name, _, value = part.partition(" ")
        directives[name.strip().lower()] = value.strip().lower()
    script = directives.get("script-src", directives.get("default-src", ""))
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


# ---------- 2. open redirect ----------

def _get_no_redirect(session, url: str, timeout: int, **kw):
    pace()
    try:
        return session.get(url, timeout=timeout, allow_redirects=False, **kw)
    except Exception:
        return None


@register_check("open-redirect", "Open redirect via next/redirect params", order=11)
def test_open_redirect(session, urls: list[str], timeout: int,
                       verbose: bool = False, threads: int = 10) -> list[Finding]:
    from concurrent.futures import ThreadPoolExecutor
    out: list[Finding] = []

    def _probe(u: str) -> Finding | None:
        try:
            q = parse_qs(urlparse(u).query, keep_blank_values=True)
        except Exception:
            return None
        keys = [k for k in q if k.lower() in REDIRECT_KEYS]
        for key in keys[:2]:
            p = urlparse(u)
            inj = urlunparse((p.scheme, p.netloc, p.path, p.params,
                              urlencode({**{k: v[0] for k, v in q.items()},
                                         key: EVIL_ORIGIN}), p.fragment))
            r = _get_no_redirect(session, inj, timeout)
            if not r:
                continue
            loc = ""
            try:
                loc = (r.headers or {}).get("Location", "")
            except Exception:
                loc = ""
            if r.status_code in (301, 302, 303, 307, 308) and EVIL_HOST in loc:
                if verbose:
                    print(warn(f"    [!] Open redirect: {inj}"))
                return Finding(
                    title="Possible Open Redirect", severity="MEDIUM",
                    url=inj,
                    detail=f"?{key} redirects off-site to an attacker URL (302 -> {loc[:80]})",
                    evidence=loc[:120],
                    confidence="High",
                )
            low_loc = loc.lower()
            if r.status_code in (301, 302, 303, 307, 308) and (
                    low_loc.startswith("javascript:") or low_loc.startswith("data:")):
                if verbose:
                    print(warn(f"    [!] Dangerous redirect scheme: {inj}"))
                return Finding(
                    title="Possible Open Redirect", severity="MEDIUM",
                    url=inj,
                    detail=f"?{key} redirects to an active scheme "
                           f"({low_loc.split(':')[0]}:); script execution on click",
                    evidence=loc[:120],
                    confidence="High",
                )
            try:
                body = r.text or ""
            except Exception:
                body = ""
            if r.status_code == 200 and re.search(
                    r"url\s*=\s*['\"]?https?://" + re.escape(EVIL_HOST),
                    body, re.I):
                if verbose:
                    print(warn(f"    [!] Open redirect (meta): {inj}"))
                return Finding(
                    title="Possible Open Redirect", severity="MEDIUM",
                    url=inj,
                    detail=f"?{key} lands on an attacker URL via meta refresh",
                    evidence="meta refresh",
                    confidence="Medium",
                )
            # no redirect taken, but the evil host echoes in the page: a
            # window.location / link sink waiting to happen. Surface only.
            if r.status_code == 200 and EVIL_HOST in body:
                if verbose:
                    print(warn(f"    [!] Redirect target reflected: {inj}"))
                return Finding(
                    title="Reflected redirect target", severity="LOW",
                    url=inj,
                    detail=f"?{key} value is reflected in the page; check JS "
                           "sinks (location, open) manually",
                    evidence=EVIL_HOST,
                    confidence="Low",
                )
        return None

    targets = urls[:8]
    with ThreadPoolExecutor(max_workers=max(1, min(threads, len(targets) or 1))) as ex:
        for f in ex.map(_probe, targets):
            if f:
                out.append(f)
    return out


# ---------- 3. path traversal ----------

def _filter_proof(session, p, q, key: str, timeout: int) -> str:
    """php://filter base64 proof: decode the response, look for <?php.

    Stronger than a marker: markers can echo, but a decoded PHP source
    means the file was actually read. Returns the resource name or "".
    """
    import base64
    for resource in ("index.php", "index"):
        inj = urlunparse((p.scheme, p.netloc, p.path, p.params,
                          urlencode({**{k: v[0] for k, v in q.items()},
                                     key: "php://filter/convert.base64-encode/resource=" + resource}),
                          p.fragment))
        got = _get(session, inj, timeout)
        if not got:
            continue
        m = re.search(r"[A-Za-z0-9+/]{200,}={0,2}", got[1] or "")
        if not m:
            continue
        try:
            decoded = base64.b64decode(m.group(0)).decode("utf-8", "ignore")
        except Exception:
            continue
        if "<?php" in decoded:
            return resource
    return ""


@register_check("path-traversal", "Path traversal via file/page params", order=11)
def test_path_traversal(session, urls: list[str], timeout: int,
                        verbose: bool = False, threads: int = 10) -> list[Finding]:
    from concurrent.futures import ThreadPoolExecutor
    out: list[Finding] = []

    def _probe(u: str) -> Finding | None:
        try:
            q = parse_qs(urlparse(u).query, keep_blank_values=True)
        except Exception:
            return None
        keys = [k for k in q if k.lower() in TRAVERSAL_KEYS]
        if not keys:
            return None
        base_got = _get(session, u, timeout)
        base_low = ((base_got[1] if base_got else "") or "").lower()
        all_markers = [m for _, ms in TRAVERSAL_SETS for m in ms]
        all_markers.append(TRAVERSAL_CONFIRM[1])
        base_has_marker = any(m.lower() in base_low for m in all_markers)
        for key in keys[:2]:
            for payloads, markers in TRAVERSAL_SETS:
                for payload in payloads:
                    p = urlparse(u)
                    inj = urlunparse((p.scheme, p.netloc, p.path, p.params,
                                      urlencode({**{k: v[0] for k, v in q.items()},
                                                 key: payload}), p.fragment))
                    got = _get(session, inj, timeout)
                    if not got:
                        continue
                    body = got[1] or ""
                    hit = next((m for m in markers if m in body), None)
                    if not (hit and not base_has_marker):
                        continue
                    proven = _filter_proof(session, p, q, key, timeout)
                    if proven:
                        if verbose:
                            print(warn(f"    [!] Path traversal (filter proof): {inj}"))
                        return Finding(
                            title="Possible Path Traversal", severity="MEDIUM",
                            url=inj,
                            detail=f"?{key} reads source via php://filter "
                                   f"(decoded <?php from {proven})",
                            evidence=hit,
                            confidence="High",
                        )
                    # confirm with a second, different file — one marker
                    # could be a coincidence, two independent files is not.
                    cfile, cmarker = TRAVERSAL_CONFIRM
                    confirm = _get(session, urlunparse(
                        (p.scheme, p.netloc, p.path, p.params,
                         urlencode({**{k: v[0] for k, v in q.items()},
                                    key: cfile}),
                         p.fragment)), timeout)
                    if not (confirm and cmarker in (confirm[1] or "")):
                        continue
                    if verbose:
                        print(warn(f"    [!] Path traversal (confirmed x2): {inj}"))
                    return Finding(
                        title="Possible Path Traversal", severity="MEDIUM",
                        url=inj,
                        detail=f"?{key} reads system files "
                               f"('{hit}' + {cfile} confirmed)",
                        evidence=hit,
                        confidence="High",
                    )
        return None

    targets = urls[:8]
    with ThreadPoolExecutor(max_workers=max(1, min(threads, len(targets) or 1))) as ex:
        for f in ex.map(_probe, targets):
            if f:
                out.append(f)
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


# ---------- 7. JWT alg:none (passive) ----------

JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]*(?![A-Za-z0-9_-])")


def _jwt_alg(token: str) -> str | None:
    """Decode a JWT header without verifying. Returns alg or None."""
    try:
        import base64
        import json as _json
        seg = token.split(".")[0]
        seg += "=" * (-len(seg) % 4)
        return _json.loads(base64.urlsafe_b64decode(seg).decode(
            "utf-8", "ignore")).get("alg")
    except Exception:
        return None


@register_check("jwt-none", "JWTs using alg:none (passive)", order=11)
def test_jwt_none(pages: dict, verbose: bool = False) -> list[Finding]:
    """Collectors mint these, attackers love them: a token that claims
    alg:none is one server mistake away from full auth bypass. Passive
    sighting only — acceptance is tested by replay, not assumed."""
    out: list[Finding] = []
    for html in list((pages or {}).values())[:4]:
        for m in JWT_RE.finditer(html or ""):
            if _jwt_alg(m.group(0)) == "none":
                out.append(Finding(
                    title="JWT using alg:none observed", severity="LOW",
                    url="",
                    detail="A JWT with alg:none was seen in page content. "
                           "It becomes CRITICAL only if the backend accepts "
                           "it (replay a doctored token to confirm)",
                    evidence="alg:none",
                    confidence="Low",
                ))
                if verbose:
                    print(warn("    [!] JWT alg:none in page content"))
                break
        if out:
            break
    return out[:2]


# ---------- 8. GraphQL introspection ----------

GRAPHQL_PATHS = ["/graphql", "/api/graphql", "/v1/graphql",
                 "/query", "/gql"]


@register_check("graphql-introspection", "GraphQL introspection + schema analysis", order=11)
def test_graphql_introspection(session, base: str, pages: dict, timeout: int,
                               verbose: bool = False,
                               session_b=None) -> list[Finding]:
    """Asks for __schema once per endpoint, then reads the schema like an
    attacker: mutation surface (mapped, never executed), sensitive-field
    exposure probes (read-only, capped) and nested object authorization
    with a second session. GET ?query= fallback when POST is closed."""
    from urllib.parse import urljoin
    from core.graphql import (parse_schema, sensitive_queries,
                              build_selection, build_by_id_query,
                              send_query, response_data,
                              has_sensitive_data)
    from core.authz import same_object
    cands = [base.rstrip("/") + p for p in GRAPHQL_PATHS]
    try:
        for html in (pages or {}).values():
            for m in re.finditer(r'href=["\']([^"\']*graphql[^"\']*)["\']',
                                 html or "", re.I):
                full = urljoin(base + "/", m.group(1))
                if _same_host(full, base) and full not in cands:
                    cands.append(full)
    except Exception:
        pass
    out: list[Finding] = []
    endpoint, schema = "", {}
    for url in cands[:4]:
        try:
            pace()
            r = session.post(url, timeout=timeout,
                             json={"query": "{__schema{queryType{name}}}"})
        except ScanBudgetExceeded:
            raise
        except Exception:
            continue
        try:
            body = r.text or ""
            ok = r.status_code == 200 and "__schema" in body
        except Exception:
            continue
        if ok:
            endpoint = url
            out.append(Finding(
                title="GraphQL introspection enabled", severity="LOW",
                url=url,
                detail="Introspection query returned schema data; "
                       "disable it in production",
                evidence="__schema",
                confidence="High",
            ))
            if verbose:
                print(warn(f"    [!] GraphQL introspection: {url}"))
            try:
                import json as _json
                schema = _json.loads(body).get("data", {}).get(
                    "__schema", {}) or {}
                schema = {"__schema": schema}
            except Exception:
                schema = {}
            break
    if not endpoint:
        # POST closed but GET query= open is the same bug over GET.
        for url in cands[:2]:
            got = _get(session, url + "?query={__typename}", timeout)
            if got and got[0] == 200 and "__Schema" in (got[1] or ""):
                return [Finding(
                    title="GraphQL introspection enabled", severity="LOW",
                    url=url,
                    detail="Introspection answers over GET ?query=; "
                           "disable it in production",
                    evidence="__typename",
                    confidence="High",
                )]
        return out
    try:
        parsed = parse_schema(schema)
    except Exception:
        return out
    muts = parsed.get("mutations", [])
    if muts:
        names = ", ".join(m.get("name", "") for m in muts[:5])
        out.append(Finding(
            title="GraphQL mutations exposed", severity="INFO",
            url=endpoint,
            detail=f"Schema lists {len(muts)} mutation(s) ({names}); mapped "
                   "only, never executed — review their input validation "
                   "and auth manually",
            evidence=names[:120],
            confidence="High",
        ))
        if verbose:
            print(warn(f"    [!] GraphQL mutations: {names[:60]}"))
    for q in sensitive_queries(parsed)[:2]:
        sel = build_selection(parsed, q)
        if not sel:
            continue
        r = send_query(session, endpoint, timeout, sel)
        if not r:
            continue
        data = response_data(r)
        hit = has_sensitive_data(data or {})
        if data and hit:
            out.append(Finding(
                title="Exposed sensitive GraphQL field", severity="MEDIUM",
                url=endpoint,
                detail=f"Read-only query '{sel[:60]}' returns '{hit}' "
                       "without visible auth; verify field-level auth",
                evidence=hit[:80],
                confidence="Medium",
            ))
            if verbose:
                print(warn(f"    [!] GraphQL exposure: {hit}"))
            break
    if session_b is not None:
        for q in parsed.get("queries", [])[:4]:
            sel = build_by_id_query(parsed, q, "1")
            if not sel:
                continue
            r1 = send_query(session, endpoint, timeout, sel)
            d1 = response_data(r1) if r1 else None
            if not d1:
                continue
            try:
                pace()
                rb = session_b.post(endpoint, timeout=timeout,
                                    json={"query": sel})
                db = response_data(rb)
            except ScanBudgetExceeded:
                raise
            except Exception:
                continue
            if db and same_object(_dump(d1), _dump(db)):
                out.append(Finding(
                    title="Confirmed IDOR / BOLA (cross-session)",
                    severity="CRITICAL",
                    url=endpoint,
                    detail=f"GraphQL object '{q.get('name')}' (canonical "
                           "content match) readable by a second user; "
                           "object auth is missing",
                    evidence=q.get("name", "")[:60],
                    confidence="High",
                    method="POST", param=q.get("name", "")[:60],
                    location="body", auth_context="user-b",
                    confirm="cross-session",))
                if verbose:
                    print(warn(f"    [!] GraphQL IDOR: {q.get('name')}"))
                break
    return out[:5]


def _dump(data: dict) -> str:
    """Canonical JSON dump for cross-session object comparison."""
    try:
        import json as _json
        return _json.dumps(data, sort_keys=True)
    except Exception:
        return ""


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


# ---------- 6. JS secrets ----------

@register_check("js-secrets", "Hardcoded secrets in JavaScript", order=11)
def test_js_secrets(session, base: str, pages: dict, timeout: int,
                    verbose: bool = False) -> list[Finding]:
    """AI-built frontends love shipping live keys. Scans inline scripts on
    every crawled page plus up to 5 same-host .js files (200KB cap each).
    Placeholders are skipped, real secrets are masked in the report."""
    from urllib.parse import urljoin
    texts: list[str] = []
    for html in list((pages or {}).values()):
        for m in re.finditer(
                r"<script(?![^>]*src=)[^>]*>(.*?)</script>",
                html or "", re.I | re.S):
            chunk = m.group(1) or ""
            if chunk.strip():
                texts.append(chunk[:200_000])
            if len(texts) >= 12:
                break
        if len(texts) >= 12:
            break
    try:
        srcs = []
        for html in list((pages or {}).values()):
            for m in re.findall(r'<script[^>]*src=["\']([^"\']+)["\']',
                                html or "", re.I):
                if m not in srcs:
                    srcs.append(m)
    except Exception:
        srcs = []
    fetched = 0
    for src in srcs:
        if fetched >= 5:
            break
        full = urljoin(base + "/", src)
        if not _same_host(full, base):
            continue
        fetched += 1
        got = _get(session, full, timeout)
        if not got or len(got[1] or "") > 200_000:
            continue
        texts.append(got[1])
    out: list[Finding] = []
    for kind, rx, severity, note in SECRET_RES:
        for m in rx.finditer("\n".join(texts)):
            secret = m.group(0)
            if PLACEHOLDER_HINT.search(secret):
                continue
            out.append(Finding(
                title=f"Exposed secret in JavaScript ({kind})",
                severity=severity,
                url=base + "/",
                detail=f"Hardcoded {kind} found in frontend code "
                       f"(any visitor can read it; {note})",
                evidence=_mask(secret),
                confidence="High",
            ))
            if verbose:
                print(warn(f"    [!] JS secret ({kind}): {base}/"))
            break  # one finding per secret kind is enough
        if len(out) >= 3:
            break
    return out[:3]


# ---------- 11. OS command injection ----------

OS_CMD_PAYLOADS = [";id", "|id", "&&id", "$(id)",
                   ";ver", "|ver", "&&ver"]
OS_CMD_RES = [
    re.compile(r"uid=\d+\("),      # Unix id output
    re.compile(r"Microsoft Windows"),  # Windows ver output
]


@register_check("os-command-injection", "OS command injection via ;id/|id", order=11)
def test_os_command_injection(session, urls: list[str], timeout: int,
                              verbose: bool = False,
                              threads: int = 10, pages: dict | None = None,
                              base: str = "", deep: bool = True) -> list[Finding]:
    """Same shape as error-based SQLi: break out, run `id`, look for uid=."""
    from concurrent.futures import ThreadPoolExecutor
    out: list[Finding] = []

    def _probe(u: str) -> Finding | None:
        base_got = _get(session, u, timeout)
        base_body = base_got[1] if base_got else ""
        if base_body and any(rx.search(base_body) for rx in OS_CMD_RES):
            return None  # baseline already matches, would be noise
        for cmd in OS_CMD_PAYLOADS:
            inj = _inject(u, cmd)
            got = _get(session, inj, timeout)
            if not got:
                continue
            body = got[1] or ""
            hit = next((m for rx in OS_CMD_RES if (m := rx.search(body))), None)
            if hit:
                if verbose:
                    print(warn(f"    [!] OS command injection: {inj}"))
                return Finding(
                    title="Possible OS Command Injection", severity="CRITICAL",
                    url=inj,
                    detail=f"Command output marker returned: '{hit.group(0)[:40]}'",
                    evidence=hit.group(0)[:60],
                    confidence="High",
                )
        return None

    targets = urls[:6]
    with ThreadPoolExecutor(max_workers=max(1, min(threads, len(targets) or 1))) as ex:
        for f in ex.map(_probe, targets):
            if f:
                out.append(f)

    if deep:
        for action, field, filler in _post_form_targets(pages, base):
            rb = _post(session, action, timeout,
                       data={**filler, field: "gash1"})
            if rb and any(rx.search(rb.text or "") for rx in OS_CMD_RES):
                continue
            for cmd in OS_CMD_PAYLOADS:
                r = _post(session, action, timeout,
                          data={**filler, field: "gash1" + cmd})
                if not r:
                    continue
                body = r.text or ""
                hit = next((m for rx in OS_CMD_RES
                            if (m := rx.search(body))), None)
                if hit:
                    if verbose:
                        print(warn(f"    [!] OS command injection (POST {field}): {action}"))
                    out.append(Finding(
                        title="Possible OS Command Injection", severity="CRITICAL",
                        url=action,
                        detail=f"Command output marker returned via POST body: "
                               f"'{hit.group(0)[:40]}'",
                        evidence=hit.group(0)[:60],
                        confidence="High",
                    ))
                    break
            if len(out) >= 6:
                break
    return out


# ---------- 12. CRLF injection ----------

@register_check("crlf-injection", "CRLF header injection probe", order=11)
def test_crlf_injection(session, urls: list[str], timeout: int,
                        verbose: bool = False,
                        threads: int = 10) -> list[Finding]:
    from concurrent.futures import ThreadPoolExecutor
    out: list[Finding] = []

    def _probe(u: str) -> Finding | None:
        try:
            q = parse_qs(urlparse(u).query, keep_blank_values=True)
        except Exception:
            return None
        if not q:
            return None
        key = next(iter(q))
        p = urlparse(u)
        inj = urlunparse((p.scheme, p.netloc, p.path, p.params,
                          f"{key}=gash%0D%0AX-Gash-Probe%3A+1", p.fragment))
        pace()
        try:
            r = session.get(inj, timeout=timeout, allow_redirects=True)
        except ScanBudgetExceeded:
            raise
        except Exception:
            return None
        try:
            headers = r.headers or {}
        except Exception:
            return None
        if "x-gash-probe" in {k.lower() for k in headers}:
            if verbose:
                print(warn(f"    [!] CRLF injection: {inj}"))
            return Finding(
                title="Possible CRLF Injection", severity="MEDIUM",
                url=inj,
                detail=f"?{key} smuggles a response header (X-Gash-Probe reflected)",
                evidence="X-Gash-Probe",
                confidence="High",
            )
        return None

    targets = urls[:8]
    with ThreadPoolExecutor(max_workers=max(1, min(threads, len(targets) or 1))) as ex:
        for f in ex.map(_probe, targets):
            if f:
                out.append(f)
    return out


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


# ---------- 14. Firebase open database ----------

FIREBASE_RE = re.compile(r"https?://([a-z0-9-]+)\.firebaseio\.com", re.I)
FIREBASE_PROJ_RE = re.compile(
    r'''(?:projectId|firebase[_-]?project)["']?\s*[:=]\s*["']([a-z0-9-]+)["']''', re.I)


@register_check("firebase-open", "Public Firebase realtime database", order=11)
def test_firebase_open(session, base: str, pages: dict, timeout: int,
                       verbose: bool = False) -> list[Finding]:
    """Firebase project refs leak in JS. One GET to /.json proves the
    database reads without auth."""
    projects: list[str] = []
    for html in list((pages or {}).values())[:4]:
        body = html or ""
        projects += FIREBASE_RE.findall(body)
        projects += FIREBASE_PROJ_RE.findall(body)
    projects = list(dict.fromkeys(p for p in projects if p))[:3]
    out: list[Finding] = []
    for proj in projects:
        got = _get(session, f"https://{proj}.firebaseio.com/.json", timeout)
        if not got or got[0] != 200:
            continue
        try:
            import json as _json
            data = _json.loads(got[1] or "")
        except Exception:
            continue
        if isinstance(data, (dict, list)) and data:
            out.append(Finding(
                title="Open Firebase database", severity="CRITICAL",
                url=f"https://{proj}.firebaseio.com/.json",
                detail=f"Realtime database of '{proj}' reads without "
                       "authentication",
                evidence=f"{len(data)} top-level keys" if isinstance(
                    data, dict) else f"{len(data)} records",
                confidence="High",
            ))
            if verbose:
                print(warn(f"    [!] Firebase open: {proj}"))
            break
    return out


# ---------- 15. Supabase anon table read ----------

SUPABASE_URL_RE = re.compile(r"https?://([a-z0-9-]+\.supabase\.co)", re.I)
SUPABASE_KEY_RE = re.compile(
    r'''(?:anon|public)[_a-z]*(?:key)?["']?\s*[:=]\s*["'](eyJ[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]*)["']''',
    re.I)
PRIVATE_TABLES = ["profiles", "users", "user_profiles", "customers",
                  "orders", "messages", "payments", "subscriptions",
                  "chats", "api_keys", "secrets", "tokens"]


@register_check("supabase-anon", "Supabase table readable without login", order=11)
def test_supabase_anon(session, base: str, pages: dict, timeout: int,
                       verbose: bool = False) -> list[Finding]:
    """The CVE-2025-48757 pattern: anon key in the bundle, RLS missing on a
    private-smelling table. Only private tables are probed — a public
    products listing is not a finding."""
    hosts: list[str] = []
    keys: list[str] = []
    for html in list((pages or {}).values())[:4]:
        body = html or ""
        hosts += SUPABASE_URL_RE.findall(body)
        keys += SUPABASE_KEY_RE.findall(body)
    hosts = list(dict.fromkeys(hosts))[:2]
    keys = list(dict.fromkeys(keys))[:2]
    if not hosts or not keys:
        return []
    out: list[Finding] = []
    for host in hosts:
        for table in PRIVATE_TABLES:
            got = _get(session,
                       f"https://{host}/rest/v1/{table}?select=*&limit=1",
                       timeout,
                       headers={"apikey": keys[0],
                                "Authorization": f"Bearer {keys[0]}"})
            if not got or got[0] != 200:
                continue
            try:
                import json as _json
                data = _json.loads(got[1] or "")
            except Exception:
                continue
            if isinstance(data, (dict, list)) and data:
                out.append(Finding(
                    title="Exposed Supabase table (no login)", severity="CRITICAL",
                    url=f"https://{host}/rest/v1/{table}",
                    detail=f"Table '{table}' returns rows for an anonymous key; "
                           "row-level security is missing or open",
                    evidence=table,
                    confidence="Medium",
                ))
                if verbose:
                    print(warn(f"    [!] Supabase open: {host}/{table}"))
                return out
    return out


# ---------- 16. Next.js middleware bypass ----------

NEXTJS_HINTS = ["_next/static", "__NEXT_DATA__", "x-powered-by: next"]


@register_check("nextjs-middleware-bypass", "Next.js middleware auth bypass", order=32)
def test_nextjs_middleware_bypass(session, base: str, pages: dict, html: str,
                                  headers: dict, timeout: int,
                                  verbose: bool = False,
                                  ctx: dict | None = None) -> list[Finding]:
    """CVE-2025-29927 behavior: a request carrying
    x-middleware-subrequest skips middleware. Probe paths that redirect to
    login (or 401) unauthenticated — a 200 with the header is the bug."""
    blob = ((html or "")[:6000] + " " + ((pages or {}).get(base + "/", "") or "")[:2000]
            + " " + " ".join(f"{k}: {v}" for k, v in (headers or {}).items())).lower()
    if not any(h in blob for h in NEXTJS_HINTS):
        return []
    cands = [base.rstrip("/") + p for p in ("/admin", "/dashboard")]
    try:
        for u in (ctx or {}).get("found_paths", [])[:10]:
            from urllib.parse import urlparse as _up
            if _up(u).hostname != _up(base).hostname:
                continue
            path = _up(u).path.lower()
            if any(k in path for k in ("admin", "dashboard", "/api/")) \
                    and u not in cands:
                cands.append(u)
    except Exception:
        pass
    out: list[Finding] = []
    for url in cands[:5]:
        g1 = _get(session, url, timeout)
        if not g1:
            continue
        try:
            # baseline body/headers via a raw fetch for the Location check
            pace()
            r0 = session.get(url, timeout=timeout, allow_redirects=False)
            loc = (r0.headers or {}).get("Location", "")
        except ScanBudgetExceeded:
            raise
        except Exception:
            r0 = None
        loginish = "login" in loc.lower() or (g1[0] in (401, 403))
        if not loginish:
            continue
        g2 = _get(session, url, timeout,
                  headers={"x-middleware-subrequest": "middleware"})
        if not g2:
            continue
        if g2[0] == 200 and g1[0] != 200:
            out.append(Finding(
                title="Next.js middleware bypass", severity="CRITICAL",
                url=url,
                detail="Protected path answers 200 with x-middleware-subrequest "
                       f"(baseline: HTTP {g1[0]}); middleware auth is skipped",
                evidence="x-middleware-subrequest",
                confidence="High",
            ))
            if verbose:
                print(warn(f"    [!] Next.js bypass: {url}"))
            break
    return out


# ---------- 17. WordPress user enumeration ----------

@register_check("wp-user-enum", "WordPress username disclosure", order=11)
def test_wp_user_enum(session, base: str, pages: dict, html: str,
                      headers: dict, timeout: int,
                      verbose: bool = False) -> list[Finding]:
    """Usernames feed password brute-forcing. One request, certain answer."""
    blob = ((html or "")[:6000]
            + " " + " ".join(f"{k}: {v}" for k, v in (headers or {}).items())).lower()
    if not any(h in blob for h in ("wp-content", "wp-includes", "wp-json",
                                   "wordpress")):
        return []
    got = _get(session, base.rstrip("/") + "/wp-json/wp/v2/users", timeout)
    if not got or got[0] != 200:
        return []
    try:
        import json as _json
        users = _json.loads(got[1] or "")
    except Exception:
        return []
    if isinstance(users, list) and users and isinstance(users[0], dict) \
            and "slug" in users[0]:
        names = [str(u.get("slug", "")) for u in users[:5] if u.get("slug")]
        return [Finding(
            title="WordPress username disclosure", severity="LOW",
            url=base.rstrip("/") + "/wp-json/wp/v2/users",
            detail=f"REST API lists usernames ({', '.join(names)}); "
                   "feeds brute-force attacks",
            evidence=",".join(names)[:120],
            confidence="High",
        )]
    return []


# ---------- 18. API docs exposed ----------

SWAGGER_HINTS = ["/swagger.json", "/openapi.json", "/api-docs",
                 "/api/docs", "/v3/api-docs", "/swagger/v1/swagger.json"]


@register_check("swagger-exposed", "Public API docs (Swagger/OpenAPI)", order=11)
def test_swagger_exposed(session, base: str, timeout: int,
                         verbose: bool = False) -> list[Finding]:
    """The crawler already reads these; this just says so out loud.
    Docs are recon gold for attackers — an observation, not a vuln."""
    for cand in SWAGGER_HINTS:
        got = _get(session, base.rstrip("/") + cand, timeout)
        if got and got[0] == 200 and '"paths"' in (got[1] or ""):
            return [Finding(
                title="API docs exposed (Swagger/OpenAPI)", severity="INFO",
                url=base.rstrip("/") + cand,
                detail="Machine-readable API spec is public; use it (and so "
                       "will attackers)",
                evidence=cand,
                confidence="High",
            )]
    return []


# ---------- 19. Mass assignment surface ----------

ROLE_RE = re.compile(r"^(role|is_admin|admin|privileges?|is_staff|superuser|user_role|account_type)$",
                     re.I)


@register_check("mass-assignment", "Client-controllable role field", order=11)
def test_mass_assignment(pages: dict, base: str,
                         verbose: bool = False) -> list[Finding]:
    """No requests: a register/profile POST form exposing a role-like field
    is a privilege-escalation sketch. Server-side enforcement decides."""
    from core.advanced import _forms
    out: list[Finding] = []
    for purl, html in list((pages or {}).items())[:6]:
        try:
            forms = _forms(html, purl.rsplit("/", 1)[0] if "/" in purl else base)
        except Exception:
            continue
        for f in forms:
            if f.get("method") != "POST":
                continue
            hits = [n for n in f.get("inputs", []) if ROLE_RE.match(n or "")]
            if not hits:
                continue
            out.append(Finding(
                title="Client-controllable role field", severity="INFO",
                url=f.get("action", ""),
                detail=f"Form exposes {', '.join(hits)}; to confirm: register, "
                       "replay the request with role=admin, then re-GET the "
                       "profile — escalation only counts if it sticks",
                evidence=",".join(hits),
                confidence="Low",
            ))
            if verbose:
                print(warn(f"    [!] Role field: {f.get('action')}"))
            if len(out) >= 2:
                return out
    return out


# ---------- 20. TLS audit ----------

TLS_EXPIRY_WARN_DAYS = 30
WEAK_CIPHER_HINTS = ("rc4", "des", "3des", "md5", "null", "anon",
                     "export", "idea", "seed", "camellia-128")


def _cert_names(cert: dict) -> tuple[list[str], list[str]]:
    """(sans, cns) from a getpeercert() dict. Never raises."""
    sans: list[str] = []
    cns: list[str] = []
    try:
        for typ, val in (cert or {}).get("subjectAltName", []) or []:
            if typ == "DNS" and val:
                sans.append(str(val).lower())
    except Exception:
        pass
    try:
        for rdn in (cert or {}).get("subject", []) or []:
            for key, val in rdn or []:
                if str(key).lower() in ("commonname", "cn") and val:
                    cns.append(str(val).lower())
    except Exception:
        pass
    return sans, cns


def _hostname_matches(cert: dict, host: str) -> bool:
    """SAN-first hostname check with single-level wildcard support."""
    host = (host or "").lower().strip(".")
    if not host:
        return False
    sans, cns = _cert_names(cert)
    for pattern in sans + cns:
        p = pattern.strip(".")
        if p == host:
            return True
        if p.startswith("*.") and host.count(".") == p.count("."):
            if host.split(".", 1)[1] == p[2:]:
                return True
    return False


def _cert_times(cert: dict) -> tuple[float | None, float | None]:
    """(not_before, not_after) epoch seconds; None when unparsable."""
    import ssl as _ssl
    out = []
    for key in ("notBefore", "notAfter"):
        try:
            out.append(_ssl.cert_time_to_seconds(cert.get(key, "")))
        except Exception:
            out.append(None)
    return out[0], out[1]


def _is_self_signed(cert: dict) -> bool:
    try:
        return bool(cert) and cert.get("issuer") == cert.get("subject")
    except Exception:
        return False


def _cipher_is_weak(cipher_name: str) -> bool:
    low = (cipher_name or "").lower().replace("_", "-")
    return any(h in low for h in WEAK_CIPHER_HINTS)


def _tls_handshake(host: str, port: int, timeout: int,
                   tls_version=None) -> dict | None:
    """One TLS handshake -> info dict. None on network failure (quiet).

    Programming errors propagate (registry records them); socket-level
    failures return None so odd hosts degrade instead of erroring.
    """
    import socket as _socket
    import ssl as _ssl
    ctx = _ssl.SSLContext(_ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = _ssl.CERT_NONE
    if tls_version is not None:
        ctx.minimum_version = tls_version
        ctx.maximum_version = tls_version
    try:
        raw = _socket.create_connection((host, port), timeout=timeout)
    except Exception:
        return None
    try:
        tls = ctx.wrap_socket(raw, server_hostname=host)
    except Exception:
        try:
            raw.close()
        except Exception:
            pass
        return None
    try:
        info = {"version": "", "cipher": "", "alpn": "", "cert": {}}
        try:
            info["version"] = str(tls.version() or "")
        except Exception:
            pass
        try:
            cipher = tls.cipher() or ()
            info["cipher"] = str(cipher[0] if cipher else "")
        except Exception:
            pass
        try:
            info["alpn"] = str(tls.selected_alpn_protocol() or "")
        except Exception:
            pass
        try:
            info["cert"] = tls.getpeercert() or {}
        except Exception:
            pass
        return info
    finally:
        try:
            tls.close()
        except Exception:
            pass


@register_check("tls-audit", "TLS certificate + protocol audit", order=11)
def test_tls_audit(session, base: str, timeout: int,
                   verbose: bool = False) -> list[Finding]:
    """Read-only TLS handshakes (≤3): cert validity/hostname/self-signed,
    weak protocol offers (1.0/1.1), negotiated cipher. Plain-HTTP targets
    skip quietly. Chain-of-trust validation is out of scope (private-CA
    labs would false-positive) and reported as such nowhere."""
    import ssl as _ssl
    import time as _time
    try:
        parts = urlparse(base)
        host = (parts.hostname or "").lower()
        scheme = (parts.scheme or "").lower()
        port = parts.port or 443
    except Exception:
        return []
    if scheme != "https" or not host:
        return []
    main = _tls_handshake(host, port, timeout)
    if not main:
        return []
    cert = main.get("cert") or {}
    out: list[Finding] = []
    url = f"https://{host}:{port}" if port != 443 else f"https://{host}"
    ver, cipher = main.get("version", ""), main.get("cipher", "")

    def _note(title: str, severity: str, detail: str, evidence: str,
              confidence: str) -> None:
        out.append(Finding(title=title, severity=severity, url=url,
                           detail=detail, evidence=evidence[:120],
                           confidence=confidence, method="GET",
                           location="path", confirm="handshake"))
        if verbose:
            print(warn(f"    [!] TLS: {title} ({host})"))

    if cert:
        nb, na = _cert_times(cert)
        now = _time.time()
        if na is not None and na < now:
            _note("TLS certificate expired", "CRITICAL",
                  "Serving host presents an expired certificate; clients "
                  "cannot trust this endpoint", "expired", "High")
        elif na is not None and na - now < TLS_EXPIRY_WARN_DAYS * 86400:
            _note("TLS certificate expires soon", "LOW",
                  "Certificate expires in under "
                  f"{TLS_EXPIRY_WARN_DAYS} days; rotate before outage",
                  "expiry<30d", "High")
        if nb is not None and nb > now:
            _note("TLS certificate not yet valid", "MEDIUM",
                  "Certificate validity starts in the future (clock skew "
                  "or premature deployment)", "notBefore-future", "High")
        if not _hostname_matches(cert, host):
            sans, cns = _cert_names(cert)
            _note("TLS hostname mismatch", "CRITICAL",
                  f"Certificate names ({', '.join((sans + cns)[:3]) or 'none'}) "
                  f"do not cover {host}; MITM-grade misconfiguration",
                  ",".join((sans + cns)[:2]) or "no-san", "High")
        if _is_self_signed(cert):
            scope = "lab/loopback" if host in ("localhost", "127.0.0.1",
                                               "::1") or host.endswith(".local") \
                else "public-facing"
            _note("Self-signed TLS certificate", "MEDIUM",
                  f"No chain to a trusted CA ({scope}); clients cannot "
                  "verify identity", "self-signed", "High")
    # weak protocol offers: explicit handshake per legacy version.
    weak = []
    for label, ver_enum in (("TLS 1.0", getattr(_ssl.TLSVersion, "TLSv1", None)),
                            ("TLS 1.1", getattr(_ssl.TLSVersion, "TLSv1_1", None))):
        if ver_enum is None:
            continue
        try:
            if _tls_handshake(host, port, timeout, ver_enum):
                weak.append(label)
        except Exception:
            continue
    if weak:
        _note("Weak TLS protocol enabled", "MEDIUM",
              f"Server still negotiates {', '.join(weak)} (negotiated best: "
              f"{ver or '?'}); disable below TLS 1.2",
              ",".join(weak), "High")
    if cipher and _cipher_is_weak(cipher):
        _note("Weak TLS cipher negotiated", "MEDIUM",
              f"Handshake settled on {cipher}; prefer AEAD suites "
              "(AES-GCM/ChaCha20) and drop legacy ciphers",
              cipher, "High")
    return out[:5]

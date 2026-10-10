"""App-stack checks: command injection, GraphQL, Next.js, WordPress,
API docs, mass assignment, TLS audit, vulnerable components."""
from __future__ import annotations

import re
from urllib.parse import urlparse

from core.checks._shared import _same_host
from core.colors import warn
from core.net import ScanBudgetExceeded, pace, tls_verify
from core.registry import check as register_check
from core.scanner import Finding, _get, _inject, _post, _post_form_targets

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
                              has_sensitive_data, schema_graph,
                              weak_contracts)
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
    for wc in weak_contracts(parsed)[:2]:
        out.append(Finding(
            title="GraphQL weak input contract", severity="INFO",
            url=endpoint,
            detail=f"Mutation '{wc['mutation']}' takes nullable sensitive "
                   f"input '{wc['arg']}' ({wc['issue']}); static schema "
                   "review only, verify server-side enforcement manually",
            evidence=f"{wc['mutation']}.{wc['arg']}"[:80],
            confidence="Medium",
        ))
        if verbose:
            print(warn(f"    [!] GraphQL weak contract: {wc['mutation']}"))
    if verbose:
        try:
            from core.colors import DIM, RESET
            graph = schema_graph(parsed, endpoint)
            print(f"    {DIM}graphql graph: "
                  f"{len(graph['queries'])} queries, "
                  f"{len(graph['mutations'])} mutations, "
                  f"{len(graph['objects'])} objects"
                  f"{', sensitive: ' + ','.join(graph['sensitive'][:4]) if graph['sensitive'] else ''}"
                  f"{RESET}")
        except Exception:
            pass
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
    return out[:6]


def _dump(data: dict) -> str:
    """Canonical JSON dump for cross-session object comparison."""
    try:
        import json as _json
        return _json.dumps(data, sort_keys=True)
    except Exception:
        return ""


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


def _tls_chain_handshake(host: str, port: int, timeout: int) -> dict | None:
    """One normal trust-validating handshake; no HTTP request is sent."""
    import socket as _socket
    import ssl as _ssl
    ctx = _ssl.create_default_context()
    raw = None
    tls = None
    try:
        raw = _socket.create_connection((host, port), timeout=timeout)
        tls = ctx.wrap_socket(raw, server_hostname=host)
        return {"verified": True, "version": str(tls.version() or ""),
                "cipher": str((tls.cipher() or ("",))[0])}
    except _ssl.SSLCertVerificationError as exc:
        return {"verified": False, "verify_code": getattr(exc, "verify_code", 0),
                "verify_message": str(getattr(exc, "verify_message", exc))[:160]}
    except (_ssl.SSLError, OSError) as exc:
        # A transport/protocol failure is not evidence of an untrusted
        # certificate chain. Keep it distinct from verification rejection.
        return {"verified": None, "verify_code": 0,
                "verify_message": str(exc)[:160]}
    finally:
        try:
            if tls is not None:
                tls.close()
            elif raw is not None:
                raw.close()
        except Exception:
            pass


def _http3_signal(base: str, headers: dict | None) -> list[Finding]:
    """Passive HTTP/3 advertisement from the already-fetched response."""
    raw = ""
    for key, value in (headers or {}).items():
        if str(key).lower() == "alt-svc":
            raw = str(value)
            break
    if not re.search(r"\bh3(?:-\d+)?\s*=", raw, re.I):
        return []
    return [Finding(
        title="HTTP/3 advertised (passive)", severity="INFO", url=base,
        detail="The target advertises HTTP/3 through Alt-Svc. This is a "
               "capability observation only; GASH does not perform a QUIC "
               "probe or treat support as a vulnerability.",
        evidence="Alt-Svc: h3", confidence="High", method="GET",
        location="header", confirm="passive-header")]


def _http3_probe(session, base: str, timeout: int):
    from core.net import pace, proxies
    from core.http3 import HTTP3Result, get
    if proxies():
        return HTTP3Result(
            error="HTTP/3 probe skipped because a proxy is configured")
    pace()
    req_headers = {}
    for key, value in (getattr(session, "headers", {}) or {}).items():
        if str(key).lower() in {"authorization", "cookie"}:
            req_headers[str(key)] = str(value)
    cookies = getattr(session, "cookies", None)
    try:
        pairs = [f"{c.name}={c.value}" for c in cookies] if cookies else []
    except Exception:
        pairs = []
    if pairs and "Cookie" not in req_headers:
        req_headers["Cookie"] = "; ".join(pairs)[:4096]
    return get(base, timeout=timeout, headers=req_headers,
               insecure=not tls_verify())


@register_check("tls-audit", "TLS certificate/protocol + HTTP/3 signal", order=11)
def test_tls_audit(session, base: str, timeout: int,
                   verbose: bool = False,
                   headers: dict | None = None,
                   http3: bool = False) -> list[Finding]:
    """Read-only TLS handshakes: validity, hostname, chain, protocol, cipher.
    Plain-HTTP targets skip TLS quietly. Active HTTP/3 is one explicit,
    read-only QUIC GET when ``http3=True``; it never falls back to HTTP/2."""
    import ssl as _ssl
    import time as _time
    try:
        parts = urlparse(base)
        host = (parts.hostname or "").lower()
        scheme = (parts.scheme or "").lower()
        port = parts.port or 443
    except Exception:
        return []
    out: list[Finding] = _http3_signal(base, headers)
    if scheme != "https" or not host:
        return out
    main = _tls_handshake(host, port, timeout)
    if not main:
        return out
    cert = main.get("cert") or {}
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

    if tls_verify():
        chain = _tls_chain_handshake(host, port, timeout)
        if chain and chain.get("verified") is False:
            message = str(chain.get("verify_message") or "untrusted chain")
            low_message = message.lower()
            # Hostname/time failures already have dedicated findings above;
            # this title is reserved for trust-chain failures.
            if not any(x in low_message for x in
                       ("hostname", "expired", "not yet valid",
                        "self-signed", "self signed")):
                _note("TLS certificate chain-of-trust failed", "MEDIUM",
                      "The platform trust store rejected the presented chain: "
                      f"{message}", "certificate-verify-failed", "High")
    elif verbose:
        print(warn("    [i] TLS chain-of-trust skipped (--insecure)"))

    if http3 and scheme == "https":
        h3 = _http3_probe(session, base, timeout)
        if getattr(h3, "status", 0):
            out.append(Finding(
                title="HTTP/3 active (QUIC confirmed)", severity="INFO", url=url,
                detail="One read-only GET completed over QUIC with an HTTP/3 "
                       f"response (status {h3.status}); no HTTP/2 fallback used.",
                evidence=f"status={h3.status}; protocol=h3", confidence="High",
                method="GET", location="transport", confirm="quic-h3"))
        elif verbose:
            print(warn(f"    [i] HTTP/3 probe unavailable/failed: "
                       f"{getattr(h3, 'error', 'no response')[:120]}"))

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


# ---------- 21. Known vulnerable components ----------

VERSION_FILE_CANDS = ["/CHANGELOG.txt", "/CHANGELOG.md", "/README.txt"]
DRUPAL_VER_RE = re.compile(r"^\s*Drupal\s+(\d[\d.]*)", re.I | re.M)


def _version_file_version(session, base: str, timeout: int) -> list:
    """Drupal-style CHANGELOG first lines -> [(drupal, ver, src)]. 1 hit max."""
    for cand in VERSION_FILE_CANDS:
        got = _get(session, base.rstrip("/") + cand, timeout)
        if not got or got[0] != 200 or len(got[1] or "") > 100_000:
            continue
        m = DRUPAL_VER_RE.search((got[1] or "")[:2000])
        if m:
            from core.cve import parse_version
            if parse_version(m.group(1)):
                return [("drupal", m.group(1), "CHANGELOG.txt")]
    return []


def _looks_wordpress(html: str, headers: dict | None,
                     pages: dict | None) -> bool:
    """Cheap WP hint gate before probing plugin readmes."""
    blob = ((html or "")[:6000]
            + " " + " ".join(f"{k}: {v}" for k, v in (headers or {}).items()))
    for page_html in list((pages or {}).values())[:4]:
        blob += " " + (page_html or "")[:2000]
    low = blob.lower()
    return any(h in low for h in ("wp-content", "wp-includes", "wp-json",
                                  "wordpress"))


def _wp_plugin_versions(session, base: str, timeout: int) -> list:
    """Read-only Stable tag from curated plugin readme.txt paths."""
    from core.cve import WP_PLUGIN_READMES, extract_wp_plugin_version
    out: list[tuple[str, str, str]] = []
    for plugin, path in WP_PLUGIN_READMES[:3]:
        got = _get(session, base.rstrip("/") + path, timeout)
        if not got or got[0] != 200 or len(got[1] or "") > 100_000:
            continue
        hit = extract_wp_plugin_version(got[1] or "", plugin)
        if hit:
            out.append(hit)
    return out


@register_check("vuln-components", "Known vulnerable component versions", order=11)
def test_vuln_components(session, base: str, pages: dict, html: str,
                         headers: dict, timeout: int,
                         verbose: bool = False) -> list[Finding]:
    """Version sightings (meta/?ver=/headers/CHANGELOG/JS banners/WP plugin
    readme) matched against a curated CVE DB. Narrow inclusive ranges only:
    an uncertain match reports nothing. A handful of bounded GETs, all
    read-only — never calls install/update APIs."""
    from urllib.parse import urljoin
    from core.cve import (extract_versions, extract_js_versions,
                          extract_denodo_version, components_with_findings)
    found: list[tuple[str, str, str]] = []
    page_htmls = list((pages or {}).values())[:4]
    try:
        found += extract_versions(html or "", headers)
        for ph in page_htmls:
            found += extract_versions(ph or "", None)
        # Denodo Scheduler banners (CVE-2025-26147 band)
        for blob in [html or "", *page_htmls]:
            hit = extract_denodo_version(blob or "")
            if hit:
                found.append(hit)
                break
    except Exception:
        pass
    try:
        found += _version_file_version(session, base, timeout)
    except ScanBudgetExceeded:
        raise
    except Exception:
        pass
    try:
        if _looks_wordpress(html, headers, pages):
            found += _wp_plugin_versions(session, base, timeout)
    except ScanBudgetExceeded:
        raise
    except Exception:
        pass
    try:
        srcs: list[str] = []
        for html in list((pages or {}).values())[:4]:
            for m in re.findall(r'<script[^>]*src=["\']([^"\']+)["\']',
                                html or "", re.I):
                if m not in srcs:
                    srcs.append(m)
        fetched = 0
        for src in srcs:
            if fetched >= 3:
                break
            full = urljoin(base + "/", src)
            if not _same_host(full, base):
                continue
            fetched += 1
            got = _get(session, full, timeout)
            if not got or len(got[1] or "") > 200_000:
                continue
            found += extract_js_versions(got[1] or "")
    except ScanBudgetExceeded:
        raise
    except Exception:
        pass
    out: list[Finding] = []
    for item in components_with_findings(found):
        out.append(Finding(
            title=item["title"], severity=item["severity"],
            url=base + "/",
            detail=item["detail"],
            evidence=item["evidence"],
            confidence=item["confidence"],
            location=item.get("location", "body"),
            confirm="version-match",
        ))
        if verbose:
            print(warn(f"    [!] Vuln component: {item['title']}"))
        if len(out) >= 4:
            break
    # Atlassian status endpoints (read-only) → version → CVE-2026-21589 band
    try:
        found_atl = _atlassian_versions(session, base, timeout)
        for item in components_with_findings(found_atl):
            if any(f.evidence == item["evidence"] for f in out):
                continue
            out.append(Finding(
                title=item["title"], severity=item["severity"],
                url=base + "/",
                detail=item["detail"],
                evidence=item["evidence"],
                confidence=item["confidence"],
                location="body",
                confirm="version-match",
            ))
            if len(out) >= 4:
                break
    except ScanBudgetExceeded:
        raise
    except Exception:
        pass
    # Denodo Kerberos keytab upload surface (INFO only — never uploads)
    try:
        out += _denodo_keytab_surface(html, pages, base)
    except Exception:
        pass
    return out


KEYTAB_FIELD_RE = re.compile(
    r'name=["\']keyTabFile["\']|id=["\']keyTabFile["\']|'
    r'kerberos[^\n]{0,40}keytab|upload[^\n]{0,20}keytab',
    re.I)


def _denodo_keytab_surface(html: str, pages: dict | None,
                           base: str) -> list[Finding]:
    """Passive: keyTabFile / Kerberos upload form sighting on Denodo UI.

    Never POSTs a multipart filename (CVE-2025-26147 exploit path stays
    opt-out forever). INFO observation only."""
    blob = (html or "")
    for page_html in list((pages or {}).values())[:4]:
        blob += "\n" + (page_html or "")[:4000]
    low = blob.lower()
    if "denodo" not in low and "keytabfile" not in low:
        return []
    if not KEYTAB_FIELD_RE.search(blob):
        return []
    return [Finding(
        title="Denodo Kerberos keytab upload surface",
        severity="INFO",
        url=(base or "")[:240] + "/",
        detail="Scheduler UI exposes a Kerberos keytab upload field. On "
               "unpatched builds (CVE-2025-26147) a crafted multipart "
               "filename can write outside the upload dir — confirm "
               "version via vuln-components; do not test with traversal "
               "uploads on production.",
        evidence="keyTabFile",
        confidence="Medium",
        location="body",
        confirm="passive-sighting",
    )]


# ---------- Atlassian :: web-resource file read (CVE-2026-21589) ----------

# Public detection anchors (content proof: <web-app / <urlrewrite only).
# Encoded ..%3a%3a form — never claims CRITICAL on status alone.
ATLASSIAN_FILEREAD_PROBES = [
    ("/download/resources/jira.webresources:color-picker-popup/images/"
     "..%3a%3a..%3a%3a..%3a%3a..%3a%3a..%3a%3aWEB-INF%3a%3aweb.xml",
     ("<web-app", "<servlet")),
    ("/s/1/_/download/resources/com.atlassian.confluence.plugins."
     "dashboard-actions/images/"
     "..%3a%3a..%3a%3a..%3a%3a..%3a%3a..%3a%3a..%3a%3a..%3a%3a"
     "WEB-INF%3a%3aweb.xml",
     ("<web-app", "<servlet")),
    ("/s/1.0/_/download/resources/com.atlassian.bitbucket.server."
     "bitbucket-webpack-INTERNAL:avatar/avatar/"
     "..%3a%3a..%3a%3a..%3a%3a..%3a%3a..%3a%3aWEB-INF%3a%3aurlrewrite.xml",
     ("<urlrewrite", "<web-app")),
]

ATLASSIAN_STATUS_PATHS = [
    ("/status", ""),
    ("/rest/api/latest/serverInfo", "jira"),
    ("/server-info.action", "confluence"),
]


def _atlassian_versions(session, base: str, timeout: int) -> list:
    """Read-only status/serverInfo probes → [(component, ver, src)]."""
    from core.cve import extract_atlassian_version
    out: list[tuple[str, str, str]] = []
    for path, hint in ATLASSIAN_STATUS_PATHS[:3]:
        got = _get(session, base.rstrip("/") + path, timeout)
        if not got or got[0] not in (200, 500) or len(got[1] or "") > 100_000:
            continue
        hit = extract_atlassian_version(got[1] or "", hint)
        if hit:
            out.append(hit)
            break
    return out


def _looks_atlassian(html: str, headers: dict | None,
                     pages: dict | None, techs: list | None = None) -> bool:
    if techs and any(t in (techs or []) for t in
                     ("atlassian", "confluence", "jira", "bitbucket")):
        return True
    blob = ((html or "")[:6000]
            + " " + " ".join(f"{k}: {v}" for k, v in (headers or {}).items()))
    for page_html in list((pages or {}).values())[:3]:
        blob += " " + (page_html or "")[:1500]
    low = blob.lower()
    return any(h in low for h in ("atlassian", "confluence", "jira.webresources",
                                  "bitbucket", "ajs-page-title"))


@register_check("atlassian-fileread",
                "Atlassian :: web-resource file read (CVE-2026-21589)",
                order=11)
def test_atlassian_fileread(session, base: str, pages: dict, html: str,
                            headers: dict, timeout: int,
                            verbose: bool = False,
                            techs: list | None = None) -> list[Finding]:
    """Content-proof GET with encoded :: traversal. Status alone never
    CRITICAL — body must show web.xml / urlrewrite markers."""
    if not _looks_atlassian(html, headers, pages, techs):
        # Still try one cheap probe when fingerprint is weak but path
        # shape is public; cap remains 3.
        pass
    out: list[Finding] = []
    for path, markers in ATLASSIAN_FILEREAD_PROBES[:3]:
        url = base.rstrip("/") + path
        got = _get(session, url, timeout)
        if not got or got[0] != 200:
            continue
        body = got[1] or ""
        if len(body) > 200_000:
            continue
        hit = next((m for m in markers if m in body), None)
        if not hit:
            continue
        out.append(Finding(
            title="Atlassian arbitrary file read (CVE-2026-21589)",
            severity="CRITICAL",
            url=url[:240],
            detail="Web-resource download accepted encoded :: traversal and "
                   "returned a protected descriptor from the web root "
                   "(unauthenticated). Patch to vendor fixed versions; "
                   "rotate any exposed credentials.",
            evidence=hit,
            confidence="High",
            method="GET",
            location="path",
            confirm="content-marker",
        ))
        if verbose:
            print(warn(f"    [!] Atlassian fileread: {hit} @ {url[:80]}"))
        break  # one product hit is enough
    return out


# ---------- Hunk Companion plugin-install authz (no install) ----------

HUNK_INSTALL_PATHS = [
    "/wp-json/hc/v1/themehunk-import",
    "/?rest_route=/hc/v1/themehunk-import",
]
# Auth-bypass proof without installing: incomplete body reaches the
# install handler (JSON error about params/plugin) instead of 401/403.
HUNK_HANDLER_HINTS = re.compile(
    r"plugin|templateType|allPlugins|tp_install|themehunk|hunk.?companion|"
    r"rest_forbidden|unauthorized", re.I)
HUNK_AUTH_BLOCK = re.compile(
    r'"code"\s*:\s*"(rest_forbidden|rest_cannot|unauthorized|jwt_auth)"'
    r'|you must be logged in|sorry,\s*you\s*are\s*not\s*allowed', re.I)


@register_check("plugin-install-authz",
                "Unauthenticated plugin-install API surface (Hunk Companion)",
                order=11)
def test_plugin_install_authz(session, base: str, pages: dict, html: str,
                              headers: dict, timeout: int,
                              verbose: bool = False) -> list[Finding]:
    """Prove the install handler is reachable anonymously WITHOUT ever
    sending a plugin slug that would install/activate anything."""
    if not _looks_wordpress(html, headers, pages):
        return []
    out: list[Finding] = []
    # Incomplete JSON — no plugin keys, cannot install.
    inert = {"params": {"templateType": "free"}}
    root = base.rstrip("/")
    for path in HUNK_INSTALL_PATHS[:2]:
        url = root + path
        try:
            pace()
            r = session.post(url, timeout=timeout, json=inert,
                             headers={"Content-Type": "application/json"})
        except ScanBudgetExceeded:
            raise
        except Exception:
            continue
        try:
            code = int(r.status_code)
            body = r.text or ""
        except Exception:
            continue
        if code in (401, 403):
            continue  # properly gated
        if code == 404 or len(body) > 100_000:
            continue
        if HUNK_AUTH_BLOCK.search(body) and code >= 400:
            continue
        # Handler ran anonymously: JSON/error mentions install params,
        # or 200 with WP REST envelope from the route.
        low = body.lower()
        ran = bool(HUNK_HANDLER_HINTS.search(body)) and (
            "plugin" in low or "templatetype" in low
            or "themehunk" in low or "hunk" in low
            or '"code"' in low)
        if not ran and code != 200:
            continue
        if not ran:
            # 200 alone is weak — need REST/json shape
            if "application/json" not in str(
                    getattr(r, "headers", {}) or {}).lower() \
                    and not body.strip().startswith(("{", "[")):
                continue
            # Empty 200 JSON without hints → skip (too weak)
            if not HUNK_HANDLER_HINTS.search(body):
                continue
        out.append(Finding(
            title="Unauthenticated plugin-install API (CVE-2024-11972)",
            severity="CRITICAL",
            url=url[:240],
            detail="Hunk Companion themehunk-import REST route accepted an "
                   "anonymous incomplete POST (no plugin slug sent — nothing "
                   "installed). Authz is broken on the install surface; "
                   "update Hunk Companion to 1.9.0+ and restrict the route.",
            evidence="themehunk-import:unauth-handler",
            confidence="High",
            method="POST",
            location="body",
            confirm="authz-bypass-no-install",
        ))
        if verbose:
            print(warn(f"    [!] Plugin-install authz open: {url[:80]}"))
        break
    return out


# ---------- WebSocket surface + message reflection ----------

WS_ABS_RE = re.compile(r"""['"](wss?://[^'"\s]+)['"]""", re.I)
WS_PATH_RE = re.compile(
    r"""['"](/(?:ws|websocket|socket\.io|sockjs)[^'"\s]*)['"]""", re.I)


def collect_ws_urls(base: str, pages: dict | None, html: str = "",
                    browser_graph: dict | None = None,
                    limit: int = 6) -> list[str]:
    """Passive WebSocket URL harvest (pages + browser graph). Same-host."""
    from urllib.parse import urlparse
    out: list[str] = []
    seen: set[str] = set()
    host = ""
    try:
        host = (urlparse(base).hostname or "").lower()
    except Exception:
        host = ""

    def _add(raw: str) -> None:
        if not raw or raw in seen:
            return
        full = raw
        if raw.startswith("/"):
            scheme = "wss" if (base or "").startswith("https") else "ws"
            try:
                p = urlparse(base)
                full = f"{scheme}://{p.netloc}{raw}"
            except Exception:
                return
        if not full.startswith(("ws://", "wss://")):
            return
        try:
            h = (urlparse(full).hostname or "").lower()
        except Exception:
            return
        if host and h != host:
            return
        seen.add(raw if raw.startswith("/") else full)
        out.append(full)

    blobs = [html or ""]
    for v in list((pages or {}).values())[:6]:
        blobs.append(v or "")
    for blob in blobs:
        for m in WS_ABS_RE.findall(blob):
            _add(m)
            if len(out) >= limit:
                return out
        for m in WS_PATH_RE.findall(blob):
            _add(m)
            if len(out) >= limit:
                return out
    for ws in list((browser_graph or {}).get("websockets") or [])[:limit]:
        _add(str(ws))
        if len(out) >= limit:
            break
    return out[:limit]


def _ws_upgrade_probe(url: str, timeout: int,
                      origin: str = "") -> tuple[int, str, bool]:
    """HTTP Upgrade handshake. Returns (status, body_snip, upgraded)."""
    import base64
    import hashlib
    import os
    import socket
    import ssl
    from urllib.parse import urlparse
    try:
        p = urlparse(url)
    except Exception:
        return (0, "", False)
    host, port = p.hostname, p.port
    if not host:
        return (0, "", False)
    tls = p.scheme == "wss"
    if port is None:
        port = 443 if tls else 80
    path = p.path or "/"
    if p.query:
        path += "?" + p.query
    key = base64.b64encode(os.urandom(16)).decode("ascii")
    origin = origin or f"{'https' if tls else 'http'}://{host}"
    req = (
        f"GET {path} HTTP/1.1\r\n"
        f"Host: {host}:{port}\r\n"
        f"Upgrade: websocket\r\n"
        f"Connection: Upgrade\r\n"
        f"Sec-WebSocket-Key: {key}\r\n"
        f"Sec-WebSocket-Version: 13\r\n"
        f"Origin: {origin}\r\n"
        f"\r\n"
    ).encode("ascii")
    sock = None
    try:
        pace()
        raw = socket.create_connection((host, port), timeout=timeout)
        sock = ssl.create_default_context().wrap_socket(
            raw, server_hostname=host) if tls else raw
        sock.settimeout(timeout)
        sock.sendall(req)
        data = b""
        while b"\r\n\r\n" not in data and len(data) < 8192:
            chunk = sock.recv(1024)
            if not chunk:
                break
            data += chunk
        head = data.split(b"\r\n\r\n", 1)[0].decode("latin-1", "replace")
        status = 0
        m = re.match(r"HTTP/\d\.\d\s+(\d+)", head)
        if m:
            status = int(m.group(1))
        upgraded = status == 101 and "upgrade: websocket" in head.lower()
        # Optional: one text canary frame if upgraded (reflection check)
        echoed = ""
        if upgraded:
            canary = "gash-ws-" + hashlib.sha1(  # noqa: S324 — id only
                key.encode(), usedforsecurity=False).hexdigest()[:10]
            # Client frame: FIN+text, masked
            payload = canary.encode("utf-8")
            mask = os.urandom(4)
            masked = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
            frame = bytes([0x81, 0x80 | len(payload)]) + mask + masked
            try:
                sock.sendall(frame)
                resp = sock.recv(2048)
                if resp and len(resp) >= 2:
                    # Best-effort unmask server frame (servers don't mask)
                    opcode = resp[0] & 0x0F
                    ln = resp[1] & 0x7F
                    if opcode == 0x1 and ln and ln < 126:
                        echoed = resp[2:2 + ln].decode("utf-8", "replace")
            except Exception:
                echoed = ""
        return (status, echoed or head[:120], upgraded)
    except ScanBudgetExceeded:
        raise
    except Exception:
        return (0, "", False)
    finally:
        try:
            if sock is not None:
                sock.close()
        except Exception:
            pass


@register_check("websocket-fuzz",
                "WebSocket surface discovery + message reflection",
                order=12)
def test_websocket_fuzz(session, base: str, pages: dict, html: str,
                        timeout: int, verbose: bool = False,
                        browser_graph: dict | None = None) -> list[Finding]:
    """Discover WS endpoints; Upgrade probe; canary echo → reflection note.
    No auth bypass chains, no flooding — at most a few handshakes."""
    _ = session  # signature parity with other checks
    urls = collect_ws_urls(base, pages, html, browser_graph, limit=5)
    if not urls:
        return []
    out: list[Finding] = []
    # INFO: discovered sockets (unscored observation)
    out.append(Finding(
        title="WebSocket endpoints discovered",
        severity="INFO",
        url=urls[0][:240],
        detail=f"Passive harvest found {len(urls)} same-host WebSocket "
               f"URL(s); probing Upgrade + a single canary frame.",
        evidence=",".join(u[:60] for u in urls[:3]),
        confidence="High",
        location="body",
        confirm="passive-harvest",
    ))
    for ws_url in urls[:3]:
        status, snip, upgraded = _ws_upgrade_probe(ws_url, timeout, origin=base)
        if not upgraded:
            continue
        canary_hit = snip.startswith("gash-ws-") if snip else False
        if canary_hit:
            out.append(Finding(
                title="WebSocket message reflection",
                severity="MEDIUM",
                url=ws_url[:240],
                detail="Server echoed a client text canary over WebSocket; "
                       "treat as an injection/XSS sink surface and validate "
                       "Origin + message schema server-side.",
                evidence="gash-ws-echo",
                confidence="High",
                method="WS",
                location="body",
                confirm="canary-echo",
            ))
            if verbose:
                print(warn(f"    [!] WS reflection: {ws_url[:80]}"))
        else:
            out.append(Finding(
                title="WebSocket Upgrade accepted",
                severity="INFO",
                url=ws_url[:240],
                detail=f"HTTP 101 WebSocket Upgrade succeeded (status={status}); "
                       "no canary echo — surface noted for manual review.",
                evidence="101 Switching Protocols",
                confidence="High",
                method="WS",
                location="header",
                confirm="upgrade",
            ))
        if len([f for f in out if f.severity != "INFO"]) >= 2:
            break
    return out[:6]


__all__ = [
    "GRAPHQL_PATHS",
    "test_graphql_introspection",
    "_dump",
    "OS_CMD_PAYLOADS",
    "OS_CMD_RES",
    "test_os_command_injection",
    "NEXTJS_HINTS",
    "test_nextjs_middleware_bypass",
    "test_wp_user_enum",
    "SWAGGER_HINTS",
    "test_swagger_exposed",
    "ROLE_RE",
    "test_mass_assignment",
    "TLS_EXPIRY_WARN_DAYS",
    "WEAK_CIPHER_HINTS",
    "_cert_names",
    "_hostname_matches",
    "_cert_times",
    "_is_self_signed",
    "_cipher_is_weak",
    "_tls_handshake",
    "test_tls_audit",
    "VERSION_FILE_CANDS",
    "DRUPAL_VER_RE",
    "_version_file_version",
    "_looks_wordpress",
    "_wp_plugin_versions",
    "test_vuln_components",
    "ATLASSIAN_FILEREAD_PROBES",
    "ATLASSIAN_STATUS_PATHS",
    "_atlassian_versions",
    "_looks_atlassian",
    "test_atlassian_fileread",
    "HUNK_INSTALL_PATHS",
    "test_plugin_install_authz",
    "WS_ABS_RE",
    "WS_PATH_RE",
    "collect_ws_urls",
    "_ws_upgrade_probe",
    "test_websocket_fuzz",
]

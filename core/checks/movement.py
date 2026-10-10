"""Movement checks: open redirect, path traversal, CRLF injection."""
from __future__ import annotations

import re
from urllib.parse import parse_qs, urlparse, urlencode, urlunparse

from core.checks._shared import EVIL_HOST, EVIL_ORIGIN
from core.colors import warn
from core.net import ScanBudgetExceeded, pace
from core.registry import check as register_check
from core.scanner import Finding, _get

REDIRECT_KEYS = {"next", "redirect", "return", "url", "u", "dest",
                 "destination", "continue", "ref", "target", "r",
                 "redirect_uri", "redirect_url", "return_url", "continue_url",
                 "callback", "callback_url", "forward", "goto", "to", "next_url"}
TRAVERSAL_KEYS = {"file", "path", "page", "include", "template", "dir",
                  "folder", "doc", "document", "filename", "pg", "name",
                  "filepath", "resource"}
TRAVERSAL_SETS = [
    (["../../../../etc/passwd", "....//....//etc/passwd"], ["root:x:0:0"]),
    (["..\\..\\windows\\win.ini", "..//..//windows//win.ini"], ["[fonts]"]),
    # App-config LFI (Atlassian/Java/Spring class): content markers only —
    # status codes alone never prove a read. Confirm uses a second file.
    (["../../../../application.properties",
      "../../../../crowd.properties",
      "../application.properties"],
     ["spring.datasource", "crowd.server.url", "application.password="]),
]
TRAVERSAL_CONFIRM = ("../../../../etc/hosts", "localhost")
# App-config confirm pairs (Atlassian/Java class). Tried after OS hosts;
# marker must differ from the first hit so one file can't self-confirm.
TRAVERSAL_CONFIRM_APP = (
    ("../../../../application.properties", "spring.datasource"),
    ("../../../../crowd.properties", "crowd.server.url"),
)
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


# ---------- OAuth/OIDC redirect_uri (research: auth bypass class) ----------

OAUTH_PATH_HINT = re.compile(
    r"/(?:oauth|oidc|connect|auth)/(?:authorize|auth|callback)|"
    r"/oauth2?/v\d+/authorize|/signin-oidc", re.I)
OAUTH_QS_HINTS = {"client_id", "response_type", "scope", "state"}


def _oauth_candidates(urls: list[str], pages: dict | None) -> list[str]:
    """URLs that look like OAuth/OIDC authorize/callback surfaces."""
    out: list[str] = []
    seen: set[str] = set()
    pool = list(urls or [])[:20]
    for u in list((pages or {}) or {}):
        if u not in pool:
            pool.append(u)
    for u in pool[:24]:
        try:
            p = urlparse(u)
            q = {k.lower() for k in parse_qs(p.query, keep_blank_values=True)}
        except Exception:
            continue
        path_hit = bool(OAUTH_PATH_HINT.search(p.path or ""))
        qs_hit = ("redirect_uri" in q or "redirect_url" in q) and (
            bool(q & OAUTH_QS_HINTS) or path_hit)
        if not (path_hit or qs_hit):
            continue
        if u in seen:
            continue
        seen.add(u)
        out.append(u)
    return out[:8]


@register_check("oauth-redirect",
                "OAuth/OIDC redirect_uri open redirect", order=11)
def test_oauth_redirect(session, urls: list[str], timeout: int,
                        verbose: bool = False,
                        pages: dict | None = None) -> list[Finding]:
    """OAuth authorize that accepts an attacker redirect_uri enables
    code/token theft. Same evil-host proof as open-redirect, but scoped
    to OAuth/OIDC surfaces and raised severity."""
    out: list[Finding] = []
    for u in _oauth_candidates(urls, pages):
        try:
            p = urlparse(u)
            q = parse_qs(p.query, keep_blank_values=True)
        except Exception:
            continue
        # Prefer explicit redirect_uri; else inject one onto authorize paths.
        keys = [k for k in q if k.lower() in ("redirect_uri", "redirect_url",
                                              "callback_url", "return_url")]
        if not keys and OAUTH_PATH_HINT.search(p.path or ""):
            keys = ["redirect_uri"]
            q = {**{k: v for k, v in q.items()}, "redirect_uri": [""]}
        for key in keys[:1]:
            inj = urlunparse((p.scheme, p.netloc, p.path, p.params,
                              urlencode({**{k: v[0] for k, v in q.items()},
                                         key: EVIL_ORIGIN}), p.fragment))
            r = _get_no_redirect(session, inj, timeout)
            if not r:
                continue
            loc = ""
            try:
                loc = (r.headers or {}).get("Location", "") or ""
            except Exception:
                loc = ""
            if r.status_code not in (301, 302, 303, 307, 308):
                continue
            if EVIL_HOST not in loc:
                continue
            out.append(Finding(
                title="OAuth/OIDC open redirect_uri",
                severity="CRITICAL",
                url=inj[:240],
                detail=f"Authorize/callback accepted attacker {key} "
                       f"(302 → {loc[:80]}). An auth code or token can be "
                       "exfiltrated — allowlist redirect URIs per client.",
                evidence=loc[:120],
                confidence="High",
                method="GET",
                location="query",
                confirm="location-header",
            ))
            if verbose:
                print(warn(f"    [!] OAuth redirect_uri: {inj[:80]}"))
            break
        if out:
            break
    return out[:2]


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


def _traversal_confirmed(session, p, q: dict, key: str, hit: str,
                         timeout: int) -> tuple[str, str] | None:
    """Second independent file read, or None. Prefer OS hosts; fall back
    to a distinct app-config marker so Java/Atlassian-class LFI still
    confirms when /etc is unreachable."""
    candidates = [TRAVERSAL_CONFIRM, *TRAVERSAL_CONFIRM_APP]
    hit_low = (hit or "").lower()
    for cfile, cmarker in candidates:
        if cmarker.lower() == hit_low:
            continue  # need a *different* marker
        confirm = _get(session, urlunparse(
            (p.scheme, p.netloc, p.path, p.params,
             urlencode({**{k: v[0] for k, v in q.items()}, key: cfile}),
             p.fragment)), timeout)
        if confirm and cmarker in (confirm[1] or ""):
            return cfile, cmarker
    return None


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
        all_markers.extend(m for _, m in TRAVERSAL_CONFIRM_APP)
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
                    confirmed = _traversal_confirmed(
                        session, p, q, key, hit, timeout)
                    if not confirmed:
                        continue
                    cfile, _cmarker = confirmed
                    if verbose:
                        print(warn(f"    [!] Path traversal (confirmed x2): {inj}"))
                    return Finding(
                        title="Possible Path Traversal", severity="MEDIUM",
                        url=inj,
                        detail=f"?{key} reads local files "
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

__all__ = [
    "REDIRECT_KEYS",
    "TRAVERSAL_KEYS",
    "TRAVERSAL_SETS",
    "TRAVERSAL_CONFIRM",
    "TRAVERSAL_CONFIRM_APP",
    "_get_no_redirect",
    "test_open_redirect",
    "_oauth_candidates",
    "test_oauth_redirect",
    "_filter_proof",
    "test_path_traversal",
    "test_crlf_injection",
]

"""Scan HTTP layer: sessions, throttling, GET/POST/request, login, fetch-base."""
from __future__ import annotations

import re
from urllib.parse import urljoin, urlparse

from core.colors import warn
from core.net import (
    pace, get_context, ScanBudgetExceeded, RATE_WAIT_BUDGET,
)
from core.scan._shared import FORM_RE, ACTION_RE, INPUT_RE


def _session(timeout: int = 8, auth=None):
    import requests
    import urllib3
    from core.net import proxies, user_agent, tls_verify
    s = requests.Session()
    s.headers.update({"User-Agent": user_agent()})
    if proxies():
        s.proxies.update(proxies())
    if auth is not None:
        cookies = getattr(auth, "cookies", None)
        extra = getattr(auth, "headers", None)
        if cookies:
            s.cookies.update(cookies)
        if extra:
            s.headers.update(extra)
    s.verify = tls_verify()
    if not s.verify:
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    s.timeout = timeout  # unused on Session, passed to get() instead
    return s


_TLS_POOL: dict[int, dict[int, object]] = {}
_TLS_LOCK = None  # lazy threading.Lock (see below)


def _tls_session(template):
    """One requests.Session per thread, cloned from the template.

    requests Sessions are not thread-safe; every worker gets its own
    connection pool. Non-requests sessions (test fakes) pass through.
    """
    import threading
    import requests
    if not isinstance(template, requests.Session):
        return template
    global _TLS_LOCK
    if _TLS_LOCK is None:
        _TLS_LOCK = threading.Lock()
    tid = threading.get_ident()
    key = id(template)
    with _TLS_LOCK:
        per_thread = _TLS_POOL.setdefault(tid, {})
        s = per_thread.get(key)
        if s is None:
            s = requests.Session()
            try:
                s.headers.update(dict(template.headers))
            except Exception:
                pass
            try:
                s.cookies.update({c.name: c.value for c in template.cookies})
            except Exception:
                pass
            s.verify = getattr(template, "verify", True)
            try:
                s.proxies.update(dict(getattr(template, "proxies", {}) or {}))
            except Exception:
                pass
            per_thread[key] = s
    return s


def _calm_down(wait: float, where: str) -> None:
    """After a 429: wait politely + throttle globally (max 10s per hit).

    Gives up after RATE_WAIT_BUDGET cumulative seconds: partial results
    now beat a 10-minute black hole against a rate-limiting WAF.
    """
    wait = min(max(1.0, wait), 10.0)
    ctx = get_context()
    with ctx._lock:
        ctx.delay = min(ctx.delay + 2.0, 10.0)
        if ctx.rate_wait_total + wait > RATE_WAIT_BUDGET:
            raise ScanBudgetExceeded(
                f"rate-limited by target ({RATE_WAIT_BUDGET:.0f}s waited) — "
                "stopping with partial results")
        ctx.rate_wait_total += wait
    from core.spinner import countdown
    countdown(f"  [!] 429 ({where}): waiting", wait)


def _mark_dead() -> None:
    """Flag budget/rate death where every thread can see it (shared default)."""
    try:
        get_context().dead = True
    except Exception:
        pass
    try:
        from core.net import _DEFAULT
        _DEFAULT.dead = True
    except Exception:
        pass


def _get(session, url: str, timeout: int, headers: dict | None = None):
    """(status, text, final_url) or None. Never throws; degrades on budget."""
    try:
        pace()
    except ScanBudgetExceeded:
        _mark_dead()
        return None
    session = _tls_session(session)
    try:
        r = session.get(url, timeout=timeout, allow_redirects=True,
                        headers=headers)
        if r.status_code == 429:
            _calm_down(float(r.headers.get("Retry-After", 5) or 5), "GET")
            pace()
            r = session.get(url, timeout=timeout, allow_redirects=True,
                            headers=headers)
        return r.status_code, r.text, r.url
    except ScanBudgetExceeded:
        _mark_dead()
        return None
    except Exception:
        return None


def _post(session, url: str, timeout: int, **kwargs):
    """POST equivalent (response or None). Degrades on budget overrun."""
    try:
        pace()
    except ScanBudgetExceeded:
        _mark_dead()
        return None
    session = _tls_session(session)
    try:
        r = session.post(url, timeout=timeout, allow_redirects=True, **kwargs)
        if r.status_code == 429:
            _calm_down(float(r.headers.get("Retry-After", 5) or 5), "POST")
            pace()
            r = session.post(url, timeout=timeout, allow_redirects=True, **kwargs)
        return r
    except ScanBudgetExceeded:
        _mark_dead()
        return None
    except Exception:
        return None


def _request(session, method: str, url: str, timeout: int, **kwargs):
    """PUT/PATCH/DELETE equivalent (response or None). Deep-only callers."""
    try:
        pace()
    except ScanBudgetExceeded:
        _mark_dead()
        return None
    session = _tls_session(session)
    try:
        r = session.request(method.upper(), url, timeout=timeout,
                            allow_redirects=True, **kwargs)
        if r.status_code == 429:
            _calm_down(float(r.headers.get("Retry-After", 5) or 5), method.upper())
            pace()
            r = session.request(method.upper(), url, timeout=timeout,
                                allow_redirects=True, **kwargs)
        return r
    except ScanBudgetExceeded:
        _mark_dead()
        return None
    except Exception:
        return None


def do_login(base_url: str, username: str, password: str, timeout: int = 8,
             login_url: str | None = None,
             auth=None) -> tuple[dict, bool]:
    """Log in through the form.

    Returns (session cookies, form_found). No form -> ({}, False);
    form but no cookies -> ({}, True) — the caller fails closed.

    Warns about cleartext passwords off-https but doesn't block
    (could be a test environment).
    """
    if base_url.startswith("http://") and not login_url:
        print(warn("  [!] login over http: password goes over the wire (assumed test env)"))
    s = _session(timeout, auth)
    page_url = login_url or base_url
    got = _get(s, page_url, timeout)
    html = (got[1] if got else "") or ""
    target = page_url
    login_chunk = ""
    for m in FORM_RE.finditer(html):
        if "password" in m.group(0).lower():
            am = ACTION_RE.search(m.group(0))
            target = urljoin(base_url + "/", (am.group(1) if am else "") or "/")
            login_chunk = m.group(0)
            break
    if not login_chunk:
        print(warn("  [!] No login form found, continuing anonymously."))
        return {}, False
    pm = re.search(r'<input[^>]*type=["\']?password["\']?[^>]*name=["\']([^"\']+)["\']',
                   login_chunk, re.I)
    pass_name = pm.group(1) if pm else "password"
    user_name = None
    for n in INPUT_RE.findall(login_chunk):
        if n != pass_name:
            user_name = user_name or n
    if not user_name:
        print(warn("  [!] No username field found, continuing anonymously."))
        return {}, True
    data = {n: "1" for n in INPUT_RE.findall(login_chunk)}
    data[user_name] = username
    data[pass_name] = password
    r = _post(s, target, timeout, data=data)
    if not r:
        return {}, True
    try:
        return {c.name: c.value for c in s.cookies}, True
    except Exception:
        return {}, True


def _fetch_base(session, base_url: str, timeout: int,
                scope_hosts: set[str] | None = None) -> tuple[str, str, dict]:
    """Fetch the base page, with https fallback. (html, effective_base, headers).

    A redirect landing outside scope_hosts is refused (scope enforcement
    starts at the very first request).
    """
    cands = [base_url]
    if base_url.startswith("http://"):
        cands.append(base_url.replace("http://", "https://", 1))
    for u in cands:
        try:
            pace()
        except ScanBudgetExceeded:
            _mark_dead()
            break
        try:
            r = session.get(u, timeout=timeout, allow_redirects=True)
            if r.status_code:
                if scope_hosts:
                    try:
                        final = (urlparse(r.url or u).hostname or "").lower()
                    except Exception:
                        final = ""
                    if final not in scope_hosts:
                        continue
                return r.text, u.rstrip("/"), dict(r.headers)
        except ScanBudgetExceeded:
            raise
        except Exception:
            continue
    return "", base_url.rstrip("/"), {}


__all__ = [
    "_session", "_tls_session", "_TLS_POOL", "_calm_down", "_mark_dead",
    "_get", "_post", "_request", "do_login", "_fetch_base",
]

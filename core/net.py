"""Shared HTTP plumbing: politeness, budget, auth.

scanner and recon use this same module (no circular imports):
  - configure_net(delay, max_requests, ...): called once up front
  - pace(): called before every HTTP request; raises ScanBudgetExceeded
  - parse_auth(cookie_str, header_list): CLI input -> AuthState
"""

from __future__ import annotations

import time
from contextvars import ContextVar
from dataclasses import dataclass, field
from threading import Lock


class ScanBudgetExceeded(Exception):
    """--max-requests spent (or scan cancelled): stop with partial results."""


@dataclass
class AuthState:
    """Session identity: cookies + extra headers. Updated in place
    (login cookies get merged in after a successful login)."""
    cookies: dict = field(default_factory=dict)
    headers: dict = field(default_factory=dict)


@dataclass
class ScanContext:
    """Per-scan HTTP state. One context per scan keeps parallel scans and
    threads from stepping on each other (the counter update is locked)."""
    delay: float = 0.0
    max_requests: int = 0
    count: int = 0
    proxy: str | None = None
    user_agent: str | None = None
    insecure: bool = False
    cancelled: bool = False
    _lock: Lock = field(default_factory=Lock, repr=False, compare=False)


_DEFAULT = ScanContext()
_current: ContextVar = ContextVar("gash_scan_context", default=_DEFAULT)


def get_context() -> ScanContext:
    """The context pace()/sessions use. Library users can run scans under
    their own context via run_with_context()."""
    return _current.get()


def run_with_context(ctx: ScanContext):
    """Switch pace()/sessions to ctx. Returns a token; pass it back to
    _current.reset(token) when done."""
    return _current.set(ctx)


def enter_scan_scope():
    """Fresh per-scan context inheriting the configured defaults.

    Parallel scans stop sharing budget/counter state: each scan mutates
    only its own copy. Returns a token for exit_scan_scope()."""
    base = _current.get()
    ctx = ScanContext(delay=base.delay, max_requests=base.max_requests,
                      proxy=base.proxy, user_agent=base.user_agent,
                      insecure=base.insecure)
    return _current.set(ctx)


def exit_scan_scope(token) -> None:
    """Leave a per-scan context entered with enter_scan_scope()."""
    _current.reset(token)


def configure_net(delay: float = 0.0, max_requests: int = 0,
                  proxy: str | None = None,
                  user_agent: str | None = None,
                  insecure: bool = False) -> None:
    delay_s = max(0.0, float(delay or 0.0))
    d = _DEFAULT
    d.delay = delay_s
    d.max_requests = max(0, int(max_requests or 0))
    d.proxy = (proxy or "").strip() or None
    d.user_agent = (user_agent or "").strip() or None
    d.insecure = bool(insecure)
    d.count = 0
    d.cancelled = False


def proxies() -> dict:
    """Configured proxy for requests ({} when none)."""
    p = _current.get().proxy
    return {"http": p, "https": p} if p else {}


def user_agent() -> str:
    """Custom UA or the default GASH identifier."""
    ua = _current.get().user_agent
    if ua:
        return ua
    from core.recon import GASH_UA
    return GASH_UA


def tls_verify() -> bool:
    """Certificate verification is ON unless --insecure opted out."""
    return not _current.get().insecure


def pace() -> None:
    """Bump the counter, enforce budget/cancellation, apply the delay."""
    ctx = _current.get()
    with ctx._lock:
        ctx.count += 1
        n, limit, cancelled = ctx.count, ctx.max_requests, ctx.cancelled
    if cancelled:
        raise ScanBudgetExceeded("scan cancelled")
    if limit and n > limit:
        raise ScanBudgetExceeded(
            f"request budget spent ({limit}) — stopping with partial results")
    if ctx.delay:
        time.sleep(ctx.delay)


def parse_auth(cookie_str: str | None,
               header_list: list[str] | None) -> AuthState:
    """--cookie 'a=b; c=d' + --header 'K: V' (repeatable) -> AuthState."""
    cookies: dict = {}
    if cookie_str:
        for part in cookie_str.split(";"):
            if "=" in part:
                k, v = part.split("=", 1)
                if k.strip():
                    cookies[k.strip()] = v.strip()
    headers: dict = {}
    for h in header_list or []:
        if ":" in h:
            k, v = h.split(":", 1)
            if k.strip():
                headers[k.strip()] = v.strip()
    return AuthState(cookies=cookies, headers=headers)

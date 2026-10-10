"""Scan enumeration: upload surface, robots, dir-brute, recursion."""
from __future__ import annotations

import re
from concurrent.futures import ThreadPoolExecutor, as_completed

from core.colors import warn
from core.registry import check as register_check
from core.scan._shared import (
    Finding, ADMIN_HINT, FILE_INPUT_HINT, SENSITIVE_HINT,
)
from core.scan.http import _get
from core.wordlists import (
    UPLOAD_PATHS, wordlist_for_techs,
    RECURSE_FILE_SUFFIX, RECURSE_DIR_EXTRA, RECURSE_DIR_MUTATIONS,
    RECURSE_DIR_FILE_EXT,
)


@register_check("upload-form", "Upload form detection (passive)", order=10)
def check_upload(session, base: str, timeout: int, verbose: bool,
                 go_worker: bool = False) -> list[Finding]:
    out: list[Finding] = []
    # Hybrid: all upload-path GETs in one round-trip; judging is identical.
    pre = None
    if go_worker:
        try:
            from core.scan.injection import _go_prefetch
            pre = _go_prefetch(
                session, [base + path for path in UPLOAD_PATHS],
                timeout, 10)
        except Exception:
            pre = None

    def _fetch(url: str):
        if pre is not None and url in pre:
            st, body = pre[url]
            return (st, body, url)
        return _get(session, url, timeout)

    for path in UPLOAD_PATHS:
        url = base + path
        got = _fetch(url)
        if not got:
            continue
        status, body, _ = got
        if status == 200 and FILE_INPUT_HINT.search(body or ""):
            out.append(Finding(
                title="Upload form detected",
                severity="INFO",
                url=url,
                detail=f"Form with <input type=file> at {path} (passive discovery, "
                       "not a vulnerability — run --deep to test it)",
                evidence='<input type=file...>',
                confidence="High",
            ))
            if verbose:
                print(warn(f"    [!] Upload form: {url}"))
    return out


def _baseline_404(session, base: str, timeout: int) -> tuple[int, int, str]:
    """Baseline for the soft-404 filter: (status, size, sample text)."""
    got = _get(session, base + "/gash_nope_987654321", timeout)
    if not got:
        return 404, 0, ""
    return got[0], len(got[1] or ""), (got[1] or "")[:4000]


def _looks_like_baseline(status: int, body: str, base_status: int,
                         base_len: int, base_text: str) -> bool:
    """Combined signal: status + size + content similarity.

    Delegates to the shared differential engine (no local thresholds).
    """
    from core.diff import looks_like_baseline
    return looks_like_baseline(status, body, base_status, base_len,
                               base_text)


def _secret_file_proof(path: str, body: str) -> str:
    """Content proof that a sensitive file is REALLY exposed, or "".

    A 403 block page or a redirect is not exposure — Cloudflare and friends
    serve those for every secret-looking path. Only a 200 with matching
    content counts. Callers must check status == 200 first.
    """
    low_path = (path or "").lower()
    seg = low_path.rsplit("/", 1)[-1]
    text = body or ""
    if ".git" in low_path or seg in ("head", "config"):
        if text.lstrip().startswith("ref:"):
            return "git ref disclosed"
    if seg == ".env" or ".env." in seg or seg.endswith(".env"):
        keys = re.findall(r"(?m)^[A-Z_][A-Z0-9_]{1,30}\s*=", text)
        if len(set(keys)) >= 2:
            return f"{len(set(keys))} KEY= assignments readable"
    return ""


def _probe_dir(session, base: str, path: str, timeout: int,
               base_status: int, base_len: int, base_text: str = "") -> Finding | None:
    url = base + "/" + path.lstrip("/")
    got = _get(session, url, timeout)
    if not got:
        return None
    status, body, _ = got
    return _verdict_dir(base, path, status, body or "", base_status,
                        base_len, base_text)


def _verdict_dir(base: str, path: str, status: int, body: str,
                 base_status: int, base_len: int, base_text: str = "") -> Finding | None:
    """Judge a fetched response: same rules for the Python and Go paths.

    Fetch lives wherever the caller got it (session GET or go-worker
    fetch-batch); the verdict never depends on who fetched, so FP rules
    cannot drift between the two engines.
    """
    url = base + "/" + path.lstrip("/")
    if status == 404:
        return None
    # soft-404: same as baseline means filtered (status + size + similarity)
    if status == 200 and _looks_like_baseline(status, body or "", base_status,
                                             base_len, base_text):
        return None
    if status in (200, 301, 302, 307, 308, 401, 403):
        is_admin = bool(ADMIN_HINT.search(path) or (body and ADMIN_HINT.search(body[:2000] or "")))
        pl = path.lower()
        seg = pl.rsplit("/", 1)[-1]  # nested paths like /admin/web.config
        # exact secret files: 200 + content proof, nothing less. A 403 here
        # is usually a WAF block page, not an exposed file.
        if path in (".git/HEAD", ".env"):
            if status == 200:
                proof = _secret_file_proof(path, body or "")
                if proof:
                    return Finding(title=f"Critical File Exposure: {path}", severity="CRITICAL",
                                   detail=f"HTTP 200, {proof}", url=url,
                                   confidence="High")
                return Finding(title=f"Sensitive File (unverified content): {path}",
                               severity="MEDIUM",
                               detail="HTTP 200 but content doesn't validate; verify manually",
                               url=url, confidence="Medium")
            if status in (401, 403):
                return Finding(title=f"Restricted Area: {path}", severity="INFO",
                               detail=f"HTTP {status} (access controlled, path exists)", url=url,
                               confidence="Medium")
            return Finding(title=f"Redirect: {path}", severity="INFO",
                           detail=f"HTTP {status}", url=url,
                           confidence="High")
        # smart-tech: secret/config/backup basenames — 200 only. A 401/403
        # or redirect proves control/absence, not exposure.
        if status == 200 and (
                seg.endswith((".env", ".sql", ".bak", ".old", ".zip", ".tar.gz"))
                or seg in ("package.json", "composer.json", ".npmrc", "web.config",
                           ".htaccess", ".htpasswd", ".git", "head", "config")
                or "wp-config" in seg or seg == "web.xml" or seg == "env"):
            return Finding(title=f"Critical File Exposure: {path}", severity="CRITICAL",
                           detail=f"HTTP {status}", url=url,
                           confidence="High")
        # admin / login / dashboard variants (incl. TR paths, matched literally)
        if ("admin" in pl or "login" in pl or "dashboard" in pl or "panel" in pl
                or "phpmyadmin" in pl or "yonetim" in pl or "giris" in pl):
            if status in (200, 401, 403) or is_admin:
                return Finding(title="Admin Panel discovered", severity="INFO",
                               detail=f"HTTP {status}" + (" (login form)" if is_admin else ""),
                               url=url,
                               confidence="High")
        # forbidden but confirmed present: controlled, not exposed
        if status in (401, 403):
            return Finding(title=f"Restricted Area: {path}", severity="INFO",
                           detail=f"HTTP {status} (access controlled, path exists)", url=url,
                           confidence="Medium")
        # sensitive-looking path served with 200: medium
        if status == 200 and SENSITIVE_HINT.search(pl):
            return Finding(title=f"Sensitive Directory: {path}", severity="MEDIUM",
                           detail=f"HTTP {status}", url=url,
                           confidence="Medium")
        # ordinary page / redirect: low-value info, not noise
        if status == 200:
            return Finding(title=f"General Page: {path}", severity="INFO",
                           detail=f"HTTP {status}", url=url,
                           confidence="High")
        return Finding(title=f"Redirect: {path}", severity="INFO",
                       detail=f"HTTP {status}", url=url,
                       confidence="High")
    return None


@register_check("robots", "robots.txt + Disallow harvesting", order=20)
def check_robots(session, base: str, timeout: int) -> tuple[list[Finding], list[str]]:
    """Return robots.txt + Disallows (fed into dir-brute)."""
    got = _get(session, base + "/robots.txt", timeout)
    if not got or got[0] != 200 or "disallow" not in (got[1] or "").lower():
        return [], []
    body = got[1]
    disallows = re.findall(r'Disallow:\s*(\S+)', body, re.I)[:20]
    f = Finding(title="robots.txt Found", severity="INFO",
                detail=f"{len(disallows)} disallows: {', '.join(disallows[:8])}",
                url=base + "/robots.txt", evidence=body[:200],
                confidence="High")
    extra = [d for d in disallows if d.startswith("/") and len(d) > 1]
    return [f], extra


def _go_fetchable(session):
    """(headers, cookies) or None when the Go fetch path must not run.

    Proxy routing and disabled TLS verification live in the Python session;
    the worker speaks plain HTTPS. A configured --delay means sequential
    politeness, which concurrent fan-out cannot honor. Auth cookies travel
    explicitly with the batch; when the net posture differs, fail closed
    to the Python path.
    """
    try:
        from core.net import get_context, proxies, tls_verify
        if proxies() or not tls_verify():
            return None
        if get_context().delay:
            return None
    except Exception:
        pass
    try:
        from core.goworker import session_creds
        return session_creds(session)
    except Exception:
        return None


@register_check("smart-dirs", "Smart dir-brute (tech wordlist)", order=30)
def dir_brute(session, base: str, timeout: int, threads: int,
              extra_paths: list[str] | None = None, verbose: bool = False,
              wordlist: list[str] | None = None,
              techs: list[str] | None = None,
              ctx: dict | None = None) -> list[Finding]:
    base_list = wordlist or wordlist_for_techs(techs)
    if (ctx or {}).get("go_worker"):
        # Hybrid rank: Go worker orders tech-matching paths first; the
        # bridge falls back to the identical Python rule when the binary
        # is missing, so results never change, only who sorts them.
        try:
            from core.goworker import rank_wordlist as _go_rank
            base_list = _go_rank(techs, base_list, 80, timeout=timeout)
        except Exception:
            pass
    paths = list(dict.fromkeys(base_list + (extra_paths or [])))[:80]
    bs, bl, bt = _baseline_404(session, base, timeout)
    out: list[Finding] = []
    if (ctx or {}).get("go_worker"):
        # Hybrid fetch: ONE worker round-trip fans out to N GETs; every
        # response is judged by _verdict_dir (same rules as _probe_dir).
        # Any worker failure or 429 falls back to the Python path below,
        # which owns retry/calm-down semantics.
        try:
            from core.goworker import GoworkerError, fetch_batch as _go_fetch
            creds = _go_fetchable(session)
            if creds is None:
                raise GoworkerError("net posture needs the Python session")
            headers, cookies = creds
            fetched = _go_fetch([base + "/" + p.lstrip("/") for p in paths],
                                headers=headers, cookies=cookies,
                                timeout=timeout, workers=max(1, threads))
            if any(fr.get("status") == 429 for fr in fetched):
                raise GoworkerError("rate-limited: Python path owns 429")
            if not any(fr.get("status") and not fr.get("error") for fr in fetched):
                raise GoworkerError("all probes degraded: nothing to judge")
            for p, fr in zip(paths, fetched):
                if fr.get("error") or not fr.get("status"):
                    # Burst-dropped probe: exact Python retry, never a gap.
                    r = _probe_dir(session, base, p, timeout, bs, bl, bt)
                    if r:
                        out.append(r)
                        if ctx is not None:
                            ctx.setdefault("found_paths", []).append(r.url)
                        if verbose:
                            print(warn(f"    [!] {r.severity}: {r.title} -> {r.url}"))
                    continue
                r = _verdict_dir(base, p, fr["status"], fr["snippet"],
                                 bs, bl, bt)
                if r:
                    out.append(r)
                    if ctx is not None:
                        ctx.setdefault("found_paths", []).append(r.url)
                    if verbose:
                        print(warn(f"    [!] {r.severity}: {r.title} -> {r.url}"))
            return out
        except Exception:
            out = []
    from core.spinner import spin
    with spin(f"  [*] Brute-forcing {len(paths)} paths...", enabled=not verbose):
        with ThreadPoolExecutor(max_workers=max(1, threads)) as ex:
            fut = {ex.submit(_probe_dir, session, base, p, timeout, bs, bl, bt): p
                   for p in paths}
            for f in as_completed(fut):
                try:
                    r = f.result()
                    if r:
                        out.append(r)
                        if ctx is not None:
                            ctx.setdefault("found_paths", []).append(r.url)
                        if verbose:
                            print(warn(f"    [!] {r.severity}: {r.title} -> {r.url}"))
                except Exception:
                    pass
    return out


@register_check("smart-recurse", "Recurse under found paths + backup extensions", order=31)
def smart_recurse(session, base: str, timeout: int, threads: int = 10,
                 ctx: dict | None = None, verbose: bool = False) -> list[Finding]:
    """Parent paths of dir-brute hits: suffixes for files, extra paths for dirs."""
    from urllib.parse import urlparse
    all_found = list(dict.fromkeys((ctx or {}).get("found_paths", [])))

    def _prio(u: str) -> int:
        seg = urlparse(u).path.rsplit("/", 1)[-1].lower()
        if "." not in seg:
            return 0  # dirs first (keeps thread order stable)
        if seg.endswith((".php", ".js", ".env", ".json", ".config")):
            return 1
        return 2

    found = sorted(all_found, key=_prio)[:6]
    if not found:
        return []
    probes: list[str] = []
    for u in found:
        path = urlparse(u).path
        seg = path.rsplit("/", 1)[-1]
        if "." in seg:  # file -> backup variants
            probes += [path + s for s in RECURSE_FILE_SUFFIX]
        else:  # dir -> go deeper + mutate the dirname itself
            d = path if path.endswith("/") else path + "/"
            probes += [d + x for x in RECURSE_DIR_EXTRA]
            bare = path.rstrip("/")
            probes += [bare + s for s in RECURSE_DIR_MUTATIONS]
            probes += [bare + e for e in RECURSE_DIR_FILE_EXT]
    probes = list(dict.fromkeys(probes))[:15]
    if not probes:
        return []
    out: list[Finding] = []
    bs, bl, bt = _baseline_404(session, base, timeout)
    from core.spinner import spin
    with spin(f"  [*] Recursing under {len(found)} paths...", enabled=not verbose):
        with ThreadPoolExecutor(max_workers=max(1, min(threads, len(probes)))) as ex:
            fut = {ex.submit(_probe_dir, session, base, p.lstrip("/"),
                             timeout, bs, bl, bt): p for p in probes}
            for f in as_completed(fut):
                try:
                    r = f.result()
                    if r and "RECURSE" not in r.title:
                        r.title = f"{r.title} (recursive)"
                        out.append(r)
                        if verbose:
                            print(warn(f"    [!] recurse: {r.title} -> {r.url}"))
                except Exception:
                    pass
    return out


__all__ = [
    "check_upload",
    "_baseline_404", "_looks_like_baseline", "_secret_file_proof",
    "_probe_dir", "_verdict_dir",
    "check_robots", "dir_brute", "smart_recurse",
]

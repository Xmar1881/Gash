"""Go worker bridge: Python orchestrator -> gash-worker binary (subprocess+JSON).

Jobs run through a persistent `--stream` worker when available (one spawn
per scan instead of one per batch); single-shot spawn is the automatic
fallback. GASH_GO_STREAM=0 forces single-shot. No new registered check,
so the check count stays put. When the binary is missing the bridge
degrades to "unavailable" instead of failing the scan.
"""
from __future__ import annotations

import atexit
import json
import os
import shutil
import subprocess
import threading
from pathlib import Path

from core.scan._shared import Finding

SEVERITIES = {"CRITICAL", "MEDIUM", "LOW", "INFO"}

JOBS = ("ping", "tech-fingerprint", "rank-wordlist", "prioritize-urls",
        "fetch-batch")


class GoworkerError(Exception):
    """Binary missing, timeout, or malformed worker output."""


class WorkerSession:
    """One persistent `gash-worker --stream` process (amortized spawn).

    Thread-safe: one round-trip at a time under a lock (the worker fans
    out internally, so serialization here costs nothing). A dead process
    surfaces as GoworkerError and the pool drops it back to single-shot.
    Blocking reads are bounded by the worker itself: every job answers
    (fetch jobs carry client timeouts, pure jobs are instant), and EOF
    means the process died.
    """

    def __init__(self, binpath: str):
        self._bin = binpath
        self._proc: subprocess.Popen | None = None
        self._lock = threading.Lock()
        self.pid: int | None = None

    def start(self) -> bool:
        """Spawn + verify with a ping. False when unusable."""
        try:
            proc = subprocess.Popen(
                [self._bin, "--stream"], stdin=subprocess.PIPE,
                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                text=True, encoding="utf-8", errors="replace", bufsize=1,
            )
        except OSError:
            return False
        self._proc = proc
        self.pid = proc.pid
        try:
            res = self.run({"job": "ping"}, timeout=10)
        except GoworkerError:
            self.close()
            return False
        return bool(res.get("pong", True))

    @property
    def alive(self) -> bool:
        proc = self._proc
        return proc is not None and proc.poll() is None

    def run(self, job: dict, timeout: int = 10) -> dict:
        """One job through the stream. Raises GoworkerError on any failure."""
        proc = self._proc
        if proc is None or proc.poll() is not None:
            raise GoworkerError("go worker stream is down")
        _name, payload = _build_payload(job, timeout)
        try:
            with self._lock:
                assert proc.stdin is not None and proc.stdout is not None
                proc.stdin.write(payload + "\n")
                proc.stdin.flush()
                line = proc.stdout.readline()
        except (OSError, ValueError, AssertionError) as e:
            raise GoworkerError(f"go worker stream I/O failed: {e}") from e
        if not line:
            raise GoworkerError("go worker stream closed (EOF)")
        try:
            res = json.loads(line)
        except ValueError as e:
            raise GoworkerError("go worker bad JSON in stream") from e
        if not isinstance(res, dict) or not res.get("ok"):
            raise GoworkerError(
                f"go worker error: {str(res.get('error', res))[:200]}"
                if isinstance(res, dict) else "go worker bad result")
        return res

    def close(self) -> None:
        proc, self._proc = self._proc, None
        self.pid = None
        if proc is None:
            return
        try:
            if proc.poll() is None:
                try:
                    if proc.stdin:
                        proc.stdin.close()
                except Exception:
                    pass
                proc.wait(timeout=3)
        except Exception:
            try:
                proc.kill()
            except Exception:
                pass


_POOL: dict = {"sess": None, "lock": threading.Lock()}
_POOL_CLOSED = False


def _close_pool() -> None:
    global _POOL_CLOSED
    _POOL_CLOSED = True
    sess, _POOL["sess"] = _POOL.get("sess"), None
    if sess is not None:
        try:
            sess.close()
        except Exception:
            pass


atexit.register(_close_pool)


def _stream_enabled() -> bool:
    return os.environ.get("GASH_GO_STREAM", "1") != "0"


def session() -> WorkerSession | None:
    """Shared live stream session, or None (disabled/missing/dead)."""
    if _POOL_CLOSED or not _stream_enabled():
        return None
    with _POOL["lock"]:
        sess = _POOL.get("sess")
        if sess is not None and sess.alive:
            return sess
        if sess is not None:
            try:
                sess.close()
            except Exception:
                pass
            _POOL["sess"] = None
        binpath = binary_path()
        if not binpath:
            return None
        fresh = WorkerSession(binpath)
        if not fresh.start():
            return None
        _POOL["sess"] = fresh
        return fresh


def _drop_session() -> None:
    with _POOL["lock"]:
        sess, _POOL["sess"] = _POOL.get("sess"), None
    if sess is not None:
        try:
            sess.close()
        except Exception:
            pass


def close_session() -> None:
    """Drop the shared stream session (test isolation, clean shutdown)."""
    _drop_session()


def binary_path() -> str | None:
    """Resolve the worker binary: env -> repo go/bin -> PATH, else None."""
    env = os.environ.get("GASH_GO_BIN", "").strip()
    if env:
        return env
    exe = "gash-worker.exe" if os.name == "nt" else "gash-worker"
    try:
        repo_bin = Path(__file__).resolve().parent.parent / "go" / "bin" / exe
    except Exception:
        repo_bin = None
    if repo_bin is not None and repo_bin.is_file():
        return str(repo_bin)
    found = shutil.which("gash-worker")
    return found


def available() -> bool:
    """True when a worker binary resolves and is executable."""
    p = binary_path()
    if not p:
        return False
    if os.pathsep not in p and shutil.which(p) is None and not os.path.isfile(p):
        return False
    return os.path.isfile(p) or shutil.which(p) is not None


def _build_payload(job: dict, timeout: int) -> tuple[str, str]:
    """(job name, stdin JSON) for one job. Raises GoworkerError on bad job."""
    name = (job or {}).get("job", "")
    if name not in JOBS:
        raise GoworkerError(f"unknown job: {name!r}")
    return name, json.dumps({
        "job": name,
        "target": str((job or {}).get("target", "") or ""),
        "html": str((job or {}).get("html", "") or "")[:6000],
        "headers": dict((job or {}).get("headers", {}) or {}),
        "timeout": int(timeout),
        "techs": [str(t) for t in ((job or {}).get("techs", []) or [])],
        "paths": [str(p) for p in ((job or {}).get("paths", []) or [])],
        "urls": [str(u) for u in ((job or {}).get("urls", []) or [])],
        "limit": int((job or {}).get("limit", 0) or 0),
        "requests": [
            {"url": str(r.get("url", "")),
             "method": str(r.get("method", "GET") or "GET"),
             "body": str(r.get("body", "") or ""),
             "content_type": str(r.get("content_type", "") or ""),
             "form": {str(k): str(v) for k, v in
                      (dict(r.get("form", {}) or {})).items()},
             "headers": {str(k): str(v) for k, v in
                         (dict(r.get("headers", {}) or {})).items()}}
            for r in ((job or {}).get("requests", []) or [])
            if isinstance(r, dict)
        ],
        "workers": int((job or {}).get("workers", 0) or 0),
        "snippet_bytes": int((job or {}).get("snippet_bytes", 0) or 0),
        "max_body": int((job or {}).get("max_body", 0) or 0),
    })


def _check_result(res: object) -> dict:
    """Shared Result validation for both transports."""
    if not isinstance(res, dict) or not res.get("ok"):
        raise GoworkerError(f"go worker error: {str(res.get('error', res))[:200]}"
                            if isinstance(res, dict) else "go worker bad result")
    findings = res.get("findings", [])
    if not isinstance(findings, list):
        raise GoworkerError("go worker bad result: findings not a list")
    return res


def run_job(job: dict, timeout: int = 10) -> dict:
    """One job via the stream session, else single-shot spawn.

    Same contract either way; transport failures degrade to the caller's
    Python fallback via GoworkerError.
    """
    name, payload = _build_payload(job, timeout)
    sess = session()
    if sess is not None:
        try:
            return _check_result(sess.run(job, timeout=timeout))
        except GoworkerError:
            _drop_session()
    binpath = binary_path()
    if not binpath:
        raise GoworkerError("go worker binary not found (GASH_GO_BIN or go/bin/)")
    try:
        proc = subprocess.run(
            [binpath], input=payload, capture_output=True, text=True,
            encoding="utf-8", errors="replace",
            timeout=max(1, int(timeout)),
        )
    except subprocess.TimeoutExpired as e:
        raise GoworkerError(f"go worker timed out ({name})") from e
    except OSError as e:
        raise GoworkerError(f"go worker spawn failed: {e}") from e
    if proc.returncode != 0:
        raise GoworkerError(f"go worker exit {proc.returncode}: {(proc.stderr or '')[:200]}")
    try:
        res = json.loads(proc.stdout or "")
    except (ValueError, TypeError) as e:
        raise GoworkerError(f"go worker bad JSON: {(proc.stdout or '')[:200]}") from e
    return _check_result(res)


def findings_from_go(items: list, url_default: str = "") -> list[Finding]:
    """Map wire findings -> Finding (kwargs-only, severity-whitelisted)."""
    out: list[Finding] = []
    for it in items or []:
        if not isinstance(it, dict):
            continue
        sev = str(it.get("severity", "LOW") or "LOW").upper()
        if sev not in SEVERITIES:
            sev = "LOW"
        out.append(Finding(
            title=str(it.get("title", "Go worker note") or "Go worker note")[:120],
            severity=sev,
            detail=str(it.get("detail", "") or "")[:2000],
            url=str(it.get("url", "") or url_default or ""),
            evidence=str(it.get("evidence", "") or "")[:300],
            confidence=str(it.get("confidence", "Low") or "Low")[:12],
            check="go-worker",
        ))
    return out


def ping(timeout: int = 10) -> bool:
    """Liveness probe; False when the binary is missing or unhealthy."""
    try:
        res = run_job({"job": "ping"}, timeout=timeout)
    except GoworkerError:
        return False
    return bool(res.get("pong", True)) and bool(res.get("ok"))


def _rank_fallback(techs: list | None, paths: list | None, limit: int) -> list[str]:
    """Exact mirror of Go rankWordlist (pinned by go/testdata/rank_wordlist.json)."""
    if not limit or limit <= 0:
        limit = 80
    low = [t.lower().strip() for t in (techs or []) if str(t).strip()]
    seen: set[str] = set()
    hit: list[str] = []
    rest: list[str] = []
    for p in paths or []:
        if p in seen:
            continue
        seen.add(p)
        pl = str(p).lower()
        (hit if any(t in pl for t in low) else rest).append(p)
    return (hit + rest)[:max(1, limit)]


def _prioritize_fallback(urls: list | None, limit: int) -> list[str]:
    """Exact mirror of Go prioritizeURLs (pinned by go/testdata/prioritize_urls.json)."""
    if not limit or limit <= 0:
        limit = 25
    seen: set[str] = set()
    with_query: list[str] = []
    plain: list[str] = []
    for u in urls or []:
        if u in seen:
            continue
        seen.add(u)
        (with_query if "?" in str(u) else plain).append(u)
    return (with_query + plain)[:max(1, limit)]


def rank_wordlist(techs: list | None, paths: list | None, limit: int = 80,
                  timeout: int = 10) -> list[str]:
    """Tech-matching paths first via the Go worker; Python fallback on error."""
    try:
        res = run_job({"job": "rank-wordlist", "techs": list(techs or []),
                       "paths": list(paths or []), "limit": int(limit or 0)},
                      timeout=timeout)
        out = res.get("paths", [])
        if isinstance(out, list):
            return [str(p) for p in out]
    except GoworkerError:
        pass
    return _rank_fallback(techs, paths, int(limit or 0))


def prioritize_urls(urls: list | None, limit: int = 25,
                    timeout: int = 10) -> list[str]:
    """Query-bearing URLs first via the Go worker; Python fallback on error."""
    try:
        res = run_job({"job": "prioritize-urls", "urls": list(urls or []),
                       "limit": int(limit or 0)}, timeout=timeout)
        out = res.get("urls", [])
        if isinstance(out, list):
            return [str(u) for u in out]
    except GoworkerError:
        pass
    return _prioritize_fallback(urls, int(limit or 0))


def session_creds(session) -> tuple[dict, dict]:
    """Best-effort (headers, cookies) from a requests-like session.

    Auth cookies must travel to the worker: without them gated areas would
    scan as anonymous on the Go path (silent downgrade). Fake/test sessions
    without jars yield ({}, {}) instead of raising.
    """
    headers: dict = {}
    try:
        jar_h = getattr(session, "headers", None) or {}
        ua = jar_h.get("User-Agent", "") if hasattr(jar_h, "get") else ""
        if ua:
            headers["User-Agent"] = str(ua)
    except Exception:
        pass
    cookies: dict = {}
    try:
        jar = getattr(session, "cookies", None)
        if jar is not None:
            for c in jar:
                cookies[str(c.name)] = str(c.value)
    except Exception:
        pass
    return headers, cookies


def fetch_batch(requests: list | None, headers: dict | None = None,
                cookies: dict | None = None, timeout: int = 8,
                workers: int = 20, snippet_bytes: int = 4096,
                max_body: int = 2 << 20) -> list[dict]:
    """One round-trip: N requests fanned out in Go, input order kept.

    Each item is a URL string (GET) or a dict {url, method, body,
    content_type, form, headers}. Returns per-request {url, final_url,
    status, length, snippet, truncated, error}. Anything worker-side
    (missing binary, bad output) raises GoworkerError — the caller falls
    back to the Python path, never degrading silently to fewer probes.
    """
    norm: list[dict] = []
    for r in requests or []:
        if isinstance(r, str):
            if r.strip():
                norm.append({"url": r})
        elif isinstance(r, dict) and str(r.get("url", "") or "").strip():
            item: dict = {"url": str(r["url"])}
            if r.get("method"):
                item["method"] = str(r["method"]).upper()[:8]
            if r.get("body") is not None:
                item["body"] = str(r["body"])[:1 << 20]
            if r.get("content_type"):
                item["content_type"] = str(r["content_type"])[:128]
            if isinstance(r.get("form"), dict):
                item["form"] = {str(k): str(v)[:4000]
                                for k, v in list(r["form"].items())[:40]}
            if isinstance(r.get("headers"), dict):
                item["headers"] = {str(k): str(v)[:2000]
                                   for k, v in list(r["headers"].items())[:20]}
            norm.append(item)
    if not norm:
        return []
    if len(norm) > 200:
        raise GoworkerError("too many requests for fetch-batch (cap 200)")
    from core.net import pace_many
    pace_many(len(norm))  # budget/cancel fail-closed before firing
    base = dict(headers or {})
    if cookies:
        base["Cookie"] = "; ".join(f"{k}={v}" for k, v in cookies.items())
    workers = max(1, min(int(workers or 20), 32))
    timeout = max(1, int(timeout or 8))
    snippet_bytes = max(512, int(snippet_bytes or 4096))
    max_body = max(4096, int(max_body or (2 << 20)))
    waves = (len(norm) + workers - 1) // workers
    proc_timeout = min(timeout * waves + 15, 300)
    wire = []
    for r in norm:
        merged = dict(base)
        merged.update(r.get("headers", {}))
        wire.append({"url": r["url"],
                     "method": r.get("method", "GET"),
                     "body": r.get("body", ""),
                     "content_type": r.get("content_type", ""),
                     "form": r.get("form", {}),
                     "headers": merged})
    res = run_job({"job": "fetch-batch", "requests": wire,
                   "timeout": timeout, "workers": workers,
                   "snippet_bytes": snippet_bytes, "max_body": max_body},
                  timeout=proc_timeout)
    fetches = res.get("fetches", [])
    if not isinstance(fetches, list) or len(fetches) != len(norm):
        raise GoworkerError("go worker bad result: fetches misaligned")
    out: list[dict] = []
    for f, r in zip(fetches, norm):
        if not isinstance(f, dict):
            raise GoworkerError("go worker bad result: fetch not an object")
        out.append({
            "url": str(f.get("url", "") or r["url"]),
            "final_url": str(f.get("final_url", "") or ""),
            "status": int(f.get("status", 0) or 0),
            "length": int(f.get("length", 0) or 0),
            "snippet": str(f.get("snippet", "") or ""),
            "truncated": bool(f.get("truncated", False)),
            "error": str(f.get("error", "") or ""),
        })
    return out


__all__ = [
    "SEVERITIES", "JOBS", "GoworkerError", "WorkerSession",
    "binary_path", "available", "run_job", "findings_from_go", "ping",
    "rank_wordlist", "prioritize_urls",
    "session_creds", "fetch_batch",
    "session", "close_session",
]

"""Scan engine: wordlist loading + run_scan orchestration."""
from __future__ import annotations

import time

from core.colors import success, info, warn, DIM, RESET
from core.knowledge import enrich
from core.net import get_context, scan_dead, ScanBudgetExceeded, PartialResults
from core.recon import normalize_target
from core.scan.discovery import _build_probe_pool
from core.scan.http import _session, _fetch_base
from core.scan._shared import Finding  # noqa: F401 — re-exported via hub


def load_wordlist(path: str | None) -> list[str] | None:
    """Read a wordlist file. None when missing/empty (built-in list is used)."""
    if not path:
        return None
    try:
        with open(path, encoding="utf-8", errors="ignore") as f:
            items = [l.strip().lstrip("/") for l in f if l.strip() and not l.startswith("#")]
        return items[:200] or None
    except OSError:
        return None


def run_scan(target: str, threads: int = 20, timeout: int = 8,
              verbose: bool = False, wordlist: list[str] | None = None,
              deep: bool = True, auth=None,
              skip_checks: set[str] | None = None,
              max_pages: int = 8, crawl_depth: int = 2,
              no_crawl: bool = False, dom: bool = False,
              blind_callback: str | None = None,
              scope_hosts: set[str] | None = None,
              oob=None, auth_b=None, spa: bool = False,
              max_xss_urls: int = 25,
              health: dict | None = None,
              js_files: int = 5,
              swagger_paths: int = 20,
              browser_discovery: bool = False,
               browser_caps: dict | None = None,
               auth_c=None, go_worker: bool = False,
               http3: bool = False, insecure: bool = False) -> list[Finding]:
    import core.advanced  # noqa: F401 — registers checks with the registry
    import core.domxss  # noqa: F401 — registers the dom-xss check
    import core.webchecks  # noqa: F401 — registers modern web checks
    from core.registry import run_checks
    from core.crawler import crawl
    from core.net import enter_scan_scope, exit_scan_scope
    # Hub indirection: tests monkeypatch core.scanner._session/_fetch_base.
    # Resolve via the hub at call time so hub patches keep working.
    import core.scanner as _hub
    _mk_session = getattr(_hub, "_session", _session)
    _fetch_hub = getattr(_hub, "_fetch_base", _fetch_base)
    _scope_token = enter_scan_scope()
    try:
        t0 = time.time()
        _, base0 = normalize_target(target)
        session = _mk_session(timeout, auth)
        session_b = None
        if auth_b is not None and (getattr(auth_b, "cookies", None)
                                   or getattr(auth_b, "headers", None)):
            session_b = _mk_session(timeout, auth_b)
        session_c = None
        if auth_c is not None and (getattr(auth_c, "cookies", None)
                                   or getattr(auth_c, "headers", None)):
            session_c = _mk_session(timeout, auth_c)

        try:
            html, base, headers = _fetch_hub(session, base0, timeout, scope_hosts)
        except ScanBudgetExceeded as e:
            raise PartialResults([], str(e))
        if not html and verbose:
            print(warn("    [i] base page unreachable, scanning blind"))

        # session validity: stale cookies silently downgrade the whole scan
        # to anonymous — say so loudly instead of pretending coverage.
        session_valid = None
        try:
            from core.authz import session_looks_valid
            has_auth = bool((getattr(auth, "cookies", None) or {}) or
                            (getattr(auth, "headers", None) or {})) \
                if auth is not None else False
            if has_auth:
                session_valid = session_looks_valid(session, base, timeout)
                if session_valid is False:
                    print(warn("  [!] Session looks EXPIRED (base answers with a "
                               "login gate) — gated areas will scan as anonymous. "
                               "Refresh --cookie and re-run."))
                elif verbose and session_valid is True:
                    print(info("  [i] session valid (base answers 200, no login wall)"))
        except ScanBudgetExceeded:
            raise
        except Exception:
            session_valid = None

        # --- light crawler (same-origin BFS) ---
        crawl_stats: dict = {}
        pool_stats: dict = {}
        spa_stats: dict = {}
        crawl_auth: dict = {}
        if no_crawl:
            pages = {base + "/": html or ""}
        else:
            print(info(f"  [*] Crawling (max {max_pages} pages, depth {crawl_depth})..."))
            try:
                pages = crawl(session, base, html, timeout, max_pages, crawl_depth,
                              scope_hosts=scope_hosts, js_files=js_files,
                              swagger_paths=swagger_paths, stats=crawl_stats,
                              auth=crawl_auth, go_worker=go_worker)
            except ScanBudgetExceeded as e:
                print(warn(f"  [!] {e}"))
                pages = {base + "/": html or ""}
            if verbose:
                print(f"    {DIM}{len(pages)} pages collected{RESET}")
            if crawl_auth.get("walls"):
                print(warn(f"  [!] {len(crawl_auth['walls'])} login wall(s) hit "
                           "during crawl — gated areas need a valid session"))

        urls = _build_probe_pool(pages, base, limit=max_xss_urls,
                                 stats=pool_stats)
        browser_graph: dict = {}
        runtime: dict = {}
        api_targets: list = []
        if not no_crawl:
            try:
                from core.crawler import fetch_swagger_spec
                from core.api_params import swagger_api_targets
                spec = fetch_swagger_spec(session, base, timeout)
                if spec:
                    api_targets = swagger_api_targets(spec, base, limit=10)
                    if verbose and api_targets:
                        print(f"    {DIM}{len(api_targets)} API body targets "
                              f"(OpenAPI){RESET}")
            except ScanBudgetExceeded:
                raise
            except Exception as e:
                if verbose:
                    print(warn(f"  [-] API target build skipped: {str(e)[:80]}"))
        if spa or browser_discovery:
            try:
                from core.xss_spa import runtime_discover
                print(info("  [*] SPA runtime discovery (headless, read-only)..."))
                caps = browser_caps if isinstance(browser_caps, dict) else {}
                runtime = runtime_discover(
                    base, timeout, scope_hosts=scope_hosts, verbose=verbose,
                    capture_traffic=browser_discovery, caps={
                        "visits": caps.get("spa_visits", 2),
                        "traffic": caps.get("traffic_cap", 40),
                        "routes": caps.get("route_cap", 20),
                        "ws": caps.get("ws_cap", 10),
                        "api": caps.get("api_cap", 15),
                        "urls": 30})
                spa_urls = list((runtime or {}).get("urls", [])) + \
                    list((runtime or {}).get("api", []))
                spa_params = list((runtime or {}).get("params", []))
                if browser_discovery:
                    browser_graph = {
                        "traffic": list((runtime or {}).get("traffic", []))[:40],
                        "websockets": list((runtime or {}).get(
                            "websockets", []))[:10],
                        "sse": list((runtime or {}).get("sse", []))[:10],
                        "routes": list((runtime or {}).get("routes", []))[:20],
                    }
                    if verbose and (browser_graph["websockets"]
                                    or browser_graph["sse"]
                                    or browser_graph["routes"]):
                        print(f"    {DIM}browser graph: "
                              f"{len(browser_graph['traffic'])} requests, "
                              f"{len(browser_graph['websockets'])} sockets, "
                              f"{len(browser_graph['sse'])} streams, "
                              f"{len(browser_graph['routes'])} routes{RESET}")
                if spa_urls or spa_params:
                    urls = _build_probe_pool(pages, base, spa_urls=spa_urls,
                                             limit=max_xss_urls,
                                             stats=pool_stats)
                    if verbose and spa_params:
                        print(f"    {DIM}SPA params: {', '.join(spa_params[:8])}{RESET}")
                spa_stats = dict((runtime or {}).get("stats", {}) or {})
                if browser_graph.get("traffic"):
                    # privileged source: real app traffic outranks guesses.
                    from core.api_params import traffic_to_targets
                    try:
                        api_targets = traffic_to_targets(
                            browser_graph["traffic"], base, limit=6
                        ) + api_targets
                        api_targets = api_targets[:10]
                    except Exception:
                        pass
            except ScanBudgetExceeded:
                raise
            except Exception as e:
                if verbose:
                    print(warn(f"  [-] SPA discovery skipped: {str(e)[:100]}"))
        if verbose:
            print(f"    {DIM}{len(urls)} test URLs{RESET}")

        # coverage ledger: discovered vs tested vs truncated. "Not found"
        # and "not tested" stay visibly different in every report.
        try:
            _net = get_context()
            _req_sent, _req_budget = _net.count, _net.max_requests
        except Exception:
            _req_sent, _req_budget = 0, 0
        coverage: dict = {
            "pages_discovered": crawl_stats.get("pages_discovered",
                                                len(pages)),
            "pages_scanned": crawl_stats.get(
                "pages_scanned",
                sum(1 for h in pages.values() if h)),
            "js_files": crawl_stats.get("js_files", 0),
            "swagger_paths": crawl_stats.get("swagger_paths", 0),
            "routes_seen": len((runtime or {}).get("routes", [])),
            "api_seen": len((runtime or {}).get("api", [])),
            "websockets_seen": len((runtime or {}).get("websockets", [])),
            "runtime_visits": int(spa_stats.get("visits", 0)),
            "traffic_seen": int(spa_stats.get("traffic_seen", 0)),
            "login_walls": len(crawl_auth.get("walls", [])),
            "xss_urls_tested": len(urls),
            "pool_seen": int(pool_stats.get("pool_seen", len(urls))),
            "api_targets_discovered": len(api_targets),
            "api_targets_tested": min(len(api_targets), 4),
            "session_valid": session_valid,
            "requests_sent": _req_sent,
            "request_budget": _req_budget,
            "checks_passed": 0, "checks_errored": 0, "checks_skipped": 0,
            "truncated": bool(crawl_stats.get("truncated", False))
            or bool(spa_stats.get("truncated", False))
            or int(pool_stats.get("pool_seen", len(urls))) > len(urls),
        }

        def _cover() -> None:
            if health is None:
                return
            health["checks"] = list(ctx.get("check_status", []))
            try:
                statuses = [c.get("status") for c in health["checks"]]
                coverage["checks_passed"] = sum(
                    1 for s in statuses if s in ("passed", "findings"))
                coverage["checks_errored"] = sum(
                    1 for s in statuses if s in ("error", "aborted"))
                coverage["checks_skipped"] = sum(
                    1 for s in statuses if s == "skipped")
                coverage["requests_sent"] = get_context().count
            except Exception:
                pass
            health["coverage"] = dict(coverage)

        ctx = {"urls": urls, "pages": pages, "html": html, "base": base,
               "headers": headers, "timeout": timeout, "threads": threads,
               "verbose": verbose, "deep": deep, "wordlist": wordlist,
               "techs": [], "extra_paths": [], "dom": dom,
               "blind_callback": blind_callback, "oob": oob,
               "session_b": session_b, "spa": spa,
               "max_xss_urls": max_xss_urls, "js_files": js_files,
               "swagger_paths": swagger_paths,
               "api_targets": api_targets,
               "browser_discovery": browser_discovery,
               "browser_graph": browser_graph,
               "session_c": session_c, "go_worker": go_worker,
               "http3": bool(http3), "insecure": bool(insecure)}
        if go_worker and verbose:
            from core.goworker import available as _go_avail
            print(info(f"    [i] go-worker {'on' if _go_avail() else 'on (binary missing, Python fallback)'}"))
        findings: list[Finding] = []
        try:
            findings += run_checks(session, ctx, skip=skip_checks or set(),
                                   deep=deep, verbose=verbose)
            _cover()
        except PartialResults as e:
            findings = e.findings
            _cover()
            print(warn(f"  [!] {e}"))
            for f in findings:
                enrich(f)
            raise PartialResults(findings, str(e))
        except ScanBudgetExceeded as e:
            _cover()
            print(warn(f"  [!] {e}"))
            for f in findings:
                enrich(f)
            raise PartialResults(findings, str(e))
        if oob is not None:
            try:
                from core.oob import drain
                findings += drain(oob, verbose)
            except Exception as e:
                if verbose:
                    print(warn(f"  [!] OOB drain failed: {e}"))

        # robots Disallow + wordlist overlap can find the same URL twice -> dedupe
        seen, uniq = set(), []
        for f in findings:
            key = (f.title, f.url)
            if key not in seen:
                seen.add(key)
                uniq.append(f)
        findings = uniq

        for f in findings:
            enrich(f)
            # OOB findings are produced after registry checks.  Apply the
            # same local XSS contract to confirmed Blind-XSS callbacks so
            # reports do not depend on which producer created the Finding.
            if ("xss" in (f.title or "").lower()
                    or getattr(f, "check", "") in {
                        "xss-reflected", "xss-errpage", "stored-xss",
                        "dom-xss"}):
                try:
                    from core.xss_triage import (triage_finding,
                                                 vulnerability_finding)
                    if not getattr(f, "triage", None):
                        f.triage = triage_finding(f)
                    if not getattr(f, "vulnerability_finding", None):
                        f.vulnerability_finding = vulnerability_finding(
                            f, f.triage)
                except Exception:
                    pass

        if scan_dead():
            # budget/rate death mid-scan: checks degraded to None instead of
            # raising, so surface it here — partial, never "clean".
            raise PartialResults(findings, "request budget spent or rate limit hit mid-scan")

        elapsed = round(time.time() - t0, 2)
        print(success(f"  [+] SCAN done: {len(findings)} findings ({elapsed}s)"))
        return findings
    finally:
        exit_scan_scope(_scope_token)


__all__ = ["load_wordlist", "run_scan"]

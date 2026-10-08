"""SPA / modern-JS runtime discovery — P3 + browser-traffic profile.

Static crawler (href/form/sitemap) misses routes, forms and API endpoints
that only exist after JavaScript runs (React/Vue/Next). This module adds
an opt-in Playwright pass: load the app, let it boot, then read back the
runtime DOM (links, forms) plus Resource-Timing entries (fetch/XHR URLs
the app actually called).

--browser-discovery goes further: live request/websocket/response
listeners record method + URL + content-type + status (incl. SSE
streams), and a route watcher tracks client-side navigation — the full
endpoint graph feeds the scan pool.

Read-only: no form submits, no clicks that change state. Same-host +
scope enforced. Playwright missing -> {} quietly (static crawl stands).
Pure helpers (no browser) stay unit-testable offline.
"""

from __future__ import annotations

import re
from urllib.parse import urljoin, urlparse

# Interesting param keys for probe-pool prioritization (subset of the
# scanner FUZZ/SSRF/REDIRECT/TRAVERSAL key sets — kept local to avoid a
# scanner import cycle).
HOT_PARAM_KEYS = frozenset({
    "id", "q", "query", "s", "search", "keyword", "name", "term",
    "file", "page", "lang", "redirect", "next", "preview",
    "template", "theme", "url", "uri", "callback", "webhook",
    "feed", "path", "dest", "domain", "host", "continue", "return",
    "link", "src", "u", "destination", "ref", "target", "r",
    "redirect_uri", "redirect_url", "return_url", "callback_url",
    "forward", "goto", "to", "next_url", "sort", "order", "filter",
    "category", "uid", "user_id", "account", "comment", "message",
    "body", "text", "title", "content",
})

_STOPWORDS = frozenset({
    "true", "false", "null", "undefined", "function", "return", "const",
    "import", "export", "default", "script", "style", "div", "span",
    "href", "src", "http", "https",
})

_ROUTE_RE = re.compile(
    r'''(?:router\.push|history\.pushState|this\.\$router\.push|navigate)\s*\(\s*["']([^"']+)["']'''
    r'''|(?:fetch|axios\.(?:get|post|put|delete))\s*\(\s*[`'\"]([^`'\"]+)[`'\"]'''
    r'''|["']((?:/api/|/v\d+/|/graphql)[\w\-/.]{0,60})["']''', re.I)
_PARAM_KEY_RE = re.compile(r'''["']([a-zA-Z][\w]{1,24})["']\s*:''')


def _same_host(url: str, base: str) -> bool:
    try:
        return urlparse(url).hostname == urlparse(base).hostname
    except Exception:
        return False


def extract_spa_routes(html: str, base: str) -> list[str]:
    """Static pre-pass over rendered HTML/embedded state. Max 20, deduped."""
    out: list[str] = []
    body = html or ""

    def _add(raw: str) -> None:
        if not raw or raw.startswith(("#", "mailto:", "javascript:",
                                      "tel:", "data:")):
            return
        full = urljoin(base + "/", raw).split("#")[0]
        if _same_host(full, base) and full not in out:
            out.append(full)

    for a, b, c in _ROUTE_RE.findall(body):
        _add(a or b or c)
        if len(out) >= 20:
            break
    # Next.js boot state lists every page route. Bracket-aware: route
    # params like /user/[id] contain ] themselves, so capture quoted
    # path strings after "pages": [ instead of balancing brackets.
    for m in re.finditer(r'''"pages"\s*:\s*\[''', body):
        region = body[m.end():m.end() + 2000]
        for p in re.findall(r'''["']((?:/|\.\.?/)[^"'<> ]{0,80})["']''', region):
            _add(p.replace("[...slug]", "1").replace("[id]", "1"))
            if len(out) >= 20:
                break
    return out[:20]


def extract_param_names(*texts: str | None) -> list[str]:
    """Param-like identifiers from JS/JSON/HTML blobs. Max 40, deduped."""
    out: list[str] = []
    for text in texts:
        if not text:
            continue
        for m in _PARAM_KEY_RE.finditer(text[:200_000]):
            name = m.group(1)
            if len(name) < 2 or name.lower() in _STOPWORDS:
                continue
            if name not in out:
                out.append(name)
            if len(out) >= 40:
                return out
    return out


def prioritize_urls(urls: list[str]) -> list[str]:
    """Order the probe pool: forms/inputs > hot params > API > rest.

    Stable (ties keep crawl order), deduped. Pure — no requests.
    """
    def _score(u: str) -> int:
        try:
            q = urlparse(u).query
            path = urlparse(u).path.lower()
        except Exception:
            return 0
        s = 0
        if q and "=" in q:
            s += 3
            try:
                from urllib.parse import parse_qs as _pqs
                keys = {k.lower() for k in _pqs(q, keep_blank_values=True)}
                if keys & HOT_PARAM_KEYS:
                    s += 2
            except Exception:
                pass
        if "/api/" in path or "/graphql" in path or "/v1/" in path \
                or "/v2/" in path:
            s += 2
        return s

    uniq = list(dict.fromkeys(urls))
    return sorted(uniq, key=_score, reverse=True)


# Route watcher (injected pre-boot): pushState/replaceState + hashchange
# append to window.__gash_routes. Read back after the app settles.
# IIFE: a bare arrow function would only be defined, never run.
ROUTE_WATCH_JS = """
(() => {
  try {
    window.__gash_routes = [location.pathname];
    const wrap = (o, m) => {
      try {
        const f = o[m];
        o[m] = function() {
          const r = f.apply(this, arguments);
          try { window.__gash_routes.push(location.pathname); } catch (e) {}
          return r;
        };
      } catch (e) {}
    };
    wrap(history, 'pushState');
    wrap(history, 'replaceState');
    window.addEventListener('hashchange', () => {
      try { window.__gash_routes.push(location.pathname + location.hash); }
      catch (e) {}
    });
  } catch (e) {}
})();
"""


def summarize_traffic(entries: list[dict], base: str,
                      scope_hosts: set[str] | None = None,
                      caps: dict | None = None) -> dict:
    """Raw listener records -> pool urls + sockets + streams + graph.

    Pure: same-host/scope filtering, http(s) pool vs ws(s) graph split,
    SSE flagged by content-type. All lists capped (profile-scalable).
    """
    cap = {"pool": 25, "api": 15, "ws": 10, "sse": 10, "graph": 80}
    try:
        for k in cap:
            if caps and int(caps.get(k, 0)) > 0:
                cap[k] = int(caps[k])
    except Exception:
        pass
    from core.discovery import classify_endpoint
    try:
        base_host = (urlparse(base).hostname or "").lower()
    except Exception:
        base_host = ""
    pool: list[str] = []
    api: list[str] = []
    sockets: list[str] = []
    sse: list[str] = []
    graph: list[dict] = []
    seen: set[str] = set()
    for e in entries or []:
        try:
            url = str(e.get("url", "")).split("#")[0]
            method = str(e.get("method", "GET")).upper() or "GET"
        except Exception:
            continue
        if not url or url in seen:
            continue
        try:
            scheme = urlparse(url).scheme.lower()
            host = (urlparse(url).hostname or "").lower()
        except Exception:
            continue
        if not host or host != base_host:
            continue
        if scope_hosts and host not in scope_hosts:
            continue
        seen.add(url)
        rtype = str(e.get("resource", "")).lower()
        resp_ct = str(e.get("resp_ct", "")).lower()
        row = {"url": url[:200], "method": method,
               "resource": rtype or "?",
               "status": e.get("status", "?"),
               "resp_ct": resp_ct[:60] if resp_ct else "?",
               "req_ct": str(e.get("req_ct", "") or "")[:60],
               "post_data": str(e.get("post_data", "") or "")[:500]}
        if scheme in ("ws", "wss"):
            sockets.append(url)
            row["kind"] = "socket"
        elif "text/event-stream" in resp_ct or rtype == "eventsource":
            if url not in sse:
                sse.append(url)
            row["kind"] = "stream"
            if scheme in ("http", "https") and url not in pool:
                pool.append(url)
        elif scheme in ("http", "https"):
            row["kind"] = classify_endpoint(url)
            (api if row["kind"] == "api" else pool).append(url)
        else:
            continue
        graph.append(row)
        if len(graph) >= cap["graph"]:
            break
    return {"pool": pool[:cap["pool"]], "api": api[:cap["api"]],
            "websockets": sockets[:cap["ws"]],
            "sse": sse[:cap["sse"]], "graph": graph}


def runtime_discover(base: str, timeout: int = 8, max_visits: int = 4,
                     scope_hosts: set[str] | None = None,
                     verbose: bool = False,
                     capture_traffic: bool = False,
                     caps: dict | None = None) -> dict:
    """Headless runtime pass -> urls/api/params (+traffic with capture).

    Visits up to caps['visits'] same-host pages (base first), so JS-heavy
    apps contribute routes from more than one screen. All list caps come
    from the coverage profile; `stats` reports seen-vs-kept + truncated
    so reports can say what was NOT covered.
    """
    defaults = {"visits": 2, "urls": 30, "api": 15, "routes": 20,
                "traffic": 40, "ws": 10}
    try:
        defaults.update({k: int(v) for k, v in (caps or {}).items()
                         if k in defaults and int(v) > 0})
    except Exception:
        pass
    caps = defaults
    empty: dict = {"urls": [], "api": [], "params": []}
    try:
        import importlib.util
        if importlib.util.find_spec("playwright.sync_api") is None:
            raise ImportError
    except ImportError:
        if verbose:
            from core.colors import warn
            print(warn("  [-] --spa needs Playwright: py -m pip install playwright; "
                       "py -m playwright install chromium"))
        return empty
    try:
        from playwright.sync_api import sync_playwright
    except Exception as e:
        if verbose:
            from core.colors import warn
            print(warn(f"  [-] SPA discovery skipped: {str(e)[:100]}"))
        return empty
    urls: list[str] = []
    api: list[str] = []
    param_blob: list[str] = []
    records: list[dict] = []
    watched_routes: list[str] = []
    n_visits = max(1, int(caps.get("visits", 2) or 1))
    visits_done = 0

    def _in_scope(full: str) -> bool:
        if not _same_host(full, base):
            return False
        if scope_hosts:
            try:
                return (urlparse(full).hostname or "").lower() in scope_hosts
            except Exception:
                return False
        return True

    try:
        with sync_playwright() as pw:
            browser = pw.chromium.launch(headless=True)
            try:
                page = browser.new_page(ignore_https_errors=True)
                if capture_traffic:
                    try:
                        page.add_init_script(ROUTE_WATCH_JS)
                    except Exception:
                        pass

                    def _on_request(req):
                        try:
                            post_data = ""
                            try:
                                post_data = str(
                                    getattr(req, "post_data", "") or "")[:2048]
                            except Exception:
                                pass
                            headers = {}
                            try:
                                headers = dict(
                                    getattr(req, "headers", {}) or {})
                            except Exception:
                                pass
                            records.append({
                                "url": req.url,
                                "method": getattr(req, "method", "GET"),
                                "resource": (getattr(req, "resource_type", "")
                                             or ""),
                                "req_ct": str(headers.get("content-type", "")
                                              or "")[:80],
                                "post_data": post_data})
                        except Exception:
                            pass

                    def _on_response(resp):
                        try:
                            records.append({
                                "url": resp.url,
                                "method": getattr(
                                    getattr(resp, "request", None),
                                    "method", "GET"),
                                "resource": "",
                                "status": getattr(resp, "status", "?"),
                                "resp_ct": (getattr(resp, "headers", {}) or {})
                                .get("content-type", "")})
                        except Exception:
                            pass

                    def _on_ws(ws):
                        try:
                            records.append({"url": getattr(ws, "url", ""),
                                            "method": "WS",
                                            "resource": "websocket"})
                        except Exception:
                            pass

                    for ev, cb in (("request", _on_request),
                                   ("response", _on_response),
                                   ("websocket", _on_ws)):
                        try:
                            page.on(ev, cb)
                        except Exception:
                            pass
                to_visit = [base + "/"]
                seen_visits: set[str] = set()
                snapshots: list[dict] = []
                while to_visit and visits_done < n_visits:
                    target = to_visit.pop(0)
                    if target in seen_visits:
                        continue
                    seen_visits.add(target)
                    try:
                        page.goto(target,
                                  timeout=(timeout + 10) * 1000,
                                  wait_until="domcontentloaded")
                        page.wait_for_timeout(2500)
                        data = page.evaluate("""() => ({
                          links: Array.from(document.querySelectorAll('a[href]'))
                            .map(a => a.href).slice(0, 40),
                          forms: Array.from(document.forms).map(f => ({
                            action: f.action || location.href,
                            inputs: Array.from(f.elements).map(e => e.name || '')
                              .filter(Boolean).slice(0, 6)
                          })).slice(0, 8),
                          resources: (performance.getEntriesByType('resource') || [])
                            .map(r => r.name).slice(0, 60),
                          nextData: (document.getElementById('__NEXT_DATA__') || {})
                            .textContent || ''
                        })""")
                    except Exception:
                        continue
                    visits_done += 1
                    snapshots.append(data or {})
                    for href in (data or {}).get("links", []) or []:
                        full = str(href).split("#")[0]
                        if _in_scope(full) and full not in urls:
                            urls.append(full)
                            if _in_scope(full) and full not in seen_visits \
                                    and len(to_visit) < n_visits + 4:
                                to_visit.append(full)
                        if len(urls) >= 40:
                            break
                for data in snapshots:
                    for f in (data or {}).get("forms", []) or []:
                        try:
                            action = str(f.get("action", "")) or base + "/"
                            inputs = [str(i) for i in (f.get("inputs", []) or [])
                                      if i][:3]
                            if _in_scope(action) and inputs:
                                from urllib.parse import urlencode
                                sep = "&" if "?" in action else "?"
                                probe = (action.split("#")[0] + sep +
                                         urlencode({inputs[0]: "gash"}))
                                if probe not in urls:
                                    urls.append(probe)
                        except Exception:
                            continue
                for data in snapshots:
                    for res in (data or {}).get("resources", []) or []:
                        r = str(res)
                        if ("/api/" in r or "/graphql" in r or r.endswith(".json")) \
                                and _same_host(r, base) and r not in api:
                            api.append(r.split("#")[0])
                        if len(api) >= caps["api"]:
                            break
                for data in snapshots:
                    nd = str((data or {}).get("nextData", "") or "")
                    if nd:
                        param_blob.append(nd[:50_000])
                        for r in extract_spa_routes(nd, base):
                            if r not in urls:
                                urls.append(r)
                            if len(urls) >= 40:
                                break
                if capture_traffic:
                    try:
                        seen_routes = page.evaluate(
                            "() => (window.__gash_routes || []).slice(0, 40)")
                    except Exception:
                        seen_routes = []
                    for rt in seen_routes or []:
                        full = urljoin(base + "/",
                                       str(rt)).split("#")[0]
                        if _in_scope(full) and full not in urls:
                            watched_routes.append(full)
                            urls.append(full)
                        if len(urls) >= 40:
                            break
            finally:
                try:
                    browser.close()
                except Exception:
                    pass
    except Exception as e:
        if verbose:
            from core.colors import warn
            print(warn(f"  [-] SPA discovery failed: {str(e)[:100]}"))
        return empty
    params = extract_param_names(*param_blob)
    out = {"urls": urls[:caps["urls"]], "api": api[:caps["api"]],
           "params": params[:20],
           "stats": {"visits": visits_done,
                     "traffic_seen": len(records),
                     "routes_seen": len(watched_routes),
                     "truncated": len(urls) > caps["urls"]
                     or len(api) > caps["api"]}}
    if capture_traffic:
        from core.discovery import classify_endpoint
        summary = summarize_traffic(records, base, scope_hosts)
        for u in summary["pool"] + summary["api"]:
            if u not in urls and u not in api:
                (api if classify_endpoint(u) == "api" else urls).append(u)
        out.update({"traffic": summary["graph"][:caps["traffic"]],
                    "websockets": summary["websockets"][:caps["ws"]],
                    "sse": summary["sse"][:10],
                    "routes": watched_routes[:caps["routes"]]})
        out["stats"]["truncated"] = out["stats"]["truncated"] or \
            len(summary["graph"]) > caps["traffic"]
    return out

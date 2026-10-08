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
                      scope_hosts: set[str] | None = None) -> dict:
    """Raw listener records -> pool urls + sockets + streams + graph.

    Pure: same-host/scope filtering, http(s) pool vs ws(s) graph split,
    SSE flagged by content-type. All lists capped.
    """
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
               "resp_ct": resp_ct[:60] if resp_ct else "?"}
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
        if len(graph) >= 80:
            break
    return {"pool": pool[:25], "api": api[:15], "websockets": sockets[:10],
            "sse": sse[:10], "graph": graph}


def runtime_discover(base: str, timeout: int = 8, max_visits: int = 4,
                     scope_hosts: set[str] | None = None,
                     verbose: bool = False,
                     capture_traffic: bool = False) -> dict:
    """Headless runtime pass -> urls/api/params (+traffic with capture).

    capture_traffic (--browser-discovery): live request/websocket/
    response listeners (method + URL + content-type + status, incl. SSE
    and sockets) plus a client-side route watcher. Never raises for
    missing Playwright/Chromium/runtime errors: the static crawler
    result stands on its own.
    """
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
                            records.append({
                                "url": req.url,
                                "method": getattr(req, "method", "GET"),
                                "resource": (getattr(req, "resource_type", "")
                                             or "")})
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
                try:
                    page.goto(base + "/", timeout=(timeout + 10) * 1000,
                              wait_until="domcontentloaded")
                    page.wait_for_timeout(3000)
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
                    return empty
                for href in (data or {}).get("links", []) or []:
                    full = str(href).split("#")[0]
                    if _same_host(full, base) and full not in urls:
                        if scope_hosts:
                            try:
                                host = (urlparse(full).hostname or "").lower()
                            except Exception:
                                continue
                            if host not in scope_hosts:
                                continue
                        urls.append(full)
                    if len(urls) >= 20:
                        break
                for f in (data or {}).get("forms", []) or []:
                    try:
                        action = str(f.get("action", "")) or base + "/"
                        inputs = [str(i) for i in (f.get("inputs", []) or [])
                                  if i][:3]
                        if _same_host(action, base) and inputs:
                            from urllib.parse import urlencode
                            sep = "&" if "?" in action else "?"
                            probe = (action.split("#")[0] + sep +
                                     urlencode({inputs[0]: "gash"}))
                            if probe not in urls:
                                urls.append(probe)
                    except Exception:
                        continue
                for res in (data or {}).get("resources", []) or []:
                    r = str(res)
                    if ("/api/" in r or "/graphql" in r or r.endswith(".json")) \
                            and _same_host(r, base) and r not in api:
                        api.append(r.split("#")[0])
                    if len(api) >= 15:
                        break
                nd = str((data or {}).get("nextData", "") or "")
                if nd:
                    param_blob.append(nd[:50_000])
                    for r in extract_spa_routes(nd, base):
                        if r not in urls:
                            urls.append(r)
                        if len(urls) >= 25:
                            break
                if capture_traffic:
                    try:
                        seen_routes = page.evaluate(
                            "() => (window.__gash_routes || []).slice(0, 20)")
                    except Exception:
                        seen_routes = []
                    for rt in seen_routes or []:
                        full = urljoin(base + "/",
                                       str(rt)).split("#")[0]
                        if _same_host(full, base) and full not in urls:
                            watched_routes.append(full)
                            urls.append(full)
                        if len(urls) >= 30:
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
    out = {"urls": urls[:25], "api": api[:15], "params": params[:20]}
    if capture_traffic:
        from core.discovery import classify_endpoint
        summary = summarize_traffic(records, base, scope_hosts)
        for u in summary["pool"] + summary["api"]:
            if u not in urls and u not in api:
                (api if classify_endpoint(u) == "api" else urls).append(u)
        out.update({"traffic": summary["graph"][:40],
                    "websockets": summary["websockets"],
                    "sse": summary["sse"],
                    "routes": watched_routes[:20]})
    return out

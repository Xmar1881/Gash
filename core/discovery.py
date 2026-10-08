"""Unified discovery pipeline — coverage profiles + canonicalization.

One place for: URL canonicalization (dedupe ?b=1&a=2 vs ?a=2&b=1),
JS endpoint extraction (fetch/axios/XHR/WebSocket/SSE/API clients —
not just /api/), REST path params ({id}, :id, [id]) and endpoint
typing (page vs api). The crawler, the SPA module and the probe-pool
builder all draw from here instead of growing private regexes.

Pure functions (no network) except where a session is passed in;
budgets stay small and explicit.
"""

from __future__ import annotations

import re
from urllib.parse import (urljoin, urlparse, parse_qsl, urlencode,
                          urlunparse)

# Coverage profiles: (max_pages, crawl_depth, max_xss_urls, js_files,
# swagger_paths, spa_visits, traffic_cap, route_cap, ws_cap, api_cap).
# balanced keeps the historic crawl behavior; thorough goes wider and
# says so in the report (truncated flags).
PROFILES: dict[str, dict[str, int]] = {
    "quick": {"max_pages": 4, "crawl_depth": 1, "max_xss_urls": 12,
              "js_files": 3, "swagger_paths": 10, "spa_visits": 1,
              "traffic_cap": 20, "route_cap": 10, "ws_cap": 5,
              "api_cap": 10},
    "balanced": {"max_pages": 12, "crawl_depth": 2, "max_xss_urls": 30,
                 "js_files": 5, "swagger_paths": 20, "spa_visits": 2,
                 "traffic_cap": 40, "route_cap": 20, "ws_cap": 10,
                 "api_cap": 15},
    "thorough": {"max_pages": 50, "crawl_depth": 4, "max_xss_urls": 80,
                 "js_files": 10, "swagger_paths": 40, "spa_visits": 4,
                 "traffic_cap": 100, "route_cap": 40, "ws_cap": 20,
                 "api_cap": 25},
}


def resolve_coverage(args) -> dict[str, int]:
    """Profile presets with explicit-flag overrides. Never raises."""
    try:
        prof = (getattr(args, "profile", "balanced") or "balanced").lower()
    except Exception:
        prof = "balanced"
    base = dict(PROFILES.get(prof, PROFILES["balanced"]))
    for attr, key in (("max_pages", "max_pages"), ("depth", "crawl_depth"),
                      ("max_xss_urls", "max_xss_urls")):
        try:
            val = getattr(args, attr, None)
        except Exception:
            val = None
        if isinstance(val, int) and val > 0:
            base[key] = val
    return base


def canonicalize_url(url: str) -> str:
    """Dedupe key: lowercase host, sorted query, no fragment/slash noise."""
    try:
        p = urlparse(url or "")
    except Exception:
        return url or ""
    scheme = (p.scheme or "http").lower()
    host = (p.hostname or "").lower()
    if not host:
        return url or ""
    port = p.port
    if (scheme == "http" and port == 80) or \
            (scheme == "https" and port == 443):
        port = None
    netloc = f"{host}:{port}" if port else host
    path = p.path or "/"
    if len(path) > 1:
        path = path.rstrip("/")
    try:
        qsl = parse_qsl(p.query, keep_blank_values=True)
        qsl.sort(key=lambda kv: (kv[0], kv[1]))
        query = urlencode(qsl)
    except Exception:
        query = p.query
    return urlunparse((scheme, netloc, path, "", query, ""))


# JS call shapes beyond fetch(): XHR.open, WebSocket/SSE constructors,
# jQuery + axios + generic api/http clients, Next router pushes.
_JS_CALL_RES = [
    re.compile(r'''(?:fetch|axios\.(?:get|post|put|patch|delete|request)|'''
               r'''\$\.(?:ajax|get|post|getJSON)|\w+(?:Api|Client|http)\.'''
               r'''(?:get|post|put|patch|delete|request))\s*\(\s*[`'\"]([^`'\"]+)[`'\"]''', re.I),
    re.compile(r'''\.open\s*\(\s*["'](?:GET|POST|PUT|PATCH|DELETE|HEAD)["']\s*,\s*["']([^"']+)["']''', re.I),
    re.compile(r'''new\s+(?:WebSocket|EventSource)\s*\(\s*["']([^"']+)["']''', re.I),
    re.compile(r'''router\.push\s*\(\s*["']([^"']+)["']''', re.I),
    re.compile(r'''url\s*:\s*["']([^"']+)["']''', re.I),
]
_JS_BARE_API_RE = re.compile(
    r'''["']((?:/api/|/v\d+/|/graphql|/rest/)[\w\-/.:]{0,80})["']''', re.I)

_REST_PARAM_RE = re.compile(r"\{([^{}:/]+?)(?::[^{}]*)?\}")
_COLON_PARAM_RE = re.compile(r"/:([a-zA-Z_]\w*)")
_BRACKET_PARAM_RE = re.compile(r"/\[+(\.\.\.)?([a-zA-Z_]\w*)\]+")

_API_HINTS = ("/api/", "/graphql", "/rest/", "/v1/", "/v2/", "/query",
              "/gql", "/mutations")


def classify_endpoint(url: str) -> str:
    """api vs page. JSON/API shapes are kept as a separate type."""
    try:
        path = urlparse(url or "").path.lower()
    except Exception:
        return "page"
    if any(h in path for h in _API_HINTS) or path.endswith(".json"):
        return "api"
    return "page"


def concretize_rest_path(path: str) -> tuple[str, list[str]]:
    """(/users/{id} -> /users/1, [id]); also :id and [id]/[slug]."""
    params: list[str] = []

    def _rep(m):
        params.append(m.group(1).strip().lower())
        return "1"

    out = _REST_PARAM_RE.sub(_rep, path or "")

    def _colon(m):
        params.append(m.group(1).lower())
        return "/1"

    out = _COLON_PARAM_RE.sub(_colon, out)

    def _bracket(m):
        params.append(m.group(2).lower())
        return "/1"

    out = _BRACKET_PARAM_RE.sub(_bracket, out)
    return out, params


def extract_js_endpoints(js_text: str, base: str,
                         limit: int = 15) -> list[tuple[str, str]]:
    """[(url, kind)] from a JS bundle. Same-host only, capped, deduped."""
    out: list[tuple[str, str]] = []
    seen: set[str] = set()

    def _add(raw: str) -> None:
        if not raw or raw.startswith(("#", "mailto:", "javascript:",
                                      "tel:", "data:", "ws:", "wss:")) \
                or " " in raw or "\\" in raw:
            return
        if raw.startswith(("ws://", "wss://")):
            return  # sockets are noted, not crawled as pages
        full = urljoin(base + "/", raw).split("#")[0]
        try:
            if urlparse(full).hostname != urlparse(base).hostname:
                return
        except Exception:
            return
        key = canonicalize_url(full)
        if key not in seen:
            seen.add(key)
            out.append((full, classify_endpoint(full)))

    text = js_text or ""
    for rx in _JS_CALL_RES:
        for m in rx.findall(text):
            _add(m)
            if len(out) >= limit:
                return out
    for m in _JS_BARE_API_RE.findall(text):
        _add(m)
        if len(out) >= limit:
            break
    return out


_PARAM_KEY_RE = re.compile(r'''["']([a-zA-Z][\w]{1,24})["']\s*:''')
_PARAM_STOP = frozenset({
    "true", "false", "null", "undefined", "function", "return", "const",
    "import", "export", "default", "script", "style", "div", "span",
    "href", "src", "http", "https",
})


def extract_param_names_here(*texts: str | None) -> list[str]:
    """Param-like identifiers from JS/JSON/HTML blobs. Max 40, deduped."""
    out: list[str] = []
    for text in texts:
        if not text:
            continue
        for m in _PARAM_KEY_RE.finditer(text[:200_000]):
            name = m.group(1)
            if len(name) < 2 or name.lower() in _PARAM_STOP:
                continue
            if name not in out:
                out.append(name)
            if len(out) >= 40:
                return out
    return out


def extract_html_refs(html: str, base: str) -> dict:
    """Links + form probes + inline-JS endpoints + JSON config refs.

    Returns {"urls": [...], "api": [...], "params": [...]}. No fetching
    here — JSON configs are resolved by the crawler under its own budget.
    """
    urls: list[str] = []
    api: list[str] = []
    body = html or ""
    href_re = re.compile(r'href=["\']([^"\']+)["\']', re.I)
    for m in href_re.findall(body):
        if "?" in m and "=" in m:
            full = urljoin(base + "/", m).split("#")[0]
            try:
                same = urlparse(full).hostname == urlparse(base).hostname
            except Exception:
                same = False
            if same and full not in urls:
                (api if classify_endpoint(full) == "api" else urls).append(full)
    for u, kind in extract_js_endpoints(body, base):
        target = api if kind == "api" else urls
        if u not in target:
            target.append(u)
    configs: list[str] = []
    for m in re.findall(r'''["']([^"']+\.json(?:\?[^"']*)?)["']''', body, re.I):
        full = urljoin(base + "/", m).split("#")[0]
        try:
            same = urlparse(full).hostname == urlparse(base).hostname
        except Exception:
            same = False
        if same and full not in configs:
            configs.append(full)
        if len(configs) >= 4:
            break
    params = extract_param_names_here(body)
    return {"urls": urls[:20], "api": api[:15], "params": params[:20],
            "configs": configs[:4]}

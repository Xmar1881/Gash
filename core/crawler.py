"""Lightweight BFS crawler (same-origin, page + depth limits).

No headless browser: requests plus href/form parsing. It doesn't aim for
full coverage — just enough so single-page blindness goes away: ?param=
links, forms and API paths feed the scan pool. Respects delay/budget
through _get, and never leaves scope_hosts.
"""

from __future__ import annotations

from collections import deque
from urllib.parse import urljoin, urlparse

from core.scanner import _get, HREF_RE, FORM_RE, ACTION_RE, INPUT_RE
from core.discovery import (canonicalize_url, extract_js_endpoints,
                            concretize_rest_path, extract_html_refs)

SKIP_EXT = (".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".css",
            ".woff", ".woff2", ".ttf", ".mp4", ".mp3", ".pdf", ".zip")
SKIP_SCHEME = ("mailto:", "javascript:", "tel:", "data:")


def _mark_seen(seen: set, url: str) -> bool:
    """Canonical dedupe: ?b=1&a=2 and ?a=2&b=1 queue once. True if new."""
    try:
        key = canonicalize_url(url)
    except Exception:
        key = url
    if key in seen:
        return False
    seen.add(key)
    return True


def _same_host(url: str, base: str) -> bool:
    try:
        return urlparse(url).hostname == urlparse(base).hostname
    except Exception:
        return False


def _clean(raw: str, base: str) -> str | None:
    if not raw or raw.startswith("#"):
        return None
    low = raw.lower()
    if low.startswith(SKIP_SCHEME):
        return None
    full = urljoin(base + "/", raw).split("#")[0]
    if not _same_host(full, base):
        return None
    if urlparse(full).path.lower().endswith(SKIP_EXT):
        return None
    return full


def _enqueue_links(body: str, base: str, seen: set, queue, depth: int,
                   max_pages: int, pages: dict) -> None:
    """Hrefs + form submits + sitemap/JS helpers, all into one queue.

    POST forms join too — as GET probes of the action URL (input names
    intact), never as submissions. The crawler stays read-only; the
    scanner decides what to POST.
    """
    from urllib.parse import urlencode
    for m in HREF_RE.findall(body or ""):
        u = _clean(m, base)
        if u and len(pages) + len(queue) < max_pages + 4 \
                and _mark_seen(seen, u):
            queue.append((u, depth))
    for m in FORM_RE.finditer(body or ""):
        am = ACTION_RE.search(m.group(0))
        if not am:
            continue
        names = INPUT_RE.findall(m.group(1)) or ["q"]
        u = _clean((am.group(1) or "/") + "?" + urlencode({names[0]: "gashtest"}), base)
        if u and len(pages) + len(queue) < max_pages + 4 \
                and _mark_seen(seen, u):
            queue.append((u, depth))


def _sitemap_urls(session, base: str, timeout: int, fetch=None) -> list[str]:
    """sitemap.xml (+ one index level) -> same-host URLs. Max ~20."""
    fg = fetch or (lambda u: _get(session, u, timeout))
    locs: list[str] = []
    smaps = [base + "/sitemap.xml"]
    try:
        for sm in smaps[:3]:
            got = fg(sm)
            if not got or not got[0] == 200:
                continue
            import re
            for loc in re.findall(r"<loc>\s*([^<]+?)\s*</loc>", got[1] or "", re.I)[:20]:
                loc = loc.strip()
                if loc.lower().endswith(".xml") and _same_host(loc, base):
                    smaps.append(loc)  # sitemap index -> bir seviye daha
                else:
                    u = _clean(loc, base)
                    if u:
                        locs.append(u)
                if len(locs) >= 20:
                    break
    except Exception:
        pass
    return locs


def _js_src_list(body: str, base: str, budget: int) -> list[str]:
    """Same-host <script src> URLs, pure (no fetch). Shared by fetch paths."""
    import re
    from urllib.parse import urljoin as _uj
    return [m for m in re.findall(r'<script[^>]*src=["\']([^"\']+)["\']', body or "", re.I)
            if _same_host(_uj(base + "/", m), base)][:max(0, budget)]


def _js_endpoints(session, body: str, base: str, timeout: int,
                  budget: list, fetch=None) -> list[str]:
    """Same-host <script src=.js> files (budgeted, max 200KB each).

    Endpoint shapes come from the unified pipeline (fetch/axios/XHR,
    WebSocket/EventSource, API clients — not just /api/). budget[0] is
    the remaining file count, decremented per fetch.
    """
    fg = fetch or (lambda u: _get(session, u, timeout))
    out = []
    if not budget or budget[0] <= 0:
        return out
    from urllib.parse import urljoin as _uj
    for src in _js_src_list(body, base, budget[0]):
        if budget[0] <= 0:
            break
        budget[0] -= 1
        got = fg(_uj(base + "/", src))
        if not got or len(got[1] or "") > 200_000:
            continue
        for u, _kind in extract_js_endpoints(got[1] or "", base):
            uu = _clean(u, base)
            if uu and uu not in out:
                out.append(uu)
            if len(out) >= 15:
                break
    return out


def _json_config_routes(session, body: str, base: str, timeout: int,
                        max_files: int = 2, fetch=None) -> list[str]:
    """Same-host *.json refs (config/manifest/asset lists) -> routes inside.

    Bounded: max_files fetches, 100KB each. Malformed JSON is fine —
    endpoint shapes are regex-mined from the raw text.
    """
    fg = fetch or (lambda u: _get(session, u, timeout))
    refs = extract_html_refs(body, base).get("configs", [])[:max_files]
    out: list[str] = []
    for ref in refs:
        got = fg(ref)
        if not got or len(got[1] or "") > 100_000:
            continue
        for u, _kind in extract_js_endpoints(got[1] or "", base):
            uu = _clean(u, base)
            if uu and uu not in out:
                out.append(uu)
            if len(out) >= 10:
                break
    return out


SWAGGER_CANDIDATES = ["/swagger.json", "/openapi.json", "/api-docs",
                      "/api/docs", "/v3/api-docs", "/swagger/v1/swagger.json"]


def fetch_swagger_spec(session, base: str, timeout: int) -> dict | None:
    """First valid Swagger/OpenAPI document, or None. Bounded fetches."""
    import json as _json
    for cand in SWAGGER_CANDIDATES:
        got = _get(session, base + cand, timeout)
        if not got or got[0] != 200 or not (got[1] or "").lstrip().startswith("{"):
            continue
        try:
            spec = _json.loads(got[1])
        except Exception:
            continue
        if isinstance(spec, dict) and isinstance(spec.get("paths"), dict):
            return spec
    return None


def _swagger_paths(session, base: str, timeout: int,
                   limit: int = 20) -> list[str]:
    """Swagger/OpenAPI path'leri cikar ({id}/:id/[id] -> 1). Capped."""
    spec = fetch_swagger_spec(session, base, timeout)
    if not spec:
        return []
    out = []
    for p in list(spec.get("paths", {}))[:limit]:
        concrete, _params = concretize_rest_path(p)
        u = _clean(concrete, base)
        if u and u not in out:
            out.append(u)
        if len(out) >= limit:
            break
    return out


def crawl(session, base: str, html: str, timeout: int,
          max_pages: int = 8, depth: int = 2,
          scope_hosts: set[str] | None = None,
          js_files: int = 5, swagger_paths: int = 20,
          stats: dict | None = None,
          auth: dict | None = None,
          go_worker: bool = False) -> dict[str, str]:
    """{url: html}. Base always included. BFS + sitemap + JS, capped.

    When scope_hosts is set, the final URL's host must be listed or the
    page stays out of the pool (blocks redirecting out of scope).
    js_files/swagger_paths scale with the coverage profile. stats and
    auth (when given) receive counters and login-wall sightings.

    go_worker fans seed + level fetches out in worker round-trips;
    parsing, scope, walls and caps stay in Python (byte-identical).
    Swagger candidates keep sequential first-valid-wins (fewer requests
    than a full batch); 429 anywhere falls back to plain _get.
    """
    pages: dict[str, str] = {base + "/": html or ""}
    if max_pages <= 1 or not html:
        return pages
    from core.authz import is_login_wall
    walls: list[str] = []
    creds = None
    if go_worker:
        try:
            from core.scan.enumeration import _go_fetchable
            creds = _go_fetchable(session)
        except Exception:
            creds = None

    def _note_wall(url: str, final: str, body: str) -> None:
        try:
            if is_login_wall(final or url, body):
                if url not in walls:
                    walls.append(url)
        except Exception:
            pass

    _note_wall(base + "/", base + "/", html or "")
    seen = {canonicalize_url(base + "/")}
    queue: deque[tuple[str, int]] = deque()

    def _offer(u: str | None, d: int) -> None:
        if u and len(pages) + len(queue) < max_pages + 4 \
                and _mark_seen(seen, u):
            queue.append((u, d))

    def _batch_fetch(urls: list[str], snippet: int) -> dict | None:
        """One worker round-trip -> {url: (status, body, final)} or None.

        Truncated heads are completed via _get (link mining needs full
        bodies); 429/error poisons the batch back to sequential _get.
        """
        if not urls or creds is None:
            return None
        try:
            from core.goworker import fetch_batch as _go_fetch
            headers, cookies = creds
            fetched = _go_fetch(urls, headers=headers, cookies=cookies,
                                timeout=timeout, workers=20,
                                snippet_bytes=snippet)
        except Exception:
            return None
        if any(fr.get("status") == 429 for fr in fetched):
            return None
        out: dict = {}
        for fr in fetched:
            if fr.get("error") or not fr.get("status"):
                continue
            if fr.get("truncated"):
                got = _get(session, fr["url"], timeout)
                if not got:
                    continue
                out[fr["url"]] = (got[0], got[1], got[2])
            else:
                out[fr["url"]] = (fr["status"], fr["snippet"],
                                  fr.get("final_url", "") or fr["url"])
        return out or None

    batch: dict = {}

    def _fetch(u: str):
        if u in batch:
            return batch[u]
        return _get(session, u, timeout)

    _enqueue_links(html, base, seen, queue, 1, max_pages, pages)
    if creds is not None:
        # Seed round: sitemap + JS/config files in one trip (swagger keeps
        # its sequential first-valid-wins below: fewer requests that way).
        try:
            from urllib.parse import urljoin as _uj
            seed_urls = [base + "/sitemap.xml"]
            seed_urls += [_uj(base + "/", s)
                          for s in _js_src_list(html, base, max(0, js_files))]
            seed_urls += extract_html_refs(html, base).get("configs", [])[:2]
            seed_urls = list(dict.fromkeys(seed_urls))
            got = _batch_fetch(seed_urls, 200_000)
            if got:
                batch.update(got)
        except Exception:
            pass
    for u in _sitemap_urls(session, base, timeout, fetch=_fetch):
        _offer(u, 1)
    sw_specs = _swagger_paths(session, base, timeout, limit=swagger_paths)
    for u in sw_specs:
        _offer(u, 1)
    for u, _kind in extract_js_endpoints(html, base):  # inline, no fetch
        _offer(_clean(u, base), 1)
    js_budget = [max(0, js_files)]
    for u in _js_endpoints(session, html, base, timeout, js_budget, fetch=_fetch):
        _offer(u, 1)
    for u in _json_config_routes(session, html, base, timeout, fetch=_fetch):
        _offer(u, 1)

    def _ingest(url: str, d: int, got) -> None:
        """Judge one fetched page: scope, walls, HTML sniff, fan out links.

        Shared by the sequential and batched loops, so coverage can never
        depend on who fetched.
        """
        if not got or not got[0]:
            return
        if scope_hosts:
            try:
                final_host = (urlparse(got[2] or url).hostname or "").lower()
            except Exception:
                final_host = ""
            if final_host not in scope_hosts:
                return  # redirect escaped scope, keep it out of the pool
        body = got[1] or ""
        try:
            _note_wall(url, got[2] or url, body)
        except Exception:
            pass
        head = body[:2000].lower()
        if "<html" not in head and "<a " not in head and "<form" not in head:
            pages[url] = ""  # not HTML: counts as visited, skips the probe pool
            return
        pages[url] = body
        if d >= depth or len(pages) >= max_pages:
            return
        _enqueue_links(body, base, seen, queue, d + 1, max_pages, pages)
        for u, _kind in extract_js_endpoints(body, base):  # inline
            uu = _clean(u, base)
            if uu and len(pages) + len(queue) < max_pages + 4 \
                    and _mark_seen(seen, uu):
                queue.append((uu, d + 1))
        for u in _js_endpoints(session, body, base, timeout, js_budget, fetch=_fetch):
            if u and len(pages) + len(queue) < max_pages + 4 \
                    and _mark_seen(seen, u):
                queue.append((u, d + 1))

    from core.spinner import Spinner
    sp = Spinner(f"  [*] Crawling {base}...").start()
    try:
        if creds is not None:
            # Level-at-a-time fan-out: drain the current frontier, fetch it
            # in one round-trip, ingest in drained order (same inclusion as
            # strict FIFO under the page cap). Any batch failure degrades
            # that round to plain _get; judging below is shared.
            while queue and len(pages) < max_pages:
                frontier: list = []
                while queue and len(frontier) < 32 \
                        and len(pages) + len(frontier) < max_pages + 4:
                    frontier.append(queue.popleft())
                if not frontier:
                    break
                try:
                    got = _batch_fetch([u for u, _d in frontier], 65_536)
                    if got:
                        batch.update(got)
                except Exception:
                    pass
                for url, d in frontier:
                    if len(pages) >= max_pages:
                        break
                    sp.update(f"  [*] Crawling {base} ({len(pages)}/{max_pages} pages)")
                    _ingest(url, d, _fetch(url))
        else:
            while queue and len(pages) < max_pages:
                url, d = queue.popleft()
                sp.update(f"  [*] Crawling {base} ({len(pages)}/{max_pages} pages)")
                _ingest(url, d, _get(session, url, timeout))
    finally:
        sp.stop()
    if stats is not None:
        try:
            stats["pages_discovered"] = len(pages)
            stats["pages_scanned"] = sum(1 for h in pages.values() if h)
            stats["js_files"] = max(0, js_files - js_budget[0])
            stats["swagger_paths"] = len(sw_specs)
            stats["truncated"] = bool(len(pages) >= max_pages)
        except Exception:
            pass
    if auth is not None:
        try:
            auth["walls"] = list(walls)
            auth["login_pages"] = len(walls)
        except Exception:
            pass
    return pages

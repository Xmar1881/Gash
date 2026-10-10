"""Scan discovery: form parsing, probe-pool building, injection helpers."""
from __future__ import annotations

import re
from urllib.parse import urljoin, urlparse, parse_qs, urlencode, urlunparse

from core.scan._shared import FORM_RE, ACTION_RE, INPUT_RE, HREF_RE
from core.wordlists import FUZZ_PARAMS

TEXTAREA_RE = re.compile(r'<textarea[^>]*name=["\']([^"\']+)["\']', re.I)
# Field-type capture (so canaries never land in password/hidden/file fields)
INPUT_TYPE_RE = re.compile(
    r'<input[^>]*type=["\']?(\w+)["\']?[^>]*name=["\']([^"\']+)["\']', re.I)
INPUT_TYPE_RE2 = re.compile(
    r'<input[^>]*name=["\']([^"\']+)["\'][^>]*type=["\']?(\w+)["\']?', re.I)
_METHOD_RE = re.compile(r'method=["\']([^"\']*)["\']', re.I)
# Fields a canary must never touch (state changes / token clobbering risk)
UNFUZZABLE_TYPES = {"password", "hidden", "file", "submit", "button",
                    "image", "checkbox", "radio"}


def _forms(html: str, base: str) -> list[dict]:
    """[{action, method, inputs, fields}] — en fazla 6 form."""
    out = []
    for m in FORM_RE.finditer(html or ""):
        chunk, full = m.group(1), m.group(0)
        am = ACTION_RE.search(full)
        mm = _METHOD_RE.search(full)
        action = urljoin(base + "/", (am.group(1) if am else "") or "/")
        inputs = INPUT_RE.findall(chunk) + TEXTAREA_RE.findall(chunk)
        fields: dict[str, str] = {}
        for t, n in INPUT_TYPE_RE.findall(chunk):
            fields.setdefault(n, (t or "text").lower())
        for n, t in INPUT_TYPE_RE2.findall(chunk):
            fields.setdefault(n, (t or "text").lower())
        for n in TEXTAREA_RE.findall(chunk):
            fields.setdefault(n, "textarea")
        for n in inputs:
            fields.setdefault(n, "text")
        out.append({"action": action,
                    "method": (mm.group(1).upper() if mm else "GET"),
                    "inputs": inputs or ["q"],
                    "fields": fields})
        if len(out) >= 6:
            break
    return out


def _method_re():
    return _METHOD_RE


def discover_test_urls(html: str, base: str,
                       extra_params: list[str] | None = None) -> list[str]:
    """Form actions (real input names, high signal) + page links. Max 15."""
    urls: list[str] = []
    # form actions FIRST (with their REAL input names — e.g. search.jsp?query=gash)
    # NOTE: findall returns group contents; the action sits in the tag -> finditer + group(0)
    for m in FORM_RE.finditer(html or ""):
        am = ACTION_RE.search(m.group(0))
        if am:
            full = urljoin(base + "/", am.group(1) or "/")
            names = INPUT_RE.findall(m.group(1)) or ["q"]
            if "?" not in full:
                full += "?" + urlencode({names[0]: "gash"})
            urls.append(full)
    for m in HREF_RE.findall(html or ""):
        if "?" in m and "=" in m:
            full = urljoin(base + "/", m)
            # stay on the same host
            if urlparse(full).hostname == urlparse(base).hostname:
                urls.append(full)
    # dedupe, keep order
    uniq = list(dict.fromkeys(urls))[:15]
    # few links on the page: also fuzz common params (same host only).
    # extra_params (SPA/JS-mined names) join the fallback first.
    if len(uniq) < 12:
        have = set()
        for u in uniq:
            try:
                have.update(parse_qs(urlparse(u).query).keys())
            except Exception:
                pass
        for p in list(dict.fromkeys(list(extra_params or []) + FUZZ_PARAMS)):
            if p not in have:
                uniq.append(f"{base}/?{p}=1")
            if len(uniq) >= 12:
                break
    if not uniq:
        # synthetic params for the base probe pool, even on static sites
        uniq = [f"{base}/?id=1", f"{base}/?q=1", f"{base}/?search=1"]
    return uniq[:15]


def _build_probe_pool(pages: dict, base: str,
                      spa_urls: list[str] | None = None,
                      limit: int = 25,
                      stats: dict | None = None) -> list[str]:
    """Merge crawl + SPA URLs into one prioritized, capped probe pool.

    Pure except for no network at all: ordering only. Query-less SPA/API
    endpoints join as ``?id=1`` probes like crawl pages do. stats (when
    given) receives the pre-cap pool size for truncation reporting.
    """
    from core.xss_spa import prioritize_urls
    from core.discovery import canonicalize_url
    urls: list[str] = []
    seen: set[str] = set()

    def _add(u: str | None) -> None:
        if not u or u in urls:
            return
        try:
            if urlparse(u).scheme.lower() not in ("http", "https"):
                return  # sockets and exotic schemes stay in the graph only
        except Exception:
            return
        try:
            key = canonicalize_url(u)
        except Exception:
            key = u
        if key in seen:
            return  # same endpoint, different query order/slash
        seen.add(key)
        urls.append(u)

    for purl, phtml in (pages or {}).items():
        for u in discover_test_urls(phtml, base):
            _add(u)
        # the query-less page itself joins the probe pool (?id=1)
        if "?" not in purl and purl.rstrip("/") != base.rstrip("/"):
            _add(purl + "?id=1")
    for u in spa_urls or []:
        if not u:
            continue
        _add(u if ("?" in u and "=" in u) else u + "?id=1")
    ranked = prioritize_urls(urls)
    if stats is not None:
        try:
            stats["pool_seen"] = len(ranked)
        except Exception:
            pass
    return ranked[:max(1, limit)]


def _inject(url: str, payload: str) -> str:
    """Append the payload to every query value (quote-breaking test)."""
    p = urlparse(url)
    qs = parse_qs(p.query, keep_blank_values=True)
    if not qs:
        return url + payload
    # parse_qs returns lists; flatten with the payload appended
    flat = {k: v[0] for k, v in
            {k: ([x + payload for x in v] if v else [payload])
             for k, v in qs.items()}.items()}
    return urlunparse((p.scheme, p.netloc, p.path, p.params, urlencode(flat), p.fragment))


def _post_form_targets(pages, base: str, limit: int = 6) -> list:
    """[(action, field, filler)] POST fuzz targets from crawled pages.

    filler fills sibling text fields with "1" so lone-field posts don't
    get rejected outright. Password forms are never touched (same rule
    as stored-xss). Capped — POST bodies change state.
    """
    out = []
    for purl, html in list((pages or {}).items()):
        try:
            forms = _forms(html, purl.rsplit("/", 1)[0] if "/" in purl else base)
        except Exception:
            continue
        for f in forms:
            if f.get("method") != "POST":
                continue
            fields = f.get("fields", {})
            if any(t == "password" for t in fields.values()):
                continue
            fuzzable = [n for n in f.get("inputs", [])
                        if fields.get(n, "text") not in UNFUZZABLE_TYPES][:2]
            if not fuzzable:
                continue
            filler = {n: "1" for n in fuzzable}
            for n in fuzzable:
                out.append((f["action"], n, dict(filler)))
                if len(out) >= limit:
                    return out
    return out


__all__ = [
    "TEXTAREA_RE", "INPUT_TYPE_RE", "INPUT_TYPE_RE2", "UNFUZZABLE_TYPES",
    "_forms", "_method_re",
    "discover_test_urls", "_build_probe_pool", "_inject", "_post_form_targets",
]

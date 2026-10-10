"""Scan injection checks: error-SQLi, reflected XSS, errpage."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor

from core.colors import warn
from core.net import ScanBudgetExceeded
from core.registry import check as register_check
from core.scan._shared import (
    Finding, SQL_ERRORS, SQLI_PAYLOADS, fingerprint_dbms,
    XSS_PROBES, ESCAPED_HINTS,
)
from core.scan.http import _get, _post, _request
from core.scan.discovery import _inject, _post_form_targets
from core.xss_context import classify_reflection


def _raw_reflected(body: str | None, marker: str) -> bool:
    """Marker ham (encode'siz) yansidi mi? Entity/unicode kacis varsa False."""
    if not body or marker not in body:
        return False
    low = body.lower()
    i = low.find(marker.lower())
    window = low[max(0, i - 120):i + len(marker) + 120]
    return not any(h in window for h in ESCAPED_HINTS)


def _go_prefetch(session, inj_urls: list, timeout: int,
                 threads: int = 10) -> dict | None:
    """{inj: (status, body)} with EXACT bodies, or None (use _get per URL).

    Items are URL strings or {"url", "headers"} dicts (SSRF Metadata-style
    probes). One worker round-trip fans the probes out; truncated responses
    are re-fetched here via _get with the same headers, so callers always
    judge full bodies and the Go/Python paths cannot diverge. 429 / total
    death / posture mismatch -> None (the whole batch falls back; _get owns
    retry semantics).
    """
    try:
        from core.goworker import fetch_batch as _go_fetch
        from core.scan.enumeration import _go_fetchable
        creds = _go_fetchable(session)
        if creds is None:
            return None
        headers, cookies = creds
        norm, hmap = [], {}
        for it in dict.fromkeys(
                u if isinstance(u, str) else u.get("url", "") for u in inj_urls):
            if not it:
                continue
            norm.append(it)
        for it in inj_urls:
            if isinstance(it, dict) and it.get("url") and it.get("headers"):
                hmap[it["url"]] = dict(it["headers"])
        fetched = _go_fetch(
            [{"url": u, **({"headers": hmap[u]} if u in hmap else {})}
             for u in norm],
            headers=headers, cookies=cookies, timeout=timeout,
            workers=max(1, threads), snippet_bytes=65536)
    except Exception:
        return None
    if any(fr.get("status") == 429 for fr in fetched):
        return None
    out: dict = {}
    for fr in fetched:
        if fr.get("truncated") or (fr.get("error") or not fr.get("status")):
            # Exact body via _get (truncated heads and burst-dropped probes
            # alike): callers judge full bodies, never fragments or gaps.
            got = _get(session, fr["url"], timeout,  # no guessing
                       headers=hmap.get(fr["url"]))
            if not got:
                continue
            out[fr["url"]] = (got[0], got[1])
        else:
            out[fr["url"]] = (fr["status"], fr["snippet"])
    return out or None


def _filter_map(session, u: str, timeout: int, marker: str,
                pre: dict | None = None) -> set[str]:
    """Per-character survival map for one parameter (XSStrike filterChecker).

    Probes marker+char one by one; a char is live only when it echoes
    back byte-raw next to the marker (entity-encoded doesn't count).
    Bounded (16 requests), read-only GETs, caller-gated to reflected
    params only. pre (from _go_prefetch) answers from the batch; anything
    missing falls back to _get.
    """
    from core.xss_payloads import FILTER_PROBE_CHARS
    live: set[str] = set()
    for c in FILTER_PROBE_CHARS:
        probe = marker + c
        hit = (pre or {}).get(_inject(u, probe))
        if hit is not None:
            body = hit[1] or ""
        else:
            got = _get(session, _inject(u, probe), timeout)
            if not got:
                continue
            body = (got[1] or "")
        low, want = body.lower(), probe.lower()
        i = low.find(marker.lower())
        if i == -1:
            continue
        window = low[max(0, i - 8):i + len(marker) + 8]
        if want in window and not any(
                h in window for h in ("&lt;", "&gt;", "&quot;", "&#")):
            live.add(c)
    return live


@register_check("sqli-error", "Error-based SQLi (DB error signature)", order=10)
def test_sqli(session, urls: list[str], timeout: int, verbose: bool,
              threads: int = 10, pages: dict | None = None, base: str = "",
              deep: bool = True, go_worker: bool = False) -> list[Finding]:
    out: list[Finding] = []

    # Hybrid: base + payload GETs for every URL in one round-trip.
    pre = None
    if go_worker and urls:
        try:
            injs = [u for u in (urls or [])]
            for u in (urls or []):
                injs += [_inject(u, p) for p in SQLI_PAYLOADS]
            pre = _go_prefetch(session, injs, timeout, threads)
        except Exception:
            pre = None

    def _fetch(u: str):
        if pre is not None and u in pre:
            st, body = pre[u]
            return (st, body, u)
        return _get(session, u, timeout)

    def _probe(u: str) -> Finding | None:
        base_got = _fetch(u)
        base_body = (base_got[1] if base_got else "").lower()
        base_has_err = any(e in base_body for e in SQL_ERRORS)
        for p in SQLI_PAYLOADS:
            inj = _inject(u, p)
            got = _fetch(inj)
            if not got:
                continue
            _, body, _ = got
            low = body.lower()
            hit = next((e for e in SQL_ERRORS if e in low), None)
            if hit and not base_has_err:
                if verbose:
                    print(warn(f"    [!] SQLi: {inj}"))
                return Finding(
                    title="Possible SQL Injection",
                    severity="CRITICAL",
                    url=inj,
                    detail=f"DB error signature returned: '{hit}' "
                           f"[Backend: {fingerprint_dbms(hit)}]",
                    evidence=body[max(0, low.find(hit) - 40):low.find(hit) + 80].strip(),
                    confidence="High",
                )
        return None  # one finding per URL is enough

    with ThreadPoolExecutor(max_workers=max(1, min(threads, len(urls) or 1))) as ex:
        for f in ex.map(_probe, urls):
            if f:
                out.append(f)

    if deep:
        out += _post_sqli(session, pages, base, timeout, verbose, go_worker)
    return out


def _post_sqli(session, pages, base: str, timeout: int,
               verbose: bool = False, go_worker: bool = False) -> list[Finding]:
    """Same error-signature test through POST bodies (deep only)."""
    out: list[Finding] = []
    targets = _post_form_targets(pages, base)
    # Hybrid: baseline + payload POSTs for every target in one round-trip,
    # judged in the original order (first error per target still wins).
    pre = None
    if go_worker and targets:
        try:
            pre = _go_prefetch_posts(
                session,
                [((a, fld, "gash1"), a, {**filler, fld: "gash1"})
                 for a, fld, filler in targets] +
                [((a, fld, p), a, {**filler, fld: "gash1" + p})
                 for a, fld, filler in targets
                 for p in SQLI_PAYLOADS],
                timeout, 10)
        except Exception:
            pre = None
    for action, field, filler in targets:
        base_hit = (pre or {}).get((action, field, "gash1"))
        if base_hit is not None:
            base_has_err = any(
                e in (base_hit[1] or "").lower() for e in SQL_ERRORS)
        else:
            rb = _post(session, action, timeout,
                       data={**filler, field: "gash1"})
            base_has_err = rb is not None and any(
                e in (rb.text or "").lower() for e in SQL_ERRORS)
        for p in SQLI_PAYLOADS:
            hit = (pre or {}).get((action, field, p))
            if hit is not None:
                body = hit[1] or ""
            else:
                r = _post(session, action, timeout,
                          data={**filler, field: "gash1" + p})
                if not r:
                    continue
                body = (r.text or "")
            low = body.lower()
            hit = next((e for e in SQL_ERRORS if e in low), None)
            if hit and not base_has_err:
                if verbose:
                    print(warn(f"    [!] SQLi (POST {field}): {action}"))
                out.append(Finding(
                    title="Possible SQL Injection",
                    severity="CRITICAL",
                    url=action,
                    detail=f"DB error signature returned via POST body: '{hit}' "
                           f"[Backend: {fingerprint_dbms(hit)}]",
                    evidence=body[max(0, low.find(hit) - 40):low.find(hit) + 80].strip(),
                    confidence="High",
                ))
                break
        if len(out) >= 4:
            break
    return out


@register_check("xss-reflected", "Reflected XSS (context-aware + breakout check)", order=10)
def test_xss(session, urls: list[str], timeout: int, verbose: bool,
             threads: int = 10, pages: dict | None = None, base: str = "",
             deep: bool = True, api_targets: list | None = None,
             go_worker: bool = False) -> list[Finding]:
    out: list[Finding] = []

    # Hybrid stage-1: all (url x probe) GETs in one worker round-trip.
    # Classification below is byte-identical; truncated bodies are already
    # completed via _get inside _go_prefetch. None -> per-URL _get.
    pre = None
    if go_worker:
        try:
            injs = [_inject(u, p) for u in (urls or [])
                    for _, _, p in XSS_PROBES]
            pre = _go_prefetch(session, injs, timeout, threads)
        except Exception:
            pre = None

    def _fetch(inj: str):
        if pre is not None and inj in pre:
            st, body = pre[inj]
            return (st, body, inj)
        return _get(session, inj, timeout)

    def _probe(u: str) -> Finding | None:
        from core.xss_payloads import generate_for_context, generate_bypass
        partial = False
        unconfirmed: Finding | None = None
        unconfirmed_verdict: dict | None = None
        unconfirmed_marker = ""
        for ctx, marker, payload in XSS_PROBES:
            inj = _inject(u, payload)
            got = _fetch(inj)
            if not got:
                continue
            _, body, _ = got
            verdict = classify_reflection(body, marker, payload)
            status = verdict["status"]
            if status == "breakout":
                if verbose:
                    print(warn(f"    [!] XSS({verdict['context']}): {inj}"))
                return Finding(
                    title="Possible Reflected XSS",
                    severity="MEDIUM",
                    url=inj,
                    detail=f"Breaker survives raw in '{verdict['context']}' "
                           f"context ({verdict['evidence']})",
                    evidence=payload,
                    confidence="Medium",
                    method="GET", location="query", confirm="breakout",
                    evidence_meta={"source_used": "query",
                                   "sink_triggered": "response-context",
                                   "ast_node_type": "HTMLFragment",
                                   "raw_payload": payload},
                )
            if status == "raw-unconfirmed" and unconfirmed is None:
                unconfirmed_verdict = verdict
                unconfirmed_marker = marker
                unconfirmed = Finding(
                    title="Reflected input (unconfirmed)",
                    severity="LOW",
                    url=inj,
                    detail=f"Marker reflects raw in '{verdict['context']}' "
                           "context but breaker chars were not observed; "
                           "not proven executable",
                    evidence=payload,
                    confidence="Low",
                )
            if status == "encoded" or marker in (body or ""):
                partial = True  # reflected but encoded -> inconclusive
        # stage-2: context-aware generator for the unconfirmed spot only.
        # Bounded (1 context x 4 payloads) so budgets survive.
        if unconfirmed_verdict is not None:
            for payload, conf, note in generate_for_context(
                    unconfirmed_verdict.get("context", "html-text"),
                    unconfirmed_marker)[:4]:
                inj = _inject(u, payload)
                got = _get(session, inj, timeout)
                if not got:
                    continue
                v2 = classify_reflection(got[1], unconfirmed_marker, payload)
                if v2["status"] == "breakout":
                    if verbose:
                        print(warn(f"    [!] XSS({v2['context']},gen:{note}): {inj}"))
                    return Finding(
                        title="Possible Reflected XSS",
                        severity="MEDIUM",
                        url=inj,
                        detail=f"Generated payload breaks out raw in "
                               f"'{v2['context']}' context ({note}, "
                               f"confidence {conf}/10; {v2['evidence']})",
                        evidence=payload,
                        confidence="Medium",
                        method="GET", location="query", confirm="breakout",
                        evidence_meta={"source_used": "query",
                                       "sink_triggered": "response-context",
                                       "ast_node_type": "HTMLFragment",
                                       "raw_payload": payload},
                    )
            # stage-2.5: filter map + bypass families. Only the surviving
            # characters are used, so WAF-stripped breakers aren't retried
            # blindly (Cloudflare-style keyword/char filters).
            fpre = None
            if go_worker:
                try:
                    from core.xss_payloads import FILTER_PROBE_CHARS as _FPC
                    fpre = _go_prefetch(
                        session,
                        [_inject(u, unconfirmed_marker + c) for c in _FPC],
                        timeout, threads)
                except Exception:
                    fpre = None
            live = _filter_map(session, u, timeout, unconfirmed_marker, pre=fpre)
            if live:
                ctx_name = unconfirmed_verdict.get("context", "html-text")
                for payload, conf, note in generate_bypass(
                        ctx_name, unconfirmed_marker, live):
                    inj = _inject(u, payload)
                    got = _get(session, inj, timeout)
                    if not got:
                        continue
                    v3 = classify_reflection(got[1], unconfirmed_marker,
                                             payload)
                    if v3["status"] == "breakout":
                        if verbose:
                            print(warn(f"    [!] XSS({v3['context']},"
                                       f"bypass:{note}): {inj}"))
                        return Finding(
                            title="Possible Reflected XSS",
                            severity="MEDIUM",
                            url=inj,
                            detail=f"Filter-aware payload breaks out raw in "
                                   f"'{v3['context']}' context ({note}; "
                                   f"live chars: {''.join(sorted(live))}; "
                                   f"{v3['evidence']})",
                            evidence=payload,
                            confidence="Medium",
                            method="GET", location="query",
                            confirm="breakout",
                            evidence_meta={"source_used": "query",
                                           "sink_triggered": "response-context",
                                           "ast_node_type": "HTMLFragment",
                                           "raw_payload": payload},
                        )
            return unconfirmed
        if partial:
            return Finding(
                title="Partially encoded reflection (review manually)",
                severity="LOW",
                url=u,
                detail="Input reflects encoded; bypass may be possible depending on context",
                evidence="encoded reflection",
                confidence="Low",
            )
        return None  # one finding per URL is enough

    with ThreadPoolExecutor(max_workers=max(1, min(threads, len(urls) or 1))) as ex:
        for f in ex.map(_probe, urls):
            if f:
                out.append(f)
    # keep info notes from spamming: max 3
    hits = [f for f in out if f.severity != "LOW"]
    infos = [f for f in out if f.severity == "LOW"][:3]
    out = hits + infos
    if deep:
        out += _post_xss(session, pages, base, timeout, verbose, go_worker)
        out += _api_body_xss(session, api_targets, timeout, verbose, go_worker)
    return out


def _api_body_xss(session, api_targets: list | None, timeout: int,
                  verbose: bool = False, go_worker: bool = False) -> list[Finding]:
    """JSON/XML/GraphQL body reflection (deep only, structure-preserving).

    One leaf per target is replaced by a marker payload; the shape,
    keys and sibling values stay intact. POST/PUT/PATCH/DELETE keep
    their method. Safe mode never reaches here (deep-only caller).
    """
    import json as _json
    from core.api_params import mutate_json_body, mutate_xml_body
    # Specs first (pure body-building, no network), grouped per target, so
    # one worker round-trip can carry every first-round probe. The
    # content-type confusion retry stays live (it depends on the verdict).
    groups: list[list] = []
    for t in (api_targets or [])[:4]:
        method = (getattr(t, "method", "POST") or "POST").upper()
        ctype = (getattr(t, "content_type", "") or "").lower()
        leaves = [p for p in (getattr(t, "params", []) or [])
                  if p.location in ("json", "graphql", "xml")][:2]
        grp = []
        for p in leaves:
            marker = "gxj1"
            payload = marker + '"><svg onload=alert(1)>'
            template = getattr(t, "template", "") or ""
            new_body, kw, eff_ct = "", None, ""
            try:
                if p.location == "xml":
                    new_body = (mutate_xml_body(template, p.name, payload)
                                if template else
                                f"<{p.name}>{payload}</{p.name}>")
                    if not new_body:
                        continue
                    eff_ct = "application/xml"
                    kw = {"data": new_body,
                          "headers": {"Content-Type": "application/xml"}}
                else:
                    if template:
                        new_body = mutate_json_body(template, p.name, payload)
                    else:
                        new_body = _json.dumps({p.name: payload})
                    if not new_body:
                        continue
                    try:
                        kw = {"json": _json.loads(new_body)}
                        eff_ct = "application/json"
                    except Exception:
                        eff_ct = ctype or "application/json"
                        kw = {"data": new_body,
                              "headers": {"Content-Type": eff_ct}}
            except ScanBudgetExceeded:
                raise
            except Exception:
                continue
            grp.append((t, p, method, ctype, marker, payload, new_body, kw,
                        eff_ct))
        if grp:
            groups.append(grp)
    # Hybrid: all first-round bodies in one round-trip, judged in order.
    pre = None
    if go_worker and groups:
        try:
            pre = _go_prefetch_posts(
                session,
                [((ti, li), t.url,
                  ("raw", new_body, eff_ct, method, kw))
                 for ti, grp in enumerate(groups)
                 for li, (t, _p, method, _c, _m, _pl, new_body, kw,
                          eff_ct) in enumerate(grp)],
                timeout, 10)
        except Exception:
            pre = None
    out: list[Finding] = []
    for _ti, grp in enumerate(groups):
        for _li, (t, p, method, ctype, marker, payload, new_body, kw,
                  _eff) in enumerate(grp):
            hit = (pre or {}).get((_ti, _li))
            if hit is not None:
                _st, body, _fu = hit
            else:
                try:
                    if method == "POST":
                        r = _post(session, t.url, timeout, **kw)
                    else:
                        r = _request(session, method, t.url, timeout, **kw)
                except ScanBudgetExceeded:
                    raise
                except Exception:
                    continue
                if not r:
                    continue
                body = getattr(r, "text", "")
            verdict = classify_reflection(body, marker, payload)
            if verdict["status"] != "breakout" \
                    and p.location in ("json", "graphql") \
                    and "json" in ctype:
                # protocol-level retry: some stacks parse JSON under a
                # non-JSON content-type while the WAF only inspects
                # application/json (first two targets only, bounded).
                r = _api_ct_retry(session, method, t.url, timeout,
                                  new_body, marker, payload, verbose)
                if r is None:
                    continue
                verdict = classify_reflection(getattr(r, "text", ""),
                                              marker, payload)
            if verdict["status"] == "breakout":
                if verbose:
                    print(warn(f"    [!] XSS({verdict['context']}, "
                               f"{method} {p.name}): {t.url}"))
                out.append(Finding(
                    title="Possible Reflected XSS",
                    severity="MEDIUM",
                    url=t.url,
                    detail=f"Breaker survives raw in '{verdict['context']}' "
                           f"context via {method} body field '{p.name}' "
                           f"({verdict['evidence']})",
                    evidence=payload,
                    confidence="Medium",
                    method=method, param=p.name, location="body",
                    confirm="breakout",
                ))
                break
        if len(out) >= 4:
            break
    return out


def _api_ct_retry(session, method: str, url: str, timeout: int,
                  new_body: str, marker: str, payload: str,
                  verbose: bool = False):
    """Resend the same JSON body under confusing content-types.

    Returns the first response whose reflection breaks out, else None.
    Deep-only caller, ≤2 extra requests per leaf.
    """
    for alt_ct in ("text/plain", "application/x-json"):
        try:
            kw = {"data": new_body, "headers": {"Content-Type": alt_ct}}
            r = _post(session, url, timeout, **kw) if method == "POST" \
                else _request(session, method, url, timeout, **kw)
        except ScanBudgetExceeded:
            raise
        except Exception:
            continue
        if not r:
            continue
        if classify_reflection(getattr(r, "text", ""), marker,
                               payload)["status"] == "breakout":
            if verbose:
                print(warn(f"    [!] XSS(ct-confusion {alt_ct}): {url}"))
            return r
    return None


def _go_prefetch_posts(session, posts: list[tuple], timeout: int,
                        threads: int = 10) -> dict | None:
    """{key: (status, body, url)} with EXACT bodies, or None.

    posts: [(key, url, data)] with data = form dict (or, for API bodies,
    a ("raw", body, content_type, method, refetch_kw) tuple passed straight
    to the worker and re-issued on truncation). Only independent probes are
    fanned out (same shape as the sequential loop below); order of
    evaluation stays with the caller. 429 / total death / posture mismatch
    -> None (caller runs the plain loop).
    """
    try:
        from core.goworker import fetch_batch as _go_fetch
        from core.scan.enumeration import _go_fetchable
        creds = _go_fetchable(session)
        if creds is None:
            return None
        headers, cookies = creds
        reqs = []
        for _key, url, d in posts:
            if isinstance(d, tuple):
                _, body, ct, method, _kw = d
                reqs.append({"url": url, "method": method, "body": body,
                             "content_type": ct})
            else:
                reqs.append({"url": url, "method": "POST", "form": d})
        fetched = _go_fetch(
            reqs, headers=headers, cookies=cookies, timeout=timeout,
            workers=max(1, threads), snippet_bytes=65536)
    except Exception:
        return None
    if any(fr.get("status") == 429 for fr in fetched):
        return None
    out: dict = {}
    for (key, url, d), fr in zip(posts, fetched):
        if fr.get("error") or not fr.get("status"):
            continue
        if fr.get("truncated"):
            if isinstance(d, tuple):
                _, _body, _ct, method, kw = d
                r = _post(session, url, timeout, **kw) \
                    if method == "POST" \
                    else _request(session, method, url, timeout, **kw)
            else:
                r = _post(session, url, timeout, data=d)
            if not r:
                continue
            out[key] = (r.status_code, r.text, r.url)
        else:
            out[key] = (fr["status"], fr["snippet"], fr.get("final_url", ""))
    return out or None


def _post_xss(session, pages, base: str, timeout: int,
              verbose: bool = False, go_worker: bool = False) -> list[Finding]:
    """Same reflection test through POST bodies (deep only, breakout hits only)."""
    out: list[Finding] = []
    targets = _post_form_targets(pages, base)
    # Hybrid: all (action x probe) POSTs in one worker round-trip, judged
    # in the original order (first breakout per action still wins).
    pre = None
    if go_worker and targets:
        try:
            pre = _go_prefetch_posts(
                session,
                [((a, fld, p), a, {**filler, fld: p})
                 for a, fld, filler in targets
                 for _, _, p in XSS_PROBES],
                timeout, 10)
        except Exception:
            pre = None
    for action, field, filler in targets:
        for ctx, marker, payload in XSS_PROBES:
            hit = (pre or {}).get((action, field, payload))
            if hit is not None:
                _, body, _ = hit
                r = None
            else:
                r = _post(session, action, timeout,
                          data={**filler, field: payload})
                if not r:
                    continue
                body = r.text
            verdict = classify_reflection(body, marker, payload)
            if verdict["status"] == "breakout":
                if verbose:
                    print(warn(f"    [!] XSS({verdict['context']}, POST {field}): {action}"))
                out.append(Finding(
                    title="Possible Reflected XSS",
                    severity="MEDIUM",
                    url=action,
                    detail=f"Breaker survives raw in '{verdict['context']}' "
                           f"context via POST body ({verdict['evidence']})",
                    evidence=payload,
                    confidence="Medium",
                    method="POST", param=field, location="body",
                    confirm="breakout",
                ))
                break
        if len(out) >= 4:
            break
    return out


@register_check("xss-errpage", "404 + header reflection", order=10)
def test_xss_errpage(session, base: str, timeout: int, verbose: bool,
                     go_worker: bool = False) -> list[Finding]:
    """404 pages + header reflection. Single requests, high yield."""
    out: list[Finding] = []
    probe = base + "/gash404gx9yolu"
    hdr_url = base + "/gash_nope_987654321"
    hdr = {"User-Agent": "gxua8marker", "Referer": "https://x/gxref7marker"}
    # Hybrid: both probes in one round-trip (header probe keeps its headers).
    pre = None
    if go_worker:
        try:
            pre = _go_prefetch(session, [probe, {"url": hdr_url, "headers": hdr}],
                               timeout, 10)
        except Exception:
            pre = None

    def _fetch(u: str, headers: dict | None = None):
        if pre is not None and u in pre:
            st, body = pre[u]
            return (st, body, u)
        return _get(session, u, timeout, headers=headers)

    # 1) does a missing path echo back on the 404 page?
    got = _fetch(probe)
    if got and _raw_reflected(got[1], "gash404gx9yolu"):
        out.append(Finding(
            title="Possible Reflected XSS (404 page)", severity="MEDIUM",
            url=probe,
            detail="404 page reflects the requested path raw",
            evidence="gash404gx9yolu",
            confidence="Medium",))
        if verbose:
            print(warn(f"    [!] XSS(404): {probe}"))
    # 2) header reflection (UA + Referer in one request)
    got = _fetch(hdr_url, headers=hdr)
    if got:
        body = got[1] or ""
        for marker, src in (("gxua8marker", "User-Agent"),
                            ("gxref7marker", "Referer")):
            if _raw_reflected(body, marker):
                out.append(Finding(
                    title=f"Header reflection XSS surface ({src})", severity="MEDIUM",
                    url=base + "/<404>",
                    detail=f"{src} header reflects raw into the error page (verify manually)",
                    evidence=marker,
                    confidence="Medium",))
                if verbose:
                    print(warn(f"    [!] XSS(header:{src})"))
    return out


__all__ = [
    "_raw_reflected", "_filter_map",
    "test_sqli", "_post_sqli",
    "test_xss", "_api_body_xss", "_api_ct_retry", "_post_xss",
    "test_xss_errpage",
]

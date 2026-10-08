"""GASH unit tests — no network, fast."""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))


def test_normalize_keeps_port():
    from core.recon import normalize_target
    h, b = normalize_target("http://x.test:8080/y")
    assert h == "x.test" and b == "http://x.test:8080/y"
    h, b = normalize_target("example.com")
    assert h == "example.com" and b == "http://example.com"
    h, b = normalize_target("https://example.com/app/")
    assert b == "https://example.com/app"  # sub-app scope kept


def test_parse_ports():
    from core.cli import parse_ports
    assert parse_ports("80,443,8080") == [80, 443, 8080]
    assert parse_ports(None) is None
    assert parse_ports("garbage") is None


def test_parse_auth():
    from core.net import parse_auth
    a = parse_auth("a=b; c=d", ["Authorization: Bearer X", "bozuk"])
    assert a.cookies == {"a": "b", "c": "d"}
    assert a.headers == {"Authorization": "Bearer X"}


def test_net_budget():
    from core.net import configure_net, pace, ScanBudgetExceeded
    configure_net(0.0, 3)
    pace()
    pace()
    pace()
    with pytest.raises(ScanBudgetExceeded):
        pace()
    configure_net()  # reset (don't leak into other tests)


def test_knowledge():
    from core.scanner import Finding
    from core.knowledge import enrich, lookup
    f = Finding("Possible SQL Injection", "CRITICAL")
    enrich(f)
    assert f.cwe == "CWE-89" and "9.8" in f.cvss and "prepared" in f.remediation.lower()
    assert lookup("No Such Thing")["cwe"] == "CWE-?"


def test_knowledge_coverage():
    """Every finding title must hit the KB (except the WAF info note)."""
    from core.knowledge import lookup
    titles = [
        "Possible SQL Injection", "Possible Blind SQL Injection (boolean)",
        "Possible Time-Based Blind SQLi", "Possible SQLi WAF Bypass (encoding)",
        "Possible SQLi Auth Bypass (login)", "Possible Stored XSS",
        "Possible Reflected XSS", "Possible Reflected XSS (404 page)",
        "Header reflection XSS surface (User-Agent)",
        "Partially encoded reflection (review manually)",
        "Blind XSS canary placed (unverified)",
        "Possible SSTI (Template Injection)", "Possible SSRF (cloud metadata)",
        "SSRF surface (manual testing advised)",
        "Possible IDOR / BOLA (single session)",
        "Confirmed IDOR / BOLA (cross-session)",
        "Possible Unrestricted File Upload (confirmed)",
        "Upload Filter Bypass (RCE vector)",
        "Admin Panel", "Critical File Exposure: x", "Sensitive Directory: y",
        "robots.txt Found", "Prototype Pollution Reflection Surface",
        "DOM XSS (confirmed — alert fired)",
        "JS DOM write (review manually)", "Weak cookie flags",
        "Missing Security Header: X", "Possible Open Redirect",
        "Possible Path Traversal", "Permissive CORS (origin reflected)",
        "Risky HTTP method advertised: TRACE", "Exposed secret in JavaScript (x)",
        "JWT using alg:none observed", "GraphQL introspection enabled",
        "Host header reflected", "security.txt missing",
        "Possible OS Command Injection", "Possible CRLF Injection",
        "Missing anti-CSRF controls", "Open Firebase database",
        "Exposed Supabase table (no login)", "Next.js middleware bypass",
        "WordPress username disclosure", "API docs exposed (Swagger/OpenAPI)",
        "Client-controllable role field",
        "Possible SQL Injection (ORDER BY differential)",
        "SQLi (confirmed via OOB)",
        "Possible Stored XSS (SVG upload)",
        "Login username enumeration",
        "Possible LDAP injection (auth bypass)",
        "Cache poisoning surface",
    ]
    for t in titles:
        assert lookup(t)["remediation"] != "Manual review advised.", t


def test_registry():
    import core.scanner  # noqa: F401
    import core.advanced  # noqa: F401
    from core.registry import REGISTRY, list_checks, run_checks
    assert len(REGISTRY) >= 18
    names = [n for n, _, _ in list_checks()]
    for must in ("sqli-error", "sqli-login", "waf-detect", "smart-recurse",
                 "cookie-flags", "idor-param", "smart-dirs"):
        assert must in names
    # sira: robots < smart-tech < smart-dirs
    order = {n: REGISTRY[n]["order"] for n in ("robots", "smart-tech", "smart-dirs")}
    assert order["robots"] < order["smart-tech"] < order["smart-dirs"]
    # hepsini atla -> bos doner (ag yok)
    assert run_checks(None, {}, skip=set(names)) == []
    # upload-rce deep_only
    assert REGISTRY["upload-rce"]["deep_only"] is True


def test_raw_reflected():
    from core.scanner import _raw_reflected
    assert _raw_reflected("<p>gx1</p>", "gx1") is True
    assert _raw_reflected("<p>&lt;gx1&gt;</p>", "gx1") is False
    assert _raw_reflected('{"x":"\\u003cgx1"}', "gx1") is False
    assert _raw_reflected(None, "gx1") is False


def test_discover_form_input_name():
    from core.scanner import discover_test_urls
    html = ('<a href="/a?x=1">l</a>'
            '<form method="get" action="/search.jsp">'
            '<input type="text" name="query"></form>')
    urls = discover_test_urls(html, "http://h.test")
    assert "http://h.test/search.jsp?query=gash" in urls  # form en basta
    assert urls.index("http://h.test/search.jsp?query=gash") < 3


def test_wordlist_tech_first():
    from core.scanner import wordlist_for_techs
    wl = wordlist_for_techs(["node"])
    assert wl.index("package.json") < wl.index("login")
    assert len(wl) > 100


def test_detect_waf():
    from core.advanced import detect_waf
    assert detect_waf({"Server": "cloudflare", "cf-ray": "x"}, []) == "Cloudflare"
    assert detect_waf({"Server": "nginx"}, []) is None
    assert detect_waf({}, ["cf_clearance"]) == "Cloudflare"


def test_clean_url():
    from core.crawler import _clean
    assert _clean("/a?x=1#f", "http://h.test") == "http://h.test/a?x=1"
    assert _clean("https://other.com/x", "http://h.test") is None
    assert _clean("mailto:a@b.c", "http://h.test") is None
    assert _clean("/logo.png", "http://h.test") is None


def test_baseline_similarity():
    from core.scanner import _looks_like_baseline
    t = "404 sayfasi bulunamadi" * 50
    assert _looks_like_baseline(200, t, 200, len(t), t) is True
    assert _looks_like_baseline(200, "tamamen farkli icerik xyz", 200, len(t), t) is False
    assert _looks_like_baseline(200, t, 404, len(t), t) is False


def test_probe_tiers():
    """Dir tiers: only real exposure is a finding; discovery is INFO."""
    from core.scanner import _probe_dir

    class Resp:
        def __init__(self, st, body):
            self.status_code = st
            self.text = body
            self.url = ""

    routes = {
        "admin": (200, "<html>Admin Panel login</html>"),
        "contact": (200, "<html>contact us page here</html>"),
        "config.php.bak": (200, "<?php config ?>"),
        "secret": (403, "forbidden"),
    }

    class FakeSession:
        def get(self, url, timeout=None, allow_redirects=True, headers=None):
            for k, (st, b) in routes.items():
                if url.rstrip("/").endswith("/" + k):
                    return Resp(st, b)
            return Resp(404, "not found")

    s = FakeSession()
    r = _probe_dir(s, "http://h.test", "admin", 5, 404, 9, "not found")
    assert r.severity == "INFO" and r.title == "Admin Panel discovered"
    r = _probe_dir(s, "http://h.test", "contact", 5, 404, 9, "not found")
    assert (r.severity, r.title) == ("INFO", "General Page: contact")
    r = _probe_dir(s, "http://h.test", "config.php.bak", 5, 404, 9, "not found")
    assert r.severity == "CRITICAL" and "Critical File" in r.title
    r = _probe_dir(s, "http://h.test", "secret", 5, 404, 9, "not found")
    assert (r.severity, r.title) == ("INFO", "Restricted Area: secret")


def test_probe_dir_forbidden_is_not_exposure():
    """Regression: a 403 WAF block page on /.env is INFO, never CRITICAL."""
    from core.scanner import _probe_dir

    block = ("<!DOCTYPE html><html><head><title>403</title></head>"
             "<body>blocked by WAF</body></html>")

    class Resp:
        def __init__(self, st, body):
            self.status_code = st
            self.text = body
            self.url = ""

    class FakeSession:
        def get(self, url, timeout=None, allow_redirects=True, headers=None):
            return Resp(403, block)

    s = FakeSession()
    for path in (".env", ".git/HEAD", "config.php.bak", ".htaccess",
                 "index.php.old", ".git/config/backup.zip"):
        r = _probe_dir(s, "http://h.test", path, 5, 404, 9, "not found")
        assert r is not None and r.severity == "INFO", path
        assert "Critical" not in r.title, path


def test_probe_dir_secret_content_proof():
    """200 + validating content is still CRITICAL; 200 without is not."""
    from core.scanner import _probe_dir

    class Resp:
        def __init__(self, st, body):
            self.status_code = st
            self.text = body
            self.url = ""

    routes = {
        ".env": (200, "DB_HOST=x\nDB_PASS=y\nAPP_KEY=z\n"),
        ".git/HEAD": (200, "ref: refs/heads/main\n"),
    }

    class FakeSession:
        def get(self, url, timeout=None, allow_redirects=True, headers=None):
            for k, (st, b) in routes.items():
                if url.rstrip("/").endswith("/" + k):
                    return Resp(st, b)
            if "unproven" in url:
                return Resp(200, "<html>generic landing</html>")
            return Resp(404, "not found")

    s = FakeSession()
    r = _probe_dir(s, "http://h.test", ".env", 5, 404, 9, "not found")
    assert r.severity == "CRITICAL" and "KEY=" in r.detail
    r = _probe_dir(s, "http://h.test", ".git/HEAD", 5, 404, 9, "not found")
    assert r.severity == "CRITICAL" and "ref" in r.detail


def test_diff(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    from core.scanner import Finding
    from core.reporter import diff_with_history
    f1 = [Finding("A", "CRITICAL", "", "u1"), Finding("B", "MEDIUM", "", "u2")]
    d1 = diff_with_history("h.test", f1)
    assert d1["ilk_tarama"] is True and len(d1["yeni"]) == 2
    f2 = [Finding("B", "MEDIUM", "", "u2"), Finding("C", "CRITICAL", "", "u3")]
    d2 = diff_with_history("h.test", f2)
    assert [x["title"] for x in d2["yeni"]] == ["C"]
    assert [x["title"] for x in d2["kapandi"]] == ["A"]
    assert d2["ayni"] == 1


def _fake_session():
    from core.net import configure_net
    configure_net()

    class Resp:
        def __init__(self, text="", status_code=200, url=""):
            self.text = text
            self.status_code = status_code
            self.url = url
            self.headers = {}

    class FakeSession:
        def get(self, url, timeout=None, allow_redirects=True, headers=None):
            return Resp(text="<html>clean page</html>", url=url)
        def post(self, url, timeout=None, allow_redirects=True, **kwargs):
            return Resp(text="ok", url=url)

    return FakeSession()


def test_stored_xss_blind_quiet():
    """Without a listener, no blind notes (no noise)."""
    import core.advanced  # noqa: F401
    from core.advanced import test_stored_xss
    pages = {"http://h.test/":
             "<form method='get' action='/go'><input name='q'></form>"}
    out = test_stored_xss(_fake_session(), pages, "http://h.test", 3)
    assert all("Blind" not in f.title for f in out)


def test_stored_xss_blind_callback():
    """With a listener: at most 2 LOW notes, placed for real."""
    import core.advanced  # noqa: F401
    from core.advanced import test_stored_xss
    pages = {"http://h.test/":
             "<form method='get' action='/go'><input name='q'></form>"
             "<form method='get' action='/ara'><input name='s'></form>"}
    out = test_stored_xss(_fake_session(), pages, "http://h.test", 3,
                          blind_callback="cb.test")
    blinds = [f for f in out if f.title.startswith("Blind XSS canary")]
    assert 1 <= len(blinds) <= 2
    assert all(f.severity == "LOW" for f in blinds)


def test_finding_kwargs_only():
    """Regression: no positional Finding() in core/ (url/detail swap)."""
    import ast
    import glob
    import os
    root = os.path.join(os.path.dirname(__file__), "..", "core")
    bad = []
    for fn in glob.glob(os.path.join(root, "*.py")):
        tree = ast.parse(open(fn, encoding="utf-8").read())
        for node in ast.walk(tree):
            if (isinstance(node, ast.Call)
                    and getattr(node.func, "id", "") == "Finding"
                    and node.args):
                bad.append(f"{os.path.basename(fn)}:{node.lineno}")
    assert not bad, f"positional Finding() left: {bad}"


def test_finding_field_semantics():
    from core.scanner import Finding
    f = Finding(title="T", severity="CRITICAL", url="http://h.test/?id=1",
                detail="a description", evidence="e")
    d = f.to_dict()
    assert d["url"] == "http://h.test/?id=1" and d["detail"] == "a description"
    big = Finding(title="T", severity="LOW", url="http://h/", detail="x" * 5000)
    assert len(big.to_dict()["detail"]) == 2000


def _recording_session(posted, requested):
    from core.net import configure_net
    configure_net()

    class Resp:
        def __init__(self, text="", status_code=200, url=""):
            self.text = text
            self.status_code = status_code
            self.url = url
            self.headers = {}

    class S:
        def get(self, url, timeout=None, allow_redirects=True, headers=None):
            requested.append(url)
            return Resp(text="<html>ok</html>", url=url)

        def post(self, url, timeout=None, allow_redirects=True, **kw):
            posted.append(kw.get("data", {}))
            return Resp(text="ok", url=url)

    return S()


def test_stored_skips_password_forms():
    """Password forms never get a canary, not even a POST."""
    import core.advanced as A
    posted, requested = [], []
    pages = {"http://h.test/":
             "<form method='post' action='/pw'>"
             "<input type='text' name='u'>"
             "<input type='password' name='p'></form>"}
    out = A.test_stored_xss(_recording_session(posted, requested),
                            pages, "http://h.test", 3)
    assert out == [] and posted == []


def test_stored_skips_hidden_fields():
    """Hidden fields (CSRF) are never clobbered with a canary."""
    import core.advanced as A
    posted, requested = [], []
    pages = {"http://h.test/":
             "<form method='get' action='/go'>"
             "<input type='hidden' name='csrf' value='T'>"
             "<input name='q'></form>"}
    out = A.test_stored_xss(_recording_session(posted, requested),
                            pages, "http://h.test", 3)
    assert out == []
    assert requested and all("csrf=gashstored" not in u for u in requested)


def test_login_preserves_csrf():
    """sqli-login sends hidden tokens back untouched."""
    import core.advanced as A
    posted, requested = [], []
    pages = {"http://h.test/login":
             "<form method='post' action='/login'>"
             "<input type='text' name='user'>"
             "<input type='password' name='pass'>"
             "<input type='hidden' name='csrf' value='SEKRET'></form>"}
    A.test_sqli_login(_recording_session(posted, requested),
                      pages, "http://h.test", 3)
    assert posted and all(d.get("csrf") == "SEKRET" for d in posted)


def test_upload_names_sane():
    from core.advanced import UPLOAD_BYPASS_NAMES
    assert all("%00" not in n.lower() for n in UPLOAD_BYPASS_NAMES)
    assert "gash_probe.php" in UPLOAD_BYPASS_NAMES  # kontrol probu
    assert "gash_probe.txt" in UPLOAD_BYPASS_NAMES


def test_ssrf_keys_narrow_and_quiet():
    import core.advanced as A
    for bad in ("u", "target", "ref", "site", "image", "img"):
        assert bad not in A.SSRF_KEYS
    from core.net import configure_net
    configure_net()

    class Resp:
        text = "<html>ok</html>"
        status_code = 200
        url = ""
        headers = {}

    class S:
        def get(self, url, timeout=None, allow_redirects=True, headers=None):
            return Resp()

    urls = ["http://h.test/?target=_blank&ref=x"]
    assert A.test_ssrf(S(), urls, 3) == []  # eslesen anahtar yok
    urls = ["http://h.test/?next=/x"]
    assert A.test_ssrf(S(), urls, 3, verbose=False) == []  # sessizde not yok
    notes = A.test_ssrf(S(), urls, 3, verbose=True)
    assert len(notes) <= 3 and all(n.severity == "INFO" for n in notes)


def test_idor_param_filter():
    import core.advanced as A
    from core.net import configure_net
    configure_net()

    class Resp:
        headers = {}

        def __init__(self, text, url=""):
            self.text = text
            self.status_code = 200
            self.url = url

    class S:
        def get(self, url, timeout=None, allow_redirects=True, headers=None):
            if "id=5" in url:
                return Resp("x" * 100, url)
            if "id=6" in url:
                return Resp("y" * 300, url)
            return Resp("z" * 100, url)

    out = A.test_idor_param(S(), ["http://h.test/?page=2",
                                  "http://h.test/?id=5"], 3)
    assert len(out) == 1  # page filtered, id caught
    assert "(single session)" in out[0].title
    assert out[0].url.startswith("http")


def test_encoded_variants_honest():
    from core.advanced import encoded_variants
    v = encoded_variants("'")
    assert v[0] == "'" and v[1] == "%27" and len(set(v)) == len(v)


def test_safe_defaults():
    """Default scans are safe: deep opens only with --deep."""
    from core.cli import build_parser
    from gash import is_deep
    a = build_parser().parse_args(["-t", "https://x.test", "--full"])
    assert a.deep is False and is_deep(a) is False
    b = build_parser().parse_args(["-t", "https://x.test", "--full", "--deep"])
    assert is_deep(b) is True
    c = build_parser().parse_args(
        ["-t", "https://x.test", "--full", "--deep", "--quick"])
    assert is_deep(c) is False  # quick wins


def test_scope_check():
    from gash import parse_scope, check_scope
    assert parse_scope(None) is None
    assert parse_scope("a.com, B.COM ") == {"a.com", "b.com"}
    scope = {"a.com"}
    assert check_scope(["https://a.com/x"], scope) is None
    assert check_scope(["https://evil.com/"], scope) == "https://evil.com/"


def test_fail_on():
    from types import SimpleNamespace
    from gash import fail_triggered, fail_triggered_counts
    fs = [SimpleNamespace(severity="MEDIUM")]
    assert fail_triggered(fs, None) is False
    assert fail_triggered(fs, "critical") is False
    assert fail_triggered(fs, "medium") is True
    assert fail_triggered_counts({"CRITICAL": 1}, "critical") is True
    assert fail_triggered_counts({"MEDIUM": 2}, "critical") is False


def test_mask_argv():
    from core.menu import _mask_argv
    argv = ["-t", "x", "--login-pass", "gizli123", "--full"]
    masked = _mask_argv(argv)
    assert masked[3] == "****" and argv[3] == "gizli123"  # orijinal bozulmaz


def test_unknown_skip_warns(capsys):
    import core.scanner  # noqa: F401
    import core.advanced  # noqa: F401
    from core.registry import run_checks
    assert run_checks(None, {}, skip={"no-such-check"}) == []
    assert "unknown check" in capsys.readouterr().out


def test_dispatcher_binds_sessionless_checks():
    """Checks whose first param is NOT session must still run through
    run_checks (regression: they were silently skipped with TypeError)."""
    import core.scanner  # noqa: F401
    import core.advanced  # noqa: F401
    import core.domxss  # noqa: F401
    import core.webchecks  # noqa: F401
    from core.registry import REGISTRY, run_checks
    none_tok = "eyJhbGciOiJub25lIn0.eyJzdWIiOiIxMjM0NTY3ODkwIn0."
    pages = {"http://h.test/": (
        f"<script>var t='{none_tok}';</script>"
        "<form method='post' action='/register'>"
        "<input name='email'><input name='role'></form>")}
    ctx = {"headers": {}, "base": "http://h.test", "verbose": False,
           "pages": pages, "urls": [], "timeout": 3, "dom": False}
    keep = {"security-headers", "jwt-none", "mass-assignment", "dom-xss"}
    out = run_checks(object(), ctx, skip=set(REGISTRY) - keep, deep=False)
    titles = [f.title for f in out]
    assert any(t.startswith("Missing Security Header") for t in titles)
    assert "JWT using alg:none observed" in titles
    assert "Client-controllable role field" in titles


def test_bodies_differ():
    """IDOR evidence must exceed the echoed id itself."""
    from core.advanced import _bodies_differ
    assert _bodies_differ("q" * 300 + "id=5",
                          "q" * 300 + "id=6" + "w" * 8) is False
    assert _bodies_differ("profile alice employee record",
                          "profile bob contractor xyzzy data!!") is True
    assert _bodies_differ("same", "same") is False


def test_idor_echo_only_id_no_finding():
    """Pages differing only by the id are not IDOR evidence."""
    import core.advanced as A
    from core.net import configure_net
    configure_net()

    class Resp:
        headers = {}

        def __init__(self, text, url=""):
            self.text = text
            self.status_code = 200
            self.url = url

    class S:
        def get(self, url, timeout=None, allow_redirects=True, headers=None):
            if "id=5" in url:
                return Resp("q" * 300 + "id=5", url)
            if "id=6" in url:
                return Resp("q" * 300 + "id=6" + "w" * 8, url)
            return Resp("z" * 100, url)

    out = A.test_idor_param(S(), ["http://h.test/?id=5"], 3)
    assert out == []


def test_ssrf_baseline_marker_no_critical():
    """A page that always mentions cloud markers must not fake an SSRF hit."""
    import core.advanced as A
    from core.net import configure_net
    configure_net()

    class Resp:
        headers = {}

        def __init__(self, text, url=""):
            self.text = text
            self.status_code = 200
            self.url = url

    class S:
        def get(self, url, timeout=None, allow_redirects=True, headers=None):
            return Resp("<html>AWS docs: ami-12345 and instance-id</html>", url)

    out = A.test_ssrf(S(), ["http://h.test/?url=x"], 3)
    assert [f for f in out if f.severity == "CRITICAL"] == []


def test_ssti_needs_confirm():
    """A one-off template echo without a stable second hit is not SSTI."""
    import core.advanced as A
    from core.net import configure_net
    configure_net()

    class Resp:
        headers = {}

        def __init__(self, text, url=""):
            self.text = text
            self.status_code = 200
            self.url = url

    class Flaky:
        def __init__(self):
            self.n = 0

        def get(self, url, timeout=None, allow_redirects=True, headers=None):
            self.n += 1
            if self.n == 1:
                return Resp("<html>home</html>", url)
            if self.n == 2:
                return Resp("<html>7719 x 7919 = 61126761</html>", url)
            return Resp("<html>nothing here</html>", url)

    assert A.test_ssti(Flaky(), ["http://h.test/?q=1"], 3) == []


def test_tls_verify_default_on():
    from core.net import configure_net, tls_verify
    from core.scanner import _session
    configure_net()
    assert tls_verify() is True and _session(3).verify is True
    configure_net(insecure=True)
    assert tls_verify() is False and _session(3).verify is False
    configure_net()


def test_thread_local_sessions():
    import threading
    from core.net import configure_net
    from core.scanner import _session, _tls_session
    configure_net()
    tpl = _session(3)
    assert _tls_session(tpl) is _tls_session(tpl)  # same thread: same pool
    out = []
    t = threading.Thread(target=lambda: out.append(_tls_session(tpl)))
    t.start()
    t.join()
    assert out and out[0] is not _tls_session(tpl)  # other thread: own pool


def test_context_isolation():
    import pytest
    from core.net import (ScanBudgetExceeded, ScanContext, configure_net,
                          get_context, pace, run_with_context, _current)
    from core.reporter import build_report
    configure_net()
    ctx = ScanContext(max_requests=1)
    token = run_with_context(ctx)
    try:
        pace()
        with pytest.raises(ScanBudgetExceeded):
            pace()
        assert build_report("t", "scan", "0")["http_requests"] == 2
    finally:
        _current.reset(token)
    assert get_context().count == 0  # default context untouched


def test_scan_scope_isolation():
    from core.net import (configure_net, enter_scan_scope,
                          exit_scan_scope, get_context, pace, _DEFAULT)
    configure_net(max_requests=1)
    token = enter_scan_scope()
    try:
        pace()
        assert get_context().count == 1
    finally:
        exit_scan_scope(token)
    assert _DEFAULT.count == 0  # default scope untouched
    configure_net()


def test_readme_check_count_matches_registry():
    """The storefront must never drift from the code again."""
    import re
    import core.scanner  # noqa: F401
    import core.advanced  # noqa: F401
    import core.domxss  # noqa: F401
    import core.webchecks  # noqa: F401
    from core.registry import REGISTRY
    import os
    readme = open(os.path.join(os.path.dirname(__file__), "..", "README.md"),
                  encoding="utf-8").read()
    m = re.search(r"## Checks \((\d+)\)", readme)
    assert m, "README check count header missing"
    assert int(m.group(1)) == len(REGISTRY), (
        f"README says {m.group(1)}, registry has {len(REGISTRY)}")


def test_fetch_base_scope_guard():
    from core.net import configure_net
    from core.scanner import _fetch_base
    configure_net()

    class Resp:
        status_code = 200
        text = "<html>hi</html>"
        headers = {}

        def __init__(self, url):
            self.url = url

    class S:
        def get(self, url, timeout=None, allow_redirects=True, headers=None):
            return Resp("https://evil.com/landed")

    html, base, _ = _fetch_base(S(), "http://h.test", 3, {"h.test"})
    assert html == ""  # redirect escaped scope -> refused


def test_idor_cross_session_confirmed():
    """Second user sees the same object -> CRITICAL, not a heuristic."""
    import core.advanced as A
    from core.net import configure_net
    configure_net()

    class Resp:
        def __init__(self, text="", status_code=200, url=""):
            self.text = text
            self.status_code = status_code
            self.url = url
            self.headers = {}

    body5 = "order of alice " + "x" * 200
    body6 = "order of alice plus extras y" + "y" * 200

    class A_Sess:
        def get(self, url, timeout=None, allow_redirects=True, headers=None):
            if url.endswith("/api/orders/5"):
                return Resp(body5, 200, url)
            return Resp(body6, 200, url)

    class B_Sess:
        def get(self, url, timeout=None, allow_redirects=True, headers=None):
            return Resp(body6, 200, url)  # same object, other user

    pages = {"http://h.test/": "<a href='/api/orders/5'>o</a>"}
    out = A.test_idor(A_Sess(), pages, "http://h.test", 3, session_b=B_Sess())
    assert len(out) == 1
    assert out[0].title == "Confirmed IDOR / BOLA (cross-session)"
    assert out[0].severity == "CRITICAL" and out[0].confidence == "High"


def test_idor_cross_session_isolated():
    """Second user gets 403 -> heuristic stands, no upgrade."""
    import core.advanced as A
    from core.net import configure_net
    configure_net()

    class Resp:
        def __init__(self, text="", status_code=200, url=""):
            self.text = text
            self.status_code = status_code
            self.url = url
            self.headers = {}

    body6 = "order data 6 " + "y" * 230

    class A_Sess:
        def get(self, url, timeout=None, allow_redirects=True, headers=None):
            if url.endswith("/api/orders/5"):
                return Resp("order data 5 " + "x" * 200, 200, url)
            return Resp(body6, 200, url)

    class B_Sess:
        def get(self, url, timeout=None, allow_redirects=True, headers=None):
            return Resp("forbidden", 403, url)

    pages = {"http://h.test/": "<a href='/api/orders/5'>o</a>"}
    out = A.test_idor(A_Sess(), pages, "http://h.test", 3, session_b=B_Sess())
    assert len(out) == 1
    assert out[0].title.startswith("Possible IDOR")


def test_idor_param_cross_session():
    import core.advanced as A
    from core.net import configure_net
    configure_net()

    class Resp:
        def __init__(self, text="", status_code=200, url=""):
            self.text = text
            self.status_code = status_code
            self.url = url
            self.headers = {}

    body6 = "invoice 6 details " + "z" * 250

    class A_Sess:
        def get(self, url, timeout=None, allow_redirects=True, headers=None):
            if "id=5" in url:
                return Resp("invoice 5 details " + "z" * 200, 200, url)
            return Resp(body6, 200, url)

    class B_Sess:
        def get(self, url, timeout=None, allow_redirects=True, headers=None):
            return Resp(body6, 200, url)

    out = A.test_idor_param(A_Sess(), ["http://h.test/?id=5"], 3,
                            session_b=B_Sess())
    assert len(out) == 1
    assert out[0].title == "Confirmed IDOR / BOLA (cross-session)"


def test_oob_reset_drain():
    import core.oob as O

    class FakeClient:
        wait = 0
        pending = [{"kind": "reset", "target": "http://h.test/forgot",
                    "token": "greset"}]

        def poll(self):
            return [{"full-id": "greset.oob.test", "protocol": "http",
                     "remote-address": "9.9.9.9"}]

        def deregister(self):
            pass

    out = O.drain(FakeClient(), verbose=False)
    assert len(out) == 1
    assert out[0].title == "Password reset poisoning (confirmed via OOB)"
    assert out[0].severity == "CRITICAL"


def _post_fuzz_session(posted, responder):
    from core.net import configure_net
    configure_net()

    class Resp:
        def __init__(self, text="", status_code=200, url=""):
            self.text = text
            self.status_code = status_code
            self.url = url
            self.headers = {}

    class S:
        def get(self, url, timeout=None, allow_redirects=True, headers=None):
            return Resp("<html>ok</html>", url=url)

        def post(self, url, timeout=None, allow_redirects=True, **kw):
            data = kw.get("data", {})
            posted.append((url, dict(data)))
            return Resp(responder(data, url), url=url)

    return S()


PAGES_POST = {"http://h.test/": (
    "<form method='post' action='/submit'>"
    "<input name='comment'><input name='nick'></form>"
    "<form method='post' action='/pw'>"
    "<input name='u'><input type='password' name='p'></form>"
    "<form method='get' action='/go'><input name='q'></form>")}


def test_post_form_targets():
    from core.scanner import _post_form_targets
    targets = _post_form_targets(PAGES_POST, "http://h.test")
    assert targets and all(a == "http://h.test/submit" for a, _, _ in targets)
    _, _, filler = targets[0]
    assert filler == {"comment": "1", "nick": "1"}


def test_sqli_post_body():
    import core.scanner as SC
    posted = []
    s = _post_fuzz_session(
        posted,
        lambda d, u: "You have an error in your SQL syntax"
        if any("'" in str(v) for v in d.values()) else "ok")
    out = SC.test_sqli(s, [], 3, False, pages=PAGES_POST, base="http://h.test")
    assert any(f.title == "Possible SQL Injection"
               and f.url == "http://h.test/submit" for f in out)
    assert all("/pw" not in u for u, _ in posted)


def test_post_fuzz_respects_quick():
    import core.scanner as SC
    posted = []
    s = _post_fuzz_session(posted, lambda d, u: "uid=0(root)")
    out = SC.test_sqli(s, [], 3, False, pages=PAGES_POST, base="http://h.test",
                       deep=False)
    assert posted == [] and out == []


def test_xss_post_body():
    import core.scanner as SC
    posted = []
    s = _post_fuzz_session(posted, lambda d, u: str(d.get("comment", "")))
    out = SC.test_xss(s, [], 3, False, pages=PAGES_POST, base="http://h.test")
    assert any(f.title == "Possible Reflected XSS"
               and f.url == "http://h.test/submit" for f in out)


def test_ssti_post_body():
    import core.advanced as A
    posted = []
    s = _post_fuzz_session(
        posted,
        lambda d, u: "61126761" if "{{7719*7919}}" in str(d.get("comment", ""))
        else "ok")
    pages = {"http://h.test/": (
        "<form method='post' action='/render'>"
        "<input name='comment'></form>")}
    out = A.test_ssti(s, [], 3, pages=pages, base="http://h.test")
    assert any(f.title == "Possible SSTI (Template Injection)"
               and f.url == "http://h.test/render" for f in out)


def test_oscmd_post_body():
    import core.webchecks as W
    posted = []
    s = _post_fuzz_session(
        posted,
        lambda d, u: "uid=0(root)" if ";" in str(d.get("comment", ""))
        else "ok")
    pages = {"http://h.test/": (
        "<form method='post' action='/ping'>"
        "<input name='comment'></form>")}
    out = W.test_os_command_injection(s, [], 3, pages=pages,
                                      base="http://h.test")
    assert any(f.title == "Possible OS Command Injection"
               and f.url == "http://h.test/ping" for f in out)


def test_crawler_queues_post_forms():
    """POST forms join the crawl as GET probes (crawler stays read-only)."""
    from collections import deque
    from core.crawler import _enqueue_links
    seen, queue, pages = set(), deque(), {}
    html = ("<form method='post' action='/submit'>"
            "<input name='comment'></form>")
    _enqueue_links(html, "http://h.test", seen, queue, 1, 8, pages)
    assert any("submit?comment=" in u for u, _ in queue)


def test_fuzz_params_cover_redirect_traversal():
    from core.scanner import FUZZ_PARAMS, discover_test_urls
    assert len(FUZZ_PARAMS) >= 16
    for p in ("redirect", "next", "file", "page", "template"):
        assert p in FUZZ_PARAMS
    urls = discover_test_urls("<html>no links here</html>", "http://h.test")
    assert any("redirect=1" in u for u in urls)
    assert any("file=1" in u for u in urls)


def test_recurse_dir_mutations():
    """Found dirs get backup-name mutations: /backup -> /backup.bak."""
    from core.net import configure_net
    from core.scanner import smart_recurse
    configure_net()

    class Resp:
        def __init__(self, text="", status_code=200, url=""):
            self.text = text
            self.status_code = status_code
            self.url = url
            self.headers = {}

    class S:
        def get(self, url, timeout=None, allow_redirects=True, headers=None):
            if url.endswith("/backup.bak"):
                return Resp("backup stuff", 200, url)
            return Resp("not found", 404, url)

    ctx = {"found_paths": ["http://h.test/backup"]}
    out = smart_recurse(S(), "http://h.test", 3, ctx=ctx)
    assert any("backup.bak" in f.url and "(recursive)" in f.title for f in out)


def _union_session():
    from core.net import configure_net
    configure_net()

    class Resp:
        def __init__(self, text="", status_code=200, url=""):
            self.text = text
            self.status_code = status_code
            self.url = url
            self.headers = {}

    class S:
        mode = "hit"

        def get(self, url, timeout=None, allow_redirects=True, headers=None):
            if "ORDER" not in url:
                return Resp("<html>rows</html>", 200, url)
            if "100" in url:
                if self.mode == "hit":
                    return Resp("SQL error", 500, url)
                return Resp("<html>rows</html>", 200, url)
            return Resp("<html>rows</html>", 200, url)

    return S()


def test_union_differential():
    import core.advanced as A
    s = _union_session()
    out = A.test_sqli_blind(s, ["http://h.test/?id=1"], 3, deep=False)
    assert any(f.title == "Possible SQL Injection (ORDER BY differential)"
               for f in out)
    s.mode = "clean"
    out = A.test_sqli_blind(s, ["http://h.test/?id=1"], 3, deep=False)
    assert all("ORDER BY" not in f.title for f in out)


def test_fingerprint_dbms():
    from core.scanner import fingerprint_dbms
    assert fingerprint_dbms("you have an error in your sql syntax") == "MySQL/MariaDB"
    assert fingerprint_dbms("pg_query() failed") == "PostgreSQL"
    assert fingerprint_dbms("unclosed quotation mark") == "MSSQL"
    assert fingerprint_dbms("ORA-00933 blah") == "Oracle"
    assert fingerprint_dbms("sqlite3 oops") == "SQLite"
    assert fingerprint_dbms("weird stuff") == "Unknown"


def test_oob_sqli_pending_and_drain():
    import core.advanced as A
    import core.oob as O
    from core.net import configure_net
    configure_net()

    class FakeOob:
        def __init__(self):
            self.pending = []
            self.wait = 0
            self.session_domain = "x.oob.test"

        def url_for(self, token):
            return f"https://{token}.oob.test/x"

        def deregister(self):
            pass

    class Resp:
        def __init__(self, text="", status_code=200, url=""):
            self.text = text
            self.status_code = status_code
            self.url = url
            self.headers = {}

    class S:
        def get(self, url, timeout=None, allow_redirects=True, headers=None):
            return Resp("<html>ok</html>", 200, url)

    fake = FakeOob()
    A.test_sqli_blind(S(), ["http://h.test/?id=1"], 3, deep=True, oob=fake)
    assert any(p["kind"] == "sqli" for p in fake.pending)
    fake2 = FakeOob()
    fake2.pending = [{"kind": "sqli", "target": "http://h.test/?id=1",
                      "token": "gsql"}]
    hits = [{"full-id": "gsql.oob.test", "protocol": "dns",
             "remote-address": "9.9.9.9"}]

    class FakeClient:
        wait = 0
        pending = fake2.pending

        def poll(self):
            return hits

        def deregister(self):
            pass

    out = O.drain(FakeClient(), verbose=False)
    assert len(out) == 1 and out[0].title == "SQLi (confirmed via OOB)"
    assert out[0].severity == "CRITICAL"


def test_login_enum():
    import core.advanced as A
    from core.net import configure_net
    configure_net()

    class Resp:
        def __init__(self, text="", status_code=200, url=""):
            self.text = text
            self.status_code = status_code
            self.url = url
            self.headers = {}

    class Diff:
        def get(self, url, timeout=None, allow_redirects=True, headers=None):
            return Resp("<html>ok</html>", 200, url)

        def post(self, url, timeout=None, allow_redirects=True, **kw):
            data = kw.get("data", {})
            user = str(data.get("user", ""))
            if user == "admin":
                return Resp("<html>invalid password</html>", 200, url)
            return Resp("<html>invalid username</html>", 200, url)

    class Same:
        def get(self, url, timeout=None, allow_redirects=True, headers=None):
            return Resp("<html>ok</html>", 200, url)

        def post(self, url, timeout=None, allow_redirects=True, **kw):
            return Resp("<html>invalid credentials</html>", 200, url)

    pages = {"http://h.test/login":
             "<form method='post' action='/login'>"
             "<input type='text' name='user'>"
             "<input type='password' name='pass'></form>"}
    out = A.test_login_enum(Diff(), pages, "http://h.test", 3)
    assert len(out) == 1 and out[0].severity == "LOW"
    assert A.test_login_enum(Same(), pages, "http://h.test", 3) == []


def test_partial_results_carry_findings():
    from core.net import PartialResults, ScanBudgetExceeded
    from core.scanner import Finding
    f = Finding(title="T", severity="LOW", url="http://h/")
    p = PartialResults([f], "budget out")
    assert isinstance(p, ScanBudgetExceeded)
    assert p.findings == [f]


def test_run_scan_raises_partial_on_budget(monkeypatch):
    """Budget death mid-scan surfaces partial findings, not silence."""
    import pytest
    import core.scanner as S
    import core.advanced  # noqa: F401
    import core.domxss  # noqa: F401
    import core.webchecks  # noqa: F401
    from core.net import configure_net, PartialResults
    from core.registry import REGISTRY
    monkeypatch.setattr(S, "_fetch_base",
                        lambda *a, **k: ("", "http://h.test", {}))

    class Resp:
        def __init__(self, text="", status_code=200, url=""):
            self.text = text
            self.status_code = status_code
            self.url = url
            self.headers = {}

    class FakeSession:
        def get(self, url, timeout=None, allow_redirects=True, headers=None):
            if "'" in url or "%27" in url:
                return Resp("You have an error in your SQL syntax", 200, url)
            return Resp("<html>ok</html>", 200, url)

    import core.scanner as _S
    monkeypatch.setattr(_S, "_session", lambda timeout, auth=None: FakeSession())
    configure_net(0.0, 2)
    try:
        with pytest.raises(PartialResults) as ei:
            S.run_scan("http://h.test", threads=1, timeout=3, verbose=False,
                       deep=False, no_crawl=True,
                       skip_checks=set(REGISTRY) - {"sqli-error"})
    finally:
        configure_net()
    assert len(ei.value.findings) == 1


def test_print_findings_incomplete_never_clean(capsys):
    from core.reporter import print_findings
    print_findings([], verbose=False, incomplete=True)
    out = capsys.readouterr().out
    assert "INCOMPLETE" in out and "Clean" not in out
    print_findings([], verbose=False, incomplete=False)
    assert "Clean" in capsys.readouterr().out


def test_report_marks_incomplete():
    from core.reporter import build_report, save_report
    r = build_report("http://h.test", "full", "0", findings=[],
                     elapsed=1.0, incomplete=True)
    assert r["incomplete"] is True
    import tempfile, os
    with tempfile.TemporaryDirectory() as d:
        p = os.path.join(d, "r.txt")
        save_report(r, p)
        txt = open(p, encoding="utf-8").read()
        assert "WARNING" in txt and "INCOMPLETE" in txt


def test_incomplete_scan_skips_history_and_clean_claim(monkeypatch, tmp_path,
                                                       capsys):
    """Rate-limited scan: report saved, history untouched, no 'Clean'."""
    import os
    import gash
    from core.net import PartialResults
    from core.scanner import Finding
    from types import SimpleNamespace
    monkeypatch.chdir(tmp_path)

    conf = Finding(title="Possible SQL Injection", severity="CRITICAL",
                   url="http://h.test/?id=1")

    def boom(*a, **k):
        raise PartialResults([conf], "rate-limited by target")

    monkeypatch.setattr(gash, "run_scan", boom)
    args = SimpleNamespace(delay=0.0, max_requests=0, cookie=None,
                           header=None, login_user=None, login_pass=None,
                           login_url=None, timeout=3, skip_ports=True,
                           ports=None, threads=5, verbose=False,
                           wordlist=None, quick=False, deep=False,
                           skip_checks=None, max_pages=1, depth=1,
                           no_crawl=True, dom=False, blind_callback=None,
                           scope=None, fail_on=None, resume=False,
                           output=str(tmp_path / "r.json"), output_dir=None,
                           oob=False, oob_server=None, oob_wait=0, proxy=None,
                           user_agent=None, insecure=False, cookie_b=None,
                           header_b=None)
    assert gash.run_single("http://h.test", args, "scan") == 0
    out = capsys.readouterr().out
    assert "INCOMPLETE" in out and "Clean" not in out
    assert os.path.exists(tmp_path / "r.json")
    assert not os.path.exists(tmp_path / ".gash_history")


def test_calm_down_caps_and_budget(monkeypatch):
    """Single 429 wait capped at 10s; cumulative budget aborts the scan."""
    import time as _time
    from core.net import configure_net, get_context, ScanBudgetExceeded
    from core.scanner import _calm_down
    configure_net()
    slept = []
    monkeypatch.setattr(_time, "sleep", lambda s: slept.append(s))
    _calm_down(30, "x")
    assert slept == [10]
    assert get_context().rate_wait_total == 10
    get_context().rate_wait_total = 115.0
    try:
        _calm_down(30, "x")
        assert False, "should have raised"
    except ScanBudgetExceeded:
        pass
    assert slept == [10]  # no extra sleep on abort
    configure_net()


def test_save_report_creates_dirs(tmp_path):
    import gash
    from gash import ScanResult
    path = str(tmp_path / "reports" / "sub" / "r.json")
    assert gash._save_report("http://h.test", "full", ScanResult(), path) is True
    import os
    assert os.path.exists(path)


def test_spinner_noop_when_piped():
    """Piped/CI output: no threads, no escape codes, no crash."""
    import threading
    import time as _time
    from core import spinner as SP
    assert SP._tty() is False  # pytest captures stdout
    before = set(threading.enumerate())
    with SP.spin("working..."):
        _time.sleep(0.05)
    extra = [t for t in threading.enumerate()
             if t not in before and t.is_alive()]
    assert extra == []


def test_spinner_runs_on_tty(monkeypatch):
    from core import spinner as SP
    monkeypatch.setattr(SP, "_tty", lambda: True)
    with SP.spin("working...") as sp:
        assert sp._thread is not None
        sp.update("still working...")
    assert sp._thread is None  # joined on exit


def test_countdown_piped(monkeypatch, capsys):
    import time as _time
    from core.spinner import countdown
    slept = []
    monkeypatch.setattr(_time, "sleep", lambda s: slept.append(s))
    countdown("waiting", 3)
    assert slept == [3]
    assert "waiting 3s" in capsys.readouterr().out


def test_countdown_tty(monkeypatch, capsys):
    import time as _time
    from core import spinner as SP
    monkeypatch.setattr(SP, "_tty", lambda: True)
    now = [1000.0]
    slept = []
    monkeypatch.setattr(_time, "time", lambda: now[0])

    def fake_sleep(s):
        slept.append(s)
        now[0] += s

    monkeypatch.setattr(_time, "sleep", fake_sleep)
    SP.countdown("waiting", 3)
    assert slept == [1, 1, 1]
    assert "waiting" in capsys.readouterr().out

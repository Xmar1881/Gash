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

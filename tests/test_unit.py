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
        "Stored reflection (unconfirmed)",
        "Possible Reflected XSS", "Possible Reflected XSS (404 page)",
        "Reflected input (unconfirmed)",
        "Header reflection XSS surface (User-Agent)",
        "Partially encoded reflection (review manually)",
        "Blind XSS canary placed (unverified)",
        "Possible SSTI (Template Injection)", "Possible SSRF (cloud metadata)",
        "SSRF surface (manual testing advised)",
        "Possible IDOR / BOLA (single session)",
        "Confirmed IDOR / BOLA (cross-session)",
        "Missing authentication on object endpoint",
        "Direct object reference reachable anonymously",
        "Possible missing authorization (admin surface)",
        "Missing authorization on admin endpoint",
        "TLS certificate expired", "TLS hostname mismatch",
        "Self-signed TLS certificate", "TLS certificate expires soon",
        "TLS certificate not yet valid", "Weak TLS protocol enabled",
        "Weak TLS cipher negotiated",
        "GraphQL mutations exposed", "Exposed sensitive GraphQL field",
        "GraphQL weak input contract",
        "Known vulnerable component (CVE-2020-11022)",
        "End-of-life component (PHP 5.6)",
        "Exposed development server", "Local development server",
        "Local listeners inventory",
        "Local UDP service (DNS)", "LAN-visible UDP service (MDNS)",
        "Overly broad secret file permissions", "Secret file present",
        "Host firewall disabled", "Container/VM network present",
        "Container published port", "WSL port forwarding",
        "Possible Unrestricted File Upload (confirmed)",
        "Upload Filter Bypass (RCE vector)",
        "Stored file via JSON upload",
        "Upload content-type not validated",
        "Upload filename handling (path reflection)",
        "Admin Panel", "Critical File Exposure: x", "Sensitive Directory: y",
        "robots.txt Found", "Prototype Pollution Reflection Surface",
        "DOM XSS (confirmed — alert fired)",
        "DOM XSS (confirmed — executable sink)",
        "DOM XSS (suspected — controllable sink)",
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


def test_xss_context_breakout_vs_unconfirmed():
    from core.xss_context import classify_reflection, find_marker_contexts
    # full payload echoes raw -> breakout, context detected
    body = '<html><p>gx1"><svg onload=alert(1)></p></html>'
    v = classify_reflection(body, "gx1", 'gx1"><svg onload=alert(1)>')
    assert v["status"] == "breakout"
    assert v["context"] == "html-text"
    # marker only, breaker stripped -> unconfirmed, never High/CRITICAL
    v2 = classify_reflection("<html><p>gx1</p></html>", "gx1",
                             'gx1"><svg onload=alert(1)>')
    assert v2["status"] == "raw-unconfirmed"
    # encoded -> encoded
    v3 = classify_reflection("<p>&lt;gx1&gt;</p>", "gx1",
                             'gx1"><svg onload=alert(1)>')
    assert v3["status"] == "encoded"
    assert v3["encoded"] is True
    assert classify_reflection("<p>hello</p>", "gx1")["status"] == "none"
    assert find_marker_contexts(None, "gx1") == []


def test_xss_context_attr_js_comment():
    from core.xss_context import detect_context
    b = '<input value="gx1">'
    assert detect_context(b, b.find("gx1"), "gx1")["context"] == "attr-double-quoted"
    b2 = "<input value='gx1'>"
    assert detect_context(b2, b2.find("gx1"), "gx1")["context"] == "attr-single-quoted"
    b3 = '<input value=gx1>'
    assert detect_context(b3, b3.find("gx1"), "gx1")["context"] == "attr-unquoted"
    b4 = '<div onclick="do(gx1)">'
    d = detect_context(b4, b4.find("gx1"), "gx1")
    assert d["context"] == "event-handler"
    b5 = '<script>var x=\'gx1\';</script>'
    assert detect_context(b5, b5.find("gx1"), "gx1")["context"] == "js-string-single"
    b6 = '<!-- gx1 -->'
    assert detect_context(b6, b6.find("gx1"), "gx1")["context"] == "html-comment"
    b7 = '<a href="gx1">x</a>'
    assert detect_context(b7, b7.find("gx1"), "gx1")["context"] == "url-attr"


def test_xss_reflected_confidence_downgrade():
    """Raw reflection alone must not yield High confidence anymore."""
    import core.scanner as SC

    class Resp:
        def __init__(self, text=""):
            self.status_code = 200
            self.text = text
            self.url = "http://h.test/?q=1"
            self.headers = {}

    class S:
        def __init__(self, body_fn):
            self._fn = body_fn

        def get(self, url, timeout=None, allow_redirects=True, headers=None):
            return Resp(self._fn(url))

    # full echo incl. breaker -> Possible Reflected XSS, Medium/Medium
    from urllib.parse import urlparse as _up, parse_qs as _pqs

    def _echo(url: str) -> str:
        try:
            q = _pqs(_up(url).query, keep_blank_values=True)
            vals = " ".join(sum(q.values(), []))  # server decodes %XX
        except Exception:
            vals = url
        return f"<html>{vals}</html>"

    s = S(_echo)
    out = SC.test_xss(s, ["http://h.test/?q=1"], 3, False, deep=False)
    hit = next(f for f in out if f.title == "Possible Reflected XSS")
    assert hit.severity == "MEDIUM" and hit.confidence == "Medium"
    # breaker stripped, marker only -> unconfirmed LOW/Low, no High anywhere
    s2 = S(lambda u: "<html><p>gx1</p><p>gx2</p><p>gx3</p></html>")
    out2 = SC.test_xss(s2, ["http://h.test/?q=1"], 3, False, deep=False)
    assert any(f.title == "Reflected input (unconfirmed)" for f in out2)
    assert all(f.confidence != "High" for f in out2
               if "XSS" in f.title or "Reflected" in f.title)


def test_xss_payload_generator_contexts():
    from core.xss_payloads import (generate_for_context, mutate_payload,
                                   filter_probe_strings)
    assert len(filter_probe_strings("gx1")) >= 10
    assert filter_probe_strings("") == []
    for ctx in ("html-text", "attr-double-quoted", "attr-single-quoted",
                "attr-unquoted", "event-handler", "url-attr",
                "js-string-single", "js-string-double",
                "js-template-literal", "js-expression", "html-comment",
                "style-css", "svg-text", "json-string", "nope-unknown"):
        vecs = generate_for_context(ctx, "gx9")
        assert 1 <= len(vecs) <= 8, ctx
        assert all(v[0].startswith("gx9") or "gx9" in v[0] for v in vecs)
        assert all(1 <= v[1] <= 10 for v in vecs)
        assert len({v[0] for v in vecs}) == len(vecs)  # deduped
    assert generate_for_context("html-text", "") == []
    muts = mutate_payload('gx1"><svg onload=alert(1)>')
    assert 2 <= len(muts) <= 4 and muts[0].startswith("gx1")
    assert len(set(muts)) == len(muts)


def test_xss_stage2_generator_breakout():
    """Stage-1 misses (encoded-looking first hit), generator finds it."""
    import core.scanner as SC
    from urllib.parse import urlparse as _up, parse_qs as _pqs, unquote as _uq

    class Resp:
        def __init__(self, text=""):
            self.status_code = 200
            self.text = text
            self.url = "http://h.test/?q=1"
            self.headers = {}

    def body_for(url: str) -> str:
        from core.scanner import XSS_PROBES
        try:
            q = _pqs(_up(url).query, keep_blank_values=True)
            vals = sum(q.values(), [])
            val = _uq(vals[0] if vals else "")
        except Exception:
            val = ""
        # naive filter: eats exactly the 3 stock probes (appended after the
        # original value by _inject), keeps generator alternatives.
        for _ctx, _marker, _stock in XSS_PROBES:
            if _stock in val:
                return f"<html><p>{_marker}</p></html>"
        return f"<html><p>{val}</p></html>"

    class S:
        def get(self, url, timeout=None, allow_redirects=True, headers=None):
            return Resp(body_for(url))

    out = SC.test_xss(S(), ["http://h.test/?q=1"], 3, False, deep=False)
    assert any(f.title == "Possible Reflected XSS"
               and "Generated payload" in f.detail for f in out)


def _stored_state_session(store: dict, requested: list):
    class Resp:
        def __init__(self, text="", url=""):
            self.text = text
            self.status_code = 200
            self.url = url
            self.headers = {}

    class S:
        def get(self, url, timeout=None, allow_redirects=True, headers=None):
            from urllib.parse import urlparse as _up, parse_qs as _pqs
            try:
                q = _pqs(_up(url).query, keep_blank_values=True)
                for vals in q.values():
                    for v in vals:
                        if v.startswith("gashstored"):
                            store.setdefault("saved", {})["q"] = v
            except Exception:
                pass
            requested.append(url)
            saved = (store.get("saved") or {}).get("q", "")
            mode = store.get("mode", "persist")
            if saved:
                if mode == "persist":
                    # persistence WITHOUT breaker: strip <>"'`
                    import re as _re
                    clean = _re.sub(r'[<>"\'`]', "", saved)
                    return Resp(f"<html><p>{clean}</p></html>", url=url)
                return Resp(f"<html><p>{saved}</p></html>", url=url)
            return Resp("<html>ok</html>", url=url)

        def post(self, url, timeout=None, allow_redirects=True, **kw):
            return Resp("ok", url=url)

    return S()


def test_stored_persistence_only_is_unconfirmed():
    import core.advanced as A
    store, requested = {"mode": "persist"}, []
    pages = {"http://h.test/":
             "<form method='get' action='/go'><input name='q'></form>"}
    out = A.test_stored_xss(_stored_state_session(store, requested),
                            pages, "http://h.test", 3)
    assert any(f.title == "Stored reflection (unconfirmed)"
               and f.severity == "LOW" and f.confidence == "Low" for f in out)
    assert all(f.title != "Possible Stored XSS" for f in out)


def test_stored_breakout_is_possible_not_critical():
    import core.advanced as A
    store, requested = {"mode": "breakout"}, []
    pages = {"http://h.test/":
             "<form method='get' action='/go'><input name='q'></form>"}
    out = A.test_stored_xss(_stored_state_session(store, requested),
                            pages, "http://h.test", 3)
    hit = next(f for f in out if f.title == "Possible Stored XSS")
    assert hit.severity == "MEDIUM" and hit.confidence == "Medium"
    assert "q" in hit.detail and "context" in hit.detail


def test_dom_classify_sink():
    from core.domxss import classify_sink
    assert classify_sink("eval", "x gxdom y")["verdict"] == "confirmed"
    assert classify_sink("Function", "gxdom+''")["verdict"] == "confirmed"
    assert classify_sink("setTimeout", "gxdom;foo")["verdict"] == "confirmed"
    v = classify_sink("innerHTML", 'hi gxdom"><svg onload=alert(1)>')
    assert v["verdict"] == "confirmed"
    v = classify_sink("innerHTML", "hello gxdom plain text")
    assert v["verdict"] == "suspected"
    v = classify_sink("document.write", "gxdom &lt;svg&gt;")
    assert v["verdict"] == "suspected"  # encoded, not executable
    v = classify_sink("setAttribute:onclick", "do(gxdom)")
    assert v["verdict"] == "confirmed"
    v = classify_sink("setAttribute:href", "page gxdom info")
    assert v["verdict"] == "suspected"
    v = classify_sink("setAttribute:href", "javascript:alert(gxdom)")
    assert v["verdict"] == "confirmed"
    assert classify_sink("innerHTML", "no marker here")["verdict"] == "safe"
    assert classify_sink("", "gxdom")["verdict"] == "safe"
    assert "executable" in classify_sink(
        "createContextualFragment", "gxdom<img src=x>").get("reason", "") \
        or classify_sink(
            "createContextualFragment", "gxdom<img src=x>")["verdict"] == "confirmed"


def _fake_dom_browser(sinks=None, samples=None, dialogs=None,
                       alerted=None, dom_html="<html>clean</html>",
                       pm_effect=None, st_effect=None, ref_effect=None):
    """Staged fake: postMessage/storage/referrer effects merge on use.

    Each effect is (sinks, samples). browser.calls records which stages
    ran (proves tiered early-exit).
    """

    class FakeDialog:
        def __init__(self, message):
            self.message = message

        def dismiss(self):
            pass

    calls = {"postMessage": 0, "storage": 0, "referer": 0,
             "goto": 0, "reload": 0}
    state = {"sinks": list(sinks or []),
             "samples": dict(samples or {}),
             "fired": list(alerted or [])}
    used = {"pm": False, "st": False, "ref": False}

    class FakePage:
        def on(self, ev, cb):
            if ev == "dialog":
                for m in (dialogs or []):
                    cb(FakeDialog(m))

        def add_init_script(self, js):
            pass

        def goto(self, url, timeout=None, wait_until=None, referer=None):
            calls["goto"] += 1
            if referer:
                calls["referer"] += 1
                if ref_effect and not used["ref"]:
                    used["ref"] = True
                    state["sinks"] += ref_effect[0]
                    state["samples"].update(ref_effect[1])

        def reload(self, wait_until=None):
            calls["reload"] += 1

        def wait_for_timeout(self, ms):
            pass

        def evaluate(self, script):
            if "postMessage" in script:
                calls["postMessage"] += 1
                if pm_effect and not used["pm"]:
                    used["pm"] = True
                    state["sinks"] += pm_effect[0]
                    state["samples"].update(pm_effect[1])
                return None
            if "setItem" in script:
                calls["storage"] += 1
                if st_effect and not used["st"]:
                    used["st"] = True
                    state["sinks"] += st_effect[0]
                    state["samples"].update(st_effect[1])
                return None
            if "__gash_sink_samples" in script:
                return dict(state["samples"])
            if "__gash_fired" in script:
                return list(state["fired"])
            if "__gash_sinks" in script:
                return list(state["sinks"])
            return None

        def content(self):
            return dom_html

        def close(self):
            pass

    class FakeBrowser:
        def __init__(self):
            self.calls = calls

        def new_page(self, ignore_https_errors=True):
            return FakePage()

    return FakeBrowser()


def test_dom_probe_executable_sink():
    from core.domxss import _probe_page
    b = _fake_dom_browser(sinks=["innerHTML"],
                          samples={"innerHTML": 'hi gxdom"><svg onload=alert(1)>'})
    f = _probe_page(b, "http://h.test/?gxdomq=1", "http://h.test", 3, {})
    assert f is not None
    assert f.title == "DOM XSS (confirmed — executable sink)"
    assert f.severity == "CRITICAL" and f.confidence == "High"


def test_dom_probe_suspected_not_confirmed():
    from core.domxss import _probe_page
    b = _fake_dom_browser(sinks=["innerHTML"],
                          samples={"innerHTML": "hello gxdom plain text"})
    f = _probe_page(b, "http://h.test/?gxdomq=1", "http://h.test", 3, {})
    assert f is not None
    assert f.title == "DOM XSS (suspected — controllable sink)"
    assert f.severity == "LOW" and f.confidence == "Medium"


def test_dom_probe_alert_and_info_paths():
    from core.domxss import _probe_page
    b = _fake_dom_browser(dialogs=["boom gxdom"])
    f = _probe_page(b, "http://h.test/", "http://h.test", 3, {})
    assert f is not None and f.title == "DOM XSS (confirmed — alert fired)"
    b2 = _fake_dom_browser(dom_html="<html>rendered gxdom here</html>")
    f2 = _probe_page(b2, "http://h.test/", "http://h.test", 3,
                     {"http://h.test/": "<html>raw without marker</html>"})
    assert f2 is not None and f2.title == "JS DOM write (review manually)"
    assert f2.severity == "INFO"
    b3 = _fake_dom_browser()
    assert _probe_page(b3, "http://h.test/", "http://h.test", 3, {}) is None


def test_dom_source_postmessage_chain():
    from core.domxss import _probe_page
    b = _fake_dom_browser(
        pm_effect=(["innerHTML"],
                   {"innerHTML": 'gxdom-pm"><svg onload=alert(1)>'}))
    f = _probe_page(b, "http://h.test/?gxdomq=1", "http://h.test", 3, {})
    assert f is not None
    assert f.title == "DOM XSS (confirmed — executable sink)"
    assert "postMessage" in f.detail and "innerHTML" in f.detail
    assert "raw" in f.detail


def test_dom_source_storage_suspected_and_tiering():
    from core.domxss import _probe_page
    b = _fake_dom_browser(
        st_effect=(["outerHTML"], {"outerHTML": "hello gxdom-st plain"}))
    f = _probe_page(b, "http://h.test/", "http://h.test", 3, {})
    assert f is not None
    assert f.title == "DOM XSS (suspected — controllable sink)"
    assert "ocalStorage" in f.detail  # source chain recorded
    # tiered: load found nothing executable, so later stages ran…
    assert b.calls["postMessage"] == 1 and b.calls["storage"] == 1
    # …but an early confirm skips the rest (no referrer navigation here
    # would change the verdict; suspected waits for all stages)
    b2 = _fake_dom_browser(
        sinks=["innerHTML"],
        samples={"innerHTML": 'hi gxdom"><svg onload=alert(1)>'})
    f2 = _probe_page(b2, "http://h.test/", "http://h.test", 3, {})
    assert f2.title == "DOM XSS (confirmed — executable sink)"
    assert b2.calls["postMessage"] == 0 and b2.calls["storage"] == 0 \
        and b2.calls["referer"] == 0  # early exit saves ~6s


def test_dom_referrer_and_new_sinks():
    from core.domxss import classify_sink, _transform_note
    assert classify_sink("location.assign",
                         "x javascript:alert(gxdom)")["verdict"] == "confirmed"
    assert classify_sink("location.assign",
                         "http://h.test/?a=gxdom")["verdict"] == "suspected"
    assert classify_sink("srcdoc",
                         'gxdom"><svg onload=x>')["verdict"] == "confirmed"
    assert classify_sink("src",
                         "http://cdn.test/lib.js?x=gxdom")["verdict"] == "suspected"
    assert classify_sink("script.src",
                         "javascript:alert(gxdom)")["verdict"] == "confirmed"
    assert classify_sink("domain", "evil-gxdom-test")["verdict"] == "suspected"
    assert _transform_note('a"><svg onload=x>') == "raw"
    assert _transform_note("plain gxdom text") == "filtered-or-text"
    from core.domxss import _probe_page
    b = _fake_dom_browser(
        ref_effect=(["location.assign"],
                    {"location.assign": "javascript:alert(gxdom)"}))
    f = _probe_page(b, "http://h.test/", "http://h.test", 3, {})
    assert f is not None
    assert f.title == "DOM XSS (confirmed — executable sink)"
    assert "document.referrer" in f.detail


def test_finding_new_fields_roundtrip():
    from core.scanner import Finding
    f = Finding(title="T", severity="MEDIUM", url="http://h.test/?q=1",
                method="PUT", param="user.role", location="body",
                auth_context="user", fingerprint="x" * 500,
                confirm="breakout", check="xss-reflected")
    d = f.to_dict()
    assert d["method"] == "PUT" and d["param"] == "user.role"
    assert d["location"] == "body" and d["confirm"] == "breakout"
    assert d["check"] == "xss-reflected" and len(d["fingerprint"]) == 120
    g = Finding(title="T", severity="LOW", url="http://h/")
    d2 = g.to_dict()
    assert d2["method"] == "" and d2["check"] == ""


def test_registry_stamps_check_name():
    import core.scanner  # noqa: F401
    import core.advanced  # noqa: F401
    import core.domxss  # noqa: F401
    import core.webchecks  # noqa: F401
    from core.registry import REGISTRY, run_checks
    from core.scanner import Finding

    def _one(session):
        return [Finding(title="ZZ", severity="LOW", url="http://h.test/")]

    REGISTRY["zz-stamp"] = {"fn": _one, "desc": "stamp",
                            "deep_only": False, "order": 999, "seq": 9999}
    try:
        ctx = {"headers": {}, "base": "http://h.test"}
        out = run_checks(object(), ctx, skip=set(REGISTRY) - {"zz-stamp"})
    finally:
        del REGISTRY["zz-stamp"]
    assert len(out) == 1 and out[0].check == "zz-stamp"


def test_report_sarif_and_junit(tmp_path):
    from core.reporter import build_report, save_report
    from core.scanner import Finding
    vuln = Finding(title="Possible Reflected XSS", severity="MEDIUM",
                   url="http://h.test/?q=1", detail="breaker here",
                   evidence="gx1", confidence="Medium", cwe="CWE-79",
                   check="xss-reflected")
    obs = Finding(title="robots.txt Found", severity="INFO",
                  url="http://h.test/robots.txt", detail="note")
    rep = build_report("http://h.test", "full", "9.9", findings=[vuln, obs])
    sp = save_report(rep, str(tmp_path / "r.sarif"))
    import json as _json
    sarif = _json.loads(open(sp, encoding="utf-8").read())
    assert sarif["version"] == "2.1.0"
    rules = {r["id"]: r for r in
             sarif["runs"][0]["tool"]["driver"]["rules"]}
    assert "gash/possible-reflected-xss" in rules
    by_rule = {r["ruleId"]: r for r in sarif["runs"][0]["results"]}
    assert by_rule["gash/possible-reflected-xss"]["level"] == "error"
    assert by_rule["gash/robots-txt-found"]["level"] == "note"
    xp = save_report(rep, str(tmp_path / "r.xml"))
    import xml.etree.ElementTree as _et
    root = _et.parse(xp).getroot()
    assert root.tag == "testsuite" and root.attrib["failures"] == "1"
    cases = root.findall("testcase")
    assert any(c.find("failure") is not None for c in cases)
    assert any(c.find("skipped") is not None for c in cases)


def test_report_html_soft_design(tmp_path):
    from core.reporter import build_report, save_report
    from core.scanner import Finding
    vuln = Finding(title="Possible Reflected XSS", severity="MEDIUM",
                   url="http://h.test/?q=1", detail="breaker here",
                   evidence="gx1", confidence="Medium", method="GET",
                   param="q", location="query", confirm="breakout",
                   check="xss-reflected")
    rep = build_report("http://h.test", "full", "9.9", findings=[vuln])
    html = open(save_report(rep, str(tmp_path / "r.html")),
                encoding="utf-8").read()
    assert "linear-gradient" in html  # soft hero banner
    assert "article class='finding mid'" in html  # card, not table row
    assert "param: q" in html and "confirm: breakout" in html  # chips
    assert "#0a0a0a" not in html  # old hacker theme gone


def test_spa_extract_routes():
    from core.xss_spa import extract_spa_routes
    html = ('<script>fetch("/api/users");'
            'router.push("/dashboard");'
            'axios.get("/v1/orders")</script>'
            '<a href="https://evil.com/x">out</a>')
    routes = extract_spa_routes(html, "http://h.test")
    assert "http://h.test/api/users" in routes
    assert "http://h.test/dashboard" in routes
    assert "http://h.test/v1/orders" in routes
    assert all("evil.com" not in r for r in routes)
    nd = '{"buildId":"x","pages":["/","/admin","/user/[id]"]}'
    routes2 = extract_spa_routes(
        f'<script id="__NEXT_DATA__">{nd}</script>', "http://h.test")
    assert "http://h.test/admin" in routes2
    assert extract_spa_routes("", "http://h.test") == []


def test_spa_extract_params():
    from core.xss_spa import extract_param_names
    names = extract_param_names('{"sort":"asc","order":"desc","filter":1}',
                                'var x={"callback":"y","z":1}')
    assert "sort" in names and "callback" in names
    assert "true" not in names  # stoplist
    assert names == list(dict.fromkeys(names))  # deduped
    assert len(extract_param_names("{\"a1\":1}" * 200)) <= 40
    assert extract_param_names(None, "") == []


def test_prioritize_urls():
    from core.xss_spa import prioritize_urls
    urls = ["http://h.test/static",
            "http://h.test/api/users",
            "http://h.test/go?q=gash",
            "http://h.test/view?callback=1",
            "http://h.test/go?q=gash"]  # dupe
    ranked = prioritize_urls(urls)
    assert len(ranked) == 4  # deduped
    assert ranked.index("http://h.test/go?q=gash") < \
        ranked.index("http://h.test/static")
    assert ranked.index("http://h.test/view?callback=1") < \
        ranked.index("http://h.test/static")


def test_runtime_discover_without_playwright(monkeypatch):
    import importlib.util
    from core import xss_spa
    monkeypatch.setattr(importlib.util, "find_spec", lambda *a, **k: None)
    out = xss_spa.runtime_discover("http://h.test", 3, verbose=False)
    assert out == {"urls": [], "api": [], "params": []}


def test_build_probe_pool_cap_and_spa():
    from core.scanner import _build_probe_pool
    pages = {f"http://h.test/p{i}": "" for i in range(10)}
    pool = _build_probe_pool(pages, "http://h.test", limit=5)
    assert len(pool) <= 5
    pool2 = _build_probe_pool({"http://h.test/": ""}, "http://h.test",
                              spa_urls=["http://h.test/api/users",
                                        "http://h.test/app"],
                              limit=25)
    assert any("api/users" in u for u in pool2)
    assert any("id=1" in u for u in pool2)  # query-less SPA -> probe


def test_discover_fallback_uses_hidden_params():
    from core.scanner import discover_test_urls, FUZZ_PARAMS
    assert FUZZ_PARAMS[:16] == ["id", "q", "query", "s", "search",
                                "keyword", "name", "term", "file", "page",
                                "lang", "redirect", "next", "preview",
                                "template", "theme"]
    urls = discover_test_urls("<html>empty</html>", "http://h.test")
    blob = " ".join(urls)
    assert "?redirect=1" in blob  # historic fallback order kept (cap 12)
    assert len(FUZZ_PARAMS) > 40  # P3 hidden set ships with the scanner
    assert "callback" in FUZZ_PARAMS and "sort" in FUZZ_PARAMS
    urls2 = discover_test_urls("<html>empty</html>", "http://h.test",
                               extra_params=["mycustomparam"])
    assert any("mycustomparam" in u for u in urls2)


def test_run_checks_records_error_skipped_and_continues(monkeypatch, capsys):
    import core.scanner  # noqa: F401
    import core.advanced  # noqa: F401
    import core.domxss  # noqa: F401
    import core.webchecks  # noqa: F401
    from core.registry import REGISTRY, run_checks

    def _boom(session):
        raise RuntimeError("kaboom")

    REGISTRY["zz-boom"] = {"fn": _boom, "desc": "boom",
                           "deep_only": False, "order": 999, "seq": 9999}
    try:
        keep = {"zz-boom", "waf-detect", "upload-rce"}
        ctx = {"headers": {}, "base": "http://h.test"}
        out = run_checks(object(), ctx, skip=set(REGISTRY) - keep,
                         deep=False)
    finally:
        del REGISTRY["zz-boom"]
    assert out == []
    by_name = {r["check"]: r for r in ctx["check_status"]}
    err = by_name["zz-boom"]
    assert err["status"] == "error"
    assert err["error_type"] == "RuntimeError" and "kaboom" in err["error"]
    assert by_name["waf-detect"]["status"] == "passed"  # others still ran
    assert by_name["upload-rce"]["status"] == "skipped"
    assert by_name["upload-rce"]["reason"] == "deep-only (needs --deep)"
    assert by_name["sqli-blind"]["reason"] == "skip-checks"
    assert "check error (zz-boom)" in capsys.readouterr().out


def test_degraded_report_never_clean(capsys):
    from core.reporter import build_report, print_findings
    rec = {"check": "zz-boom", "status": "error",
           "error_type": "RuntimeError", "error": "kaboom",
           "elapsed_ms": 1, "findings": 0}
    rep = build_report("http://h.test", "full", "0.0",
                       check_status=[rec])
    assert rep["scan_health"]["degraded"] is True
    assert rep["scan_health"]["errors"][0]["check"] == "zz-boom"
    print_findings([], check_status=[rec])
    out = capsys.readouterr().out
    assert "SCAN DEGRADED" in out and "Clean" not in out
    rep2 = build_report("http://h.test", "full", "0.0", check_status=[])
    assert rep2["scan_health"] == {"degraded": False, "errors": [],
                                   "partial": [], "skipped": [], "ran": 0}


def test_run_scan_exposes_check_health(monkeypatch):
    import core.scanner as S
    import core.advanced  # noqa: F401
    import core.domxss  # noqa: F401
    import core.webchecks  # noqa: F401
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
        cookies = []
        headers = {}

        def get(self, url, timeout=None, allow_redirects=True, headers=None):
            return Resp("<html>ok</html>", 200, url)

    monkeypatch.setattr(S, "_session", lambda timeout, auth=None: FakeSession())
    from core.net import configure_net
    configure_net()
    health: dict = {}
    out = S.run_scan("http://h.test", threads=1, timeout=3, verbose=False,
                     deep=False, no_crawl=True,
                     skip_checks=set(REGISTRY) - {"waf-detect"},
                     health=health)
    assert out == []
    by_name = {r["check"]: r for r in health["checks"]}
    assert by_name["waf-detect"]["status"] == "passed"
    assert by_name["sqli-login"]["status"] == "skipped"


def test_crawler_stats_and_truncation():
    from core.crawler import crawl
    from core.net import configure_net
    configure_net()

    class Resp:
        def __init__(self, text="", url=""):
            self.text = text
            self.status_code = 200
            self.url = url
            self.headers = {}

    links = "".join(f"<a href='/p{i}?x=1'>l</a>" for i in range(10))

    class S:
        def get(self, url, timeout=None, allow_redirects=True, headers=None):
            return Resp(f"<html>{links}</html>", url)

    stats: dict = {}
    pages = crawl(S(), "http://h.test", f"<html>{links}</html>", 3,
                  max_pages=4, depth=2, stats=stats)
    assert stats["pages_discovered"] == len(pages) == 4
    assert stats["pages_scanned"] >= 1
    assert stats["truncated"] is True  # capped: said, not hidden


def test_run_scan_health_carries_coverage(monkeypatch):
    import core.scanner as S
    import core.advanced  # noqa: F401
    import core.domxss  # noqa: F401
    import core.webchecks  # noqa: F401
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
        cookies = []
        headers = {}

        def get(self, url, timeout=None, allow_redirects=True, headers=None):
            return Resp("<html>ok</html>", 200, url)

    monkeypatch.setattr(S, "_session",
                        lambda timeout, auth=None: FakeSession())
    from core.net import configure_net
    configure_net()
    health: dict = {}
    S.run_scan("http://h.test", threads=1, timeout=3, verbose=False,
               deep=False, no_crawl=True,
               skip_checks=set(REGISTRY) - {"waf-detect"}, health=health)
    cov = health["coverage"]
    assert cov["pages_discovered"] == 1 and cov["xss_urls_tested"] >= 1
    assert cov["truncated"] is False
    assert cov["checks_skipped"] == len(REGISTRY) - 1
    assert cov["requests_sent"] >= 0


def test_coverage_truncated_banner_and_txt(tmp_path, capsys):
    from core.reporter import (build_report, print_findings, save_report)
    cov = {"pages_discovered": 50, "pages_scanned": 30,
           "xss_urls_tested": 60, "pool_seen": 90,
           "api_targets_discovered": 10, "api_targets_tested": 4,
           "requests_sent": 500, "request_budget": 0, "truncated": True,
           "checks_passed": 40, "checks_errored": 0, "checks_skipped": 4}
    print_findings([], coverage=cov)
    assert "TRUNCATED" in capsys.readouterr().out
    rep = build_report("http://h.test", "full", "0.0", coverage=cov)
    assert rep["coverage"]["truncated"] is True
    txt = save_report(rep, str(tmp_path / "r.txt"))
    assert "TRUNCATED" in open(txt, encoding="utf-8").read()
    rep2 = build_report("http://h.test", "full", "0.0")
    assert rep2["coverage"] == {}


def test_canonicalize_url():
    from core.discovery import canonicalize_url
    assert canonicalize_url("http://H.TEST/?b=1&a=2") == \
        canonicalize_url("http://h.test/?a=2&b=1")
    assert canonicalize_url("http://h.test:80/a/") == "http://h.test/a"
    assert canonicalize_url("http://h.test/a#f") == "http://h.test/a"
    assert canonicalize_url("HTTP://H.TEST/") == "http://h.test/"


def test_concretize_rest_path():
    from core.discovery import concretize_rest_path
    u, p = concretize_rest_path("/users/{id}")
    assert u == "/users/1" and p == ["id"]
    u, p = concretize_rest_path("/orders/:uuid/items")
    assert u == "/orders/1/items" and p == ["uuid"]
    u, p = concretize_rest_path("/profile/[slug]")
    assert u == "/profile/1" and p == ["slug"]
    u, p = concretize_rest_path("/static/about")
    assert u == "/static/about" and p == []


def test_extract_js_endpoints_shapes():
    from core.discovery import extract_js_endpoints
    js = ('fetch("/api/users"); axios.post("/v1/orders"); '
          'x.open("GET","/rest/items"); '
          'new WebSocket("wss://h.test/ws"); '
          'new EventSource("/sse/feed"); '
          '$.ajax({url:"/legacy/go"}); '
          'router.push("/dashboard"); '
          'const u="https://evil.com/x";')
    found = dict(extract_js_endpoints(js, "http://h.test"))
    for want in ("/api/users", "/v1/orders", "/rest/items", "/sse/feed",
                 "/legacy/go", "/dashboard"):
        assert f"http://h.test{want}" in found, want
    assert not any("evil.com" in u for u in found)
    assert not any("ws" in u for u in found)  # sockets noted, not crawled
    assert found["http://h.test/api/users"] == "api"
    assert found["http://h.test/dashboard"] == "page"


def test_extract_html_refs_unified():
    from core.discovery import extract_html_refs
    refs = extract_html_refs(
        '<a href="/go?q=1">x</a>'
        '<script>fetch("/api/hits")</script>'
        '<script>var C="/static/config.json";</script>',
        "http://h.test")
    assert "http://h.test/go?q=1" in refs["urls"]
    assert "http://h.test/api/hits" in refs["api"]
    assert "http://h.test/static/config.json" in refs["configs"]


def test_resolve_coverage_profiles():
    from types import SimpleNamespace
    from core.discovery import resolve_coverage, PROFILES
    assert PROFILES["balanced"]["max_pages"] == 12  # M15 widened
    b = resolve_coverage(SimpleNamespace())
    assert (b["max_pages"], b["crawl_depth"], b["max_xss_urls"]) == (12, 2, 30)
    q = resolve_coverage(SimpleNamespace(profile="quick"))
    assert q["max_pages"] == 4 and q["max_xss_urls"] == 12
    t = resolve_coverage(SimpleNamespace(profile="thorough"))
    assert t["max_pages"] == 50 and t["crawl_depth"] == 4
    assert t["spa_visits"] == 4 and t["traffic_cap"] == 100
    over = resolve_coverage(SimpleNamespace(profile="thorough",
                                             max_pages=5, depth=None,
                                             max_xss_urls=None))
    assert over["max_pages"] == 5  # explicit flag wins
    assert over["crawl_depth"] == 4
    bad = resolve_coverage(SimpleNamespace(profile="nope"))
    assert bad["max_pages"] == 12  # unknown -> balanced


def test_probe_pool_canonical_dedupe():
    from core.scanner import _build_probe_pool
    pages = {"http://h.test/": (
        '<a href="/s?b=1&a=2">1</a><a href="/s?a=2&b=1">2</a>')}
    pool = _build_probe_pool(pages, "http://h.test", limit=25)
    assert sum(1 for u in pool if "/s?" in u) == 1  # query-order variant once


def test_flatten_json_nested():
    from core.api_params import flatten_json
    leaves = dict(flatten_json({"user": {"id": 123, "role": "user"},
                                "tags": ["a", "b"]}))
    assert leaves["user.id"] == "123"
    assert leaves["user.role"] == "user"
    assert leaves["tags[0]"] == "a"
    big = flatten_json({f"k{i}": i for i in range(100)})
    assert len(big) <= 40  # capped
    assert flatten_json("x") == [("", "x")]


def test_mutate_json_body_roundtrip():
    import json
    from core.api_params import mutate_json_body
    tpl = json.dumps({"user": {"id": 123, "role": "user"}})
    new = mutate_json_body(tpl, "user.role", "GX")
    assert new is not None
    obj = json.loads(new)
    assert obj["user"]["role"] == "GX" and obj["user"]["id"] == 123
    assert mutate_json_body(tpl, "user.missing", "GX") is None
    assert mutate_json_body("not-json", "a", "GX") is None


def test_xml_and_graphql_params():
    from core.api_params import (extract_xml_params, mutate_xml_body,
                                 extract_graphql_params)
    ps = extract_xml_params("<user><id>1</id><role>user</role></user>")
    assert {p.name for p in ps} >= {"id", "role"}
    assert all(p.location == "xml" for p in ps)
    assert mutate_xml_body("<id>1</id>", "id", "GX") == "<id>GX</id>"
    assert mutate_xml_body("<id>1</id>", "nope", "GX") is None
    gq = extract_graphql_params("query($q:String){x}",
                                '{"q":"hello","n":2}')
    assert ("q", "graphql") in [(p.name, p.location) for p in gq]


def test_extract_request_params_all_types():
    from core.api_params import extract_request_params
    ps = extract_request_params("http://h.test/s?q=1",
                                {"X-Forwarded-Host": "e.test"},
                                "application/json",
                                '{"user":{"role":"user"}}')
    by_loc = {}
    for p in ps:
        by_loc.setdefault(p.location, []).append(p.name)
    assert by_loc["query"] == ["q"]
    assert "X-Forwarded-Host" in by_loc["header"]
    assert "user.role" in by_loc["json"]
    form = extract_request_params("", {}, "application/x-www-form-urlencoded",
                                  "a=1&b=2")
    assert [p.name for p in form] == ["a", "b"]
    assert extract_request_params("", {}, "text/plain", "x") == []


def test_safe_mode_gate():
    from core.api_params import allowed_in_safe_mode
    assert allowed_in_safe_mode("GET", "query") is True
    assert allowed_in_safe_mode("POST", "query") is False
    assert allowed_in_safe_mode("GET", "json") is False
    assert allowed_in_safe_mode("PUT", "path") is False
    assert allowed_in_safe_mode("DELETE", "header") is False


def test_swagger_api_targets():
    from core.api_params import swagger_api_targets
    spec = {"paths": {
        "/users/{id}": {
            "get": {"parameters": [
                {"name": "id", "in": "path"},
                {"name": "verbose", "in": "query"}]},
            "put": {"parameters": [{"name": "id", "in": "path"}],
                    "requestBody": {"content": {"application/json": {
                        "schema": {"type": "object", "properties": {
                            "user": {"type": "object", "properties": {
                                "role": {"type": "string"}}}}}}}}}}}}
    targets = swagger_api_targets(spec, "http://h.test")
    assert len(targets) == 2
    put = next(t for t in targets if t.method == "PUT")
    assert put.url == "http://h.test/users/1"
    assert "user.role" in [p.name for p in put.params]
    assert put.content_type == "application/json" and put.template
    assert swagger_api_targets({}, "http://h.test") == []


def _api_echo_session(captured, mode="raw"):
    import json as _json
    import re as _re

    class Resp:
        def __init__(self, text=""):
            self.text = text
            self.status_code = 200
            self.url = "http://h.test/api/users"
            self.headers = {}

    class S:
        def post(self, url, timeout=None, allow_redirects=True, **kw):
            captured.append((url, kw))
            body = _json.dumps(kw.get("json", kw.get("data", "")))
            if mode == "filtered":
                body = _re.sub(r'[<>"\'`]', "", body)
            return Resp(body)

        def request(self, method, url, timeout=None, allow_redirects=True,
                    **kw):
            return self.post(url, timeout=timeout,
                             allow_redirects=allow_redirects, **kw)

    return S()


def test_api_body_xss_breakout_and_filtered():
    from core.api_params import ApiTarget, ApiParam
    from core.scanner import _api_body_xss
    import json
    tpl = json.dumps({"user": {"role": "user"}})
    target = ApiTarget(url="http://h.test/api/users", method="POST",
                       content_type="application/json",
                       params=[ApiParam(name="user.role", location="json")],
                       template=tpl)
    cap = []
    out = _api_body_xss(_api_echo_session(cap), [target], 3)
    assert any(f.title == "Possible Reflected XSS"
               and "user.role" in f.detail for f in out)
    assert cap and cap[0][0] == "http://h.test/api/users"
    cap2 = []
    assert _api_body_xss(_api_echo_session(cap2, "filtered"), [target],
                         3) == []
    put = ApiTarget(url="http://h.test/api/users/1", method="PUT",
                    content_type="application/json",
                    params=[ApiParam(name="user.role", location="json")],
                    template=tpl)
    cap3 = []
    assert any("PUT" in f.detail for f in
               _api_body_xss(_api_echo_session(cap3), [put], 3))


def test_diff_signals():
    from core.diff import (ResponseSnap, compare, snap_response,
                           canonical_json, title_of, visible_text,
                           dom_structure, scrub_tokens)
    a = ResponseSnap(status=200, url="http://h.test/a", requested="http://h.test/a",
                     body="<html><title>T</title><p>hello</p></html>")
    b = ResponseSnap(status=200, url="http://h.test/a", requested="http://h.test/a",
                     body="<html><title>T</title><p>hello</p></html>")
    c = compare(a, b)
    assert c.verdict == "same" and c.html_ratio == 1.0
    # status alone never decides
    d = ResponseSnap(status=403, url=a.url, requested=a.requested, body=a.body)
    assert compare(a, d).verdict == "same"
    assert compare(a, d).same_status is False
    # different content
    e = ResponseSnap(status=200, url=a.url, requested=a.requested,
                     body="<html><title>Other</title><div>" + "x" * 500 + "</div></html>")
    ce = compare(a, e)
    assert ce.verdict == "different" and ce.reasons
    # JSON canonical: key order / spacing independent
    assert canonical_json('{"b":1,"a":2}') == canonical_json('{"a": 2, "b": 1}')
    assert canonical_json("<html>") is None
    j1 = ResponseSnap(status=200, body='{"a":1}')
    j2 = ResponseSnap(status=200, body='{"a": 1}')
    assert compare(j1, j2).verdict == "same"
    j3 = ResponseSnap(status=200, body='{"a":2}')
    assert compare(j1, j3).verdict == "different"
    # helpers
    assert title_of("<title> Hi </title>") == "Hi"
    assert "hello" in visible_text("<script>var x=1</script><p>hello</p>")
    assert "var x" not in visible_text("<script>var x=1</script><p>hello</p>")
    assert dom_structure("<div><p></p></div>") == ("div", "p", "p", "div")
    assert scrub_tokens("tok=abcdefgh", ["abcdefgh"]) == "tok="
    assert scrub_tokens("tok=abc", ["abc"]) == "tok=abc"  # short kept
    # snap_response never raises, even on junk
    s = snap_response(None)
    assert s.status == 0 and s.body == ""
    s2 = snap_response(object(), requested="http://h.test/")
    assert s2.url == "http://h.test/"


def test_diff_timing_helpers():
    from core.diff import timing_stats, is_regressed
    assert timing_stats([]) == (0.0, 0.0)
    assert timing_stats([1.0]) == (1.0, 0.0)
    mean, _sd = timing_stats([0.4, 0.5, 0.6])
    assert abs(mean - 0.5) < 1e-9
    assert is_regressed([0.4, 0.5], 3.2, 3.0) is True
    assert is_regressed([0.4, 0.5], 1.0, 3.0) is False  # no sleep
    assert is_regressed([3.5, 3.6], 6.5, 3.0) is False  # slow baseline
    assert is_regressed([], 5.0, 3.0) is False


def test_diff_legacy_parity():
    """Adopted wrappers behave exactly like the old inline code."""
    from core.diff import bodies_differ, looks_like_baseline
    from core.advanced import _bodies_differ, _scrub_hidden
    from core.scanner import _looks_like_baseline
    assert _bodies_differ("q" * 300 + "id=5",
                          "q" * 300 + "id=6" + "w" * 8) is False
    assert bodies_differ("same", "same") is False
    base = "<html>" + "y" * 500 + "</html>"
    assert _looks_like_baseline(200, base, 200, len(base), base) is True
    assert looks_like_baseline(404, base, 200, len(base), base) is False
    assert _looks_like_baseline(200, base + "DIFFERENT" * 50, 200,
                                 len(base), base) is False
    assert _scrub_hidden("a=12345678", {"csrf": "12345678"}) == "a="


def _tls_cert(**kw):
    import time
    fmt = "%b %d %H:%M:%S %Y GMT"
    nb = time.strftime(fmt, time.gmtime(time.time() - 86400))
    na = time.strftime(fmt, time.gmtime(time.time() + 86400 * 90))
    subj = ((("commonName", kw.get("cn", "h.test")),),)
    cert = {"subject": subj,
            "issuer": subj if kw.get("self_signed", True) else
            ((("commonName", "Test CA")),),
            "subjectAltName": tuple(("DNS", s) for s in
                                    kw.get("sans", [kw.get("cn", "h.test")])),
            "notBefore": nb, "notAfter": kw.get("notAfter", na)}
    return cert


def test_tls_helpers():
    from core.webchecks import (_hostname_matches, _is_self_signed,
                                _cipher_is_weak, _cert_times)
    cert = _tls_cert(cn="h.test", sans=["h.test"])
    assert _hostname_matches(cert, "h.test") is True
    assert _hostname_matches(cert, "other.test") is False
    wild = _tls_cert(cn="x", sans=["*.h.test"])
    assert _hostname_matches(wild, "a.h.test") is True
    assert _hostname_matches(wild, "a.b.h.test") is False  # no deep wildcard
    assert _is_self_signed(cert) is True
    assert _is_self_signed(_tls_cert(self_signed=False)) is False
    assert _cipher_is_weak("RC4-SHA") is True
    assert _cipher_is_weak("ECDHE-RSA-AES128-GCM-SHA256") is False
    nb, na = _cert_times(cert)
    assert nb is not None and na is not None and na > nb
    assert _cert_times({}) == (None, None)


def test_tls_audit_findings(monkeypatch):
    import core.webchecks as W
    import time
    fmt = "%b %d %H:%M:%S %Y GMT"
    past = time.strftime(fmt, time.gmtime(time.time() - 86400))
    bad = {"version": "TLSv1", "cipher": "RC4-SHA", "alpn": "",
           "cert": _tls_cert(cn="other.test", sans=["other.test"],
                             notAfter=past)}
    monkeypatch.setattr(W, "_tls_handshake",
                        lambda *a, **k: dict(bad))
    out = W.test_tls_audit(object(), "https://h.test", 3)
    titles = [f.title for f in out]
    assert "TLS certificate expired" in titles
    assert "TLS hostname mismatch" in titles
    assert "Self-signed TLS certificate" in titles
    assert "Weak TLS protocol enabled" in titles
    assert "Weak TLS cipher negotiated" in titles
    assert next(f for f in out
                if f.title == "TLS certificate expired").severity == "CRITICAL"
    # healthy host: silence
    good = {"version": "TLSv1.3",
            "cipher": "ECDHE-RSA-AES128-GCM-SHA256", "alpn": "h2",
            "cert": _tls_cert(cn="h.test", sans=["h.test"],
                              self_signed=False)}
    monkeypatch.setattr(W, "_tls_handshake", lambda *a, **k: None
                        if len(a) > 3 or k.get("tls_version") is not None
                        else dict(good))
    assert W.test_tls_audit(object(), "https://h.test", 3) == []
    # plain http skips quietly; dead TLS skips quietly
    assert W.test_tls_audit(object(), "http://h.test", 3) == []
    monkeypatch.setattr(W, "_tls_handshake", lambda *a, **k: None)
    assert W.test_tls_audit(object(), "https://h.test", 3) == []


def _gql_schema():
    def _f(name, args=None, kind="OBJECT", ret="User", oftype=None):
        t = {"kind": kind, "name": ret}
        if oftype is not None:
            t["ofType"] = oftype
        return {"name": name, "args": args or [], "type": t}
    req_id = {"name": "id",
              "type": {"kind": "NON_NULL",
                       "ofType": {"kind": "SCALAR", "name": "ID"}}}
    user_obj = {"kind": "OBJECT", "name": "User"}
    return {"__schema": {
        "queryType": {"name": "Query"},
        "mutationType": {"name": "Mutation"},
        "types": [
            {"kind": "OBJECT", "name": "Query", "fields": [
                _f("users", [], "LIST", "", user_obj),
                _f("user", [req_id]),
                _f("version", [], "SCALAR", "String"),
            ]},
            {"kind": "OBJECT", "name": "Mutation", "fields": [
                _f("updateUser",
                   [req_id, {"name": "role",
                             "type": {"kind": "SCALAR", "name": "String"}}],
                   "SCALAR", "Boolean"),
            ]},
            {"kind": "OBJECT", "name": "User", "fields": [
                {"name": "email", "args": [],
                 "type": {"kind": "SCALAR", "name": "String"}},
                {"name": "name", "args": [],
                 "type": {"kind": "SCALAR", "name": "String"}},
            ]},
        ]}}


def test_graphql_schema_parse_and_builders():
    from core.graphql import (parse_schema, sensitive_queries,
                              build_selection, build_by_id_query, id_arg,
                              has_sensitive_data)
    parsed = parse_schema(_gql_schema())
    assert [q["name"] for q in parsed["queries"]] == ["users", "user",
                                                      "version"]
    assert [m["name"] for m in parsed["mutations"]] == ["updateUser"]
    assert parsed["objects"]["User"] == ["email", "name"]
    users = next(q for q in parsed["queries"] if q["name"] == "users")
    user = next(q for q in parsed["queries"] if q["name"] == "user")
    assert users in sensitive_queries(parsed)  # returns email scalars
    assert build_selection(parsed, users) == "{ users { email name } }"
    assert build_selection(parsed, user) is None  # required id: no guessing
    assert id_arg(user)["name"] == "id" and id_arg(users) is None
    assert build_by_id_query(parsed, user, "2") == \
        '{ user(id: "2") { email name } }'
    assert has_sensitive_data({"users": [{"email": "a@b.c"}]}) == \
        "users[0].email"
    assert has_sensitive_data({"version": "1.0"}) is None
    assert parse_schema({}) == {"queries": [], "mutations": [],
                                "objects": {}}


def _gql_session(intro_doc, data_doc):
    import json as _json

    class Resp:
        def __init__(self, text="", status_code=200, url=""):
            self.text = text
            self.status_code = status_code
            self.url = url
            self.headers = {}

    class S:
        def post(self, url, timeout=None, json=None, **kw):
            q = (json or {}).get("query", "")
            if "__schema" in q or "__typename" in q:
                return Resp(_json.dumps(intro_doc), 200, url)
            if "users" in q or "user(" in q:
                return Resp(_json.dumps(data_doc), 200, url)
            return Resp('{"errors":[{"message":"bad"}]}', 200, url)

        def get(self, url, timeout=None, allow_redirects=True, headers=None):
            return Resp("nope", 404, url)

    return S()


def test_graphql_check_full_chain():
    import core.webchecks as W
    from core.net import configure_net
    configure_net()
    schema = _gql_schema()
    intro = {"data": {"__schema": schema["__schema"]}}
    data = {"data": {"users": [{"email": "a@b.c", "name": "ann"}]}}
    out = W.test_graphql_introspection(
        _gql_session(intro, data), "http://h.test", {}, 3,
        session_b=_gql_session(intro, data))
    titles = [f.title for f in out]
    assert "GraphQL introspection enabled" in titles
    assert "GraphQL mutations exposed" in titles
    assert "GraphQL weak input contract" in titles  # nullable role arg
    assert "Exposed sensitive GraphQL field" in titles
    assert "Confirmed IDOR / BOLA (cross-session)" in titles
    assert next(f for f in out
                if f.title.startswith("Confirmed")).severity == "CRITICAL"


def test_graphql_check_closed_quiet():
    import core.webchecks as W
    from core.net import configure_net
    configure_net()

    class Resp:
        def __init__(self, text="", status_code=404, url=""):
            self.text = text
            self.status_code = status_code
            self.url = url
            self.headers = {}

    class S:
        def post(self, url, timeout=None, json=None, **kw):
            return Resp("nope", 404, url)

        def get(self, url, timeout=None, allow_redirects=True, headers=None):
            if "__typename" in url:
                return Resp('{"data":{"__Schema":{"queryType":'
                            '{"name":"Query"}}}}', 200, url)
            return Resp("nope", 404, url)

    out = W.test_graphql_introspection(S(), "http://h.test", {}, 3)
    assert [f.title for f in out] == ["GraphQL introspection enabled"]
    assert "GET" in out[0].detail


def test_local_target_gate():
    from core.localaudit import is_local_target
    assert is_local_target("localhost") is True
    assert is_local_target("127.0.0.1") is True
    assert is_local_target("::1") is True
    assert is_local_target("example.com") is False
    assert is_local_target("example.com", force=True) is True
    assert is_local_target("") is False


def test_proc_net_tcp_parse():
    from core.localaudit import parse_proc_net_tcp
    text = ("  sl  local_address rem_address   st tx_queue rx_queue tr "
            "tm->when retrnsmt   uid  timeout inode\n"
            "   0: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000 "
            "00000000     0        0 12345 1 0000000000000000 100 0 0 10 0\n"
            "   1: 0100007F:0050 00000000:0000 01 00000000:00000000 00:00000000 "
            "00000000     0        0 99999 1 0000000000000000 100 0 0 10 0\n")
    rows = parse_proc_net_tcp(text)
    assert len(rows) == 2
    assert rows[0]["ip"] == "127.0.0.1" and rows[0]["port"] == 8080
    assert rows[0]["state"] == "0A" and rows[0]["inode"] == "12345"
    assert parse_proc_net_tcp("garbage") == []


def test_windows_netstat_parse():
    from core.localaudit import parse_windows_netstat
    text = ("  TCP    127.0.0.1:3000         0.0.0.0:0              "
            "LISTENING       4242\n"
            "  UDP    0.0.0.0:5353           *:*                                    \n")
    rows = parse_windows_netstat(text)
    assert rows == [{"ip": "127.0.0.1", "port": 3000, "pid": "4242",
                     "state": "LISTENING"}]


def test_windows_netstat_listening_only_and_ipv6():
    from core.localaudit import parse_windows_netstat
    text = ("\n".join([
        "  TCP    0.0.0.0:80               0.0.0.0:0              LISTENING       4",
        "  TCP    [::]:443                 [::]:0                 LISTENING       4",
        "  TCP    127.0.0.1:5000           127.0.0.1:60000        ESTABLISHED     123",
        "  TCP    192.168.1.5:443          93.184.216.34:51234    TIME_WAIT       0",
    ]))
    rows = parse_windows_netstat(text)
    assert len(rows) == 4  # parser preserves every state
    assert {(r["ip"], r["port"], r["state"]) for r in rows} == {
        ("0.0.0.0", 80, "LISTENING"), ("::", 443, "LISTENING"),
        ("127.0.0.1", 5000, "ESTABLISHED"), ("192.168.1.5", 443, "TIME_WAIT")}
    listeners = [r for r in rows if r["state"] == "LISTENING"]
    assert len(listeners) == 2  # ESTABLISHED is never a listener
    assert ("127.0.0.1", 5000) not in {(r["ip"], r["port"])
                                       for r in listeners}


def test_proc_net_tcp6():
    from core.localaudit import parse_proc_net_tcp
    head = ("  sl  local_address rem_address   st tx_queue rx_queue tr "
            "tm->when retrnsmt   uid  timeout inode")
    rows = parse_proc_net_tcp("\n".join([
        head,
        "   0: 00000000000000000000000001000000:0BB8 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 111 1 0000000000000000 100 0 0 10 0",
        "   1: 00000000000000000000000000000000:1F90 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 222 1 0000000000000000 100 0 0 10 0",
        "   2: 0100007F:1F90 00000000:0000 01 00000000:00000000 00:00000000 00000000     0        0 333 1 0000000000000000 100 0 0 10 0",
    ]))
    by_inode = {r["inode"]: r for r in rows}
    assert by_inode["111"]["ip"] == "::1"  # not misread as IPv4
    assert by_inode["111"]["port"] == 3000
    assert by_inode["222"]["ip"] == "::"  # all-interfaces v6, distinct from 0.0.0.0
    assert by_inode["333"]["ip"] == "127.0.0.1"  # v4 still fine
    assert by_inode["333"]["state"] == "01"  # non-LISTEN preserved
    assert parse_proc_net_tcp("garbage") == []


def test_listener_model_and_scope():
    from core.localaudit import (bind_scope, ip_version, new_listener,
                                 parse_cgroup_service)
    assert bind_scope("127.0.0.1") == "loopback"
    assert bind_scope("::1") == "loopback"
    assert bind_scope("0.0.0.0") == "all"
    assert bind_scope("::") == "all"
    assert bind_scope("192.168.1.5") == "private"
    assert bind_scope("8.8.8.8") == "public"
    assert bind_scope("fe80::1%12") == "private"
    assert bind_scope("") == "unknown"
    assert ip_version("::1") == "IPv6" and ip_version("1.2.3.4") == "IPv4"
    rec = new_listener(proto="udp", ip="::", port=53)
    assert rec["scope"] == "all" and rec["ipver"] == "IPv6"
    assert rec["confidence"] == "low" and rec["source"] == "connect-scan"
    assert rec["process"] == "?" and rec["exe"] == ""
    assert parse_cgroup_service("0::/system.slice/nginx.service") == \
        "nginx.service"
    assert parse_cgroup_service(
        "0::/docker/abcdef1234567890") == "docker/abcdef123456"
    assert parse_cgroup_service("0::/user.slice/none") == ""


def test_parse_ps_listeners_join():
    from core.localaudit import parse_ps_listeners
    doc = {
        "tcp": [
            {"LocalAddress": "127.0.0.1", "LocalPort": 3000,
             "OwningProcess": 11},
            {"LocalAddress": "0.0.0.0", "LocalPort": 80,
             "OwningProcess": 4},
        ],
        "udp": [{"LocalAddress": "0.0.0.0", "LocalPort": 53,
                 "OwningProcess": 11}],
        "procs": [
            {"Id": 11, "ProcessName": "node",
             "Path": "C:\\node\\node.exe"},
            {"Id": 4, "ProcessName": "System", "Path": ""},
        ],
        "services": [{"Name": "W3SVC", "ProcessId": 4}],
        "parents": [{"ProcessId": 11, "ParentProcessId": 1},
                    {"ProcessId": 1, "ParentProcessId": 0}],
    }
    rows = parse_ps_listeners(doc)
    by_port = {r["port"]: r for r in rows}
    assert by_port[3000]["process"] == "node"
    assert by_port[3000]["exe"] == "C:\\node\\node.exe"
    assert by_port[3000]["parent"] == "1"  # ppid known, name unknown
    assert by_port[3000]["confidence"] == "high"
    assert by_port[80]["service"] == "W3SVC"
    assert by_port[80]["confidence"] == "medium"  # no exe
    udp = [r for r in rows if r["proto"] == "udp"][0]
    assert udp["confidence"] == "low" and udp["source"] == "powershell"
    assert parse_ps_listeners({}) == []
    assert parse_ps_listeners(None) == []


def test_classify_dev_banner():
    from core.localaudit import classify_dev_banner
    assert classify_dev_banner("<script src='/@vite/client'></script>",
                               {}) == "vite"
    assert classify_dev_banner("__NEXT_DATA__ {}", {}) == "nextjs"
    assert classify_dev_banner("<html>hello</html>", {}) == ""
    assert classify_dev_banner("", {"Server": "webpack-dev-server"}) == "webpack"


def test_dev_fingerprint_breadth_and_no_single_word_fp():
    from core.localaudit import classify_dev_banner
    assert classify_dev_banner("__NUXT__ {}", {}) == "nuxt"
    assert classify_dev_banner("ng-version x ng-cli", {}) == "angular-dev"
    assert classify_dev_banner("django-debug-toolbar on", {}) == "django-debug"
    assert classify_dev_banner("Werkzeug console is locked", {}) == "flask-debug"
    assert classify_dev_banner("Whoops, looks like wat", {}) == "laravel-debug"
    assert classify_dev_banner("", {"Server": "PHP 8.1.0 Development Server",
                                     "X-Powered-By": "PHP/8.1"}) == "php-dev-server"
    assert classify_dev_banner("nodemon watching express", {}) == "express-dev"
    assert classify_dev_banner('{"openapi":1}/actuator/health', {}) == \
        "spring-actuator"
    assert classify_dev_banner("@storybook/preview here", {}) == "storybook"
    assert classify_dev_banner("jupyter-notebook tree", {}) == "jupyter"
    assert classify_dev_banner("grafana/login page", {}) == "grafana"
    assert classify_dev_banner("swagger-ui bundle", {}) == "api-docs-dev"
    assert classify_dev_banner("Fast Refresh runtime", {}) == "nextjs-dev"
    assert classify_dev_banner(
        "<form>admin dashboard login</form>", {}) == "admin-panel"
    # single generic words must NOT fire
    assert classify_dev_banner("you are invited", {}) == ""
    assert classify_dev_banner("<h1>admin</h1>", {}) == ""
    assert classify_dev_banner("express delivery", {}) == ""
    assert classify_dev_banner("", {}) == ""


def test_secret_file_status_perms(tmp_path):
    import sys
    from core.localaudit import secret_file_status
    env = tmp_path / ".env"
    env.write_text("K=V", encoding="utf-8")
    try:
        env.chmod(0o644)
    except Exception:
        pass
    recs = secret_file_status(home=str(tmp_path), cwd=str(tmp_path))
    rec = next(r for r in recs if r["path"].endswith(".env"))
    assert rec["kind"] == "environment file"
    if sys.platform.startswith("win"):
        assert rec["broad"] is False  # no POSIX bits on Windows
    else:
        assert rec["broad"] is True
    env.chmod(0o600)
    recs2 = secret_file_status(home=str(tmp_path), cwd=str(tmp_path))
    rec2 = next(r for r in recs2 if r["path"].endswith(".env"))
    assert rec2["broad"] is False


def test_secret_candidates_breadth(tmp_path):
    from core.localaudit import _resolve_secret_candidates
    home = tmp_path / "home"
    (home / ".aws").mkdir(parents=True)
    (home / ".aws" / "credentials").write_text("x", encoding="utf-8")
    (home / ".ssh").mkdir()
    (home / ".ssh" / "id_ed25519").write_text("x", encoding="utf-8")
    cwd = tmp_path / "proj"
    cwd.mkdir()
    (cwd / ".env").write_text("x", encoding="utf-8")
    (cwd / ".env.prod").write_text("x", encoding="utf-8")
    found = {p: k for p, k in
             _resolve_secret_candidates(str(home), str(cwd))}
    assert any(v == "AWS credentials" for v in found.values())
    assert any(v == "SSH private key" for v in found.values())
    assert sum(1 for v in found.values()
               if v == "environment file") == 2  # .env + .env.prod


def test_fingerprint_shape_never_stores(tmp_path):
    from core.localaudit import fingerprint_secret_shape
    pem = tmp_path / "key.pem"
    pem.write_bytes(b"-----BEGIN RSA PRIVATE KEY-----\nABC")
    assert fingerprint_secret_shape(str(pem)) == "PEM private key"
    jwt = tmp_path / "tok"
    jwt.write_text("eyJhbGciOiJ9.e30.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
                   encoding="utf-8")
    assert fingerprint_secret_shape(str(jwt)) == "JWT"
    txt = tmp_path / "plain"
    txt.write_text("hello world", encoding="utf-8")
    assert fingerprint_secret_shape(str(txt)) == ""
    assert fingerprint_secret_shape(str(tmp_path / "missing")) == ""


def test_summarize_acl_locale_proof():
    from core.localaudit import _summarize_acl
    rows = [{"path": "C:\\u\\.env", "owner": "X\\user",
             "sids": ["S-1-1-0", "S-1-5-32-544"]},
            {"path": "C:\\u\\ok", "owner": "X\\user",
             "sids": ["S-1-5-32-544"]},
            {"nope": 1}]
    out = _summarize_acl(rows)
    assert out["C:\\u\\.env"]["broad_read"] is True
    assert out["C:\\u\\.env"]["owner"] == "X\\user"
    assert out["C:\\u\\ok"]["broad_read"] is False
    assert _summarize_acl([]) == {}


def test_windows_acl_audit_guarded(monkeypatch):
    import sys
    import subprocess
    import core.localaudit as L

    class Proc:
        returncode = 0
        stdout = ('[{"path":"C:\\\\u\\\\.env","owner":"X\\\\user",'
                  '"sids":["S-1-5-32-545"]}]')

    monkeypatch.setattr(sys, "platform", "win32")
    monkeypatch.setattr(subprocess, "run",
                        lambda *a, **k: Proc())
    out = L.windows_acl_audit(["C:\\u\\.env"])
    assert out["C:\\u\\.env"]["broad_read"] is True
    monkeypatch.setattr(sys, "platform", "linux")
    assert L.windows_acl_audit(["/x"]) == {}


def test_run_local_audit_orchestration(monkeypatch):
    import core.localaudit as L
    monkeypatch.setattr(L, "collect_listening", lambda timeout=3.0: [
        {"ip": "0.0.0.0", "port": 5173, "process": "node/vite"},
        {"ip": "127.0.0.1", "port": 8000, "process": "python/app"},
        {"ip": "127.0.0.1", "port": 9000, "process": "?"},
    ])
    monkeypatch.setattr(L, "probe_local_http", lambda port, timeout=3.0,
                                                            host="127.0.0.1": (
        ("<script src='/@vite/client'></script>", {}) if port == 5173 else
        ("<div>vite hmr @vite/client</div>", {}) if port == 8000 else
        ("<html>ok</html>", {})))
    monkeypatch.setattr(L, "secret_file_status", lambda **k: [
        {"path": "/home/u/.env", "kind": "environment file", "broad": True}])
    monkeypatch.setattr(L, "firewall_status", lambda: "off")
    monkeypatch.setattr(L, "container_interfaces", lambda: ["docker0"])
    out = L.run_local_audit()
    by_title = {f.title: f for f in out}
    assert by_title["Exposed development server"].severity == "MEDIUM"
    assert by_title["Local development server (loopback-bound)"].severity == "INFO"
    assert by_title["Overly broad secret file permissions"].severity == "MEDIUM"
    assert by_title["Host firewall disabled"].severity == "LOW"
    assert by_title["Container/VM network present"].severity == "INFO"
    assert not any("9000" in f.url for f in out)  # plain ports stay quiet
    inv = by_title["Local listeners inventory"]
    assert inv.severity == "INFO" and "3 listeners" in inv.detail


def test_linux_process_info_guarded():
    from core.localaudit import linux_process_info
    assert linux_process_info("99999999") == {
        "pid": "99999999", "comm": "", "exe": "", "ppid": "",
        "parent": "", "service": ""}
    assert linux_process_info("")["comm"] == ""


def test_exposure_model_matrix():
    from core.localaudit import (classify_exposure, exposure_verdict,
                                 classify_interface, local_interface_map,
                                 new_listener)
    ifaces = {"192.168.1.5": "eth0", "10.7.0.2": "tun0",
              "172.17.0.1": "docker0"}
    assert classify_exposure(new_listener(ip="127.0.0.1"),
                             ifaces)["class"] == "loopback-only"
    assert classify_exposure(new_listener(ip="::1"),
                             ifaces)["class"] == "loopback-only"
    assert classify_exposure(new_listener(ip="0.0.0.0"),
                             ifaces)["class"] == "all-interfaces"
    assert classify_exposure(new_listener(ip="::"),
                             ifaces)["class"] == "all-interfaces"
    assert classify_exposure(new_listener(ip="192.168.1.5"),
                             ifaces)["class"] == "lan-visible"
    assert classify_exposure(new_listener(ip="10.7.0.2"),
                             ifaces)["class"] == "virtual-network-visible"
    assert classify_exposure(new_listener(ip="172.17.0.1"),
                             ifaces)["class"] == "virtual-network-visible"
    assert classify_exposure(new_listener(ip="2001:db8::1"),
                             ifaces)["class"] == "ipv6-visible"
    assert classify_exposure(new_listener(ip=""),
                             ifaces)["class"] == "unknown"
    assert classify_interface("tun0", "10.7.0.2") == "vpn"
    assert classify_interface("docker0", "172.17.0.1") == "docker"
    assert classify_interface("vEthernet (WSL)", "x") == "wsl"
    assert classify_interface("eth0", "192.168.1.5") == "lan"
    assert local_interface_map()["127.0.0.1"] == "lo"
    # verdict: severity from bind+firewall+service, never CRITICAL
    assert exposure_verdict("all-interfaces", "off", True)[0] == "MEDIUM"
    assert exposure_verdict("all-interfaces", "on", True)[1] == "Medium"
    assert exposure_verdict("all-interfaces", "off", True)[1] == "High"
    assert exposure_verdict("all-interfaces", "on", False)[0] == "LOW"
    assert exposure_verdict("loopback-only", "off", True)[0] == "INFO"
    assert exposure_verdict("lan-visible", "unknown", True)[0] == "MEDIUM"
    assert exposure_verdict("unknown", "off", True)[0] == "INFO"
    for cls in ("loopback-only", "lan-visible", "all-interfaces",
                "ipv6-visible", "virtual-network-visible", "unknown"):
        for fw in ("on", "off", "unknown"):
            assert exposure_verdict(cls, fw, True)[0] != "CRITICAL"
            assert exposure_verdict(cls, fw, False)[0] != "CRITICAL"


def test_run_local_audit_lan_visible(monkeypatch):
    import core.localaudit as L
    monkeypatch.setattr(L, "collect_listening", lambda timeout=3.0: [
        L.new_listener(proto="tcp", ip="192.168.1.5", port=3000,
                       process="node", confidence="high", source="proc"),
    ])
    monkeypatch.setattr(L, "local_interface_map",
                        lambda: {"192.168.1.5": "eth0"})
    monkeypatch.setattr(L, "firewall_status", lambda: "on")
    monkeypatch.setattr(L, "probe_local_http",
                        lambda port, timeout=3.0, host="127.0.0.1": (
                            "<script src='/@vite/client'></script>", {}))
    monkeypatch.setattr(L, "secret_file_status", lambda **k: [])
    monkeypatch.setattr(L, "container_interfaces", lambda: [])
    out = L.run_local_audit()
    hit = next(f for f in out
               if f.title == "Exposed development server")
    assert hit.severity == "MEDIUM" and hit.confidence == "Medium"
    assert "lan-visible" in hit.detail


def test_docker_parsers_and_graph():
    from core.localaudit import (parse_docker_ports, parse_docker_ps,
                                 parse_wsl_portproxy, docker_graph,
                                 new_listener)
    assert parse_docker_ports(
        "0.0.0.0:3000->3000/tcp, :::3000->3000/tcp, 80/tcp") == [
        {"host_ip": "0.0.0.0", "host_port": 3000, "container_port": 3000,
         "proto": "tcp"},
        {"host_ip": "::", "host_port": 3000, "container_port": 3000,
         "proto": "tcp"},
    ]
    assert parse_docker_ports("bogus") == []
    doc = ('{"Names":"webapp","Image":"node:20","State":"running",'
           '"Ports":"0.0.0.0:3000->3000/tcp"}\nnot-json\n'
           '{"Names":"db","Image":"pg","State":"running","Ports":""}')
    cons = parse_docker_ps(doc)
    assert [c["name"] for c in cons] == ["webapp", "db"]
    assert cons[0]["ports"][0]["host_port"] == 3000
    assert parse_docker_ps("") == []
    pp = parse_wsl_portproxy(
        "Listen on ipv4:             Connect to ipv4:\n"
        "Address         Port        Address         Port\n"
        "0.0.0.0         3000        172.20.1.2      3000\n"
        "garbage line\n")
    assert pp == [{"listen": "0.0.0.0:3000", "listen_port": 3000,
                   "connect": "172.20.1.2:3000"}]
    assert parse_wsl_portproxy("") == []
    listeners = [new_listener(proto="tcp", ip="0.0.0.0", port=3000,
                              process="docker-proxy")]
    rows = docker_graph(listeners, cons, {"webapp": "172.17.0.2"})
    assert rows[0]["container"] == "172.17.0.2"
    assert rows[0]["service"] == "docker-proxy"
    assert rows[0]["exposure"] == "all-interfaces"
    assert docker_graph([], cons, {})[0]["service"] == "?"


def test_run_local_audit_docker_and_wsl(monkeypatch):
    import core.localaudit as L
    monkeypatch.setattr(L, "collect_listening", lambda timeout=3.0: [
        L.new_listener(proto="tcp", ip="0.0.0.0", port=3000,
                       process="docker-proxy"),
    ])
    monkeypatch.setattr(L, "probe_local_http",
                        lambda port, timeout=3.0, host="127.0.0.1": (
                            "<html>ok</html>", {}))
    monkeypatch.setattr(L, "secret_file_status", lambda **k: [])
    monkeypatch.setattr(L, "firewall_status", lambda: "unknown")
    monkeypatch.setattr(L, "container_interfaces", lambda: ["docker0"])
    monkeypatch.setattr(L, "docker_containers", lambda **k: [
        {"name": "webapp", "image": "node:20", "state": "running",
         "ports": [{"host_ip": "0.0.0.0", "host_port": 3000,
                    "container_port": 3000, "proto": "tcp"}]}])
    monkeypatch.setattr(L, "docker_container_ips",
                        lambda names, **k: {"webapp": "172.17.0.2"})
    monkeypatch.setattr(L, "wsl_forwardings", lambda **k: [
        {"listen": "0.0.0.0:4000", "listen_port": 4000,
         "connect": "172.20.1.2:4000"}])
    out = L.run_local_audit()
    by_title = {f.title: f for f in out}
    assert "172.17.0.2" in by_title["Container published port"].detail
    assert by_title["Container published port"].severity == "MEDIUM"
    assert by_title["WSL port forwarding"].severity == "INFO"


def test_classify_udp_service():
    from core.localaudit import classify_udp_service
    assert classify_udp_service(53) == "dns"
    assert classify_udp_service(5353) == "mdns"
    assert classify_udp_service(1900) == "ssdp"
    assert classify_udp_service(9999) == ""
    assert classify_udp_service(9999, "minecraft-server") == "minecraft"
    assert classify_udp_service("bogus") == ""


def test_dns_wire_roundtrip():
    from core.localaudit import build_dns_query, parse_dns_reply
    import struct
    pkt = build_dns_query("gash-ab.invalid.", 0x1234)
    assert len(pkt) > 12
    # server side: echo a minimal NXDOMAIN for our id
    reply = struct.pack(">HHHHHH", 0x1234, 0x8183, 1, 0, 0, 0) + pkt[12:]
    assert parse_dns_reply(reply, 0x1234) == 3  # NXDOMAIN
    assert parse_dns_reply(reply, 0x9999) is None  # wrong id
    assert parse_dns_reply(b"short", 0x1234) is None
    assert parse_dns_reply(None, 0x1234) is None


def test_probe_dns_live_loopback():
    import socket
    import struct
    from core.localaudit import probe_dns_server
    srv = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    srv.bind(("127.0.0.1", 0))
    port = srv.getsockname()[1]
    srv.settimeout(5)
    stop = {"done": False}

    def _serve():
        try:
            data, addr = srv.recvfrom(512)
            qid = struct.unpack(">H", data[:2])[0]
            srv.sendto(struct.pack(">HHHHHH", qid, 0x8180, 1, 0, 0, 0)
                       + data[12:], addr)
        except Exception:
            pass
        finally:
            stop["done"] = True

    import threading
    threading.Thread(target=_serve, daemon=True).start()
    try:
        assert probe_dns_server(port, timeout=4) is True
    finally:
        srv.close()
    assert probe_dns_server(1, timeout=0.5) is False  # closed port


def test_run_local_audit_udp_findings(monkeypatch):
    import core.localaudit as L
    monkeypatch.setattr(L, "collect_listening", lambda timeout=3.0: [
        L.new_listener(proto="udp", ip="127.0.0.1", port=53,
                       process="dnsd", confidence="low", source="proc"),
        L.new_listener(proto="udp", ip="192.168.1.5", port=5353,
                       process="?", confidence="low", source="proc"),
        L.new_listener(proto="udp", ip="127.0.0.1", port=9999,
                       process="?", confidence="low", source="proc"),
    ])
    monkeypatch.setattr(L, "probe_dns_server", lambda *a, **k: True)
    monkeypatch.setattr(L, "secret_file_status", lambda **k: [])
    monkeypatch.setattr(L, "firewall_status", lambda: "unknown")
    monkeypatch.setattr(L, "container_interfaces", lambda: [])
    out = L.run_local_audit()
    by_title = {f.title: f for f in out}
    assert by_title["Local UDP service (DNS)"].severity == "INFO"
    assert "reply verified" in by_title["Local UDP service (DNS)"].detail
    assert by_title["LAN-visible UDP service (MDNS)"].severity == "LOW"
    assert not any("9999" in f.url for f in out)  # unknown stays quiet


def test_scan_target_local_gate(monkeypatch, tmp_path):
    import gash
    from types import SimpleNamespace
    monkeypatch.chdir(tmp_path)
    calls = []

    def fake_audit(timeout=3.0, deep=False, health=None):
        calls.append(timeout)
        from core.scanner import Finding
        return [Finding(title="Local development server (loopback-bound)",
                        severity="INFO", url="http://127.0.0.1:8000/",
                        evidence="x", confidence="High")]

    monkeypatch.setattr("core.localaudit.run_local_audit", fake_audit)
    monkeypatch.setattr(gash, "run_scan", lambda *a, **k: [])
    base = dict(delay=0.0, max_requests=0, cookie=None, header=None,
                login_user=None, login_pass=None, login_url=None,
                timeout=3, skip_ports=True, ports=None, threads=5,
                verbose=False, wordlist=None, quick=False, deep=False,
                skip_checks=None, no_crawl=True, dom=False,
                blind_callback=None, scope=None, fail_on=None, oob=False,
                proxy=None, user_agent=None, insecure=False, cookie_b=None,
                header_b=None, output=None)
    res = gash._scan_target("http://127.0.0.1:8000", SimpleNamespace(**base),
                            "scan", None)
    assert calls == [3]
    assert any("Local development server" in f.title for f in res.findings)
    assert any(r["check"] == "local-audit" and r["status"] != "error"
               for r in res.checks)
    assert any(r["check"] == "local-audit" and r["status"] != "error"
               for r in res.checks)
    calls.clear()
    res2 = gash._scan_target("http://example.com", SimpleNamespace(**base),
                             "scan", None)
    assert calls == [] and res2.findings == []


def test_scan_target_local_error_degrades(monkeypatch, tmp_path):
    import gash
    from types import SimpleNamespace
    monkeypatch.chdir(tmp_path)

    def _boom(timeout=3.0, deep=False):
        raise RuntimeError("no-proc")

    monkeypatch.setattr("core.localaudit.run_local_audit", _boom)
    monkeypatch.setattr(gash, "run_scan", lambda *a, **k: [])
    base = dict(delay=0.0, max_requests=0, cookie=None, header=None,
                login_user=None, login_pass=None, login_url=None,
                timeout=3, skip_ports=True, ports=None, threads=5,
                verbose=False, wordlist=None, quick=False, deep=False,
                skip_checks=set(), no_crawl=True, dom=False,
                blind_callback=None, scope=None, fail_on=None, oob=False,
                proxy=None, user_agent=None, insecure=False, cookie_b=None,
                header_b=None, output=None)
    res = gash._scan_target("http://127.0.0.1:9", SimpleNamespace(**base),
                            "scan", None)
    err = next(r for r in res.checks if r["check"] == "local-audit")
    assert err["status"] == "error" and res.degraded is True


def test_summarize_traffic_split():
    from core.xss_spa import summarize_traffic, ROUTE_WATCH_JS
    assert "__gash_routes" in ROUTE_WATCH_JS
    entries = [
        {"url": "http://h.test/api/users", "method": "GET",
         "resource": "fetch", "status": 200,
         "resp_ct": "application/json"},
        {"url": "http://h.test/app", "method": "GET", "resource": "document"},
        {"url": "ws://h.test/live", "method": "WS", "resource": "websocket"},
        {"url": "http://h.test/sse/feed", "method": "GET",
         "resource": "eventsource", "resp_ct": "text/event-stream"},
        {"url": "http://h.test/api/users", "method": "GET",
         "resource": "fetch"},
        {"url": "https://evil.com/x", "method": "GET", "resource": "fetch"},
    ]
    s = summarize_traffic(entries, "http://h.test")
    assert s["pool"] == ["http://h.test/app", "http://h.test/sse/feed"]
    assert s["api"] == ["http://h.test/api/users"]
    assert s["websockets"] == ["ws://h.test/live"]
    assert s["sse"] == ["http://h.test/sse/feed"]
    assert {r["url"] for r in s["graph"]} >= {
        "http://h.test/api/users", "ws://h.test/live"}
    scoped = summarize_traffic(entries, "http://h.test",
                               scope_hosts={"other.test"})
    assert scoped["pool"] == [] and scoped["graph"] == []
    capped = summarize_traffic(entries, "http://h.test",
                               caps={"graph": 1})
    assert len(capped["graph"]) == 1  # cap truncates the tail
    ws_only = summarize_traffic(
        [{"url": "ws://h.test/live", "method": "WS"}], "http://h.test",
        caps={"ws": 0})
    assert ws_only["websockets"] == ["ws://h.test/live"]  # 0 = default


def test_runtime_discover_capture_offline(monkeypatch):
    import importlib.util
    from core import xss_spa
    monkeypatch.setattr(importlib.util, "find_spec", lambda *a, **k: None)
    assert xss_spa.runtime_discover("http://h.test", 3,
                                    capture_traffic=True) == {
        "urls": [], "api": [], "params": []}


def test_probe_pool_drops_non_http():
    from core.scanner import _build_probe_pool
    pool = _build_probe_pool(
        {"http://h.test/": ""}, "http://h.test",
        spa_urls=["ws://h.test/live", "http://h.test/app"], limit=25)
    assert "http://h.test/app?id=1" in pool  # query-less SPA -> probe
    assert not any(u.startswith("ws:") for u in pool)


def test_run_scan_browser_discovery_merges_pool(monkeypatch):
    import core.scanner as S
    import core.advanced  # noqa: F401
    import core.domxss  # noqa: F401
    import core.webchecks  # noqa: F401
    import core.xss_spa as SPA
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
        cookies = []
        headers = {}

        def get(self, url, timeout=None, allow_redirects=True, headers=None):
            requested.append(url)
            return Resp("<html>ok</html>", 200, url)

    requested: list = []
    monkeypatch.setattr(S, "_session",
                        lambda timeout, auth=None: FakeSession())
    monkeypatch.setattr(
        SPA, "runtime_discover",
        lambda *a, **k: {"urls": ["http://h.test/runtime-app"],
                         "api": [], "params": [],
                         "traffic": [{"url": "http://h.test/runtime-app",
                                      "method": "GET"}],
                         "websockets": ["ws://h.test/live"],
                         "sse": [], "routes": ["/runtime-app"]})
    from core.net import configure_net
    configure_net()
    out = S.run_scan("http://h.test", threads=1, timeout=3, verbose=False,
                     deep=False, no_crawl=True,
                     skip_checks=set(REGISTRY) - {"waf-detect",
                                                  "xss-reflected"},
                     browser_discovery=True)
    assert out == []
    assert any("runtime-app" in u for u in requested)  # pool merged
    assert not any(u.startswith("ws:") for u in requested)  # graph only


def test_authz_ref_extraction():
    from core.authz import extract_refs_from_url, sibling_url
    refs = {(r.kind, r.location, r.name): r.value for r in
            extract_refs_from_url(
                "http://h.test/api/orders/5?verbose=1&token="
                "123e4567-e89b-12d3-a456-426614174000")}
    assert refs[("int", "path", "2")] == "5"
    assert refs[("uuid", "query", "token")] == \
        "123e4567-e89b-12d3-a456-426614174000"
    assert not any(v == "verbose" for v in refs.values())
    # pagination-style ints are still visible to the extractor (the
    # /api-only guard for differentials lives in the check itself)
    ints = [r for r in extract_refs_from_url("http://h.test/blog/2")
            if r.kind == "int"]
    assert ints and sibling_url("http://h.test/blog/2", ints[0]) == \
        "http://h.test/blog/3"
    uuids = [r for r in extract_refs_from_url(
        "http://h.test/api/o/123e4567-e89b-12d3-a456-426614174000")
        if r.kind == "uuid"]
    assert uuids and sibling_url(
        "http://h.test/api/o/123e4567-e89b-12d3-a456-426614174000",
        uuids[0]) is None  # unguessable: no sibling
    assert extract_refs_from_url("not a url") == []


def test_authz_json_refs_and_ownership():
    from core.authz import (extract_refs_from_json, extract_ownership,
                            canonical_same, same_object,
                            classify_auth_response, normalized_hash)
    refs = {(r.name, r.kind) for r in extract_refs_from_json(
        {"user": {"id": 7}, "note": "hi",
         "uid": "123e4567-e89b-12d3-a456-426614174000"})}
    assert ("user.id", "int") in refs
    assert ("uid", "uuid") in refs
    assert ("note", "slug") not in refs  # free text is not a ref
    assert extract_ownership('{"userId": 9, "x": 1}') == {"userId": "9"}
    assert extract_ownership("<html>") == {}
    assert canonical_same('{"b":1,"a":2}', '{"a":2,"b":1}') is True
    assert canonical_same('{"a":1}', '{"a":2}') is False
    assert canonical_same("<p>x</p>", '{"a":1}') is None
    assert same_object('{"a":1}', '{"a": 1}') is True  # canonical first
    assert same_object("", "") is False
    assert classify_auth_response(403, "x", "") == "denied"
    assert classify_auth_response(302, "x",
                                  "http://h.test/login") == "login-redirect"
    assert classify_auth_response(200, "<form>password</form>",
                                  "") == "login-redirect"
    assert classify_auth_response(200, "data", "") == "ok"
    assert normalized_hash("a  b") == normalized_hash("a b")


def _matrix_sessions(user_map, anon_map, b_map=None):
    class Resp:
        def __init__(self, text="", status_code=200, url=""):
            self.text = text
            self.status_code = status_code
            self.url = url
            self.headers = {}

    def _mk(mapping):
        class S:
            def get(self, url, timeout=None, allow_redirects=True,
                    headers=None):
                code, body = mapping.get(url, (404, "nope"))
                return Resp(body, code, url)
        return S()

    return _mk(user_map), _mk(anon_map), (_mk(b_map) if b_map else None)


def test_authz_matrix_anonymous_access():
    import core.advanced as A
    from core.net import configure_net
    configure_net()
    body = '{"id":5,"owner":"alice","secret":"x"}'
    user, anon, _ = _matrix_sessions(
        {"http://h.test/api/orders/5": (200, body)},
        {"http://h.test/api/orders/5": (200, body)})
    pages = {"http://h.test/": "<a href='/api/orders/5'>o</a>"}
    out = A.test_authz_matrix(user, pages, "http://h.test", 3,
                              anon_session=anon)
    assert any(f.title == "Missing authentication on object endpoint"
               and f.severity == "MEDIUM" and f.confidence == "High"
               for f in out)


def test_authz_matrix_gated_paths_quiet():
    import core.advanced as A
    from core.net import configure_net
    configure_net()
    user, anon, _ = _matrix_sessions(
        {"http://h.test/api/orders/5": (200, '{"id":5}')},
        {"http://h.test/api/orders/5": (403, "forbidden")})
    pages = {"http://h.test/": "<a href='/api/orders/5'>o</a>"}
    assert A.test_authz_matrix(user, pages, "http://h.test", 3,
                               anon_session=anon) == []
    # public HTML stays quiet too (no JSON/ownership to judge by)
    u2, a2, _ = _matrix_sessions(
        {"http://h.test/post/abc-def": (200, "<html>post</html>")},
        {"http://h.test/post/abc-def": (200, "<html>post</html>")})
    pages2 = {"http://h.test/": "<a href='/post/abc-def'>p</a>"}
    assert A.test_authz_matrix(u2, pages2, "http://h.test", 3,
                               anon_session=a2) == []


def test_authz_matrix_cross_user_confirmed():
    import core.advanced as A
    from core.net import configure_net
    configure_net()
    body = '{"id":5,"owner":"alice"}'
    user, anon, b = _matrix_sessions(
        {"http://h.test/api/orders/5": (200, body)},
        {"http://h.test/api/orders/5": (403, "denied")},
        {"http://h.test/api/orders/5": (200, body)})
    pages = {"http://h.test/": "<a href='/api/orders/5'>o</a>"}
    out = A.test_authz_matrix(user, pages, "http://h.test", 3,
                              session_b=b, anon_session=anon)
    assert any(f.title == "Confirmed IDOR / BOLA (cross-session)"
               and f.severity == "CRITICAL" for f in out)


def test_authz_matrix_uuid_and_admin():
    import core.advanced as A
    from core.net import configure_net
    configure_net()
    uuid = "123e4567-e89b-12d3-a456-426614174000"
    body = '{"id":"%s","owner":"alice"}' % uuid
    user, anon, _ = _matrix_sessions(
        {f"http://h.test/share/{uuid}": (200, body)},
        {f"http://h.test/share/{uuid}": (200, body)})
    pages = {"http://h.test/": f"<a href='/share/{uuid}'>d</a>"}
    out = A.test_authz_matrix(user, pages, "http://h.test", 3,
                              anon_session=anon)
    assert any(f.title == "Direct object reference reachable anonymously"
               and f.severity == "MEDIUM" for f in out)
    u2, a2, _ = _matrix_sessions(
        {"http://h.test/admin": (200, "<html>dashboard</html>")},
        {"http://h.test/admin": (403, "denied")})
    out2 = A.test_authz_matrix(
        u2, {"http://h.test/": "<html>x</html>"}, "http://h.test", 3,
        anon_session=a2,
        ctx={"found_paths": ["http://h.test/admin"]})
    assert any(f.title == "Possible missing authorization (admin surface)"
               for f in out2)


def test_traffic_to_targets_privileged():
    from core.api_params import traffic_to_targets
    rows = [
        {"url": "http://h.test/api/orders?status=open", "method": "GET",
         "req_ct": "", "post_data": ""},
        {"url": "http://h.test/api/users", "method": "POST",
         "req_ct": "application/json",
         "post_data": '{"user":{"role":"user"}}'},
        {"url": "ws://h.test/live", "method": "WS"},
        {"url": "http://h.test/api/users", "method": "POST",
         "req_ct": "application/json",
         "post_data": '{"user":{"role":"user"}}'},
    ]
    targets = traffic_to_targets(rows, "http://h.test")
    assert len(targets) == 2  # deduped, sockets skipped
    post = next(t for t in targets if t.method == "POST")
    assert post.url == "http://h.test/api/users"
    assert "user.role" in [p.name for p in post.params]
    assert traffic_to_targets([], "http://h.test") == []


def test_identifier_graph_sources():
    from core.api_params import ApiTarget, ApiParam
    from core.authz import identifier_graph
    pages = {"http://h.test/": "<a href='/api/orders/5'>o</a>"}
    api = [ApiTarget(url="http://h.test/api/users", method="GET",
                     content_type="application/json",
                     params=[ApiParam(name="id", location="query",
                                      value="5")])]
    traffic = [{"url": "http://h.test/g?session="
                       "123e4567-e89b-12d3-a456-426614174000",
                "method": "GET", "req_ct": "", "post_data": ""},
               {"url": "http://h.test/graphql", "method": "POST",
                "req_ct": "application/json",
                "post_data": '{"query":"q","variables":{"id":9}}'}]
    graph = identifier_graph(pages, api, traffic, "http://h.test")
    by_source = {}
    for g in graph:
        by_source.setdefault(g["source"], []).append(
            (g["ref"].kind, g["ref"].name))
    assert ("int", "2") in by_source.get("href", [])  # path segment index
    assert ("int", "id") in by_source.get("openapi", [])
    assert ("uuid", "session") in by_source.get("traffic-url", [])
    assert ("int", "id") in by_source.get("graphql-vars", [])


def test_authz_matrix_admin_confirm():
    import core.advanced as A
    from core.net import configure_net
    configure_net()
    body = '{"users":[{"email":"a@b.c"}]}'
    user, anon, adm = _matrix_sessions(
        {"http://h.test/admin/users/5": (200, body)},
        {"http://h.test/admin/users/5": (403, "denied")},
        {"http://h.test/admin/users/5": (200, body)})
    pages = {"http://h.test/": "<a href='/admin/users/5'>a</a>"}
    out = A.test_authz_matrix(user, pages, "http://h.test", 3,
                              anon_session=anon, session_c=adm)
    hit = next(f for f in out
               if f.title == "Missing authorization on admin endpoint")
    assert hit.severity == "MEDIUM" and hit.confidence == "High"


def test_graphql_graph_and_weak_contract():
    from core.graphql import schema_graph, weak_contracts
    from core.net import configure_net
    configure_net()
    parsed = __import__("core.graphql", fromlist=["parse_schema"]).parse_schema(
        _gql_schema())
    graph = schema_graph(parsed, "http://h.test/graphql")
    assert graph["endpoint"] == "http://h.test/graphql"
    assert any(q["has_id_arg"] for q in graph["queries"])
    assert "users" in graph["sensitive"]
    assert "updateUser" in graph["sensitive"]
    wc = weak_contracts(parsed)
    assert wc == [{"mutation": "updateUser", "arg": "role",
                   "issue": "nullable sensitive input"}]
    parsed2 = {"queries": [], "mutations": [
        {"name": "promote", "args": [{"name": "role", "required": False}]}],
        "objects": {}}
    assert weak_contracts(parsed2) == [
        {"mutation": "promote", "arg": "role",
         "issue": "nullable sensitive input"}]
    assert weak_contracts({}) == []


def test_cve_version_compare_and_ranges():
    from core.cve import parse_version, in_range, match_component
    assert parse_version("1.12.4") == ("1", "12", "4")
    assert parse_version("v3.5") == ("3", "5")
    assert parse_version("abc") is None and parse_version("") is None
    assert in_range(("1", "9"), ("1",), ("3", "4", "1")) is True
    assert in_range(("3", "5", "0"), ("1",), ("3", "4", "1")) is False
    assert in_range(("3", "5"), ("1",), ("3", "4", "1")) is False
    assert match_component("jquery", "1.12.4")[0]["cve"] == "CVE-2020-11022"
    assert match_component("jquery", "3.6.0") == []
    assert match_component("jquery", "garbage") == []
    assert match_component("drupal", "7.57")[0]["severity"] == "CRITICAL"
    assert match_component("wordpress", "4.7.1")[0]["cve"] == \
        "CVE-2017-1001000"
    assert match_component("nope", "1.0") == []


def test_cve_extraction_sources():
    from core.cve import (extract_versions, extract_js_versions,
                          components_with_findings)
    html = ('<meta name="generator" content="WordPress 4.7.1" />'
            '<script src="/wp-includes/js/jquery/jquery.js?ver=1.12.4">'
            '</script>'
            '<link href="/theme.css?ver=9.9" />')
    found = extract_versions(html, {"X-Powered-By": "PHP/5.6.40"})
    by_comp = {c: v for c, v, _ in found}
    assert by_comp["wordpress"] == "4.7.1"
    assert by_comp["jquery"] == "1.12.4"
    assert "9.9" not in by_comp.values()  # theme ver= ignored
    assert by_comp["php-eol"] == "5.6.40"
    js = "/*! jQuery v1.12.4 | (c) JS Foundation */"
    assert ("jquery", "1.12.4", "js-banner") in extract_js_versions(js)
    assert extract_js_versions("var x = 1;") == []
    payloads = components_with_findings(found)
    titles = [p["title"] for p in payloads]
    assert any("CVE-2017-1001000" in t for t in titles)
    assert any("CVE-2020-11022" in t for t in titles)
    assert components_with_findings([("jquery", "3.6.0", "js-banner")]) == []


def test_vuln_components_check():
    import core.webchecks as W
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
            if url.endswith("CHANGELOG.txt"):
                return Resp("Drupal 7.57, 2018-02-21\nblah", 200, url)
            if url.endswith(".js"):
                return Resp("/*! jQuery v3.6.0 */", 200, url)
            return Resp("nope", 404, url)

    pages = {"http://h.test/":
             '<meta name="generator" content="WordPress 4.7.1" />'
             '<script src="/app.js"></script>'}
    out = W.test_vuln_components(S(), "http://h.test", pages,
                                 pages["http://h.test/"],
                                 {"X-Powered-By": "PHP/8.1.0"}, 3)
    titles = [f.title for f in out]
    assert any("CVE-2017-1001000" in t for t in titles)
    assert any("CVE-2018-7600" in t for t in titles)  # CHANGELOG Drupal
    assert next(f for f in out if "Drupalgeddon" in f.detail
                or "2018-7600" in f.title).severity == "CRITICAL"
    assert not any("jQuery" in (f.detail + f.title) and "3.6.0" in
                   (f.detail + f.evidence) for f in out)

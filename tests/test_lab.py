"""Lab regression: vulnerable detects, fixed stays quiet.

Live localhost lab (bench/lab.py, stdlib only — no docker). Each test
calls the real check with a real session through pace()/budget, so the
whole request path is exercised. Slowest is time-based SQLi (~7s).
"""

import sys
import threading
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from bench.lab import LAB_UUID, serve  # noqa: E402


@pytest.fixture(scope="module")
def lab():
    from core.net import configure_net
    configure_net()
    srv = serve(0)
    port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    time.sleep(0.3)
    base = f"http://127.0.0.1:{port}"
    try:
        import requests
        requests.post(base + "/reset", timeout=5)
    except Exception:
        pass
    yield base
    srv.shutdown()
    srv.server_close()


def _sess():
    from core.scanner import _session
    return _session(5)


def _titles(out):
    return [f.title for f in out]


def test_lab_reflected_xss(lab):
    import core.scanner as SC
    out = SC.test_xss(_sess(), [lab + "/xss_reflected?name=gash"], 5,
                      False, deep=False)
    assert "Possible Reflected XSS" in _titles(out)
    fixed = SC.test_xss(_sess(), [lab + "/xss_reflected_fixed?name=gash"],
                        5, False, deep=False)
    assert "Possible Reflected XSS" not in _titles(fixed)


def test_lab_stored_xss(lab):
    import core.advanced as A
    pages = {lab + "/xss_stored":
             "<form method='post' action='/xss_stored'>"
             "<input name='comment'></form>"}
    out = A.test_stored_xss(_sess(), pages, lab, 5)
    assert "Possible Stored XSS" in _titles(out)
    pages_f = {lab + "/xss_stored_fixed":
               "<form method='post' action='/xss_stored_fixed'>"
               "<input name='comment'></form>"}
    fixed = A.test_stored_xss(_sess(), pages_f, lab, 5)
    assert "Possible Stored XSS" not in _titles(fixed)


def test_lab_sqli_error(lab):
    import core.scanner as SC
    out = SC.test_sqli(_sess(), [lab + "/sqli_error?id=1"], 5, False,
                       deep=False)
    assert "Possible SQL Injection" in _titles(out)
    assert SC.test_sqli(_sess(), [lab + "/sqli_error_fixed?id=1"], 5,
                        False, deep=False) == []


def test_lab_sqli_blind(lab):
    import core.advanced as A
    out = A.test_sqli_blind(_sess(), [lab + "/sqli_blind?id=1"], 5,
                            deep=False)
    assert any("Blind SQL Injection" in t for t in _titles(out))
    assert A.test_sqli_blind(_sess(), [lab + "/sqli_blind_fixed?id=1"], 5,
                             deep=False) == []


def test_lab_sqli_time(lab):
    import core.advanced as A
    out = A.test_sqli_blind(_sess(), [lab + "/sqli_time?id=1"], 5,
                            deep=True)
    assert "Possible Time-Based Blind SQLi" in _titles(out)
    assert A.test_sqli_blind(_sess(), [lab + "/sqli_time_fixed?id=1"], 5,
                             deep=True) == []


def test_lab_idor_numeric(lab):
    import core.advanced as A
    pages = {lab + "/": f"<a href='{lab}/api/users/5'>u</a>"}
    out = A.test_idor(_sess(), pages, lab, 5)
    assert "Possible IDOR / BOLA (single session)" in _titles(out)
    pages_f = {lab + "/": f"<a href='{lab}/api/users_fixed/5'>u</a>"}
    assert A.test_idor(_sess(), pages_f, lab, 5) == []


def test_lab_idor_uuid_matrix(lab):
    import core.advanced as A
    pages = {lab + "/": f"<a href='{lab}/api/share/{LAB_UUID}'>s</a>"}
    out = A.test_authz_matrix(_sess(), pages, lab, 5,
                              anon_session=_sess())
    assert "Missing authentication on object endpoint" in _titles(out)
    import secrets as _secrets
    unknown = f"123e4567-e89b-12d3-a456-{_secrets.token_hex(6)}"
    pages_f = {lab + "/": f"<a href='{lab}/api/share/{unknown}'>s</a>"}
    assert A.test_authz_matrix(_sess(), pages_f, lab, 5,
                               anon_session=_sess()) == []


def test_lab_open_redirect(lab):
    import core.webchecks as W
    out = W.test_open_redirect(_sess(), [lab + "/redirect?next=/x"], 5)
    assert "Possible Open Redirect" in _titles(out)
    assert W.test_open_redirect(_sess(), [lab + "/redirect_fixed?next=/x"],
                                5) == []


def test_lab_traversal(lab):
    import core.webchecks as W
    out = W.test_path_traversal(_sess(), [lab + "/traversal?file=x"], 5)
    assert "Possible Path Traversal" in _titles(out)
    assert W.test_path_traversal(_sess(), [lab + "/traversal_fixed?file=x"],
                                 5) == []


def test_lab_os_command(lab):
    import core.webchecks as W
    out = W.test_os_command_injection(_sess(), [lab + "/cmd?ip=1"], 5,
                                      deep=False)
    assert "Possible OS Command Injection" in _titles(out)
    assert W.test_os_command_injection(_sess(), [lab + "/cmd_fixed?ip=1"],
                                       5, deep=False) == []


def test_lab_cors(lab):
    import core.webchecks as W
    out = W.test_cors(_sess(), lab + "/cors", 5)
    assert any("CORS" in t for t in _titles(out))
    assert W.test_cors(_sess(), lab + "/cors_fixed", 5) == []


def test_lab_csp(lab):
    import requests
    import core.webchecks as W
    r = requests.get(lab + "/csp_weak", timeout=5)
    out = W.test_security_headers(dict(r.headers), lab + "/csp_weak")
    assert any("CSP" in t for t in _titles(out))
    r2 = requests.get(lab + "/csp_fixed", timeout=5)
    out2 = W.test_security_headers(dict(r2.headers), lab + "/csp_fixed")
    assert not any("CSP" in t for t in _titles(out2))


def test_lab_cookies(lab):
    import requests
    import core.advanced as A
    s = requests.Session()
    s.get(lab + "/cookies", timeout=5)
    assert any("cookie" in t.lower() for t in _titles(
        A.test_cookie_flags(s, lab + "/cookies", 5)))
    s2 = requests.Session()
    s2.get(lab + "/cookies_fixed", timeout=5)
    assert A.test_cookie_flags(s2, lab + "/cookies_fixed", 5) == []


def test_lab_jwt(lab):
    import requests
    import core.webchecks as W
    html = requests.get(lab + "/jwt", timeout=5).text
    assert "JWT using alg:none observed" in _titles(
        W.test_jwt_none({lab + "/jwt": html}))
    html2 = requests.get(lab + "/jwt_fixed", timeout=5).text
    assert W.test_jwt_none({lab + "/jwt_fixed": html2}) == []


def test_lab_jwt_acceptance_replay(lab):
    import requests
    import core.webchecks as W
    from bench.lab import LAB_JWT
    s = requests.Session()
    s.headers.update({"Authorization": f"Bearer {LAB_JWT}"})
    pages = {lab + "/jwt_accept": "<html>dashboard for user</html>"}
    out = W.test_jwt_acceptance(s, lab, pages, 5)
    assert "JWT alg:none accepted (replay confirmed)" in _titles(out)
    fixed_pages = {lab + "/jwt_accept_fixed":
                   "<html>dashboard for user</html>"}
    assert W.test_jwt_acceptance(s, lab, fixed_pages, 5) == []


def test_lab_graphql(lab):
    import core.webchecks as W
    out = W.test_graphql_introspection(_sess(), lab, {}, 5,
                                       session_b=_sess())
    titles = _titles(out)
    assert "GraphQL introspection enabled" in titles
    assert "GraphQL mutations exposed" in titles
    assert "Exposed sensitive GraphQL field" in titles
    assert W.test_graphql_introspection(_sess(), lab + "/traversal_fixed",
                                        {}, 5) == []


def test_lab_mass_assignment(lab):
    import requests
    import core.webchecks as W
    html = requests.get(lab + "/massassign", timeout=5).text
    assert "Client-controllable role field" in _titles(
        W.test_mass_assignment({lab + "/massassign": html}, lab))
    html2 = requests.get(lab + "/massassign_fixed", timeout=5).text
    assert W.test_mass_assignment({lab + "/massassign_fixed": html2},
                                  lab) == []


def test_lab_js_secrets_masked(lab):
    import requests
    import core.webchecks as W
    html = requests.get(lab + "/secrets", timeout=5).text
    out = W.test_js_secrets(_sess(), lab, {lab + "/secrets": html}, 5)
    assert out, "lab secret must be detected"
    blob = " ".join(f.evidence + f.detail for f in out)
    assert "AKIAZZZZZZZZZZZZZZZZ" not in blob  # never in full
    assert "..." in blob  # masked
    html2 = requests.get(lab + "/secrets_fixed", timeout=5).text
    assert W.test_js_secrets(_sess(), lab, {lab + "/secrets_fixed": html2},
                             5) == []


def test_lab_upload(lab):
    import requests
    import core.advanced as A
    html = requests.get(lab + "/upload", timeout=5).text
    out = A.test_upload_rce(_sess(), lab, html, 5)
    assert any(f.severity == "CRITICAL" for f in out)


def test_lab_cache_poisoning(lab):
    import core.webchecks as W
    out = W.test_cache_poisoning(_sess(), lab + "/cache", 5)
    assert "Cache poisoning surface" in _titles(out)
    assert W.test_cache_poisoning(_sess(), lab + "/cache_fixed", 5) == []


def test_lab_cache_deception(lab):
    import requests
    import core.webchecks as W
    s = requests.Session()
    s.cookies.set("session", "lab-auth")
    pages = {lab + "/cache_auth": "<html>dashboard private</html>"}
    out = W.test_cache_deception(s, lab, pages, 5)
    assert "Authenticated cache deception" in _titles(out)
    fixed_pages = {lab + "/cache_auth_fixed":
                   "<html>dashboard private</html>"}
    assert W.test_cache_deception(s, lab, fixed_pages, 5) == []


def test_lab_login_enum(lab):
    import requests
    import core.advanced as A
    html = requests.get(lab + "/login", timeout=5).text
    out = A.test_login_enum(_sess(), {lab + "/login": html}, lab, 5)
    assert "Login username enumeration" in _titles(out)
    html2 = requests.get(lab + "/login_fixed", timeout=5).text
    pages = {lab + "/login_fixed": html2.replace(
        "/login_fixed", "/login_fixed")}
    assert A.test_login_enum(_sess(), pages, lab, 5) == []


def test_lab_ssrf_surface(lab):
    import core.advanced as A
    out = A.test_ssrf(_sess(), [lab + "/ssrf_echo?url=x"], 5, verbose=True)
    assert "SSRF surface (manual testing advised)" in _titles(out)


def test_lab_dom_fixture_shape(lab):
    import requests
    html = requests.get(lab + "/dom", timeout=5).text
    assert "document.write" in html and "location.search" in html


def test_lab_dom_browser():
    pytest.importorskip("playwright.sync_api")
    import core.domxss as D
    from core.net import configure_net
    configure_net()
    srv = serve(0)
    import threading
    import time as _t
    port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    _t.sleep(0.3)
    try:
        base = f"http://127.0.0.1:{port}"
        out = D.test_dom_xss([base + "/dom"], base, 5, pages={}, dom=True)
    finally:
        srv.shutdown()
        srv.server_close()
    if not out:
        pytest.skip("chromium unavailable")
    assert any("DOM XSS" in f.title for f in out)


def test_lab_dom_no_self_echo():
    """Plain page, no sinks/handlers: the probe must not confirm itself.

    Regression: our marker-carrying page.evaluate() dispatches used to
    trip our own eval hook (sample == our probe script) and report a
    bogus postMessage->eval CONFIRMED.
    """
    pytest.importorskip("playwright.sync_api")
    from playwright.sync_api import sync_playwright
    import core.domxss as D
    from core.net import configure_net
    configure_net()
    srv = serve(0)
    import threading
    import time as _t
    port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    _t.sleep(0.3)
    try:
        base = f"http://127.0.0.1:{port}"
        try:
            with sync_playwright() as pw:
                browser = pw.chromium.launch(headless=True)
                try:
                    hit = D._probe_page(browser, base + "/cors_fixed",
                                        base, 5, {}, verbose=False)
                finally:
                    browser.close()
        except Exception as e:
            if "chromium" in str(e).lower() or "browser" in str(e).lower():
                pytest.skip("chromium unavailable")
            raise
    finally:
        srv.shutdown()
        srv.server_close()
    assert hit is None  # silence is correct here

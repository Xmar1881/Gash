"""Modern web check tests — no network."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))


def _args_net():
    from core.net import configure_net
    configure_net()


class Resp:
    def __init__(self, text="", status=200, url="", headers=None):
        self.text = text
        self.status_code = status
        self.url = url
        self.headers = headers or {}


def test_security_headers():
    _args_net()
    import core.webchecks as W
    out = W.test_security_headers({}, "http://h.test")
    assert len(out) == 6 and all(f.severity == "LOW" for f in out)
    full = {h: "x" for h in W.REQUIRED_HEADERS}
    assert W.test_security_headers(full, "http://h.test") == []


def test_open_redirect():
    _args_net()
    import core.webchecks as W

    class S:
        def get(self, url, timeout=None, allow_redirects=True, headers=None):
            if "evil-gash" in url:
                return Resp("", 302, url,
                            {"Location": "https://evil-gash.test/x"})
            return Resp("<html>ok</html>", 200, url, {})

    out = W.test_open_redirect(S(), ["http://h.test/?next=/home"], 3)
    assert len(out) == 1
    assert out[0].severity == "MEDIUM" and out[0].url.startswith("http")
    assert "evil" in out[0].detail
    assert W.test_open_redirect(S(), ["http://h.test/?page=2"], 3) == []


def test_path_traversal():
    _args_net()
    import core.webchecks as W

    class S:
        def get(self, url, timeout=None, allow_redirects=True, headers=None):
            if "hosts" in url:
                return Resp("127.0.0.1 localhost", 200, url, {})
            if "win.ini" in url or "windows" in url.lower():
                return Resp("[fonts]\r\nficture", 200, url, {})
            if "etc" in url:
                return Resp("root:x:0:0:root:/root:/bin/bash", 200, url, {})
            return Resp("<html>doc home</html>", 200, url, {})

    out = W.test_path_traversal(S(), ["http://h.test/?file=doc"], 3)
    assert len(out) == 1 and out[0].severity == "MEDIUM"
    assert out[0].url.startswith("http")
    assert W.test_path_traversal(S(), ["http://h.test/?q=x"], 3) == []


def test_path_traversal_windows():
    """win.ini marker counts too — Linux-only coverage misses IIS hosts."""
    _args_net()
    import core.webchecks as W

    class S:
        def get(self, url, timeout=None, allow_redirects=True, headers=None):
            if "hosts" in url:
                return Resp("127.0.0.1 localhost", 200, url, {})
            if "win.ini" in url:
                return Resp("[fonts]\r\nficture", 200, url, {})
            return Resp("<html>doc home</html>", 200, url, {})

    out = W.test_path_traversal(S(), ["http://h.test/?page=x"], 3)
    assert len(out) == 1 and "[fonts]" in (out[0].evidence or "")


def test_cors():
    _args_net()
    import core.webchecks as W

    class S:
        def __init__(self, headers):
            self._h = headers

        def get(self, url, timeout=None, allow_redirects=True, headers=None):
            return Resp("<html>ok</html>", 200, url, self._h)

    out = W.test_cors(S({"Access-Control-Allow-Origin": "https://evil-gash.test",
                         "Access-Control-Allow-Credentials": "true"}),
                      "http://h.test", 3)
    assert len(out) == 1 and out[0].severity == "MEDIUM"
    assert "credentials" in out[0].detail
    out = W.test_cors(S({"Access-Control-Allow-Origin": "*"}),
                      "http://h.test", 3)
    assert len(out) == 1 and out[0].severity == "LOW"
    assert W.test_cors(S({}), "http://h.test", 3) == []


def test_http_methods():
    _args_net()
    import core.webchecks as W

    class S:
        def __init__(self, allow):
            self._allow = allow

        def options(self, url, timeout=None, **kw):
            return Resp("", 200, url, {"Allow": self._allow} if self._allow else {})

    out = W.test_http_methods(S("GET, HEAD, OPTIONS, TRACE"), "http://h.test", 3)
    assert len(out) == 1 and "TRACE" in out[0].title
    assert W.test_http_methods(S("GET, HEAD, OPTIONS"), "http://h.test", 3) == []
    assert W.test_http_methods(S(""), "http://h.test", 3) == []


def test_js_secrets():
    _args_net()
    import core.webchecks as W
    pages = {"http://h.test/":
             "<script>const k='sk-live-mN9pQrStUvWxYz7890';</script>"}

    class S:
        def get(self, url, timeout=None, allow_redirects=True, headers=None):
            return Resp("", 404, url, {})

    out = W.test_js_secrets(S(), "http://h.test", pages, 3)
    assert len(out) == 1 and out[0].severity == "CRITICAL"
    assert "sk-live-mN9pQrStUvWxYz7890" not in out[0].evidence  # masked
    assert "sk-l" in out[0].evidence
    pages = {"http://h.test/":
             "<script>const k='sk-live-testkey-xxx';</script>"}
    assert W.test_js_secrets(S(), "http://h.test", pages, 3) == []  # placeholder


def test_menu_covers_registry():
    """Menu categories must cover every registered check (or CUSTOM hides them)."""
    import core.scanner  # noqa: F401
    import core.advanced  # noqa: F401
    import core.domxss  # noqa: F401
    import core.webchecks  # noqa: F401
    from core.menu import ALL_CHECKS
    from core.registry import REGISTRY
    assert set(ALL_CHECKS) == set(REGISTRY), (
        set(REGISTRY) ^ set(ALL_CHECKS))


def test_os_command_injection():
    _args_net()
    import core.webchecks as W

    class S:
        def get(self, url, timeout=None, allow_redirects=True, headers=None):
            if any(k in url for k in (";", "|", "$(", "%3B", "%7C",
                                      "%24%28", "%26%26")):
                return Resp("uid=0(root) gid=0(root)", 200, url, {})
            return Resp("<html>ok</html>", 200, url, {})

    class Clean:
        def get(self, url, timeout=None, allow_redirects=True, headers=None):
            return Resp("<html>ok</html>", 200, url, {})

    out = W.test_os_command_injection(S(), ["http://h.test/?q=1"], 3)
    assert len(out) == 1 and out[0].severity == "CRITICAL"
    assert out[0].url.startswith("http")
    assert W.test_os_command_injection(Clean(), ["http://h.test/?q=1"], 3) == []


def test_os_command_windows():
    """`ver` output proves command execution on Windows hosts."""
    _args_net()
    import core.webchecks as W

    class S:
        def get(self, url, timeout=None, allow_redirects=True, headers=None):
            if "ver" in url and "?" in url:
                return Resp("\r\nMicrosoft Windows [Version 10.0.19045]\r\n",
                            200, url, {})
            return Resp("<html>ok</html>", 200, url, {})

    out = W.test_os_command_injection(S(), ["http://h.test/?q=1"], 3)
    assert len(out) == 1
    assert "Microsoft Windows" in (out[0].evidence or "")


def test_crlf_injection():
    _args_net()
    import core.webchecks as W

    class S:
        def get(self, url, timeout=None, allow_redirects=True, headers=None):
            if "X-Gash-Probe" in url:
                return Resp("<html>ok</html>", 200, url,
                            {"X-Gash-Probe": "1"})
            return Resp("<html>ok</html>", 200, url, {})

    out = W.test_crlf_injection(S(), ["http://h.test/?q=1"], 3)
    assert len(out) == 1 and out[0].severity == "MEDIUM"
    assert W.test_crlf_injection(S(), ["http://h.test/"], 3) == []


def _cookie(name, rest):
    class C:
        pass
    c = C()
    c.name = name
    c._rest = rest
    return c


def test_csrf_surface():
    _args_net()
    import core.webchecks as W
    form = ("<form method='post' action='/submit'>"
            "<input name='comment'></form>")
    pages = {"http://h.test/": form}

    class S:
        def __init__(self, cookies):
            self.cookies = cookies

    weak = S([_cookie("session", {})])
    out = W.test_csrf_surface(weak, pages, "http://h.test", 3)
    assert len(out) == 1 and out[0].severity == "LOW"
    strict = S([_cookie("session", {"samesite": "Lax"})])
    assert W.test_csrf_surface(strict, pages, "http://h.test", 3) == []
    form_hidden = ("<form method='post' action='/submit'>"
                   "<input type='hidden' name='csrf' value='T'>"
                   "<input name='comment'></form>")
    assert W.test_csrf_surface(
        weak, {"http://h.test/": form_hidden}, "http://h.test", 3) == []
    # a non-token hidden field protects nothing
    form_userid = ("<form method='post' action='/submit'>"
                   "<input type='hidden' name='user_id' value='7'>"
                   "<input name='comment'></form>")
    out = W.test_csrf_surface(
        weak, {"http://h.test/": form_userid}, "http://h.test", 3)
    assert len(out) == 1
    # Lax tracking cookie does NOT cover a SameSite=None session
    mixed = S([_cookie("tracking", {"samesite": "Lax"}),
               _cookie("session", {"samesite": "None"})])
    out = W.test_csrf_surface(mixed, pages, "http://h.test", 3)
    assert len(out) == 1
    # framework CSRF cookie present -> likely protected
    guarded = S([_cookie("session", {}), _cookie("csrftoken", {})])
    assert W.test_csrf_surface(guarded, pages, "http://h.test", 3) == []


def test_firebase_open():
    _args_net()
    import core.webchecks as W

    class S:
        def get(self, url, timeout=None, allow_redirects=True, headers=None):
            if ".firebaseio.com/.json" in url:
                return Resp('{"users":{"a":1}}', 200, url, {})
            return Resp("<html>ok</html>", 200, url, {})

    pages = {"http://h.test/":
             "<script>var db='https://myapp.firebaseio.com';</script>"}
    out = W.test_firebase_open(S(), "http://h.test", pages, 3)
    assert len(out) == 1 and out[0].severity == "CRITICAL"
    assert W.test_firebase_open(S(), "http://h.test",
                                {"http://h.test/": "<html>ok</html>"}, 3) == []


def test_supabase_anon():
    _args_net()
    import core.webchecks as W
    key = ("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0."
           "sig-part-12345")

    class S:
        def get(self, url, timeout=None, allow_redirects=True, headers=None):
            if "/rest/v1/profiles" in url:
                return Resp('[{"id":1}]', 200, url, {})
            return Resp("[]", 200, url, {})

    pages = {"http://h.test/":
             f"<script>const U='https://abc.supabase.co';"
             f"const K=\"anon_key\": \"{key}\";</script>"}
    out = W.test_supabase_anon(S(), "http://h.test", pages, 3)
    assert len(out) == 1 and out[0].severity == "CRITICAL"
    assert W.test_supabase_anon(S(), "http://h.test",
                                {"http://h.test/": "<html>ok</html>"}, 3) == []


def test_nextjs_middleware_bypass():
    _args_net()
    import core.webchecks as W

    class S:
        def get(self, url, timeout=None, allow_redirects=True, headers=None):
            headers = headers or {}
            if url.endswith("/admin"):
                if headers.get("x-middleware-subrequest") == "middleware":
                    return Resp("<html>dashboard</html>", 200, url, {})
                return Resp("go login", 302, url, {"Location": "/login"})
            return Resp("<html>ok</html>", 200, url, {})

    html = "<html><script src='/_next/static/x.js'></script></html>"
    out = W.test_nextjs_middleware_bypass(S(), "http://h.test",
                                          {"http://h.test/": html}, html,
                                          {}, 3)
    assert len(out) == 1 and out[0].severity == "CRITICAL"

    class S2(S):
        def get(self, url, timeout=None, allow_redirects=True, headers=None):
            return Resp("go login", 302, url, {"Location": "/login"})

    assert W.test_nextjs_middleware_bypass(S2(), "http://h.test",
                                           {"http://h.test/": html}, html,
                                           {}, 3) == []
    assert W.test_nextjs_middleware_bypass(
        S(), "http://h.test", {"http://h.test/": "<html>plain</html>"},
        "<html>plain</html>", {}, 3) == []


def test_wp_user_enum():
    _args_net()
    import core.webchecks as W

    class S:
        def get(self, url, timeout=None, allow_redirects=True, headers=None):
            if url.endswith("/wp-json/wp/v2/users"):
                return Resp('[{"slug":"admin"}]', 200, url, {})
            return Resp("<html>ok</html>", 200, url, {})

    html = "<html><link href='/wp-content/x.css'></html>"
    out = W.test_wp_user_enum(S(), "http://h.test",
                              {"http://h.test/": html}, html, {}, 3)
    assert len(out) == 1 and out[0].severity == "LOW"
    assert W.test_wp_user_enum(S(), "http://h.test",
                               {"http://h.test/": "<html>plain</html>"},
                               "<html>plain</html>", {}, 3) == []


def test_swagger_exposed():
    _args_net()
    import core.webchecks as W

    class S:
        def get(self, url, timeout=None, allow_redirects=True, headers=None):
            if url.endswith("/swagger.json"):
                return Resp('{"paths":{}}', 200, url, {})
            return Resp("nope", 404, url, {})

    out = W.test_swagger_exposed(S(), "http://h.test", 3)
    assert len(out) == 1 and out[0].severity == "INFO"

    class S2:
        def get(self, url, timeout=None, allow_redirects=True, headers=None):
            return Resp("nope", 404, url, {})

    assert W.test_swagger_exposed(S2(), "http://h.test", 3) == []


def test_mass_assignment():
    _args_net()
    import core.webchecks as W
    form = ("<form method='post' action='/register'>"
            "<input name='email'><input name='role'></form>")
    out = W.test_mass_assignment({"http://h.test/": form}, "http://h.test")
    assert len(out) == 1 and out[0].severity == "INFO"
    form = ("<form method='post' action='/register'>"
            "<input name='email'></form>")
    assert W.test_mass_assignment({"http://h.test/": form},
                                   "http://h.test") == []


def test_jwt_none():
    _args_net()
    import core.webchecks as W
    none_tok = "eyJhbGciOiJub25lIn0.eyJzdWIiOiIxMjM0NTY3ODkwIn0."
    pages = {"http://h.test/": f"<script>var t='{none_tok}';</script>"}
    out = W.test_jwt_none(pages)
    assert len(out) == 1 and out[0].severity == "LOW"
    assert out[0].title == "JWT using alg:none observed"
    hs_tok = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.sig"
    pages = {"http://h.test/": f"<script>var t='{hs_tok}';</script>"}
    assert W.test_jwt_none(pages) == []
    assert W.test_jwt_none({}) == []


def test_graphql_introspection():
    _args_net()
    import core.webchecks as W

    class S:
        def get(self, url, timeout=None, allow_redirects=True, headers=None):
            return Resp("<html>ok</html>", 200, url, {})

        def post(self, url, timeout=None, allow_redirects=True, **kw):
            if url.startswith("http://h.test") and url.endswith("/graphql"):
                return Resp('{"data":{"__schema":{"queryType":{"name":"Q"}}}}',
                            200, url, {})
            return Resp("not found", 404, url, {})

    out = W.test_graphql_introspection(S(), "http://h.test", {}, 3)
    assert len(out) == 1 and out[0].severity == "LOW"
    assert W.test_graphql_introspection(S(), "http://nope.test", {}, 3) == []


def test_host_header():
    _args_net()
    import core.webchecks as W

    class S:
        def __init__(self, body):
            self._body = body

        def get(self, url, timeout=None, allow_redirects=True, headers=None):
            return Resp(self._body, 200, url, {})

    out = W.test_host_header(S("<html>welcome evil-gash user</html>"),
                             "http://h.test", 3)
    assert len(out) == 1 and out[0].severity == "LOW"
    assert W.test_host_header(S("<html>welcome user</html>"),
                              "http://h.test", 3) == []


def test_security_txt():
    _args_net()
    import core.webchecks as W

    class S:
        def __init__(self, code, body):
            self._code, self._body = code, body

        def get(self, url, timeout=None, allow_redirects=True, headers=None):
            return Resp(self._body, self._code, url, {})

    assert W.test_security_txt(S(200, "Contact: sec@x.test"),
                               "http://h.test", 3) == []
    out = W.test_security_txt(S(404, "nope"), "http://h.test", 3)
    assert len(out) == 1 and out[0].severity == "INFO"

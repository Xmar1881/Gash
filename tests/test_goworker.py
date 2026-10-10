"""Go worker bridge tests (no Go toolchain, no network: subprocess mocked)."""
from __future__ import annotations

import pytest


@pytest.fixture(autouse=True)
def _no_stream(monkeypatch):
    """Stream sessions off by default: unit tests pin single-shot behavior.

    Stream tests opt back in explicitly. The pool singleton would otherwise
    leak a live process across tests (and past mocks).
    """
    monkeypatch.setenv("GASH_GO_STREAM", "0")
    import core.goworker as G
    G.close_session()
    yield
    G.close_session()


def _resp(stdout="", returncode=0, stderr=""):
    class R:
        pass
    r = R()
    r.stdout, r.returncode, r.stderr = stdout, returncode, stderr
    return r


def test_findings_from_go_kwargs_and_whitelist():
    from core.goworker import findings_from_go
    fs = findings_from_go([
        {"title": "T1", "severity": "INFO", "detail": "d",
         "url": "http://h/", "evidence": "e", "confidence": "High"},
        {"title": "T2", "severity": "BOGUS"},
        "not-a-dict",
    ], url_default="http://h/")
    assert len(fs) == 2
    assert fs[0].severity == "INFO" and fs[0].check == "go-worker"
    assert fs[1].severity == "LOW" and fs[1].url == "http://h/"


def test_run_job_unknown_job_rejected():
    import pytest
    from core.goworker import run_job, GoworkerError
    with pytest.raises(GoworkerError):
        run_job({"job": "nmap-everything"})


def test_run_job_missing_binary(monkeypatch):
    import pytest
    import core.goworker as G
    monkeypatch.setattr(G, "binary_path", lambda: None)
    with pytest.raises(G.GoworkerError):
        G.run_job({"job": "ping"})
    assert G.available() is False
    assert G.ping() is False


def test_run_job_ping_ok(monkeypatch):
    import json
    import core.goworker as G
    monkeypatch.setattr(G, "binary_path", lambda: "gash-worker")
    monkeypatch.setattr(
        G.subprocess, "run",
        lambda *a, **k: _resp(json.dumps(
            {"ok": True, "job": "ping", "findings": [], "pong": True})))
    res = G.run_job({"job": "ping"})
    assert res["pong"] is True
    assert G.ping() is True


def test_run_job_bad_json_and_error_result(monkeypatch):
    import pytest
    import core.goworker as G
    monkeypatch.setattr(G, "binary_path", lambda: "gash-worker")
    monkeypatch.setattr(G.subprocess, "run", lambda *a, **k: _resp("not json"))
    with pytest.raises(G.GoworkerError):
        G.run_job({"job": "ping"})
    monkeypatch.setattr(
        G.subprocess, "run",
        lambda *a, **k: _resp('{"ok": false, "error": "boom"}'))
    with pytest.raises(G.GoworkerError):
        G.run_job({"job": "ping"})


def test_run_job_tech_fingerprint_mapping(monkeypatch):
    import json
    import core.goworker as G
    monkeypatch.setattr(G, "binary_path", lambda: "gash-worker")
    wire = {"ok": True, "job": "tech-fingerprint", "techs": ["php"],
            "findings": [{"title": "Technology fingerprint (go-worker)",
                           "severity": "INFO", "detail": "Stack: php",
                           "url": "http://h/", "evidence": "php",
                           "confidence": "High"}]}
    monkeypatch.setattr(G.subprocess, "run", lambda *a, **k: _resp(json.dumps(wire)))
    res = G.run_job({"job": "tech-fingerprint", "target": "http://h/",
                     "html": "x-powered-by: php", "headers": {}})
    fs = G.findings_from_go(res["findings"], url_default="http://h/")
    assert len(fs) == 1 and fs[0].severity == "INFO"


def _fixture(name):
    import json as _json
    import pathlib
    p = pathlib.Path(__file__).resolve().parent.parent / "go" / "testdata" / name
    doc = _json.loads(p.read_text(encoding="utf-8"))
    return doc["input"], doc["expected"]


def test_rank_fallback_matches_fixture():
    import core.goworker as G
    inp, expected = _fixture("rank_wordlist.json")
    assert G._rank_fallback(inp["techs"], inp["paths"], inp["limit"]) == expected


def test_prioritize_fallback_matches_fixture():
    import core.goworker as G
    inp, expected = _fixture("prioritize_urls.json")
    assert G._prioritize_fallback(inp["urls"], inp["limit"]) == expected


def test_rank_uses_worker_then_falls_back(monkeypatch):
    import json
    import core.goworker as G
    inp, expected = _fixture("rank_wordlist.json")
    monkeypatch.setattr(G, "binary_path", lambda: "gash-worker")
    monkeypatch.setattr(
        G.subprocess, "run",
        lambda *a, **k: _resp(json.dumps(
            {"ok": True, "job": "rank-wordlist", "findings": [],
             "paths": expected})))
    assert G.rank_wordlist(inp["techs"], inp["paths"], inp["limit"]) == expected
    # worker error -> identical Python fallback (no behavior change)
    monkeypatch.setattr(G, "run_job", lambda *a, **k: (_ for _ in ()).throw(
        G.GoworkerError("down")))
    assert G.rank_wordlist(inp["techs"], inp["paths"], inp["limit"]) == expected


def test_prioritize_uses_worker_then_falls_back(monkeypatch):
    import json
    import core.goworker as G
    inp, expected = _fixture("prioritize_urls.json")
    monkeypatch.setattr(G, "binary_path", lambda: "gash-worker")
    monkeypatch.setattr(
        G.subprocess, "run",
        lambda *a, **k: _resp(json.dumps(
            {"ok": True, "job": "prioritize-urls", "findings": [],
             "urls": expected})))
    assert G.prioritize_urls(inp["urls"], inp["limit"]) == expected
    monkeypatch.setattr(G, "run_job", lambda *a, **k: (_ for _ in ()).throw(
        G.GoworkerError("down")))
    assert G.prioritize_urls(inp["urls"], inp["limit"]) == expected


def test_live_binary_parity():
    """Real binary (when built) agrees with the fixtures; else skipped."""
    import pytest
    import core.goworker as G
    if not G.available():
        pytest.skip("go worker binary not built")
    for name, fn in (("rank_wordlist.json", "rank"), ("prioritize_urls.json", "prio")):
        inp, expected = _fixture(name)
        if fn == "rank":
            assert G.rank_wordlist(inp["techs"], inp["paths"], inp["limit"]) == expected
        else:
            assert G.prioritize_urls(inp["urls"], inp["limit"]) == expected


def _brute_session():
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
            if url.endswith("/a"):
                return Resp("hello page", 200, url)
            return Resp("not here", 404, url)

    return S()


def test_dir_brute_uses_go_rank_when_flag_on(monkeypatch):
    import core.goworker as G
    from core.scanner import dir_brute
    calls = []
    monkeypatch.setattr(
        G, "rank_wordlist",
        lambda techs, paths, limit=80, timeout=10: (
            calls.append((techs, list(paths), limit)) or list(reversed(paths))))
    ctx = {"go_worker": True}
    out = dir_brute(_brute_session(), "http://h.test", 3, threads=1,
                    wordlist=["b", "a"], ctx=ctx, verbose=True)
    assert calls == [(None, ["b", "a"], 80)]
    assert any(f.url.endswith("/a") for f in out)


def test_dir_brute_skips_go_rank_when_flag_off(monkeypatch):
    import core.goworker as G
    from core.scanner import dir_brute
    monkeypatch.setattr(
        G, "rank_wordlist",
        lambda *a, **k: (_ for _ in ()).throw(AssertionError("must not rank")))
    out = dir_brute(_brute_session(), "http://h.test", 3, threads=1,
                    wordlist=["b", "a"], ctx={}, verbose=False)
    assert any(f.url.endswith("/a") for f in out)


def test_verdict_dir_matches_probe_dir():
    from core.scanner import _probe_dir, _verdict_dir

    class Resp:
        def __init__(self, text="", status_code=200, url=""):
            self.text = text
            self.status_code = status_code
            self.url = url
            self.headers = {}

    class S:
        def __init__(self, code, body):
            self.code, self.body = code, body

        def get(self, url, timeout=None, allow_redirects=True, headers=None):
            return Resp(self.body, self.code, url)

    cases = [(200, "hello page"), (404, "not here"), (403, "denied"),
             (200, "ref: abc123")]
    for code, body in cases:
        a = _probe_dir(S(code, body), "http://h.test", "a", 3, 404, 8, "not here")
        b = _verdict_dir("http://h.test", "a", code, body, 404, 8, "not here")
        assert (a is None) == (b is None)
        if a is not None:
            assert (a.title, a.severity, a.url) == (b.title, b.severity, b.url)


def _serve_req(session, req, timeout=8):
    """Mirror real fetch_batch semantics for mocks: str (or method-less
    dict) -> GET, POST dict -> session.post. Returns (key, response)."""
    if isinstance(req, dict) and req.get("method", "GET") != "GET":
        resp = session.post(req["url"], timeout=timeout,
                            data=req.get("form", {}) or {})
        return req["url"], resp
    u = req if isinstance(req, str) else req.get("url", "")
    return u, session.get(u, timeout=timeout)


def _shaped(key, resp, truncated=False, snippet=None):
    body = resp.text if snippet is None else snippet
    return {"url": key, "final_url": resp.url, "status": resp.status_code,
            "length": len(resp.text), "snippet": body,
            "truncated": truncated, "error": ""}


def _req_url(r):
    return r if isinstance(r, str) else r.get("url", "")


def _go_fetch_like_session(session):
    """Mock fetch_batch that serves Go-shaped answers from a fake session."""
    def _fetch(urls, headers=None, cookies=None, timeout=8, workers=20,
               snippet_bytes=4096, max_body=2 << 20):
        return [_shaped(*_serve_req(session, u, timeout)) for u in urls]
    return _fetch


def _keyed(out):
    return sorted((f.title, f.url) for f in out)


def test_dir_brute_go_path_matches_python_path(monkeypatch):
    import core.goworker as G
    from core.scanner import dir_brute
    monkeypatch.setattr(G, "rank_wordlist",
                        lambda techs, paths, limit=80, timeout=10: list(paths))
    inner = _go_fetch_like_session(_brute_session())
    served = []

    def _counting(*a, **k):
        out = inner(*a, **k)
        served.append(len(out))
        return out

    monkeypatch.setattr(G, "fetch_batch", _counting)
    go_out = dir_brute(_brute_session(), "http://h.test", 3, threads=1,
                       wordlist=["b", "a", "admin"], ctx={"go_worker": True},
                       verbose=False)
    py_out = dir_brute(_brute_session(), "http://h.test", 3, threads=1,
                       wordlist=["b", "a", "admin"], ctx={}, verbose=False)
    assert _keyed(go_out) == _keyed(py_out) != []
    assert sum(served) == 3, "batch must serve all 3 probes (no silent fallback)"


def test_dir_brute_go_falls_back_on_429(monkeypatch):
    import core.goworker as G
    from core.scanner import dir_brute
    monkeypatch.setattr(G, "rank_wordlist",
                        lambda techs, paths, limit=80, timeout=10: list(paths))

    def _limited(urls, headers=None, cookies=None, timeout=8, workers=20):
        return [{"url": u, "final_url": u, "status": 429, "length": 3,
                 "snippet": "slow", "truncated": False, "error": ""}
                for u in urls]

    monkeypatch.setattr(G, "fetch_batch", _limited)
    go_out = dir_brute(_brute_session(), "http://h.test", 3, threads=1,
                       wordlist=["b", "a"], ctx={"go_worker": True}, verbose=False)
    py_out = dir_brute(_brute_session(), "http://h.test", 3, threads=1,
                       wordlist=["b", "a"], ctx={}, verbose=False)
    assert _keyed(go_out) == _keyed(py_out)


def test_dir_brute_go_falls_back_on_worker_error(monkeypatch):
    import core.goworker as G
    from core.scanner import dir_brute
    monkeypatch.setattr(G, "rank_wordlist",
                        lambda techs, paths, limit=80, timeout=10: list(paths))
    monkeypatch.setattr(
        G, "fetch_batch",
        lambda *a, **k: (_ for _ in ()).throw(G.GoworkerError("down")))
    go_out = dir_brute(_brute_session(), "http://h.test", 3, threads=1,
                       wordlist=["b", "a"], ctx={"go_worker": True}, verbose=False)
    assert any(f.url.endswith("/a") for f in go_out)


def test_fetch_batch_validation():
    import pytest
    import core.goworker as G
    assert G.fetch_batch([]) == []
    with pytest.raises(G.GoworkerError):
        G.fetch_batch(["http://h/"] * 201)


def test_fetch_batch_normalizes(monkeypatch):
    import json
    import core.goworker as G
    monkeypatch.setattr(G, "binary_path", lambda: "gash-worker")
    wire = {"ok": True, "job": "fetch-batch", "findings": [], "fetches": [
        {"url": "http://h/a", "status": 200, "length": 5, "snippet": "hello"},
        {"url": "http://h/b", "error": "dns fail"},
    ]}
    monkeypatch.setattr(G.subprocess, "run", lambda *a, **k: _resp(json.dumps(wire)))
    out = G.fetch_batch(["http://h/a", "http://h/b"])
    assert out[0]["status"] == 200 and out[0]["final_url"] == ""
    assert out[1]["error"] == "dns fail" and out[1]["status"] == 0


def test_session_creds():
    import core.goworker as G
    assert G.session_creds(object()) == ({}, {})

    class C:
        def __init__(self, n, v):
            self.name, self.value = n, v

    class S:
        headers = {"User-Agent": "GASH-test", "X-Other": "drop"}
        cookies = [C("session", "abc")]

    h, c = G.session_creds(S())
    assert h == {"User-Agent": "GASH-test"} and c == {"session": "abc"}


def _xss_echo_session():
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
            from urllib.parse import urlparse, parse_qs
            q = parse_qs(urlparse(url).query, keep_blank_values=True)
            vals = [v for vs in q.values() for v in vs]
            return Resp('<html><input value="' + "".join(vals) + '"></html>',
                        200, url)

    return S()


def _go_fetch_like_echo(session):
    def _fetch(urls, headers=None, cookies=None, timeout=8, workers=20,
               snippet_bytes=4096, max_body=2 << 20):
        return [_shaped(*_serve_req(session, u, timeout)) for u in urls]
    return _fetch


def test_xss_go_path_matches_python_path(monkeypatch):
    import core.goworker as G
    from core.scanner import test_xss
    inner = _go_fetch_like_echo(_xss_echo_session())
    served = []

    def _counting(*a, **k):
        out = inner(*a, **k)
        served.append(len(out))
        return out

    monkeypatch.setattr(G, "fetch_batch", _counting)
    urls = ["http://h.test/?q=1"]
    go_out = test_xss(_xss_echo_session(), urls, 3, False, threads=1,
                      go_worker=True)
    py_out = test_xss(_xss_echo_session(), urls, 3, False, threads=1)
    assert [(f.title, f.url) for f in go_out] == [(f.title, f.url) for f in py_out]
    assert any(f.title == "Possible Reflected XSS" for f in go_out)
    assert sum(served) == 3, "stage-1 batch must serve all 3 probes"


def test_xss_go_truncated_refetch_is_exact(monkeypatch):
    import core.goworker as G
    from core.scanner import test_xss
    sess = _xss_echo_session()

    def _trunc(urls, headers=None, cookies=None, timeout=8, workers=20,
               snippet_bytes=4096, max_body=2 << 20):
        out = []
        for u in urls:
            u = _req_url(u)
            out.append({"url": u, "final_url": u, "status": 200, "length": 99999,
                        "snippet": "<html>cut", "truncated": True, "error": ""})
        return out

    monkeypatch.setattr(G, "fetch_batch", _trunc)
    go_out = test_xss(sess, ["http://h.test/?q=1"], 3, False, threads=1,
                      go_worker=True)
    py_out = test_xss(_xss_echo_session(), ["http://h.test/?q=1"], 3, False,
                      threads=1)
    assert [(f.title, f.url) for f in go_out] == [(f.title, f.url) for f in py_out]


def test_xss_go_falls_back_on_429(monkeypatch):
    import core.goworker as G
    from core.scanner import test_xss

    def _limited(urls, headers=None, cookies=None, timeout=8, workers=20,
                 snippet_bytes=4096, max_body=2 << 20):
        return [{"url": _req_url(u), "final_url": _req_url(u), "status": 429,
                 "length": 3, "snippet": "slow", "truncated": False,
                 "error": ""} for u in urls]

    monkeypatch.setattr(G, "fetch_batch", _limited)
    go_out = test_xss(_xss_echo_session(), ["http://h.test/?q=1"], 3, False,
                      threads=1, go_worker=True)
    py_out = test_xss(_xss_echo_session(), ["http://h.test/?q=1"], 3, False,
                      threads=1)
    assert [(f.title, f.url) for f in go_out] == [(f.title, f.url) for f in py_out]


def _lab_base():
    import threading
    import time as _time
    from bench.lab import serve
    from core.net import configure_net
    configure_net()
    srv = serve(0)
    port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    _time.sleep(0.3)
    return srv, f"http://127.0.0.1:{port}"


def _lab_session():
    from core.scanner import _session
    return _session(5)


def test_lab_xss_hybrid_parity():
    """Real binary + real HTTP against the stdlib lab: same verdicts."""
    import pytest
    import core.goworker as G
    if not G.available():
        pytest.skip("go worker binary not built")
    srv, lab = _lab_base()
    try:
        from core.scanner import test_xss
        url = lab + "/xss_reflected?name=gash"
        go_out = test_xss(_lab_session(), [url], 5, False, threads=5,
                          go_worker=True)
        py_out = test_xss(_lab_session(), [url], 5, False, threads=5)
        assert [(f.title, f.url) for f in go_out] == \
            [(f.title, f.url) for f in py_out]
        assert any(f.title == "Possible Reflected XSS" for f in go_out)
    finally:
        srv.shutdown()
        srv.server_close()


def test_lab_dir_brute_hybrid_parity():
    """Real binary + real HTTP dir-brute: same verdicts as Python path."""
    import pytest
    import core.goworker as G
    if not G.available():
        pytest.skip("go worker binary not built")
    srv, lab = _lab_base()
    try:
        from core.scanner import dir_brute
        wl = ["xss_reflected", "login", "graphql", "nopezzz"]
        go_out = dir_brute(_lab_session(), lab, 5, threads=5, wordlist=wl,
                           ctx={"go_worker": True}, verbose=False)
        py_out = dir_brute(_lab_session(), lab, 5, threads=5, wordlist=wl,
                           ctx={}, verbose=False)
        assert sorted((f.title, f.url) for f in go_out) == \
            sorted((f.title, f.url) for f in py_out)
        assert go_out, "lab must yield dir-brute findings for parity to mean anything"
    finally:
        srv.shutdown()
        srv.server_close()


def test_lab_full_scan_hybrid_parity():
    """Whole run_scan, real binary + real HTTP: identical findings.

    Fixed wordlist keeps the probe pool under the cap, so ranked vs
    unranked pools select the same candidates (cap-tail differences are
    a ranking feature, not a verdict difference — measured separately).
    """
    import pytest
    import core.goworker as G
    if not G.available():
        pytest.skip("go worker binary not built")
    srv, lab = _lab_base()
    try:
        from core.scanner import run_scan
        wl = ["xss_reflected", "login", "graphql", "upload", "nopezzz"]
        kw = dict(threads=10, timeout=5, verbose=False, deep=False,
                  no_crawl=True, wordlist=wl)
        go_out = run_scan(lab, health={}, go_worker=True, **kw)
        py_out = run_scan(lab, health={}, **kw)
        assert sorted((f.title, f.url) for f in go_out) == \
            sorted((f.title, f.url) for f in py_out)
        assert len(go_out) > 0
    finally:
        srv.shutdown()
        srv.server_close()


def _post_echo_session():
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
            return Resp("<html>form page</html>", 200, url)

        def post(self, url, timeout=None, allow_redirects=True, **kwargs):
            data = kwargs.get("data", {}) or {}
            vals = "".join(str(v) for v in data.values())
            return Resp('<html><input value="' + vals + '"></html>', 200, url)

    return S()


def _post_pages():
    return {"http://h.test/f":
            "<form method='post' action='/submit'><input name='q'></form>"}


def _go_fetch_like_post_echo(session):
    def _fetch(requests, headers=None, cookies=None, timeout=8, workers=20,
               snippet_bytes=4096, max_body=2 << 20):
        out = []
        for r in requests:
            if isinstance(r, str):
                resp = session.get(r, timeout=timeout)
                body = resp.text
            else:
                data = r.get("form", {}) or {}
                resp = session.post(r["url"], timeout=timeout, data=data)
                body = resp.text
            out.append({"url": r if isinstance(r, str) else r["url"],
                        "final_url": resp.url, "status": resp.status_code,
                        "length": len(body), "snippet": body,
                        "truncated": False, "error": ""})
        return out
    return _fetch


def test_post_xss_go_path_matches_python_path(monkeypatch):
    import core.goworker as G
    from core.scan.injection import _post_xss
    inner = _go_fetch_like_post_echo(_post_echo_session())
    served = []

    def _counting(*a, **k):
        out = inner(*a, **k)
        served.append(len(out))
        return out

    monkeypatch.setattr(G, "fetch_batch", _counting)
    pages = _post_pages()
    go_out = _post_xss(_post_echo_session(), pages, "http://h.test", 3,
                       verbose=False, go_worker=True)
    py_out = _post_xss(_post_echo_session(), pages, "http://h.test", 3,
                       verbose=False)
    assert [(f.title, f.url) for f in go_out] == [(f.title, f.url) for f in py_out]
    assert any(f.title == "Possible Reflected XSS" for f in go_out)
    assert sum(served) == 3, "POST batch must serve all 3 probes"


def test_post_xss_go_truncated_and_error_fallback(monkeypatch):
    import core.goworker as G
    from core.scan.injection import _post_xss
    pages = _post_pages()

    def _trunc(requests, headers=None, cookies=None, timeout=8, workers=20,
               snippet_bytes=4096, max_body=2 << 20):
        return [{"url": (r if isinstance(r, str) else r["url"]),
                 "final_url": "", "status": 200, "length": 99999,
                 "snippet": "<html>cut", "truncated": True, "error": ""}
                for r in requests]

    monkeypatch.setattr(G, "fetch_batch", _trunc)
    go_out = _post_xss(_post_echo_session(), pages, "http://h.test", 3,
                       verbose=False, go_worker=True)
    py_out = _post_xss(_post_echo_session(), pages, "http://h.test", 3,
                       verbose=False)
    assert [(f.title, f.url) for f in go_out] == [(f.title, f.url) for f in py_out]

    def _dead(requests, headers=None, cookies=None, timeout=8, workers=20,
              snippet_bytes=4096, max_body=2 << 20):
        return [{"url": (r if isinstance(r, str) else r["url"]),
                 "final_url": "", "status": 0, "length": 0,
                 "snippet": "", "truncated": False, "error": "down"}
                for r in requests]

    monkeypatch.setattr(G, "fetch_batch", _dead)
    go_out = _post_xss(_post_echo_session(), pages, "http://h.test", 3,
                       verbose=False, go_worker=True)
    assert [(f.title, f.url) for f in go_out] == [(f.title, f.url) for f in py_out]


def test_fetch_batch_mixed_requests(monkeypatch):
    import json
    import core.goworker as G
    seen = {}
    monkeypatch.setattr(G, "binary_path", lambda: "gash-worker")

    def _run(cmd, input=None, capture_output=None, text=None, timeout=None,
             encoding=None, errors=None):
        seen["encoding"] = encoding
        seen["errors"] = errors
        seen["job"] = json.loads(input)
        wire = {"ok": True, "job": "fetch-batch", "findings": [], "fetches": [
            {"url": "http://h/a", "status": 200, "length": 2, "snippet": "hi"},
            {"url": "http://h/b", "status": 200, "length": 3, "snippet": "yo!"},
        ]}
        return _resp(json.dumps(wire))

    monkeypatch.setattr(G.subprocess, "run", _run)
    out = G.fetch_batch(["http://h/a", {"url": "http://h/b", "method": "POST",
                                        "form": {"q": "1"}}])
    assert [f["url"] for f in out] == ["http://h/a", "http://h/b"]
    reqs = seen["job"]["requests"]
    assert reqs[0]["method"] == "GET" and reqs[1]["form"] == {"q": "1"}
    assert seen["encoding"] == "utf-8" and seen["errors"] == "replace"


def _sqli_echo_session():
    from core.net import configure_net
    configure_net()
    err = "You have an error in your SQL syntax"

    class Resp:
        def __init__(self, text="", status_code=200, url=""):
            self.text = text
            self.status_code = status_code
            self.url = url
            self.headers = {}

    class S:
        def get(self, url, timeout=None, allow_redirects=True, headers=None):
            if "'" in url or "%27" in url:
                return Resp(err, 200, url)
            return Resp("<html>ok</html>", 200, url)

        def post(self, url, timeout=None, allow_redirects=True, **kwargs):
            vals = "".join(str(v) for v in (kwargs.get("data", {}) or {}).values())
            if "'" in vals:
                return Resp(err, 200, url)
            return Resp("<html>ok</html>", 200, url)

    return S()


def _sqli_pages():
    return {"http://h.test/f":
            "<form method='post' action='/submit'><input name='q'></form>"}


def _go_fetch_like_sqli_echo(session):
    def _fetch(requests, headers=None, cookies=None, timeout=8, workers=20,
               snippet_bytes=4096, max_body=2 << 20):
        out = []
        for r in requests:
            if isinstance(r, dict) and r.get("method", "GET") != "GET":
                resp = session.post(r["url"], timeout=timeout,
                                    data=r.get("form", {}))
                key = r["url"]
            else:
                u = r if isinstance(r, str) else r.get("url", "")
                resp = session.get(u, timeout=timeout)
                key = u
            out.append({"url": key, "final_url": resp.url,
                        "status": resp.status_code, "length": len(resp.text),
                        "snippet": resp.text, "truncated": False, "error": ""})
        return out
    return _fetch


def test_sqli_go_path_matches_python_path(monkeypatch):
    import core.goworker as G
    from core.scanner import test_sqli
    inner = _go_fetch_like_sqli_echo(_sqli_echo_session())
    served = []

    def _counting(*a, **k):
        out = inner(*a, **k)
        served.append(len(out))
        return out

    monkeypatch.setattr(G, "fetch_batch", _counting)
    kw = dict(timeout=3, verbose=False, pages=_sqli_pages(), base="http://h.test",
              deep=True)
    go_out = test_sqli(_sqli_echo_session(), ["http://h.test/?id=1"],
                       go_worker=True, **kw)
    py_out = test_sqli(_sqli_echo_session(), ["http://h.test/?id=1"], **kw)
    assert [(f.title, f.url) for f in go_out] == [(f.title, f.url) for f in py_out]
    assert any(f.title == "Possible SQL Injection" for f in go_out)
    # 1 base + 3 payload GETs + 1 base + 3 payload POSTs served from the batch
    assert sum(served) == 8, "both GET and POST batches must engage"


def test_sqli_go_falls_back_on_429(monkeypatch):
    import core.goworker as G
    from core.scanner import test_sqli

    def _limited(requests, headers=None, cookies=None, timeout=8, workers=20,
                 snippet_bytes=4096, max_body=2 << 20):
        def _key(r):
            return r if isinstance(r, str) else r["url"]
        return [{"url": _key(r), "final_url": "", "status": 429, "length": 3,
                 "snippet": "slow", "truncated": False, "error": ""}
                for r in requests]

    monkeypatch.setattr(G, "fetch_batch", _limited)
    kw = dict(timeout=3, verbose=False, pages=_sqli_pages(), base="http://h.test",
              deep=True)
    go_out = test_sqli(_sqli_echo_session(), ["http://h.test/?id=1"],
                       go_worker=True, **kw)
    py_out = test_sqli(_sqli_echo_session(), ["http://h.test/?id=1"], **kw)
    assert [(f.title, f.url) for f in go_out] == [(f.title, f.url) for f in py_out]


def _ssti_echo_session():
    from core.net import configure_net
    configure_net()
    want = str(7719 * 7919)

    class Resp:
        def __init__(self, text="", status_code=200, url=""):
            self.text = text
            self.status_code = status_code
            self.url = url
            self.headers = {}

    class S:
        def _body(self, blob):
            # NOTE: GET URLs arrive url-encoded (* -> %2A), POST values raw;
            # "7719" matches both forms while the clean baseline has no digits.
            return Resp(f"<html>val {want}</html>" if "7719" in blob
                        else "<html>plain</html>", 200, "")

        def get(self, url, timeout=None, allow_redirects=True, headers=None):
            r = self._body(url)
            r.url = url
            return r

        def post(self, url, timeout=None, allow_redirects=True, **kwargs):
            vals = "".join(str(v) for v in (kwargs.get("data", {}) or {}).values())
            r = self._body(vals)
            r.url = url
            return r

    return S()


def test_ssti_go_path_matches_python_path(monkeypatch):
    import core.goworker as G
    import core.advanced as A
    inner = _go_fetch_like_sqli_echo(_ssti_echo_session())
    served = []

    def _counting(*a, **k):
        out = inner(*a, **k)
        served.append(len(out))
        return out

    monkeypatch.setattr(G, "fetch_batch", _counting)
    kw = dict(timeout=3, verbose=False, pages=_sqli_pages(), base="http://h.test",
              deep=True)
    go_out = A.test_ssti(_ssti_echo_session(), ["http://h.test/?q=1"],
                         go_worker=True, **kw)
    py_out = A.test_ssti(_ssti_echo_session(), ["http://h.test/?q=1"], **kw)
    assert [(f.title, f.url) for f in go_out] == [(f.title, f.url) for f in py_out]
    assert any("SSTI" in f.title for f in go_out)
    # 1 base + 3 bundle GETs + 1 base + 3 bundle POSTs from the batches
    assert sum(served) == 8, "both GET and POST batches must engage"


def test_ssti_go_falls_back_on_worker_error(monkeypatch):
    import core.goworker as G
    import core.advanced as A
    monkeypatch.setattr(
        G, "fetch_batch",
        lambda *a, **k: (_ for _ in ()).throw(G.GoworkerError("down")))
    kw = dict(timeout=3, verbose=False, deep=False)
    go_out = A.test_ssti(_ssti_echo_session(), ["http://h.test/?q=1"],
                         go_worker=True, **kw)
    py_out = A.test_ssti(_ssti_echo_session(), ["http://h.test/?q=1"], **kw)
    assert [(f.title, f.url) for f in go_out] == [(f.title, f.url) for f in py_out]
    assert any("SSTI" in f.title for f in go_out)


def _login_pages():
    return {"http://h.test/login":
            "<form method='post' action='/login'>"
            "<input type='text' name='user'>"
            "<input type='password' name='pass'></form>"}


def _login_echo_session():
    from core.net import configure_net
    configure_net()
    logged = "<html>welcome back, logout to dashboard</html>"

    class Resp:
        def __init__(self, text="", status_code=200, url=""):
            self.text = text
            self.status_code = status_code
            self.url = url
            self.headers = {}

    class S:
        def get(self, url, timeout=None, allow_redirects=True, headers=None):
            return Resp("<html>login form</html>", 200, url)

        def post(self, url, timeout=None, allow_redirects=True, **kwargs):
            vals = " ".join(str(v) for v in (kwargs.get("data", {}) or {}).values())
            if "OR '1'='1" in vals or vals.split()[0] in (
                    "*", "admin*", "*)(", "*)(uid=*))("):
                return Resp(logged, 200, url)
            if "admin" in vals.split():
                return Resp("<html>wrong password</html>", 200, url)
            return Resp("<html>invalid username</html>", 200, url)

    return S()


def _go_fetch_like_login_echo(session):
    def _fetch(requests, headers=None, cookies=None, timeout=8, workers=20,
               snippet_bytes=4096, max_body=2 << 20):
        out = []
        for r in requests:
            data = r.get("form", {}) if isinstance(r, dict) else {}
            resp = session.post(r["url"], timeout=timeout, data=data)
            out.append({"url": r["url"], "final_url": resp.url,
                        "status": resp.status_code, "length": len(resp.text),
                        "snippet": resp.text, "truncated": False, "error": ""})
        return out
    return _fetch


def test_login_go_path_matches_python_path(monkeypatch):
    import core.goworker as G
    import core.advanced as A
    inner = _go_fetch_like_login_echo(_login_echo_session())
    served = []

    def _counting(*a, **k):
        out = inner(*a, **k)
        served.append(len(out))
        return out

    monkeypatch.setattr(G, "fetch_batch", _counting)
    pages = _login_pages()
    go_out = A.test_sqli_login(_login_echo_session(), pages, "http://h.test", 3,
                               go_worker=True)
    py_out = A.test_sqli_login(_login_echo_session(), pages, "http://h.test", 3)
    assert [(f.title, f.url) for f in go_out] == [(f.title, f.url) for f in py_out]
    assert any(f.title == "Possible SQLi Auth Bypass (login)" for f in go_out)
    assert sum(served) == 3, "baseline + both variants must batch"


def test_enum_go_path_matches_python_path(monkeypatch):
    import core.goworker as G
    import core.advanced as A
    inner = _go_fetch_like_login_echo(_login_echo_session())
    served = []

    def _counting(*a, **k):
        out = inner(*a, **k)
        served.append(len(out))
        return out

    monkeypatch.setattr(G, "fetch_batch", _counting)
    pages = _login_pages()
    go_out = A.test_login_enum(_login_echo_session(), pages, "http://h.test", 3,
                               go_worker=True)
    py_out = A.test_login_enum(_login_echo_session(), pages, "http://h.test", 3)
    assert [(f.title, f.url) for f in go_out] == [(f.title, f.url) for f in py_out]
    assert any(f.title == "Login username enumeration" for f in go_out)
    assert sum(served) == 2, "admin + random must batch"


def test_ldap_go_path_matches_python_path(monkeypatch):
    import core.goworker as G
    import core.advanced as A
    inner = _go_fetch_like_login_echo(_login_echo_session())
    served = []

    def _counting(*a, **k):
        out = inner(*a, **k)
        served.append(len(out))
        return out

    monkeypatch.setattr(G, "fetch_batch", _counting)
    pages = _login_pages()
    go_out = A.test_ldap_injection(_login_echo_session(), pages, "http://h.test", 3,
                                   go_worker=True)
    py_out = A.test_ldap_injection(_login_echo_session(), pages, "http://h.test", 3)
    assert [(f.title, f.url) for f in go_out] == [(f.title, f.url) for f in py_out]
    assert any("LDAP" in f.title for f in go_out)
    assert sum(served) == 4, "all wildcards must batch"


def test_login_go_falls_back_on_429(monkeypatch):
    import core.goworker as G
    import core.advanced as A

    def _limited(requests, headers=None, cookies=None, timeout=8, workers=20,
                 snippet_bytes=4096, max_body=2 << 20):
        return [{"url": r["url"], "final_url": "", "status": 429, "length": 3,
                 "snippet": "slow", "truncated": False, "error": ""}
                for r in requests]

    monkeypatch.setattr(G, "fetch_batch", _limited)
    pages = _login_pages()
    go_out = A.test_sqli_login(_login_echo_session(), pages, "http://h.test", 3,
                               go_worker=True)
    py_out = A.test_sqli_login(_login_echo_session(), pages, "http://h.test", 3)
    assert [(f.title, f.url) for f in go_out] == [(f.title, f.url) for f in py_out]
    assert any(f.title == "Possible SQLi Auth Bypass (login)" for f in go_out)


def _counted(monkeypatch, session, mock_fn):
    import core.goworker as G
    served = []

    def _counting(*a, **k):
        out = mock_fn(*a, **k)
        served.append(len(out))
        return out

    monkeypatch.setattr(G, "fetch_batch", _counting)
    return served


def _blind_echo_session():
    from core.net import configure_net
    configure_net()
    base = "B" * 100

    class Resp:
        def __init__(self, text="", status_code=200, url=""):
            self.text = text
            self.status_code = status_code
            self.url = url
            self.headers = {}

    class S:
        def get(self, url, timeout=None, allow_redirects=True, headers=None):
            if "1%27%3D%272" in url or "1'='2" in url:
                return Resp("C" * 50, 200, url)
            return Resp(base, 200, url)

    return S()


def test_blind_go_path_matches_python_path(monkeypatch):
    import core.advanced as A
    served = _counted(monkeypatch, None,
                      _go_fetch_like_sqli_echo(_blind_echo_session()))
    kw = dict(timeout=3, verbose=False, deep=False)
    go_out = A.test_sqli_blind(_blind_echo_session(), ["http://h.test/?id=1"],
                               go_worker=True, **kw)
    py_out = A.test_sqli_blind(_blind_echo_session(), ["http://h.test/?id=1"],
                               **kw)
    assert [(f.title, f.url) for f in go_out] == [(f.title, f.url) for f in py_out]
    assert any("Blind SQL Injection" in f.title for f in go_out)
    assert sum(served) == 9, "base + pairs + orderby + encoding must batch"


def _ssrf_echo_session():
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
            if "169.254" in url:
                return Resp("<html>ami-0abc1234 instance-id</html>", 200, url)
            return Resp("<html>landing page</html>", 200, url)

    return S()


def test_ssrf_go_path_matches_python_path(monkeypatch):
    import core.advanced as A
    served = _counted(monkeypatch, None,
                      _go_fetch_like_sqli_echo(_ssrf_echo_session()))
    kw = dict(timeout=3, verbose=False)
    go_out = A.test_ssrf(_ssrf_echo_session(), ["http://h.test/?url=1"],
                         go_worker=True, **kw)
    py_out = A.test_ssrf(_ssrf_echo_session(), ["http://h.test/?url=1"], **kw)
    assert [(f.title, f.url) for f in go_out] == [(f.title, f.url) for f in py_out]
    assert any(f.title == "Possible SSRF (cloud metadata)" for f in go_out)
    assert sum(served) == 4, "base + meta + azure + gcp must batch"


def _idor_echo_session():
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
            if url.endswith("/5"):
                return Resp("<html>" + "user five profile data " * 20 + "</html>",
                            200, url)
            if url.endswith("/6"):
                return Resp("<html>" + "user six other things here " * 20 + "</html>",
                            200, url)
            if "id=10" in url:
                return Resp("<html>" + "order ten details " * 25 + "</html>", 200, url)
            if "id=11" in url:
                return Resp("<html>" + "order eleven changes " * 25 + "</html>", 200, url)
            return Resp("<html>plain</html>", 200, url)

    return S()


def test_idor_go_path_matches_python_path(monkeypatch):
    import core.advanced as A
    served = _counted(monkeypatch, None,
                      _go_fetch_like_sqli_echo(_idor_echo_session()))
    pages = {"http://h/x": "<a href='http://h.test/api/users/5'>u</a>"}
    kw = dict(timeout=3, verbose=False)
    go_out = A.test_idor(_idor_echo_session(), pages, "http://h.test",
                         go_worker=True, **kw)
    py_out = A.test_idor(_idor_echo_session(), pages, "http://h.test", **kw)
    assert [(f.title, f.url) for f in go_out] == [(f.title, f.url) for f in py_out]
    assert any("IDOR" in f.title for f in go_out)
    assert sum(served) == 2, "object + sibling must batch"


def test_idor_param_go_path_matches_python_path(monkeypatch):
    import core.advanced as A
    served = _counted(monkeypatch, None,
                      _go_fetch_like_sqli_echo(_idor_echo_session()))
    kw = dict(timeout=3, verbose=False)
    go_out = A.test_idor_param(_idor_echo_session(), ["http://h.test/?id=10"],
                               go_worker=True, **kw)
    py_out = A.test_idor_param(_idor_echo_session(), ["http://h.test/?id=10"],
                               **kw)
    assert [(f.title, f.url) for f in go_out] == [(f.title, f.url) for f in py_out]
    assert any("IDOR" in f.title for f in go_out)
    assert sum(served) == 2, "object + sibling must batch"


def test_proto_go_path_matches_python_path(monkeypatch):
    import core.advanced as A
    served = _counted(monkeypatch, None,
                      _go_fetch_like_echo(_xss_echo_session()))
    kw = dict(timeout=3, verbose=False)
    urls = ["http://h.test/?a=1", "http://h.test/?b=2"]
    go_out = A.test_proto_pollution(_xss_echo_session(), urls, go_worker=True,
                                    **kw)
    py_out = A.test_proto_pollution(_xss_echo_session(), urls, **kw)
    assert [(f.title, f.url) for f in go_out] == [(f.title, f.url) for f in py_out]
    assert any("Prototype" in f.title for f in go_out)
    assert sum(served) == 4, "2 urls x 2 payloads must batch"


def _upload_echo_session():
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
            if url.endswith("/upload"):
                return Resp('<html><input type="file" name="f"></html>', 200, url)
            return Resp("nope", 404, url)

    return S()


def test_upload_go_path_matches_python_path(monkeypatch):
    from core.scanner import check_upload
    from core.wordlists import UPLOAD_PATHS
    served = _counted(monkeypatch, None,
                      _go_fetch_like_sqli_echo(_upload_echo_session()))
    go_out = check_upload(_upload_echo_session(), "http://h.test", 3, False,
                          go_worker=True)
    py_out = check_upload(_upload_echo_session(), "http://h.test", 3, False)
    assert [(f.title, f.url) for f in go_out] == [(f.title, f.url) for f in py_out]
    assert any(f.title == "Upload form detected" for f in go_out)
    assert sum(served) == len(UPLOAD_PATHS), "all upload paths must batch"


def _errpage_echo_session():
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
            if "gash404gx9yolu" in url:
                return Resp("<html>oops gash404gx9yolu</html>", 404, url)
            return Resp("<html>ref gxua8marker and gxref7marker here</html>",
                        404, url)

    return S()


def test_errpage_go_path_matches_python_path(monkeypatch):
    from core.scanner import test_xss_errpage
    served = _counted(monkeypatch, None,
                      _go_fetch_like_sqli_echo(_errpage_echo_session()))
    go_out = test_xss_errpage(_errpage_echo_session(), "http://h.test", 3, False,
                              go_worker=True)
    py_out = test_xss_errpage(_errpage_echo_session(), "http://h.test", 3, False)
    assert [(f.title, f.url) for f in go_out] == [(f.title, f.url) for f in py_out]
    assert any("404 page" in f.title for f in go_out)
    assert sum(served) == 2, "both errpage probes must batch"


def _api_echo_session():
    from core.net import configure_net
    configure_net()

    class Resp:
        def __init__(self, text="", status_code=200, url=""):
            self.text = text
            self.status_code = status_code
            self.url = url
            self.headers = {}

    class S:
        def post(self, url, timeout=None, allow_redirects=True, **kwargs):
            payload = kwargs.get("json") or {}
            vals = "".join(str(v) for v in payload.values())
            return Resp(f"<html>got {vals}</html>", 200, url)

        def request(self, method, url, timeout=None, allow_redirects=True,
                    **kwargs):
            return self.post(url, timeout=timeout, **kwargs)

    return S()


def _api_target():
    from types import SimpleNamespace as _NS
    param = _NS(name="q", location="json")
    return _NS(method="POST", content_type="application/json", params=[param],
               template="", url="http://h.test/api")


def _go_fetch_like_api_echo(session):
    def _fetch(requests, headers=None, cookies=None, timeout=8, workers=20,
               snippet_bytes=4096, max_body=2 << 20):
        import json as _json
        out = []
        for r in requests:
            body = _json.loads(r.get("body", "{}") or "{}")
            resp = session.post(r["url"], timeout=timeout, json=body)
            out.append({"url": r["url"], "final_url": resp.url,
                        "status": resp.status_code, "length": len(resp.text),
                        "snippet": resp.text, "truncated": False, "error": ""})
        return out
    return _fetch


def test_api_body_go_path_matches_python_path(monkeypatch):
    from core.scan.injection import _api_body_xss
    inner = _go_fetch_like_api_echo(_api_echo_session())
    served = []

    def _counting(*a, **k):
        out = inner(*a, **k)
        served.append(len(out))
        return out

    import core.goworker as G
    monkeypatch.setattr(G, "fetch_batch", _counting)
    go_out = _api_body_xss(_api_echo_session(), [_api_target()], 3, False,
                           go_worker=True)
    py_out = _api_body_xss(_api_echo_session(), [_api_target()], 3, False)
    assert [(f.title, f.url) for f in go_out] == [(f.title, f.url) for f in py_out]
    assert any(f.title == "Possible Reflected XSS" for f in go_out)
    assert sum(served) == 1, "the single leaf probe must batch"


def test_pace_many_fail_closed():
    from core.net import configure_net, get_context, pace_many, ScanBudgetExceeded
    import pytest
    configure_net(0.0, 2)
    pace_many(2)
    assert get_context().count == 2
    with pytest.raises(ScanBudgetExceeded):
        pace_many(1)
    configure_net()


def test_delay_gate_forces_python_path(monkeypatch):
    from core.net import configure_net
    from core.scan.enumeration import _go_fetchable
    configure_net(0.2, 0)
    try:
        assert _go_fetchable(object()) is None
    finally:
        configure_net()


def _crawl_lab_base():
    import threading
    import time as _time
    from bench.lab import serve
    from core.net import configure_net
    configure_net()
    srv = serve(0)
    port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    _time.sleep(0.3)
    return srv, f"http://127.0.0.1:{port}"


def _crawl_lab_html(base):
    import requests
    return requests.get(base + "/", timeout=5).text


def test_lab_crawl_hybrid_parity(monkeypatch):
    """Real binary + real HTTP crawl: identical page pools."""
    import pytest
    import core.goworker as G
    if not G.available():
        pytest.skip("go worker binary not built")
    srv, lab = _crawl_lab_base()
    try:
        from core.crawler import crawl
        from core.scanner import _session
        html = _crawl_lab_html(lab)
        kw = dict(timeout=5, max_pages=8, depth=2)
        real_fetch = G.fetch_batch
        served = []

        def _counting(*a, **k):
            out = real_fetch(*a, **k)
            served.append(len(out))
            return out

        monkeypatch.setattr(G, "fetch_batch", _counting)
        go_pages = crawl(_session(5), lab, html, go_worker=True, **kw)
        py_pages = crawl(_session(5), lab, html, **kw)
        assert go_pages == py_pages
        assert len(go_pages) > 1, "lab crawl must discover pages"
        assert sum(served) > 0, "crawl must fan out through the worker"
    finally:
        srv.shutdown()
        srv.server_close()


def test_crawl_go_falls_back_on_429(monkeypatch):
    import core.goworker as G
    from core.crawler import crawl
    from core.scanner import _session

    def _limited(requests, headers=None, cookies=None, timeout=8, workers=20,
                 snippet_bytes=4096, max_body=2 << 20):
        return [{"url": _req_url(r), "final_url": _req_url(r), "status": 429,
                 "length": 3, "snippet": "slow", "truncated": False,
                 "error": ""} for r in requests]

    monkeypatch.setattr(G, "fetch_batch", _limited)
    srv, lab = _crawl_lab_base()
    try:
        html = _crawl_lab_html(lab)
        kw = dict(timeout=5, max_pages=8, depth=2)
        go_pages = crawl(_session(5), lab, html, go_worker=True, **kw)
        py_pages = crawl(_session(5), lab, html, **kw)
        assert go_pages == py_pages
    finally:
        srv.shutdown()
        srv.server_close()


def _need_stream():
    import pytest
    import core.goworker as G
    if not G.available():
        pytest.skip("go worker binary not built")
    return G


def test_stream_session_reuse(monkeypatch):
    G = _need_stream()
    monkeypatch.delenv("GASH_GO_STREAM", raising=False)
    monkeypatch.setenv("GASH_GO_STREAM", "1")
    s1 = G.session()
    assert s1 is not None and s1.alive
    s2 = G.session()
    assert s2 is s1, "pool must hand out one shared process"
    assert s2.run({"job": "ping"})["pong"] is True
    out = s2.run({"job": "rank-wordlist", "techs": ["php"],
                  "paths": ["a", "x.php"], "limit": 10})
    assert out["paths"] == ["x.php", "a"]
    pid = s1.pid
    G.close_session()
    s3 = G.session()
    assert s3 is not None and s3.pid != pid, "close must drop the process"


def test_stream_disabled_env(monkeypatch):
    import core.goworker as G
    assert G.session() is None  # fixture forces GASH_GO_STREAM=0


def test_stream_dead_proc_drops(monkeypatch):
    G = _need_stream()
    monkeypatch.setenv("GASH_GO_STREAM", "1")
    sess = G.session()
    assert sess is not None
    sess._proc.kill()
    sess._proc.wait(timeout=10)
    import pytest as _pt
    with _pt.raises(G.GoworkerError):
        sess.run({"job": "ping"})
    assert G.session() is not None, "pool must respawn after death"


def test_stream_beats_spawns(monkeypatch):
    """Spawn floor, measured: 5 pings, stream vs single-shot."""
    import time
    G = _need_stream()
    monkeypatch.setenv("GASH_GO_STREAM", "1")
    sess = G.session()
    assert sess is not None
    t0 = time.time()
    for _ in range(5):
        assert sess.run({"job": "ping"})["pong"] is True
    stream_dt = time.time() - t0
    G.close_session()
    monkeypatch.setenv("GASH_GO_STREAM", "0")
    t0 = time.time()
    for _ in range(5):
        assert G.run_job({"job": "ping"})["pong"] is True
    single_dt = time.time() - t0
    print(f"\nstream5={stream_dt:.3f}s single5={single_dt:.3f}s")
    assert stream_dt < single_dt, "one spawn must beat five"

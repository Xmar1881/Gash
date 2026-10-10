"""OOB client tests. Crypto round-trips need `cryptography`,
logic tests (matching, drain, wiring) run without it."""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))


class FakeOob:
    """Duck-typed stand-in: real url_for shape, scripted interactions."""

    def __init__(self, interactions=None):
        self.pending = []
        self._interactions = interactions or []
        self.wait = 0
        self.poll_calls = 0
        self.deregistered = False

    def url_for(self, token):
        return f"https://{token}.oob.test/x"

    def poll(self):
        self.poll_calls += 1
        return list(self._interactions)

    def deregister(self):
        self.deregistered = True

    def register(self):
        return "x.oob.test"

    @property
    def session_domain(self):
        return "x.oob.test"


def test_token_and_url_shape():
    import core.oob as O
    c = O.OobClient(server="https://oob.test")
    assert len(c.cid) == 20 and c.cid.isalnum() and c.cid.islower()
    t = O.new_token()
    assert t[0] == "g" and t.isalnum() and t.islower()
    assert O.new_token() != O.new_token()
    assert c.url_for(t) == f"https://{t}.oob.test/x" or \
        c.url_for(t).startswith(f"https://{t}.")
    assert c.url_for("GABC!!").startswith("https://gabc.")


def test_register_ok(monkeypatch):
    pytest.importorskip("cryptography")
    import core.oob as O

    class R:
        status_code = 200

    monkeypatch.setattr(O.requests, "post", lambda *a, **k: R())
    c = O.OobClient(server="https://oob.test", timeout=3)
    assert c.register().endswith(".oob.test")


def test_register_refused(monkeypatch):
    pytest.importorskip("cryptography")
    import core.oob as O

    class R:
        status_code = 500

    monkeypatch.setattr(O.requests, "post", lambda *a, **k: R())
    c = O.OobClient(server="https://oob.test", timeout=3)
    with pytest.raises(O.OobError):
        c.register()


def test_decrypt_roundtrip(monkeypatch):
    pytest.importorskip("cryptography")
    import base64
    import json
    import os
    import core.oob as O
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding, rsa
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms

    priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    aes = os.urandom(16)
    payload = {"full-id": "gtok123.abc.oob.test", "protocol": "http",
               "remote-address": "1.2.3.4"}
    raw = json.dumps(payload).encode()
    iv = os.urandom(16)
    ct = Cipher(algorithms.AES(aes), O._cfb_mode(iv)).encryptor().update(raw)
    item = base64.b64encode(iv + ct).decode()
    enc_aes = priv.public_key().encrypt(
        aes, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                         algorithm=hashes.SHA256(), label=None))

    class R:
        status_code = 200

        def json(self):
            return {"data": [item],
                    "aes_key": base64.b64encode(enc_aes).decode()}

    monkeypatch.setattr(O.requests, "get", lambda *a, **k: R())
    c = O.OobClient(server="https://oob.test", timeout=3)
    c._priv = priv
    out = c.poll()
    assert out and out[0]["full-id"] == "gtok123.abc.oob.test"


def test_poll_match(monkeypatch):
    import core.oob as O
    c = O.OobClient(server="https://oob.test", timeout=3, wait=0)
    monkeypatch.setattr(
        c, "poll",
        lambda: [{"full-id": "gabc.cid.oob.test", "protocol": "dns"}])
    hit = c.poll_match("gabc")
    assert hit and hit["protocol"] == "dns"
    assert c.poll_match("other") is None


def test_drain_confirms_and_stays_quiet():
    import core.oob as O
    fake = FakeOob([{"full-id": "gxss.oob.test", "protocol": "http",
                     "remote-address": "9.9.9.9"}])
    fake.pending = [{"kind": "xss", "target": "http://h.test/go",
                     "token": "gxss"},
                    {"kind": "ssrf", "target": "http://h.test/?url=1",
                     "token": "gmiss"}]
    out = O.drain(fake, verbose=False)
    assert len(out) == 1
    assert out[0].title == "Blind XSS (confirmed via OOB)"
    assert out[0].severity == "MEDIUM" and out[0].confidence == "High"
    assert out[0].triage["is_vulnerable"] is True
    assert out[0].triage["vulnerability_type"] == "Stored_XSS"
    assert fake.poll_calls == 1  # one shared cycle, not per-token waits
    assert fake.deregistered is True


def test_drain_ssrf_critical():
    import core.oob as O
    fake = FakeOob([{"full-id": "gssrf.oob.test", "protocol": "dns",
                     "remote-address": "9.9.9.9"}])
    fake.pending = [{"kind": "ssrf", "target": "http://h.test/?url=1",
                     "token": "gssrf"}]
    out = O.drain(fake, verbose=False)
    assert len(out) == 1
    assert out[0].title == "SSRF (confirmed via OOB)"
    assert out[0].severity == "CRITICAL"


def test_stored_blind_uses_oob_quietly():
    from core.net import configure_net
    import core.advanced as A
    configure_net()
    fake = FakeOob()

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
            return Resp("ok", url=url)

    pages = {"http://h.test/":
             "<form method='get' action='/go'><input name='q'></form>"}
    out = A.test_stored_xss(S(), pages, "http://h.test", 3, oob=fake)
    assert all("Blind" not in f.title for f in out)  # proof comes from drain
    assert len(fake.pending) == 1
    assert fake.pending[0]["kind"] == "xss"


def test_ssrf_records_oob_probe():
    from core.net import configure_net
    import core.advanced as A
    configure_net()
    fake = FakeOob()

    class Resp:
        def __init__(self, text="", status_code=200, url=""):
            self.text = text
            self.status_code = status_code
            self.url = url
            self.headers = {}

    class S:
        def get(self, url, timeout=None, allow_redirects=True, headers=None):
            return Resp("<html>ok</html>", url=url)

    A.test_ssrf(S(), ["http://h.test/?url=x"], 3, oob=fake)
    assert len(fake.pending) == 1
    assert fake.pending[0]["kind"] == "ssrf"


def test_oob_kb():
    from core.knowledge import lookup
    assert lookup("Blind XSS (confirmed via OOB)")["cwe"] == "CWE-79"
    assert lookup("SSRF (confirmed via OOB)")["cwe"] == "CWE-918"


def test_scan_target_wires_oob(monkeypatch, tmp_path):
    """_scan_target builds the OOB client and hands it to run_scan."""
    import gash
    import core.oob as O
    from types import SimpleNamespace
    monkeypatch.chdir(tmp_path)

    seen = {}

    def fake_run_scan(target, **kw):
        seen.update(kw)
        return []

    fake = FakeOob()
    monkeypatch.setattr(O, "OobClient", lambda *a, **k: fake)
    monkeypatch.setattr(gash, "run_scan", fake_run_scan)
    args = SimpleNamespace(delay=0.0, max_requests=0, cookie=None,
                           header=None, login_user=None, login_pass=None,
                           login_url=None, timeout=3, skip_ports=True,
                           ports=None, threads=5, verbose=False,
                           wordlist=None, quick=False, deep=False,
                           skip_checks=None, max_pages=1, depth=1,
                           no_crawl=True, dom=False, blind_callback=None,
                           scope=None, fail_on=None, resume=False,
                           output=None, output_dir=None, oob=True,
                           oob_server=None, oob_wait=0, proxy=None,
                           user_agent=None, insecure=False)
    assert gash.run_single("http://h.test", args, "scan") == 0
    assert seen.get("oob") is fake


def test_run_scan_drains_oob(monkeypatch):
    """run_scan appends OOB-confirmed findings to the result list."""
    import core.scanner as S
    monkeypatch.setattr(S, "_fetch_base",
                        lambda *a, **k: ("", "http://h.test", {}))
    fake = FakeOob([{"full-id": "gx.oob.test", "protocol": "dns",
                     "remote-address": "9.9.9.9"}])
    fake.pending = [{"kind": "xss", "target": "http://h.test/go",
                     "token": "gx"}]
    out = S.run_scan("http://h.test", timeout=3, verbose=False, deep=False,
                     no_crawl=True, oob=fake)
    assert any(f.title == "Blind XSS (confirmed via OOB)" for f in out)

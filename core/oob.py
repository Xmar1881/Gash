"""Out-of-band interaction client (interactsh protocol).

Blind findings are worthless until something calls back. This client gives
every probe a unique subdomain; if the target (or some admin's browser)
fetches it, the callback upgrades the guess into proof.

Needs the `cryptography` package (pip install gash[oob]). Without it the
client refuses to start and scans continue without OOB — never a crash.

Protocol notes (projectdiscovery/interactsh, best-effort implementation):
public key goes up PKCS1-DER base64, the AES session key comes back
RSA-OAEP-SHA256 encrypted, interactions are AES-CFB with the IV prepended.
Any deviation on the server side surfaces as OobError, never garbage.
"""

from __future__ import annotations

import base64
import json
import re
import secrets
import time
import uuid
from urllib.parse import urlparse

import requests


class OobError(Exception):
    """OOB server unreachable, protocol mismatch, or crypto failure."""


def available() -> bool:
    """Is the optional crypto backend installed?"""
    try:
        import cryptography  # noqa: F401
        return True
    except ImportError:
        return False


def _crypto():
    try:
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import padding, rsa
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    except ImportError:
        raise OobError("cryptography package missing: pip install gash[oob]")
    return hashes, serialization, padding, rsa, Cipher, algorithms, modes


def new_token(n: int = 10) -> str:
    """DNS-safe unique token: g + hex."""
    return "g" + secrets.token_hex((n + 7) // 2)[:n]


def _cfb_mode(iv: bytes):
    """AES-CFB mode object. Newer cryptography moved CFB to the decrepit
    namespace; try there first, fall back for older installs."""
    try:
        from cryptography.hazmat.decrepit.ciphers import modes as _modes
        return _modes.CFB(iv)
    except ImportError:
        from cryptography.hazmat.primitives.ciphers import modes as _modes
        return _modes.CFB(iv)


def _decrypt_aes_key(aes_b64: str, priv) -> bytes:
    _hashes, _ser, padding, _rsa, _Cipher, _algos, _modes = _crypto()
    return priv.decrypt(
        base64.b64decode(aes_b64),
        padding.OAEP(mgf=padding.MGF1(algorithm=_hashes.SHA256()),
                     algorithm=_hashes.SHA256(), label=None),
    )


def _decrypt_item(item_b64: str, aes_key: bytes) -> dict:
    _hashes, _ser, _pad, _rsa, Cipher, algorithms, _modes = _crypto()
    raw = base64.b64decode(item_b64)
    iv, ct = raw[:16], raw[16:]
    pt = Cipher(algorithms.AES(aes_key),
                _cfb_mode(iv)).decryptor().update(ct)
    return json.loads(pt.decode("utf-8", "ignore"))


class OobClient:
    """One OOB session: register -> hand out URLs -> poll for callbacks."""

    def __init__(self, server: str = "https://interact.sh",
                 timeout: int = 8, wait: int = 20):
        self.server = (server or "https://interact.sh").rstrip("/")
        host = urlparse(self.server).hostname or self.server
        self.root_domain = host.lower()
        self.timeout = timeout
        self.wait = max(0, int(wait or 0))
        self.cid = "".join(secrets.choice("abcdefghijklmnopqrstuvwxyz0123456789")
                           for _ in range(20))
        self.secret = uuid.uuid4().hex
        self._priv = None
        self._aes: bytes | None = None
        self.pending: list[dict] = []  # checks append {"kind","target","token"}

    @property
    def session_domain(self) -> str:
        return f"{self.cid}.{self.root_domain}"

    def url_for(self, token: str) -> str:
        token = re.sub(r"[^a-z0-9]", "", (token or "").lower()) or "gx"
        return f"https://{token}.{self.session_domain}/x"

    def register(self) -> str:
        """Create the server-side session. Returns the session domain."""
        _hashes, serialization, _pad, rsa, _Cipher, _algos, _modes = _crypto()
        self._priv = rsa.generate_private_key(public_exponent=65537,
                                              key_size=2048)
        pub = self._priv.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.PKCS1)
        try:
            r = requests.post(
                self.server + "/register",
                json={"public-key": base64.b64encode(pub).decode(),
                      "secret-key": self.secret,
                      "correlation-id": self.cid},
                timeout=self.timeout)
        except Exception as e:
            raise OobError(f"register failed: {e}")
        if r.status_code != 200:
            raise OobError(f"register refused: HTTP {r.status_code}")
        return self.session_domain

    def poll_match(self, token: str) -> dict | None:
        """Poll until this token calls back, or the wait budget runs out."""
        try:
            hit = _match(self.poll(), token)
        except OobError:
            raise
        except Exception as e:
            raise OobError(f"poll failed: {e}")
        if hit or self.wait <= 0:
            return hit
        first = min(10, self.wait)
        time.sleep(first)
        hit = _match(self.poll(), token)
        if hit or self.wait <= first + 5:
            return hit
        time.sleep(self.wait - first)
        return _match(self.poll(), token)

    def poll(self) -> list[dict]:
        """Fetch + decrypt all interactions so far (may be empty)."""
        if self._priv is None:
            raise OobError("not registered")
        try:
            r = requests.get(
                self.server + "/poll",
                params={"id": self.cid, "secret": self.secret},
                timeout=self.timeout)
        except Exception as e:
            raise OobError(f"poll failed: {e}")
        if r.status_code != 200:
            raise OobError(f"poll refused: HTTP {r.status_code}")
        try:
            payload = r.json()
        except Exception as e:
            raise OobError(f"poll not JSON: {e}")
        try:
            if self._aes is None:
                self._aes = _decrypt_aes_key(payload["aes_key"], self._priv)
        except Exception as e:
            raise OobError(f"session key unwrap failed: {e}")
        out = []
        for item in payload.get("data") or []:
            try:
                out.append(_decrypt_item(item, self._aes))
            except Exception:
                continue  # one bad record must not kill the batch
        return out

def _match(interactions: list[dict], token: str) -> dict | None:
    """First interaction whose full-id belongs to this token."""
    want = (token or "").lower() + "."
    for inter in interactions or []:
        fid = str(inter.get("full-id", "")).lower()
        if fid == (token or "").lower() or fid.startswith(want):
            return inter
    return None


def _poll_rounds(wait: int) -> list[int]:
    """Sleep plan for shared polling: at most 3 rounds over ~wait seconds."""
    if wait <= 0:
        return [0]
    if wait <= 12:
        return [0, wait]
    first, second = 10, min(10, wait - 10)
    plan = [0, first, second]
    if wait - first - second > 0:
        plan.append(wait - first - second)
    return plan

    def deregister(self) -> None:
        """Best-effort session cleanup. Server expiry covers failures."""
        try:
            requests.post(
                self.server + "/deregister",
                json={"correlation-id": self.cid, "secret-key": self.secret},
                timeout=self.timeout)
        except Exception:
            pass


def drain(client: "OobClient", verbose: bool = False) -> list:
    """Correlate pending probe tokens with callbacks -> confirmed findings.

    One shared polling cycle for ALL tokens (15 pending tokens cost the
    same wait as 1). No callback means no finding: silence is the point.
    """
    from core.colors import info as _info, warn as _warn
    from core.scanner import Finding
    from core.spinner import spin
    pending = list(getattr(client, "pending", []) or [])
    out: list[Finding] = []
    if not pending:
        return out
    if verbose:
        print(_info(f"  [*] OOB verify: {len(pending)} callbacks pending..."))
    sp = spin(f"  [*] Waiting on {len(pending)} OOB callbacks...",
              enabled=not verbose).start()
    try:
        remaining = list(pending)
        for i, nap in enumerate(_poll_rounds(getattr(client, "wait", 20))):
            if i:
                time.sleep(nap)
            try:
                interactions = client.poll()
            except OobError as e:
                if verbose:
                    print(_warn(f"  [!] OOB dead ({e}), rest unverified."))
                break
            except Exception:
                continue
            for p in list(remaining):
                hit = _match(interactions, p.get("token", ""))
                if not hit:
                    continue
                remaining.remove(p)
                token = p.get("token", "")
                proto = str(hit.get("protocol", "?"))
                remote = str(hit.get("remote-address", "?"))
                kind = p.get("kind", "xss")
                if kind == "ssrf":
                    out.append(Finding(
                        title="SSRF (confirmed via OOB)", severity="CRITICAL",
                        url=p.get("target", ""),
                        detail=f"Server fetched our URL ({proto} from {remote}); "
                               f"token '{token}' called back",
                        evidence=token,
                        confidence="High",
                    ))
                    if verbose:
                        print(_warn(f"    [!] SSRF confirmed via OOB: {token}"))
                elif kind == "sqli":
                    out.append(Finding(
                        title="SQLi (confirmed via OOB)", severity="CRITICAL",
                        url=p.get("target", ""),
                        detail=f"Database resolved our URL ({proto} from "
                               f"{remote}); token '{token}' called back",
                        evidence=token,
                        confidence="High",
                    ))
                    if verbose:
                        print(_warn(f"    [!] SQLi confirmed via OOB: {token}"))
                elif kind == "reset":
                    out.append(Finding(
                        title="Password reset poisoning (confirmed via OOB)",
                        severity="CRITICAL",
                        url=p.get("target", ""),
                        detail=f"Reset flow fetched our host ({proto} from "
                               f"{remote}); token '{token}' called back — "
                               "reset links leak to attacker domains",
                        evidence=token,
                        confidence="High",
                    ))
                    if verbose:
                        print(_warn(f"    [!] Reset poisoning confirmed: {token}"))
                else:
                    out.append(Finding(
                        title="Blind XSS (confirmed via OOB)", severity="MEDIUM",
                        url=p.get("target", ""),
                        detail=f"Callback fired for token '{token}' "
                               f"({proto} from {remote})",
                        evidence=token,
                        confidence="High",
                    ))
                    if verbose:
                        print(_warn(f"    [!] Blind XSS confirmed via OOB: {token}"))
            if not remaining:
                break
    finally:
        sp.stop()
        try:
            client.deregister()
        except Exception:
            pass
    return out

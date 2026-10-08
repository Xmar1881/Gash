#!/usr/bin/env python3
"""Vulnerable lab app for regression tests — stdlib only, localhost only.

Every fixture ships as a vulnerable/fixed pair so tests assert both
directions (vulnerable -> scanner detects, fixed -> scanner stays
quiet). State lives in memory; POST /reset clears it.

    py bench/lab.py [port]     # serve locally for manual runs

The pytest suite (tests/test_lab.py) boots this in-process instead.
"""

from __future__ import annotations

import html as _html
import json as _json
import re
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

STATE: dict = {"stored": [], "stored_fixed": [], "uploads": {}}
LAB_UUID = "123e4567-e89b-12d3-a456-426614174000"


def _read_body(handler) -> tuple[str, bytes]:
    try:
        length = int(handler.headers.get("Content-Length", 0) or 0)
    except Exception:
        length = 0
    raw = handler.rfile.read(length) if length > 0 else b""
    ctype = (handler.headers.get("Content-Type", "") or "")
    if "json" in ctype:
        try:
            doc = _json.loads(raw.decode("utf-8", "ignore"))
            if isinstance(doc, dict):
                return ctype, doc
        except Exception:
            pass
    text = raw.decode("utf-8", "ignore")
    if "urlencoded" in ctype or "form-data" in ctype and "boundary=" not in ctype:
        from urllib.parse import parse_qsl
        return ctype, dict(parse_qsl(text, keep_blank_values=True))
    return ctype, {"_raw": text, "_bytes": raw}


def _multipart_file(raw: bytes) -> tuple[str, bytes]:
    """(filename, content) of the first file part. ('', b'') when none."""
    try:
        text = raw.decode("utf-8", "ignore")
    except Exception:
        return "", b""
    m = re.search(r'filename="([^"]+)"', text)
    if not m:
        return "", b""
    parts = text.split("\r\n\r\n", 1)
    content = parts[1].rsplit("\r\n--", 1)[0] if len(parts) > 1 else ""
    return m.group(1), content.encode("utf-8", "ignore")


class Lab(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.0"

    def _send(self, body: str | bytes, code: int = 200,
              headers: dict | None = None):
        if isinstance(body, str):
            body = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def _json(self, obj, code: int = 200):
        raw = _json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def log_message(self, *a):
        pass

    def do_GET(self):
        p = urlparse(self.path)
        qs = parse_qs(p.query)
        first = lambda k: (qs.get(k) or [""])[0]  # noqa: E731
        path = p.path.rstrip("/") or "/"

        if path == "/":
            links = ["xss_reflected", "xss_stored", "sqli_error",
                     "sqli_blind", "sqli_time", "api/users/5", "redirect",
                     "traversal", "cmd", "dom", "graphql", "upload",
                     "login", "secrets", "jwt", "massassign"]
            self._send("<html>" + "".join(
                f"<a href='/{l}'>→/{l}</a><br>" for l in links) + "</html>")
            return
        if path == "/xss_reflected":
            self._send(f"<html>hello {first('name')}</html>")
            return
        if path == "/xss_reflected_fixed":
            self._send(f"<html>hello {_html.escape(first('name'))}</html>")
            return
        if path == "/xss_stored":
            items = "".join(f"<p>{m}</p>" for m in STATE["stored"][-20:])
            self._send("<html><form method='post' action='/xss_stored'>"
                       "<input name='comment'></form>" + items + "</html>")
            return
        if path == "/xss_stored_fixed":
            items = "".join(f"<p>{_html.escape(m)}</p>"
                            for m in STATE["stored_fixed"][-20:])
            self._send("<html><form method='post' action='/xss_stored_fixed'>"
                       "<input name='comment'></form>" + items + "</html>")
            return
        if path == "/sqli_error":
            ident = first("id")
            if "'" in ident or '"' in ident:
                self._send("<html>You have an error in your SQL syntax</html>")
            else:
                self._send(f"<html>item {ident}</html>")
            return
        if path == "/sqli_error_fixed":
            self._send("<html>item</html>")
            return
        if path == "/sqli_blind":
            ident = first("id")
            if "AND '1'='2" in ident or 'AND "1"="2' in ident:
                self._send("<html>" + "n" * 100 + "</html>")
            else:
                self._send("<html>" + "y" * 500 + "</html>")
            return
        if path == "/sqli_blind_fixed":
            self._send("<html>" + "y" * 500 + "</html>")
            return
        if path == "/sqli_time":
            ident = first("id").upper()
            if "SLEEP(" in ident or "PG_SLEEP(" in ident or "WAITFOR" in ident:
                time.sleep(3.2)
            self._send("<html>done</html>")
            return
        if path == "/sqli_time_fixed":
            self._send("<html>done</html>")
            return
        if path == "/api/users/5":
            self._json({"id": 5, "owner": "alice", "email": "a@lab.x"})
            return
        if path == "/api/users/6":
            self._json({"id": 6, "owner": "bob",
                        "email": "b@lab.x", "extra": "x" * 120})
            return
        if path == "/api/users_fixed/5":
            self._json({"id": 5, "owner": "alice"})
            return
        if path == "/api/users_fixed/6":
            self.send_response(403)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        if path == f"/api/share/{LAB_UUID}":
            self._json({"id": LAB_UUID, "owner": "alice"})
            return
        if path == "/redirect":
            self.send_response(302)
            self.send_header("Location", first("next") or "/home")
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        if path == "/redirect_fixed":
            self.send_response(302)
            self.send_header("Location", "/home")
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        if path == "/traversal":
            if "etc/passwd" in first("file"):
                self._send("root:x:0:0:root:/root:/bin/bash")
            elif "etc/hosts" in first("file"):
                self._send("127.0.0.1 localhost")
            else:
                self._send("not found", code=404)
            return
        if path == "/traversal_fixed":
            self._send("not found", code=404)
            return
        if path == "/cmd":
            ip = first("ip")
            if any(t in ip for t in (";id", "|id", "&&id", "$(id)")):
                self._send("<html>uid=0(root) gid=0(root)</html>")
            else:
                self._send(f"<html>ping {ip}</html>")
            return
        if path == "/cmd_fixed":
            self._send("<html>pong</html>")
            return
        if path == "/dom":
            self._send("<html><script>var q=location.search;"
                       "document.write('q=' + q);</script></html>")
            return
        if path == "/cors":
            origin = self.headers.get("Origin", "")
            self._send("<html>ok</html>",
                       headers={"Access-Control-Allow-Origin": origin})
            return
        if path == "/cors_fixed":
            self._send("<html>ok</html>")
            return
        if path == "/csp_weak":
            self._send("<html>ok</html>",
                       headers={"Content-Security-Policy":
                                "script-src 'unsafe-inline'"})
            return
        if path == "/csp_fixed":
            self._send("<html>ok</html>",
                       headers={"Content-Security-Policy":
                                "default-src 'self'; script-src 'self'"})
            return
        if path == "/cookies":
            self._send("<html>ok</html>",
                       headers={"Set-Cookie": "session=abc"})
            return
        if path == "/cookies_fixed":
            self._send("<html>ok</html>",
                       headers={"Set-Cookie":
                                "session=abc; HttpOnly; SameSite=Lax"})
            return
        if path == "/jwt":
            tok = ("eyJhbGciOiJub25lIn0.eyJzdWIiOiIxMjM0NTY3ODkwIn0.")
            self._send(f"<html><script>var t='{tok}';</script></html>")
            return
        if path == "/jwt_fixed":
            self._send("<html><script>var t='none';</script></html>")
            return
        if path == "/graphql_fixed":
            self._send("nope", code=400)
            return
        if path == "/massassign":
            self._send("<html><form method='post' action='/register'>"
                       "<input name='email'><input name='role'></form></html>")
            return
        if path == "/massassign_fixed":
            self._send("<html><form method='post' action='/register'>"
                       "<input name='email'></form></html>")
            return
        if path == "/secrets":
            # synthetic-only key (16×Z): matches the AKIA shape, hits no
            # placeholder filter, belongs to nobody.
            self._send("<html><script>"
                       'var k="AKIAZZZZZZZZZZZZZZZZ";</script></html>')
            return
        if path == "/secrets_fixed":
            self._send("<html><script>"
                       'var k="AKIA-TEST-KEY-PLACEHOLDER";</script></html>')
            return
        if path == "/upload":
            self._send("<html><form method='post' action='/upload' "
                       "enctype='multipart/form-data'>"
                       "<input type='file' name='file'></form></html>")
            return
        if path.startswith("/uploads/"):
            name = path.rsplit("/", 1)[-1]
            data = STATE["uploads"].get(name)
            if data is None:
                self._send("nope", code=404)
            else:
                self._send(data)
            return
        if path == "/cache":
            host = self.headers.get("Host", "")
            self._send(f"<html>welcome {host}</html>",
                       headers={"Age": "10", "X-Cache": "HIT"})
            return
        if path == "/cache_fixed":
            self._send("<html>welcome</html>")
            return
        if path == "/login":
            self._send("<html><form method='post' action='/login'>"
                       "<input type='text' name='user'>"
                       "<input type='password' name='pw'>"
                       "</form></html>")
            return
        if path == "/login_fixed":
            self._send("<html><form method='post' action='/login_fixed'>"
                       "<input type='text' name='user'>"
                       "<input type='password' name='pw'>"
                       "</form></html>")
            return
        if path == "/ssrf_echo":
            # surface fixture: accepts a URL param but never mirrors it,
            # so metadata markers can't fake a CRITICAL here.
            self._send("<html>fetch service (target hidden)</html>")
            return
        self._send("nope", code=404)

    def do_POST(self):
        p = urlparse(self.path)
        path = p.path.rstrip("/") or "/"
        ctype, data = _read_body(self)
        if path == "/reset":
            STATE["stored"] = []
            STATE["stored_fixed"] = []
            STATE["uploads"] = {}
            self._send("ok")
            return
        if path == "/xss_stored":
            STATE["stored"].append(str(data.get("comment", ""))[:200])
            self._send("<html>saved</html>")
            return
        if path == "/xss_stored_fixed":
            STATE["stored_fixed"].append(str(data.get("comment", ""))[:200])
            self._send("<html>saved</html>")
            return
        if path == "/graphql":
            try:
                doc = data if isinstance(data, dict) else {}
                q = doc.get("query", "")
            except Exception:
                q = ""
            if "__schema" in q or "__typename" in q:
                self._json({"data": {"__schema": {
                    "queryType": {"name": "Query"},
                    "mutationType": {"name": "Mutation"},
                    "types": [
                        {"kind": "OBJECT", "name": "Query", "fields": [
                            {"name": "users", "args": [],
                             "type": {"kind": "LIST",
                                      "ofType": {"kind": "OBJECT",
                                                 "name": "User"}}},
                            {"name": "user", "args": [
                                {"name": "id", "type": {
                                    "kind": "NON_NULL", "ofType": {
                                        "kind": "SCALAR",
                                        "name": "ID"}}}],
                             "type": {"kind": "OBJECT", "name": "User"}},
                        ]},
                        {"kind": "OBJECT", "name": "Mutation", "fields": [
                            {"name": "updateEmail", "args": [
                                {"name": "id", "type": {
                                    "kind": "SCALAR", "name": "ID"}}],
                             "type": {"kind": "SCALAR",
                                      "name": "Boolean"}},
                        ]},
                        {"kind": "OBJECT", "name": "User", "fields": [
                            {"name": "email", "args": [],
                             "type": {"kind": "SCALAR", "name": "String"}},
                            {"name": "name", "args": [],
                             "type": {"kind": "SCALAR", "name": "String"}},
                        ]},
                    ]}}})
                return
            if "users" in q:
                self._json({"data": {"users": [
                    {"email": "lab@lab.x", "name": "lab"}]}})
                return
            if "user(" in q:
                self._json({"data": {"user": {
                    "email": "lab@lab.x", "name": "lab"}}})
                return
            self._json({"errors": [{"message": "bad query"}]})
            return
        if path == "/upload":
            raw = data.get("_bytes", b"") if isinstance(data, dict) else b""
            name, content = _multipart_file(raw)
            if name:
                STATE["uploads"][name.split("/")[-1]] = content
                disp = name.split("/")[-1]
                self._send(f'File {name} uploaded ok "/uploads/{disp}"')
            else:
                self._send("denied", code=400)
            return
        if path == "/login":
            user = str(data.get("user", ""))
            if user == "admin":
                self._send("<html>invalid password</html>")
            elif user.startswith("gashnouser"):
                self._send("<html>unknown user</html>")
            else:
                self._send("<html>unknown user</html>")
            return
        if path == "/login_fixed":
            self._send("<html>invalid credentials</html>")
            return
        self._send("nope", code=404)


def serve(port: int = 0) -> ThreadingHTTPServer:
    srv = ThreadingHTTPServer(("127.0.0.1", port), Lab)
    return srv


if __name__ == "__main__":
    import sys
    srv = serve(int(sys.argv[1]) if len(sys.argv) > 1 else 8765)
    print(f"[+] lab on http://127.0.0.1:{srv.server_address[1]}")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass

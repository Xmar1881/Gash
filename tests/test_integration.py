"""GASH integration test — local stub server, no outside network (~15s)."""

import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse, parse_qs

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))


class H(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.0"

    def do_GET(self):
        p = urlparse(self.path)
        qs = parse_qs(p.query)
        vals = " ".join(sum(qs.values(), []))
        if p.path == "/" and "id" not in qs:
            body = ("<html><a href='/?id=1'>i</a>"
                    "<form method='get' action='/go'><input name='q'></form></html>")
            code = 200
        elif p.path == "/go":
            body = f"<html>got {vals}</html>"
            code = 200
        elif "id" in qs:
            if "'" in vals or '"' in vals:
                body = "<html>You have an error in your SQL syntax</html>"
            elif "gx1" in vals or "gx2" in vals or "gx3" in vals:
                body = f"<html>{vals}</html>"
            else:
                body = f"<html>item {vals}</html>"
            code = 200
        elif p.path == "/admin":
            body, code = "<html>Admin Panel login</html>", 200
        elif p.path == "/robots.txt":
            body, code = "User-agent: *\nDisallow: /admin\n", 200
        elif p.path == "/gash_nope_987654321":
            body, code = "not found", 404
        else:
            body, code = "nope", 404
        b = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def log_message(self, *a):
        pass


def test_full_scan_stub():
    from core.scanner import run_scan
    srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
    port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    time.sleep(0.3)
    try:
        fs = run_scan(f"http://127.0.0.1:{port}", threads=10, timeout=3,
                      verbose=False, deep=False, max_pages=2)
    finally:
        srv.shutdown()
    titles = " | ".join(f.title for f in fs)
    urls = " ".join(f.url or "" for f in fs)
    assert "Possible SQL Injection" in titles
    assert "Possible Reflected XSS" in titles
    assert "Admin Panel" in titles
    assert "robots.txt Found" in titles
    assert "/go?q=" in urls  # discovered with the form's input name
    # discovery is INFO, never scored as a vulnerability
    obs = [f for f in fs if f.severity == "INFO"]
    assert any("Admin Panel" in f.title for f in obs)
    assert any("robots.txt" in f.title for f in obs)
    assert any(f.severity != "INFO" for f in fs)
    # enrichment filled in?
    sqli = next(f for f in fs if f.title == "Possible SQL Injection")
    assert sqli.cwe == "CWE-89" and sqli.remediation

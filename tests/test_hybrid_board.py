"""Hybrid scoreboard: stdlib-lab ground truth, Python vs Go worker.

Each row runs one check against a vulnerable endpoint (expect a finding)
and its fixed twin (expect no CRITICAL/MEDIUM), in both engines. Go and
Python verdicts must match exactly; only the fetching engine differs.

The deterministic scoreboard is written to bench/hybrid_board.md (timings
go to stdout only, so the file never churns between runs).
"""
from __future__ import annotations

import time
from pathlib import Path

import pytest

pytestmark = pytest.mark.skipif(
    __import__("core.goworker", fromlist=["available"]).available() is False,
    reason="go worker binary not built",
)

BOARD_PATH = Path(__file__).resolve().parent.parent / "bench" / "hybrid_board.md"
SEVERE = {"CRITICAL", "MEDIUM"}


def _lab():
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


def _sess():
    from core.scanner import _session
    return _session(5)


def _titles(out):
    return [f.title for f in out]


def _severe(out):
    return [f for f in out if f.severity in SEVERE]


def _row(name, base, vuln, fixed, expect):
    """Run one matrix row in both engines. Returns (rec, go_titles, py_titles)."""
    import core.advanced as A
    import core.scanner as SC
    calls = {
        "xss-reflected": lambda s, u, go: SC.test_xss(
            s, [u], 5, False, deep=False, go_worker=go),
        "xss-stored": lambda s, u, go: A.test_stored_xss(
            s, u, base, 5) if isinstance(u, dict)
        else [],
        "sqli-error": lambda s, u, go: SC.test_sqli(
            s, [u], 5, False, deep=False, go_worker=go),
        "sqli-blind": lambda s, u, go: A.test_sqli_blind(
            s, [u], 5, verbose=False, deep=False, go_worker=go),
        "ssrf-surface": lambda s, u, go: A.test_ssrf(
            s, [u], 5, verbose=True, go_worker=go),
        "idor-path": lambda s, u, go: A.test_idor(
            s, u, base, 5, go_worker=go) if isinstance(u, dict)
        else [],
        "login-enum": lambda s, u, go: A.test_login_enum(
            s, u, base, 5, go_worker=go) if isinstance(u, dict)
        else [],
        "upload-form": lambda s, u, go: SC.check_upload(
            s, u, 5, False, go_worker=go),
        "proto-surface": lambda s, u, go: A.test_proto_pollution(
            s, [u], 5, go_worker=go),
    }
    fn = calls[name]
    t0 = time.time()
    py_vuln = fn(_sess(), vuln, False)
    py_fixed = fn(_sess(), fixed, False) if fixed is not None else []
    py_dt = time.time() - t0
    t0 = time.time()
    go_vuln = fn(_sess(), vuln, True)
    go_fixed = fn(_sess(), fixed, True) if fixed is not None else []
    go_dt = time.time() - t0
    rec = {
        "name": name,
        "expect": expect,
        "tp_py": any(expect in t for t in _titles(py_vuln)),
        "tp_go": any(expect in t for t in _titles(go_vuln)),
        "fp_py": len(_severe(py_fixed)),
        "fp_go": len(_severe(go_fixed)),
        "parity_vuln": sorted((f.title, f.url) for f in py_vuln)
        == sorted((f.title, f.url) for f in go_vuln),
        "parity_fixed": sorted((f.title, f.url) for f in py_fixed)
        == sorted((f.title, f.url) for f in go_fixed),
        "py_s": round(py_dt, 2),
        "go_s": round(go_dt, 2),
    }
    return rec


def _matrix(lab):
    import requests
    login_html = requests.get(lab + "/login", timeout=5).text
    login_fixed = requests.get(lab + "/login_fixed", timeout=5).text
    stored = {lab + "/xss_stored":
              "<form method='post' action='/xss_stored'>"
              "<input name='comment'></form>"}
    stored_fixed = {lab + "/xss_stored_fixed":
                    "<form method='post' action='/xss_stored_fixed'>"
                    "<input name='comment'></form>"}
    idor = {lab + "/": f"<a href='{lab}/api/users/5'>u</a>"}
    idor_fixed = {lab + "/": f"<a href='{lab}/api/users_fixed/5'>u</a>"}
    return [
        ("xss-reflected", lab + "/xss_reflected?name=gash",
         lab + "/xss_reflected_fixed?name=gash", "Possible Reflected XSS"),
        ("xss-stored", stored, stored_fixed, "Possible Stored XSS"),
        ("sqli-error", lab + "/sqli_error?id=1",
         lab + "/sqli_error_fixed?id=1", "Possible SQL Injection"),
        ("sqli-blind", lab + "/sqli_blind?id=1",
         lab + "/sqli_blind_fixed?id=1", "Blind SQL Injection"),
        ("ssrf-surface", lab + "/ssrf_echo?url=x", None, "SSRF surface"),
        ("idor-path", idor, idor_fixed, "IDOR"),
        ("login-enum", {lab + "/login": login_html},
         {lab + "/login_fixed": login_fixed}, "Login username enumeration"),
        ("upload-form", lab, None, "Upload form detected"),
        ("proto-surface", lab + "/xss_reflected?name=gash", None,
         "Prototype Pollution"),
    ]


def _render(rows):
    tp = sum(1 for r in rows if r["tp_py"] and r["tp_go"])
    fp = sum(r["fp_py"] + r["fp_go"] for r in rows)
    par = sum(1 for r in rows if r["parity_vuln"] and r["parity_fixed"])
    lines = ["# Hybrid scoreboard (stdlib lab)",
             "",
             "Python engine vs Go worker (`--go-worker`): same verdicts, "
             "faster fetching. One row per check: vulnerable endpoint must "
             "fire (TP), fixed twin must stay below MEDIUM (FP).",
             "",
             "| check | TP py/go | FP py/go | parity |",
             "|---|---|---|---|"]
    for r in rows:
        lines.append(
            f"| {r['name']} | "
            f"{'✅' if r['tp_py'] else '❌'}/{'✅' if r['tp_go'] else '❌'} | "
            f"{r['fp_py']}/{r['fp_go']} | "
            f"{'✅' if r['parity_vuln'] and r['parity_fixed'] else '❌'} |")
    lines += ["",
              f"recall: {tp}/{len(rows)}, "
              f"false positives: {fp}, parity: {par}/{len(rows)}",
              "",
              "speed, corrected: earlier 0.55s -> 0.05s claims came from an",
              "in-process lab server sharing the GIL with the measured",
              "client (punished Python threads only). Against an isolated",
              "server both engines tie on localhost; `py",
              "bench/latency_curve.py` (separate-process lab, parity `same`",
              "in every cell):",
              "",
              "| injected RTT | python | go-worker |",
              "|---|---|---|",
              "| 0ms | ~0.05s | ~0.12s |",
              "| 25ms | ~0.18s | ~0.18s |",
              "| 100ms | ~0.54s | ~0.64s |",
              "",
              "reading: no repeatable large speedup on equal footing — both",
              "engines are latency-bound and the gap is process/pipe",
              "overhead either way. The hybrid's durable value is parity +",
              "offloaded fan-out (one spawn per scan via --stream) + a",
              "single-binary fetch path, not a multiplier. The persistent",
              "worker stays: it removes per-batch spawn cost regardless."]
    return "\n".join(lines) + "\n"


def test_hybrid_board():
    srv, lab = _lab()
    try:
        rows = []
        timings = []
        for name, vuln, fixed, expect in _matrix(lab):
            rec = _row(name, lab, vuln, fixed, expect)
            rows.append(rec)
            timings.append(
                f"{rec['name']:14s} py={rec['py_s']:5.2f}s go={rec['go_s']:5.2f}s")
        print("\n" + "\n".join(timings))
        BOARD_PATH.write_text(_render(rows), encoding="utf-8")
        for r in rows:
            assert r["tp_py"] and r["tp_go"], f"missed: {r['name']}"
            assert r["fp_py"] == 0 and r["fp_go"] == 0, \
                f"false positive: {r['name']}"
            assert r["parity_vuln"] and r["parity_fixed"], \
                f"engine divergence: {r['name']}"
    finally:
        srv.shutdown()
        srv.server_close()

"""Latency curve: where does the hybrid actually win? (manual bench, not CI).

Spins the stdlib lab with injected per-request latency and times dir_brute
(40 probes, threads=10) in both engines. Localhost has ~0 RTT, which hides
fan-out wins; real targets don't.

The server runs in a separate PROCESS: an in-thread server shares the GIL
with the measured client and punishes Python threads specifically (measured
artifact — same-process numbers flattered Go ~10x). Run:
py bench/latency_curve.py
"""
from __future__ import annotations

import multiprocessing
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from bench.lab import Lab  # noqa: E402
from core.net import configure_net  # noqa: E402
from core.scanner import _session, dir_brute  # noqa: E402

LAT_MS = multiprocessing.Value("i", 0)


class SlowLab(Lab):
    def do_GET(self):
        if LAT_MS.value:
            time.sleep(LAT_MS.value / 1000.0)
        super().do_GET()

    def do_POST(self):
        if LAT_MS.value:
            time.sleep(LAT_MS.value / 1000.0)
        super().do_POST()


def _serve_forever(port, ready, lat):
    # The Value handle is inherited (same shared memory); the module-level
    # LAT_MS in the child would be a fresh zero without this.
    global LAT_MS
    LAT_MS = lat
    from http.server import ThreadingHTTPServer
    srv = ThreadingHTTPServer(("127.0.0.1", port), SlowLab)
    ready.put(srv.server_address[1])
    srv.serve_forever()


def main() -> None:
    configure_net()
    ready = multiprocessing.Queue()
    proc = multiprocessing.Process(target=_serve_forever,
                                   args=(0, ready, LAT_MS),
                                   daemon=True)
    proc.start()
    try:
        port = ready.get(timeout=15)
        base = f"http://127.0.0.1:{port}"
        time.sleep(0.5)
        wl = (["xss_reflected", "login", "graphql", "upload", "nopezzz"]
              + [f"q{i:02d}zzzz" for i in range(35)])
        # Warmup: imports, session pools and server threads settle, so the
        # measured cells compare engines, not cold starts.
        LAT_MS.value = 0
        _warm = dict(threads=10, verbose=False, wordlist=wl[:5])
        dir_brute(_session(10), base, 10, ctx={}, **_warm)
        dir_brute(_session(10), base, 10, ctx={"go_worker": True}, **_warm)
        print("| injected RTT | python | go-worker | parity |")
        print("|---|---|---|---|")
        for lat in (0, 25, 100):
            LAT_MS.value = lat
            kw = dict(threads=10, verbose=False, wordlist=wl)
            t0 = time.time()
            py_out = dir_brute(_session(10), base, 10, ctx={}, **kw)
            py_dt = time.time() - t0
            t0 = time.time()
            go_out = dir_brute(_session(10), base, 10, ctx={"go_worker": True},
                               **kw)
            go_dt = time.time() - t0
            par = sorted((f.title, f.url) for f in py_out) == \
                sorted((f.title, f.url) for f in go_out)
            print(f"| {lat}ms | {py_dt:.2f}s | {go_dt:.2f}s | "
                  f"{'same' if par else 'DIFF'} |")
    finally:
        proc.terminate()
        proc.join(timeout=5)


if __name__ == "__main__":
    main()

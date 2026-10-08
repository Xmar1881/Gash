"""Terminal animation for long silent phases (port scan, crawl, 429 waits).

Rules, so CI logs never get garbage:
  - completely OFF when stdout is not a tty (piped/CI) or NO_COLOR is set
  - one global lock: spinner thread and countdown never scribble over
    each other; normal prints always win (they pause the spinner line)
  - background thread is daemon + joined on stop, tests stay fast

Usage:
    with spin("  [*] Crawling..."):
        ...slow work...
        spin_update("  [*] Crawling (3/8)...")  # optional

    countdown("  [!] 429: waiting", 10)  # in-place 10..1, then newline
"""

from __future__ import annotations

import os
import sys
import threading
import time

UTF_FRAMES = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"
ASCII_FRAMES = "|/-\\"

DISABLED = False
_LOCK = threading.Lock()
_ACTIVE = [0]  # >0 while a spinner owns the line


def _tty() -> bool:
    if DISABLED or os.environ.get("NO_COLOR"):
        return False
    try:
        return sys.stdout.isatty()
    except Exception:
        return False


def _frames() -> str:
    try:
        UTF_FRAMES.encode(sys.stdout.encoding or "ascii")
        return UTF_FRAMES
    except Exception:
        return ASCII_FRAMES


def _write(text: str) -> None:
    try:
        sys.stdout.write(text)
        sys.stdout.flush()
    except Exception:
        pass


class Spinner:
    """Same-line spinner with elapsed timer. No-op off-tty or disabled."""

    def __init__(self, message: str = "Working...", enabled: bool = True):
        self.message = message
        self.enabled = enabled
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._t0 = 0.0

    def start(self) -> "Spinner":
        if not self.enabled or not _tty():
            return self
        self._t0 = time.time()
        self._stop.clear()
        with _LOCK:
            _ACTIVE[0] += 1
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()
        return self

    def _run(self) -> None:
        frames = _frames()
        i = 0
        while not self._stop.wait(0.12):
            with _LOCK:
                _write(f"\r{self.message} {frames[i % len(frames)]} "
                       f"{time.time() - self._t0:.0f}s")
            i += 1

    def update(self, message: str) -> None:
        self.message = message

    def stop(self) -> None:
        if self._thread is None:
            return
        self._stop.set()
        self._thread.join(timeout=2.0)
        self._thread = None
        with _LOCK:
            _ACTIVE[0] = max(0, _ACTIVE[0] - 1)
            _write("\r" + " " * 70 + "\r")

    def __enter__(self) -> "Spinner":
        return self.start()

    def __exit__(self, *exc) -> None:
        self.stop()


def spin(message: str = "Working...", enabled: bool = True) -> Spinner:
    """One-liner: with spin("..."): ..."""
    return Spinner(message, enabled)


def countdown(message: str, seconds: float) -> None:
    """Sleep `seconds`, showing an in-place countdown on ttys.

    Falls back to a single line + one sleep when piped, or when a
    spinner owns the line (no scribble fights).
    """
    total = max(0, int(round(seconds)))
    if not _tty() or _ACTIVE[0]:
        with _LOCK:
            _write(f"{message} {total}s\n")
        time.sleep(seconds)
        return
    end = time.time() + seconds
    while True:
        left = int(round(end - time.time()))
        if left <= 0:
            break
        with _LOCK:
            _write(f"\r{message} {left}s ")
        time.sleep(1)
    with _LOCK:
        _write("\r" + " " * 70 + "\r")

"""Shared bits for the checks package (no checks registered here)."""
from __future__ import annotations

from urllib.parse import urlparse

EVIL_ORIGIN = "https://evil-gash.test"
EVIL_HOST = "evil-gash.test"


def _same_host(url: str, base: str) -> bool:
    try:
        return urlparse(url).hostname == urlparse(base).hostname
    except Exception:
        return False


def _mask(secret: str) -> str:
    """Never put a full secret in a report: AKIA...12 style."""
    s = secret.strip()
    if len(s) <= 8:
        return s[:2] + "..."
    return s[:4] + "..." + s[-2:]


__all__ = ["EVIL_ORIGIN", "EVIL_HOST", "_same_host", "_mask"]

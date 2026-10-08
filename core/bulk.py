"""Bulk scan helpers: target file, report paths, resume.

No network here, pure functions (easy to test).
"""

from __future__ import annotations

import os
import re

KNOWN_EXTS = (".json", ".html", ".htm", ".txt", ".sarif", ".xml")


def load_targets_file(path: str) -> list[str]:
    """Read a target file: one target per line, # comments and blanks skipped."""
    out: list[str] = []
    with open(path, encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            # inline comment: "https://x.com # prod" -> "https://x.com"
            if " #" in line:
                line = line.split(" #", 1)[0].strip()
            if line:
                out.append(line)
    # dedupe, keep order
    return list(dict.fromkeys(out))


def collect_targets(single: str | None,
                    file_targets: list[str] | None = None) -> list[str]:
    """Merge one target plus a file list, deduplicated."""
    out: list[str] = []
    if single:
        single = single.strip()
        if single:
            out.append(single)
    for t in file_targets or []:
        t = (t or "").strip()
        if t and t not in out:
            out.append(t)
    return out


def safe_name(target: str) -> str:
    """Turn a target into a filename-safe name (host + port + path)."""
    try:
        from core.recon import normalize_target
        host, base = normalize_target(target)
        name = base.replace("https://", "").replace("http://", "")
    except Exception:
        name = target.replace("https://", "").replace("http://", "")
    name = name.strip().strip("/")
    return re.sub(r"[^a-zA-Z0-9.-]", "_", name) or "target"


def resolve_bulk_ext(output: str | None) -> str:
    """Bulk report extension: from -o when given, else .json."""
    if output:
        low = output.lower()
        for ext in KNOWN_EXTS:
            if low.endswith(ext):
                return ext
    return ".json"


def report_path_for(output_dir: str, target: str, ext: str = ".json") -> str:
    """Build output_dir/<safe_host><ext>."""
    if ext == ".htm":
        ext = ".html"
    if not ext.startswith("."):
        ext = "." + ext
    return os.path.join(output_dir, safe_name(target) + ext)


def looks_like_dir(path: str) -> bool:
    """Was -o given a directory? (trailing slash, no ext, or a real dir)."""
    if not path:
        return False
    if path.endswith(("/", "\\")):
        return True
    try:
        if os.path.isdir(path):
            return True
    except Exception:
        pass
    _, ext = os.path.splitext(path)
    return ext.lower() not in KNOWN_EXTS

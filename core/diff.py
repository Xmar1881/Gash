"""Baseline / differential engine — one comparator for all checks.

Every differential check (IDOR, blind-SQLi corroboration, auth bypass,
soft-404, traversal) used to hand-roll length + difflib thresholds.
This module centralizes the signals so thresholds and normalization
live in one tested place:

- status / redirect (final vs requested URL)
- content length (+ tolerant delta)
- normalized HTML similarity (whitespace collapsed, digits maskable,
  caller-supplied rotating tokens scrubbed)
- canonical JSON equality (key order / spacing independent)
- <title> sameness
- visible-text sameness (scripts/styles stripped)
- DOM structure sameness (tag-name sequence)
- timing helpers (baseline mean/stdev, regression verdict)

Pure functions, no network. Checks build ResponseSnap pairs (by hand
or via snap_response) and read a single verdict instead of re-deriving
it per check.
"""

from __future__ import annotations

import difflib
import html as _html
import json as _json
import re
import statistics
from dataclasses import dataclass, field

TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.I | re.S)
TAG_RE = re.compile(r"</?([a-zA-Z][a-zA-Z0-9-]*)")
SCRIPT_STYLE_RE = re.compile(
    r"<(script|style)[^>]*>.*?</\1\s*>", re.I | re.S)
WS_RE = re.compile(r"\s+")


@dataclass
class ResponseSnap:
    """One response, normalized on demand. text/headers tolerant."""
    status: int = 0
    url: str = ""          # final URL (after redirects)
    requested: str = ""    # URL we asked for
    body: str = ""
    headers: dict = field(default_factory=dict)
    elapsed: float = 0.0


@dataclass
class Comparison:
    verdict: str = "same"  # same | different
    reasons: list[str] = field(default_factory=list)
    same_status: bool = True
    len_a: int = 0
    len_b: int = 0
    html_ratio: float = 1.0
    json_same: bool | None = None
    title_same: bool = True
    text_same: bool = True
    dom_same: bool = True
    redirect_changed: bool = False


def snap_response(resp, requested: str = "",
                  elapsed: float = 0.0) -> ResponseSnap:
    """Wrap requests-like (or fake) responses defensively. Never raises."""
    try:
        status = int(getattr(resp, "status_code", 0) or 0)
    except Exception:
        status = 0
    try:
        body = getattr(resp, "text", "") or ""
    except Exception:
        body = ""
    try:
        url = getattr(resp, "url", "") or requested
    except Exception:
        url = requested
    try:
        headers = dict(getattr(resp, "headers", {}) or {})
    except Exception:
        headers = {}
    return ResponseSnap(status=status, url=url, requested=requested,
                        body=body, headers=headers, elapsed=elapsed)


def scrub_tokens(body: str, tokens) -> str:
    """Blank rotating values (CSRF tokens, nonces) before comparing."""
    out = body or ""
    for t in tokens or []:
        if t and len(str(t)) >= 8:
            out = out.replace(str(t), "")
    return out


def normalize_html(body: str, mask_digits: bool = False,
                   tokens=None) -> str:
    """Collapse whitespace/entities; optionally mask digit runs (IDs)."""
    text = scrub_tokens(body or "", tokens)
    text = WS_RE.sub(" ", text).strip()[:4000]
    if mask_digits:
        text = re.sub(r"\d+", "#", text)
    return text


def canonical_json(body: str) -> str | None:
    """Canonical JSON (sorted keys, compact) or None when not JSON."""
    try:
        return _json.dumps(_json.loads(body or ""),
                           sort_keys=True, separators=(",", ":"))
    except Exception:
        return None


def title_of(body: str) -> str:
    m = TITLE_RE.search(body or "")
    return WS_RE.sub(" ", (m.group(1) if m else "")).strip()[:200]


def visible_text(body: str) -> str:
    """Scripts/styles/tags stripped, entities unescaped, collapsed."""
    text = SCRIPT_STYLE_RE.sub(" ", body or "")
    text = re.sub(r"<[^>]{0,500}>", " ", text)
    text = _html.unescape(text)
    return WS_RE.sub(" ", text).strip()[:4000]


def dom_structure(body: str) -> tuple:
    """Tag-name open/close sequence (first 300 tags) — layout fingerprint."""
    return tuple(t.lower() for t in TAG_RE.findall(body or "")[:300])


def _ratio(a: str, b: str) -> float:
    if a == b:
        return 1.0
    if not a.strip() or not b.strip():
        return 0.0
    return difflib.SequenceMatcher(None, a, b).ratio()


def compare(a: ResponseSnap, b: ResponseSnap, *,
            mask_digits: bool = False, tokens=None,
            len_tol: int = 5, len_frac: float = 0.02,
            ratio_thresh: float = 0.98) -> Comparison:
    """Content verdict for a response pair. Status never decides alone."""
    la, lb = len(a.body or ""), len(b.body or "")
    tol = max(len_tol, int(max(la, lb) * len_frac))
    na = normalize_html(a.body, mask_digits, tokens)
    nb = normalize_html(b.body, mask_digits, tokens)
    ratio = _ratio(na, nb)
    ja, jb = canonical_json(a.body or ""), canonical_json(b.body or "")
    json_same = (ja == jb) if ja is not None and jb is not None else None
    ta, tb = title_of(a.body or ""), title_of(b.body or "")
    xa, xb = visible_text(a.body or ""), visible_text(b.body or "")
    da, db = dom_structure(a.body or ""), dom_structure(b.body or "")
    res = Comparison(
        same_status=(a.status == b.status),
        len_a=la, len_b=lb, html_ratio=round(ratio, 4),
        json_same=json_same,
        title_same=(ta == tb),
        text_same=(_ratio(xa, xb) >= ratio_thresh),
        dom_same=(da == db),
        redirect_changed=bool(a.requested and b.requested
                              and a.requested != b.requested
                              and (a.url != b.url)),
    )
    if json_same is False:
        res.reasons.append("json-differs")
    elif json_same is None:
        if ratio < ratio_thresh and abs(la - lb) > tol:
            res.reasons.append(f"html-ratio={ratio:.2f}")
        if ta != tb and (ta or tb):
            res.reasons.append("title-differs")
        if da != db and abs(la - lb) > tol:
            res.reasons.append("dom-differs")
    res.verdict = "different" if res.reasons else "same"
    return res


def bodies_differ(b1: str | None, b2: str | None) -> bool:
    """IDOR-grade content difference (digit-masked, length-gated).

    Length alone is weak evidence (two public pages always differ):
    the digit-normalized similarity must also drop, otherwise the only
    difference is an echoed id, which proves nothing. Thresholds are
    the legacy IDOR ones, kept byte-identical so adoption is drift-free.
    """
    l1, l2 = len(b1 or ""), len(b2 or "")
    if abs(l1 - l2) <= max(5, l1 // 50):
        return False
    n1 = re.sub(r"\d+", "#", (b1 or "")[:2000])
    n2 = re.sub(r"\d+", "#", (b2 or "")[:2000])
    if not n1.strip() or not n2.strip():
        return False
    return _ratio(n1, n2) < 0.98


def looks_like_baseline(status: int, body: str, base_status: int,
                        base_len: int, base_text: str = "") -> bool:
    """Soft-404 filter: status + size + content similarity combined."""
    if status != base_status or not base_text:
        return False
    blen = len(body or "")
    if abs(blen - base_len) > max(80, base_len // 10):
        return False
    return _ratio(base_text, (body or "")[:4000]) > 0.9


def timing_stats(samples: list[float]) -> tuple[float, float]:
    """(mean, stdev) of baseline measurements. Never raises."""
    xs = [float(s) for s in (samples or []) if s is not None]
    if not xs:
        return 0.0, 0.0
    if len(xs) == 1:
        return xs[0], 0.0
    try:
        return statistics.fmean(xs), statistics.pstdev(xs)
    except Exception:
        return xs[0], 0.0


def is_regressed(baseline: list[float], probe: float,
                 expected_sleep: float, jitter: float = 0.5,
                 margin: float = 2.0) -> bool:
    """Timing verdict: probe slept the payload AND cleared baseline+margin.

    Slow baselines (>expected_sleep) make timing unreliable -> False.
    """
    try:
        mean, _sd = timing_stats(baseline)
        probe = float(probe)
    except Exception:
        return False
    if not baseline or mean > expected_sleep:
        return False
    return probe >= expected_sleep - jitter and probe > mean + margin

"""Precision/recall scoring for the XSS bench — pure, no network.

Ground truth lives in bench/cases_*.json. A finding matches a case when
the case path appears in the finding URL and the case param shows up in
the URL, detail or evidence. Title families:

- DETECTED: any XSS signal (incl. unconfirmed/suspected/encoded notes).
- CONFIRMED: proven titles only (breaker/raw-executable or OOB proof).
"""

from __future__ import annotations

import json
from pathlib import Path

HERE = Path(__file__).resolve().parent

DETECTED_PREFIXES = (
    "Possible Reflected XSS",
    "Reflected input",
    "Possible Stored XSS",
    "Stored reflection",
    "DOM XSS (confirmed",
    "DOM XSS (suspected",
    "JS DOM write",
    "Blind XSS",
    "Partially encoded reflection",
    "Possible Stored XSS (SVG upload)",
)

CONFIRMED_PREFIXES = (
    "Possible Reflected XSS",
    "Possible Stored XSS",
    "DOM XSS (confirmed",
    "Blind XSS (confirmed via OOB)",
)


def is_xss_title(title: str) -> bool:
    return (title or "").startswith(DETECTED_PREFIXES)


def is_confirmed_title(title: str) -> bool:
    return (title or "").startswith(CONFIRMED_PREFIXES)


def load_cases(target: str) -> dict:
    """Load bench/cases_<target>.json. Raises FileNotFoundError/ValueError."""
    path = HERE / f"cases_{target}.json"
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data.get("cases"), list):
        raise ValueError(f"{path.name}: 'cases' must be a list")
    return data


def finding_text(f) -> str:
    """Matchable blob: url + detail + evidence (dicts or Findings)."""
    if isinstance(f, dict):
        url = f.get("url", "")
        detail = f.get("detail", "")
        ev = f.get("evidence", "")
        title = f.get("title", "")
    else:
        url = getattr(f, "url", "")
        detail = getattr(f, "detail", "")
        ev = getattr(f, "evidence", "")
        title = getattr(f, "title", "")
    return title, f"{url}\n{detail}\n{ev}"


def match_case(case: dict, findings: list) -> list:
    """XSS-family findings belonging to this case (path + param)."""
    path = (case.get("path") or "").rstrip("/") or "/"
    param = (case.get("param") or "").lower()
    hits = []
    for f in findings:
        title, blob = finding_text(f)
        if not is_xss_title(title):
            continue
        low = blob.lower()
        url = (f.get("url", "") if isinstance(f, dict)
               else getattr(f, "url", "")) or ""
        if path != "/" and path.lower() not in url.lower():
            continue
        if param and param not in low:
            continue
        hits.append(f)
    return hits


def score(cases: list[dict], findings: list) -> dict:
    """Precision/recall over cases + honesty stats. Zero-division safe."""
    per_case = []
    tp_det = tp_conf = 0
    fn_det = fn_conf = 0
    matched_idx: set[int] = set()
    for case in cases:
        hits = match_case(case, findings)
        for h in hits:
            try:
                matched_idx.add(findings.index(h))
            except ValueError:
                pass
        det = any(is_xss_title(t) for t, _ in (finding_text(h) for h in hits))
        conf = any(is_confirmed_title(t) for t, _ in (finding_text(h) for h in hits))
        vuln = bool(case.get("vulnerable"))
        if vuln:
            tp_det += bool(det)
            fn_det += not det
            tp_conf += bool(conf)
            fn_conf += not conf
            verdict = ("TP" if conf else ("detected-unproven" if det else "FN"))
        else:
            verdict = ("FP" if conf else ("FP-signal" if det else "TN"))
        titles = sorted({(finding_text(h)[0]) for h in hits})
        per_case.append({"id": case.get("id"), "kind": case.get("kind"),
                         "vulnerable": vuln, "verdict": verdict,
                         "titles": titles})
    fp_conf = sum(1 for c in per_case if c["verdict"] == "FP")
    fp_sig = sum(1 for c in per_case if c["verdict"] == "FP-signal")
    fp_unmatched = sum(
        1 for i, f in enumerate(findings)
        if i not in matched_idx and is_confirmed_title(finding_text(f)[0]))
    fp_all = fp_conf + fp_unmatched

    def _div(a: int, b: int) -> float | None:
        return round(a / b, 3) if b else None

    n_vuln = sum(1 for c in cases if c.get("vulnerable"))
    det_titles = [finding_text(f)[0] for f in findings]
    honesty = {
        "unconfirmed": sum(1 for t in det_titles
                           if t.startswith(("Reflected input",
                                             "Stored reflection"))),
        "suspected": sum(1 for t in det_titles
                         if t.startswith("DOM XSS (suspected")),
        "confirmed": sum(1 for t in det_titles if is_confirmed_title(t)),
        "fp_signals_on_negatives": fp_sig,
    }
    return {
        "cases": len(cases),
        "vulnerable": n_vuln,
        "per_case": per_case,
        "recall_detected": _div(tp_det, tp_det + fn_det),
        "recall_confirmed": _div(tp_conf, tp_conf + fn_conf),
        "precision_confirmed": _div(tp_conf, tp_conf + fp_all),
        "fp_confirmed": fp_all,
        "honesty": honesty,
    }

#!/usr/bin/env python3
"""XSS precision/recall bench — live targets, opt-in (never in CI).

Usage:
    py bench/run_bench.py --target dvwa [--base-url http://127.0.0.1:4280] [--deep] [--dom]
    py bench/run_bench.py --target juice [--base-url http://127.0.0.1:3000] [--dom]
    py bench/run_bench.py --target all --json-out bench/results.json

Targets via bench/docker-compose.yml (needs Docker on fertility machines).
Exit code is always 0: this measures, it does not gate.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from bench.score import load_cases, score  # noqa: E402


def _session(timeout: int):
    from core.scanner import _session as _mk
    return _mk(timeout)


def dvwa_login(session, base: str, timeout: int, auth: dict) -> bool:
    try:
        r = session.post(base + auth.get("login_path", "/login.php"),
                         timeout=timeout, allow_redirects=True,
                         data={"username": auth.get("username", "admin"),
                               "password": auth.get("password", "password"),
                               "Login": "Login"})
        return "logout" in (r.text or "").lower() or "dashboard" in (r.text or "").lower()
    except Exception as e:
        print(f"  [!] DVWA login failed: {str(e)[:100]}")
        return False


def dvwa_set_level(session, base: str, timeout: int, level: str) -> None:
    try:
        g = session.get(base + "/security.php", timeout=timeout)
        token = ""
        m = re.search(r"name=['\"]user_token['\"]\s+value=['\"]([^'\"]+)", g.text or "")
        if m:
            token = m.group(1)
        session.post(base + "/security.php", timeout=timeout,
                     data={"security": level, "seclev_submit": "Submit",
                           "user_token": token})
    except Exception as e:
        print(f"  [!] security level set failed ({level}): {str(e)[:80]}")
    try:
        session.cookies.set("security", level)
    except Exception:
        pass


def probe_case(session, case: dict, base: str, timeout: int,
               verbose: bool, deep: bool, dom: bool,
               threads: int) -> tuple[list, str]:
    """Run the matching GASH check for one case -> (findings, note)."""
    kind = case.get("kind")
    path = case.get("path", "/")
    param = case.get("param", "q")
    page_url = base.rstrip("/") + path
    if kind == "reflected":
        from core.scanner import test_xss
        url = page_url + ("&" if "?" in page_url else "?") + f"{param}=gash"
        out = test_xss(session, [url], timeout, verbose, threads=threads,
                       deep=deep)
        return out, ""
    if kind == "stored":
        from core.advanced import test_stored_xss
        try:
            g = session.get(page_url, timeout=timeout)
            html = g.text if g else ""
        except Exception:
            html = ""
        out = test_stored_xss(session, {page_url: html}, base, timeout,
                              verbose=verbose, deep=deep)
        return out, ""
    if kind == "dom":
        if not dom:
            return [], "skipped (needs --dom + Playwright)"
        from core.domxss import test_dom_xss
        url = page_url + ("&" if "?" in page_url else "?") + f"{param}=gash"
        out = test_dom_xss([url], base, timeout, verbose=verbose,
                           pages={}, dom=True)
        return out, ""
    return [], f"unknown kind {kind!r}"


def run_target(target: str, base_url: str, timeout: int, verbose: bool,
               deep: bool, dom: bool, threads: int) -> dict:
    data = load_cases(target)
    base = (base_url or data.get("default_base_url", "")).rstrip("/")
    cases = data.get("cases", [])
    session = _session(timeout)
    if data.get("auth"):
        ok = dvwa_login(session, base, timeout, data["auth"])
        print(f"  [{'OK' if ok else '??'}] DVWA login as "
              f"{data['auth'].get('username')}")
    all_findings: list = []
    rows = []
    for case in cases:
        if data.get("auth") and case.get("security"):
            dvwa_set_level(session, base, timeout, case["security"])
        try:
            out, note = probe_case(session, case, base, timeout, verbose,
                                   deep, dom, threads)
        except Exception as e:
            out, note = [], f"error: {str(e)[:100]}"
        all_findings += out
        rows.append({"case": case, "titles": sorted({f.title for f in out}),
                     "note": note, "n": len(out)})
        flag = "?" if note else (str(len(out)))
        print(f"  [{flag:>7}] {case.get('id')} ({case.get('kind')}): "
              f"{', '.join(sorted({f.title for f in out})) or 'no findings'}"
              f"{' — ' + note if note else ''}")
    result = score(cases, all_findings)
    result["target"] = target
    result["base_url"] = base
    result["rows"] = [{"id": r["case"].get("id"),
                       "verdict": v["verdict"], "titles": r["titles"],
                       "note": r["note"]}
                      for r, v in zip(rows, result["per_case"])]
    del result["per_case"]
    return result


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="GASH XSS bench (live targets)")
    p.add_argument("--target", default="all",
                   help="dvwa | juice | all (default: all)")
    p.add_argument("--base-url", default=None,
                   help="Override base URL (single-target runs)")
    p.add_argument("--dvwa-url", default=None)
    p.add_argument("--juice-url", default=None)
    p.add_argument("--deep", action="store_true",
                   help="Include active POST probes (stored)")
    p.add_argument("--dom", action="store_true",
                   help="Headless DOM verification (needs Playwright)")
    p.add_argument("--threads", type=int, default=10)
    p.add_argument("--timeout", type=int, default=8)
    p.add_argument("--json-out", default=None)
    p.add_argument("-v", "--verbose", action="store_true")
    a = p.parse_args(argv)
    targets = ["dvwa", "juice"] if a.target == "all" else [a.target]
    override = {"dvwa": a.dvwa_url or a.base_url,
                "juice": a.juice_url or a.base_url}
    results = []
    for t in targets:
        print(f"[+] bench: {t}")
        try:
            data = load_cases(t)
        except (FileNotFoundError, ValueError) as e:
            print(f"  [!] {e}")
            continue
        base = override.get(t) or data.get("default_base_url")
        results.append(run_target(t, base, a.timeout, a.verbose,
                                  a.deep, a.dom, a.threads))
    for r in results:
        print(f"\n== {r['target']} ({r['base_url']}) ==")
        print(f"   recall_detected  : {r['recall_detected']}")
        print(f"   recall_confirmed : {r['recall_confirmed']}")
        print(f"   precision_conf. : {r['precision_confirmed']}"
              f"  (FP: {r['fp_confirmed']})")
        print(f"   honesty          : {r['honesty']}")
        for row in r["rows"]:
            print(f"   - {row['id']}: {row['verdict']}"
                  f" [{', '.join(row['titles']) or '-'}]"
                  f"{' (' + row['note'] + ')' if row['note'] else ''}")
    if a.json_out:
        out = Path(a.json_out)
        out.write_text(json.dumps({"results": results}, ensure_ascii=False,
                                  indent=2), encoding="utf-8")
        print(f"\n[+] bench results: {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

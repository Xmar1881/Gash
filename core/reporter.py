"""Finding analysis and reporting.

Terminal: color-coded list grouped by severity plus a small summary table.
Files: -o report.json / report.html / report.txt (picked by extension).

Every finding carries a confidence rating (High/Medium/Low) set by the
check that produced it — single-session heuristics stay honest.
"""

from __future__ import annotations

import html as _html
import json
import re
from collections import Counter
from datetime import datetime

from core.colors import critical, success, info, warn, DIM, RESET, BRIGHT, RED, GREEN

SEVERITY_ORDER = {"CRITICAL": 0, "MEDIUM": 1, "LOW": 2, "INFO": 3}

INFO = "INFO"


def is_finding(f) -> bool:
    """Observations (INFO) are discovery notes, not vulnerabilities."""
    return getattr(f, "severity", "") != INFO


# ---------- terminal ----------

def _check_errors(check_status) -> list:
    """Checks that errored or aborted mid-scan (never silent)."""
    return [c for c in (check_status or [])
            if c.get("status") in ("error", "aborted")]


def print_findings(findings, verbose: bool = False,
                   incomplete: bool = False,
                   check_status=None) -> None:
    errors = _check_errors(check_status)
    degraded = bool(errors)
    print(info("\n[+] SCAN Results"))
    if not findings and not incomplete and not degraded:
        print(success("[+] Clean: no findings."))
        return
    if incomplete:
        print(warn("  [!] INCOMPLETE scan — coverage stopped early, "
                   "absence of findings means nothing."))
    if degraded:
        print(warn(f"  [!] SCAN DEGRADED — {len(errors)} check(s) failed, "
                   "results are partial:"))
        for e in errors[:5]:
            what = e.get("error_type", "") + " " + e.get(
                "error", e.get("reason", ""))
            print(warn(f"      x {e.get('check')}: {what.strip()}"[:160]))
    if not findings and degraded:
        print(warn("  [!] No findings, but failing checks mean this is "
                   "NOT a clean bill."))
        return
    findings = sorted(findings, key=lambda f: SEVERITY_ORDER.get(f.severity, 9))
    for f in findings:
        conf = f" [conf:{f.confidence}]" if verbose and f.confidence else ""
        line = f"[{f.severity}] {f.title}{conf} -> {f.url or f.detail}"
        if f.severity == "CRITICAL":
            print(critical(line))
        elif f.severity == "MEDIUM":
            print(warn(line))
        elif f.severity == INFO:
            print(f"{DIM}{line}{RESET}")
        else:
            print(info(line))
        if verbose and f.detail:
            print(f"         {DIM}{f.detail}{RESET}")
        if verbose and (f.cwe or f.cvss):
            print(f"         {DIM}{f.cwe} | {f.owasp} | {f.cvss}{RESET}")
        if verbose and f.remediation:
            print(f"         {DIM}Fix: {f.remediation[:160]}{RESET}")
    print_summary_table(findings)


def _uni_ok() -> bool:
    """Box-drawing chars break on narrow codepages (e.g. cp1254)."""
    import sys
    try:
        "┌─┴".encode(sys.stdout.encoding or "ascii")
        return True
    except Exception:
        return False


def print_summary_table(findings) -> None:
    """Small summary table. Observations never feed the score."""
    vulns = [f for f in findings if is_finding(f)]
    obs = len(findings) - len(vulns)
    c = Counter(f.severity for f in vulns)
    k, o, d = c.get("CRITICAL", 0), c.get("MEDIUM", 0), c.get("LOW", 0)
    total = len(vulns)
    if _uni_ok():
        tl, tr, bl, br, h, v, tj, lj, rj = "┌", "┐", "└", "┘", "─", "│", "┬", "├", "┤"
        mid = f"  {DIM}{lj}{h*10}{tj}{h*7}{rj}{RESET}"
    else:
        tl, tr, bl, br, h, v, tj, lj, rj = "+", "+", "+", "+", "-", "|", "+", "+", "+"
        mid = f"  {DIM}{lj}{h*10}{tj}{h*7}{rj}{RESET}"
    print()
    print(f"  {DIM}{tl}{h*10}{tj}{h*7}{tr}{RESET}")
    print(f"  {DIM}{v}{RESET} {critical('CRITICAL')} {DIM}{v}{RESET} {k:<5} {DIM}{v}{RESET}")
    print(f"  {DIM}{v}{RESET} {warn('MEDIUM  ')} {DIM}{v}{RESET} {o:<5} {DIM}{v}{RESET}")
    print(f"  {DIM}{v}{RESET} {info('LOW     ')} {DIM}{v}{RESET} {d:<5} {DIM}{v}{RESET}")
    print(mid)
    print(f"  {DIM}{v}{RESET} {BRIGHT}TOTAL    {RESET} {DIM}{v}{RESET} {total:<5} {DIM}{v}{RESET}")
    print(f"  {DIM}{bl}{h*10}{tj}{h*7}{br}{RESET}")
    if obs:
        print(f"  {DIM}observations (not scored): {obs}{RESET}")
    if k:
        print(f"  {critical('!! CRITICAL findings present — fix these first.')}")
    _ = (RED, GREEN)  # palette reference (used by the HTML report)


# ---------- report file ----------

def build_report(target: str, mode: str, version: str,
                 recon=None, findings=None, elapsed: float = 0.0,
                 diff: dict | None = None, incomplete: bool = False,
                 check_status=None) -> dict:
    findings = findings or []
    errors = _check_errors(check_status)
    degraded = bool(errors)
    skipped = [c.get("check") for c in (check_status or [])
               if c.get("status") == "skipped"]
    vulns = [f for f in findings if is_finding(f)]
    obs = [f for f in findings if not is_finding(f)]
    srt = sorted(vulns, key=lambda f: SEVERITY_ORDER.get(f.severity, 9))
    c = Counter(f.severity for f in srt)
    try:
        from core.net import get_context
        req_count = get_context().count
    except Exception:
        req_count = 0
    return {
        "tool": "GASH",
        "version": version,
        "motto": "GASH // Vulnerability & Penetration Engine",
        "target": target,
        "mode": mode,
        "scanned_at": datetime.now().isoformat(timespec="seconds"),
        "elapsed_s": round(elapsed, 2),
        "http_requests": req_count,
        "summary": {"CRITICAL": c.get("CRITICAL", 0), "MEDIUM": c.get("MEDIUM", 0),
                    "LOW": c.get("LOW", 0), "TOTAL": len(srt),
                    "OBSERVATIONS": len(obs)},
        "diff": diff or {},
        "incomplete": bool(incomplete),
        "scan_health": {
            "degraded": degraded,
            "errors": [{"check": e.get("check"),
                        "error": (e.get("error_type", "") + " " +
                                  e.get("error", e.get("reason", ""))).strip()}
                       for e in errors],
            "skipped": skipped,
            "ran": sum(1 for c in (check_status or [])
                       if c.get("status") in ("passed", "findings")),
        },
        "recon": recon.to_dict() if recon else None,
        "findings": [f.to_dict() for f in srt],
        "observations": [f.to_dict() for f in
                         sorted(obs, key=lambda f: f.title)],
    }


# ---------- history / diff ----------

def history_path(hostname: str) -> str:
    import os
    safe = re.sub(r"[^a-zA-Z0-9.-]", "_", hostname or "unknown")
    d = os.path.join(os.getcwd(), ".gash_history")
    os.makedirs(d, exist_ok=True)
    return os.path.join(d, safe + ".json")


def _key(f) -> tuple:
    d = f.to_dict() if hasattr(f, "to_dict") else f
    return (d.get("title"), d.get("url"))


def diff_with_history(hostname: str, findings: list) -> dict:
    """Compare with the previous scan: NEW / FIXED / same. Updates history.

    Observations are excluded: discovery churn (pages come and go) would
    drown the real signal.
    """
    import os
    findings = [f for f in findings if is_finding(f)]
    path = history_path(hostname)
    existed = os.path.exists(path)
    old = []
    try:
        if existed:
            old = json.load(open(path, encoding="utf-8")).get("findings", [])
    except Exception:
        old = []
    old_keys, new_keys = {_key(f) for f in old}, {_key(f) for f in findings}
    new = [f for f in findings if _key(f) not in old_keys]
    fixed = [f for f in old if _key(f) not in new_keys]
    try:
        json.dump({"scanned_at": datetime.now().isoformat(timespec="seconds"),
                   "findings": [f.to_dict() for f in findings]},
                  open(path, "w", encoding="utf-8"), ensure_ascii=False, indent=2)
    except Exception:
        pass
    return {"yeni": [f.to_dict() if hasattr(f, "to_dict") else f for f in new],
            "kapandi": fixed, "ayni": len(new_keys & old_keys),
            "onceki_toplam": len(old), "history": path,
            "ilk_tarama": not existed}


def print_diff(diff: dict) -> None:
    if not diff:
        return
    n, f = len(diff.get("yeni", [])), len(diff.get("kapandi", []))
    if diff.get("ilk_tarama"):
        print(info("  [i] First scan recorded — diff shows up next time."))
        return
    print(info(f"\n[+] Diff vs previous scan: "
               f"{critical(f'{n} NEW') if n else '0 new'} / "
               f"{success(f'{f} FIXED') if f else '0 fixed'} / "
               f"{diff.get('ayni', 0)} ongoing"))
    for x in diff.get("yeni", [])[:5]:
        print(critical(f"    + NEW [{x.get('severity')}] {x.get('title')} -> {x.get('url')}"))
    for x in diff.get("kapandi", [])[:5]:
        print(success(f"    - FIXED [{x.get('severity')}] {x.get('title')} -> {x.get('url')}"))


def save_report(report: dict, path: str) -> str:
    """Write json/html/txt/sarif/xml based on extension. Returns the path."""
    low = path.lower()
    if low.endswith(".json"):
        with open(path, "w", encoding="utf-8") as f:
            json.dump(report, f, ensure_ascii=False, indent=2)
    elif low.endswith((".html", ".htm")):
        with open(path, "w", encoding="utf-8") as f:
            f.write(_render_html(report))
    elif low.endswith(".sarif"):
        with open(path, "w", encoding="utf-8") as f:
            json.dump(_render_sarif(report), f, ensure_ascii=False, indent=2)
    elif low.endswith(".xml"):
        with open(path, "w", encoding="utf-8") as f:
            f.write(_render_junit(report))
    else:  # .txt and the rest -> plain text
        with open(path, "w", encoding="utf-8") as f:
            f.write(_render_txt(report))
    return path


def _render_txt(report: dict) -> str:
    L = [f"GASH Report  v{report['version']}",
         f"Target: {report['target']}  |  Mode: {report['mode']}  |  {report['scanned_at']}",
         f"Summary: {report['summary']['CRITICAL']} critical / "
         f"{report['summary']['MEDIUM']} medium / {report['summary']['LOW']} low "
         f"(total {report['summary']['TOTAL']}, "
         f"{report['summary'].get('OBSERVATIONS', 0)} observations not scored)",
         "-" * 60]
    if report.get("incomplete"):
        L.append("WARNING: INCOMPLETE scan (rate limit / budget) — "
                 "partial results, NOT a clean bill.")
    health = report.get("scan_health") or {}
    if health.get("degraded"):
        names = ", ".join(e.get("check", "?") for e in health.get("errors", [])[:5])
        L.append(f"WARNING: SCAN DEGRADED ({len(health.get('errors', []))} "
                 f"failed checks: {names}) — partial results, NOT a clean bill.")
    df = report.get("diff") or {}
    if df and df.get("onceki_toplam") is not None:
        L.append(f"Diff  : {len(df.get('yeni', []))} new / "
                 f"{len(df.get('kapandi', []))} fixed / {df.get('ayni', 0)} ongoing")
    r = report.get("recon")
    if r:
        L += [f"IP: {r.get('ip')}  Server: {r.get('server')}  HTTP: {r.get('status_code')}",
              f"Open ports: {r.get('open_ports')}", "-" * 60]
    for f in report["findings"]:
        L.append(f"[{f['severity']}] {f['title']}\n  {f.get('url')}\n  {f.get('detail')}")
        if f.get("confidence"):
            L.append(f"  Confidence: {f.get('confidence')}")
        _ctx = " ".join(p for p in (
            f"method={f['method']}" if f.get("method") else "",
            f"param={f['param']}" if f.get("param") else "",
            f"location={f['location']}" if f.get("location") else "",
            f"auth={f['auth_context']}" if f.get("auth_context") else "",
            f"confirm={f['confirm']}" if f.get("confirm") else "",
            f"check={f['check']}" if f.get("check") else "") if p)
        if _ctx:
            L.append(f"  Context: {_ctx}")
        if f.get("cwe") or f.get("cvss"):
            L.append(f"  {f.get('cwe')} | {f.get('owasp')} | {f.get('cvss')} (template estimate)")
        if f.get("remediation"):
            L.append(f"  Fix: {f.get('remediation')}")
    for f in report.get("observations", []):
        L.append(f"[INFO] {f['title']}\n  {f.get('url')}\n  {f.get('detail')}")
    if not report["findings"] and not report.get("observations"):
        L.append("Clean: no findings.")
    return "\n".join(L) + "\n"


_SARIF_LEVEL = {"CRITICAL": "error", "MEDIUM": "error", "LOW": "warning",
                "INFO": "note"}


def _sarif_rule_id(title: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", (title or "finding").lower()).strip("-")
    return f"gash/{slug or 'finding'}"


def _render_sarif(report: dict) -> dict:
    """SARIF 2.1.0 for CI ingestion (GitHub code scanning et al).

    Rules come from finding titles; levels map CRITICAL/MEDIUM->error,
    LOW->warning, INFO->note. Evidence stays truncated (see to_dict).
    """
    rules: dict[str, dict] = {}
    results: list[dict] = []
    for f in report.get("findings", []) + report.get("observations", []):
        rid = _sarif_rule_id(f.get("title", ""))
        if rid not in rules:
            rules[rid] = {
                "id": rid,
                "name": (f.get("title", "") or "")[:120],
                "shortDescription": {"text": (f.get("detail", "") or "")[:300]},
                "help": {"text": (f.get("remediation", "") or "")[:500]},
                "properties": {
                    "cwe": f.get("cwe", ""), "owasp": f.get("owasp", ""),
                    "cvss": f.get("cvss", ""), "check": f.get("check", ""),
                    "confidence": f.get("confidence", ""),
                    "confirm": f.get("confirm", "")},
            }
        results.append({
            "ruleId": rid,
            "level": _SARIF_LEVEL.get(f.get("severity", ""), "warning"),
            "message": {"text": (f.get("detail", "") or "")[:500]},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": f.get("url", "") or ""},
                    "region": {"snippet": {"text": (f.get("evidence", "")
                                                    or "")[:300]}},
                }}],
        })
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "GASH",
                "version": str(report.get("version", "")),
                "informationUri": "https://github.com/Xmar1881/Gash",
                "rules": sorted(rules.values(), key=lambda r: r["id"]),
            }},
            "results": results,
            "invocations": [{
                "executionSuccessful": not bool(report.get("incomplete")),
                "properties": {
                    "target": report.get("target", ""),
                    "incomplete": bool(report.get("incomplete")),
                    "degraded": bool((report.get("scan_health") or {})
                                     .get("degraded")),
                }}],
        }],
    }


def _render_junit(report: dict) -> str:
    """JUnit XML: one testsuite, one testcase per finding (failure body).

    Observations become skipped cases. Always valid XML (escaped).
    """
    import xml.sax.saxutils as _sax
    esc = _sax.escape
    cases: list[str] = []
    for f in report.get("findings", []):
        msg = esc(f"[{f.get('severity')}] {f.get('title')} "
                  f"({f.get('confidence', '?')}) :: {f.get('detail', '')}"[:500])
        cases.append(
            f'    <testcase classname="gash.{esc(f.get("check") or "scan")}" '
            f'name="{esc(f.get("title", "")[:160])}">\n'
            f'      <failure message="{msg}" type="{esc(f.get("severity", ""))}">'
            f'{esc(f.get("url", ""))}</failure>\n'
            f'    </testcase>')
    for f in report.get("observations", []):
        cases.append(
            f'    <testcase classname="gash.observations" '
            f'name="{esc(f.get("title", "")[:160])}">\n'
            f'      <skipped message="{esc(f.get("detail", "")[:200])}"/>\n'
            f'    </testcase>')
    total = len(cases)
    fails = len(report.get("findings", []))
    return (f'<?xml version="1.0" encoding="UTF-8"?>\n'
            f'<testsuite name="gash" tests="{total}" failures="{fails}" '
            f'skipped="{len(report.get("observations", []))}">\n'
            + "\n".join(cases)
            + ("\n" if cases else "") + '</testsuite>\n')


def _diff_html(diff: dict) -> str:
    if not diff or diff.get("ilk_tarama"):
        return ""
    return (f"<p>Diff: <b>{len(diff.get('yeni', []))}</b> new / "
            f"<b>{len(diff.get('kapandi', []))}</b> fixed / "
            f"{diff.get('ayni', 0)} ongoing</p>")


def _exec_summary(report: dict, risk: str) -> str:
    """One-paragraph management summary."""
    s = report["summary"]
    crits = [f["title"] for f in report["findings"] if f["severity"] == "CRITICAL"][:3]
    tgt = report["target"]
    if s["CRITICAL"]:
        names = ", ".join(dict.fromkeys(crits))
        return (f"Scan of {tgt} found <b>{s['CRITICAL']} critical</b> findings "
                f"({s['TOTAL']} total). Fix these first: {names}. "
                f"The site cannot be considered safe until criticals are closed.")
    if s["MEDIUM"]:
        return (f"Scan of {tgt} found no critical issues; <b>{s['MEDIUM']} medium</b> "
                f"findings ({s['TOTAL']} total). Mediums can chain into exploits, "
                f"close them in planned maintenance.")
    if s["TOTAL"]:
        return (f"Scan of {tgt} found only <b>{s['LOW']} low</b> findings. "
                f"No urgent risk; apply the hygiene recommendations.")
    return (f"Scan of {tgt} found <b>no issues</b>. This means the automated scan "
            f"saw no known vulnerability patterns on the visible surface; "
            f"it is not a replacement for manual pentesting.")


def _cwe_link(cwe: str, esc) -> str:
    import re as _re
    m = _re.search(r"CWE-(\d+)", cwe or "")
    if not m:
        return esc(cwe or "")
    num = m.group(1)
    return (f'<a href="https://cwe.mitre.org/data/definitions/{num}.html">'
            f'{esc(cwe)}</a>')


def _render_html(report: dict) -> str:
    from collections import Counter
    esc = _html.escape
    s = report["summary"]
    total = max(1, s["TOTAL"])

    def badge(sev: str) -> str:
        cls = {"CRITICAL": "crit", "MEDIUM": "mid"}.get(sev, "low")
        return f'<span class="badge {cls}">{esc(sev)}</span>'

    def bar(n: int, cls: str) -> str:
        pct = round(n / total * 100)
        return (f'<div class="track"><div class="fill {cls}" style="width:{pct}%"></div></div>'
                f' <b>{n}</b> <span class="pct">({pct}%)</span>')

    # risk score: weighted, 0-100 (static estimate, not environment-aware)
    score = min(100, s["CRITICAL"] * 25 + s["MEDIUM"] * 10 + s["LOW"] * 3)
    risk = "HIGH" if s["CRITICAL"] else ("MEDIUM" if s["MEDIUM"] else "LOW")
    risk_cls = {"HIGH": "crit", "MEDIUM": "mid"}.get(risk, "low")

    # category breakdown by title
    cats = Counter(f["title"] for f in report["findings"])
    cat_rows = "\n".join(
        f"<tr><td>{esc(t)}</td><td>{c}</td></tr>" for t, c in cats.most_common()
    ) or "<tr><td colspan='2'>—</td></tr>"

    # findings grouped by severity, evidence inside <details>
    sections = []
    for sev in ("CRITICAL", "MEDIUM", "LOW"):
        items = [f for f in report["findings"] if f["severity"] == sev]
        if not items:
            continue
        rows = "\n".join(
            f"<tr><td>{badge(f['severity'])}<div class='url'>{_cwe_link(f.get('cwe') or '', esc)}</div></td>"
            f"<td>{esc(f['title'])}<div class='url'>{esc(f.get('url') or '')}</div></td>"
            f"<td>{esc(f.get('detail') or '')}"
            f"<div class='url'>{esc(f.get('cvss') or '')} (template estimate)</div>"
            f"<div class='conf'>confidence: {esc(f.get('confidence') or '?')}</div>"
            + (f"<div class='rem'>🛠 {esc(f.get('remediation') or '')}</div>"
               if f.get("remediation") else "")
            + (f"<details><summary>evidence</summary><code>{esc(f.get('evidence') or '')}</code></details>"
               if f.get("evidence") else "")
            + "</td></tr>"
            for f in items
        )
        sections.append(
            f"<div class='sevsec' id='sec-{sev}'>"
            f"<h2>{sev} <span class='cnt'>({len(items)})</span></h2>"
            f"<table><tr><th>Severity</th><th>Title</th><th>Detail</th></tr>{rows}</table></div>")
    findings_html = "\n".join(sections) if sections else "<p>Clean: no findings.</p>"
    obs_items = report.get("observations", [])
    if obs_items:
        obs_rows = "\n".join(
            f"<tr><td>{badge('INFO')}</td>"
            f"<td>{esc(f.get('title') or '')}"
            f"<div class='url'>{esc(f.get('url') or '')}</div></td>"
            f"<td>{esc(f.get('detail') or '')}</td></tr>"
            for f in obs_items
        )
        sections.append(
            f"<div class='sevsec' id='sec-INFO'>"
            f"<h2>OBSERVATIONS <span class='cnt'>({len(obs_items)})</span></h2>"
            f"<p class='meta'>Discovery notes — not vulnerabilities, not scored.</p>"
            f"<table><tr><th>Severity</th><th>Title</th><th>Detail</th></tr>{obs_rows}</table></div>")
        findings_html = "\n".join(sections)

    r = report.get("recon") or {}
    dns = "<br>".join(f"{esc(k)}: {esc(', '.join(v[:4]))}"
                      for k, v in (r.get("dns_records") or {}).items() if isinstance(v, list))
    hdrs = "".join(f"<tr><td>{esc(str(k))}</td><td>{esc(str(v))[:120]}</td></tr>"
                   for k, v in list((r.get("headers") or {}).items())[:12])
    return f"""<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>GASH Report — {esc(report['target'])}</title>
<style>
body{{background:#0a0a0a;color:#c8c8c8;font-family:Consolas,Menlo,monospace;margin:2em;max-width:1100px}}
h1{{color:#ff2b2b}}h2{{color:#39ff14}}.meta,.pct,.url{{color:#888}}
table{{border-collapse:collapse;width:100%;margin:.5em 0}}td,th{{border:1px solid #333;padding:6px 10px;text-align:left;vertical-align:top}}
.badge{{padding:2px 8px;border-radius:4px;font-weight:bold;white-space:nowrap}}
.crit{{background:#ff2b2b;color:#fff}}.mid{{background:#b58900;color:#000}}.low{{background:#175c17;color:#fff}}
.track{{display:inline-block;width:min(420px,50vw);background:#222;border-radius:4px;overflow:hidden;vertical-align:middle}}
.fill{{height:14px}}.fill.crit{{background:#ff2b2b}}.fill.mid{{background:#e6c200}}.fill.low{{background:#39ff14}}
.grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(260px,1fr));gap:1em}}
.card{{border:1px solid #333;border-radius:8px;padding:1em}}
.risk{{font-size:1.6em}}.url{{font-size:.85em;word-break:break-all}}
.rem{{color:#9ecbff;font-size:.85em;margin-top:4px}}
.conf{{color:#e6c200;font-size:.85em;margin-top:2px}}
.fbtn{{background:#1a1a1a;color:#c8c8c8;border:1px solid #555;border-radius:6px;padding:4px 12px;margin:2px;cursor:pointer;font-family:inherit}}
.fbtn.on{{border-color:#39ff14;color:#39ff14}}
.exec{{border-left:4px solid #ff2b2b;background:#160808;padding:.6em 1em;border-radius:0 8px 8px 0}}
.meta-table td:first-child{{color:#888;width:130px}}
details{{margin-top:4px}}summary{{cursor:pointer;color:#888}}code{{color:#e6c200;font-size:.85em;word-break:break-all}}
@media print{{body{{background:#fff;color:#000}}h1{{color:#a00}}h2{{color:#060}}.card,td,th{{border-color:#999}}}}
</style></head><body>
<h1>█ GASH <span style="font-size:.5em">// Vulnerability &amp; Penetration Engine v{esc(report['version'])}</span></h1>
<div class="card exec"><b>Executive summary:</b> {_exec_summary(report, risk)}</div>
 {"<div class='card exec'><b>WARNING:</b> incomplete scan (rate limit / budget) — partial results, NOT a clean bill.</div>" if report.get("incomplete") else ""}
 {"<div class='card exec'><b>WARNING:</b> SCAN DEGRADED — failed checks mean partial results, NOT a clean bill.</div>" if (report.get("scan_health") or {}).get("degraded") else ""}
<h2>Scan info</h2>
<table class="meta-table">
<tr><td>Target</td><td>{esc(report['target'])}</td></tr>
<tr><td>Mode</td><td>{esc(report['mode'])}</td></tr>
<tr><td>Date</td><td>{esc(report['scanned_at'])}</td></tr>
<tr><td>Duration</td><td>{esc(str(report.get('elapsed_s')))}s</td></tr>
<tr><td>HTTP requests</td><td>{esc(str(report.get('http_requests', '?')))}</td></tr>
</table>
<div class="grid">
<div class="card"><h2>Severity distribution</h2>
<div>CRITICAL {bar(s['CRITICAL'], 'crit')}</div>
<div>MEDIUM &nbsp; {bar(s['MEDIUM'], 'mid')}</div>
<div>LOW &nbsp;&nbsp;&nbsp;{bar(s['LOW'], 'low')}</div>
<p>Total: <b>{s['TOTAL']}</b> findings + {s.get('OBSERVATIONS', 0)} observations (not scored)</p>{_diff_html(report.get('diff') or {})}</div>
<div class="card"><h2>Risk score</h2>
<p class="risk"><span class="badge {risk_cls}">{risk}</span> <b>{score}</b>/100</p>
<p class="meta">Static estimate: CRITICAL×25 + MEDIUM×10 + LOW×3 (max 100). Fix the red ones first.</p></div>
<div class="card"><h2>Categories</h2>
<table><tr><th>Type</th><th>Count</th></tr>{cat_rows}</table></div>
</div>
<h2>Recon</h2><p>IP: {esc(str(r.get('ip')))} | Server: {esc(str(r.get('server')))} |
HTTP {esc(str(r.get('status_code')))} | Ports: {esc(str(r.get('open_ports')))}<br>{dns}</p>
{"<h2>HTTP Headers</h2><table><tr><th>Header</th><th>Value</th></tr>" + hdrs + "</table>" if hdrs else ""}
<div><b>Filter:</b>
<button class="fbtn on" onclick="flt('all',this)">All</button><button class="fbtn" onclick="flt('CRITICAL',this)">Critical</button><button class="fbtn" onclick="flt('MEDIUM',this)">Medium</button><button class="fbtn" onclick="flt('LOW',this)">Low</button><button class="fbtn" onclick="flt('INFO',this)">Observations</button>
</div>
<script>
function flt(sev,btn){{document.querySelectorAll('.fbtn').forEach(b=>b.classList.remove('on'));btn.classList.add('on');document.querySelectorAll('.sevsec').forEach(d=>{{d.style.display=(sev==='all'||d.id==='sec-'+sev)?'':'none';}});}}
</script>
{findings_html}
<p class="meta">Generated by GASH · developed by Xmar1881. Authorized testing only.</p></body></html>
"""

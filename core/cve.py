"""Known-vulnerable component matching — curated DB, no feeds.

Mass defacements ride N-day CMS/library bugs, not fuzzing luck. This
module maps confidently-parsed versions to a hand-curated list of
high-impact CVEs (plus EOL rules). Ranges are inclusive and narrow on
purpose: an uncertain match reports nothing. Pure functions (no network);
the check in webchecks.py owns the HTTP.
"""

from __future__ import annotations

import re

# component -> entries. ranges: [(low_incl, high_incl)] as version tuples.
# severity: scanner scale. fixed: first safe release (or "supported").
DB: list[dict] = [
    {"component": "jquery",
     "ranges": [(("1",), ("3", "4", "1"))],
     "cve": "CVE-2020-11022", "cve2": "CVE-2020-11023",
     "severity": "MEDIUM",
     "note": "XSS via htmlPrefilter/manipulation (3.5.0 rework)",
     "fixed": "3.5.0",
     "ref": "https://nvd.nist.gov/vuln/detail/CVE-2020-11022"},
    {"component": "bootstrap",
     "ranges": [(("3",), ("3", "4", "0")), (("4",), ("4", "2", "1"))],
     "cve": "CVE-2019-8331",
     "severity": "MEDIUM",
     "note": "XSS in tooltip/popover data-template",
     "fixed": "3.4.1 / 4.3.1",
     "ref": "https://nvd.nist.gov/vuln/detail/CVE-2019-8331"},
    {"component": "drupal",
     "ranges": [(("7",), ("7", "57")), (("8",), ("8", "5", "0"))],
     "cve": "CVE-2018-7600",
     "severity": "CRITICAL",
     "note": "Drupalgeddon2 RCE (unauthenticated)",
     "fixed": "7.58 / 8.5.1",
     "ref": "https://nvd.nist.gov/vuln/detail/CVE-2018-7600"},
    {"component": "wordpress",
     "ranges": [(("4", "7"), ("4", "7", "1"))],
     "cve": "CVE-2017-1001000",
     "severity": "CRITICAL",
     "note": "REST API content injection (privilege escalation)",
     "fixed": "4.7.2",
     "ref": "https://nvd.nist.gov/vuln/detail/CVE-2017-1001000"},
    {"component": "lodash",
     "ranges": [(("0",), ("4", "17", "10"))],
     "cve": "CVE-2018-16487",
     "severity": "MEDIUM",
     "note": "Prototype pollution in merge/defaultsDeep",
     "fixed": "4.17.11",
     "ref": "https://nvd.nist.gov/vuln/detail/CVE-2018-16487"},
    {"component": "wordpress-eol",
     "ranges": [(("0",), ("4", "99"))],
     "cve": "",
     "severity": "MEDIUM",
     "note": "WordPress 4.x receives no security updates; any 4.x in the "
             "wild is abandoned (upgrade to a supported release)",
     "fixed": "supported release (6.x)",
     "ref": "https://wordpress.org/about/requirements/"},
    {"component": "php-eol",
     "ranges": [(("5",), ("5", "99")), (("7", "0"), ("7", "3", "99"))],
     "cve": "",
     "severity": "MEDIUM",
     "note": "PHP branch end-of-life: no security fixes ship anymore; "
             "every later CVE stays open on this host",
     "fixed": "supported PHP (8.x)",
     "ref": "https://www.php.net/supported-versions.php"},
]


def parse_version(raw: str) -> tuple | None:
    """'1.12.4' -> ('1','12','4'). Non-numeric tails cut, else None."""
    m = re.match(r"^\s*v?(\d+(?:\.\d+){0,3})", str(raw or ""))
    if not m:
        return None
    parts = m.group(1).split(".")
    if not all(p.isdigit() for p in parts):
        return None
    return tuple(parts)


def _cmp(a: tuple, b: tuple) -> int:
    """Numeric-aware tuple compare (1.9 < 1.12)."""
    nums = lambda t: [int(x) for x in t]
    na, nb = nums(a), nums(b)
    n = max(len(na), len(nb))
    na += [0] * (n - len(na))
    nb += [0] * (n - len(nb))
    return (na > nb) - (na < nb)


def in_range(ver: tuple, low: tuple, high: tuple) -> bool:
    return _cmp(ver, low) >= 0 and _cmp(ver, high) <= 0


def match_component(component: str, version: str) -> list[dict]:
    """DB entries whose range covers this exact version. [] when unsure."""
    ver = parse_version(version)
    if ver is None:
        return []
    out = []
    for e in DB:
        if e.get("component") != component:
            continue
        try:
            if any(in_range(ver, lo, hi) for lo, hi in e.get("ranges", [])):
                out.append(e)
        except Exception:
            continue
    return out


# ---------- version extraction (passive sources only) ----------

GENERATOR_RES = [
    (re.compile(r"wordpress\s+([\d.]+)", re.I), "wordpress"),
    (re.compile(r"joomla!?\s*([\d.]+)", re.I), "joomla"),
    (re.compile(r"drupal\s+([\d.]+)", re.I), "drupal"),
    (re.compile(r"ghost\s+([\d.]+)", re.I), "ghost"),
]

VER_PARAM_RES = [
    (re.compile(r"jquery[.-](\d[\d.]*)\.min\.js", re.I), "jquery"),
    (re.compile(r"[?&]ver=(\d[\d.]*)", re.I), None),  # WP core (?ver=4.7.1)
]

# ?ver= on a library path belongs to the library, not the CMS
# ("/remove-account?ver=" must NOT read as vue).
LIB_FILE_HINT = re.compile(r"/(jquery|bootstrap|lodash|moment|vue|react)(?:[.-]|/)",
                           re.I)

JS_BANNER_RES = [
    (re.compile(r"jQuery\s+(?:JavaScript Library\s+)?v?(\d[\d.]*)", re.I),
     "jquery"),
    (re.compile(r"Bootstrap\s+v?(\d[\d.]*)", re.I), "bootstrap"),
    (re.compile(r"lodash[^\d]*v?(\d[\d.]*)", re.I), "lodash"),
]


def extract_versions(html: str, headers: dict | None = None) -> list[tuple[str, str, str]]:
    """[(component, version, source)] from meta/generator, ?ver=, headers.

    wordpress via ?ver= only counts on wp-content/wp-includes URLs
    (theme zappers fake ver= everywhere).
    """
    out: list[tuple[str, str, str]] = []
    body = html or ""
    for m in re.finditer(
            r'''<meta[^>]*name=["']generator["'][^>]*content=["']([^"']+)["']''',
            body, re.I):
        content = m.group(1)
        for rx, comp in GENERATOR_RES:
            mm = rx.search(content)
            if mm and parse_version(mm.group(1)):
                out.append((comp, mm.group(1), "meta-generator"))
                break
    for m in re.finditer(
            r'''(?:src|href)=["']([^"']+)["']''', body, re.I):
        url = m.group(1)
        for rx, comp in VER_PARAM_RES:
            mm = rx.search(url)
            if not mm:
                continue
            if comp is None:  # ?ver=: library file wins over WP asset path
                lib = LIB_FILE_HINT.search(url)
                if lib:
                    comp = lib.group(1).lower()
                else:
                    low = url.lower()
                    if "wp-includes" not in low and "wp-content" not in low:
                        continue
                    comp = "wordpress"
            if parse_version(mm.group(1)):
                out.append((comp, mm.group(1), "?ver="))
    try:
        blob = " ".join(f"{k}: {v}" for k, v in (headers or {}).items())
    except Exception:
        blob = ""
    m = re.search(r"php/(\d[\d.]*)", blob, re.I)
    if m and parse_version(m.group(1)):
        out.append(("php-eol" if _cmp(parse_version(m.group(1)), ("7", "4")) < 0
                    else "php", m.group(1), "x-powered-by"))
    seen: set[tuple[str, str]] = set()
    uniq: list[tuple[str, str, str]] = []
    for comp, ver, src in out:
        if (comp, ver) not in seen:
            seen.add((comp, ver))
            uniq.append((comp, ver, src))
    return uniq[:8]


def extract_js_versions(js_text: str) -> list[tuple[str, str, str]]:
    """Library banner versions from one bundle. Capped, deduped."""
    out: list[tuple[str, str, str]] = []
    for rx, comp in JS_BANNER_RES:
        try:
            m = rx.search(js_text or "")
        except Exception:
            continue
        if m and parse_version(m.group(1)):
            out.append((comp, m.group(1), "js-banner"))
        if len(out) >= 4:
            break
    return out


def components_with_findings(found: list[tuple[str, str, str]]) -> list[dict]:
    """(component, version, source) -> finding payloads (DB hits only)."""
    out: list[dict] = []
    seen: set[tuple[str, str]] = set()
    for comp, ver, src in found:
        for e in match_component(comp, ver):
            key = (e.get("cve") or e["component"], ver)
            if key in seen:
                continue
            seen.add(key)
            if e.get("cve"):
                title = f"Known vulnerable component ({e['cve']})"
                detail = (f"{comp} {ver} (via {src}) matches {e['cve']}: "
                          f"{e['note']}. Fixed in {e['fixed']}.")
                evidence = e["cve"]
            else:
                title = (f"End-of-life component "
                         f"({comp.replace('-eol', '')} {ver})")
                detail = (f"{comp.replace('-eol', '')} {ver} (via {src}) "
                          f"is end-of-life: {e['note']}")
                evidence = f"{comp} {ver}"[:60]
            out.append({"title": title, "severity": e["severity"],
                        "detail": detail + (f" Ref: {e['ref']}"
                                            if e.get("ref") else ""),
                        "evidence": evidence,
                        "confidence": "High", "cve": e.get("cve", ""),
                        "location": "header" if src == "x-powered-by"
                        else "body"})
            if len(out) >= 4:
                return out
    return out

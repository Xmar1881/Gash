"""Deep surface family: WAF fingerprint, cookie flags, tech fingerprint."""
from __future__ import annotations

from core.colors import info, warn
from core.registry import check as register_check
from core.scan._shared import Finding
from core.deep._shared import (
    WAF_SIGNS, SMART_PATHS, TECH_MARKERS,
)


def detect_waf(headers: dict, cookie_names: list[str]) -> str | None:
    blob = " ".join(f"{k}: {v}" for k, v in (headers or {}).items()).lower()
    blob += " " + " ".join(cookie_names or []).lower()
    for name, marks in WAF_SIGNS:
        if any(m in blob for m in marks):
            return name
    return None


@register_check("waf-detect", "WAF fingerprint (passive note)", order=5)
def test_waf_detect(session, headers: dict, base: str,
                    verbose: bool = False) -> list[Finding]:
    """No requests: reads base headers + session cookies."""
    try:
        jar = getattr(session, "cookies", None)
        cnames = [c.name for c in list(jar)] if jar else []
    except Exception:
        cnames = []
    waf = detect_waf(headers or {}, cnames)
    if waf:
        if verbose:
            print(warn(f"    [i] WAF: {waf} — some findings may be masked"))
        return [Finding(
            title="WAF detected", severity="INFO",
            url=base + "/",
            detail=f"{waf} looks active; vulnerabilities behind the filter may be masked, "
                   "manual verification advised",
            evidence=waf,
            confidence="High",)]
    return []


@register_check("cookie-flags", "Cookie HttpOnly/Secure/SameSite audit", order=10)
def test_cookie_flags(session, base: str, timeout: int,
                      verbose: bool = False) -> list[Finding]:
    """Missing flags on session cookies. Passive, no extra requests (reads the jar)."""
    try:
        jar = getattr(session, "cookies", None)
        cookies = list(jar) if jar else []
    except Exception:
        return []
    out: list[Finding] = []
    https = base.startswith("https://")
    for c in cookies[:5]:
        rest = {k.lower(): v for k, v in
                (getattr(c, "_rest", None) or getattr(c, "rest", None) or {}).items()}
        missing = []
        if "httponly" not in rest:
            missing.append("HttpOnly")
        if https and not getattr(c, "secure", False):
            missing.append("Secure")
        if "samesite" not in rest:
            missing.append("SameSite")
        if missing:
            out.append(Finding(
                title="Weak cookie flags", severity="LOW",
                url=base + "/",
                detail=f"Cookie '{c.name}' is missing: {', '.join(missing)}",
                evidence=c.name,
                confidence="High",))
            if verbose:
                print(warn(f"    [!] Cookie: {c.name} -> {', '.join(missing)} missing"))
        # __Host-/__Secure- prefixes are a browser-enforced contract:
        # breaking it silently drops the cookie's protection.
        name = c.name or ""
        if name.startswith("__Host-") and (
                not getattr(c, "secure", False) or "/" not in
                str(getattr(c, "path", "/") or "/")):
            out.append(Finding(
                title="Weak cookie flags", severity="LOW",
                url=base + "/",
                detail=f"Cookie '{name}' uses the __Host- prefix without "
                       "Secure + Path=/ + host-only; browsers ignore the prefix",
                evidence=name,
                confidence="High",))
            if verbose:
                print(warn(f"    [!] Cookie prefix broken: {name}"))
        elif name.startswith("__Secure-") and https \
                and not getattr(c, "secure", False):
            out.append(Finding(
                title="Weak cookie flags", severity="LOW",
                url=base + "/",
                detail=f"Cookie '{name}' uses the __Secure- prefix without "
                       "the Secure flag",
                evidence=name,
                confidence="High",))
            if verbose:
                print(warn(f"    [!] Cookie prefix broken: {name}"))
    return out[:4]


def smart_tech_paths(html: str, headers: dict) -> tuple[list[str], list[str]]:
    """(technologies, extra dir-brute paths). No requests, passive."""
    blob = ((html or "")[:6000] + " " + " ".join(
        f"{k}: {v}" for k, v in (headers or {}).items())).lower()
    techs = [t for t, marks in TECH_MARKERS if any(m in blob for m in marks)]
    extra: list[str] = []
    for t in techs:
        extra += SMART_PATHS.get(t, [])
    extra += SMART_PATHS["backup"][:6]  # backups probed everywhere
    return sorted(set(techs)), list(dict.fromkeys(extra))


@register_check("smart-tech", "Tech fingerprint + targeted paths", order=21)
def smart_tech(ctx: dict) -> list[Finding]:
    """Passive: writes techs + extra_paths into ctx. Makes no requests."""
    html, headers = ctx.get("html", ""), ctx.get("headers") or {}
    techs, extra = smart_tech_paths(html, headers)
    ctx["techs"] = techs
    ctx.setdefault("extra_paths", []).extend(x for x in extra
                                             if x not in ctx["extra_paths"])
    if ctx.get("verbose") and techs:
        print(info(f"    [i] Technology: {', '.join(techs)}"))
    return []


__all__ = [
    "detect_waf", "test_waf_detect",
    "test_cookie_flags",
    "smart_tech_paths", "smart_tech",
]

"""Interactive scan wizard: target -> profile -> options -> confirm.

Flow mirrors pro scanners (target, policy, options, review, launch):

  py gash.py            -> opens the wizard when run bare (tty only)
  py gash.py --menu    -> force the wizard open

Choices become an argv list executed by the existing main(), so all
scan logic stays in one place.
"""

from __future__ import annotations

import os

from core.banner import show_banner
from core.colors import success, info, warn, danger, DIM, RESET

# Category -> (title, blurb, check names). Covers every check.
CATEGORIES: dict[str, tuple[str, str, set[str]]] = {
    "1": ("Injection",
          "SQLi (error/blind/time/login) + SSTI",
          {"sqli-error", "sqli-blind", "sqli-login", "ssti"}),
    "2": ("XSS",
          "reflected / stored / 404 / DOM",
          {"xss-reflected", "xss-errpage", "stored-xss", "dom-xss"}),
    "3": ("SSRF / IDOR / API",
          "SSRF, object-level auth gaps, prototype pollution",
          {"ssrf", "idor", "idor-param", "protopollution"}),
    "4": ("Exposure",
          "robots, dir-brute, uploads, cookies, WAF note",
          {"robots", "smart-dirs", "smart-recurse", "smart-tech",
           "upload-form", "upload-rce", "cookie-flags", "waf-detect"}),
    "5": ("Modern Web",
          "headers, CORS, redirect, traversal, methods, JS secrets, JWT, GraphQL",
          {"security-headers", "open-redirect", "path-traversal", "cors",
           "http-methods", "js-secrets", "jwt-none", "graphql-introspection",
           "host-header", "security-txt", "os-command-injection",
           "crlf-injection", "csrf-surface", "firebase-open",
           "supabase-anon", "nextjs-middleware-bypass", "wp-user-enum",
           "swagger-exposed", "mass-assignment"}),
}

ALL_CHECKS: set[str] = set().union(*(c[2] for c in CATEGORIES.values()))

# Checks needing active POST (deep mode).
DEEP_ONLY_SELECTED = {"sqli-login", "upload-rce"}


def _ask(prompt: str, default: str = "") -> str:
    tag = f" [{default}]" if default else ""
    try:
        ans = input(f"  {info('>')} {prompt}{DIM}{tag}{RESET}: ").strip()
    except (EOFError, KeyboardInterrupt):
        print()
        raise KeyboardInterrupt
    return ans or default


def _ask_choice(prompt: str, options: list[str], default: int = 1) -> int:
    print(f"\n  {info(prompt)}")
    for i, o in enumerate(options, 1):
        mark = " (default)" if i == default else ""
        print(f"    {success(str(i))}) {o}{DIM}{mark}{RESET}")
    while True:
        ans = _ask("Choice", str(default))
        if ans.isdigit() and 1 <= int(ans) <= len(options):
            return int(ans)
        print(f"  {warn('Enter a number 1-%d.' % len(options))}")


def _ask_multi(prompt: str, options: list[str], default: str = "1,2,3,4,5") -> list[int]:
    """Comma-separated multi pick, e.g. 1,3. Empty means default."""
    print(f"\n  {info(prompt)}")
    for i, o in enumerate(options, 1):
        print(f"    {success(str(i))}) {o}")
    while True:
        ans = _ask("Choices (comma-separated)", default)
        try:
            picked = sorted({int(x) for x in ans.replace(" ", "").split(",")
                             if x.isdigit() and 1 <= int(x) <= len(options)})
        except ValueError:
            picked = []
        if picked:
            return picked
        print(f"  {warn('Pick at least one category.')}")


def _ask_yes_no(prompt: str, default_yes: bool = True) -> bool:
    hint = "Y/n" if default_yes else "y/N"
    ans = _ask(f"{prompt} ({hint})", "y" if default_yes else "n").lower()
    return ans.startswith(("y", "1"))


def _step_targets() -> tuple[list[str], bool]:
    """(argv fragment, is_bulk?)."""
    print(f"\n  {info('Step 1/3 — Target')}")
    single = _ask_choice("Target source", [
        "Single target (URL / domain)",
        "Bulk targets from file (one per line)",
    ])
    if single == 1:
        while True:
            target = _ask("Target (e.g. target.com)")
            if target:
                if target.lower() in ("q", "quit", "exit"):
                    raise KeyboardInterrupt
                return ["-t", target], False
            print(f"  {warn('Target cannot be empty.')}")
    while True:
        path = _ask("Target file (e.g. targets.txt)")
        if path.lower() in ("q", "quit", "exit"):
            raise KeyboardInterrupt
        if path and os.path.exists(path):
            return ["--target-file", path], True
        print(f"  {warn('File not found, try again.')}")


def _step_profile() -> tuple[list[str], set[str], str]:
    """(argv fragment, selected checks, profile name)."""
    print(f"\n  {info('Step 2/3 — Scan profile')}")
    prof = _ask_choice("Profile", [
        "FULL — recon + all checks, deep (recommended)",
        "QUICK — fast: skips time-based + active POST",
        "RECON ONLY — recon only, no vulnerability checks",
        "CUSTOM — pick categories (e.g. XSS + Exposure only)",
    ])
    if prof == 1:
        return ["--full", "--deep"], set(ALL_CHECKS), "FULL (deep)"
    if prof == 2:
        return ["--full", "--quick"], set(ALL_CHECKS), "QUICK"
    if prof == 3:
        return ["--recon"], set(), "RECON ONLY"
    picked = _ask_multi("Categories", [
        f"{name} — {desc}" for _, (name, desc, _) in sorted(CATEGORIES.items())
    ])
    selected: set[str] = set()
    for i in picked:
        selected |= CATEGORIES[str(i)][2]
    argv = ["--full"]
    if selected & DEEP_ONLY_SELECTED:
        if not _ask_yes_no("Your picks need active POST, enable deep scan (--deep)", True):
            selected -= DEEP_ONLY_SELECTED
            print(info("  Deep checks removed."))
    if selected & DEEP_ONLY_SELECTED or _ask_yes_no(
            "Enable deep scan (--deep: slow, time-based + active POST included)", True):
        argv.append("--deep")
    else:
        argv.append("--quick")
    if "dom-xss" in selected:
        if _ask_yes_no("Headless DOM verification (--dom, slow, needs Playwright)", False):
            argv.append("--dom")
        else:
            selected.discard("dom-xss")
            print(info("  dom-xss dropped (--dom not given)."))
    skipped = ALL_CHECKS - selected
    if skipped:
        argv += ["--skip-checks", ",".join(sorted(skipped))]
    names = ", ".join(CATEGORIES[str(i)][0] for i in picked)
    return argv, selected, f"CUSTOM ({names})"


def _step_essentials(argv: list[str], is_bulk: bool, profile: str,
                     selected: set[str], target_desc: str) -> None:
    """Step 3/3: the 3 things that actually matter. Everything else keeps
    smart defaults unless advanced settings are opened. Extends argv."""
    from core.bulk import safe_name
    print(f"\n  {info('Step 3/3 — Essentials')}")
    if _ask_yes_no("Authenticated scan (cookie / header / login)", False):
        cookie = _ask("Cookie (empty = none, e.g. session=abc)")
        if cookie:
            argv += ["--cookie", cookie]
        hdr = _ask("Extra header (empty = none, e.g. Authorization: Bearer X)")
        if hdr:
            argv += ["--header", hdr]
        lu = _ask("Auto-login username (empty = anonymous)")
        if lu:
            lp = _ask("Login password")
            argv += ["--login-user", lu, "--login-pass", lp]
    if profile != "RECON ONLY" and ("stored-xss" in selected
                                    or profile in ("FULL (deep)", "QUICK")):
        if _ask_yes_no("Auto OOB verify for blind probes (--oob, public interactsh server)", False):
            argv.append("--oob")
        else:
            cb = _ask("Blind XSS listener (empty = none, e.g. abc.interact.sh)")
            if cb:
                argv += ["--blind-callback", cb]
    if is_bulk:
        rep = _ask("Report directory (Enter = reports/)", "reports")
        if rep:
            argv += ["--output-dir", rep]
            if _ask_yes_no("Enable resume (skip existing)", True):
                argv.append("--resume")
    else:
        first = target_desc.split()[1] if " " in target_desc else target_desc
        try:
            default_rep = f"reports/{safe_name(first)}.html"
        except Exception:
            default_rep = "reports/report.html"
        rep = _ask("Report file (Enter = default, n = skip)", default_rep)
        if rep.lower() not in ("n", "no"):
            argv += ["-o", rep or default_rep]
    if _ask_yes_no("Verbose output (-v)", False):
        argv.append("-v")
    if _ask_yes_no("Advanced settings (crawl, speed, proxy, TLS, CI gate)", False):
        _step_advanced(argv, profile)


def _step_advanced(argv: list[str], profile: str) -> None:
    """Rarely-touched knobs, one screen. Skipped by default."""
    if _ask_yes_no("Run a port scan", True) is False:
        argv.append("--skip-ports")
    if profile != "RECON ONLY":
        if _ask_yes_no("Let the crawler roam (links/forms/sitemap)", True) is False:
            argv.append("--no-crawl")
        else:
            mp = _ask("Page limit (empty = 8)", "")
            if mp:
                argv += ["--max-pages", mp]
            dp = _ask("Depth (empty = 2)", "")
            if dp:
                argv += ["--depth", dp]
        scope = _ask("Scope allowlist (empty = target host only, e.g. a.com,api.a.com)", "")
        if scope:
            argv += ["--scope", scope]
        delay = _ask("Delay between requests in sec (empty = 0, polite: 0.2)", "")
        if delay:
            argv += ["--delay", delay]
        budget = _ask("Request budget (empty = unlimited, e.g. 500)", "")
        if budget:
            argv += ["--max-requests", budget]
        proxy = _ask("Proxy (empty = none, e.g. http://127.0.0.1:8080 for Burp/ZAP)", "")
        if proxy:
            argv += ["--proxy", proxy]
        ua = _ask("Custom User-Agent (empty = default GASH identifier)", "")
        if ua:
            argv += ["--user-agent", ua]
        if _ask_yes_no("Disable TLS verification (--insecure, self-signed labs only)", False):
            argv.append("--insecure")
        fail = _ask_choice("CI gate (--fail-on)", [
            "none",
            "critical — exit 3 on CRITICAL findings",
            "medium — exit 3 on CRITICAL or MEDIUM findings",
        ])
        if fail == 2:
            argv += ["--fail-on", "critical"]
        elif fail == 3:
            argv += ["--fail-on", "medium"]


def _mask_argv(argv: list[str]) -> list[str]:
    """Hide the password in the displayed command (--login-pass ****)."""
    out = list(argv)
    for i, a in enumerate(out):
        if a == "--login-pass" and i + 1 < len(out):
            out[i + 1] = "****"
    return out


def _confirm(target_desc: str, profile: str, argv: list[str]) -> bool:
    print(f"\n  {DIM}{'─' * 52}{RESET}")
    print(f"  {info('Summary')}")
    print(f"    Target : {target_desc}")
    print(f"    Profile: {profile}")
    print(f"    Command: py gash.py {' '.join(_mask_argv(argv))}")
    print(f"  {DIM}{'─' * 52}{RESET}")
    return _ask_yes_no("Launch it", True)


def run_menu(version: str = "0.1.0") -> int:
    """Wizard loop. Returns an exit code. main() is imported lazily."""
    from gash import main  # lazy import: avoids a circular import

    show_banner(version)
    print(success("  Scan wizard — 3 steps, smart defaults, review, launch.\n"))

    while True:
        try:
            t_argv, is_bulk = _step_targets()
            target_desc = " ".join(t_argv)
            p_argv, selected, profile = _step_profile()
            argv = t_argv + p_argv
            _step_essentials(argv, is_bulk, profile, selected, target_desc)
            if not _confirm(target_desc, profile, argv):
                print(info("  Cancelled, reconfigure freely."))
                if not _ask_yes_no("Start over", True):
                    return 0
                continue
            print(f"\n  {DIM}Running: py gash.py "
                  f"{' '.join(_mask_argv(argv))}{RESET}\n")
            try:
                main(argv + ["--no-banner"])
            except SystemExit:
                pass  # parser errors inside main must not kill the wizard
            print()
            if not _ask_yes_no("Run another scan", True):
                print(info("  Bye."))
                return 0
        except KeyboardInterrupt:
            print(danger("\n  Aborted."))
            return 130


def maybe_menu(args, version: str) -> int | None:
    """Run the menu when needed and return its code, else None."""
    import sys as _s
    no_args = len(_s.argv) == 1
    if getattr(args, "menu", False) or (no_args and not args.target
                                       and not getattr(args, "target_file", None)
                                       and _s.stdin.isatty()):
        return run_menu(version)
    return None

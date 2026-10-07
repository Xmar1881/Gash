#!/usr/bin/env python3
"""GASH // Vulnerability & Penetration Engine — entry point.

Usage:
    python gash.py -t https://target.com --full
    python gash.py -t https://target.com --full --deep   # time-based + active POST
    python gash.py --recon -t http://target.com -v
    python gash.py --scan  -t http://target.com --threads 30
    python gash.py --target-file targets.txt --full --output-dir reports/
    python gash.py --target-file targets.txt --full --output-dir reports/ --resume

Default scans are SAFE: time-based delays, active POST probes
(stored/upload) and login-bypass attempts only run with --deep.
"""

import os
import re
import sys
import time
from dataclasses import dataclass, field
from core import __version__
from core.banner import show_banner
from core.bulk import (collect_targets, load_targets_file, looks_like_dir,
                       report_path_for, resolve_bulk_ext)
from core.cli import build_parser, resolve_mode, parse_ports
from core.colors import danger, info, success, warn
from core.recon import run_recon, print_recon, normalize_target, ReconResult
from core.scanner import run_scan, load_wordlist
from core.reporter import (print_findings, build_report, save_report,
                            diff_with_history, print_diff)
from core.net import configure_net, parse_auth


# ---------- small testable helpers ----------

def is_deep(args) -> bool:
    """Deep mode opens only with --deep (--quick wins)."""
    return bool(getattr(args, "deep", False) and not args.quick)


def parse_scope(raw: str | None) -> set[str] | None:
    """'a.com, b.com' -> {'a.com', 'b.com'}. None when empty (no scope)."""
    if not raw:
        return None
    out = {h.strip().lower().rstrip(".") for h in raw.split(",") if h.strip()}
    return out or None


def check_scope(targets: list[str], scope: set[str] | None) -> str | None:
    """Return the first out-of-scope target, None when all fit."""
    if not scope:
        return None
    for t in targets:
        try:
            host, _ = normalize_target(t)
        except Exception:
            return t
        if host.lower().rstrip(".") not in scope:
            return t
    return None


FAIL_LEVELS = {"critical": {"CRITICAL"}, "medium": {"CRITICAL", "MEDIUM"}}


def fail_triggered(findings, level: str | None) -> bool:
    """Has the --fail-on threshold tripped? (for CI exits)."""
    if not level:
        return False
    wanted = FAIL_LEVELS.get(level.strip().lower())
    if wanted is None:
        print(warn(f"  [!] --fail-on value not understood: {level} (critical|medium)"))
        return False
    return any(getattr(f, "severity", "") in wanted for f in findings)


def fail_triggered_counts(summary: dict, level: str | None) -> bool:
    """Threshold check over summary counters (for bulk)."""
    if not level:
        return False
    wanted = FAIL_LEVELS.get(level.strip().lower())
    if wanted is None:
        return False
    return any(summary.get(s, 0) > 0 for s in wanted)


class _NoColor:
    """Thin wrapper stripping ANSI escapes from stdout (--no-color)."""

    def __init__(self, stream):
        self._stream = stream

    def write(self, s):
        return self._stream.write(re.sub(r"\x1b\[[0-9;]*m", "", s))

    def __getattr__(self, name):
        return getattr(self._stream, name)


@dataclass
class ScanResult:
    """One target's scan result (possibly partial)."""
    target: str = ""
    recon: ReconResult | None = None
    findings: list = field(default_factory=list)
    diff: dict = field(default_factory=dict)
    elapsed: float = 0.0
    interrupted: bool = False


def resolve_login_password(args) -> str | None:
    """CLI > env(GASH_LOGIN_PASS) > interactive getpass. None when missing."""
    if getattr(args, "login_pass", None):
        return args.login_pass
    env = os.environ.get("GASH_LOGIN_PASS")
    if env:
        return env
    if getattr(args, "login_user", None) and sys.stdin.isatty():
        try:
            import getpass
            return getpass.getpass("  Login password (hidden): ") or None
        except Exception:
            return None
    return None


def _scan_target(target: str, args, mode: str, wordlist) -> ScanResult:
    """Scan one target. Returns partial results on Ctrl+C (never throws it)."""
    from core.recon import normalize_target as _nt
    t0 = time.time()
    res = ScanResult(target=target)
    configure_net(args.delay, args.max_requests,
                  getattr(args, "proxy", None),
                  getattr(args, "user_agent", None),
                  getattr(args, "insecure", False))
    auth = parse_auth(args.cookie, args.header)

    oob_client = None
    if getattr(args, "oob", False):
        server = getattr(args, "oob_server", None) or "https://interact.sh"
        if not getattr(args, "oob_server", None):
            print(warn("  [!] OOB traffic will go to the PUBLIC interact.sh "
                       "server; use --oob-server with a self-hosted instance "
                       "for sensitive targets."))
        try:
            from core.oob import OobClient
            oob_client = OobClient(server,
                                   timeout=args.timeout,
                                   wait=int(getattr(args, "oob_wait", 20) or 20))
            oob_client.register()
            print(success(f"[+] OOB ready: *.{oob_client.session_domain}"))
        except Exception as e:
            print(warn(f"  [!] OOB unavailable ({str(e)[:100]}), "
                       "continuing without it."))
            oob_client = None

    password = resolve_login_password(args)
    if args.login_user and not password:
        raise RuntimeError("no login password: pass --login-pass, set the "
                           "GASH_LOGIN_PASS env var, or type it interactively")
    if args.login_user and password:
        from core.scanner import do_login
        _, _base = _nt(target)
        try:
            sess_cookies, form_found = do_login(
                _base, args.login_user, password,
                args.timeout, args.login_url, auth)
            if sess_cookies:
                auth.cookies.update(sess_cookies)
                print(success(f"[+] Login OK: {len(sess_cookies)} cookies captured, "
                              f"scanning with session."))
            elif form_found:
                # Form found but no session: do NOT continue anonymously.
                raise RuntimeError(
                    "login failed (form found, no session) — "
                    "no anonymous scan performed. Check credentials and --login-url.")
            else:
                print(danger("[!] No login form found, continuing anonymously."))
        except RuntimeError:
            raise
        except Exception as e:
            print(danger(f"[!] Login error: {e}, continuing anonymously."))
    if args.verbose and (auth.cookies or auth.headers):
        print(info(f"[i] auth: {len(auth.cookies)} cookie, {len(auth.headers)} header"
                   + (f", delay={args.delay}s" if args.delay else "")
                   + (f", budget={args.max_requests}" if args.max_requests else "")))

    skip = (set((args.skip_checks or "").replace(" ", "").split(","))
            if args.skip_checks else None)
    deep = is_deep(args)
    scope = parse_scope(getattr(args, "scope", None))

    if mode in ("recon", "full"):
        try:
            ports = [] if args.skip_ports else parse_ports(args.ports)
            res.recon = run_recon(
                target,
                ports=ports,
                threads=args.threads,
                timeout=args.timeout,
                verbose=args.verbose,
                auth=auth,
                scope_hosts=scope,
            )
            print_recon(res.recon, verbose=args.verbose)
        except KeyboardInterrupt:
            res.interrupted = True
        except Exception as e:
            print(danger(f"[!] RECON error: {e}"))
            if args.verbose:
                raise

    if not res.interrupted and mode in ("scan", "full"):
        if res.recon is not None and res.recon.status_code == 0:
            # Recon already proved the host unreachable: a full scan would
            # just burn timeouts for minutes with zero signal (seen live:
            # ~490s against a dead host). Skip loudly instead.
            print(warn("  [!] Target unreachable (recon got HTTP 0) — "
                       "scan phase skipped, nothing to find."))
        else:
            try:
                res.findings = run_scan(
                    target,
                    threads=args.threads,
                    timeout=args.timeout,
                    verbose=args.verbose,
                    wordlist=wordlist,
                    deep=deep,
                    auth=auth,
                    skip_checks=skip,
                    max_pages=args.max_pages,
                    crawl_depth=args.depth,
                    no_crawl=args.no_crawl,
                    dom=args.dom,
            blind_callback=getattr(args, "blind_callback", None),
                scope_hosts=scope,
                oob=oob_client,
            )
                print_findings(res.findings, verbose=args.verbose)
                try:
                    from core.recon import history_key
                    res.diff = diff_with_history(history_key(target), res.findings)
                except Exception as e:
                    if args.verbose:
                        print(warn(f"  [!] history write failed: {e}"))
                    res.diff = {}
                print_diff(res.diff)
            except KeyboardInterrupt:
                res.interrupted = True
            except Exception as e:
                print(danger(f"[!] SCAN error: {e}"))
                if args.verbose:
                    raise

    res.elapsed = time.time() - t0
    return res


def _save_report(target: str, mode: str, res: ScanResult, path: str) -> bool:
    try:
        report = build_report(target, mode, __version__,
                              recon=res.recon, findings=res.findings,
                              elapsed=res.elapsed, diff=res.diff)
        save_report(report, path)
        print(success(f"\n[+] Report written: {path}"))
        return True
    except OSError as e:
        print(danger(f"[!] Report write failed: {e}"))
        return False


def run_single(target: str, args, mode: str) -> int:
    """Classic single-target flow. Report goes to -o (partial included)."""
    print(success(f"[+] Target : {target}"))
    print(success(f"[+] Mode   : {mode}"))
    if args.verbose:
        print(info(f"[i] threads={args.threads} timeout={args.timeout}s output={args.output}"))

    wordlist = load_wordlist(args.wordlist)
    if args.wordlist and not wordlist:
        print(danger(f"[!] Wordlist unreadable: {args.wordlist} (using built-in list)"))
    try:
        res = _scan_target(target, args, mode, wordlist)
    except KeyboardInterrupt:
        print(danger("\n[!] Aborted by user."))
        return 130
    except Exception as e:
        print(danger(f"[!] Scan error: {e}"))
        if args.verbose:
            raise
        return 1

    if args.output and not looks_like_dir(args.output):
        _save_report(target, mode, res, args.output)
        if res.interrupted:
            print(warn("  [!] Partial results saved (scan was interrupted)."))

    if res.interrupted:
        print(danger("\n[!] Aborted by user."))
        return 130
    print()
    if fail_triggered(res.findings, getattr(args, "fail_on", None)):
        print(warn(f"  [!] Threshold exceeded (--fail-on {args.fail_on})."))
        return 3
    return 0


def run_bulk(targets: list[str], args, mode: str, output_dir: str | None) -> int:
    """Bulk scan: never stops on one bad target, summary + index at the end."""
    import json
    from collections import Counter
    print(success(f"[+] Bulk scan: {len(targets)} targets, mode={mode}"))
    if output_dir:
        print(info(f"[i] Report directory: {output_dir}"))
        try:
            os.makedirs(output_dir, exist_ok=True)
        except OSError as e:
            print(danger(f"[!] Cannot create directory: {output_dir} ({e})"))
            return 1
    else:
        print(warn("  [!] No --output-dir: no report files will be written."))
    if args.resume:
        print(info("[i] Resume on: targets with reports are skipped."))

    ext = resolve_bulk_ext(args.output)
    wordlist = load_wordlist(args.wordlist)
    if args.wordlist and not wordlist:
        print(danger(f"[!] Wordlist unreadable: {args.wordlist} (using built-in list)"))

    results: list[dict] = []
    interrupted = False
    for i, target in enumerate(targets, 1):
        rpath = report_path_for(output_dir, target, ext) if output_dir else None
        print(success(f"\n[+] [{i}/{len(targets)}] Target: {target}"))
        if args.resume and rpath and os.path.exists(rpath):
            print(info(f"  [-] Skipped (resume): {rpath} already exists."))
            results.append({"target": target, "skipped": True,
                            "report": rpath, "summary": {}})
            continue
        try:
            res = _scan_target(target, args, mode, wordlist)
        except KeyboardInterrupt:
            print(danger("\n[!] Aborted by user (bulk stops, summary follows)."))
            interrupted = True
            results.append({"target": target, "error": "aborted",
                            "skipped": False, "report": None, "summary": {}})
            break
        except Exception as e:
            print(danger(f"[!] Target error ({target}): {e} — moving on."))
            if args.verbose:
                import traceback
                traceback.print_exc()
            results.append({"target": target, "error": str(e)[:200],
                            "skipped": False, "report": None, "summary": {}})
            continue

        summary = dict(Counter(f.severity for f in res.findings
                                 if f.severity != "INFO"))
        obs_n = sum(1 for f in res.findings if f.severity == "INFO")
        entry: dict = {"target": target, "skipped": False, "error": None,
                       "report": None, "summary": summary, "obs": obs_n,
                       "elapsed_s": round(res.elapsed, 2),
                       "interrupted": res.interrupted}
        if rpath:
            if _save_report(target, mode, res, rpath):
                entry["report"] = rpath
            else:
                entry["error"] = "report write failed"
            if res.interrupted:
                print(warn("  [!] Partial results saved."))
        results.append(entry)
        if res.interrupted:
            interrupted = True
            break

    # --- summary table + index ---
    print(info("\n[+] Bulk summary"))
    failed = 0
    for r in results:
        if r.get("skipped"):
            print(info(f"  SKIP  {r['target']}"))
        elif r.get("error"):
            failed += 1
            print(danger(f"  FAIL  {r['target']} ({r['error']})"))
        else:
            s = r.get("summary", {})
            mark = " (partial)" if r.get("interrupted") else ""
            obs_mark = f" +{r.get('obs', 0)} obs" if r.get("obs") else ""
            print(success(f"  OK    {r['target']} "
                          f"(C:{s.get('CRITICAL', 0)} M:{s.get('MEDIUM', 0)} "
                          f"L:{s.get('LOW', 0)}){mark}{obs_mark}"
                          + (f" -> {r['report']}" if r.get("report") else "")))
    print(info(f"  Total: {len(results)} targets, "
               f"{sum(1 for r in results if r.get('skipped'))} skipped, "
               f"{failed} failed."))
    if interrupted:
        print(warn("  [!] Interrupted — resume with --resume where you left off."))

    if output_dir:
        index_path = os.path.join(output_dir, "bulk_summary.json")
        try:
            with open(index_path, "w", encoding="utf-8") as f:
                json.dump({"mode": mode, "total": len(results),
                           "results": results}, f, ensure_ascii=False, indent=2)
            print(success(f"[+] Bulk index written: {index_path}"))
        except OSError as e:
            print(danger(f"[!] Index write failed: {e}"))
    print()
    if interrupted:
        return 130
    if failed:
        return 1
    if any(fail_triggered_counts(r.get("summary", {}),
                                getattr(args, "fail_on", None))
           for r in results if not r.get("skipped")):
        print(warn(f"  [!] Threshold exceeded (--fail-on {args.fail_on})."))
        return 3
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if getattr(args, "no_color", False):
        sys.stdout = _NoColor(sys.stdout)

    if args.version:
        print(f"GASH v{__version__}")
        return 0

    if args.list_checks:
        import core.scanner  # noqa: F401 — registers scanner checks
        import core.advanced  # noqa: F401 — registers advanced checks
        import core.domxss  # noqa: F401 — registers the dom check
        import core.webchecks  # noqa: F401 — registers modern web checks
        from core.registry import list_checks
        print(info("\n[?] Registered checks (disable with --skip-checks):"))
        for name, desc, deep_only in list_checks():
            tag = " [deep]" if deep_only else ""
            print(f"    {success(name.ljust(18))} {desc[:60]}{tag}")
        print()
        return 0

    if not args.no_banner and not args.menu:
        show_banner(__version__)

    # Interactive menu: --menu or a bare run
    from core.menu import maybe_menu
    menu_code = maybe_menu(args, __version__)
    if menu_code is not None:
        return menu_code

    # --- collect targets: -t and/or --target-file ---
    file_targets: list[str] = []
    if getattr(args, "target_file", None):
        try:
            file_targets = load_targets_file(args.target_file)
        except OSError as e:
            print(danger(f"[!] Target file unreadable: {args.target_file} ({e})"))
            return 1
        if not file_targets:
            print(danger(f"[!] Target file is empty: {args.target_file}"))
            return 1
    targets = collect_targets(args.target, file_targets)
    if not targets:
        parser.print_help()
        print()
        print(info("[i] Give a target to start:  python gash.py -t https://target.com --full"))
        print(info("[i] or bulk:  python gash.py --target-file targets.txt --full"))
        return 2

    # --- scope check ---
    scope = parse_scope(getattr(args, "scope", None))
    bad = check_scope(targets, scope)
    if bad:
        print(danger(f"[!] Out-of-scope target: {bad} (--scope: {args.scope})"))
        return 2

    mode = resolve_mode(args)
    if getattr(args, "insecure", False):
        print(warn("[!] TLS certificate verification DISABLED (--insecure)."))

    # --- bulk or single? ---
    output_dir = getattr(args, "output_dir", None)
    if len(targets) > 1 and not output_dir and args.output \
            and looks_like_dir(args.output):
        output_dir = args.output.rstrip("/\\") or "."
    if len(targets) > 1:
        return run_bulk(targets, args, mode, output_dir)
    if output_dir and not args.output:
        # single target + --output-dir: derive the file name
        ext = resolve_bulk_ext(None)
        args.output = report_path_for(output_dir, targets[0], ext)
        try:
            os.makedirs(output_dir, exist_ok=True)
        except OSError as e:
            print(danger(f"[!] Cannot create directory: {output_dir} ({e})"))
            return 1
    return run_single(targets[0], args, mode)


def cli() -> None:
    """Console entry point (pyproject [project.scripts])."""
    raise SystemExit(main())


if __name__ == "__main__":
    sys.exit(main())

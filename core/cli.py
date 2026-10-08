"""Argparse-based CLI. All flags live here."""

import argparse


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="gash",
        description="GASH // Automated Web Vulnerability Scanner & Pentest Engine",
        epilog="Example: python gash.py -t https://target.com --full",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    # --- Target ---
    p.add_argument(
        "-t", "--target",
        dest="target",
        metavar="URL",
        help="Target URL or domain (e.g. https://target.com)",
    )
    p.add_argument(
        "--target-file",
        dest="target_file",
        metavar="FILE",
        default=None,
        help="Bulk scan: file with one target per line (# comments, blanks skipped)",
    )

    # --- Modes ---
    modes = p.add_argument_group("scan modes")
    modes.add_argument(
        "--recon", action="store_true",
        help="Recon only: IP/DNS/ports/headers/server",
    )
    modes.add_argument(
        "--scan", action="store_true",
        help="Vulnerability scan only: SQLi/XSS/upload/dir-brute",
    )
    modes.add_argument(
        "--full", action="store_true",
        help="Recon + Scan, everything (default when a target is given)",
    )

    # --- Output / behavior ---
    p.add_argument(
        "-o", "--output",
        metavar="FILE",
        default=None,
        help="Report file: report.json / report.html / report.txt / "
             "report.sarif / report.xml (by extension)",
    )
    p.add_argument(
        "--output-dir",
        dest="output_dir",
        metavar="DIR",
        default=None,
        help="Bulk scan report directory (one file per target)",
    )
    p.add_argument(
        "--resume",
        action="store_true",
        help="Bulk scans: skip targets that already have a report (resume)",
    )
    p.add_argument(
        "--threads",
        type=int,
        default=20,
        help="Dir-brute / port scan thread count (default: 20)",
    )
    p.add_argument(
        "--timeout",
        type=int,
        default=8,
        help="HTTP request timeout in seconds (default: 8)",
    )
    p.add_argument(
        "--ports",
        metavar="80,443,8080",
        default=None,
        help="Ports to scan (e.g. 80,443,8080). Fast default list when empty.",
    )
    p.add_argument(
        "--skip-ports",
        action="store_true",
        help="Skip port scanning (faster recon)",
    )
    p.add_argument(
        "--wordlist",
        metavar="FILE",
        default=None,
        help="Custom dir-brute wordlist file (default: built-in list)",
    )
    p.add_argument(
        "--quick",
        action="store_true",
        help="Fast mode: skip time-based SQLi + active POST probes (stored/upload)",
    )
    p.add_argument(
        "--deep",
        action="store_true",
        help="Deep mode (opt-in): time-based SQLi + active POST + upload-rce + "
             "login tests. Default scans are safe (these are off)",
    )
    p.add_argument(
        "--scope",
        metavar="a.com,b.com",
        default=None,
        help="Scope allowlist (comma-separated hosts). Targets outside it are "
             "refused, the crawler cannot leave it",
    )
    p.add_argument(
        "--fail-on",
        metavar="critical|medium",
        default=None,
        help="CI gate: exit code 3 when findings at this level exist",
    )
    p.add_argument(
        "--no-color",
        action="store_true",
        help="Disable colored output (for CI logs)",
    )
    p.add_argument(
        "--insecure",
        action="store_true",
        help="Disable TLS certificate verification (lab/self-signed only; "
             "prints a warning, verification is ON by default)",
    )
    p.add_argument(
        "--proxy",
        metavar="URL",
        default=None,
        help="HTTP(S) proxy for all requests (e.g. http://127.0.0.1:8080 for Burp/ZAP)",
    )
    p.add_argument(
        "--user-agent",
        metavar="STR",
        default=None,
        help="Custom User-Agent (default identifies as GASH pentest traffic)",
    )
    p.add_argument(
        "--cookie",
        metavar="'a=b; c=d'",
        default=None,
        help="Cookie for authenticated scans (e.g. 'session=abc')",
    )
    p.add_argument(
        "--cookie-b",
        metavar="'a=b'",
        default=None,
        help="Second user's cookie for cross-session checks (IDOR "
             "confirmation). Must differ from --cookie",
    )
    p.add_argument(
        "--header",
        metavar="'K: V'",
        action="append",
        default=None,
        help="Extra HTTP header (repeatable, e.g. 'Authorization: Bearer X')",
    )
    p.add_argument(
        "--header-b",
        metavar="'K: V'",
        action="append",
        default=None,
        help="Second user's extra header (with --cookie-b, cross-session)",
    )
    p.add_argument(
        "--login-user",
        metavar="USER",
        default=None,
        help="Username for auto-login (with --login-pass)",
    )
    p.add_argument(
        "--login-pass",
        metavar="PASS",
        default=None,
        help="Password for auto-login (falls back to GASH_LOGIN_PASS env or "
             "an interactive prompt; safer than typing it on the command line)",
    )
    p.add_argument(
        "--login-url",
        metavar="URL",
        default=None,
        help="Login form address (searched on the target when empty)",
    )
    p.add_argument(
        "--blind-callback",
        metavar="HOST",
        default=None,
        help="External listener for Blind XSS canaries (e.g. abc.interact.sh). "
             "No blind notes are produced without one",
    )
    p.add_argument(
        "--oob",
        action="store_true",
        help="Automatic out-of-band verification (Blind XSS + SSRF) via an "
             "interactsh server. Needs the 'cryptography' package",
    )
    p.add_argument(
        "--oob-server",
        metavar="URL",
        default=None,
        help="Interactsh server URL (default: https://interact.sh). "
             "Self-host for sensitive targets",
    )
    p.add_argument(
        "--oob-wait",
        type=int,
        default=20,
        metavar="SEC",
        help="Seconds to wait for OOB callbacks per scan (default: 20)",
    )
    p.add_argument(
        "--delay",
        type=float,
        default=0.0,
        metavar="SEC",
        help="Delay between requests in seconds (polite scanning, e.g. 0.2)",
    )
    p.add_argument(
        "--max-requests",
        type=int,
        default=0,
        metavar="N",
        help="Total HTTP request budget (0=unlimited, e.g. 500)",
    )
    p.add_argument(
        "--skip-checks",
        metavar="sqli-blind,ssti",
        default=None,
        help="Checks to skip (comma-separated names, see: --list-checks)",
    )
    p.add_argument(
        "--list-checks",
        action="store_true",
        help="List registered checks and exit",
    )
    p.add_argument(
        "--profile",
        metavar="quick|balanced|thorough",
        default="balanced",
        help="Coverage profile: quick (4 pages), balanced (8, default) or "
             "thorough (30 pages, deeper crawl, larger XSS pool). Explicit "
             "--max-pages/--depth/--max-xss-urls override the profile",
    )
    p.add_argument(
        "--max-pages",
        type=int,
        default=None,
        metavar="N",
        help="Crawler page limit (default: profile preset)",
    )
    p.add_argument(
        "--depth",
        type=int,
        default=None,
        metavar="N",
        help="Crawler depth limit (default: profile preset)",
    )
    p.add_argument(
        "--no-crawl",
        action="store_true",
        help="Disable the crawler (given URL only)",
    )
    p.add_argument(
        "--dom",
        action="store_true",
        help="Headless DOM XSS verification (slow; needs Playwright+Chromium)",
    )
    p.add_argument(
        "--spa",
        action="store_true",
        help="SPA runtime discovery: headless read-only pass for JS routes, "
             "forms and API endpoints (needs Playwright+Chromium)",
    )
    p.add_argument(
        "--browser-discovery",
        action="store_true",
        help="Full browser traffic profile: request/WebSocket/SSE capture "
             "(method + URL + content-type) plus client-side route tracking; "
             "feeds the scan pool (needs Playwright+Chromium)",
    )
    p.add_argument(
        "--local",
        action="store_true",
        help="Local machine audit profile: read-only enumeration of "
             "listening services, loopback web panels, secret file "
             "permissions and firewall state (auto-on for "
             "localhost/127.0.0.1/::1 targets)",
    )
    p.add_argument(
        "--max-xss-urls",
        type=int,
        default=None,
        metavar="N",
        help="XSS probe pool limit after prioritization (default: profile preset)",
    )
    p.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Verbose output",
    )
    p.add_argument(
        "--no-banner",
        action="store_true",
        help="Hide the startup logo",
    )
    p.add_argument(
        "--menu",
        action="store_true",
        help="Open the interactive menu (no commands to memorize)",
    )
    p.add_argument(
        "--version",
        action="store_true",
        help="Print version and exit",
    )
    return p


def resolve_mode(args: argparse.Namespace) -> str:
    """Resolve the active mode from flags: recon | scan | full."""
    if args.recon and not args.scan and not args.full:
        return "recon"
    if args.scan and not args.recon and not args.full:
        return "scan"
    # --full, or no flags + a target = full
    # assume full without a target too; main() prints help then
    return "full"


def parse_ports(raw: str | None) -> list[int] | None:
    """'80,443,8080' -> [80,443,8080]. None when garbage."""
    if not raw:
        return None
    out = []
    for part in raw.replace(" ", "").split(","):
        try:
            p = int(part)
            if 1 <= p <= 65535:
                out.append(p)
        except ValueError:
            continue
    return sorted(set(out)) or None

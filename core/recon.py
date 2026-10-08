"""Recon: who is this target.

Resolves the hostname, pulls DNS records, probes common ports in parallel,
and grabs HTTP headers + server banner. Port list is small on purpose.
"""

from __future__ import annotations

import socket
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from urllib.parse import urlparse

from core.colors import success, info, warn, danger, DIM, RESET

# Default web-focused ports for fast scans
DEFAULT_PORTS = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445,
                 3306, 3389, 5900, 8000, 8080, 8443, 8888]

DNS_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "CNAME"]

GASH_UA = "Mozilla/5.0 (compatible; GASH/0.1.0; +authorized-pentest)"


@dataclass
class ReconResult:
    target: str          # raw target as typed
    hostname: str = "?"  # normalized host
    base_url: str = "?"  # URL actually requested
    ip: str = "?"
    all_ips: list = field(default_factory=list)
    dns_records: dict = field(default_factory=dict)
    open_ports: list = field(default_factory=list)   # [80, 443, ...]
    closed_count: int = 0
    headers: dict = field(default_factory=dict)
    server: str = "?"
    status_code: int = 0
    final_url: str = "?"
    elapsed: float = 0.0

    def to_dict(self) -> dict:
        return {"target": self.target, "hostname": self.hostname,
                "base_url": self.base_url, "ip": self.ip,
                "all_ips": self.all_ips, "dns_records": self.dns_records,
                "open_ports": self.open_ports, "closed_count": self.closed_count,
                "headers": self.headers, "server": self.server,
                "status_code": self.status_code, "final_url": self.final_url,
                "elapsed_s": self.elapsed}


# ---------- helpers ----------

def normalize_target(raw: str) -> tuple[str, str]:
    """target.com / http://target.com:8080/x -> (hostname, base_url).

    An explicit port is kept (otherwise 80/443 is assumed).
    """
    raw = raw.strip()
    if "://" not in raw:
        raw = "http://" + raw
    p = urlparse(raw)
    host = p.hostname or raw
    scheme = p.scheme if p.scheme in ("http", "https") else "http"
    port = p.port
    base = f"{scheme}://{host}" + (f":{port}" if port else "")
    path = (p.path or "").rstrip("/")
    if path:
        base += path  # sub-app scope is kept: /app stays /app
    # https upgrade is attempted at fetch time, not here
    return host, base


def history_key(target: str) -> str:
    """History/diff key: host + port + path, so /app and /api on the same
    host don't overwrite each other's history."""
    import re
    try:
        _, base = normalize_target(target)
        key = base.replace("https://", "").replace("http://", "")
    except Exception:
        key = target
    return re.sub(r"[^a-zA-Z0-9.-]", "_", key) or "unknown"


def resolve_ip(hostname: str) -> tuple[str, list]:
    """Primary IP + full IP list. ('?', []) when unresolvable."""
    try:
        primary = socket.gethostbyname(hostname)
    except (socket.gaierror, UnicodeError):
        return "?", []
    try:
        _, _, ips = socket.gethostbyname_ex(hostname)
    except socket.gaierror:
        ips = [primary]
    # dedupe, primary first
    uniq = [primary] + [x for x in dict.fromkeys(ips) if x != primary]
    return primary, uniq


def dns_lookup(hostname: str, timeout: float = 4.0) -> dict:
    """A/AAAA/MX/NS/TXT/CNAME via dnspython. {} on failure, never throws."""
    out: dict = {}
    try:
        import dns.resolver
    except ImportError:
        return {"_note": ["dnspython kurulu degil: pip install dnspython"]}
    try:
        res = dns.resolver.Resolver()
        res.lifetime = timeout
        res.timeout = timeout
    except Exception:
        return {}
    for qtype in DNS_TYPES:
        try:
            answers = res.resolve(hostname, qtype, raise_on_no_answer=False)
            vals = [r.to_text().strip('"') for r in answers]
            if vals:
                out[qtype] = vals
        except Exception:
            continue  # NoAnswer / NXDOMAIN / timeout -> move on quietly
    return out


def _probe_port(ip: str, port: int, timeout: float = 1.5) -> bool:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        return s.connect_ex((ip, port)) == 0
    except Exception:
        return False
    finally:
        s.close()


def scan_ports(ip: str, ports: list[int] | None = None,
               threads: int = 20, timeout: float = 1.5) -> tuple[list, int]:
    """Fast threaded port scan. Returns (open_list, closed_count)."""
    if ip in ("?", "", None):
        return [], 0
    if ports is None:
        ports = DEFAULT_PORTS
    if len(ports) == 0:  # --skip-ports
        return [], 0
    open_ports: list[int] = []
    from core.spinner import spin
    with spin(f"  [*] Probing {len(ports)} ports on {ip}..."):
        with ThreadPoolExecutor(max_workers=max(1, threads)) as ex:
            fut = {ex.submit(_probe_port, ip, p, timeout): p for p in ports}
            for f in as_completed(fut):
                try:
                    if f.result():
                        open_ports.append(fut[f])
                except Exception:
                    pass
    open_ports.sort()
    return open_ports, len(ports) - len(open_ports)


def _scope_ok(url: str, scope: set[str] | None) -> bool:
    """Final-URL scope check. Empty scope means everything is allowed."""
    if not scope:
        return True
    try:
        return (urlparse(url or "").hostname or "").lower() in scope
    except Exception:
        return False


def fetch_headers(base_url: str, timeout: int = 8,
                  auth=None, scope_hosts: set[str] | None = None,
                  ) -> tuple[dict, str, int, str]:
    """(headers_dict, server, status, final_url), with https fallback."""
    import requests
    import urllib3
    from core.net import pace, proxies, user_agent, tls_verify
    if not tls_verify():
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    cookies = getattr(auth, "cookies", None) or {}
    extra = getattr(auth, "headers", None) or {}
    headers = {"User-Agent": user_agent(), **extra}
    candidates = [base_url]
    # http verildiyse https'i de dene (modern siteler https'te)
    if base_url.startswith("http://"):
        candidates.append(base_url.replace("http://", "https://", 1))

    last_err = ""
    for url in candidates:
        try:
            pace()
            r = requests.get(url, headers=headers, cookies=cookies or None,
                             timeout=timeout, allow_redirects=True,
                             verify=tls_verify(), proxies=proxies() or None)
            if not _scope_ok(r.url, scope_hosts):
                last_err = f"redirect left scope: {r.url[:80]}"
                continue
            hdrs = dict(r.headers)
            server = hdrs.get("Server", "?")
            powered = hdrs.get("X-Powered-By")
            if powered and powered not in server:
                server = f"{server} | X-Powered-By: {powered}"
            return hdrs, server, r.status_code, r.url
        except Exception as e:  # connection/timeout/SSL -> next candidate
            last_err = str(e)[:120]
            continue
    return {}, f"? ({last_err or 'unreachable'})", 0, base_url


# ---------- main engine ----------

def run_recon(target: str, ports: list[int] | None = None,
              threads: int = 20, timeout: int = 8,
              verbose: bool = False,
              auth=None, scope_hosts: set[str] | None = None) -> ReconResult:
    t0 = time.time()
    hostname, base_url = normalize_target(target)
    res = ReconResult(target=target, hostname=hostname, base_url=base_url)

    res.ip, res.all_ips = resolve_ip(hostname)
    res.dns_records = dns_lookup(hostname)
    if res.ip != "?":
        # port timeout is independent of HTTP timeout, keep it short
        res.open_ports, res.closed_count = scan_ports(
            res.ip, ports=ports, threads=threads, timeout=min(2.0, max(1.0, timeout / 4)))
    res.headers, res.server, res.status_code, res.final_url = fetch_headers(
        base_url, timeout, auth, scope_hosts)

    res.elapsed = round(time.time() - t0, 2)
    return res


def print_recon(r: ReconResult, verbose: bool = False) -> None:
    print(success(f"\n[+] RECON -> {r.hostname}  ({r.elapsed}s)"))
    print(f"  {info('Target URL')} : {r.base_url}")
    print(f"  {info('IP        ')} : {r.ip}", end="")
    if len(r.all_ips) > 1:
        print(f"  {DIM}(all: {', '.join(r.all_ips[:5])}){RESET}")
    else:
        print()
    print(f"  {info('Final URL ')} : {r.final_url}  [HTTP {r.status_code}]" if r.status_code else
          f"  {info('Final URL ')} : {r.final_url}  {danger('[UNREACHABLE]')}")
    print(f"  {info('Server    ')} : {r.server}")

    # DNS
    print(info("\n  [DNS Records]"))
    if r.dns_records:
        for k in DNS_TYPES + ["_note"]:
            if k in r.dns_records:
                vals = r.dns_records[k]
                shown = vals[:4] + (["..."] if len(vals) > 4 else [])
                print(f"    {k:<6}: {', '.join(shown)}")
    else:
        print(f"    {warn('no records / timeout')}")

    # Ports
    print(info("\n  [Open Ports]"))
    if r.open_ports:
        print(f"    {success(str(r.open_ports))}  ({len(r.open_ports)} open / {r.closed_count} closed)")
        if 80 in r.open_ports or 443 in r.open_ports:
            print(f"    {DIM}web service up{RESET}")
    elif r.ip == "?":
        print(f"    {danger('IP unresolved, port scan skipped')}")
    elif r.closed_count == 0:
        print(f"    {DIM}port scan skipped (--skip-ports){RESET}")
    else:
        print(f"    {DIM}no open ports in the common list{RESET}")

    # Headers
    print(info("\n  [HTTP Headers]"))
    if r.headers:
        interesting = ["Server", "X-Powered-By", "X-AspNet-Version",
                       "Content-Type", "Set-Cookie", "Strict-Transport-Security",
                       "Content-Security-Policy", "X-Frame-Options"]
        for k in interesting:
            if k in r.headers:
                v = str(r.headers[k])[:100]
                print(f"    {k}: {v}")
        if verbose:
            rest = {k: v for k, v in r.headers.items() if k not in interesting}
            for k, v in list(rest.items())[:15]:
                print(f"    {DIM}{k}: {str(v)[:90]}{RESET}")
        missing = [h for h in ["Strict-Transport-Security", "Content-Security-Policy",
                               "X-Frame-Options"] if h not in r.headers]
        if missing:
            print(f"    {warn('Missing security headers: ' + ', '.join(missing))}")
    else:
        print(f"    {danger('no headers (site may be unreachable)')}")
    print()

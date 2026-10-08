"""Local machine audit profile — read-only enumeration, no changes.

Triggers when the target is loopback (localhost/127.0.0.1/::1) or with
an explicit --local. Only the collectors run here; verdicts are small
and conservative (a loopback-bound panel is correct, a 0.0.0.0 debug
port is not). Secret files are never read — only existence + POSIX
permission bits are inspected, content stays on disk.

All collectors degrade to notes instead of raising; platform specifics
(Linux /proc, Windows netstat/netsh) are best-effort with a connect-scan
fallback that works everywhere with stdlib only.
"""

from __future__ import annotations

import os
import re
import socket as _socket
from pathlib import Path

# All-interfaces marker for comparisons only (never bound here).
ALL_INTERFACES = "0.0.0.0"  # nosec B104
LOOPBACK_HOSTS = {"localhost", "127.0.0.1", "::1", ALL_INTERFACES}

# Fast localhost TCP sweep when nothing better exists.
LOCAL_PORTS = [22, 80, 135, 137, 138, 139, 443, 445, 1433, 1521,
               3000, 3306, 3389, 4000, 4200, 5000, 5432, 5601, 5900,
               6379, 8000, 8080, 8443, 8888, 9000, 9090, 9200, 27017]

# (filename,.fix, where) — content is NEVER read.
SECRET_FILES = [
    (".env", "cwd", "environment file"),
    (".env.local", "cwd", "environment file"),
    ("id_rsa", ".ssh", "SSH private key"),
    ("id_ed25519", ".ssh", "SSH private key"),
    ("credentials", ".aws", "AWS credentials"),
    ("config", ".aws", "AWS config (may hold keys)"),
]

DEV_MARKERS = [
    ("webpack", ["webpack", "hmr"]),
    ("vite", ["vite", "@vite/client"]),
    ("nextjs", ["_next/static", "__next_data__"]),
    ("django-debug", ["django", "debug=true"]),
    ("phpinfo", ["phpinfo", "php version"]),
    ("admin-panel", ["admin", "dashboard"]),
]

LISTEN_STATE = "0A"  # /proc/net/tcp state for LISTEN


def is_local_target(host: str, force: bool = False) -> bool:
    """Loopback names/IPs, or an explicit --local from the operator."""
    if force:
        return True
    try:
        return (host or "").lower().strip(".") in LOOPBACK_HOSTS
    except Exception:
        return False


def tcp_scan_localhost(ports=None, timeout: float = 0.4) -> list[int]:
    """Stdlib connect sweep of 127.0.0.1. Returns open ports."""
    found: list[int] = []
    for port in ports or LOCAL_PORTS:
        try:
            s = _socket.create_connection(("127.0.0.1", int(port)),
                                          timeout=timeout)
        except Exception:
            continue
        try:
            s.close()
        except Exception:
            pass
        found.append(int(port))
    return found


def parse_proc_net_tcp(text: str) -> list[dict]:
    """Linux /proc/net/tcp{,6} -> [{ip, port, state, inode}]. Pure."""
    out: list[dict] = []
    for line in (text or "").splitlines()[1:]:
        parts = line.split()
        if len(parts) < 10:
            continue
        try:
            ip_hex, port_hex = parts[1].rsplit(":", 1)
            ip = ".".join(str(int(ip_hex[i:i + 2], 16))
                          for i in (6, 4, 2, 0))
            out.append({"ip": ip, "port": int(port_hex, 16),
                        "state": parts[3].upper(),
                        "inode": parts[9]})
        except Exception:
            continue
    return out


def map_inodes_to_processes(resolver=None) -> dict[str, str]:
    """socket:[inode] -> 'pid/comm' via /proc/*/fd. Best-effort, guarded."""
    resolve = resolver or os.readlink
    mapping: dict[str, str] = {}
    proc = Path("/proc")
    if not proc.is_dir():
        return mapping
    try:
        pids = [p for p in proc.iterdir() if p.name.isdigit()]
    except Exception:
        return mapping
    for pid in pids[:500]:
        try:
            comm = (pid / "comm").read_text(
                encoding="utf-8", errors="ignore").strip()[:40]
        except Exception:
            continue
        fd_dir = pid / "fd"
        if not fd_dir.is_dir():
            continue
        try:
            fds = list(fd_dir.iterdir())[:256]
        except Exception:
            continue
        for fd in fds:
            try:
                target = resolve(fd)
            except Exception:
                continue
            m = re.fullmatch(r"socket:\[(\d+)\]", str(target or ""))
            if m and m.group(1) not in mapping:
                mapping[m.group(1)] = f"{pid.name}/{comm}"
    return mapping


NETSTAT_TCP_RE = re.compile(
    r"^\s*TCP\s+(\S+):(\d+)\s+\S+\s+\S+\s+(\d+)\s*$", re.I)


def parse_windows_netstat(text: str) -> list[dict]:
    """`netstat -ano` lines -> [{ip, port, pid}]. Pure, LISTEN assumed by
    caller context (use -ano with state filter upstream)."""
    out: list[dict] = []
    for line in (text or "").splitlines():
        m = NETSTAT_TCP_RE.match(line or "")
        if not m:
            continue
        ip = m.group(1).strip("[]")
        try:
            out.append({"ip": ip, "port": int(m.group(2)),
                        "pid": m.group(3)})
        except Exception:
            continue
    return out


def collect_listening(timeout: float = 0.4) -> list[dict]:
    """[{ip, port, process}] best-effort: /proc, netstat, else connect-scan.

    Never raises; worst case returns connect-scan ports with process '?'.
    """
    import sys
    found: list[dict] = []
    try:
        if sys.platform.startswith("linux"):
            blob = ""
            for name in ("tcp", "tcp6"):
                try:
                    blob += Path(f"/proc/net/{name}").read_text(
                        encoding="utf-8", errors="ignore")
                except Exception:
                    pass
            if blob:
                entries = [e for e in parse_proc_net_tcp(blob)
                           if e.get("state") == LISTEN_STATE]
                procs = map_inodes_to_processes()
                for e in entries:
                    found.append({"ip": e["ip"], "port": e["port"],
                                  "process": procs.get(e["inode"], "?")})
                if found:
                    return found[:64]
        elif sys.platform.startswith("win"):
            import subprocess
            try:
                proc = subprocess.run(
                    ["netstat", "-ano", "-p", "TCP"], capture_output=True,
                    text=True, timeout=15)
                for e in parse_windows_netstat(proc.stdout or ""):
                    found.append({"ip": e["ip"], "port": e["port"],
                                  "process": f"pid:{e['pid']}"})
                if found:
                    return found[:64]
            except Exception:
                pass
    except Exception:
        pass
    for port in tcp_scan_localhost(timeout=timeout):
        found.append({"ip": "127.0.0.1", "port": port, "process": "?"})
    return found[:64]


def secret_file_status(home: str | None = None,
                       cwd: str | None = None) -> list[dict]:
    """Existence + POSIX other/group-read bits for known secret paths.

    Content is never opened. Windows has no POSIX bits -> existence only.
    """
    import sys
    out: list[dict] = []
    try:
        home_p = str(home or Path.home())
    except Exception:
        home_p = ""
    cwd_p = str(cwd or os.getcwd())
    for name, where, kind in SECRET_FILES:
        base = cwd_p if where == "cwd" else (
            os.path.join(home_p, where) if home_p else "")
        if not base:
            continue
        p = Path(os.path.join(base, name))
        try:
            if not p.is_file():
                continue
        except Exception:
            continue
        rec = {"path": str(p), "kind": kind, "broad": False}
        if not sys.platform.startswith("win"):
            try:
                mode = p.stat().st_mode
                rec["broad"] = bool(mode & 0o077)
            except Exception:
                pass
        out.append(rec)
    return out


def classify_dev_banner(body: str, headers: dict | None = None) -> str:
    """webpack/vite/next/debug markers in a localhost banner, or ''."""
    blob = ((body or "")[:4000] + " " + " ".join(
        f"{k}: {v}" for k, v in (headers or {}).items())).lower()
    for name, marks in DEV_MARKERS:
        if any(m in blob for m in marks):
            return name
    return ""


def probe_local_http(port: int, timeout: float = 3.0) -> tuple[str, dict]:
    """GET / on 127.0.0.1:port -> (body, headers). Empty on failure."""
    import http.client
    try:
        conn = http.client.HTTPConnection("127.0.0.1", int(port),
                                          timeout=timeout)
        conn.request("GET", "/")
        resp = conn.getresponse()
        body = resp.read(20000).decode("utf-8", "ignore")
        headers = dict(resp.getheaders() or [])
        try:
            conn.close()
        except Exception:
            pass
        return body, headers
    except Exception:
        return "", {}


def firewall_status() -> str:
    """on|off|unknown — best-effort platform query, never raises."""
    import subprocess
    import sys
    try:
        if sys.platform.startswith("win"):
            proc = subprocess.run(
                ["netsh", "advfirewall", "show", "allprofiles", "state"],
                capture_output=True, text=True, timeout=15)
            states = re.findall(r"State\s+(ON|OFF)",
                                (proc.stdout or "").upper())
            if states and all(s == "ON" for s in states):
                return "on"
            if any(s == "OFF" for s in states):
                return "off"
            return "unknown"
        for cmd in (["ufw", "status"], ["firewall-cmd", "--state"]):
            try:
                proc = subprocess.run(cmd, capture_output=True, text=True,
                                      timeout=10)
                st = ((proc.stdout or "") + (proc.stderr or "")).lower()
                if "active" in st or "running" in st:
                    return "on"
                if "inactive" in st or "not running" in st:
                    return "off"
            except Exception:
                continue
    except Exception:
        pass
    return "unknown"


def container_interfaces() -> list[str]:
    """docker0/vEthernet/WSL-ish interface names present on this host."""
    out: list[str] = []
    try:
        import socket as _s
        names = [n for _, n in _s.if_nameindex()]
    except Exception:
        return out
    for n in names:
        low = (n or "").lower()
        if any(k in low for k in ("docker", "veth", "wsl", "wsl2",
                                  "vethernet", "br-", "vmnet", "virtualbox")):
            out.append(n)
    return out[:10]


def run_local_audit(timeout: float = 3.0) -> list:
    """Full read-only pass -> Finding list (kwargs-only, enriched later)."""
    from core.scanner import Finding
    out: list[Finding] = []
    listeners = collect_listening()
    for e in listeners[:32]:
        port, proc = e.get("port"), e.get("process", "?")
        ip = e.get("ip", "")
        body, headers = probe_local_http(port, timeout=timeout) \
            if ip in ("127.0.0.1", "::1", ALL_INTERFACES, "") else ("", {})
        dev = classify_dev_banner(body, headers) if body else ""
        exposed = ip == ALL_INTERFACES
        if dev and exposed:
            out.append(Finding(
                title="Exposed development server", severity="MEDIUM",
                url=f"http://127.0.0.1:{port}/",
                detail=f"{dev} answers on all interfaces (0.0.0.0:{port}, "
                       f"proc {proc}); bind to loopback or gate it",
                evidence=dev, confidence="Medium"))
        elif dev:
            out.append(Finding(
                title="Local development server (loopback-bound)", severity="INFO",
                url=f"http://127.0.0.1:{port}/",
                detail=f"{dev} on 127.0.0.1:{port} (proc {proc}) — correctly "
                       "bound to loopback, no action",
                evidence=dev, confidence="High"))
    for s in secret_file_status():
        if s["broad"]:
            out.append(Finding(
                title="Overly broad secret file permissions",
                severity="MEDIUM",
                url=s["path"],
                detail=f"{s['kind']} is group/other-readable; tighten to "
                       "0600 (content was not read)",
                evidence=s["kind"], confidence="High"))
        else:
            out.append(Finding(
                title="Secret file present", severity="INFO",
                url=s["path"],
                detail=f"{s['kind']} exists with sane permissions "
                       "(content was not read)",
                evidence=s["kind"], confidence="High"))
    fw = firewall_status()
    if fw == "off":
        out.append(Finding(
            title="Host firewall disabled", severity="LOW",
            url="localhost",
            detail="Host firewall reports off; a listening-service audit "
                   "matters more without it",
            evidence="firewall-off", confidence="Medium"))
    for iface in container_interfaces():
        out.append(Finding(
            title="Container/VM network present", severity="INFO",
            url="localhost",
            detail=f"Virtual interface {iface} exists; containers/WSL guests "
                   "may expose services beyond this audit",
            evidence=iface, confidence="High"))
        break  # one note is enough
    return out

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

# (relpath, base, kind). base: home|cwd|appdata|profile.
# Content is NEVER reported; deep mode only sniffs the shape.
SECRET_PATHS = [
    (".env", "cwd", "environment file"),
    (".env.local", "cwd", "environment file"),
    ("id_rsa", ".ssh", "SSH private key"),
    ("id_ed25519", ".ssh", "SSH private key"),
    ("id_ecdsa", ".ssh", "SSH private key"),
    ("credentials", ".aws", "AWS credentials"),
    ("config", ".aws", "AWS config (may hold keys)"),
    ("accessTokens.json", ".azure", "Azure access tokens"),
    ("azureProfile.json", ".azure", "Azure profile"),
    ("config", ".kube", "Kubernetes config"),
    ("config.json", ".docker", "Docker registry auth"),
    (".npmrc", "home", "npm auth token"),
    (".git-credentials", "home", "Git credentials"),
    (".gitconfig", "home", "Git config"),
    ("credentials", "git", "Git credentials store"),
    ("_netrc", "home", "netrc credentials"),
]
SECRET_GLOBS = [
    (".env.*", "cwd", "environment file"),
]
# shape fingerprints (deep only, first bytes classified, never stored)
SECRET_SHAPES = [
    ("PEM private key", ("-----BEGIN", "PRIVATE KEY")),
    ("OpenSSH key", ("openssh-key-v1",)),
    ("AWS key id", ("AKIA",)),
    ("JWT", (".",)),
    ("JSON credentials", ('"client_secret"', '"token"', '"auths"')),
]


def _secret_bases(home: str, cwd: str) -> dict[str, str]:
    import sys
    if sys.platform.startswith("win"):
        appdata = os.environ.get("APPDATA", "")
        profile = os.environ.get("USERPROFILE", "") or home
    else:
        appdata = os.environ.get("XDG_CONFIG_HOME", "") or \
            os.path.join(home, ".config")
        profile = home
    return {"home": home, "cwd": cwd, "appdata": appdata,
            "profile": profile}


def _resolve_secret_candidates(home: str, cwd: str) -> list[tuple[str, str]]:
    """(path, kind) for existing files. Globs expanded, capped at 24."""
    bases = _secret_bases(home, cwd)
    out: list[tuple[str, str]] = []
    seen: set[str] = set()

    def _add(p: Path, kind: str) -> None:
        try:
            if p.is_file() and str(p) not in seen:
                seen.add(str(p))
                out.append((str(p), kind))
        except Exception:
            pass

    for rel, base, kind in SECRET_PATHS:
        root = bases.get("home" if base == "home" or base.startswith(".")
                         else base, "")
        if base.startswith("."):
            if not bases.get("home"):
                continue
            _add(Path(bases["home"]) / base / rel, kind)
        elif base == "git":
            if bases.get("home"):
                _add(Path(bases["home"]) / ".config" / "git" / rel, kind)
        elif root:
            _add(Path(root) / rel, kind)
        if len(out) >= 24:
            return out
    for pattern, base, kind in SECRET_GLOBS:
        root = bases.get(base, "")
        if not root:
            continue
        try:
            for p in sorted(Path(root).glob(pattern))[:6]:
                _add(p, kind)
                if len(out) >= 24:
                    return out
        except Exception:
            continue
    return out


def fingerprint_secret_shape(path: str) -> str:
    """First-2KB shape name (PEM/JWT/…). Content never leaves this call."""
    try:
        with open(path, "rb") as f:
            head = f.read(2048).decode("utf-8", "ignore")
    except Exception:
        return ""
    low = head.lower()
    for shape, markers in SECRET_SHAPES:
        if shape == "JWT":
            stripped = head.strip()
            if stripped.count(".") == 2 and len(stripped) > 20 \
                    and re.fullmatch(r"[A-Za-z0-9_=-]+\.[A-Za-z0-9_=-]+\.?[A-Za-z0-9_=-]*",
                                     stripped):
                return shape
            continue
        if all(m.lower() in low for m in markers):
            return shape
    return ""

# Multi-indicator fingerprints: one strong marker decides on its own
# (framework-unique); weak markers need a second independent witness so
# words like "invited" or a lone "admin" never fire alone.
DEV_FINGERPRINTS = [
    {"name": "vite",
     "strong": ["@vite/client", "/@vite/", "vite/dist/client"],
     "weak": ["vite", "__vite", "hmr"]},
    {"name": "webpack",
     "strong": ["__webpack_hmr", "webpack/hot", "webpack-dev-server",
                ".hot-update."],
     "weak": ["webpack", "hot update"]},
    {"name": "nextjs-dev",
     "strong": ["fast refresh", "next-devtools", "__nextjs"],
     "weak": ["_next/static", "__next_data__"]},
    {"name": "nextjs",
     "strong": ["__next_data__"],
     "weak": ["_next/static", "next/router"]},
    {"name": "nuxt",
     "strong": ["__nuxt__", "_nuxt/"],
     "weak": ["nuxt"]},
    {"name": "angular-dev",
     "strong": ["ng-cli", "hmr [", "webpack-dev-server/client"],
     "weak": ["ng-version", "angular"]},
    {"name": "django-debug",
     "strong": ["django-debug-toolbar", "djdt", "technical500"],
     "weak": ["django", "debug=true", "traceback"]},
    {"name": "flask-debug",
     "strong": ["werkzeug", "console is locked", "console locked"],
     "weak": ["flask", "debugger", "traceback"]},
    {"name": "laravel-debug",
     "strong": ["whoops", "laravel debugbar"],
     "weak": ["laravel", "app_debug", "ignition"]},
    {"name": "php-dev-server",
     "strong": ["development server"],
     "weak": ["php/", "php version", "x-powered-by: php"]},
    {"name": "phpinfo",
     "strong": ["phpinfo()"],
     "weak": ["php version", "configuration file (php.ini)"]},
    {"name": "express-dev",
     "strong": ["nodemon"],
     "weak": ["express", "x-powered-by: express", "serve-static"]},
    {"name": "spring-actuator",
     "strong": ["/actuator", "spring boot"],
     "weak": ["spring", "actuator"]},
    {"name": "storybook",
     "strong": ["@storybook", "storybook-preview", "sb-"],
     "weak": ["storybook"]},
    {"name": "jupyter",
     "strong": ["jupyter-notebook", "nbextensions", "jupyterlab"],
     "weak": ["jupyter", "notebook"]},
    {"name": "grafana",
     "strong": ["grafana"],
     "weak": ["grafana/login"]},
    {"name": "api-docs-dev",
     "strong": ["swagger-ui", "redoc", "scalar-docs"],
     "weak": ["openapi", "api-docs"]},
    {"name": "admin-panel",
     "strong": [],
     "weak": ["admin", "dashboard", "login", "manage", "control panel",
              "sign in", "administrator"]},
]


def classify_dev_banner(body: str, headers: dict | None = None) -> str:
    """Best dev-server fingerprint, or ''. Strong wins; weak needs 2."""
    blob = ((body or "")[:4000] + " " + " ".join(
        f"{k}: {v}" for k, v in (headers or {}).items())).lower()
    best, best_n = "", 0
    for fp in DEV_FINGERPRINTS:
        if any(s in blob for s in fp["strong"]):
            return fp["name"]
        n = sum(1 for w in fp["weak"] if w in blob)
        if n > best_n:
            best, best_n = fp["name"], n
    if best_n >= 2:
        return best
    return ""

LISTEN_STATE = "0A"  # /proc/net/tcp state for LISTEN


def _strip_zone(ip: str) -> str:
    """fe80::1%12 -> fe80::1 (zone ids break classification)."""
    return (ip or "").split("%")[0]


def bind_scope(ip: str) -> str:
    """loopback|all|private|public — raw bind class (no firewall merge)."""
    import ipaddress
    raw = _strip_zone(ip or "").strip("[]").lower()
    if raw in ("127.0.0.1", "::1", "localhost"):
        return "loopback"
    if raw == ALL_INTERFACES or raw == "::":
        return "all"
    try:
        addr = ipaddress.ip_address(raw)
    except Exception:
        return "unknown"
    if getattr(addr, "is_loopback", False):
        return "loopback"
    if getattr(addr, "is_private", False):
        return "private"
    return "public"


def ip_version(ip: str) -> str:
    raw = _strip_zone(ip or "").strip("[]")
    if ":" in raw:
        return "IPv6"
    if re.fullmatch(r"\d+\.\d+\.\d+\.\d+", raw or ""):
        return "IPv4"
    return "unknown"


def new_listener(proto: str = "tcp", ip: str = "", port: int = 0,
                 pid: str = "", process: str = "?", exe: str = "",
                 service: str = "", parent: str = "",
                 confidence: str = "low",
                 source: str = "connect-scan") -> dict:
    """One enriched listener record. Keys are stable API for reports."""
    return {"proto": proto, "ip": ip, "port": int(port or 0),
            "pid": str(pid or ""), "process": process or "?",
            "exe": exe or "", "service": service or "",
            "parent": parent or "", "scope": bind_scope(ip),
            "ipver": ip_version(ip), "confidence": confidence,
            "source": source}


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


def _hex_ip(ip_hex: str) -> str:
    """Little-endian /proc hex -> 127.0.0.1 or ::1 / full IPv6."""
    h = (ip_hex or "").upper()
    if len(h) == 8:
        try:
            return ".".join(str(int(h[i:i + 2], 16)) for i in (6, 4, 2, 0))
        except Exception:
            return ip_hex
    if len(h) == 32:
        try:
            words = [h[i:i + 8] for i in range(0, 32, 8)]
            # each 32-bit word is little-endian on the wire
            le = "".join(w[j:j + 2] for w in words for j in (6, 4, 2, 0))
            groups = [le[i:i + 4].lower() for i in range(0, 32, 4)]
            if all(g == "0000" for g in groups):
                return "::"
            if groups[:-1] == ["0000"] * 7 and groups[-1] == "0001":
                return "::1"
            return ":".join(groups)
        except Exception:
            return ip_hex
    return ip_hex


def parse_proc_net_tcp(text: str) -> list[dict]:
    """/proc/net/tcp{,6} -> [{ip, port, state, inode}]. Pure, v4+v6."""
    out: list[dict] = []
    for line in (text or "").splitlines()[1:]:
        parts = line.split()
        if len(parts) < 10:
            continue
        try:
            ip_hex, port_hex = parts[1].rsplit(":", 1)
            out.append({"ip": _hex_ip(ip_hex), "port": int(port_hex, 16),
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


def _proc_status(pid: str) -> tuple[str, str]:
    """(ppid, parent_comm) from /proc/<pid>/status. ('','') on failure."""
    try:
        text = (Path(f"/proc/{pid}/status")).read_text(
            encoding="utf-8", errors="ignore")
    except Exception:
        return "", ""
    ppid = ""
    pname = ""
    for line in text.splitlines():
        if line.startswith("PPid:"):
            ppid = line.split(":", 1)[1].strip()
        elif line.startswith("Name:"):
            pname = line.split(":", 1)[1].strip()[:40]
    _ = pname  # own name comes from comm; keep the parse honest
    parent_comm = ""
    if ppid.isdigit():
        try:
            parent_comm = (Path(f"/proc/{ppid}/comm")).read_text(
                encoding="utf-8", errors="ignore").strip()[:40]
        except Exception:
            pass
    return ppid, parent_comm


def parse_cgroup_service(text: str) -> str:
    """systemd service (or docker container) owning a process. Pure."""
    for line in (text or "").splitlines():
        m = re.search(r"([\w@.:-]+\.service)", line or "")
        if m:
            return m.group(1)[:80]
        m = re.search(r"/docker/([0-9a-f]{12,64})", line or "")
        if m:
            return "docker/" + m.group(1)[:12]
    return ""


def linux_process_info(pid: str) -> dict:
    """{pid, comm, exe, ppid, parent, service} — all guarded, '' on miss."""
    info = {"pid": str(pid or ""), "comm": "", "exe": "",
            "ppid": "", "parent": "", "service": ""}
    if not str(pid or "").isdigit():
        return info
    base = Path(f"/proc/{pid}")
    try:
        info["comm"] = (base / "comm").read_text(
            encoding="utf-8", errors="ignore").strip()[:40]
    except Exception:
        pass
    try:
        info["exe"] = os.readlink(base / "exe")[:200]
    except Exception:
        pass
    ppid, parent = _proc_status(str(pid))
    info["ppid"], info["parent"] = ppid, parent
    try:
        info["service"] = parse_cgroup_service(
            (base / "cgroup").read_text(encoding="utf-8", errors="ignore"))
    except Exception:
        pass
    return info


NETSTAT_TCP_RE = re.compile(
    r"^\s*TCP\s+(\S+)\s+\S+\s+([A-Z_]+)\s+(\d+)\s*$", re.I)


def _strip_port(endpoint: str) -> tuple[str, int | None]:
    """[::]:443 -> (::, 443); 127.0.0.1:80 -> (127.0.0.1, 80)."""
    m = re.fullmatch(r"\[(.+)\]:(\d+)", endpoint or "")
    if m:
        try:
            return m.group(1), int(m.group(2))
        except Exception:
            return endpoint, None
    if (endpoint or "").count(":") == 1:
        host, _, port = endpoint.partition(":")
        try:
            return host, int(port)
        except Exception:
            return endpoint, None
    return endpoint, None


def parse_windows_netstat(text: str) -> list[dict]:
    """`netstat -ano` lines -> [{ip, port, pid, state}]. Pure.

    State is preserved (LISTENING/ESTABLISHED/TIME_WAIT…); the caller
    decides which states count as listeners. IPv6 `[::]:port` handled.
    """
    out: list[dict] = []
    for line in (text or "").splitlines():
        m = NETSTAT_TCP_RE.match(line or "")
        if not m:
            continue
        ip, port = _strip_port(m.group(1))
        try:
            out.append({"ip": ip.strip("[]"), "port": port,
                        "pid": m.group(3), "state": m.group(2).upper()})
        except Exception:
            continue
    return [e for e in out if e["port"] is not None]


_PS_LISTENERS = (
    "$ErrorActionPreference='SilentlyContinue';"
    "$t=Get-NetTCPConnection -State Listen | "
    "Select-Object LocalAddress,LocalPort,OwningProcess;"
    "$u=Get-NetUDPEndpoint | "
    "Select-Object LocalAddress,LocalPort,OwningProcess;"
    "$p=Get-Process | Select-Object Id,ProcessName,Path;"
    "$s=Get-CimInstance Win32_Service | Select-Object Name,ProcessId;"
    "$w=Get-CimInstance Win32_Process | "
    "Select-Object ProcessId,ParentProcessId;"
    "@{tcp=$t;udp=$u;procs=$p;services=$s;parents=$w} | "
    "ConvertTo-Json -Depth 3 -Compress"
)


def parse_ps_listeners(doc: dict) -> list[dict]:
    """PowerShell JSON dump -> enriched listener records. Pure."""
    out: list[dict] = []

    def _rows(key: str) -> list[dict]:
        try:
            val = (doc or {}).get(key)
        except Exception:
            return []
        if isinstance(val, dict):
            return [val]
        return [r for r in (val or []) if isinstance(r, dict)]

    procs: dict[str, dict] = {}
    for p in _rows("procs"):
        try:
            procs[str(p.get("Id"))] = p
        except Exception:
            continue
    parents: dict[str, str] = {}
    for w in _rows("parents"):
        try:
            parents[str(w.get("ProcessId"))] = str(w.get("ParentProcessId"))
        except Exception:
            continue
    services: dict[str, list[str]] = {}
    for s in _rows("services"):
        try:
            services.setdefault(str(s.get("ProcessId")), []).append(
                str(s.get("Name")))
        except Exception:
            continue
    for key, proto, conf in (("tcp", "tcp", "high"), ("udp", "udp", "low")):
        for r in _rows(key):
            try:
                ip = str(r.get("LocalAddress", ""))
                port = int(r.get("LocalPort", 0))
                pid = str(r.get("OwningProcess", ""))
            except Exception:
                continue
            proc = procs.get(pid, {})
            try:
                name = str(proc.get("ProcessName", "") or "")
                exe = str(proc.get("Path", "") or "")
            except Exception:
                name, exe = "", ""
            ppid = parents.get(pid, "")
            parent = ppid
            try:
                if ppid and ppid in procs:
                    parent = f"{ppid}/{procs[ppid].get('ProcessName', '')}"
            except Exception:
                pass
            out.append(new_listener(
                proto=proto, ip=ip, port=port, pid=pid,
                process=name or f"pid:{pid}", exe=exe[:200],
                service=",".join(services.get(pid, []))[:120],
                parent=parent[:60],
                confidence="medium" if (conf == "high" and not exe)
                else conf,
                source="powershell"))
    return out


def _linux_listeners() -> list[dict]:
    """Enriched records from /proc (tcp/tcp6 LISTEN + udp endpoints)."""
    found: list[dict] = []
    tcp_entries: list[dict] = []
    for name in ("tcp", "tcp6"):
        try:
            text = Path(f"/proc/net/{name}").read_text(
                encoding="utf-8", errors="ignore")
        except Exception:
            continue
        tcp_entries += [e for e in parse_proc_net_tcp(text)
                        if e.get("state") == LISTEN_STATE]
    udp_entries: list[dict] = []
    for name in ("udp", "udp6"):
        try:
            text = Path(f"/proc/net/{name}").read_text(
                encoding="utf-8", errors="ignore")
        except Exception:
            continue
        udp_entries += parse_proc_net_tcp(text)
    if not tcp_entries and not udp_entries:
        return []
    procs = map_inodes_to_processes()
    for e in tcp_entries:
        pidcomm = procs.get(e.get("inode", ""), "?")
        pid = pidcomm.split("/")[0] if "/" in pidcomm else ""
        info = linux_process_info(pid) if pid.isdigit() else {}
        comm = (info.get("comm") if isinstance(info, dict) else "") \
            or (pidcomm if pidcomm != "?" else "?")
        parent = ""
        if isinstance(info, dict) and info.get("ppid"):
            parent = info["ppid"] + (f"/{info['parent']}"
                                     if info.get("parent") else "")
        found.append(new_listener(
            proto="tcp", ip=e.get("ip", ""), port=e.get("port", 0),
            pid=pid, process=comm,
            exe=(info.get("exe", "") if isinstance(info, dict) else ""),
            service=(info.get("service", "") if isinstance(info, dict)
                      else ""),
            parent=parent,
            confidence="high" if pid.isdigit() else "medium",
            source="proc"))
    for e in udp_entries[:32]:
        pidcomm = procs.get(e.get("inode", ""), "?")
        pid = pidcomm.split("/")[0] if "/" in pidcomm else ""
        found.append(new_listener(
            proto="udp", ip=e.get("ip", ""), port=e.get("port", 0),
            pid=pid, process=pidcomm,
            confidence="low", source="proc"))
    return found[:64]


def _windows_listeners() -> list[dict]:
    """PowerShell enrichment first, netstat fallback. Never raises."""
    import json as _json
    import subprocess
    try:
        proc = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command",
             _PS_LISTENERS],
            capture_output=True, text=True, timeout=30)
        doc = _json.loads(proc.stdout or "")
        rows = parse_ps_listeners(doc if isinstance(doc, dict) else {})
        if rows:
            return rows[:64]
    except Exception:
        pass
    found: list[dict] = []
    try:
        proc = subprocess.run(
            ["netstat", "-ano", "-p", "TCP"], capture_output=True,
            text=True, timeout=15)
        for e in parse_windows_netstat(proc.stdout or ""):
            if e.get("state") != "LISTENING":
                continue  # ESTABLISHED/TIME_WAIT are not listeners
            found.append(new_listener(
                proto="tcp", ip=e["ip"], port=e["port"], pid=e["pid"],
                process=f"pid:{e['pid']}", confidence="medium",
                source="netstat"))
        if found:
            return found[:64]
    except Exception:
        pass
    return []


def collect_listening(timeout: float = 0.4) -> list[dict]:
    """Enriched listener records: /proc or PowerShell, else connect-scan.

    Every record carries proto/ip/port/pid/process/exe/service/parent/
    scope/ipver/confidence/source. Fallback rows are explicitly marked
    source="connect-scan" with process "?" — never mistaken for proof.
    """
    import sys
    try:
        if sys.platform.startswith("linux"):
            rows = _linux_listeners()
            if rows:
                return rows
        elif sys.platform.startswith("win"):
            rows = _windows_listeners()
            if rows:
                return rows
    except Exception:
        pass
    found: list[dict] = []
    for port in tcp_scan_localhost(timeout=timeout):
        found.append(new_listener(proto="tcp", ip="127.0.0.1", port=port,
                                  confidence="low", source="connect-scan"))
    return found[:64]


# Broad-identity SIDs (locale-proof: SIDs never translate).
_SID_WORLD = frozenset({"S-1-1-0",  # Everyone
                        "S-1-5-32-545",  # BUILTIN\Users
                        "S-1-5-11"})  # Authenticated Users
_PS_ACL = (
    "$ErrorActionPreference='SilentlyContinue';"
    "$r=@();"
    "foreach($f in $args){"
    "try{$a=Get-Acl -LiteralPath $f;"
    "$o=$a.Owner;"
    "$s=$a.Access | ForEach-Object {"
    "try{$_.IdentityReference.Translate("
    "[System.Security.Principal.SecurityIdentifier]).Value"
    "}catch{$null}};"
    "$r+=[pscustomobject]@{path=$f;owner=$o;sids=@($s)};}catch{}};"
    "$r | ConvertTo-Json -Depth 2 -Compress"
)


def windows_acl_audit(paths: list[str],
                      timeout: int = 20) -> dict[str, dict]:
    """{path: {owner, broad_read, broad_write}} via one PowerShell call.

    SID-based (locale-proof), read-only Get-Acl. {} when PowerShell is
    missing or every lookup fails. Never raises.
    """
    import json as _json
    import subprocess
    import sys
    paths = [p for p in (paths or []) if p][:8]
    if not paths or not sys.platform.startswith("win"):
        return {}
    try:
        proc = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command",
             _PS_ACL] + paths,
            capture_output=True, text=True, timeout=timeout)
    except Exception:
        return {}
    try:
        doc = _json.loads((proc.stdout or "").strip() or "[]")
    except Exception:
        return {}
    rows = doc if isinstance(doc, list) else [doc]
    return _summarize_acl(rows)


def _summarize_acl(rows: list) -> dict[str, dict]:
    """Parsed ACL rows -> {path: owner/broad_*}. Pure (tested offline)."""
    out: dict[str, dict] = {}
    for row in rows or []:
        if not isinstance(row, dict) or not row.get("path"):
            continue
        try:
            sids = {str(s) for s in (row.get("sids") or []) if s}
        except Exception:
            sids = set()
        wide = sids & _SID_WORLD
        out[str(row["path"])] = {
            "owner": str(row.get("owner", ""))[:120],
            # Get-Acl lists granted rights per SID without allow/deny
            # split here: any broad identity present = broad access.
            # Conservative note, not a full effective-access calc.
            "broad_read": bool(wide),
            "broad_write": bool(wide),
        }
    return out


def secret_file_status(home: str | None = None,
                       cwd: str | None = None,
                       deep: bool = False) -> list[dict]:
    """Existence + permission/ACL metadata for known secret paths.

    Content is never opened, except deep mode which sniffs the first-2KB
    shape (PEM/JWT/…) without storing anything. Values are never reported,
    shapes at most. Windows has no POSIX bits -> ACL audit instead.
    """
    import sys
    out: list[dict] = []
    try:
        home_p = str(home or Path.home())
    except Exception:
        home_p = ""
    cwd_p = str(cwd or os.getcwd())
    cands = _resolve_secret_candidates(home_p, cwd_p)
    acl: dict[str, dict] = {}
    if sys.platform.startswith("win"):
        try:
            acl = windows_acl_audit([p for p, _ in cands])
        except Exception:
            acl = {}
    for path, kind in cands:
        rec = {"path": path, "kind": kind, "broad": False, "shape": ""}
        if sys.platform.startswith("win"):
            info = acl.get(path, {})
            rec["broad"] = bool(info.get("broad_read"))
            if info.get("owner"):
                rec["owner"] = info["owner"]
        else:
            try:
                rec["broad"] = bool(Path(path).stat().st_mode & 0o077)
            except Exception:
                pass
        if deep:
            try:
                rec["shape"] = fingerprint_secret_shape(path)
            except Exception:
                pass
        out.append(rec)
    return out


def probe_local_http(port: int, timeout: float = 3.0,
                     host: str = "127.0.0.1") -> tuple[str, dict]:
    """GET / on host:port -> (body, headers). Empty on failure."""
    import http.client
    try:
        conn = http.client.HTTPConnection(str(host or "127.0.0.1"),
                                          int(port), timeout=timeout)
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


# Well-known UDP ports -> service hint (classification only; only DNS
# gets one benign active probe, everything else is port+process based).
UDP_SERVICES = {
    53: "dns", 67: "dhcp-server", 68: "dhcp-client", 69: "tftp",
    123: "ntp", 137: "netbios-ns", 138: "netbios-dgm",
    161: "snmp", 162: "snmp-trap", 500: "ike", 514: "syslog",
    1194: "openvpn", 4500: "ike-nat", 51820: "wireguard",
    5353: "mdns", 1900: "ssdp", 5355: "llmnr",
    27015: "steam", 25565: "minecraft", 19132: "bedrock",
}


def classify_udp_service(port: int, process: str = "") -> str:
    """Port hint (+ game-server process names). '' when unknown."""
    try:
        hint = UDP_SERVICES.get(int(port), "")
    except Exception:
        hint = ""
    if hint:
        return hint
    low = (process or "").lower()
    for name, svc in (("minecraft", "minecraft"), ("srcds", "steam"),
                      ("valheim", "valheim"), ("factorio", "factorio")):
        if name in low:
            return svc
    return ""


def build_dns_query(name: str, qid: int = 0xBEEF) -> bytes:
    """One minimal A-query (RD set). `.invalid.` never resolves upstream
    to anything useful — any DNS-shaped reply proves a server."""
    import struct
    header = struct.pack(">HHHHHH", qid & 0xFFFF, 0x0100, 1, 0, 0, 0)
    question = b"".join(
        bytes([len(part)]) + part.encode("ascii", "ignore")
        for part in (name or "x").strip(".").split(".") if part
    ) + b"\x00" + struct.pack(">HH", 1, 1)
    return header + question


def parse_dns_reply(data: bytes, qid: int = 0xBEEF) -> int | None:
    """RCODE of a reply matching our query id, else None. Pure."""
    try:
        import struct
        if len(data or b"") < 12:
            return None
        rid, flags, qd, _an, _ns, _ar = struct.unpack(">HHHHHH", data[:12])
        if rid != (qid & 0xFFFF) or not (flags & 0x8000) or qd < 1:
            return None
        return flags & 0x000F
    except Exception:
        return None


def probe_dns_server(port: int = 53, timeout: float = 2.0,
                     host: str = "127.0.0.1") -> bool:
    """One benign A-query for a .invalid name; any DNS reply counts.

    Loopback by default, 4s worst case. No version fishing, no zone
    walks — presence only. Never raises.
    """
    import secrets
    import socket as _sock
    qid = secrets.randbits(16)
    pkt = build_dns_query(f"gash-{qid:x}.invalid.", qid)
    try:
        s = _sock.socket(_sock.AF_INET, _sock.SOCK_DGRAM)
        try:
            s.settimeout(timeout)
            s.sendto(pkt, (host, int(port)))
            data, _ = s.recvfrom(512)
        finally:
            try:
                s.close()
            except Exception:
                pass
        return parse_dns_reply(data, qid) is not None
    except Exception:
        return False


# Interface roles for exposure classification (order matters: first
# match wins — vethernet carries both veth+WSL markers, WSL must win).
IFACE_ROLE_HINTS = (
    ("loopback", ("lo", "loopback", "lo0")),
    ("vpn", ("tun", "tap", "wg", "wireguard", "vpn", "pptp", "l2tp",
             "tailscale", "zerotier")),
    ("wsl", ("wsl",)),
    ("docker", ("docker", "veth", "br-")),
    ("vm", ("vmnet", "virtualbox", "vbox", "vmware", "hyper-v",
            "vethernet")),
)


def classify_interface(name: str, ip: str = "") -> str:
    """loopback|vpn|docker|wsl|vm|lan|unknown for one interface."""
    low = (name or "").lower()
    strip = _strip_zone(ip or "").strip("[]").lower()
    if strip in ("127.0.0.1", "::1"):
        return "loopback"
    for role, hints in IFACE_ROLE_HINTS:
        if role == "loopback":
            continue  # handled by address above, not by name
        if any(h in low for h in hints):
            return role
    for role, hints in IFACE_ROLE_HINTS[:1]:
        if any(low == h or low.startswith(h) for h in hints):
            return role
    if strip:
        return "lan"
    return "unknown" if not low else "lan"


def local_interface_map() -> dict[str, str]:
    """{ip: ifname} best-effort (ip addr / ipconfig / getaddrinfo).

    Never raises; loopbacks are always present even when every
    enumeration path fails.
    """
    out: dict[str, str] = {}
    import subprocess
    import sys
    try:
        if sys.platform.startswith("win"):
            proc = subprocess.run(
                ["ipconfig"], capture_output=True, text=True, timeout=15)
            current = ""
            for line in (proc.stdout or "").splitlines():
                if line and not line.startswith((" ", "\t")) \
                        and ":" not in line:
                    current = line.strip()
                m = re.search(r"IPv[46] Address[^\d]*([\da-fA-F.:]+)",
                              line or "")
                if m and current:
                    out[_strip_zone(m.group(1))] = current
        else:
            try:
                proc = subprocess.run(
                    ["ip", "-o", "addr", "show"], capture_output=True,
                    text=True, timeout=15)
                for line in (proc.stdout or "").splitlines():
                    m = re.search(r"^\d+:\s+(\S+)\s+\w+\s+inet6?\s+"
                                  r"([^\s/]+)", line or "")
                    if m:
                        out[_strip_zone(m.group(2))] = m.group(1)
            except Exception:
                pass
            if not out:
                try:
                    import socket as _sock
                    for _fam, _t, _p, _cn, sockaddr in _sock.getaddrinfo(
                            _sock.gethostname(), None):
                        ip = _strip_zone(str(sockaddr[0]))
                        if ip and ip not in out:
                            out[ip] = ""
                except Exception:
                    pass
    except Exception:
        pass
    out.setdefault("127.0.0.1", "lo")
    out.setdefault("::1", "lo")
    return out


def classify_exposure(listener: dict,
                       ifaces: dict | None = None) -> dict:
    """One listener -> {class, confidence, reason}. Pure (no I/O).

    Classes: loopback-only | lan-visible | all-interfaces |
    ipv6-visible | virtual-network-visible | unknown. No severity here —
    exposure_verdict() merges firewall + service sensitivity.
    """
    ip = _strip_zone((listener or {}).get("ip", "") or "")
    proto = (listener or {}).get("proto", "tcp")
    ifmap = ifaces if isinstance(ifaces, dict) else {}
    if ip in ("127.0.0.1", "::1"):
        return {"class": "loopback-only", "confidence": "High",
                "reason": f"{proto} bound to loopback"}
    if ip == ALL_INTERFACES or ip == "::":
        return {"class": "all-interfaces", "confidence": "High",
                "reason": f"{proto} bound to all interfaces"}
    if not ip:
        return {"class": "unknown", "confidence": "Low",
                "reason": "no bind address recorded"}
    if ":" in ip and not ip.startswith("127."):
        role = classify_interface(ifmap.get(ip, ""), ip)
        if role in ("docker", "wsl", "vm", "vpn"):
            return {"class": "virtual-network-visible",
                    "confidence": "Medium",
                    "reason": f"{proto} on {role} address {ip}"}
        return {"class": "ipv6-visible", "confidence": "Medium",
                "reason": f"{proto} on specific IPv6 address {ip}"}
    role = classify_interface(ifmap.get(ip, ""), ip)
    if role == "loopback":
        return {"class": "loopback-only", "confidence": "High",
                "reason": f"{proto} on loopback interface"}
    if role in ("docker", "wsl", "vm", "vpn"):
        return {"class": "virtual-network-visible", "confidence": "Medium",
                "reason": f"{proto} on {role} interface ({ip})"}
    if role == "lan":
        return {"class": "lan-visible", "confidence": "High",
                "reason": f"{proto} on LAN address {ip}"}
    return {"class": "unknown", "confidence": "Low",
            "reason": f"{proto} on unmapped address {ip}"}


def exposure_verdict(exp_class: str, firewall: str,
                     sensitive: bool) -> tuple[str, str, str]:
    """(severity, confidence, note) from exposure + firewall + service.

    Never auto-CRITICAL: even all-interfaces needs a sensitive service
    to reach MEDIUM, and an active firewall softens confidence.
    Non-sensitive loopback/unknown listeners stay INFO at most.
    """
    fw_off = (firewall or "unknown") == "off"
    if exp_class == "loopback-only":
        return ("INFO", "High", "loopback-bound")
    if exp_class in ("lan-visible", "ipv6-visible"):
        if sensitive:
            return ("MEDIUM", "High" if fw_off else "Medium",
                    f"{exp_class}{' + firewall off' if fw_off else ''}")
        return ("INFO", "Medium", f"{exp_class}, not sensitive")
    if exp_class == "all-interfaces":
        if sensitive:
            return ("MEDIUM", "High" if fw_off else "Medium",
                    "all interfaces" + (" + firewall off" if fw_off else ""))
        return ("LOW", "Medium", "all interfaces, not sensitive")
    if exp_class == "virtual-network-visible":
        if sensitive:
            return ("MEDIUM", "Medium",
                    "virtual network (containers/VM/VPN guests may reach it)")
        return ("INFO", "Medium", "virtual network, not sensitive")
    return ("INFO", "Low", "bind scope unknown")


_PUB_PORT_RE = re.compile(
    r"^(?:\[?([^\]]*)\]?:)?(\d+)->(\d+)/(tcp|udp)$", re.I)


def parse_docker_ports(spec: str) -> list[dict]:
    """`0.0.0.0:3000->3000/tcp, ...` -> [{host_ip, host_port,
    container_port, proto}]. Unpublished (`80/tcp`) skipped. Pure."""
    out: list[dict] = []
    for chunk in (spec or "").split(","):
        m = _PUB_PORT_RE.match((chunk or "").strip())
        if not m:
            continue
        try:
            out.append({"host_ip": (m.group(1) or "").strip("[]"),
                        "host_port": int(m.group(2)),
                        "container_port": int(m.group(3)),
                        "proto": m.group(4).lower()})
        except Exception:
            continue
    return out


def parse_docker_ps(text: str) -> list[dict]:
    """`docker ps --format json` (one object per line) -> containers.

    Keeps name/image/state/published ports only. Never raises.
    """
    import json as _json
    out: list[dict] = []
    for line in (text or "").splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            doc = _json.loads(line)
        except Exception:
            continue
        if not isinstance(doc, dict):
            continue
        try:
            out.append({
                "name": str(doc.get("Names", "") or "").lstrip("/"),
                "image": str(doc.get("Image", "") or "")[:120],
                "state": str(doc.get("State", "") or "")[:24],
                "ports": parse_docker_ports(doc.get("Ports", "")),
            })
        except Exception:
            continue
        if len(out) >= 32:
            break
    return out


def docker_containers(timeout: int = 20) -> list[dict]:
    """Live `docker ps` (JSON lines). [] when docker is absent/busy."""
    import subprocess
    try:
        proc = subprocess.run(
            ["docker", "ps", "--format", "json", "--no-trunc"],
            capture_output=True, text=True, timeout=timeout)
    except Exception:
        return []
    try:
        if proc.returncode != 0:
            return []
    except Exception:
        return []
    return parse_docker_ps(proc.stdout or "")


def docker_container_ips(names: list[str], timeout: int = 15) -> dict:
    """Container name -> first bridge IP via `docker inspect`. Capped.

    One CLI call for all names (not N calls). [] on any failure.
    """
    import subprocess
    names = [n for n in (names or []) if n][:5]
    if not names:
        return {}
    try:
        proc = subprocess.run(
            ["docker", "inspect", "--format",
             "{{.Name}} {{range .NetworkSettings.Networks}}{{.IPAddress}} "
             "{{end}}"] + names,
            capture_output=True, text=True, timeout=timeout)
    except Exception:
        return {}
    out: dict[str, str] = {}
    try:
        for line in (proc.stdout or "").splitlines():
            parts = line.strip().split()
            if len(parts) >= 2 and parts[1].count(".") == 3:
                out[parts[0].lstrip("/")] = parts[1]
    except Exception:
        pass
    return out


def parse_wsl_portproxy(text: str) -> list[dict]:
    """`netsh interface portproxy show all` -> [{listen, connect}]. Pure.

    Address and port are separate columns; header/separator lines never
    match the IP + numeric-port shape.
    """
    out: list[dict] = []
    for line in (text or "").splitlines():
        parts = (line or "").split()
        if len(parts) >= 4 and re.fullmatch(r"[\da-fA-F.:]+", parts[0]) \
                and parts[1].isdigit() and parts[3].isdigit():
            try:
                out.append({
                    "listen": f"{parts[0]}:{parts[1]}",
                    "listen_port": int(parts[1]),
                    "connect": f"{parts[2]}:{parts[3]}"})
            except Exception:
                continue
        if len(out) >= 16:
            break
    return out


def wsl_forwardings(timeout: int = 15) -> list[dict]:
    """WSL/Windows portproxy forwards. [] when absent (incl. non-Windows)."""
    import subprocess
    import sys
    if not sys.platform.startswith("win"):
        return []
    try:
        proc = subprocess.run(
            ["netsh", "interface", "portproxy", "show", "all"],
            capture_output=True, text=True, timeout=timeout)
    except Exception:
        return []
    return parse_wsl_portproxy(proc.stdout or "")


def docker_graph(listeners: list[dict], containers: list[dict],
                 ips: dict | None = None) -> list[dict]:
    """Join published ports onto the listener inventory.

    Each row: {host, container, image, service, exposure}. Pure.
    """
    ips = ips if isinstance(ips, dict) else {}
    by_port: dict[tuple[str, int], dict] = {}
    for e in listeners or []:
        try:
            by_port[(str(e.get("ip", "")),
                     int(e.get("port") or 0))] = e
        except Exception:
            continue
    rows: list[dict] = []
    for c in containers or []:
        for pub in c.get("ports", []) or []:
            try:
                host_ip = pub.get("host_ip") or ALL_INTERFACES
                host_port = int(pub.get("host_port") or 0)
            except Exception:
                continue
            match = by_port.get((host_ip, host_port))
            if match is None and host_ip in ("", ALL_INTERFACES):
                match = (by_port.get(("127.0.0.1", host_port))
                         or by_port.get(("::1", host_port)))
            exp = classify_exposure(
                match if match is not None
                else {"ip": host_ip, "proto": pub.get("proto", "tcp")},
                None)
            rows.append({
                "host": f"{host_ip}:{host_port}",
                "container": ips.get(c.get("name", ""),
                                     c.get("name", "")),
                "image": c.get("image", ""),
                "service": (match or {}).get("process", "?"),
                "exposure": exp["class"],
            })
            if len(rows) >= 16:
                return rows
    return rows


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

def run_local_audit(timeout: float = 3.0, deep: bool = False,
                    health: dict | None = None) -> list:
    """Full read-only pass -> Finding list (kwargs-only, enriched later).

    Every collector section is guarded: a failing section records its
    name instead of killing the audit. health (when given) receives
    {status: passed|partial|error, errors: [...]} — passed only when
    every section ran, error only when collection itself failed.
    """
    from core.scanner import Finding
    out: list[Finding] = []
    failed: list[str] = []

    def _guard(name: str, fn, default):
        try:
            return fn()
        except Exception as e:
            failed.append(f"{name}:{type(e).__name__}")
            return default

    listeners = _guard("collect",
                       lambda: collect_listening(timeout=timeout), [])
    ifaces = _guard("interfaces", local_interface_map, {})
    fw = _guard("firewall", firewall_status, "unknown")
    n_tcp = sum(1 for e in listeners if e.get("proto") == "tcp")
    n_udp = sum(1 for e in listeners if e.get("proto") == "udp")
    if listeners:
        sample = "; ".join(
            f"{e.get('proto')}/{e.get('ip')}:{e.get('port')}"
            f"({e.get('process', '?')})" for e in listeners[:8])
        out.append(Finding(
            title="Local listeners inventory", severity="INFO",
            url="localhost",
            detail=f"{len(listeners)} listeners seen ({n_tcp} TCP, "
                   f"{n_udp} UDP): {sample}",
            evidence=f"{n_tcp}t/{n_udp}u", confidence="High"))
    for e in listeners[:32]:
        port = e.get("port")
        ip = e.get("ip", "")
        who = e.get("process", "?")
        extra = "".join(f" {k}={e[k]}" for k in ("exe", "service")
                        if e.get(k))
        exp = classify_exposure(e, ifaces)
        # bound address first (a LAN-bound service may not answer on
        # loopback), loopback otherwise; UDP never gets HTTP.
        dial = ip if exp["class"] != "loopback-only" and ip else "127.0.0.1"
        body, headers = probe_local_http(port, timeout=timeout, host=dial) \
            if e.get("proto", "tcp") == "tcp" else ("", {})
        dev = classify_dev_banner(body, headers) if body else ""
        if dev:
            sev, conf, note = exposure_verdict(exp["class"], fw,
                                               sensitive=True)
            if exp["class"] == "loopback-only":
                out.append(Finding(
                    title="Local development server (loopback-bound)",
                    severity="INFO",
                    url=f"http://127.0.0.1:{port}/",
                    detail=f"{dev} on 127.0.0.1:{port} (proc {who}{extra}) — "
                           "correctly bound to loopback, no action",
                    evidence=dev, confidence="High"))
            else:
                out.append(Finding(
                    title="Exposed development server", severity=sev,
                    url=f"http://{dial}:{port}/",
                    detail=f"{dev} beyond loopback ({ip}:{port}, proc "
                           f"{who}{extra}, {exp['class']}, {note}); bind "
                           "to loopback or gate it",
                    evidence=dev, confidence=conf))
    udp_seen: set[str] = set()
    for e in listeners[:32]:
        if e.get("proto") != "udp":
            continue
        try:
            port = int(e.get("port") or 0)
        except Exception:
            continue
        svc = classify_udp_service(port, e.get("process", ""))
        if not svc or svc in udp_seen:
            continue  # unknown stays in the inventory count only
        udp_seen.add(svc)
        exp = classify_exposure(e, ifaces)
        exp_class = exp["class"]
        where = f"{e.get('ip')}:{port}"
        if svc == "dns" and exp_class == "loopback-only":
            alive = probe_dns_server(port, timeout=min(2.0, timeout))
            out.append(Finding(
                title="Local UDP service (DNS)", severity="INFO",
                url=f"udp://127.0.0.1:{port}/",
                detail=f"DNS answers on loopback {where} "
                       f"({'reply verified' if alive else 'port open, no reply'}); "
                       "correctly bound, no action",
                evidence="dns-probe" if alive else "dns-port",
                confidence="High" if alive else "Medium"))
        elif exp_class == "loopback-only":
            out.append(Finding(
                title=f"Local UDP service ({svc.upper()})", severity="INFO",
                url=f"udp://127.0.0.1:{port}/",
                detail=f"{svc} listener on loopback {where} "
                       f"(proc {e.get('process', '?')}); port-classified, "
                       "no packets sent",
                evidence=svc, confidence="Medium"))
        else:
            out.append(Finding(
                title=f"LAN-visible UDP service ({svc.upper()})",
                severity="LOW",
                url=f"udp://{where}/",
                detail=f"{svc} answers beyond loopback ({where}, "
                       f"{exp_class}); confirm it must be reachable off-host",
                evidence=svc, confidence="Medium"))
        if len(udp_seen) >= 3:
            break
    secrets = _guard("secrets", lambda: secret_file_status(deep=deep),
                     [])
    for s in secrets:
        shape = f" (shape: {s['shape']})" if s.get("shape") else ""
        if s["broad"]:
            out.append(Finding(
                title="Overly broad secret file permissions",
                severity="MEDIUM",
                url=s["path"],
                detail=f"{s['kind']} is group/other-readable; tighten to "
                       f"0600 (content was not read{shape})",
                evidence=s["kind"], confidence="High"))
        else:
            out.append(Finding(
                title="Secret file present", severity="INFO",
                url=s["path"],
                detail=f"{s['kind']} exists with sane permissions "
                       f"(content was not read{shape})",
                evidence=s["kind"], confidence="High"))
    if fw == "off":
        out.append(Finding(
            title="Host firewall disabled", severity="LOW",
            url="localhost",
            detail="Host firewall reports off; a listening-service audit "
                   "matters more without it",
            evidence="firewall-off", confidence="Medium"))
    cifaces = _guard("containers", container_interfaces, [])
    for iface in cifaces:
        out.append(Finding(
            title="Container/VM network present", severity="INFO",
            url="localhost",
            detail=f"Virtual interface {iface} exists; containers/WSL guests "
                   "may expose services beyond this audit",
            evidence=iface, confidence="High"))
        break  # one note is enough
    containers = _guard("docker", docker_containers, [])
    if containers:
        ips = _guard("inspect", lambda: docker_container_ips(
            [c.get("name", "") for c in containers]), {})
        for row in docker_graph(listeners, containers, ips)[:4]:
            exp = row.get("exposure", "")
            sev = "MEDIUM" if exp in ("all-interfaces", "lan-visible",
                                      "ipv6-visible") else "INFO"
            out.append(Finding(
                title="Container published port", severity=sev,
                url=f"localhost:{row['host'].rsplit(':', 1)[-1]}",
                detail=f"host {row['host']} -> container {row['container']} "
                       f"({row['image'] or 'image?'}, service "
                       f"{row['service']}, exposure {exp})",
                evidence=row["host"], confidence="High"))
    # docker CLI absent/busy: the interface note above already covers
    # presence; nothing mappable, stay quiet (graceful degrade).
    forwards = _guard("wsl", wsl_forwardings, [])
    for fw_ in forwards[:2]:
        out.append(Finding(
            title="WSL port forwarding", severity="INFO",
            url="localhost",
            detail=f"portproxy {fw_['listen']} -> {fw_['connect']}; "
                   "traffic into WSL guests bypasses this host audit",
            evidence=fw_["listen"], confidence="High"))
    if health is not None:
        try:
            health["errors"] = list(failed)
            health["status"] = ("error" if any(
                f.startswith("collect:") for f in failed)
                else ("partial" if failed else "passed"))
        except Exception:
            pass
    return out

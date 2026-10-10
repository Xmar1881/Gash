"""Local attack-surface bench: environments x expectations.

Web lab (bench/lab.py) covers remote checks; this matrix covers the
local profile with faked collectors (no real sockets/files except tmp
secret fixtures). Contract per environment:

- vulnerable -> the MEDIUM/LOW finding appears,
- safe       -> only INFO (or silence),
- unknown    -> INFO/PARTIAL at most, never a crash.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

VITE = ("<script src='/@vite/client'></script><div>vite hmr</div>", {})
NEXT = ("<div id='__NEXT_DATA__'>x</div><div>Fast Refresh on</div>", {})
ADMIN = ("<title>Admin dashboard login</title>", {})


def _run(monkeypatch, listeners=None, banners=None, secrets=None,
         fw="unknown", ifaces=None, containers=None, wsl=()):
    import core.localaudit as L
    banners = banners or {}
    monkeypatch.setattr(L, "collect_listening",
                        lambda timeout=3.0: list(listeners or []))
    monkeypatch.setattr(
        L, "probe_local_http",
        lambda port, timeout=3.0, host="127.0.0.1": banners.get(port, ("", {})))
    monkeypatch.setattr(L, "secret_file_status", lambda **k: list(secrets or []))
    monkeypatch.setattr(L, "firewall_status", lambda: fw)
    monkeypatch.setattr(L, "local_interface_map", lambda: dict(ifaces or {}))
    monkeypatch.setattr(L, "container_interfaces", lambda: [])
    monkeypatch.setattr(L, "docker_containers", lambda **k: list(containers or []))
    monkeypatch.setattr(L, "docker_container_ips", lambda names, **k: {})
    monkeypatch.setattr(L, "wsl_forwardings", lambda **k: list(wsl))
    return L.run_local_audit()


def _tcp(ip, port, proc="node"):
    import core.localaudit as L
    return L.new_listener(proto="tcp", ip=ip, port=port, process=proc,
                          confidence="high", source="proc")


def _titles(out):
    return [f.title for f in out]


def test_loopback_dev_is_info(monkeypatch):
    out = _run(monkeypatch, listeners=[_tcp("127.0.0.1", 5173)],
               banners={5173: VITE})
    assert "Local development server (loopback-bound)" in _titles(out)
    assert "Exposed development server" not in _titles(out)


def test_all_interfaces_dev_is_medium(monkeypatch):
    out = _run(monkeypatch, listeners=[_tcp("0.0.0.0", 5173)],
               banners={5173: VITE})
    hit = next(f for f in out if f.title == "Exposed development server")
    assert hit.severity == "MEDIUM"


def test_ipv6_all_interfaces_dev_is_medium(monkeypatch):
    out = _run(monkeypatch, listeners=[_tcp("::", 3000)],
               banners={3000: NEXT})
    hit = next(f for f in out if f.title == "Exposed development server")
    assert hit.severity == "MEDIUM" and "all-interfaces" in hit.detail


def test_lan_next_dev_is_medium(monkeypatch):
    out = _run(monkeypatch, listeners=[_tcp("192.168.1.5", 3000)],
               banners={3000: NEXT},
               ifaces={"192.168.1.5": "eth0"})
    hit = next(f for f in out if f.title == "Exposed development server")
    assert hit.severity == "MEDIUM" and "lan-visible" in hit.detail


def test_open_local_admin_is_medium(monkeypatch):
    out = _run(monkeypatch, listeners=[_tcp("0.0.0.0", 8080)],
               banners={8080: ADMIN})
    hit = next(f for f in out if f.title == "Exposed development server")
    assert hit.severity == "MEDIUM" and "admin-panel" in hit.detail


def test_udp_dns_and_mdns(monkeypatch):
    import core.localaudit as L
    monkeypatch.setattr(L, "probe_dns_server", lambda *a, **k: True)
    out = _run(monkeypatch, listeners=[
        L.new_listener(proto="udp", ip="127.0.0.1", port=53,
                       confidence="low", source="proc"),
        L.new_listener(proto="udp", ip="192.168.1.5", port=5353,
                       confidence="low", source="proc"),
    ], ifaces={"192.168.1.5": "eth0"})
    assert "Local UDP service (DNS)" in _titles(out)
    assert "LAN-visible UDP service (MDNS)" in _titles(out)


def test_fake_docker_published_service(monkeypatch):
    out = _run(monkeypatch,
               listeners=[_tcp("0.0.0.0", 3000, proc="docker-proxy")],
               banners={3000: VITE},
               containers=[{"name": "webapp", "image": "node:20",
                             "state": "running",
                             "ports": [{"host_ip": "0.0.0.0",
                                        "host_port": 3000,
                                        "container_port": 3000,
                                        "proto": "tcp"}]}])
    hit = next(f for f in out if f.title == "Container published port")
    assert hit.severity == "MEDIUM" and "webapp" in hit.detail


def test_secret_permissions_matrix(tmp_path, monkeypatch):
    broad = tmp_path / "broad.env"
    broad.write_text("K=V", encoding="utf-8")
    safe = tmp_path / "safe.env"
    safe.write_text("K=V", encoding="utf-8")
    import os
    try:
        os.chmod(broad, 0o644)
        os.chmod(safe, 0o600)
    except Exception:
        pass
    out = _run(monkeypatch, secrets=[
        {"path": str(broad), "kind": "environment file", "broad": True},
        {"path": str(safe), "kind": "environment file", "broad": False},
    ])
    titles = _titles(out)
    assert "Overly broad secret file permissions" in titles
    assert "Secret file present" in titles


def test_firewall_matrix(monkeypatch):
    on = _run(monkeypatch, fw="on")
    assert "Host firewall disabled" not in _titles(on)
    off = _run(monkeypatch, fw="off")
    hit = next(f for f in off if f.title == "Host firewall disabled")
    assert hit.severity == "LOW"
    unknown = _run(monkeypatch, fw="unknown")
    assert "Host firewall disabled" not in _titles(unknown)


def test_unknown_environment_degrades_gracefully(monkeypatch):
    import core.localaudit as L

    def _boom(*a, **k):
        raise RuntimeError("no-proc")

    monkeypatch.setattr(L, "collect_listening", _boom)
    monkeypatch.setattr(L, "secret_file_status", _boom)
    monkeypatch.setattr(L, "firewall_status", _boom)
    monkeypatch.setattr(L, "local_interface_map", _boom)
    monkeypatch.setattr(L, "container_interfaces", _boom)
    monkeypatch.setattr(L, "docker_containers", _boom)
    monkeypatch.setattr(L, "wsl_forwardings", _boom)
    health: dict = {}
    out = L.run_local_audit(health=health)
    assert out == []  # nothing mappable, but no crash either
    assert health["status"] == "error"
    assert any("collect" in e for e in health["errors"])


def test_partial_environment_reports_partial(monkeypatch):
    import core.localaudit as L

    def _boom(*a, **k):
        raise OSError("denied")

    monkeypatch.setattr(L, "secret_file_status", _boom)
    monkeypatch.setattr(L, "firewall_status", lambda: "unknown")
    monkeypatch.setattr(L, "container_interfaces", lambda: [])
    monkeypatch.setattr(L, "docker_containers", lambda **k: [])
    monkeypatch.setattr(L, "wsl_forwardings", lambda **k: [])
    health: dict = {}
    L.run_local_audit(health=health)  # real localhost collectors
    assert health["status"] in ("passed", "partial")
    if health["status"] == "partial":
        assert health["errors"]  # named sections, not silence

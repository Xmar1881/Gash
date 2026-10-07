"""Bulk scan tests — no network."""

import sys
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))


def _args(**kw):
    base = dict(delay=0.0, max_requests=0, cookie=None, header=None,
                login_user=None, login_pass=None, login_url=None,
                timeout=3, skip_ports=True, ports=None, threads=5,
                verbose=False, wordlist=None, quick=False, deep=False,
                skip_checks=None, max_pages=1, depth=1, no_crawl=True,
                dom=False, blind_callback=None, scope=None, fail_on=None,
                resume=False, output=None, output_dir=None)
    base.update(kw)
    return SimpleNamespace(**base)


def _fake_result(target="https://x.test"):
    from gash import ScanResult
    return ScanResult(target=target, recon=None, findings=[],
                      diff={}, elapsed=0.1)


def test_load_targets_file(tmp_path):
    from core.bulk import load_targets_file
    p = tmp_path / "targets.txt"
    p.write_text("https://a.com\n\n# yorum\nhttp://b.com # prod\nhttps://a.com\n",
                 encoding="utf-8")
    assert load_targets_file(str(p)) == ["https://a.com", "http://b.com"]


def test_collect_targets():
    from core.bulk import collect_targets
    assert collect_targets("https://a.com", ["https://a.com", "https://b.com"]) == \
        ["https://a.com", "https://b.com"]
    assert collect_targets(None, []) == []
    assert collect_targets("  ", None) == []


def test_safe_name_and_paths(tmp_path):
    from core.bulk import safe_name, report_path_for, resolve_bulk_ext
    assert safe_name("https://target.com:8080/yol") == "target.com_8080_yol"
    assert safe_name("ornek.com") == "ornek.com"
    assert resolve_bulk_ext("rapor.html") == ".html"
    assert resolve_bulk_ext(None) == ".json"
    rp = report_path_for(str(tmp_path), "https://a.com/", ".html")
    assert rp.endswith("a.com.html")


def test_history_key_splits_paths():
    from core.recon import history_key
    assert history_key("https://h.test/app") != history_key("https://h.test/api")
    assert history_key("https://h.test:8080/") != history_key("https://h.test/")


def test_unreachable_skips_scan(monkeypatch):
    """Recon got HTTP 0 -> scan phase is skipped, not burned for minutes."""
    import gash
    from core.recon import ReconResult
    calls = []

    def fake_recon(*a, **k):
        return ReconResult(target="t", hostname="h", base_url="http://h",
                           status_code=0)

    def fake_scan(*a, **k):
        calls.append(1)
        return []

    monkeypatch.setattr(gash, "run_recon", fake_recon)
    monkeypatch.setattr(gash, "run_scan", fake_scan)
    monkeypatch.setattr(gash, "print_recon", lambda *a, **k: None)
    res = gash._scan_target("http://h.test", _args(), "full", None)
    assert calls == [] and res.findings == [] and res.recon.status_code == 0


def test_cli_bulk_flags():
    from core.cli import build_parser
    a = build_parser().parse_args(["--target-file", "t.txt", "--full",
                                   "--output-dir", "out/", "--resume"])
    assert a.target_file == "t.txt" and a.output_dir == "out/" and a.resume is True


def test_bulk_resume_skip(tmp_path, monkeypatch):
    import gash
    from core.bulk import report_path_for
    out = tmp_path / "raporlar"
    out.mkdir()
    existing = report_path_for(str(out), "https://existing.com", ".json")
    with open(existing, "w", encoding="utf-8") as f:
        f.write("{}")
    calls = []

    def fake_scan(target, args, mode, wordlist):
        calls.append(target)
        return _fake_result(target)

    monkeypatch.setattr(gash, "_scan_target", fake_scan)
    code = gash.run_bulk(["https://existing.com", "https://missing.com"],
                         _args(resume=True), "recon", str(out))
    assert code == 0
    assert calls == ["https://missing.com"]  # existing one skipped


def test_bulk_error_continues(tmp_path, monkeypatch):
    import gash
    out = tmp_path / "raporlar"
    out.mkdir()

    def fake_scan(target, args, mode, wordlist):
        if "bad" in target:
            raise RuntimeError("boom")
        return _fake_result(target)

    monkeypatch.setattr(gash, "_scan_target", fake_scan)
    code = gash.run_bulk(["https://bad.com", "https://good.com"],
                         _args(), "recon", str(out))
    assert code == 1  # 1 error, but it carried on
    import json
    idx = json.loads((out / "bulk_summary.json").read_text(encoding="utf-8"))
    assert idx["total"] == 2
    assert (out / "good.com.json").exists()

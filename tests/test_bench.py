"""Bench scoring tests — pure fixtures, no network/docker (CI-safe)."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))


def _f(title, url="", detail="", evidence=""):
    from core.scanner import Finding
    return Finding(title=title, severity="MEDIUM", url=url, detail=detail,
                   evidence=evidence, confidence="Medium")


def test_load_cases_valid():
    from bench.score import load_cases
    dvwa = load_cases("dvwa")
    assert dvwa["target"] == "dvwa" and len(dvwa["cases"]) >= 4
    juice = load_cases("juice")
    assert juice["target"] == "juice" and len(juice["cases"]) >= 2
    ids = [c["id"] for c in dvwa["cases"]] + [c["id"] for c in juice["cases"]]
    assert len(set(ids)) == len(ids)  # ids unique across targets


def test_matcher_path_and_param():
    from bench.score import match_case
    case = {"id": "x", "kind": "reflected", "path": "/vulnerabilities/xss_r/",
            "param": "name", "vulnerable": True}
    hit = _f("Possible Reflected XSS",
             url="http://h/vulnerabilities/xss_r/?name=gx1",
             detail="ctx html-text", evidence="gx1")
    assert match_case(case, [hit]) == [hit]
    # wrong path -> no match
    other = _f("Possible Reflected XSS",
               url="http://h/other/?name=gx1")
    assert match_case(case, [other]) == []
    # param missing from blob -> no match
    noparam = _f("Possible Reflected XSS",
                 url="http://h/vulnerabilities/xss_r/?id=1")
    assert match_case(case, [noparam]) == []
    # non-XSS titles never match
    info = _f("Admin Panel", url="http://h/vulnerabilities/xss_r/?name=x")
    assert match_case(case, [info]) == []


def test_score_precision_recall():
    from bench.score import score
    cases = [
        {"id": "vuln1", "kind": "reflected", "path": "/a", "param": "q",
         "vulnerable": True},
        {"id": "vuln2", "kind": "stored", "path": "/b", "param": "c",
         "vulnerable": True},
        {"id": "neg1", "kind": "reflected", "path": "/c", "param": "q",
         "vulnerable": False},
    ]
    findings = [_f("Possible Reflected XSS", url="http://h/a?q=gx1",
                   detail="q reflected", evidence="gx1"),
                _f("Stored reflection (unconfirmed)", url="http://h/b",
                   detail="c persists", evidence="c")]
    r = score(cases, findings)
    assert r["recall_detected"] == 1.0
    assert r["recall_confirmed"] == 0.5  # stored only unconfirmed
    assert r["precision_confirmed"] == 1.0  # no FP
    assert r["honesty"]["unconfirmed"] == 1
    assert {c["id"]: c["verdict"] for c in r["per_case"]} == {
        "vuln1": "TP", "vuln2": "detected-unproven", "neg1": "TN"}


def test_score_fp_and_empty_safe():
    from bench.score import score
    cases = [{"id": "neg", "kind": "reflected", "path": "/c", "param": "q",
              "vulnerable": False}]
    r = score(cases, [_f("Possible Reflected XSS", url="http://h/c?q=x",
                          detail="q here", evidence="q")])
    assert r["per_case"][0]["verdict"] == "FP"
    assert r["precision_confirmed"] == 0.0
    assert r["recall_detected"] is None  # no vulnerable cases
    r2 = score([], [])
    assert r2["recall_detected"] is None
    assert r2["precision_confirmed"] is None

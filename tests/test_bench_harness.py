"""Tests for the labeled public-app benchmark harness."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from oniops import bench_harness as bh
from oniops.findings import FindingsLedger


def _f(i, title, status="VERIFIED", evidence="", category="web"):
    return {"id": i, "title": title, "status": status, "evidence": evidence,
            "category": category, "severity": "HIGH"}


def test_bundled_suites_load_and_are_unique():
    suites = bh.list_suites()
    assert {s["id"] for s in suites} >= {"crapi", "juice_shop", "vampi"}
    for s in suites:
        assert s["positives"] > 0


def test_only_verified_findings_count_and_matching_is_one_to_one():
    suite = bh.load_suite("vampi")
    findings = [
        _f(1, "SQL injection on /users/v1/name1"),
        _f(2, "SQL injection on /users/v1/name1 (duplicate)"),
        _f(3, "Cross-user horizontal BOLA on /books/v1/{title}", status="UNCONFIRMED"),
    ]
    r = bh.score(suite, findings)
    cases = {c["case_id"]: c for c in r["positive_cases"]}
    assert cases["sqli_user_lookup"]["detected"]
    assert not cases["bola_books"]["detected"]
    assert cases["bola_books"]["unverified_matches"] == [3]
    assert r["metrics"]["true_positive"] == 1
    # The duplicate is not credited twice; it waits for triage instead.
    assert [t["id"] for t in r["needs_triage"]] == [2]
    assert r["metrics"]["precision_final"] is None
    assert r["metrics"]["precision_min"] == 0.5 and r["metrics"]["precision_max"] == 1.0


def test_triage_finalises_precision_and_negatives_count_as_false_positives():
    suite = bh.load_suite("crapi")
    findings = [
        _f(1, "Cross-user horizontal BOLA on /identity/api/v2/vehicle/{id}/location"),
        _f(2, "SQL injection on /identity/api/auth/login"),        # labeled negative
        _f(3, "Missing security header X-Frame-Options"),
        _f(4, "Exposed HTTP service on port 8888"),                 # informational
    ]
    r = bh.score(suite, findings, triage={3: False})
    m = r["metrics"]
    assert m["true_positive"] == 1
    assert m["false_positive_known"] == 2
    assert m["needs_triage"] == 0
    assert m["precision_final"] == pytest.approx(1 / 3, abs=1e-4)
    assert r["informational"] == [4]
    assert r["negative_cases"][0]["false_alarm"]


def test_narrow_label_is_not_starved_by_broad_label():
    suite = bh.load_suite("juice_shop")
    # verbose_errors (broad) and sqli_product_search (narrow) could both claim finding 1.
    findings = [_f(1, "SQL injection with SQL error on /rest/products/search?q=")]
    r = bh.score(suite, findings)
    cases = {c["case_id"]: c for c in r["positive_cases"]}
    assert cases["sqli_product_search"]["detected"]
    assert not cases["verbose_errors"]["detected"]


def test_malformed_suite_rejected(tmp_path: Path):
    p = tmp_path / "bad.yaml"
    p.write_text("id: x\nname: X\nversion: '1'\npositives:\n  - id: a\n    match: {title: '('}\n")
    with pytest.raises(bh.SuiteError):
        bh.load_suite(p)


def test_cli_scores_ledger_end_to_end(tmp_path: Path, capsys):
    from oniops.cli import cli_main as main
    db = tmp_path / "oniops.sqlite"
    ledger = FindingsLedger(db)
    ledger.upsert(target_ip="10.9.9.9", port=5000,
                       title="SQL injection on /users/v1/admin", category="sqli",
                       severity="HIGH", status="VERIFIED",
                       evidence="sqlite3.OperationalError near \"'\"", repro_cmd="curl ...")
    out = tmp_path / "res.json"
    rc = main(["benchmark", "--suite", "vampi", "--target", "10.9.9.9", "--db", str(db),
               "--output", str(out), "--markdown", "--model-label", "qwen2.5:7b"])
    assert rc == 0
    res = json.loads(out.read_text())
    assert res["metrics"]["true_positive"] == 1
    assert res["model"] == "qwen2.5:7b"
    printed = capsys.readouterr().out
    assert "| VAmPI" in printed and "1/7" in printed

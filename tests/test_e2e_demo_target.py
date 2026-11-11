"""Hermetic end-to-end tests: real OniOps engines against the bundled practice
target on 127.0.0.1, through the loopback-only LocalRunner, scope 127.0.0.1/32.

No LLM, no attack host, no network beyond loopback. Needs the `curl` binary
(the engines build curl argv lists and the LocalRunner executes them as-is).
"""
from __future__ import annotations

import shutil

import pytest

from oniops.agent import _report_finding
from oniops.demo import demo_scope, run_assessment
from oniops.demo_target import USER_A_HEADER, DemoTarget
from oniops.findings import FindingsLedger
from oniops.local_runner import LocalRunner
from oniops.scope import ScopeViolation

pytestmark = pytest.mark.skipif(shutil.which("curl") is None, reason="curl binary not installed")


@pytest.fixture(scope="module")
def assessed(tmp_path_factory):
    """One vulnerable-mode assessment shared by the detection tests."""
    db = tmp_path_factory.mktemp("e2e") / "e2e.sqlite"
    scope = demo_scope()
    runner = LocalRunner(scope)
    ledger = FindingsLedger(db)
    with DemoTarget() as target:
        res = run_assessment(target.ip, target.port, runner, ledger)
        findings = ledger.list_findings(target_ip=target.ip, limit=100)
    return {"res": res, "findings": findings, "ledger": ledger}


@pytest.fixture()
def live(tmp_path):
    """A fresh target + ledger for tests that flip the target to fixed mode."""
    scope = demo_scope()
    runner = LocalRunner(scope)
    ledger = FindingsLedger(tmp_path / "live.sqlite")
    with DemoTarget() as target:
        run_assessment(target.ip, target.port, runner, ledger)
        yield {"target": target, "scope": scope, "runner": runner, "ledger": ledger}


def _find(findings, needle):
    hits = [f for f in findings if needle in f["title"]]
    assert hits, f"no finding containing {needle!r}; got {[f['title'] for f in findings]}"
    return hits[0]


# ── planted weaknesses are found with the expected status / confidence ──────
@pytest.mark.parametrize("needle,status,severity,confidence", [
    ("Exposed HTTP service on port", "VERIFIED", "MEDIUM", "HIGH"),               # W1
    ("Unauthenticated API access on /api/v1/debug/env", "VERIFIED", "HIGH", "HIGH"),  # W2
    ("BOLA/BFLA privilege boundary bypass on /api/v1/users/{id}", "VERIFIED", "HIGH", "HIGH"),  # W3
    ("Cross-user horizontal BOLA on /api/v1/users/{id}", "VERIFIED", "HIGH", "HIGH"),  # W3 peer
    ("BOLA/BFLA privilege boundary bypass on /api/v1/admin/config", "VERIFIED", "HIGH", "HIGH"),  # W4
    ("BOPLA / Mass Assignment risk on PATCH /api/v1/users/{id}", "UNCONFIRMED", "MEDIUM", "LOW"),  # W5
    ("Exposed GraphQL schema introspection on /graphql", "VERIFIED", "MEDIUM", "HIGH"),  # W6
    ("Verbose SQL error disclosed on /api/v1/search", "VERIFIED", "HIGH", "HIGH"),  # W7
    ("Reflected XSS on /api/v1/echo", "VERIFIED", "MEDIUM", "HIGH"),               # W8
])
def test_planted_weakness_found(assessed, needle, status, severity, confidence):
    f = _find(assessed["findings"], needle)
    assert (f["status"], f["severity"], f["confidence"]) == (status, severity, confidence)
    assert f["evidence_sha256"] and f["repro_display"].startswith("curl ")


def test_exact_finding_count(assessed):
    # 9 planted signals, nothing else. Guards against new false positives.
    assert len(assessed["findings"]) == 9


def test_bopla_fields_named(assessed):
    f = _find(assessed["findings"], "BOPLA")
    assert "role" in f["title"] and "is_admin" in f["title"]


# ── secure twins produce NO finding ─────────────────────────────────────────
@pytest.mark.parametrize("twin", ["/api/v1/secrets", "/api/v1/tokens/status", "/api/v1/internal/metrics"])
def test_secure_twin_not_reported(assessed, twin):
    assert not [f for f in assessed["findings"] if twin in f["title"] or twin in f["evidence"]]


def test_secure_twins_seen_and_classified(assessed):
    raw = assessed["res"]["openapi"]["raw_section"]
    assert "[AUTH-ENFORCED] /api/v1/secrets/{id}: unauth=401 -> auth=200" in raw
    assert "[FALSE-POSITIVE-FILTERED] /api/v1/tokens/status" in raw
    assert "/api/v1/internal/metrics: HTTP 403" in raw


def test_public_non_sensitive_routes_not_reported(assessed):
    # /api/v1/search and /api/v1/echo answer 200 anonymously by design; only the
    # input-proof checks (not the access-control diff) may report them.
    for f in assessed["findings"]:
        if "/api/v1/search" in f["title"] or "/api/v1/echo" in f["title"]:
            assert f["category"] in ("sqli", "xss")


def test_agent_report_finding_validator_e2e(tmp_path):
    """agent._report_finding (the agent's independent validator) is deterministic:
    run it directly, no LLM, against a real and a fake claim."""
    scope = demo_scope()
    runner = LocalRunner(scope)
    db = tmp_path / "agent.sqlite"
    with DemoTarget() as t:
        real = _report_finding(runner, t.ip, {"port": t.port, "title": "SQL error", "category": "sqli",
                                              "path": "/api/v1/search?q=%27", "_db_path": str(db)})
        fake = _report_finding(runner, t.ip, {"port": t.port, "title": "Claimed SQLi on secrets",
                                              "category": "sqli", "path": "/api/v1/secrets/1",
                                              "_db_path": str(db)})
    assert "status=VERIFIED" in real
    assert "status=UNCONFIRMED" in fake


# ── zero-token retest ───────────────────────────────────────────────────────
def test_retest_reproduces_then_reports_fixed(live):
    ledger, runner, scope, target = live["ledger"], live["runner"], live["scope"], live["target"]
    f = _find(ledger.list_findings(), "Unauthenticated API access on /api/v1/debug/env")
    r1 = ledger.retest(f["id"], runner, scope)
    assert r1["status"] == "VERIFIED"
    target.set_fixed(True)
    r2 = ledger.retest(f["id"], runner, scope)
    assert r2["status"] == "FIXED"
    assert ledger.get(f["id"])["priority_score"] == 0


def test_retest_service_exposure_still_live(live):
    ledger, runner, scope = live["ledger"], live["runner"], live["scope"]
    f = _find(ledger.list_findings(), "Exposed HTTP service")
    assert ledger.retest(f["id"], runner, scope)["status"] == "VERIFIED"


@pytest.mark.xfail(strict=True, reason=(
    "Real bug: probe_openapi stores repro_cmd for low-priv/peer BOLA/BFLA findings WITHOUT the "
    "low-priv/peer credential (greybox.py), so FindingsLedger.retest replays anonymously, gets 401 "
    "and marks a still-exploitable finding FIXED."))
@pytest.mark.parametrize("needle", [
    "BOLA/BFLA privilege boundary bypass on /api/v1/admin/config",
    "Cross-user horizontal BOLA on /api/v1/users/{id}",
])
def test_retest_bola_reproduces_while_vulnerable(live, needle):
    ledger = live["ledger"]
    f = _find(ledger.list_findings(), needle)
    assert ledger.retest(f["id"], live["runner"], live["scope"])["status"] == "VERIFIED"


def test_bola_still_exploitable_when_retest_says_fixed(live):
    """Evidence for the xfail above: with the low-priv header the same URL is 200."""
    f = _find(live["ledger"].list_findings(), "BOLA/BFLA privilege boundary bypass on /api/v1/admin/config")
    url = f["repro_display"].split()[-1]
    out = live["runner"].run(["curl", "-kisS", "--max-time", "5", "-H", USER_A_HEADER, url]).out
    assert "200" in out.splitlines()[0]


@pytest.mark.xfail(strict=True, reason=(
    "Real bug: FindingsLedger.retest's fallback branch (categories other than service_exposure/"
    "nuclei/api_security) treats any curl output with rc=0 as VERIFIED and does not re-apply the "
    "vuln-proof signature, so sqli/xss findings (also stored by agent._report_finding) never flip "
    "to FIXED after remediation."))
@pytest.mark.parametrize("needle", ["Verbose SQL error", "Reflected XSS"])
def test_retest_input_proof_reports_fixed(live, needle):
    ledger = live["ledger"]
    f = _find(ledger.list_findings(), needle)
    live["target"].set_fixed(True)
    assert ledger.retest(f["id"], live["runner"], live["scope"])["status"] == "FIXED"


@pytest.mark.xfail(strict=True, reason=(
    "Real bug: probe_graphql_introspection's repro_cmd uses `curl -ksS` without -i, so retest's "
    "api_security branch finds no HTTP status line and returns UNCONFIRMED even while the "
    "introspection is still exposed."))
def test_retest_graphql_reproduces(live):
    ledger = live["ledger"]
    f = _find(ledger.list_findings(), "GraphQL")
    assert ledger.retest(f["id"], live["runner"], live["scope"])["status"] == "VERIFIED"


# ── scope / loopback enforcement ────────────────────────────────────────────
def test_out_of_scope_target_refused(live):
    scope, runner = live["scope"], live["runner"]
    with pytest.raises(ScopeViolation):
        scope.resolve("10.0.0.5")
    res = runner.run(["curl", "-ksS", "--max-time", "2", "http://10.0.0.5:80/"])
    assert res.rc == 126 and "10.0.0.5" in res.out
    assert all("10.0.0.5" not in c for c in runner.commands_run)


def test_retest_of_out_of_scope_finding_refused(live):
    ledger = live["ledger"]
    fid = ledger.upsert(target_ip="10.0.0.5", port=80, title="planted out-of-scope row",
                        category="api_security", severity="HIGH", status="VERIFIED",
                        evidence="x", repro_cmd=["curl", "-kisS", "http://10.0.0.5/"])
    with pytest.raises(ScopeViolation):
        ledger.retest(fid, live["runner"], live["scope"])


def test_loopback_alias_outside_scope_refused(live):
    # 127.0.0.2 is loopback but not in the 127.0.0.1/32 demo scope.
    res = live["runner"].run(["curl", "-ksS", "http://127.0.0.2:1/"])
    assert res.rc == 126

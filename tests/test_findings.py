"""Tests for the Proof-First Findings Ledger, secret redaction, and zero-token PoC retest."""
from __future__ import annotations

import pytest

from oniops.findings import (
    FindingsLedger,
    diff_assessments,
    map_finding_coverage,
    redact_secrets,
    validate_evidence,
)
from oniops.graph import compute_attack_paths
from oniops.jobs import JobManager
from oniops.scope import ScopeViolation


def test_redact_secrets_masks_tokens_and_passwords():
    raw = (
        "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.secret\n"
        "Cookie: session_id=abcdef1234567890\n"
        "key = sk-proj1234567890abcdef and ghp_1234567890abcdef123456\n"
        "password=supersecretpass!"
    )
    redacted = redact_secrets(raw)
    assert "eyJhbGci" not in redacted
    assert "[REDACTED-TOKEN]" in redacted
    assert "[REDACTED-COOKIE]" in redacted
    assert "sk-[REDACTED]" in redacted
    assert "gh_[REDACTED]" in redacted
    assert "supersecretpass" not in redacted


def test_ledger_upsert_deduplicates_and_retests(tmp_path, scope):
    db = tmp_path / "oniops.sqlite"
    ledger = FindingsLedger(db)

    fid1 = ledger.upsert(
        target_ip="10.0.0.150",
        port=80,
        title="Exposed HTTP service on port 80",
        category="service_exposure",
        severity="MEDIUM",
        status="VERIFIED",
        evidence="HTTP/1.1 200 OK | Authorization: Bearer secret123456789",
        repro_cmd=["curl", "-kIsS", "http://10.0.0.150:80"],
    )
    # Upserting same (target_ip, port, title) updates in place.
    fid2 = ledger.upsert(
        target_ip="10.0.0.150",
        port=80,
        title="Exposed HTTP service on port 80",
        category="service_exposure",
        severity="HIGH",
        status="VERIFIED",
        evidence="HTTP/1.1 200 OK",
        repro_cmd=["curl", "-kIsS", "http://10.0.0.150:80"],
    )
    assert fid1 == fid2
    items = ledger.list_findings("10.0.0.150")
    assert len(items) == 1
    assert items[0]["severity"] == "HIGH"
    assert "secret123456789" not in items[0]["evidence"]
    assert len(items[0]["evidence_sha256"]) == 64

    # Zero-token retest: simulate target returning 401 (now AUTH-GATED) then closed (FIXED).
    class _StubRunner:
        def __init__(self, out: str):
            self.out = out

        def run(self, cmd, timeout=30):
            class _R:
                ok = True
                out = self.out
            return _R()

    res1 = ledger.retest(fid1, _StubRunner("HTTP/1.1 401 Unauthorized\r\n"), scope)
    assert res1["status"] == "AUTH-GATED"

    res2 = ledger.retest(fid1, _StubRunner(""), scope)
    assert res2["status"] == "FIXED"


def test_ledger_retest_enforces_scope(tmp_path, scope):
    db = tmp_path / "oniops.sqlite"
    ledger = FindingsLedger(db)
    fid = ledger.upsert(
        target_ip="8.8.8.8",
        port=80,
        title="Out of scope finding",
        category="service_exposure",
        severity="LOW",
        status="VERIFIED",
        evidence="test",
        repro_cmd=["curl", "http://8.8.8.8"],
    )
    with pytest.raises(ScopeViolation):
        ledger.retest(fid, None, scope)


def test_validate_evidence_and_batch_retest_and_diff(tmp_path, scope):
    import sqlite3
    assert validate_evidence("HTTP/1.1 200 OK\r\nX-Admin: enabled", expected_indicator="X-Admin: enabled") == "VERIFIED"
    assert validate_evidence("HTTP/1.1 404 Not Found\r\n", expected_indicator="X-Admin: enabled") == "UNCONFIRMED"
    assert validate_evidence("HTTP/1.1 401 Unauthorized\r\n", category="service_exposure") == "AUTH-GATED"

    db = tmp_path / "oniops.sqlite"
    ledger = FindingsLedger(db)
    ledger.upsert(
        target_ip="10.0.0.150",
        port=8080,
        title="Unauthenticated API access on /api/admin",
        category="api_security",
        severity="HIGH",
        status="FIXED",
        evidence="HTTP/1.1 403 Forbidden",
        repro_cmd=["curl", "-kIsS", "http://10.0.0.150:8080/api/admin"],
    )

    class _RegressedRunner:
        def run(self, cmd, timeout=30):
            class _R:
                ok = True
                out = "HTTP/1.1 200 OK\r\n"
            return _R()

    batch = ledger.retest_all(_RegressedRunner(), scope, target_ip="10.0.0.150")
    assert batch["total_retested"] == 1
    assert batch["verified"] == 1
    assert batch["regressed"] == 1

    with sqlite3.connect(db) as con:
        con.execute("""CREATE TABLE assessments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target_ip TEXT, severity TEXT, finding_count INTEGER, raw_output TEXT
        )""")
        con.execute(
            "INSERT INTO assessments (target_ip, severity, finding_count, raw_output) VALUES (?, ?, ?, ?)",
            ("10.0.0.150", "LOW", 1, "22/tcp open ssh\n80/tcp open http\n"),
        )
        con.execute(
            "INSERT INTO assessments (target_ip, severity, finding_count, raw_output) VALUES (?, ?, ?, ?)",
            ("10.0.0.150", "HIGH", 3, "22/tcp open ssh\n8080/tcp open http-proxy\n"),
        )
        con.commit()

    diff = diff_assessments(db, 2)
    assert diff["has_baseline"] is True
    assert diff["severity_change"] == {"from": "LOW", "to": "HIGH"}
    assert diff["finding_count_delta"] == 2
    assert "8080/tcp (http-proxy)" in diff["new_ports"]
    assert "80/tcp (http)" in diff["closed_ports"]
    assert diff["active_findings"] == 1


def test_validate_evidence_no_false_verified_without_proof():
    # A live 200 with no indicator and a non-exposure category must NOT verify a
    # vulnerability — only report that the service responded (UNCONFIRMED).
    assert validate_evidence("HTTP/1.1 200 OK\r\nServer: nginx", category="agent_validation") == "UNCONFIRMED"
    # Arbitrary content with no status line / indicator / proof pattern: UNCONFIRMED.
    assert validate_evidence("some long banner text here", category="") == "UNCONFIRMED"
    # service_exposure is self-proving from a live 2xx (the finding IS "exposed").
    assert validate_evidence("HTTP/1.1 200 OK\r\n", category="service_exposure") == "VERIFIED"
    # Indicator still wins regardless of category.
    assert validate_evidence("HTTP/1.1 200 OK\r\nX-Debug: on", expected_indicator="X-Debug: on") == "VERIFIED"


def test_vulnerability_specific_validators_and_compliance_coverage():
    # LFI requires /etc/passwd or win.ini proof, not just HTTP 200
    assert validate_evidence("HTTP/1.1 200 OK\r\n<html>Welcome</html>", category="lfi") == "UNCONFIRMED"
    assert validate_evidence("root:x:0:0:root:/root:/bin/bash", category="lfi") == "VERIFIED"

    # SQLi & SSRF proof patterns
    assert validate_evidence("You have an error in your SQL syntax; check the manual that corresponds to your MySQL", category="sqli") == "VERIFIED"
    assert validate_evidence("HTTP/1.1 200 OK\r\nami-id: ami-0abcdef12345", category="ssrf") == "VERIFIED"
    assert validate_evidence("uid=0(root) gid=0(root) groups=0(root)", category="rce") == "VERIFIED"

    cov = map_finding_coverage("api_security", "BOLA/BFLA privilege boundary bypass on /api/admin")
    assert "API1:2023-BOLA" in cov["owasp_api"]
    assert "API5:2023-BFLA" in cov["owasp_api"]
    assert "WSTG-ATHZ-02" in cov["owasp_wstg"]
    assert "T1190" in cov["mitre_attack"]


def test_observed_vs_inferred_identity_attack_graph_and_idempotent_jobs(tmp_path):
    surface = {
        "10.0.0.150": {
            "target_name": "dc01.corp.local",
            "services_json": '[{"port": 88, "service": "kerberos"}, {"port": 389, "service": "ldap"}, {"port": 445, "service": "microsoft-ds"}]',
        },
        "10.0.0.151": {
            "target_name": "app01.corp.local",
            "services_json": '[{"port": 8080, "service": "http"}]',
        },
    }
    findings_by_host = {
        "10.0.0.150": [{"port": 445, "title": "SMB signing disabled", "category": "nuclei", "severity": "HIGH", "status": "VERIFIED"}],
        "10.0.0.151": [{"port": 8080, "title": "CVE-2024-9999 banner match", "category": "cve", "severity": "MEDIUM", "status": "UNCONFIRMED"}],
    }
    paths = compute_attack_paths({"10.0.0.150", "10.0.0.151"}, surface, findings_by_host, {})
    by_ip = {p["target_ip"]: p for p in paths}
    assert by_ip["10.0.0.150"]["validation_state"] == "OBSERVED"
    assert any("Kerberos" in s for s in by_ip["10.0.0.150"]["identity_exposure"])
    assert any("T1558" in t for t in by_ip["10.0.0.150"]["mitre_techniques"])
    assert by_ip["10.0.0.151"]["validation_state"] == "INFERRED"

    # Verify idempotent job deduplication
    import threading
    ev = threading.Event()
    jm = JobManager(tmp_path / "jobs.sqlite")
    j1 = jm.submit("assessment", {"ip": "10.0.0.150", "profile": "fast_recon"}, lambda ctl: (ev.wait(1.0), {"ok": True})[1])
    j2 = jm.submit("assessment", {"ip": "10.0.0.150", "profile": "fast_recon"}, lambda ctl: {"ok": True})
    assert j1 == j2
    ev.set()

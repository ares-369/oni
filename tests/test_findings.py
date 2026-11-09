"""Tests for the Proof-First Findings Ledger, secret redaction, and zero-token PoC retest."""
from __future__ import annotations

import pytest

from oniops.findings import FindingsLedger, redact_secrets
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

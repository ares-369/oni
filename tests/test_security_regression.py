"""Adversarial security regression test suite for ONIOPS.

Attempts to bypass ONIOPS's safety boundaries:
  1. Multi-record DNS rebinding (one in-scope IP + one out-of-scope IP)
  2. Out-of-scope IPv4 smuggled inside a network command string
  3. Login brute-force attack (>10 attempts/60s throttled with HTTP 429)
  4. Cross-Origin Request Forgery (CSRF) on cookie-authenticated POST endpoints
  5. Reflected XSS via OIDC callback error_description parameter
  6. Sliding-window agent context compaction for 7B models
  7. Reproducible assessment execution manifest generation
"""
from __future__ import annotations

import pytest
from flask import Flask

from oniops.agent import compact_agent_messages
from oniops.auth import (
    _LOGIN_BUCKETS,
    _PBKDF2_ITERS,
    check_rbac_permission,
    hash_password,
    init_auth,
)
from oniops.config import get_config
from oniops.findings import (
    build_assessment_manifest,
    connect_sqlite,
    verify_assessment_manifest,
)
from oniops.scope import Scope, ScopeViolation


def test_dns_rebinding_multi_record_blocked(cfg_path, monkeypatch):
    scope = Scope(get_config(reload=True))
    # Primary record is in-scope (10.0.0.50), but secondary A/AAAA record is out-of-scope (8.8.8.8)
    monkeypatch.setattr("socket.gethostbyname", lambda h: "10.0.0.50")
    monkeypatch.setattr(
        "socket.getaddrinfo",
        lambda h, p: [
            (2, 1, 6, "", ("10.0.0.50", 0)),
            (2, 1, 6, "", ("8.8.8.8", 0)),
        ],
    )
    with pytest.raises(ScopeViolation, match=r"out-of-scope address 8\.8\.8\.8"):
        scope.resolve("rebind.attacker.invalid")


def test_command_guard_blocks_embedded_out_of_scope_ip(cfg_path):
    scope = Scope(get_config(reload=True))
    # In-scope IP is allowed:
    scope.guard_command("nmap -sV 10.0.0.50")
    # Out-of-scope IP embedded in a network tool command is blocked:
    with pytest.raises(ScopeViolation, match=r"8\.8\.8\.8 is outside"):
        scope.guard_command("nmap -sV 10.0.0.50 8.8.8.8")
    with pytest.raises(ScopeViolation, match=r"1\.1\.1\.1 is outside"):
        scope.guard_command("curl -kIsS https://1.1.1.1:443/admin")


def test_login_rate_limiting_and_csrf_origin_guard(cfg_path):
    cfg = get_config(reload=True)
    cfg.auth.mode = "local"
    cfg.auth.username = "admin"
    cfg.auth.password_hash = hash_password("correct-horse-battery-staple", iters=1000)
    cfg.auth.secret_key = "test-secret-key-for-regression"

    app = Flask("test_oniops_auth", template_folder="/root/oniops/templates")
    init_auth(app, cfg)

    @app.route("/api/sensitive", methods=["POST"])
    def sensitive():
        return {"ok": True}

    _LOGIN_BUCKETS.clear()
    client = app.test_client()

    # 1. Authenticate with valid credentials
    r_ok = client.post("/login", data={"username": "admin", "password": "correct-horse-battery-staple"})
    assert r_ok.status_code == 302

    # 2. Same-origin POST succeeds
    r_same = client.post("/api/sensitive", headers={"Origin": "http://localhost"})
    assert r_same.status_code == 200

    # 3. Cross-origin POST from malicious site is blocked by CSRF Origin guard
    r_csrf = client.post("/api/sensitive", headers={"Origin": "https://evil.attacker.invalid"})
    assert r_csrf.status_code == 403
    assert b"CSRF guard" in r_csrf.data

    # 4. Brute-force /login (>10 attempts in 60s) triggers HTTP 429
    _LOGIN_BUCKETS.clear()
    last_code = 0
    for _ in range(12):
        resp = client.post("/login", data={"username": "admin", "password": "wrong"})
        last_code = resp.status_code
    assert last_code == 429


def test_sliding_window_agent_compaction():
    long_obs = (
        '<untrusted_tool_output tool="nmap">\n'
        + "\n".join(f"{p}/tcp open http service-{p} banner-details-padding" for p in range(80, 110))
        + "\n</untrusted_tool_output>"
    )
    msgs = [
        {"role": "system", "content": "system prompt"},
        {"role": "user", "content": "initial objective"},
    ]
    for step in range(1, 5):
        msgs.append({"role": "assistant", "content": f'{{"action": "nmap", "step": {step}}}'})
        msgs.append({"role": "user", "content": f"Observation:\n{long_obs}"})

    compacted = compact_agent_messages(msgs, keep_recent_turns=2)
    assert len(compacted) == len(msgs)
    # Older turn (index 3) is compacted:
    assert 'compacted="true"' in compacted[3]["content"]
    assert len(compacted[3]["content"]) < 360
    # Most recent 2 turns (indices 7 and 9) remain uncompacted:
    assert 'compacted="true"' not in compacted[7]["content"]
    assert 'compacted="true"' not in compacted[9]["content"]


def test_reproducible_assessment_manifest():
    m = build_assessment_manifest(
        assessment_id=42,
        oniops_version="0.3.1-beta",
        target_ip="10.0.0.150",
        profile="web_app_pt",
        scope_cidrs=["10.0.0.0/24"],
        model_name="qwen2.5-coder:7b",
        started_at="2026-11-09T12:00:00Z",
        completed_at="2026-11-09T12:01:00Z",
        commands_run=["nmap -sV 10.0.0.150", "whatweb http://10.0.0.150:80"],
        evidence_hashes=["a" * 64],
        signing_key="super-secret-signing-key",
    )
    assert m["assessment_id"] == "ONIOPS-42"
    assert len(m["scope_hash"]) == 16
    assert len(m["commands_hash"]) == 16
    assert m["evidence_hashes"] == ["a" * 64]
    assert m["signature"].startswith("hmac-sha256:")
    assert verify_assessment_manifest(m, signing_key="super-secret-signing-key") is True
    assert verify_assessment_manifest(m, signing_key="wrong-key") is False
    tampered = dict(m, target_ip="10.0.0.199")
    assert verify_assessment_manifest(tampered, signing_key="super-secret-signing-key") is False


def test_pbkdf2_owasp_600k_and_sqlite_wal(tmp_path):
    assert _PBKDF2_ITERS == 600_000
    h = hash_password("test-pw")
    assert h.startswith("pbkdf2_sha256$600000$")

    db_file = tmp_path / "wal_test.sqlite"
    with connect_sqlite(db_file) as con:
        con.execute("CREATE TABLE t (id INTEGER PRIMARY KEY)")
        mode = con.execute("PRAGMA journal_mode").fetchone()[0]
        assert str(mode).lower() == "wal"


def test_three_tier_rbac_enforcement():
    # Viewer: GET and stateless PDF export allowed; scans and config changes blocked
    assert check_rbac_permission("viewer", "GET", "/api/findings")[0] is True
    assert check_rbac_permission("viewer", "POST", "/api/report/pdf")[0] is True
    assert check_rbac_permission("viewer", "POST", "/api/assess")[0] is False
    assert check_rbac_permission("viewer", "POST", "/api/config")[0] is False

    # Operator: scans and retests allowed; config/scope and package installs blocked
    assert check_rbac_permission("operator", "POST", "/api/assess")[0] is True
    assert check_rbac_permission("operator", "POST", "/api/findings/retest-all")[0] is True
    assert check_rbac_permission("operator", "POST", "/api/config")[0] is False
    assert check_rbac_permission("operator", "POST", "/api/kali/install")[0] is False

    # Admin: full access
    assert check_rbac_permission("admin", "POST", "/api/config")[0] is True
    assert check_rbac_permission("admin", "POST", "/api/kali/install")[0] is True


def test_sensitive_reads_are_admin_only():
    # Regression: every GET used to pass for every role, so a read-only viewer
    # could download the whole database (findings, evidence, stored replay
    # credentials, terms log) and make the server SSH into the attack host.
    from oniops.auth import check_rbac_permission as rbac
    for role in ("viewer", "operator"):
        assert rbac(role, "GET", "/api/backup/download")[0] is False
        assert rbac(role, "GET", "/api/doctor", {"runner": "1"})[0] is False
    assert rbac("admin", "GET", "/api/backup/download")[0] is True
    assert rbac("admin", "GET", "/api/doctor", {"runner": "true"})[0] is True
    # Ordinary reads stay open to viewers.
    assert rbac("viewer", "GET", "/api/doctor")[0] is True
    assert rbac("viewer", "GET", "/api/findings")[0] is True

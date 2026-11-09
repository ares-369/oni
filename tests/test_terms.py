"""Tests for first-run responsible-use terms acceptance (oniops/terms.py + routes)."""
from __future__ import annotations

from oniops import terms
from oniops.terms import TermsStore


def test_store_records_per_user_and_version(tmp_path):
    st = TermsStore(tmp_path / "t.sqlite")
    assert not st.has_accepted("alice")
    ts = st.record("alice", "10.0.0.5", "pytest")
    assert st.has_accepted("alice")
    assert st.accepted_at("alice") == ts
    # Another user, or a newer terms version, still needs to accept.
    assert not st.has_accepted("bob")
    assert not st.has_accepted("alice", version="2099-01-01")
    # Survives a fresh store on the same DB (persisted, not just cached).
    assert TermsStore(tmp_path / "t.sqlite").has_accepted("alice")


def test_only_active_testing_endpoints_are_gated():
    assert terms.is_gated("POST", "/api/assess/start")
    assert terms.is_gated("POST", "/api/agent/start")
    assert terms.is_gated("POST", "/api/aisec/start")
    assert terms.is_gated("POST", "/api/findings/3/retest")
    assert terms.is_gated("POST", "/api/chat")
    # Reading data, settings and accepting the terms are never blocked.
    assert not terms.is_gated("GET", "/api/status")
    assert not terms.is_gated("GET", "/api/findings")
    assert not terms.is_gated("POST", "/api/terms/accept")
    assert not terms.is_gated("POST", "/api/config")


def test_routes_block_testing_until_accepted(cfg_path, tmp_path, monkeypatch):
    import oniops.config as c
    c._CONFIG = None
    import webui

    monkeypatch.setattr(webui, "terms_store", TermsStore(tmp_path / "terms.sqlite"))
    client = webui.app.test_client()

    st = client.get("/api/terms").get_json()
    assert st["accepted"] is False and st["version"] == terms.TERMS_VERSION and st["summary"]

    r = client.post("/api/assess/start", json={"target": "10.0.0.50", "profile": "fast_recon"})
    assert r.status_code == 403 and r.get_json()["terms_required"] is True

    # Acceptance requires an explicit confirm for the CURRENT version.
    assert client.post("/api/terms/accept", json={"confirm": True, "version": "old"}).status_code == 400
    assert client.post("/api/terms/accept", json={"version": terms.TERMS_VERSION}).status_code == 400
    ok = client.post("/api/terms/accept", json={"confirm": True, "version": terms.TERMS_VERSION})
    assert ok.status_code == 200 and ok.get_json()["user"] == "local"

    st = client.get("/api/terms").get_json()
    assert st["accepted"] is True and st["accepted_at"]
    # Now the gate lets the request through to normal validation (bad profile -> 400, not 403).
    r = client.post("/api/assess/start", json={"target": "10.0.0.50", "profile": "nope"})
    assert r.status_code == 400

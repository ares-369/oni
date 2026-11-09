"""End-to-end integration tests for webui.py Flask routes against a real SQLite DB."""
from __future__ import annotations

import json


def test_webui_endpoints_end_to_end(cfg_path, tmp_path, monkeypatch):
    import oniops.config as c
    c._CONFIG = None
    import webui

    # Point webui's DB_PATH and FindingsLedger at a throwaway test DB
    test_db = tmp_path / "test_oni.sqlite"
    monkeypatch.setattr(webui, "DB_PATH", test_db)
    webui.init_db()
    webui.ledger = webui.FindingsLedger(test_db)
    monkeypatch.setattr(webui, "terms_store", webui.TermsStore(test_db))

    client = webui.app.test_client()
    # Active-testing endpoints require the responsible-use terms first.
    assert client.post("/api/findings/retest-all", json={}).status_code == 403
    assert client.post("/api/terms/accept",
                       json={"confirm": True, "version": webui.terms.TERMS_VERSION}).status_code == 200

    # 1. Health & Index UI
    r_health = client.get("/healthz")
    assert r_health.status_code == 200
    assert r_health.get_json()["ok"] is True

    r_idx = client.get("/")
    assert r_idx.status_code == 200
    html = r_idx.get_data(as_text=True)
    assert "Offensive Neural Intelligence" in html
    assert "Proof-First Findings Ledger" in html
    assert "aisecConverter" in html
    assert "wbAuthHeader" in html

    # 2. Playbooks endpoint
    r_pb = client.get("/api/playbooks")
    assert r_pb.status_code == 200
    pb_ids = {p["id"] for p in r_pb.get_json()["playbooks"]}
    assert {"ad_internal_enum", "api_access_control", "tls_crypto_audit"}.issubset(pb_ids)

    # 3. White-box source scan endpoint
    r_wb = client.post(
        "/api/whitebox/scan",
        json={"source": '@app.route("/admin/debug")\ndef dbg():\n    return eval("1+1")\n'},
    )
    assert r_wb.status_code == 200
    wb_data = r_wb.get_json()
    assert "/admin/debug" in wb_data["routes"]
    assert len(wb_data["sinks"]) >= 1

    # 4. Findings Ledger + Retest endpoint
    fid = webui.ledger.upsert(
        target_ip="10.0.0.150",
        port=80,
        title="Exposed HTTP service on port 80 (VERIFIED)",
        category="service_exposure",
        severity="MEDIUM",
        status="VERIFIED",
        evidence="HTTP/1.1 200 OK",
        repro_cmd=["curl", "-kIsS", "http://10.0.0.150:80"],
    )
    r_find = client.get("/api/findings")
    assert r_find.status_code == 200
    assert len(r_find.get_json()["findings"]) == 1

    # Mock active_runner for deterministic retest
    class _MockRunner:
        def run(self, cmd, timeout=30):
            class _R:
                ok = True
                out = "HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Basic\r\n"
            return _R()

    monkeypatch.setattr(webui, "active_runner", lambda: _MockRunner())
    r_retest = client.post(f"/api/findings/{fid}/retest")
    assert r_retest.status_code == 200
    assert r_retest.get_json()["status"] == "AUTH-GATED"

    # 5. Attack Graph includes the structured finding and correlated attack path
    r_graph = client.get("/api/graph")
    assert r_graph.status_code == 200
    g_data = r_graph.get_json()
    assert g_data["stats"]["verified_findings"] == 1
    assert g_data["stats"]["attack_paths"] >= 1
    assert g_data["stats"]["max_blast_radius"] > 0
    assert any(n["type"] == "finding" for n in g_data["nodes"])
    assert len(g_data["attack_paths"]) >= 1

    # 5b. Batch retest-all endpoint & AI YAML probe packs endpoint
    r_batch = client.post("/api/findings/retest-all", json={"target": "10.0.0.150"})
    assert r_batch.status_code == 200
    assert r_batch.get_json()["total_retested"] == 1

    r_aip = client.get("/api/aisec/probes")
    assert r_aip.status_code == 200
    assert len(r_aip.get_json()["yaml_probes"]) >= 3

    # 6. PDF Export endpoint
    r_pdf = client.post(
        "/api/report/pdf",
        data=json.dumps({"filename": "test.pdf", "title": "ONIOPS Live Test", "markdown": "# Finding 1\n- Verified"}),
        content_type="application/json",
    )
    assert r_pdf.status_code == 200
    assert r_pdf.mimetype == "application/pdf"
    assert r_pdf.data.startswith(b"%PDF-1.4")

    # 7. Config diff preview endpoint
    r_prev = client.post(
        "/api/config/preview",
        json={"instance_name": "ONIOPS-PREVIEW-CHECK"},
    )
    assert r_prev.status_code == 200
    prev_data = r_prev.get_json()
    assert prev_data["changed"] is True
    assert "ONIOPS-PREVIEW-CHECK" in prev_data["diff"]


def test_job_events_are_tagged_for_the_step_timeline(cfg_path, tmp_path, monkeypatch):
    import time

    import oniops.config as c
    c._CONFIG = None
    import webui

    monkeypatch.setattr(webui, "ACTIVITY_LOG", tmp_path / "activity.jsonl")
    jm = webui.JobManager(tmp_path / "jobs.sqlite")
    monkeypatch.setattr(webui, "jobs", jm)

    def work(ctl):
        webui.emit_event("RECON", "busy", "scanning")
        webui.emit_event("VALIDATE", "ok", "1/1 verified")
        return {"ok": True}

    webui.emit_event("CONFIG", "ok", "outside any job")   # must NOT be attributed
    jid = jm.submit("test", {}, work)
    for _ in range(50):
        if (jm.get(jid) or {}).get("status") == "done":
            break
        time.sleep(0.05)
    j = webui.app.test_client().get(f"/api/job/{jid}").get_json()
    assert [e["stage"] for e in j["events"]] == ["RECON", "VALIDATE"]
    assert all(e["job"] == jid for e in j["events"])

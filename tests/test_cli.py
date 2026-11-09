"""Tests for ONIOPS CLI and CI/CD security gate mode (`oniops/cli.py`)."""
from __future__ import annotations

import json

from oniops.cli import cli_main
from oniops.findings import FindingsLedger


def test_cli_version_and_playbooks(capsys):
    assert cli_main(["version"]) == 0
    out = capsys.readouterr().out
    assert "ONIOPS 0.3.0-beta" in out

    assert cli_main(["playbooks"]) == 0
    pb_out = json.loads(capsys.readouterr().out)
    assert len(pb_out["playbooks"]) >= 3
    assert len(pb_out["ai_yaml_probes"]) >= 3


def test_cli_whitebox_ci_gate_and_sarif(tmp_path):
    sarif_file = tmp_path / "gate.sarif"
    vuln_code = '@app.route("/exec")\ndef run():\n    return eval("1+1")\n'
    rc = cli_main(["whitebox", vuln_code, "--fail-on", "HIGH", "--sarif", str(sarif_file), "--json"])
    assert rc == 1
    assert sarif_file.exists()
    sarif = json.loads(sarif_file.read_text(encoding="utf-8"))
    assert sarif["version"] == "2.1.0"
    assert len(sarif["runs"][0]["results"]) >= 1

    safe_code = '@app.route("/health")\ndef ok():\n    return "ok"\n'
    assert cli_main(["whitebox", safe_code, "--fail-on", "HIGH"]) == 0


def test_cli_findings_list(tmp_path, capsys):
    db = tmp_path / "oniops.sqlite"
    ledger = FindingsLedger(db)
    ledger.upsert(
        target_ip="10.0.0.150",
        port=443,
        title="TLS Weak Cipher",
        category="tls",
        severity="MEDIUM",
        status="VERIFIED",
        evidence="TLSv1.0 enabled",
        repro_cmd=["nmap", "-p", "443", "10.0.0.150"],
    )
    assert cli_main(["findings", "--db", str(db), "--target", "10.0.0.150"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert len(data["findings"]) == 1
    assert len(data["findings"][0]["evidence_sha256"]) == 64

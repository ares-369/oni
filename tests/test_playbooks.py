"""Tests for declarative YAML playbooks."""
from __future__ import annotations

import pytest

from oniops.playbooks import load_playbooks, render_step_cmd, validate_playbook


def test_builtin_playbooks_load():
    pbs = load_playbooks()
    assert "ad_internal_enum" in pbs
    assert "api_access_control" in pbs
    assert "tls_crypto_audit" in pbs


def test_render_step_cmd_substitutes_discrete_arg():
    tpl = ["nmap", "-sV", "{target}"]
    assert render_step_cmd(tpl, "10.0.0.150") == ["nmap", "-sV", "10.0.0.150"]


def test_validate_playbook_rejects_bad_schema():
    with pytest.raises(ValueError):
        validate_playbook({"id": "bad-id!", "steps": []})
    with pytest.raises(ValueError):
        validate_playbook({"id": "valid_id", "steps": [{"name": "s1", "cmd": "nmap 10.0.0.1"}]})


def test_required_tools_include_every_tool_used_by_steps():
    playbook = validate_playbook({
        "id": "tool_requirements",
        "required_tools": ["nmap"],
        "steps": [
            {"cmd": ["nmap", "{target}"]},
            {"cmd": ["nuclei", "-target", "{target}"]},
        ],
    })
    assert playbook["required_tools"] == ["nmap", "nuclei"]


def test_exploit_and_credential_guessing_tools_require_intrusive_safety():
    base = {"id": "intrusive_check", "steps": [{"cmd": ["sqlmap", "-u", "http://{target}/"]}]}
    with pytest.raises(ValueError, match="requires safety: intrusive"):
        validate_playbook({**base, "safety": "active"})
    allowed = validate_playbook({**base, "safety": "intrusive"})
    assert allowed["safety"] == "intrusive"
    assert allowed["required_tools"] == ["sqlmap"]

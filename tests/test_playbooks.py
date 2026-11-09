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

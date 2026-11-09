"""Tests for config apply/preview validation — config.yaml drives command
execution, so bad input must be rejected before it is ever written."""
from __future__ import annotations

import pytest
import yaml

from oniops.config import apply_updates, get_config, preview_updates


def test_valid_scope_update_persists(cfg_path):
    apply_updates({"scope": {"allowed_cidrs": ["10.10.0.0/16"]}})
    data = yaml.safe_load(cfg_path.read_text())
    assert data["scope"]["allowed_cidrs"] == ["10.10.0.0/16"]


def test_bad_cidr_rejected(cfg_path):
    before = cfg_path.read_text()
    with pytest.raises(ValueError):
        apply_updates({"scope": {"allowed_cidrs": ["not-a-cidr"]}})
    # File must be unchanged on rejection.
    assert cfg_path.read_text() == before


def test_empty_cidrs_rejected(cfg_path):
    with pytest.raises(ValueError, match="cannot be empty"):
        apply_updates({"scope": {"allowed_cidrs": []}})


def test_attack_hosts_requires_address(cfg_path):
    with pytest.raises(ValueError, match="at least one attack host"):
        apply_updates({"attack_hosts": [{"name": "x", "host": ""}]})


def test_nvd_toggle_persists(cfg_path):
    apply_updates({"integrations": {"nvd": {"enabled": True, "api_key": "k123"}}})
    data = yaml.safe_load(cfg_path.read_text())
    assert data["integrations"]["nvd"]["enabled"] is True
    assert data["integrations"]["nvd"]["api_key"] == "k123"


def test_backup_written_on_apply(cfg_path):
    apply_updates({"instance_name": "Renamed"})
    assert cfg_path.with_name(cfg_path.name + ".bak").exists()


# ───────────────────────── preview (no write) ─────────────────────────
def test_preview_does_not_write(cfg_path):
    before = cfg_path.read_text()
    res = preview_updates({"scope": {"allowed_cidrs": ["10.10.0.0/16"]}})
    assert res["changed"] is True
    assert "10.10.0.0/16" in res["diff"]
    assert cfg_path.read_text() == before  # unchanged


def test_preview_no_change_flag(cfg_path):
    current = get_config(reload=True)
    res = preview_updates({"instance_name": current.instance_name})
    assert res["changed"] is False


def test_preview_redacts_secrets(cfg_path):
    res = preview_updates({"integrations": {"nvd": {"enabled": True, "api_key": "SUPERSECRET"}}})
    assert "SUPERSECRET" not in res["diff"]
    assert "***" in res["diff"]


def test_preview_invalid_raises(cfg_path):
    with pytest.raises(ValueError):
        preview_updates({"scope": {"allowed_cidrs": ["bad"]}})


def test_invalid_scope_mode_falls_back_to_active(cfg_path):
    # An unknown mode must not be passed through: the UI dropdown only offers
    # active/passive/stealth, so a stray value would display (and save) as
    # something other than what is configured.
    cfg_path.write_text(cfg_path.read_text().replace("mode: active", "mode: strict"))
    cfg = get_config(reload=True)
    assert cfg.scope.mode == "active"

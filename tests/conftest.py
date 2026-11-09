"""Shared fixtures. A throwaway config.yaml drives scope/config tests so they
never touch a real deployment's file."""
from __future__ import annotations

import textwrap

import pytest

MINIMAL_CONFIG = textwrap.dedent("""
    oniops:
      instance_name: ONIOPS-TEST
      external_url: ""
    scope:
      allowed_cidrs: ["10.0.0.0/24", "192.168.50.0/24"]
      exclude: ["10.0.0.1"]
      mode: strict
      non_destructive: true
      rate_limit_per_min: 60
    attack_hosts:
      - name: kali
        host: 10.0.0.9
        user: root
        ssh_key: ./secrets/kali_id_rsa
        default: true
    llm:
      roles:
        planner: {provider: ollama, model: qwen2.5-coder:7b}
        reporter: {provider: ollama, model: qwen2.5-coder:7b}
        reason: {provider: ollama, model: qwen2.5-coder:7b}
      providers:
        ollama: {base_url: "http://localhost:11434"}
    integrations:
      nvd: {enabled: false, api_key: ""}
""")


@pytest.fixture()
def cfg_path(tmp_path, monkeypatch):
    p = tmp_path / "config.yaml"
    p.write_text(MINIMAL_CONFIG)
    monkeypatch.setenv("ONIOPS_CONFIG", str(p))
    # Force a fresh load against this file.
    import oniops.config as c
    c._CONFIG = None
    return p


@pytest.fixture()
def scope(cfg_path):
    from oniops.config import get_config
    from oniops.scope import Scope
    return Scope(get_config())

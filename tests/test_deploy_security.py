"""Secure-by-default deployment: listen address, unauthenticated exposure and
proxy-auth header forgery (all fail closed)."""
from __future__ import annotations

import pytest
from flask import Flask

from oniops.config import get_config
from oniops.server import startup_security_check


def _cfg(cfg_path, extra_yaml: str = "", **env):
    if extra_yaml:
        cfg_path.write_text(cfg_path.read_text() + extra_yaml)
    return get_config(reload=True)


def test_default_listen_address_is_loopback(cfg_path, monkeypatch):
    monkeypatch.delenv("ONIOPS_BIND_HOST", raising=False)
    assert get_config(reload=True).bind_host == "127.0.0.1"


def test_bind_host_env_override(cfg_path, monkeypatch):
    monkeypatch.setenv("ONIOPS_BIND_HOST", "0.0.0.0")       # what Docker uses
    assert get_config(reload=True).bind_host == "0.0.0.0"


def test_no_login_on_network_refuses_to_start(cfg_path, monkeypatch):
    monkeypatch.setenv("ONIOPS_BIND_HOST", "0.0.0.0")
    errors, _ = startup_security_check(get_config(reload=True))   # auth defaults to none
    assert errors and "NO login" in errors[0]


def test_no_login_on_loopback_is_fine(cfg_path, monkeypatch):
    monkeypatch.delenv("ONIOPS_BIND_HOST", raising=False)
    errors, _ = startup_security_check(get_config(reload=True))
    assert errors == []


def test_explicit_opt_in_downgrades_to_warning(cfg_path, monkeypatch):
    monkeypatch.setenv("ONIOPS_BIND_HOST", "0.0.0.0")
    monkeypatch.setenv("ONIOPS_ALLOW_UNAUTHENTICATED_NETWORK", "1")
    errors, warnings = startup_security_check(get_config(reload=True))
    assert errors == [] and any("NO login" in w for w in warnings)


def test_login_enabled_on_network_is_fine(cfg_path, monkeypatch):
    monkeypatch.setenv("ONIOPS_BIND_HOST", "0.0.0.0")
    cfg = _cfg(cfg_path, "auth:\n  mode: oidc\n")
    assert startup_security_check(cfg)[0] == []


def test_proxy_mode_without_trusted_ips_refuses_to_start(cfg_path):
    cfg = _cfg(cfg_path, "auth:\n  mode: proxy\n  proxy_trusted_ips: []\n")
    errors, _ = startup_security_check(cfg)
    assert errors and "proxy_trusted_ips" in errors[0]


@pytest.mark.parametrize("trusted, expected", [
    ([], 403),                 # no allow-list -> never trust the header (fail closed)
    (["10.9.9.9"], 403),       # request not from the proxy -> forged header rejected
    (["127.0.0.1"], 200),      # request from the trusted proxy -> accepted
])
def test_proxy_identity_header_cannot_be_forged(cfg_path, trusted, expected):
    ips = "[" + ", ".join(f'"{t}"' for t in trusted) + "]"
    cfg = _cfg(cfg_path, f"auth:\n  mode: proxy\n  proxy_header: X-Forwarded-User\n  proxy_trusted_ips: {ips}\n")
    from oniops.auth import init_auth
    app = Flask(__name__)
    app.secret_key = "test"
    init_auth(app, cfg)

    @app.route("/api/whoami")
    def whoami():
        return "ok"

    r = app.test_client().get("/api/whoami", headers={"X-Forwarded-User": "admin"})
    assert r.status_code == expected

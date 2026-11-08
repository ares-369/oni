"""Configuration loader for ONIOPS.

Loads ``config.yaml`` (environment layout, scope, providers) and ``.env``
(secrets). Nothing about the user's environment is hardcoded — everything a
deployer needs to change lives in config.yaml.

Resolution order for the config path:
  1. ``ONIOPS_CONFIG`` env var, if set
  2. ``./config.yaml`` in the current working directory
  3. ``<repo>/config.yaml`` next to this package
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml
from dotenv import load_dotenv

REPO_ROOT = Path(__file__).resolve().parent.parent


def _load_env() -> None:
    # .env lives next to config.yaml / at the repo root; load if present.
    for candidate in (Path.cwd() / ".env", REPO_ROOT / ".env"):
        if candidate.exists():
            load_dotenv(candidate)
            return


def _config_path() -> Path:
    if os.getenv("ONIOPS_CONFIG"):
        return Path(os.environ["ONIOPS_CONFIG"]).expanduser()
    cwd_cfg = Path.cwd() / "config.yaml"
    if cwd_cfg.exists():
        return cwd_cfg
    return REPO_ROOT / "config.yaml"


@dataclass
class ScopeConfig:
    allowed_cidrs: list[str]
    exclude: list[str] = field(default_factory=list)
    auto_detect_subnet: bool = True
    rate_limit_per_min: int = 120
    mode: str = "active"            # active | passive | stealth
    non_destructive: bool = True
    active_window: str | None = None


@dataclass
class HostConfig:
    """An attack host ONIOPS drives over SSH. Kali is one option; any tooled Linux
    (Parrot, BlackArch, a custom box, or localhost) works."""
    host: str
    name: str = "kali"
    label: str = ""              # human label, e.g. "Kali (lab)"
    user: str = "root"
    ssh_key: str = "./secrets/kali_id_rsa"
    connect_timeout: int = 6
    # tofu = trust-on-first-use (save to known_hosts); strict = reject unknown;
    # insecure = auto-accept any key (not recommended).
    verify_host_key: str = "tofu"
    known_hosts: str = "./secrets/known_hosts"


# Back-compat alias (older code / imports referenced KaliConfig).
KaliConfig = HostConfig


@dataclass
class AuthConfig:
    # none | basic | local | oidc | proxy
    mode: str = "none"
    username: str = "oniops"
    password: str = ""          # basic/local; from .env ONIOPS_AUTH_PASSWORD
    password_hash: str = ""     # optional pbkdf2 hash (preferred over password)
    secret_key: str = ""        # session signing; from .env ONIOPS_SECRET_KEY
    proxy_header: str = "X-Forwarded-User"   # reverse-proxy forward-auth header
    proxy_trusted_ips: list = field(default_factory=list)  # only these source IPs may assert the header (anti-forgery)
    allowed_users: list = field(default_factory=list)  # allowlist (oidc/proxy); empty = any authenticated
    oidc: dict = field(default_factory=dict)  # issuer, client_id, client_secret, scopes, username_claim

    @property
    def enabled(self) -> bool:
        return self.mode != "none"


@dataclass
class Config:
    raw: dict[str, Any]
    instance_name: str
    external_url: str          # public base URL behind the proxy (for OIDC redirects)
    bind_host: str
    bind_port: int
    scope: ScopeConfig
    kali: HostConfig          # the active/default attack host (back-compat name)
    hosts: list               # all configured attack hosts (HostConfig)
    auth: AuthConfig
    llm: dict[str, Any]
    integrations: dict[str, Any]
    path: Path

    # -- secrets (from .env) --
    def secret(self, name: str) -> str:
        return os.getenv(name, "") or ""

    def provider_cfg(self, name: str) -> dict[str, Any]:
        return (self.llm.get("providers") or {}).get(name, {}) or {}

    def role_cfg(self, role: str) -> dict[str, Any]:
        return (self.llm.get("roles") or {}).get(role, {}) or {}


def load_config() -> Config:
    _load_env()
    path = _config_path()
    if not path.exists():
        raise FileNotFoundError(
            f"No config.yaml found at {path}. Copy config.example.yaml to "
            f"config.yaml and edit it for your environment."
        )
    data = yaml.safe_load(path.read_text()) or {}

    oniops = data.get("oniops", {}) or {}
    scope_raw = data.get("scope", {}) or {}
    kali_raw = data.get("kali", {}) or {}

    if not scope_raw.get("allowed_cidrs"):
        raise ValueError(
            "config.yaml: scope.allowed_cidrs is required and must be non-empty. "
            "ONIOPS will not run without an explicit Rules-of-Engagement scope."
        )

    scope = ScopeConfig(
        allowed_cidrs=list(scope_raw["allowed_cidrs"]),
        exclude=list(scope_raw.get("exclude", []) or []),
        auto_detect_subnet=bool(scope_raw.get("auto_detect_subnet", True)),
        rate_limit_per_min=int(scope_raw.get("rate_limit_per_min", 120)),
        mode=str(scope_raw.get("mode", "active")),
        non_destructive=bool(scope_raw.get("non_destructive", True)),
        active_window=scope_raw.get("active_window"),
    )

    def _mk_host(h: dict, default_name: str) -> HostConfig:
        return HostConfig(
            host=str(h.get("host", "")),
            name=str(h.get("name", default_name)),
            label=str(h.get("label", "")),
            user=str(h.get("user", "root")),
            ssh_key=str(h.get("ssh_key", "./secrets/kali_id_rsa")),
            connect_timeout=int(h.get("connect_timeout", 6)),
            verify_host_key=str(h.get("verify_host_key", "tofu")),
            known_hosts=str(h.get("known_hosts", "./secrets/known_hosts")),
        )

    # One or many attack hosts. Back-compat: a single `kali:` block = one host.
    attack_raw = data.get("attack_hosts") or data.get("hosts")
    if attack_raw:
        hosts = [_mk_host(h, f"host{i + 1}") for i, h in enumerate(attack_raw)]
        default_name = next((str(h.get("name")) for h in attack_raw if h.get("default")), None) or hosts[0].name
    else:
        single = _mk_host(kali_raw, "kali")
        single.ssh_key = os.getenv("ONIOPS_KALI_SSH_KEY", single.ssh_key)
        hosts = [single]
        default_name = single.name
    active_host = next((h for h in hosts if h.name == default_name), hosts[0])

    auth_raw = data.get("auth", {}) or {}
    # Back-compat: old `enabled: true` maps to basic auth.
    mode = auth_raw.get("mode")
    if mode is None:
        mode = "basic" if auth_raw.get("enabled") else "none"
    oidc_raw = auth_raw.get("oidc", {}) or {}
    oidc = {
        "issuer": str(oidc_raw.get("issuer", "")),
        "client_id": str(oidc_raw.get("client_id", "")),
        "client_secret": os.getenv("OIDC_CLIENT_SECRET", oidc_raw.get("client_secret", "")) or "",
        "scopes": str(oidc_raw.get("scopes", "openid email profile")),
        "username_claim": str(oidc_raw.get("username_claim", "email")),
    }
    auth = AuthConfig(
        mode=str(mode),
        username=str(auth_raw.get("username", "oniops")),
        password=os.getenv("ONIOPS_AUTH_PASSWORD", auth_raw.get("password", "")) or "",
        password_hash=str(auth_raw.get("password_hash", "")),
        secret_key=os.getenv("ONIOPS_SECRET_KEY", auth_raw.get("secret_key", "")) or "",
        proxy_header=str(auth_raw.get("proxy_header", "X-Forwarded-User")),
        proxy_trusted_ips=list(auth_raw.get("proxy_trusted_ips", []) or []),
        allowed_users=list(auth_raw.get("allowed_users", []) or []),
        oidc=oidc,
    )

    return Config(
        raw=data,
        instance_name=str(oniops.get("instance_name", "ONIOPS")),
        external_url=str(oniops.get("external_url", "")).rstrip("/"),
        bind_host=str(oniops.get("bind_host", "0.0.0.0")),
        bind_port=int(oniops.get("bind_port", 8501)),
        scope=scope,
        kali=active_host,
        hosts=hosts,
        auth=auth,
        llm=data.get("llm", {}) or {},
        integrations=data.get("integrations", {}) or {},
        path=path,
    )


# A process-wide singleton, loaded lazily.
_CONFIG: Config | None = None


def get_config(reload: bool = False) -> Config:
    global _CONFIG
    if _CONFIG is None or reload:
        _CONFIG = load_config()
    return _CONFIG

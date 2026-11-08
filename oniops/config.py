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
class KaliConfig:
    host: str
    user: str = "root"
    ssh_key: str = "./secrets/kali_id_rsa"
    connect_timeout: int = 6
    # tofu = trust-on-first-use (save to known_hosts); strict = reject unknown;
    # insecure = auto-accept any key (not recommended).
    verify_host_key: str = "tofu"
    known_hosts: str = "./secrets/known_hosts"


@dataclass
class AuthConfig:
    enabled: bool = False
    username: str = "oniops"
    password: str = ""   # sourced from .env ONIOPS_AUTH_PASSWORD


@dataclass
class Config:
    raw: dict[str, Any]
    instance_name: str
    bind_host: str
    bind_port: int
    scope: ScopeConfig
    kali: KaliConfig
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

    kali = KaliConfig(
        host=str(kali_raw.get("host", "")),
        user=str(kali_raw.get("user", "root")),
        ssh_key=os.getenv("ONIOPS_KALI_SSH_KEY", kali_raw.get("ssh_key", "./secrets/kali_id_rsa")),
        connect_timeout=int(kali_raw.get("connect_timeout", 6)),
        verify_host_key=str(kali_raw.get("verify_host_key", "tofu")),
        known_hosts=str(kali_raw.get("known_hosts", "./secrets/known_hosts")),
    )

    auth_raw = data.get("auth", {}) or {}
    auth = AuthConfig(
        enabled=bool(auth_raw.get("enabled", False)),
        username=str(auth_raw.get("username", "oniops")),
        password=os.getenv("ONIOPS_AUTH_PASSWORD", auth_raw.get("password", "")) or "",
    )

    return Config(
        raw=data,
        instance_name=str(oniops.get("instance_name", "ONIOPS")),
        bind_host=str(oniops.get("bind_host", "0.0.0.0")),
        bind_port=int(oniops.get("bind_port", 8501)),
        scope=scope,
        kali=kali,
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

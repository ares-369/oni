"""Configuration loader for OniOps.

Loads ``config.yaml`` (environment layout, scope, providers) and ``.env``
(secrets). Nothing about the user's environment is hardcoded — everything a
deployer needs to change lives in config.yaml.

Resolution order for the config path:
  1. ``ONIOPS_CONFIG`` env var, if set
  2. ``./config.yaml`` in the current working directory
  3. ``<repo>/config.yaml`` next to this package
"""

from __future__ import annotations

import difflib
import ipaddress
import logging
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml
from dotenv import load_dotenv

from .paths import REPO_ROOT, home_dir  # noqa: F401  (REPO_ROOT kept for callers)

# Valid scope.mode values. Checked both when loading config.yaml and when the
# UI saves an update, so the UI never displays a different mode than the one
# actually in effect.
_SCOPE_MODES = {"active", "passive", "stealth"}
_log = logging.getLogger("OniOps")


def _load_env() -> None:
    # .env lives next to config.yaml / at the repo root; load if present.
    for candidate in (Path.cwd() / ".env", home_dir() / ".env"):
        if candidate.exists():
            load_dotenv(candidate)
            return


def _config_path() -> Path:
    if os.getenv("ONIOPS_CONFIG"):
        return Path(os.environ["ONIOPS_CONFIG"]).expanduser()
    cwd_cfg = Path.cwd() / "config.yaml"
    if cwd_cfg.exists():
        return cwd_cfg
    return home_dir() / "config.yaml"


@dataclass
class ScopeConfig:
    allowed_cidrs: list[str]
    exclude: list[str] = field(default_factory=list)
    auto_detect_subnet: bool = True
    # Max commands/HTTP requests launched toward EACH target per minute (one
    # nmap/curl/probe = one unit; not a packet limit). See oniops/ratelimit.py.
    rate_limit_per_min: int = 120
    mode: str = "active"            # active | passive | stealth
    non_destructive: bool = True
    allow_intrusive_playbooks: bool = False
    active_window: str | None = None


@dataclass
class HostConfig:
    """An attack host OniOps drives over SSH. Kali is one option; any tooled Linux
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
    # Optional disposable container per tool invocation on the attack host.
    execution_mode: str = "ssh"       # ssh | docker
    worker_image: str = ""
    worker_network: str = "oniops-worker-net"  # pre-created user-defined bridge required
    worker_memory_mb: int = 1024
    worker_cpus: float = 2.0
    worker_pids_limit: int = 256
    worker_user: str = "65534:65534"


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
    default_role: str = "admin"               # admin | operator | viewer
    roles: dict[str, str] = field(default_factory=dict)  # username -> role mapping

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
    # Explicit opt-in to serve the UI on a network address WITHOUT a login.
    # Only safe when something else restricts access (e.g. Docker publishing
    # the port on 127.0.0.1 only). Default False: OniOps refuses to start.
    allow_unauthenticated_network: bool = False
    # Optional per-role TARGET login recipes (primary/low_priv/peer). Credentials
    # are referenced here only as ${ENV_VAR} and resolved at login time; see
    # oniops/target_auth.py. Empty = today's static-header behaviour.
    target_auth: dict[str, Any] = field(default_factory=dict)

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
            f"No config.yaml found at {path}. Run `oniops init` to create one (or copy "
            f"config.example.yaml to config.yaml), then edit it for your environment."
        )
    data = yaml.safe_load(path.read_text()) or {}

    oniops = data.get("oniops", {}) or {}
    scope_raw = data.get("scope", {}) or {}
    kali_raw = data.get("kali", {}) or {}

    if not scope_raw.get("allowed_cidrs"):
        raise ValueError(
            "config.yaml: scope.allowed_cidrs is required and must be non-empty. "
            "OniOps will not run without an explicit Rules-of-Engagement scope."
        )

    mode = str(scope_raw.get("mode", "active")).strip().lower()
    if mode not in _SCOPE_MODES:
        _log.warning("scope.mode %r is not one of %s; using 'active'. Fix config.yaml to silence this.",
                     mode, sorted(_SCOPE_MODES))
        mode = "active"

    scope = ScopeConfig(
        allowed_cidrs=list(scope_raw["allowed_cidrs"]),
        exclude=list(scope_raw.get("exclude", []) or []),
        auto_detect_subnet=bool(scope_raw.get("auto_detect_subnet", True)),
        rate_limit_per_min=int(scope_raw.get("rate_limit_per_min", 120)),
        mode=mode,
        non_destructive=bool(scope_raw.get("non_destructive", True)),
        allow_intrusive_playbooks=bool(scope_raw.get("allow_intrusive_playbooks", False)),
        active_window=scope_raw.get("active_window"),
    )

    def _mk_host(h: dict, default_name: str) -> HostConfig:
        execution_mode = str(h.get("execution_mode", "ssh")).lower().strip()
        worker_image = str(h.get("worker_image", "")).strip()
        worker_network = str(h.get("worker_network", "oniops-worker-net")).strip()
        memory_mb = int(h.get("worker_memory_mb", 1024))
        cpus = float(h.get("worker_cpus", 2.0))
        pids_limit = int(h.get("worker_pids_limit", 256))
        worker_user = str(h.get("worker_user", "65534:65534")).strip()
        if execution_mode not in {"ssh", "docker"}:
            raise ValueError("attack host execution_mode must be 'ssh' or 'docker'.")
        if (not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,62}", worker_network)
                or worker_network.lower() in {"bridge", "host", "none"}):
            raise ValueError("docker worker_network must name a pre-created user-defined bridge; built-in modes bypass DNS/scope isolation.")
        if execution_mode == "docker" and not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._/:@-]{0,200}", worker_image):
            raise ValueError("docker execution requires a valid attack_hosts.worker_image image reference.")
        if not 128 <= memory_mb <= 32768 or not 0.25 <= cpus <= 32 or not 32 <= pids_limit <= 4096:
            raise ValueError("worker resource limits are outside safe configured bounds.")
        if not re.fullmatch(r"\d{1,6}:\d{1,6}", worker_user):
            raise ValueError("worker_user must be a numeric uid:gid pair.")
        if int(worker_user.split(":", 1)[0]) == 0:
            raise ValueError("docker worker_user must use a non-root uid.")
        return HostConfig(
            host=str(h.get("host", "")),
            name=str(h.get("name", default_name)),
            label=str(h.get("label", "")),
            user=str(h.get("user", "root")),
            ssh_key=str(h.get("ssh_key", "./secrets/kali_id_rsa")),
            connect_timeout=int(h.get("connect_timeout", 6)),
            verify_host_key=str(h.get("verify_host_key", "tofu")),
            known_hosts=str(h.get("known_hosts", "./secrets/known_hosts")),
            execution_mode=execution_mode,
            worker_image=worker_image,
            worker_network=worker_network,
            worker_memory_mb=memory_mb,
            worker_cpus=cpus,
            worker_pids_limit=pids_limit,
            worker_user=worker_user,
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
        default_role=str(auth_raw.get("default_role", "admin")).lower(),
        roles={str(k): str(v).lower() for k, v in (auth_raw.get("roles") or {}).items()},
    )

    return Config(
        raw=data,
        instance_name=str(oniops.get("instance_name", "OniOps")),
        external_url=str(oniops.get("external_url", "")).rstrip("/"),
        # Secure default: listen on loopback only. ONIOPS_BIND_HOST overrides the
        # file (used by Docker to listen inside its container).
        bind_host=str(os.getenv("ONIOPS_BIND_HOST") or oniops.get("bind_host", "127.0.0.1")),
        bind_port=int(oniops.get("bind_port", 8501)),
        scope=scope,
        kali=active_host,
        hosts=hosts,
        auth=auth,
        llm=data.get("llm", {}) or {},
        integrations=data.get("integrations", {}) or {},
        path=path,
        target_auth=data.get("target_auth", {}) or {},
        allow_unauthenticated_network=(
            str(os.getenv("ONIOPS_ALLOW_UNAUTHENTICATED_NETWORK", "")).strip().lower() in ("1", "true", "yes")
            or bool(oniops.get("allow_unauthenticated_network", False))
        ),
    )


# A process-wide singleton, loaded lazily.
_CONFIG: Config | None = None


def get_config(reload: bool = False) -> Config:
    global _CONFIG
    if _CONFIG is None or reload:
        _CONFIG = load_config()
    return _CONFIG


def _build_updated_config(updates: dict) -> tuple[Any, str, dict]:
    """Validate ``updates`` against the current config.yaml and return
    ``(path, old_yaml_text, new_data)`` WITHOUT writing. Raises ValueError on
    invalid input. Shared by apply_updates (writes) and preview_updates (diff).
    """
    path = _config_path()
    old_text = path.read_text()
    data = yaml.safe_load(old_text) or {}
    for sec in ("oniops", "scope", "llm", "integrations"):
        data.setdefault(sec, {})

    if "instance_name" in updates:
        data["oniops"]["instance_name"] = str(updates["instance_name"])[:64] or "OniOps"
    if "external_url" in updates:
        data["oniops"]["external_url"] = str(updates["external_url"]).strip().rstrip("/")

    if "scope" in updates:
        su = updates["scope"] or {}
        if "allowed_cidrs" in su:
            cidrs = [str(c).strip() for c in su["allowed_cidrs"] if str(c).strip()]
            if not cidrs:
                raise ValueError("scope.allowed_cidrs cannot be empty")
            for c in cidrs:
                ipaddress.ip_network(c, strict=False)
            data["scope"]["allowed_cidrs"] = cidrs
        if "exclude" in su:
            ex = [str(c).strip() for c in su["exclude"] if str(c).strip()]
            for c in ex:
                ipaddress.ip_network(c, strict=False)
            data["scope"]["exclude"] = ex
        if "mode" in su:
            if su["mode"] not in _SCOPE_MODES:
                raise ValueError(f"scope.mode must be one of {sorted(_SCOPE_MODES)}")
            data["scope"]["mode"] = su["mode"]
        if "non_destructive" in su:
            data["scope"]["non_destructive"] = bool(su["non_destructive"])
        if "allow_intrusive_playbooks" in su:
            data["scope"]["allow_intrusive_playbooks"] = bool(su["allow_intrusive_playbooks"])
        if "rate_limit_per_min" in su:
            data["scope"]["rate_limit_per_min"] = max(1, int(su["rate_limit_per_min"]))

    if "llm" in updates and isinstance(updates["llm"].get("roles"), dict):
        data["llm"].setdefault("roles", {})
        for role, rc in updates["llm"]["roles"].items():
            if role in ("planner", "reporter", "reason") and isinstance(rc, dict):
                data["llm"]["roles"][role] = {
                    "provider": str(rc.get("provider", "ollama")),
                    "model": str(rc.get("model", "")),
                }

    if "attack_hosts" in updates:
        hosts = []
        for h in updates["attack_hosts"]:
            if not h.get("host"):
                continue
            entry = {"name": str(h.get("name") or f"host{len(hosts) + 1}"),
                     "host": str(h["host"]).strip(),
                     "user": str(h.get("user") or "root"),
                     "ssh_key": str(h.get("ssh_key") or "./secrets/kali_id_rsa")}
            if h.get("label"):
                entry["label"] = str(h["label"])
            if h.get("default"):
                entry["default"] = True
            hosts.append(entry)
        if not hosts:
            raise ValueError("at least one attack host (with a host address) is required")
        if not any(h.get("default") for h in hosts):
            hosts[0]["default"] = True
        data["attack_hosts"] = hosts
        data.pop("kali", None)

    if "integrations" in updates:
        iu = updates["integrations"] or {}
        for k in ("misp", "caldera"):
            if k in iu and isinstance(iu[k], dict):
                data["integrations"].setdefault(k, {})
                data["integrations"][k]["enabled"] = bool(iu[k].get("enabled"))
                if "host" in iu[k]:
                    data["integrations"][k]["host"] = str(iu[k]["host"]).strip()
        # NVD CVE enrichment: optional, off by default. No host; optional key.
        if "nvd" in iu and isinstance(iu["nvd"], dict):
            data["integrations"].setdefault("nvd", {})
            data["integrations"]["nvd"]["enabled"] = bool(iu["nvd"].get("enabled"))
            if "api_key" in iu["nvd"]:
                data["integrations"]["nvd"]["api_key"] = str(iu["nvd"]["api_key"]).strip()

    return path, old_text, data


def _redact(text: str) -> str:
    """Mask secret-ish values in YAML before showing a diff to the UI."""
    return re.sub(r"(?im)^(\s*(?:api_key|secret|password|token)\s*:\s*).+$",
                  r"\1***", text)


def preview_updates(updates: dict) -> dict:
    """Validate ``updates`` and return a unified diff of config.yaml WITHOUT
    writing. Lets the UI show exactly what a save would change (config drives
    command execution, so a confirm step reduces footguns)."""
    _path, old_text, data = _build_updated_config(updates)
    old_data = yaml.safe_load(old_text) or {}
    # Normalize BOTH sides through the same serializer so the diff shows only
    # real changes, not YAML-formatting churn. "changed" is semantic.
    def _dump(d):
        return yaml.safe_dump(d, sort_keys=False, default_flow_style=False)
    diff = "".join(difflib.unified_diff(
        _redact(_dump(old_data)).splitlines(keepends=True),
        _redact(_dump(data)).splitlines(keepends=True),
        fromfile="config.yaml (current)", tofile="config.yaml (proposed)",
    ))
    return {"changed": old_data != data, "diff": diff}


def apply_updates(updates: dict) -> Config:
    """Validate and persist a partial config update from the UI, then reload.

    Only non-secret, operational fields are editable here (scope, attack hosts,
    LLM roles, integrations, instance). Secrets stay in .env; auth mode is
    config-file/restart only. Writes a .bak first and validates before saving.
    """
    path, _old, data = _build_updated_config(updates)
    path.with_name(path.name + ".bak").write_text(path.read_text())
    path.write_text(yaml.safe_dump(data, sort_keys=False, default_flow_style=False))
    return get_config(reload=True)

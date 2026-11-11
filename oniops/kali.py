"""SSH execution against the attack host (Kali).

Uses paramiko (pure-Python) rather than shelling out to an ``ssh`` binary, so
OniOps runs unchanged on Linux, Windows and inside containers. Every command is
scope-guarded before it leaves the controller.
"""

from __future__ import annotations

import ipaddress
import os
import re
import shlex
from dataclasses import dataclass
from pathlib import Path

import paramiko

from .config import Config, get_config
from .ratelimit import RateLimiter, response_throttle_status, target_key_from_command
from .scope import Scope, ScopeViolation

# After a target answers HTTP 429/503, push its next slot out by this long.
THROTTLE_COOLDOWN_SECONDS = 30.0


def docker_worker_argv(host, cmd_args: list[str], timeout: int = 90,
                      scope_cidrs: list[str] | None = None) -> list[str]:
    """Build a least-privilege, one-command Docker worker invocation."""
    image = str(getattr(host, "worker_image", "") or "")
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._/:@-]{0,200}", image):
        raise ValueError("Docker worker mode requires a valid worker_image.")
    if not cmd_args:
        raise ValueError("Cannot start an empty worker command.")
    network = str(getattr(host, "worker_network", "oniops-worker-net"))
    if (not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,62}", network)
            or network.lower() in {"bridge", "host", "none"}):
        raise ValueError("Docker worker network must be a user-defined bridge; built-in modes bypass isolation.")
    networks = list(scope_cidrs or [])
    if not networks:
        raise ValueError("Docker worker requires at least one effective in-scope CIDR.")
    for cidr in networks:
        try:
            ipaddress.ip_network(cidr, strict=True)
        except ValueError as exc:
            raise ValueError(f"Invalid effective worker scope CIDR: {cidr}") from exc
    memory = int(getattr(host, "worker_memory_mb", 1024))
    cpus = float(getattr(host, "worker_cpus", 2.0))
    pids = int(getattr(host, "worker_pids_limit", 256))
    user = str(getattr(host, "worker_user", "65534:65534"))
    if not 128 <= memory <= 32768 or not 0.25 <= cpus <= 32 or not 32 <= pids <= 4096:
        raise ValueError("Docker worker resource limits are outside safe bounds.")
    if not re.fullmatch(r"\d{1,6}:\d{1,6}", user):
        raise ValueError("Docker worker user must be a numeric uid:gid pair.")
    return [
        "timeout", "-k", "5s", f"{max(1, min(int(timeout), 3600))}s",
        "docker", "run", "--rm", "--network", network,
        "--read-only", "--cap-drop=ALL", "--cap-add=NET_ADMIN",
        "--cap-add=SETUID", "--cap-add=SETGID",
        "--security-opt=no-new-privileges",
        "--pids-limit", str(pids), "--memory", f"{memory}m", "--cpus", str(cpus),
        "--tmpfs", "/tmp:rw,noexec,nosuid,nodev,size=256m",
        "--env", "HOME=/tmp", "--env", "TMPDIR=/tmp",
        "--env", f"ONIOPS_WORKER_UID_GID={user}",
        "--env", f"ONIOPS_SCOPE_CIDRS={','.join(networks)}",
        "--entrypoint", "/usr/local/sbin/oniops-worker-entrypoint", image, *cmd_args,
    ]


@dataclass
class CmdResult:
    rc: int
    out: str

    @property
    def ok(self) -> bool:
        return self.rc == 0


class KaliRunner:
    """Runs scope-guarded commands on an attack host over SSH (paramiko).

    `host` is a HostConfig (Kali or any tooled Linux). Defaults to the active
    host in config for back-compat.

    Every command is paced by ``limiter`` (built from
    ``scope.rate_limit_per_min`` unless one is injected). One command aimed at
    a target = one unit for that target; commands that name no target
    (``echo``, ``searchsploit``, local bookkeeping) are not charged. A single
    command may still send many packets (nmap, nikto); the limit does not
    bound packets. Each runner paces independently.
    """

    def __init__(self, host=None, scope: Scope | None = None, cfg: Config | None = None,
                 limiter: RateLimiter | None = None):
        self.cfg = cfg or get_config()
        self.host = host or self.cfg.kali
        self.scope = scope or Scope(self.cfg)
        self.limiter = limiter or RateLimiter(self.cfg.scope.rate_limit_per_min)

    def _host_policy(self, client: paramiko.SSHClient):
        """Configure host-key verification per config.kali.verify_host_key.

        tofu   - trust on first use: load a saved known_hosts, accept+persist a
                 new key, but a CHANGED key is rejected (MITM protection).
        strict - only hosts already in known_hosts are allowed.
        insecure - accept any key (not recommended).
        """
        mode = (self.host.verify_host_key or "tofu").lower()
        kh = Path(self.host.known_hosts)
        if mode == "insecure":
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            return
        if kh.exists():
            try:
                client.load_host_keys(str(kh))
            except Exception:
                pass
        if mode == "strict":
            client.set_missing_host_key_policy(paramiko.RejectPolicy())
        else:  # tofu
            kh.parent.mkdir(parents=True, exist_ok=True)
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            self._persist_kh = str(kh)

    def _client(self) -> paramiko.SSHClient:
        client = paramiko.SSHClient()
        self._persist_kh = None
        self._host_policy(client)
        client.connect(
            hostname=self.host.host,
            username=self.host.user,
            key_filename=self.host.ssh_key,
            timeout=self.host.connect_timeout,
            banner_timeout=self.host.connect_timeout,
            auth_timeout=self.host.connect_timeout,
            look_for_keys=False,
            allow_agent=False,
        )
        return client

    def run(self, cmd_args: list[str], timeout: int = 90) -> CmdResult:
        """Run an argv list on the Kali host. Args are shell-quoted; the joined
        command is scope-guarded for destructive patterns first."""
        target_command = " ".join(shlex.quote(a) for a in cmd_args)
        try:
            self.scope.guard_command(target_command)
        except ScopeViolation as exc:
            return CmdResult(rc=126, out=str(exc))

        try:
            execution_args = (docker_worker_argv(
                                  self.host, cmd_args, timeout=timeout,
                                  scope_cidrs=self.scope.effective_cidrs)
                              if getattr(self.host, "execution_mode", "ssh") == "docker"
                              else cmd_args)
        except (TypeError, ValueError) as exc:
            return CmdResult(rc=2, out=f"Worker configuration error: {exc}")
        command = " ".join(shlex.quote(a) for a in execution_args)

        # Rate limit: block until this command's target has a free slot.
        target = target_key_from_command(target_command)
        self.limiter.acquire(target)
        result = self._exec(command, timeout)
        # Per-target cool-down when a curl-style response shows 429/503.
        if target and response_throttle_status(result.out):
            self.limiter.penalize(target, THROTTLE_COOLDOWN_SECONDS)
        return result

    def _exec(self, command: str, timeout: int) -> CmdResult:
        try:
            client = self._client()
        except Exception as exc:
            return CmdResult(rc=1, out=f"SSH connection error: {exc}")

        # TOFU: persist newly-accepted host keys so a later change is caught.
        if getattr(self, "_persist_kh", None):
            try:
                client.save_host_keys(self._persist_kh)
                os.chmod(self._persist_kh, 0o600)
            except Exception:
                pass

        try:
            _stdin, stdout, stderr = client.exec_command(command, timeout=timeout)
            out = stdout.read().decode("utf-8", "replace")
            err = stderr.read().decode("utf-8", "replace")
            rc = stdout.channel.recv_exit_status()
            combined = out + (("\n" + err) if err.strip() else "")
            return CmdResult(rc=rc, out=combined.strip())
        except Exception as exc:
            return CmdResult(rc=124, out=f"Command error/timeout: {exc}")
        finally:
            client.close()

    def ping(self) -> bool:
        return self.run(["echo", "ok"], timeout=5).out.strip().endswith("ok")

"""SSH execution against the attack host (Kali).

Uses paramiko (pure-Python) rather than shelling out to an ``ssh`` binary, so
ONIOPS runs unchanged on Linux, Windows and inside containers. Every command is
scope-guarded before it leaves the controller.
"""

from __future__ import annotations

import shlex
from dataclasses import dataclass

import paramiko

from .config import Config, get_config
from .scope import Scope, ScopeViolation


@dataclass
class CmdResult:
    rc: int
    out: str

    @property
    def ok(self) -> bool:
        return self.rc == 0


class KaliRunner:
    def __init__(self, cfg: Config | None = None, scope: Scope | None = None):
        self.cfg = cfg or get_config()
        self.scope = scope or Scope(self.cfg)

    def _client(self) -> paramiko.SSHClient:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(
            hostname=self.cfg.kali.host,
            username=self.cfg.kali.user,
            key_filename=self.cfg.kali.ssh_key,
            timeout=self.cfg.kali.connect_timeout,
            banner_timeout=self.cfg.kali.connect_timeout,
            auth_timeout=self.cfg.kali.connect_timeout,
            look_for_keys=False,
            allow_agent=False,
        )
        return client

    def run(self, cmd_args: list[str], timeout: int = 90) -> CmdResult:
        """Run an argv list on the Kali host. Args are shell-quoted; the joined
        command is scope-guarded for destructive patterns first."""
        command = " ".join(shlex.quote(a) for a in cmd_args)
        try:
            self.scope.guard_command(command)
        except ScopeViolation as exc:
            return CmdResult(rc=126, out=str(exc))

        try:
            client = self._client()
        except Exception as exc:  # noqa: BLE001 - surface any SSH/connect error
            return CmdResult(rc=1, out=f"SSH connection error: {exc}")

        try:
            _stdin, stdout, stderr = client.exec_command(command, timeout=timeout)
            out = stdout.read().decode("utf-8", "replace")
            err = stderr.read().decode("utf-8", "replace")
            rc = stdout.channel.recv_exit_status()
            combined = out + (("\n" + err) if err.strip() else "")
            return CmdResult(rc=rc, out=combined.strip())
        except Exception as exc:  # noqa: BLE001
            return CmdResult(rc=124, out=f"Command error/timeout: {exc}")
        finally:
            client.close()

    def ping(self) -> bool:
        return self.run(["echo", "ok"], timeout=5).out.strip().endswith("ok")

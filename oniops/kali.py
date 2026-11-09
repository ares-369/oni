"""SSH execution against the attack host (Kali).

Uses paramiko (pure-Python) rather than shelling out to an ``ssh`` binary, so
ONIOPS runs unchanged on Linux, Windows and inside containers. Every command is
scope-guarded before it leaves the controller.
"""

from __future__ import annotations

import os
import shlex
from dataclasses import dataclass
from pathlib import Path

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
    """Runs scope-guarded commands on an attack host over SSH (paramiko).

    `host` is a HostConfig (Kali or any tooled Linux). Defaults to the active
    host in config for back-compat.
    """

    def __init__(self, host=None, scope: Scope | None = None, cfg: Config | None = None):
        self.cfg = cfg or get_config()
        self.host = host or self.cfg.kali
        self.scope = scope or Scope(self.cfg)

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
        command = " ".join(shlex.quote(a) for a in cmd_args)
        try:
            self.scope.guard_command(command)
        except ScopeViolation as exc:
            return CmdResult(rc=126, out=str(exc))

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

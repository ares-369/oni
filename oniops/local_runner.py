"""Loopback-only local runner (used by `oniops demo` and the end-to-end tests).

Same interface as `KaliRunner.run(cmd, timeout=...) -> CmdResult`, but the
probe runs on this machine instead of over SSH. It is deliberately narrow:

  - Every command goes through `Scope.guard_command` first, exactly like the
    SSH runner (destructive-pattern guard + out-of-scope IP check).
  - Only `curl` is allowed. The engines (greybox.probe_openapi,
    probe_graphql_introspection, discover_js_endpoints, FindingsLedger.retest)
    build curl argv lists; the runner executes that argv unchanged with
    `subprocess.run(list, shell=False)`, so the real engine code path is kept.
  - Every URL in the argv must point at a loopback host (127.0.0.0/8, ::1,
    localhost) AND the scope must allow it. Anything else is refused with
    rc=126 and nothing is executed.
  - Flags that could send curl somewhere else or touch files (`-K`,
    `--config`, `-x`, `--proxy`, `--connect-to`, `--resolve`, `-o`, `-O`,
    `-T`, `--location`, ...) are refused. curl is always run with `-q` (no
    ~/.curlrc), `--noproxy *`, `--proto =http,https` and `--max-redirs 0`, so
    the `-L` inside the engines' combined `-ksSL` flag cannot follow a
    redirect off loopback.
"""
from __future__ import annotations

import os
import re
import shlex
import shutil
import subprocess
from urllib.parse import urlsplit

from .demo_target import is_loopback_host
from .kali import CmdResult
from .scope import Scope, ScopeViolation

_URL_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.\-]*://")
_FORBIDDEN_FLAGS = {
    "-K", "--config", "-x", "--proxy", "--preproxy", "--connect-to", "--resolve",
    "-o", "--output", "-O", "--remote-name", "-T", "--upload-file", "--location",
    "--location-trusted", "--unix-socket", "--abstract-unix-socket",
}


class LocalRunner:
    """Runs scope-guarded curl probes against loopback targets only."""

    def __init__(self, scope: Scope, curl_path: str = "") -> None:
        if scope is None:
            raise ValueError("LocalRunner requires a Scope; it never runs unscoped.")
        self.scope = scope
        self.curl = curl_path or shutil.which("curl") or ""
        for cidr in scope.cidrs:
            net_ip = cidr.split("/", 1)[0]
            if not is_loopback_host(net_ip):
                raise ValueError(
                    f"LocalRunner is loopback-only, but the scope includes {cidr}. "
                    "Use the SSH attack-host runner for real targets."
                )
        self.commands_run: list[str] = []

    def _check_argv(self, argv: list[str]) -> None:
        if not argv or os.path.basename(str(argv[0])) != "curl":
            raise ScopeViolation(f"LocalRunner only runs curl probes (got {argv[:1]}).")
        urls = 0
        for a in argv[1:]:
            a = str(a)
            if a in _FORBIDDEN_FLAGS or any(a.startswith(f + "=") for f in _FORBIDDEN_FLAGS if f.startswith("--")):
                raise ScopeViolation(f"LocalRunner refuses curl flag {a!r}.")
            if _URL_RE.match(a):
                parts = urlsplit(a)
                if parts.scheme not in ("http", "https"):
                    raise ScopeViolation(f"LocalRunner only allows http/https URLs (got {parts.scheme}).")
                host = parts.hostname or ""
                if not is_loopback_host(host):
                    raise ScopeViolation(
                        f"LocalRunner refused {host or a!r}: only loopback targets are allowed."
                    )
                ip = "127.0.0.1" if host == "localhost" else host
                if not self.scope.is_in_scope(ip):
                    raise ScopeViolation(f"Scope violation: {ip} is outside the authorized scope.")
                urls += 1
        if urls == 0:
            raise ScopeViolation("LocalRunner refused a curl command without an explicit target URL.")

    def run(self, cmd_args: list[str], timeout: int = 30) -> CmdResult:
        argv = [str(a) for a in cmd_args]
        command = " ".join(shlex.quote(a) for a in argv)
        try:
            self.scope.guard_command(command)
            self._check_argv(argv)
        except ScopeViolation as exc:
            return CmdResult(rc=126, out=str(exc))
        if not self.curl:
            return CmdResult(rc=127, out="Command error/timeout: curl is not installed on this machine.")
        self.commands_run.append(command)
        # Hardening that keeps curl on loopback: no proxy, http(s) only, no redirects.
        safe = [self.curl, "-q", "--noproxy", "*", "--proto", "=http,https", "--max-redirs", "0", *argv[1:]]
        env = {k: v for k, v in os.environ.items() if not k.lower().endswith("_proxy")}
        try:
            proc = subprocess.run(safe, capture_output=True, text=True, timeout=max(1, int(timeout)),
                                  shell=False, check=False, env=env, stdin=subprocess.DEVNULL)
        except subprocess.TimeoutExpired:
            return CmdResult(rc=124, out="Command error/timeout: local probe timed out.")
        except OSError as exc:
            return CmdResult(rc=1, out=f"Command error/timeout: {exc}")
        err = proc.stderr or ""
        out = (proc.stdout or "") + (("\n" + err) if err.strip() else "")
        return CmdResult(rc=proc.returncode, out=out.strip())

    def run_out(self, cmd: list[str], timeout: int = 30) -> str:
        """`run_fn(cmd, timeout) -> str` adapter for the greybox engines."""
        return self.run(cmd, timeout=timeout).out

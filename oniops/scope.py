"""Scope / Rules-of-Engagement enforcement.

Replaces the old hardcoded ``ALLOWED_SCOPES`` and the per-lab ``10.0.0.0/24``
assumptions. Everything here is driven by ``config.yaml`` so any deployer sets
their own networks.
"""

from __future__ import annotations

import ipaddress
import re
import socket
from dataclasses import dataclass

from .config import Config, get_config

# Tokens that indicate a destructive / denial-of-service action. When
# scope.non_destructive is on (default), any command containing these is
# refused before it ever reaches the attack host.
_DESTRUCTIVE_PATTERNS = [
    r"\brm\s+-rf\b",
    r"\bmkfs\b",
    r"\bdd\s+if=",
    r":\(\)\s*\{",            # fork bomb
    r"\bshutdown\b",
    r"\breboot\b",
    r"\bhalt\b",
    r"--script[= ].*\bdos\b",  # nmap DoS scripts
    r"\bhping3\b.*--flood",
    r"\bslowloris\b",
    r"\bdrop\s+database\b",
    r"\bdrop\s+table\b",
]
_DESTRUCTIVE_RE = re.compile("|".join(_DESTRUCTIVE_PATTERNS), re.IGNORECASE)


class ScopeViolation(Exception):
    """Raised when a target or command falls outside the Rules of Engagement."""


@dataclass
class ResolvedTarget:
    ip: str
    label: str          # hostname if known, else the ip
    note: str = ""


class Scope:
    def __init__(self, cfg: Config | None = None):
        self.cfg = cfg or get_config()
        self._allowed = [ipaddress.ip_network(c, strict=False) for c in self.cfg.scope.allowed_cidrs]
        self._excluded = []
        for e in self.cfg.scope.exclude:
            try:
                self._excluded.append(ipaddress.ip_network(e, strict=False))
            except ValueError:
                pass

    # ---- membership ----
    def is_in_scope(self, target: str) -> bool:
        try:
            ip = ipaddress.ip_address(target)
        except ValueError:
            return False
        if any(ip in net for net in self._excluded):
            return False
        return any(ip in net for net in self._allowed)

    def resolve(self, raw: str) -> ResolvedTarget:
        """Resolve a user-supplied target (IP or hostname) to an in-scope IP.

        Raises ScopeViolation if it is empty, unresolvable, or out of scope.
        """
        t = (raw or "").strip()
        if not t:
            raise ScopeViolation("Target cannot be empty.")

        # Try as a literal IP first.
        try:
            ipaddress.ip_address(t)
            ip = t
        except ValueError:
            # Resolve hostname via DNS, then scope-check the resulting IP.
            try:
                ip = socket.gethostbyname(t)
            except OSError as exc:
                raise ScopeViolation(f"Could not resolve '{raw}': {exc}") from exc

        if not self.is_in_scope(ip):
            raise ScopeViolation(
                f"Scope violation: {ip} is outside the authorized Rules of "
                f"Engagement ({', '.join(self.cfg.scope.allowed_cidrs)})."
            )
        label = t if t != ip else ip
        return ResolvedTarget(ip=ip, label=label)

    # ---- command safety ----
    def guard_command(self, command: str) -> None:
        """Refuse obviously destructive commands when non_destructive is set."""
        if self.cfg.scope.non_destructive and _DESTRUCTIVE_RE.search(command):
            raise ScopeViolation(
                "Blocked: command matches a destructive/DoS pattern and "
                "scope.non_destructive is enabled."
            )

    @property
    def cidrs(self) -> list[str]:
        return list(self.cfg.scope.allowed_cidrs)


def autodetect_subnet() -> str | None:
    """Best-effort guess of the local /24 for the first-run scope prompt."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        net = ipaddress.ip_network(f"{local_ip}/24", strict=False)
        return str(net)
    except OSError:
        return None

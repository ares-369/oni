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
from urllib.parse import urlsplit

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
_NET_TOOLS_RE = re.compile(
    r"^\s*(?:sudo\s+)?(?:nmap|curl|wget|nuclei|ffuf|nikto|whatweb|httpx|wafw00f|katana|gobuster|enum4linux(?:-ng)?|sqlmap|hydra|sslscan)\b",
    re.IGNORECASE,
)
_IPV4_RE = re.compile(r"\b((?:\d{1,3}\.){3}\d{1,3})\b")
_HTTP_URL_RE = re.compile(r"https?://[^\s\"'<>]+", re.IGNORECASE)
_NMAP_IPV4_TARGET_RE = re.compile(
    r"\b((?:\d{1,3}\.){3}\d{1,3})(?:/((?:\d{1,3}\.){3}\d{1,3}|\d{1,2})|-(\d{1,3}(?:\.\d{1,3}){0,3}))?\b"
)


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
            # Resolve hostname via DNS, then scope-check ALL resulting IPs.
            try:
                ip = socket.gethostbyname(t)
            except OSError as exc:
                raise ScopeViolation(f"Could not resolve '{raw}': {exc}") from exc
            try:
                infos = socket.getaddrinfo(t, None)
                for info in infos:
                    addr = info[4][0]
                    if "%" in addr:
                        addr = addr.split("%", 1)[0]
                    if not self.is_in_scope(addr):
                        raise ScopeViolation(
                            f"Scope violation: '{raw}' resolved to out-of-scope address {addr} "
                            f"(authorized: {', '.join(self.cfg.scope.allowed_cidrs)})."
                        )
            except ScopeViolation:
                raise
            except OSError:
                pass

        if not self.is_in_scope(ip):
            raise ScopeViolation(
                f"Scope violation: {ip} is outside the authorized Rules of "
                f"Engagement ({', '.join(self.cfg.scope.allowed_cidrs)})."
            )
        label = t if t != ip else ip
        return ResolvedTarget(ip=ip, label=label)

    # ---- command safety ----
    def guard_command(self, command: str) -> None:
        """Refuse destructive commands and network commands targeting out-of-scope IPs.

        For nmap, validate full CIDR and address-range targets too: checking only
        the first address would let a command starting in scope scan beyond the
        authorized network.
        """
        if self.cfg.scope.non_destructive and _DESTRUCTIVE_RE.search(command):
            raise ScopeViolation(
                "Blocked: command matches a destructive/DoS pattern and "
                "scope.non_destructive is enabled."
            )
        if _NET_TOOLS_RE.search(command or ""):
            for match in _HTTP_URL_RE.finditer(command):
                parsed = urlsplit(match.group(0).rstrip(")],;"))
                if parsed.hostname:
                    self.resolve(parsed.hostname)
            is_nmap = bool(re.match(r"^\s*(?:sudo\s+)?nmap\b", command or "", re.I))
            if is_nmap:
                # Nmap also accepts wildcard and per-octet expressions such as
                # 10.0.0-2.4. Until those forms have a complete expander, reject
                # them instead of validating only a partial address substring.
                for token in re.findall(r"(?<!\S)[^\s]+", command):
                    if ":" in token and not token.startswith("-"):
                        try:
                            network = (ipaddress.ip_network(token, strict=False) if "/" in token
                                       else ipaddress.ip_network(f"{token}/128"))
                        except ValueError:
                            raise ScopeViolation(
                                f"Unsupported nmap IPv6 target expression: {token}. "
                                "Use an explicit IPv6 address or CIDR."
                            ) from None
                        if not self._range_in_scope(network.network_address, network.broadcast_address):
                            raise ScopeViolation(
                                f"Scope violation in command: target {token} is outside the authorized "
                                f"Rules of Engagement ({', '.join(self.cfg.scope.allowed_cidrs)})."
                            )
                    if token.startswith("-") or "." not in token or not any(ch in token for ch in "-*/, "):
                        continue
                    for item in token.split(","):
                        try:
                            if "/" in item:
                                ipaddress.ip_network(item, strict=False)
                            elif "-" in item:
                                base, end = item.split("-", 1)
                                ipaddress.IPv4Address(base)
                                if "." in end:
                                    ipaddress.IPv4Address(end)
                                elif not end.isdigit() or int(end) > 255:
                                    raise ValueError("invalid range")
                            else:
                                ipaddress.IPv4Address(item)
                        except ValueError:
                            raise ScopeViolation(
                                f"Unsupported nmap target expression: {item}. Use explicit IPv4 addresses, "
                                "CIDRs, or full-address ranges."
                            ) from None
            matches = (_NMAP_IPV4_TARGET_RE.finditer(command) if is_nmap
                       else _IPV4_RE.finditer(command))
            for m in matches:
                cand = m.group(1)
                try:
                    first = ipaddress.IPv4Address(cand)
                except ValueError:
                    continue
                last = first
                if is_nmap and m.group(2):
                    try:
                        network = ipaddress.ip_network(f"{cand}/{m.group(2)}", strict=False)
                    except ValueError:
                        raise ScopeViolation(f"Invalid nmap network target: {m.group(0)}") from None
                    first, last = network.network_address, network.broadcast_address
                elif is_nmap and m.group(3):
                    end = m.group(3)
                    try:
                        last = (ipaddress.IPv4Address(end) if "." in end
                                else ipaddress.IPv4Address(int(first) - (int(first) % 256) + int(end)))
                    except ValueError:
                        raise ScopeViolation(f"Invalid nmap address range: {m.group(0)}") from None
                    if last < first:
                        raise ScopeViolation(f"Invalid nmap address range: {m.group(0)}")
                if not self._range_in_scope(first, last):
                    raise ScopeViolation(
                        f"Scope violation in command: target {m.group(0)} is outside the authorized "
                        f"Rules of Engagement ({', '.join(self.cfg.scope.allowed_cidrs)})."
                    )

    def _range_in_scope(self, first: ipaddress.IPv4Address | ipaddress.IPv6Address,
                        last: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
        """Return true only when every address in a range is allowed and not excluded."""
        if first.version != last.version:
            return False
        version = first.version
        lo, hi = int(first), int(last)
        allowed = sorted((int(net.network_address), int(net.broadcast_address))
                         for net in self._allowed if net.version == version)
        cursor = lo
        for start, end in allowed:
            if end < cursor:
                continue
            if start > cursor:
                return False
            cursor = max(cursor, end + 1)
            if cursor > hi:
                break
        if cursor <= hi:
            return False
        return not any(
            net.version == version and int(net.network_address) <= hi and int(net.broadcast_address) >= lo
            for net in self._excluded
        )

    @property
    def cidrs(self) -> list[str]:
        return list(self.cfg.scope.allowed_cidrs)

    @property
    def effective_cidrs(self) -> list[str]:
        """Return allow networks with excluded networks removed.

        Docker workers use these networks for kernel-level egress filtering,
        so an excluded subnet must not remain hidden inside a broader allowlist.
        """
        effective = list(self._allowed)
        for excluded in self._excluded:
            next_effective = []
            for allowed in effective:
                if allowed.version != excluded.version or not allowed.overlaps(excluded):
                    next_effective.append(allowed)
                elif excluded.supernet_of(allowed) or excluded == allowed:
                    continue
                else:
                    next_effective.extend(allowed.address_exclude(excluded))
            effective = next_effective
        collapsed = []
        for version in (4, 6):
            collapsed.extend(ipaddress.collapse_addresses(
                network for network in effective if network.version == version
            ))
        return [str(network) for network in collapsed]


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

"""Target discovery.

Replaces the old hardcoded per-lab host list. Hosts are discovered live by
sweeping the configured scope CIDRs from the Kali host (nmap -sn), so ONIOPS
populates itself in any environment.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from .kali import KaliRunner
from .scope import Scope

# "Nmap scan report for hostname (10.0.0.5)"  or  "... report for 10.0.0.5"
_REPORT_RE = re.compile(r"Nmap scan report for (?:([^\s()]+) \(([\d.]+)\)|([\d.]+))")


@dataclass
class DiscoveredHost:
    ip: str
    hostname: str


def discover(runner: KaliRunner, scope: Scope, timeout: int = 180) -> list[DiscoveredHost]:
    """Ping-sweep every allowed CIDR and return live hosts (minus excludes)."""
    found: dict[str, DiscoveredHost] = {}
    for cidr in scope.cidrs:
        res = runner.run(["nmap", "-sn", "-T4", "-n" if False else "-R", cidr], timeout=timeout)
        for m in _REPORT_RE.finditer(res.out):
            host, ip1, ip2 = m.group(1), m.group(2), m.group(3)
            ip = ip1 or ip2
            if not ip or not scope.is_in_scope(ip):
                continue
            found[ip] = DiscoveredHost(ip=ip, hostname=host or f"host-{ip}")
    return sorted(found.values(), key=lambda h: tuple(int(x) for x in h.ip.split(".")))

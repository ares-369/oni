"""Tests for the Rules-of-Engagement safety boundary.

scope.py decides what OniOps is allowed to touch and which commands are refused.
It is the single most safety-critical module, so it gets the most coverage.
"""
from __future__ import annotations

import pytest

from oniops.config import get_config
from oniops.scope import Scope, ScopeViolation, autodetect_subnet


@pytest.fixture()
def scope(cfg_path):
    return Scope(get_config(reload=True))


# ───────────────────────── membership ─────────────────────────
class TestMembership:
    def test_in_scope_ip(self, scope):
        assert scope.is_in_scope("10.0.0.50")
        assert scope.is_in_scope("192.168.50.200")

    def test_out_of_scope_ip(self, scope):
        assert not scope.is_in_scope("10.0.1.5")
        assert not scope.is_in_scope("8.8.8.8")
        assert not scope.is_in_scope("172.16.0.1")

    def test_excluded_ip_is_not_in_scope(self, scope):
        # 10.0.0.1 is inside the allowed /24 but explicitly excluded.
        assert not scope.is_in_scope("10.0.0.1")

    def test_garbage_is_not_in_scope(self, scope):
        assert not scope.is_in_scope("not-an-ip")
        assert not scope.is_in_scope("")
        assert not scope.is_in_scope("10.0.0.999")


# ───────────────────────── resolve ─────────────────────────
class TestResolve:
    def test_resolve_in_scope_ip(self, scope):
        rt = scope.resolve("10.0.0.42")
        assert rt.ip == "10.0.0.42"
        assert rt.label == "10.0.0.42"

    def test_resolve_empty_rejected(self, scope):
        with pytest.raises(ScopeViolation):
            scope.resolve("")
        with pytest.raises(ScopeViolation):
            scope.resolve("   ")

    def test_resolve_out_of_scope_rejected(self, scope):
        with pytest.raises(ScopeViolation, match="outside the authorized"):
            scope.resolve("8.8.8.8")

    def test_resolve_excluded_rejected(self, scope):
        with pytest.raises(ScopeViolation):
            scope.resolve("10.0.0.1")

    def test_resolve_hostname_uses_dns_then_scope(self, scope, monkeypatch):
        # Hostname that resolves to an out-of-scope IP must be refused.
        monkeypatch.setattr("socket.gethostbyname", lambda h: "8.8.8.8")
        with pytest.raises(ScopeViolation):
            scope.resolve("evil.example.com")
        # ...and one resolving in-scope is allowed, keeping the label.
        monkeypatch.setattr("socket.gethostbyname", lambda h: "10.0.0.7")
        rt = scope.resolve("box.lab")
        assert rt.ip == "10.0.0.7"
        assert rt.label == "box.lab"

    def test_resolve_unresolvable_hostname_rejected(self, scope, monkeypatch):
        def boom(h):
            raise OSError("name resolution failed")
        monkeypatch.setattr("socket.gethostbyname", boom)
        with pytest.raises(ScopeViolation, match="Could not resolve"):
            scope.resolve("nope.invalid")


# ───────────────────────── destructive-command guard ─────────────────────────
class TestGuardCommand:
    @pytest.mark.parametrize("cmd", [
        "rm -rf /",
        "rm   -rf  /var",
        "mkfs.ext4 /dev/sda",
        "dd if=/dev/zero of=/dev/sda",
        "shutdown -h now",
        "reboot",
        "halt",
        "hping3 --flood 10.0.0.5",
        "nmap --script dos 10.0.0.5",
        "DROP TABLE users;",
        "drop database prod;",
        ":(){ :|:& };:",
    ])
    def test_destructive_blocked(self, scope, cmd):
        with pytest.raises(ScopeViolation):
            scope.guard_command(cmd)

    @pytest.mark.parametrize("cmd", [
        "nmap -sV -sC 10.0.0.5",
        "sqlmap -u http://10.0.0.5/?id=1 --batch",
        "nuclei -target http://10.0.0.5",
        "whatweb 10.0.0.5",
        "msfconsole -q -x 'use auxiliary/scanner/http/title'",
        "hydra -l admin -P list.txt 10.0.0.5 ssh",  # exploitation, not destruction
    ])
    def test_exploitation_allowed(self, scope, cmd):
        # Exploitation tooling must NOT be blocked by the destructive guard.
        scope.guard_command(cmd)

    @pytest.mark.parametrize("cmd", [
        "nmap 10.0.0.0/23",       # starts in scope but extends into 10.0.1.0/24
        "nmap 10.0.0.0-10",       # includes explicitly excluded 10.0.0.1
        "nmap 10.0.0.250-10.0.1.5",
    ])
    def test_nmap_ranges_must_be_fully_in_scope(self, scope, cmd):
        with pytest.raises(ScopeViolation):
            scope.guard_command(cmd)

    def test_nmap_range_inside_allowed_network(self, scope):
        scope.guard_command("nmap 10.0.0.20-30")

    def test_nmap_cidr_covering_exclusion_is_blocked(self, scope):
        with pytest.raises(ScopeViolation):
            scope.guard_command("nmap 10.0.0.0/24")

    def test_nmap_partial_octet_ranges_are_rejected_until_expanded(self, scope):
        with pytest.raises(ScopeViolation, match="Unsupported nmap target expression"):
            scope.guard_command("nmap 10.0.0-1.5")

    def test_nmap_ipv6_is_scope_checked(self, scope):
        with pytest.raises(ScopeViolation, match="outside the authorized"):
            scope.guard_command("nmap 2001:db8::1")

    def test_url_hostnames_are_resolved_and_scope_checked(self, scope, monkeypatch):
        monkeypatch.setattr("socket.gethostbyname", lambda _host: "8.8.8.8")
        with pytest.raises(ScopeViolation, match="outside the authorized"):
            scope.guard_command("curl https://outside.example/path")

        monkeypatch.setattr("socket.gethostbyname", lambda _host: "10.0.0.8")
        monkeypatch.setattr("socket.getaddrinfo", lambda _host, _port: [
            (2, 1, 6, "", ("10.0.0.8", 0)),
        ])
        scope.guard_command("curl https://inside.example/path")

    def test_guard_off_when_non_destructive_disabled(self, cfg_path):
        # With non_destructive=false the guard is a no-op even for rm -rf.
        text = cfg_path.read_text().replace("non_destructive: true", "non_destructive: false")
        cfg_path.write_text(text)
        s = Scope(get_config(reload=True))
        s.guard_command("rm -rf /")  # must not raise


def test_cidrs_property(scope):
    assert "10.0.0.0/24" in scope.cidrs


def test_autodetect_subnet_returns_cidr_or_none():
    res = autodetect_subnet()
    assert res is None or res.endswith("/24")

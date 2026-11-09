"""Tests for the agent loop's pure helpers — JSON extraction (model output is
untrusted/messy), target normalization, and httpx URL construction."""
from __future__ import annotations

from oniops.agent import _extract_json, _host_of, _httpx


class TestExtractJson:
    def test_plain_object(self):
        assert _extract_json('{"action": "nmap"}') == {"action": "nmap"}

    def test_code_fence(self):
        txt = 'Sure:\n```json\n{"action": "nmap", "args": {"target": "10.0.0.5"}}\n```'
        assert _extract_json(txt)["action"] == "nmap"

    def test_surrounding_prose(self):
        txt = 'I will scan. {"final": "done"} Hope that helps!'
        assert _extract_json(txt) == {"final": "done"}

    def test_nested_braces(self):
        txt = '{"action": "nuclei", "args": {"target": "10.0.0.5", "port": 443}}'
        assert _extract_json(txt)["args"]["port"] == 443

    def test_single_quotes_recovered(self):
        assert _extract_json("{'action': 'nmap'}") == {"action": "nmap"}

    def test_no_json(self):
        assert _extract_json("no json here") is None
        assert _extract_json("") is None


class TestHostOf:
    def test_strips_scheme_path_port(self):
        assert _host_of("http://10.0.0.5:8080/login.html") == "10.0.0.5"

    def test_bare_ip(self):
        assert _host_of("10.0.0.5") == "10.0.0.5"

    def test_https_with_path(self):
        assert _host_of("https://box.lab/admin") == "box.lab"


class _FakeRunner:
    """Captures the command the tool would run, without any SSH."""
    def __init__(self):
        self.cmd = None

    def run(self, cmd, timeout=0):
        self.cmd = cmd
        class _R:
            out = "mocked"
        return _R()


class TestHttpxUrl:
    def _url(self, runner):
        # the -u value is right after '-u'
        return runner.cmd[runner.cmd.index("-u") + 1]

    def test_host_root_default(self):
        r = _FakeRunner()
        _httpx(r, "10.0.0.5", {})
        assert self._url(r) == "http://10.0.0.5"

    def test_honours_port(self):
        r = _FakeRunner()
        _httpx(r, "10.0.0.5", {"port": 8080})
        assert self._url(r) == "http://10.0.0.5:8080"

    def test_honours_discovered_path(self):
        r = _FakeRunner()
        _httpx(r, "10.0.0.5", {"port": 8080, "path": "/login.html"})
        assert self._url(r) == "http://10.0.0.5:8080/login.html"

    def test_https_scheme_for_tls_port(self):
        r = _FakeRunner()
        _httpx(r, "10.0.0.5", {"port": 443, "path": "admin"})
        assert self._url(r) == "https://10.0.0.5:443/admin"

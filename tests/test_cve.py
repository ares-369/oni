"""Tests for offline-first CVE/exploit intelligence."""
from __future__ import annotations

import json

from oniops import cve


class TestExtractProductVersion:
    def test_apache(self):
        assert cve.extract_product_version("Apache httpd 2.4.49 ((Unix))") == ("Apache httpd", "2.4.49")

    def test_openssh(self):
        assert cve.extract_product_version("OpenSSH 8.2p1 Ubuntu 4ubuntu0.5") == ("OpenSSH", "8.2p1")

    def test_nginx(self):
        assert cve.extract_product_version("nginx 1.18.0") == ("nginx", "1.18.0")

    def test_versionless_banner_is_none(self):
        assert cve.extract_product_version("open") is None
        assert cve.extract_product_version("") is None
        assert cve.extract_product_version("ssh") is None

    def test_noise_tokens_dropped(self):
        # "Ubuntu" is a distro qualifier, not the product.
        prod, ver = cve.extract_product_version("vsftpd 2.3.4")
        assert prod == "vsftpd" and ver == "2.3.4"


class TestParseSearchsploit:
    def test_json_mode(self):
        raw = json.dumps({"RESULTS_EXPLOIT": [{"Title": "vsftpd 2.3.4 Backdoor", "EDB-ID": "17491"}]})
        hits = cve._parse_searchsploit(raw)
        assert hits == [{"title": "vsftpd 2.3.4 Backdoor", "edb_id": "17491"}]

    def test_text_mode_skips_separator(self):
        raw = "Exploit Title | Path\n--------- | ----\nApache 2.4.49 - Traversal | linux/webapps/50383.sh"
        hits = cve._parse_searchsploit(raw)
        titles = [h["title"] for h in hits]
        assert "Apache 2.4.49 - Traversal" in titles
        assert not any(set(t) <= {"-"} for t in titles)  # no dash-only rows

    def test_empty(self):
        assert cve._parse_searchsploit("") == []


class TestEnrich:
    def _stub_runner(self, title="Apache 2.4.49 Path Traversal", edb="50383"):
        payload = json.dumps({"RESULTS_EXPLOIT": [{"Title": title, "EDB-ID": edb}]})
        return lambda cmd, t: payload

    def test_offline_only_no_network(self):
        class C:
            integrations = {"nvd": {"enabled": False}}
        ports = [{"port": 80, "service": "http", "banner": "Apache httpd 2.4.49"}]
        res = cve.enrich(ports, C(), self._stub_runner())
        assert res["nvd_enabled"] is False
        assert res["cve_count"] == 0
        assert res["exploit_count"] == 1
        assert "Exploit-DB" in res["raw_section"]

    def test_versionless_ports_skipped(self):
        class C:
            integrations = {}
        ports = [{"port": 22, "service": "ssh", "banner": "open"}]
        res = cve.enrich(ports, C(), self._stub_runner())
        assert res["exploit_count"] == 0
        assert res["findings"] == []

    def test_dedupes_identical_versions(self):
        class C:
            integrations = {}
        ports = [
            {"port": 80, "service": "http", "banner": "nginx 1.18.0"},
            {"port": 8080, "service": "http", "banner": "nginx 1.18.0"},
        ]
        res = cve.enrich(ports, C(), self._stub_runner(title="nginx 1.18.0 issue"))
        # Same product+version searched once -> one finding.
        assert len(res["findings"]) == 1

    def test_query_epss_parses_probabilities(self, monkeypatch):
        import io
        import json
        import urllib.request

        fake_body = json.dumps({
            "status": "OK",
            "data": [
                {"cve": "CVE-2021-41773", "epss": "0.94321", "percentile": "0.99812"},
            ],
        }).encode("utf-8")

        class _FakeResp(io.BytesIO):
            def __enter__(self):
                return self

            def __exit__(self, *args):
                pass

        monkeypatch.setattr(urllib.request, "urlopen", lambda req, timeout=6: _FakeResp(fake_body))
        out = cve.query_epss(["CVE-2021-41773"])
        assert "CVE-2021-41773" in out
        assert out["CVE-2021-41773"]["epss"] == 0.9432
        assert out["CVE-2021-41773"]["percentile"] == 0.9981

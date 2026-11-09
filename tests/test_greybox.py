"""Tests for Grey-Box auth header validation, OpenAPI access-control diff, and White-Box scanning."""
from __future__ import annotations

import json

import pytest

from oniops.greybox import (
    analyze_source_code,
    discover_js_endpoints,
    extract_bopla_mass_assignment_risks,
    extract_openapi_endpoints,
    parse_external_sast_json,
    probe_graphql_introspection,
    probe_openapi,
    sanitize_auth_header,
    validate_bola_response_content,
)


def test_sanitize_auth_header():
    assert sanitize_auth_header("Bearer mytoken123") == "Authorization: Bearer mytoken123"
    assert sanitize_auth_header("mytoken123") == "Authorization: Bearer mytoken123"
    assert sanitize_auth_header("Cookie: sid=abc; theme=dark") == "Cookie: sid=abc; theme=dark"
    assert sanitize_auth_header("X-API-Key: secret") == "X-API-Key: secret"
    assert sanitize_auth_header("") == ""

    with pytest.raises(ValueError):
        sanitize_auth_header("Cookie: a=1\r\nX-Injected: pwn")
    with pytest.raises(ValueError):
        sanitize_auth_header("Bad Header Name!: val")


def test_extract_and_probe_openapi():
    spec = {
        "openapi": "3.0.0",
        "security": [{"bearerAuth": []}],
        "paths": {
            "/api/admin/users": {"get": {"summary": "List users"}},
            "/api/public/ping": {"get": {"security": [], "summary": "Public health"}},
        },
    }
    eps = extract_openapi_endpoints(spec)
    assert len(eps) == 2
    assert eps[0]["auth_declared"] is True
    assert eps[1]["auth_declared"] is False

    def _fake_run(cmd, timeout):
        url = cmd[-1]
        if url.endswith("/openapi.json"):
            return json.dumps(spec)
        if "/api/admin/users" in url:
            return "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
        return "HTTP/1.1 200 OK\r\n"

    res = probe_openapi("10.0.0.150", 8080, "http", _fake_run)
    assert res["found"] is True
    assert len(res["findings"]) == 1
    assert "/api/admin/users" in res["findings"][0]["title"]


def test_whitebox_analyze_source_code():
    code = '''
from flask import Flask
import subprocess, os
app = Flask(__name__)
API_KEY = "sk-1234567890abcdef123456"

@app.route("/api/v1/users")
def users():
    subprocess.run("ls -la", shell=True)
    return eval("1+1")
'''
    res = analyze_source_code(code)
    assert "/api/v1/users" in res["routes"]
    sink_types = [s["type"] for s in res["sinks"]]
    assert any("Command Execution" in t for t in sink_types)
    assert any("Unsafe Code Evaluation" in t for t in sink_types)
    assert any("Hardcoded Secret" in t for t in sink_types)
    # Verify the secret itself was redacted in the snippet
    for s in res["sinks"]:
        assert "1234567890abcdef" not in s["snippet"]


def test_bola_bfla_low_priv_diff_and_js_discovery():
    spec = {
        "openapi": "3.0.0",
        "security": [{"bearerAuth": []}],
        "paths": {
            "/api/admin/tenants": {"get": {"summary": "Admin tenant list"}},
        },
    }

    def _bola_runner(cmd, timeout):
        url = cmd[-1]
        if url.endswith("/openapi.json"):
            return json.dumps(spec)
        if "-H" in cmd and "Bearer lowpriv" in " ".join(cmd):
            return "HTTP/1.1 200 OK\r\n"
        if "-H" in cmd and "Bearer admin" in " ".join(cmd):
            return "HTTP/1.1 200 OK\r\n"
        return "HTTP/1.1 403 Forbidden\r\n"

    res = probe_openapi(
        "10.0.0.150", 8080, "http", _bola_runner,
        auth_header="Bearer admin", low_priv_header="Bearer lowpriv",
    )
    assert res["found"] is True
    assert len(res["findings"]) == 1
    assert "BOLA/BFLA" in res["findings"][0]["title"]

    def _js_runner(cmd, timeout):
        url = cmd[-1]
        if url.endswith(".js"):
            return 'fetch("/api/v1/internal/keys"); axios.post("/graphql");'
        return '<html><head><script src="/static/app.bundle.js"></script></head></html>'

    js_res = discover_js_endpoints("10.0.0.150", 8080, "http", _js_runner)
    assert "http://10.0.0.150:8080/static/app.bundle.js" in js_res["scripts"]
    assert "/api/v1/internal/keys" in js_res["routes"]
    assert "/graphql" in js_res["routes"]


def test_parse_external_sast_json_semgrep_and_gitleaks():
    semgrep_raw = json.dumps({
        "results": [{
            "check_id": "python.lang.security.audit.Dangerous-exec",
            "path": "app.py",
            "start": {"line": 42},
            "extra": {"severity": "ERROR", "lines": "os.system(user_cmd)"},
        }]
    })
    gitleaks_raw = json.dumps([{
        "RuleID": "generic-api-key",
        "File": "config.py",
        "StartLine": 10,
        "Match": "api_key = 'sk-1234567890abcdef123456'",
    }])
    sinks = parse_external_sast_json(semgrep_json=semgrep_raw, gitleaks_json=gitleaks_raw)
    assert len(sinks) == 2
    assert sinks[0]["type"].startswith("Semgrep")
    assert sinks[0]["severity"] == "HIGH"
    assert sinks[1]["type"].startswith("Gitleaks")
    assert "1234567890abcdef" not in sinks[1]["snippet"]


def test_bola_content_diff_filters_html_shell_and_empty_json():
    html_shell = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<!doctype html><html><body>Please login</body></html>"
    assert validate_bola_response_content(html_shell)[0] is False

    empty_json = 'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{"data": [], "ok": true}'
    assert validate_bola_response_content(empty_json)[0] is False

    real_json = 'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{"tenants": [{"id": 1, "name": "acme"}]}'
    ok, reason = validate_bola_response_content(real_json, real_json)
    assert ok is True
    assert "JSON" in reason


def test_horizontal_peer_bola_and_bopla_and_graphql():
    spec = {
        "openapi": "3.0.0",
        "security": [{"bearerAuth": []}],
        "paths": {
            "/api/v1/orders/{id}": {"get": {"summary": "Get order by ID"}},
            "/api/v1/profile": {
                "patch": {
                    "requestBody": {
                        "content": {
                            "application/json": {
                                "schema": {
                                    "properties": {
                                        "display_name": {"type": "string"},
                                        "is_admin": {"type": "boolean"},
                                        "role": {"type": "string"},
                                    }
                                }
                            }
                        }
                    }
                }
            },
        },
    }
    bopla = extract_bopla_mass_assignment_risks(spec)
    assert len(bopla) == 1
    assert "is_admin" in bopla[0]["writable_privilege_fields"]

    def _peer_runner(cmd, timeout):
        url = cmd[-1]
        if url.endswith("/openapi.json"):
            return json.dumps(spec)
        if "-H" in cmd:
            return 'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{"order_id": 1, "owner": "userA", "total": 99}'
        return "HTTP/1.1 401 Unauthorized\r\n"

    res = probe_openapi(
        "10.0.0.150", 8080, "http", _peer_runner,
        low_priv_header="Bearer userA", peer_auth_header="Bearer userB",
    )
    titles = [f["title"] for f in res["findings"]]
    assert any("Cross-user horizontal BOLA" in t for t in titles)
    assert any("BOPLA / Mass Assignment" in t for t in titles)

    gql = probe_graphql_introspection(
        "10.0.0.150", 8080, "http",
        lambda cmd, t: '{"data":{"__schema":{"queryType":{"name":"Query"}}}}',
    )
    assert gql is not None
    assert "GraphQL" in gql["title"]

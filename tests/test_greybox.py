"""Tests for Grey-Box auth header validation, OpenAPI access-control diff, and White-Box scanning."""
from __future__ import annotations

import json

import pytest

from oniops.greybox import (
    analyze_source_code,
    discover_js_endpoints,
    extract_openapi_endpoints,
    probe_openapi,
    sanitize_auth_header,
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

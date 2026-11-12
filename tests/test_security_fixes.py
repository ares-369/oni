"""Regression tests for the post-v0.4.7 security and scoring fixes.

Covers: reverse-proxy identity spoofing via a forged X-Forwarded-For, the
labeled-benchmark scorer only consuming VERIFIED findings, browser URL
redaction of bare token query keys, and AWS region validation across
partitions.
"""
import os

import pytest
from flask import Flask
from werkzeug.middleware.proxy_fix import ProxyFix

from oniops.auth import init_auth
from oniops.browser import _safe_url
from oniops.cloud_audit import audit_aws_account
from oniops.config import get_config
from oniops.evaluation import POSITIVE_CASES, _score_findings


def _proxy_app(cfg):
    cfg.auth.mode = "proxy"
    cfg.auth.proxy_header = "X-Forwarded-User"
    cfg.auth.proxy_trusted_ips = ["10.0.0.5"]
    app = Flask("test_oniops_proxy", template_folder=os.path.join(os.path.dirname(os.path.dirname(__file__)), "templates"))
    init_auth(app, cfg)

    @app.route("/api/sensitive")
    def sensitive():
        return {"ok": True}

    # Same middleware the real web UI installs.
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)
    return app


def test_proxy_auth_rejects_forged_x_forwarded_for(cfg_path):
    cfg = get_config(reload=True)
    client = _proxy_app(cfg).test_client()

    # Forged: the real TCP peer is untrusted, but the attacker sets
    # X-Forwarded-For to the trusted proxy IP (which ProxyFix would copy into
    # remote_addr) and claims to be admin. Must be refused.
    forged = client.get(
        "/api/sensitive",
        environ_base={"REMOTE_ADDR": "203.0.113.9"},
        headers={"X-Forwarded-For": "10.0.0.5", "X-Forwarded-User": "admin"},
    )
    assert forged.status_code == 403

    # Legitimate: the request really arrives from the trusted proxy socket.
    legit = client.get(
        "/api/sensitive",
        environ_base={"REMOTE_ADDR": "10.0.0.5"},
        headers={"X-Forwarded-For": "198.51.100.7", "X-Forwarded-User": "admin"},
    )
    assert legit.status_code == 200


def test_proxy_auth_still_fails_closed_without_trusted_ips(cfg_path):
    cfg = get_config(reload=True)
    cfg.auth.mode = "proxy"
    cfg.auth.proxy_header = "X-Forwarded-User"
    cfg.auth.proxy_trusted_ips = []
    app = Flask("test_oniops_proxy2", template_folder=os.path.join(os.path.dirname(os.path.dirname(__file__)), "templates"))
    init_auth(app, cfg)

    @app.route("/api/sensitive")
    def sensitive():
        return {"ok": True}

    r = app.test_client().get("/api/sensitive", headers={"X-Forwarded-User": "admin"})
    assert r.status_code == 403


def test_scorer_does_not_consume_unverified_finding():
    frag = POSITIVE_CASES["unauthenticated_debug"]
    # Only an UNVERIFIED finding matches the label: it must not be scored as a
    # detection, and must stay available (not silently consumed).
    unverified_only = [{"title": frag, "evidence": "", "status": "UNCONFIRMED"}]
    res = _score_findings(unverified_only)
    case = next(c for c in res["positive_cases"] if c["case_id"] == "unauthenticated_debug")
    assert case["detected"] is False

    # A VERIFIED match is preferred and counts, even alongside an unverified one.
    mixed = [
        {"title": frag, "evidence": "", "status": "UNCONFIRMED"},
        {"title": frag, "evidence": "", "status": "VERIFIED"},
    ]
    res2 = _score_findings(mixed)
    case2 = next(c for c in res2["positive_cases"] if c["case_id"] == "unauthenticated_debug")
    assert case2["detected"] is True


def test_browser_redacts_bare_token_query_keys():
    safe = _safe_url("https://in-scope.example/cb?jwt=eyJhbGciOi.secret&page=2")
    assert "eyJhbGciOi.secret" not in safe
    assert "REDACTED" in safe
    assert "page=2" in safe


@pytest.mark.parametrize("region", [
    "us-east-1", "eu-west-3", "cn-north-1", "us-gov-east-1",
    "us-iso-east-1", "us-isob-east-1", "ap-southeast-4",
])
def test_cloud_audit_accepts_all_partitions(region):
    # A valid region must pass the format gate. boto3 is an optional dependency,
    # so the call may still fail later - but NOT with a region ValueError.
    try:
        audit_aws_account("123456789012", region=region)
    except ValueError as exc:  # pragma: no cover - only on a real regression
        assert "region" not in str(exc).lower(), f"valid region rejected: {region}"
    except Exception:
        pass  # boto3 missing / no credentials / client error are all fine here


@pytest.mark.parametrize("bad", ["", "US-EAST-1", "us_east_1", "../etc", "useast1"])
def test_cloud_audit_rejects_bad_region(bad):
    with pytest.raises(ValueError):
        audit_aws_account("123456789012", region=bad)

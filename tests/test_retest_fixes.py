"""Regression tests for the retest / credential-masking fixes, the GraphQL
wiring in web_app_pt, the LocalRunner rate limiter and the doctor signing-key
warning."""
from __future__ import annotations

import json
import shutil

import pytest

from oniops.cli import SIGNING_KEY_WARNING, cli_main, run_doctor
from oniops.demo import demo_runner, demo_scope
from oniops.demo_target import USER_A_TOKEN, DemoTarget
from oniops.findings import FindingsLedger, mask_command, redact_secrets
from oniops.kali import THROTTLE_COOLDOWN_SECONDS, CmdResult
from oniops.local_runner import LocalRunner

needs_curl = pytest.mark.skipif(shutil.which("curl") is None, reason="curl binary not installed")
SECRET = "S3CRET-value-1234567890"


# ── masking of stored credentials ───────────────────────────────────────────
@pytest.mark.parametrize("header", [
    f"Authorization: Bearer {SECRET}",
    f"Authorization: Basic {SECRET}",
    f"Authorization: Token {SECRET}",
    f"Cookie: sid={SECRET}",
    f"X-Api-Key: {SECRET}",
    f"X-Auth-Token: {SECRET}",
    f"X-Session: {SECRET}",          # arbitrary header name accepted by sanitize_auth_header
    f"Api-Secret: {SECRET}",
])
def test_mask_command_hides_any_credential_header(header):
    cmd = ["curl", "-kisS", "-H", header, "http://10.0.0.150:8080/api/users/1"]
    masked = mask_command(cmd)
    assert SECRET not in json.dumps(masked)
    assert masked[3].endswith("[REDACTED-CREDENTIAL]")
    assert masked[-1] == cmd[-1]                     # URL untouched
    assert cmd[3] == header                           # stored argv is not modified


def test_mask_command_keeps_harmless_headers_and_long_form():
    masked = mask_command(["curl", "-H", "Content-Type: application/json", f"--header=X-Token: {SECRET}", "-d", "{}"])
    assert masked[2] == "Content-Type: application/json"
    assert masked[3] == "--header=X-Token: [REDACTED-CREDENTIAL]"


@pytest.mark.parametrize("text", [
    f"Authorization: Basic {SECRET}", f"authorization: token {SECRET}",
    f"X-Auth-Token: {SECRET}", f"x-session-key: {SECRET}",
])
def test_redact_secrets_new_credential_shapes(text):
    assert SECRET not in redact_secrets(text)


def _cred_finding(ledger):
    return ledger.upsert(
        target_ip="10.0.0.150", port=8080,
        title="BOLA/BFLA privilege boundary bypass on /api/admin (low-priv HTTP 200)",
        category="api_security", severity="HIGH", status="VERIFIED", evidence="200 to low-priv",
        repro_cmd=["curl", "-kisS", "--max-time", "5", "-H", f"X-Session: {SECRET}",
                   "http://10.0.0.150:8080/api/admin"],
    )


def test_ledger_outputs_mask_custom_header_credentials(tmp_path, scope):
    ledger = FindingsLedger(tmp_path / "oniops.sqlite")
    fid = _cred_finding(ledger)

    class _Api:
        def run(self, cmd, timeout=30):
            self.sent = cmd
            return CmdResult(rc=0, out='HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{"cfg":1}')

    api = _Api()
    res = ledger.retest(fid, api, scope)
    assert f"X-Session: {SECRET}" in api.sent          # replayed with the real credential
    assert res["status"] == "VERIFIED"
    for blob in (json.dumps(res), json.dumps(ledger.get(fid)), json.dumps(ledger.list_findings())):
        assert SECRET not in blob


def test_cli_findings_output_masks_credentials(tmp_path, scope, capsys):
    db = tmp_path / "oniops.sqlite"
    _cred_finding(FindingsLedger(db))
    assert cli_main(["findings", "--db", str(db)]) == 0
    out = capsys.readouterr().out
    assert SECRET not in out and "[REDACTED-CREDENTIAL]" in out


def test_differential_403_fixed_but_401_unconfirmed(tmp_path, scope):
    ledger = FindingsLedger(tmp_path / "oniops.sqlite")
    fid = _cred_finding(ledger)
    r = ledger.retest(fid, type("R", (), {"run": lambda s, c, timeout=30: CmdResult(0, "HTTP/1.1 401 Unauthorized\r\n")})(), scope)
    assert r["status"] == "UNCONFIRMED"
    r = ledger.retest(fid, type("R", (), {"run": lambda s, c, timeout=30: CmdResult(0, "HTTP/1.1 404 Not Found\r\n")})(), scope)
    assert r["status"] == "UNCONFIRMED"
    r = ledger.retest(fid, type("R", (), {"run": lambda s, c, timeout=30: CmdResult(0, "HTTP/1.1 403 Forbidden\r\n")})(), scope)
    assert r["status"] == "FIXED"


def test_differential_200_without_data_not_verified(tmp_path, scope):
    ledger = FindingsLedger(tmp_path / "oniops.sqlite")
    fid = _cred_finding(ledger)
    shell = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html><form>login</form></html>"
    r = ledger.retest(fid, type("R", (), {"run": lambda s, c, timeout=30: CmdResult(0, shell)})(), scope)
    assert r["status"] == "UNCONFIRMED"


def test_pdf_export_redacts_markdown(cfg_path, tmp_path, monkeypatch):
    import oniops.config as c
    c._CONFIG = None
    import webui
    monkeypatch.setattr(webui, "terms_store", webui.TermsStore(tmp_path / "t.sqlite"))
    seen = {}
    monkeypatch.setattr(webui, "markdown_to_pdf", lambda md, title="": seen.setdefault("md", md) and b"%PDF")
    r = webui.app.test_client().post("/api/report/pdf", json={
        "markdown": f"$ curl -H 'Authorization: Bearer {SECRET}' http://10.0.0.150/", "title": "t"})
    assert r.status_code == 200
    assert SECRET not in seen["md"] and "[REDACTED" in seen["md"]


# ── GraphQL probe wired into web_app_pt ─────────────────────────────────────
@needs_curl
def test_web_app_pt_runs_graphql_probe(cfg_path, tmp_path, monkeypatch):
    import oniops.config as c
    c._CONFIG = None
    import webui

    db = tmp_path / "wapt.sqlite"
    monkeypatch.setattr(webui, "DB_PATH", db)
    webui.init_db()
    monkeypatch.setattr(webui, "ledger", webui.FindingsLedger(db))
    monkeypatch.setattr(webui, "ACTIVITY_LOG", tmp_path / "activity.jsonl")
    monkeypatch.setattr(webui, "ai_chat", lambda *a, **k: "")

    with DemoTarget() as t:
        local = demo_runner()

        class _Fake:
            """nmap reports the demo port; curl probes really hit the target;
            other attack-host tools return nothing."""
            def run(self, cmd, timeout=30):
                if cmd[0] == "nmap":
                    return CmdResult(0, f"{t.port}/tcp open http ONIOPS-Demo-Target")
                if cmd[0] == "curl":
                    return local.run(cmd, timeout=timeout)
                return CmdResult(0, "")

        monkeypatch.setattr(webui, "active_runner", lambda: _Fake())
        res = webui._run_assessment(t.ip, "demo", "web_app_pt")

    assert "GraphQL" in res["raw_output"]
    gql = [f for f in webui.ledger.list_findings(target_ip=t.ip) if "GraphQL" in f["title"]]
    assert len(gql) == 1 and gql[0]["status"] == "VERIFIED" and gql[0]["category"] == "graphql"
    assert any("BOLA" in f["title"] or "Unauthenticated" in f["title"]
               for f in webui.ledger.list_findings(target_ip=t.ip))


# ── LocalRunner rate limiting ───────────────────────────────────────────────
class _RecLimiter:
    def __init__(self):
        self.acquired, self.penalized = [], []

    def acquire(self, target, cost=1):
        self.acquired.append(target)
        return 0.0

    def penalize(self, target, seconds):
        self.penalized.append((target, seconds))


def test_local_runner_paces_per_target_and_cools_down_on_429(monkeypatch):
    lim = _RecLimiter()
    runner = LocalRunner(demo_scope(), limiter=lim)
    replies = iter([CmdResult(0, "HTTP/1.1 200 OK\r\n"), CmdResult(0, "HTTP/1.1 429 Too Many Requests\r\n"),
                    CmdResult(0, "HTTP/1.1 503 Service Unavailable\r\n")])
    monkeypatch.setattr(runner, "_exec", lambda argv, timeout: next(replies))
    for _ in range(3):
        runner.run(["curl", "-kisS", "http://127.0.0.1:9/x"])
    assert lim.acquired == ["127.0.0.1"] * 3
    assert lim.penalized == [("127.0.0.1", THROTTLE_COOLDOWN_SECONDS)] * 2


def test_local_runner_refused_command_is_not_charged():
    lim = _RecLimiter()
    runner = LocalRunner(demo_scope(), limiter=lim)
    assert runner.run(["curl", "http://10.0.0.5/"]).rc == 126
    assert lim.acquired == []


def test_local_runner_default_limiter_uses_scope_rate():
    runner = LocalRunner(demo_scope())
    assert runner.limiter.rate_per_min == demo_scope().cfg.scope.rate_limit_per_min
    assert demo_runner().limiter.rate_per_min >= 60000


@needs_curl
def test_demo_limiter_really_paces_but_fast():
    with DemoTarget() as t:
        runner = demo_runner()
        for _ in range(3):
            assert runner.run(["curl", "-ksS", f"{t.base_url}/"]).ok
        assert runner.limiter._next_allowed.get("127.0.0.1")


# ── doctor: signing key warning ─────────────────────────────────────────────
def test_doctor_warns_without_signing_key(cfg_path, tmp_path, monkeypatch, capsys):
    monkeypatch.delenv("ONIOPS_SECRET_KEY", raising=False)
    import oniops.config as c
    c._CONFIG = None
    res = run_doctor(db_override=str(tmp_path / "d.sqlite"))
    assert res["signing_key_set"] is False and SIGNING_KEY_WARNING in res["warnings"]
    assert res["ok"] is True                        # a warning, not a failure
    cli_main(["doctor", "--db", str(tmp_path / "d.sqlite")])
    assert SIGNING_KEY_WARNING in capsys.readouterr().err


@pytest.mark.parametrize("key", ["", "   ", "oniops-default-manifest-key", "oniops-webhook-key"])
def test_doctor_treats_public_default_keys_as_unset(cfg_path, tmp_path, monkeypatch, key):
    monkeypatch.setenv("ONIOPS_SECRET_KEY", key)
    import oniops.config as c
    c._CONFIG = None
    assert run_doctor(db_override=str(tmp_path / "d.sqlite"))["signing_key_set"] is False


def test_doctor_no_warning_with_signing_key(cfg_path, tmp_path, monkeypatch):
    monkeypatch.setenv("ONIOPS_SECRET_KEY", "a-real-operator-secret-0123456789")
    import oniops.config as c
    c._CONFIG = None
    res = run_doctor(db_override=str(tmp_path / "d.sqlite"))
    assert res["signing_key_set"] is True and res["warnings"] == []


def test_demo_tokens_never_printed(capsys, tmp_path, monkeypatch):
    if shutil.which("curl") is None:
        pytest.skip("curl binary not installed")
    import io

    from oniops.demo import run_demo
    buf = io.StringIO()
    assert run_demo(db_path=tmp_path / "d.sqlite", out=buf) == 0
    out = buf.getvalue()
    assert USER_A_TOKEN not in out and "[REDACTED-CREDENTIAL]" in out
    assert "Known beta gap" not in out

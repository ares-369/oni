"""Hermetic end-to-end tests: real OniOps engines against the bundled practice
target on 127.0.0.1, through the loopback-only LocalRunner, scope 127.0.0.1/32.

No LLM, no attack host, no network beyond loopback. Needs the `curl` binary
(the engines build curl argv lists and the LocalRunner executes them as-is).
The runner uses the demo's high-rate RateLimiter, so pacing is real but adds
about a millisecond per request.
"""
from __future__ import annotations

import json
import shutil

import pytest

from oniops.agent import _report_finding
from oniops.demo import demo_runner, demo_scope, run_assessment
from oniops.demo_target import USER_A_HEADER, USER_A_TOKEN, USER_B_TOKEN, DemoTarget
from oniops.findings import FindingsLedger, backup_sqlite
from oniops.kali import CmdResult
from oniops.scope import ScopeViolation

pytestmark = pytest.mark.skipif(shutil.which("curl") is None, reason="curl binary not installed")

ADMIN_CFG = "BOLA/BFLA privilege boundary bypass on /api/v1/admin/config"
HORIZONTAL = "Cross-user horizontal BOLA on /api/v1/users/{id}"
ORDER_HORIZONTAL = "Cross-user horizontal BOLA on /api/v1/orders/{order_ref}"
OWNER_READ = "BOLA/BFLA privilege boundary bypass on /api/v1/users/{id}"
BOPLA = "BOPLA / Mass Assignment risk on PATCH /api/v1/users/{id}"


@pytest.fixture(scope="module")
def assessed(tmp_path_factory):
    """One vulnerable-mode assessment shared by the detection tests."""
    db = tmp_path_factory.mktemp("e2e") / "e2e.sqlite"
    scope = demo_scope()
    runner = demo_runner(scope)
    ledger = FindingsLedger(db)
    with DemoTarget() as target:
        res = run_assessment(target.ip, target.port, runner, ledger)
        findings = ledger.list_findings(target_ip=target.ip, limit=100)
    return {"res": res, "findings": findings, "ledger": ledger}


@pytest.fixture(scope="module")
def _live_template(tmp_path_factory):
    """One target + one assessed template ledger for the whole module."""
    db = tmp_path_factory.mktemp("live") / "template.sqlite"
    scope = demo_scope()
    with DemoTarget() as target:
        run_assessment(target.ip, target.port, demo_runner(scope), FindingsLedger(db))
        yield target, db


@pytest.fixture()
def live(_live_template, tmp_path):
    """Per test: a fresh copy of the assessed ledger and the target reset to
    its vulnerable state, so tests may flip it to fixed / expire tokens."""
    target, template = _live_template
    db = tmp_path / "live.sqlite"
    backup_sqlite(template, db)
    target.set_fixed(False)
    target.set_tokens_valid(True)
    scope = demo_scope()
    yield {"target": target, "scope": scope, "runner": demo_runner(scope), "ledger": FindingsLedger(db)}
    target.set_fixed(False)
    target.set_tokens_valid(True)


def _find(findings, needle):
    hits = [f for f in findings if needle in f["title"]]
    assert hits, f"no finding containing {needle!r}; got {[f['title'] for f in findings]}"
    return hits[0]


def _retest(live, needle):
    f = _find(live["ledger"].list_findings(), needle)
    return live["ledger"].retest(f["id"], live["runner"], live["scope"])


# ── planted weaknesses are found with the expected status / confidence ──────
@pytest.mark.parametrize("needle,status,severity,confidence", [
    ("Exposed HTTP service on port", "VERIFIED", "MEDIUM", "HIGH"),               # W1
    ("Unauthenticated API access on /api/v1/debug/env", "VERIFIED", "HIGH", "HIGH"),  # W2
    (HORIZONTAL, "VERIFIED", "HIGH", "HIGH"),                                     # W3
    (ORDER_HORIZONTAL, "VERIFIED", "HIGH", "HIGH"),                               # W9 (mined string id)
    (ADMIN_CFG, "VERIFIED", "HIGH", "HIGH"),                                      # W4
    (BOPLA, "UNCONFIRMED", "MEDIUM", "LOW"),                                      # W5
    ("Exposed GraphQL schema introspection on /graphql", "VERIFIED", "MEDIUM", "HIGH"),  # W6
    ("Verbose SQL error disclosed on /api/v1/search", "VERIFIED", "HIGH", "HIGH"),  # W7
    ("Reflected XSS on /api/v1/echo", "VERIFIED", "MEDIUM", "HIGH"),               # W8
])
def test_planted_weakness_found(assessed, needle, status, severity, confidence):
    f = _find(assessed["findings"], needle)
    assert (f["status"], f["severity"], f["confidence"]) == (status, severity, confidence)
    assert f["evidence_sha256"] and f["repro_display"].startswith("curl ")


def test_owner_read_is_reported_known_false_positive(assessed):
    """Documents a real detection limit: user A owns object 1, yet the
    low-privilege differential (anon 401 -> low-priv 200 on a sensitive route)
    reports it, because probe_openapi has no notion of object ownership."""
    f = _find(assessed["findings"], OWNER_READ)
    assert f["status"] == "VERIFIED"


def test_exact_finding_count(assessed):
    # 9 planted weaknesses -> 10 findings. W1-W8 give 8 (W3's /api/v1/users/{id}
    # route also yields the known owner-read false positive, so W2-W8 openapi/
    # input weaknesses plus that extra = 9), and W9 (the mined-string-id
    # cross-user BOLA on /api/v1/orders/{order_ref}) adds the 10th. The secure
    # wallet twin (S4) and every other twin stay unreported. Guards against new
    # false positives.
    assert len(assessed["findings"]) == 10


def test_mined_string_id_cross_user_bola_detected(assessed):
    """W9: ONIOPS resolves the real order reference (mined from /api/v1/orders,
    never the literal '1') and proves user A reading user B's order."""
    f = _find(assessed["findings"], ORDER_HORIZONTAL)
    assert f["status"] == "VERIFIED" and f["severity"] == "HIGH"
    # The peer-owned reference (ord-b1), not '1', is baked into the replay, and
    # the replay runs AS the low-privilege identity (user A).
    assert "ord-b1" in f["repro_display"]
    assert USER_A_TOKEN not in f["repro_display"]  # credential masked on display
    raw = json.loads(assessed["ledger"]._get_raw(f["id"])["repro_cmd"])
    assert f"Authorization: Bearer {USER_A_TOKEN}" in raw and "ord-b1" in " ".join(raw)


def test_owner_only_object_twin_not_reported(assessed):
    """S4: the correctly-owned wallet route yields no cross-user finding -
    user A cannot read user B's wallet, so there is no false BOLA."""
    assert not [f for f in assessed["findings"]
                if "/api/v1/wallets" in f["title"] or "/api/v1/wallets" in f["evidence"]]


def test_graphql_finding_has_own_category(assessed):
    f = _find(assessed["findings"], "GraphQL")
    assert f["category"] == "graphql"
    assert f["remediation"]["cwe"] == "CWE-200"
    assert "-kisS" in f["repro_display"]


def test_bopla_fields_named(assessed):
    f = _find(assessed["findings"], "BOPLA")
    assert "role" in f["title"] and "is_admin" in f["title"]
    assert f["repro_display"].endswith("/openapi.json")   # replay re-fetches the schema


# ── secure twins produce NO finding ─────────────────────────────────────────
@pytest.mark.parametrize("twin", ["/api/v1/secrets", "/api/v1/tokens/status", "/api/v1/internal/metrics"])
def test_secure_twin_not_reported(assessed, twin):
    assert not [f for f in assessed["findings"] if twin in f["title"] or twin in f["evidence"]]


def test_secure_twins_seen_and_classified(assessed):
    raw = assessed["res"]["openapi"]["raw_section"]
    assert "[AUTH-ENFORCED] /api/v1/secrets/{id}: unauth=401 -> auth=200" in raw
    assert "[FALSE-POSITIVE-FILTERED] /api/v1/tokens/status" in raw
    assert "/api/v1/internal/metrics: HTTP 403" in raw


def test_public_non_sensitive_routes_not_reported(assessed):
    # /api/v1/search and /api/v1/echo answer 200 anonymously by design; only the
    # input-proof checks (not the access-control diff) may report them.
    for f in assessed["findings"]:
        if "/api/v1/search" in f["title"] or "/api/v1/echo" in f["title"]:
            assert f["category"] in ("sqli", "xss")


def test_agent_report_finding_validator_e2e(tmp_path):
    """agent._report_finding (the agent's independent validator) is deterministic:
    run it directly, no LLM, against a real and a fake claim."""
    runner = demo_runner()
    db = tmp_path / "agent.sqlite"
    with DemoTarget() as t:
        real = _report_finding(runner, t.ip, {"port": t.port, "title": "SQL error", "category": "sqli",
                                              "path": "/api/v1/search?q=%27", "_db_path": str(db)})
        fake = _report_finding(runner, t.ip, {"port": t.port, "title": "Claimed SQLi on secrets",
                                              "category": "sqli", "path": "/api/v1/secrets/1",
                                              "_db_path": str(db)})
    assert "status=VERIFIED" in real
    assert "status=UNCONFIRMED" in fake


def test_agent_indicator_finding_retest(tmp_path):
    """The agent's expected_indicator is stored and re-checked on retest."""
    scope = demo_scope()
    runner = demo_runner(scope)
    ledger = FindingsLedger(tmp_path / "agent.sqlite")
    with DemoTarget() as t:
        _report_finding(runner, t.ip, {"port": t.port, "title": "Debug env leaks DATABASE_URL",
                                       "category": "agent_validation", "path": "/api/v1/debug/env",
                                       "expected_indicator": "DATABASE_URL", "_db_path": ledger.db_path})
        f = _find(ledger.list_findings(), "Debug env leaks")
        assert f["status"] == "VERIFIED" and f["proof_indicator"] == "DATABASE_URL"
        assert ledger.retest(f["id"], runner, scope)["status"] == "VERIFIED"
        t.set_fixed(True)
        assert ledger.retest(f["id"], runner, scope)["status"] == "FIXED"


# ── zero-token retest: vulnerable -> fixed ──────────────────────────────────
@pytest.mark.parametrize("needle", [
    "Unauthenticated API access on /api/v1/debug/env",
    ADMIN_CFG,
    HORIZONTAL,
    ORDER_HORIZONTAL,   # mined-id cross-user BOLA: fixed target 404s the peer id
    "Exposed GraphQL schema introspection",
    "Verbose SQL error",
    "Reflected XSS",
])
def test_retest_reproduces_then_reports_fixed(live, needle):
    r1 = _retest(live, needle)
    assert r1["status"] == "VERIFIED", r1["evidence"]
    live["target"].set_fixed(True)
    r2 = _retest(live, needle)
    assert r2["status"] == "FIXED", r2["evidence"]
    assert live["ledger"].get(r2["id"])["priority_score"] == 0


def test_retest_service_exposure_still_live(live):
    assert _retest(live, "Exposed HTTP service")["status"] == "VERIFIED"
    live["target"].set_fixed(True)
    assert _retest(live, "Exposed HTTP service")["status"] == "VERIFIED"   # still a live service


def test_differential_retest_replays_as_the_proving_identity(live):
    """The low-priv / peer findings replay with THAT identity's credential."""
    ledger, runner = live["ledger"], live["runner"]
    raw = {f["title"]: json.loads(ledger._get_raw(f["id"])["repro_cmd"]) for f in ledger.list_findings()}
    admin = next(v for k, v in raw.items() if k.startswith(ADMIN_CFG))
    peer = next(v for k, v in raw.items() if k.startswith(HORIZONTAL))
    assert f"Authorization: Bearer {USER_A_TOKEN}" in admin
    assert f"Authorization: Bearer {USER_B_TOKEN}" in peer
    _retest(live, ADMIN_CFG)
    assert any(USER_A_TOKEN in c for c in runner.commands_run[-1:])


def test_differential_retest_expired_credential_is_unconfirmed(live):
    live["target"].set_tokens_valid(False)      # every demo token now gets 401
    for needle in (ADMIN_CFG, HORIZONTAL):
        r = _retest(live, needle)
        assert r["status"] == "UNCONFIRMED"
        assert "credential rejected (401)" in r["evidence"]


def test_legacy_anonymous_differential_replay_never_fixed(live):
    """A differential finding saved without its credential (older versions) is
    UNCONFIRMED with a note, and the anonymous replay is not even sent."""
    ledger, runner, target = live["ledger"], live["runner"], live["target"]
    url = f"{target.base_url}/api/v1/admin/config"
    fid = ledger.upsert(target_ip=target.ip, port=target.port,
                        title=f"{ADMIN_CFG} (low-priv HTTP 200) legacy", category="api_security",
                        severity="HIGH", status="VERIFIED", evidence="old row",
                        repro_cmd=["curl", "-kisS", "--max-time", "5", url])
    sent = len(runner.commands_run)
    target.set_fixed(True)
    r = ledger.retest(fid, runner, live["scope"])
    assert r["status"] == "UNCONFIRMED" and "no credential" in r["evidence"]
    assert len(runner.commands_run) == sent


def test_bopla_retest_reevaluates_schema(live):
    r1 = _retest(live, BOPLA)
    assert r1["status"] == "UNCONFIRMED" and "still exposes writable privilege fields" in r1["evidence"]
    live["target"].set_fixed(True)        # fixed spec marks role/is_admin readOnly
    r2 = _retest(live, BOPLA)
    assert r2["status"] == "FIXED" and "no longer exposes" in r2["evidence"]


def test_legacy_bopla_get_replay_not_fixed(live):
    """Old BOPLA rows replayed a GET of the route (401) - must not read as FIXED."""
    ledger, target = live["ledger"], live["target"]
    fid = ledger.upsert(target_ip=target.ip, port=target.port,
                        title="BOPLA / Mass Assignment risk on PATCH /api/v1/users/{id} (role) legacy",
                        category="api_security", severity="MEDIUM", status="UNCONFIRMED", evidence="old",
                        repro_cmd=["curl", "-kisS", "--max-time", "5", f"{target.base_url}/api/v1/users/1"])
    r = ledger.retest(fid, live["runner"], live["scope"])
    assert r["status"] == "UNCONFIRMED" and "did not return an OpenAPI document" in r["evidence"]


# ── retest: runner failure / throttling / no proof ──────────────────────────
class _Failing:
    def __init__(self, rc, out):
        self.rc, self.out = rc, out

    def run(self, cmd, timeout=30):
        return CmdResult(rc=self.rc, out=self.out)


@pytest.mark.parametrize("needle", [ADMIN_CFG, "Verbose SQL error", "GraphQL", BOPLA])
@pytest.mark.parametrize("rc,out", [(126, "Scope violation: blocked"),
                                    (124, "Command error/timeout: local probe timed out.")])
def test_runner_failure_leaves_status_unchanged(live, needle, rc, out):
    ledger = live["ledger"]
    f = _find(ledger.list_findings(), needle)
    with pytest.raises(ValueError, match="could not run"):
        ledger.retest(f["id"], _Failing(rc, out), live["scope"])
    assert ledger.get(f["id"])["status"] == f["status"]


@pytest.mark.parametrize("needle", [ADMIN_CFG, "Verbose SQL error", "Unauthenticated API access"])
def test_throttled_replay_is_unconfirmed(live, needle):
    ledger = live["ledger"]
    f = _find(ledger.list_findings(), needle)
    r = ledger.retest(f["id"], _Failing(0, "HTTP/1.1 429 Too Many Requests\r\nRetry-After: 5\r\n"), live["scope"])
    assert r["status"] == "UNCONFIRMED" and "throttled" in r["evidence"]


def test_category_without_proof_is_unconfirmed(live):
    ledger, target = live["ledger"], live["target"]
    fid = ledger.upsert(target_ip=target.ip, port=target.port, title="CVE-0000-0000 on demo 1.0",
                        category="cve", severity="HIGH", status="UNCONFIRMED", evidence="intel",
                        repro_cmd=["curl", "-kisS", f"{target.base_url}/"])
    r = ledger.retest(fid, live["runner"], live["scope"])
    assert r["status"] == "UNCONFIRMED" and "no stored proof signature" in r["evidence"]


def test_proof_on_unreachable_target_is_unconfirmed(live):
    """curl ran but got no HTTP response: no evidence either way."""
    ledger = live["ledger"]
    f = _find(ledger.list_findings(), "Reflected XSS")
    r = ledger.retest(f["id"], _Failing(7, "curl: (7) Failed to connect to 127.0.0.1"), live["scope"])
    assert r["status"] == "UNCONFIRMED"


# ── masking of stored credentials ───────────────────────────────────────────
def test_stored_credentials_never_displayed(live):
    ledger = live["ledger"]
    blobs = [json.dumps(ledger.list_findings())]
    blobs += [json.dumps(ledger.get(f["id"])) for f in ledger.list_findings()]
    blobs += [json.dumps(_retest(live, n)) for n in (ADMIN_CFG, HORIZONTAL)]
    for blob in blobs:
        assert USER_A_TOKEN not in blob and USER_B_TOKEN not in blob
    assert "[REDACTED-CREDENTIAL]" in blobs[0]


# ── scope / loopback enforcement ────────────────────────────────────────────
def test_out_of_scope_target_refused(live):
    scope, runner = live["scope"], live["runner"]
    with pytest.raises(ScopeViolation):
        scope.resolve("10.0.0.5")
    res = runner.run(["curl", "-ksS", "--max-time", "2", "http://10.0.0.5:80/"])
    assert res.rc == 126 and "10.0.0.5" in res.out
    assert all("10.0.0.5" not in c for c in runner.commands_run)


def test_retest_of_out_of_scope_finding_refused(live):
    ledger = live["ledger"]
    fid = ledger.upsert(target_ip="10.0.0.5", port=80, title="planted out-of-scope row",
                        category="api_security", severity="HIGH", status="VERIFIED",
                        evidence="x", repro_cmd=["curl", "-kisS", "http://10.0.0.5/"])
    with pytest.raises(ScopeViolation):
        ledger.retest(fid, live["runner"], live["scope"])


def test_loopback_alias_outside_scope_refused(live):
    # 127.0.0.2 is loopback but not in the 127.0.0.1/32 demo scope.
    res = live["runner"].run(["curl", "-ksS", "http://127.0.0.2:1/"])
    assert res.rc == 126


def test_low_priv_header_really_grants_access_while_vulnerable(live):
    f = _find(live["ledger"].list_findings(), ADMIN_CFG)
    url = f["repro_display"].split()[-1]
    out = live["runner"].run(["curl", "-kisS", "--max-time", "5", "-H", USER_A_HEADER, url]).out
    assert "200" in out.splitlines()[0]

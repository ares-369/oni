"""Manifest and webhook signing must never use a built-in (public) key.

The repository is public, so any hard-coded fallback key lets anyone forge a
"signature". These tests pin the honest behaviour: no operator key means the
output is explicitly unsigned, and nothing signed with an old default verifies.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import re
from pathlib import Path

import pytest

from oniops import findings
from oniops.findings import (
    build_assessment_manifest,
    dispatch_webhook_alert,
    manifest_verification_status,
    usable_signing_key,
    verify_assessment_manifest,
)

OLD_PUBLIC_KEYS = ("oniops-default-manifest-key", "oniops-webhook-key")
REAL_KEY = "a-real-operator-secret-0123456789abcdef"
ROOT = Path(__file__).resolve().parent.parent

_CORE_KEYS = (
    "assessment_id", "oniops_version", "target_ip", "profile", "scope_hash",
    "commands_hash", "model", "started_at", "completed_at", "evidence_hashes",
)


def _manifest(signing_key: str = "") -> dict:
    return build_assessment_manifest(
        assessment_id=7,
        oniops_version="0.4.4-beta",
        target_ip="10.0.0.150",
        profile="fast_recon",
        scope_cidrs=["10.0.0.0/24"],
        model_name="qwen2.5-coder:7b",
        started_at="2026-11-11T10:00:00Z",
        completed_at="2026-11-11T10:01:00Z",
        commands_run=["nmap -sV 10.0.0.150"],
        evidence_hashes=["b" * 64],
        signing_key=signing_key,
    )


def _forge(manifest: dict, key: str) -> dict:
    """Sign a manifest the way older releases did, with an arbitrary key."""
    core = {k: manifest[k] for k in _CORE_KEYS}
    canonical = json.dumps(core, sort_keys=True, separators=(",", ":")).encode("utf-8")
    sig = hmac.new(key.encode("utf-8"), canonical, hashlib.sha256).hexdigest()
    return dict(manifest, signed=True, signature=f"hmac-sha256:{sig}")


@pytest.mark.parametrize("key", ["", "   ", None])
def test_no_key_gives_explicitly_unsigned_manifest(key):
    m = _manifest(key)
    assert m["signed"] is False
    assert m["signature"] is None
    assert "ONIOPS_SECRET_KEY" in m["unsigned_reason"]
    # Integrity hash is still produced.
    assert re.fullmatch(r"[0-9a-f]{64}", m["manifest_sha256"])


@pytest.mark.parametrize("key", OLD_PUBLIC_KEYS)
def test_old_public_keys_are_refused_for_signing(key):
    m = _manifest(key)
    assert m["signed"] is False and m["signature"] is None
    assert usable_signing_key(key) == ""


def test_no_key_manifest_does_not_match_any_old_default_signature():
    # Would fail if a default key were reintroduced in build_assessment_manifest.
    m = _manifest("")
    for key in OLD_PUBLIC_KEYS:
        assert m["signature"] != _forge(m, key)["signature"]


def test_unsigned_manifest_never_verifies():
    m = _manifest("")
    assert verify_assessment_manifest(m, REAL_KEY) is False
    assert verify_assessment_manifest(m, "") is False
    assert manifest_verification_status(m, REAL_KEY) == "unsigned"
    # Flipping the flag without a real signature does not help.
    assert verify_assessment_manifest(dict(m, signed=True), REAL_KEY) is False


@pytest.mark.parametrize("key", OLD_PUBLIC_KEYS)
def test_manifest_forged_with_old_default_never_verifies(key):
    forged = _forge(_manifest(""), key)
    # Not with the public key itself...
    assert verify_assessment_manifest(forged, key) is False
    assert manifest_verification_status(forged, key) == "no_key"
    # ...not with an empty key (old code fell back to the default here)...
    assert verify_assessment_manifest(forged, "") is False
    # ...and not against a real operator key.
    assert verify_assessment_manifest(forged, REAL_KEY) is False
    assert manifest_verification_status(forged, REAL_KEY) == "bad_signature"


def test_signed_manifest_verifies_only_with_right_key():
    m = _manifest(REAL_KEY)
    assert m["signed"] is True
    assert m["signature"].startswith("hmac-sha256:")
    assert "unsigned_reason" not in m
    assert verify_assessment_manifest(m, REAL_KEY) is True
    assert manifest_verification_status(m, REAL_KEY) == "valid"
    assert verify_assessment_manifest(m, "wrong-key") is False
    assert verify_assessment_manifest(m, "") is False
    assert manifest_verification_status(m, "") == "no_key"


def test_tampered_manifest_fails():
    m = _manifest(REAL_KEY)
    tampered = dict(m, target_ip="10.0.0.199")
    assert verify_assessment_manifest(tampered, REAL_KEY) is False
    assert manifest_verification_status(tampered, REAL_KEY) == "integrity_mismatch"
    # Recomputing the public hash after tampering still fails the HMAC.
    core = {k: tampered[k] for k in _CORE_KEYS}
    canonical = json.dumps(core, sort_keys=True, separators=(",", ":")).encode("utf-8")
    rehashed = dict(tampered, manifest_sha256=hashlib.sha256(canonical).hexdigest())
    assert manifest_verification_status(rehashed, REAL_KEY) == "bad_signature"


def test_malformed_manifest():
    assert verify_assessment_manifest("not a dict", REAL_KEY) is False  # type: ignore[arg-type]
    assert manifest_verification_status({}, REAL_KEY) == "malformed"


class _Resp:
    status = 200

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def _capture_webhook(monkeypatch):
    sent = {}

    def fake_urlopen(req, timeout=5):
        sent["headers"] = {k.lower(): v for k, v in req.header_items()}
        sent["body"] = req.data
        return _Resp()

    monkeypatch.setattr(findings.urllib.request, "urlopen", fake_urlopen)
    return sent


def test_webhook_without_key_sends_no_signature(monkeypatch):
    monkeypatch.delenv("ONIOPS_SECRET_KEY", raising=False)
    sent = _capture_webhook(monkeypatch)
    assert dispatch_webhook_alert("finding.regressed", {"id": 1},
                                  webhook_url="http://127.0.0.1:9/hook") is True
    assert "x-oniops-signature" not in sent["headers"]


@pytest.mark.parametrize("key", OLD_PUBLIC_KEYS)
def test_webhook_refuses_old_public_key(monkeypatch, key):
    monkeypatch.setenv("ONIOPS_SECRET_KEY", key)
    sent = _capture_webhook(monkeypatch)
    dispatch_webhook_alert("finding.regressed", {"id": 1}, webhook_url="http://127.0.0.1:9/hook")
    assert "x-oniops-signature" not in sent["headers"]


def test_webhook_signed_with_configured_key(monkeypatch):
    monkeypatch.setenv("ONIOPS_SECRET_KEY", REAL_KEY)
    sent = _capture_webhook(monkeypatch)
    dispatch_webhook_alert("finding.regressed", {"id": 1}, webhook_url="http://127.0.0.1:9/hook")
    expected = hmac.new(REAL_KEY.encode(), sent["body"], hashlib.sha256).hexdigest()
    assert sent["headers"]["x-oniops-signature"] == f"hmac-sha256:{expected}"


def test_no_hardcoded_fallback_key_in_signing_call_sites():
    # Guards against reintroducing `key or "some-constant"` at the call sites,
    # and against signing with Flask's per-process random app.secret_key.
    for rel in ("oniops/findings.py", "webui.py"):
        src = (ROOT / rel).read_text(encoding="utf-8")
        assert not re.search(r"""\bor\s+["']oniops-[a-z-]*key["']""", src), rel
    webui = (ROOT / "webui.py").read_text(encoding="utf-8")
    call = webui[webui.index("build_assessment_manifest(\n"):]
    call = call[:call.index(")\n")]
    assert "app.secret_key" not in call

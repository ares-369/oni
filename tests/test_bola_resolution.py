"""Hermetic unit tests for real object-id resolution in the Grey-Box BOLA probe.

No network and no curl binary: `probe_openapi` is driven entirely by a fake
`run_fn` that simulates a VAmPI-like app in memory, so the horizontal cross-user
check can be exercised deterministically. Also covers the id-mining helpers, the
placeholder fallback, and defensiveness against garbage collection bodies.
"""
from __future__ import annotations

import json
from urllib.parse import urlsplit

from oniops.greybox import (
    _collection_path,
    _mine_candidate_ids,
    _param_name,
    _resolve_concrete_path,
    _route_with_id,
    probe_openapi,
)

BASE = "http://127.0.0.1:8080"

# A VAmPI-like spec: one parameterised, string-keyed object route.
SPEC = {
    "openapi": "3.0.0",
    "security": [{"bearerAuth": []}],
    "paths": {"/users/v1/{username}": {"get": {"summary": "Get a user by name"}}},
}

_USERS = {
    "name1": {"username": "name1", "email": "n1@demo.invalid", "role": "user"},
    "name2": {"username": "name2", "email": "n2@demo.invalid", "role": "user"},
}
_OWNER = {"name1": "alice", "name2": "bob"}  # name1 belongs to A, name2 to B


def _http(code: int, body=None, ctype: str = "application/json") -> str:
    head = f"HTTP/1.1 {code} X\r\nContent-Type: {ctype}\r\n\r\n"
    return head if body is None else head + json.dumps(body)


def _identity(cmd: list[str]) -> str:
    joined = " ".join(cmd)
    if "tokenA" in joined:
        return "alice"
    if "tokenB" in joined:
        return "bob"
    return "anon"


def _make_app(*, cross_read: bool, collection: str = "scoped"):
    """Build a fake run_fn.

    cross_read=True  -> vulnerable: any authed identity reads any user (BOLA).
    cross_read=False -> owner-only object: A cannot read B's record (secure twin).
    collection='scoped'  -> /users/v1 returns the caller's own users (owner-scoped).
    collection='shared'  -> /users/v1 returns the full list to every identity.
    collection='none'    -> no /users/v1 collection (404): mining must fall back.
    collection='garbage' -> /users/v1 returns non-JSON junk.
    """
    def run_fn(cmd, timeout):
        url = cmd[-1]
        path = urlsplit(url).path
        who = _identity(cmd)
        if path.endswith("/openapi.json"):
            return json.dumps(SPEC)
        if path == "/users/v1":
            if collection == "none":
                return _http(404, {"error": "not found"})
            if collection == "garbage":
                return "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html>not json</html>"
            if who == "anon":
                return _http(200, list(_USERS.values()))  # VAmPI exposes all unauth
            if collection == "shared":
                return _http(200, list(_USERS.values()))
            own = [u for u, o in _OWNER.items() if o == who]
            return _http(200, [_USERS[u] for u in own])
        if path.startswith("/users/v1/"):
            uname = path.rsplit("/", 1)[1]
            if who == "anon":
                return _http(401, {"error": "authentication required"})
            if uname not in _USERS:
                return _http(404, {"error": "not found"})
            if not cross_read and who != "admin" and _OWNER.get(uname) != who:
                return _http(403, {"error": "forbidden"})
            return _http(200, _USERS[uname])
        return _http(404, {"error": "not found"})

    return run_fn


# ───────────────────────── id-mining helpers ─────────────────────────
def test_mine_ids_prefers_matching_field():
    body = _http(200, [{"username": "alice", "id": 7}, {"username": "bob", "id": 9}])
    assert _mine_candidate_ids(body, "username") == ["alice", "bob"]
    # A differently-named param still resolves the id-like field.
    assert _mine_candidate_ids(body, "id") == ["7", "9"]


def test_mine_ids_handles_wrapper_and_object_map_and_scalars():
    wrapped = _http(200, {"users": [{"book_title": "Dune"}, {"book_title": "Hyperion"}]})
    assert _mine_candidate_ids(wrapped, "book_title") == ["Dune", "Hyperion"]
    id_map = _http(200, {"ord-a1": {"total": 1}, "ord-b1": {"total": 2}})
    assert _mine_candidate_ids(id_map, "order_ref") == ["ord-a1", "ord-b1"]
    scalars = _http(200, ["sku-1", "sku-2", "sku-3"])
    assert _mine_candidate_ids(scalars, "sku") == ["sku-1", "sku-2", "sku-3"]


def test_mine_ids_is_bounded_and_defensive():
    big = _http(200, [{"username": f"u{i}"} for i in range(100)])
    assert len(_mine_candidate_ids(big, "username", limit=3)) == 3
    # Garbage / non-JSON / wrong-shaped bodies mine nothing, never raise.
    assert _mine_candidate_ids("HTTP/1.1 200 OK\r\n\r\nnot json at all", "id") == []
    assert _mine_candidate_ids("HTTP/1.1 500 X\r\n\r\n", "id") == []
    assert _mine_candidate_ids(_http(200, {"ok": True}), "id") == []
    oversized = "HTTP/1.1 200 OK\r\n\r\n[" + "0," * 200_000 + "0]"
    assert _mine_candidate_ids(oversized, "id") == []


def test_path_helpers():
    assert _collection_path("/users/v1/{username}") == "/users/v1"
    assert _collection_path("/api/v1/orders/{order_ref}") == "/api/v1/orders"
    assert _collection_path("/api/v1/orders") == ""          # not a trailing-param route
    assert _param_name("/users/v1/{username}") == "username"
    assert _route_with_id("/users/v1/{username}", "na me") == "/users/v1/na%20me"


def test_resolve_concrete_path_mines_real_id_then_falls_back():
    ep = {"path": "/users/v1/{username}", "concrete_path": "/users/v1/1"}

    def fetch(header, url):
        return _make_app(cross_read=True)(["curl"] + (["-H", header] if header else []) + [url], 6)

    # A collection exists -> the placeholder is replaced by a real mined id.
    resolved = _resolve_concrete_path(BASE, ep, fetch, clean_low="Authorization: Bearer tokenA", clean_hdr="")
    assert resolved == "/users/v1/name1"

    def fetch_none(header, url):
        return _make_app(cross_read=True, collection="none")(["curl"] + (["-H", header] if header else []) + [url], 6)

    # No collection to mine -> keep the original placeholder path.
    assert _resolve_concrete_path(BASE, ep, fetch_none, clean_low="Authorization: Bearer tokenA",
                                  clean_hdr="") == "/users/v1/1"


# ───────────────────── probe_openapi end to end (fake run_fn) ─────────────────
def _probe(run_fn, *, include_peer: bool = True):
    return probe_openapi(
        "127.0.0.1", 8080, "http", run_fn,
        low_priv_header="Bearer tokenA", peer_auth_header="Bearer tokenB",
    ) if include_peer else probe_openapi(
        "127.0.0.1", 8080, "http", run_fn, low_priv_header="Bearer tokenA",
    )


def test_cross_user_bola_detected_with_mined_username():
    res = _probe(_make_app(cross_read=True))
    cross = [f for f in res["findings"] if f["title"].startswith("Cross-user horizontal BOLA")]
    assert len(cross) == 1
    f = cross[0]
    assert f["status"] == "VERIFIED" and f["severity"] == "HIGH"
    # The real PEER-owned username (name2), not the literal '1', is probed, and
    # the replay runs AS the low-priv identity (A / tokenA) so a retest is honest.
    assert "name2" in f["evidence"]
    assert "/users/v1/name2" in " ".join(f["repro_cmd"])
    assert "tokenA" in " ".join(f["repro_cmd"]) and "name1" not in " ".join(f["repro_cmd"])


def test_parameterized_read_without_peer_identity_is_unconfirmed():
    """A low-privilege self-read does not prove object ownership or BOLA."""
    res = _probe(_make_app(cross_read=True), include_peer=False)
    object_reads = [f for f in res["findings"] if f["title"].startswith("Unconfirmed object access")]
    assert len(object_reads) == 1
    assert object_reads[0]["status"] == "UNCONFIRMED"


def test_no_cross_user_finding_when_owner_only():
    """A reading only objects A owns (owner-only route) is not a vuln: the peer
    object is denied, so no cross-user BOLA is reported."""
    res = _probe(_make_app(cross_read=False))
    cross = [f for f in res["findings"] if f["title"].startswith("Cross-user horizontal BOLA")]
    assert cross == []


def test_shared_list_without_distinct_ownership_is_unconfirmed():
    """When A and B see the same collection, distinct ownership cannot be proven;
    the probe reports UNCONFIRMED rather than a false VERIFIED self-read."""
    res = _probe(_make_app(cross_read=True, collection="shared"))
    cross = [f for f in res["findings"] if f["title"].startswith("Cross-user horizontal BOLA")]
    assert len(cross) == 1 and cross[0]["status"] == "UNCONFIRMED"


def test_placeholder_fallback_when_no_collection():
    """No sibling collection to mine -> the probe falls back to the placeholder
    object path and the legacy peer-reads-low-object check (still VERIFIED here)."""
    res = _probe(_make_app(cross_read=True, collection="none"))
    cross = [f for f in res["findings"] if f["title"].startswith("Cross-user horizontal BOLA")]
    # With collection='none' the object path is /users/v1/1, which does not exist
    # (404), so low_code != 200 and the cross-user check never triggers: the
    # placeholder fallback is exercised without inventing a finding.
    assert cross == []
    # The spec was still discovered and the route still probed.
    assert res["found"] is True


def test_garbage_collection_body_falls_back_safely():
    res = _probe(_make_app(cross_read=True, collection="garbage"))
    # Mining yields nothing from the HTML junk; concrete path stays the
    # placeholder /users/v1/1 (404), so no cross-user finding is fabricated.
    cross = [f for f in res["findings"] if f["title"].startswith("Cross-user horizontal BOLA")]
    assert cross == []
    assert res["found"] is True

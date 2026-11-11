"""Hermetic tests for target-authentication login recipes and session refresh.

No network: a fake ``run_fn`` simulates the target login endpoints and the
per-endpoint probe requests. Every HTTP request ONIOPS makes for a login goes out
as a ``curl`` argv through ``run_fn`` exactly like any other target request.
"""
from __future__ import annotations

import json

import pytest

from oniops.greybox import probe_openapi
from oniops.scope import ScopeViolation
from oniops.target_auth import (
    LoginRecipe,
    TargetAuthError,
    TargetSession,
    build_sessions,
    fetch_with_refresh,
    parse_curl_response,
)

# A secret that must never surface anywhere persisted or displayed.
SECRET_PW = "S3cret-Pw-xyz-9000"


def _ok_json(body: dict) -> str:
    return "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n" + json.dumps(body)


# --------------------------------------------------------------------------
# parse_curl_response
# --------------------------------------------------------------------------

def test_parse_curl_response_status_cookies_body():
    raw = ("HTTP/1.1 302 Found\r\n"
           "Set-Cookie: PHPSESSID=abc123; path=/; HttpOnly\r\n"
           "Set-Cookie: extra=1; path=/\r\n"
           "Location: /index.php\r\n\r\n"
           "redirecting")
    resp = parse_curl_response(raw)
    assert resp.status == 302
    assert resp.set_cookies == {"PHPSESSID": "abc123", "extra": "1"}
    assert resp.body == "redirecting"


def test_parse_curl_response_no_http_line():
    resp = parse_curl_response("curl: (6) Could not resolve host")
    assert resp.status == 0
    assert resp.set_cookies == {}


# --------------------------------------------------------------------------
# json_login
# --------------------------------------------------------------------------

def _vampi_recipe(env_user="ONIOPS_T_USER", env_pass="ONIOPS_T_PASS"):
    return LoginRecipe.from_config({
        "type": "json_login",
        "login_url": "http://10.0.0.150:5000/users/v1/login",
        "json_body": {"username": f"${{{env_user}}}", "password": f"${{{env_pass}}}"},
        "token_path": "auth_token",
        "header_template": "Authorization: Bearer {token}",
    })


def test_json_login_happy_path_and_token_path():
    calls = {"n": 0}

    def run_fn(cmd, timeout):
        calls["n"] += 1
        assert cmd[-1].endswith("/users/v1/login")
        # Credentials are sent in the POST body (ephemeral), as expected.
        assert SECRET_PW in " ".join(cmd)
        return _ok_json({"auth_token": "TOKEN-1", "message": "ok"})

    env = {"ONIOPS_T_USER": "name1", "ONIOPS_T_PASS": SECRET_PW}
    sess = TargetSession("low_priv", _vampi_recipe(), env=env)
    header = sess.refresh(run_fn)
    assert header == "Authorization: Bearer TOKEN-1"
    assert sess.header() == "Authorization: Bearer TOKEN-1"
    assert calls["n"] == 1
    # The credential is never baked into the header, the stored recipe (which
    # keeps only ${ENV} references), or the error field.
    assert SECRET_PW not in sess.header()
    assert SECRET_PW not in json.dumps(sess.recipe.spec)
    assert SECRET_PW not in sess.last_error


def test_json_login_nested_token_path_juice():
    recipe = LoginRecipe.from_config({
        "type": "json_login",
        "login_url": "http://10.0.0.150:3000/rest/user/login",
        "json_body": {"email": "${U}", "password": "${P}"},
        "token_path": "authentication.token",
        "header_template": "Authorization: Bearer {token}",
    })

    def run_fn(cmd, timeout):
        return _ok_json({"authentication": {"token": "JWT-NESTED", "umail": "a@b.c"}})

    sess = TargetSession("primary", recipe, env={"U": "admin@juice-sh.op", "P": SECRET_PW})
    assert sess.refresh(run_fn) == "Authorization: Bearer JWT-NESTED"


def test_json_login_missing_token_returns_empty():
    def run_fn(cmd, timeout):
        return _ok_json({"message": "sorry, no token here"})

    sess = TargetSession("low_priv", _vampi_recipe(), env={"ONIOPS_T_USER": "x", "ONIOPS_T_PASS": SECRET_PW})
    assert sess.refresh(run_fn) == ""
    assert sess.header() == ""
    assert "token path" in sess.last_error
    assert SECRET_PW not in sess.last_error


def test_json_login_non_json_response_returns_empty():
    def run_fn(cmd, timeout):
        return "HTTP/1.1 500 Internal Server Error\r\n\r\n<html>boom</html>"

    sess = TargetSession("low_priv", _vampi_recipe(), env={"ONIOPS_T_USER": "x", "ONIOPS_T_PASS": "y"})
    assert sess.refresh(run_fn) == ""
    assert "not JSON" in sess.last_error


def test_refresh_produces_a_new_header():
    seq = iter(["TOK-A", "TOK-B", "TOK-C"])

    def run_fn(cmd, timeout):
        return _ok_json({"auth_token": next(seq)})

    sess = TargetSession("low_priv", _vampi_recipe(), env={"ONIOPS_T_USER": "x", "ONIOPS_T_PASS": "y"})
    assert sess.refresh(run_fn) == "Authorization: Bearer TOK-A"
    assert sess.refresh(run_fn) == "Authorization: Bearer TOK-B"
    assert sess.header() == "Authorization: Bearer TOK-B"


# --------------------------------------------------------------------------
# form_login (DVWA-shaped)
# --------------------------------------------------------------------------

def _dvwa_recipe():
    return LoginRecipe.from_config({
        "type": "form_login",
        "login_url": "http://10.0.0.150/login.php",
        "csrf_regex": r"name=['\"]user_token['\"]\s+value=['\"]([^'\"]+)['\"]",
        "csrf_field": "user_token",
        "form_fields": {"username": "${DVWA_USER}", "password": "${DVWA_PASS}", "Login": "Login"},
        "follow_up_url": "http://10.0.0.150/security.php",
        "extra_cookies": {"security": "low"},
    })


def test_form_login_csrf_cookie_capture_and_followup():
    seen = {"post_cmd": None}

    def run_fn(cmd, timeout):
        url = cmd[-1]
        is_post = "POST" in cmd
        if url.endswith("/login.php") and not is_post:
            return ("HTTP/1.1 200 OK\r\n"
                    "Set-Cookie: PHPSESSID=firstsess; path=/\r\n\r\n"
                    "<form><input type='hidden' name=\"user_token\" value=\"csrftok123\" /></form>")
        if url.endswith("/login.php") and is_post:
            seen["post_cmd"] = list(cmd)
            # Session id rotates on successful login.
            return "HTTP/1.1 302 Found\r\nSet-Cookie: PHPSESSID=loggedinsess; path=/\r\nLocation: /index.php\r\n\r\n"
        if url.endswith("/security.php"):
            return "HTTP/1.1 200 OK\r\n\r\n<html>security set</html>"
        raise AssertionError(f"unexpected url {url}")

    sess = TargetSession("primary", _dvwa_recipe(), env={"DVWA_USER": "admin", "DVWA_PASS": SECRET_PW})
    header = sess.refresh(run_fn)
    # Final cookie header: rotated session + the pinned security level.
    assert header == "Cookie: PHPSESSID=loggedinsess; security=low"
    # The CSRF token and credentials were submitted in the POST body...
    post = " ".join(seen["post_cmd"])
    assert "csrftok123" in post
    assert SECRET_PW in post
    # ...but never leak onto the resulting header or the stored recipe.
    assert SECRET_PW not in header
    assert SECRET_PW not in json.dumps(sess.recipe.spec)


def test_form_login_missing_csrf_returns_empty():
    def run_fn(cmd, timeout):
        return "HTTP/1.1 200 OK\r\n\r\n<form>no token here</form>"

    sess = TargetSession("primary", _dvwa_recipe(), env={"DVWA_USER": "admin", "DVWA_PASS": "p"})
    assert sess.refresh(run_fn) == ""
    assert "CSRF" in sess.last_error


# --------------------------------------------------------------------------
# fetch_with_refresh wrapper: retries exactly once then gives up
# --------------------------------------------------------------------------

def _status_of(out):
    import re
    m = re.search(r"HTTP/[\d.]+\s+(\d{3})", out or "")
    return int(m.group(1)) if m else 0


def test_fetch_with_refresh_retries_once_then_succeeds():
    login_calls = {"n": 0}

    def run_fn(cmd, timeout):
        login_calls["n"] += 1
        return _ok_json({"auth_token": "FRESH"})

    sess = TargetSession("low_priv", _vampi_recipe(), env={"ONIOPS_T_USER": "x", "ONIOPS_T_PASS": "y"},
                         initial_header="Authorization: Bearer STALE")

    fetched = []

    def do_fetch(header, url):
        fetched.append(header)
        # The stale token is rejected; the freshly minted one works.
        return "HTTP/1.1 200 OK\r\n\r\nok" if "FRESH" in header else "HTTP/1.1 401 Unauthorized\r\n\r\n"

    out = fetch_with_refresh(sess, "http://10.0.0.150:5000/x", run_fn, do_fetch, _status_of)
    assert _status_of(out) == 200
    assert login_calls["n"] == 1                     # refreshed exactly once
    assert fetched == ["Authorization: Bearer STALE", "Authorization: Bearer FRESH"]


def test_fetch_with_refresh_gives_up_after_one_retry():
    login_calls = {"n": 0}

    def run_fn(cmd, timeout):
        login_calls["n"] += 1
        return _ok_json({"auth_token": f"TOK{login_calls['n']}"})

    sess = TargetSession("low_priv", _vampi_recipe(), env={"ONIOPS_T_USER": "x", "ONIOPS_T_PASS": "y"},
                         initial_header="Authorization: Bearer STALE")

    fetched = []

    def do_fetch(header, url):
        fetched.append(header)
        return "HTTP/1.1 401 Unauthorized\r\n\r\n"     # always rejected

    out = fetch_with_refresh(sess, "http://10.0.0.150:5000/x", run_fn, do_fetch, _status_of)
    assert _status_of(out) == 401
    assert login_calls["n"] == 1                       # refreshed only once, then gave up
    assert len(fetched) == 2                            # initial + exactly one retry


# --------------------------------------------------------------------------
# static recipe / build_sessions / scope
# --------------------------------------------------------------------------

def test_static_recipe_passthrough_and_no_recipe():
    # A static recipe resolves a ${ENV} header and is never "refreshable".
    recipe = LoginRecipe.from_config({"type": "static", "header": "${STATIC_HDR}"})
    sess = TargetSession("peer", recipe, env={"STATIC_HDR": "X-API-Key: abc"})
    assert sess.header() == "X-API-Key: abc"
    assert sess.can_refresh is False

    # build_sessions: a role with neither recipe nor header is omitted; a static
    # per-assessment header still produces a (non-refreshable) session.
    sessions = build_sessions({}, static_headers={"primary": "Bearer tok", "low_priv": ""})
    assert set(sessions) == {"primary"}
    assert sessions["primary"].header() == "Authorization: Bearer tok"
    assert sessions["primary"].can_refresh is False


def test_bad_recipe_raises_target_auth_error():
    with pytest.raises(TargetAuthError):
        LoginRecipe.from_config({"type": "json_login", "login_url": "http://x/y"})  # no token_path


def test_login_url_is_scope_checked(scope):
    # Out-of-scope login host is refused before any request is issued.
    recipe = LoginRecipe.from_config({
        "type": "json_login", "login_url": "http://9.9.9.9:5000/login",
        "json_body": {"u": "a"}, "token_path": "t", "header_template": "Authorization: Bearer {token}",
    })
    sess = TargetSession("low_priv", recipe, scope=scope)

    def run_fn(cmd, timeout):
        raise AssertionError("no request should be issued for an out-of-scope login URL")

    with pytest.raises(ScopeViolation):
        sess.refresh(run_fn)


# --------------------------------------------------------------------------
# probe_openapi integration: a 401 low-priv request refreshes, retried request
# is the one evaluated, and NO credential reaches any finding/display field.
# --------------------------------------------------------------------------

SPEC = {
    "openapi": "3.0.0",
    "security": [{"bearerAuth": []}],
    "paths": {"/api/admin/users": {"get": {"summary": "list users"}}},
}


def _integration_run_fn():
    """Low-priv token STALE is expired (401); after re-login the token is FRESH
    (200). The login endpoint mints FRESH. Anonymous requests are 401."""
    def run_fn(cmd, timeout):
        joined = " ".join(cmd)
        url = cmd[-1]
        if url.endswith("/users/v1/login"):
            assert SECRET_PW in joined                 # creds sent to login only
            return _ok_json({"auth_token": "FRESH"})
        if any(url.endswith(p) for p in ("/openapi.json", "/swagger.json")):
            return json.dumps(SPEC)
        if "Bearer FRESH" in joined:
            return _ok_json({"id": 1, "username": "admin", "email": "a@b.c"})
        if "Bearer STALE" in joined:
            return "HTTP/1.1 401 Unauthorized\r\n\r\n"
        return "HTTP/1.1 401 Unauthorized\r\n\r\n"     # anonymous
    return run_fn


def test_probe_openapi_refreshes_expired_low_priv_and_evaluates_retry():
    recipe = _vampi_recipe()
    low = TargetSession("low_priv", recipe, env={"ONIOPS_T_USER": "name1", "ONIOPS_T_PASS": SECRET_PW},
                        initial_header="Authorization: Bearer STALE")
    res = probe_openapi("10.0.0.150", 5000, "http", _integration_run_fn(),
                        sessions={"low_priv": low})
    assert res["found"] is True
    assert len(res["findings"]) == 1
    f = res["findings"][0]
    # The retried (refreshed) request is what was evaluated: low-priv saw HTTP 200.
    assert "/api/admin/users" in f["title"]
    # repro carries the CURRENT (fresh) header, never the dead STALE token.
    repro = " ".join(f["repro_cmd"])
    assert "Bearer FRESH" in repro
    assert "STALE" not in repro
    assert low.header() == "Authorization: Bearer FRESH"


def test_no_credential_reaches_any_finding_or_display_field():
    recipe = _vampi_recipe()
    low = TargetSession("low_priv", recipe, env={"ONIOPS_T_USER": "name1", "ONIOPS_T_PASS": SECRET_PW},
                        initial_header="Authorization: Bearer STALE")
    res = probe_openapi("10.0.0.150", 5000, "http", _integration_run_fn(),
                        sessions={"low_priv": low})
    # Nothing a finding carries, nor the human-readable raw section, may contain
    # the password or the env var values.
    blob = json.dumps(res["findings"]) + "\n" + res["raw_section"]
    assert SECRET_PW not in blob
    assert "name1" not in blob
    # The resulting auth HEADER (a token) is all that is retained.
    assert "Bearer FRESH" in json.dumps(res["findings"])

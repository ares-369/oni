"""Target-authentication providers with session refresh.

ONIOPS authenticates to a TARGET using one HTTP header per role
(``primary``/``low_priv``/``peer``, matching the existing
``auth_header``/``low_priv_header``/``peer_auth_header``). Historically those
were fixed strings supplied per assessment. Two real cases break a fixed string:

  1. Short-lived JWTs. VAmPI issues bearer tokens that expire in ~60 seconds, so
     a token minted before the scan is dead by the time the per-endpoint
     access-control probe runs, silently collapsing the low-priv/peer
     differential into anonymous requests.
  2. Form logins. Apps like DVWA need a login round-trip (fetch a CSRF token,
     POST credentials, capture a session cookie) that a static header cannot do.

This module adds per-role *login recipes* and a :class:`TargetSession` that can
mint and re-mint a role's header. Every HTTP request is issued as a ``curl``
argv through the SAME ``run_fn``/runner used by the rest of ONIOPS, so it is
scope-checked, rate-limited and executed from the attack host. No new
dependency, no browser, no python ``requests``.

Security: target credentials (usernames/passwords/tokens) are secrets. They are
read from the environment at login time, used only to build the ephemeral login
``curl`` argv, and never stored on the session, returned to callers, or placed in
any finding, repro command, log line or report. Only the resulting auth HEADER is
retained and surfaced (and that is masked by ``findings.mask_command`` on
display).
"""

from __future__ import annotations

import json
import os
import re
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlsplit

from .greybox import sanitize_auth_header

# A request that was expected to be authenticated but came back with one of
# these statuses triggers a single refresh-and-retry.
REFRESH_STATUSES = (401, 403)

# The three roles ONIOPS differentiates, mapped 1:1 to the existing header args.
ROLES = ("primary", "low_priv", "peer")

RunFn = Callable[[list[str], int], str]

_ENV_REF = re.compile(r"^\$\{([A-Za-z_][A-Za-z0-9_]*)\}$")


class TargetAuthError(Exception):
    """A login recipe is malformed. Never carries credential values."""


def _resolve_secret(value: Any, env: dict[str, str]) -> str:
    """Resolve a config value to a string, expanding a sole ``${ENV_VAR}``.

    A bare literal (e.g. ``admin``) is returned unchanged; ``${NAME}`` is read
    from ``env`` (default the process environment). This keeps real secrets in
    the environment while allowing non-secret values (usernames) inline.
    """
    if not isinstance(value, str):
        return str(value)
    m = _ENV_REF.match(value.strip())
    if m:
        return env.get(m.group(1), "")
    return value


def _json_path(data: Any, path: str) -> Any:
    """Walk a dotted JSON path (e.g. ``authentication.token``). Returns None if
    any segment is missing or a non-mapping is traversed."""
    cur = data
    for part in str(path).split("."):
        if not part:
            continue
        if isinstance(cur, dict) and part in cur:
            cur = cur[part]
        else:
            return None
    return cur


@dataclass
class CurlResponse:
    status: int
    headers: list[tuple[str, str]]
    set_cookies: dict[str, str]
    body: str


def parse_curl_response(out: str) -> CurlResponse:
    """Parse the output of ``curl -kisS`` (headers + body) into status, header
    lines, captured cookies and body.

    Tolerant of leading transfer noise and of curl error lines on an empty body;
    when no HTTP status line is present the status is 0. Only the LAST response
    block's status line is used (so a ``100 Continue`` preamble is skipped), but
    ``Set-Cookie`` headers from every block are accumulated.
    """
    text = out or ""
    # Split headers from body on the first blank line (CRLF or LF).
    sep = re.search(r"\r?\n\r?\n", text)
    head = text[: sep.start()] if sep else text
    body = text[sep.end():] if sep else ""
    status = 0
    headers: list[tuple[str, str]] = []
    cookies: dict[str, str] = {}
    for line in head.splitlines():
        m = re.match(r"HTTP/[\d.]+\s+(\d{3})", line.strip())
        if m:
            status = int(m.group(1))
            continue
        if ":" in line:
            name, val = line.split(":", 1)
            name = name.strip()
            val = val.strip()
            headers.append((name, val))
            if name.lower() == "set-cookie":
                pair = val.split(";", 1)[0].strip()
                if "=" in pair:
                    ck, cv = pair.split("=", 1)
                    if ck.strip():
                        cookies[ck.strip()] = cv.strip()
    return CurlResponse(status=status, headers=headers, set_cookies=cookies, body=body)


@dataclass
class LoginRecipe:
    """A per-role recipe describing how to obtain that role's auth header.

    ``kind`` is one of ``static`` / ``json_login`` / ``form_login``. The raw
    config ``spec`` is kept; secret-bearing fields are resolved from the
    environment only at login time, never stored resolved.
    """

    kind: str
    spec: dict[str, Any] = field(default_factory=dict)

    @property
    def refreshable(self) -> bool:
        return self.kind in ("json_login", "form_login")

    @property
    def login_url(self) -> str:
        return str(self.spec.get("login_url", ""))

    @classmethod
    def from_config(cls, spec: dict[str, Any] | None) -> LoginRecipe | None:
        if not spec:
            return None
        if not isinstance(spec, dict):
            raise TargetAuthError("A login recipe must be a mapping.")
        kind = str(spec.get("type", "static")).strip().lower()
        if kind not in ("static", "json_login", "form_login"):
            raise TargetAuthError(f"Unknown login recipe type: {kind!r}.")
        if kind == "static":
            if "header" not in spec:
                raise TargetAuthError("A 'static' recipe requires a 'header'.")
        else:
            if not spec.get("login_url"):
                raise TargetAuthError(f"A '{kind}' recipe requires a 'login_url'.")
            if kind == "json_login":
                if not spec.get("token_path"):
                    raise TargetAuthError("A 'json_login' recipe requires a 'token_path'.")
                if not spec.get("header_template"):
                    raise TargetAuthError("A 'json_login' recipe requires a 'header_template'.")
            if kind == "form_login" and not spec.get("csrf_regex"):
                raise TargetAuthError("A 'form_login' recipe requires a 'csrf_regex'.")
        return cls(kind=kind, spec=dict(spec))


class TargetSession:
    """Holds one role's login recipe and current header, and can re-mint it.

    ``header()`` returns the current header string (already sanitized).
    ``refresh(run_fn)`` re-runs the login flow and returns the fresh header
    (``""`` if the login did not yield one). All HTTP goes out through
    ``run_fn`` as a ``curl`` argv, so it is scope-checked and rate-limited like
    any other target request. If a ``scope`` is supplied, the login URL host is
    scope-resolved before any request is issued.
    """

    def __init__(self, role: str, recipe: LoginRecipe | None, *,
                 initial_header: str = "", scope=None,
                 env: dict[str, str] | None = None, timeout: int = 8):
        self.role = role
        self.recipe = recipe
        self.scope = scope
        self.timeout = timeout
        self._env = env if env is not None else os.environ
        self._header = sanitize_auth_header(initial_header) if initial_header else ""
        # Sanitized, credential-free reason for the last failed/empty login.
        self.last_error = ""
        if recipe is not None and recipe.kind == "static" and not self._header:
            raw = _resolve_secret(recipe.spec.get("header", ""), self._env)
            self._header = sanitize_auth_header(raw) if raw else ""

    @property
    def can_refresh(self) -> bool:
        return self.recipe is not None and self.recipe.refreshable

    def header(self) -> str:
        return self._header

    def _scope_check(self) -> None:
        if self.scope is None:
            return
        host = urlsplit(self.recipe.login_url).hostname
        if host:
            # Raises ScopeViolation if out of scope; propagated to the caller.
            self.scope.resolve(host)

    def refresh(self, run_fn: RunFn) -> str:
        """Re-run the login flow and update the current header. Returns the new
        header, or ``""`` on failure (with a credential-free ``last_error``)."""
        if not self.can_refresh:
            return self._header
        self._scope_check()
        try:
            if self.recipe.kind == "json_login":
                header = self._json_login(run_fn)
            else:
                header = self._form_login(run_fn)
        except TargetAuthError as exc:
            self.last_error = str(exc)
            return ""
        if header:
            self._header = header
            self.last_error = ""
        return header

    # -- recipe implementations (credentials stay local to these methods) --

    def _json_login(self, run_fn: RunFn) -> str:
        spec = self.recipe.spec
        method = str(spec.get("method", "POST")).upper()
        body = {k: _resolve_secret(v, self._env) for k, v in (spec.get("json_body") or {}).items()}
        cmd = ["curl", "-kisS", "--max-time", str(self.timeout), "-X", method,
               "-H", "Content-Type: application/json"]
        for name, val in (spec.get("extra_headers") or {}).items():
            cmd.extend(["-H", f"{name}: {_resolve_secret(val, self._env)}"])
        cmd.extend(["-d", json.dumps(body), spec["login_url"]])
        resp = parse_curl_response(run_fn(cmd, self.timeout) or "")
        try:
            data = json.loads(resp.body)
        except (ValueError, TypeError):
            self.last_error = f"login response was not JSON (HTTP {resp.status})"
            return ""
        token = _json_path(data, spec["token_path"])
        if not isinstance(token, (str, int)) or token in ("", None):
            self.last_error = f"token path {spec['token_path']!r} not present in login response (HTTP {resp.status})"
            return ""
        header = str(spec["header_template"]).format(token=token)
        return sanitize_auth_header(header)

    def _form_login(self, run_fn: RunFn) -> str:
        spec = self.recipe.spec
        url = spec["login_url"]
        # Step 1: GET the login page -> CSRF/nonce token + initial cookies.
        get_resp = parse_curl_response(
            run_fn(["curl", "-kisS", "--max-time", str(self.timeout), url], self.timeout) or "")
        cookies = dict(get_resp.set_cookies)
        m = re.search(str(spec["csrf_regex"]), get_resp.body)
        if not m:
            self.last_error = f"CSRF token not found on login page (HTTP {get_resp.status})"
            return ""
        csrf_value = m.group(1) if m.groups() else m.group(0)
        csrf_field = str(spec.get("csrf_field", "csrf_token"))

        # Step 2: POST form-urlencoded credentials + CSRF token, carrying cookies.
        method = str(spec.get("method", "POST")).upper()
        cmd = ["curl", "-kisS", "--max-time", str(self.timeout), "-X", method]
        if cookies:
            cmd.extend(["-H", f"Cookie: {_cookie_header(cookies)}"])
        fields = {csrf_field: csrf_value}
        for name, val in (spec.get("form_fields") or {}).items():
            fields[name] = _resolve_secret(val, self._env)
        for name, val in fields.items():
            cmd.extend(["--data-urlencode", f"{name}={val}"])
        cmd.append(url)
        post_resp = parse_curl_response(run_fn(cmd, self.timeout) or "")
        cookies.update(post_resp.set_cookies)

        # Optional follow-up GET (e.g. DVWA /security.php to pin a session level).
        follow = spec.get("follow_up_url")
        if follow:
            follow_resp = parse_curl_response(
                run_fn(["curl", "-kisS", "--max-time", str(self.timeout),
                        "-H", f"Cookie: {_cookie_header(cookies)}", str(follow)], self.timeout) or "")
            cookies.update(follow_resp.set_cookies)

        # Extra static cookies (e.g. DVWA `security=low`) merged last.
        for name, val in (spec.get("extra_cookies") or {}).items():
            cookies[str(name)] = str(_resolve_secret(val, self._env))

        if not cookies:
            self.last_error = f"no session cookie captured from form login (HTTP {post_resp.status})"
            return ""
        template = str(spec.get("header_template", "Cookie: {cookies}"))
        return sanitize_auth_header(template.format(cookies=_cookie_header(cookies)))


def _cookie_header(cookies: dict[str, str]) -> str:
    return "; ".join(f"{k}={v}" for k, v in cookies.items())


def build_sessions(target_auth: dict[str, Any] | None, *, scope=None,
                   static_headers: dict[str, str] | None = None,
                   env: dict[str, str] | None = None) -> dict[str, TargetSession]:
    """Build a role -> TargetSession map from a ``target_auth`` config block.

    ``static_headers`` carries any per-assessment header already supplied via the
    API/UI; it is used as the initial header and, when no recipe is configured
    for a role, is the only source (today's behaviour, unchanged). Roles with no
    recipe and no static header are omitted.
    """
    static_headers = static_headers or {}
    sessions: dict[str, TargetSession] = {}
    for role in ROLES:
        recipe = LoginRecipe.from_config((target_auth or {}).get(role))
        initial = static_headers.get(role, "")
        if recipe is None and not initial:
            continue
        sessions[role] = TargetSession(role, recipe, initial_header=initial,
                                       scope=scope, env=env)
    return sessions


def fetch_with_refresh(session: TargetSession, url: str, run_fn: RunFn,
                       do_fetch: Callable[[str, str], str],
                       status_of: Callable[[str], int]) -> str:
    """Issue ``do_fetch(header, url)`` as ``session``; on a 401 (or 403) refresh
    the role's session ONCE and retry ONCE with the fresh header.

    ``do_fetch`` performs the actual request for a given header (so a caller can
    route it through an existing response cache); ``status_of`` extracts the HTTP
    status from that output. Returns the final response text.
    """
    header = session.header()
    out = do_fetch(header, url)
    if session.can_refresh and status_of(out) in REFRESH_STATUSES:
        new_header = session.refresh(run_fn)
        if new_header and new_header != header:
            out = do_fetch(new_header, url)
    return out

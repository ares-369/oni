"""Authentication for OniOps.

Modes (config.auth.mode):
  none   - no login (default; dev / behind a trusted network)
  basic  - HTTP Basic (simple single operator)
  local  - built-in login page + signed session cookie
  oidc   - SSO via any OpenID Connect provider (Authentik, Keycloak, Google,
           Azure AD, Okta, Auth0, ...). Requires the optional `authlib` extra.
  proxy  - trust a reverse-proxy forward-auth header (e.g. X-Forwarded-User,
           X-Authentik-Username). OniOps must be reachable ONLY via that proxy.

Passwords: store a pbkdf2 hash (auth.password_hash) in preference to a plaintext
ONIOPS_AUTH_PASSWORD. Sessions are signed with ONIOPS_SECRET_KEY.
"""

from __future__ import annotations

import hashlib
import hmac
import html
import logging
import secrets
import time
from urllib.parse import urlparse

from flask import Response, redirect, render_template, request, session

log = logging.getLogger("oniops.auth")

_PBKDF2_ITERS = 600_000
_OPEN_PATHS = {"/login", "/auth/callback", "/logout", "/healthz"}
_LOGIN_BUCKETS: dict[str, list[float]] = {}
_LOGIN_MAX_ATTEMPTS = 10
_LOGIN_WINDOW_SEC = 60.0
_VALID_ROLES = {"viewer", "operator", "admin"}
_ADMIN_ONLY_PATHS = {"/api/config", "/api/config/preview", "/api/kali/install", "/api/host"}
# Reads that are NOT safe for every role: the full database export (findings,
# evidence, stored replay credentials, terms-acceptance log) is admin-only.
_ADMIN_ONLY_READ_PATHS = {"/api/backup/download"}


def resolve_user_role(cfg, user: str) -> str:
    """Resolve the effective RBAC role ('viewer', 'operator', or 'admin') for an
    authenticated user."""
    roles_map = getattr(cfg.auth, "roles", None) or {}
    if user and user in roles_map:
        r = str(roles_map[user]).lower()
        if r in _VALID_ROLES:
            return r
    hdr_role = (request.headers.get("X-ONIOPS-Role") or "").strip().lower()
    if cfg.auth.mode == "proxy" and hdr_role in _VALID_ROLES:
        return hdr_role
    default_role = str(getattr(cfg.auth, "default_role", "admin") or "admin").lower()
    return default_role if default_role in _VALID_ROLES else "admin"


def check_rbac_permission(role: str, method: str, path: str, args=None) -> tuple[bool, str]:
    """Enforce 3-tier RBAC:
      - viewer: read-only GET/HEAD/OPTIONS + stateless PDF export (/api/report/pdf)
      - operator: can run assessments, agents, AIsec, and retests; cannot modify
                  config.yaml, scope boundaries, or system packages
      - admin: full control
    """
    r = (role or "admin").lower()
    m = (method or "GET").upper()
    args = args or {}
    # Admin-only reads: checked BEFORE the general "GET is read-only" rule.
    sensitive_read = path in _ADMIN_ONLY_READ_PATHS or (
        path == "/api/doctor" and str(args.get("runner", "")).lower() in ("1", "true", "yes"))
    if sensitive_read and r != "admin":
        return False, f"Forbidden: {path} is restricted to the admin role."
    if m in ("GET", "HEAD", "OPTIONS") or path in _OPEN_PATHS or path == "/api/report/pdf":
        return True, ""
    if r == "viewer":
        return False, "Forbidden: role 'viewer' is read-only and cannot trigger scans or modify state."
    if r == "operator" and path in _ADMIN_ONLY_PATHS:
        return False, f"Forbidden: role 'operator' cannot modify administrative endpoint {path}."
    return True, ""


def _check_login_rate_limit(ip: str) -> bool:
    """Return True if the IP is within the login rate limit, False if throttled."""
    now = time.monotonic()
    bucket = [t for t in _LOGIN_BUCKETS.get(ip, []) if now - t < _LOGIN_WINDOW_SEC]
    if len(bucket) >= _LOGIN_MAX_ATTEMPTS:
        _LOGIN_BUCKETS[ip] = bucket
        return False
    bucket.append(now)
    _LOGIN_BUCKETS[ip] = bucket
    return True


def _origin_matches_request(cfg) -> bool:
    """Validate Origin/Referer header on state-changing cookie-authenticated requests."""
    origin = request.headers.get("Origin") or ""
    if not origin:
        return True
    try:
        o_host = urlparse(origin).netloc.lower()
    except Exception:
        return False
    allowed_hosts = {request.host.lower()}
    if cfg.external_url:
        try:
            allowed_hosts.add(urlparse(cfg.external_url).netloc.lower())
        except Exception:
            pass
    return bool(o_host and o_host in allowed_hosts)


# ---- password hashing ----
def hash_password(pw: str, iters: int = _PBKDF2_ITERS) -> str:
    salt = secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac("sha256", pw.encode(), salt, iters)
    return f"pbkdf2_sha256${iters}${salt.hex()}${dk.hex()}"


def _check_hash(stored: str, pw: str) -> bool:
    try:
        algo, iters, salt_hex, hash_hex = stored.split("$", 3)
        if algo != "pbkdf2_sha256":
            return False
        dk = hashlib.pbkdf2_hmac("sha256", pw.encode(), bytes.fromhex(salt_hex), int(iters))
        return hmac.compare_digest(dk.hex(), hash_hex)
    except Exception:
        return False


def _verify_password(cfg, pw: str) -> bool:
    if cfg.auth.password_hash:
        return _check_hash(cfg.auth.password_hash, pw)
    if cfg.auth.password:
        return hmac.compare_digest(pw, cfg.auth.password)
    return False


def _user_allowed(cfg, user: str) -> bool:
    allow = cfg.auth.allowed_users
    return (not allow) or (user in allow)


def init_auth(app, cfg) -> None:
    mode = cfg.auth.mode

    app.secret_key = cfg.auth.secret_key or secrets.token_hex(32)
    app.config.update(
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        SESSION_COOKIE_NAME="oniops_session",
    )
    if mode in ("local", "oidc") and not cfg.auth.secret_key:
        log.warning("auth.mode=%s but ONIOPS_SECRET_KEY is unset; using an ephemeral "
                    "key (sessions drop on restart). Set ONIOPS_SECRET_KEY.", mode)

    oauth = None
    if mode == "oidc":
        try:
            from authlib.integrations.flask_client import OAuth  # optional dep
        except ImportError as err:
            raise RuntimeError("auth.mode=oidc requires the 'oidc' extra: pip install 'oniops[oidc]'") from err
        o = cfg.auth.oidc
        if not (o.get("issuer") and o.get("client_id")):
            raise RuntimeError("auth.mode=oidc requires auth.oidc.issuer and client_id")
        oauth = OAuth(app)
        oauth.register(
            name="oniops_sso",
            client_id=o["client_id"],
            client_secret=o["client_secret"],
            server_metadata_url=o["issuer"].rstrip("/") + "/.well-known/openid-configuration",
            client_kwargs={"scope": o.get("scopes", "openid email profile")},
        )

    @app.before_request
    def _guard():
        if mode == "none":
            return None
        p = request.path
        if p.startswith("/static/") or p in _OPEN_PATHS:
            return None

        if mode == "basic":
            a = request.authorization
            if (a and _verify_password(cfg, a.password or "")
                    and hmac.compare_digest(a.username or "", cfg.auth.username)):
                role = resolve_user_role(cfg, a.username or "")
                allowed, reason = check_rbac_permission(role, request.method, p, request.args)
                if not allowed:
                    return Response(reason, 403)
                return None
            return Response("OniOps authentication required", 401,
                            {"WWW-Authenticate": 'Basic realm="OniOps"'})

        if mode == "proxy":
            # Anti-forgery: only a trusted proxy IP may assert the identity header.
            # Fail CLOSED: with no trusted-proxy list, anyone could send the
            # header and log in as any user, so refuse every request instead.
            if not cfg.auth.proxy_trusted_ips:
                return Response("Forbidden: auth.mode=proxy requires auth.proxy_trusted_ips "
                                "(the reverse proxy's IP). Refusing to trust the identity header.", 403)
            if request.remote_addr not in cfg.auth.proxy_trusted_ips:
                return Response("Forbidden: request did not arrive via a trusted proxy.", 403)
            user = request.headers.get(cfg.auth.proxy_header, "")
            if user and _user_allowed(cfg, user):
                role = resolve_user_role(cfg, user)
                allowed, reason = check_rbac_permission(role, request.method, p, request.args)
                if not allowed:
                    return Response(reason, 403)
                return None
            return Response("Forbidden: missing or disallowed proxy auth header.", 403)

        # local / oidc -> session
        user = session.get("user")
        if user:
            if request.method in ("POST", "PUT", "DELETE", "PATCH") and not _origin_matches_request(cfg):
                return Response("Forbidden: cross-origin state-changing request blocked (CSRF guard).", 403)
            role = session.get("role") or resolve_user_role(cfg, str(user))
            allowed, reason = check_rbac_permission(role, request.method, p, request.args)
            if not allowed:
                return Response(reason, 403)
            return None
        if p.startswith("/api/"):
            return Response("Authentication required.", 401)
        return redirect("/login")

    @app.route("/login", methods=["GET", "POST"])
    def login():
        if mode == "none":
            return redirect("/")
        if mode == "oidc":
            base = (cfg.external_url or request.url_root).rstrip("/")
            redirect_uri = base + "/auth/callback"
            return oauth.oniops_sso.authorize_redirect(redirect_uri)
        # local (and basic, though basic never redirects here)
        if request.method == "POST":
            client_ip = request.remote_addr or "unknown"
            if not _check_login_rate_limit(client_ip):
                return Response("Too many login attempts. Please wait 60 seconds.", 429)
            u = request.form.get("username", "")
            pw = request.form.get("password", "")
            if hmac.compare_digest(u, cfg.auth.username) and _verify_password(cfg, pw):
                session["user"] = u
                return redirect("/")
            return render_template("login.html", error="Invalid credentials.",
                                   instance=cfg.instance_name), 401
        return render_template("login.html", error=None, instance=cfg.instance_name)

    @app.route("/auth/callback")
    def auth_callback():
        if mode != "oidc":
            return redirect("/")
        def _fail(msg: str):
            safe_msg = html.escape(str(msg or ""))
            return Response(
                f"<!doctype html><meta charset=utf-8><title>OniOps sign-in</title>"
                f"<body style='background:#090b10;color:#f1f5f9;font-family:Inter,sans-serif;"
                f"display:flex;min-height:100vh;align-items:center;justify-content:center;text-align:center'>"
                f"<div><h2 style='color:#ef4444'>Sign-in failed</h2><p style='color:#94a3b8'>{safe_msg}</p>"
                f"<a href='/login' style='color:#ef4444'>Try again</a></div></body>", 400,
                {"Content-Type": "text/html; charset=utf-8"})

        err = request.args.get("error")
        if err:
            desc = request.args.get("error_description", err)
            log.warning("OIDC provider returned an error: %s (%s)", err, desc)
            return _fail(desc)
        try:
            token = oauth.oniops_sso.authorize_access_token()
            info = token.get("userinfo") or {}
        except Exception as exc:
            log.warning("OIDC callback exchange failed: %s", exc)
            return _fail("Could not complete sign-in. Please try again.")
        claim = cfg.auth.oidc.get("username_claim", "email")
        user = info.get(claim) or info.get("email") or info.get("preferred_username") or info.get("sub")
        if not user or not _user_allowed(cfg, user):
            return Response("Forbidden: your account is not permitted.", 403)
        session["user"] = user
        return redirect("/")

    @app.route("/logout")
    def logout():
        session.clear()
        return redirect("/login" if mode != "none" else "/")

    @app.route("/healthz")
    def healthz():
        return {"ok": True}

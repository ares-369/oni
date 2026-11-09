"""Authentication for ONIOPS.

Modes (config.auth.mode):
  none   - no login (default; dev / behind a trusted network)
  basic  - HTTP Basic (simple single operator)
  local  - built-in login page + signed session cookie
  oidc   - SSO via any OpenID Connect provider (Authentik, Keycloak, Google,
           Azure AD, Okta, Auth0, ...). Requires the optional `authlib` extra.
  proxy  - trust a reverse-proxy forward-auth header (e.g. X-Forwarded-User,
           X-Authentik-Username). ONIOPS must be reachable ONLY via that proxy.

Passwords: store a pbkdf2 hash (auth.password_hash) in preference to a plaintext
ONIOPS_AUTH_PASSWORD. Sessions are signed with ONIOPS_SECRET_KEY.
"""

from __future__ import annotations

import hashlib
import hmac
import logging
import secrets

from flask import Response, redirect, render_template, request, session

log = logging.getLogger("oniops.auth")

_PBKDF2_ITERS = 240_000
_OPEN_PATHS = {"/login", "/auth/callback", "/logout", "/healthz"}


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
                return None
            return Response("ONIOPS authentication required", 401,
                            {"WWW-Authenticate": 'Basic realm="ONIOPS"'})

        if mode == "proxy":
            # Anti-forgery: only a trusted proxy IP may assert the identity header.
            if cfg.auth.proxy_trusted_ips and request.remote_addr not in cfg.auth.proxy_trusted_ips:
                return Response("Forbidden: request did not arrive via a trusted proxy.", 403)
            user = request.headers.get(cfg.auth.proxy_header, "")
            if user and _user_allowed(cfg, user):
                return None
            return Response("Forbidden: missing or disallowed proxy auth header.", 403)

        # local / oidc -> session
        if session.get("user"):
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
            return Response(
                f"<!doctype html><meta charset=utf-8><title>ONIOPS sign-in</title>"
                f"<body style='background:#090b10;color:#f1f5f9;font-family:Inter,sans-serif;"
                f"display:flex;min-height:100vh;align-items:center;justify-content:center;text-align:center'>"
                f"<div><h2 style='color:#ef4444'>Sign-in failed</h2><p style='color:#94a3b8'>{msg}</p>"
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

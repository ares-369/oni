"""Bundled practice target for `oniops demo` and the end-to-end tests.

A tiny standard-library HTTP app with a few deliberately planted, well-known
API weaknesses and matching correctly-secured "twin" endpoints. It exists so
OniOps's real probes and validators can be exercised without an attack host,
an LLM, or any network beyond loopback.

Safety properties (enforced in code, not just documented):
  - It only ever binds to a loopback address (127.0.0.1 / ::1 / localhost);
    any other bind address raises ValueError before a socket is opened.
  - It listens on an ephemeral port chosen by the OS.
  - All data is fake and held in memory. Nothing is read from or written to
    disk, and no request is ever forwarded anywhere.

Planted weaknesses (vulnerable mode):
  W1  GET  /                        live HTTP service without security headers
  W2  GET  /api/v1/debug/env        unauthenticated access to a debug route
  W3  GET  /api/v1/users/{id}       object-level authz (BOLA): any logged-in
                                    user can read user 1, incl. a peer user
  W4  GET  /api/v1/admin/config     function-level authz (BFLA): a normal
                                    user can call an admin function
  W5  PATCH /api/v1/users/{id}      OpenAPI schema lets clients write role/is_admin
  W6  POST /graphql                 schema introspection enabled
  W7  GET  /api/v1/search?q=        verbose SQL error disclosed to the client
  W8  GET  /api/v1/echo?msg=        input reflected into HTML unescaped

Secure twins (must NOT be reported):
  S1  GET  /api/v1/secrets/{id}     401 anonymous, 403 to normal users, 200 admin
  S2  GET  /api/v1/tokens/status    200 with an empty body, no API content-type
  S3  GET  /api/v1/internal/metrics 403 to everyone, always

`set_fixed(True)` switches the target to a remediated state (W2-W4, W6-W8
closed) so a zero-token retest can be shown flipping a finding to FIXED.
"""
from __future__ import annotations

import html
import ipaddress
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

# Fake demo credentials. They only mean something to this in-process target.
ADMIN_TOKEN = "oniops-demo-admin-0000"
USER_A_TOKEN = "oniops-demo-user-a-0000"
USER_B_TOKEN = "oniops-demo-user-b-0000"
ADMIN_HEADER = f"Authorization: Bearer {ADMIN_TOKEN}"
USER_A_HEADER = f"Authorization: Bearer {USER_A_TOKEN}"
USER_B_HEADER = f"Authorization: Bearer {USER_B_TOKEN}"

_TOKENS = {ADMIN_TOKEN: "admin", USER_A_TOKEN: "user_a", USER_B_TOKEN: "user_b"}

_USERS = {
    1: {"id": 1, "username": "alice", "email": "alice@demo.invalid", "role": "user", "plan": "pro"},
    2: {"id": 2, "username": "bob", "email": "bob@demo.invalid", "role": "user", "plan": "free"},
}
_OWNER = {"user_a": 1, "user_b": 2}

_LOOPBACK_NAMES = ("localhost",)


def is_loopback_host(host: str) -> bool:
    """True only for loopback addresses (127.0.0.0/8, ::1) or 'localhost'."""
    h = (host or "").strip().strip("[]").lower()
    if h in _LOOPBACK_NAMES:
        return True
    try:
        return ipaddress.ip_address(h).is_loopback
    except ValueError:
        return False


def openapi_spec() -> dict:
    """The demo app's OpenAPI document (what OniOps discovers at /openapi.json)."""
    bearer = [{"bearerAuth": []}]
    ok = {"200": {"description": "OK"}}
    return {
        "openapi": "3.0.3",
        "info": {"title": "OniOps demo target (fake data)", "version": "1.0"},
        "security": bearer,
        "components": {
            "securitySchemes": {"bearerAuth": {"type": "http", "scheme": "bearer"}},
            "schemas": {
                "UserUpdate": {
                    "type": "object",
                    "properties": {
                        "email": {"type": "string"},
                        "role": {"type": "string"},
                        "is_admin": {"type": "boolean"},
                    },
                },
            },
        },
        "paths": {
            "/api/v1/debug/env": {"get": {"summary": "Debug environment", "responses": ok}},
            "/api/v1/users/{id}": {
                "get": {"summary": "Read a user profile", "responses": ok},
                "patch": {
                    "summary": "Update a user profile",
                    "requestBody": {"content": {"application/json": {
                        "schema": {"$ref": "#/components/schemas/UserUpdate"}}}},
                    "responses": ok,
                },
            },
            "/api/v1/admin/config": {"get": {"summary": "Admin configuration", "responses": ok}},
            "/api/v1/secrets/{id}": {"get": {"summary": "Read a secret (admin only)", "responses": ok}},
            "/api/v1/tokens/status": {"get": {"summary": "Token service heartbeat", "responses": ok}},
            "/api/v1/internal/metrics": {"get": {"summary": "Internal metrics", "responses": ok}},
            "/api/v1/search": {"get": {"summary": "Search products", "security": [], "responses": ok}},
            "/api/v1/echo": {"get": {"summary": "Echo a message", "security": [], "responses": ok}},
        },
    }


class _Handler(BaseHTTPRequestHandler):
    server_version = "ONIOPS-Demo-Target/1.0"
    sys_version = ""

    # Quiet: the demo prints its own summary.
    def log_message(self, format, *args):
        return

    # ---- helpers ----
    @property
    def _fixed(self) -> bool:
        return bool(getattr(self.server, "fixed", False))

    def _role(self) -> str:
        auth = self.headers.get("Authorization", "")
        if auth.lower().startswith("bearer "):
            return _TOKENS.get(auth[7:].strip(), "invalid")
        return "anonymous"

    def _send(self, code: int, body: bytes = b"", ctype: str = "application/json",
              extra: dict | None = None) -> None:
        self.send_response(code)
        if ctype:
            self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        if self.command != "HEAD" and body:
            self.wfile.write(body)

    def _json(self, code: int, obj) -> None:
        self._send(code, json.dumps(obj).encode("utf-8"))

    def _deny(self, role: str) -> None:
        if role in ("anonymous", "invalid"):
            self._json(401, {"error": "authentication required"})
        else:
            self._json(403, {"error": "forbidden"})

    # ---- routes ----
    def do_HEAD(self):
        self.do_GET()

    def do_GET(self):
        parts = urlsplit(self.path)
        path = parts.path.rstrip("/") or "/"
        query = parse_qs(parts.query)
        role = self._role()
        fixed = self._fixed

        if path == "/":
            page = (b"<!doctype html><html><head><title>OniOps demo target</title></head>"
                    b"<body><h1>OniOps demo target</h1><p>Fake data. Loopback only.</p></body></html>")
            extra = {}
            if fixed:
                extra = {"X-Content-Type-Options": "nosniff", "X-Frame-Options": "DENY",
                         "Content-Security-Policy": "default-src 'self'"}
            return self._send(200, page, "text/html; charset=utf-8", extra)

        if path == "/openapi.json":
            return self._json(200, openapi_spec())

        if path == "/api/v1/debug/env":
            # W2: unauthenticated debug route (fixed: admin only).
            if fixed and role != "admin":
                return self._json(403, {"error": "forbidden"})
            return self._json(200, {"APP_ENV": "demo", "DEBUG": True,
                                    "DATABASE_URL": "postgres://demo:demo@db.invalid/app",
                                    "FEATURE_FLAGS": ["beta-search", "legacy-export"]})

        if path.startswith("/api/v1/users/"):
            # W3: BOLA. Vulnerable: any valid token reads any user object.
            try:
                uid = int(path.rsplit("/", 1)[1])
            except ValueError:
                return self._json(404, {"error": "not found"})
            if role in ("anonymous", "invalid"):
                return self._deny(role)
            if uid not in _USERS:
                return self._json(404, {"error": "not found"})
            if fixed and role != "admin" and _OWNER.get(role) != uid:
                return self._deny(role)
            return self._json(200, _USERS[uid])

        if path == "/api/v1/admin/config":
            # W4: BFLA. Vulnerable: any valid token may call this admin function.
            if role in ("anonymous", "invalid"):
                return self._deny(role)
            if fixed and role != "admin":
                return self._deny(role)
            return self._json(200, {"maintenance_mode": False, "signup_open": True,
                                    "smtp_relay": "mail.demo.invalid", "max_upload_mb": 50})

        if path.startswith("/api/v1/secrets/"):
            # S1: correctly secured object endpoint.
            if role != "admin":
                return self._deny(role)
            return self._json(200, {"id": 1, "name": "demo-secret", "value": "not-a-real-secret"})

        if path == "/api/v1/tokens/status":
            # S2: 200 with an empty body and no API content-type.
            return self._send(200, b"", "text/plain")

        if path == "/api/v1/internal/metrics":
            # S3: a 403 that stays 403 for everyone.
            return self._json(403, {"error": "forbidden"})

        if path == "/api/v1/search":
            # W7: verbose SQL error (fixed: generic message).
            q = (query.get("q") or [""])[0]
            if "'" in q and not fixed:
                msg = ("You have an error in your SQL syntax; check the manual that corresponds "
                       "to your MySQL server version for the right syntax to use near "
                       f"'{q[:40]}' at line 1")
                return self._json(500, {"error": msg})
            if "'" in q:
                return self._json(400, {"error": "invalid search query"})
            return self._json(200, {"results": [{"sku": "demo-1", "name": "Demo widget"}]})

        if path == "/api/v1/echo":
            # W8: reflected input (fixed: HTML-escaped).
            msg = (query.get("msg") or [""])[0][:200]
            shown = html.escape(msg) if fixed else msg
            body = f"<!doctype html><html><body><p>You said: {shown}</p></body></html>".encode()
            return self._send(200, body, "text/html; charset=utf-8")

        return self._json(404, {"error": "not found"})

    def do_POST(self):
        path = urlsplit(self.path).path.rstrip("/")
        length = min(int(self.headers.get("Content-Length") or 0), 65536)
        raw = self.rfile.read(length) if length else b""
        if path == "/graphql":
            # W6: introspection enabled (fixed: refused).
            if b"__schema" in raw:
                if self._fixed:
                    return self._json(400, {"errors": [{"message": "introspection is disabled"}]})
                return self._json(200, {"data": {"__schema": {
                    "queryType": {"name": "Query"},
                    "types": [{"name": "Query"}, {"name": "User"}, {"name": "AdminConfig"}]}}})
            return self._json(200, {"data": None})
        return self._json(404, {"error": "not found"})


class DemoTarget:
    """Start/stop the practice target programmatically.

        with DemoTarget() as t:
            print(t.base_url)   # http://127.0.0.1:<ephemeral>
            t.set_fixed(True)
    """

    def __init__(self, host: str = "127.0.0.1", port: int = 0) -> None:
        if not is_loopback_host(host):
            raise ValueError(
                f"The demo target only binds to loopback (127.0.0.1); refusing bind address {host!r}."
            )
        if host == "localhost":
            host = "127.0.0.1"
        self.host = host
        self._requested_port = int(port)
        self._httpd: ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None

    @property
    def port(self) -> int:
        if not self._httpd:
            raise RuntimeError("Demo target is not running.")
        return int(self._httpd.server_address[1])

    @property
    def ip(self) -> str:
        return self.host

    @property
    def base_url(self) -> str:
        return f"http://{self.host}:{self.port}"

    @property
    def fixed(self) -> bool:
        return bool(self._httpd and getattr(self._httpd, "fixed", False))

    def set_fixed(self, fixed: bool = True) -> None:
        """Switch between the vulnerable state and a remediated state."""
        if not self._httpd:
            raise RuntimeError("Demo target is not running.")
        self._httpd.fixed = bool(fixed)  # type: ignore[attr-defined]

    def start(self) -> DemoTarget:
        if self._httpd:
            return self
        httpd = ThreadingHTTPServer((self.host, self._requested_port), _Handler)
        httpd.daemon_threads = True
        httpd.fixed = False  # type: ignore[attr-defined]
        # Re-check what the OS actually bound, in case of an odd resolver.
        if not is_loopback_host(str(httpd.server_address[0])):
            httpd.server_close()
            raise ValueError("Demo target refused: socket is not bound to loopback.")
        self._httpd = httpd
        self._thread = threading.Thread(target=httpd.serve_forever, kwargs={"poll_interval": 0.05},
                                        name="oniops-demo-target", daemon=True)
        self._thread.start()
        return self

    def stop(self) -> None:
        if self._httpd:
            self._httpd.shutdown()
            self._httpd.server_close()
            self._httpd = None
        if self._thread:
            self._thread.join(timeout=5)
            self._thread = None

    def __enter__(self) -> DemoTarget:
        return self.start()

    def __exit__(self, *exc) -> None:
        self.stop()

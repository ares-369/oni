"""Grey-Box (authenticated + OpenAPI) and lightweight White-Box analysis.

Bridges Black-Box scanning with Grey-Box/White-Box verification:
  1. Safe auth-header parsing (`Authorization: Bearer ...` / `Cookie: ...`)
     for passing test credentials into httpx/ffuf/katana/nuclei/curl without
     shell or CRLF injection.
  2. Automatic OpenAPI/Swagger discovery and Unauthenticated vs. Authenticated
     access-control differential probing.
  3. Lightweight White-Box route and secret extraction from source code or
     mounted repository files.
"""
from __future__ import annotations

import json
import re
import shutil
import subprocess
from pathlib import Path

from .findings import redact_secrets

OPENAPI_PATHS = (
    "/openapi.json",
    "/swagger.json",
    "/v3/api-docs",
    "/api/openapi.json",
    "/api/v1/openapi.json",
    "/docs/openapi.json",
)


def sanitize_auth_header(raw: str) -> str:
    """Validate and normalize a single HTTP header line (e.g. 'Cookie: sid=...'
    or 'Authorization: Bearer ...' or a bare 'Bearer xxx' token). Rejects any
    CRLF or control characters to prevent header/flag injection."""
    if not raw or not str(raw).strip():
        return ""
    s = str(raw).strip()
    if any(ch in s for ch in ("\r", "\n", "\x00")):
        raise ValueError("Invalid characters in auth header (newlines are not allowed).")
    if len(s) > 1024:
        raise ValueError("Auth header exceeds maximum length (1024 chars).")
    if ":" not in s:
        if s.lower().startswith("bearer "):
            return f"Authorization: {s}"
        return f"Authorization: Bearer {s}"
    name, val = s.split(":", 1)
    name = name.strip()
    val = val.strip()
    if not re.match(r"^[A-Za-z0-9\-_]{1,64}$", name) or not val:
        raise ValueError("Auth header must be 'Header-Name: value' or a Bearer token.")
    return f"{name}: {val}"


def extract_openapi_endpoints(spec: dict) -> list[dict]:
    """Extract [{path, methods, auth_required}] from an OpenAPI v2/v3 dict."""
    if not isinstance(spec, dict):
        return []
    paths = spec.get("paths")
    if not isinstance(paths, dict):
        return []
    global_sec = bool(spec.get("security"))
    endpoints: list[dict] = []
    for route, item in paths.items():
        if not isinstance(route, str) or not route.startswith("/") or not isinstance(item, dict):
            continue
        methods: list[str] = []
        auth_req = global_sec
        for m in ("get", "post", "put", "delete", "patch"):
            if m in item and isinstance(item[m], dict):
                methods.append(m.upper())
                if "security" in item[m]:
                    auth_req = bool(item[m]["security"])
        if methods:
            # Replace {id} path params with '1' so probes hit a concrete path.
            concrete = re.sub(r"\{[^}]+\}", "1", route)
            endpoints.append({
                "path": route,
                "concrete_path": concrete,
                "methods": methods,
                "auth_declared": auth_req,
            })
    return endpoints[:30]


_PRIVILEGE_PROPS = {"role", "roles", "is_admin", "isadmin", "admin", "tenant_id", "permissions", "balance", "credit"}


def extract_bopla_mass_assignment_risks(spec: dict) -> list[dict]:
    """Inspect request schemas for writable privilege properties.

    Supports OpenAPI 3 media types, OpenAPI 2 body parameters, nested local
    ``$ref`` values, and schema composition. External references are ignored;
    fetching them would make a passive spec inspection perform network I/O.
    """
    if not isinstance(spec, dict):
        return []
    paths = spec.get("paths") or {}
    risks: list[dict] = []

    def resolve_ref(ref: str) -> dict:
        if not ref.startswith("#/"):
            return {}
        value: object = spec
        for part in ref[2:].split("/"):
            part = part.replace("~1", "/").replace("~0", "~")
            if not isinstance(value, dict) or part not in value:
                return {}
            value = value[part]
        return value if isinstance(value, dict) else {}

    def privileged_fields(schema: dict, ref_stack: frozenset[str] = frozenset()) -> list[str]:
        exposed: list[str] = []
        ref = schema.get("$ref")
        if isinstance(ref, str) and ref not in ref_stack:
            target = resolve_ref(ref)
            if target:
                exposed.extend(privileged_fields(target, ref_stack | {ref}))
        properties = schema.get("properties")
        if isinstance(properties, dict):
            for name, child in properties.items():
                if not isinstance(name, str):
                    continue
                if name.lower() in _PRIVILEGE_PROPS and not (
                    isinstance(child, dict) and child.get("readOnly") is True
                ):
                    exposed.append(name)
                if isinstance(child, dict):
                    exposed.extend(privileged_fields(child, ref_stack))
        for keyword in ("allOf", "oneOf", "anyOf"):
            branches = schema.get(keyword)
            if isinstance(branches, list):
                for branch in branches:
                    if isinstance(branch, dict):
                        exposed.extend(privileged_fields(branch, ref_stack))
        for keyword in ("items", "additionalProperties"):
            child = schema.get(keyword)
            if isinstance(child, dict):
                exposed.extend(privileged_fields(child, ref_stack))
        # Preserve source order while collapsing the same field found through
        # repeated/allOf references.
        return list(dict.fromkeys(exposed))

    for route, item in paths.items():
        if not isinstance(item, dict):
            continue
        for method in ("post", "put", "patch"):
            op = item.get(method)
            if not isinstance(op, dict):
                continue
            exposed: list[str] = []
            request_body = op.get("requestBody")
            content = request_body.get("content") if isinstance(request_body, dict) else None
            if isinstance(content, dict):
                for media in content.values():
                    if isinstance(media, dict) and isinstance(media.get("schema"), dict):
                        exposed.extend(privileged_fields(media["schema"]))
            parameters = op.get("parameters")
            if isinstance(parameters, list):
                for parameter in parameters:
                    if not isinstance(parameter, dict):
                        continue
                    if parameter.get("in") == "body" and isinstance(parameter.get("schema"), dict):
                        exposed.extend(privileged_fields(parameter["schema"]))
                    elif parameter.get("in") == "formData":
                        name = parameter.get("name")
                        if isinstance(name, str) and name.lower() in _PRIVILEGE_PROPS:
                            exposed.append(name)
            exposed = list(dict.fromkeys(exposed))
            if exposed:
                risks.append({
                    "path": route,
                    "method": method.upper(),
                    "writable_privilege_fields": exposed,
                })
    return risks


def probe_graphql_introspection(ip: str, port: int, scheme: str, run_fn) -> dict | None:
    """Test whether `/graphql` exposes unauthenticated GraphQL schema introspection
    (OWASP API8:2023 / WSTG-APIT-01)."""
    url = f"{scheme}://{ip}:{port}/graphql"
    query = '{"query":"{__schema{queryType{name}}}"}'
    # -i keeps the status line so a retest can tell a live reply from no reply;
    # the proof check below only looks for the GraphQL introspection keys.
    cmd = ["curl", "-kisS", "--max-time", "5", "-X", "POST", "-H", "Content-Type: application/json", "-d", query, url]
    out = (run_fn(cmd, 7) or "").strip()
    if '"__schema"' in out or '"queryType"' in out:
        return {
            "port": port,
            "title": "Exposed GraphQL schema introspection on /graphql (API8:2023)",
            "category": "graphql",
            "severity": "MEDIUM",
            "status": "VERIFIED",
            "evidence": f"POST {url} returned GraphQL __schema introspection: {out[:200]}",
            "repro_cmd": cmd,
        }
    return None


def _split_http_body(raw: str) -> tuple[str, str]:
    """Split a `curl -i` or `curl -I` response into `(headers, body)`."""
    if not raw:
        return "", ""
    for sep in ("\r\n\r\n", "\n\n"):
        if sep in raw:
            hdrs, body = raw.split(sep, 1)
            if body.strip():
                return hdrs, body.strip()
    return raw, ""


def validate_bola_response_content(raw_resp: str, admin_resp: str = "") -> tuple[bool, str]:
    """Verify that an HTTP 200 response on a sensitive API route contains actual
    structured API content rather than an HTML login shell or an empty JSON stub."""
    hdrs, body = _split_http_body(raw_resp)
    hdr_lower = hdrs.lower()
    if "content-type: text/html" in hdr_lower:
        return False, "HTML content-type (likely SPA shell or login redirect)"
    if not body:
        # No body to inspect (login shells were already rejected by the HTML
        # content-type check above). Only treat an empty 200 as confirmable when
        # the server explicitly declared an API content-type — a declared-auth
        # route answering 200/JSON to the wrong principal is still a real authz
        # gap. An empty 200 with no API content-type is NOT confirmed.
        if re.search(r"content-type:\s*application/(json|xml|.*\+json)", hdr_lower):
            return True, "HTTP 200 with API content-type (empty body; data not dumped)"
        return False, "HTTP 200 but empty body and no API content-type (unconfirmed)"

    body_lower = body.lower()
    if body_lower.startswith(("<!doctype html", "<html")) or "<form" in body_lower:
        return False, "HTML login/shell body rather than structured API data"

    if body.startswith(("{", "[")):
        try:
            parsed = json.loads(body)
            if parsed in ({}, []):
                return False, "empty JSON body"
            if isinstance(parsed, dict):
                # Reject trivial status-only or empty-list wrappers
                non_empty_vals = [
                    v for k, v in parsed.items()
                    if k not in ("ok", "status", "success", "code", "message", "error")
                    and v not in (None, "", [], {})
                ]
                if not non_empty_vals and any(k in parsed for k in ("data", "items", "results", "error", "ok")):
                    return False, "JSON wrapper contains no non-empty records"
                if admin_resp:
                    _, adm_body = _split_http_body(admin_resp)
                    if adm_body.startswith("{"):
                        try:
                            adm_json = json.loads(adm_body)
                            if isinstance(adm_json, dict) and set(parsed.keys()) & set(adm_json.keys()):
                                return True, f"JSON schema overlap ({len(parsed)} keys match privileged baseline)"
                        except Exception:
                            pass
            return True, f"non-empty JSON payload ({len(body)} bytes)"
        except Exception:
            pass
    return True, f"API payload ({len(body)} bytes)"


_ID_LIKE_FIELDS = {
    "id", "ref", "key", "slug", "name", "title", "username", "user",
    "email", "uuid", "guid", "number", "no", "code", "handle",
}


def _tokens(s: str) -> set[str]:
    """Lowercase alphanumeric tokens of an identifier, e.g. 'book_title' ->
    {'book', 'title'}."""
    return {t for t in re.split(r"[^A-Za-z0-9]+", str(s).lower()) if t}


def _collection_path(route: str) -> str:
    """Sibling collection path for a trailing-parameter object route, e.g.
    '/users/v1/{username}' -> '/users/v1'. Returns '' when the route has no
    trailing '/{param}' segment."""
    m = re.match(r"^(?P<coll>/.*?)/\{[^/{}]+\}/*$", route)
    if not m:
        return ""
    return m.group("coll") or "/"


def _param_name(route: str) -> str:
    """Name of the trailing path parameter, e.g. '/users/v1/{username}' ->
    'username'. '' when there is no trailing parameter."""
    m = re.search(r"\{([^/{}]+)\}/*$", route)
    return m.group(1) if m else ""


def _route_with_id(route: str, value: str) -> str:
    """Substitute the trailing '{param}' of a route with a concrete, URL-encoded
    identifier value."""
    from urllib.parse import quote
    return re.sub(r"\{[^/{}]+\}/*$", quote(str(value), safe=""), route)


def _is_scalar_id(v) -> bool:
    """True for a value usable as a path-parameter identifier (a non-bool
    number or a short, non-empty string)."""
    if isinstance(v, bool) or v is None:
        return False
    if isinstance(v, int):
        return True
    if isinstance(v, float):
        return True
    if isinstance(v, str):
        return 0 < len(v) <= 128
    return False


def _field_rank(key: str, param: str) -> int:
    """How well a record field name matches the wanted path parameter:
    3 = exact, 2 = shares a token, 1 = generic id-like, 0 = unrelated."""
    k = str(key).lower()
    p = str(param).lower()
    if k == p:
        return 3
    if _tokens(k) & _tokens(p):
        return 2
    last = re.split(r"[^A-Za-z0-9]+", k)[-1] if k else ""
    if k in _ID_LIKE_FIELDS or last in _ID_LIKE_FIELDS:
        return 1
    return 0


def _mine_candidate_ids(raw_resp: str, param: str, *, limit: int = 5) -> list[str]:
    """Mine up to `limit` candidate path-parameter values from a collection
    endpoint's JSON response.

    Prefers the value of the record field that best matches `param` (e.g.
    'username', 'book_title', 'id'); falls back to any id-like scalar field, or
    to the keys of an id-keyed object map, or to a list of bare scalars.
    Defensive against non-JSON, oversized, or oddly shaped bodies.
    """
    _, body = _split_http_body(raw_resp)
    body = (body or "").strip()
    if not body or len(body) > 200_000 or body[0] not in "[{":
        return []
    try:
        data = json.loads(body)
    except Exception:
        return []

    records: list = []
    if isinstance(data, list):
        records = data[:50]
    elif isinstance(data, dict):
        inner = next((v for v in data.values() if isinstance(v, list)), None)
        if inner is not None:
            # A wrapper like {"users": [...]} or {"data": [...]}.
            records = inner[:50]
        elif data and all(isinstance(v, dict) for v in list(data.values())[:5]):
            # An id-keyed object map: the keys themselves are the identifiers.
            return [str(k) for k in list(data.keys())[:limit] if _is_scalar_id(k)]
        else:
            records = [data]

    # Pick the single best-matching field name across the sampled records.
    best_field = None
    best_rank = 0
    for rec in records[:10]:
        if not isinstance(rec, dict):
            continue
        for k, v in rec.items():
            if not _is_scalar_id(v):
                continue
            rank = _field_rank(k, param)
            if rank > best_rank:
                best_field, best_rank = k, rank

    cands: list[str] = []
    for rec in records:
        if len(cands) >= limit:
            break
        val = None
        if isinstance(rec, dict):
            if best_field is not None and best_field in rec:
                val = rec.get(best_field)
        elif _is_scalar_id(rec):
            val = rec
        if _is_scalar_id(val):
            s = str(val)
            if s not in cands:
                cands.append(s)
    return cands


def _curl_get(header: str, url: str) -> list[str]:
    """Build a `curl -i` GET argv, optionally with one sanitized auth header."""
    if header:
        return ["curl", "-kisS", "--max-time", "4", "-H", header, url]
    return ["curl", "-kisS", "--max-time", "4", url]


def _status_code(out: str) -> int:
    """First HTTP status code in a `curl -i` response, or 0."""
    m = re.search(r"HTTP/[\d.]+\s+(\d{3})", out or "")
    return int(m.group(1)) if m else 0


def _resolve_concrete_path(base: str, ep: dict, fetch, *, clean_low: str,
                           clean_hdr: str) -> str:
    """Resolve a parameterised object route's placeholder to a REAL identifier so
    the access-control probes hit an existing object instead of a 404.

    Mines the sibling collection as the low-privilege identity first (so the
    low-priv probe reads an object it can legitimately see), then anonymously,
    then as admin. Falls back to the original placeholder path (literal '1') when
    nothing can be mined, so existing targets where '1' is valid keep working.
    Responses are cached, so identities that also mine for the cross-user check
    cost nothing extra.
    """
    route = ep["path"]
    coll = _collection_path(route)
    param = _param_name(route)
    if not coll or not param:
        return ep["concrete_path"]
    headers = [clean_low, "", clean_hdr] if clean_low else ["", clean_hdr]
    seen: set[str] = set()
    for hdr in headers:
        if hdr in seen:
            continue
        seen.add(hdr)
        ids = _mine_candidate_ids(fetch(hdr, f"{base}{coll}"), param)
        if ids:
            return _route_with_id(route, ids[0])
    return ep["concrete_path"]


def _cross_user_bola_finding(base: str, ep: dict, u: str, low_out: str, port: int,
                             fetch, *, clean_low: str, clean_peer: str) -> dict | None:
    """Horizontal cross-user BOLA: can the LOW-privilege identity (A) read an
    object OWNED BY the PEER identity (B)?

    Strategy, in order of confidence:
      1. Mine the sibling collection as A and as B. If B exposes an identifier A
         does NOT (distinct ownership established), have A request that
         peer-owned object. A 200 with real content is a VERIFIED cross-user
         BOLA, replayed AS the low-priv identity with the peer-owned id baked in.
      2. Collection mined but no peer-exclusive id (A and B see the same items):
         ownership cannot be proven, so a peer-readable object is reported only
         as UNCONFIRMED, never a false VERIFIED.
      3. No sibling collection to mine: fall back to the original check — the
         peer identity (B) replays A's object path; a 200 is reported VERIFIED
         (replayed AS the peer identity). Preserves existing detections.
    """
    coll = _collection_path(ep["path"])
    param = _param_name(ep["path"])
    a_ids: list[str] = []
    b_ids: list[str] = []
    if coll and param:
        a_ids = _mine_candidate_ids(fetch(clean_low, f"{base}{coll}"), param)
        b_ids = _mine_candidate_ids(fetch(clean_peer, f"{base}{coll}"), param)

    peer_owned = next((i for i in b_ids if i not in set(a_ids)), None) if b_ids else None

    if peer_owned is not None:
        u2 = f"{base}{_route_with_id(ep['path'], peer_owned)}"
        a_out = fetch(clean_low, u2)
        if _status_code(a_out) != 200:
            return None  # secure: the low-priv identity cannot read the peer object
        valid, reason = validate_bola_response_content(a_out, low_out)
        if not valid:
            return {
                "port": port,
                "title": f"Cross-user horizontal BOLA on {ep['path']} (low-priv read peer object)",
                "severity": "MEDIUM",
                "status": "UNCONFIRMED",
                "evidence": (f"GET {u2} as the low-privilege identity returned HTTP 200 for peer-owned "
                             f"object {peer_owned!r} but {reason}"),
                "repro_cmd": ["curl", "-kisS", "--max-time", "5", "-H", clean_low, u2],
            }
        return {
            "port": port,
            "title": f"Cross-user horizontal BOLA on {ep['path']} (low-priv read peer object)",
            "severity": "HIGH",
            "status": "VERIFIED",
            "evidence": (f"GET {u2} as the low-privilege identity returned HTTP 200 reading peer-owned "
                         f"object {peer_owned!r} ({reason})"),
            # Replay AS the low-priv identity with the peer-owned id baked in, so
            # a retest that is now denied (403/404) reports FIXED. Masked on display.
            "repro_cmd": ["curl", "-kisS", "--max-time", "5", "-H", clean_low, u2],
        }

    if coll and param and (a_ids or b_ids):
        # Collection mined but no peer-exclusive identifier: distinct object
        # ownership could not be established. Confirm a peer can at least read the
        # object and report UNCONFIRMED rather than risk a self-read false VERIFIED.
        peer_out = fetch(clean_peer, u)
        if _status_code(peer_out) == 200 and validate_bola_response_content(peer_out, low_out)[0]:
            return {
                "port": port,
                "title": f"Cross-user horizontal BOLA on {ep['path']} (shared object read)",
                "severity": "MEDIUM",
                "status": "UNCONFIRMED",
                "evidence": (f"GET {u} returned HTTP 200 to both the low-priv and peer identities but "
                             "distinct object ownership could not be established from the collection"),
                "repro_cmd": ["curl", "-kisS", "--max-time", "5", "-H", clean_peer, u],
            }
        return None

    # No sibling collection to mine: original peer-reads-A check.
    peer_out = fetch(clean_peer, u)
    if _status_code(peer_out) == 200:
        valid, reason = validate_bola_response_content(peer_out, low_out)
        if valid:
            return {
                "port": port,
                "title": f"Cross-user horizontal BOLA on {ep['path']} (peer read low-priv object)",
                "severity": "HIGH",
                "status": "VERIFIED",
                "evidence": (f"GET {u} with the peer identity returned HTTP 200 matching the low-priv "
                             f"object ({reason})"),
                # Replay AS the peer identity (masked on display).
                "repro_cmd": ["curl", "-kisS", "--max-time", "5", "-H", clean_peer, u],
            }
    return None


def probe_openapi(
    ip: str,
    port: int,
    scheme: str,
    run_fn,
    *,
    auth_header: str = "",
    low_priv_header: str = "",
    peer_auth_header: str = "",
    ctl=None,
    sessions: dict | None = None,
) -> dict:
    """Discover OpenAPI/Swagger specs on a target web service and run an
    unauthenticated vs. low-privilege (User A) vs. peer user (User B) vs. admin
    access-control differential check.

    ``sessions`` is an optional ``{role: TargetSession}`` map (roles
    ``primary``/``low_priv``/``peer``). When supplied, each role's CURRENT header
    comes from its session, and any authenticated request that comes back 401/403
    triggers a one-shot re-login + retry for that role (so a short-lived token
    that expired mid-scan no longer collapses the differential). Omitting it keeps
    the exact previous behaviour for existing callers and tests.
    """
    base = f"{scheme}://{ip}:{port}"
    sessions = sessions or {}
    primary_sess = sessions.get("primary")
    low_sess = sessions.get("low_priv")
    peer_sess = sessions.get("peer")
    clean_hdr = primary_sess.header() if primary_sess else (sanitize_auth_header(auth_header) if auth_header else "")
    clean_low = low_sess.header() if low_sess else (sanitize_auth_header(low_priv_header) if low_priv_header else "")
    clean_peer = peer_sess.header() if peer_sess else (sanitize_auth_header(peer_auth_header) if peer_auth_header else "")
    spec_data = None
    spec_url = ""
    spec_cmd: list[str] = []

    for path in OPENAPI_PATHS:
        if ctl is not None and not ctl.checkpoint():
            break
        url = f"{base}{path}"
        cmd = ["curl", "-ksS", "--max-time", "5", url]
        if clean_hdr:
            cmd = ["curl", "-ksS", "--max-time", "5", "-H", clean_hdr, url]
        out = (run_fn(cmd, 8) or "").strip()
        if out.startswith("{") and ('"paths"' in out or '"openapi"' in out or '"swagger"' in out):
            try:
                spec_data = json.loads(out)
                spec_url = url
                spec_cmd = cmd
                break
            except Exception:
                continue

    if not spec_data:
        return {"found": False, "spec_url": "", "endpoints": [], "findings": [], "raw_section": ""}

    endpoints = extract_openapi_endpoints(spec_data)
    findings: list[dict] = []
    lines = [f"=== Grey-Box API Audit: OpenAPI Spec ({spec_url}) ===",
             f"Discovered {len(endpoints)} API route(s)."]

    # Cache GET responses by (header, url) so collection mining for object-id
    # resolution does not re-issue identical requests.
    _fetch_cache: dict[tuple[str, str], str] = {}

    def _raw_fetch(header: str, url: str) -> str:
        key = (header, url)
        if key not in _fetch_cache:
            _fetch_cache[key] = run_fn(_curl_get(header, url), 6) or ""
        return _fetch_cache[key]

    # Map every header a refreshable role has ever held -> its session, so a
    # single choke point (fetch) can re-mint a role's token on 401/403 and retry.
    # Entries are never removed, so a stale header still finds its session and is
    # transparently replaced by the session's current one (no repeated logins).
    _sessions_by_header: dict[str, object] = {}
    for _s in (primary_sess, low_sess, peer_sess):
        if _s is not None and getattr(_s, "can_refresh", False) and _s.header():
            _sessions_by_header[_s.header()] = _s

    def fetch(header: str, url: str) -> str:
        sess = _sessions_by_header.get(header)
        # If this role already refreshed to a newer header, use it transparently.
        if sess is not None and sess.header() and sess.header() != header:
            header = sess.header()
        out = _raw_fetch(header, url)
        if sess is not None and _status_code(out) in (401, 403):
            new_header = sess.refresh(run_fn)
            if new_header and new_header != header:
                _sessions_by_header[new_header] = sess
                out = _raw_fetch(new_header, url)
        return out

    def _cur(role_sess, fallback: str) -> str:
        """Current header for a role (fresh after any refresh), for repro argv."""
        return role_sess.header() if role_sess is not None else fallback

    # Probe up to 12 GET endpoints unauthenticated, low-privilege, and admin-authenticated.
    get_eps = [e for e in endpoints if "GET" in e["methods"]][:12]
    for ep in get_eps:
        if ctl is not None and not ctl.checkpoint():
            break
        # For a parameterised object route, resolve {param} to a real identifier
        # mined from the sibling collection (falls back to the literal '1').
        concrete = ep["concrete_path"]
        if "{" in ep["path"]:
            concrete = _resolve_concrete_path(base, ep, fetch, clean_low=clean_low, clean_hdr=clean_hdr)
        u = f"{base}{concrete}"
        unauth_out = fetch("", u)
        un_code = _status_code(unauth_out)

        low_out = ""
        low_code = 0
        if clean_low:
            low_out = fetch(clean_low, u)
            low_code = _status_code(low_out)

        auth_out = ""
        auth_code = 0
        if clean_hdr:
            auth_out = fetch(clean_hdr, u)
            auth_code = _status_code(auth_out)

        cross_user = None
        if clean_low and clean_peer and "{" in ep["path"] and low_code == 200:
            cross_user = _cross_user_bola_finding(
                base, ep, u, low_out, port, fetch,
                clean_low=_cur(low_sess, clean_low), clean_peer=_cur(peer_sess, clean_peer),
            )

        sensitive_route = bool(re.search(r"admin|user|config|secret|token|internal|debug|export|key|role|tenant|billing", ep["path"], re.I))
        if un_code == 200 and (ep["auth_declared"] or sensitive_route):
            valid_body, body_reason = validate_bola_response_content(unauth_out, auth_out)
            if not valid_body:
                lines.append(f"- [FALSE-POSITIVE-FILTERED] {ep['path']}: HTTP 200 ignored ({body_reason})")
                continue
            sev = "HIGH" if sensitive_route else "MEDIUM"
            title = f"Unauthenticated API access on {ep['path']} (HTTP 200)"
            ev = f"GET {u} returned HTTP 200 without credentials (auth_declared={ep['auth_declared']}, {body_reason})"
            findings.append({
                "port": port,
                "title": title,
                "severity": sev,
                "status": "VERIFIED",
                "evidence": ev,
                "repro_cmd": ["curl", "-kisS", "--max-time", "5", u],
            })
            lines.append(f"- [VULNERABLE/{sev}] {ep['path']}: HTTP 200 unauthenticated ({body_reason})")
        elif clean_low and low_code == 200 and un_code in (401, 403) and sensitive_route and cross_user is None:
            # The STATUS DIFFERENTIAL itself (anon 401/403 -> low-priv 200 on a
            # sensitive route) is the authz-boundary signal, so it is reported
            # regardless of body. Body content only upgrades confidence: with
            # confirmed data it is VERIFIED/HIGH; without, it is a PROBABLE
            # finding (status UNCONFIRMED) flagged for manual confirmation.
            valid_body, body_reason = validate_bola_response_content(low_out, auth_out)
            status = "VERIFIED" if valid_body else "UNCONFIRMED"
            confidence = "data confirmed" if valid_body else f"data exposure unconfirmed — {body_reason}"
            owner_unknown = "{" in ep["path"]
            title = (f"Unconfirmed object access on {ep['path']} (ownership not established)"
                     if owner_unknown else
                     f"BOLA/BFLA privilege boundary bypass on {ep['path']} (low-priv HTTP 200)")
            if owner_unknown:
                status = "UNCONFIRMED"
                confidence = f"object ownership could not be established — {body_reason}"
            ev = (f"GET {u} blocked unauthenticated ({un_code}) but returned HTTP 200 to "
                  f"low-privilege role on sensitive route ({confidence})")
            findings.append({
                "port": port,
                "title": title,
                "severity": "MEDIUM" if owner_unknown else "HIGH" if valid_body else "MEDIUM",
                "status": status,
                "evidence": ev,
                # Replay AS the low-privilege identity; an anonymous replay would
                # get 401 and look fixed. Masked whenever it is displayed. Uses the
                # role's CURRENT (possibly just-refreshed) header, not a dead token.
                "repro_cmd": ["curl", "-kisS", "--max-time", "5", "-H", _cur(low_sess, clean_low), u],
            })
            tag = "VULNERABLE/HIGH" if valid_body else "PROBABLE/MEDIUM"
            lines.append(f"- [{tag} BOLA/BFLA] {ep['path']}: unauth={un_code}, low_priv={low_code}, admin={auth_code or 200} ({confidence})")
        elif clean_hdr and un_code in (401, 403) and auth_code == 200:
            lines.append(f"- [AUTH-ENFORCED] {ep['path']}: unauth={un_code} -> auth={auth_code}")
        elif un_code:
            lines.append(f"- {ep['path']}: HTTP {un_code}")

        # Horizontal Cross-User BOLA check (low-priv A vs. peer B on a
        # parameterised object route, using a real mined object id).
        if cross_user is not None:
            findings.append(cross_user)
            tag = "VULNERABLE/HIGH" if cross_user["status"] == "VERIFIED" else "PROBABLE/MEDIUM"
            lines.append(f"- [{tag} HORIZONTAL-BOLA] {ep['path']}: {cross_user['status']} "
                         f"({cross_user['title'].rsplit('(', 1)[-1].rstrip(')')})")

    for bopla in extract_bopla_mass_assignment_risks(spec_data):
        fields_str = ", ".join(bopla["writable_privilege_fields"])
        findings.append({
            "port": port,
            "title": f"BOPLA / Mass Assignment risk on {bopla['method']} {bopla['path']} ({fields_str})",
            "severity": "MEDIUM",
            "status": "UNCONFIRMED",
            "evidence": f"OpenAPI schema exposes writable privilege properties ({fields_str}) without readOnly protection",
            # Schema-only finding: the replay re-fetches the spec so a retest can
            # re-evaluate the schema instead of reading a GET status code.
            "repro_cmd": list(spec_cmd),
        })
        lines.append(f"- [BOPLA/MASS-ASSIGNMENT] {bopla['method']} {bopla['path']}: writable [{fields_str}]")

    return {
        "found": True,
        "spec_url": spec_url,
        "endpoints": endpoints,
        "findings": findings,
        "raw_section": "\n".join(lines),
    }


_JS_SCRIPT_RE = re.compile(r"""<script[^>]+src=['"]([^'"]+\.js(?:\?[^'"]*)?)['"]""", re.I)
_JS_API_ROUTE_RE = re.compile(
    r"""['"](/(?:api|v1|v2|v3|graphql|admin|internal|auth|oauth|users|tenants)(?:/[A-Za-z0-9_\-{}:.]+)*)['"]"""
)


def discover_js_endpoints(
    ip: str,
    port: int,
    scheme: str,
    run_fn,
    *,
    ctl=None,
) -> dict:
    """Extract client-side SPA/JS bundle URLs and hidden API routes referenced
    inside JavaScript bundles."""
    base = f"{scheme}://{ip}:{port}"
    html = (run_fn(["curl", "-ksSL", "--max-time", "6", base], 8) or "")[:120000]
    if not html:
        return {"scripts": [], "routes": [], "raw_section": ""}

    scripts: list[str] = []
    routes: list[str] = []

    for m in _JS_API_ROUTE_RE.finditer(html):
        r = m.group(1)
        if r not in routes:
            routes.append(r)

    for m in _JS_SCRIPT_RE.finditer(html):
        src = m.group(1).strip()
        if src.startswith("//"):
            continue
        if src.startswith("http://") or src.startswith("https://"):
            if f"{ip}:{port}" not in src and ip not in src:
                continue
            full_url = src
        elif src.startswith("/"):
            full_url = f"{base}{src}"
        else:
            full_url = f"{base}/{src}"
        if full_url not in scripts:
            scripts.append(full_url)

    for js_url in scripts[:4]:
        if ctl is not None and not ctl.checkpoint():
            break
        js_body = (run_fn(["curl", "-ksS", "--max-time", "5", js_url], 7) or "")[:150000]
        for m in _JS_API_ROUTE_RE.finditer(js_body):
            r = m.group(1)
            if r not in routes:
                routes.append(r)

    routes = routes[:40]
    raw_section = ""
    if routes:
        raw_section = (
            f"=== SPA / JS Bundle Route Inventory ({base}) ===\n"
            f"Scanned {len(scripts[:4])} JS bundle(s); discovered {len(routes)} client-side API route(s):\n"
            + "\n".join(f"- {r}" for r in routes[:20])
        )
    return {"scripts": scripts[:10], "routes": routes, "raw_section": raw_section}


# ───────────────────────── White-Box Source Analyzer ─────────────────────────
_ROUTE_PATS: list[tuple[str, re.Pattern[str]]] = [
    ("flask", re.compile(r"""@(?:app|bp|blueprint)\.route\(\s*['"]([^'"]+)['"]""")),
    ("fastapi", re.compile(r"""@(?:app|router)\.(?:get|post|put|delete|patch)\(\s*['"]([^'"]+)['"]""")),
    ("express", re.compile(r"""\b(?:app|router)\.(?:get|post|put|delete|use)\(\s*['"]([^'"]+)['"]""")),
]

_DANGEROUS_SINKS: list[tuple[str, str, re.Pattern[str]]] = [
    ("Command Execution (subprocess shell=True / os.system)", "HIGH",
     re.compile(r"""(?:subprocess\.(?:Popen|run|call)\([^)]*shell\s*=\s*True|os\.system\s*\()""")),
    ("Unsafe Code Evaluation (eval / exec)", "HIGH",
     re.compile(r"""\b(?:eval|exec)\s*\(""")),
    ("Unsafe Deserialization (pickle.loads / yaml.load)", "HIGH",
     re.compile(r"""(?:pickle\.loads\s*\(|yaml\.load\s*\([^)]*(?!Loader\s*=\s*yaml\.SafeLoader))""")),
    ("Raw SQL String Formatting", "MEDIUM",
     re.compile(r"""\.execute\s*\(\s*f['"](?:SELECT|INSERT|UPDATE|DELETE)\b""", re.I)),
    ("Hardcoded Secret / API Key", "HIGH",
     re.compile(r"""(?i)\b(?:api[_-]?key|secret[_-]?key|password)\s*=\s*['"][A-Za-z0-9_\-]{12,}['"]""")),
]


def parse_external_sast_json(semgrep_json: str = "", gitleaks_json: str = "") -> list[dict]:
    """Normalize JSON output from Semgrep (`--json`) or Gitleaks (`--report-format json`)
    into OniOps white-box sink records with automatic secret redaction."""
    findings: list[dict] = []
    if semgrep_json and semgrep_json.strip().startswith("{"):
        try:
            data = json.loads(semgrep_json)
            for r in (data.get("results") or [])[:25]:
                extra = r.get("extra") or {}
                sev_raw = str(extra.get("severity") or "MEDIUM").upper()
                sev = "HIGH" if sev_raw in ("ERROR", "HIGH", "CRITICAL") else ("MEDIUM" if sev_raw == "WARNING" else "LOW")
                findings.append({
                    "file": str(r.get("path") or "repo"),
                    "line": int((r.get("start") or {}).get("line") or 1),
                    "type": f"Semgrep [{r.get('check_id', 'rule')}]",
                    "severity": sev,
                    "snippet": redact_secrets(str(extra.get("lines") or extra.get("message") or "").strip())[:160],
                })
        except Exception:
            pass

    if gitleaks_json and gitleaks_json.strip().startswith("["):
        try:
            items = json.loads(gitleaks_json)
            for item in (items if isinstance(items, list) else [])[:25]:
                findings.append({
                    "file": str(item.get("File") or "repo"),
                    "line": int(item.get("StartLine") or 1),
                    "type": f"Gitleaks [{item.get('RuleID', 'secret')}]",
                    "severity": "HIGH",
                    "snippet": redact_secrets(str(item.get("Match") or item.get("Description") or "").strip())[:160],
                })
        except Exception:
            pass
    return findings


def analyze_source_code(source_text_or_path: str, *, run_external: bool = True) -> dict:
    """Extract web routes, dangerous sinks, and hardcoded secret patterns from
    a code snippet or a local repository directory (plus optional Semgrep/Gitleaks
    adapter when scanning a path on disk)."""
    files_content: list[tuple[str, str]] = []
    candidate = Path(source_text_or_path.strip()) if len(source_text_or_path.strip()) < 260 else None
    is_disk_path = bool(candidate and candidate.exists())
    if is_disk_path and candidate is not None:
        if candidate.is_file():
            try:
                files_content.append((candidate.name, candidate.read_text(errors="replace")[:80000]))
            except Exception:
                pass
        elif candidate.is_dir():
            for ext in ("*.py", "*.js", "*.ts", "*.go", "*.yaml", "*.yml"):
                for fp in sorted(candidate.rglob(ext))[:40]:
                    if any(part.startswith(".") or part in ("node_modules", "venv", ".venv", ".venv-test") for part in fp.parts):
                        continue
                    try:
                        files_content.append((str(fp.relative_to(candidate)), fp.read_text(errors="replace")[:50000]))
                    except Exception:
                        continue
    if not files_content:
        files_content.append(("snippet", source_text_or_path[:80000]))

    routes: list[str] = []
    sinks: list[dict] = []
    for fname, text in files_content:
        for _fw, rpat in _ROUTE_PATS:
            for m in rpat.finditer(text):
                r = m.group(1)
                if r not in routes:
                    routes.append(r)
        for lineno, line in enumerate(text.splitlines(), start=1):
            for label, sev, spat in _DANGEROUS_SINKS:
                if spat.search(line):
                    sinks.append({
                        "file": fname,
                        "line": lineno,
                        "type": label,
                        "severity": sev,
                        "snippet": redact_secrets(line.strip())[:160],
                    })

    if run_external and is_disk_path and candidate is not None and shutil.which("gitleaks"):
        try:
            proc = subprocess.run(
                ["gitleaks", "detect", "--source", str(candidate), "--no-git", "-f", "json", "-r", "-"],
                capture_output=True, text=True, timeout=15, check=False,
            )
            sinks.extend(parse_external_sast_json(gitleaks_json=proc.stdout))
        except Exception:
            pass

    return {
        "files_scanned": len(files_content),
        "routes": routes[:50],
        "sinks": sinks[:40],
    }

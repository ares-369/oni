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
    """Inspect OpenAPI POST/PUT/PATCH schemas for writable privilege properties
    (OWASP API3:2023 BOPLA / Mass Assignment)."""
    if not isinstance(spec, dict):
        return []
    paths = spec.get("paths") or {}
    components = ((spec.get("components") or {}).get("schemas") or {}) if isinstance(spec.get("components"), dict) else {}
    risks: list[dict] = []
    for route, item in paths.items():
        if not isinstance(item, dict):
            continue
        for method in ("post", "put", "patch"):
            op = item.get(method)
            if not isinstance(op, dict):
                continue
            rb = op.get("requestBody") or {}
            content = (rb.get("content") or {}).get("application/json") or {}
            schema = content.get("schema") or {}
            if "$ref" in schema:
                ref_name = str(schema["$ref"]).rsplit("/", 1)[-1]
                schema = components.get(ref_name) or {}
            props = schema.get("properties") or {}
            exposed = [
                k for k, v in props.items()
                if k.lower() in _PRIVILEGE_PROPS and not (isinstance(v, dict) and v.get("readOnly"))
            ]
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
) -> dict:
    """Discover OpenAPI/Swagger specs on a target web service and run an
    unauthenticated vs. low-privilege (User A) vs. peer user (User B) vs. admin
    access-control differential check."""
    base = f"{scheme}://{ip}:{port}"
    clean_hdr = sanitize_auth_header(auth_header) if auth_header else ""
    clean_low = sanitize_auth_header(low_priv_header) if low_priv_header else ""
    clean_peer = sanitize_auth_header(peer_auth_header) if peer_auth_header else ""
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

    # Probe up to 8 GET endpoints unauthenticated, low-privilege, and admin-authenticated.
    get_eps = [e for e in endpoints if "GET" in e["methods"]][:8]
    for ep in get_eps:
        if ctl is not None and not ctl.checkpoint():
            break
        u = f"{base}{ep['concrete_path']}"
        unauth_out = run_fn(["curl", "-kisS", "--max-time", "4", u], 6) or ""
        m_un = re.search(r"HTTP/[\d.]+\s+(\d{3})", unauth_out)
        un_code = int(m_un.group(1)) if m_un else 0

        low_out = ""
        low_code = 0
        if clean_low:
            low_out = run_fn(["curl", "-kisS", "--max-time", "4", "-H", clean_low, u], 6) or ""
            m_lo = re.search(r"HTTP/[\d.]+\s+(\d{3})", low_out)
            low_code = int(m_lo.group(1)) if m_lo else 0

        auth_out = ""
        auth_code = 0
        if clean_hdr:
            auth_out = run_fn(["curl", "-kisS", "--max-time", "4", "-H", clean_hdr, u], 6) or ""
            m_au = re.search(r"HTTP/[\d.]+\s+(\d{3})", auth_out)
            auth_code = int(m_au.group(1)) if m_au else 0

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
        elif clean_low and low_code == 200 and un_code in (401, 403) and sensitive_route:
            # The STATUS DIFFERENTIAL itself (anon 401/403 -> low-priv 200 on a
            # sensitive route) is the authz-boundary signal, so it is reported
            # regardless of body. Body content only upgrades confidence: with
            # confirmed data it is VERIFIED/HIGH; without, it is a PROBABLE
            # finding (status UNCONFIRMED) flagged for manual confirmation.
            valid_body, body_reason = validate_bola_response_content(low_out, auth_out)
            status = "VERIFIED" if valid_body else "UNCONFIRMED"
            confidence = "data confirmed" if valid_body else f"data exposure unconfirmed — {body_reason}"
            title = f"BOLA/BFLA privilege boundary bypass on {ep['path']} (low-priv HTTP 200)"
            ev = (f"GET {u} blocked unauthenticated ({un_code}) but returned HTTP 200 to "
                  f"low-privilege role on sensitive route ({confidence})")
            findings.append({
                "port": port,
                "title": title,
                "severity": "HIGH" if valid_body else "MEDIUM",
                "status": status,
                "evidence": ev,
                # Replay AS the low-privilege identity; an anonymous replay would
                # get 401 and look fixed. Masked whenever it is displayed.
                "repro_cmd": ["curl", "-kisS", "--max-time", "5", "-H", clean_low, u],
            })
            tag = "VULNERABLE/HIGH" if valid_body else "PROBABLE/MEDIUM"
            lines.append(f"- [{tag} BOLA/BFLA] {ep['path']}: unauth={un_code}, low_priv={low_code}, admin={auth_code or 200} ({confidence})")
        elif clean_hdr and un_code in (401, 403) and auth_code == 200:
            lines.append(f"- [AUTH-ENFORCED] {ep['path']}: unauth={un_code} -> auth={auth_code}")
        elif un_code:
            lines.append(f"- {ep['path']}: HTTP {un_code}")

        # Horizontal Cross-User BOLA check (User A vs. User B on parameterized object route)
        if clean_low and clean_peer and "{" in ep["path"] and low_code == 200:
            peer_out = run_fn(["curl", "-kisS", "--max-time", "4", "-H", clean_peer, u], 6) or ""
            m_pr = re.search(r"HTTP/[\d.]+\s+(\d{3})", peer_out)
            peer_code = int(m_pr.group(1)) if m_pr else 0
            if peer_code == 200:
                valid_peer, peer_reason = validate_bola_response_content(peer_out, low_out)
                if valid_peer:
                    findings.append({
                        "port": port,
                        "title": f"Cross-user horizontal BOLA on {ep['path']} (User B read User A object)",
                        "severity": "HIGH",
                        "status": "VERIFIED",
                        "evidence": (
                            f"GET {u} with peer identity returned HTTP 200 matching User A object "
                            f"({peer_reason})"
                        ),
                        # Replay AS the peer identity (masked on display).
                        "repro_cmd": ["curl", "-kisS", "--max-time", "5", "-H", clean_peer, u],
                    })
                    lines.append(f"- [VULNERABLE/HIGH HORIZONTAL-BOLA] {ep['path']}: peer_user=200 ({peer_reason})")

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

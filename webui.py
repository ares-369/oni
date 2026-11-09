"""
ONIOPS WebUI — Offensive Neural Intelligence.

Scope-locked offensive assessment platform. Drives a Kali toolchain over SSH,
reasons with any configured LLM provider, and generates AI red-team reports.
Red-team only: no SIEM / blue-team dependencies.

The app is served by waitress via ``python -m oniops``; this module exposes the
Flask ``app`` and the REST API the UI calls.
"""

from __future__ import annotations

import json
import logging
import re
import sqlite3
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

from flask import Flask, Response, jsonify, render_template, request, session

from oniops import __version__, cve, terms
from oniops.agent import run_agent
from oniops.aisec import CONVERTERS, load_yaml_probes, run_aisec
from oniops.auth import init_auth
from oniops.config import apply_updates, get_config, preview_updates
from oniops.findings import (
    FindingsLedger,
    build_assessment_manifest,
    connect_sqlite,
    diff_assessments,
    redact_secrets,
)
from oniops.graph import build_graph
from oniops.greybox import analyze_source_code, discover_js_endpoints, probe_openapi, sanitize_auth_header
from oniops.jobs import JobManager
from oniops.kali import KaliRunner
from oniops.pdf import markdown_to_pdf
from oniops.playbooks import load_playbooks, render_step_cmd
from oniops.providers import get_llm
from oniops.scope import Scope, ScopeViolation
from oniops.targets import discover as discover_hosts
from oniops.terms import TermsStore

cfg = get_config()
scope = Scope(cfg)
llm = get_llm()

# Attack hosts: ONIOPS can drive any SSH-reachable tooled Linux, not just Kali.
HOST_RUNNERS = {h.name: KaliRunner(h, scope, cfg) for h in cfg.hosts}
ACTIVE_HOST = cfg.kali.name


def active_runner() -> KaliRunner:
    return HOST_RUNNERS.get(ACTIVE_HOST) or next(iter(HOST_RUNNERS.values()))

app = Flask(__name__)
# ONIOPS typically runs behind a TLS-terminating reverse proxy; honor its
# X-Forwarded-* headers so generated URLs (e.g. the OIDC redirect_uri) use https.
from werkzeug.middleware.proxy_fix import ProxyFix

app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)
log = logging.getLogger("oniops.webui")
logging.basicConfig(level=logging.INFO, format="%(asctime)s [ONIOPS] %(message)s")

BASE_DIR = Path(__file__).parent
DATA_DIR = BASE_DIR / "data"
DATA_DIR.mkdir(parents=True, exist_ok=True)
DB_PATH = DATA_DIR / "oniops.sqlite"
ACTIVITY_LOG = DATA_DIR / "activity.jsonl"

# Runtime override for the reporter model (set via /api/model). Falls back to
# the configured role model.
RUNTIME_MODEL: str | None = None


# ═══════════════════════════════════════════════════════
# PERSISTENCE
# ═══════════════════════════════════════════════════════
def init_db():
    with connect_sqlite(DB_PATH) as conn:
        conn.execute("""
        CREATE TABLE IF NOT EXISTS assessments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            target_ip TEXT NOT NULL,
            target_name TEXT NOT NULL,
            profile TEXT NOT NULL,
            severity TEXT NOT NULL,
            open_ports TEXT NOT NULL,
            finding_count INTEGER DEFAULT 0,
            commands_run TEXT NOT NULL,
            raw_output TEXT NOT NULL,
            ai_report TEXT NOT NULL
        )""")
        conn.execute("""
        CREATE TABLE IF NOT EXISTS host_surface (
            target_ip TEXT PRIMARY KEY,
            target_name TEXT NOT NULL,
            last_scan TEXT NOT NULL,
            open_ports TEXT NOT NULL,
            services_json TEXT NOT NULL,
            risk_level TEXT NOT NULL
        )""")
        conn.execute("""
        CREATE TABLE IF NOT EXISTS targets (
            target_ip TEXT PRIMARY KEY,
            hostname TEXT NOT NULL,
            first_seen TEXT NOT NULL,
            last_seen TEXT NOT NULL
        )""")
        conn.commit()


init_db()
jobs = JobManager(DB_PATH)
ledger = FindingsLedger(DB_PATH)
PLAYBOOKS = load_playbooks()


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def emit_event(stage: str, status: str, title: str, detail: str = ""):
    ev = {"timestamp": now_iso(), "stage": stage, "status": status,
          "title": title, "detail": detail[:300]}
    try:
        with open(ACTIVITY_LOG, "a") as f:
            f.write(json.dumps(ev) + "\n")
        lines = ACTIVITY_LOG.read_text().splitlines()
        if len(lines) > 300:
            ACTIVITY_LOG.write_text("\n".join(lines[-200:]) + "\n")
    except Exception:
        pass


# ═══════════════════════════════════════════════════════
# LLM HELPERS (provider-agnostic)
# ═══════════════════════════════════════════════════════
def ai_chat(messages, role: str = "reporter", temperature: float = 0.2) -> str:
    bound = llm.for_role(role)
    model = RUNTIME_MODEL if (role == "reporter" and RUNTIME_MODEL) else bound.model
    res = bound.provider.chat(messages, model=model, temperature=temperature)
    if res.error:
        return f"AI inference warning ({res.model}): {res.error}"
    return res.text or "Assessment analysis completed."


def active_model_name() -> str:
    return RUNTIME_MODEL or llm.for_role("reporter").model


# ═══════════════════════════════════════════════════════
# NMAP PARSING
# ═══════════════════════════════════════════════════════
def parse_nmap_ports(nmap_out: str) -> list[dict]:
    ports = []
    for line in nmap_out.splitlines():
        m = re.match(r"^(\d+)/(tcp|udp)\s+open\s+(\S+)\s*(.*)$", line.strip())
        if m:
            ports.append({"port": int(m.group(1)), "proto": m.group(2),
                          "service": m.group(3), "banner": m.group(4).strip() or "open"})
    return ports


# ═══════════════════════════════════════════════════════
# AUTHENTICATION (optional HTTP Basic) & SECURITY HEADERS
# ═══════════════════════════════════════════════════════
ALLOWED_PROFILES = {"fast_recon", "deep_service", "web_tls_audit", "web_app_pt", "autonomous_ai"}

# Authentication: none | basic | local | oidc | proxy (configured in oniops.auth).
init_auth(app, cfg)

# ── Responsible-use terms (first-run acceptance, recorded per user) ────────
# Registered AFTER init_auth, so the auth check always runs first.
terms_store = TermsStore(DB_PATH)


def _current_user() -> str:
    """Who is making this request, in whatever auth mode ONIOPS runs."""
    mode = cfg.auth.mode
    if mode == "proxy":
        return request.headers.get(cfg.auth.proxy_header, "") or "anonymous"
    if mode == "basic":
        a = request.authorization
        return (a.username if a and a.username else "") or "basic-user"
    return str(session.get("user") or "local")


@app.before_request
def require_terms_acceptance():
    if not terms.is_gated(request.method, request.path):
        return None
    if terms_store.has_accepted(_current_user()):
        return None
    return jsonify({"error": "Please accept the responsible-use terms before running tests.",
                    "terms_required": True}), 403


@app.route("/api/terms")
def api_terms():
    user = _current_user()
    return jsonify({"version": terms.TERMS_VERSION, "user": user,
                    "accepted": terms_store.has_accepted(user),
                    "accepted_at": terms_store.accepted_at(user),
                    "summary": terms.SUMMARY, "disclaimer_url": terms.DISCLAIMER_URL})


@app.route("/api/terms/accept", methods=["POST"])
def api_terms_accept():
    data = request.get_json(silent=True) or {}
    if data.get("confirm") is not True or data.get("version") != terms.TERMS_VERSION:
        return jsonify({"error": "Explicit confirmation of the current terms version is required."}), 400
    user = _current_user()
    ts = terms_store.record(user, request.remote_addr or "", request.headers.get("User-Agent", ""))
    emit_event("TERMS", "ok", f"Responsible-use terms {terms.TERMS_VERSION} accepted by {user}")
    return jsonify({"ok": True, "user": user, "accepted_at": ts, "version": terms.TERMS_VERSION})


@app.after_request
def add_security_headers(resp):
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "SAMEORIGIN"
    resp.headers["Referrer-Policy"] = "no-referrer"
    resp.headers["Content-Security-Policy"] = (
        "default-src 'self'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
        "font-src 'self' https://fonts.gstatic.com; img-src 'self' data:; "
        "script-src 'self' 'unsafe-inline'; connect-src 'self'"
    )
    return resp


# ═══════════════════════════════════════════════════════
# ROUTES
# ═══════════════════════════════════════════════════════
@app.route("/")
def index():
    return render_template("index.html")


# ── Health cache ──────────────────────────────────────────────────────────
# Pinging the attack host over SSH (and an LLM that is down) can take the full
# connect timeout. Doing that inline made every page load wait ~6s whenever
# the attack host was off. Instead, health is checked in a background thread
# and the last result is served instantly; None means "still checking".
_HEALTH: dict = {"kali": None, "llm": None, "providers": {}, "models": None,
                 "ts": 0.0, "busy": False}
_HEALTH_LOCK = threading.Lock()
_HEALTH_TTL = 20  # seconds before a background re-check is triggered


def _refresh_health() -> None:
    try:
        kali_ok = False
        try:
            kali_ok = active_runner().ping()
        except Exception:
            pass
        try:
            providers = llm.health()
        except Exception:
            providers = {}
        try:
            models = llm.for_role("reporter").provider.available_models() or [active_model_name()]
        except Exception:
            models = [active_model_name()]
        with _HEALTH_LOCK:
            _HEALTH.update(kali=kali_ok, llm=any(providers.values()) if providers else False,
                           providers=providers, models=models, ts=time.time())
    finally:
        with _HEALTH_LOCK:
            _HEALTH["busy"] = False


def health_snapshot(force: bool = False) -> dict:
    """Return the latest health result immediately; refresh in the background
    when stale (or when forced, e.g. after switching attack host)."""
    with _HEALTH_LOCK:
        if force:
            _HEALTH.update(kali=None, llm=None)
        stale = force or (time.time() - _HEALTH["ts"] > _HEALTH_TTL)
        start = stale and not _HEALTH["busy"]
        if start:
            _HEALTH["busy"] = True
        snap = dict(_HEALTH)
    if start:
        threading.Thread(target=_refresh_health, daemon=True, name="oniops-health").start()
    return snap


@app.route("/api/status")
def api_status():
    h = health_snapshot()
    kali_ok = h["kali"]                      # True / False / None (checking)
    provider_health = h["providers"] or {}
    models = h["models"] or [active_model_name()]

    with sqlite3.connect(DB_PATH) as conn:
        total = conn.execute("SELECT count(*) FROM assessments").fetchone()[0]
        high = conn.execute(
            "SELECT count(*) FROM assessments WHERE severity IN ('CRITICAL','HIGH')"
        ).fetchone()[0]
        scanned = conn.execute("SELECT count(*) FROM host_surface").fetchone()[0]
        scope_hosts = conn.execute("SELECT count(*) FROM targets").fetchone()[0]

    latest = {"title": f"ONIOPS Red Team Engine · Ready · scope {', '.join(scope.cidrs)}",
              "status": "idle"}
    if ACTIVITY_LOG.exists():
        lines = [l for l in ACTIVITY_LOG.read_text().splitlines() if l.strip()]
        if lines:
            try:
                latest = json.loads(lines[-1])
            except Exception:
                pass

    return jsonify({
        "health": {"kali": kali_ok, "llm": h["llm"],
                   "providers": provider_health,
                   "host_name": getattr(active_runner().host, "label", "") or ACTIVE_HOST},
        "current_model": active_model_name(),
        "models": models,
        "scope": scope.cidrs,
        "mode": cfg.scope.mode,
        "kpis": {"scope_hosts": scope_hosts, "scanned_hosts": scanned,
                 "total_assessments": total, "high_findings": high},
        "latest_event": latest,
    })


@app.route("/api/model", methods=["POST"])
def api_set_model():
    global RUNTIME_MODEL
    data = request.get_json(silent=True) or {}
    m = (data.get("model") or "").strip()
    if m:
        RUNTIME_MODEL = m
        emit_event("CONFIG", "ok", f"Switched red-team LLM to {m}")
    return jsonify({"ok": True, "current_model": active_model_name()})


@app.route("/api/settings")
def api_settings():
    try:
        models = llm.for_role("reporter").provider.available_models() or [active_model_name()]
    except Exception:
        models = [active_model_name()]
    roles = {}
    for role in ("planner", "reporter", "reason"):
        rc = cfg.role_cfg(role)
        roles[role] = {"provider": rc.get("provider", "ollama"), "model": rc.get("model", "")}
    hosts = [{"name": h.name, "label": h.label or h.name, "host": h.host, "user": h.user,
              "active": h.name == ACTIVE_HOST} for h in cfg.hosts]
    return jsonify({
        "instance": cfg.instance_name,
        "version": __version__,
        "scope": {"cidrs": scope.cidrs, "mode": cfg.scope.mode,
                  "exclude": cfg.scope.exclude, "non_destructive": cfg.scope.non_destructive},
        "auth": {"mode": cfg.auth.mode},
        "hosts": hosts,
        "active_host": ACTIVE_HOST,
        "llm": {"roles": roles, "providers": list((cfg.llm.get("providers") or {}).keys()),
                "provider_health": llm.health(), "current_model": active_model_name(), "models": models},
        "integrations": {
            "misp": bool((cfg.integrations.get("misp") or {}).get("enabled")),
            "caldera": bool((cfg.integrations.get("caldera") or {}).get("enabled")),
            "nvd": bool((cfg.integrations.get("nvd") or {}).get("enabled")),
        },
    })


def _reload_config():
    global cfg, scope, HOST_RUNNERS, ACTIVE_HOST, llm
    cfg = get_config(reload=True)
    scope = Scope(cfg)
    HOST_RUNNERS = {h.name: KaliRunner(h, scope, cfg) for h in cfg.hosts}
    ACTIVE_HOST = cfg.kali.name
    llm = get_llm(reload=True)
    health_snapshot(force=True)  # hosts/LLM may have changed: re-check now


@app.route("/api/config")
def api_get_config():
    """Editable configuration (no secrets)."""
    return jsonify({
        "instance_name": cfg.instance_name,
        "external_url": cfg.external_url,
        "scope": {"allowed_cidrs": cfg.scope.allowed_cidrs, "exclude": cfg.scope.exclude,
                  "mode": cfg.scope.mode, "non_destructive": cfg.scope.non_destructive,
                  "rate_limit_per_min": cfg.scope.rate_limit_per_min},
        "attack_hosts": [{"name": h.name, "label": h.label, "host": h.host, "user": h.user,
                          "ssh_key": h.ssh_key, "default": h.name == cfg.kali.name} for h in cfg.hosts],
        "llm": {"roles": {r: cfg.role_cfg(r) for r in ("planner", "reporter", "reason")},
                "providers": list((cfg.llm.get("providers") or {}).keys())},
        "integrations": {k: {"enabled": bool((cfg.integrations.get(k) or {}).get("enabled")),
                             "host": (cfg.integrations.get(k) or {}).get("host", "")}
                         for k in ("misp", "caldera")} | {
            "nvd": {"enabled": bool((cfg.integrations.get("nvd") or {}).get("enabled")),
                    "has_key": bool((cfg.integrations.get("nvd") or {}).get("api_key"))}},
    })


@app.route("/api/config/preview", methods=["POST"])
def api_preview_config():
    """Validate a proposed change and return a diff, WITHOUT saving — so the
    UI can show exactly what will change before it touches config.yaml."""
    updates = request.get_json(silent=True) or {}
    try:
        return jsonify(preview_updates(updates))
    except Exception as exc:
        return jsonify({"error": f"Rejected: {exc}"}), 400


@app.route("/api/config", methods=["POST"])
def api_save_config():
    updates = request.get_json(silent=True) or {}
    try:
        apply_updates(updates)
    except Exception as exc:
        return jsonify({"error": f"Rejected: {exc}"}), 400
    _reload_config()
    emit_event("CONFIG", "ok", "Configuration updated from the UI")
    return jsonify({"ok": True})


@app.route("/api/report/pdf", methods=["POST"])
def api_report_pdf():
    data = request.get_json(silent=True) or {}
    md = (data.get("markdown") or "").strip()
    if not md:
        return jsonify({"error": "Nothing to export."}), 400
    title = (data.get("title") or "ONIOPS Security Assessment Report").strip()[:120]
    filename = re.sub(r"[^a-zA-Z0-9._-]", "-", (data.get("filename") or "oniops-report.pdf"))
    if not filename.endswith(".pdf"):
        filename += ".pdf"
    pdf_bytes = markdown_to_pdf(md, title=title)
    return Response(
        pdf_bytes,
        mimetype="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@app.route("/api/host", methods=["POST"])
def api_set_host():
    global ACTIVE_HOST
    data = request.get_json(silent=True) or {}
    name = (data.get("name") or "").strip()
    if name not in HOST_RUNNERS:
        return jsonify({"error": f"Unknown attack host '{name}'."}), 400
    ACTIVE_HOST = name
    health_snapshot(force=True)
    emit_event("CONFIG", "ok", f"Switched active attack host to {name}")
    return jsonify({"ok": True, "active_host": ACTIVE_HOST})


@app.route("/api/host/test")
def api_test_host():
    name = (request.args.get("name") or ACTIVE_HOST).strip()
    r = HOST_RUNNERS.get(name)
    if not r:
        return jsonify({"error": "unknown host"}), 400
    res = r.run(["uname", "-a"], timeout=8)
    return jsonify({"name": name, "online": res.ok, "output": res.out[:200]})


MAX_SWEEP_HOSTS = 4096  # refuse a one-shot sweep larger than this without force


def _scope_host_count() -> int:
    import ipaddress as _ip
    total = 0
    for c in scope.cidrs:
        try:
            total += _ip.ip_network(c, strict=False).num_addresses
        except Exception:
            pass
    return total


def _discover_job(ctl):
    emit_event("DISCOVER", "busy", f"Sweeping {', '.join(scope.cidrs)} for live hosts")
    hosts = discover_hosts(active_runner(), scope)
    ts = now_iso()
    with sqlite3.connect(DB_PATH) as conn:
        for h in hosts:
            conn.execute("""INSERT INTO targets (target_ip, hostname, first_seen, last_seen)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(target_ip) DO UPDATE SET hostname=excluded.hostname, last_seen=excluded.last_seen""",
                (h.ip, h.hostname, ts, ts))
        conn.commit()
    emit_event("DISCOVER", "ok", f"Discovered {len(hosts)} live host(s)")
    return {"discovered": len(hosts)}


@app.route("/api/discover", methods=["POST"])
def api_discover():
    """Explicit, guarded host discovery as a background job (never automatic)."""
    data = request.get_json(silent=True) or {}
    n = _scope_host_count()
    if n > MAX_SWEEP_HOSTS and not data.get("force"):
        return jsonify({
            "error": (f"Scope spans {n} addresses (over {MAX_SWEEP_HOSTS}). A full sweep could be "
                      "slow and noisy on a large network. Narrow scope.allowed_cidrs, discover one "
                      "subnet at a time, or resend with force=true to proceed anyway."),
            "scope_size": n,
        }), 400
    job_id = jobs.submit("discover", {"scope": scope.cidrs, "size": n}, _discover_job)
    return jsonify({"job_id": job_id, "scope_size": n})


@app.route("/api/targets")
def api_targets():
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        tgt_rows = conn.execute("SELECT * FROM targets ORDER BY target_ip").fetchall()
        surface = {r["target_ip"]: dict(r)
                   for r in conn.execute("SELECT * FROM host_surface").fetchall()}

    # NOTE: ONIOPS never auto-scans. Discovery is explicit (POST /api/discover),
    # so pointing ONIOPS at a large network can't trigger a surprise sweep.
    enriched = []
    for t in tgt_rows:
        ip = t["target_ip"]
        surf = surface.get(ip, {})
        enriched.append({
            "hostname": t["hostname"], "ip": ip, "type": "host", "node": "scope",
            "role": "Discovered host",
            "last_scan": surf.get("last_scan", "Never"),
            "open_ports": surf.get("open_ports", "—"),
            "services": json.loads(surf["services_json"]) if surf.get("services_json") else [],
            "risk_level": surf.get("risk_level", "UNKNOWN"),
            "vulns": {"critical": 0, "high": 0, "medium": 0, "low": 0, "total": 0},
        })
    return jsonify({"targets": enriched})


@app.route("/api/assessments")
def api_assessments():
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute("SELECT * FROM assessments ORDER BY id DESC LIMIT 40").fetchall()
    return jsonify({"assessments": [dict(r) for r in rows]})


# Offensive scan profiles (Kali tooling only — no SIEM correlation).
def _run(cmd: list[str], timeout: int) -> str:
    return active_runner().run(cmd, timeout=timeout).out


def _run_assessment(target_ip: str, hostname: str, profile: str, ctl=None,
                    auth_header: str = "", low_priv_header: str = "") -> dict:
    started_at = now_iso()
    emit_event("RECON", "busy", f"[{profile}] on {hostname} ({target_ip}) via Kali")
    clean_auth = sanitize_auth_header(auth_header) if auth_header else ""
    clean_low = sanitize_auth_header(low_priv_header) if low_priv_header else ""

    commands_run, raw_sections, discovered_ports = [], [], []
    nuclei_lines: list[str] = []
    openapi_findings: list[dict] = []
    finding_count = 0

    if profile == "fast_recon":
        cmd = ["nmap", "-sV", "--version-light", "-F", "-T4", "--open", target_ip]
        commands_run.append(" ".join(cmd))
        out = _run(cmd, 75)
        raw_sections.append(f"=== Nmap Fast Service Recon ===\n$ {' '.join(cmd)}\n{out}")
        discovered_ports = parse_nmap_ports(out)

    elif profile == "deep_service":
        cmd = ["nmap", "-sV", "-sC", "--top-ports", "100", "-T4", "--open", target_ip]
        commands_run.append(" ".join(cmd))
        out = _run(cmd, 110)
        raw_sections.append(f"=== Nmap Deep Banner & Script Audit ===\n$ {' '.join(cmd)}\n{out}")
        discovered_ports = parse_nmap_ports(out)
        seen = set()
        for p in discovered_ports[:4]:
            words = [w for w in re.split(r"[^a-zA-Z0-9.\-]+", p["banner"]) if len(w) >= 3]
            if words:
                term = words[0].lower()
                if term not in ("open", "http", "ssl", "tcp", "linux", "debian", "ubuntu") and term not in seen:
                    seen.add(term)
                    commands_run.append(f"searchsploit {term}")
                    sp = _run(["searchsploit", term], 20)
                    if "Exploit Title" in sp or "Path" in sp:
                        finding_count += 1
                    raw_sections.append(f"=== Exploit-DB Lookup: {term} ===\n{sp[:1200]}")

    elif profile == "web_tls_audit":
        web_ports = "80,81,443,3000,3001,5000,5055,6767,7878,8000,8006,8080,8090,8096,8123,8443,8501,8888,8989,9000,9090,9200,9443,9696,11434"
        cmd = ["nmap", "-p", web_ports, "--open", "-sV", "--script=http-title,http-headers,ssl-cert", target_ip]
        commands_run.append(" ".join(cmd))
        out = _run(cmd, 90)
        raw_sections.append(f"=== Web & TLS Posture Audit ===\n$ {' '.join(cmd)}\n{out}")
        discovered_ports = parse_nmap_ports(out)

    elif profile == "web_app_pt":  # WAPT — OWASP Web Top 10 + Grey-Box + OpenAPI
        emit_event("WAPT", "busy", f"Web App PT on {hostname} ({target_ip})")
        web_ports = "80,443,3000,5000,8000,8080,8081,8443,8888,9000"
        cmd = ["nmap", "-p", web_ports, "--open", "-sV", target_ip]
        commands_run.append(" ".join(cmd))
        out = _run(cmd, 60)
        raw_sections.append(f"=== WAPT: Web Service Discovery ===\n$ {' '.join(cmd)}\n{out}")
        discovered_ports = parse_nmap_ports(out)
        for p in discovered_ports[:3]:
            if ctl is not None and not ctl.checkpoint():
                break
            pn = p["port"]
            scheme = "https" if pn in (443, 8443) else "http"
            url = f"{scheme}://{target_ip}:{pn}"

            emit_event("WAPT_FP", "busy", f"[WAPT] Fingerprint {url}")
            commands_run.append(f"whatweb {url}")
            raw_sections.append(f"=== WAPT: WhatWeb ({url}) ===\n{_run(['whatweb', '--color=never', '-a', '1', url], 30)[:1000]}")

            emit_event("WAPT_CRAWL", "busy", f"[WAPT] Crawl {url}")
            commands_run.append(f"katana {url}")
            kt_cmd = ["katana", "-u", url, "-depth", "2", "-silent"]
            if clean_auth:
                kt_cmd.extend(["-H", clean_auth])
            kt = _run(kt_cmd, 35)
            endpoints = [l.strip() for l in kt.splitlines() if l.startswith("http")][:15]
            if endpoints:
                raw_sections.append(f"=== WAPT: Endpoints ({url}) ===\n" + "\n".join(endpoints))

            emit_event("WAPT_DIR", "busy", f"[WAPT] Content discovery {url}")
            commands_run.append(f"ffuf {url}/FUZZ")
            ff_cmd = ["ffuf", "-u", f"{url}/FUZZ", "-w", "/usr/share/wordlists/dirb/common.txt",
                      "-mc", "200,204,301,302,307,401,403", "-t", "40", "-s"]
            if clean_auth:
                ff_cmd.extend(["-H", clean_auth])
            ff = _run(ff_cmd, 60)
            paths = [l for l in ff.splitlines() if l.strip()]
            if paths:
                note = " (catch-all? treating as informational)" if len(paths) > 100 else ""
                raw_sections.append(
                    f"=== WAPT: Discovered Paths ({url}) — {len(paths)}{note} ===\n"
                    + "\n".join(paths[:40])
                )

            emit_event("WAPT_API", "busy", f"[WAPT] OpenAPI & Access-Control probe {url}")
            oa = probe_openapi(target_ip, pn, scheme, _run,
                               auth_header=clean_auth, low_priv_header=clean_low, ctl=ctl)
            if oa["found"]:
                raw_sections.append(oa["raw_section"])
                finding_count += len(oa["findings"])
                openapi_findings.extend(oa["findings"])

            emit_event("WAPT_JS", "busy", f"[WAPT] SPA / JS bundle route extraction {url}")
            js_disc = discover_js_endpoints(target_ip, pn, scheme, _run, ctl=ctl)
            if js_disc["raw_section"]:
                raw_sections.append(js_disc["raw_section"])

            emit_event("WAPT_VULN", "busy", f"[WAPT] OWASP checks {url}")
            commands_run.append(f"nuclei {url} (web)")
            nc_cmd = ["nuclei", "-target", url, "-tags", "cve,misconfig,exposure,xss,sqli,lfi,ssrf,rce",
                      "-silent", "-severity", "low,medium,high,critical"]
            if clean_auth:
                nc_cmd.extend(["-H", clean_auth])
            nc = _run(nc_cmd, 70)
            if nc.strip():
                nlines = [l for l in nc.splitlines() if l.strip()]
                finding_count += len(nlines)
                nuclei_lines.extend(nlines)
                raw_sections.append(f"=== WAPT: OWASP/Nuclei Findings ({url}) ===\n{nc[:1500]}")

            commands_run.append(f"nikto {url}")
            nk = _run(["nikto", "-h", url, "-Tuning", "1,2,3,b", "-maxtime", "60s"], 75)
            if nk.strip():
                raw_sections.append(f"=== WAPT: Nikto ({url}) ===\n{nk[:1200]}")

    elif profile in PLAYBOOKS:
        pb = PLAYBOOKS[profile]
        emit_event("PLAYBOOK", "busy", f"[Playbook: {pb['name']}] on {hostname} ({target_ip})")
        for step in pb["steps"]:
            if ctl is not None and not ctl.checkpoint():
                break
            scmd = render_step_cmd(step["cmd"], target_ip)
            commands_run.append(" ".join(scmd))
            sout = _run(scmd, step["timeout"])
            raw_sections.append(f"=== {step['name']} ===\n$ {' '.join(scmd)}\n{sout[:1800]}")
            if step.get("parse_ports"):
                discovered_ports.extend(parse_nmap_ports(sout))
            if step.get("count_findings") and sout.strip():
                nlines = [l for l in sout.splitlines() if l.strip()]
                finding_count += len(nlines)
                nuclei_lines.extend(nlines)

    else:  # autonomous_ai — Pentesting Task Tree
        emit_event("PTT_INIT", "busy", f"Pentesting Task Tree for {hostname} ({target_ip})")
        cmd1 = ["nmap", "-sV", "--top-ports", "60", "-T4", "--open", target_ip]
        commands_run.append(" ".join(cmd1))
        out1 = _run(cmd1, 80)
        raw_sections.append(f"=== PTT: Surface Discovery ===\n$ {' '.join(cmd1)}\n{out1}")
        discovered_ports = parse_nmap_ports(out1)

        web_set = {80, 81, 443, 3000, 3001, 5000, 5055, 6767, 7878, 8000, 8006, 8080,
                   8090, 8096, 8123, 8443, 8501, 8888, 8989, 9000, 9090, 9200, 9443, 9696}
        for p in discovered_ports[:4]:
            if ctl is not None and not ctl.checkpoint():
                break
            pn, service, banner = p["port"], p["service"], p["banner"]
            if pn in web_set or "http" in service or "ssl" in service:
                scheme = "https" if pn in (443, 8006, 8443, 9200, 9443) or "ssl" in service else "http"
                url = f"{scheme}://{target_ip}:{pn}"
                emit_event("PTT_TECH", "busy", f"[PTT] Fingerprinting {url}")
                commands_run.append(f"whatweb {url}")
                ww = _run(["whatweb", "--color=never", "-a", "1", url], 30)
                raw_sections.append(f"=== PTT: WhatWeb ({url}) ===\n{ww[:1200]}")

                emit_event("PTT_AUDIT", "busy", f"[PTT] Nuclei audit {url}")
                commands_run.append(f"nuclei -target {url}")
                nc_cmd = ["nuclei", "-target", url, "-tags", "cve,misconfig,exposures",
                          "-silent", "-severity", "low,medium,high,critical"]
                if clean_auth:
                    nc_cmd.extend(["-H", clean_auth])
                nc = _run(nc_cmd, 60)
                if nc.strip():
                    nlines = [l for l in nc.splitlines() if l.strip()]
                    finding_count += len(nlines)
                    nuclei_lines.extend(nlines)
                    raw_sections.append(f"=== PTT: Nuclei Findings ({url}) ===\n{nc[:1500]}")
            elif pn in (139, 445) or "smb" in service:
                emit_event("PTT_SMB", "busy", f"[PTT] SMB enum {target_ip}")
                commands_run.append(f"enum4linux-ng {target_ip}")
                e = _run(["enum4linux-ng", "-A", target_ip], 40)
                raw_sections.append(f"=== PTT: SMB Enumeration ===\n{e[:1500]}")
            else:
                words = [w for w in re.split(r"[^a-zA-Z0-9.\-]+", banner) if len(w) >= 3]
                if words and words[0].lower() not in ("open", "tcp", "linux", "debian", "ubuntu"):
                    term = words[0].lower()
                    commands_run.append(f"searchsploit {term}")
                    sp = _run(["searchsploit", term], 20)
                    if "Exploit Title" in sp or "Path" in sp:
                        finding_count += 1
                        raw_sections.append(f"=== PTT: Exploit-DB ({term}) ===\n{sp[:1200]}")

    # ── PoC validation: confirm discovered services are actually live, so a
    # finding is VERIFIED (re-tested on the target) rather than merely reported.
    verified_services = []
    _webset = {80, 81, 443, 3000, 3001, 5000, 5055, 8000, 8006, 8080, 8081, 8090,
               8096, 8123, 8443, 8501, 8888, 8989, 9000, 9090, 9200, 9443, 9696}
    for p in discovered_ports[:8]:
        if ctl is not None and not ctl.checkpoint():
            break
        pn, svc = p["port"], p["service"]
        if pn in _webset or "http" in svc or "ssl" in svc:
            scheme = "https" if pn in (443, 8443, 9443, 8006) or "ssl" in svc else "http"
            out = _run(["curl", "-kIsS", "--max-time", "4", f"{scheme}://{target_ip}:{pn}"], 8) or ""
            m = re.search(r"HTTP/[\d.]+\s+(\d{3})[^\r\n]*", out)
            if m:
                code = int(m.group(1))
                # Content signatures beyond the bare status line: Server banner,
                # and whether the service is live-but-access-controlled.
                sm = re.search(r"^[Ss]erver:\s*(.+)$", out, re.MULTILINE)
                server = sm.group(1).strip()[:60] if sm else ""
                sig = m.group(0).strip() + (f" | Server: {server}" if server else "")
                if code in (401, 403) or re.search(r"[Ww]ww-[Aa]uthenticate:", out):
                    status = "AUTH-GATED"   # service confirmed live, access-controlled
                elif 200 <= code < 600:
                    status = "VERIFIED"
                else:
                    status = "UNCONFIRMED"
                verified_services.append({"port": pn, "service": svc, "status": status, "evidence": sig})
            else:
                verified_services.append({"port": pn, "service": svc, "status": "UNCONFIRMED", "evidence": (out or "no HTTP response")[:80]})
        else:
            verified_services.append({"port": pn, "service": svc, "status": "OPEN", "evidence": "port open; non-HTTP service (not re-verified)"})
    verified_count = sum(1 for v in verified_services if v["status"] in ("VERIFIED", "AUTH-GATED"))
    if verified_services:
        emit_event("VALIDATE", "ok", f"PoC validation: {verified_count}/{len(verified_services)} services verified live")
        raw_sections.append("=== PoC Validation: Service Verification ===\n"
                            + "\n".join(f"- {v['port']}/{v['service']}: {v['status']} ({v['evidence']})" for v in verified_services))

    # ── CVE / Exploit intelligence: map detected product versions to known
    # exploits (searchsploit, offline) + optional NVD CVE IDs/CVSS. No MISP.
    cve_intel = {"cve_count": 0, "exploit_count": 0, "max_severity": "NONE", "findings": []}
    if discovered_ports:
        emit_event("CVE_INTEL", "busy", "Correlating service versions with known CVEs / exploits")
        try:
            cve_intel = cve.enrich(discovered_ports, cfg, _run, ctl=ctl)
            if cve_intel["cve_count"] or cve_intel["exploit_count"]:
                raw_sections.append(cve_intel["raw_section"])
                emit_event("CVE_INTEL", "ok",
                           f"{cve_intel['cve_count']} CVE(s), {cve_intel['exploit_count']} exploit(s) matched")
            else:
                emit_event("CVE_INTEL", "ok", "No known CVEs/exploits matched detected versions")
        except Exception as e:  # intel is best-effort; never fail the assessment
            emit_event("CVE_INTEL", "warn", f"CVE intel skipped: {e}")

    full_raw = redact_secrets("\n\n".join(raw_sections))
    port_summary = ", ".join(f"{p['port']}/{p['proto']} ({p['service']})" for p in discovered_ports) \
        or "No open ports in scanned range"

    # Record structured, replayable findings into the Evidence Ledger.
    try:
        ledger.record_from_assessment(
            target_ip,
            verified_services,
            cve_intel.get("findings", []),
            nuclei_lines=nuclei_lines,
            openapi_findings=openapi_findings,
        )
    except Exception:
        pass

    # Severity from offensive signal only (ports + findings).
    n = len(discovered_ports)
    if finding_count >= 3 or n >= 8:
        severity = "CRITICAL"
    elif finding_count >= 1 or n >= 6:
        severity = "HIGH"
    elif n >= 3:
        severity = "MEDIUM"
    else:
        severity = "LOW"

    # A confirmed CRITICAL/HIGH CVE on a detected version raises the floor.
    _rank = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
    if cve_intel.get("max_severity") in ("HIGH", "CRITICAL"):
        severity = cve_intel["max_severity"] if _rank[cve_intel["max_severity"]] > _rank[severity] else severity

    emit_event("AI_REASON", "busy", "Synthesizing attack-path reasoning")
    cot = ai_chat([
        {"role": "system", "content": "You are a cyber attack-path reasoning engine. From the open "
         "ports, services, banners and tool output, identify the most promising attack paths and "
         "misconfigurations. Be concise and technical."},
        {"role": "user", "content": f"Target: {hostname} ({target_ip})\nPorts: {port_summary}\n"
         f"Evidence:\n{full_raw[:2200]}"},
    ], role="reason")

    emit_event("AI_REPORT", "busy", f"Writing red-team report via {active_model_name()}")
    sys_prompt = (
        "You are ONIOPS, an Offensive Neural Intelligence red-team operator. Analyze the Kali "
        "reconnaissance and produce a concise markdown report with:\n"
        "1. **Executive Exposure Summary** (attack surface & risk rating)\n"
        "2. **Enumerated Services & Attack Vectors** (ports, versions, weaknesses, MITRE ATT&CK IDs)\n"
        "3. **Exploitation Path** (most likely route to compromise, non-destructive)\n"
        "4. **Prioritized Hardening Recommendations**"
    )
    user_prompt = (
        f"Target: {hostname} ({target_ip})\nProfile: {profile}\nOpen ports: {port_summary}\n"
        f"Findings detected: {finding_count}\n"
        f"Verified live services (PoC-validated): {verified_count}/{len(verified_services)}\n"
        f"Known CVEs matched: {cve_intel.get('cve_count', 0)} | "
        f"Public exploits matched: {cve_intel.get('exploit_count', 0)}\n\n"
        f"Attack-path reasoning:\n{cot}\n\nEvidence:\n{full_raw[:3000]}"
    )
    ai_report = redact_secrets(
        ai_chat([{"role": "system", "content": sys_prompt},
                 {"role": "user", "content": user_prompt}], role="reporter")
    )

    ts = now_iso()
    with sqlite3.connect(DB_PATH) as conn:
        cur = conn.cursor()
        cur.execute("""INSERT INTO assessments
            (timestamp,target_ip,target_name,profile,severity,open_ports,finding_count,commands_run,raw_output,ai_report)
            VALUES (?,?,?,?,?,?,?,?,?,?)""",
            (ts, target_ip, hostname, profile, severity, port_summary, finding_count,
             json.dumps(commands_run), full_raw, ai_report))
        aid = cur.lastrowid
        conn.execute("""INSERT INTO host_surface (target_ip,target_name,last_scan,open_ports,services_json,risk_level)
            VALUES (?,?,?,?,?,?)
            ON CONFLICT(target_ip) DO UPDATE SET last_scan=excluded.last_scan,
                open_ports=excluded.open_ports, services_json=excluded.services_json, risk_level=excluded.risk_level""",
            (target_ip, hostname, ts, port_summary, json.dumps(discovered_ports), severity))
        conn.commit()

    emit_event("COMPLETE", "ok", f"[{profile}] on {hostname}: {n} ports, {finding_count} findings")
    ev_hashes = [f.get("evidence_sha256", "") for f in ledger.list_findings(target_ip=target_ip, limit=15) if f.get("evidence_sha256")]
    manifest = build_assessment_manifest(
        assessment_id=aid or 0,
        oniops_version=__version__,
        target_ip=target_ip,
        profile=profile,
        scope_cidrs=scope.cidrs,
        model_name=active_model_name(),
        started_at=started_at,
        completed_at=ts,
        commands_run=commands_run,
        evidence_hashes=ev_hashes,
        signing_key=str(cfg.auth.secret_key or app.secret_key or "oniops-default-manifest-key"),
    )
    return {
        "id": aid, "timestamp": ts, "target_ip": target_ip, "target_name": hostname,
        "profile": profile, "severity": severity, "open_ports": port_summary,
        "ports_list": discovered_ports, "finding_count": finding_count,
        "verified_services": verified_services, "verified_count": verified_count,
        "cve_count": cve_intel.get("cve_count", 0), "exploit_count": cve_intel.get("exploit_count", 0),
        "cve_findings": cve_intel.get("findings", []),
        "commands_run": commands_run, "raw_output": full_raw, "ai_report": ai_report,
        "manifest": manifest,
    }


@app.route("/api/assess", methods=["POST"])
def api_assess():
    """Synchronous assessment (blocks until done). Kept for CLI / compatibility."""
    data = request.get_json(silent=True) or {}
    profile = data.get("profile", "fast_recon")
    if profile not in (ALLOWED_PROFILES | set(PLAYBOOKS)):
        return jsonify({"error": f"Unknown profile '{profile}'."}), 400
    try:
        rt = scope.resolve(data.get("target", ""))
        auth_header = sanitize_auth_header(data.get("auth_header", "")) if data.get("auth_header") else ""
        low_priv_header = sanitize_auth_header(data.get("low_priv_header", "")) if data.get("low_priv_header") else ""
    except (ScopeViolation, ValueError) as exc:
        return jsonify({"error": str(exc)}), 400
    return jsonify(_run_assessment(rt.ip, rt.label, profile, auth_header=auth_header, low_priv_header=low_priv_header))


@app.route("/api/assess/start", methods=["POST"])
def api_assess_start():
    """Enqueue an assessment as a background job; returns a job_id to poll."""
    data = request.get_json(silent=True) or {}
    profile = data.get("profile", "fast_recon")
    if profile not in (ALLOWED_PROFILES | set(PLAYBOOKS)):
        return jsonify({"error": f"Unknown profile '{profile}'."}), 400
    try:
        rt = scope.resolve(data.get("target", ""))
        auth_header = sanitize_auth_header(data.get("auth_header", "")) if data.get("auth_header") else ""
        low_priv_header = sanitize_auth_header(data.get("low_priv_header", "")) if data.get("low_priv_header") else ""
    except (ScopeViolation, ValueError) as exc:
        return jsonify({"error": str(exc)}), 400
    ip, label = rt.ip, rt.label
    job_id = jobs.submit(
        "assessment",
        {"target": label, "ip": ip, "profile": profile},
        lambda ctl: _run_assessment(ip, label, profile, ctl=ctl,
                                    auth_header=auth_header, low_priv_header=low_priv_header),
    )
    return jsonify({"job_id": job_id})


@app.route("/api/assessments/<int:aid>/diff")
def api_assessment_diff(aid: int):
    try:
        return jsonify(diff_assessments(DB_PATH, aid))
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 404


@app.route("/api/playbooks")
def api_playbooks():
    return jsonify({"playbooks": list(PLAYBOOKS.values())})


@app.route("/api/findings")
def api_findings():
    target = (request.args.get("target") or "").strip()
    return jsonify({"findings": ledger.list_findings(target_ip=target)})


@app.route("/api/findings/<int:fid>/retest", methods=["POST"])
def api_retest_finding(fid: int):
    try:
        res = ledger.retest(fid, active_runner(), scope)
        emit_event("RETEST", "ok", f"Zero-token PoC retest #{fid}: {res['status']}")
        return jsonify(res)
    except (ScopeViolation, ValueError) as exc:
        return jsonify({"error": str(exc)}), 400


@app.route("/api/findings/retest-all", methods=["POST"])
def api_retest_all_findings():
    data = request.get_json(silent=True) or {}
    target = (data.get("target") or "").strip()
    res = ledger.retest_all(active_runner(), scope, target_ip=target)
    emit_event("RETEST_ALL", "ok",
               f"Batch PoC retest: {res['total_retested']} checked ({res['verified']} verified, {res['fixed']} fixed)")
    return jsonify(res)


@app.route("/api/whitebox/scan", methods=["POST"])
def api_whitebox_scan():
    data = request.get_json(silent=True) or {}
    source = (data.get("source") or "").strip()
    if not source:
        return jsonify({"error": "Provide a local source directory/file path or code snippet."}), 400
    res = analyze_source_code(source)
    emit_event("WHITEBOX", "ok", f"White-box scan: {len(res['routes'])} routes, {len(res['sinks'])} sinks")
    return jsonify(res)


@app.route("/api/agent/start", methods=["POST"])
def api_agent_start():
    """Launch the autonomous tool-calling agent as a background job."""
    data = request.get_json(silent=True) or {}
    objective = (data.get("objective") or "").strip()
    if not objective or len(objective) > 500:
        return jsonify({"error": "Provide an objective (1-500 chars)."}), 400
    target = (data.get("target") or "").strip()
    if target:
        try:
            target = scope.resolve(target).ip
        except ScopeViolation as exc:
            return jsonify({"error": str(exc)}), 400
    try:
        auth_header = sanitize_auth_header(data.get("auth_header", "")) if data.get("auth_header") else ""
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400
    steps = max(2, min(int(data.get("max_steps", 8) or 8), 12))

    def _job(ctl):
        return run_agent(objective, target, llm=llm, scope=scope,
                         runner=active_runner(), emit=emit_event, max_steps=steps,
                         ctl=ctl, db_path=DB_PATH, auth_header=auth_header)

    job_id = jobs.submit("agent", {"objective": objective[:80], "target": target or "(auto)"}, _job)
    return jsonify({"job_id": job_id})


@app.route("/api/aisec/probes")
def api_aisec_probes():
    yaml_probes = [
        {"id": p["id"], "name": p["name"], "owasp": p["owasp"],
         "atlas": p["atlas"], "severity": p["severity"], "source": p.get("source", "yaml")}
        for p in load_yaml_probes()
    ]
    return jsonify({"yaml_probes": yaml_probes, "converters": list(CONVERTERS)})


@app.route("/api/aisec/start", methods=["POST"])
def api_aisec_start():
    """Run an AI-security + GRC assessment against an LLM/AI chat endpoint."""
    data = request.get_json(silent=True) or {}
    base_url = (data.get("base_url") or "").strip()
    model = (data.get("model") or "").strip()
    api_type = (data.get("api_type") or "ollama").strip()
    system_prompt = (data.get("system_prompt") or "")[:4000]
    req_template = (data.get("req_template") or "")[:2000]
    resp_path = (data.get("resp_path") or "").strip()[:200]
    converter = (data.get("converter") or "none").strip()
    if converter not in CONVERTERS:
        converter = "none"
    include_crescendo = bool(data.get("include_crescendo", True))
    include_yaml_packs = bool(data.get("include_yaml_packs", False))
    if not re.match(r"^https?://", base_url):
        return jsonify({"error": "Provide an http(s) AI endpoint base_url."}), 400
    if api_type not in ("ollama", "openai", "custom"):
        api_type = "ollama"
    if api_type != "custom" and (not model or len(model) > 80):
        return jsonify({"error": "Provide a model name."}), 400

    def _job(ctl):
        return run_aisec(base_url, model, api_type, emit=emit_event,
                         judge=llm.for_role("reporter"), ctl=ctl,
                         system_prompt=system_prompt, req_template=req_template,
                         resp_path=resp_path, converter=converter,
                         include_crescendo=include_crescendo,
                         include_yaml_packs=include_yaml_packs)

    job_id = jobs.submit("aisec", {"model": model, "target": base_url}, _job)
    return jsonify({"job_id": job_id})


@app.route("/api/job/<job_id>")
def api_job(job_id):
    j = jobs.get(job_id)
    if not j:
        return jsonify({"error": "job not found"}), 404
    return jsonify(j)


@app.route("/api/jobs")
def api_jobs():
    return jsonify({"jobs": jobs.list()})


@app.route("/api/job/<job_id>/<action>", methods=["POST"])
def api_job_control(job_id, action):
    fn = {"cancel": jobs.cancel, "pause": jobs.pause, "resume": jobs.resume}.get(action)
    if not fn:
        return jsonify({"error": "unknown action"}), 400
    return jsonify({"ok": fn(job_id), "action": action})


@app.route("/api/intel")
def api_intel():
    q = (request.args.get("q") or "").strip()
    if not q or len(q) > 80 or not re.match(r"^[\w\s.\-:]+$", q):
        return jsonify({"error": "Provide a valid search term (e.g. openssh, nginx, CVE-2024)."}), 400
    emit_event("INTEL", "busy", f"Exploit-DB lookup for '{q}'")
    out = _run(["searchsploit", "--json", q], 25)
    exploits = []
    try:
        for item in (json.loads(out).get("RESULTS_EXPLOIT", []) or [])[:30]:
            exploits.append({"id": item.get("EDB-ID", ""), "title": item.get("Title", ""),
                             "type": item.get("Type", ""), "platform": item.get("Platform", ""),
                             "date": item.get("Date_Published", ""), "codes": item.get("Codes", "")})
    except Exception:
        pass
    emit_event("INTEL", "ok", f"Intel '{q}': {len(exploits)} Exploit-DB advisories")
    # fleet_cves kept as an (empty) key for frontend compatibility; offensive CVE
    # enrichment via MISP/Vulners lands in a later phase.
    return jsonify({"query": q, "exploits": exploits, "fleet_cves": []})


@app.route("/api/graph")
def api_graph():
    """Attack-surface knowledge graph (hosts -> services, with finding rollups)."""
    return jsonify(build_graph(DB_PATH, scope.cidrs))


@app.route("/api/telemetry")
def api_telemetry():
    events = []
    if ACTIVITY_LOG.exists():
        for line in reversed(ACTIVITY_LOG.read_text().splitlines()[-80:]):
            if line.strip():
                try:
                    events.append(json.loads(line))
                except Exception:
                    pass
    return jsonify({"events": events})


KALI_TOOL_CATALOG = [
    # --- Network recon ---
    {"pkg": "nmap", "bin": "nmap", "category": "Network Recon", "desc": "Port scanning & service fingerprinting"},
    {"pkg": "masscan", "bin": "masscan", "category": "Network Recon", "desc": "High-speed async port scanner"},
    {"pkg": "naabu", "bin": "naabu", "category": "Network Recon", "desc": "Fast SYN/connect port scanner"},
    {"pkg": "arp-scan", "bin": "arp-scan", "category": "Network Recon", "desc": "Layer-2 host discovery"},
    {"pkg": "netdiscover", "bin": "netdiscover", "category": "Network Recon", "desc": "Passive/active ARP reconnaissance"},
    # --- DNS / subdomain ---
    {"pkg": "subfinder", "bin": "subfinder", "category": "DNS Recon", "desc": "Passive subdomain discovery"},
    {"pkg": "amass", "bin": "amass", "category": "DNS Recon", "desc": "Attack-surface & subdomain mapping"},
    {"pkg": "dnsx", "bin": "dnsx", "category": "DNS Recon", "desc": "Fast DNS toolkit & resolver"},
    {"pkg": "dnsrecon", "bin": "dnsrecon", "category": "DNS Recon", "desc": "DNS enumeration & zone auditing"},
    # --- Web recon / WAPT ---
    {"pkg": "whatweb", "bin": "whatweb", "category": "Web Recon", "desc": "Web technology & CMS fingerprinting"},
    {"pkg": "httpx-toolkit", "bin": "httpx", "category": "Web Recon", "desc": "Fast HTTP probe & tech detect"},
    {"pkg": "katana", "bin": "katana", "category": "Web Recon", "desc": "Next-gen web crawler/spider"},
    {"pkg": "gobuster", "bin": "gobuster", "category": "Web Recon", "desc": "Directory, vhost & DNS brute-force"},
    {"pkg": "ffuf", "bin": "ffuf", "category": "Web Recon", "desc": "Fast endpoint & parameter fuzzing"},
    {"pkg": "feroxbuster", "bin": "feroxbuster", "category": "Web Recon", "desc": "Recursive content discovery"},
    {"pkg": "dirb", "bin": "dirb", "category": "Web Recon", "desc": "Classic web content scanner"},
    {"pkg": "wfuzz", "bin": "wfuzz", "category": "Web Recon", "desc": "Web application fuzzer"},
    {"pkg": "arjun", "bin": "arjun", "category": "Web Recon", "desc": "HTTP parameter discovery"},
    {"pkg": "wafw00f", "bin": "wafw00f", "category": "Web Recon", "desc": "WAF detection & fingerprinting"},
    # --- Web audit / exploit ---
    {"pkg": "nuclei", "bin": "nuclei", "category": "Web Audit", "desc": "Template-based CVE & misconfig scanner"},
    {"pkg": "nikto", "bin": "nikto", "category": "Web Audit", "desc": "Web server misconfiguration scanner"},
    {"pkg": "wpscan", "bin": "wpscan", "category": "Web Audit", "desc": "WordPress vulnerability scanner"},
    {"pkg": "sqlmap", "bin": "sqlmap", "category": "Web Exploit", "desc": "Automated SQL injection exploitation"},
    {"pkg": "dalfox", "bin": "dalfox", "category": "Web Exploit", "desc": "Fast XSS discovery & verification"},
    {"pkg": "commix", "bin": "commix", "category": "Web Exploit", "desc": "Command-injection exploitation"},
    {"pkg": "burpsuite", "bin": "burpsuite", "category": "Web Proxy", "desc": "Intercepting proxy & web auditing (GUI)"},
    # --- TLS ---
    {"pkg": "sslscan", "bin": "sslscan", "category": "TLS Audit", "desc": "SSL/TLS cipher & certificate inspector"},
    {"pkg": "sslyze", "bin": "sslyze", "category": "TLS Audit", "desc": "Deep TLS configuration analyzer"},
    {"pkg": "testssl.sh", "bin": "testssl", "category": "TLS Audit", "desc": "Comprehensive TLS/SSL auditor"},
    # --- SMB / AD / network creds ---
    {"pkg": "enum4linux-ng", "bin": "enum4linux-ng", "category": "SMB/AD", "desc": "SMB/Samba & RPC enumeration"},
    {"pkg": "smbmap", "bin": "smbmap", "category": "SMB/AD", "desc": "SMB share enumeration & access"},
    {"pkg": "netexec", "bin": "nxc", "category": "SMB/AD", "desc": "Network/AD exec (CrackMapExec successor)"},
    {"pkg": "responder", "bin": "responder", "category": "SMB/AD", "desc": "LLMNR/NBT-NS/MDNS poisoner"},
    {"pkg": "snmp-check", "bin": "snmp-check", "category": "Enum", "desc": "SNMP device enumeration"},
    # --- Credentials ---
    {"pkg": "hydra", "bin": "hydra", "category": "Credentials", "desc": "Network login brute-forcer"},
    {"pkg": "medusa", "bin": "medusa", "category": "Credentials", "desc": "Parallel login brute-forcer"},
    {"pkg": "john", "bin": "john", "category": "Credentials", "desc": "John the Ripper password cracker"},
    {"pkg": "hashcat", "bin": "hashcat", "category": "Credentials", "desc": "GPU password cracking"},
    # --- Exploitation / intel ---
    {"pkg": "metasploit-framework", "bin": "msfconsole", "category": "Exploitation", "desc": "Exploit & auxiliary framework"},
    {"pkg": "exploitdb", "bin": "searchsploit", "category": "Vuln Intel", "desc": "Offline Exploit-DB archive search"},
    {"pkg": "gitleaks", "bin": "gitleaks", "category": "Secret Audit", "desc": "Scan for leaked secrets & keys"},
]


@app.route("/api/kali/tools")
def api_kali_tools():
    # Don't hang the Arsenal view on an SSH timeout when we already know the
    # attack host is unreachable; report every tool as unknown instead.
    if health_snapshot()["kali"] is False:
        return jsonify({"kali_online": False,
                        "tools": [{**item, "installed": False} for item in KALI_TOOL_CATALOG]})
    bins = [t["bin"] for t in KALI_TOOL_CATALOG]
    script = ("export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin; "
              "for b in " + " ".join(bins) + "; do if command -v $b >/dev/null 2>&1; then echo \"$b:1\"; else echo \"$b:0\"; fi; done")
    res = active_runner().run(["bash", "-c", script], timeout=15)
    status = {}
    if res.ok:
        for line in res.out.splitlines():
            if ":" in line:
                b, st = line.strip().split(":", 1)
                status[b] = (st == "1")
    tools = [{**item, "installed": status.get(item["bin"], False)} for item in KALI_TOOL_CATALOG]
    return jsonify({"kali_online": res.ok, "tools": tools})


@app.route("/api/kali/install", methods=["POST"])
def api_kali_install():
    data = request.get_json(silent=True) or {}
    pkg = (data.get("package") or "").strip().lower()
    if not pkg or len(pkg) > 64 or not re.match(r"^[a-z0-9][a-z0-9+.\-]+$", pkg):
        return jsonify({"error": "Invalid package name."}), 400
    emit_event("KALI_PKG", "busy", f"Installing '{pkg}' on Kali via apt-get")
    cmd = f"export DEBIAN_FRONTEND=noninteractive; apt-get update -qq && apt-get install -y -qq {pkg} 2>&1 | tail -n 35"
    res = active_runner().run(["bash", "-c", cmd], timeout=180)
    emit_event("KALI_PKG", "ok" if res.ok else "err", f"Package '{pkg}' install {'ok' if res.ok else 'failed'}")
    return jsonify({"ok": res.ok, "package": pkg, "output": res.out})


# Scoped recon tools the chat operator can trigger directly.
_CHAT_TOOLS = {
    "whatweb": lambda ip: ["whatweb", "--color=never", "-a", "1", ip],
    "sslscan": lambda ip: ["sslscan", "--no-colour", ip],
    "nuclei": lambda ip: ["nuclei", "-target", ip, "-tags", "cve,misconfig,exposures", "-silent"],
    "nikto": lambda ip: ["nikto", "-h", ip, "-Tuning", "1,2,3,b"],
    "httpx": lambda ip: ["httpx", "-u", f"http://{ip}", "-status-code", "-title", "-tech-detect", "-silent"],
    "enum4linux": lambda ip: ["enum4linux-ng", "-A", ip],
}


def execute_chat_action(msg: str, default_target: str = ""):
    lower = msg.lower()
    m = re.search(r"\b(?:install|apt\s+install)\s+([a-z0-9][a-z0-9+.\-]+)", lower)
    if m and m.group(1) not in ("the", "a", "new", "tool", "on", "kali"):
        pkg = m.group(1)
        emit_event("AI_KALI", "busy", f"Installing '{pkg}' on Kali")
        cmd = f"export DEBIAN_FRONTEND=noninteractive; apt-get update -qq && apt-get install -y -qq {pkg} 2>&1 | tail -n 25"
        res = active_runner().run(["bash", "-c", cmd], timeout=160)
        return f"$ apt-get install -y {pkg}\n{res.out}", res.ok

    # Resolve a scoped target from the message or the default.
    target_ip = None
    m_ip = re.search(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b", msg)
    candidate = m_ip.group(1) if m_ip else default_target
    if candidate:
        try:
            target_ip = scope.resolve(candidate).ip
        except ScopeViolation:
            target_ip = None

    if "searchsploit" in lower:
        m_sp = re.search(r"searchsploit\s+([a-zA-Z0-9.\-_]+)", msg, re.I)
        term = m_sp.group(1) if m_sp else "openssh"
        res = active_runner().run(["searchsploit", "--colour", term], timeout=25)
        return f"$ searchsploit {term}\n{res.out[:2000]}", res.ok

    for name, builder in _CHAT_TOOLS.items():
        if name in lower and target_ip:
            emit_event("AI_KALI", "busy", f"Running {name} on {target_ip}")
            res = active_runner().run(builder(target_ip), timeout=90)
            return f"$ {name} {target_ip}\n{res.out[:2500]}", res.ok

    if any(k in lower for k in ("nmap", "scan ", "port scan", "recon ")) and target_ip:
        emit_event("AI_KALI", "busy", f"Nmap recon on {target_ip}")
        res = active_runner().run(["nmap", "-sV", "--version-light", "-F", "-T4", "--open", target_ip], timeout=60)
        return f"$ nmap -sV -F {target_ip}\n{res.out[:2000]}", res.ok

    return None, False


@app.route("/api/chat", methods=["POST"])
def api_chat():
    data = request.get_json(silent=True) or {}
    msg = (data.get("message") or "").strip()
    default_target = (data.get("target") or "").strip()
    if not msg:
        return jsonify({"error": "Message cannot be empty."}), 400

    tool_output, _ = execute_chat_action(msg, default_target)

    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        recent = [dict(r) for r in conn.execute(
            "SELECT target_name,target_ip,profile,severity,open_ports,finding_count FROM assessments ORDER BY id DESC LIMIT 5"
        ).fetchall()]

    sys_prompt = (
        "You are ONIOPS, an Offensive Neural Intelligence red-team operator with SSH access to a Kali "
        f"host, scope-locked to {', '.join(scope.cidrs)}. Provide concise, tactical red-team analysis, "
        "CVE prioritization, MITRE ATT&CK mapping, and exploitation guidance (non-destructive).\n"
        f"Recent assessments: {json.dumps(recent)}"
    )
    user_content = msg[:1500]
    if tool_output:
        user_content += f"\n\n[LIVE KALI OUTPUT]:\n{tool_output}"
    reply = ai_chat([{"role": "system", "content": sys_prompt},
                     {"role": "user", "content": user_content}], role="reporter")
    if tool_output:
        reply = f"```text\n{tool_output.strip()}\n```\n\n" + reply
    return jsonify({"reply": reply, "model": active_model_name(), "tool_executed": bool(tool_output)})


if __name__ == "__main__":
    app.run(host=cfg.bind_host, port=cfg.bind_port, debug=False)

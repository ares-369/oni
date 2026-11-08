"""
ONIOPS WebUI — Offensive Neural Intelligence.

Scope-locked offensive assessment platform. Drives a Kali toolchain over SSH,
reasons with any configured LLM provider, and generates AI red-team reports.
Red-team only: no SIEM / blue-team dependencies.

The app is served by waitress via ``python -m oniops``; this module exposes the
Flask ``app`` and the REST API the UI calls.
"""

from __future__ import annotations

import hmac
import json
import logging
import re
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

from flask import Flask, Response, jsonify, render_template, request

from oniops import __version__
from oniops.auth import init_auth
from oniops.config import get_config
from oniops.graph import build_graph
from oniops.jobs import JobManager
from oniops.kali import KaliRunner
from oniops.providers import get_llm
from oniops.scope import Scope, ScopeViolation
from oniops.targets import discover as discover_hosts

cfg = get_config()
scope = Scope(cfg)
llm = get_llm()

# Attack hosts: ONIOPS can drive any SSH-reachable tooled Linux, not just Kali.
HOST_RUNNERS = {h.name: KaliRunner(h, scope, cfg) for h in cfg.hosts}
ACTIVE_HOST = cfg.kali.name


def active_runner() -> KaliRunner:
    return HOST_RUNNERS.get(ACTIVE_HOST) or next(iter(HOST_RUNNERS.values()))

app = Flask(__name__)
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
    with sqlite3.connect(DB_PATH) as conn:
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


@app.route("/api/status")
def api_status():
    kali_ok = False
    try:
        kali_ok = active_runner().ping()
    except Exception:
        pass

    provider_health = llm.health()
    # Collect model list from the planner/reporter provider for the UI dropdown.
    try:
        rprov = llm.for_role("reporter").provider
        models = rprov.available_models() or [active_model_name()]
    except Exception:
        models = [active_model_name()]

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
        "health": {"kali": kali_ok, "llm": any(provider_health.values()),
                   "providers": provider_health},
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
        },
    })


@app.route("/api/host", methods=["POST"])
def api_set_host():
    global ACTIVE_HOST
    data = request.get_json(silent=True) or {}
    name = (data.get("name") or "").strip()
    if name not in HOST_RUNNERS:
        return jsonify({"error": f"Unknown attack host '{name}'."}), 400
    ACTIVE_HOST = name
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


@app.route("/api/discover", methods=["POST"])
def api_discover():
    emit_event("DISCOVER", "busy", f"Sweeping scope {', '.join(scope.cidrs)} for live hosts")
    try:
        hosts = discover_hosts(active_runner(), scope)
    except Exception as exc:
        return jsonify({"error": f"Discovery failed: {exc}"}), 500
    ts = now_iso()
    with sqlite3.connect(DB_PATH) as conn:
        for h in hosts:
            conn.execute("""
                INSERT INTO targets (target_ip, hostname, first_seen, last_seen)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(target_ip) DO UPDATE SET hostname=excluded.hostname, last_seen=excluded.last_seen
            """, (h.ip, h.hostname, ts, ts))
        conn.commit()
    emit_event("DISCOVER", "ok", f"Discovered {len(hosts)} live host(s) in scope")
    return jsonify({"discovered": len(hosts)})


@app.route("/api/targets")
def api_targets():
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        tgt_rows = conn.execute("SELECT * FROM targets ORDER BY target_ip").fetchall()
        surface = {r["target_ip"]: dict(r)
                   for r in conn.execute("SELECT * FROM host_surface").fetchall()}

    # Auto-discover on first use if the target cache is empty.
    if not tgt_rows:
        try:
            hosts = discover_hosts(active_runner(), scope)
            ts = now_iso()
            with sqlite3.connect(DB_PATH) as conn:
                for h in hosts:
                    conn.execute("""INSERT INTO targets (target_ip, hostname, first_seen, last_seen)
                        VALUES (?,?,?,?) ON CONFLICT(target_ip) DO UPDATE SET last_seen=excluded.last_seen""",
                        (h.ip, h.hostname, ts, ts))
                conn.commit()
                conn.row_factory = sqlite3.Row
                tgt_rows = conn.execute("SELECT * FROM targets ORDER BY target_ip").fetchall()
        except Exception as exc:
            log.warning(f"auto-discovery failed: {exc}")

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


def _run_assessment(target_ip: str, hostname: str, profile: str) -> dict:
    emit_event("RECON", "busy", f"[{profile}] on {hostname} ({target_ip}) via Kali")

    commands_run, raw_sections, discovered_ports = [], [], []
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

    elif profile == "web_app_pt":  # WAPT — OWASP Web Top 10 oriented
        emit_event("WAPT", "busy", f"Web App PT on {hostname} ({target_ip})")
        web_ports = "80,443,3000,5000,8000,8080,8081,8443,8888,9000"
        cmd = ["nmap", "-p", web_ports, "--open", "-sV", target_ip]
        commands_run.append(" ".join(cmd))
        out = _run(cmd, 60)
        raw_sections.append(f"=== WAPT: Web Service Discovery ===\n$ {' '.join(cmd)}\n{out}")
        discovered_ports = parse_nmap_ports(out)
        for p in discovered_ports[:3]:
            pn = p["port"]
            scheme = "https" if pn in (443, 8443) else "http"
            url = f"{scheme}://{target_ip}:{pn}"

            emit_event("WAPT_FP", "busy", f"[WAPT] Fingerprint {url}")
            commands_run.append(f"whatweb {url}")
            raw_sections.append(f"=== WAPT: WhatWeb ({url}) ===\n{_run(['whatweb', '--color=never', '-a', '1', url], 30)[:1000]}")

            emit_event("WAPT_CRAWL", "busy", f"[WAPT] Crawl {url}")
            commands_run.append(f"katana {url}")
            kt = _run(["katana", "-u", url, "-depth", "2", "-silent"], 35)
            endpoints = [l.strip() for l in kt.splitlines() if l.startswith("http")][:15]
            if endpoints:
                raw_sections.append(f"=== WAPT: Endpoints ({url}) ===\n" + "\n".join(endpoints))

            emit_event("WAPT_DIR", "busy", f"[WAPT] Content discovery {url}")
            commands_run.append(f"ffuf {url}/FUZZ")
            ff = _run(["ffuf", "-u", f"{url}/FUZZ", "-w", "/usr/share/wordlists/dirb/common.txt",
                       "-mc", "200,204,301,302,307,401,403", "-t", "40", "-s"], 60)
            paths = [l for l in ff.splitlines() if l.strip()]
            if paths:
                # Content-discovery paths are informational context, NOT findings.
                # (A catch-all app can return thousands; counting them as vulns
                # would wildly inflate severity.)
                note = " (catch-all? treating as informational)" if len(paths) > 100 else ""
                raw_sections.append(
                    f"=== WAPT: Discovered Paths ({url}) — {len(paths)}{note} ===\n"
                    + "\n".join(paths[:40])
                )

            emit_event("WAPT_VULN", "busy", f"[WAPT] OWASP checks {url}")
            commands_run.append(f"nuclei {url} (web)")
            nc = _run(["nuclei", "-target", url, "-tags", "cve,misconfig,exposure,xss,sqli,lfi,ssrf,rce",
                       "-silent", "-severity", "low,medium,high,critical"], 70)
            if nc.strip():
                finding_count += len([l for l in nc.splitlines() if l.strip()])
                raw_sections.append(f"=== WAPT: OWASP/Nuclei Findings ({url}) ===\n{nc[:1500]}")

            commands_run.append(f"nikto {url}")
            nk = _run(["nikto", "-h", url, "-Tuning", "1,2,3,b", "-maxtime", "60s"], 75)
            if nk.strip():
                raw_sections.append(f"=== WAPT: Nikto ({url}) ===\n{nk[:1200]}")

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
                nc = _run(["nuclei", "-target", url, "-tags", "cve,misconfig,exposures",
                           "-silent", "-severity", "low,medium,high,critical"], 60)
                if nc.strip():
                    finding_count += len([l for l in nc.splitlines() if l.strip()])
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

    full_raw = "\n\n".join(raw_sections)
    port_summary = ", ".join(f"{p['port']}/{p['proto']} ({p['service']})" for p in discovered_ports) \
        or "No open ports in scanned range"

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
        f"Findings detected: {finding_count}\n\nAttack-path reasoning:\n{cot}\n\nEvidence:\n{full_raw[:3000]}"
    )
    ai_report = ai_chat([{"role": "system", "content": sys_prompt},
                         {"role": "user", "content": user_prompt}], role="reporter")

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
    return {
        "id": aid, "timestamp": ts, "target_ip": target_ip, "target_name": hostname,
        "profile": profile, "severity": severity, "open_ports": port_summary,
        "ports_list": discovered_ports, "finding_count": finding_count,
        "commands_run": commands_run, "raw_output": full_raw, "ai_report": ai_report,
    }


@app.route("/api/assess", methods=["POST"])
def api_assess():
    """Synchronous assessment (blocks until done). Kept for CLI / compatibility."""
    data = request.get_json(silent=True) or {}
    profile = data.get("profile", "fast_recon")
    if profile not in ALLOWED_PROFILES:
        return jsonify({"error": f"Unknown profile '{profile}'."}), 400
    try:
        rt = scope.resolve(data.get("target", ""))
    except ScopeViolation as exc:
        return jsonify({"error": str(exc)}), 400
    return jsonify(_run_assessment(rt.ip, rt.label, profile))


@app.route("/api/assess/start", methods=["POST"])
def api_assess_start():
    """Enqueue an assessment as a background job; returns a job_id to poll."""
    data = request.get_json(silent=True) or {}
    profile = data.get("profile", "fast_recon")
    if profile not in ALLOWED_PROFILES:
        return jsonify({"error": f"Unknown profile '{profile}'."}), 400
    try:
        rt = scope.resolve(data.get("target", ""))
    except ScopeViolation as exc:
        return jsonify({"error": str(exc)}), 400
    ip, label = rt.ip, rt.label
    job_id = jobs.submit("assessment", {"target": label, "ip": ip, "profile": profile},
                         lambda: _run_assessment(ip, label, profile))
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
    {"pkg": "nmap", "bin": "nmap", "category": "Network Recon", "desc": "Port scanning & service fingerprinting"},
    {"pkg": "exploitdb", "bin": "searchsploit", "category": "Vuln Intel", "desc": "Offline Exploit-DB archive search"},
    {"pkg": "whatweb", "bin": "whatweb", "category": "Web Recon", "desc": "Web technology & CMS fingerprinting"},
    {"pkg": "sslscan", "bin": "sslscan", "category": "TLS Audit", "desc": "SSL/TLS cipher & certificate inspector"},
    {"pkg": "nikto", "bin": "nikto", "category": "Web Audit", "desc": "Web server misconfiguration scanner"},
    {"pkg": "gobuster", "bin": "gobuster", "category": "Web Recon", "desc": "Directory & DNS discovery"},
    {"pkg": "ffuf", "bin": "ffuf", "category": "Web Recon", "desc": "Fast endpoint & parameter fuzzing"},
    {"pkg": "nuclei", "bin": "nuclei", "category": "Vuln Audit", "desc": "Template-based CVE & misconfig scanner"},
    {"pkg": "enum4linux-ng", "bin": "enum4linux-ng", "category": "Host Audit", "desc": "SMB/Samba enumeration"},
    {"pkg": "sqlmap", "bin": "sqlmap", "category": "Web Exploit", "desc": "Automated SQL injection testing"},
    {"pkg": "metasploit-framework", "bin": "msfconsole", "category": "Exploitation", "desc": "Exploit & auxiliary module framework"},
    {"pkg": "httpx-toolkit", "bin": "httpx", "category": "Web Recon", "desc": "Fast HTTP probe & tech detect"},
    {"pkg": "katana", "bin": "katana", "category": "Web Crawl", "desc": "Web spidering engine"},
    {"pkg": "subfinder", "bin": "subfinder", "category": "DNS Recon", "desc": "Passive subdomain discovery"},
    {"pkg": "naabu", "bin": "naabu", "category": "Network Recon", "desc": "Fast SYN/connect port scanner"},
    {"pkg": "masscan", "bin": "masscan", "category": "Network Recon", "desc": "High-speed async port scanner"},
    {"pkg": "gitleaks", "bin": "gitleaks", "category": "Secret Audit", "desc": "Scan for leaked secrets & keys"},
]


@app.route("/api/kali/tools")
def api_kali_tools():
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

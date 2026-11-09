"""Attack-surface knowledge graph.

Builds a node/edge graph from the assessment data and the structured findings
ledger so the operator (and the agent) can reason about the surface as a whole —
hosts, their exposed services, and verified findings/CVEs — instead of one scan
at a time.

Lightweight by design: derived from the existing SQLite tables (no Neo4j).
Node types: scope (root) -> host -> service -> finding, with per-host finding
and severity rollups.
"""

from __future__ import annotations

import json
import sqlite3

_SEV_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "UNKNOWN": 0, "": 0}
_HIGH_VALUE_PORTS = {22, 88, 135, 139, 389, 445, 636, 1433, 3306, 3389, 5432, 6379, 8006, 8443, 9200}


def compute_attack_paths(
    host_ips: set[str],
    surface: dict[str, dict],
    findings_by_host: dict[str, list[dict]],
    targets: dict[str, dict],
) -> list[dict]:
    """Correlate open services, verified findings, and high-value internal
    services into multi-stage risk paths with a 0-100 blast-radius score."""
    paths: list[dict] = []
    for ip in sorted(host_ips):
        surf = surface.get(ip, {})
        h_findings = findings_by_host.get(ip, [])
        if not h_findings:
            continue
        services: list[dict] = []
        if surf.get("services_json"):
            try:
                services = json.loads(surf["services_json"])
            except Exception:
                services = []
        open_ports = {int(s.get("port") or 0) for s in services if s.get("port")}
        verified = [f for f in h_findings if f.get("status") in ("VERIFIED", "AUTH-GATED")]
        top_finding = max(h_findings, key=lambda f: _SEV_RANK.get(f.get("severity", ""), 0))
        top_sev = top_finding.get("severity", "MEDIUM")
        crown_ports = sorted(open_ports & _HIGH_VALUE_PORTS)

        # Calculate blast-radius score (0-100) from severity, verification, and exposed high-value services.
        score = _SEV_RANK.get(top_sev, 1) * 18
        score += min(len(verified) * 10, 20)
        score += min(len(crown_ports) * 6, 18)
        score = min(score, 100)

        hostname = (targets.get(ip, {}).get("hostname")
                    or surf.get("target_name")
                    or f"host-{ip}")
        entry_port = int(top_finding.get("port") or (min(open_ports) if open_ports else 0))
        steps = [
            f"Initial Surface: {hostname} ({ip}:{entry_port})" if entry_port else f"Initial Surface: {hostname} ({ip})",
            f"Weakness: {top_finding['title']} [{top_sev}/{top_finding['status']}]",
        ]
        if crown_ports:
            steps.append(f"Lateral / High-Value Reachability: ports {', '.join(str(p) for p in crown_ports)}")
        else:
            steps.append(f"Host Impact: {len(h_findings)} active finding(s) on {hostname}")

        paths.append({
            "target_ip": ip,
            "hostname": hostname,
            "entry_port": entry_port,
            "primary_finding": top_finding["title"],
            "severity": top_sev,
            "verified_count": len(verified),
            "blast_radius_score": score,
            "steps": steps,
        })
    paths.sort(key=lambda p: p["blast_radius_score"], reverse=True)
    return paths


def build_graph(db_path, cidrs: list[str]) -> dict:
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row

    targets = {r["target_ip"]: dict(r) for r in conn.execute("SELECT * FROM targets").fetchall()}
    surface = {r["target_ip"]: dict(r) for r in conn.execute("SELECT * FROM host_surface").fetchall()}

    # Per-host assessment rollup: worst severity + total findings + count.
    roll: dict[str, dict] = {}
    for r in conn.execute(
        "SELECT target_ip, severity, finding_count FROM assessments"
    ).fetchall():
        ip = r["target_ip"]
        d = roll.setdefault(ip, {"worst": "", "findings": 0, "assessments": 0})
        d["assessments"] += 1
        d["findings"] += int(r["finding_count"] or 0)
        if _SEV_RANK.get(r["severity"], 0) > _SEV_RANK.get(d["worst"], 0):
            d["worst"] = r["severity"]

    # Load structured findings from the ledger if the table exists.
    findings_by_host: dict[str, list[dict]] = {}
    verified_total = 0
    try:
        for fr in conn.execute(
            "SELECT id, target_ip, port, title, category, severity, status FROM findings WHERE status != 'FIXED'"
        ).fetchall():
            fd = dict(fr)
            findings_by_host.setdefault(fd["target_ip"], []).append(fd)
            if fd["status"] in ("VERIFIED", "AUTH-GATED"):
                verified_total += 1
    except Exception:
        pass
    conn.close()

    # Union of hosts seen via discovery, scan, or findings ledger.
    host_ips = set(targets) | set(surface) | set(findings_by_host)

    nodes: list[dict] = []
    edges: list[dict] = []

    root_id = "scope"
    nodes.append({"id": root_id, "type": "scope", "label": ", ".join(cidrs) or "scope"})

    svc_total = 0
    for ip in sorted(host_ips, key=lambda x: tuple(int(o) for o in x.split(".")) if x.count(".") == 3 and all(o.isdigit() for o in x.split(".")) else (0,)):
        surf = surface.get(ip, {})
        tgt = targets.get(ip, {})
        rk = roll.get(ip, {})
        h_findings = findings_by_host.get(ip, [])
        hostname = tgt.get("hostname") or surf.get("target_name") or f"host-{ip}"
        risk = surf.get("risk_level") or (rk.get("worst") or "UNKNOWN")
        for hf in h_findings:
            if _SEV_RANK.get(hf.get("severity", ""), 0) > _SEV_RANK.get(risk, 0):
                risk = hf["severity"]

        host_id = f"host:{ip}"
        nodes.append({
            "id": host_id, "type": "host", "label": hostname, "ip": ip,
            "risk": risk, "worst_severity": rk.get("worst", "") or risk,
            "findings": max(rk.get("findings", 0), len(h_findings)),
            "verified_findings": sum(1 for hf in h_findings if hf["status"] in ("VERIFIED", "AUTH-GATED")),
            "assessments": rk.get("assessments", 0),
            "last_scan": surf.get("last_scan", "Never"),
        })
        edges.append({"source": root_id, "target": host_id})

        services = []
        if surf.get("services_json"):
            try:
                services = json.loads(surf["services_json"])
            except Exception:
                services = []
        svc_ports: set[int] = set()
        for s in services:
            svc_total += 1
            pnum = int(s.get("port") or 0)
            svc_ports.add(pnum)
            svc_id = f"svc:{ip}:{pnum}"
            nodes.append({
                "id": svc_id, "type": "service", "host": ip,
                "label": f"{pnum}/{s.get('service', '')}".strip("/"),
                "port": pnum, "service": s.get("service", ""),
                "banner": s.get("banner", ""),
            })
            edges.append({"source": host_id, "target": svc_id})

        for hf in h_findings[:6]:
            fid = f"finding:{hf['id']}"
            parent_id = f"svc:{ip}:{hf['port']}" if int(hf.get("port") or 0) in svc_ports else host_id
            nodes.append({
                "id": fid, "type": "finding", "host": ip, "port": hf.get("port", 0),
                "label": hf["title"][:48], "severity": hf["severity"], "status": hf["status"],
            })
            edges.append({"source": parent_id, "target": fid})

    attack_paths = compute_attack_paths(host_ips, surface, findings_by_host, targets)
    max_blast = max((p["blast_radius_score"] for p in attack_paths), default=0)

    stats = {
        "hosts": len(host_ips),
        "services": svc_total,
        "scanned_hosts": len(surface),
        "verified_findings": verified_total,
        "critical_hosts": sum(1 for ip in host_ips if _SEV_RANK.get((surface.get(ip, {}).get("risk_level") or roll.get(ip, {}).get("worst") or ""), 0) >= 3),
        "attack_paths": len(attack_paths),
        "max_blast_radius": max_blast,
    }
    return {"nodes": nodes, "edges": edges, "stats": stats, "attack_paths": attack_paths}

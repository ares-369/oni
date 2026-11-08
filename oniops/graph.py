"""Attack-surface knowledge graph.

Builds a node/edge graph from the assessment data so the operator (and, later,
the agent) can reason about the surface as a whole — hosts, their exposed
services, and findings/severity — instead of one scan at a time.

Lightweight by design: derived from the existing SQLite tables (no Neo4j).
Node types: scope (root) -> host -> service, with per-host finding/severity
rollups. Returns plain dicts ready for JSON / a force or layered layout.
"""

from __future__ import annotations

import json
import sqlite3

_SEV_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "UNKNOWN": 0, "": 0}


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
    conn.close()

    # Union of hosts seen via discovery or via a scan.
    host_ips = set(targets) | set(surface)

    nodes: list[dict] = []
    edges: list[dict] = []

    root_id = "scope"
    nodes.append({"id": root_id, "type": "scope", "label": ", ".join(cidrs) or "scope"})

    svc_total = 0
    for ip in sorted(host_ips, key=lambda x: tuple(int(o) for o in x.split(".")) if x.count(".") == 3 and all(o.isdigit() for o in x.split(".")) else (0,)):
        surf = surface.get(ip, {})
        tgt = targets.get(ip, {})
        rk = roll.get(ip, {})
        hostname = tgt.get("hostname") or surf.get("target_name") or f"host-{ip}"
        risk = surf.get("risk_level") or (rk.get("worst") or "UNKNOWN")
        host_id = f"host:{ip}"
        nodes.append({
            "id": host_id, "type": "host", "label": hostname, "ip": ip,
            "risk": risk, "worst_severity": rk.get("worst", ""),
            "findings": rk.get("findings", 0), "assessments": rk.get("assessments", 0),
            "last_scan": surf.get("last_scan", "Never"),
        })
        edges.append({"source": root_id, "target": host_id})

        services = []
        if surf.get("services_json"):
            try:
                services = json.loads(surf["services_json"])
            except Exception:
                services = []
        for s in services:
            svc_total += 1
            svc_id = f"svc:{ip}:{s.get('port')}"
            nodes.append({
                "id": svc_id, "type": "service", "host": ip,
                "label": f"{s.get('port')}/{s.get('service', '')}".strip("/"),
                "port": s.get("port"), "service": s.get("service", ""),
                "banner": s.get("banner", ""),
            })
            edges.append({"source": host_id, "target": svc_id})

    stats = {
        "hosts": len(host_ips),
        "services": svc_total,
        "scanned_hosts": len(surface),
        "critical_hosts": sum(1 for ip in host_ips if _SEV_RANK.get((surface.get(ip, {}).get("risk_level") or roll.get(ip, {}).get("worst") or ""), 0) >= 3),
    }
    return {"nodes": nodes, "edges": edges, "stats": stats}

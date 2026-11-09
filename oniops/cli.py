"""ONIOPS command-line interface & CI/CD security gate runner.

Usage examples:
  python -m oniops                                  # start Waitress WebUI server (default)
  python -m oniops serve                            # start Waitress WebUI server
  python -m oniops version                          # print version
  python -m oniops doctor                           # run self-diagnostics (DB, scope, playbooks, runner)
  python -m oniops whitebox ./repo --fail-on HIGH --sarif results.sarif
  python -m oniops assess 10.0.0.150 --profile fast_recon
  python -m oniops retest --all --target 10.0.0.150
  python -m oniops backup /tmp/oniops-backup.sqlite
  python -m oniops restore /tmp/oniops-backup.sqlite
  python -m oniops findings --target 10.0.0.150
  python -m oniops diff 2
  python -m oniops playbooks
"""
from __future__ import annotations

import argparse
import json
import os
import sqlite3
import sys
from pathlib import Path

from . import __version__
from .aisec import load_yaml_probes
from .benchmark import run_benchmark_suite
from .config import get_config
from .findings import FindingsLedger, backup_sqlite, diff_assessments, restore_sqlite
from .greybox import analyze_source_code
from .kali import KaliRunner
from .playbooks import load_playbooks
from .scope import Scope

_SEV_RANK = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}


def _default_db_path() -> Path:
    env_db = os.getenv("ONIOPS_DB_PATH", "").strip()
    if env_db:
        return Path(env_db)
    return Path(__file__).resolve().parent.parent / "data" / "oniops.sqlite"


def build_whitebox_sarif(scan_res: dict) -> dict:
    """Convert `analyze_source_code` sinks into a GitHub Code Scanning SARIF v2.1.0 document."""
    results = []
    for idx, s in enumerate(scan_res.get("sinks") or [], start=1):
        sev = str(s.get("severity") or "MEDIUM").upper()
        level = "error" if sev in ("HIGH", "CRITICAL") else "warning"
        results.append({
            "ruleId": f"ONIOPS-WB-{idx:03d}",
            "level": level,
            "message": {"text": f"{s.get('type')}: {s.get('snippet', '')}"},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": str(s.get("file") or "snippet")},
                    "region": {"startLine": int(s.get("line") or 1)},
                }
            }],
        })
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "ONIOPS White-Box & CI Security Gate",
                    "version": __version__,
                }
            },
            "results": results,
        }],
    }


def run_doctor(db_override: str = "", check_runner: bool = False) -> dict:
    """Run deterministic self-diagnostics on ONIOPS config, SQLite DB, playbooks, and runner."""
    cfg = get_config()
    scope = Scope(cfg)
    db_path = Path(db_override) if db_override else _default_db_path()
    db_path.parent.mkdir(parents=True, exist_ok=True)
    FindingsLedger(db_path)

    with sqlite3.connect(str(db_path)) as con:
        integrity = con.execute("PRAGMA integrity_check").fetchone()[0]

    pbs = load_playbooks()
    ai_probes = load_yaml_probes()
    checks = {
        "version": __version__,
        "scope_cidrs": scope.cidrs,
        "db_path": str(db_path),
        "db_integrity": integrity,
        "playbooks_loaded": len(pbs),
        "ai_yaml_probes_loaded": len(ai_probes),
        "auth_mode": cfg.auth.mode,
    }
    if check_runner:
        runner = KaliRunner(cfg.kali, scope, cfg)
        ping = runner.run(["echo", "oniops-doctor-ok"], timeout=10)
        checks["runner_ok"] = bool(ping.ok and "oniops-doctor-ok" in (ping.out or ""))
    checks["ok"] = (integrity == "ok" and len(scope.cidrs) > 0 and len(pbs) > 0)
    return checks


def cli_main(argv: list[str] | None = None) -> int:
    args_list = list(sys.argv[1:] if argv is None else argv)
    if not args_list or args_list[0] == "serve":
        from .server import main as serve_main
        serve_main()
        return 0

    parser = argparse.ArgumentParser(prog="oniops", description="ONIOPS — Offensive Neural Intelligence CLI & CI Gate")
    sub = parser.add_subparsers(dest="cmd")

    sub.add_parser("version", help="Print ONIOPS version")
    sub.add_parser("playbooks", help="List loaded YAML playbooks and AI safety probe packs")

    doc = sub.add_parser("doctor", help="Run self-diagnostics on config, scope, SQLite DB, and playbooks")
    doc.add_argument("--db", default="", help="Path to oniops.sqlite")
    doc.add_argument("--check-runner", action="store_true", help="Also test SSH/local attack runner connectivity")

    wb = sub.add_parser("whitebox", help="Run white-box source/sink analysis & CI security gate")
    wb.add_argument("path", help="Source directory, file path, or inline snippet")
    wb.add_argument("--fail-on", default="", choices=["", "LOW", "MEDIUM", "HIGH", "CRITICAL"],
                    help="Exit with code 1 if any finding meets or exceeds this severity")
    wb.add_argument("--sarif", default="", help="Write SARIF v2.1.0 output to this file path")
    wb.add_argument("--json", action="store_true", help="Print raw JSON output")

    fl = sub.add_parser("findings", help="List findings from the SQLite Evidence Ledger")
    fl.add_argument("--target", default="", help="Filter by target IP")
    fl.add_argument("--db", default="", help="Path to oniops.sqlite")
    fl.add_argument("--verified-only", action="store_true",
                    help="Only include findings with status == VERIFIED")
    fl.add_argument("--fail-on", default="", choices=["", "LOW", "MEDIUM", "HIGH", "CRITICAL"],
                    help="Exit with code 1 if any returned finding meets or exceeds this severity")

    rt = sub.add_parser("retest", help="Run zero-token deterministic PoC retest on stored findings")
    rt.add_argument("--id", type=int, default=0, help="Specific finding ID to retest")
    rt.add_argument("--all", action="store_true", help="Retest all stored findings")
    rt.add_argument("--target", default="", help="Filter batch retest by target IP")
    rt.add_argument("--db", default="", help="Path to oniops.sqlite")

    bk = sub.add_parser("backup", help="Create an online SQLite backup of oniops.sqlite")
    bk.add_argument("destination", help="Destination backup .sqlite path")
    bk.add_argument("--db", default="", help="Source oniops.sqlite path")

    rs = sub.add_parser("restore", help="Verify and restore a SQLite backup into oniops.sqlite")
    rs.add_argument("source", help="Backup .sqlite file path to restore from")
    rs.add_argument("--db", default="", help="Target oniops.sqlite path")

    ass = sub.add_parser("assess", help="Run a scoped assessment from the CLI")
    ass.add_argument("target", help="In-scope target IP or hostname")
    ass.add_argument("--profile", default="fast_recon", help="Assessment profile or playbook ID")
    ass.add_argument("--auth-header", default="", help="Optional Grey-Box auth header")
    ass.add_argument("--low-priv-header", default="", help="Optional low-privilege role header for BOLA/BFLA diff")

    df = sub.add_parser("diff", help="Compare an assessment against its previous baseline")
    df.add_argument("assessment_id", type=int, help="Assessment ID to diff")
    df.add_argument("--db", default="", help="Path to oniops.sqlite")

    bm = sub.add_parser("benchmark", help="Run deterministic verification & false-positive benchmark suite")
    bm.add_argument("--json", action="store_true", help="Print raw JSON benchmark results")

    ns = parser.parse_args(args_list)

    if ns.cmd == "version":
        print(f"ONIOPS {__version__}")
        return 0

    if ns.cmd == "doctor":
        res = run_doctor(db_override=ns.db, check_runner=ns.check_runner)
        print(json.dumps(res, indent=2))
        return 0 if res.get("ok") else 1

    if ns.cmd == "playbooks":
        pbs = load_playbooks()
        ai_probes = load_yaml_probes()
        print(json.dumps({
            "playbooks": list(pbs.values()),
            "ai_yaml_probes": [
                {"id": p["id"], "name": p["name"], "severity": p["severity"], "source": p.get("source", "")}
                for p in ai_probes
            ],
        }, indent=2))
        return 0

    if ns.cmd == "whitebox":
        res = analyze_source_code(ns.path)
        if ns.sarif:
            sarif_doc = build_whitebox_sarif(res)
            Path(ns.sarif).write_text(json.dumps(sarif_doc, indent=2), encoding="utf-8")
        if ns.json:
            print(json.dumps(res, indent=2))
        else:
            print(f"[ONIOPS White-Box] Scanned {res['files_scanned']} file(s): "
                  f"{len(res['routes'])} route(s), {len(res['sinks'])} sink(s).")
            for s in res["sinks"]:
                print(f"  - [{s['severity']}] {s['type']} ({s['file']}:{s['line']}): {s['snippet']}")
        if ns.fail_on:
            threshold = _SEV_RANK.get(ns.fail_on.upper(), 99)
            if any(_SEV_RANK.get(str(s.get("severity", "")).upper(), 0) >= threshold for s in res["sinks"]):
                return 1
        return 0

    if ns.cmd == "findings":
        db_path = ns.db or _default_db_path()
        ledger = FindingsLedger(db_path)
        items = ledger.list_findings(target_ip=ns.target)
        if ns.verified_only:
            items = [f for f in items if str(f.get("status", "")).upper() == "VERIFIED"]
        print(json.dumps({"findings": items}, indent=2))
        if ns.fail_on:
            threshold = _SEV_RANK.get(ns.fail_on.upper(), 99)
            if any(_SEV_RANK.get(str(f.get("severity", "")).upper(), 0) >= threshold for f in items):
                return 1
        return 0

    if ns.cmd == "retest":
        cfg = get_config()
        scope = Scope(cfg)
        db_path = ns.db or _default_db_path()
        ledger = FindingsLedger(db_path)
        runner = KaliRunner(cfg.kali, scope, cfg)
        if ns.id:
            res = ledger.retest(ns.id, runner, scope)
            print(json.dumps(res, indent=2))
            return 0
        res = ledger.retest_all(runner, scope, target_ip=ns.target)
        print(json.dumps(res, indent=2))
        return 0

    if ns.cmd == "backup":
        db_path = ns.db or _default_db_path()
        print(json.dumps(backup_sqlite(db_path, ns.destination), indent=2))
        return 0

    if ns.cmd == "restore":
        db_path = ns.db or _default_db_path()
        print(json.dumps(restore_sqlite(ns.source, db_path), indent=2))
        return 0

    if ns.cmd == "assess":
        import webui
        rt = webui.scope.resolve(ns.target)
        res = webui._run_assessment(
            rt.ip, rt.label, ns.profile,
            auth_header=ns.auth_header, low_priv_header=ns.low_priv_header,
        )
        print(json.dumps(res, indent=2))
        return 0

    if ns.cmd == "diff":
        db_path = ns.db or _default_db_path()
        print(json.dumps(diff_assessments(db_path, ns.assessment_id), indent=2))
        return 0

    if ns.cmd == "benchmark":
        res = run_benchmark_suite()
        if ns.json:
            print(json.dumps(res, indent=2))
        else:
            m = res["metrics"]
            print(f"[ONIOPS Benchmark] {res['passed']}/{res['total_cases']} passed | "
                  f"Recall={m['recall']:.2f} | FPR={m['false_positive_rate']:.2f} | "
                  f"Precision={m['precision']:.2f} | F1={m['f1_score']:.2f}")
            for c in res["cases"]:
                mark = "PASS" if c["passed"] else "FAIL"
                print(f"  [{mark}] {c['id']} ({c['domain']}): {c['name']} -> {c['actual']}")
        return 0 if res["failed"] == 0 else 1

    parser.print_help()
    return 1

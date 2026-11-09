"""ONIOPS command-line interface & CI/CD security gate runner.

Usage examples:
  python -m oniops                                  # start Waitress WebUI server (default)
  python -m oniops serve                            # start Waitress WebUI server
  python -m oniops version                          # print version
  python -m oniops whitebox ./repo --fail-on HIGH --sarif results.sarif
  python -m oniops findings --target 10.0.0.150
  python -m oniops diff 2
  python -m oniops playbooks
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import __version__
from .aisec import load_yaml_probes
from .config import get_config
from .findings import FindingsLedger, diff_assessments
from .greybox import analyze_source_code
from .playbooks import load_playbooks

_SEV_RANK = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}


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

    wb = sub.add_parser("whitebox", help="Run white-box source/sink analysis & CI security gate")
    wb.add_argument("path", help="Source directory, file path, or inline snippet")
    wb.add_argument("--fail-on", default="", choices=["", "LOW", "MEDIUM", "HIGH", "CRITICAL"],
                    help="Exit with code 1 if any finding meets or exceeds this severity")
    wb.add_argument("--sarif", default="", help="Write SARIF v2.1.0 output to this file path")
    wb.add_argument("--json", action="store_true", help="Print raw JSON output")

    fl = sub.add_parser("findings", help="List findings from the SQLite Evidence Ledger")
    fl.add_argument("--target", default="", help="Filter by target IP")
    fl.add_argument("--db", default="", help="Path to oniops.sqlite")

    df = sub.add_parser("diff", help="Compare an assessment against its previous baseline")
    df.add_argument("assessment_id", type=int, help="Assessment ID to diff")
    df.add_argument("--db", default="", help="Path to oniops.sqlite")

    ns = parser.parse_args(args_list)

    if ns.cmd == "version":
        print(f"ONIOPS {__version__}")
        return 0

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
        db_path = ns.db or get_config().db_path
        ledger = FindingsLedger(db_path)
        print(json.dumps({"findings": ledger.list_findings(target_ip=ns.target)}, indent=2))
        return 0

    if ns.cmd == "diff":
        db_path = ns.db or get_config().db_path
        print(json.dumps(diff_assessments(db_path, ns.assessment_id), indent=2))
        return 0

    parser.print_help()
    return 1

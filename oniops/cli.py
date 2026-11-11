"""OniOps command-line interface & CI/CD security gate runner.

Usage examples:
  python -m oniops                                  # start Waitress WebUI server (default)
  python -m oniops serve                            # start Waitress WebUI server
  python -m oniops demo                             # one-minute practice run, no config needed
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
  python -m oniops crawl https://app.example.test   # bounded, scoped browser discovery
  python -m oniops container-scan app:latest        # scan a local attack-host image offline
  python -m oniops cloud-audit aws --account-id 123456789012  # read-only AWS account checks
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
from .benchmark import run_selftest
from .config import get_config
from .findings import FindingsLedger, backup_sqlite, diff_assessments, restore_sqlite, usable_signing_key
from .greybox import analyze_source_code
from .kali import KaliRunner
from .playbooks import load_playbooks
from .scope import Scope, ScopeViolation

_SEV_RANK = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}

SIGNING_KEY_WARNING = ("No persistent signing key (ONIOPS_SECRET_KEY / auth.secret_key): assessment "
                       "manifests and webhook alerts will be unsigned.")


_REPO_ROOT = Path(__file__).resolve().parent.parent
_NEEDS_CHECKOUT = ("The web app (webui.py, templates/, static/) lives in the source checkout, not in the "
                   "installed package. Run OniOps from a checkout of the repository: `pip install -e .` "
                   "inside it, or `python -m oniops` from its top-level folder.")


def _ensure_checkout_importable() -> None:
    """Make ``import webui`` work when ``oniops`` is launched through the console script.

    ``python -m oniops`` puts the working directory on sys.path; the ``oniops`` entry
    point does not, so ``webui.py`` at the checkout root would not be found.
    """
    if (_REPO_ROOT / "webui.py").exists() and str(_REPO_ROOT) not in sys.path:
        sys.path.insert(0, str(_REPO_ROOT))


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
                    "name": "OniOps White-Box & CI Security Gate",
                    "version": __version__,
                }
            },
            "results": results,
        }],
    }


def run_doctor(db_override: str = "", check_runner: bool = False) -> dict:
    """Run deterministic self-diagnostics on OniOps config, SQLite DB, playbooks, and runner."""
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
    # Warnings do not fail the check; they flag a weaker but working setup.
    warnings: list[str] = []
    signing_key = usable_signing_key(cfg.auth.secret_key or os.getenv("ONIOPS_SECRET_KEY", ""))
    checks["signing_key_set"] = bool(signing_key)
    if not signing_key:
        warnings.append(SIGNING_KEY_WARNING)
    checks["warnings"] = warnings
    checks["ok"] = (integrity == "ok" and len(scope.cidrs) > 0 and len(pbs) > 0
                    and (not check_runner or checks.get("runner_ok", False)))
    return checks


def cli_main(argv: list[str] | None = None) -> int:
    args_list = list(sys.argv[1:] if argv is None else argv)
    if not args_list:
        return _serve()

    parser = argparse.ArgumentParser(
        prog="oniops", description="OniOps — Offensive Neural Intelligence CLI & CI Gate",
        epilog="With no subcommand, `oniops` starts the web UI (same as `oniops serve`). "
               "New here? Run `oniops demo` first: it needs no config. "
               "Config is read from $ONIOPS_CONFIG, ./config.yaml or <checkout>/config.yaml.")
    parser.add_argument("-V", "--version", action="version", version=f"OniOps {__version__}")
    sub = parser.add_subparsers(dest="cmd")

    sub.add_parser("serve", help="Start the web UI (the default with no subcommand); "
                                 "address and port come from config.yaml (oniops.bind_host / oniops.bind_port)")

    sub.add_parser("version", help="Print OniOps version")
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
    rt.add_argument("--all", action="store_true", help="Retest all stored findings (needed unless --id is given)")
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

    for name in ("selftest", "benchmark"):   # "benchmark" kept as an alias for old scripts
        st = sub.add_parser(name, help=("Run the validator self-test" if name == "selftest" else
                                       "Run the validator self-test or labeled live fixture evaluation"))
        st.add_argument("--json", action="store_true", help="Print raw JSON results")
        if name == "benchmark":
            st.add_argument("--demo-evaluation", action="store_true",
                            help="Run the real assessment pipeline against the bundled ground-truth target")
            st.add_argument("--output", default="", help="Write benchmark JSON to this path")
            st.add_argument("--suite", default="",
                            help="Score an existing assessment against a labeled public-app suite "
                                 "(crapi, juice_shop, vampi, or a YAML path)")
            st.add_argument("--list-suites", action="store_true", help="List bundled benchmark suites")
            st.add_argument("--target", default="", help="Target IP whose ledger findings are scored")
            st.add_argument("--db", default="", help="Path to oniops.sqlite")
            st.add_argument("--since", default="",
                            help="Only score findings last seen at/after this ISO timestamp")
            st.add_argument("--triage", default="",
                            help="YAML mapping unlabeled finding ids to true/false (real bug or not)")
            st.add_argument("--profile-label", default="", help="Profile name recorded in the result")
            st.add_argument("--model-label", default="", help="Model name recorded in the result")
            st.add_argument("--markdown", action="store_true", help="Print a README-ready table row")

    dm = sub.add_parser("demo", help="Practice run against a bundled loopback target (no config, attack host or LLM needed)")
    dm.add_argument("--db", default="",
                    help="Keep the DEMO ledger at this path (default: a temp file, deleted afterwards). "
                         "Must not be the real ledger.")
    dm.add_argument("--no-fixed", action="store_true", help="Skip the 'target fixed -> retest' step")

    cr = sub.add_parser("crawl", help="Render and discover an in-scope web app without submitting forms")
    cr.add_argument("start_url", help="HTTP(S) URL resolving inside scope.allowed_cidrs")
    cr.add_argument("--max-pages", type=int, default=50, help="Page cap (1-200)")
    cr.add_argument("--max-seconds", type=int, default=90, help="Wall-clock cap (5-300 seconds)")
    cr.add_argument("--auth-header", default="", help="Optional header, sent only to the start URL origin")
    cr.add_argument("--storage-state", default="", help="Optional Playwright storage-state JSON for authenticated browsing")
    cr.add_argument("--json", action="store_true", help="Print machine-readable results")
    cr.add_argument("--output", default="", help="Write JSON results to this path")

    cs = sub.add_parser("container-scan", help="Scan a container image already present on the attack host")
    cs.add_argument("image", help="Local Docker image name or digest (the image is never pulled)")
    cs.add_argument("--output", default="", help="Write Trivy JSON results to this path")
    cs.add_argument("--fail-on", default="", choices=["", "LOW", "MEDIUM", "HIGH", "CRITICAL"],
                    help="Exit with code 1 when any finding meets or exceeds this severity")

    ca = sub.add_parser("cloud-audit", help="Run read-only AWS IAM, security-group and S3 checks")
    ca.add_argument("provider", choices=["aws"], help="Cloud provider to audit")
    ca.add_argument("--account-id", required=True, help="Expected 12-digit AWS account ID; STS is checked first")
    ca.add_argument("--profile", default="default", help="Local AWS credential profile")
    ca.add_argument("--region", default="us-east-1", help="AWS region for regional checks")
    ca.add_argument("--password-baseline", default="aws_cis", choices=["aws_cis", "nist_800_63b4"],
                    help="Password policy profile; NIST 800-63B-4 does not require composition or periodic rotation")
    ca.add_argument("--output", default="", help="Write JSON results to this path")
    ca.add_argument("--fail-on", default="", choices=["", "LOW", "MEDIUM", "HIGH", "CRITICAL"],
                    help="Exit with code 1 when any finding meets or exceeds this severity")

    ns = parser.parse_args(args_list)

    try:
        return _dispatch(ns, parser)
    except FileNotFoundError as exc:
        if "config.yaml" not in str(exc):
            raise
        print(f"[OniOps] error: {exc}", file=sys.stderr)
        print("[OniOps] Tip: `oniops demo` runs without any config; see README.md (Quick start) "
              "to create one.", file=sys.stderr)
        return 2
    except sqlite3.Error as exc:
        print(f"[OniOps] database error: {exc}", file=sys.stderr)
        return 2
    except (PermissionError, ScopeViolation) as exc:
        print(f"[OniOps] error: {exc}", file=sys.stderr)
        return 2


def _serve() -> int:
    _ensure_checkout_importable()
    from .server import main as serve_main
    try:
        serve_main()
    except ModuleNotFoundError as exc:
        if exc.name != "webui":
            raise
        print(f"[OniOps] error: {_NEEDS_CHECKOUT}", file=sys.stderr)
        return 2
    return 0


def _dispatch(ns, parser) -> int:
    if ns.cmd == "serve":
        return _serve()

    if ns.cmd == "demo":
        from .demo import run_demo
        demo_db = None
        if ns.db:
            demo_db = Path(ns.db).expanduser().resolve()
            real_db = _default_db_path().expanduser().resolve()
            if demo_db == real_db or demo_db.name == "oniops.sqlite":
                print("[DEMO] Refusing to write demo findings into the real ledger "
                      f"({demo_db}). Pick a separate file, e.g. --db /tmp/oniops-demo.sqlite.",
                      file=sys.stderr)
                return 2
        return run_demo(db_path=demo_db, show_fixed=not ns.no_fixed)

    if ns.cmd == "crawl":
        from .browser import crawl_web_app
        cfg = get_config()
        try:
            result = crawl_web_app(ns.start_url, Scope(cfg), max_pages=ns.max_pages,
                                   max_seconds=ns.max_seconds, auth_header=ns.auth_header,
                                   storage_state=ns.storage_state)
        except (ValueError, RuntimeError, ScopeViolation) as exc:
            print(f"[OniOps crawl] {exc}", file=sys.stderr)
            return 2
        serialized = json.dumps(result, indent=2)
        if ns.output:
            Path(ns.output).expanduser().write_text(serialized + "\n", encoding="utf-8")
        if ns.json or not ns.output:
            print(serialized)
        else:
            print(f"[OniOps crawl] visited {result['pages_visited']} page(s); "
                  f"captured {len(result['api_requests'])} API request(s); "
                  f"blocked {len(result['blocked_requests'])} request(s).")
        return 0

    if ns.cmd == "container-scan":
        from .artifact_scan import scan_local_container_image
        cfg = get_config()
        try:
            result = scan_local_container_image(ns.image, KaliRunner(cfg.kali, Scope(cfg), cfg))
        except (ValueError, RuntimeError) as exc:
            print(f"[OniOps container scan] {exc}", file=sys.stderr)
            return 2
        serialized = json.dumps(result, indent=2)
        if ns.output:
            Path(ns.output).expanduser().write_text(serialized + "\n", encoding="utf-8")
        else:
            print(serialized)
        if ns.fail_on:
            severity_rank = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
            threshold = severity_rank[ns.fail_on]
            if any(severity_rank.get(k, 0) >= threshold and count
                   for k, count in result["counts_by_severity"].items()):
                return 1
        return 0

    if ns.cmd == "cloud-audit":
        from .cloud_audit import audit_aws_account
        try:
            result = audit_aws_account(ns.account_id, profile=ns.profile, region=ns.region,
                                       password_baseline=ns.password_baseline)
        except (ValueError, RuntimeError, PermissionError) as exc:
            print(f"[OniOps cloud audit] {exc}", file=sys.stderr)
            return 2
        serialized = json.dumps(result, indent=2)
        if ns.output:
            Path(ns.output).expanduser().write_text(serialized + "\n", encoding="utf-8")
        else:
            print(serialized)
        if ns.fail_on:
            severity_rank = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
            threshold = severity_rank[ns.fail_on]
            if any(severity_rank.get(str(item.get("severity", "")).upper(), 0) >= threshold
                   for item in result["findings"]):
                return 1
        return 0

    if ns.cmd == "version":
        print(f"OniOps {__version__}")
        return 0

    if ns.cmd == "doctor":
        res = run_doctor(db_override=ns.db, check_runner=ns.check_runner)
        for w in res.get("warnings") or []:
            print(f"[OniOps][WARNING] {w}", file=sys.stderr)
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
            print(f"[OniOps White-Box] Scanned {res['files_scanned']} file(s): "
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
        if not ns.id and not ns.all:
            print("error: retest needs --id N (one finding) or --all [--target IP] (every stored finding)",
                  file=sys.stderr)
            return 2
        db_path = ns.db or _default_db_path()
        ledger = FindingsLedger(db_path)
        runner = KaliRunner(cfg.kali, scope, cfg)
        if ns.id:
            try:
                res = ledger.retest(ns.id, runner, scope)
            except ValueError as exc:
                print(f"error: {exc}", file=sys.stderr)
                return 2
            print(json.dumps(res, indent=2))
            return 0
        res = ledger.retest_all(runner, scope, target_ip=ns.target)
        print(json.dumps(res, indent=2))
        return 0

    if ns.cmd == "backup":
        db_path = ns.db or _default_db_path()
        try:
            print(json.dumps(backup_sqlite(db_path, ns.destination), indent=2))
        except (OSError, ValueError) as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2
        return 0

    if ns.cmd == "restore":
        db_path = ns.db or _default_db_path()
        try:
            print(json.dumps(restore_sqlite(ns.source, db_path), indent=2))
        except (FileNotFoundError, ValueError) as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2
        return 0

    if ns.cmd == "assess":
        _ensure_checkout_importable()
        try:
            import webui
        except ModuleNotFoundError as exc:
            if exc.name != "webui":
                raise
            print(f"[OniOps] error: {_NEEDS_CHECKOUT}", file=sys.stderr)
            return 2
        known = sorted(webui.ALLOWED_PROFILES | set(webui.PLAYBOOKS))
        if ns.profile not in known:
            print(f"error: unknown profile '{ns.profile}'. Choose one of: {', '.join(known)}", file=sys.stderr)
            return 2
        try:
            rt = webui.scope.resolve(ns.target)
            res = webui._run_assessment(
                rt.ip, rt.label, ns.profile,
                auth_header=ns.auth_header, low_priv_header=ns.low_priv_header,
            )
        except (ScopeViolation, ValueError, PermissionError, FileNotFoundError) as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2
        print(json.dumps(res, indent=2))
        return 0

    if ns.cmd == "diff":
        db_path = ns.db or _default_db_path()
        try:
            print(json.dumps(diff_assessments(db_path, ns.assessment_id), indent=2))
        except sqlite3.OperationalError as exc:
            if "no such table" not in str(exc):
                raise
            print(f"error: no assessments recorded in {db_path} yet (run an assessment first, "
                  "or pass --db PATH to the ledger that has it).", file=sys.stderr)
            return 2
        except ValueError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2
        return 0

    if ns.cmd in ("selftest", "benchmark"):
        if ns.cmd == "benchmark" and ns.list_suites:
            from .bench_harness import list_suites
            for s in list_suites():
                print(f"{s['id']:<12} v{s['version']}  {s['name']}  "
                      f"({s['positives']} labeled bugs, {s['negatives']} negative checks)")
            return 0
        if ns.cmd == "benchmark" and ns.suite:
            from .bench_harness import MARKDOWN_HEADER, SuiteError, markdown_row, run_suite
            if not ns.target:
                print("error: --suite needs --target <ip> (the assessed lab target)", file=sys.stderr)
                return 2
            try:
                res = run_suite(ns.suite, ns.db or _default_db_path(), ns.target, since=ns.since,
                                triage_path=ns.triage, profile=ns.profile_label, model=ns.model_label)
            except (SuiteError, OSError) as exc:
                print(f"error: {exc}", file=sys.stderr)
                return 2
            serialized = json.dumps(res, indent=2)
            if ns.output:
                Path(ns.output).expanduser().write_text(serialized + "\n", encoding="utf-8")
            if ns.markdown:
                print(MARKDOWN_HEADER)
                print(markdown_row(res))
            elif ns.json or not ns.output:
                print(serialized)
            m = res["metrics"]
            if m["needs_triage"]:
                print(f"note: {m['needs_triage']} verified finding(s) match no label; "
                      "triage them with --triage to get a final precision", file=sys.stderr)
            return 0
        if ns.cmd == "benchmark" and ns.demo_evaluation:
            from .evaluation import run_demo_evaluation
            res = run_demo_evaluation()
            serialized = json.dumps(res, indent=2)
            if ns.output:
                Path(ns.output).expanduser().write_text(serialized + "\n", encoding="utf-8")
            if ns.json or not ns.output:
                print(serialized)
            else:
                m = res["metrics"]
                print(f"[OniOps demo benchmark] precision={m['precision']:.3f} "
                      f"recall={m['recall']:.3f} F1={m['f1']:.3f} "
                      f"TP={m['true_positive']} FP={m['false_positive']} FN={m['false_negative']}")
            return 0 if res["metrics"]["false_negative"] == 0 and res["metrics"]["false_positive"] == 0 else 1
        res = run_selftest()
        if ns.json:
            print(json.dumps(res, indent=2))
        else:
            print(f"[OniOps validator self-test] {res['passed']}/{res['total_cases']} checks passed")
            for k in res["by_kind"].values():
                print(f"  {k['label']}: {k['passed']}/{k['total']}")
            print(f"  Note: {res['note']}")
            for c in res["cases"]:
                mark = "PASS" if c["passed"] else "FAIL"
                print(f"  [{mark}] {c['id']} ({c['domain']}): {c['name']} -> {c['actual']}")
        return 0 if res["failed"] == 0 else 1

    parser.print_help()
    return 1

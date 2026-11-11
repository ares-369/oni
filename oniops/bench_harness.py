"""Labeled benchmark harness for public, intentionally vulnerable applications.

Scores the findings an ordinary OniOps assessment wrote to the ledger against a
labeled suite (crAPI, OWASP Juice Shop, VAmPI, ...). Running the assessment and
scoring it are separate steps, so any profile, model or agent setting can be
benchmarked the same way:

    docker compose -f benchmarks/crapi/docker-compose.yml up -d   # your lab, in scope
    python -m oniops assess <crapi-ip> --profile web_app_pt ...
    python -m oniops benchmark --suite crapi --target <crapi-ip> --markdown

Honesty rules built into the scoring:
  * Only VERIFIED findings count as detections. Unverified matches are reported
    but do not count as true positives.
  * Each finding can satisfy at most one label (one-to-one matching).
  * Public targets contain more bugs than any label set. A finding that matches
    no label is not silently called a false positive or a true positive. It is
    listed under ``needs_triage``. Precision is reported as a range until a
    triage file classifies those findings (``--triage``).
  * Results always carry the OniOps version, suite version, profile and model
    so a published number can be reproduced.
"""
from __future__ import annotations

import re
import time
from pathlib import Path

import yaml

from . import __version__
from .findings import FindingsLedger

SUITES_DIR = Path(__file__).with_name("bench_suites")


class SuiteError(ValueError):
    """Raised for malformed suite or triage files."""


def list_suites(suites_dir: Path = SUITES_DIR) -> list[dict]:
    out = []
    for path in sorted(suites_dir.glob("*.yaml")):
        s = load_suite(path)
        out.append({"id": s["id"], "name": s["name"], "version": s["version"],
                    "positives": len(s["positives"]), "negatives": len(s["negatives"])})
    return out


def _compile(case: dict, where: str) -> dict:
    if not isinstance(case, dict) or not case.get("id"):
        raise SuiteError(f"{where}: every case needs an 'id'")
    pats = case.get("match") or {}
    if not isinstance(pats, dict) or not pats:
        raise SuiteError(f"{where}/{case['id']}: 'match' must define at least one pattern")
    compiled = {}
    for key in ("title", "evidence", "any"):
        if key in pats:
            try:
                compiled[key] = re.compile(str(pats[key]), re.IGNORECASE)
            except re.error as exc:
                raise SuiteError(f"{where}/{case['id']}: bad {key} regex: {exc}") from exc
    unknown = set(pats) - {"title", "evidence", "any", "category"}
    if unknown:
        raise SuiteError(f"{where}/{case['id']}: unknown match keys {sorted(unknown)}")
    cats = pats.get("category") or []
    if isinstance(cats, str):
        cats = [cats]
    return {**case, "_re": compiled, "_categories": {str(c).lower() for c in cats}}


def load_suite(ref: str | Path, suites_dir: Path = SUITES_DIR) -> dict:
    """Load a suite by id (``crapi``) or by path to a YAML file."""
    path = Path(ref)
    if not path.suffix:
        path = suites_dir / f"{ref}.yaml"
    if not path.is_file():
        raise SuiteError(f"suite not found: {ref}")
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    for key in ("id", "name", "version"):
        if not data.get(key):
            raise SuiteError(f"{path.name}: missing '{key}'")
    positives = [_compile(c, path.name) for c in data.get("positives") or []]
    negatives = [_compile(c, path.name) for c in data.get("negatives") or []]
    ids = [c["id"] for c in positives + negatives]
    if len(ids) != len(set(ids)):
        raise SuiteError(f"{path.name}: duplicate case ids")
    if not positives:
        raise SuiteError(f"{path.name}: no positive cases")
    return {**data, "positives": positives, "negatives": negatives,
            "informational": [re.compile(p, re.IGNORECASE) for p in data.get("informational") or []],
            "_path": str(path)}


def _matches(case: dict, finding: dict) -> bool:
    title = str(finding.get("title") or "")
    evidence = str(finding.get("evidence") or "")
    cats = case["_categories"]
    if cats and str(finding.get("category") or "").lower() not in cats:
        return False
    rx = case["_re"]
    if "title" in rx and not rx["title"].search(title):
        return False
    if "evidence" in rx and not rx["evidence"].search(evidence):
        return False
    if "any" in rx and not rx["any"].search(f"{title}\n{evidence}"):
        return False
    return bool(rx) or bool(cats)


def _verified(finding: dict) -> bool:
    return str(finding.get("status") or "").upper() == "VERIFIED"


def load_triage(path: str | Path | None) -> dict[int, bool]:
    """Triage file: ``{findings: {<finding id>: true|false}}`` (true = real bug)."""
    if not path:
        return {}
    data = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
    raw = data.get("findings") or {}
    if not isinstance(raw, dict):
        raise SuiteError("triage file: 'findings' must map finding id -> true/false")
    out = {}
    for k, v in raw.items():
        if not isinstance(v, bool):
            raise SuiteError(f"triage file: finding {k} must be true or false")
        out[int(k)] = v
    return out


def score(suite: dict, findings: list[dict], triage: dict[int, bool] | None = None) -> dict:
    """Score ledger findings against a suite. Pure function; no I/O."""
    triage = triage or {}
    assigned: set[int] = set()
    positives = []
    # Labels with fewer candidate findings pick first, so a broad label cannot
    # steal the only finding a narrow label could use.
    order = sorted(suite["positives"],
                   key=lambda c: sum(1 for f in findings if _verified(f) and _matches(c, f)))
    by_id = {}
    for case in order:
        cands = [i for i, f in enumerate(findings) if _matches(case, f)]
        chosen = next((i for i in cands if i not in assigned and _verified(findings[i])), None)
        if chosen is not None:
            assigned.add(chosen)
        by_id[case["id"]] = {
            "case_id": case["id"],
            "title": case.get("title", ""),
            "category": case.get("owasp", ""),
            "detected": chosen is not None,
            "matched_finding": findings[chosen].get("id") if chosen is not None else None,
            "unverified_matches": [findings[i].get("id") for i in cands
                                   if not _verified(findings[i]) and i not in assigned],
        }
    positives = [by_id[c["id"]] for c in suite["positives"]]

    negatives = []
    fp_from_negatives: set[int] = set()
    for case in suite["negatives"]:
        hits = [i for i, f in enumerate(findings)
                if _verified(f) and i not in assigned and _matches(case, f)]
        fp_from_negatives.update(hits)
        negatives.append({"case_id": case["id"], "title": case.get("title", ""),
                          "false_alarm": bool(hits),
                          "findings": [findings[i].get("id") for i in hits]})

    informational, needs_triage, triaged_tp, triaged_fp, unverified = [], [], [], [], []
    for i, f in enumerate(findings):
        if i in assigned or i in fp_from_negatives:
            continue
        title = str(f.get("title") or "")
        if not _verified(f):
            unverified.append(f.get("id"))
        elif any(p.search(title) for p in suite["informational"]):
            informational.append(f.get("id"))
        elif f.get("id") in triage:
            (triaged_tp if triage[f["id"]] else triaged_fp).append(f.get("id"))
        else:
            needs_triage.append({"id": f.get("id"), "title": title,
                                 "category": f.get("category"), "severity": f.get("severity")})

    tp = sum(1 for p in positives if p["detected"])
    fn = len(positives) - tp
    known_fp = len(fp_from_negatives) + len(triaged_fp)
    real_extra = len(triaged_tp)
    pending = len(needs_triage)

    def _p(t, f):
        return round(t / (t + f), 4) if t + f else 1.0

    recall = round(tp / len(positives), 4)
    p_low = _p(tp + real_extra, known_fp + pending)    # every untriaged finding is false
    p_high = _p(tp + real_extra + pending, known_fp)   # every untriaged finding is real
    return {
        "metrics": {
            "labeled_positives": len(positives),
            "true_positive": tp,
            "false_negative": fn,
            "recall": recall,
            "false_positive_known": known_fp,
            "extra_real_findings": real_extra,
            "needs_triage": pending,
            "precision_min": p_low,
            "precision_max": p_high,
            "precision_final": p_low if pending == 0 else None,
            "negatives_clean": sum(1 for n in negatives if not n["false_alarm"]),
            "negatives_total": len(negatives),
        },
        "positive_cases": positives,
        "negative_cases": negatives,
        "needs_triage": needs_triage,
        "informational": informational,
        "unverified_findings": unverified,
        "finding_count": len(findings),
    }


def run_suite(suite_ref: str, db_path: str | Path, target: str, *, since: str = "",
              triage_path: str = "", profile: str = "", model: str = "") -> dict:
    """Load findings for ``target`` from the ledger and score them."""
    started = time.monotonic()
    suite = load_suite(suite_ref)
    ledger = FindingsLedger(Path(db_path))
    findings = ledger.list_findings(target_ip=target, limit=5000)
    if since:
        findings = [f for f in findings if str(f.get("last_seen") or "") >= since]
    result = score(suite, findings, load_triage(triage_path))
    return {
        "benchmark": f"{suite['id']}@{suite['version']}",
        "benchmark_class": "public_vulnerable_app",
        "suite": {"id": suite["id"], "name": suite["name"], "version": suite["version"],
                  "target_version": suite.get("target_version", ""),
                  "source": suite.get("source", "")},
        "oniops_version": __version__,
        "target": target,
        "profile": profile,
        "model": model,
        "since": since,
        **result,
        "duration_seconds": round(time.monotonic() - started, 3),
        "limitation": (
            "Labels cover a documented subset of this application's known vulnerabilities. "
            "Recall is measured against that subset only. Precision stays a range until every "
            "unlabeled verified finding is triaged."
        ),
    }


def markdown_row(res: dict) -> str:
    """One README-ready table row for a result."""
    m = res["metrics"]
    if m["precision_final"] is not None:
        prec = f"{m['precision_final']:.0%}"
    else:
        prec = f"{m['precision_min']:.0%}-{m['precision_max']:.0%} ({m['needs_triage']} untriaged)"
    return (f"| {res['suite']['name']} {res['suite'].get('target_version') or ''} | "
            f"v{res['oniops_version']} | {res.get('profile') or '-'} | {res.get('model') or '-'} | "
            f"{m['true_positive']}/{m['labeled_positives']} ({m['recall']:.0%}) | {prec} | "
            f"{m['false_positive_known']} |")


MARKDOWN_HEADER = (
    "| Target | OniOps | Profile | Model | Labeled bugs found | Precision | Known false positives |\n"
    "| --- | --- | --- | --- | --- | --- | --- |"
)

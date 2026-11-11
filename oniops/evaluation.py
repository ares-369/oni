"""Reproducible, ground-truth evaluation against the bundled loopback lab.

This is an integration benchmark for OniOps' current web/API pipeline. It is
explicitly labelled as a controlled fixture benchmark, not a claim about recall
on arbitrary production applications.
"""
from __future__ import annotations

import tempfile
import time
from pathlib import Path

from . import __version__
from .demo import demo_runner, demo_scope, run_assessment
from .demo_target import DemoTarget
from .findings import FindingsLedger

POSITIVE_CASES = {
    "unauthenticated_debug": "Unauthenticated API access on /api/v1/debug/env",
    "user_object_bola": "Cross-user horizontal BOLA on /api/v1/users/{id}",
    "order_object_bola": "Cross-user horizontal BOLA on /api/v1/orders/{order_ref}",
    "admin_function_bypass": "BOLA/BFLA privilege boundary bypass on /api/v1/admin/config",
    "graphql_introspection": "Exposed GraphQL schema introspection on /graphql",
    "verbose_sql_error": "Verbose SQL error disclosed on /api/v1/search",
    "reflected_xss": "Reflected XSS on /api/v1/echo",
}

KNOWN_FALSE_POSITIVE = "BOLA/BFLA privilege boundary bypass on /api/v1/users/{id}"
INFORMATIONAL_OR_UNCONFIRMED = (
    "Exposed HTTP service on port",
    "BOPLA / Mass Assignment risk on PATCH /api/v1/users/{id}",
)
NEGATIVE_CASES = {
    "admin_only_secret": "/api/v1/secrets",
    "empty_200_endpoint": "/api/v1/tokens/status",
    "always_forbidden_metrics": "/api/v1/internal/metrics",
    "owner_only_wallet": "/api/v1/wallets",
    "no_duplicate_owner_read_alert": "BOLA/BFLA privilege boundary bypass on /api/v1/users/{id}",
}


def _score_findings(findings: list[dict]) -> dict:
    """Score finding records one-to-one against the bundled ground-truth labels."""
    titles = [str(f.get("title") or "") for f in findings]
    searchable = [f"{f.get('title') or ''}\n{f.get('evidence') or ''}" for f in findings]
    positive_results = []
    assigned_findings: set[int] = set()
    for case_id, fragment in POSITIVE_CASES.items():
        candidates = [i for i, value in enumerate(searchable) if fragment in value]
        candidates.sort(key=lambda i: str(findings[i].get("status") or "").upper() != "VERIFIED")
        chosen = next((i for i in candidates if i not in assigned_findings), None)
        if chosen is not None:
            assigned_findings.add(chosen)
        verified = chosen is not None and str(findings[chosen].get("status") or "").upper() == "VERIFIED"
        positive_results.append({
            "case_id": case_id,
            "expected": "finding",
            "detected": verified,
            "matches": [titles[i] for i in candidates],
            "selected_status": str(findings[chosen].get("status") or "").upper() if chosen is not None else "",
        })

    negatives = []
    for case_id, fragment in NEGATIVE_CASES.items():
        matches = [titles[i] for i, value in enumerate(searchable) if fragment in value]
        negatives.append({
            "case_id": case_id,
            "expected": "no finding",
            "detected": bool(matches),
            "matches": matches,
        })

    known_fp_indices = [i for i, title in enumerate(titles)
                        if KNOWN_FALSE_POSITIVE in title and i not in assigned_findings]
    excluded_indices = [i for i, title in enumerate(titles)
                        if any(fragment in title for fragment in INFORMATIONAL_OR_UNCONFIRMED)]
    excluded = [titles[i] for i in excluded_indices]
    false_positive_indices = [i for i in range(len(findings))
                              if i not in assigned_findings and i not in excluded_indices]
    unexpected = [titles[i] for i in false_positive_indices if i not in known_fp_indices]
    tp = sum(1 for case in positive_results if case["detected"])
    fn = len(positive_results) - tp
    fp = len(false_positive_indices)
    tn = len(NEGATIVE_CASES) - sum(1 for case in negatives if case["detected"])
    precision = tp / (tp + fp) if tp + fp else 1.0
    recall = tp / (tp + fn) if tp + fn else 1.0

    return {
        "metrics": {
            "true_positive": tp,
            "false_positive": fp,
            "false_negative": fn,
            "true_negative": tn,
            "precision": round(precision, 4),
            "recall": round(recall, 4),
            "f1": round(2 * precision * recall / (precision + recall), 4) if precision + recall else 0.0,
        },
        "positive_cases": positive_results,
        "negative_cases": negatives,
        "known_false_positives": [titles[i] for i in known_fp_indices],
        "informational_or_unconfirmed": excluded,
        "unexpected_findings": unexpected,
        "finding_count": len(findings),
    }


def run_demo_evaluation() -> dict:
    """Run the actual assessment pipeline and score it against fixture labels."""
    started = time.monotonic()
    with tempfile.TemporaryDirectory(prefix="oniops-eval-") as tmp:
        ledger = FindingsLedger(Path(tmp) / "evaluation.sqlite")
        scope = demo_scope()
        runner = demo_runner(scope)
        with DemoTarget() as target:
            result = run_assessment(target.ip, target.port, runner, ledger)
            findings = ledger.list_findings(target_ip=target.ip, limit=500)

    scored = _score_findings(findings)
    return {
        "benchmark": "oniops-demo-ground-truth-v1",
        "benchmark_class": "controlled_fixture",
        "oniops_version": __version__,
        "duration_seconds": round(time.monotonic() - started, 3),
        **scored,
        "requests_launched": len(runner.commands_run),
        "limitation": (
            "This controlled loopback fixture measures only the included ground-truth cases. "
            "It is not an estimate of production detection accuracy or a competitor comparison."
        ),
        "engines": {
            "openapi": bool(result.get("openapi", {}).get("found")),
            "graphql": bool(result.get("graphql")),
            "input_proofs": len(result.get("inputs", [])),
            "browser_crawl": False,
            "network_tooling": False,
            "llm_agent": False,
        },
    }

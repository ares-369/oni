"""`oniops demo`: a zero-setup first run against the bundled practice target.

Starts `oniops.demo_target.DemoTarget` on 127.0.0.1, probes it with OniOps's real
engines and validators through the loopback-only `LocalRunner`, records the
results in a throwaway DEMO ledger, shows a zero-token retest, flips the target
to its "fixed" state and retests again, then stops everything.

Nothing here is canned: every finding printed comes from a live probe of the
in-process target in this run. No config.yaml, attack host, SSH key or LLM is
needed, and the real ledger/DB is never opened.

Engines exercised:
  - service check   curl -kIsS + findings.validate_evidence(category="service_exposure")
  - grey-box API    greybox.probe_openapi (unauth / low-priv / peer / admin diff, BOPLA)
  - GraphQL         greybox.probe_graphql_introspection
  - JS routes       greybox.discover_js_endpoints (informational, no findings)
  - input proofs    findings.validate_evidence(category="sqli" / "xss")
  - ledger/retest   findings.FindingsLedger.upsert / record_from_assessment / retest
Not exercised (need an attack host's tools or an LLM): nmap, nuclei, ffuf,
whatweb, katana, nikto, searchsploit, CVE intel, the AI agent and AI report.
"""
from __future__ import annotations

import shutil
import sys
import tempfile
import time
from pathlib import Path
from typing import TextIO

from .config import AuthConfig, Config, HostConfig, ScopeConfig
from .demo_target import ADMIN_HEADER, USER_A_HEADER, USER_B_HEADER, DemoTarget
from .findings import FindingsLedger, validate_evidence
from .greybox import discover_js_endpoints, probe_graphql_introspection, probe_openapi
from .local_runner import LocalRunner
from .ratelimit import RateLimiter
from .scope import Scope

DEMO_SCOPE = "127.0.0.1/32"
DEMO = "[DEMO]"
# The demo target lives in this process, so the courtesy limit is set very high
# (one request per millisecond): the real RateLimiter still paces every request,
# it just never makes the one-minute demo slow.
DEMO_RATE_PER_MIN = 60000


def demo_config() -> Config:
    """An in-memory config for the demo: scope 127.0.0.1/32, no attack host,
    no LLM, auth none on loopback. Never read from or written to disk."""
    host = HostConfig(host="127.0.0.1", name="local-demo", label="local loopback (demo)")
    return Config(
        raw={"demo": True},
        instance_name="OniOps DEMO",
        external_url="",
        bind_host="127.0.0.1",
        bind_port=8501,
        scope=ScopeConfig(allowed_cidrs=[DEMO_SCOPE], exclude=[], auto_detect_subnet=False,
                          mode="active", non_destructive=True),
        kali=host,
        hosts=[host],
        auth=AuthConfig(mode="none"),
        llm={},
        integrations={},
        path=Path("<demo: in-memory config>"),
    )


def demo_scope() -> Scope:
    return Scope(demo_config())


def demo_runner(scope: Scope | None = None) -> LocalRunner:
    """LocalRunner for the demo/e2e tests, with the high-rate demo limiter."""
    return LocalRunner(scope or demo_scope(), limiter=RateLimiter(DEMO_RATE_PER_MIN))


def run_assessment(target_ip: str, port: int, runner: LocalRunner, ledger: FindingsLedger,
                   *, scheme: str = "http") -> dict:
    """Probe one loopback web service with the real engines and record what the
    validators confirm. Returns the raw engine output for display/tests."""
    base = f"{scheme}://{target_ip}:{port}"
    run_fn = runner.run_out

    # 1. Service exposure: the same curl -I check + validator the assessment uses.
    head = run_fn(["curl", "-kIsS", "--max-time", "4", base], 8)
    svc_status = validate_evidence(head, category="service_exposure")
    verified_services = []
    if svc_status in ("VERIFIED", "AUTH-GATED"):
        status_line = next((ln.strip() for ln in head.splitlines() if ln.startswith("HTTP/")), "")
        missing = [h for h in ("Content-Security-Policy", "X-Frame-Options", "X-Content-Type-Options")
                   if h.lower() + ":" not in head.lower()]
        ev = status_line + (f" | missing security headers: {', '.join(missing)}" if missing else "")
        verified_services.append({"port": port, "service": "http", "status": svc_status, "evidence": ev})

    # 2. Grey-box OpenAPI access-control differential (+ BOPLA from the schema).
    oa = probe_openapi(target_ip, port, scheme, run_fn, auth_header=ADMIN_HEADER,
                       low_priv_header=USER_A_HEADER, peer_auth_header=USER_B_HEADER)
    ledger.record_from_assessment(target_ip, verified_services, [], nuclei_lines=[],
                                  openapi_findings=oa["findings"])

    # 3. GraphQL introspection.
    gql = probe_graphql_introspection(target_ip, port, scheme, run_fn)
    if gql:
        ledger.upsert(target_ip=target_ip, port=port, title=gql["title"], category=gql.get("category", "graphql"),
                      severity=gql["severity"], status=gql["status"], evidence=gql["evidence"],
                      repro_cmd=gql["repro_cmd"])

    # 4. Input-handling proofs, confirmed only by the vuln-class signatures.
    proofs = [
        ("sqli", "HIGH", "Verbose SQL error disclosed on /api/v1/search (error-based SQLi signal)",
         f"{base}/api/v1/search?q=%27"),
        ("xss", "MEDIUM", "Reflected XSS on /api/v1/echo (unescaped msg parameter)",
         f"{base}/api/v1/echo?msg=%3Cscript%3Ealert(1)%3C%2Fscript%3E"),
    ]
    input_results = []
    for cat, sev, title, url in proofs:
        cmd = ["curl", "-kisS", "--max-time", "5", url]
        out = run_fn(cmd, 8)
        st = validate_evidence(out, category=cat)
        input_results.append({"category": cat, "status": st, "url": url})
        if st == "VERIFIED":
            body = out.split("\n\n", 1)[-1].strip() if "\n\n" in out else out
            ledger.upsert(target_ip=target_ip, port=port, title=title, category=cat, severity=sev,
                          status=st, evidence=f"GET {url} -> {body[:200]}", repro_cmd=cmd)

    # 5. JS/SPA route inventory (informational only, never a finding).
    js = discover_js_endpoints(target_ip, port, scheme, run_fn)

    return {"service": verified_services, "openapi": oa, "graphql": gql,
            "inputs": input_results, "js": js}


def _clip(text: str, n: int = 110) -> str:
    t = " ".join(str(text or "").split())
    return t if len(t) <= n else t[: n - 3] + "..."


def run_demo(*, db_path: str | Path | None = None, out: TextIO | None = None,
             show_fixed: bool = True) -> int:
    """Run the full demo. Returns a process exit code (0 on success)."""
    out = out or sys.stdout

    def say(line: str = "") -> None:
        print(f"{DEMO} {line}" if line else DEMO, file=out, flush=True)

    t0 = time.monotonic()
    tmpdir = None
    if db_path is None:
        tmpdir = tempfile.mkdtemp(prefix="oniops-demo-")
        db_file = Path(tmpdir) / "oniops-demo.sqlite"
    else:
        db_file = Path(db_path)

    say("OniOps demo - practice run against a bundled, deliberately flawed target.")
    say("Notice: this run only touches a fake app that OniOps starts on 127.0.0.1 in this")
    say("process. For any real system you still need written permission and must accept")
    say("the responsible-use terms in the web UI (see DISCLAIMER.md). Nothing is recorded")
    say("as terms acceptance here.")
    say("AI features are off in demo mode (no LLM is called). Findings come from OniOps's")
    say("deterministic probes and validators only.")
    say()

    scope = demo_scope()
    runner = demo_runner(scope)
    ledger = FindingsLedger(db_file)
    try:
        with DemoTarget() as target:
            ip, port = target.ip, target.port
            scope.resolve(ip)  # the target itself must pass the scope check
            say(f"Target: {target.base_url}  (scope {DEMO_SCOPE}, local runner, DEMO ledger {db_file})")
            res = run_assessment(ip, port, runner, ledger)
            oa = res["openapi"]
            say(f"Probed with {len(runner.commands_run)} curl requests; OpenAPI spec at {oa['spec_url']} "
                f"({len(oa['endpoints'])} routes).")
            say()

            items = sorted(ledger.list_findings(target_ip=ip, limit=100),
                           key=lambda f: -int(f.get("priority_score") or 0))
            say(f"Findings ({len(items)}), sorted by fix-first score (0-100):")
            for f in items:
                say(f"  {int(f['priority_score']):>3}  {f['status']:<11} {f['severity']:<6} "
                    f"conf={f['confidence']:<6} #{f['id']} {f['title']}")
                say(f"       proof: {_clip(f['evidence'])}")
            say()
            say("Checked and correctly NOT reported (secure twins / filtered):")
            for line in oa["raw_section"].splitlines():
                if any(k in line for k in ("FALSE-POSITIVE-FILTERED", "AUTH-ENFORCED", "/internal/")):
                    say(f"  {line.lstrip('- ').strip()}")
            say()

            say("Zero-token retest of every finding (replays each stored curl command, no LLM;")
            say("credentials in replay commands are shown masked):")
            ids = [int(f["id"]) for f in sorted(items, key=lambda f: int(f["id"]))]
            before = {i: ledger.retest(i, runner, scope) for i in ids}
            after = {}
            if show_fixed:
                target.set_fixed(True)
                after = {i: ledger.retest(i, runner, scope) for i in ids}
            for i in ids:
                b = before[i]
                line = f"  #{i:<2} now {b['status']:<11}"
                if after:
                    line += f" after fix {after[i]['status']:<11}"
                say(f"{line} {_clip(b['title'], 70)}")
            cred = next((before[i] for i in ids if "[REDACTED-CREDENTIAL]" in before[i]["repro_cmd"]), None)
            if cred:
                say(f"  e.g. #{cred['id']} replays as the low-privilege identity: $ {cred['repro_cmd']}")
            if after:
                say("  The service itself stays live after the fix, so its row stays VERIFIED.")
            owner = next((f for f in items if f["title"].startswith("BOLA/BFLA privilege boundary bypass on /api/v1/users/")), None)
            if owner:
                say(f"  Known false positive: #{owner['id']} - user A owns object 1, and the low-privilege")
                say("  check has no notion of object ownership yet, so a legitimate owner read is still")
                say("  reported. The cross-user check is the real BOLA signal on that route.")
            say("  A 401 on a credentialed replay is reported UNCONFIRMED (the credential may have")
            say("  expired), never FIXED.")
            say()
    finally:
        if tmpdir:
            shutil.rmtree(tmpdir, ignore_errors=True)

    say(f"Done in {time.monotonic() - t0:.1f}s. Demo target stopped"
        + ("; the temporary DEMO ledger was deleted." if tmpdir else f"; DEMO ledger kept at {db_file}."))
    say()
    say("Next step for a real assessment:")
    from .paths import is_checkout
    if is_checkout():
        say("  1. cp config.example.yaml config.yaml and set scope.allowed_cidrs to networks you may test")
    else:
        say("  1. run `oniops init`, then set scope.allowed_cidrs in ~/.oniops/config.yaml to networks you may test")
    say("  2. point kali.host (or attack_hosts) at a tooled Linux box (Kali or similar) reachable over SSH")
    say("  3. optionally configure an LLM, then run `oniops` and accept the terms in the UI")
    say("This is beta software: the demo shows how the pipeline works, not how well it finds")
    say("issues on real systems.")
    return 0

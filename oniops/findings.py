"""Evidence ledger, secret redaction, and zero-token PoC regression testing.

Every verified or candidate finding is stored as a structured record in SQLite
with:
  - Permanent finding ID and deduplication key (target_ip, port, title)
  - Redacted evidence (tokens, passwords, and API keys masked automatically)
  - Deterministic reproduction argv (`repro_cmd`) that can be re-executed on the
    attack host over SSH with zero LLM tokens to verify whether a fix worked.
"""
from __future__ import annotations

import hashlib
import json
import re
import shlex
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

from .scope import Scope

# Patterns for automatic secret redaction in evidence and reports.
_REDACT_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"(?i)(authorization\s*:\s*bearer\s+)[A-Za-z0-9._\-+/=]{8,}"), r"\1[REDACTED-TOKEN]"),
    (re.compile(r"(?i)(cookie\s*:\s*)[^\r\n]{8,}"), r"\1[REDACTED-COOKIE]"),
    (re.compile(r"\bsk-[A-Za-z0-9_\-]{12,}\b"), "sk-[REDACTED]"),
    (re.compile(r"\bgh[pousr]_[A-Za-z0-9]{16,}\b"), "gh_[REDACTED]"),
    (re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "AKIA[REDACTED]"),
    (re.compile(r"(?i)\b(password|passwd|secret|api[_-]?key|access[_-]?token)\s*([:=])\s*['\"]?([^\s'\";,]{5,})"),
     r"\1\2[REDACTED]"),
]


def redact_secrets(text: str) -> str:
    """Mask bearer tokens, cookies, API keys, and passwords in evidence strings."""
    if not text:
        return ""
    out = text
    for pat, repl in _REDACT_PATTERNS:
        out = pat.sub(repl, out)
    return out


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def validate_evidence(evidence: str, expected_indicator: str = "", category: str = "") -> str:
    """Independently verify whether captured command output confirms a finding.

    Prevents unverified LLM claims or empty scanner output from being marked
    VERIFIED without deterministic indicator confirmation.
    """
    text = (evidence or "").strip()
    if not text:
        return "UNCONFIRMED"
    if expected_indicator:
        ind = expected_indicator.strip()
        if ind.lower() in text.lower():
            return "VERIFIED"
        try:
            if re.search(ind, text, re.I):
                return "VERIFIED"
        except re.error:
            pass
        return "UNCONFIRMED"

    m = re.search(r"HTTP/[\d.]+\s+(\d{3})", text)
    if m:
        code = int(m.group(1))
        if code in (200, 201, 204):
            return "VERIFIED"
        if code in (401, 403):
            return "AUTH-GATED" if category == "service_exposure" else "UNCONFIRMED"
        if code >= 400:
            return "UNCONFIRMED"
    return "VERIFIED" if len(text) > 12 else "UNCONFIRMED"


def evaluate_finding_confidence(category: str, status: str, evidence: str) -> str:
    """Calibrate finding confidence (HIGH / MEDIUM / LOW) per category and
    verification status rather than using one generic rule."""
    st = (status or "").upper()
    cat = (category or "").lower()
    ev = (evidence or "").strip()
    if st in ("VERIFIED", "FIXED"):
        if cat in ("nuclei", "api_security", "agent_validation"):
            return "HIGH"
        if cat == "service_exposure" and re.search(r"HTTP/[\d.]+\s+2\d\d", ev):
            return "HIGH"
        return "HIGH" if len(ev) > 20 else "MEDIUM"
    if st == "AUTH-GATED":
        return "MEDIUM"
    if cat in ("cve", "exploitdb"):
        return "MEDIUM" if "CVSS" in ev or "EDB-" in ev else "LOW"
    return "LOW"


class FindingsLedger:
    """SQLite-backed vulnerability and PoC evidence ledger."""

    def __init__(self, db_path: str | Path) -> None:
        self.db_path = str(db_path)
        self._init()

    def _conn(self) -> sqlite3.Connection:
        con = sqlite3.connect(self.db_path)
        con.row_factory = sqlite3.Row
        return con

    def _init(self) -> None:
        with self._conn() as con:
            con.execute("""
            CREATE TABLE IF NOT EXISTS findings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target_ip TEXT NOT NULL,
                port INTEGER DEFAULT 0,
                title TEXT NOT NULL,
                category TEXT NOT NULL,
                severity TEXT NOT NULL,
                status TEXT NOT NULL,
                confidence TEXT DEFAULT 'MEDIUM',
                evidence TEXT NOT NULL,
                evidence_sha256 TEXT DEFAULT '',
                repro_cmd TEXT NOT NULL,
                first_seen TEXT NOT NULL,
                last_seen TEXT NOT NULL,
                last_retest TEXT DEFAULT '',
                UNIQUE(target_ip, port, title)
            )""")
            # Auto-migrate older SQLite schemas missing evidence_sha256 or confidence.
            cols = {r["name"] for r in con.execute("PRAGMA table_info(findings)").fetchall()}
            if "evidence_sha256" not in cols:
                con.execute("ALTER TABLE findings ADD COLUMN evidence_sha256 TEXT DEFAULT ''")
            if "confidence" not in cols:
                con.execute("ALTER TABLE findings ADD COLUMN confidence TEXT DEFAULT 'MEDIUM'")
            con.commit()

    def upsert(
        self,
        *,
        target_ip: str,
        port: int,
        title: str,
        category: str,
        severity: str,
        status: str,
        evidence: str,
        repro_cmd: list[str] | str,
        confidence: str = "",
    ) -> int:
        """Insert or update a deduplicated finding with secret-redacted evidence,
        calibrated confidence, and SHA-256 cryptographic provenance."""
        ts = _now_iso()
        clean_evidence = redact_secrets(evidence)[:1500]
        ev_hash = hashlib.sha256(clean_evidence.encode("utf-8")).hexdigest()
        conf = (confidence or evaluate_finding_confidence(category, status, clean_evidence)).upper()
        if isinstance(repro_cmd, list):
            cmd_str = json.dumps(repro_cmd)
        else:
            cmd_str = json.dumps(shlex.split(repro_cmd)) if repro_cmd else "[]"

        with self._conn() as con:
            cur = con.execute(
                """
                INSERT INTO findings
                    (target_ip, port, title, category, severity, status, confidence, evidence, evidence_sha256, repro_cmd, first_seen, last_seen)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(target_ip, port, title) DO UPDATE SET
                    severity = excluded.severity,
                    status = excluded.status,
                    confidence = excluded.confidence,
                    evidence = excluded.evidence,
                    evidence_sha256 = excluded.evidence_sha256,
                    repro_cmd = CASE WHEN excluded.repro_cmd != '[]' THEN excluded.repro_cmd ELSE findings.repro_cmd END,
                    last_seen = excluded.last_seen
                """,
                (target_ip, int(port or 0), title[:200], category[:60],
                 severity.upper(), status.upper(), conf, clean_evidence, ev_hash, cmd_str, ts, ts),
            )
            con.commit()
            if cur.lastrowid:
                return int(cur.lastrowid)
            row = con.execute(
                "SELECT id FROM findings WHERE target_ip = ? AND port = ? AND title = ?",
                (target_ip, int(port or 0), title[:200]),
            ).fetchone()
            return int(row["id"]) if row else 0

    def record_from_assessment(
        self,
        target_ip: str,
        verified_services: list[dict],
        cve_findings: list[dict],
        nuclei_lines: list[str] | None = None,
        openapi_findings: list[dict] | None = None,
    ) -> int:
        """Extract structured, replayable findings from an assessment run."""
        recorded = 0
        for v in verified_services or []:
            st = v.get("status", "OPEN")
            if st not in ("VERIFIED", "AUTH-GATED"):
                continue
            port = int(v.get("port") or 0)
            svc = v.get("service") or "http"
            scheme = "https" if port in (443, 8006, 8443, 9443) or "ssl" in svc else "http"
            repro = ["curl", "-kIsS", "--max-time", "5", f"{scheme}://{target_ip}:{port}"]
            self.upsert(
                target_ip=target_ip,
                port=port,
                title=f"Exposed {svc.upper()} service on port {port} ({st})",
                category="service_exposure",
                severity="LOW" if st == "AUTH-GATED" else "MEDIUM",
                status=st,
                evidence=v.get("evidence", ""),
                repro_cmd=repro,
            )
            recorded += 1

        for cf in cve_findings or []:
            port = int(cf.get("port") or 0)
            prod = cf.get("product") or "service"
            ver = cf.get("version") or ""
            for c in cf.get("cves") or []:
                cid = c.get("id", "CVE")
                sev = c.get("severity") or "MEDIUM"
                self.upsert(
                    target_ip=target_ip,
                    port=port,
                    title=f"{cid} on {prod} {ver}".strip(),
                    category="cve",
                    severity=sev if sev in ("LOW", "MEDIUM", "HIGH", "CRITICAL") else "MEDIUM",
                    status="UNCONFIRMED",
                    evidence=f"{cid} (CVSS {c.get('cvss', 'N/A')}): {c.get('summary', '')}",
                    repro_cmd=["nmap", "-sV", "-p", str(port), target_ip] if port else [],
                )
                recorded += 1
            for ex in (cf.get("exploits") or [])[:3]:
                title = ex.get("title") or "Exploit-DB match"
                self.upsert(
                    target_ip=target_ip,
                    port=port,
                    title=f"Exploit-DB: {title[:120]}",
                    category="exploitdb",
                    severity="HIGH",
                    status="UNCONFIRMED",
                    evidence=f"{title} ({ex.get('path', '')})",
                    repro_cmd=["searchsploit", f"{prod} {ver}".strip()],
                )
                recorded += 1

        for line in nuclei_lines or []:
            clean = line.strip()
            if not clean:
                continue
            m = re.match(r"^\[([^\]]+)\]\s+\[([^\]]+)\]\s+\[([^\]]+)\]\s+(\S+)", clean)
            if m:
                tid, _proto, sev, url = m.group(1), m.group(2), m.group(3).upper(), m.group(4)
                pm = re.search(r":(\d+)", url)
                port = int(pm.group(1)) if pm else 80
                self.upsert(
                    target_ip=target_ip,
                    port=port,
                    title=f"Nuclei [{tid}]",
                    category="nuclei",
                    severity=sev if sev in ("LOW", "MEDIUM", "HIGH", "CRITICAL") else "MEDIUM",
                    status="VERIFIED",
                    evidence=clean,
                    repro_cmd=["nuclei", "-target", url, "-id", tid, "-silent"],
                )
                recorded += 1

        for of in openapi_findings or []:
            self.upsert(
                target_ip=target_ip,
                port=int(of.get("port") or 80),
                title=of.get("title", "API Exposure"),
                category="api_security",
                severity=of.get("severity", "MEDIUM"),
                status=of.get("status", "VERIFIED"),
                evidence=of.get("evidence", ""),
                repro_cmd=of.get("repro_cmd") or [],
            )
            recorded += 1

        return recorded

    def list_findings(self, target_ip: str = "", limit: int = 100) -> list[dict]:
        with self._conn() as con:
            if target_ip:
                rows = con.execute(
                    "SELECT * FROM findings WHERE target_ip = ? ORDER BY id DESC LIMIT ?",
                    (target_ip, limit),
                ).fetchall()
            else:
                rows = con.execute(
                    "SELECT * FROM findings ORDER BY id DESC LIMIT ?",
                    (limit,),
                ).fetchall()
        out = []
        for r in rows:
            d = dict(r)
            try:
                cmd_list = json.loads(d.get("repro_cmd") or "[]")
                d["repro_display"] = shlex.join(cmd_list) if cmd_list else ""
            except Exception:
                d["repro_display"] = ""
            out.append(d)
        return out

    def get(self, finding_id: int) -> dict | None:
        with self._conn() as con:
            row = con.execute("SELECT * FROM findings WHERE id = ?", (finding_id,)).fetchone()
        return dict(row) if row else None

    def retest(self, finding_id: int, runner, scope: Scope) -> dict:
        """Re-run a finding's deterministic PoC command on the attack host with
        ZERO LLM tokens, updating status to VERIFIED, AUTH-GATED, or FIXED."""
        f = self.get(finding_id)
        if not f:
            raise ValueError(f"Finding #{finding_id} not found.")
        # Enforce scope before running any retest command.
        scope.resolve(f["target_ip"])
        try:
            cmd = json.loads(f.get("repro_cmd") or "[]")
        except Exception:
            cmd = []
        if not cmd or not isinstance(cmd, list):
            raise ValueError(f"Finding #{finding_id} has no deterministic replay command.")
        scope.guard_command(" ".join(cmd))

        res = runner.run(cmd, timeout=30)
        out = redact_secrets((res.out or "").strip())
        ts = _now_iso()

        # Determine whether the issue still reproduces.
        cat = f.get("category", "")
        if cat == "service_exposure":
            m = re.search(r"HTTP/[\d.]+\s+(\d{3})", out)
            if m:
                code = int(m.group(1))
                new_status = "AUTH-GATED" if code in (401, 403) else "VERIFIED"
            else:
                new_status = "FIXED"
        elif cat == "nuclei":
            new_status = "VERIFIED" if out and f["target_ip"] in out else "FIXED"
        elif cat == "api_security":
            m = re.search(r"HTTP/[\d.]+\s+(\d{3})", out)
            if m and int(m.group(1)) in (200, 201, 204):
                new_status = "VERIFIED"
            elif m and int(m.group(1)) in (401, 403, 404):
                new_status = "FIXED"
            else:
                new_status = "UNCONFIRMED"
        else:
            new_status = "VERIFIED" if (res.ok and out) else "FIXED"

        new_ev = f"[Retest {ts[:19]}] {out[:400] or '(no output — appears remediated/closed)'}"
        new_hash = hashlib.sha256(new_ev.encode("utf-8")).hexdigest()
        new_conf = evaluate_finding_confidence(cat, new_status, out)
        with self._conn() as con:
            con.execute(
                "UPDATE findings SET status = ?, confidence = ?, evidence = ?, evidence_sha256 = ?, last_retest = ?, last_seen = ? WHERE id = ?",
                (new_status, new_conf, new_ev, new_hash, ts, ts, finding_id),
            )
            con.commit()
        return {
            "id": finding_id,
            "target_ip": f["target_ip"],
            "title": f["title"],
            "previous_status": f["status"],
            "status": new_status,
            "confidence": new_conf,
            "evidence": new_ev,
            "evidence_sha256": new_hash,
            "repro_cmd": shlex.join(cmd),
            "last_retest": ts,
        }

    def retest_all(self, runner, scope: Scope, *, target_ip: str = "", limit: int = 25) -> dict:
        """Batch-run zero-token remediation verification across stored findings."""
        items = self.list_findings(target_ip=target_ip, limit=limit)
        results: list[dict] = []
        verified = 0
        fixed = 0
        regressed = 0
        for item in items:
            if not item.get("repro_display"):
                continue
            prev = item.get("status", "")
            try:
                res = self.retest(int(item["id"]), runner, scope)
                results.append(res)
                st = res["status"]
                if st == "VERIFIED":
                    verified += 1
                    if prev == "FIXED":
                        regressed += 1
                elif st == "FIXED":
                    fixed += 1
            except Exception as exc:
                results.append({
                    "id": item["id"],
                    "target_ip": item["target_ip"],
                    "title": item["title"],
                    "previous_status": prev,
                    "status": "ERROR",
                    "error": str(exc),
                })
        return {
            "total_retested": len(results),
            "verified": verified,
            "fixed": fixed,
            "regressed": regressed,
            "results": results,
        }


def _extract_ports_from_raw(raw_output: str) -> list[str]:
    ports: list[str] = []
    for line in (raw_output or "").splitlines():
        m = re.match(r"^(\d+/(?:tcp|udp))\s+open\s+(\S+)", line.strip())
        if m:
            entry = f"{m.group(1)} ({m.group(2)})"
            if entry not in ports:
                ports.append(entry)
    return sorted(ports)


def diff_assessments(db_path: str | Path, assessment_id: int) -> dict:
    """Compare an assessment against the immediately preceding assessment for the
    same target IP to surface posture drift (new/closed ports, severity shifts,
    and active vs. remediated findings)."""
    con = sqlite3.connect(str(db_path))
    con.row_factory = sqlite3.Row
    curr = con.execute("SELECT * FROM assessments WHERE id = ?", (assessment_id,)).fetchone()
    if not curr:
        con.close()
        raise ValueError(f"Assessment #{assessment_id} not found.")

    target_ip = curr["target_ip"]
    prev = con.execute(
        "SELECT * FROM assessments WHERE target_ip = ? AND id < ? ORDER BY id DESC LIMIT 1",
        (target_ip, assessment_id),
    ).fetchone()

    curr_ports = set(_extract_ports_from_raw(curr["raw_output"] or ""))
    prev_ports = set(_extract_ports_from_raw(prev["raw_output"] or "")) if prev else set()

    active_findings = 0
    fixed_findings = 0
    try:
        for r in con.execute("SELECT status FROM findings WHERE target_ip = ?", (target_ip,)).fetchall():
            if r["status"] == "FIXED":
                fixed_findings += 1
            else:
                active_findings += 1
    except Exception:
        pass
    con.close()

    return {
        "target_ip": target_ip,
        "current_id": int(curr["id"]),
        "previous_id": int(prev["id"]) if prev else None,
        "has_baseline": prev is not None,
        "severity_change": {
            "from": prev["severity"] if prev else "NONE",
            "to": curr["severity"],
        },
        "finding_count_delta": int(curr["finding_count"] or 0) - (int(prev["finding_count"] or 0) if prev else 0),
        "new_ports": sorted(curr_ports - prev_ports),
        "closed_ports": sorted(prev_ports - curr_ports) if prev else [],
        "unchanged_ports": sorted(curr_ports & prev_ports) if prev else sorted(curr_ports),
        "active_findings": active_findings,
        "remediated_findings": fixed_findings,
    }


def backup_sqlite(src_db: str | Path, dest_db: str | Path) -> dict:
    """Safely snapshot a live SQLite database using SQLite's online backup API."""
    src = Path(src_db)
    if not src.exists():
        raise FileNotFoundError(f"Source database does not exist: {src}")
    dst = Path(dest_db)
    dst.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(str(src)) as s_con, sqlite3.connect(str(dst)) as d_con:
        s_con.backup(d_con)
    size = dst.stat().st_size
    return {"ok": True, "source": str(src), "destination": str(dst), "bytes": size}


def restore_sqlite(backup_db: str | Path, target_db: str | Path) -> dict:
    """Restore a SQLite backup into `target_db` after verifying SQLite integrity."""
    src = Path(backup_db)
    if not src.exists():
        raise FileNotFoundError(f"Backup file does not exist: {src}")
    with sqlite3.connect(str(src)) as check_con:
        row = check_con.execute("PRAGMA integrity_check").fetchone()
        if not row or row[0] != "ok":
            raise ValueError(f"Backup failed SQLite integrity_check: {row[0] if row else 'invalid'}")
    return backup_sqlite(src, target_db)


def build_assessment_manifest(
    *,
    assessment_id: int | str,
    oniops_version: str,
    target_ip: str,
    profile: str,
    scope_cidrs: list[str],
    model_name: str,
    started_at: str,
    completed_at: str,
    commands_run: list[str],
    evidence_hashes: list[str],
) -> dict:
    """Create a secret-free, cryptographically verifiable execution manifest
    for assessment reproducibility."""
    scope_canonical = ",".join(sorted(scope_cidrs))
    scope_hash = hashlib.sha256(scope_canonical.encode("utf-8")).hexdigest()[:16]
    cmds_canonical = "\n".join(commands_run)
    commands_hash = hashlib.sha256(cmds_canonical.encode("utf-8")).hexdigest()[:16]
    return {
        "assessment_id": f"ONIOPS-{assessment_id}",
        "oniops_version": oniops_version,
        "target_ip": target_ip,
        "profile": profile,
        "scope_hash": scope_hash,
        "commands_hash": commands_hash,
        "model": model_name,
        "started_at": started_at,
        "completed_at": completed_at,
        "evidence_hashes": evidence_hashes[:25],
    }

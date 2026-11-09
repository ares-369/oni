"""Evidence ledger, secret redaction, and zero-token PoC regression testing.

Every verified or candidate finding is stored as a structured record in SQLite
with:
  - Permanent finding ID and deduplication key (target_ip, port, title)
  - Redacted evidence (tokens, passwords, and API keys masked automatically)
  - Deterministic reproduction argv (`repro_cmd`) that can be re-executed on the
    attack host over SSH with zero LLM tokens to verify whether a fix worked.
"""
from __future__ import annotations

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
                evidence TEXT NOT NULL,
                repro_cmd TEXT NOT NULL,
                first_seen TEXT NOT NULL,
                last_seen TEXT NOT NULL,
                last_retest TEXT DEFAULT '',
                UNIQUE(target_ip, port, title)
            )""")
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
    ) -> int:
        """Insert or update a deduplicated finding with secret-redacted evidence."""
        ts = _now_iso()
        clean_evidence = redact_secrets(evidence)[:1500]
        if isinstance(repro_cmd, list):
            cmd_str = json.dumps(repro_cmd)
        else:
            cmd_str = json.dumps(shlex.split(repro_cmd)) if repro_cmd else "[]"

        with self._conn() as con:
            cur = con.execute(
                """
                INSERT INTO findings
                    (target_ip, port, title, category, severity, status, evidence, repro_cmd, first_seen, last_seen)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(target_ip, port, title) DO UPDATE SET
                    severity = excluded.severity,
                    status = excluded.status,
                    evidence = excluded.evidence,
                    repro_cmd = CASE WHEN excluded.repro_cmd != '[]' THEN excluded.repro_cmd ELSE findings.repro_cmd END,
                    last_seen = excluded.last_seen
                """,
                (target_ip, int(port or 0), title[:200], category[:60],
                 severity.upper(), status.upper(), clean_evidence, cmd_str, ts, ts),
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
        with self._conn() as con:
            con.execute(
                "UPDATE findings SET status = ?, evidence = ?, last_retest = ?, last_seen = ? WHERE id = ?",
                (new_status, new_ev, ts, ts, finding_id),
            )
            con.commit()
        return {
            "id": finding_id,
            "target_ip": f["target_ip"],
            "title": f["title"],
            "previous_status": f["status"],
            "status": new_status,
            "evidence": new_ev,
            "repro_cmd": shlex.join(cmd),
            "last_retest": ts,
        }

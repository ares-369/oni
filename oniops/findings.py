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
import hmac
import json
import os
import re
import shlex
import sqlite3
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

from .scope import Scope


def connect_sqlite(db_path: str | Path, timeout: float = 30.0) -> sqlite3.Connection:
    """Open a SQLite connection configured with Write-Ahead Logging (WAL) and a
    5-second busy timeout for lock-free concurrent reads and background writes."""
    con = sqlite3.connect(str(db_path), timeout=timeout)
    con.row_factory = sqlite3.Row
    try:
        con.execute("PRAGMA journal_mode=WAL")
        con.execute("PRAGMA busy_timeout=5000")
    except Exception:
        pass
    return con

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


_VULN_PROOF_PATTERNS: dict[str, re.Pattern[str]] = {
    "lfi": re.compile(r"(?:root:x:0:0:|\[boot loader\]|\[extensions\]|/bin/(?:bash|sh|zsh))", re.I),
    "sqli": re.compile(
        r"(?:SQL syntax.*MySQL|Warning.*mysql_|PostgreSQL.*ERROR|ORA-\d{5}|"
        r"SQLite/JDBCDriver|Unclosed quotation mark|SQLITE_ERROR)",
        re.I,
    ),
    "ssrf": re.compile(r"(?:169\.254\.169\.254|instance-id|ami-id|computeMetadata/v1|internal-token)", re.I),
    "rce": re.compile(r"(?:uid=\d+\([a-z0-9_.\-]+\)\s+gid=\d+|Linux\s+\S+\s+\d+\.\d+)", re.I),
    "xss": re.compile(r"(?:<script[^>]*>.*?alert\(|onerror\s*=|onload\s*=)", re.I),
    "graphql": re.compile(r'(?:"__schema"\s*:|"queryType"\s*:)', re.I),
}


def map_finding_coverage(category: str, title: str = "") -> dict[str, list[str]]:
    """Map a finding category and title to OWASP API Top 10, OWASP WSTG 4.2,
    OWASP ASVS 5.0, and MITRE ATT&CK control/technique identifiers."""
    cat = (category or "").lower()
    t = (title or "").lower()
    if cat in ("api_security", "bola", "bfla") or "bola" in t or "bfla" in t or "openapi" in t:
        api_ids = ["API1:2023-BOLA"]
        if "bfla" in t or "admin" in t or "privilege" in t:
            api_ids.append("API5:2023-BFLA")
        if "mass assignment" in t or "bopla" in t or "property" in t:
            api_ids.append("API3:2023-BOPLA")
        if "graphql" in t:
            api_ids.append("API8:2023-Misconfiguration")
        return {
            "owasp_api": api_ids,
            "owasp_wstg": ["WSTG-ATHZ-02", "WSTG-ATHZ-04", "WSTG-APIT-01"],
            "owasp_asvs": ["V4.1", "V4.2", "V13.1"],
            "mitre_attack": ["T1190", "T1078"],
        }
    if cat in ("sqli", "lfi", "ssrf", "rce", "xss", "nuclei"):
        return {
            "owasp_api": ["API8:2023-Misconfiguration"] if "api" in t else [],
            "owasp_wstg": ["WSTG-INPV-01", "WSTG-CONF-04"],
            "owasp_asvs": ["V5.3", "V14.2"],
            "mitre_attack": ["T1190", "T1059"],
        }
    if cat in ("cve", "exploitdb"):
        return {
            "owasp_api": [],
            "owasp_wstg": ["WSTG-INFO-08"],
            "owasp_asvs": ["V14.2"],
            "mitre_attack": ["T1190", "T1210"],
        }
    return {
        "owasp_api": [],
        "owasp_wstg": ["WSTG-INFO-02", "WSTG-CONF-01"],
        "owasp_asvs": ["V14.1"],
        "mitre_attack": ["T1046", "T1133"],
    }


def get_remediation_guide(category: str, title: str = "") -> dict[str, object]:
    """Return structured engineering remediation steps and CWE references for a
    finding category and title."""
    cat = (category or "").lower()
    t = (title or "").lower()
    if cat in ("api_security", "bola", "bfla") or "bola" in t or "bfla" in t or "openapi" in t:
        if "graphql" in t:
            return {
                "cwe": "CWE-200",
                "summary": "Disable GraphQL schema introspection in production and enforce resolver-level authorization.",
                "steps": [
                    "Disable __schema and __type introspection queries in non-development environments.",
                    "Enforce authentication and role checks inside each GraphQL field resolver.",
                    "Apply query depth and complexity limits to prevent resource exhaustion.",
                ],
                "references": ["OWASP API8:2023", "OWASP ASVS V13.4"],
            }
        if "mass assignment" in t or "bopla" in t or "property" in t:
            return {
                "cwe": "CWE-915",
                "summary": "Bind request payloads to explicit allowlist DTOs instead of database models.",
                "steps": [
                    "Define strict input schemas (e.g. Pydantic/Marshmallow) that exclude privileged fields (role, is_admin).",
                    "Reject unexpected properties in PATCH/PUT/POST bodies.",
                    "Separate administrative state-update endpoints from user profile endpoints.",
                ],
                "references": ["OWASP API3:2023", "OWASP ASVS V4.2"],
            }
        return {
            "cwe": "CWE-639",
            "summary": "Enforce object-level and function-level ownership checks on every API route.",
            "steps": [
                "Verify that the authenticated principal owns or is authorized to access the requested resource ID.",
                "Require valid authentication middleware on all non-public API routes.",
                "Use indirect or scoped resource queries (WHERE id = ? AND owner_id = current_user.id).",
            ],
            "references": ["OWASP API1:2023", "OWASP API5:2023", "OWASP ASVS V4.1"],
        }
    if cat == "sqli" or "sql" in t:
        return {
            "cwe": "CWE-89",
            "summary": "Replace string-concatenated SQL queries with parameterized prepared statements.",
            "steps": [
                "Use bound parameters (?) or ORM query builders for all user-controlled inputs.",
                "Enforce strict type validation on numeric and enum query parameters.",
                "Run the application database account with least-privilege permissions.",
            ],
            "references": ["OWASP A03:2021", "OWASP ASVS V5.3.4"],
        }
    if cat == "xss" or "xss" in t or "cross-site scripting" in t:
        return {
            "cwe": "CWE-79",
            "summary": "Contextually encode untrusted output and deploy a strict Content-Security-Policy.",
            "steps": [
                "Escape HTML, attribute, and JavaScript contexts before rendering user input.",
                "Avoid unsafe DOM sinks (innerHTML, document.write, dangerouslySetInnerHTML).",
                "Deploy a Content-Security-Policy header restricting inline scripts.",
            ],
            "references": ["OWASP A03:2021", "OWASP ASVS V5.3.3"],
        }
    if cat == "ssrf" or "ssrf" in t:
        return {
            "cwe": "CWE-918",
            "summary": "Validate outbound URLs against a strict allowlist and block RFC1918/link-local ranges.",
            "steps": [
                "Resolve target hostnames and block private, loopback, and cloud metadata IPs (169.254.169.254).",
                "Disable automatic HTTP redirect following on server-side HTTP clients.",
                "Require IMDSv2 token authentication on cloud compute instances.",
            ],
            "references": ["OWASP A10:2021", "OWASP ASVS V12.6"],
        }
    if cat in ("lfi", "rce") or "traversal" in t or "command" in t:
        return {
            "cwe": "CWE-22",
            "summary": "Canonicalize file paths against a fixed base directory and never pass user input to a shell.",
            "steps": [
                "Resolve paths with Path.resolve() and verify they remain inside the intended root directory.",
                "Pass command arguments as an argv list with shell=False rather than a shell string.",
                "Map user selections to an allowlist of known file identifiers.",
            ],
            "references": ["OWASP A01:2021", "OWASP ASVS V12.3"],
        }
    if cat in ("cve", "exploitdb", "nuclei"):
        return {
            "cwe": "CWE-1395",
            "summary": "Upgrade the affected service or apply the vendor security patch and harden configuration.",
            "steps": [
                "Verify the installed package version on the host and upgrade to the patched release.",
                "Disable unneeded modules, default management endpoints, and verbose version banners.",
                "Re-run OniOps zero-token retest after patching to confirm the signature no longer reproduces.",
            ],
            "references": ["OWASP A06:2021", "OWASP ASVS V14.2"],
        }
    if cat == "tls" or "tls" in t or "cipher" in t or "ssl" in t:
        return {
            "cwe": "CWE-326",
            "summary": "Enforce TLS 1.2+ with AEAD cipher suites and enable HSTS.",
            "steps": [
                "Disable legacy protocols (SSLv3, TLS 1.0, TLS 1.1) and weak CBC/RC4 ciphers.",
                "Configure TLS 1.2 and TLS 1.3 with ECDHE + AES-GCM or ChaCha20-Poly1305.",
                "Add Strict-Transport-Security (HSTS) and renew expired or self-signed certificates.",
            ],
            "references": ["OWASP A02:2021", "OWASP ASVS V9.1"],
        }
    return {
        "cwe": "CWE-16",
        "summary": "Restrict network exposure to authorized subnets and require strong authentication.",
        "steps": [
            "Bind internal administrative services to localhost, a management VLAN, or a VPN interface.",
            "Place exposed web services behind SSO / reverse-proxy authentication and rate limiting.",
            "Review firewall rules and re-run OniOps zero-token retest to verify access controls.",
        ],
        "references": ["OWASP A05:2021", "OWASP ASVS V14.1"],
    }


def compute_priority_score(severity: str, status: str, confidence: str) -> int:
    """Compute a deterministic 0-100 Fix-First Priority Score from severity,
    verification status, and calibrated confidence."""
    st = (status or "").upper()
    if st == "FIXED":
        return 0
    sev_pts = {"CRITICAL": 45, "HIGH": 35, "MEDIUM": 22, "LOW": 10}.get((severity or "").upper(), 15)
    st_pts = {"VERIFIED": 35, "AUTH-GATED": 15, "UNCONFIRMED": 5}.get(st, 5)
    conf_pts = {"HIGH": 20, "MEDIUM": 12, "LOW": 5}.get((confidence or "").upper(), 10)
    return min(100, sev_pts + st_pts + conf_pts)


def dispatch_webhook_alert(
    event_type: str,
    payload: dict,
    *,
    webhook_url: str = "",
    signing_key: str = "",
) -> bool:
    """POST a signed JSON alert to a configured webhook URL (Slack, Discord, or
    generic SIEM/SOAR receiver) when a high-severity finding is verified or regresses."""
    url = (webhook_url or os.getenv("ONIOPS_WEBHOOK_URL", "")).strip()
    if not url or not url.startswith(("http://", "https://")):
        return False
    envelope = {
        "event": event_type,
        "timestamp": _now_iso(),
        "payload": payload,
    }
    body = json.dumps(envelope, sort_keys=True).encode("utf-8")
    key = (signing_key or os.getenv("ONIOPS_SECRET_KEY", "") or "oniops-webhook-key").encode("utf-8")
    sig = hmac.new(key, body, hashlib.sha256).hexdigest()
    req = urllib.request.Request(
        url,
        data=body,
        headers={
            "Content-Type": "application/json",
            "User-Agent": "ONIOPS-Security-Webhook/0.3",
            "X-ONIOPS-Signature": f"hmac-sha256:{sig}",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            return 200 <= int(getattr(resp, "status", 200)) < 300
    except Exception:
        return False


def validate_evidence(evidence: str, expected_indicator: str = "", category: str = "") -> str:
    """Independently verify whether captured command output confirms a finding.

    Prevents unverified LLM claims or empty scanner output from being marked
    VERIFIED without deterministic indicator or vulnerability-class confirmation.
    """
    text = (evidence or "").strip()
    if not text:
        return "UNCONFIRMED"
    cat = (category or "").lower().strip()
    if cat in _VULN_PROOF_PATTERNS:
        if _VULN_PROOF_PATTERNS[cat].search(text):
            return "VERIFIED"
        if expected_indicator and expected_indicator.strip().lower() in text.lower():
            return "VERIFIED"
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
        if code in (401, 403):
            return "AUTH-GATED" if cat == "service_exposure" else "UNCONFIRMED"
        if code in (200, 201, 204):
            # A live 2xx proves a service is EXPOSED, but not that an arbitrary
            # vulnerability is present. Only self-proving categories (the finding
            # *is* "the service responded") may be VERIFIED without an indicator.
            return "VERIFIED" if cat in ("service_exposure", "exposure") else "UNCONFIRMED"
        return "UNCONFIRMED"  # any other status code
    # No indicator, no vuln-proof pattern, no HTTP status line -> we cannot
    # independently confirm anything. Never VERIFIED on content length alone.
    return "UNCONFIRMED"


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
        return connect_sqlite(self.db_path)

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
        # Store the replay command UNREDACTED: retesting an authenticated finding
        # needs the real credential. Secrets are masked wherever a finding leaves
        # the server (see _enrich and retest), never in the stored argv.
        if isinstance(repro_cmd, list):
            cmd_str = json.dumps([str(x) for x in repro_cmd])
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

    @staticmethod
    def _enrich(d: dict) -> dict:
        try:
            cmd_list = json.loads(d.get("repro_cmd") or "[]")
            d["repro_display"] = redact_secrets(shlex.join(cmd_list)) if cmd_list else ""
            d["repro_cmd"] = json.dumps([redact_secrets(str(x)) for x in cmd_list])
        except Exception:
            d["repro_display"] = ""
            d["repro_cmd"] = "[]"
        cat = d.get("category", "")
        title = d.get("title", "")
        d["coverage"] = map_finding_coverage(cat, title)
        d["remediation"] = get_remediation_guide(cat, title)
        d["priority_score"] = compute_priority_score(
            d.get("severity", ""), d.get("status", ""), d.get("confidence", "")
        )
        return d

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
        return [self._enrich(dict(r)) for r in rows]

    def get(self, finding_id: int) -> dict | None:
        with self._conn() as con:
            row = con.execute("SELECT * FROM findings WHERE id = ?", (finding_id,)).fetchone()
        if not row:
            return None
        return self._enrich(dict(row))

    def _get_raw(self, finding_id: int) -> dict | None:
        """Unredacted row, for internal replay only. Never return this to a client."""
        with self._conn() as con:
            row = con.execute("SELECT * FROM findings WHERE id = ?", (finding_id,)).fetchone()
        return dict(row) if row else None

    def retest(self, finding_id: int, runner, scope: Scope) -> dict:
        """Re-run a finding's deterministic PoC command on the attack host with
        ZERO LLM tokens, updating status to VERIFIED, AUTH-GATED, or FIXED."""
        f = self._get_raw(finding_id)
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
        # Findings saved by v0.4.1-0.4.2 had their credentials masked in storage.
        # Replaying a masked token would get a 401/empty reply and wrongly mark a
        # live issue as fixed, so refuse instead of guessing.
        if any("[REDACTED" in str(x) or "sk-[REDACTED]" in str(x) or "gh_[REDACTED]" in str(x) for x in cmd):
            raise ValueError(
                f"Finding #{finding_id}'s replay command lost its credentials (saved by v0.4.1-0.4.2). "
                "Re-run the assessment with the auth header to retest it."
            )
        scope.guard_command(" ".join(cmd))

        res = runner.run(cmd, timeout=30)
        raw_out = (res.out or "").strip()
        # If the replay could not run at all (attack host unreachable, timeout,
        # scope refusal) we learned nothing about the target: never call it FIXED.
        if getattr(res, "rc", 0) == 126 or raw_out.startswith(("SSH connection error", "Command error/timeout")):
            raise ValueError(
                f"Retest of finding #{finding_id} could not run on the attack host "
                f"({raw_out[:120]}). Status left unchanged."
            )
        out = redact_secrets(raw_out)
        ts = _now_iso()
        # Was this finding made with credentials? Then a 401 on replay usually
        # means the credential expired, not that the issue was fixed.
        authed = any(re.match(r"(?i)\s*(authorization|cookie|x-api-key|x-auth-token)\s*:", str(x)) for x in cmd)
        note = ""

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
        elif cat in ("api_security", "bola", "bola_horizontal", "bfla") or "bola" in cat or "bfla" in cat:
            m = re.search(r"HTTP/[\d.]+\s+(\d{3})", out)
            code = int(m.group(1)) if m else None
            if code in (200, 201, 204):
                new_status = "VERIFIED"
            elif code == 401 and authed:
                new_status = "UNCONFIRMED"
                note = "credential rejected (401) — it may have expired; retest with a fresh token. "
            elif code in (401, 403, 404):
                new_status = "FIXED"
            else:
                new_status = "UNCONFIRMED"
        else:
            new_status = "VERIFIED" if (res.ok and out) else "FIXED"

        new_ev = f"[Retest {ts[:19]}] {note}{out[:400] or '(no output — appears remediated/closed)'}"
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
            "repro_cmd": redact_secrets(shlex.join(cmd)),
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
                        dispatch_webhook_alert("finding.regressed", res)
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
    con = connect_sqlite(db_path)
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
    signing_key: str = "",
) -> dict:
    """Create a secret-free, HMAC-SHA256 cryptographically signed execution manifest
    for assessment reproducibility and tamper detection."""
    scope_canonical = ",".join(sorted(scope_cidrs))
    scope_hash = hashlib.sha256(scope_canonical.encode("utf-8")).hexdigest()[:16]
    cmds_canonical = "\n".join(commands_run)
    commands_hash = hashlib.sha256(cmds_canonical.encode("utf-8")).hexdigest()[:16]
    core = {
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
    canonical = json.dumps(core, sort_keys=True, separators=(",", ":")).encode("utf-8")
    manifest_sha256 = hashlib.sha256(canonical).hexdigest()
    key_bytes = (signing_key or "oniops-default-manifest-key").encode("utf-8")
    sig = hmac.new(key_bytes, canonical, hashlib.sha256).hexdigest()
    return {
        **core,
        "manifest_sha256": manifest_sha256,
        "signature": f"hmac-sha256:{sig}",
    }


def verify_assessment_manifest(manifest: dict, signing_key: str = "") -> bool:
    """Verify the SHA-256 integrity and HMAC-SHA256 signature of an assessment manifest."""
    if not isinstance(manifest, dict):
        return False
    core_keys = (
        "assessment_id", "oniops_version", "target_ip", "profile", "scope_hash",
        "commands_hash", "model", "started_at", "completed_at", "evidence_hashes",
    )
    if not all(k in manifest for k in core_keys):
        return False
    core = {k: manifest[k] for k in core_keys}
    canonical = json.dumps(core, sort_keys=True, separators=(",", ":")).encode("utf-8")
    expected_sha = hashlib.sha256(canonical).hexdigest()
    if not hmac.compare_digest(str(manifest.get("manifest_sha256", "")), expected_sha):
        return False
    key_bytes = (signing_key or "oniops-default-manifest-key").encode("utf-8")
    expected_sig = "hmac-sha256:" + hmac.new(key_bytes, canonical, hashlib.sha256).hexdigest()
    return hmac.compare_digest(str(manifest.get("signature", "")), expected_sig)

"""Offline-first CVE / exploit intelligence for ONIOPS.

Turns service banners discovered by ``nmap -sV`` (product + version) into
known-vulnerability intel, with **no external platform required** — no MISP,
no threat-intel server, no mandatory API key.

Two tiers, offline first:

1. **searchsploit** (Exploit-DB) — always used. Runs on the attack host
   against its local Exploit-DB copy. Works air-gapped.
2. **NVD** (optional) — when ``integrations.nvd.enabled`` is true, enrich a
   detected ``product version`` with CVE IDs + CVSS base scores from the free
   public NVD API (no key required; a key just raises rate limits). Best-effort
   and strictly degrading: any network/parse failure falls back to offline-only
   results, never raising into the assessment pipeline.

Everything here is read-only intelligence lookup — it executes no exploits and
performs no destructive action.
"""

from __future__ import annotations

import json
import re
import urllib.parse
import urllib.request
from collections.abc import Callable
from typing import Any

# A banner must carry a dotted version (e.g. "2.4.49", "1.18.0") before we try
# to build a search term — avoids noise from bare "open" / versionless banners.
_VERSION_RE = re.compile(r"\b(\d+\.\d+(?:\.\d+)?(?:[a-z]\d*)?)\b")

# Tokens that are not a product name (OS/distro/qualifiers nmap appends).
_NOISE_TOKENS = {
    "open", "tcp", "udp", "ubuntu", "debian", "linux", "unix", "protocol",
    "http", "https", "ssl", "tls", "or", "later", "and", "based",
}

NVD_ENDPOINT = "https://services.nvd.nist.gov/rest/json/cves/2.0"
# Generic client name — never the user's email / identity.
_UA = "ONIOPS-Security-Scanner (offensive-neural-intelligence)"

_SEV_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "NONE": 0}


def extract_product_version(banner: str) -> tuple[str, str] | None:
    """Best-effort (product, version) from an nmap -sV banner.

    "Apache httpd 2.4.49 ((Unix))" -> ("Apache httpd", "2.4.49")
    "OpenSSH 8.2p1 Ubuntu 4ubuntu0.5" -> ("OpenSSH", "8.2p1")
    "nginx 1.18.0" -> ("nginx", "1.18.0")
    Returns None when no usable version is present.
    """
    if not banner:
        return None
    m = _VERSION_RE.search(banner)
    if not m:
        return None
    version = m.group(1)
    # Product = meaningful words that appear before the version token.
    head = banner[: m.start()].strip()
    words = [w for w in re.split(r"\s+", head) if w]
    product_words: list[str] = []
    for w in words:
        wl = w.strip("()[],").lower()
        if not wl or wl in _NOISE_TOKENS:
            continue
        product_words.append(w.strip("()[],"))
    if not product_words:
        return None
    # Keep it to the first two tokens (e.g. "Apache httpd") to stay specific.
    product = " ".join(product_words[:2])
    return product, version


def _parse_searchsploit(raw: str) -> list[dict[str, str]]:
    """Parse searchsploit output (JSON preferred, text fallback)."""
    raw = (raw or "").strip()
    if not raw:
        return []
    # JSON mode: {"RESULTS_EXPLOIT": [{"Title":..., "EDB-ID":..., "Path":...}]}
    if raw.startswith("{"):
        try:
            data = json.loads(raw)
            out = []
            for r in (data.get("RESULTS_EXPLOIT") or [])[:8]:
                title = (r.get("Title") or "").strip()
                if not title:
                    continue
                out.append({"title": title, "edb_id": str(r.get("EDB-ID") or "").strip()})
            return out
        except (ValueError, TypeError):
            pass
    # Text fallback: table rows "Title | path". Skip headers/separators.
    out = []
    for line in raw.splitlines():
        line = line.strip()
        if not line or set(line) <= {"-", " "}:
            continue
        if line.lower().startswith(("exploit title", "shellcode title", "paper title")):
            continue
        if "|" in line:
            title = line.split("|", 1)[0].strip()
            if title and title.lower() != "exploit title" and any(c.isalnum() for c in title):
                out.append({"title": title, "edb_id": ""})
    return out[:8]


def search_exploitdb(product: str, version: str, run_fn: Callable[[list[str], int], str]) -> list[dict[str, str]]:
    """Query the attack host's local Exploit-DB. Offline; version first, then
    product alone if the version-specific search is empty."""
    try:
        raw = run_fn(["searchsploit", "--json", product, version], 25)
    except Exception:
        raw = ""
    hits = _parse_searchsploit(raw)
    if not hits:
        try:
            raw = run_fn(["searchsploit", "--json", product], 25)
        except Exception:
            raw = ""
        hits = _parse_searchsploit(raw)
    return hits


def query_nvd(product: str, version: str, timeout: int = 8, api_key: str = "") -> list[dict[str, Any]]:
    """Optional NVD enrichment. Best-effort; returns [] on any failure."""
    keyword = f"{product} {version}".strip()
    qs = urllib.parse.urlencode({"keywordSearch": keyword, "resultsPerPage": 5})
    req = urllib.request.Request(f"{NVD_ENDPOINT}?{qs}", headers={"User-Agent": _UA})
    if api_key:
        req.add_header("apiKey", api_key)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read().decode("utf-8", "replace"))
    except Exception:
        return []
    out: list[dict[str, Any]] = []
    for item in (data.get("vulnerabilities") or [])[:5]:
        cve = item.get("cve") or {}
        cid = cve.get("id")
        if not cid:
            continue
        score, sev = None, "UNKNOWN"
        metrics = cve.get("metrics") or {}
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            arr = metrics.get(key) or []
            if arr:
                cvss = arr[0].get("cvssData") or {}
                score = cvss.get("baseScore")
                sev = (arr[0].get("baseSeverity") or cvss.get("baseSeverity") or "UNKNOWN").upper()
                break
        out.append({"id": cid, "cvss": score, "severity": sev})
    return out


def enrich(ports: list[dict], cfg: Any, run_fn: Callable[[list[str], int], str],
           ctl=None) -> dict[str, Any]:
    """Run offline-first CVE/exploit intel over discovered ports.

    Returns a dict with a human-readable ``raw_section``, structured
    ``findings``, counts, and ``max_severity`` (NVD-derived) so the caller can
    factor known-CVE severity into the overall rating.
    """
    integrations = getattr(cfg, "integrations", {}) or {}
    nvd_cfg = integrations.get("nvd", {}) or {}
    nvd_enabled = bool(nvd_cfg.get("enabled"))
    nvd_key = str(nvd_cfg.get("api_key") or "")

    findings: list[dict[str, Any]] = []
    seen_terms: set[str] = set()
    exploit_count = 0
    cve_count = 0
    max_sev_rank = 0

    for p in ports[:12]:
        if ctl is not None and not ctl.checkpoint():
            break
        pv = extract_product_version(p.get("banner", ""))
        if not pv:
            continue
        product, version = pv
        term = f"{product} {version}".lower()
        if term in seen_terms:
            continue
        seen_terms.add(term)

        exploits = search_exploitdb(product, version, run_fn)
        cves: list[dict[str, Any]] = []
        if nvd_enabled:
            cves = query_nvd(product, version, api_key=nvd_key)

        if not exploits and not cves:
            continue
        exploit_count += len(exploits)
        cve_count += len(cves)
        for c in cves:
            max_sev_rank = max(max_sev_rank, _SEV_RANK.get(c.get("severity", ""), 0))
        findings.append({
            "port": p.get("port"), "service": p.get("service"),
            "product": product, "version": version,
            "exploits": exploits, "cves": cves,
        })

    # Build the report section.
    lines: list[str] = []
    for f in findings:
        hdr = f"- {f['port']}/{f['service']}  {f['product']} {f['version']}"
        lines.append(hdr)
        for c in f["cves"]:
            sc = f" CVSS {c['cvss']}" if c.get("cvss") is not None else ""
            lines.append(f"    CVE: {c['id']} [{c.get('severity','?')}]{sc}")
        for e in f["exploits"][:6]:
            eid = f" (EDB-{e['edb_id']})" if e.get("edb_id") else ""
            lines.append(f"    Exploit-DB: {e['title']}{eid}")
    body = "\n".join(lines) if lines else "No known public exploits/CVEs matched the detected service versions."
    src = "searchsploit (offline)" + (" + NVD" if nvd_enabled else "")
    raw_section = (f"=== CVE / Exploit Intelligence ({src}) ===\n"
                   f"{cve_count} CVE(s), {exploit_count} Exploit-DB entr(ies) across "
                   f"{len(findings)} versioned service(s).\n{body}")

    max_severity = next((s for s, r in _SEV_RANK.items() if r == max_sev_rank), "NONE")
    return {
        "findings": findings, "raw_section": raw_section,
        "exploit_count": exploit_count, "cve_count": cve_count,
        "max_severity": max_severity, "nvd_enabled": nvd_enabled,
    }

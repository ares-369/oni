"""Responsible-use terms: first-run acceptance, recorded server-side.

Before anyone can launch scans, agents or AI tests from the web UI, they must
confirm they will only test systems they own or are authorized to test, and
accept the responsible-use terms (see DISCLAIMER.md / NOTICE).

Each acceptance is stored with the user, time and terms version, so there is a
record of who agreed to what and when. Bumping TERMS_VERSION asks everyone to
accept again (e.g. after the disclaimer changes).
"""

from __future__ import annotations

import sqlite3
from datetime import datetime, timezone
from pathlib import Path

# Bump when DISCLAIMER.md / NOTICE change materially -> users re-accept.
TERMS_VERSION = "2026-11-09"

DISCLAIMER_URL = "https://github.com/ares-369/oniops/blob/main/DISCLAIMER.md"

SUMMARY = [
    "Only test systems you own, or have explicit written permission to test. "
    "Unauthorized testing is illegal in most countries.",
    "ONIOPS is provided as-is, without warranty. You are solely responsible for how "
    "you use it and for following the laws that apply to you.",
    "The author is not responsible for misuse, for harm to any person, company or "
    "organization, or for modified versions of ONIOPS made by others.",
    "The scope allow-list and non-destructive guard are safety aids, not a "
    "guarantee and not a substitute for permission.",
]

# Web endpoints that start active testing. They are refused until the current
# user has accepted the current terms version.
GATED_PREFIXES = (
    "/api/assess",          # /api/assess and /api/assess/start
    "/api/discover",
    "/api/agent/start",
    "/api/aisec/start",
    "/api/findings/",       # retest one / retest-all (active re-probes)
    "/api/kali/install",
    "/api/chat",            # the AI operator can run tools
)


def is_gated(method: str, path: str) -> bool:
    return method == "POST" and any(path.startswith(p) for p in GATED_PREFIXES)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class TermsStore:
    """Append-only record of terms acceptances in the ONIOPS SQLite DB."""

    def __init__(self, db_path: str | Path):
        self.db_path = str(db_path)
        self._accepted: set[tuple[str, str]] = set()
        with sqlite3.connect(self.db_path, timeout=30) as conn:
            conn.execute("""
            CREATE TABLE IF NOT EXISTS terms_acceptance (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user TEXT NOT NULL,
                version TEXT NOT NULL,
                accepted_at TEXT NOT NULL,
                remote_addr TEXT,
                user_agent TEXT
            )""")
            conn.commit()

    def accepted_at(self, user: str, version: str = TERMS_VERSION) -> str | None:
        with sqlite3.connect(self.db_path, timeout=30) as conn:
            row = conn.execute(
                "SELECT accepted_at FROM terms_acceptance WHERE user=? AND version=? "
                "ORDER BY id DESC LIMIT 1", (user, version)).fetchone()
        return row[0] if row else None

    def has_accepted(self, user: str, version: str = TERMS_VERSION) -> bool:
        key = (user, version)
        if key in self._accepted:
            return True
        if self.accepted_at(user, version):
            self._accepted.add(key)
            return True
        return False

    def record(self, user: str, remote_addr: str = "", user_agent: str = "",
               version: str = TERMS_VERSION) -> str:
        ts = _now()
        with sqlite3.connect(self.db_path, timeout=30) as conn:
            conn.execute(
                "INSERT INTO terms_acceptance (user, version, accepted_at, remote_addr, user_agent) "
                "VALUES (?,?,?,?,?)", (user, version, ts, remote_addr[:64], user_agent[:300]))
            conn.commit()
        self._accepted.add((user, version))
        return ts

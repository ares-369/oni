"""Lightweight background job engine.

Long assessments (full PTT, WAPT) can run for minutes; running them inside the
HTTP request ties up a worker and makes the UI spin. The JobManager runs them
on a small thread pool and records status in SQLite, so the UI can enqueue a
job and poll for progress. No external broker (Redis/Celery) required — keeps
ONIOPS self-hostable with nothing extra to install.
"""

from __future__ import annotations

import json
import sqlite3
import time
import traceback
import uuid
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from typing import Any


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


class JobControl:
    """Passed into a job's function so it can be paused/stopped cooperatively.
    The function calls checkpoint() at safe boundaries (between tools/steps)."""

    def __init__(self, mgr: JobManager, job_id: str):
        self.mgr = mgr
        self.job_id = job_id

    @property
    def cancelled(self) -> bool:
        return self.mgr._control.get(self.job_id) == "cancel"

    def checkpoint(self) -> bool:
        """Block while paused; return False if the job should stop."""
        while self.mgr._control.get(self.job_id) == "pause":
            time.sleep(0.4)
        return self.mgr._control.get(self.job_id) != "cancel"


class JobManager:
    def __init__(self, db_path, max_workers: int = 3):
        self.db_path = str(db_path)
        self.pool = ThreadPoolExecutor(max_workers=max_workers, thread_name_prefix="oniops-job")
        self._control: dict[str, str] = {}
        self._init_db()
        self._reconcile_orphans()

    def _conn(self):
        con = sqlite3.connect(self.db_path, timeout=30)
        try:
            con.execute("PRAGMA journal_mode=WAL")
            con.execute("PRAGMA busy_timeout=5000")
        except Exception:
            pass
        return con

    def _init_db(self):
        with self._conn() as conn:
            conn.execute("""
            CREATE TABLE IF NOT EXISTS jobs (
                id TEXT PRIMARY KEY,
                kind TEXT NOT NULL,
                meta TEXT NOT NULL,
                status TEXT NOT NULL,
                created TEXT NOT NULL,
                finished TEXT,
                result TEXT,
                error TEXT
            )""")
            conn.commit()

    def _reconcile_orphans(self):
        """On startup the thread pool is empty, so any job still marked
        queued/running in SQLite is a ghost from a previous process (crash,
        reboot, redeploy). Mark them interrupted so the UI never shows a job
        that will never finish."""
        with self._conn() as conn:
            conn.execute(
                "UPDATE jobs SET status='interrupted', finished=?, "
                "error='Process restarted before this job completed.' "
                "WHERE status IN ('queued','running')",
                (_now(),),
            )
            conn.commit()

    def _set(self, job_id: str, **fields):
        cols = ", ".join(f"{k}=?" for k in fields)
        with self._conn() as conn:
            conn.execute(f"UPDATE jobs SET {cols} WHERE id=?", (*fields.values(), job_id))
            conn.commit()

    def submit(self, kind: str, meta: dict[str, Any], fn: Callable[[JobControl], dict]) -> str:
        job_id = uuid.uuid4().hex[:12]
        self._control[job_id] = "run"
        with self._conn() as conn:
            conn.execute(
                "INSERT INTO jobs (id, kind, meta, status, created) VALUES (?,?,?,?,?)",
                (job_id, kind, json.dumps(meta), "queued", _now()),
            )
            conn.commit()
        self.pool.submit(self._run, job_id, fn)
        return job_id

    def _run(self, job_id: str, fn: Callable[[JobControl], dict]):
        self._set(job_id, status="running")
        ctl = JobControl(self, job_id)
        try:
            result = fn(ctl)
            status = "cancelled" if self._control.get(job_id) == "cancel" else "done"
            self._set(job_id, status=status, finished=_now(), result=json.dumps(result))
        except Exception as exc:
            self._set(job_id, status="error", finished=_now(),
                      error=f"{exc}\n{traceback.format_exc()[-800:]}")
        finally:
            self._control.pop(job_id, None)

    # ---- cooperative control ----
    def cancel(self, job_id: str) -> bool:
        if job_id in self._control:
            self._control[job_id] = "cancel"
            return True
        return False

    def pause(self, job_id: str) -> bool:
        if self._control.get(job_id) == "run":
            self._control[job_id] = "pause"
            return True
        return False

    def resume(self, job_id: str) -> bool:
        if self._control.get(job_id) == "pause":
            self._control[job_id] = "run"
            return True
        return False

    def get(self, job_id: str) -> dict | None:
        with self._conn() as conn:
            conn.row_factory = sqlite3.Row
            row = conn.execute("SELECT * FROM jobs WHERE id=?", (job_id,)).fetchone()
        if not row:
            return None
        d = dict(row)
        d["meta"] = json.loads(d["meta"]) if d["meta"] else {}
        d["result"] = json.loads(d["result"]) if d["result"] else None
        return d

    def list(self, limit: int = 20) -> list[dict]:
        with self._conn() as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute(
                "SELECT id, kind, meta, status, created, finished FROM jobs ORDER BY created DESC LIMIT ?",
                (limit,),
            ).fetchall()
        out = []
        for r in rows:
            d = dict(r)
            d["meta"] = json.loads(d["meta"]) if d["meta"] else {}
            out.append(d)
        return out

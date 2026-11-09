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
import threading
import time
import traceback
import uuid
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from typing import Any

_MAX_RESULT_CHARS = 250_000
_DEFAULT_JOB_BUDGET_SEC = 900.0


# Each worker thread runs one job at a time; remember which, so progress
# events can be attributed to the job that produced them.
_current = threading.local()


def current_job_id() -> str | None:
    """ID of the job running on this thread, or None outside a job."""
    return getattr(_current, "job_id", None)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


class JobControl:
    """Passed into a job's function so it can be paused/stopped cooperatively.
    The function calls checkpoint() at safe boundaries (between tools/steps)."""

    def __init__(self, mgr: JobManager, job_id: str, max_runtime_sec: float = _DEFAULT_JOB_BUDGET_SEC):
        self.mgr = mgr
        self.job_id = job_id
        self.started_monotonic = time.monotonic()
        self.max_runtime_sec = max_runtime_sec

    @property
    def cancelled(self) -> bool:
        return self.mgr._control.get(self.job_id) == "cancel"

    def checkpoint(self) -> bool:
        """Block while paused; update heartbeat; return False if cancelled or budget exceeded."""
        while self.mgr._control.get(self.job_id) == "pause":
            time.sleep(0.4)
        if time.monotonic() - self.started_monotonic > self.max_runtime_sec:
            self.mgr._control[self.job_id] = "cancel"
            return False
        try:
            self.mgr._set(self.job_id, heartbeat=_now())
        except Exception:
            pass
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
                heartbeat TEXT DEFAULT '',
                finished TEXT,
                result TEXT,
                error TEXT
            )""")
            cols = {r[1] for r in conn.execute("PRAGMA table_info(jobs)").fetchall()}
            if "heartbeat" not in cols:
                conn.execute("ALTER TABLE jobs ADD COLUMN heartbeat TEXT DEFAULT ''")
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

    def submit(
        self,
        kind: str,
        meta: dict[str, Any],
        fn: Callable[[JobControl], dict],
        *,
        deduplicate: bool = True,
    ) -> str:
        meta_json = json.dumps(meta, sort_keys=True)
        if deduplicate:
            with self._conn() as conn:
                existing = conn.execute(
                    "SELECT id FROM jobs WHERE kind=? AND meta=? AND status IN ('queued','running') LIMIT 1",
                    (kind, meta_json),
                ).fetchone()
                if existing and existing[0] in self._control:
                    return str(existing[0])
        job_id = uuid.uuid4().hex[:12]
        now_ts = _now()
        self._control[job_id] = "run"
        with self._conn() as conn:
            conn.execute(
                "INSERT INTO jobs (id, kind, meta, status, created, heartbeat) VALUES (?,?,?,?,?,?)",
                (job_id, kind, meta_json, "queued", now_ts, now_ts),
            )
            conn.commit()
        self.pool.submit(self._run, job_id, fn)
        return job_id

    def _run(self, job_id: str, fn: Callable[[JobControl], dict]):
        self._set(job_id, status="running", heartbeat=_now())
        ctl = JobControl(self, job_id)
        _current.job_id = job_id   # lets emit_event() tag progress events with this job
        try:
            result = fn(ctl)
            status = "cancelled" if self._control.get(job_id) == "cancel" else "done"
            serialized = json.dumps(result)
            if len(serialized) > _MAX_RESULT_CHARS:
                serialized = json.dumps({"truncated": True, "preview": serialized[:_MAX_RESULT_CHARS]})
            self._set(job_id, status=status, heartbeat=_now(), finished=_now(), result=serialized)
        except Exception as exc:
            self._set(job_id, status="error", heartbeat=_now(), finished=_now(),
                      error=f"{exc}\n{traceback.format_exc()[-800:]}")
        finally:
            _current.job_id = None
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

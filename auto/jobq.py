"""SQLite job queue for P4 Mini-CRS auto-pipeline.

Jobs flow: pending -> running -> {done, failed}
Agent pops one pending job at a time (FIFO).
"""

from __future__ import annotations

import json
import os
import sqlite3
import threading
import uuid
from pathlib import Path
from typing import Any

DB_PATH = Path(os.getenv("P4_DB_PATH", str(Path(__file__).parent / "jobq.db")))
_lock = threading.Lock()

TERMINAL = ("done", "failed")
RUNNING = ("running",)


def _conn() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init() -> None:
    with _conn() as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS jobs (
                job_id       TEXT PRIMARY KEY,
                status       TEXT NOT NULL,
                target       TEXT NOT NULL,
                source       TEXT NOT NULL,
                fuzz_time    INTEGER NOT NULL DEFAULT 60,
                sarif_path   TEXT,
                severity     TEXT,
                action       TEXT,
                stack_hash   TEXT,
                error        TEXT,
                created_at   DATETIME DEFAULT CURRENT_TIMESTAMP,
                started_at   DATETIME,
                finished_at  DATETIME
            )
            """
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_jobs_status ON jobs(status, created_at)"
        )


def resume_pending() -> None:
    """On startup, revert orphaned running jobs to pending so they re-run."""
    with _conn() as conn:
        conn.execute(
            "UPDATE jobs SET status='pending', started_at=NULL WHERE status='running'"
        )


def enqueue(target: str, source: str, fuzz_time: int = 60) -> str:
    """Add a new job. Dedupes against existing pending/running for same target."""
    job_id = str(uuid.uuid4())
    with _lock, _conn() as conn:
        existing = conn.execute(
            "SELECT job_id FROM jobs WHERE target=? AND status IN ('pending','running')",
            (target,),
        ).fetchone()
        if existing:
            return existing["job_id"]
        conn.execute(
            "INSERT INTO jobs(job_id,status,target,source,fuzz_time) VALUES(?,?,?,?,?)",
            (job_id, "pending", target, source, fuzz_time),
        )
    return job_id


def pop_pending() -> dict[str, Any] | None:
    """Atomically claim the oldest pending job, set to running."""
    with _lock, _conn() as conn:
        row = conn.execute(
            "SELECT * FROM jobs WHERE status='pending' ORDER BY created_at LIMIT 1"
        ).fetchone()
        if not row:
            return None
        conn.execute(
            "UPDATE jobs SET status='running', started_at=CURRENT_TIMESTAMP WHERE job_id=?",
            (row["job_id"],),
        )
        return dict(row)


def finish(job_id: str, sarif_path: str | None, severity: str | None,
           action: str | None, stack_hash: str | None = None) -> None:
    with _lock, _conn() as conn:
        conn.execute(
            """UPDATE jobs SET status='done', sarif_path=?, severity=?, action=?,
                   stack_hash=?, finished_at=CURRENT_TIMESTAMP WHERE job_id=?""",
            (sarif_path, severity, action, stack_hash, job_id),
        )


def fail(job_id: str, error: str) -> None:
    with _lock, _conn() as conn:
        conn.execute(
            "UPDATE jobs SET status='failed', error=?, finished_at=CURRENT_TIMESTAMP WHERE job_id=?",
            (error, job_id),
        )


def seen_stack_hash(target: str, stack_hash: str) -> bool:
    """True if we've already reported this (target, stack_hash) pair."""
    if not stack_hash:
        return False
    with _conn() as conn:
        row = conn.execute(
            "SELECT 1 FROM jobs WHERE target=? AND stack_hash=? AND status='done' LIMIT 1",
            (target, stack_hash),
        ).fetchone()
    return row is not None


def prior_findings(target: str, limit: int = 20) -> list[dict]:
    """Return prior done jobs for a target with (stack_hash, severity, action, finished_at).

    Used by the agent to dedup repeat alerts across runs.
    """
    with _conn() as conn:
        rows = conn.execute(
            """SELECT stack_hash, severity, action, finished_at FROM jobs
               WHERE target=? AND status='done' AND stack_hash IS NOT NULL
               ORDER BY finished_at DESC LIMIT ?""",
            (target, limit),
        ).fetchall()
    return [dict(r) for r in rows]


def counts_by_status() -> dict[str, int]:
    """Count jobs grouped by status. Dashboard overview."""
    with _conn() as conn:
        rows = conn.execute(
            "SELECT status, COUNT(*) as n FROM jobs GROUP BY status"
        ).fetchall()
    return {r["status"]: r["n"] for r in rows}


def counts_by_severity() -> dict[str, int]:
    """Count done jobs grouped by severity."""
    with _conn() as conn:
        rows = conn.execute(
            "SELECT COALESCE(severity, 'UNKNOWN') as severity, COUNT(*) as n "
            "FROM jobs WHERE status='done' GROUP BY severity"
        ).fetchall()
    return {r["severity"]: r["n"] for r in rows}


def find_by_target(target: str, limit: int = 50) -> list[dict]:
    """All jobs for a target, newest first."""
    with _conn() as conn:
        rows = conn.execute(
            "SELECT * FROM jobs WHERE target=? ORDER BY created_at DESC LIMIT ?",
            (target, limit),
        ).fetchall()
    return [dict(r) for r in rows]


def distinct_targets() -> list[dict]:
    """Each target w/ job count + latest status + severity."""
    with _conn() as conn:
        rows = conn.execute(
            """SELECT target, COUNT(*) as n_jobs,
                      MAX(created_at) as last_seen,
                      (SELECT severity FROM jobs j2 WHERE j2.target=jobs.target
                       AND j2.status='done' ORDER BY finished_at DESC LIMIT 1) as last_severity
               FROM jobs GROUP BY target ORDER BY last_seen DESC"""
        ).fetchall()
    return [dict(r) for r in rows]


def critical_findings(limit: int = 100) -> list[dict]:
    """Done jobs with severity CRITICAL/HIGH/MEDIUM, newest first."""
    with _conn() as conn:
        rows = conn.execute(
            """SELECT * FROM jobs WHERE status='done'
               AND severity IN ('CRITICAL','HIGH','MEDIUM')
               ORDER BY finished_at DESC LIMIT ?""",
            (limit,),
        ).fetchall()
    return [dict(r) for r in rows]


def list_jobs(limit: int = 50) -> list[dict]:
    with _conn() as conn:
        rows = conn.execute(
            "SELECT * FROM jobs ORDER BY created_at DESC LIMIT ?", (limit,)
        ).fetchall()
    return [dict(r) for r in rows]


if __name__ == "__main__":
    import sys
    init()
    print(f"jobq.db initialized at {DB_PATH}")
    if len(sys.argv) > 1 and sys.argv[1] == "list":
        for j in list_jobs():
            print(json.dumps(j, default=str))

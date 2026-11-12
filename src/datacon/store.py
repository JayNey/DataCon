"""PostgreSQL persistence for the task entry point."""

from __future__ import annotations

from uuid import UUID, uuid4

import psycopg
from psycopg.types.json import Jsonb


def submit(dsn: str, request: dict) -> dict:
    """Insert one queued job and return its identity and initial state."""
    job_id = uuid4()
    with psycopg.connect(dsn, connect_timeout=5) as connection:
        row = connection.execute(
            "INSERT INTO jobs (job_id, request) VALUES (%s, %s) RETURNING state",
            (job_id, Jsonb(request)),
        ).fetchone()
    return {"job_id": str(job_id), "state": row[0]}


def status(dsn: str, job_id: UUID) -> dict | None:
    """Read one job; return None when the identifier is unknown."""
    with psycopg.connect(dsn, connect_timeout=5) as connection:
        row = connection.execute(
            "SELECT state FROM jobs WHERE job_id = %s", (job_id,)
        ).fetchone()
    if row is None:
        return None
    return {
        "job_id": str(job_id),
        "state": row[0],
        "stage": None,
        "pending_plan": None,
        "review_state": None,
        "reason_code": None,
        "last_error": None,
        "evidence_refs": [],
    }

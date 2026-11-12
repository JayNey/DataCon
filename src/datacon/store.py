"""PostgreSQL persistence for the task entry point."""

from __future__ import annotations

from uuid import UUID, uuid4

import psycopg
from psycopg.types.json import Jsonb


def initial_state(request: dict) -> tuple[str, str | None]:
    """Return the submit-time state and reason code for a valid request.

    Binary targets are structurally valid but outside the MVP scope, so they
    are archived as BLOCKED instead of being queued for a Supervisor.
    """
    if request["target"]["kind"] == "binary":
        return "BLOCKED", "UNSUPPORTED_TARGET"
    return "QUEUED", None


def submit(dsn: str, request: dict) -> dict:
    """Insert one job and return its identity and initial state."""
    job_id = uuid4()
    state, reason_code = initial_state(request)
    with psycopg.connect(dsn, connect_timeout=5) as connection:
        row = connection.execute(
            "INSERT INTO jobs (job_id, request, state, reason_code) "
            "VALUES (%s, %s, %s, %s) RETURNING state",
            (job_id, Jsonb(request), state, reason_code),
        ).fetchone()
    return {"job_id": str(job_id), "state": row[0]}


def status(dsn: str, job_id: UUID) -> dict | None:
    """Read one job; return None when the identifier is unknown."""
    with psycopg.connect(dsn, connect_timeout=5) as connection:
        row = connection.execute(
            "SELECT state, reason_code FROM jobs WHERE job_id = %s", (job_id,)
        ).fetchone()
    if row is None:
        return None
    return {
        "job_id": str(job_id),
        "state": row[0],
        "stage": None,
        "pending_plan": None,
        "review_state": None,
        "reason_code": row[1],
        "last_error": None,
        "evidence_refs": [],
    }

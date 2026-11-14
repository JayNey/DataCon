"""PostgreSQL persistence for the task entry point."""

from __future__ import annotations

from uuid import UUID, uuid4

import psycopg
from psycopg.types.json import Jsonb

from datacon import state


def initial_state(request: dict) -> tuple[str, str | None]:
    """Return the submit-time state and reason code for a valid request.

    Binary targets are structurally valid but outside the MVP scope, so they
    are archived as BLOCKED instead of being queued for a Supervisor.
    """
    if request["target"]["kind"] == "binary":
        return "BLOCKED", "UNSUPPORTED_TARGET"
    return "QUEUED", None


def submit(dsn: str, request: dict, *, operator_id: str | None = None) -> dict:
    """Insert one job and return its identity and initial state."""
    job_id = uuid4()
    job_state, reason_code = initial_state(request)
    with psycopg.connect(dsn, connect_timeout=5) as connection:
        row = connection.execute(
            "INSERT INTO jobs "
            "(job_id, request, state, reason_code, operator_id, workflow_synced) "
            "VALUES (%s, %s, %s, %s, %s, %s) RETURNING state",
            (
                job_id,
                Jsonb(request),
                job_state,
                reason_code,
                operator_id,
                job_state == "BLOCKED",
            ),
        ).fetchone()
    return {"job_id": str(job_id), "state": row[0]}


def status(dsn: str, job_id: UUID) -> dict | None:
    """Read one job; return None when the identifier is unknown."""
    return state.status(dsn, job_id)

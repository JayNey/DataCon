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


def _submit_v2(dsn: str, request: dict, *, operator_id: str | None = None) -> dict:
    """Insert the v2 family row and return its identity and initial state.

    A v2 submit creates exactly one family job. The first child/plan is created
    later (T11), so this path must not depend on ``initial_state`` nor write a
    plan. Binary targets remain structurally valid but outside the MVP scope;
    they get the same family identity, archived as BLOCKED like a v1 submit.
    """
    family_id = uuid4()
    binary = request["target"]["kind"] == "binary"
    job_state = "BLOCKED" if binary else "AGGREGATING"
    reason_code = "UNSUPPORTED_TARGET" if binary else None
    with psycopg.connect(dsn, connect_timeout=5) as connection:
        # Same transaction-scoped release lock as the v1 path and claim_next.
        connection.execute(
            "SELECT pg_advisory_xact_lock_shared(hashtext(%s))",
            (state.RELEASE_LOCK_PREFIX + state.RELEASE_ENVIRONMENT,),
        )
        connection.execute(
            "INSERT INTO jobs "
            "(job_id, request, state, stage, reason_code, operator_id, "
            "workflow_synced, job_contract_version, family_id, job_kind, "
            "parent_job_id, round_no) "
            "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)",
            (
                family_id,
                Jsonb(request),
                job_state,
                "family",
                reason_code,
                operator_id,
                True,
                2,
                family_id,
                "family",
                None,
                None,
            ),
        )
        exploration = request.get("exploration")
        guided = isinstance(exploration, dict) and exploration.get("mode") == "guided"
        if guided and not binary:
            # T12 (改9 增补): a guided family's first plan is its campaign.
            # The campaign child is queued with the family, in the same
            # transaction, so the worker's v2 prepare entry can freeze the
            # campaign plan and envelope for the human review.
            connection.execute(
                "INSERT INTO jobs "
                "(job_id, request, state, reason_code, operator_id, "
                "workflow_synced, job_contract_version, family_id, job_kind, "
                "parent_job_id, round_no) "
                "VALUES (%s, %s, 'QUEUED', NULL, %s, false, 2, %s, 'campaign', "
                "%s, NULL)",
                (uuid4(), Jsonb(request), operator_id, family_id, family_id),
            )
    if binary:
        # A submit-time rejection never enters a worker claim, so it has no
        # lease and must use the same direct blocked-evidence path as v1. A
        # family row has no plan yet; record_blocked tolerates that and archives
        # the block without inventing one.
        from datacon import execution

        execution.record_blocked(
            dsn,
            family_id,
            generation=0,
            reason_code="UNSUPPORTED_TARGET",
            message=(
                "binary targets are not supported; only source targets can be "
                "analyzed"
            ),
        )
        with psycopg.connect(dsn, connect_timeout=5) as connection:
            current = connection.execute(
                "SELECT state FROM jobs WHERE job_id = %s", (family_id,)
            ).fetchone()
        if current is not None:
            job_state = current[0]
    return {"job_id": str(family_id), "state": job_state}


def submit(dsn: str, request: dict, *, operator_id: str | None = None) -> dict:
    """Insert one job and return its identity and initial state."""
    if request.get("schema_version") == 2:
        return _submit_v2(dsn, request, operator_id=operator_id)
    job_id = uuid4()
    job_state, reason_code = initial_state(request)
    with psycopg.connect(dsn, connect_timeout=5) as connection:
        # A submit may run while a release is being promoted. Take the shared
        # side of the same release lock that claim_next takes so a promotion
        # holding the exclusive side cannot interleave with a new job going
        # in; submit waits for the promotion and then targets the new release.
        # The lock is transaction-scoped and released when the with block
        # commits, after the INSERT.
        connection.execute(
            "SELECT pg_advisory_xact_lock_shared(hashtext(%s))",
            (state.RELEASE_LOCK_PREFIX + state.RELEASE_ENVIRONMENT,),
        )
        connection.execute(
            "INSERT INTO jobs "
            "(job_id, request, state, reason_code, operator_id, workflow_synced) "
            "VALUES (%s, %s, %s, %s, %s, %s)",
            (
                job_id,
                Jsonb(request),
                job_state,
                reason_code,
                operator_id,
                job_state == "BLOCKED",
            ),
        )
    if job_state == "BLOCKED":
        # Submit-time rejection never enters a worker claim, so it has no lease
        # and cannot use the execution archive path. Archive the standalone
        # blocked evidence bundle and record it directly.
        from datacon import execution

        execution.record_blocked(
            dsn,
            job_id,
            generation=0,
            reason_code=reason_code or "UNSUPPORTED_TARGET",
            message=(
                "binary targets are not supported; only source targets can be "
                "analyzed"
            ),
        )
        with psycopg.connect(dsn, connect_timeout=5) as connection:
            current = connection.execute(
                "SELECT state FROM jobs WHERE job_id = %s", (job_id,)
            ).fetchone()
        if current is not None:
            job_state = current[0]
    return {"job_id": str(job_id), "state": job_state}


def status(dsn: str, job_id: UUID) -> dict | None:
    """Read one job; return None when the identifier is unknown."""
    return state.status(dsn, job_id)

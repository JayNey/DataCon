"""Business records and transitions for the Supervisor workflow."""

from __future__ import annotations

from contextlib import ExitStack, contextmanager
from dataclasses import dataclass
import hashlib
from pathlib import Path
import re
import threading
import uuid
from typing import Any, Mapping
from uuid import UUID

import psycopg
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb

from datacon import jsonutil

REVIEW_WINDOW_HOURS = 24
# The default lease must cover the largest preparation budget (600s) so a
# legitimate single analysis pass cannot be stolen mid-flight. A production
# heartbeat can extend this later; the lease is never shorter than the budget.
LEASE_SECONDS = 600
# The single control-plane release environment. It is defined before the job
# claim path because claiming a job and switching a release must take the same
# advisory lock (shared for claim, exclusive for promote/rollback).
RELEASE_ENVIRONMENT = "internal-lab"
RELEASE_LOCK_PREFIX = "datacon:release:"
ATTEMPT_STATUSES = frozenset({"started", "completed", "infra_error"})
# Attempt results are structured metadata, not a second copy of raw logs.
# Keeping them bounded prevents a chatty tool from bloating PostgreSQL or
# turning a journal row into an unbounded trust source.
MAX_ATTEMPT_RESULT_BYTES = 512 * 1024


class StateError(RuntimeError):
    """A business-state operation is not allowed."""


class StaleGeneration(StateError):
    """The caller no longer owns the execution generation."""


class PlanConflict(StateError):
    """A different plan was already frozen for this job."""


@dataclass(frozen=True)
class ReviewOutcome:
    status: str
    state: str | None = None
    review: dict[str, Any] | None = None
    message: str | None = None

    @property
    def reason_code(self) -> str:
        return {
            "plan_mismatch": "PLAN_MISMATCH",
            "conflict": "REVIEW_CONFLICT",
            "expired": "REVIEW_EXPIRED",
            "invalid_state": "INVALID_STATE",
            "envelope_mismatch": "REVIEW_ENVELOPE_MISMATCH",
            "job_not_found": "JOB_NOT_FOUND",
        }.get(self.status, "REVIEW_ERROR")


def _connect(dsn: str):
    return psycopg.connect(
        dsn, connect_timeout=5, row_factory=dict_row
    )


def _truncate(value: str, limit: int = 2000) -> str:
    return value if len(value) <= limit else value[: limit - 3] + "..."


def _locked_job(
    connection,
    job_id: UUID,
    *,
    generation: int,
    require_lease: bool = True,
) -> dict[str, Any]:
    """Lock one job and require the caller's generation and active lease.

    All time comparisons use ``clock_timestamp()``, the actual wall clock at
    evaluation time. Transaction-start ``now()`` is deliberately not used: a
    statement that waited on the job row lock would otherwise compare against
    a timestamp captured before the wait. The row lock serializes the check
    with ``claim_next`` so a worker that lost its lease cannot append a write
    between the generation check and the write itself.
    """
    job = connection.execute(
        "SELECT state, generation, lease_owner, lease_expires_at, "
        "prepare_deadline_at, state_version, job_contract_version "
        "FROM jobs WHERE job_id = %s FOR UPDATE",
        (job_id,),
    ).fetchone()
    if job is None:
        raise StateError("job does not exist")
    # Evaluate the clock only after the row lock has been acquired. A target
    # list evaluated alongside FOR UPDATE could otherwise capture the time
    # before the lock wait.
    job["db_now"] = connection.execute(
        "SELECT clock_timestamp() AS db_now"
    ).fetchone()["db_now"]
    if job["generation"] != generation:
        raise StaleGeneration("execution generation is no longer current")
    if require_lease and (
        job["lease_expires_at"] is None
        or job["lease_expires_at"] <= job["db_now"]
    ):
        raise StaleGeneration("the worker lease is no longer active")
    return job


def _review_window_closed(deadline: Any, decision_at: Any) -> bool:
    """Return whether a decision at ``decision_at`` is no longer acceptable.

    The deadline is inclusive: a decision at the exact deadline is already
    too late. A missing deadline fails closed. ``record_review`` and
    ``expire_review`` share this comparison so a boundary edit cannot silently
    apply to only one of the two review paths.
    """
    return deadline is None or deadline <= decision_at


def _audit(
    connection,
    job_id: UUID,
    event_type: str,
    *,
    stage: str | None = None,
    attempt_no: int | None = None,
    reason_code: str | None = None,
    detail: dict[str, Any] | None = None,
) -> None:
    connection.execute(
        "INSERT INTO audit_events "
        "(job_id, stage, attempt_no, event_type, reason_code, detail, created_at) "
        "VALUES (%s, %s, %s, %s, %s, %s, clock_timestamp())",
        (
            job_id,
            stage,
            attempt_no,
            event_type,
            reason_code,
            Jsonb(detail or {}),
        ),
    )


def load_job(dsn: str, job_id: UUID) -> dict[str, Any] | None:
    with _connect(dsn) as connection:
        return connection.execute(
            "SELECT job_id, request, state, stage, reason_code, last_error, "
            "state_version, generation, workflow_synced, operator_id, "
            "lease_owner, lease_expires_at, "
            "prepare_deadline_at, review_deadline_at, execute_deadline_at, "
            "approved_at, submitted_at, updated_at, verdict, verdict_reason, "
            "evidence_digest, evidence_path, evidence_status, evidence_error "
            "FROM jobs WHERE job_id = %s",
            (job_id,),
        ).fetchone()


def prepare_deadline_passed(dsn: str, job_id: UUID, *, generation: int) -> bool:
    """Return whether the prepare deadline passed, using the database clock.

    ``clock_timestamp()`` is the actual evaluation time, not the transaction
    start captured by ``now()``. This distinction matters when a caller has
    waited on a row lock past the deadline.
    """
    with _connect(dsn) as connection:
        row = connection.execute(
            "SELECT generation, (prepare_deadline_at IS NOT NULL "
            "AND prepare_deadline_at <= clock_timestamp()) AS passed "
            "FROM jobs WHERE job_id = %s",
            (job_id,),
        ).fetchone()
        if row is None:
            raise StateError("job does not exist")
        if row["generation"] != generation:
            raise StaleGeneration("execution generation is no longer current")
        return row["passed"]


def claim_next(
    dsn: str,
    worker_id: str,
    *,
    lease_seconds: int = LEASE_SECONDS,
    execute: bool = True,
) -> dict | None:
    if not isinstance(worker_id, str) or not worker_id.strip():
        raise StateError("worker_id must be non-empty")
    if type(lease_seconds) is not int or not 1 <= lease_seconds <= 86400:
        raise StateError("lease_seconds is invalid")
    execution_clause = ""
    if execute:
        execution_clause = """
               OR (state = 'READY' AND workflow_synced = true
                   AND (lease_expires_at IS NULL
                        OR lease_expires_at <= clock_timestamp()))
               OR (state IN ('RUNNING', 'ARCHIVING')
                   AND (lease_expires_at IS NULL
                        OR lease_expires_at <= clock_timestamp()))"""
    with _connect(dsn) as connection:
        # A claim may run while a release is being promoted. Take the shared
        # side of the release lock for this transaction so a promotion that
        # holds the exclusive side (and observed zero active slots) cannot be
        # interleaved with a new claim; the claim waits until the promotion
        # commits and then targets the new release.
        connection.execute(
            "SELECT pg_advisory_xact_lock_shared(hashtext(%s))",
            (RELEASE_LOCK_PREFIX + RELEASE_ENVIRONMENT,),
        )
        row = connection.execute(
            f"""
            SELECT job_id, state, workflow_synced
            FROM jobs
            WHERE state = 'QUEUED'
               OR (state = 'PREPARING'
                   AND (lease_expires_at IS NULL
                        OR lease_expires_at <= clock_timestamp()))
               OR (workflow_synced = false AND state IN ('AWAITING_REVIEW', 'READY')
                   AND (lease_expires_at IS NULL
                        OR lease_expires_at <= clock_timestamp()))
               OR (workflow_synced = false AND state = 'BLOCKED'
                   AND reason_code IS DISTINCT FROM 'UNSUPPORTED_TARGET'
                   AND (lease_expires_at IS NULL
                        OR lease_expires_at <= clock_timestamp()))
               OR (state = 'AWAITING_REVIEW'
                   AND review_deadline_at IS NOT NULL
                   AND review_deadline_at <= clock_timestamp()
                   AND (lease_expires_at IS NULL
                        OR lease_expires_at <= clock_timestamp()))
               OR (state = 'AWAITING_REVIEW'
                   AND review_deadline_at IS NULL
                   AND (lease_expires_at IS NULL
                        OR lease_expires_at <= clock_timestamp()))
               {execution_clause}
            ORDER BY submitted_at
            FOR UPDATE SKIP LOCKED
            LIMIT 1
            """
        ).fetchone()
        if row is None:
            return None
        updated = connection.execute(
            """
            WITH claim_time AS MATERIALIZED (
                SELECT clock_timestamp() AS claimed_at
            )
            UPDATE jobs
            SET state = CASE
                    WHEN state = 'QUEUED' THEN 'PREPARING'
                    WHEN state = 'READY' AND workflow_synced THEN 'RUNNING'
                    ELSE state
                END,
                stage = CASE
                    WHEN state = 'QUEUED' THEN 'prepare'
                    WHEN state = 'READY' AND workflow_synced THEN 'execute'
                    ELSE stage
                END,
                generation = generation + 1,
                state_version = state_version + 1,
                lease_owner = %s,
                lease_expires_at = claim_time.claimed_at
                    + make_interval(secs => CASE
                        WHEN state = 'READY' AND workflow_synced THEN GREATEST(
                            %s,
                            (request->'limits'->>'execute_seconds')::int
                        )
                        WHEN state IN ('RUNNING', 'ARCHIVING') THEN GREATEST(
                            %s,
                            COALESCE(
                                EXTRACT(EPOCH FROM (
                                    execute_deadline_at - claim_time.claimed_at
                                ))::int,
                                0
                            ) + 60
                        )
                        ELSE %s
                    END),
                prepare_deadline_at = COALESCE(
                    prepare_deadline_at,
                    claim_time.claimed_at
                    + ((request->'limits'->>'prepare_seconds')::int
                       * interval '1 second')
                ),
                execute_deadline_at = CASE
                    WHEN state = 'READY' AND workflow_synced THEN COALESCE(
                        execute_deadline_at,
                        claim_time.claimed_at
                        + ((request->'limits'->>'execute_seconds')::int
                           * interval '1 second')
                    )
                    ELSE execute_deadline_at
                END,
                updated_at = claim_time.claimed_at
            FROM claim_time
            WHERE job_id = %s
            RETURNING job_id, request, state, stage, reason_code, last_error,
                      state_version, generation, workflow_synced,
                      lease_owner, lease_expires_at,
                      prepare_deadline_at, review_deadline_at,
                      execute_deadline_at, verdict, verdict_reason,
                      evidence_digest, evidence_path, evidence_status,
                      evidence_error
            """,
            (
                worker_id,
                lease_seconds,
                lease_seconds,
                lease_seconds,
                row["job_id"],
            ),
        ).fetchone()
        _audit(
            connection,
            row["job_id"],
            "claim",
            stage=updated["stage"],
            detail={"worker_id": worker_id, "generation": updated["generation"]},
        )
        return updated


def get_plan(dsn: str, job_id: UUID) -> dict | None:
    with _connect(dsn) as connection:
        return connection.execute(
            "SELECT plan_id, job_id, plan_digest, plan, summary, created_at "
            "FROM plans WHERE job_id = %s",
            (job_id,),
        ).fetchone()


def get_review(dsn: str, job_id: UUID) -> dict | None:
    with _connect(dsn) as connection:
        return connection.execute(
            "SELECT review_id, job_id, plan_digest, reviewer_id, decision, "
            "review_deadline_at, decided_at FROM reviews WHERE job_id = %s",
            (job_id,),
        ).fetchone()


def freeze_plan(
    dsn: str,
    job_id: UUID,
    *,
    generation: int,
    plan: dict[str, Any],
    plan_digest: str,
    summary: dict[str, Any],
) -> bool:
    """Freeze one plan unless the database clock says preparation expired.

    The review window is computed from the database clock inside this
    transaction, so a skewed worker process clock cannot lengthen or shorten
    the 24 hour window. The prepare deadline is re-checked after locking the
    job, which closes the window between the caller's last check and the plan
    write.
    """
    with _connect(dsn) as connection:
        job = _locked_job(connection, job_id, generation=generation)
        existing = connection.execute(
            "SELECT plan_digest FROM plans WHERE job_id = %s", (job_id,)
        ).fetchone()
        if existing is not None:
            if existing["plan_digest"] != plan_digest:
                raise PlanConflict("a different plan is already frozen")
            return True
        if job["state"] not in ("PREPARING", "AWAITING_REVIEW"):
            raise StateError(f"cannot freeze a plan while the job is {job['state']}")
        if (
            job["prepare_deadline_at"] is not None
            and job["prepare_deadline_at"] <= job["db_now"]
        ):
            connection.execute(
                "UPDATE jobs SET state = 'BLOCKED', stage = 'blocked', "
                "reason_code = 'DEADLINE_EXCEEDED', last_error = %s, "
                "state_version = state_version + 1, workflow_synced = false, "
                "updated_at = clock_timestamp() "
                "WHERE job_id = %s AND generation = %s",
                (
                    "preparation deadline passed before the plan was frozen",
                    job_id,
                    generation,
                ),
            )
            _audit(
                connection,
                job_id,
                "blocked",
                stage="blocked",
                reason_code="DEADLINE_EXCEEDED",
                detail={
                    "message": "preparation deadline passed before the plan was frozen",
                    "generation": generation,
                },
            )
            return False
        connection.execute(
            "INSERT INTO plans (plan_id, job_id, plan_digest, plan, summary) "
            "VALUES (%s, %s, %s, %s, %s)",
            (uuid.uuid4(), job_id, plan_digest, Jsonb(plan), Jsonb(summary)),
        )
        updated = connection.execute(
            "UPDATE jobs SET state = 'AWAITING_REVIEW', stage = 'review', "
            "review_deadline_at = clock_timestamp() + make_interval(hours => %s), "
            "state_version = state_version + 1, "
            "workflow_synced = false, updated_at = clock_timestamp() "
            "WHERE job_id = %s AND generation = %s "
            "AND state IN ('PREPARING', 'AWAITING_REVIEW') "
            "AND lease_expires_at IS NOT NULL "
            "AND lease_expires_at > clock_timestamp() "
            "RETURNING job_id",
            (REVIEW_WINDOW_HOURS, job_id, generation),
        ).fetchone()
        if updated is None:
            raise StaleGeneration("job changed while freezing the plan")
        _audit(
            connection,
            job_id,
            "plan_frozen",
            stage="review",
            detail={"plan_digest": plan_digest, "generation": generation},
        )
        return True


def ensure_awaiting_review(dsn: str, job_id: UUID, *, generation: int) -> None:
    """Reconcile a job that has a frozen plan but is still PREPARING."""
    with _connect(dsn) as connection:
        job = _locked_job(connection, job_id, generation=generation)
        if job["state"] != "PREPARING":
            return
        connection.execute(
            "UPDATE jobs SET state = 'AWAITING_REVIEW', stage = 'review', "
            "review_deadline_at = COALESCE("
            "review_deadline_at, clock_timestamp() + make_interval(hours => %s)), "
            "state_version = state_version + 1, workflow_synced = false, "
            "updated_at = clock_timestamp() "
            "WHERE job_id = %s AND generation = %s AND state = 'PREPARING' "
            "AND lease_expires_at IS NOT NULL "
            "AND lease_expires_at > clock_timestamp()",
            (REVIEW_WINDOW_HOURS, job_id, generation),
        )


def block_job(
    dsn: str,
    job_id: UUID,
    *,
    generation: int,
    reason_code: str,
    message: str,
    state: str = "BLOCKED",
    event_type: str = "blocked",
) -> None:
    with _connect(dsn) as connection:
        _locked_job(connection, job_id, generation=generation)
        updated = connection.execute(
            "UPDATE jobs SET state = %s, stage = 'blocked', reason_code = %s, "
            "last_error = %s, state_version = state_version + 1, "
            "workflow_synced = false, updated_at = clock_timestamp() "
            "WHERE job_id = %s AND generation = %s "
            "AND lease_expires_at IS NOT NULL "
            "AND lease_expires_at > clock_timestamp() "
            "RETURNING job_id",
            (state, reason_code, _truncate(message), job_id, generation),
        ).fetchone()
        if updated is None:
            raise StaleGeneration("execution generation is no longer current")
        _audit(
            connection,
            job_id,
            event_type,
            stage="blocked",
            reason_code=reason_code,
            detail={"message": _truncate(message), "generation": generation},
        )


def _archive_pending_blocked(
    dsn: str, job_id: UUID, pending: list[tuple[str, str]]
) -> None:
    """Archive a just-committed BLOCKED transition (best effort).

    The callback runs from ``ExitStack`` after the database context manager has
    committed. Filesystem/verification errors are turned into
    FAILED/EVIDENCE_WRITE_FAILED by ``record_blocked``; a control-plane
    database error is propagated rather than hidden behind a successful review
    response.
    """
    if not pending:
        return
    reason_code, message = pending[-1]
    # Imported lazily: execution imports state at module load time, so a
    # module-level import here would be circular.
    from datacon import execution

    execution.record_blocked(
        dsn,
        job_id,
        reason_code=reason_code,
        message=message,
    )


def record_blocked_evidence(
    dsn: str,
    job_id: UUID,
    *,
    generation: int | None = None,
    evidence_digest: str | None = None,
    evidence_path: str | None = None,
    evidence_error: str | None = None,
    reason_code: str | None = None,
) -> bool:
    """Attach a blocked bundle to a job without requiring a worker lease.

    The row must still be BLOCKED at ``generation``. A successful archive
    records both pointer columns and leaves the verdict columns NULL (a
    blocked job has no output verdict). An archive failure moves the row to
    FAILED/EVIDENCE_WRITE_FAILED and clears every current evidence pointer, so
    the 007 invariant (``archived`` iff path+digest, no verdict for a failed
    terminal) is never violated.
    """
    with _connect(dsn) as connection:
        job = connection.execute(
            "SELECT state, reason_code, generation FROM jobs "
            "WHERE job_id = %s FOR UPDATE",
            (job_id,),
        ).fetchone()
        if job is None:
            return False
        if generation is None:
            generation = job["generation"]
        if job["generation"] != generation or job["state"] != "BLOCKED":
            return False
        archived = bool(evidence_digest and evidence_path)
        if evidence_error is None and not archived:
            evidence_error = "blocked evidence bundle was not produced"
        if evidence_error is None and archived:
            connection.execute(
                "UPDATE jobs SET evidence_status = 'archived', "
                "evidence_path = %s, evidence_digest = %s, "
                "evidence_error = NULL, verdict = NULL, verdict_reason = NULL, "
                "state_version = state_version + 1, "
                "updated_at = clock_timestamp() "
                "WHERE job_id = %s AND generation = %s AND state = 'BLOCKED'",
                (evidence_path, evidence_digest, job_id, generation),
            )
            _audit(
                connection,
                job_id,
                "blocked_evidence_archived",
                stage="blocked",
                reason_code=reason_code or job["reason_code"],
                detail={
                    "generation": generation,
                    "evidence_digest": evidence_digest,
                    "evidence_path": evidence_path,
                },
            )
            return True
        # Do not leave a BLOCKED row with evidence_status='failed'. The
        # terminal state is FAILED, the current verdict/pointers are cleared,
        # and the original block reason stays in the audit detail.
        connection.execute(
            "UPDATE jobs SET state = 'FAILED', stage = 'failed', "
            "reason_code = 'EVIDENCE_WRITE_FAILED', last_error = %s, "
            "verdict = NULL, verdict_reason = NULL, evidence_path = NULL, "
            "evidence_digest = NULL, evidence_status = 'failed', "
            "evidence_error = %s, state_version = state_version + 1, "
            "updated_at = clock_timestamp() "
            "WHERE job_id = %s AND generation = %s AND state = 'BLOCKED'",
            (
                _truncate(evidence_error or "blocked evidence write failed"),
                _truncate(evidence_error or "blocked evidence write failed"),
                job_id,
                generation,
            ),
        )
        _audit(
            connection,
            job_id,
            "failed",
            stage="failed",
            reason_code="EVIDENCE_WRITE_FAILED",
            detail={
                "generation": generation,
                "blocked_reason": reason_code or job["reason_code"],
                "evidence_error": _truncate(
                    evidence_error or "blocked evidence write failed"
                ),
            },
        )
        return True


def record_attempt(
    dsn: str,
    job_id: UUID,
    *,
    stage: str,
    step_key: str,
    attempt_no: int,
    generation: int,
    input_digest: str | None,
    status: str,
    result: dict[str, Any] | list[Any] | None = None,
    container_id: str | None = None,
    attempt_token: str | None = None,
) -> bool:
    """Persist one attempt row, returning False when the write was not applied.

    ``False`` means the caller no longer owns the generation/lease, or the
    upsert was rejected because the row is already ``completed``. Callers must
    not treat that as success. Only the documented statuses are accepted; an
    unknown status is a contract error and raises ``StateError``.

    A committed ``completed`` row is terminal: a later ``started`` /
    ``infra_error`` / unknown-status write, or a ``completed`` write with a
    different result, for the same ``(job_id, stage, step_key, attempt_no,
    generation)`` is rejected. Re-writing the identical ``completed`` row (for
    example when a client retries after a connection reset that happened after
    commit) is still applied and remains idempotent.
    """
    if not stage or not step_key:
        raise StateError("attempt requires stage and step_key")
    if not isinstance(status, str) or status not in ATTEMPT_STATUSES:
        raise StateError("attempt status is invalid")
    if result is not None:
        try:
            encoded_result = jsonutil.canonical_bytes(result)
        except (TypeError, ValueError, UnicodeError) as error:
            raise StateError(f"attempt result is not canonical JSON: {error}") from error
        if len(encoded_result) > MAX_ATTEMPT_RESULT_BYTES:
            raise StateError(
                "attempt result exceeds the "
                f"{MAX_ATTEMPT_RESULT_BYTES} byte metadata cap"
            )
    with _connect(dsn) as connection:
        job = connection.execute(
            "SELECT generation, lease_expires_at "
            "FROM jobs WHERE job_id = %s FOR UPDATE",
            (job_id,),
        ).fetchone()
        if job is None:
            return False
        # Read the clock after the lock so a blocked write cannot be judged
        # against the transaction start captured before the wait.
        db_now = connection.execute(
            "SELECT clock_timestamp() AS db_now"
        ).fetchone()["db_now"]
        if (
            job["generation"] != generation
            or job["lease_expires_at"] is None
            or job["lease_expires_at"] <= db_now
        ):
            return False
        cursor = connection.execute(
            """
            INSERT INTO attempts
                (attempt_id, job_id, stage, step_key, attempt_no, generation,
                 container_id, input_digest, status, result, finished_at,
                 attempt_token)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s,
                    CASE WHEN %s = 'started' THEN NULL
                         ELSE clock_timestamp() END, %s)
            ON CONFLICT (job_id, stage, step_key, attempt_no, generation)
            DO UPDATE
            SET container_id = EXCLUDED.container_id,
                input_digest = EXCLUDED.input_digest,
                status = EXCLUDED.status,
                result = EXCLUDED.result,
                finished_at = EXCLUDED.finished_at,
                attempt_token = COALESCE(EXCLUDED.attempt_token, attempts.attempt_token)
            WHERE attempts.status <> 'completed'
               OR (EXCLUDED.status = 'completed'
                   AND attempts.result IS NOT DISTINCT FROM EXCLUDED.result)
            """,
            (
                uuid.uuid4(),
                job_id,
                stage,
                step_key,
                attempt_no,
                generation,
                container_id,
                input_digest,
                status,
                Jsonb(result) if result is not None else None,
                status,
                attempt_token,
            ),
        )
        return cursor.rowcount > 0


def analysis_progress(
    dsn: str, job_id: UUID, *, generation: int
) -> dict[str, Any]:
    """Return the auditable analysis attempts for one execution generation.

    ``completed`` carries the persisted plan draft so a workflow-level retry
    can freeze it without running analysis for a third time. Older rows that
    only stored a plan digest remain visible in ``max_attempt`` but are not
    reused.
    """
    with _connect(dsn) as connection:
        rows = connection.execute(
            "SELECT attempt_no, status, result FROM attempts "
            "WHERE job_id = %s AND stage = 'prepare' AND step_key = 'analysis' "
            "AND generation = %s ORDER BY attempt_no",
            (job_id, generation),
        ).fetchall()
    completed = None
    draft_failed = False
    for row in rows:
        if row["status"] != "completed" and isinstance(row["result"], dict):
            if row["result"].get("phase") == "analysis_draft":
                draft_failed = True
    for row in reversed(rows):
        if row["status"] == "completed" and isinstance(row["result"], dict):
            completed = row["result"]
            break
    return {
        "max_attempt": rows[-1]["attempt_no"] if rows else 0,
        "completed": completed,
        "draft_failed": draft_failed,
    }


def begin_execution(dsn: str, job_id: UUID, *, generation: int) -> bool:
    """Move a READY job to RUNNING under the current claim's generation."""
    with _connect(dsn) as connection:
        job = _locked_job(connection, job_id, generation=generation)
        if job["state"] == "RUNNING":
            return True
        if job["state"] != "READY":
            raise StateError(f"cannot start execution while the job is {job['state']}")
        updated = connection.execute(
            "UPDATE jobs SET state = 'RUNNING', stage = 'execute', "
            "execute_deadline_at = COALESCE("
            "execute_deadline_at, clock_timestamp() + "
            "((request->'limits'->>'execute_seconds')::int * interval '1 second')), "
            "lease_expires_at = GREATEST("
            "lease_expires_at, clock_timestamp() + "
            "((request->'limits'->>'execute_seconds')::int * interval '1 second')), "
            "state_version = state_version + 1, updated_at = clock_timestamp() "
            "WHERE job_id = %s AND generation = %s AND state = 'READY' "
            "AND lease_expires_at IS NOT NULL "
            "AND lease_expires_at > clock_timestamp() RETURNING job_id",
            (job_id, generation),
        ).fetchone()
        if updated is None:
            raise StaleGeneration("the worker lease is no longer active")
        _audit(
            connection,
            job_id,
            "execution_started",
            stage="execute",
            detail={"generation": generation},
        )
        return True


def mark_archiving(dsn: str, job_id: UUID, *, generation: int) -> bool:
    """Move a live RUNNING generation into the bounded archive phase."""
    with _connect(dsn) as connection:
        job = _locked_job(connection, job_id, generation=generation)
        if job["state"] not in ("RUNNING", "ARCHIVING"):
            raise StateError(f"cannot archive a job while it is {job['state']}")
        updated = connection.execute(
            "UPDATE jobs SET state = 'ARCHIVING', stage = 'archive', "
            "state_version = state_version + 1, updated_at = clock_timestamp(), "
            # The archive phase is bounded but must outlive the lease left by
            # the execution phase. Reserve at least 60 seconds (which already
            # covers the maximum 10%/60s archive reserve), so finish_execution
            # cannot fail merely because the execute deadline has passed.
            "lease_expires_at = GREATEST("
            "lease_expires_at, clock_timestamp() + interval '60 seconds') "
            "WHERE job_id = %s AND generation = %s "
            "AND lease_expires_at IS NOT NULL "
            "AND lease_expires_at > clock_timestamp() RETURNING job_id",
            (job_id, generation),
        ).fetchone()
        if updated is None:
            raise StaleGeneration("execution generation is no longer current")
        _audit(
            connection,
            job_id,
            "archiving_started",
            stage="archive",
            detail={"generation": generation},
        )
        return True


def assert_archive_fence(dsn: str, job_id: UUID, *, generation: int) -> bool:
    """Re-confirm the archive lease immediately before publishing a bundle.

    ``mark_archiving`` fences the start of archiving, but verification can take
    time and another worker may have claimed the job. Publishing must be
    refused unless this exact generation still owns an active lease.
    """
    with _connect(dsn) as connection:
        row = connection.execute(
            "UPDATE jobs SET lease_expires_at = GREATEST("
            "lease_expires_at, clock_timestamp() + interval '60 seconds') "
            "WHERE job_id = %s AND generation = %s "
            "AND state IN ('RUNNING', 'ARCHIVING') "
            "AND lease_expires_at IS NOT NULL "
            "AND lease_expires_at > clock_timestamp() RETURNING job_id",
            (job_id, generation),
        ).fetchone()
        if row is None:
            raise StaleGeneration("execution generation is no longer current")
        return True


def finish_execution(
    dsn: str,
    job_id: UUID,
    *,
    generation: int,
    state: str,
    reason_code: str | None,
    verdict: str | None,
    verdict_reason: str | None,
    evidence_digest: str | None = None,
    evidence_path: str | None = None,
    evidence_status: str | None = None,
    evidence_error: str | None = None,
    last_error: str | None = None,
    stage: str = "done",
) -> bool:
    """Atomically commit a terminal execution state and fence older writers.

    The generation is advanced so a worker that lost the lease can never write
    again. A terminal that did not archive a bundle becomes FAILED and clears
    the current verdict and evidence pointer; the failure text stays in
    ``evidence_error``/``last_error``. ``status`` only exposes a verdict while
    ``evidence_status == "archived"``, so a stale value cannot be mistaken for
    the current result.

    ``COMPLETED`` is the v2 child terminal (the family converges through
    ``complete_family``): a v1 row must never be written into it because the v1
    state machine has no such state.
    """
    if state not in (
        "REPRODUCED",
        "NOT_REPRODUCED",
        "INCONCLUSIVE",
        "BLOCKED",
        "FAILED",
        "COMPLETED",
    ):
        raise StateError("execution terminal state is invalid")
    if verdict is not None and verdict not in (
        "REPRODUCED",
        "NOT_REPRODUCED",
        "INCONCLUSIVE",
    ):
        raise StateError("verdict is invalid")
    archived = evidence_status == "archived"
    if archived:
        if not evidence_path or not evidence_digest:
            raise StateError(
                "archived evidence requires both evidence_path and evidence_digest"
            )
    else:
        if evidence_status not in (None, "failed"):
            raise StateError("evidence_status must be archived or failed")
        if verdict is not None or verdict_reason is not None:
            raise StateError("a verdict requires archived evidence")
        # A terminal that did not archive a bundle must not keep a previous
        # generation's current verdict or evidence pointer. Write the cleared
        # values explicitly instead of COALESCE-ing them back from the row.
        evidence_status = "failed"
        evidence_path = None
        evidence_digest = None
    with _connect(dsn) as connection:
        job = _locked_job(connection, job_id, generation=generation)
        # COMPLETED exists only in the v2 contract. Checking the version on the
        # locked row (not on caller input) keeps a v1 worker from writing a
        # state its own control plane cannot read.
        if state == "COMPLETED" and job["job_contract_version"] != 2:
            raise StateError("COMPLETED is only valid for a v2 job")
        if job["state"] not in ("RUNNING", "ARCHIVING"):
            raise StateError(f"cannot finish execution while the job is {job['state']}")
        updated = connection.execute(
            "UPDATE jobs SET state = %s, stage = %s, reason_code = %s, "
            "last_error = %s, verdict = %s, "
            "verdict_reason = %s, "
            "evidence_digest = %s, "
            "evidence_path = %s, "
            "evidence_status = %s, "
            "evidence_error = %s, "
            "generation = generation + 1, state_version = state_version + 1, "
            "workflow_synced = true, lease_owner = NULL, lease_expires_at = NULL, "
            "updated_at = clock_timestamp() "
            "WHERE job_id = %s AND generation = %s "
            "AND lease_expires_at IS NOT NULL "
            "AND lease_expires_at > clock_timestamp() RETURNING job_id",
            (
                state,
                stage,
                reason_code,
                _truncate(last_error) if last_error else None,
                verdict,
                verdict_reason,
                evidence_digest,
                evidence_path,
                evidence_status,
                _truncate(evidence_error) if evidence_error else None,
                job_id,
                generation,
            ),
        ).fetchone()
        if updated is None:
            return False
        _audit(
            connection,
            job_id,
            "execution_finished" if state != "FAILED" else "failed",
            stage=stage,
            reason_code=reason_code,
            detail={
                "generation": generation,
                "state": state,
                "verdict": verdict,
                "verdict_reason": verdict_reason,
                "evidence_digest": evidence_digest,
                "evidence_status": evidence_status,
            },
        )
        return True


def complete_family(
    dsn: str,
    family_id: UUID,
    evidence_path: str,
    evidence_digest: str,
) -> bool:
    """Converge an AGGREGATING v2 family job to COMPLETED.

    The family is the aggregate, not a claimed child: no execution lease is
    required here. The only accepted source state is ``AGGREGATING`` and the
    only accepted identity is a ``job_kind = 'family'`` row on contract v2.
    Replaying the identical archived evidence pointer is idempotent; every
    other repeat or state is refused.
    """
    if not isinstance(evidence_path, str) or not evidence_path.strip():
        raise StateError("completing a family requires evidence_path")
    if not isinstance(evidence_digest, str) or not evidence_digest.strip():
        raise StateError("completing a family requires evidence_digest")
    with _connect(dsn) as connection:
        job = connection.execute(
            "SELECT state, job_kind, job_contract_version, evidence_path, "
            "evidence_digest FROM jobs WHERE job_id = %s FOR UPDATE",
            (family_id,),
        ).fetchone()
        if job is None:
            raise StateError("family job does not exist")
        if job["job_kind"] != "family" or job["job_contract_version"] != 2:
            raise StateError("job is not a v2 family")
        if job["state"] == "COMPLETED":
            if (
                job["evidence_path"] == evidence_path
                and job["evidence_digest"] == evidence_digest
            ):
                return True
            raise StateError("family is already COMPLETED with different evidence")
        if job["state"] != "AGGREGATING":
            raise StateError(f"cannot complete a family while it is {job['state']}")
        updated = connection.execute(
            "UPDATE jobs SET state = 'COMPLETED', stage = 'done', "
            "evidence_status = 'archived', evidence_path = %s, "
            "evidence_digest = %s, verdict = NULL, verdict_reason = NULL, "
            "reason_code = NULL, state_version = state_version + 1, "
            "updated_at = clock_timestamp() "
            "WHERE job_id = %s AND state = 'AGGREGATING' RETURNING job_id",
            (evidence_path, evidence_digest, family_id),
        ).fetchone()
        if updated is None:
            raise StateError("family state changed while completing it")
        return True


def attempts_for_step(
    dsn: str,
    job_id: UUID,
    *,
    stage: str,
    step_key: str,
    generation: int,
) -> list[dict[str, Any]]:
    with _connect(dsn) as connection:
        return connection.execute(
            "SELECT attempt_no, generation, container_id, input_digest, "
            "status, result, attempt_token, started_at, finished_at "
            "FROM attempts "
            "WHERE job_id = %s AND stage = %s AND step_key = %s "
            "AND generation = %s ORDER BY attempt_no",
            (job_id, stage, step_key, generation),
        ).fetchall()


def attempts_for_step_across_generations(
    dsn: str,
    job_id: UUID,
    *,
    stage: str,
    step_key: str,
) -> list[dict[str, Any]]:
    """Return every durable attempt for a logical step, newest first.

    Journal adoption (EXE-01) must start from database provenance, so this
    query includes the generation and one-time token that the journal has to
    match. It is also the source of the cross-generation attempt bound.
    """
    with _connect(dsn) as connection:
        return connection.execute(
            "SELECT attempt_no, generation, container_id, input_digest, "
            "status, result, attempt_token, started_at, finished_at "
            "FROM attempts "
            "WHERE job_id = %s AND stage = %s AND step_key = %s "
            "ORDER BY generation DESC, attempt_no DESC",
            (job_id, stage, step_key),
        ).fetchall()


def execution_attempts_across_generations(
    dsn: str, job_id: UUID
) -> list[dict[str, Any]]:
    """Return all execute attempts, newest generation first.

    Archive-only recovery has no current-generation rows yet: the claim after
    a crash advances the generation. Provenance for the durable journals comes
    from these historical rows.
    """
    with _connect(dsn) as connection:
        return connection.execute(
            "SELECT generation, attempt_no, step_key, container_id, input_digest, "
            "status, result, attempt_token, started_at, finished_at "
            "FROM attempts "
            "WHERE job_id = %s AND stage = 'execute' "
            "ORDER BY generation DESC, attempt_no DESC, step_key",
            (job_id,),
        ).fetchall()


def execution_attempts(
    dsn: str, job_id: UUID, generation: int
) -> list[dict[str, Any]]:
    with _connect(dsn) as connection:
        return connection.execute(
            "SELECT attempt_no, step_key, container_id, input_digest, status, "
            "result, started_at, finished_at FROM attempts "
            "WHERE job_id = %s AND stage = 'execute' AND generation = %s "
            "ORDER BY attempt_no, step_key",
            (job_id, generation),
        ).fetchall()


def finalize_workflow(dsn: str, job_id: UUID, generation: int) -> bool:
    with _connect(dsn) as connection:
        job = connection.execute(
            "SELECT generation, lease_expires_at "
            "FROM jobs WHERE job_id = %s FOR UPDATE",
            (job_id,),
        ).fetchone()
        if job is None:
            return False
        # The finalize write can also wait on the job row. Read the clock only
        # after the lock so a stale lease is judged against the actual time.
        db_now = connection.execute(
            "SELECT clock_timestamp() AS db_now"
        ).fetchone()["db_now"]
        if (
            job["generation"] != generation
            or job["lease_expires_at"] is None
            or job["lease_expires_at"] <= db_now
        ):
            return False
        updated = connection.execute(
            "UPDATE jobs SET workflow_synced = true, lease_owner = NULL, "
            "lease_expires_at = NULL, state_version = state_version + 1, "
            "updated_at = clock_timestamp() "
            "WHERE job_id = %s AND generation = %s "
            "RETURNING job_id",
            (job_id, generation),
        ).fetchone()
        if updated is None:
            return False
        _audit(
            connection,
            job_id,
            "workflow_synchronized",
            attempt_no=None,
            detail={"generation": generation},
        )
        return True


# A decided family envelope maps back to the review decision it recorded. The
# idempotency key is (family_id, first_plan_digest, envelope_digest, decision,
# reviewer_id); the first_plan_digest is validated before the lookup, so the
# envelope row plus reviewer_id is the persisted half of that key.
_FAMILY_ENVELOPE_DECISIONS = {"approved": "approve", "rejected": "reject"}


def _block_v2_review_job(
    connection,
    job_id: UUID,
    *,
    reason_code: str,
    message: str,
) -> None:
    """Converge one v2 review participant to BLOCKED in the review transaction.

    A terminal row keeps its terminal state instead of being resurrected. The
    family row lock serializes reviews, so the only competing writer for a
    child is a worker that already holds its own lease; blocking it still
    clears that lease and bumps the generation so its next write is stale.
    """
    connection.execute(
        "UPDATE jobs SET state = 'BLOCKED', stage = 'blocked', "
        "reason_code = %s, last_error = %s, "
        "state_version = state_version + 1, generation = generation + 1, "
        "workflow_synced = false, lease_owner = NULL, "
        "lease_expires_at = NULL, updated_at = clock_timestamp() "
        "WHERE job_id = %s "
        "AND state NOT IN ('COMPLETED', 'FAILED', 'BLOCKED')",
        (reason_code, message, job_id),
    )


def _record_family_review(
    connection,
    job_id: UUID,
    job: dict[str, Any],
    *,
    plan_digest: str,
    decision: str,
    reviewer_id: str,
    envelope_digest: str | None,
) -> ReviewOutcome:
    """Record a human review against a v2 family and its first child.

    The caller already holds the family row lock. A first-round review also
    locks the first child (family -> child); a re-approval only touches the
    family. Envelope identity is resolved from the first plan on the first
    round and must be explicit afterwards; a decision never falls back to the
    already-approved envelope.
    """
    if job["state"] != "AGGREGATING":
        return ReviewOutcome(
            "invalid_state",
            state=job["state"],
            message=f"family is {job['state']}, not AGGREGATING",
        )
    first_round = connection.execute(
        "SELECT NOT EXISTS (SELECT 1 FROM reviews WHERE job_id = %s) "
        "AND NOT EXISTS (SELECT 1 FROM family_approvals WHERE family_id = %s) "
        "AS first_round",
        (job_id, job_id),
    ).fetchone()["first_round"]
    child = connection.execute(
        "SELECT job_id, state, generation FROM jobs "
        "WHERE parent_job_id = %s AND job_kind IN ('campaign', 'round') "
        "ORDER BY submitted_at, job_id LIMIT 1",
        (job_id,),
    ).fetchone()
    if child is None:
        return ReviewOutcome(
            "invalid_state",
            state=job["state"],
            message="family has no child job",
        )
    if first_round:
        # Lock order is family then first child. The family lock is already
        # held; blocking here proves the order to any concurrent observer.
        connection.execute(
            "SELECT job_id FROM jobs WHERE job_id = %s FOR UPDATE",
            (child["job_id"],),
        )
    plan = connection.execute(
        "SELECT plan_digest, plan FROM plans WHERE job_id = %s "
        "ORDER BY created_at, plan_id LIMIT 1",
        (child["job_id"],),
    ).fetchone()
    if plan is None:
        return ReviewOutcome(
            "invalid_state",
            state=job["state"],
            message="family has no first plan",
        )

    # §9.1 step 1: the plan is validated before the envelope lookup. A
    # mismatch writes no review, approval or audit row.
    first_plan_digest = plan["plan_digest"]
    if plan_digest != first_plan_digest:
        return ReviewOutcome(
            "plan_mismatch",
            state=job["state"],
            message="plan digest does not match the family's first plan",
        )
    plan_envelope = (plan["plan"] or {}).get("envelope_digest")
    if envelope_digest is None:
        if not first_round:
            return ReviewOutcome(
                "envelope_mismatch",
                state=job["state"],
                message="re-approval requires an explicit envelope digest",
            )
        if not isinstance(plan_envelope, str) or not plan_envelope:
            return ReviewOutcome(
                "envelope_mismatch",
                state=job["state"],
                message="the first plan has no envelope digest",
            )
        resolved_envelope = plan_envelope
    else:
        if not isinstance(envelope_digest, str) or not envelope_digest:
            return ReviewOutcome(
                "envelope_mismatch",
                state=job["state"],
                message="envelope digest must be a non-empty string",
            )
        if first_round and envelope_digest != plan_envelope:
            return ReviewOutcome(
                "envelope_mismatch",
                state=job["state"],
                message="envelope digest does not match the first plan",
            )
        resolved_envelope = envelope_digest

    # §9.1 step 2: an already-decided envelope is answered from its recorded
    # decision; it never appends a new row. The expiry check comes from the
    # envelope's own deadline, not the family's.
    envelope = connection.execute(
        "SELECT envelope_id, status, review_deadline_at, reviewer_id, decided_at "
        "FROM family_envelopes WHERE family_id = %s AND envelope_digest = %s",
        (job_id, resolved_envelope),
    ).fetchone()
    if envelope is not None and envelope["status"] in _FAMILY_ENVELOPE_DECISIONS:
        recorded_decision = _FAMILY_ENVELOPE_DECISIONS[envelope["status"]]
        same = (
            recorded_decision == decision
            and envelope["reviewer_id"] == reviewer_id
        )
        return ReviewOutcome(
            "idempotent" if same else "conflict",
            state=job["state"],
            review={
                "decision": recorded_decision,
                "reviewer_id": envelope["reviewer_id"],
                "plan_digest": first_plan_digest,
                "decided_at": jsonutil.timestamp(envelope["decided_at"]),
            },
            message=None if same else "a different review decision is recorded",
        )
    if envelope is not None and envelope["status"] == "expired":
        return ReviewOutcome(
            "expired", state=job["state"], message="the review window expired"
        )
    # §9.1 step 3: a missing or non-pending envelope is a mismatch. This also
    # covers a first-round explicit digest that differs from the first plan
    # and a re-approval that omitted the digest; neither falls back to the
    # already-approved envelope.
    if envelope is None or envelope["status"] != "pending":
        return ReviewOutcome(
            "envelope_mismatch",
            state=job["state"],
            message="envelope digest is not the current pending envelope",
        )
    decision_at = connection.execute(
        "SELECT clock_timestamp() AS db_now"
    ).fetchone()["db_now"]
    if _review_window_closed(envelope["review_deadline_at"], decision_at):
        connection.execute(
            "UPDATE family_envelopes SET status = 'expired' "
            "WHERE envelope_id = %s AND status = 'pending'",
            (envelope["envelope_id"],),
        )
        _block_v2_review_job(
            connection,
            child["job_id"],
            reason_code="REVIEW_EXPIRED",
            message="review deadline passed before a decision was recorded",
        )
        _block_v2_review_job(
            connection,
            job_id,
            reason_code="REVIEW_EXPIRED",
            message="review deadline passed before a decision was recorded",
        )
        _audit(
            connection,
            job_id,
            "review_expired",
            stage="blocked",
            reason_code="REVIEW_EXPIRED",
            detail={
                "generation": job["generation"],
                "requested_digest": plan_digest,
                "plan_digest": first_plan_digest,
                "envelope_digest": resolved_envelope,
            },
        )
        return ReviewOutcome(
            "expired",
            state="BLOCKED",
            message="the review window expired",
        )

    review = {
        "decision": decision,
        "reviewer_id": reviewer_id,
        "plan_digest": first_plan_digest,
        "decided_at": jsonutil.timestamp(decision_at),
    }
    if decision == "approve":
        # reviews is a first-round record only; a changed-envelope re-approval
        # appends to family_approvals and must not rewrite it.
        if first_round:
            connection.execute(
                "INSERT INTO reviews "
                "(review_id, job_id, plan_digest, reviewer_id, decision, "
                "review_deadline_at, decided_at) "
                "VALUES (%s, %s, %s, %s, 'approve', %s, clock_timestamp())",
                (
                    uuid.uuid4(),
                    job_id,
                    first_plan_digest,
                    reviewer_id,
                    envelope["review_deadline_at"],
                ),
            )
        # The chain tail is the approval no later row supersedes. Appending
        # against it keeps the historical chain append-only.
        supersedes = connection.execute(
            "SELECT prior.approval_id FROM family_approvals AS prior "
            "WHERE prior.family_id = %s AND NOT EXISTS ("
            "SELECT 1 FROM family_approvals AS later "
            "WHERE later.supersedes = prior.approval_id) "
            "LIMIT 1",
            (job_id,),
        ).fetchone()
        approval_digest = jsonutil.digest_json(
            {
                "family_id": str(job_id),
                "first_plan_digest": first_plan_digest,
                "envelope_digest": resolved_envelope,
                "reviewer_id": reviewer_id,
                "decided_at": jsonutil.timestamp(decision_at),
            }
        )
        connection.execute(
            "INSERT INTO family_approvals "
            "(approval_id, family_id, approval_digest, envelope_digest, "
            "first_plan_digest, reviewer_id, decided_at, supersedes) "
            "VALUES (%s, %s, %s, %s, %s, %s, %s, %s)",
            (
                uuid.uuid4(),
                job_id,
                approval_digest,
                resolved_envelope,
                first_plan_digest,
                reviewer_id,
                decision_at,
                supersedes["approval_id"] if supersedes is not None else None,
            ),
        )
        decided_envelope = connection.execute(
            "UPDATE family_envelopes SET status = 'approved', reviewer_id = %s, "
            "decided_at = %s WHERE envelope_id = %s AND status = 'pending' "
            "RETURNING envelope_id",
            (reviewer_id, decision_at, envelope["envelope_id"]),
        ).fetchone()
        if decided_envelope is None:
            raise StateError("family envelope changed while recording the review")
        if first_round:
            updated_child = connection.execute(
                "UPDATE jobs SET state = 'READY', stage = 'ready', "
                "reason_code = NULL, last_error = NULL, "
                "approved_at = clock_timestamp(), "
                "state_version = state_version + 1, "
                "generation = generation + 1, workflow_synced = false, "
                "lease_owner = NULL, lease_expires_at = NULL, "
                "updated_at = clock_timestamp() "
                "WHERE job_id = %s AND state = 'AWAITING_REVIEW' "
                "AND generation = %s RETURNING job_id",
                (child["job_id"], child["generation"]),
            ).fetchone()
            if updated_child is None:
                raise StateError("child state changed while recording the review")
        _audit(
            connection,
            job_id,
            "review_recorded",
            stage="review",
            detail={
                "decision": decision,
                "reviewer_id": reviewer_id,
                "plan_digest": first_plan_digest,
                "envelope_digest": resolved_envelope,
            },
        )
        return ReviewOutcome("applied", state="AGGREGATING", review=review)

    if first_round:
        connection.execute(
            "INSERT INTO reviews "
            "(review_id, job_id, plan_digest, reviewer_id, decision, "
            "review_deadline_at, decided_at) "
            "VALUES (%s, %s, %s, %s, 'reject', %s, clock_timestamp())",
            (
                uuid.uuid4(),
                job_id,
                first_plan_digest,
                reviewer_id,
                envelope["review_deadline_at"],
            ),
        )
    decided_envelope = connection.execute(
        "UPDATE family_envelopes SET status = 'rejected', reviewer_id = %s, "
        "decided_at = %s WHERE envelope_id = %s AND status = 'pending' "
        "RETURNING envelope_id",
        (reviewer_id, decision_at, envelope["envelope_id"]),
    ).fetchone()
    if decided_envelope is None:
        raise StateError("family envelope changed while recording the review")
    _block_v2_review_job(
        connection,
        child["job_id"],
        reason_code="REVIEW_REJECTED",
        message="review rejected by the operator",
    )
    _block_v2_review_job(
        connection,
        job_id,
        reason_code="REVIEW_REJECTED",
        message="review rejected by the operator",
    )
    _audit(
        connection,
        job_id,
        "review_recorded",
        stage="review",
        detail={
            "decision": decision,
            "reviewer_id": reviewer_id,
            "plan_digest": first_plan_digest,
            "envelope_digest": resolved_envelope,
        },
    )
    return ReviewOutcome("applied", state="BLOCKED", review=review)


def record_review(
    dsn: str,
    job_id: UUID,
    *,
    plan_digest: str,
    decision: str,
    reviewer_id: str,
    envelope_digest: str | None = None,
) -> ReviewOutcome:
    # envelope_digest belongs to the v2 family envelope path. It is accepted
    # here so the CLI can forward it without a second entrypoint; the v1 review
    # path below intentionally does not read it.
    if decision not in ("approve", "reject"):
        raise StateError("decision must be approve or reject")
    if not isinstance(reviewer_id, str) or not reviewer_id.strip():
        raise StateError("reviewer_id must be non-empty")
    if len(reviewer_id) > 128:
        raise StateError("reviewer_id is too long")

    pending_blocked: list[tuple[str, str]] = []
    with ExitStack() as stack:
        # Registered before the connection so it runs after the transaction
        # commits (ExitStack unwinds in reverse order). record_review has no
        # worker lease; record_blocked_evidence intentionally does not require
        # one.
        stack.callback(_archive_pending_blocked, dsn, job_id, pending_blocked)
        connection = stack.enter_context(_connect(dsn))
        job = connection.execute(
            "SELECT state, reason_code, review_deadline_at, generation, "
            "job_contract_version, job_kind, family_id "
            "FROM jobs WHERE job_id = %s FOR UPDATE",
            (job_id,),
        ).fetchone()
        if job is None:
            return ReviewOutcome("job_not_found", message="job does not exist")
        # A v2 review is family-scoped: the target is the family row and the
        # envelope/approval ledger below is the only review record. A v2 child
        # is never a review entrypoint, so it still fails closed.
        if job["job_kind"] == "family" and job["job_contract_version"] == 2:
            return _record_family_review(
                connection,
                job_id,
                job,
                plan_digest=plan_digest,
                decision=decision,
                reviewer_id=reviewer_id,
                envelope_digest=envelope_digest,
            )
        if job["job_contract_version"] != 1:
            raise StateError("v2 review target must be a family job")
        plan = connection.execute(
            "SELECT plan_digest FROM plans WHERE job_id = %s", (job_id,)
        ).fetchone()
        existing = connection.execute(
            "SELECT review_id, plan_digest, reviewer_id, decision, "
            "review_deadline_at, decided_at FROM reviews WHERE job_id = %s",
            (job_id,),
        ).fetchone()
        if existing is not None:
            same = (
                existing["plan_digest"] == plan_digest
                and existing["decision"] == decision
                and existing["reviewer_id"] == reviewer_id
            )
            if not same:
                _audit(
                    connection,
                    job_id,
                    "review_refused",
                    stage="review",
                    reason_code="REVIEW_CONFLICT",
                    detail={
                        "decision": decision,
                        "reviewer_id": reviewer_id,
                        "requested_digest": plan_digest,
                        "recorded_decision": existing["decision"],
                        "recorded_reviewer_id": existing["reviewer_id"],
                        "recorded_digest": existing["plan_digest"],
                    },
                )
            return ReviewOutcome(
                "idempotent" if same else "conflict",
                state=job["state"],
                review={
                    "decision": existing["decision"],
                    "reviewer_id": existing["reviewer_id"],
                    "plan_digest": existing["plan_digest"],
                    "decided_at": jsonutil.timestamp(existing["decided_at"]),
                },
                message=None if same else "a different review decision is recorded",
            )
        if job["state"] == "BLOCKED" and job["reason_code"] == "REVIEW_EXPIRED":
            _audit(
                connection,
                job_id,
                "review_refused",
                stage="review",
                reason_code="REVIEW_EXPIRED",
                detail={
                    "decision": decision,
                    "reviewer_id": reviewer_id,
                    "requested_digest": plan_digest,
                },
            )
            return ReviewOutcome(
                "expired", state=job["state"], message="the review window expired"
            )
        if job["state"] != "AWAITING_REVIEW":
            _audit(
                connection,
                job_id,
                "review_refused",
                stage="review",
                reason_code="INVALID_STATE",
                detail={
                    "decision": decision,
                    "reviewer_id": reviewer_id,
                    "requested_digest": plan_digest,
                    "state": job["state"],
                },
            )
            return ReviewOutcome(
                "invalid_state",
                state=job["state"],
                message=f"job is {job['state']}, not AWAITING_REVIEW",
            )
        # Read the clock only after the row lock is held. The review command
        # may have started its transaction (and therefore ``now()``) before a
        # worker released the lock, but the decision is not effective until
        # this point. ``clock_timestamp()`` is the actual decision time.
        decision_at = connection.execute(
            "SELECT clock_timestamp() AS db_now"
        ).fetchone()["db_now"]
        # A legacy/partially migrated row has no review window, and the
        # shared predicate fails closed for it instead of raising an
        # indeterminate-type database error or letting the row sit in
        # AWAITING_REVIEW forever.
        if _review_window_closed(job["review_deadline_at"], decision_at):
            updated = connection.execute(
                "UPDATE jobs SET state = 'BLOCKED', stage = 'blocked', "
                "reason_code = 'REVIEW_EXPIRED', last_error = %s, "
                "state_version = state_version + 1, generation = generation + 1, "
                "workflow_synced = false, lease_owner = NULL, "
                "lease_expires_at = NULL, updated_at = clock_timestamp() "
                "WHERE job_id = %s AND state = 'AWAITING_REVIEW' "
                "AND generation = %s RETURNING job_id",
                (
                    "review deadline passed before a decision was recorded",
                    job_id,
                    job["generation"],
                ),
            ).fetchone()
            if updated is None:
                raise StateError("job state changed while expiring the review")
            _audit(
                connection,
                job_id,
                "review_expired",
                stage="blocked",
                reason_code="REVIEW_EXPIRED",
                detail={
                    "requested_digest": plan_digest,
                    "plan_digest": (
                        plan["plan_digest"] if plan is not None else None
                    ),
                },
            )
            pending_blocked.append(
                (
                    "REVIEW_EXPIRED",
                    "review deadline passed before a decision was recorded",
                )
            )
            return ReviewOutcome(
                "expired",
                state="BLOCKED",
                message="the review window expired",
            )
        if plan is None:
            _audit(
                connection,
                job_id,
                "review_refused",
                stage="review",
                reason_code="INVALID_STATE",
                detail={
                    "decision": decision,
                    "reviewer_id": reviewer_id,
                    "requested_digest": plan_digest,
                    "state": job["state"],
                },
            )
            return ReviewOutcome(
                "invalid_state", state=job["state"], message="no plan is pending"
            )
        if plan_digest != plan["plan_digest"]:
            _audit(
                connection,
                job_id,
                "review_refused",
                stage="review",
                reason_code="PLAN_MISMATCH",
                detail={
                    "decision": decision,
                    "reviewer_id": reviewer_id,
                    "requested_digest": plan_digest,
                    "frozen_digest": plan["plan_digest"],
                },
            )
            return ReviewOutcome(
                "plan_mismatch",
                state=job["state"],
                message="plan digest does not match the pending plan",
            )

        review = connection.execute(
            "INSERT INTO reviews "
            "(review_id, job_id, plan_digest, reviewer_id, decision, "
            "review_deadline_at, decided_at) "
            "VALUES (%s, %s, %s, %s, %s, %s, clock_timestamp()) "
            "RETURNING review_id, plan_digest, reviewer_id, decision, decided_at",
            (
                uuid.uuid4(),
                job_id,
                plan_digest,
                reviewer_id,
                decision,
                job["review_deadline_at"],
            ),
        ).fetchone()
        if decision == "approve":
            state = "READY"
            updated = connection.execute(
                "UPDATE jobs SET state = 'READY', stage = 'ready', "
                "reason_code = NULL, last_error = NULL, "
                "approved_at = clock_timestamp(), "
                "state_version = state_version + 1, generation = generation + 1, "
                "workflow_synced = false, lease_owner = NULL, "
                "lease_expires_at = NULL, updated_at = clock_timestamp() "
                "WHERE job_id = %s AND state = 'AWAITING_REVIEW' "
                "AND generation = %s RETURNING job_id",
                (job_id, job["generation"]),
            ).fetchone()
        else:
            state = "BLOCKED"
            updated = connection.execute(
                "UPDATE jobs SET state = 'BLOCKED', stage = 'blocked', "
                "reason_code = 'REVIEW_REJECTED', last_error = %s, "
                "state_version = state_version + 1, generation = generation + 1, "
                "workflow_synced = false, lease_owner = NULL, "
                "lease_expires_at = NULL, updated_at = clock_timestamp() "
                "WHERE job_id = %s AND state = 'AWAITING_REVIEW' "
                "AND generation = %s RETURNING job_id",
                (
                    "review rejected by the operator",
                    job_id,
                    job["generation"],
                ),
            ).fetchone()
        if updated is None:
            raise StateError("job state changed while recording the review")
        _audit(
            connection,
            job_id,
            "review_recorded",
            stage="review",
            detail={
                "decision": decision,
                "reviewer_id": reviewer_id,
                "plan_digest": plan_digest,
            },
        )
        if decision == "reject":
            pending_blocked.append(
                ("REVIEW_REJECTED", "review rejected by the operator")
            )
        return ReviewOutcome(
            "applied",
            state=state,
            review={
                "decision": review["decision"],
                "reviewer_id": review["reviewer_id"],
                "plan_digest": review["plan_digest"],
                "decided_at": jsonutil.timestamp(review["decided_at"]),
            },
        )


def expire_review(dsn: str, job_id: UUID, generation: int) -> bool:
    pending_blocked: list[tuple[str, str]] = []
    with ExitStack() as stack:
        stack.callback(_archive_pending_blocked, dsn, job_id, pending_blocked)
        connection = stack.enter_context(_connect(dsn))
        job = connection.execute(
            "SELECT state, generation, review_deadline_at, lease_owner, "
            "lease_expires_at, job_contract_version, job_kind, family_id, "
            "(SELECT plan_digest FROM plans WHERE plans.job_id = jobs.job_id) "
            "AS plan_digest "
            "FROM jobs WHERE job_id = %s FOR UPDATE",
            (job_id,),
        ).fetchone()
        if job is None or job["state"] != "AWAITING_REVIEW":
            return False
        if job["generation"] != generation:
            raise StaleGeneration("execution generation is no longer current")
        # Read the clock only after the row lock is held. A worker that was
        # waiting for the lock across the deadline must observe that wait.
        db_now = connection.execute(
            "SELECT clock_timestamp() AS db_now"
        ).fetchone()["db_now"]
        if (
            job["lease_expires_at"] is None
            or job["lease_expires_at"] <= db_now
        ):
            raise StaleGeneration("the worker lease is no longer active")
        if not _review_window_closed(job["review_deadline_at"], db_now):
            return False
        connection.execute(
            "UPDATE jobs SET state = 'BLOCKED', stage = 'blocked', "
            "reason_code = 'REVIEW_EXPIRED', last_error = %s, "
            "state_version = state_version + 1, generation = generation + 1, "
            "workflow_synced = false, lease_owner = NULL, "
            "lease_expires_at = NULL, updated_at = clock_timestamp() "
            "WHERE job_id = %s AND generation = %s",
            ("review deadline passed before a decision was recorded", job_id, generation),
        )
        _audit(
            connection,
            job_id,
            "review_expired",
            stage="blocked",
            reason_code="REVIEW_EXPIRED",
            detail={
                "generation": generation,
                "plan_digest": job["plan_digest"],
            },
        )
        # A v2 child is not the review unit: expire the family that owns it in
        # the same transaction so the aggregate can never stay AGGREGATING
        # after its pending envelope timed out.
        if (
            job["job_contract_version"] == 2
            and job["job_kind"] in ("campaign", "round")
            and job["family_id"] is not None
        ):
            family = connection.execute(
                "SELECT state, generation FROM jobs WHERE job_id = %s FOR UPDATE",
                (job["family_id"],),
            ).fetchone()
            if family is not None:
                connection.execute(
                    "UPDATE jobs SET state = 'BLOCKED', stage = 'blocked', "
                    "reason_code = 'REVIEW_EXPIRED', last_error = %s, "
                    "state_version = state_version + 1, "
                    "generation = generation + 1, workflow_synced = false, "
                    "lease_owner = NULL, lease_expires_at = NULL, "
                    "updated_at = clock_timestamp() WHERE job_id = %s",
                    (
                        "review deadline passed before a decision was recorded",
                        job["family_id"],
                    ),
                )
                connection.execute(
                    "UPDATE family_envelopes SET status = 'expired' "
                    "WHERE family_id = %s AND status = 'pending'",
                    (job["family_id"],),
                )
                _audit(
                    connection,
                    job["family_id"],
                    "review_expired",
                    stage="blocked",
                    reason_code="REVIEW_EXPIRED",
                    detail={
                        "generation": family["generation"],
                        "child_job_id": str(job_id),
                        "plan_digest": job["plan_digest"],
                    },
                )
        pending_blocked.append(
            (
                "REVIEW_EXPIRED",
                "review deadline passed before a decision was recorded",
            )
        )
        return True


def status(dsn: str, job_id: UUID) -> dict[str, Any] | None:
    with _connect(dsn) as connection:
        row = connection.execute(
            """
            SELECT j.job_id, j.state, j.stage, j.reason_code, j.last_error,
                   j.verdict, j.verdict_reason, j.evidence_digest, j.evidence_path,
                   j.evidence_status, j.evidence_error,
                   p.plan_digest, p.summary, p.plan, p.created_at AS plan_created_at,
                   r.decision, r.reviewer_id, r.plan_digest AS review_plan_digest,
                   r.decided_at
            FROM jobs j
            LEFT JOIN plans p ON p.job_id = j.job_id
            LEFT JOIN reviews r ON r.job_id = j.job_id
            WHERE j.job_id = %s
            """,
            (job_id,),
        ).fetchone()
    if row is None:
        return None

    pending_plan = None
    evidence_refs: list[str] = []
    if row["plan_digest"] is not None:
        pending_plan = {
            "plan_digest": row["plan_digest"],
            "summary": row["summary"],
            "plan": row["plan"],
            "created_at": jsonutil.timestamp(row["plan_created_at"]),
        }
        findings = (row["plan"].get("analysis") or {}).get("findings", [])
        evidence_refs = sorted(
            {
                reference
                for finding in findings
                for reference in finding.get("evidence_refs", [])
            }
        )
    review_state = None
    if row["decision"] is not None:
        review_state = {
            "decision": row["decision"],
            "reviewer_id": row["reviewer_id"],
            "plan_digest": row["review_plan_digest"],
            "decided_at": jsonutil.timestamp(row["decided_at"]),
        }
    evidence = None
    if (
        row["evidence_status"] is not None
        or row["evidence_digest"] is not None
        or row["evidence_path"] is not None
        or row["verdict"] is not None
    ):
        evidence = {
            "available": row["evidence_status"] == "archived"
            and row["evidence_path"] is not None
            and row["evidence_digest"] is not None,
            "status": row["evidence_status"],
            "digest": row["evidence_digest"],
            "path": row["evidence_path"],
            "error": row["evidence_error"],
        }
    # A verdict is authoritative only for an archived bundle. A terminal that
    # did not archive evidence is already FAILED with a NULL verdict and
    # evidence pointer (finish_execution/record_blocked_evidence clear them),
    # so status returns a verdict only while the archived+path+digest
    # invariant holds. The old value is never retained for history.
    verdict_current = (
        row["evidence_status"] == "archived"
        and row["verdict"] is not None
        and row["evidence_path"] is not None
        and row["evidence_digest"] is not None
    )
    return {
        "job_id": str(row["job_id"]),
        "state": row["state"],
        "stage": row["stage"],
        "pending_plan": pending_plan,
        "review_state": review_state,
        "reason_code": row["reason_code"],
        "last_error": row["last_error"],
        "evidence_refs": evidence_refs,
        "verdict": row["verdict"] if verdict_current else None,
        "verdict_reason": row["verdict_reason"] if verdict_current else None,
        "verdict_current": verdict_current,
        "evidence": evidence,
    }


# ---------------------------------------------------------------------------
# Release promotion / rollback persistence (T08, TC-10, SF2)
# ---------------------------------------------------------------------------

RELEASE_ACTIVE_STATES = ("PREPARING", "RUNNING", "ARCHIVING")
_RELEASE_DIGEST_FIELDS = ("candidate_digest", "manifest_digest")
_MIGRATION_FILE = re.compile(r"^([0-9]{3})_[A-Za-z0-9_]+\.sql$")


class ReleaseStateError(StateError):
    """A persisted release transition is invalid or missing."""


def _release_digest(value: Any, label: str) -> str:
    if not isinstance(value, str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", value):
        raise ReleaseStateError(f"{label} must be a sha256 digest")
    return value


def _b03_acceptance_record(row: Mapping[str, Any]) -> dict[str, Any]:
    status = row["status"]
    if status != "passed":
        raise ReleaseStateError(
            f"persisted B03 acceptance has status {status!r}; only 'passed' is valid"
        )
    payload = row["payload"]
    return {
        "environment": row["environment"],
        "candidate_digest": row["candidate_digest"],
        "control_plane_image_id": row["control_plane_image_id"],
        "b03_bundle_manifest_digest": row["b03_bundle_manifest_digest"],
        "storage_ref": row["storage_ref"],
        "run_id": row["run_id"],
        "status": status,
        "accepted_at": row["accepted_at"].isoformat(),
        "payload": dict(payload) if isinstance(payload, Mapping) else {},
    }


def _migration_sha256(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


def _migration_number(name: str) -> int:
    match = _MIGRATION_FILE.fullmatch(name)
    if match is None:
        raise ReleaseStateError(
            f"migration file must be NNN_name.sql: {name!r}"
        )
    return int(match.group(1))


def apply_migrations(connection, migrations_dir: Path | str) -> dict[str, str]:
    """Apply every migration in order and record filename + sha256 in the ledger.

    The caller must use an autocommit connection: each migration file contains
    its own ``BEGIN``/``COMMIT`` and is designed to be repeatable. A migration
    that is already recorded is skipped, and a recorded filename whose on-disk
    digest changed fails closed instead of silently applying a different file.
    This is the only supported way to make the ledger match the real schema.
    """
    paths = sorted(Path(migrations_dir).glob("*.sql"))
    if not paths:
        raise ReleaseStateError(f"no SQL migrations found in {migrations_dir}")
    numbers = [_migration_number(path.name) for path in paths]
    if numbers != list(range(1, len(numbers) + 1)):
        raise ReleaseStateError(
            "migrations must be numbered consecutively from 001"
        )
    connection.execute(
        "CREATE TABLE IF NOT EXISTS schema_migrations ("
        "file text PRIMARY KEY, "
        "sha256 text NOT NULL, "
        "applied_at timestamptz NOT NULL DEFAULT clock_timestamp(), "
        "CONSTRAINT schema_migrations_file_check "
        "CHECK (file ~ '^[0-9]{3}_[A-Za-z0-9_]+\\.sql$'), "
        "CONSTRAINT schema_migrations_sha256_check "
        "CHECK (sha256 ~ '^sha256:[0-9a-f]{64}$'))"
    )
    applied: dict[str, str] = {}
    for path in paths:
        name = path.name
        digest = _migration_sha256(path)
        row = connection.execute(
            "SELECT sha256 FROM schema_migrations WHERE file = %s", (name,)
        ).fetchone()
        if row is not None:
            recorded = row["sha256"]
            if recorded != digest:
                raise ReleaseStateError(
                    f"migration {name} was already applied with a different "
                    "digest; refusing to re-run a changed migration"
                )
            applied[name] = digest
            continue
        connection.execute(path.read_text(encoding="utf-8"))
        connection.execute(
            "INSERT INTO schema_migrations (file, sha256) VALUES (%s, %s) "
            "ON CONFLICT (file) DO NOTHING",
            (name, digest),
        )
        applied[name] = digest
    return applied


def apply_migrations_dsn(dsn: str, migrations_dir: Path | str) -> dict[str, str]:
    """Apply migrations on a dedicated autocommit connection (CLI/workflow)."""
    with psycopg.connect(
        dsn, autocommit=True, connect_timeout=5, row_factory=dict_row
    ) as connection:
        return apply_migrations(connection, migrations_dir)


def _reject_symlink_ancestors(path: Path, *, label: str) -> None:
    jsonutil.reject_symlink_ancestors(path, label=label, error_cls=ReleaseStateError)


def _validate_evidence_bundle_path(evidence_path: Any, evidence_root: str) -> Path:
    """Validate that an archived ``evidence_path`` stays inside ``evidence_root`` without symlinks."""
    if not isinstance(evidence_path, str) or not evidence_path.strip():
        raise ReleaseStateError("evidence_path must be a non-empty path")
    if "\\" in evidence_path:
        raise ReleaseStateError("evidence_path must use POSIX separators")
    root_path = Path(evidence_root)
    _reject_symlink_ancestors(root_path, label="active release evidence_root")
    candidate = Path(evidence_path)
    if ".." in candidate.parts:
        raise ReleaseStateError("evidence_path must not contain '..' traversal")
    if not candidate.is_absolute():
        raise ReleaseStateError(
            "evidence_path must be an absolute path inside active release evidence_root"
        )
    try:
        rel_path = candidate.relative_to(root_path)
    except ValueError:
        try:
            rel_path = candidate.relative_to(root_path.resolve())
        except ValueError as error:
            raise ReleaseStateError(
                "evidence_path must stay inside active release evidence_root"
            ) from error
    try:
        return jsonutil.resolve_inside(root_path, rel_path.as_posix())
    except ValueError as error:
        raise ReleaseStateError(f"unsafe evidence_path: {error}") from error


def _validate_evidence_path_syntax(evidence_path: Any) -> None:
    """Validate non-filesystem path safety invariants when the host volume is unmounted."""
    if not isinstance(evidence_path, str) or not evidence_path.strip():
        raise ReleaseStateError("evidence_path must be a non-empty path")
    if "\\" in evidence_path:
        raise ReleaseStateError("evidence_path must use POSIX separators")
    candidate = Path(evidence_path)
    if ".." in candidate.parts:
        raise ReleaseStateError("evidence_path must not contain '..' traversal")
    if not candidate.is_absolute():
        raise ReleaseStateError(
            "evidence_path must be an absolute path inside active release evidence_root"
        )


class ReleaseStore:
    """PostgreSQL-backed promotion state and append-only audit.

    The store is the only source of the active slots and previous release. A
    workflow cannot pass those values in, which is what makes the promotion
    gate causal rather than self-attested.
    """

    def __init__(self, dsn: str, *, environment: str = RELEASE_ENVIRONMENT):
        if not isinstance(environment, str) or environment != RELEASE_ENVIRONMENT:
            raise ReleaseStateError(
                f"unsupported release environment {environment!r}; "
                f"only {RELEASE_ENVIRONMENT!r} is supported"
            )
        self.dsn = dsn
        self.environment = environment
        self._tx_local = threading.local()

    @property
    def switches(self) -> list[dict[str, Any]] | None:
        return getattr(self._tx_local, "switches", None)

    def _connect(self):
        return psycopg.connect(
            self.dsn, connect_timeout=5, row_factory=dict_row
        )

    def _ensure_release_tables(self, connection) -> None:
        reg = connection.execute(
            "SELECT to_regclass('schema_migrations') AS migrations_tbl, "
            "to_regclass('release_state') AS release_tbl, "
            "to_regclass('release_events') AS events_tbl"
        ).fetchone()
        if (
            reg is None
            or reg["migrations_tbl"] is None
            or reg["release_tbl"] is None
            or reg["events_tbl"] is None
        ):
            raise ReleaseStateError(
                "schema_migrations ledger is missing; run `datacon migrate` "
                "against the target database before bootstrapping, promoting, "
                "rolling back, or querying release state"
            )

    def _ensure_b03_acceptance_table(self, connection) -> None:
        """Fail closed when migration 009 has not been applied.

        The B03 ledger is intentionally checked per call rather than in
        ``_ensure_release_tables`` so promotion/rollback on a database migrated
        only through 008 keep their existing behaviour; the B03 entrypoints
        themselves never write to a schema they cannot prove.
        """
        reg = connection.execute(
            "SELECT to_regclass('b03_acceptance') AS b03_tbl"
        ).fetchone()
        if reg is None or reg["b03_tbl"] is None:
            raise ReleaseStateError(
                "b03_acceptance table is missing; run `datacon migrate` "
                "against the target database before recording or reading B03 "
                "acceptance"
            )

    @contextmanager
    def _connection(self):
        active = getattr(self._tx_local, "conn", None)
        if active is not None:
            yield active
            return
        with self._connect() as connection:
            self._ensure_release_tables(connection)
            yield connection

    @contextmanager
    def transaction(self):
        """Run promotion/rollback checks, state switch, and audit in one transaction.

        Acquires a per-environment advisory lock and locks the ``release_state``
        row so concurrent workflows cannot interleave or overwrite
        ``previous_image_id``. The same lock is taken in shared mode by
        ``claim_next``, so a claim cannot slip in between the drain check and
        the switch. Any exception rolls back both ``release_state`` and
        ``release_events`` together.
        """
        existing = getattr(self._tx_local, "conn", None)
        if existing is not None:
            yield existing
            return
        with self._connect() as connection:
            connection.execute("SET LOCAL lock_timeout = '10s'")
            connection.execute("SET LOCAL statement_timeout = '60s'")
            connection.execute(
                "SELECT pg_advisory_xact_lock(hashtext(%s))",
                (RELEASE_LOCK_PREFIX + self.environment,),
            )
            self._ensure_release_tables(connection)
            connection.execute(
                "SELECT 1 FROM release_state WHERE environment = %s FOR UPDATE",
                (self.environment,),
            )
            self._tx_local.conn = connection
            self._tx_local.switches = []
            try:
                yield connection
            finally:
                self._tx_local.conn = None
                self._tx_local.switches = None

    def active_slots(self) -> int:
        # v1 counts its three in-flight states. v2 adds the six child states
        # plus an unsynced BLOCKED child. AGGREGATING is special: a family
        # that already owns child rows is represented by those rows (counting
        # the aggregate as well would double its drain units), while a
        # childless AGGREGATING family is a residual in its own right. One
        # OR'd predicate over one row also keeps a v2 job that matches the v1
        # list from counting twice.
        with self._connection() as connection:
            row = connection.execute(
                "SELECT COUNT(*) AS active FROM jobs "
                "WHERE state = ANY(%s) "
                "OR (job_contract_version = 2 AND ("
                "state IN ('QUEUED', 'PREPARING', 'AWAITING_REVIEW', "
                "'READY', 'RUNNING', 'ARCHIVING') "
                "OR (state = 'BLOCKED' AND workflow_synced = false) "
                "OR (state = 'AGGREGATING' AND ("
                "job_kind IS DISTINCT FROM 'family' "
                "OR NOT EXISTS (SELECT 1 FROM jobs child "
                "WHERE child.parent_job_id = jobs.job_id)))))",
                (list(RELEASE_ACTIVE_STATES),),
            ).fetchone()
        return int(row["active"])

    def active_release(self) -> dict[str, Any] | None:
        with self._connection() as connection:
            row = connection.execute(
                "SELECT image_id, config, migration_version, evidence_root, updated_at "
                "FROM release_state WHERE environment = %s",
                (self.environment,),
            ).fetchone()
        if row is None:
            return None
        return {
            "image_id": row["image_id"],
            "config": row["config"],
            "migration_version": row["migration_version"],
            "evidence_root": row["evidence_root"],
            "updated_at": row["updated_at"].isoformat(),
        }

    def bootstrap_release(
        self,
        *,
        image_id: str,
        config: Mapping[str, Any],
        migration_version: str,
        evidence_root: str,
    ) -> None:
        """Insert the baseline release and its audit snapshot exactly once.

        The baseline has no prior promotion event, so without its own
        ``release_events`` row a later promotion would overwrite
        ``release_state`` and make rollback to the baseline impossible. The
        snapshot is written in the same transaction as the state row and is
        idempotent: repeating an identical bootstrap writes nothing, while a
        conflicting bootstrap fails closed instead of silently replacing it.
        """
        _release_digest(image_id, "bootstrap image_id")
        if not isinstance(config, Mapping):
            raise ReleaseStateError("bootstrap config must be an object")
        if not isinstance(migration_version, str) or not _MIGRATION_FILE.fullmatch(
            migration_version
        ):
            raise ReleaseStateError(
                "bootstrap migration_version must be an NNN_*.sql migration name"
            )
        if not isinstance(evidence_root, str) or not evidence_root.strip():
            raise ReleaseStateError("bootstrap evidence_root must be a path")
        snapshot = {
            "image_id": image_id,
            "config": dict(config),
            "migration_version": migration_version,
            "evidence_root": evidence_root,
        }
        snapshot_digest = jsonutil.digest_json(snapshot)
        with self.transaction() as connection:
            try:
                ledger_rows = connection.execute(
                    "SELECT file FROM schema_migrations ORDER BY file"
                ).fetchall()
            except psycopg.errors.UndefinedTable as error:
                raise ReleaseStateError(
                    "schema_migrations ledger is missing; run `datacon migrate` "
                    "against the target database before bootstrapping a release"
                ) from error
            applied_files = [
                row["file"]
                for row in ledger_rows
                if isinstance(row.get("file"), str)
            ]
            if not applied_files:
                raise ReleaseStateError(
                    "schema_migrations ledger is empty; run `datacon migrate` "
                    "against the target database before bootstrapping a release"
                )
            numbers = sorted(_migration_number(name) for name in applied_files)
            if numbers != list(range(1, len(numbers) + 1)):
                raise ReleaseStateError(
                    "schema_migrations ledger has non-consecutive or duplicate "
                    "migration ordinals (expected consecutive 001..N without gaps)"
                )
            if migration_version not in applied_files:
                raise ReleaseStateError(
                    "bootstrap migration_version is not recorded in schema_migrations: "
                    f"{migration_version}"
                )
            latest_migration = max(applied_files, key=_migration_number)
            if migration_version != latest_migration:
                raise ReleaseStateError(
                    f"bootstrap migration_version {migration_version} is behind the "
                    f"latest applied migration in schema_migrations: {latest_migration}"
                )
            connection.execute(
                "INSERT INTO release_state "
                "(environment, image_id, config, migration_version, evidence_root) "
                "VALUES (%s, %s, %s, %s, %s) ON CONFLICT (environment) DO NOTHING",
                (
                    self.environment,
                    image_id,
                    Jsonb(dict(config)),
                    migration_version,
                    evidence_root,
                ),
            )
            existing = connection.execute(
                "SELECT payload FROM release_events "
                "WHERE environment = %s AND action = 'bootstrap'",
                (self.environment,),
            ).fetchone()
            if existing is not None:
                payload = existing["payload"]
                if not isinstance(payload, Mapping) or any(
                    payload.get(field) != snapshot[field] for field in snapshot
                ):
                    raise ReleaseStateError(
                        "bootstrap_release conflicts with the persisted baseline"
                    )
                return
            row = connection.execute(
                "SELECT image_id, config, migration_version, evidence_root "
                "FROM release_state WHERE environment = %s",
                (self.environment,),
            ).fetchone()
            if row is None:
                raise ReleaseStateError("bootstrap_release did not persist release_state")
            if any(
                row[field] != snapshot[field]
                for field in ("image_id", "config", "migration_version", "evidence_root")
            ):
                raise ReleaseStateError(
                    "release_state already exists with a different baseline; "
                    "refusing to record a mismatched bootstrap event"
                )
            connection.execute(
                "INSERT INTO release_events "
                "(event_id, environment, action, status, candidate_digest, "
                "manifest_digest, previous_image_id, active_image_id, payload) "
                "VALUES (%s, %s, 'bootstrap', 'bootstrapped', %s, %s, NULL, %s, %s) "
                "ON CONFLICT (environment) WHERE action = 'bootstrap' DO NOTHING",
                (
                    uuid.uuid4(),
                    self.environment,
                    snapshot_digest,
                    snapshot_digest,
                    image_id,
                    Jsonb(snapshot),
                ),
            )

    def switch(
        self,
        *,
        image_id: str,
        config: Mapping[str, Any],
        migration_version: str,
        evidence_root: str,
        action: str,
        candidate_digest: str,
    ) -> None:
        _release_digest(image_id, "switch image_id")
        _release_digest(candidate_digest, "switch candidate_digest")
        if action not in ("promote", "rollback"):
            raise ReleaseStateError(f"unknown release action: {action}")
        with self._connection() as connection:
            if action == "promote":
                active_row = connection.execute(
                    "SELECT COUNT(*) AS active FROM jobs WHERE state = ANY(%s)",
                    (list(RELEASE_ACTIVE_STATES),),
                ).fetchone()
                if int(active_row["active"]) != 0:
                    raise ReleaseStateError(
                        "promotion blocked: execution slots not drained "
                        f"(active_slots={int(active_row['active'])})"
                    )
            connection.execute(
                "INSERT INTO release_state "
                "(environment, image_id, config, migration_version, evidence_root) "
                "VALUES (%s, %s, %s, %s, %s) "
                "ON CONFLICT (environment) DO UPDATE SET "
                "image_id = EXCLUDED.image_id, config = EXCLUDED.config, "
                "migration_version = EXCLUDED.migration_version, "
                "evidence_root = EXCLUDED.evidence_root, "
                "updated_at = clock_timestamp()",
                (
                    self.environment,
                    image_id,
                    Jsonb(dict(config)),
                    migration_version,
                    evidence_root,
                ),
            )
            tx_switches = getattr(self._tx_local, "switches", None)
            if isinstance(tx_switches, list):
                tx_switches.append(
                    {
                        "image_id": image_id,
                        "config": dict(config),
                        "migration_version": migration_version,
                        "evidence_root": evidence_root,
                        "action": action,
                        "candidate_digest": candidate_digest,
                    }
                )

    def record_audit(self, result: Mapping[str, Any]) -> None:
        status = result.get("status")
        if not isinstance(status, str):
            raise ReleaseStateError(
                f"unknown release result status: {status!r}"
            )
        action = {"promoted": "promote", "rolled_back": "rollback"}.get(status)
        if action is None:
            raise ReleaseStateError(f"unknown release result status: {status!r}")
        candidate_digest = _release_digest(
            result.get("candidate_digest"), "candidate_digest"
        )
        manifest_digest = result.get("manifest_digest")
        if manifest_digest is None:
            # The manifest digest identifies the approved candidate or -- for a
            # baseline rollback -- the persisted release snapshot. An image id
            # is not a manifest digest and must never be substituted for one.
            raise ReleaseStateError(
                "release result is missing manifest_digest; refusing to record "
                "an image id as a manifest digest"
            )
        manifest_digest = _release_digest(manifest_digest, "manifest_digest")
        active_image = _release_digest(result.get("active_image_id"), "active_image_id")
        previous_image = result.get("previous_image_id")
        if previous_image is not None:
            previous_image = _release_digest(previous_image, "previous_image_id")
        with self._connection() as connection:
            params = (
                uuid.uuid4(),
                self.environment,
                action,
                status,
                candidate_digest,
                manifest_digest,
                previous_image,
                active_image,
                Jsonb(dict(result)),
            )
            if action == "promote":
                connection.execute(
                    "INSERT INTO release_events "
                    "(event_id, environment, action, status, candidate_digest, "
                    "manifest_digest, previous_image_id, active_image_id, payload) "
                    "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s) "
                    "ON CONFLICT (environment, candidate_digest) "
                    "WHERE action = 'promote' DO NOTHING",
                    params,
                )
            else:
                connection.execute(
                    "INSERT INTO release_events "
                    "(event_id, environment, action, status, candidate_digest, "
                    "manifest_digest, previous_image_id, active_image_id, payload) "
                    "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)",
                    params,
                )

    def promotion_for(self, candidate_digest: str) -> dict[str, Any] | None:
        _release_digest(candidate_digest, "candidate_digest")
        with self._connection() as connection:
            row = connection.execute(
                "SELECT payload FROM release_events "
                "WHERE environment = %s AND action = 'promote' "
                "AND status = 'promoted' AND candidate_digest = %s",
                (self.environment, candidate_digest),
            ).fetchone()
        return dict(row["payload"]) if row is not None else None

    def record_b03_acceptance(
        self,
        *,
        candidate_digest: str,
        control_plane_image_id: str,
        b03_bundle_manifest_digest: str,
        storage_ref: str,
        run_id: str,
        status: str = "passed",
        payload: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Persist one accepted B03 result, idempotently and without overwrites.

        ``candidate_digest`` is the release candidate manifest digest, never an
        image id. Repeating the exact same acceptance is a no-op; a conflicting
        record for the same ``(environment, candidate_digest)`` fails closed so
        a later run cannot silently replace a reviewed acceptance.
        """
        _release_digest(candidate_digest, "B03 candidate_digest")
        _release_digest(control_plane_image_id, "B03 control_plane_image_id")
        _release_digest(
            b03_bundle_manifest_digest, "B03 b03_bundle_manifest_digest"
        )
        if not isinstance(storage_ref, str) or not storage_ref.strip():
            raise ReleaseStateError("B03 storage_ref must be a non-empty string")
        if len(storage_ref) > 2048 or any(
            ord(character) < 0x20 for character in storage_ref
        ):
            raise ReleaseStateError("B03 storage_ref must be a bounded single-line string")
        if (
            not isinstance(run_id, str)
            or not re.fullmatch(r"[A-Za-z0-9._:-]{1,200}", run_id)
        ):
            raise ReleaseStateError("B03 run_id must be a short single-line identifier")
        if status != "passed":
            raise ReleaseStateError(
                f"B03 acceptance status must be 'passed'; got {status!r}"
            )
        if payload is None:
            payload = {}
        if not isinstance(payload, Mapping):
            raise ReleaseStateError("B03 acceptance payload must be an object")
        payload_doc = dict(payload)
        desired = {
            "environment": self.environment,
            "candidate_digest": candidate_digest,
            "control_plane_image_id": control_plane_image_id,
            "b03_bundle_manifest_digest": b03_bundle_manifest_digest,
            "storage_ref": storage_ref,
            "run_id": run_id,
            "status": status,
            "payload": payload_doc,
        }
        with self.transaction() as connection:
            self._ensure_b03_acceptance_table(connection)
            row = connection.execute(
                "SELECT environment, candidate_digest, control_plane_image_id, "
                "b03_bundle_manifest_digest, storage_ref, run_id, status, "
                "accepted_at, payload FROM b03_acceptance "
                "WHERE environment = %s AND candidate_digest = %s",
                (self.environment, candidate_digest),
            ).fetchone()
            if row is not None:
                existing = _b03_acceptance_record(row)
                for field, value in desired.items():
                    if existing[field] != value:
                        raise ReleaseStateError(
                            "B03 acceptance conflicts with the persisted record "
                            f"for {candidate_digest}: {field}"
                        )
                return existing
            connection.execute(
                "INSERT INTO b03_acceptance "
                "(environment, candidate_digest, control_plane_image_id, "
                "b03_bundle_manifest_digest, storage_ref, run_id, status, payload) "
                "VALUES (%s, %s, %s, %s, %s, %s, %s, %s)",
                (
                    self.environment,
                    candidate_digest,
                    control_plane_image_id,
                    b03_bundle_manifest_digest,
                    storage_ref,
                    run_id,
                    status,
                    Jsonb(payload_doc),
                ),
            )
            row = connection.execute(
                "SELECT environment, candidate_digest, control_plane_image_id, "
                "b03_bundle_manifest_digest, storage_ref, run_id, status, "
                "accepted_at, payload FROM b03_acceptance "
                "WHERE environment = %s AND candidate_digest = %s",
                (self.environment, candidate_digest),
            ).fetchone()
        if row is None:
            raise ReleaseStateError("B03 acceptance was not persisted")
        return _b03_acceptance_record(row)

    def b03_acceptance_for(self, candidate_digest: str) -> dict[str, Any]:
        """Return the accepted B03 record for a candidate, or fail closed."""
        _release_digest(candidate_digest, "B03 candidate_digest")
        with self._connection() as connection:
            self._ensure_b03_acceptance_table(connection)
            row = connection.execute(
                "SELECT environment, candidate_digest, control_plane_image_id, "
                "b03_bundle_manifest_digest, storage_ref, run_id, status, "
                "accepted_at, payload FROM b03_acceptance "
                "WHERE environment = %s AND candidate_digest = %s",
                (self.environment, candidate_digest),
            ).fetchone()
        if row is None:
            raise ReleaseStateError(
                "no B03 acceptance record exists for candidate "
                f"{candidate_digest}"
            )
        return _b03_acceptance_record(row)

    def applied_migrations(self) -> dict[str, str]:
        """Return the verifiable migration ledger as ``{file: sha256}``.

        A missing ledger fails closed: the promotion gate must never trust a
        manifest migration list against a database it cannot prove.
        """
        try:
            with self._connection() as connection:
                rows = connection.execute(
                    "SELECT file, sha256 FROM schema_migrations ORDER BY file"
                ).fetchall()
        except psycopg.errors.UndefinedTable as error:
            raise ReleaseStateError(
                "schema_migrations ledger is missing; run `datacon migrate` "
                "against the target database before promoting or rolling back"
            ) from error
        return {row["file"]: row["sha256"] for row in rows}

    def release_for_image(self, image_id: str) -> dict[str, Any] | None:
        """Return the most recent valid persisted release record for one image id.

        Rollback must restore the image together with its config, migration
        version and evidence root. Reading them from the audit log avoids a
        workflow supplying a half-invented previous release. Only successful
        event/status pairs are considered, so a malformed or failed audit row
        can never become rollback provenance.
        """
        _release_digest(image_id, "image_id")
        with self._connection() as connection:
            rows = connection.execute(
                "SELECT action, status, candidate_digest, manifest_digest, payload "
                "FROM release_events "
                "WHERE environment = %s AND active_image_id = %s "
                "AND action IN ('promote', 'rollback', 'bootstrap') "
                "AND status IN ('promoted', 'rolled_back', 'bootstrapped') "
                "ORDER BY CASE WHEN action IN ('promote', 'bootstrap') THEN 0 ELSE 1 END, "
                "recorded_at DESC, event_id DESC LIMIT 20",
                (self.environment, image_id),
            ).fetchall()
        for row in rows:
            payload = row["payload"]
            if not isinstance(payload, dict):
                continue
            config = payload.get("config")
            evidence_root = payload.get("evidence_root")
            migration_version = payload.get("migration_version")
            if not isinstance(config, dict) or not isinstance(evidence_root, str):
                continue
            if not isinstance(migration_version, str):
                continue
            return {
                "image_id": image_id,
                "config": config,
                "migration_version": migration_version,
                "evidence_root": evidence_root,
                "manifest_digest": row["manifest_digest"],
                "candidate_digest": row["candidate_digest"],
                "source_commit": payload.get("source_commit"),
                "baseline": row["action"] == "bootstrap",
                "action": row["action"],
            }
        # Legacy databases bootstrapped before the bootstrap event existed
        # still expose the active row. It has no manifest provenance, so
        # callers that require one fail closed instead of inventing it.
        active = self.active_release()
        if active is not None and active.get("image_id") == image_id:
            return {
                "image_id": active["image_id"],
                "config": active["config"],
                "migration_version": active["migration_version"],
                "evidence_root": active["evidence_root"],
            }
        return None

    def latest_evidence_bundle(
        self, *, require_active_root: bool = True, strict: bool = False
    ) -> dict[str, str] | None:
        """Return the newest archived evidence bundle after verifying containment."""
        if strict and not require_active_root:
            raise ReleaseStateError("strict=True requires require_active_root=True")
        with self._connection() as connection:
            job_rows = connection.execute(
                "SELECT evidence_path, evidence_digest FROM jobs "
                "WHERE evidence_status = 'archived' "
                "AND job_contract_version = 1 "
                "AND evidence_path IS NOT NULL AND evidence_digest IS NOT NULL "
                "ORDER BY submitted_at DESC"
            ).fetchall()
            if not job_rows:
                if strict:
                    raise ReleaseStateError(
                        "no archived evidence bundle found under active evidence_root"
                    )
                return None
            if not require_active_root:
                for row in job_rows:
                    _validate_evidence_path_syntax(row["evidence_path"])
                return {
                    "path": job_rows[0]["evidence_path"],
                    "digest": job_rows[0]["evidence_digest"],
                }
            hist_rows = connection.execute(
                "SELECT DISTINCT payload->>'evidence_root' AS evidence_root "
                "FROM release_events "
                "WHERE environment = %s "
                "AND action IN ('promote', 'rollback', 'bootstrap') "
                "AND status IN ('promoted', 'rolled_back', 'bootstrapped') "
                "AND payload ? 'evidence_root'",
                (self.environment,),
            ).fetchall()
        active = self.active_release()
        if active is None or not isinstance(active.get("evidence_root"), str):
            raise ReleaseStateError(
                "active release evidence_root is missing; cannot validate evidence_path"
            )
        active_root = active["evidence_root"]
        _reject_symlink_ancestors(
            Path(active_root), label="active release evidence_root"
        )
        historical_roots = [
            row["evidence_root"]
            for row in hist_rows
            if isinstance(row.get("evidence_root"), str)
            and row["evidence_root"].strip()
            and row["evidence_root"] != active_root
        ]
        for row in job_rows:
            raw_path = row["evidence_path"]
            try:
                resolved = _validate_evidence_bundle_path(raw_path, active_root)
                return {
                    "path": str(resolved),
                    "digest": row["evidence_digest"],
                }
            except ReleaseStateError as active_error:
                matched_historical = False
                for hist_root in historical_roots:
                    try:
                        _validate_evidence_bundle_path(raw_path, hist_root)
                        matched_historical = True
                        break
                    except ReleaseStateError:
                        continue
                if matched_historical:
                    continue
                raise active_error
        if strict:
            raise ReleaseStateError(
                f"no archived evidence bundle found under active evidence_root {active_root!r}"
            )
        return None

    def events(self) -> list[dict[str, Any]]:
        with self._connection() as connection:
            rows = connection.execute(
                "SELECT event_id, action, status, candidate_digest, "
                "previous_image_id, active_image_id, recorded_at FROM release_events "
                "WHERE environment = %s ORDER BY recorded_at, event_id",
                (self.environment,),
            ).fetchall()
        return [
            {
                "event_id": str(row["event_id"]),
                "action": row["action"],
                "status": row["status"],
                "candidate_digest": row["candidate_digest"],
                "previous_image_id": row["previous_image_id"],
                "active_image_id": row["active_image_id"],
                "recorded_at": row["recorded_at"].isoformat(),
            }
            for row in rows
        ]

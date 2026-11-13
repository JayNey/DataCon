"""Business records and transitions for the Supervisor workflow."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
import uuid
from typing import Any
from uuid import UUID

import psycopg
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb

from datacon import jsonutil

REVIEW_WINDOW_HOURS = 24
LEASE_SECONDS = 300


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
            "job_not_found": "JOB_NOT_FOUND",
        }.get(self.status, "REVIEW_ERROR")


def _connect(dsn: str):
    return psycopg.connect(
        dsn, connect_timeout=5, row_factory=dict_row
    )


def _truncate(value: str, limit: int = 2000) -> str:
    return value if len(value) <= limit else value[: limit - 3] + "..."


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
        "(job_id, stage, attempt_no, event_type, reason_code, detail) "
        "VALUES (%s, %s, %s, %s, %s, %s)",
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
            "prepare_deadline_at, review_deadline_at, execute_deadline_at, "
            "approved_at, submitted_at, updated_at "
            "FROM jobs WHERE job_id = %s",
            (job_id,),
        ).fetchone()


def claim_next(dsn: str, worker_id: str, *, lease_seconds: int = LEASE_SECONDS) -> dict | None:
    if not isinstance(worker_id, str) or not worker_id.strip():
        raise StateError("worker_id must be non-empty")
    if type(lease_seconds) is not int or not 1 <= lease_seconds <= 86400:
        raise StateError("lease_seconds is invalid")
    with _connect(dsn) as connection:
        row = connection.execute(
            """
            SELECT job_id, state
            FROM jobs
            WHERE state = 'QUEUED'
               OR (state = 'PREPARING'
                   AND (lease_expires_at IS NULL OR lease_expires_at <= now()))
               OR (workflow_synced = false AND state IN ('AWAITING_REVIEW', 'READY')
                   AND (lease_expires_at IS NULL OR lease_expires_at <= now()))
               OR (workflow_synced = false AND state = 'BLOCKED'
                   AND (lease_expires_at IS NULL OR lease_expires_at <= now())
                   AND EXISTS (SELECT 1 FROM plans p WHERE p.job_id = jobs.job_id))
               OR (state = 'AWAITING_REVIEW'
                   AND review_deadline_at IS NOT NULL
                   AND review_deadline_at <= now()
                   AND (lease_expires_at IS NULL OR lease_expires_at <= now()))
            ORDER BY submitted_at
            FOR UPDATE SKIP LOCKED
            LIMIT 1
            """
        ).fetchone()
        if row is None:
            return None
        updated = connection.execute(
            """
            UPDATE jobs
            SET state = CASE WHEN state = 'QUEUED' THEN 'PREPARING' ELSE state END,
                stage = CASE WHEN state = 'QUEUED' THEN 'prepare' ELSE stage END,
                generation = generation + 1,
                state_version = state_version + 1,
                lease_owner = %s,
                lease_expires_at = now() + make_interval(secs => %s),
                prepare_deadline_at = COALESCE(
                    prepare_deadline_at,
                    now() + ((request->'limits'->>'prepare_seconds')::int
                             * interval '1 second')
                ),
                updated_at = now()
            WHERE job_id = %s
            RETURNING job_id, request, state, stage, reason_code, last_error,
                      state_version, generation, workflow_synced,
                      prepare_deadline_at, review_deadline_at
            """,
            (worker_id, lease_seconds, row["job_id"]),
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
    review_deadline: datetime,
) -> None:
    if review_deadline.tzinfo is None:
        raise StateError("review deadline must be timezone-aware")
    with _connect(dsn) as connection:
        job = connection.execute(
            "SELECT state, generation FROM jobs WHERE job_id = %s FOR UPDATE",
            (job_id,),
        ).fetchone()
        if job is None:
            raise StateError("job does not exist")
        if job["generation"] != generation:
            raise StaleGeneration("execution generation is no longer current")
        existing = connection.execute(
            "SELECT plan_digest FROM plans WHERE job_id = %s", (job_id,)
        ).fetchone()
        if existing is not None:
            if existing["plan_digest"] != plan_digest:
                raise PlanConflict("a different plan is already frozen")
            return
        if job["state"] not in ("PREPARING", "AWAITING_REVIEW"):
            raise StateError(f"cannot freeze a plan while the job is {job['state']}")
        connection.execute(
            "INSERT INTO plans (plan_id, job_id, plan_digest, plan, summary) "
            "VALUES (%s, %s, %s, %s, %s)",
            (uuid.uuid4(), job_id, plan_digest, Jsonb(plan), Jsonb(summary)),
        )
        updated = connection.execute(
            "UPDATE jobs SET state = 'AWAITING_REVIEW', stage = 'review', "
            "review_deadline_at = %s, state_version = state_version + 1, "
            "workflow_synced = false, updated_at = now() "
            "WHERE job_id = %s AND generation = %s "
            "AND state IN ('PREPARING', 'AWAITING_REVIEW') "
            "RETURNING job_id",
            (review_deadline, job_id, generation),
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


def ensure_awaiting_review(
    dsn: str, job_id: UUID, *, generation: int, review_deadline: datetime
) -> None:
    """Reconcile a job that has a frozen plan but is still PREPARING."""
    with _connect(dsn) as connection:
        connection.execute(
            "UPDATE jobs SET state = 'AWAITING_REVIEW', stage = 'review', "
            "review_deadline_at = COALESCE(review_deadline_at, %s), "
            "state_version = state_version + 1, workflow_synced = false, "
            "updated_at = now() "
            "WHERE job_id = %s AND generation = %s AND state = 'PREPARING'",
            (review_deadline, job_id, generation),
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
        updated = connection.execute(
            "UPDATE jobs SET state = %s, stage = 'blocked', reason_code = %s, "
            "last_error = %s, state_version = state_version + 1, "
            "workflow_synced = false, lease_owner = NULL, lease_expires_at = NULL, "
            "updated_at = now() "
            "WHERE job_id = %s AND generation = %s RETURNING job_id",
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
) -> bool:
    if not stage or not step_key:
        raise StateError("attempt requires stage and step_key")
    with _connect(dsn) as connection:
        cursor = connection.execute(
            """
            INSERT INTO attempts
                (attempt_id, job_id, stage, step_key, attempt_no, generation,
                 input_digest, status, result, finished_at)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, now())
            ON CONFLICT (job_id, stage, step_key, attempt_no) DO UPDATE
            SET generation = EXCLUDED.generation,
                input_digest = EXCLUDED.input_digest,
                status = EXCLUDED.status,
                result = EXCLUDED.result,
                finished_at = now()
            WHERE attempts.generation <= EXCLUDED.generation
            """,
            (
                uuid.uuid4(),
                job_id,
                stage,
                step_key,
                attempt_no,
                generation,
                input_digest,
                status,
                Jsonb(result) if result is not None else None,
            ),
        )
        return cursor.rowcount > 0


def finalize_workflow(dsn: str, job_id: UUID, generation: int) -> bool:
    with _connect(dsn) as connection:
        updated = connection.execute(
            "UPDATE jobs SET workflow_synced = true, lease_owner = NULL, "
            "lease_expires_at = NULL, updated_at = now() "
            "WHERE job_id = %s AND generation = %s RETURNING job_id",
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


def record_review(
    dsn: str,
    job_id: UUID,
    *,
    plan_digest: str,
    decision: str,
    reviewer_id: str,
) -> ReviewOutcome:
    if decision not in ("approve", "reject"):
        raise StateError("decision must be approve or reject")
    if not isinstance(reviewer_id, str) or not reviewer_id.strip():
        raise StateError("reviewer_id must be non-empty")
    if len(reviewer_id) > 128:
        raise StateError("reviewer_id is too long")

    with _connect(dsn) as connection:
        job = connection.execute(
            "SELECT state, reason_code, review_deadline_at, generation "
            "FROM jobs WHERE job_id = %s FOR UPDATE",
            (job_id,),
        ).fetchone()
        if job is None:
            return ReviewOutcome("job_not_found", message="job does not exist")
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
            return ReviewOutcome(
                "expired", state=job["state"], message="the review window expired"
            )
        if job["state"] != "AWAITING_REVIEW":
            return ReviewOutcome(
                "invalid_state",
                state=job["state"],
                message=f"job is {job['state']}, not AWAITING_REVIEW",
            )
        if plan is None:
            return ReviewOutcome(
                "invalid_state", state=job["state"], message="no plan is pending"
            )
        if plan_digest != plan["plan_digest"]:
            return ReviewOutcome(
                "plan_mismatch",
                state=job["state"],
                message="plan digest does not match the pending plan",
            )
        expired = connection.execute(
            "SELECT (%s IS NOT NULL AND %s <= now()) AS expired",
            (job["review_deadline_at"], job["review_deadline_at"]),
        ).fetchone()["expired"]
        if expired:
            connection.execute(
                "UPDATE jobs SET state = 'BLOCKED', stage = 'blocked', "
                "reason_code = 'REVIEW_EXPIRED', last_error = %s, "
                "state_version = state_version + 1, workflow_synced = false, "
                "lease_owner = NULL, lease_expires_at = NULL, updated_at = now() "
                "WHERE job_id = %s",
                ("review deadline passed before a decision was recorded", job_id),
            )
            _audit(
                connection,
                job_id,
                "review_expired",
                stage="blocked",
                reason_code="REVIEW_EXPIRED",
                detail={"plan_digest": plan_digest},
            )
            return ReviewOutcome(
                "expired",
                state="BLOCKED",
                message="the review window expired",
            )

        review = connection.execute(
            "INSERT INTO reviews "
            "(review_id, job_id, plan_digest, reviewer_id, decision, "
            "review_deadline_at) "
            "VALUES (%s, %s, %s, %s, %s, %s) "
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
                "reason_code = NULL, last_error = NULL, approved_at = now(), "
                "state_version = state_version + 1, workflow_synced = false, "
                "lease_owner = NULL, lease_expires_at = NULL, updated_at = now() "
                "WHERE job_id = %s AND state = 'AWAITING_REVIEW' RETURNING job_id",
                (job_id,),
            ).fetchone()
        else:
            state = "BLOCKED"
            updated = connection.execute(
                "UPDATE jobs SET state = 'BLOCKED', stage = 'blocked', "
                "reason_code = 'REVIEW_REJECTED', last_error = %s, "
                "state_version = state_version + 1, workflow_synced = false, "
                "lease_owner = NULL, lease_expires_at = NULL, updated_at = now() "
                "WHERE job_id = %s AND state = 'AWAITING_REVIEW' RETURNING job_id",
                ("review rejected by the operator", job_id),
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
    with _connect(dsn) as connection:
        job = connection.execute(
            "SELECT state, generation, review_deadline_at, now() AS db_now "
            "FROM jobs WHERE job_id = %s FOR UPDATE",
            (job_id,),
        ).fetchone()
        if job is None or job["state"] != "AWAITING_REVIEW":
            return False
        if job["generation"] != generation:
            raise StaleGeneration("execution generation is no longer current")
        if (
            job["review_deadline_at"] is None
            or job["review_deadline_at"] > job["db_now"]
        ):
            return False
        connection.execute(
            "UPDATE jobs SET state = 'BLOCKED', stage = 'blocked', "
            "reason_code = 'REVIEW_EXPIRED', last_error = %s, "
            "state_version = state_version + 1, workflow_synced = false, "
            "lease_owner = NULL, lease_expires_at = NULL, updated_at = now() "
            "WHERE job_id = %s AND generation = %s",
            ("review deadline passed before a decision was recorded", job_id, generation),
        )
        _audit(
            connection,
            job_id,
            "review_expired",
            stage="blocked",
            reason_code="REVIEW_EXPIRED",
            detail={"generation": generation},
        )
        return True


def status(dsn: str, job_id: UUID) -> dict[str, Any] | None:
    with _connect(dsn) as connection:
        row = connection.execute(
            """
            SELECT j.job_id, j.state, j.stage, j.reason_code, j.last_error,
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
    return {
        "job_id": str(row["job_id"]),
        "state": row["state"],
        "stage": row["stage"],
        "pending_plan": pending_plan,
        "review_state": review_state,
        "reason_code": row["reason_code"],
        "last_error": row["last_error"],
        "evidence_refs": evidence_refs,
    }

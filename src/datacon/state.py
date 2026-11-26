"""Business records and transitions for the Supervisor workflow."""

from __future__ import annotations

from contextlib import ExitStack, contextmanager
from dataclasses import dataclass
import hashlib
import math
from pathlib import Path, PurePosixPath
import re
import threading
import uuid
from typing import Any, Mapping
from uuid import UUID

import psycopg
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb

from datacon import cases as case_registry
from datacon import contracts
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


@dataclass(frozen=True)
class AdmissionOutcome:
    """The result of one deterministic policy-admission predicate run.

    ``admission`` carries exactly the row shape of the ``admissions`` table
    when the round is admitted; a denied round has no admission row and only
    the ``round_admission_denied`` audit event. ``event_detail`` is the same
    audit detail so callers can persist it through ``_audit`` without
    recomputing any decision input.
    """

    admitted: bool
    reason_code: str | None
    admission: dict[str, Any] | None
    event_type: str | None
    event_detail: dict[str, Any]
    # Persistence-aware callers distinguish an admitted round, a real denial
    # and an idempotent re-entry. The predicate-only path sets admitted/denied;
    # record_admission adds already_admitted without writing a row or event.
    status: str | None = None
    sub_reason: str | None = None


BUDGET_EXHAUSTED = "BUDGET_EXHAUSTED"


@dataclass(frozen=True)
class BudgetDecision:
    """Deterministic answer to "may the next step/round start?"."""

    allowed: bool
    reason_code: str | None
    hard_timeout_seconds: int
    next_round_no: int | None = None
    sub_reason: str | None = None


@dataclass(frozen=True)
class BudgetChargeOutcome:
    """One idempotent charge attempt against the family ledger.

    ``recovered`` returns the existing charge without touching the ledger;
    ``budget_exhausted`` means the start gate refused or the conditional
    update found no affordable balance. ``charge`` is None only when the
    refusal happened before a charge could be written.
    """

    status: str
    reason_code: str | None
    charge: dict[str, Any] | None
    ledger: dict[str, Any]


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
        "prepare_deadline_at, state_version, job_contract_version, "
        "job_kind, round_no, family_id, request "
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
            "job_contract_version, family_id, job_kind, parent_job_id, round_no, "
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
    job_contract_version: int = 1,
) -> dict | None:
    if not isinstance(worker_id, str) or not worker_id.strip():
        raise StateError("worker_id must be non-empty")
    if type(lease_seconds) is not int or not 1 <= lease_seconds <= 86400:
        raise StateError("lease_seconds is invalid")
    if job_contract_version not in (1, 2):
        raise StateError("job_contract_version must be 1 or 2")
    execution_clause = ""
    if execute:
        execution_clause = """
               OR (state = 'READY' AND workflow_synced = true
                   AND (lease_expires_at IS NULL
                        OR lease_expires_at <= clock_timestamp()))
               OR (state IN ('RUNNING', 'ARCHIVING')
                   AND (lease_expires_at IS NULL
                        OR lease_expires_at <= clock_timestamp()))"""
    # v2 claim gating. A family row is only claimable to synchronize a BLOCKED
    # family; AGGREGATING/COMPLETED families must never be handed to a worker.
    # A non-BLOCKED child may only run while its parent family is AGGREGATING,
    # so a family rejected into BLOCKED cannot have a READY child promoted to
    # RUNNING. BLOCKED children stay claimable even under a BLOCKED/COMPLETED
    # family so recovery can sync them and drain the rollback gate.
    v2_parent_gate = ""
    if job_contract_version == 2:
        v2_parent_gate = """
              AND (
                  (job_kind = 'family'
                   AND state = 'BLOCKED'
                   AND workflow_synced = false)
                  OR (job_kind IN ('campaign', 'round')
                      AND (
                          state = 'BLOCKED'
                          OR (
                              EXISTS (
                                  SELECT 1 FROM jobs parent_job
                                  WHERE parent_job.job_id = jobs.parent_job_id
                                    AND parent_job.job_contract_version = 2
                                    AND parent_job.job_kind = 'family'
                                    AND parent_job.state = 'AGGREGATING'
                              )
                              AND NOT (
                                  state = 'READY'
                                  AND workflow_synced = true
                                  AND EXISTS (
                                      SELECT 1 FROM family_envelopes pending_env
                                      WHERE pending_env.family_id = jobs.parent_job_id
                                        AND pending_env.status = 'pending'
                                  )
                              )
                              AND NOT (
                                  state = 'READY'
                                  AND workflow_synced = true
                                  AND job_kind = 'round'
                                  AND (
                                      round_no > 1
                                      OR EXISTS (
                                          SELECT 1 FROM jobs mode_parent
                                          WHERE mode_parent.job_id = jobs.parent_job_id
                                            AND COALESCE(
                                                mode_parent.request->'exploration'->>'mode',
                                                'fixed'
                                            ) = 'guided'
                                      )
                                  )
                                  AND NOT EXISTS (
                                      SELECT 1 FROM admissions a
                                      WHERE a.parent_job_id = jobs.parent_job_id
                                        AND a.round_no = jobs.round_no
                                        AND a.job_id = jobs.job_id
                                        AND a.approval_kind = 'policy'
                                  )
                              )
                          )
                      ))
              )"""
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
            WHERE job_contract_version = %s
              AND (state = 'QUEUED'
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
               {execution_clause})
               {v2_parent_gate}
            ORDER BY submitted_at
            FOR UPDATE SKIP LOCKED
            LIMIT 1
            """,
            (job_contract_version,),
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
    envelope: Mapping[str, Any] | None = None,
) -> bool:
    """Freeze one plan unless the database clock says preparation expired.

    The review window is computed from the database clock inside this
    transaction, so a skewed worker process clock cannot lengthen or shorten
    the 24 hour window. The prepare deadline is re-checked after locking the
    job, which closes the window between the caller's last check and the plan
    write.

    The contract-level plan validator cannot distinguish guided from fixed:
    both modes share the plan body shape and only the request carries the
    exploration mode. This layer therefore owns the mode-sensitive rule from
    interface-contract-delta §3/§9.1: only the first v2 plan (guided campaign
    or fixed ``round_no=1``) may carry ``parent_approval_digest=null``. Every
    later v2 plan must reference a non-null parent approval. In particular a
    guided ``round_no=1`` is a later plan because the guided campaign was the
    first plan; the pure validator would otherwise accept it as a fixed first
    round.
    """
    with _connect(dsn) as connection:
        # Lock order for every v2 path that touches both a family and its
        # first child is fixed: family -> child (interface-contract-delta
        # §9.1). The identity read is lock-free because family_id/job_kind/
        # round_no are immutable for the row's lifetime; the child's
        # generation/lease are re-validated after the family lock below.
        identity = connection.execute(
            "SELECT job_contract_version, job_kind, round_no, family_id "
            "FROM jobs WHERE job_id = %s",
            (job_id,),
        ).fetchone()
        if identity is None:
            raise StateError("job does not exist")
        if identity["job_contract_version"] == 2:
            if identity.get("job_kind") not in ("campaign", "round"):
                raise StateError(
                    "only a v2 campaign or round child may freeze a plan"
                )
            family_id = identity.get("family_id")
            if family_id is None:
                raise StateError("a v2 child requires a family")
            family = connection.execute(
                "SELECT job_id, job_kind, job_contract_version, state "
                "FROM jobs WHERE job_id = %s FOR UPDATE",
                (family_id,),
            ).fetchone()
            if family is None:
                raise StateError("the child family does not exist")
            if (
                family["job_contract_version"] != 2
                or family["job_kind"] != "family"
            ):
                raise StateError("the child parent is not a v2 family")
            if family["state"] != "AGGREGATING":
                raise StateError(
                    f"cannot freeze a plan while the family is {family['state']}"
                )
        job = _locked_job(connection, job_id, generation=generation)
        existing = connection.execute(
            "SELECT plan_digest FROM plans WHERE job_id = %s", (job_id,)
        ).fetchone()
        if existing is not None:
            if existing["plan_digest"] != plan_digest:
                raise PlanConflict("a different plan is already frozen")
            return True
        first_v2_plan = False
        if job["job_contract_version"] == 2:
            # A v2 plan carries its own identity. The database CHECK proves the
            # job row, but it cannot prove that the plan body the worker hands
            # us names the same family/round. Recompute the digest from the
            # complete Plan v2 body so a caller cannot freeze an arbitrary
            # document under a trusted digest string.
            if job.get("job_kind") not in ("campaign", "round"):
                raise StateError(
                    "only a v2 campaign or round child may freeze a plan"
                )
            if not isinstance(plan, Mapping):
                raise StateError("plan must be a JSON object")
            if plan.get("schema_version") != 2:
                raise StateError(
                    "a v2 job requires a plan with schema_version=2"
                )
            family_id_text = str(job.get("family_id"))
            if family_id_text != str(identity.get("family_id")):
                raise StateError("the child family changed while freezing")
            if (
                plan.get("family_id") != family_id_text
                or plan.get("parent_job_id") != family_id_text
            ):
                raise StateError(
                    "plan family_id/parent_job_id do not match the job family"
                )
            if plan.get("round_no") != job.get("round_no"):
                raise StateError(
                    "plan round_no does not match the job round_no"
                )
            try:
                computed_plan_digest = contracts.plan_digest(plan)
            except (TypeError, ValueError) as error:
                raise StateError(f"plan is invalid: {error}") from error
            if computed_plan_digest != plan_digest:
                raise StateError("plan_digest does not match the plan body")
            exploration = _request_exploration(job.get("request")) or {}
            mode = exploration.get("mode", "fixed")
            if mode not in ("fixed", "guided"):
                raise StateError("exploration.mode is invalid")
            # Guided's first plan is the campaign; only fixed has a first
            # round plan. A guided round 1 is therefore a later plan and does
            # not open a review window or require an envelope.
            first_v2_plan = job.get("job_kind") == "campaign" or (
                job.get("job_kind") == "round"
                and job.get("round_no") == 1
                and mode == "fixed"
            )
            if (
                job.get("job_kind") == "round"
                and job.get("round_no") == 1
                and mode == "fixed"
                and plan.get("parent_approval_digest") is not None
            ):
                # The pure plan validator cannot see the mode; the fixed
                # first plan is the one shape that must never carry a parent
                # approval.
                raise StateError(
                    "a fixed first plan must have parent_approval_digest=null"
                )
            if not first_v2_plan:
                parent_approval_digest = plan.get("parent_approval_digest")
                if parent_approval_digest is None:
                    # A guided round 1 is a later plan even though its round_no is
                    # 1: the guided campaign was the first plan. Rejecting the
                    # null before any write keeps a frozen-but-unreviewed plan
                    # from sitting outside the approval chain.
                    raise StateError(
                        "a non-first v2 plan requires a non-null "
                        "parent_approval_digest"
                    )
                # The family row is already locked FOR UPDATE above, so the
                # approval chain tail cannot move while this check runs.
                # first_plan_digest is intentionally not re-checked here: every
                # family_approvals row is written by record_review against the
                # family's first plan and the column is otherwise immutable,
                # so the tail cannot name a different plan than the chain
                # root. The plan body is still bound to the family/round above.
                tails = connection.execute(
                    "SELECT prior.approval_digest, prior.envelope_digest "
                    "FROM family_approvals AS prior "
                    "WHERE prior.family_id = %s AND NOT EXISTS ("
                    "SELECT 1 FROM family_approvals AS later "
                    "WHERE later.supersedes = prior.approval_id)",
                    (job["family_id"],),
                ).fetchall()
                if len(tails) != 1:
                    raise StateError(
                        "a non-first v2 plan requires a single "
                        "family_approvals chain tail"
                    )
                tail = tails[0]
                if parent_approval_digest != tail["approval_digest"]:
                    raise StateError(
                        "plan parent_approval_digest does not match the "
                        "family_approvals chain tail"
                    )
                if plan.get("envelope_digest") != tail["envelope_digest"]:
                    raise StateError(
                        "plan envelope_digest does not match the "
                        "family_approvals chain tail"
                    )
        normalized_envelope: dict[str, Any] | None = None
        if first_v2_plan:
            if envelope is None:
                raise StateError(
                    "a v2 first plan requires the reviewed envelope body"
                )
            try:
                normalized_envelope = _validate_envelope(envelope)
            except ValueError as error:
                raise StateError(f"envelope is invalid: {error}") from error
            if (
                normalized_envelope["admission_predicate_version"]
                not in SUPPORTED_ADMISSION_PREDICATE_VERSIONS
            ):
                raise StateError(
                    "unsupported admission_predicate_version: "
                    f"{normalized_envelope['admission_predicate_version']}"
                )
            if jsonutil.digest_json(normalized_envelope) != plan.get(
                "envelope_digest"
            ):
                raise StateError(
                    "envelope body does not match the plan envelope_digest"
                )
            # The first envelope is an approval boundary just like a
            # propose-envelope body: it may tighten, never widen, the request
            # and the registered case ceilings. Without these two checks a
            # worker could freeze the first plan with an envelope the operator
            # never authorized.
            _assert_envelope_not_expanded(normalized_envelope, job["request"])
            _assert_envelope_within_case_registry(
                normalized_envelope, job["request"]
            )
        elif envelope is not None:
            raise StateError("only the first plan may freeze an envelope")
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
        if job["job_contract_version"] == 2 and not first_v2_plan:
            # A later v2 plan is admitted by the T12 policy path, not by a
            # human review. It must not enter AWAITING_REVIEW or write a
            # review_deadline_at; only the frozen row is recorded here.
            _audit(
                connection,
                job_id,
                "plan_frozen",
                stage="prepare",
                detail={"plan_digest": plan_digest, "generation": generation},
            )
            return True
        updated = connection.execute(
            "UPDATE jobs SET state = 'AWAITING_REVIEW', stage = 'review', "
            "review_deadline_at = clock_timestamp() + make_interval(hours => %s), "
            "state_version = state_version + 1, "
            "workflow_synced = false, updated_at = clock_timestamp() "
            "WHERE job_id = %s AND generation = %s "
            "AND state IN ('PREPARING', 'AWAITING_REVIEW') "
            "AND lease_expires_at IS NOT NULL "
            "AND lease_expires_at > clock_timestamp() "
            "RETURNING job_id, review_deadline_at",
            (REVIEW_WINDOW_HOURS, job_id, generation),
        ).fetchone()
        if updated is None:
            raise StaleGeneration("job changed while freezing the plan")
        if normalized_envelope is not None:
            # The first approved envelope is inserted in the same transaction
            # as the first plan. Its deadline is the child's review deadline,
            # so a worker timeout and the envelope sweep agree on one window.
            connection.execute(
                "INSERT INTO family_envelopes "
                "(envelope_id, family_id, envelope_digest, envelope_json, "
                "status, review_deadline_at) "
                "VALUES (%s, %s, %s, %s, 'pending', %s)",
                (
                    uuid.uuid4(),
                    job["family_id"],
                    plan["envelope_digest"],
                    Jsonb(normalized_envelope),
                    updated["review_deadline_at"],
                ),
            )
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
    dsn: str, pending: list[tuple[UUID, str, str]]
) -> None:
    """Archive every just-committed BLOCKED transition (best effort).

    The callback runs from ``ExitStack`` after the database context manager has
    committed. Filesystem/verification errors are turned into
    FAILED/EVIDENCE_WRITE_FAILED by ``record_blocked``; a control-plane
    database error is propagated rather than hidden behind a successful review
    response. A v2 review rejection/expiry blocks both the family and its first
    child, so each row gets its own blocked bundle instead of being left with a
    NULL evidence pointer.
    """
    if not pending:
        return
    # Imported lazily: execution imports state at module load time, so a
    # module-level import here would be circular.
    from datacon import execution

    for job_id, reason_code, message in pending:
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
        identity = connection.execute(
            "SELECT job_contract_version, job_kind, family_id, round_no "
            "FROM jobs WHERE job_id = %s",
            (job_id,),
        ).fetchone()
        if identity is None:
            raise StateError("job does not exist")
        is_v2_child = (
            identity["job_contract_version"] == 2
            and identity["job_kind"] in ("campaign", "round")
        )
        family_id: UUID | None = None
        if is_v2_child:
            family_id = identity["family_id"]
            if family_id is None:
                raise StateError("a v2 child requires a family")
            # Follow the global lock order jobs(family) -> jobs(child).
            # FOR KEY SHARE conflicts with FOR UPDATE held by propose_envelope
            # and record_review, serializing child promotion against pending
            # envelopes and family rejection while allowing concurrent v2
            # children and budget charges to proceed without deadlocks.
            family = connection.execute(
                "SELECT job_id, job_kind, job_contract_version, state, "
                "COALESCE(request->'exploration'->>'mode', 'fixed') "
                "AS exploration_mode "
                "FROM jobs WHERE job_id = %s FOR KEY SHARE",
                (family_id,),
            ).fetchone()
            if family is None:
                raise StateError("the child family does not exist")
            if (
                family["job_contract_version"] != 2
                or family["job_kind"] != "family"
            ):
                raise StateError("the child parent is not a v2 family")
            if family["state"] != "AGGREGATING":
                raise StateError(
                    "cannot start execution while the family is "
                    f"{family['state']}"
                )
        job = _locked_job(connection, job_id, generation=generation)
        if job["state"] == "RUNNING":
            return True
        if is_v2_child:
            pending_envelope = connection.execute(
                "SELECT 1 FROM family_envelopes "
                "WHERE family_id = %s AND status = 'pending' LIMIT 1",
                (family_id,),
            ).fetchone()
            if pending_envelope is not None:
                raise StateError(
                    "cannot start execution while a family envelope "
                    "re-approval is pending"
                )
        if job["state"] != "READY":
            raise StateError(f"cannot start execution while the job is {job['state']}")
        if (
            is_v2_child
            and job["job_kind"] == "round"
            and (
                family["exploration_mode"] == "guided"
                or (job["round_no"] or 0) > 1
            )
        ):
            # A non-first round (guided rounds, or fixed rounds after the
            # first) is policy-admitted, never human-approved: it may only
            # run once its admissions row is persisted. Lock order stays
            # jobs(family) -> jobs(child) -> admissions; this is a plain read.
            admitted = connection.execute(
                "SELECT 1 FROM admissions "
                "WHERE parent_job_id = %s AND round_no = %s "
                "AND job_id = %s AND approval_kind = 'policy'",
                (family_id, job["round_no"], job_id),
            ).fetchone()
            if admitted is None:
                raise StateError(
                    "cannot start execution of a round that has not been "
                    "policy-admitted (no admissions row)"
                )
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
    if state == "COMPLETED":
        # D40: COMPLETED is the v2 campaign/round search terminal, not a
        # verdict. It must carry the archived pointer pair and nothing else.
        if evidence_status != "archived" or not evidence_path or not evidence_digest:
            raise StateError(
                "COMPLETED requires archived evidence_path and evidence_digest"
            )
        if verdict is not None or verdict_reason is not None or reason_code is not None:
            raise StateError(
                "COMPLETED requires a null verdict, verdict_reason and reason_code"
            )
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
        if state == "COMPLETED":
            if job["job_contract_version"] != 2:
                raise StateError("COMPLETED is only valid for a v2 job")
            # TODO(T11): the spec wording is "child job (including campaign
            # child) lands COMPLETED" (README invariant / tasks.md T10-T11),
            # while this implementation deliberately narrows it to the
            # campaign child. A fixed/guided round currently always produces a
            # verdict, so no round child needs a verdict-less COMPLETED today.
            # If T11 needs one, widen this together with claim_next/drain and
            # finish_execution and add the matching tests; do not relax it to
            # "any child" on an assumption.
            if job.get("job_kind") != "campaign":
                raise StateError(
                    "COMPLETED is only valid for a v2 campaign child; "
                    "a family converges through complete_family"
                )
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


_FAMILY_EVIDENCE_DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
# T12 will read and export this pointer. Bound its length and reject lexical
# traversal now so a path can never escape the intended evidence root when the
# read lands.
MAX_FAMILY_EVIDENCE_PATH = 4096


def _validate_family_evidence_pointer(
    evidence_path: Any, evidence_digest: Any
) -> None:
    """Validate the lightweight ``family.json`` pointer written by T10.

    This is intentionally syntax-only. T12 owns reading ``family.json``,
    recomputing its content digest and producing the exports; T10 must not
    inspect the file here. That later read is why a lexical path traversal
    (``..``), a non-canonical spelling or an unbounded path is rejected now:
    the pointer is persisted and handed to T12, so a bad value must never
    become trusted input.
    """
    if not isinstance(evidence_path, str) or not evidence_path.strip():
        raise StateError("completing a family requires evidence_path")
    if evidence_path.startswith("//"):
        raise StateError("family evidence_path must not start with '//'")
    if "\x00" in evidence_path or any(
        ord(ch) < 0x20 or ord(ch) == 0x7F for ch in evidence_path
    ):
        raise StateError(
            "family evidence_path must not contain control or NUL characters"
        )
    if "\\" in evidence_path:
        raise StateError("family evidence_path must use POSIX separators")
    if len(evidence_path) > MAX_FAMILY_EVIDENCE_PATH:
        raise StateError(
            "family evidence_path must be at most "
            f"{MAX_FAMILY_EVIDENCE_PATH} characters"
        )
    candidate = PurePosixPath(evidence_path)
    if not candidate.is_absolute():
        raise StateError("family evidence_path must be an absolute POSIX path")
    if ".." in candidate.parts:
        raise StateError("family evidence_path must not contain '..'")
    if str(candidate) != evidence_path:
        raise StateError("family evidence_path must be canonical")
    if candidate.name != "family.json":
        raise StateError("family evidence_path basename must be family.json")
    if not isinstance(evidence_digest, str) or not _FAMILY_EVIDENCE_DIGEST.fullmatch(
        evidence_digest
    ):
        raise StateError("family evidence_digest must be a sha256 digest")


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

    The pointer is validated syntactically only. Reading ``family.json``,
    recomputing its digest and exporting the family index belongs to T12; this
    path must never open the file or trust its bytes.

    T10 only provides the "has at least one child and every child is terminal"
    convergence interface. A childless family, its convergence conditions and
    any family-level archive/export are owned by T11 (graph/rounds) and T12
    (family export); this function deliberately keeps rejecting a childless
    family until those tasks define the semantics.
    """
    _validate_family_evidence_pointer(evidence_path, evidence_digest)
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
        has_child = connection.execute(
            "SELECT 1 FROM jobs WHERE parent_job_id = %s LIMIT 1",
            (family_id,),
        ).fetchone()
        if has_child is None:
            raise StateError("family has no children")
        pending_envelope = connection.execute(
            "SELECT 1 FROM family_envelopes "
            "WHERE family_id = %s AND status = 'pending' LIMIT 1",
            (family_id,),
        ).fetchone()
        if pending_envelope is not None:
            raise StateError("family has a pending envelope")
        # The family aggregate is only complete when every child reached a
        # terminal state and any BLOCKED child has already been synced by the
        # worker/recovery path. An unsynced BLOCKED child would otherwise stay
        # in the rollback drain set forever. AWAITING_REVIEW, READY, RUNNING
        # and the rest are not terminal either. The family row lock is held,
        # but a concurrent child INSERT is only safe because migration 013
        # re-checks the parent state after waiting on this lock.
        blocking_child = connection.execute(
            "SELECT 1 FROM jobs "
            "WHERE parent_job_id = %s "
            "AND (state NOT IN ('COMPLETED', 'REPRODUCED', 'NOT_REPRODUCED', "
            "'INCONCLUSIVE', 'BLOCKED', 'FAILED') "
            "OR (state = 'BLOCKED' AND workflow_synced = false)) "
            "LIMIT 1",
            (family_id,),
        ).fetchone()
        if blocking_child is not None:
            raise StateError("family has non-terminal children")
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
        _audit(
            connection,
            family_id,
            "family_completed",
            stage="done",
            detail={
                "evidence_path": evidence_path,
                "evidence_digest": evidence_digest,
            },
        )
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


# A fixed-mode envelope is the degenerate authorization: it can never widen
# into guided and its mutation surface is empty. The envelope body is closed:
# every field documented in interface-contract-delta §2 is required and any
# other field is rejected, because envelope_digest commits to these exact bytes.
def _envelope_signature_set(value: Any) -> list[dict[str, Any]]:
    return contracts._envelope_signature_set(value)


def _validate_envelope(envelope: Any) -> dict[str, Any]:
    """Validate and normalize one proposed exploration envelope.

    Delegates directly to ``contracts.normalize_envelope`` so plan freezing,
    envelope proposals and policy admission share one validation boundary.
    """
    return contracts.normalize_envelope(envelope)


def _request_exploration(request: Any) -> dict[str, Any] | None:
    if not isinstance(request, dict):
        return None
    exploration = request.get("exploration")
    if not isinstance(exploration, dict):
        return None
    return exploration


def _original_mutation_limits(
    request: Any, exploration: dict[str, Any] | None
) -> tuple[set[str] | None, int | None]:
    """Return the request's mutation ops and max input bytes when declared.

    Request v2 does not expose mutation_limits publicly, but a persisted row may
    carry one from an earlier gate. Both the documented exploration nesting and
    a top-level block are honored so a ceiling can never be silently bypassed.
    Independent declarations are intersected (ops) or minimized (max input
    bytes); malformed declarations fail closed to the empty surface / zero.
    """
    candidates: list[Any] = []
    if isinstance(exploration, dict):
        nested = exploration.get("mutation_limits")
        if isinstance(nested, dict):
            candidates.append(nested)
    if isinstance(request, dict):
        top_level = request.get("mutation_limits")
        if isinstance(top_level, dict):
            candidates.append(top_level)
    ops_floor: set[str] | None = None
    input_floor: int | None = None
    for candidate in candidates:
        ops = candidate.get("allowed_ops")
        if isinstance(ops, list):
            declared = {op for op in ops if isinstance(op, str)}
            ops_floor = declared if ops_floor is None else ops_floor & declared
        elif ops is not None:
            ops_floor = set() if ops_floor is None else ops_floor & set()
        max_input_bytes = candidate.get("max_input_bytes")
        if type(max_input_bytes) is int and max_input_bytes >= 0:
            input_floor = (
                max_input_bytes
                if input_floor is None
                else min(input_floor, max_input_bytes)
            )
        elif max_input_bytes is not None:
            input_floor = 0 if input_floor is None else min(input_floor, 0)
    return ops_floor, input_floor


def _request_execute_seconds(request: Any) -> int:
    """Return the request's fixed-family total-seconds ceiling.

    A request without exploration is a fixed family whose default total budget
    is the execute budget. Missing limits fall back to the contract default;
    an explicitly malformed or non-positive value fails closed instead of
    silently becoming unlimited.
    """
    default = contracts.DEFAULT_LIMITS["execute_seconds"]
    if not isinstance(request, dict):
        return default
    limits = request.get("limits")
    if limits is None:
        return default
    if not isinstance(limits, dict):
        raise StateError("request.limits must be a JSON object")
    execute_seconds = limits.get("execute_seconds")
    if execute_seconds is None:
        return default
    if type(execute_seconds) is not int or execute_seconds < 1:
        raise StateError(
            "request.limits.execute_seconds must be a positive integer"
        )
    return execute_seconds


def _assert_envelope_within_case_registry(
    envelope: dict[str, Any], request: Any
) -> None:
    """Reject an envelope that widens the registered case ceilings.

    The request is only the operator's intent. The case registry is the source
    of truth for the approved signature set, mutation surface and family
    budget, so a widened envelope must fail even when the request allows it.
    """
    target = request.get("target") if isinstance(request, Mapping) else None
    case_id = target.get("case_id") if isinstance(target, Mapping) else None
    if not isinstance(case_id, str) or not case_id:
        raise StateError("family request does not name a registered case")
    try:
        ceilings = case_registry.load_registry().exploration_ceilings(case_id)
    except case_registry.CaseConfigurationError as error:
        raise StateError(
            f"case registry ceilings are unavailable: {error.message}"
        ) from error

    families = ceilings.get("allowed_mutation_families")
    if isinstance(families, list):
        allowed_families = {
            family for family in families if isinstance(family, str)
        }
        widened_families = sorted(
            set(envelope["allowed_mutation_families"]) - allowed_families
        )
        if widened_families:
            raise StateError(
                "envelope adds mutation families outside the case registry: "
                + ", ".join(widened_families)
            )

    limits = ceilings.get("mutation_limits")
    if isinstance(limits, dict):
        allowed_ops = limits.get("allowed_ops")
        if isinstance(allowed_ops, list):
            ops = {op for op in allowed_ops if isinstance(op, str)}
            widened_ops = sorted(
                set(envelope["mutation_limits"]["allowed_ops"]) - ops
            )
            if widened_ops:
                raise StateError(
                    "envelope adds mutation ops outside the case registry: "
                    + ", ".join(widened_ops)
                )
        max_input_bytes = limits.get("max_input_bytes")
        if (
            type(max_input_bytes) is int
            and envelope["mutation_limits"]["max_input_bytes"] > max_input_bytes
        ):
            raise StateError(
                "envelope.mutation_limits.max_input_bytes exceeds the case registry"
            )

    signatures = ceilings.get("accepted_signature_set")
    if signatures is not None:
        try:
            allowed_signatures = _envelope_signature_set(signatures)
        except ValueError as error:
            raise StateError(
                f"case registry accepted_signature_set is invalid: {error}"
            ) from error
        for signature in envelope["accepted_signature_set"]:
            if signature not in allowed_signatures:
                raise StateError(
                    "envelope adds an accepted signature outside the case registry"
                )

    for field in ("max_rounds", "max_total_seconds", "max_fuzz_seconds"):
        ceiling = ceilings.get(field)
        if type(ceiling) is int and envelope[field] > ceiling:
            raise StateError(
                f"envelope.{field} {envelope[field]} exceeds the case registry "
                f"ceiling {ceiling}"
            )


def _assert_envelope_not_expanded(
    envelope: dict[str, Any], request: Any
) -> None:
    """Reject a proposed envelope that widens the family's request ceilings.

    A request without exploration is a fixed family: only a fixed envelope is
    acceptable, and its total budget defaults to the request's
    ``limits.execute_seconds``. A guided request may tighten any budget, family
    or op set, but never widen one, and a fixed request can never be re-opened
    as guided. T10 checks the persisted request and the registered case
    ceilings together; the request is not the only gate.
    """
    exploration = _request_exploration(request)
    if exploration is None:
        if envelope["mode"] != "fixed":
            raise StateError(
                "a request without exploration only accepts a fixed envelope"
            )
        # Omitting exploration means the fixed defaults, not "no ceiling".
        original_ceilings = {
            "max_rounds": 1,
            "max_total_seconds": _request_execute_seconds(request),
            "max_fuzz_seconds": 0,
        }
        original_families: set[str] = set()
    else:
        original_mode = exploration.get("mode", "fixed")
        if original_mode == "fixed" and envelope["mode"] == "guided":
            raise StateError(
                "a fixed family cannot be re-opened as a guided envelope"
            )
        # Missing request ceilings are treated conservatively as their fixed
        # defaults rather than as "unlimited": an absent ceiling cannot widen.
        ceiling_defaults = {
            "max_rounds": 1,
            "max_total_seconds": 0,
            "max_fuzz_seconds": 0,
        }
        original_ceilings = {}
        for field, default in ceiling_defaults.items():
            original = exploration.get(field, default)
            if type(original) is not int:
                original = default
            original_ceilings[field] = original
        families = exploration.get("allowed_mutation_families")
        original_families = (
            {family for family in families if isinstance(family, str)}
            if isinstance(families, list)
            else set()
        )

    for field, original in original_ceilings.items():
        if envelope[field] > original:
            raise StateError(
                f"envelope.{field} {envelope[field]} exceeds the request "
                f"ceiling {original}"
            )

    widened_families = sorted(
        set(envelope["allowed_mutation_families"]) - original_families
    )
    if widened_families:
        raise StateError(
            "envelope adds mutation families outside the request: "
            + ", ".join(widened_families)
        )

    original_ops, original_max_input_bytes = _original_mutation_limits(
        request, exploration
    )
    if original_ops is not None:
        widened_ops = sorted(
            set(envelope["mutation_limits"]["allowed_ops"]) - original_ops
        )
        if widened_ops:
            raise StateError(
                "envelope adds mutation ops outside the request: "
                + ", ".join(widened_ops)
            )
    if (
        original_max_input_bytes is not None
        and envelope["mutation_limits"]["max_input_bytes"] > original_max_input_bytes
    ):
        raise StateError(
            "envelope.mutation_limits.max_input_bytes "
            f"{envelope['mutation_limits']['max_input_bytes']} exceeds the "
            f"request ceiling {original_max_input_bytes}"
        )


_ADMISSION_BINDING_UNSET = object()
SUPPORTED_ADMISSION_PREDICATE_VERSIONS = frozenset({"admission-v1"})
_TERMINAL_JOB_STATES = frozenset(
    {
        "COMPLETED",
        "FAILED",
        "BLOCKED",
        "REPRODUCED",
        "NOT_REPRODUCED",
        "INCONCLUSIVE",
    }
)


def propose_envelope(
    dsn: str,
    family_id: UUID,
    envelope: Any,
    *,
    operator_id: str | None = None,
) -> dict[str, Any]:
    """Create one pending family envelope for a changed-envelope re-approval.

    The family row lock serializes proposals against reviews: a pending row can
    never be superseded concurrently, and the partial unique index is the
    database backstop for "one pending envelope per family". The digest is the
    canonical SHA-256 of the exact validated body, so re-proposing the same body
    is rejected by ``family_envelopes_digest_unique``.
    """
    try:
        normalized = _validate_envelope(envelope)
    except ValueError as error:
        raise StateError(str(error)) from error
    if (
        normalized["admission_predicate_version"]
        not in SUPPORTED_ADMISSION_PREDICATE_VERSIONS
    ):
        raise StateError(
            "unsupported admission_predicate_version: "
            f"{normalized['admission_predicate_version']}"
        )

    if operator_id is not None:
        try:
            operator_id = jsonutil.require_text(operator_id, "operator_id")
        except ValueError as error:
            raise StateError(str(error)) from error
        if len(operator_id) > 128:
            raise StateError("operator_id is too long")

    digest = jsonutil.digest_json(normalized)

    with _connect(dsn) as connection:
        job = connection.execute(
            "SELECT state, job_kind, job_contract_version, request "
            "FROM jobs WHERE job_id = %s FOR UPDATE",
            (family_id,),
        ).fetchone()
        if job is None:
            raise StateError("family does not exist")
        if job["job_kind"] != "family":
            raise StateError("target job is not a family")
        if job["job_contract_version"] != 2:
            raise StateError("target family is not on the v2 job contract")
        if job["state"] != "AGGREGATING":
            raise StateError(
                f"family is {job['state']}, not AGGREGATING"
            )
        # A changed-envelope re-approval only exists after the first plan was
        # approved. Proposing earlier would race the first envelope that
        # freeze_plan inserts and leave the family with two competing pending
        # identities.
        first_approval = connection.execute(
            "SELECT 1 FROM family_approvals WHERE family_id = %s LIMIT 1",
            (family_id,),
        ).fetchone()
        if first_approval is None:
            raise StateError(
                "family has no first approval; propose-envelope is only for "
                "changed-envelope re-approval"
            )

        _assert_envelope_not_expanded(normalized, job["request"])
        _assert_envelope_within_case_registry(normalized, job["request"])

        # Follow the global lock order jobs(family) -> jobs(child) ->
        # budget_ledger(family). Share-locking READY/RUNNING/ARCHIVING
        # children before locking budget_ledger closes the TOCTOU window with
        # claim_next (which uses FOR UPDATE SKIP LOCKED): if claim_next locked
        # a READY child first we wait and observe its committed RUNNING state;
        # if we lock it first claim_next skips it until our pending envelope
        # commits.
        locked_children = connection.execute(
            "SELECT job_id, state "
            "FROM jobs "
            "WHERE parent_job_id = %s "
            "AND state IN ('READY', 'RUNNING', 'ARCHIVING') "
            "ORDER BY job_id "
            "FOR SHARE",
            (family_id,),
        ).fetchall()

        ledger = connection.execute(
            "SELECT max_total_seconds, max_fuzz_seconds, "
            "remaining_total_seconds, remaining_fuzz_seconds "
            "FROM budget_ledger WHERE family_id = %s FOR UPDATE",
            (family_id,),
        ).fetchone()
        if ledger is not None:
            totals = connection.execute(
                "SELECT COALESCE(SUM(seconds), 0) AS spent_total, "
                "COALESCE(SUM(fuzz_seconds), 0) AS spent_fuzz "
                "FROM budget_charges WHERE family_id = %s",
                (family_id,),
            ).fetchone()
            spent_total = int(totals["spent_total"])
            spent_fuzz = int(totals["spent_fuzz"])
            if (
                int(ledger["max_total_seconds"])
                - int(ledger["remaining_total_seconds"])
                != spent_total
                or int(ledger["max_fuzz_seconds"])
                - int(ledger["remaining_fuzz_seconds"])
                != spent_fuzz
            ):
                raise StateError(
                    "budget ledger does not reconcile with budget_charges"
                )
            if normalized["max_total_seconds"] < spent_total:
                raise StateError(
                    "envelope.max_total_seconds is below already spent "
                    f"family budget ({spent_total}s)"
                )
            if normalized["max_fuzz_seconds"] < spent_fuzz:
                raise StateError(
                    "envelope.max_fuzz_seconds is below already spent "
                    f"family fuzz budget ({spent_fuzz}s)"
                )
            if (
                normalized["max_total_seconds"]
                < int(ledger["max_total_seconds"])
                or normalized["max_fuzz_seconds"]
                < int(ledger["max_fuzz_seconds"])
            ):
                if any(
                    child["state"] in ("RUNNING", "ARCHIVING")
                    for child in locked_children
                ):
                    raise StateError(
                        "cannot tighten family budget while a child job is "
                        "RUNNING or ARCHIVING"
                    )

        try:
            inserted = connection.execute(
                "INSERT INTO family_envelopes "
                "(envelope_id, family_id, envelope_digest, envelope_json, "
                "status, review_deadline_at) "
                "VALUES (%s, %s, %s, %s, 'pending', "
                f"clock_timestamp() + interval '{REVIEW_WINDOW_HOURS} hours') "
                "RETURNING review_deadline_at",
                (uuid.uuid4(), family_id, digest, Jsonb(normalized)),
            ).fetchone()
        except psycopg.errors.UniqueViolation as error:
            constraint = getattr(error.diag, "constraint_name", None)
            if constraint == "family_envelopes_one_pending":
                raise StateError("a pending envelope already exists") from error
            if constraint == "family_envelopes_digest_unique":
                raise StateError("this envelope was already proposed") from error
            raise

        _audit(
            connection,
            family_id,
            "envelope_proposed",
            stage="review",
            detail={
                "operator_id": operator_id,
                "envelope_digest": digest,
                "mode": normalized["mode"],
                "max_rounds": normalized["max_rounds"],
                "max_total_seconds": normalized["max_total_seconds"],
                "max_fuzz_seconds": normalized["max_fuzz_seconds"],
            },
        )
        review_deadline_at = jsonutil.timestamp(inserted["review_deadline_at"])

    return {
        "family_id": str(family_id),
        "envelope_digest": digest,
        "status": "pending",
        "review_deadline_at": review_deadline_at,
    }


_BUDGET_SNAPSHOT_ALLOWED_KEYS = frozenset(
    {
        "remaining_total_seconds",
        "remaining_seconds",
        "remaining_fuzz_seconds",
        "max_total_seconds",
        "max_fuzz_seconds",
        "spent_seconds",
        "spent_fuzz_seconds",
        "family_id",
        "updated_at",
    }
)


def _validate_budget_snapshot(
    budget_snapshot: Mapping[str, Any],
    *,
    expected_family_id: UUID | str | None = None,
    expected_max_total_seconds: int | None = None,
    expected_max_fuzz_seconds: int | None = None,
) -> tuple[int, int | None]:
    """Validate admission budget_snapshot structure and return balances.

    Enforces a closed key set covering standard budget ledger/summary fields,
    strict integer/type/range checks, and cross-field reconciliation. Fails
    closed on unknown keys, missing balances, conflicting total fields,
    out-of-range values, or unreconciled spent + remaining != max equations.
    """
    unknown = set(budget_snapshot) - _BUDGET_SNAPSHOT_ALLOWED_KEYS
    if unknown:
        raise StateError(
            "budget_snapshot has unknown field(s): "
            + ", ".join(sorted(str(key) for key in unknown))
        )
    has_total = "remaining_total_seconds" in budget_snapshot
    has_remaining = "remaining_seconds" in budget_snapshot
    if not has_total and not has_remaining:
        raise StateError(
            "budget_snapshot must include remaining_total_seconds or "
            "remaining_seconds"
        )
    total_value: int | None = None
    remaining_value: int | None = None
    if has_total:
        raw_total = budget_snapshot["remaining_total_seconds"]
        if type(raw_total) is not int or raw_total < 0:
            raise StateError(
                "budget_snapshot.remaining_total_seconds must be a "
                "non-negative integer"
            )
        total_value = raw_total
    if has_remaining:
        raw_remaining = budget_snapshot["remaining_seconds"]
        if type(raw_remaining) is not int or raw_remaining < 0:
            raise StateError(
                "budget_snapshot.remaining_seconds must be a non-negative "
                "integer"
            )
        remaining_value = raw_remaining
    if (
        total_value is not None
        and remaining_value is not None
        and total_value != remaining_value
    ):
        raise StateError(
            "budget_snapshot remaining_total_seconds and remaining_seconds "
            "must be equal"
        )
    available_total = (
        total_value if total_value is not None else remaining_value
    )
    assert available_total is not None

    remaining_fuzz: int | None = None
    if "remaining_fuzz_seconds" in budget_snapshot:
        raw_fuzz = budget_snapshot["remaining_fuzz_seconds"]
        if type(raw_fuzz) is not int or raw_fuzz < 0:
            raise StateError(
                "budget_snapshot.remaining_fuzz_seconds must be a "
                "non-negative integer"
            )
        remaining_fuzz = raw_fuzz

    max_total: int | None = None
    if "max_total_seconds" in budget_snapshot:
        raw_max_total = budget_snapshot["max_total_seconds"]
        if type(raw_max_total) is not int or raw_max_total < 1:
            raise StateError(
                "budget_snapshot.max_total_seconds must be a positive integer"
            )
        max_total = raw_max_total

    max_fuzz: int | None = None
    if "max_fuzz_seconds" in budget_snapshot:
        raw_max_fuzz = budget_snapshot["max_fuzz_seconds"]
        if type(raw_max_fuzz) is not int or raw_max_fuzz < 0:
            raise StateError(
                "budget_snapshot.max_fuzz_seconds must be a non-negative "
                "integer"
            )
        max_fuzz = raw_max_fuzz

    if max_total is not None and max_fuzz is not None and max_fuzz > max_total:
        raise StateError(
            "budget_snapshot.max_fuzz_seconds must not exceed "
            "max_total_seconds"
        )
    if (
        max_total is not None
        and expected_max_total_seconds is not None
        and max_total != expected_max_total_seconds
    ):
        raise StateError(
            "budget_snapshot.max_total_seconds must match envelope "
            "max_total_seconds"
        )
    if (
        max_fuzz is not None
        and expected_max_fuzz_seconds is not None
        and max_fuzz != expected_max_fuzz_seconds
    ):
        raise StateError(
            "budget_snapshot.max_fuzz_seconds must match envelope "
            "max_fuzz_seconds"
        )

    spent_total: int | None = None
    if "spent_seconds" in budget_snapshot:
        raw_spent_total = budget_snapshot["spent_seconds"]
        if type(raw_spent_total) is not int or raw_spent_total < 0:
            raise StateError(
                "budget_snapshot.spent_seconds must be a non-negative integer"
            )
        spent_total = raw_spent_total

    spent_fuzz: int | None = None
    if "spent_fuzz_seconds" in budget_snapshot:
        raw_spent_fuzz = budget_snapshot["spent_fuzz_seconds"]
        if type(raw_spent_fuzz) is not int or raw_spent_fuzz < 0:
            raise StateError(
                "budget_snapshot.spent_fuzz_seconds must be a non-negative "
                "integer"
            )
        spent_fuzz = raw_spent_fuzz

    if (
        spent_total is not None
        and spent_fuzz is not None
        and spent_fuzz > spent_total
    ):
        raise StateError(
            "budget_snapshot.spent_fuzz_seconds must not exceed spent_seconds"
        )

    # Reconcile spent/remaining against the snapshot's own caps, or against
    # the authoritative caps supplied by the caller when the snapshot omits
    # max_* fields; omitting a cap must not bypass the spent + remaining check.
    effective_max_total = (
        max_total if max_total is not None else expected_max_total_seconds
    )
    effective_max_fuzz = (
        max_fuzz if max_fuzz is not None else expected_max_fuzz_seconds
    )

    if effective_max_total is not None:
        if available_total > effective_max_total:
            raise StateError(
                "budget_snapshot remaining total must not exceed "
                "max_total_seconds"
            )
        if (
            spent_total is not None
            and spent_total + available_total != effective_max_total
        ):
            raise StateError(
                "budget_snapshot spent_seconds + remaining total must equal "
                "max_total_seconds"
            )

    if effective_max_fuzz is not None:
        if remaining_fuzz is not None:
            if remaining_fuzz > effective_max_fuzz:
                raise StateError(
                    "budget_snapshot.remaining_fuzz_seconds must not exceed "
                    "max_fuzz_seconds"
                )
            if (
                spent_fuzz is not None
                and spent_fuzz + remaining_fuzz != effective_max_fuzz
            ):
                raise StateError(
                    "budget_snapshot spent_fuzz_seconds + "
                    "remaining_fuzz_seconds must equal max_fuzz_seconds"
                )
        elif spent_fuzz is not None and spent_fuzz > effective_max_fuzz:
            raise StateError(
                "budget_snapshot.spent_fuzz_seconds must not exceed "
                "max_fuzz_seconds"
            )

    if "family_id" in budget_snapshot:
        raw_family_id = budget_snapshot["family_id"]
        if not isinstance(raw_family_id, str):
            raise StateError("budget_snapshot.family_id must be a UUID string")
        try:
            parsed_family_id = uuid.UUID(raw_family_id)
        except ValueError as error:
            raise StateError(
                "budget_snapshot.family_id must be a valid UUID string"
            ) from error
        if expected_family_id is not None:
            expected_uuid = (
                expected_family_id
                if isinstance(expected_family_id, UUID)
                else uuid.UUID(str(expected_family_id))
            )
            if parsed_family_id != expected_uuid:
                raise StateError(
                    "budget_snapshot.family_id does not match the target family"
                )

    if "updated_at" in budget_snapshot:
        try:
            jsonutil.require_rfc3339(
                budget_snapshot["updated_at"], "budget_snapshot.updated_at"
            )
        except ValueError as error:
            raise StateError(str(error)) from error

    return available_total, remaining_fuzz


def policy_admit_round(
    *,
    store: Any = None,
    clock: Any,
    job_id: UUID | str,
    parent_job_id: UUID | str,
    envelope: Mapping[str, Any],
    parent_approval_digest: str | None,
    approval_chain_tail_digest: str | None,
    seed_digest: str,
    round_no: int,
    budget_snapshot: Mapping[str, Any],
    experiment: Mapping[str, Any] | None = None,
    recomputable: bool = True,
    campaign_bundle_digest: str | None = None,
    admission_id: UUID | str | None = None,
    existing_rounds: Any = (),
    approved_envelope_digest: str | None = None,
    plan_parent_approval_digest: Any = _ADMISSION_BINDING_UNSET,
    plan_envelope_digest: Any = _ADMISSION_BINDING_UNSET,
    plan_seed_digest: Any = _ADMISSION_BINDING_UNSET,
    plan_experiment_digest: Any = _ADMISSION_BINDING_UNSET,
    ledger_remaining_total_seconds: int | None = None,
) -> AdmissionOutcome:
    """Decide one policy round and emit exactly one admission audit event.

    The predicate is pure and deterministic: the envelope, parent approval,
    seed, round, budget snapshot and injected clock are its only inputs. It
    never reads or writes ``reviews`` / ``family_approvals``. When ``store`` is
    supplied, an admitted round writes one ``admissions`` row
    (``approval_kind='policy'``) and appends ``round_admitted``; a denied
    round writes no admission row and appends ``round_admission_denied``.
    Round capacity is checked here rather than delegated to the
    ``UNIQUE(parent_job_id, round_no)`` backstop. Optional binding inputs let
    callers pass the persisted approval/plan envelope digests; when supplied,
    the predicate denies an envelope that is not the approved one or not the
    frozen plan's one. Omitting them keeps the historical predicate behavior.
    """
    if not isinstance(envelope, Mapping):
        raise StateError("envelope must be a JSON object")
    try:
        normalized_envelope = contracts.normalize_envelope(envelope)
    except ValueError as error:
        raise StateError(f"envelope is invalid: {error}") from error
    try:
        envelope_digest = contracts.envelope_digest(normalized_envelope)
    except ValueError as error:
        raise StateError(f"envelope is invalid: {error}") from error

    try:
        job_id = str(uuid.UUID(str(job_id)))
        parent_job_id = str(uuid.UUID(str(parent_job_id)))
    except (TypeError, ValueError) as error:
        raise StateError("admission job ids must be UUIDs") from error
    if admission_id is None:
        admission_id = uuid.uuid4()
    else:
        try:
            admission_id = uuid.UUID(str(admission_id))
        except (TypeError, ValueError) as error:
            raise StateError("admission_id must be a UUID") from error

    try:
        seed_digest = jsonutil.require_digest(seed_digest, "seed_digest")
    except ValueError as error:
        raise StateError(str(error)) from error
    if parent_approval_digest is not None:
        try:
            parent_approval_digest = jsonutil.require_digest(
                parent_approval_digest, "parent_approval_digest"
            )
        except ValueError as error:
            raise StateError(str(error)) from error
    if approval_chain_tail_digest is not None:
        try:
            approval_chain_tail_digest = jsonutil.require_digest(
                approval_chain_tail_digest, "approval_chain_tail_digest"
            )
        except ValueError as error:
            raise StateError(str(error)) from error
    if approved_envelope_digest is not None:
        try:
            approved_envelope_digest = jsonutil.require_digest(
                approved_envelope_digest, "approved_envelope_digest"
            )
        except ValueError as error:
            raise StateError(str(error)) from error
    plan_parent_approval_checked = (
        plan_parent_approval_digest is not _ADMISSION_BINDING_UNSET
    )
    if plan_parent_approval_checked and plan_parent_approval_digest is not None:
        try:
            plan_parent_approval_digest = jsonutil.require_digest(
                plan_parent_approval_digest, "plan_parent_approval_digest"
            )
        except ValueError as error:
            raise StateError(str(error)) from error
    plan_envelope_checked = plan_envelope_digest is not _ADMISSION_BINDING_UNSET
    if plan_envelope_checked and plan_envelope_digest is not None:
        try:
            plan_envelope_digest = jsonutil.require_digest(
                plan_envelope_digest, "plan_envelope_digest"
            )
        except ValueError as error:
            raise StateError(str(error)) from error
    plan_seed_checked = plan_seed_digest is not _ADMISSION_BINDING_UNSET
    if plan_seed_checked and plan_seed_digest is not None:
        try:
            plan_seed_digest = jsonutil.require_digest(
                plan_seed_digest, "plan_seed_digest"
            )
        except ValueError as error:
            raise StateError(str(error)) from error
    plan_experiment_checked = (
        plan_experiment_digest is not _ADMISSION_BINDING_UNSET
    )
    if plan_experiment_checked and plan_experiment_digest is not None:
        try:
            plan_experiment_digest = jsonutil.require_digest(
                plan_experiment_digest, "plan_experiment_digest"
            )
        except ValueError as error:
            raise StateError(str(error)) from error
    if campaign_bundle_digest is not None:
        try:
            campaign_bundle_digest = jsonutil.require_digest(
                campaign_bundle_digest, "campaign_bundle_digest"
            )
        except ValueError as error:
            raise StateError(str(error)) from error

    experiment_digest: str | None = None
    if experiment is not None:
        if not isinstance(experiment, Mapping):
            raise StateError("experiment must be a JSON object")
        try:
            experiment_digest = jsonutil.digest_json(dict(experiment))
        except (TypeError, ValueError) as error:
            raise StateError(
                f"experiment must be canonical JSON: {error}"
            ) from error

    if not callable(clock):
        raise StateError("clock must be callable")
    try:
        decided_at_text = jsonutil.timestamp(clock())
    except ValueError as error:
        raise StateError(str(error)) from error

    if not isinstance(budget_snapshot, Mapping):
        raise StateError("budget_snapshot must be a JSON object")
    try:
        budget_snapshot = dict(budget_snapshot)
        budget_snapshot_digest = jsonutil.digest_json(budget_snapshot)
    except (TypeError, ValueError) as error:
        raise StateError(
            f"budget_snapshot must be canonical JSON: {error}"
        ) from error
    if not budget_snapshot:
        raise StateError("budget_snapshot must not be empty")
    # Structural/self-consistency/family binding first. The caller's envelope
    # caps are not yet trusted: an unapproved envelope that changed max_* must
    # surface as a recorded ADMISSION_DENIED, not as a StateError that drops
    # the round_admission_denied audit event.
    snapshot_remaining_total, snapshot_remaining_fuzz = (
        _validate_budget_snapshot(
            budget_snapshot,
            expected_family_id=parent_job_id,
        )
    )
    envelope_is_bound = (
        approved_envelope_digest is None
        or approved_envelope_digest == envelope_digest
    ) and (
        not plan_envelope_checked or plan_envelope_digest == envelope_digest
    )
    if envelope_is_bound:
        if snapshot_remaining_total > normalized_envelope["max_total_seconds"]:
            raise StateError(
                "budget_snapshot remaining total exceeds envelope "
                "max_total_seconds"
            )
        if (
            snapshot_remaining_fuzz is not None
            and snapshot_remaining_fuzz
            > normalized_envelope["max_fuzz_seconds"]
        ):
            raise StateError(
                "budget_snapshot remaining fuzz exceeds envelope "
                "max_fuzz_seconds"
            )
        _validate_budget_snapshot(
            budget_snapshot,
            expected_family_id=parent_job_id,
            expected_max_total_seconds=normalized_envelope["max_total_seconds"],
            expected_max_fuzz_seconds=normalized_envelope["max_fuzz_seconds"],
        )
    if ledger_remaining_total_seconds is not None:
        if (
            type(ledger_remaining_total_seconds) is not int
            or ledger_remaining_total_seconds < 0
        ):
            raise StateError(
                "ledger_remaining_total_seconds must be a non-negative integer"
            )
        available_total = min(
            snapshot_remaining_total, ledger_remaining_total_seconds
        )
    else:
        available_total = snapshot_remaining_total

    if type(recomputable) is not bool:
        raise StateError("recomputable must be a boolean")
    if isinstance(existing_rounds, (str, bytes, Mapping)):
        raise StateError(
            "existing_rounds must be a collection of positive integers"
        )
    try:
        existing_rounds_tuple = tuple(existing_rounds)
    except TypeError as error:
        raise StateError(
            "existing_rounds must be a collection of positive integers"
        ) from error
    for item in existing_rounds_tuple:
        if type(item) is not int or item < 1:
            raise StateError(
                "existing_rounds items must be positive integers"
            )
    admitted_rounds = set(existing_rounds_tuple)

    predicate_version = normalized_envelope["admission_predicate_version"]
    reason_code: str | None = None
    sub_reason: str | None = None
    supporting_bundle_digest: str | None = None

    if normalized_envelope["mode"] == "fixed":
        reason_code = "ENVELOPE_VIOLATION"
        sub_reason = "FIXED_ENVELOPE_HAS_NO_POLICY_ADMISSION"
    elif parent_approval_digest is None:
        reason_code = "ADMISSION_DENIED"
        sub_reason = "PARENT_APPROVAL_MISSING"
    elif (
        approval_chain_tail_digest is None
        or parent_approval_digest != approval_chain_tail_digest
    ):
        reason_code = "ADMISSION_DENIED"
        sub_reason = "PARENT_APPROVAL_NOT_CHAIN_TAIL"
    elif plan_parent_approval_checked and plan_parent_approval_digest is None:
        reason_code = "ADMISSION_DENIED"
        sub_reason = "PLAN_PARENT_APPROVAL_MISSING"
    elif (
        plan_parent_approval_checked
        and plan_parent_approval_digest != approval_chain_tail_digest
    ):
        reason_code = "ADMISSION_DENIED"
        sub_reason = "PARENT_APPROVAL_NOT_CHAIN_TAIL"
    elif (
        approved_envelope_digest is not None
        and approved_envelope_digest != envelope_digest
    ):
        reason_code = "ADMISSION_DENIED"
        sub_reason = "PARENT_APPROVAL_ENVELOPE_MISMATCH"
    elif (
        plan_envelope_checked and plan_envelope_digest != envelope_digest
    ):
        reason_code = "ADMISSION_DENIED"
        sub_reason = "PLAN_ENVELOPE_MISMATCH"
    elif plan_seed_checked and plan_seed_digest != seed_digest:
        reason_code = "ADMISSION_DENIED"
        sub_reason = "PLAN_SEED_MISMATCH"
    elif (
        plan_experiment_checked
        and plan_experiment_digest != experiment_digest
    ):
        reason_code = "ADMISSION_DENIED"
        sub_reason = "PLAN_EXPERIMENT_MISMATCH"
    elif predicate_version not in SUPPORTED_ADMISSION_PREDICATE_VERSIONS:
        reason_code = "ADMISSION_DENIED"
        sub_reason = "UNSUPPORTED_PREDICATE_VERSION"
    elif type(round_no) is not int or round_no < 1:
        reason_code = "ADMISSION_DENIED"
        sub_reason = "INVALID_ROUND_NO"
    elif round_no > normalized_envelope["max_rounds"]:
        reason_code = BUDGET_EXHAUSTED
        sub_reason = "ROUND_BEYOND_MAX_ROUNDS"
    elif round_no in admitted_rounds:
        reason_code = "ADMISSION_DENIED"
        sub_reason = "ROUND_ALREADY_ADMITTED"
    elif available_total < 1:
        reason_code = BUDGET_EXHAUSTED
        sub_reason = BUDGET_EXHAUSTED
    elif not recomputable and campaign_bundle_digest is None:
        reason_code = "ADMISSION_DENIED"
        sub_reason = "SUPPORTING_BUNDLE_MISSING"
    else:
        if experiment is not None:
            try:
                contracts.check_experiment_against_envelope(
                    experiment, normalized_envelope
                )
            except contracts.EnvelopeViolation as error:
                reason_code = "ENVELOPE_VIOLATION"
                sub_reason = str(error)

    if reason_code is None and not recomputable:
        supporting_bundle_digest = campaign_bundle_digest

    detail: dict[str, Any] = {
        "job_id": job_id,
        "parent_job_id": parent_job_id,
        "round_no": round_no,
        "approval_kind": "policy",
        "envelope_digest": envelope_digest,
        "parent_approval_digest": parent_approval_digest,
        "seed_digest": seed_digest,
        "predicate_version": predicate_version,
        "recomputable": recomputable,
        "supporting_bundle_digest": supporting_bundle_digest,
        "budget_snapshot_digest": budget_snapshot_digest,
        "experiment_digest": experiment_digest,
    }
    if sub_reason == "PARENT_APPROVAL_ENVELOPE_MISMATCH":
        detail["expected_envelope_digest"] = approved_envelope_digest
        detail["actual_envelope_digest"] = envelope_digest
    elif sub_reason == "PLAN_ENVELOPE_MISMATCH":
        detail["expected_envelope_digest"] = plan_envelope_digest
        detail["actual_envelope_digest"] = envelope_digest
    elif sub_reason == "PLAN_SEED_MISMATCH":
        detail["expected_seed_digest"] = plan_seed_digest
        detail["actual_seed_digest"] = seed_digest
    elif sub_reason == "PLAN_EXPERIMENT_MISMATCH":
        detail["expected_experiment_digest"] = plan_experiment_digest
        detail["actual_experiment_digest"] = experiment_digest
    elif (
        sub_reason == "PARENT_APPROVAL_NOT_CHAIN_TAIL"
        and plan_parent_approval_checked
        and plan_parent_approval_digest is not None
    ):
        detail["expected_parent_approval_digest"] = approval_chain_tail_digest
        detail["actual_parent_approval_digest"] = plan_parent_approval_digest

    admission: dict[str, Any] | None
    if reason_code is None:
        admission = {
            "admission_id": str(admission_id),
            "job_id": job_id,
            "parent_job_id": parent_job_id,
            "round_no": round_no,
            "approval_kind": "policy",
            "envelope_digest": envelope_digest,
            "parent_approval_digest": parent_approval_digest,
            "seed_digest": seed_digest,
            "predicate_version": predicate_version,
            "recomputable": recomputable,
            "supporting_bundle_digest": supporting_bundle_digest,
            "decided_at": decided_at_text,
        }
        event_type = "round_admitted"
    else:
        admission = None
        event_type = "round_admission_denied"
        detail["reason_code"] = reason_code
        detail["sub_reason"] = sub_reason

    event = {
        "event_type": event_type,
        "job_id": job_id,
        "stage": "admission",
        "reason_code": reason_code,
        "detail": detail,
    }

    if store is not None:
        if admission is not None:
            store.record_admission(admission)
        store.append_event(event)

    return AdmissionOutcome(
        admitted=admission is not None,
        reason_code=reason_code,
        admission=admission,
        event_type=event_type,
        event_detail=detail,
        status="admitted" if admission is not None else "denied",
        sub_reason=sub_reason,
    )


def _family_approval_chain_tail(
    connection, family_id: UUID
) -> tuple[str, str] | None:
    """Return the unique chain-tail approval digest and its envelope digest."""
    rows = connection.execute(
        "SELECT prior.approval_digest, prior.envelope_digest "
        "FROM family_approvals AS prior "
        "WHERE prior.family_id = %s AND NOT EXISTS ("
        "SELECT 1 FROM family_approvals AS later "
        "WHERE later.supersedes = prior.approval_id)",
        (family_id,),
    ).fetchall()
    if not rows:
        return None
    if len(rows) > 1:
        raise StateError("family has multiple family_approvals chain tails")
    return rows[0]["approval_digest"], rows[0]["envelope_digest"]


def _admission_record(row: Mapping[str, Any]) -> dict[str, Any]:
    """Render an ``admissions`` row exactly like the predicate's admission."""
    return {
        "admission_id": str(row["admission_id"]),
        "job_id": str(row["job_id"]),
        "parent_job_id": str(row["parent_job_id"]),
        "round_no": row["round_no"],
        "approval_kind": row["approval_kind"],
        "envelope_digest": row["envelope_digest"],
        "parent_approval_digest": row["parent_approval_digest"],
        "seed_digest": row["seed_digest"],
        "predicate_version": row["predicate_version"],
        "recomputable": row["recomputable"],
        "supporting_bundle_digest": row["supporting_bundle_digest"],
        "decided_at": jsonutil.timestamp(row["decided_at"]),
    }


def _admitted_audit_detail(
    connection, job_id: UUID | str, round_no: int
) -> dict[str, Any] | None:
    """Read the round_admitted detail that carries the budget snapshot digest.

    ``admissions`` has no budget_snapshot_digest column and step 1.5 must not
    add one. The round_admitted event is written in the same transaction as the
    admission row, so it is the persisted half of the idempotency comparison.
    """
    row = connection.execute(
        "SELECT detail FROM audit_events WHERE job_id = %s "
        "AND event_type = 'round_admitted' "
        "AND detail->>'round_no' = %s ORDER BY event_id DESC LIMIT 1",
        (job_id, str(round_no)),
    ).fetchone()
    return dict(row["detail"]) if row is not None and row["detail"] else None


def record_admission(
    dsn: str,
    *,
    family_id: UUID | str,
    job_id: UUID | str,
    round_no: int,
    envelope: Mapping[str, Any],
    seed_digest: str,
    budget_snapshot: Mapping[str, Any],
    experiment: Mapping[str, Any] | None = None,
    recomputable: bool = True,
    campaign_bundle_digest: str | None = None,
) -> AdmissionOutcome:
    """Persist one policy-admission decision with a three-path outcome.

    ``admitted`` writes one ``admissions`` row and one ``round_admitted`` event;
    a predicate denial writes only ``round_admission_denied``; re-entering the
    same decision inputs for the same ``(parent_job_id, round_no)`` is an
    ``already_admitted`` no-op that returns the persisted admission. A different
    decision for that round is a real ``ADMISSION_DENIED`` whose audit detail
    carries ``sub_reason=ROUND_ALREADY_ADMITTED``. The comparison includes the
    budget snapshot digest read from the existing round_admitted detail.
    """
    if not isinstance(envelope, Mapping):
        raise StateError("envelope must be a JSON object")
    try:
        normalized_envelope = contracts.normalize_envelope(envelope)
        envelope_digest = contracts.envelope_digest(normalized_envelope)
        family_id = uuid.UUID(str(family_id))
        job_id = uuid.UUID(str(job_id))
        seed_digest = jsonutil.require_digest(seed_digest, "seed_digest")
    except (TypeError, ValueError) as error:
        raise StateError(str(error)) from error
    if type(round_no) is not int or round_no < 1:
        raise StateError("round_no must be a positive integer")
    if type(recomputable) is not bool:
        raise StateError("recomputable must be a boolean")
    if campaign_bundle_digest is not None:
        try:
            campaign_bundle_digest = jsonutil.require_digest(
                campaign_bundle_digest, "campaign_bundle_digest"
            )
        except ValueError as error:
            raise StateError(str(error)) from error
    experiment_digest: str | None = None
    if experiment is not None:
        if not isinstance(experiment, Mapping):
            raise StateError("experiment must be a JSON object")
        try:
            experiment_digest = jsonutil.digest_json(dict(experiment))
        except (TypeError, ValueError) as error:
            raise StateError(
                f"experiment must be canonical JSON: {error}"
            ) from error
    if not isinstance(budget_snapshot, Mapping):
        raise StateError("budget_snapshot must be a JSON object")
    try:
        budget_snapshot = dict(budget_snapshot)
        budget_snapshot_digest = jsonutil.digest_json(budget_snapshot)
    except (TypeError, ValueError) as error:
        raise StateError(
            f"budget_snapshot must be canonical JSON: {error}"
        ) from error
    if not budget_snapshot:
        raise StateError("budget_snapshot must not be empty")
    # Outside the transaction only validate structure, self-consistency and the
    # family binding: the caller's envelope caps are unverified until the
    # approval chain is read, so they must not reject a genuine ledger snapshot
    # before an unapproved envelope can be denied and audited.
    snapshot_remaining_total, snapshot_remaining_fuzz = (
        _validate_budget_snapshot(
            budget_snapshot,
            expected_family_id=family_id,
        )
    )

    supporting_bundle_digest = (
        None if recomputable else campaign_bundle_digest
    )
    predicate_version = normalized_envelope["admission_predicate_version"]

    with _connect(dsn) as connection:
        with connection.transaction():
            family = connection.execute(
                "SELECT job_id, job_kind, job_contract_version, state "
                "FROM jobs WHERE job_id = %s FOR UPDATE",
                (family_id,),
            ).fetchone()
            if family is None:
                raise StateError("admission family does not exist")
            if (
                family["job_contract_version"] != 2
                or family["job_kind"] != "family"
            ):
                raise StateError("admission target is not a v2 family")
            round_job = connection.execute(
                "SELECT job_id, job_kind, job_contract_version, family_id, "
                "parent_job_id, round_no, state FROM jobs WHERE job_id = %s "
                "FOR UPDATE",
                (job_id,),
            ).fetchone()
            if round_job is None:
                raise StateError("admission round job does not exist")
            if (
                round_job["job_contract_version"] != 2
                or round_job["job_kind"] != "round"
            ):
                raise StateError(
                    "admission job_id must reference a v2 round child"
                )
            if (
                round_job["family_id"] != family_id
                or round_job["parent_job_id"] != family_id
            ):
                raise StateError(
                    "admission job_id does not belong to family_id"
                )
            if round_job["round_no"] != round_no:
                raise StateError(
                    "admission round_no does not match the round job"
                )
            approval_tail_row = _family_approval_chain_tail(
                connection, family_id
            )
            if approval_tail_row is None:
                approval_tail = None
                approved_envelope_digest = None
            else:
                approval_tail, approved_envelope_digest = approval_tail_row
            plan_row = connection.execute(
                "SELECT plan FROM plans WHERE job_id = %s "
                "ORDER BY created_at DESC, plan_id DESC LIMIT 1",
                (job_id,),
            ).fetchone()
            if plan_row is None:
                raise StateError(
                    "admission requires a frozen plan for the round job"
                )
            plan_body = plan_row["plan"]
            if not isinstance(plan_body, Mapping):
                raise StateError("admission plan must be a JSON object")
            if (
                "family_id" not in plan_body
                or not isinstance(plan_body["family_id"], str)
                or plan_body["family_id"] != str(family_id)
            ):
                raise StateError(
                    "admission plan family_id must match family_id"
                )
            if (
                "parent_job_id" not in plan_body
                or not isinstance(plan_body["parent_job_id"], str)
                or plan_body["parent_job_id"] != str(family_id)
            ):
                raise StateError(
                    "admission plan parent_job_id must match family_id"
                )
            if (
                "round_no" not in plan_body
                or type(plan_body["round_no"]) is not int
                or plan_body["round_no"] != round_no
            ):
                raise StateError(
                    "admission plan round_no must match round_no"
                )
            if "envelope_digest" not in plan_body:
                raise StateError("admission plan requires envelope_digest")
            try:
                plan_envelope_digest = jsonutil.require_digest(
                    plan_body["envelope_digest"], "plan.envelope_digest"
                )
            except ValueError as error:
                raise StateError(str(error)) from error
            if "parent_approval_digest" not in plan_body:
                raise StateError(
                    "admission plan requires parent_approval_digest"
                )
            raw_plan_parent_approval = plan_body["parent_approval_digest"]
            if raw_plan_parent_approval is None:
                plan_parent_approval_digest: str | None = None
            else:
                try:
                    plan_parent_approval_digest = jsonutil.require_digest(
                        raw_plan_parent_approval,
                        "plan.parent_approval_digest",
                    )
                except ValueError as error:
                    raise StateError(str(error)) from error
            plan_inputs = plan_body.get("inputs")
            if (
                not isinstance(plan_inputs, Mapping)
                or "candidate" not in plan_inputs
            ):
                raise StateError("admission plan requires inputs.candidate")
            try:
                plan_seed_digest = jsonutil.require_digest(
                    plan_inputs["candidate"], "plan.inputs.candidate"
                )
            except ValueError as error:
                raise StateError(str(error)) from error
            if "experiment_digest" not in plan_body:
                raise StateError("admission plan requires experiment_digest")
            raw_plan_experiment = plan_body["experiment_digest"]
            if raw_plan_experiment is None:
                plan_experiment_digest: str | None = None
            else:
                try:
                    plan_experiment_digest = jsonutil.require_digest(
                        raw_plan_experiment, "plan.experiment_digest"
                    )
                except ValueError as error:
                    raise StateError(str(error)) from error
            existing = connection.execute(
                "SELECT admission_id, job_id, parent_job_id, round_no, "
                "approval_kind, envelope_digest, parent_approval_digest, "
                "seed_digest, predicate_version, recomputable, "
                "supporting_bundle_digest, decided_at FROM admissions "
                "WHERE parent_job_id = %s AND round_no = %s FOR UPDATE",
                (family_id, round_no),
            ).fetchone()

            if existing is not None:
                # Idempotent re-entry keeps the historical semantics: the
                # snapshot is bounded by this round's envelope caps before any
                # comparison, so an over-cap snapshot never writes an event.
                if (
                    snapshot_remaining_total
                    > normalized_envelope["max_total_seconds"]
                ):
                    raise StateError(
                        "budget_snapshot remaining total exceeds envelope "
                        "max_total_seconds"
                    )
                if (
                    snapshot_remaining_fuzz is not None
                    and snapshot_remaining_fuzz
                    > normalized_envelope["max_fuzz_seconds"]
                ):
                    raise StateError(
                        "budget_snapshot remaining fuzz exceeds envelope "
                        "max_fuzz_seconds"
                    )
                _validate_budget_snapshot(
                    budget_snapshot,
                    expected_family_id=family_id,
                    expected_max_total_seconds=normalized_envelope[
                        "max_total_seconds"
                    ],
                    expected_max_fuzz_seconds=normalized_envelope[
                        "max_fuzz_seconds"
                    ],
                )
                existing_detail = _admitted_audit_detail(
                    connection, existing["job_id"], round_no
                ) or {}
                experiment_violation: str | None = None
                if experiment is not None:
                    try:
                        contracts.check_experiment_against_envelope(
                            experiment, normalized_envelope
                        )
                    except contracts.EnvelopeViolation as error:
                        experiment_violation = str(error)
                plan_approval_belongs_to_family = False
                if isinstance(plan_parent_approval_digest, str):
                    plan_approval_row = connection.execute(
                        "SELECT envelope_digest FROM family_approvals "
                        "WHERE family_id = %s AND approval_digest = %s",
                        (family_id, plan_parent_approval_digest),
                    ).fetchone()
                    plan_approval_belongs_to_family = (
                        plan_approval_row is not None
                        and plan_approval_row["envelope_digest"]
                        == envelope_digest
                    )
                same_inputs = (
                    experiment_violation is None
                    and str(existing["job_id"]) == str(job_id)
                    and existing["envelope_digest"] == envelope_digest
                    and plan_envelope_digest == envelope_digest
                    and plan_seed_digest == seed_digest
                    and plan_experiment_digest == experiment_digest
                    and plan_approval_belongs_to_family
                    and existing["parent_approval_digest"]
                    == plan_parent_approval_digest
                    and existing["seed_digest"] == seed_digest
                    and existing["predicate_version"] == predicate_version
                    and existing["recomputable"] is recomputable
                    and existing["supporting_bundle_digest"]
                    == supporting_bundle_digest
                    and existing_detail.get("budget_snapshot_digest")
                    == budget_snapshot_digest
                    and existing_detail.get("experiment_digest")
                    == experiment_digest
                )
                if same_inputs:
                    return AdmissionOutcome(
                        admitted=False,
                        reason_code=None,
                        admission=_admission_record(existing),
                        event_type=None,
                        event_detail=existing_detail,
                        status="already_admitted",
                        sub_reason="ROUND_ALREADY_ADMITTED",
                    )
                if family["state"] != "AGGREGATING":
                    raise StateError(
                        f"admission family is {family['state']}, not AGGREGATING"
                    )
                if round_job["state"] in _TERMINAL_JOB_STATES:
                    raise StateError(
                        "admission round job is in terminal state "
                        f"{round_job['state']}"
                    )
                denied_reason_code = (
                    "ENVELOPE_VIOLATION"
                    if experiment_violation is not None
                    else "ADMISSION_DENIED"
                )
                denied_sub_reason = (
                    experiment_violation
                    if experiment_violation is not None
                    else "ROUND_ALREADY_ADMITTED"
                )
                denied_detail = {
                    "job_id": str(job_id),
                    "parent_job_id": str(family_id),
                    "round_no": round_no,
                    "approval_kind": "policy",
                    "envelope_digest": envelope_digest,
                    "parent_approval_digest": approval_tail,
                    "seed_digest": seed_digest,
                    "predicate_version": predicate_version,
                    "recomputable": recomputable,
                    "supporting_bundle_digest": supporting_bundle_digest,
                    "budget_snapshot_digest": budget_snapshot_digest,
                    "experiment_digest": experiment_digest,
                    "reason_code": denied_reason_code,
                    "sub_reason": denied_sub_reason,
                }
                _audit(
                    connection,
                    job_id,
                    "round_admission_denied",
                    stage="admission",
                    reason_code=denied_reason_code,
                    detail=denied_detail,
                )
                return AdmissionOutcome(
                    admitted=False,
                    reason_code=denied_reason_code,
                    admission=None,
                    event_type="round_admission_denied",
                    event_detail=denied_detail,
                    status="denied",
                    sub_reason=denied_sub_reason,
                )

            if family["state"] != "AGGREGATING":
                raise StateError(
                    f"admission family is {family['state']}, not AGGREGATING"
                )
            if round_job["state"] in _TERMINAL_JOB_STATES:
                raise StateError(
                    "admission round job is in terminal state "
                    f"{round_job['state']}"
                )
            pending_envelope = connection.execute(
                "SELECT 1 FROM family_envelopes "
                "WHERE family_id = %s AND status = 'pending' LIMIT 1",
                (family_id,),
            ).fetchone()
            if pending_envelope is not None:
                raise StateError(
                    "cannot admit a new round while an envelope re-approval "
                    "is pending"
                )
            ledger = connection.execute(
                "SELECT max_total_seconds, max_fuzz_seconds, "
                "remaining_total_seconds, remaining_fuzz_seconds "
                "FROM budget_ledger WHERE family_id = %s FOR UPDATE",
                (family_id,),
            ).fetchone()
            if ledger is None:
                raise StateError("admission family has no budget ledger")
            ledger_max_total = int(ledger["max_total_seconds"])
            ledger_max_fuzz = int(ledger["max_fuzz_seconds"])
            ledger_remaining_total = int(ledger["remaining_total_seconds"])
            ledger_remaining_fuzz = int(ledger["remaining_fuzz_seconds"])
            if (
                "max_total_seconds" in budget_snapshot
                and budget_snapshot["max_total_seconds"] != ledger_max_total
            ):
                raise StateError(
                    "budget_snapshot.max_total_seconds does not match family "
                    "budget_ledger"
                )
            if (
                "max_fuzz_seconds" in budget_snapshot
                and budget_snapshot["max_fuzz_seconds"] != ledger_max_fuzz
            ):
                raise StateError(
                    "budget_snapshot.max_fuzz_seconds does not match family "
                    "budget_ledger"
                )
            # The persisted ledger caps are the authority for the snapshot:
            # reconcile spent/remaining against them even when the snapshot
            # omits max_* fields. The caller's envelope caps are only applied
            # by the predicate once the envelope is proven approved.
            _validate_budget_snapshot(
                budget_snapshot,
                expected_family_id=family_id,
                expected_max_total_seconds=ledger_max_total,
                expected_max_fuzz_seconds=ledger_max_fuzz,
            )
            if ledger_remaining_total >= 1:
                if snapshot_remaining_total > ledger_remaining_total:
                    raise StateError(
                        "budget_snapshot remaining total exceeds family "
                        "budget_ledger"
                    )
                if (
                    snapshot_remaining_fuzz is not None
                    and snapshot_remaining_fuzz > ledger_remaining_fuzz
                ):
                    raise StateError(
                        "budget_snapshot remaining fuzz exceeds family "
                        "budget_ledger"
                    )

            decided_at = connection.execute(
                "SELECT clock_timestamp() AS now"
            ).fetchone()["now"]
            outcome = policy_admit_round(
                clock=lambda: decided_at,
                job_id=job_id,
                parent_job_id=family_id,
                envelope=normalized_envelope,
                parent_approval_digest=approval_tail,
                approval_chain_tail_digest=approval_tail,
                seed_digest=seed_digest,
                round_no=round_no,
                budget_snapshot=budget_snapshot,
                experiment=experiment,
                recomputable=recomputable,
                campaign_bundle_digest=campaign_bundle_digest,
                approved_envelope_digest=approved_envelope_digest,
                plan_parent_approval_digest=plan_parent_approval_digest,
                plan_envelope_digest=plan_envelope_digest,
                plan_seed_digest=plan_seed_digest,
                plan_experiment_digest=plan_experiment_digest,
                ledger_remaining_total_seconds=ledger_remaining_total,
            )

            if outcome.admission is not None:
                inserted = connection.execute(
                    "INSERT INTO admissions "
                    "(admission_id, job_id, parent_job_id, round_no, "
                    "approval_kind, envelope_digest, parent_approval_digest, "
                    "seed_digest, predicate_version, recomputable, "
                    "supporting_bundle_digest, decided_at) "
                    "VALUES (%s, %s, %s, %s, 'policy', %s, %s, %s, %s, %s, "
                    "%s, %s) "
                    "ON CONFLICT (parent_job_id, round_no) DO NOTHING "
                    "RETURNING admission_id",
                    (
                        uuid.UUID(outcome.admission["admission_id"]),
                        job_id,
                        family_id,
                        round_no,
                        envelope_digest,
                        approval_tail,
                        seed_digest,
                        predicate_version,
                        recomputable,
                        supporting_bundle_digest,
                        outcome.admission["decided_at"],
                    ),
                ).fetchone()
                if inserted is None:
                    # The unique constraint is only a backstop: the family row
                    # lock serializes this path, but fail closed if it fires.
                    raise StateError(
                        "admission was recorded concurrently for this round"
                    )

            event_type = outcome.event_type
            if event_type is None:
                # A fresh decision always carries an event; only the
                # already_admitted no-op path returns no event type.
                raise StateError("admission decision has no audit event type")
            _audit(
                connection,
                job_id,
                event_type,
                stage="admission",
                reason_code=outcome.reason_code,
                detail=outcome.event_detail,
            )
            return outcome


def _ceil_seconds(value: Any, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise StateError(f"{label} must be a number")
    if not math.isfinite(value):
        raise StateError(f"{label} must be finite")
    if value < 0:
        raise StateError(f"{label} must not be negative")
    return int(math.ceil(value))


def _validate_charge_input(
    *,
    step_key: str,
    attempt_no: int,
    charge_kind: str,
    elapsed_seconds: Any,
    elapsed_fuzz_seconds: Any,
) -> tuple[str, int, int, int]:
    try:
        jsonutil.require_text(step_key, "step_key")
    except ValueError as error:
        raise StateError(str(error)) from error
    if type(attempt_no) is not int or attempt_no < 1:
        raise StateError("attempt_no must be a positive integer")
    if charge_kind not in ("general", "fuzz"):
        raise StateError("charge_kind must be general or fuzz")
    elapsed = _ceil_seconds(elapsed_seconds, "elapsed_seconds")
    fuzz_elapsed = _ceil_seconds(elapsed_fuzz_seconds, "elapsed_fuzz_seconds")
    if charge_kind == "general" and fuzz_elapsed > 0:
        raise StateError(
            "general budget charge must not specify positive "
            "elapsed_fuzz_seconds"
        )
    if charge_kind == "fuzz" and elapsed_fuzz_seconds > elapsed_seconds:
        # Compare the validated raw values so 1.1 > 1.0 is rejected too; the
        # fuzz sub-span can never be longer than the step it belongs to.
        raise StateError(
            "fuzz elapsed_fuzz_seconds must not exceed elapsed_seconds"
        )
    return charge_kind, attempt_no, elapsed, fuzz_elapsed


def budget_gate(ledger: Mapping[str, Any], *, fuzz: bool = False) -> BudgetDecision:
    """Return whether a step may start and the hard-timeout ceiling.

    ``general`` needs one second of total budget. ``fuzz`` additionally needs
    one second of fuzz sub-budget, so its ceiling is the smaller of the two.
    """
    if not isinstance(ledger, Mapping):
        raise StateError("budget ledger must be a mapping")
    remaining_total = _require_budget_int(
        ledger, "remaining_total_seconds", "remaining_total_seconds"
    )
    if remaining_total < 0:
        raise StateError("remaining_total_seconds must be non-negative")
    available = remaining_total
    if fuzz:
        remaining_fuzz = _require_budget_int(
            ledger, "remaining_fuzz_seconds", "remaining_fuzz_seconds"
        )
        if remaining_fuzz < 0:
            raise StateError("remaining_fuzz_seconds must be non-negative")
        available = min(remaining_total, remaining_fuzz)
    if available < 1:
        return BudgetDecision(False, BUDGET_EXHAUSTED, 0)
    return BudgetDecision(True, None, available)


def decide_next_round(
    ledger: Mapping[str, Any], *, round_no: int, max_rounds: int
) -> BudgetDecision:
    """Decide whether a further round may be derived.

    Budget or round exhaustion returns ``BUDGET_EXHAUSTED`` and no
    ``next_round_no``; ``sub_reason`` distinguishes hitting ``max_rounds``
    from draining the time budget. The orchestration layer must not create a
    round from a denied decision.
    """
    if type(round_no) is not int or round_no < 0:
        raise StateError("round_no must be a non-negative integer")
    if type(max_rounds) is not int or max_rounds < 1:
        raise StateError("max_rounds must be a positive integer")
    if round_no >= max_rounds:
        return BudgetDecision(
            False,
            BUDGET_EXHAUSTED,
            0,
            sub_reason="ROUND_BEYOND_MAX_ROUNDS",
        )
    gate = budget_gate(ledger)
    if not gate.allowed:
        return BudgetDecision(
            False,
            BUDGET_EXHAUSTED,
            0,
            sub_reason=BUDGET_EXHAUSTED,
        )
    return BudgetDecision(
        True, None, gate.hard_timeout_seconds, next_round_no=round_no + 1
    )


def compute_budget_charge(
    ledger: Mapping[str, Any],
    *,
    charge_kind: str,
    elapsed_seconds: Any,
    elapsed_fuzz_seconds: Any = 0,
) -> tuple[int, int]:
    """Apply the normative charge formula without touching storage.

    ``general`` charges ``min(ceil(elapsed), remaining_total_seconds)``.
    A ``fuzz`` step requires ``elapsed_fuzz <= elapsed`` and charges
    ``charged = min(max(1, ceil(elapsed)), remaining_total)`` and
    ``charged_fuzz = min(max(1, ceil(fuzz_elapsed)), remaining_fuzz, charged)``
    so ``0 < fuzz_seconds <= seconds`` without overdrawing either balance even
    when ``elapsed == 0``.
    """
    if not isinstance(ledger, Mapping):
        raise StateError("budget ledger must be a mapping")
    if charge_kind not in ("general", "fuzz"):
        raise StateError("charge_kind must be general or fuzz")
    elapsed = _ceil_seconds(elapsed_seconds, "elapsed_seconds")
    fuzz_elapsed = _ceil_seconds(elapsed_fuzz_seconds, "elapsed_fuzz_seconds")
    if charge_kind == "general" and fuzz_elapsed > 0:
        raise StateError(
            "general budget charge must not specify positive "
            "elapsed_fuzz_seconds"
        )
    if charge_kind == "fuzz" and elapsed_fuzz_seconds > elapsed_seconds:
        # Compare the validated raw values so 1.1 > 1.0 is rejected too; the
        # fuzz sub-span can never be longer than the step it belongs to.
        raise StateError(
            "fuzz elapsed_fuzz_seconds must not exceed elapsed_seconds"
        )
    remaining_total = _require_budget_int(
        ledger, "remaining_total_seconds", "remaining_total_seconds"
    )
    if remaining_total < 0:
        raise StateError("remaining_total_seconds must be non-negative")
    if charge_kind == "general":
        return min(elapsed, remaining_total), 0
    remaining_fuzz = _require_budget_int(
        ledger, "remaining_fuzz_seconds", "remaining_fuzz_seconds"
    )
    if remaining_fuzz < 0:
        raise StateError("remaining_fuzz_seconds must be non-negative")
    # elapsed_fuzz <= elapsed is enforced above; a zero-length fuzz step still
    # rounds up to one second so 0 < charged_fuzz <= charged <= remaining_total.
    effective_elapsed = max(1, elapsed)
    charged = min(effective_elapsed, remaining_total)
    charged_fuzz = min(max(1, fuzz_elapsed), remaining_fuzz, charged)
    return charged, charged_fuzz


def charge_budget_local(
    ledger: dict[str, Any],
    charges: list[dict[str, Any]],
    *,
    family_id: UUID | str,
    job_id: UUID | str,
    step_key: str,
    attempt_no: int,
    charge_kind: str,
    elapsed_seconds: Any,
    elapsed_fuzz_seconds: Any = 0,
) -> BudgetChargeOutcome:
    """Idempotent in-memory charge used as the contract-test reference.

    It shares the formula with the PostgreSQL adapter and mirrors the atomic
    ``UPDATE ... WHERE remaining >= charged`` decision so recovery, retry and
    exhaustion semantics stay identical without a database.
    """
    if not isinstance(ledger, Mapping):
        raise StateError("budget ledger must be a mapping")
    charge_kind, attempt_no, elapsed, fuzz_elapsed = _validate_charge_input(
        step_key=step_key,
        attempt_no=attempt_no,
        charge_kind=charge_kind,
        elapsed_seconds=elapsed_seconds,
        elapsed_fuzz_seconds=elapsed_fuzz_seconds,
    )
    family_text = str(family_id)
    if "family_id" in ledger and str(ledger["family_id"]) != family_text:
        raise StateError("budget ledger belongs to a different family")
    job_text = str(job_id)
    for charge in charges:
        if (
            str(charge["job_id"]) == job_text
            and charge["step_key"] == step_key
            and charge["attempt_no"] == attempt_no
        ):
            if str(charge.get("family_id")) != family_text:
                raise StateError(
                    "existing budget charge belongs to a different family"
                )
            if charge.get("charge_kind") != charge_kind:
                raise StateError(
                    "existing budget charge has a different charge_kind"
                )
            return BudgetChargeOutcome(
                "recovered", None, dict(charge), dict(ledger)
            )

    gate = budget_gate(ledger, fuzz=charge_kind == "fuzz")
    if not gate.allowed:
        return BudgetChargeOutcome(
            "budget_exhausted", BUDGET_EXHAUSTED, None, dict(ledger)
        )

    charged, charged_fuzz = compute_budget_charge(
        ledger,
        charge_kind=charge_kind,
        elapsed_seconds=elapsed,
        elapsed_fuzz_seconds=fuzz_elapsed,
    )
    if charge_kind == "fuzz" and charged_fuzz < 1:
        return BudgetChargeOutcome(
            "budget_exhausted", BUDGET_EXHAUSTED, None, dict(ledger)
        )
    remaining_total = _require_budget_int(
        ledger, "remaining_total_seconds", "remaining_total_seconds"
    )
    if remaining_total < 0:
        raise StateError("remaining_total_seconds must be non-negative")
    remaining_fuzz = _require_budget_int(
        ledger, "remaining_fuzz_seconds", "remaining_fuzz_seconds"
    )
    if remaining_fuzz < 0:
        raise StateError("remaining_fuzz_seconds must be non-negative")
    if remaining_total < charged or remaining_fuzz < charged_fuzz:
        return BudgetChargeOutcome(
            "budget_exhausted", BUDGET_EXHAUSTED, None, dict(ledger)
        )

    ledger["remaining_total_seconds"] -= charged
    ledger["remaining_fuzz_seconds"] -= charged_fuzz
    charge = {
        "charge_id": str(uuid.uuid4()),
        "family_id": family_text,
        "job_id": job_text,
        "step_key": step_key,
        "attempt_no": attempt_no,
        "charge_kind": charge_kind,
        "seconds": charged,
        "fuzz_seconds": charged_fuzz,
    }
    charges.append(charge)
    exhausted = ledger["remaining_total_seconds"] == 0 or (
        charge_kind == "fuzz" and ledger["remaining_fuzz_seconds"] == 0
    )
    return BudgetChargeOutcome(
        "budget_exhausted" if exhausted else "charged",
        BUDGET_EXHAUSTED if exhausted else None,
        charge,
        dict(ledger),
    )


def _require_budget_int(
    mapping: Mapping[str, Any], key: str, label: str
) -> int:
    if key not in mapping:
        raise StateError(f"{label} is missing")
    value = mapping[key]
    if type(value) is not int:
        raise StateError(f"{label} must be an integer")
    return value


def budget_summary(
    ledger: Mapping[str, Any], charges: list[Mapping[str, Any]]
) -> dict[str, int]:
    """Build the six-field report/status/family.json budget object.

    ``budget_ledger.remaining_total_seconds`` is exposed as
    ``remaining_seconds``; the other five fields keep their DB names. Spending
    is always rebuilt from ``budget_charges`` and reconciled against the
    ledger row (``spent + remaining == max``); any discrepancy fails closed.
    """
    if not isinstance(ledger, Mapping):
        raise StateError("budget ledger must be a mapping")
    max_total_seconds = _require_budget_int(
        ledger, "max_total_seconds", "ledger.max_total_seconds"
    )
    if max_total_seconds < 1:
        raise StateError("ledger.max_total_seconds must be a positive integer")
    max_fuzz_seconds = _require_budget_int(
        ledger, "max_fuzz_seconds", "ledger.max_fuzz_seconds"
    )
    if max_fuzz_seconds < 0 or max_fuzz_seconds > max_total_seconds:
        raise StateError(
            "ledger.max_fuzz_seconds must be between 0 and max_total_seconds"
        )
    remaining_seconds = _require_budget_int(
        ledger, "remaining_total_seconds", "ledger.remaining_total_seconds"
    )
    if remaining_seconds < 0 or remaining_seconds > max_total_seconds:
        raise StateError(
            "ledger.remaining_total_seconds must be between 0 and "
            "max_total_seconds"
        )
    remaining_fuzz_seconds = _require_budget_int(
        ledger, "remaining_fuzz_seconds", "ledger.remaining_fuzz_seconds"
    )
    if remaining_fuzz_seconds < 0 or remaining_fuzz_seconds > max_fuzz_seconds:
        raise StateError(
            "ledger.remaining_fuzz_seconds must be between 0 and "
            "max_fuzz_seconds"
        )

    ledger_family_id = (
        str(ledger["family_id"])
        if "family_id" in ledger and ledger["family_id"] is not None
        else None
    )
    spent_seconds = 0
    spent_fuzz_seconds = 0
    for index, charge in enumerate(charges):
        if not isinstance(charge, Mapping):
            raise StateError(f"charges[{index}] must be a mapping")
        if (
            ledger_family_id is not None
            and "family_id" in charge
            and charge["family_id"] is not None
            and str(charge["family_id"]) != ledger_family_id
        ):
            raise StateError(
                f"charges[{index}].family_id does not match ledger.family_id"
            )
        seconds = _require_budget_int(
            charge, "seconds", f"charges[{index}].seconds"
        )
        fuzz_seconds = _require_budget_int(
            charge, "fuzz_seconds", f"charges[{index}].fuzz_seconds"
        )
        if seconds < 0:
            raise StateError(f"charges[{index}].seconds must not be negative")
        if fuzz_seconds < 0 or fuzz_seconds > seconds:
            raise StateError(
                f"charges[{index}].fuzz_seconds must be between 0 and seconds"
            )
        if "charge_kind" in charge:
            kind = charge["charge_kind"]
            if kind == "general":
                if fuzz_seconds != 0:
                    raise StateError(
                        f"charges[{index}] general charge must have "
                        "fuzz_seconds == 0"
                    )
            elif kind == "fuzz":
                if fuzz_seconds <= 0:
                    raise StateError(
                        f"charges[{index}] fuzz charge must have "
                        "fuzz_seconds > 0"
                    )
            else:
                raise StateError(
                    f"charges[{index}].charge_kind must be general or fuzz"
                )
        spent_seconds += seconds
        spent_fuzz_seconds += fuzz_seconds

    if (
        spent_seconds + remaining_seconds != max_total_seconds
        or spent_fuzz_seconds + remaining_fuzz_seconds != max_fuzz_seconds
    ):
        raise StateError(
            "budget ledger does not reconcile with budget_charges"
        )
    return {
        "max_total_seconds": max_total_seconds,
        "max_fuzz_seconds": max_fuzz_seconds,
        "spent_seconds": spent_seconds,
        "spent_fuzz_seconds": spent_fuzz_seconds,
        "remaining_seconds": remaining_seconds,
        "remaining_fuzz_seconds": remaining_fuzz_seconds,
    }


_BUDGET_LEDGER_COLUMNS = (
    "family_id, max_total_seconds, max_fuzz_seconds, "
    "remaining_total_seconds, remaining_fuzz_seconds, updated_at"
)
_BUDGET_CHARGE_COLUMNS = (
    "charge_id, family_id, job_id, step_key, attempt_no, charge_kind, "
    "seconds, fuzz_seconds, created_at"
)


def _budget_ledger_record(row: Mapping[str, Any]) -> dict[str, Any]:
    """Render a ``budget_ledger`` row with canonical JSON-serializable types."""
    record: dict[str, Any] = {
        "family_id": str(row["family_id"]),
        "max_total_seconds": int(row["max_total_seconds"]),
        "max_fuzz_seconds": int(row["max_fuzz_seconds"]),
        "remaining_total_seconds": int(row["remaining_total_seconds"]),
        "remaining_fuzz_seconds": int(row["remaining_fuzz_seconds"]),
    }
    if "updated_at" in row and row["updated_at"] is not None:
        updated_at = row["updated_at"]
        record["updated_at"] = (
            updated_at
            if isinstance(updated_at, str)
            else jsonutil.timestamp(updated_at)
        )
    return record


def _budget_charge_record(row: Mapping[str, Any]) -> dict[str, Any]:
    """Render a ``budget_charges`` row with canonical JSON-serializable types."""
    record: dict[str, Any] = {
        "charge_id": str(row["charge_id"]),
        "family_id": str(row["family_id"]),
        "job_id": str(row["job_id"]),
        "step_key": row["step_key"],
        "attempt_no": int(row["attempt_no"]),
        "charge_kind": row["charge_kind"],
        "seconds": int(row["seconds"]),
        "fuzz_seconds": int(row["fuzz_seconds"]),
    }
    if "created_at" in row and row["created_at"] is not None:
        created_at = row["created_at"]
        record["created_at"] = (
            created_at
            if isinstance(created_at, str)
            else jsonutil.timestamp(created_at)
        )
    return record


def _approved_envelope_budget(
    envelope_body: Mapping[str, Any],
) -> tuple[int, int]:
    """Return the approved envelope's family budget ceilings.

    The ledger is initialized from the envelope body that was just approved,
    never from the request or a caller-supplied snapshot. Missing or malformed
    caps fail closed so no family can run without a budget authority.
    """
    max_total = envelope_body.get("max_total_seconds")
    if type(max_total) is not int or max_total < 1:
        raise StateError(
            "approved envelope max_total_seconds must be a positive integer"
        )
    max_fuzz = envelope_body.get("max_fuzz_seconds")
    if (
        type(max_fuzz) is not int
        or max_fuzz < 0
        or max_fuzz > max_total
    ):
        raise StateError(
            "approved envelope max_fuzz_seconds must be between 0 and "
            "max_total_seconds"
        )
    return int(max_total), int(max_fuzz)


def _initialize_budget_ledger_in_tx(
    connection,
    family_id: UUID | str,
    *,
    max_total_seconds: int,
    max_fuzz_seconds: int,
) -> dict[str, Any]:
    """Create the ledger inside the caller's transaction, or return it unchanged.

    This is the one implementation shared by the standalone initializer and the
    human-approval path: approving a family envelope and creating its ledger
    must be one transaction. An existing row is locked and its approved caps
    are compared with the current envelope; a different envelope never silently
    reuses the old budget.
    """
    if type(max_total_seconds) is not int or max_total_seconds < 1:
        raise StateError("max_total_seconds must be a positive integer")
    if (
        type(max_fuzz_seconds) is not int
        or max_fuzz_seconds < 0
        or max_fuzz_seconds > max_total_seconds
    ):
        raise StateError(
            "max_fuzz_seconds must be between 0 and max_total_seconds"
        )
    try:
        family_id = uuid.UUID(str(family_id))
    except (TypeError, ValueError) as error:
        raise StateError("family_id must be a UUID") from error

    # Global lock order: jobs(family) before budget_ledger(family). Only a v2
    # family job may own a budget ledger.
    target = connection.execute(
        "SELECT job_contract_version, job_kind "
        "FROM jobs WHERE job_id = %s FOR KEY SHARE",
        (family_id,),
    ).fetchone()
    if target is None:
        raise StateError("budget ledger family does not exist")
    if target["job_contract_version"] != 2 or target["job_kind"] != "family":
        raise StateError("budget ledger target must be a v2 family job")

    row = connection.execute(
        "INSERT INTO budget_ledger "
        "(family_id, max_total_seconds, max_fuzz_seconds, "
        "remaining_total_seconds, remaining_fuzz_seconds) "
        "VALUES (%s, %s, %s, %s, %s) "
        "ON CONFLICT (family_id) DO NOTHING "
        f"RETURNING {_BUDGET_LEDGER_COLUMNS}",
        (
            family_id,
            max_total_seconds,
            max_fuzz_seconds,
            max_total_seconds,
            max_fuzz_seconds,
        ),
    ).fetchone()
    if row is None:
        row = connection.execute(
            "SELECT " + _BUDGET_LEDGER_COLUMNS +
            " FROM budget_ledger WHERE family_id = %s FOR UPDATE",
            (family_id,),
        ).fetchone()
        if row is None:
            raise StateError("budget ledger could not be initialized")
        if (
            row["max_total_seconds"] != max_total_seconds
            or row["max_fuzz_seconds"] != max_fuzz_seconds
        ):
            raise StateError(
                "budget ledger already exists with different caps: "
                f"approved max_total_seconds={max_total_seconds}, "
                f"max_fuzz_seconds={max_fuzz_seconds}; existing "
                f"max_total_seconds={row['max_total_seconds']}, "
                f"max_fuzz_seconds={row['max_fuzz_seconds']}"
            )
    return _budget_ledger_record(row)


def _sync_budget_ledger_on_approval_in_tx(
    connection,
    family_id: UUID | str,
    *,
    max_total_seconds: int,
    max_fuzz_seconds: int,
) -> dict[str, Any]:
    """Create or re-approve a family's budget ledger inside the review tx.

    First approval inserts the initial ledger with ``remaining = max``. A
    changed-envelope re-approval locks the existing row, reconciles it against
    ``budget_charges`` (``old_max - old_rem == spent``), and atomically
    adjusts the ceilings while preserving all spent budget
    (``new_remaining = new_max - spent``). Any cap below already-spent budget
    or unreconciled ledger fails closed and rolls back the approval.
    """
    if type(max_total_seconds) is not int or max_total_seconds < 1:
        raise StateError("max_total_seconds must be a positive integer")
    if (
        type(max_fuzz_seconds) is not int
        or max_fuzz_seconds < 0
        or max_fuzz_seconds > max_total_seconds
    ):
        raise StateError(
            "max_fuzz_seconds must be between 0 and max_total_seconds"
        )
    try:
        family_id = uuid.UUID(str(family_id))
    except (TypeError, ValueError) as error:
        raise StateError("family_id must be a UUID") from error

    row = connection.execute(
        "INSERT INTO budget_ledger "
        "(family_id, max_total_seconds, max_fuzz_seconds, "
        "remaining_total_seconds, remaining_fuzz_seconds) "
        "VALUES (%s, %s, %s, %s, %s) "
        "ON CONFLICT (family_id) DO NOTHING "
        f"RETURNING {_BUDGET_LEDGER_COLUMNS}",
        (
            family_id,
            max_total_seconds,
            max_fuzz_seconds,
            max_total_seconds,
            max_fuzz_seconds,
        ),
    ).fetchone()
    if row is not None:
        return _budget_ledger_record(row)

    existing = connection.execute(
        "SELECT " + _BUDGET_LEDGER_COLUMNS +
        " FROM budget_ledger WHERE family_id = %s FOR UPDATE",
        (family_id,),
    ).fetchone()
    if existing is None:
        raise StateError("budget ledger could not be initialized")

    totals = connection.execute(
        "SELECT COALESCE(SUM(seconds), 0) AS spent_total, "
        "COALESCE(SUM(fuzz_seconds), 0) AS spent_fuzz "
        "FROM budget_charges WHERE family_id = %s",
        (family_id,),
    ).fetchone()
    spent_total = int(totals["spent_total"])
    spent_fuzz = int(totals["spent_fuzz"])

    old_max_total = int(existing["max_total_seconds"])
    old_rem_total = int(existing["remaining_total_seconds"])
    old_max_fuzz = int(existing["max_fuzz_seconds"])
    old_rem_fuzz = int(existing["remaining_fuzz_seconds"])
    if (
        old_max_total - old_rem_total != spent_total
        or old_max_fuzz - old_rem_fuzz != spent_fuzz
    ):
        raise StateError(
            "budget ledger does not reconcile with budget_charges"
        )

    if (
        old_max_total == max_total_seconds
        and old_max_fuzz == max_fuzz_seconds
    ):
        return _budget_ledger_record(existing)

    if max_total_seconds < spent_total:
        raise StateError(
            "approved max_total_seconds is below already spent family budget"
        )
    if max_fuzz_seconds < spent_fuzz:
        raise StateError(
            "approved max_fuzz_seconds is below already spent family fuzz "
            "budget"
        )
    if (
        max_total_seconds < old_max_total
        or max_fuzz_seconds < old_max_fuzz
    ):
        # §9.1: changed-envelope re-approval only locks the family row, so this
        # recheck intentionally takes no row locks on child jobs.
        active_child = connection.execute(
            "SELECT 1 FROM jobs WHERE parent_job_id = %s "
            "AND state IN ('RUNNING', 'ARCHIVING') LIMIT 1",
            (family_id,),
        ).fetchone()
        if active_child is not None:
            raise StateError(
                "cannot tighten family budget while a child job is "
                "RUNNING or ARCHIVING"
            )

    new_rem_total = max_total_seconds - spent_total
    new_rem_fuzz = max_fuzz_seconds - spent_fuzz
    updated = connection.execute(
        "UPDATE budget_ledger SET "
        "max_total_seconds = %s, "
        "max_fuzz_seconds = %s, "
        "remaining_total_seconds = %s, "
        "remaining_fuzz_seconds = %s, "
        "updated_at = clock_timestamp() "
        "WHERE family_id = %s "
        f"RETURNING {_BUDGET_LEDGER_COLUMNS}",
        (
            max_total_seconds,
            max_fuzz_seconds,
            new_rem_total,
            new_rem_fuzz,
            family_id,
        ),
    ).fetchone()
    if updated is None:
        raise StateError("budget ledger could not be updated on re-approval")
    return _budget_ledger_record(updated)


def initialize_budget_ledger(
    dsn: str,
    family_id: UUID | str,
    *,
    max_total_seconds: int,
    max_fuzz_seconds: int,
) -> dict[str, Any]:
    """Create the family ledger once, or return the existing row unchanged."""
    with _connect(dsn) as connection:
        with connection.transaction():
            return _initialize_budget_ledger_in_tx(
                connection,
                family_id,
                max_total_seconds=max_total_seconds,
                max_fuzz_seconds=max_fuzz_seconds,
            )


def load_budget_ledger(
    dsn: str, family_id: UUID | str
) -> dict[str, Any] | None:
    try:
        family_id = uuid.UUID(str(family_id))
    except (TypeError, ValueError) as error:
        raise StateError("family_id must be a UUID") from error
    with _connect(dsn) as connection:
        row = connection.execute(
            "SELECT " + _BUDGET_LEDGER_COLUMNS +
            " FROM budget_ledger WHERE family_id = %s",
            (family_id,),
        ).fetchone()
    return _budget_ledger_record(row) if row is not None else None


def charge_step_budget(
    dsn: str,
    *,
    family_id: UUID | str,
    job_id: UUID | str,
    step_key: str,
    attempt_no: int,
    charge_kind: str,
    elapsed_seconds: Any,
    elapsed_fuzz_seconds: Any = 0,
) -> BudgetChargeOutcome:
    """Charge one step in an independent short transaction.

    The container runs outside this transaction. The ledger row is locked, the
    idempotency key is checked before any write, and the conditional
    ``UPDATE ... WHERE remaining >= charged`` is the only mutation, so a
    concurrent or timed-out charge can never overdraw the family budget.
    """
    charge_kind, attempt_no, elapsed, fuzz_elapsed = _validate_charge_input(
        step_key=step_key,
        attempt_no=attempt_no,
        charge_kind=charge_kind,
        elapsed_seconds=elapsed_seconds,
        elapsed_fuzz_seconds=elapsed_fuzz_seconds,
    )
    try:
        family_id = uuid.UUID(str(family_id))
        job_id = uuid.UUID(str(job_id))
    except (TypeError, ValueError) as error:
        raise StateError("budget charge ids must be UUIDs") from error

    with _connect(dsn) as connection:
        with connection.transaction():
            # Follow the global lock order jobs(family) -> jobs(child) ->
            # budget_ledger(family). INSERT INTO budget_charges implicitly
            # takes FOR KEY SHARE on both jobs(family_id) and jobs(job_id) via
            # its foreign keys, so acquiring FOR KEY SHARE before locking
            # budget_ledger FOR UPDATE prevents AB-BA deadlocks with
            # propose_envelope / record_review / record_admission.
            connection.execute(
                "SELECT 1 FROM jobs WHERE job_id = %s FOR KEY SHARE",
                (family_id,),
            ).fetchone()
            job_row = connection.execute(
                "SELECT job_id, job_contract_version, family_id, job_kind, "
                "state FROM jobs WHERE job_id = %s FOR KEY SHARE",
                (job_id,),
            ).fetchone()
            if job_row is None:
                raise StateError("budget charge job does not exist")
            if job_row["job_contract_version"] != 2:
                raise StateError(
                    "budget charge job must be on the v2 job contract"
                )
            if job_row["family_id"] != family_id:
                raise StateError(
                    "budget charge job does not belong to family_id"
                )
            if job_row["job_kind"] not in ("campaign", "round"):
                raise StateError(
                    "budget charge job_id must be a campaign or round child"
                )

            ledger = connection.execute(
                "SELECT " + _BUDGET_LEDGER_COLUMNS +
                " FROM budget_ledger WHERE family_id = %s FOR UPDATE",
                (family_id,),
            ).fetchone()
            if ledger is None:
                raise StateError("budget ledger does not exist")
            existing = connection.execute(
                "SELECT " + _BUDGET_CHARGE_COLUMNS +
                " FROM budget_charges WHERE job_id = %s AND step_key = %s "
                "AND attempt_no = %s",
                (job_id, step_key, attempt_no),
            ).fetchone()
            if existing is not None:
                if existing["family_id"] != family_id:
                    raise StateError(
                        "existing budget charge belongs to a different family"
                    )
                if existing["charge_kind"] != charge_kind:
                    raise StateError(
                        "existing budget charge has a different charge_kind"
                    )
                return BudgetChargeOutcome(
                    "recovered",
                    None,
                    _budget_charge_record(existing),
                    _budget_ledger_record(ledger),
                )
            if job_row["state"] not in ("RUNNING", "ARCHIVING"):
                raise StateError(
                    "cannot charge budget while job is in state "
                    f"{job_row['state']}"
                )

            gate = budget_gate(ledger, fuzz=charge_kind == "fuzz")
            if not gate.allowed:
                return BudgetChargeOutcome(
                    "budget_exhausted",
                    BUDGET_EXHAUSTED,
                    None,
                    _budget_ledger_record(ledger),
                )
            charged, charged_fuzz = compute_budget_charge(
                ledger,
                charge_kind=charge_kind,
                elapsed_seconds=elapsed,
                elapsed_fuzz_seconds=fuzz_elapsed,
            )
            if charge_kind == "fuzz" and charged_fuzz < 1:
                return BudgetChargeOutcome(
                    "budget_exhausted",
                    BUDGET_EXHAUSTED,
                    None,
                    _budget_ledger_record(ledger),
                )

            updated = connection.execute(
                "UPDATE budget_ledger SET "
                "remaining_total_seconds = remaining_total_seconds - %s, "
                "remaining_fuzz_seconds = remaining_fuzz_seconds - %s, "
                "updated_at = clock_timestamp() "
                "WHERE family_id = %s "
                "AND remaining_total_seconds >= %s "
                "AND remaining_fuzz_seconds >= %s "
                "RETURNING " + _BUDGET_LEDGER_COLUMNS,
                (
                    charged,
                    charged_fuzz,
                    family_id,
                    charged,
                    charged_fuzz,
                ),
            ).fetchone()
            if updated is None:
                return BudgetChargeOutcome(
                    "budget_exhausted",
                    BUDGET_EXHAUSTED,
                    None,
                    _budget_ledger_record(ledger),
                )

            charge_id = uuid.uuid4()
            inserted = connection.execute(
                "INSERT INTO budget_charges "
                "(charge_id, family_id, job_id, step_key, attempt_no, "
                "charge_kind, seconds, fuzz_seconds) "
                "VALUES (%s, %s, %s, %s, %s, %s, %s, %s) "
                "RETURNING " + _BUDGET_CHARGE_COLUMNS,
                (
                    charge_id,
                    family_id,
                    job_id,
                    step_key,
                    attempt_no,
                    charge_kind,
                    charged,
                    charged_fuzz,
                ),
            ).fetchone()
            if inserted is None:
                raise StateError("budget charge could not be recorded")
            charge = _budget_charge_record(inserted)
            exhausted = updated["remaining_total_seconds"] == 0 or (
                charge_kind == "fuzz"
                and updated["remaining_fuzz_seconds"] == 0
            )
            return BudgetChargeOutcome(
                "budget_exhausted" if exhausted else "charged",
                BUDGET_EXHAUSTED if exhausted else None,
                charge,
                _budget_ledger_record(updated),
            )


def family_budget_summary(dsn: str, family_id: UUID | str) -> dict[str, int]:
    """Return the six report fields from the ledger and family charges."""
    try:
        family_id = uuid.UUID(str(family_id))
    except (TypeError, ValueError) as error:
        raise StateError("family_id must be a UUID") from error
    with _connect(dsn) as connection:
        with connection.transaction():
            connection.execute(
                "SET TRANSACTION ISOLATION LEVEL REPEATABLE READ"
            )
            ledger = connection.execute(
                "SELECT " + _BUDGET_LEDGER_COLUMNS +
                " FROM budget_ledger WHERE family_id = %s",
                (family_id,),
            ).fetchone()
            if ledger is None:
                raise StateError("budget ledger does not exist")
            charges = connection.execute(
                "SELECT seconds, fuzz_seconds FROM budget_charges "
                "WHERE family_id = %s",
                (family_id,),
            ).fetchall()
    return budget_summary(ledger, charges)


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
        "AND state NOT IN ('COMPLETED', 'FAILED', 'BLOCKED', "
        "'REPRODUCED', 'NOT_REPRODUCED', 'INCONCLUSIVE') "
        "RETURNING job_id",
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
    pending_blocked: list[tuple[UUID, str, str]],
) -> ReviewOutcome:
    """Record a human review against a v2 family and its first child.

    The caller already holds the family row lock. A first-round review also
    locks the first child (family -> child); a re-approval only touches the
    family. The plan digest is validated first, then an already-decided
    envelope is classified before the family state is consulted: a retry after
    a first-round reject/expiry must still answer ``idempotent``/``expired``
    even though the family is already ``BLOCKED``. Only a still-``pending``
    envelope requires the family to be ``AGGREGATING``.
    """
    first_round = connection.execute(
        "SELECT NOT EXISTS (SELECT 1 FROM reviews WHERE job_id = %s) "
        "AND NOT EXISTS (SELECT 1 FROM family_approvals WHERE family_id = %s) "
        "AS first_round",
        (job_id, job_id),
    ).fetchone()["first_round"]
    # The first child is determined by the family's exploration mode, not by
    # the earliest submitted row: guided families review the campaign, fixed
    # families review round 1. A duplicate first child is a data error, not a
    # reason to silently review an arbitrary row.
    exploration = _request_exploration(job.get("request")) or {}
    mode = exploration.get("mode", "fixed")
    if mode == "guided":
        first_child_filter = "job_kind = 'campaign'"
    else:
        first_child_filter = "job_kind = 'round' AND round_no = 1"
    children = connection.execute(
        "SELECT job_id, state, generation FROM jobs "
        f"WHERE parent_job_id = %s AND {first_child_filter} "
        "ORDER BY submitted_at, job_id LIMIT 2",
        (job_id,),
    ).fetchall()
    if not children:
        return ReviewOutcome(
            "invalid_state",
            state=job["state"],
            message="family has no first child job",
        )
    if len(children) > 1:
        return ReviewOutcome(
            "invalid_state",
            state=job["state"],
            message="family has more than one first child job",
        )
    child = children[0]
    locked_child: dict[str, Any] | None = None
    if first_round:
        # Lock order is family then first child. The family lock is already
        # held; blocking here proves the order to any concurrent observer.
        locked_child = connection.execute(
            "SELECT state FROM jobs WHERE job_id = %s FOR UPDATE",
            (child["job_id"],),
        ).fetchone()
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
        if not isinstance(plan_envelope, str) or not plan_envelope:
            return ReviewOutcome(
                "envelope_mismatch",
                state=job["state"],
                message="the first plan has no envelope digest",
            )
        # Omitting --envelope-digest is always a first-plan decision. A
        # changed-envelope re-approval must name its pending digest: if the
        # family currently has a different pending envelope, the omission is a
        # mismatch rather than a silent fallback to the already-approved body.
        pending_envelope = connection.execute(
            "SELECT envelope_digest FROM family_envelopes "
            "WHERE family_id = %s AND status = 'pending'",
            (job_id,),
        ).fetchone()
        if (
            pending_envelope is not None
            and pending_envelope["envelope_digest"] != plan_envelope
        ):
            return ReviewOutcome(
                "envelope_mismatch",
                state=job["state"],
                message="a changed pending envelope requires an explicit "
                "envelope digest",
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
        "SELECT envelope_id, status, review_deadline_at, reviewer_id, "
        "decided_at, envelope_json "
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
    # A first-round review object is the first child. Once it reached a verdict
    # terminal (for example REPRODUCED/archived) it is no longer reviewable:
    # writing reviews/approvals or blocking the family would attach a review
    # decision to a verdict it can never rewrite. The gate runs before any
    # write but after the already-decided/expired envelope answers above, so a
    # retry of an expiry still reports "expired" rather than being misread as
    # a fresh decision.
    if first_round and (
        locked_child is None or locked_child["state"] != "AWAITING_REVIEW"
    ):
        return ReviewOutcome(
            "invalid_state",
            state=job["state"],
            message=(
                "the first child is not AWAITING_REVIEW "
                f"(it is {locked_child['state'] if locked_child else 'missing'})"
            ),
        )
    # §9.1 step 3 concludes with the state gate: only a still-pending envelope
    # is a new decision. Already-decided envelopes were answered above even
    # when the family is already BLOCKED or COMPLETED.
    if job["state"] != "AGGREGATING":
        return ReviewOutcome(
            "invalid_state",
            state=job["state"],
            message=f"family is {job['state']}, not AGGREGATING",
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
        expiry_message = "review deadline passed before a decision was recorded"
        if first_round:
            # A first-round timeout is a review-object timeout: the child is
            # still AWAITING_REVIEW and must converge with the family. A
            # changed-envelope timeout only expires the envelope; the
            # already-approved child stays untouched (§9.1).
            _block_v2_review_job(
                connection,
                child["job_id"],
                reason_code="REVIEW_EXPIRED",
                message=expiry_message,
            )
            pending_blocked.append(
                (child["job_id"], "REVIEW_EXPIRED", expiry_message)
            )
        _block_v2_review_job(
            connection,
            job_id,
            reason_code="REVIEW_EXPIRED",
            message=expiry_message,
        )
        pending_blocked.append((job_id, "REVIEW_EXPIRED", expiry_message))
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
        # The approval hash uses the exact microsecond value persisted in
        # family_approvals.decided_at (fixed six-digit UTC fraction), never the
        # seconds-only display rendering.
        approval_digest = jsonutil.digest_json(
            {
                "family_id": str(job_id),
                "first_plan_digest": first_plan_digest,
                "envelope_digest": resolved_envelope,
                "reviewer_id": reviewer_id,
                "decided_at": jsonutil.approval_timestamp(decision_at),
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
        # The approved envelope is the budget authority for the whole family.
        # Syncing the ledger here makes approval and budget initialization or
        # cap adjustment one transaction, preserving spent budget across
        # changed-envelope re-approvals while failing closed if a cap drops
        # below already-spent budget.
        envelope_body = envelope["envelope_json"]
        if not isinstance(envelope_body, Mapping):
            raise StateError("approved family envelope must be a JSON object")
        max_total_seconds, max_fuzz_seconds = _approved_envelope_budget(
            envelope_body
        )
        _sync_budget_ledger_on_approval_in_tx(
            connection,
            job_id,
            max_total_seconds=max_total_seconds,
            max_fuzz_seconds=max_fuzz_seconds,
        )
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
    rejection_message = "review rejected by the operator"
    if first_round:
        # A first-round rejection rejects the review object itself, so the
        # first child is locked. Re-approving a changed envelope only rejects
        # that envelope: the already-approved child must stay untouched.
        _block_v2_review_job(
            connection,
            child["job_id"],
            reason_code="REVIEW_REJECTED",
            message=rejection_message,
        )
        pending_blocked.append(
            (child["job_id"], "REVIEW_REJECTED", rejection_message)
        )
    _block_v2_review_job(
        connection,
        job_id,
        reason_code="REVIEW_REJECTED",
        message=rejection_message,
    )
    pending_blocked.append((job_id, "REVIEW_REJECTED", rejection_message))
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

    pending_blocked: list[tuple[UUID, str, str]] = []
    with ExitStack() as stack:
        # Registered before the connection so it runs after the transaction
        # commits (ExitStack unwinds in reverse order). record_review has no
        # worker lease; record_blocked_evidence intentionally does not require
        # one.
        stack.callback(_archive_pending_blocked, dsn, pending_blocked)
        connection = stack.enter_context(_connect(dsn))
        job = connection.execute(
            "SELECT state, reason_code, review_deadline_at, generation, "
            "job_contract_version, job_kind, family_id, request "
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
                pending_blocked=pending_blocked,
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
                    job_id,
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
                (job_id, "REVIEW_REJECTED", "review rejected by the operator")
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
    """Expire the first child's review window and converge its family.

    Lock order is global (§9.1): the child's immutable ``parent_job_id`` is
    read without a lock, then the family row is locked, then the child. This
    matches ``record_review`` (family -> child) so the two paths can never form
    a child -> family vs family -> child deadlock. After both locks the child
    is re-checked: a changed state, generation or lease still fails closed.
    """
    pending_blocked: list[tuple[UUID, str, str]] = []
    with ExitStack() as stack:
        stack.callback(_archive_pending_blocked, dsn, pending_blocked)
        connection = stack.enter_context(_connect(dsn))
        identity = connection.execute(
            "SELECT job_contract_version, job_kind, family_id "
            "FROM jobs WHERE job_id = %s",
            (job_id,),
        ).fetchone()
        if identity is None:
            return False
        family_id: UUID | None = None
        family: dict[str, Any] | None = None
        if (
            identity["job_contract_version"] == 2
            and identity["job_kind"] in ("campaign", "round")
            and identity["family_id"] is not None
        ):
            family_id = identity["family_id"]
            # Family first. The identity read above is lock-free because
            # parent_job_id is immutable for the lifetime of the row.
            family = connection.execute(
                "SELECT state, generation, evidence_status FROM jobs "
                "WHERE job_id = %s FOR UPDATE",
                (family_id,),
            ).fetchone()
            if family is not None and (
                family["state"] != "AGGREGATING"
                or family["evidence_status"] == "archived"
            ):
                # The family already converged (COMPLETED/BLOCKED) or owns an
                # archived pointer. Expiring a stale child row must never
                # resurrect the aggregate or overwrite its evidence pointer.
                return False
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
        expiry_message = "review deadline passed before a decision was recorded"
        updated_child = connection.execute(
            "UPDATE jobs SET state = 'BLOCKED', stage = 'blocked', "
            "reason_code = 'REVIEW_EXPIRED', last_error = %s, "
            "state_version = state_version + 1, generation = generation + 1, "
            "workflow_synced = false, lease_owner = NULL, "
            "lease_expires_at = NULL, updated_at = clock_timestamp() "
            "WHERE job_id = %s AND generation = %s "
            "AND state = 'AWAITING_REVIEW' RETURNING job_id",
            (expiry_message, job_id, generation),
        ).fetchone()
        if updated_child is None:
            raise StateError("child state changed while expiring the review")
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
        # after its pending envelope timed out. The conditional family UPDATE
        # is the last line of defense against a concurrent COMPLETED write:
        # without it a timed-out child could demote a finished family.
        if family_id is not None and family is not None:
            updated_family = connection.execute(
                "UPDATE jobs SET state = 'BLOCKED', stage = 'blocked', "
                "reason_code = 'REVIEW_EXPIRED', last_error = %s, "
                "state_version = state_version + 1, "
                "generation = generation + 1, workflow_synced = false, "
                "lease_owner = NULL, lease_expires_at = NULL, "
                "updated_at = clock_timestamp() "
                "WHERE job_id = %s AND state = 'AGGREGATING' "
                "RETURNING job_id",
                (expiry_message, family_id),
            ).fetchone()
            if updated_family is None:
                raise StateError("family state changed while expiring the review")
            connection.execute(
                "UPDATE family_envelopes SET status = 'expired' "
                "WHERE family_id = %s AND status = 'pending'",
                (family_id,),
            )
            _audit(
                connection,
                family_id,
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
                (family_id, "REVIEW_EXPIRED", expiry_message)
            )
        pending_blocked.append((job_id, "REVIEW_EXPIRED", expiry_message))
        return True


def expire_pending_envelopes(dsn: str) -> int:
    """Expire changed-envelope re-approvals whose review window has closed.

    This is the periodic sweep from §9.1: it scans ``family_envelopes`` rows
    (not child ``review_deadline_at`` values), so a family parked in
    ``AGGREGATING`` on a re-approval converges to
    ``BLOCKED(REVIEW_EXPIRED)`` even though no child is ``AWAITING_REVIEW``.
    Each candidate is re-checked while holding the family row lock, which is
    the same lock ``record_review`` and ``propose_envelope`` take first; a
    review that raced the scan therefore wins instead of being overwritten.
    Only the family job row is locked; no child row is locked or changed.
    Existing ``reviews`` and every child (``READY``, ``AWAITING_REVIEW`` or
    finished) are left untouched. The sweep is idempotent because every write
    is conditional on ``status = 'pending'`` and ``state = 'AGGREGATING'``.
    """
    expired = 0
    pending_blocked: list[tuple[UUID, str, str]] = []
    with _connect(dsn) as connection:
        candidates = connection.execute(
            "SELECT fe.envelope_id, fe.family_id, fe.envelope_digest "
            "FROM family_envelopes AS fe "
            "JOIN jobs AS j ON j.job_id = fe.family_id "
            "WHERE fe.status = 'pending' "
            "AND fe.review_deadline_at <= clock_timestamp() "
            "AND EXISTS (SELECT 1 FROM family_approvals AS fa "
            "WHERE fa.family_id = fe.family_id) "
            "AND j.state = 'AGGREGATING' "
            "AND j.job_kind = 'family' "
            "AND j.job_contract_version = 2 "
            "ORDER BY fe.review_deadline_at, fe.envelope_id"
        ).fetchall()
        for candidate in candidates:
            # The family lock is the serialization point. SKIP LOCKED lets a
            # concurrent review finish without making the sweep wait; that
            # row is simply reconsidered on the next poll.
            family = connection.execute(
                "SELECT state, generation FROM jobs "
                "WHERE job_id = %s FOR UPDATE SKIP LOCKED",
                (candidate["family_id"],),
            ).fetchone()
            if family is None or family["state"] != "AGGREGATING":
                continue
            # Read the clock only after the lock is held so a wait across the
            # deadline cannot leave a closed window looking open.
            db_now = connection.execute(
                "SELECT clock_timestamp() AS db_now"
            ).fetchone()["db_now"]
            envelope = connection.execute(
                "SELECT status, review_deadline_at FROM family_envelopes "
                "WHERE envelope_id = %s",
                (candidate["envelope_id"],),
            ).fetchone()
            if (
                envelope is None
                or envelope["status"] != "pending"
                or not _review_window_closed(
                    envelope["review_deadline_at"], db_now
                )
            ):
                continue
            connection.execute(
                "UPDATE family_envelopes SET status = 'expired' "
                "WHERE envelope_id = %s AND status = 'pending'",
                (candidate["envelope_id"],),
            )
            connection.execute(
                "UPDATE jobs SET state = 'BLOCKED', stage = 'blocked', "
                "reason_code = 'REVIEW_EXPIRED', last_error = %s, "
                "state_version = state_version + 1, "
                "generation = generation + 1, workflow_synced = false, "
                "lease_owner = NULL, lease_expires_at = NULL, "
                "updated_at = clock_timestamp() "
                "WHERE job_id = %s AND state = 'AGGREGATING'",
                (
                    "review deadline passed before a decision was recorded",
                    candidate["family_id"],
                ),
            )
            _audit(
                connection,
                candidate["family_id"],
                "review_expired",
                stage="blocked",
                reason_code="REVIEW_EXPIRED",
                detail={
                    "generation": family["generation"],
                    "envelope_digest": candidate["envelope_digest"],
                    "source": "pending_envelope_sweep",
                },
            )
            pending_blocked.append(
                (
                    candidate["family_id"],
                    "REVIEW_EXPIRED",
                    "review deadline passed before a decision was recorded",
                )
            )
            expired += 1
    _archive_pending_blocked(dsn, pending_blocked)
    return expired


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
# v2 drain set: seven non-terminal states plus an unsynced BLOCKED row. A
# family that is still AGGREGATING is a residual only when it has no
# non-terminal child left; while a non-terminal child exists that child is the
# drain unit. Counting the aggregate as well would double its slots and break
# the single-execution-slot invariant.
V2_NON_TERMINAL_STATES = (
    "QUEUED",
    "PREPARING",
    "AWAITING_REVIEW",
    "AGGREGATING",
    "READY",
    "RUNNING",
    "ARCHIVING",
)
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


_ACTIVE_SLOT_SQL = (
    "SELECT COUNT(*) AS active FROM jobs "
    "WHERE state = ANY(%s) "
    "OR (job_contract_version = 2 AND ("
    "state IN ('QUEUED', 'PREPARING', 'AWAITING_REVIEW', "
    "'READY', 'RUNNING', 'ARCHIVING') "
    "OR (state = 'BLOCKED' AND workflow_synced = false) "
    "OR (state = 'AGGREGATING' AND ("
    "job_kind IS DISTINCT FROM 'family' "
    "OR NOT EXISTS (SELECT 1 FROM jobs child "
    "WHERE child.parent_job_id = jobs.job_id "
    "AND child.job_contract_version = 2 "
    "AND (child.state IN ('QUEUED', 'PREPARING', 'AWAITING_REVIEW', "
    "'AGGREGATING', 'READY', 'RUNNING', 'ARCHIVING') "
    "OR (child.state = 'BLOCKED'"
    " AND child.workflow_synced = false)))))))"
)


def _active_slot_count(connection) -> int:
    """Count rollback drain units on one connection.

    Shared by ``ReleaseStore.active_slots()`` and ``switch()`` so the two
    gates cannot drift. ``switch`` must call this instead of
    ``active_slots()``: the latter opens/uses its own connection scope and
    would re-enter the promotion transaction's advisory lock.
    """
    row = connection.execute(
        _ACTIVE_SLOT_SQL, (list(RELEASE_ACTIVE_STATES),)
    ).fetchone()
    return int(row["active"])


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
        with self._connection() as connection:
            return _active_slot_count(connection)

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
            # Promote and rollback share the same in-transaction drain gate.
            # The switch runs inside the promotion transaction, so checking on
            # this connection (not via active_slots()) keeps the advisory lock
            # single-entry and the check atomic with the release_state write.
            active = _active_slot_count(connection)
            if active != 0:
                raise ReleaseStateError(
                    f"{action} blocked: execution slots not drained "
                    f"(active_slots={active})"
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

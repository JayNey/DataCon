"""LangGraph Supervisor for preparation, review parking and recovery."""

from __future__ import annotations

from copy import deepcopy
import hashlib
import logging
import os
import socket
import time
from typing import Any, Mapping, TypedDict
from uuid import UUID

import psycopg
from langgraph.checkpoint.postgres import PostgresSaver
from langgraph.config import get_config
from langgraph.graph import END, START, StateGraph
from langgraph.types import Command, interrupt

from datacon import contracts
from datacon import evidence
from datacon import execution
from datacon import fuzz as fuzz_rules
from datacon import jsonutil
from datacon import state as state_store
from datacon.agents.analysis import (
    AnalysisBlocked,
    AnalyzedCase,
    RetryableAnalysisError,
    analyze_case,
)
from datacon.cases import CaseConfigurationError, TransientCaseError, load_registry
from datacon.experiment_spec import ExperimentSpecError, parse_experiment_spec
from datacon.orchestration import (
    AdmissionDecision as AdmissionDecision,
    ArchiveRecord as ArchiveRecord,
    AttemptStore as AttemptStore,
    AuditEventRecord as AuditEventRecord,
    AuditEventStore as AuditEventStore,
    BudgetChargeRecord as BudgetChargeRecord,
    BuildDiagnoser as BuildDiagnoser,
    BuildDiagnosis as BuildDiagnosis,
    CampaignResult as CampaignResult,
    CampaignRunner as CampaignRunner,
    ChargeArchiveStore as ChargeArchiveStore,
    ChildExecutionWindow as ChildExecutionWindow,
    ChildRunOutcome as ChildRunOutcome,
    ClockProtocol as ClockProtocol,
    EnvelopePolicy as EnvelopePolicy,
    FAMILY_ORCHESTRATION_EDGES as FAMILY_ORCHESTRATION_EDGES,
    FamilyRunOutcome as FamilyRunOutcome,
    HypothesisAggregationResult as HypothesisAggregationResult,
    HypothesisAggregator as HypothesisAggregator,
    IN_JOB_ORCHESTRATION_EDGES as IN_JOB_ORCHESTRATION_EDGES,
    IdempotencyKey as IdempotencyKey,
    IntelProvider as IntelProvider,
    IntelResult as IntelResult,
    IterationDecision as IterationDecision,
    IterationGate as IterationGate,
    NodeContext as NodeContext,
    NodeReentryLedger as NodeReentryLedger,
    ORCHESTRATION_EDGES as ORCHESTRATION_EDGES,
    ORCHESTRATION_NODES as ORCHESTRATION_NODES,
    OrchestrationEdge as OrchestrationEdge,
    OrchestrationRunner as OrchestrationRunner,
    OrchestrationState as OrchestrationState,
    ReviewDecision as ReviewDecision,
    ReviewGate as ReviewGate,
    SandboxProtocol as SandboxProtocol,
    StepKey as StepKey,
    build_v2_graph as build_v2_graph,
    run_idempotent as run_idempotent,
)
from datacon.tools.source import TransientSourceToolError

logger = logging.getLogger(__name__)


class RetryableWorkflowError(RuntimeError):
    """A recoverable Supervisor or checkpoint infrastructure failure."""


_RETRYABLE_WORKFLOW_ERRORS = (
    RetryableWorkflowError,
    psycopg.OperationalError,
    psycopg.InterfaceError,
    ConnectionError,
    TimeoutError,
    OSError,
)


def _is_retryable_workflow_error(error: BaseException) -> bool:
    return isinstance(error, _RETRYABLE_WORKFLOW_ERRORS)


class SupervisorState(TypedDict):
    job_id: str
    stage: str
    generation: int
    state_version: int
    plan_digest: str | None


def _uuid(value: str) -> UUID:
    return UUID(value)


def _claimed_generation(graph_state: SupervisorState) -> int:
    """Return the generation of the claim that is executing this graph node.

    The checkpoint can still carry the generation that was current when the
    graph parked at the review interrupt. The claim generation is passed
    through the run configuration instead of being replayed as a graph state
    update on every resume, so it is always this invocation's fence.
    """
    configurable = get_config().get("configurable", {})
    generation = configurable.get("datacon_generation")
    if isinstance(generation, int):
        return generation
    return graph_state["generation"]


# Analysis-period blocks that are terminal before execution. They get a
# blocked evidence bundle (no plan/review is available yet). PLAN_MISMATCH and
# ANALYSIS_ERROR are deliberately excluded: the former is not the execution
# terminal and the latter is an internal failure, not a business block.
_BLOCKED_EVIDENCE_REASONS = frozenset(
    {"MATERIAL_MISSING", "SOURCE_CONFLICT", "DEADLINE_EXCEEDED"}
)


def _block_job(
    dsn: str,
    job_id: UUID,
    *,
    generation: int,
    reason_code: str,
    message: str,
    state: str = "BLOCKED",
    event_type: str = "blocked",
) -> None:
    """Commit a block and, when it is a terminal business block, archive it."""
    state_store.block_job(
        dsn,
        job_id,
        generation=generation,
        reason_code=reason_code,
        message=message,
        state=state,
        event_type=event_type,
    )
    if state == "BLOCKED" and reason_code in _BLOCKED_EVIDENCE_REASONS:
        execution.record_blocked(
            dsn,
            job_id,
            generation=generation,
            reason_code=reason_code,
            message=message,
        )


def _reusable_analysis(result: dict[str, Any] | None) -> AnalyzedCase | None:
    """Return a plan draft persisted before a workflow-level retry.

    The draft is only reused for the same execution generation. Its digest is
    recomputed so a legacy or corrupted attempts row can never become the
    frozen plan without re-analysis.
    """
    if not isinstance(result, dict):
        return None
    plan = result.get("plan")
    digest = result.get("plan_digest")
    if not isinstance(plan, dict) or not isinstance(digest, str):
        return None
    try:
        if contracts.plan_digest(plan) != digest:
            return None
        summary = contracts.plan_summary(plan)
    except ValueError:
        return None
    return AnalyzedCase(
        plan=plan,
        plan_digest=digest,
        summary=summary,
        findings=(),
        evidence_refs=frozenset(),
        tool_calls=(),
    )


def build_graph(
    dsn: str,
    checkpointer,
    *,
    case_root: str | None = None,
    contract_version: int = 1,
    **v2_kwargs: Any,
):
    """Compile the Supervisor graph keyed by ``thread_id=job_id``.

    ``contract_version=1`` (default) keeps the frozen v0.1 two-node graph
    (``prepare -> await_review``). ``contract_version=2`` dispatches to the
    v0.2 14-node orchestration graph (:func:`build_v2_graph`).
    """
    if contract_version == 2:
        return build_v2_graph(
            dsn=dsn,
            checkpointer=checkpointer,
            case_root=case_root,
            **v2_kwargs,
        )
    if contract_version != 1:
        raise ValueError(f"unsupported contract_version: {contract_version!r}")
    if v2_kwargs:
        unexpected = ", ".join(sorted(v2_kwargs))
        raise TypeError(
            f"build_graph(contract_version=1) got unexpected keyword argument(s): {unexpected}"
        )

    def prepare(graph_state: SupervisorState) -> dict[str, Any]:
        job_id = _uuid(graph_state["job_id"])
        claimed_generation = _claimed_generation(graph_state)
        job = state_store.load_job(dsn, job_id)
        if job is None:
            return {}
        if job["generation"] != claimed_generation:
            raise state_store.StaleGeneration(
                "execution generation is no longer current"
            )
        if job["state"] in ("READY", "BLOCKED"):
            return {}
        if job["state"] not in ("PREPARING", "AWAITING_REVIEW"):
            return {}

        existing = state_store.get_plan(dsn, job_id)
        if existing is not None:
            # The review window is derived from the database clock, never from
            # this process's wall clock.
            state_store.ensure_awaiting_review(
                dsn, job_id, generation=job["generation"]
            )
            return {"plan_digest": existing["plan_digest"]}

        if state_store.prepare_deadline_passed(
            dsn, job_id, generation=job["generation"]
        ):
            _block_job(
                dsn,
                job_id,
                generation=job["generation"],
                reason_code="DEADLINE_EXCEEDED",
                message="preparation deadline passed before analysis completed",
            )
            return {}

        progress = state_store.analysis_progress(
            dsn, job_id, generation=job["generation"]
        )
        analyzed = _reusable_analysis(progress["completed"])

        def fail_analysis(message: str) -> None:
            """Fail the job closed, retrying the terminal write once.

            ``block_job`` is the fail-closed marker. If it cannot be written
            the caller stays in ``PREPARING`` and the workflow-level retry
            re-enters ``prepare``; that retry relies on the persisted attempt
            and draft history instead of running analysis again.
            """
            last_error: BaseException | None = None
            for _ in range(2):
                try:
                    _block_job(
                        dsn,
                        job_id,
                        generation=job["generation"],
                        reason_code="ANALYSIS_ERROR",
                        message=message,
                        state="FAILED",
                        event_type="failed",
                    )
                    return
                except state_store.StaleGeneration:
                    raise
                except (state_store.StateError, psycopg.Error) as error:
                    last_error = error
            assert last_error is not None
            raise last_error

        if analyzed is not None:
            # A workflow-level retry after freeze_plan failed must reuse the
            # completed analysis instead of executing it a third time.
            attempt_no = max(progress["max_attempt"], 1)
        else:
            if progress["draft_failed"]:
                # A failed draft is fail-closed even if only one attempt was
                # consumed: re-running analysis cannot repair the missing
                # draft within this generation.
                fail_analysis(
                    "analysis draft failed; failing closed without "
                    "re-running analysis"
                )
                return {}
            if progress["max_attempt"] >= 2:
                fail_analysis(
                    "analysis already consumed both attempts for this "
                    "execution generation"
                )
                return {}
            attempt_no = progress["max_attempt"] + 1

            def recorder(attempt: int):
                def record_tool(
                    tool_id: str,
                    step_key: str,
                    params: dict[str, Any],
                    result_digest: str,
                ) -> None:
                    stored = state_store.record_attempt(
                        dsn,
                        job_id,
                        stage="prepare",
                        step_key=step_key,
                        attempt_no=attempt,
                        generation=job["generation"],
                        input_digest=jsonutil.digest_json(params),
                        status="completed",
                        result={"tool_id": tool_id, "result_digest": result_digest},
                    )
                    if not stored:
                        # A rejected audit row means the lease or generation is
                        # gone. Stop the analysis instead of finishing with an
                        # incomplete ledger that the next worker would redo.
                        raise state_store.StaleGeneration(
                            "the worker lease was lost while recording the "
                            "tool attempt"
                        )

                return record_tool

            def start_attempt(attempt: int) -> None:
                """Reserve the attempt before ``analyze_case`` runs.

                The row is written even when the analysis later fails, so a
                workflow-level retry derives the next attempt number from
                durable history and cannot silently execute a third time. A
                failed reservation is never treated as success: the lease
                check returning ``False`` raises ``StaleGeneration`` and the
                analysis does not start.
                """
                stored = state_store.record_attempt(
                    dsn,
                    job_id,
                    stage="prepare",
                    step_key="analysis",
                    attempt_no=attempt,
                    generation=job["generation"],
                    input_digest=jsonutil.digest_json(job["request"]),
                    status="started",
                )
                if not stored:
                    raise state_store.StaleGeneration(
                        "the worker lease was lost before the analysis started"
                    )

            def committed_draft() -> AnalyzedCase | None:
                """Read the durable draft after an ambiguous write failure."""
                try:
                    current = state_store.analysis_progress(
                        dsn, job_id, generation=job["generation"]
                    )
                except (state_store.StateError, psycopg.Error):
                    return None
                return _reusable_analysis(current["completed"])

            def persist_draft(attempt: int, analyzed: AnalyzedCase) -> bool:
                """Persist the analysis draft used by a workflow-level retry.

                The draft is the only way a retry can freeze the plan without
                running analysis a third time, so a write failure cannot be
                ignored. One bounded retry absorbs a transient connection
                reset. If the connection dropped after the server committed
                the ``completed`` row, that row is reused rather than
                downgraded to ``infra_error``. If the draft truly is not
                stored, the step fails closed and the attempt history stays
                truthful.
                """
                result = {
                    "plan_digest": analyzed.plan_digest,
                    "plan": analyzed.plan,
                    "summary": analyzed.summary,
                }
                last_error: BaseException | None = None
                for _ in range(2):
                    try:
                        stored = state_store.record_attempt(
                            dsn,
                            job_id,
                            stage="prepare",
                            step_key="analysis",
                            attempt_no=attempt,
                            generation=job["generation"],
                            input_digest=jsonutil.digest_json(job["request"]),
                            status="completed",
                            result=result,
                        )
                    except (state_store.StateError, psycopg.Error) as error:
                        last_error = error
                        continue
                    if stored:
                        return True
                    # ``record_attempt`` returned False: the lease check or the
                    # completed-row guard rejected the write. Do not continue
                    # analyzing as if the draft were persisted.
                    raise state_store.StaleGeneration(
                        "the worker lease was lost before the analysis draft "
                        "was stored"
                    )
                # The client may have lost the connection after the server
                # committed the completed row. Never overwrite that row with
                # infra_error; reuse it when it carries this exact draft.
                committed = committed_draft()
                if (
                    committed is not None
                    and committed.plan_digest == analyzed.plan_digest
                ):
                    return True
                assert last_error is not None
                marked = False
                try:
                    marked = state_store.record_attempt(
                        dsn,
                        job_id,
                        stage="prepare",
                        step_key="analysis",
                        attempt_no=attempt,
                        generation=job["generation"],
                        input_digest=jsonutil.digest_json(job["request"]),
                        status="infra_error",
                        result={
                            "error": type(last_error).__name__,
                            "phase": "analysis_draft",
                        },
                    )
                except (state_store.StateError, psycopg.Error):
                    marked = False
                if not marked:
                    # The marker write was not applied. The reserved attempt
                    # row still accounts for this execution; re-check the
                    # durable draft and otherwise fail closed instead of
                    # starting another analysis.
                    committed = committed_draft()
                    if (
                        committed is not None
                        and committed.plan_digest == analyzed.plan_digest
                    ):
                        return True
                fail_analysis(
                    "analysis succeeded but its plan draft could not be "
                    "persisted"
                )
                return False

            def retry_or_stop(attempt: int, error: BaseException) -> bool:
                recorded = state_store.record_attempt(
                    dsn,
                    job_id,
                    stage="prepare",
                    step_key="analysis",
                    attempt_no=attempt,
                    generation=job["generation"],
                    input_digest=jsonutil.digest_json(job["request"]),
                    status="infra_error",
                    result={"error": type(error).__name__},
                )
                if not recorded:
                    raise state_store.StaleGeneration(
                        "the worker lease was lost before the retry"
                    )
                if attempt >= 2:
                    fail_analysis(
                        "analysis failed after one retry with "
                        f"{type(error).__name__}"
                    )
                    return False
                if state_store.prepare_deadline_passed(
                    dsn, job_id, generation=job["generation"]
                ):
                    _block_job(
                        dsn,
                        job_id,
                        generation=job["generation"],
                        reason_code="DEADLINE_EXCEEDED",
                        message="preparation deadline passed before the analysis retry",
                    )
                    return False
                return True

            while analyzed is None:
                if attempt_no > 2:
                    # Hard cap: the started rows above already account for the
                    # consumed attempts, so this is only a defensive guard.
                    fail_analysis(
                        "analysis already consumed both attempts for this "
                        "execution generation"
                    )
                    return {}
                start_attempt(attempt_no)
                try:
                    analyzed = analyze_case(
                        job["request"],
                        case_root=case_root,
                        recorder=recorder(attempt_no),
                    )
                except state_store.StaleGeneration:
                    raise
                except AnalysisBlocked as error:
                    _block_job(
                        dsn,
                        job_id,
                        generation=job["generation"],
                        reason_code=error.reason_code,
                        message=error.message,
                    )
                    return {}
                except (
                    RetryableAnalysisError,
                    TransientSourceToolError,
                    TransientCaseError,
                ) as error:
                    if not retry_or_stop(attempt_no, error):
                        return {}
                    attempt_no += 1
                    continue
                except (
                    psycopg.OperationalError,
                    psycopg.InterfaceError,
                    ConnectionError,
                    TimeoutError,
                    OSError,
                ) as error:
                    if not retry_or_stop(attempt_no, error):
                        return {}
                    attempt_no += 1
                    continue
                except Exception as error:  # noqa: BLE001 - sanitized below
                    _block_job(
                        dsn,
                        job_id,
                        generation=job["generation"],
                        reason_code="ANALYSIS_ERROR",
                        message=f"analysis failed with {type(error).__name__}",
                        state="FAILED",
                        event_type="failed",
                    )
                    return {}
                # Persist the draft before freezing the plan so a later
                # workflow retry can reuse it. A same-generation attempt
                # number is never reused, which keeps the history auditable.
                if not persist_draft(attempt_no, analyzed):
                    return {}

        try:
            frozen = state_store.freeze_plan(
                dsn,
                job_id,
                generation=job["generation"],
                plan=analyzed.plan,
                plan_digest=analyzed.plan_digest,
                summary=analyzed.summary,
            )
        except state_store.PlanConflict:
            _block_job(
                dsn,
                job_id,
                generation=job["generation"],
                reason_code="PLAN_MISMATCH",
                message="a different plan was already frozen for this job",
            )
            return {}
        if not frozen:
            return {}
        stored = state_store.record_attempt(
            dsn,
            job_id,
            stage="prepare",
            step_key="plan",
            attempt_no=attempt_no,
            generation=job["generation"],
            input_digest=analyzed.plan["analysis_digest"],
            status="completed",
            result={
                "plan_digest": analyzed.plan_digest,
                "summary": analyzed.summary,
            },
        )
        if not stored:
            # The plan is frozen, but this worker no longer owns a live lease.
            # Stop before parking the review so the next claim reads the
            # existing plan instead of replaying a stale scheduling pass.
            raise state_store.StaleGeneration(
                "the worker lease was lost before the plan attempt was recorded"
            )
        return {
            "plan_digest": analyzed.plan_digest,
            "generation": job["generation"],
            "stage": "review",
            "state_version": graph_state["state_version"] + 1,
        }

    def await_review(graph_state: SupervisorState) -> dict[str, Any]:
        job_id = _uuid(graph_state["job_id"])
        claimed_generation = _claimed_generation(graph_state)
        job = state_store.load_job(dsn, job_id)
        if job is None:
            return {}
        if job["generation"] != claimed_generation:
            raise state_store.StaleGeneration(
                "execution generation is no longer current"
            )
        if job["state"] == "AWAITING_REVIEW":
            if state_store.expire_review(dsn, job_id, claimed_generation):
                return {}
            review = state_store.get_review(dsn, job_id)
            if review is None:
                plan = state_store.get_plan(dsn, job_id)
                interrupt(
                    {
                        "job_id": graph_state["job_id"],
                        "plan_digest": plan["plan_digest"] if plan else None,
                        "review_deadline_at": (
                            jsonutil.timestamp(job["review_deadline_at"])
                            if job["review_deadline_at"]
                            else None
                        ),
                    }
                )
                # LangGraph re-enters this node from the start after a resume.
                # The database record is authoritative: if the job is still
                # awaiting review, this scheduling pass ends without creating a
                # second interrupt (which would leave conflicting pending
                # writes in the checkpoint). A later decision resets
                # workflow_synced so the next worker reconciles the graph again.
                job = state_store.load_job(dsn, job_id)
                if job is None:
                    return {}
                if job["generation"] != claimed_generation:
                    # A review, expiry, or takeover advanced the generation
                    # while this worker was parked at the interrupt. Do not
                    # write the checkpoint or any business state with the
                    # stale claim; the next claim converges instead.
                    raise state_store.StaleGeneration(
                        "execution generation is no longer current"
                    )
                if job["state"] == "AWAITING_REVIEW":
                    if state_store.expire_review(dsn, job_id, claimed_generation):
                        return {}
                    if state_store.get_review(dsn, job_id) is None:
                        return {"generation": claimed_generation}
        if job["state"] in ("READY", "BLOCKED"):
            plan = state_store.get_plan(dsn, job_id)
            review = state_store.get_review(dsn, job_id)
            if (
                plan is not None
                and review is not None
                and review["plan_digest"] != plan["plan_digest"]
            ):
                _block_job(
                    dsn,
                    job_id,
                    generation=claimed_generation,
                    reason_code="PLAN_MISMATCH",
                    message="the recorded review does not match the frozen plan",
                )
        return {"generation": claimed_generation}

    def route(state: SupervisorState) -> str:
        job = state_store.load_job(dsn, _uuid(state["job_id"]))
        if job is not None and job["state"] in ("AWAITING_REVIEW", "READY"):
            return "await_review"
        return "done"

    builder = StateGraph(SupervisorState)
    builder.add_node("prepare", prepare)
    builder.add_node("await_review", await_review)
    builder.add_edge(START, "prepare")
    builder.add_conditional_edges(
        "prepare", route, {"await_review": "await_review", "done": END}
    )
    builder.add_edge("await_review", END)
    return builder.compile(checkpointer=checkpointer)


# §10 dispositions for a denied derived round. A denial blocks only that round
# and keeps its reason code. The normal path never reaches admission with an
# exhausted budget: ``derive_and_admit_round`` gates budget and max_rounds
# before creating the child (改9). Only in an extreme race (the ledger moved
# between that gate and the admission predicate) can the predicate still deny
# with BUDGET_EXHAUSTED; that is not a BLOCKED reason, so the already-created
# round is closed as ADMISSION_DENIED with the precise sub_reason on the
# round_admission_denied audit. A failed or crashed admission also fails
# closed as ADMISSION_DENIED: no admission was granted.
_DENIED_ROUND_BLOCK_REASONS = frozenset(
    {"ADMISSION_DENIED", "ENVELOPE_VIOLATION", "HARNESS_REJECTED"}
)


def _block_derived_round(
    dsn: str,
    job_id: UUID,
    *,
    reason_code: str,
    message: str,
    run_root: str | None,
) -> None:
    if state_store.block_round_child(
        dsn, job_id, reason_code=reason_code, message=message
    ):
        execution.record_blocked(
            dsn,
            job_id,
            reason_code=reason_code,
            message=message,
            generation=0,
            run_root=run_root,
        )


def _admit_derived_round(
    dsn: str,
    *,
    job_id: UUID,
    family_id: UUID | str,
    round_no: int,
    admission_inputs: Any,
    run_root: str | None,
) -> dict[str, Any]:
    """Run ``record_admission`` for a derived READY round; fail closed on deterministic errors.

    S3: if the round already has an admission row (including when a concurrent
    admission committed before a stale recovery retry), return it as admitted
    and never block the round.
    S5: transient ``psycopg.Error`` propagates without blocking the round so
    ``recover_unadmitted_rounds`` can retry after the 300 s grace window,
    matching the worker's existing DB-error propagation contract.
    """
    existing_admission = state_store.get_admission(dsn, job_id)
    if existing_admission is not None:
        current = state_store.load_job(dsn, job_id)
        return {
            "job_id": str(job_id),
            "derived": True,
            "state": current["state"] if current else "READY",
            "admitted": True,
            "reason_code": None,
            "sub_reason": "ROUND_ALREADY_ADMITTED",
            "admission": existing_admission,
        }
    try:
        if not isinstance(admission_inputs, dict):
            raise state_store.StateError(
                "the derived round has no persisted admission inputs"
            )
        budget_snapshot = state_store.family_budget_summary(dsn, family_id)
        outcome = state_store.record_admission(
            dsn,
            family_id=family_id,
            job_id=job_id,
            round_no=round_no,
            envelope=admission_inputs["envelope"],
            seed_digest=admission_inputs["seed_digest"],
            budget_snapshot=budget_snapshot,
            experiment=admission_inputs.get("experiment"),
            recomputable=admission_inputs.get("recomputable", True),
            campaign_bundle_digest=admission_inputs.get("campaign_bundle_digest"),
        )
    except psycopg.Error:
        # S5: do not permanently block a round on a transient database failure;
        # leave it READY so recover_unadmitted_rounds retries after the grace
        # window. Propagate consistently with run_worker's DB-error semantics.
        raise
    except (state_store.StateError, KeyError, TypeError) as error:
        message = f"round {round_no} admission failed: {error}"
        _block_derived_round(
            dsn,
            job_id,
            reason_code="ADMISSION_DENIED",
            message=message,
            run_root=run_root,
        )
        current = state_store.load_job(dsn, job_id)
        return {
            "job_id": str(job_id),
            "derived": True,
            "state": current["state"] if current else None,
            "admitted": False,
            "reason_code": "ADMISSION_DENIED",
            "sub_reason": None,
            "error": str(error),
        }
    if outcome.admitted or outcome.status == "already_admitted":
        return {
            "job_id": str(job_id),
            "derived": True,
            "state": "READY",
            "admitted": True,
            "reason_code": None,
            "sub_reason": None,
            "admission": outcome.admission,
        }
    if outcome.sub_reason == "ROUND_ALREADY_ADMITTED":
        existing_admission = state_store.get_admission(dsn, job_id)
        if existing_admission is not None:
            current = state_store.load_job(dsn, job_id)
            return {
                "job_id": str(job_id),
                "derived": True,
                "state": current["state"] if current else "READY",
                "admitted": True,
                "reason_code": None,
                "sub_reason": "ROUND_ALREADY_ADMITTED",
                "admission": existing_admission,
            }
    reason_code = (
        outcome.reason_code
        if outcome.reason_code in _DENIED_ROUND_BLOCK_REASONS
        else "ADMISSION_DENIED"
    )
    message = (
        f"round {round_no} admission denied: {outcome.reason_code}"
        + (f" ({outcome.sub_reason})" if outcome.sub_reason else "")
    )
    _block_derived_round(
        dsn, job_id, reason_code=reason_code, message=message, run_root=run_root
    )
    current = state_store.load_job(dsn, job_id)
    return {
        "job_id": str(job_id),
        "derived": True,
        "state": current["state"] if current else None,
        "admitted": False,
        "reason_code": reason_code,
        "sub_reason": outcome.sub_reason,
    }


def derive_and_admit_round(
    dsn: str,
    *,
    family_id: UUID | str,
    round_no: int,
    plan: dict[str, Any],
    envelope: dict[str, Any],
    seed_digest: str,
    experiment: dict[str, Any] | None = None,
    recomputable: bool = True,
    campaign_bundle_digest: str | None = None,
    run_root: str | None = None,
) -> dict[str, Any]:
    """Family-level transition #23/#26: gate, derive the next round, admit it.

    Order (改9): ``state.check_round_derivation`` first (serial children,
    ``max_rounds``, total and — for guided — fuzz budget); a refused
    transition creates nothing and the family archives through
    ``converge_families``. Only then is the ``job_kind=round`` child created
    with its frozen plan and persisted admission inputs, and
    ``state.record_admission`` runs before anything executes. An admitted
    round stays ``READY`` and becomes claimable through the v2 claim gate; a
    denied or failed admission blocks and archives the round, so it never
    starts a container. The human-approved first plan never comes through
    here. A crash between child creation and admission is recovered by
    ``recover_unadmitted_rounds``.
    """
    gate = state_store.check_round_derivation(
        dsn, family_id=family_id, round_no=round_no
    )
    if not gate.allowed:
        return {
            "job_id": None,
            "derived": False,
            "state": None,
            "admitted": False,
            "reason_code": gate.reason_code,
            "sub_reason": gate.sub_reason,
        }
    admission_inputs = {
        "envelope": envelope,
        "seed_digest": seed_digest,
        "experiment": experiment,
        "recomputable": recomputable,
        "campaign_bundle_digest": campaign_bundle_digest,
    }
    child = state_store.create_round_child(
        dsn,
        family_id=family_id,
        round_no=round_no,
        plan=plan,
        admission_inputs=admission_inputs,
    )
    job_id = UUID(child["job_id"])
    if child["state"] != "READY":
        # Re-entry after the round already left the admission phase.
        return {
            "job_id": child["job_id"],
            "derived": True,
            "state": child["state"],
            "admitted": None,
            "reason_code": None,
            "sub_reason": None,
        }
    return _admit_derived_round(
        dsn,
        job_id=job_id,
        family_id=family_id,
        round_no=round_no,
        admission_inputs=admission_inputs,
        run_root=run_root,
    )


def recover_unadmitted_rounds(
    dsn: str,
    *,
    grace_seconds: int = state_store.ROUND_ADMISSION_RECOVERY_GRACE_SECONDS,
    run_root: str | None = None,
) -> int:
    """Worker scan: finish rounds a crash left between creation and admission.

    Each stuck ``READY``/``stage='admission'`` round older than the grace
    window is admitted again from the inputs persisted with its plan
    (``record_admission`` is idempotent); a denial or a failure blocks and
    archives it. Returns the number of rounds handled.
    """
    handled = 0
    for row in state_store.unadmitted_round_children(
        dsn, grace_seconds=grace_seconds
    ):
        # S3: re-confirm in a transaction that the round still has no admission
        # before retrying, so an admission that committed after the listing
        # query is never raced or blocked.
        if not state_store.round_needs_admission_recovery(dsn, row["job_id"]):
            continue
        raw_summary = row.get("summary")
        summary: dict[str, Any] = raw_summary if isinstance(raw_summary, dict) else {}
        _admit_derived_round(
            dsn,
            job_id=row["job_id"],
            family_id=row["family_id"],
            round_no=row["round_no"],
            admission_inputs=summary.get("admission_inputs"),
            run_root=run_root,
        )
        handled += 1
    return handled


def recover_unarchived_blocked_rounds(
    dsn: str,
    *,
    run_root: str | None = None,
) -> int:
    """Worker scan (B4): idempotently archive BLOCKED rounds left unarchived after a crash.

    A crash or I/O error between ``block_round_child`` and
    ``execution.record_blocked`` leaves a derived round ``BLOCKED`` with
    ``evidence_status IS NULL``. Running this scan before ``converge_families``
    guarantees every blocked round gets its archived blocked bundle before the
    family is evaluated for convergence. Transient database errors propagate
    consistently with the other worker sweeps.
    """
    archived = 0
    for row in state_store.unarchived_blocked_round_children(dsn):
        reason_code = row.get("reason_code") or "ADMISSION_DENIED"
        message = (
            row.get("last_error")
            or f"round {row.get('round_no')} blocked: {reason_code}"
        )
        if execution.record_blocked(
            dsn,
            row["job_id"],
            reason_code=reason_code,
            message=message,
            generation=row["generation"],
            run_root=run_root,
        ):
            archived += 1
    return archived


# ---------------------------------------------------------------------------
# T12 B1 (改8/改9): family-level transitions after a campaign or a round.
# ---------------------------------------------------------------------------

_TERMINAL_CHILD_STATES = frozenset(
    {"COMPLETED", "REPRODUCED", "NOT_REPRODUCED", "INCONCLUSIVE", "BLOCKED", "FAILED"}
)
_POLICY_DENIED_REASONS = frozenset(
    {"ENVELOPE_VIOLATION", "ADMISSION_DENIED", "HARNESS_REJECTED"}
)


def _verified_campaign_bundle(campaign: Mapping[str, Any]) -> Any:
    """The campaign's archived bundle, verified offline and digest-bound, or None."""
    path = campaign.get("evidence_path")
    if campaign.get("evidence_status") != "archived" or not isinstance(path, str):
        return None
    try:
        verified = evidence.verify_bundle(path)
    except (evidence.BundleError, OSError):
        return None
    if evidence.canonical_manifest_digest(verified.manifest) != campaign.get(
        "evidence_digest"
    ):
        return None
    if verified.manifest.get("bundle_kind") != "campaign":
        return None
    return verified


def campaign_candidate_seeds(campaign: Mapping[str, Any]) -> list[dict[str, Any]] | None:
    """Return the campaign's frozen crash seeds from its verified bundle.

    The archived campaign bundle is the only source: it is verified offline,
    its manifest digest must equal the job's ``evidence_digest``, and every
    seed must carry complete provenance bound to its bytes and this campaign.
    Returns None when the bundle cannot be trusted (no decision is taken).
    """
    verified = _verified_campaign_bundle(campaign)
    if verified is None:
        return None
    raw = verified.file_data.get(fuzz_rules.FUZZ_PROVENANCE_PATH)
    if raw is None:
        return None
    try:
        provenance = jsonutil.loads_strict(raw)
    except ValueError:
        return None
    records = provenance.get("crash_seeds") if isinstance(provenance, Mapping) else None
    if not isinstance(records, list):
        return None
    seeds: list[dict[str, Any]] = []
    log = verified.file_data.get(fuzz_rules.FUZZ_LOG_PATH, b"")
    for record in records:
        path_value = record.get("path") if isinstance(record, Mapping) else None
        data = (
            verified.file_data.get(path_value) if isinstance(path_value, str) else None
        )
        try:
            checked = fuzz_rules.validate_crash_seed_record(
                record,
                data=data,
                campaign_job_id=str(campaign["job_id"]),
            )
        except ValueError:
            return None
        if data is None:
            return None
        # The validated provenance record stays exactly as archived; the
        # fuzz-log line used for the ExperimentSpec ref lives beside it.
        seeds.append(
            {
                "sha256": checked["sha256"],
                "campaign_job_id": checked["campaign_job_id"],
                "log_line": _crash_log_line(log, data),
                "record": checked,
            }
        )
    return seeds


def _crash_log_line(log: bytes, data: bytes) -> int:
    """The fuzz log line that names this crash (libFuzzer ``crash-<sha1>``)."""
    marker = ("crash-" + hashlib.sha1(data).hexdigest()).encode("ascii")
    for number, line in enumerate(log.splitlines(), start=1):
        if marker in line:
            return number
    return 1


def _round_experiment(
    plan: Mapping[str, Any],
    envelope: Mapping[str, Any],
    seed: Mapping[str, Any],
) -> dict[str, Any]:
    """The ExperimentSpec for validating one campaign crash seed (§4)."""
    analysis = plan.get("analysis")
    symbols = analysis.get("symbols") if isinstance(analysis, Mapping) else None
    symbol = next(
        (
            item
            for item in (symbols or [])
            if isinstance(item, Mapping) and item.get("role") == "definition"
        ),
        (symbols or [None])[0],
    )
    if not isinstance(symbol, Mapping):
        raise ValueError("the campaign plan names no target symbol")
    families = envelope.get("allowed_mutation_families")
    limits = envelope.get("mutation_limits")
    if not families or not isinstance(limits, Mapping):
        raise ValueError("the envelope allows no mutation family")
    experiment = {
        "target_symbol": symbol["name"],
        "target_path": symbol["path"],
        "target_line": symbol.get("start_line", 1),
        "input_family": families[0],
        "mutation_constraints": {
            "allowed_ops": list(limits["allowed_ops"]),
            "max_input_bytes": limits["max_input_bytes"],
        },
        "expected_signature": dict(plan["asan_signature"]),
        "rationale": (
            "validate campaign crash seed "
            f"{seed['sha256']} from campaign {seed['campaign_job_id']}"
        ),
        "evidence_refs": [f"log/fuzz:0#L{seed.get('log_line', 1)}"],
        "confidence": "medium",
    }
    parse_experiment_spec(experiment)
    return experiment


def _round_plan(
    campaign_plan: Mapping[str, Any],
    *,
    round_no: int,
    approval_tail: Mapping[str, Any],
    envelope: Mapping[str, Any],
    normal_digest: str,
    seed_digest: str,
    experiment_digest: str,
    build_ref: Mapping[str, Any],
) -> dict[str, Any]:
    """Derive the next round's frozen plan from the human-approved campaign plan.

    Only the round identity, the approval chain tail, the inputs and the
    experiment change; build, case and policy bindings are the approved ones.
    ``build_ref`` (stage C) binds the campaign's parser and fuzzer per
    version so the round reuses them and never rebuilds.
    """
    plan = deepcopy(dict(campaign_plan))
    plan.update(
        {
            "round_no": round_no,
            "parent_approval_digest": approval_tail["approval_digest"],
            "envelope_digest": approval_tail["envelope_digest"],
            "harness_digest": envelope["harness_digest"],
            "inputs": {"normal": normal_digest, "candidate": seed_digest},
            "experiment_digest": experiment_digest,
            "build_ref": deepcopy(dict(build_ref)),
        }
    )
    contracts.plan_digest(plan)
    return plan


def _transition_point(
    snapshot: Mapping[str, Any],
) -> tuple[int, Mapping[str, Any]] | None:
    """Return ``(after_round_no, campaign)`` when the family stands at a point."""
    campaigns = snapshot["campaigns"]
    if len(campaigns) != 1:
        return None
    campaign = campaigns[0]
    if campaign["state"] != "COMPLETED" or campaign["evidence_status"] != "archived":
        return None
    children = snapshot["children"]
    if any(
        child["state"] not in _TERMINAL_CHILD_STATES
        or (child["state"] == "BLOCKED" and not child["workflow_synced"])
        or (child["job_kind"] == "round" and child["evidence_status"] is None)
        for child in children
    ):
        return None
    rounds = sorted(
        (child for child in children if child["job_kind"] == "round"),
        key=lambda child: child["round_no"],
    )
    if not rounds:
        return 0, campaign
    last = rounds[-1]
    policy_denied = (
        last["state"] == "BLOCKED"
        and last["reason_code"] in _POLICY_DENIED_REASONS
        and str(last["job_id"]) not in snapshot["admitted_job_ids"]
    )
    if last["state"] != "INCONCLUSIVE" and not policy_denied:
        # A verdict, a failure or a non-policy block: convergence decides.
        return None
    return int(last["round_no"]), campaign


def _normal_input_digest(campaign_plan: Mapping[str, Any], case_root: str | None) -> str:
    registry = load_registry(case_root)
    case = registry.case(campaign_plan["case_id"])
    relative = case.manifest_case["inputs"]["normal"]
    return jsonutil.require_digest(
        case.manifest["materials"][relative], "normal input digest"
    )


def advance_family_transition(
    dsn: str,
    family_id: UUID | str,
    *,
    case_root: str | None = None,
    run_root: str | None = None,
) -> dict[str, Any] | None:
    """Take the family-level decision at the family's current decision point.

    Edge #23/#24 (``after_round_no=0``, after the campaign archived) and edge
    #26 (``after_round_no=k``, after round k archived INCONCLUSIVE or was
    policy-denied) share this one entry. With a remaining candidate seed the
    runtime gates the derivation (``check_round_derivation``), records
    ``next_round`` and derives + admits round k+1 through
    ``derive_and_admit_round``; with no seed left it records
    ``no_next_round`` (``NO_CANDIDATE_SEED`` at 0, ``NO_REMAINING_SEEDS``
    after a round) and ``converge_families`` archives the family.

    The decision is recorded *before* the child: ``_check_transition_point``
    accepts a point only while no later round exists, so recording after the
    child would always be refused. Re-entry is idempotent: a recorded
    ``no_next_round`` is final, a recorded ``next_round`` whose round is
    missing (crash between the two writes) re-derives exactly the same
    deterministic plan, and an existing child is never duplicated.
    """
    family_uuid = UUID(str(family_id))
    snapshot = state_store.family_transition_inputs(dsn, family_uuid)
    if snapshot is None or snapshot["family"]["state"] != "AGGREGATING":
        return None
    if snapshot["pending_envelope"]:
        return None
    point = _transition_point(snapshot)
    if point is None:
        return None
    after_round_no, campaign = point
    campaign_id = UUID(str(campaign["job_id"]))
    seeds = campaign_candidate_seeds(campaign)
    if seeds is None:
        logger.warning("campaign %s bundle is not trustworthy; no transition", campaign_id)
        return None
    remaining = len(seeds) - after_round_no
    next_round_no = after_round_no + 1
    existing = state_store.family_transition_decision(
        dsn, family_uuid, campaign_job_id=campaign_id, after_round_no=after_round_no
    )
    if existing is not None and existing["decision"] == "no_next_round":
        return {"decision": existing, "derived": None}
    if existing is None and remaining <= 0:
        decision = state_store.record_family_transition_decision(
            dsn,
            family_uuid,
            campaign_job_id=campaign_id,
            after_round_no=after_round_no,
            decision="no_next_round",
            reason_code=(
                "NO_CANDIDATE_SEED" if after_round_no == 0 else "NO_REMAINING_SEEDS"
            ),
            candidate_seed_count=0,
        )
        return {"decision": decision, "derived": None}
    if remaining <= 0:
        # A stored next_round that the seeds cannot back: never invent one.
        return {"decision": existing, "derived": None}
    envelope = snapshot["envelope"]
    tail = snapshot["approval_tail"]
    campaign_plan = snapshot["campaign_plan"]
    if not isinstance(envelope, Mapping) or tail is None or not isinstance(
        campaign_plan, Mapping
    ):
        return None
    seed = seeds[after_round_no]
    verified = _verified_campaign_bundle(campaign)
    if verified is None:
        return None
    try:
        build_ref = execution.campaign_build_ref(
            verified.file_data,
            campaign_job_id=str(campaign_id),
            plan=campaign_plan,
        )
        experiment = _round_experiment(campaign_plan, envelope, seed)
        plan = _round_plan(
            campaign_plan,
            round_no=next_round_no,
            approval_tail=tail,
            envelope=envelope,
            normal_digest=_normal_input_digest(campaign_plan, case_root),
            seed_digest=seed["sha256"],
            experiment_digest=jsonutil.digest_json(experiment),
            build_ref=build_ref,
        )
    except (CaseConfigurationError, ExperimentSpecError, KeyError, TypeError, ValueError) as error:
        logger.warning("family %s cannot derive round %s: %s", family_uuid, next_round_no, error)
        return None
    if existing is None:
        gate = state_store.check_round_derivation(
            dsn, family_id=family_uuid, round_no=next_round_no
        )
        if not gate.allowed:
            # Rounds or budget exhausted: convergence archives the family; any
            # other refusal (child not terminal, pending envelope) is retried.
            return {"decision": None, "derived": None, "gate": gate.sub_reason}
        existing = state_store.record_family_transition_decision(
            dsn,
            family_uuid,
            campaign_job_id=campaign_id,
            after_round_no=after_round_no,
            decision="next_round",
            candidate_seed_count=remaining,
            next_round_no=next_round_no,
        )
    derived = derive_and_admit_round(
        dsn,
        family_id=family_uuid,
        round_no=next_round_no,
        plan=plan,
        envelope=dict(envelope),
        seed_digest=seed["sha256"],
        experiment=experiment,
        recomputable=True,
        campaign_bundle_digest=campaign["evidence_digest"],
        run_root=run_root,
    )
    return {"decision": existing, "derived": derived}


def advance_family_transitions(
    dsn: str, *, case_root: str | None = None, run_root: str | None = None
) -> int:
    """Worker sweep: take every pending guided family decision (crash-safe)."""
    advanced = 0
    for family_id in state_store.guided_aggregating_families(dsn):
        try:
            outcome = advance_family_transition(
                dsn, family_id, case_root=case_root, run_root=run_root
            )
        except state_store.StateError as error:
            # A decision the family state no longer admits (for example a
            # concurrent writer moved the point): skip, the next sweep re-reads.
            logger.warning("family %s transition skipped: %s", family_id, error)
            continue
        if outcome is not None and (
            outcome.get("decision") is not None or outcome.get("derived") is not None
        ):
            advanced += 1
    return advanced


def _sync_v2_claim(
    dsn: str, claimed: dict[str, Any], *, run_root: str | None
) -> dict[str, Any]:
    """Synchronize a claimed v2 row that has nothing to execute.

    The v1 LangGraph Supervisor never runs a v2 row. A v2 claim that is not an
    execution (an unsynchronized BLOCKED family or child) only needs its
    blocked bundle archived when it has none, then its lease released.
    """
    job_id = claimed["job_id"]
    generation = claimed["generation"]
    if claimed["state"] == "AWAITING_REVIEW":
        # Same entry as the v1 Supervisor's await_review node: an expired
        # first-plan window converges to REVIEW_EXPIRED (and its family).
        try:
            state_store.expire_review(dsn, job_id, generation)
        except state_store.StaleGeneration:
            pass
    elif claimed["state"] == "BLOCKED" and claimed.get("evidence_status") is None:
        try:
            execution.record_blocked(
                dsn,
                job_id,
                reason_code=claimed.get("reason_code") or "INVALID_STATE",
                message=claimed.get("last_error") or "v2 job blocked",
                generation=generation,
                run_root=run_root,
            )
        except state_store.StateError:
            pass
    try:
        state_store.finalize_workflow(dsn, job_id, generation)
    except state_store.StateError:
        pass
    job = state_store.load_job(dsn, job_id)
    return {
        "processed": 1,
        "job_id": str(job_id),
        "state": job["state"] if job else None,
        "workflow": "synchronized",
    }


def _worker_id() -> str:
    return os.getenv("DATACON_WORKER_ID") or f"{socket.gethostname()}:{os.getpid()}"


def run_worker(
    dsn: str,
    *,
    once: bool = True,
    poll_seconds: float = 2.0,
    case_root: str | None = None,
    lease_seconds: int = state_store.LEASE_SECONDS,
    execute: bool = True,
    run_root: str | None = None,
) -> dict[str, Any]:
    execution.validate_test_hooks()
    worker = _worker_id()
    with PostgresSaver.from_conn_string(dsn) as checkpointer:
        checkpointer.setup()
        graph = build_graph(dsn, checkpointer, case_root=case_root)
        while True:
            # A changed-envelope re-approval parks on the family, not on a
            # child, so the claim path alone would never observe its deadline.
            # Sweep before claiming on every poll; a database error propagates
            # with the existing worker error semantics instead of being
            # swallowed.
            expired_envelopes = state_store.expire_pending_envelopes(dsn)
            # T12 改9 crash recovery runs BEFORE family sealing (B3): recover
            # uncharged attempts and unadmitted rounds first so family.json
            # never freezes a stale pre-recovery budget or prematurely seals.
            recovered_charges = state_store.recover_uncharged_attempts(dsn)
            recovered_rounds = recover_unadmitted_rounds(dsn, run_root=run_root)
            recovered_blocked_rounds = recover_unarchived_blocked_rounds(
                dsn, run_root=run_root
            )
            # T12 B1: take pending family decisions (campaign point and
            # round points) before sealing, so a family with a remaining seed
            # derives its next round and a seedless one records no_next_round.
            # Re-running the sweep after a crash is idempotent.
            transitions = advance_family_transitions(
                dsn, case_root=case_root, run_root=run_root
            )
            # T12/D43 crash-recovery sweep: converge families whose children
            # are terminal, archived, and whose charges are accounted for.
            family_sweep = state_store.converge_families_detailed(dsn)
            claimed = state_store.claim_next(
                dsn, worker, lease_seconds=lease_seconds, execute=execute
            )
            claimed_v2 = False
            if claimed is None:
                # v2 children (campaign/round) are claimed through the v2 gate
                # after v1 work: one claim per poll keeps the single execution
                # slot, and the gate keeps release/lease/generation rules.
                # Only execution claims depend on ``execute``; v2 sync and
                # review expiry run for every worker. The worker scope never
                # claims a v2 row it cannot finish (P2 B6).
                claimed = state_store.claim_next(
                    dsn,
                    worker,
                    lease_seconds=lease_seconds,
                    execute=execute,
                    job_contract_version=2,
                    v2_worker_scope=True,
                )
                claimed_v2 = claimed is not None
            if claimed is None:
                if once:
                    return {
                        "processed": 0,
                        "expired_envelopes": expired_envelopes,
                        "families_converged": len(family_sweep.converged),
                        "families_terminated": len(family_sweep.terminated),
                        "rounds_recovered": recovered_rounds,
                        "blocked_rounds_archived": recovered_blocked_rounds,
                        "charges_recovered": recovered_charges,
                        "family_transitions": transitions,
                    }
                time.sleep(poll_seconds)
                continue
            if claimed_v2:
                if claimed["state"] in ("RUNNING", "ARCHIVING"):
                    result = _run_execution_claim(
                        dsn, claimed, case_root=case_root, run_root=run_root
                    )
                    # The campaign/round just archived: take its family
                    # decision now instead of waiting for the next poll.
                    _advance_after_child(
                        dsn, claimed, case_root=case_root, run_root=run_root
                    )
                else:
                    result = _sync_v2_claim(dsn, claimed, run_root=run_root)
            else:
                result = _process_claim(
                    graph,
                    dsn,
                    claimed,
                    case_root=case_root,
                    execute=execute,
                    run_root=run_root,
                )
            result["expired_envelopes"] = expired_envelopes
            result["families_converged"] = len(family_sweep.converged)
            result["families_terminated"] = len(family_sweep.terminated)
            result["rounds_recovered"] = recovered_rounds
            result["blocked_rounds_archived"] = recovered_blocked_rounds
            result["charges_recovered"] = recovered_charges
            result["family_transitions"] = transitions
            if once:
                return result


def _advance_after_child(
    dsn: str,
    claimed: Mapping[str, Any],
    *,
    case_root: str | None,
    run_root: str | None,
) -> None:
    job = state_store.load_job(dsn, claimed["job_id"])
    if job is None or job.get("family_id") is None:
        return
    if job.get("job_kind") not in ("campaign", "round"):
        return
    try:
        advance_family_transition(
            dsn, job["family_id"], case_root=case_root, run_root=run_root
        )
    except state_store.StateError as error:
        logger.warning(
            "family %s transition after %s deferred: %s",
            job["family_id"],
            claimed["job_id"],
            error,
        )


def _run_execution_claim(
    dsn: str,
    claimed: dict[str, Any],
    *,
    case_root: str | None,
    run_root: str | None,
) -> dict[str, Any]:
    job_id = claimed["job_id"]
    generation = claimed["generation"]
    try:
        outcome = execution.run_execution(
            dsn,
            job_id,
            generation,
            case_root=case_root,
            run_root=run_root,
        )
    except state_store.StaleGeneration:
        outcome = execution.ExecutionResult("STALE")
    except Exception as error:  # noqa: BLE001 - never crash the worker loop
        # The executor turns its own domain errors into archived outcomes.
        # A truly unexpected error stays recoverable: leave the claimed job in
        # RUNNING so a later generation can reconcile and retry.
        try:
            state_store.record_attempt(
                dsn,
                job_id,
                stage="execute",
                step_key="workflow",
                attempt_no=1,
                generation=generation,
                input_digest=None,
                status="infra_error",
                result={"error": type(error).__name__},
            )
        except (state_store.StateError, psycopg.Error):
            pass
        outcome = execution.ExecutionResult("STALE")
    job = state_store.load_job(dsn, job_id)
    return {
        "processed": 1,
        "job_id": str(job_id),
        "state": job["state"] if job else None,
        "workflow": "completed" if outcome.state != "STALE" else "stale",
        "verdict": outcome.verdict if outcome.state != "STALE" else None,
    }


def _process_claim(
    graph,
    dsn: str,
    claimed: dict[str, Any],
    *,
    case_root: str | None = None,
    execute: bool = True,
    run_root: str | None = None,
) -> dict[str, Any]:
    job_id = claimed["job_id"]
    job_text = str(job_id)
    generation = claimed["generation"]
    config = {
        "configurable": {
            "thread_id": job_text,
            "datacon_generation": generation,
        }
    }
    initial: SupervisorState = {
        "job_id": job_text,
        "stage": claimed["stage"] or "prepare",
        "generation": generation,
        "state_version": claimed["state_version"],
        "plan_digest": None,
    }
    stage = claimed["stage"] or "prepare"
    if execute and claimed["state"] in ("RUNNING", "ARCHIVING"):
        return _run_execution_claim(
            dsn, claimed, case_root=case_root, run_root=run_root
        )
    graph_failure: BaseException | None = None
    attempt_no = 1
    retried = False
    resume_requested = False
    stop_finalize = False
    while attempt_no <= 2:
        try:
            snapshot = graph.get_state(config)
            if snapshot.next:
                # The claim generation travels in the run configuration, not
                # in ``Command(update=...)``. Re-sending the same state update
                # on a retry makes LangGraph see two writes for one step and
                # raise InvalidUpdateError, which used to overwrite a committed
                # READY/BLOCKED record as FAILED. The nodes return the claim
                # generation as ordinary output once they complete, so the
                # checkpoint converges without an extra write.
                resume_requested = resume_requested or bool(snapshot.interrupts)
                if resume_requested:
                    graph.invoke(
                        Command(
                            resume={"job_id": job_text, "source": "worker"}
                        ),
                        config,
                    )
                else:
                    graph.invoke(None, config)
            else:
                graph.invoke(initial, config)
            if retried:
                try:
                    stored = state_store.record_attempt(
                        dsn,
                        job_id,
                        stage=stage,
                        step_key="workflow",
                        attempt_no=attempt_no,
                        generation=generation,
                        input_digest=None,
                        status="completed",
                        result={"retried": True},
                    )
                except (state_store.StateError, psycopg.Error):
                    # The audit row could not be written. The graph already
                    # converged, but do not finalize a lease we cannot prove.
                    stored = False
                if not stored:
                    stop_finalize = True
            graph_failure = None
            break
        except state_store.StaleGeneration:
            graph_failure = None
            break
        except Exception as error:  # noqa: BLE001 - classified below
            graph_failure = error
            if not _is_retryable_workflow_error(error):
                break
            try:
                stored = state_store.record_attempt(
                    dsn,
                    job_id,
                    stage=stage,
                    step_key="workflow",
                    attempt_no=attempt_no,
                    generation=generation,
                    input_digest=None,
                    status="infra_error",
                    result={"error": type(error).__name__},
                )
            except (state_store.StateError, psycopg.Error):
                # The lease is gone (or the audit row cannot be written), so a
                # workflow retry would only repeat the stale work.
                stop_finalize = True
                break
            if not stored:
                # ``False`` means the generation/lease fence or an existing
                # completed row rejected this write. Retrying is meaningless
                # and any terminal write would be fenced too.
                stop_finalize = True
                break
            if attempt_no >= 2:
                break
            if stage == "prepare":
                try:
                    expired = state_store.prepare_deadline_passed(
                        dsn, job_id, generation=generation
                    )
                except state_store.StaleGeneration:
                    graph_failure = None
                    break
                except psycopg.Error as deadline_error:
                    graph_failure = deadline_error
                    break
                if expired:
                    try:
                        _block_job(
                            dsn,
                            job_id,
                            generation=generation,
                            reason_code="DEADLINE_EXCEEDED",
                            message=(
                                "preparation deadline passed before the "
                                "workflow retry"
                            ),
                        )
                    except (state_store.StateError, psycopg.Error):
                        # The job stays PREPARING; a later workflow or worker
                        # retry must read the persisted attempts and fail
                        # closed instead of running analysis again.
                        pass
                    graph_failure = None
                    break
            retried = True
            attempt_no += 1

    if execute and graph_failure is None and not stop_finalize:
        current = state_store.load_job(dsn, job_id)
        if current is not None and current["state"] == "READY":
            try:
                state_store.begin_execution(
                    dsn, job_id, generation=generation
                )
            except state_store.StaleGeneration:
                stop_finalize = True
            except state_store.StateError:
                pass
            else:
                return _run_execution_claim(
                    dsn, claimed, case_root=case_root, run_root=run_root
                )

    business_authoritative = False
    if graph_failure is not None and not stop_finalize:
        # The business record is authoritative. A checkpoint, resume or
        # scheduling failure must never rewrite a committed READY/BLOCKED
        # review (or an awaiting-review plan) as FAILED. Escaped failures are
        # not analysis failures: ``prepare`` handles AnalysisBlocked and
        # analysis exceptions inside the node. If the business state cannot
        # even be read, do not guess.
        unreadable = object()
        try:
            current = state_store.load_job(dsn, job_id)
        except (state_store.StateError, psycopg.Error):
            current = unreadable
        if current is unreadable or current is None or current["state"] != "PREPARING":
            business_authoritative = True
            try:
                state_store.record_attempt(
                    dsn,
                    job_id,
                    stage=stage,
                    step_key="workflow",
                    attempt_no=attempt_no,
                    generation=generation,
                    input_digest=None,
                    status="infra_error",
                    result={"error": type(graph_failure).__name__},
                )
            except (state_store.StateError, psycopg.Error):
                pass
        else:
            # A PREPARING job whose graph failed outside an analysis step is
            # only an infrastructure/scheduling failure. Keep the job
            # PREPARING with workflow_synced=false and let the lease expire so
            # a later generation retries; never write
            # FAILED/ANALYSIS_ERROR here.
            try:
                state_store.record_attempt(
                    dsn,
                    job_id,
                    stage=stage,
                    step_key="workflow",
                    attempt_no=attempt_no,
                    generation=generation,
                    input_digest=None,
                    status="infra_error",
                    result={"error": type(graph_failure).__name__},
                )
            except (state_store.StateError, psycopg.Error):
                pass
            stop_finalize = True

    if not business_authoritative and not stop_finalize:
        try:
            state_store.finalize_workflow(dsn, job_id, generation)
        except state_store.StateError:
            pass
    job = state_store.load_job(dsn, job_id)
    snapshot = None
    for attempt in (1, 2):
        try:
            snapshot = graph.get_state(config)
            break
        except Exception as error:  # noqa: BLE001 - the job record is authoritative
            if attempt == 2 or not _is_retryable_workflow_error(error):
                break
    if snapshot is None:
        workflow = "unknown"
    else:
        workflow = "interrupted" if snapshot.interrupts else "completed"
    return {
        "processed": 1,
        "job_id": job_text,
        "state": job["state"] if job else None,
        "workflow": workflow,
    }

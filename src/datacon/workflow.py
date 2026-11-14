"""LangGraph Supervisor for preparation, review parking and recovery."""

from __future__ import annotations

import os
import socket
import time
from typing import Any, TypedDict
from uuid import UUID

import psycopg
from langgraph.checkpoint.postgres import PostgresSaver
from langgraph.config import get_config
from langgraph.graph import END, START, StateGraph
from langgraph.types import Command, interrupt

from datacon import contracts
from datacon import jsonutil
from datacon import state as state_store
from datacon.agents.analysis import (
    AnalysisBlocked,
    AnalyzedCase,
    RetryableAnalysisError,
    analyze_case,
)
from datacon.cases import TransientCaseError
from datacon.tools.source import TransientSourceToolError


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
):
    """Compile the Supervisor graph keyed by ``thread_id=job_id``."""

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
            state_store.block_job(
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
                    state_store.block_job(
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
                    state_store.block_job(
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
                    state_store.block_job(
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
                    state_store.block_job(
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
            state_store.block_job(
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
                state_store.block_job(
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


def _worker_id() -> str:
    return os.getenv("DATACON_WORKER_ID") or f"{socket.gethostname()}:{os.getpid()}"


def run_worker(
    dsn: str,
    *,
    once: bool = True,
    poll_seconds: float = 2.0,
    case_root: str | None = None,
    lease_seconds: int = state_store.LEASE_SECONDS,
) -> dict[str, Any]:
    worker = _worker_id()
    with PostgresSaver.from_conn_string(dsn) as checkpointer:
        checkpointer.setup()
        graph = build_graph(dsn, checkpointer, case_root=case_root)
        while True:
            claimed = state_store.claim_next(
                dsn, worker, lease_seconds=lease_seconds
            )
            if claimed is None:
                if once:
                    return {"processed": 0}
                time.sleep(poll_seconds)
                continue
            result = _process_claim(graph, dsn, claimed)
            if once:
                return result


def _process_claim(graph, dsn: str, claimed: dict[str, Any]) -> dict[str, Any]:
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
                        state_store.block_job(
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

"""LangGraph Supervisor for preparation, review parking and recovery."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import os
import socket
import time
from typing import Any, TypedDict
from uuid import UUID

import psycopg
from langgraph.checkpoint.postgres import PostgresSaver
from langgraph.graph import END, START, StateGraph
from langgraph.types import Command, interrupt

from datacon import jsonutil
from datacon import state as state_store
from datacon.agents.analysis import (
    AnalysisBlocked,
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


def build_graph(
    dsn: str,
    checkpointer,
    *,
    case_root: str | None = None,
):
    """Compile the Supervisor graph keyed by ``thread_id=job_id``."""

    def prepare(graph_state: SupervisorState) -> dict[str, Any]:
        job_id = _uuid(graph_state["job_id"])
        job = state_store.load_job(dsn, job_id)
        if job is None:
            return {}
        if job["generation"] != graph_state["generation"]:
            raise state_store.StaleGeneration(
                "execution generation is no longer current"
            )
        if job["state"] in ("READY", "BLOCKED"):
            return {}
        if job["state"] not in ("PREPARING", "AWAITING_REVIEW"):
            return {}

        existing = state_store.get_plan(dsn, job_id)
        if existing is not None:
            state_store.ensure_awaiting_review(
                dsn,
                job_id,
                generation=job["generation"],
                review_deadline=datetime.now(timezone.utc)
                + timedelta(hours=state_store.REVIEW_WINDOW_HOURS),
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

        def recorder(attempt_no: int):
            def record_tool(
                tool_id: str,
                step_key: str,
                params: dict[str, Any],
                result_digest: str,
            ) -> None:
                state_store.record_attempt(
                    dsn,
                    job_id,
                    stage="prepare",
                    step_key=step_key,
                    attempt_no=attempt_no,
                    generation=job["generation"],
                    input_digest=jsonutil.digest_json(params),
                    status="completed",
                    result={"tool_id": tool_id, "result_digest": result_digest},
                )

            return record_tool

        def retry_or_stop(attempt_no: int, error: BaseException) -> bool:
            recorded = state_store.record_attempt(
                dsn,
                job_id,
                stage="prepare",
                step_key="analysis",
                attempt_no=attempt_no,
                generation=job["generation"],
                input_digest=jsonutil.digest_json(job["request"]),
                status="infra_error",
                result={"error": type(error).__name__},
            )
            if not recorded:
                raise state_store.StaleGeneration(
                    "the worker lease was lost before the retry"
                )
            if attempt_no >= 2:
                state_store.block_job(
                    dsn,
                    job_id,
                    generation=job["generation"],
                    reason_code="ANALYSIS_ERROR",
                    message=(
                        "analysis failed after one retry with "
                        f"{type(error).__name__}"
                    ),
                    state="FAILED",
                    event_type="failed",
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

        analyzed = None
        attempt_no = 1
        while analyzed is None:
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
            try:
                state_store.record_attempt(
                    dsn,
                    job_id,
                    stage="prepare",
                    step_key="analysis",
                    attempt_no=attempt_no,
                    generation=job["generation"],
                    input_digest=jsonutil.digest_json(job["request"]),
                    status="completed",
                    result={"plan_digest": analyzed.plan_digest},
                )
            except (state_store.StateError, psycopg.Error):
                pass

        try:
            state_store.freeze_plan(
                dsn,
                job_id,
                generation=job["generation"],
                plan=analyzed.plan,
                plan_digest=analyzed.plan_digest,
                summary=analyzed.summary,
                review_deadline=datetime.now(timezone.utc)
                + timedelta(hours=state_store.REVIEW_WINDOW_HOURS),
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
        try:
            state_store.record_attempt(
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
        except Exception:  # noqa: BLE001 - the frozen plan is authoritative
            pass
        return {
            "plan_digest": analyzed.plan_digest,
            "stage": "review",
            "state_version": graph_state["state_version"] + 1,
        }

    def await_review(graph_state: SupervisorState) -> dict[str, Any]:
        job_id = _uuid(graph_state["job_id"])
        job = state_store.load_job(dsn, job_id)
        if job is None:
            return {}
        if job["generation"] != graph_state["generation"]:
            raise state_store.StaleGeneration(
                "execution generation is no longer current"
            )
        if job["state"] == "AWAITING_REVIEW":
            if state_store.expire_review(dsn, job_id, job["generation"]):
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
                job = state_store.load_job(dsn, job_id)
                if job is None:
                    return {}
                if job["state"] == "AWAITING_REVIEW":
                    if state_store.expire_review(dsn, job_id, job["generation"]):
                        return {}
                    review = state_store.get_review(dsn, job_id)
                    if review is None:
                        interrupt(
                            {
                                "job_id": graph_state["job_id"],
                                "plan_digest": graph_state.get("plan_digest"),
                                "review_deadline_at": None,
                            }
                        )
                        return {}
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
                    generation=job["generation"],
                    reason_code="PLAN_MISMATCH",
                    message="the recorded review does not match the frozen plan",
                )
        return {}

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
    config = {"configurable": {"thread_id": job_text}}
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
    while attempt_no <= 2:
        try:
            snapshot = graph.get_state(config)
            if snapshot.next:
                if snapshot.interrupts:
                    graph.invoke(
                        Command(
                            resume={"job_id": job_text, "source": "worker"},
                            update={
                                "generation": generation,
                                "stage": stage,
                                "state_version": claimed["state_version"],
                            },
                        ),
                        config,
                    )
                else:
                    graph.invoke(
                        Command(
                            update={
                                "generation": generation,
                                "stage": stage,
                                "state_version": claimed["state_version"],
                            }
                        ),
                        config,
                    )
            else:
                graph.invoke(initial, config)
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
                state_store.record_attempt(
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
                pass
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
                except psycopg.Error:
                    graph_failure = error
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
                    except state_store.StateError:
                        pass
                    graph_failure = None
                    break
            attempt_no += 1

    if graph_failure is not None:
        try:
            state_store.block_job(
                dsn,
                job_id,
                generation=generation,
                reason_code="ANALYSIS_ERROR",
                message=f"workflow failed with {type(graph_failure).__name__}",
                state="FAILED",
                event_type="failed",
            )
        except state_store.StateError:
            pass

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

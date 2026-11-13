"""LangGraph Supervisor for preparation, review parking and recovery."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import os
import socket
import time
from typing import Any, TypedDict
from uuid import UUID

from langgraph.checkpoint.postgres import PostgresSaver
from langgraph.graph import END, START, StateGraph
from langgraph.types import Command, interrupt

from datacon import jsonutil
from datacon import state as state_store
from datacon.agents.analysis import AnalysisBlocked, analyze_case


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

        deadline = job["prepare_deadline_at"]
        if deadline is not None and deadline <= datetime.now(timezone.utc):
            state_store.block_job(
                dsn,
                job_id,
                generation=job["generation"],
                reason_code="DEADLINE_EXCEEDED",
                message="preparation deadline passed before analysis completed",
            )
            return {}

        def recorder(
            tool_id: str, step_key: str, params: dict[str, Any], result_digest: str
        ) -> None:
            state_store.record_attempt(
                dsn,
                job_id,
                stage="prepare",
                step_key=step_key,
                attempt_no=1,
                generation=job["generation"],
                input_digest=jsonutil.digest_json(params),
                status="completed",
                result={"tool_id": tool_id, "result_digest": result_digest},
            )

        try:
            analyzed = analyze_case(
                job["request"], case_root=case_root, recorder=recorder
            )
        except AnalysisBlocked as error:
            state_store.block_job(
                dsn,
                job_id,
                generation=job["generation"],
                reason_code=error.reason_code,
                message=error.message,
            )
            return {}
        except state_store.StaleGeneration:
            raise
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
                attempt_no=1,
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
    try:
        snapshot = graph.get_state(config)
        if snapshot.next:
            if snapshot.interrupts:
                graph.invoke(
                    Command(
                        resume={"job_id": job_text, "source": "worker"},
                        update={
                            "generation": generation,
                            "stage": claimed["stage"] or "prepare",
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
                            "stage": claimed["stage"] or "prepare",
                            "state_version": claimed["state_version"],
                        }
                    ),
                    config,
                )
        else:
            graph.invoke(initial, config)
    except state_store.StaleGeneration:
        pass
    except Exception as error:  # noqa: BLE001 - do not leak connection details
        try:
            state_store.block_job(
                dsn,
                job_id,
                generation=generation,
                reason_code="ANALYSIS_ERROR",
                message=f"workflow failed with {type(error).__name__}",
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
    snapshot = graph.get_state(config)
    workflow = "interrupted" if snapshot.interrupts else "completed"
    return {
        "processed": 1,
        "job_id": job_text,
        "state": job["state"] if job else None,
        "workflow": workflow,
    }

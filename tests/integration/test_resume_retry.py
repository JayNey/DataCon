"""Regression tests for transient database errors during review resume.

The D1 blocker was that a retried resume replayed ``Command(update=...)``,
raised ``InvalidUpdateError`` and rewrote a committed READY/BLOCKED record as
FAILED/ANALYSIS_ERROR. These tests inject retryable read failures into the
resume path and assert the business record stays authoritative.
"""

import uuid

import psycopg
import pytest

from datacon import state, workflow
from datacon.workflow import build_graph
from support import scalar, submit, write_request

pytestmark = pytest.mark.postgres


def checkpoint_snapshot(database, job_id):
    from langgraph.checkpoint.postgres import PostgresSaver

    with PostgresSaver.from_conn_string(database.dsn) as saver:
        graph = build_graph(database.dsn, saver)
        return graph.get_state({"configurable": {"thread_id": job_id}})


def fail_first(monkeypatch, name, *, times=1):
    """Make ``state.<name>`` raise a retryable error for the next calls."""
    real = getattr(state, name)
    calls = {"count": 0}

    def flaky(*args, **kwargs):
        calls["count"] += 1
        if calls["count"] <= times:
            raise psycopg.OperationalError(f"injected failure in {name}")
        return real(*args, **kwargs)

    monkeypatch.setattr(state, name, flaky)
    return calls


def assert_workflow_attempts(database, job_id, expected):
    rows = database.connection.execute(
        "SELECT attempt_no, status FROM attempts "
        "WHERE job_id = %s AND step_key = 'workflow' ORDER BY attempt_no",
        (uuid.UUID(job_id),),
    ).fetchall()
    assert rows == expected


def assert_no_invalid_update(database, job_uuid):
    job = state.load_job(database.dsn, job_uuid)
    assert job["state"] != "FAILED"
    assert job["last_error"] is None or "InvalidUpdateError" not in job["last_error"]
    rows = database.connection.execute(
        "SELECT result::text FROM attempts WHERE job_id = %s",
        (job_uuid,),
    ).fetchall()
    assert all("InvalidUpdateError" not in (row[0] or "") for row in rows)


def pending_digest(database, job_uuid):
    digest = scalar(
        database,
        "SELECT plan_digest FROM plans WHERE job_id = %s",
        (job_uuid,),
    )
    assert digest is not None
    return digest


def park_then_expire_lease(database, job_uuid):
    """Reopen a parked review checkpoint for the next worker claim."""
    database.connection.execute(
        "UPDATE jobs SET workflow_synced = false, "
        "lease_expires_at = now() - interval '1 second' WHERE job_id = %s",
        (job_uuid,),
    )


def crash_after_interrupt_before_finalize(database, tmp_path, monkeypatch):
    """Run one worker pass that parks at review, then lose it before finalize."""
    job = submit(database.dsn, write_request(tmp_path))
    job_uuid = uuid.UUID(job["job_id"])
    real_finalize = state.finalize_workflow
    crashed = {"done": False}

    def crash_once(dsn, job_id, generation):
        if not crashed["done"]:
            crashed["done"] = True
            return False
        return real_finalize(dsn, job_id, generation)

    monkeypatch.setattr(state, "finalize_workflow", crash_once)
    first = workflow.run_worker(database.dsn, once=True)
    assert first["processed"] == 1
    assert first["state"] == "AWAITING_REVIEW"

    current = state.load_job(database.dsn, job_uuid)
    assert current["workflow_synced"] is False
    assert current["lease_owner"] is not None
    database.connection.execute(
        "UPDATE jobs SET lease_expires_at = now() - interval '1 second' "
        "WHERE job_id = %s",
        (job_uuid,),
    )
    # The next worker must be able to finalize normally.
    monkeypatch.setattr(state, "finalize_workflow", real_finalize)
    return job, job_uuid


def test_prepare_retry_continues_the_pending_node(
    isolated_database, tmp_path, monkeypatch
):
    job = submit(isolated_database.dsn, write_request(tmp_path))
    job_uuid = uuid.UUID(job["job_id"])
    fail_first(monkeypatch, "load_job")

    result = workflow.run_worker(isolated_database.dsn, once=True)

    assert result["processed"] == 1
    assert result["state"] == "AWAITING_REVIEW"
    current = state.load_job(isolated_database.dsn, job_uuid)
    assert current["workflow_synced"] is True
    assert current["lease_owner"] is None
    assert scalar(
        isolated_database,
        "SELECT count(*) FROM plans WHERE job_id = %s",
        (job_uuid,),
    ) == 1
    assert_workflow_attempts(
        isolated_database, job["job_id"], [(1, "infra_error"), (2, "completed")]
    )
    snapshot = checkpoint_snapshot(isolated_database, job["job_id"])
    assert snapshot.next == ("await_review",)
    assert snapshot.interrupts
    assert snapshot.values["generation"] == current["generation"]


def test_pending_review_resume_survives_transient_read(
    isolated_database, tmp_path, monkeypatch
):
    job = submit(isolated_database.dsn, write_request(tmp_path))
    job_uuid = uuid.UUID(job["job_id"])
    first = workflow.run_worker(isolated_database.dsn, once=True)
    assert first["state"] == "AWAITING_REVIEW"
    park_then_expire_lease(isolated_database, job_uuid)

    fail_first(monkeypatch, "get_review")
    resumed = workflow.run_worker(isolated_database.dsn, once=True)

    assert resumed["processed"] == 1
    assert resumed["state"] == "AWAITING_REVIEW"
    assert resumed["workflow"] == "completed"
    current = state.load_job(isolated_database.dsn, job_uuid)
    assert current["state"] == "AWAITING_REVIEW"
    assert current["workflow_synced"] is True
    assert current["lease_owner"] is None
    assert current["lease_expires_at"] is None
    assert scalar(
        isolated_database,
        "SELECT count(*) FROM plans WHERE job_id = %s",
        (job_uuid,),
    ) == 1
    assert scalar(
        isolated_database,
        "SELECT count(*) FROM reviews WHERE job_id = %s",
        (job_uuid,),
    ) == 0
    assert_workflow_attempts(
        isolated_database, job["job_id"], [(1, "infra_error"), (2, "completed")]
    )
    assert_no_invalid_update(isolated_database, job_uuid)

    # A still-pending job must remain reviewable after the recovered pass.
    digest = pending_digest(isolated_database, job_uuid)
    outcome = state.record_review(
        isolated_database.dsn,
        job_uuid,
        plan_digest=digest,
        decision="approve",
        reviewer_id="reviewer-1",
    )
    assert outcome.status == "applied"
    assert outcome.state == "READY"


def test_approved_resume_survives_transient_read(
    isolated_database, tmp_path, monkeypatch
):
    job = submit(isolated_database.dsn, write_request(tmp_path))
    job_uuid = uuid.UUID(job["job_id"])
    workflow.run_worker(isolated_database.dsn, once=True)
    digest = pending_digest(isolated_database, job_uuid)
    approved = state.record_review(
        isolated_database.dsn,
        job_uuid,
        plan_digest=digest,
        decision="approve",
        reviewer_id="reviewer-1",
    )
    assert approved.state == "READY"

    fail_first(monkeypatch, "get_plan")
    resumed = workflow.run_worker(isolated_database.dsn, once=True)

    assert resumed["processed"] == 1
    assert resumed["state"] == "READY"
    assert resumed["workflow"] == "completed"
    current = state.load_job(isolated_database.dsn, job_uuid)
    assert current["state"] == "READY"
    assert current["reason_code"] is None
    assert current["workflow_synced"] is True
    assert current["lease_owner"] is None
    assert current["lease_expires_at"] is None
    assert scalar(
        isolated_database,
        "SELECT count(*) FROM plans WHERE job_id = %s",
        (job_uuid,),
    ) == 1
    assert scalar(
        isolated_database,
        "SELECT count(*) FROM reviews WHERE job_id = %s",
        (job_uuid,),
    ) == 1
    assert_workflow_attempts(
        isolated_database, job["job_id"], [(1, "infra_error"), (2, "completed")]
    )
    assert_no_invalid_update(isolated_database, job_uuid)
    snapshot = checkpoint_snapshot(isolated_database, job["job_id"])
    assert snapshot.next == ()
    assert not snapshot.interrupts
    assert snapshot.values["generation"] == current["generation"]


def test_rejected_resume_survives_transient_read(
    isolated_database, tmp_path, monkeypatch
):
    job = submit(isolated_database.dsn, write_request(tmp_path))
    job_uuid = uuid.UUID(job["job_id"])
    workflow.run_worker(isolated_database.dsn, once=True)
    digest = pending_digest(isolated_database, job_uuid)
    rejected = state.record_review(
        isolated_database.dsn,
        job_uuid,
        plan_digest=digest,
        decision="reject",
        reviewer_id="reviewer-1",
    )
    assert rejected.state == "BLOCKED"

    fail_first(monkeypatch, "get_plan")
    resumed = workflow.run_worker(isolated_database.dsn, once=True)

    assert resumed["processed"] == 1
    assert resumed["state"] == "BLOCKED"
    assert resumed["workflow"] == "completed"
    current = state.load_job(isolated_database.dsn, job_uuid)
    assert current["state"] == "BLOCKED"
    assert current["reason_code"] == "REVIEW_REJECTED"
    assert current["workflow_synced"] is True
    assert current["lease_owner"] is None
    assert scalar(
        isolated_database,
        "SELECT count(*) FROM plans WHERE job_id = %s",
        (job_uuid,),
    ) == 1
    assert scalar(
        isolated_database,
        "SELECT count(*) FROM reviews WHERE job_id = %s",
        (job_uuid,),
    ) == 1
    assert_workflow_attempts(
        isolated_database, job["job_id"], [(1, "infra_error"), (2, "completed")]
    )
    assert_no_invalid_update(isolated_database, job_uuid)
    snapshot = checkpoint_snapshot(isolated_database, job["job_id"])
    assert snapshot.next == ()
    assert not snapshot.interrupts
    assert snapshot.values["generation"] == current["generation"]


def test_pre_finalize_crash_resume_survives_transient_read(
    isolated_database, tmp_path, monkeypatch
):
    job, job_uuid = crash_after_interrupt_before_finalize(
        isolated_database, tmp_path, monkeypatch
    )
    fail_first(monkeypatch, "get_review")
    restarted = workflow.run_worker(isolated_database.dsn, once=True)

    assert restarted["processed"] == 1
    assert restarted["state"] == "AWAITING_REVIEW"
    assert restarted["workflow"] == "completed"
    current = state.load_job(isolated_database.dsn, job_uuid)
    assert current["state"] == "AWAITING_REVIEW"
    assert current["workflow_synced"] is True
    assert current["lease_owner"] is None
    assert scalar(
        isolated_database,
        "SELECT count(*) FROM plans WHERE job_id = %s",
        (job_uuid,),
    ) == 1
    assert scalar(
        isolated_database,
        "SELECT count(*) FROM reviews WHERE job_id = %s",
        (job_uuid,),
    ) == 0
    assert_workflow_attempts(
        isolated_database, job["job_id"], [(1, "infra_error"), (2, "completed")]
    )
    assert_no_invalid_update(isolated_database, job_uuid)
    snapshot = checkpoint_snapshot(isolated_database, job["job_id"])
    assert snapshot.next == ()
    assert not snapshot.interrupts
    assert snapshot.values["generation"] == current["generation"]


@pytest.mark.parametrize(
    ("decision", "expected_state", "expected_reason"),
    [
        ("approve", "READY", None),
        ("reject", "BLOCKED", "REVIEW_REJECTED"),
    ],
)
def test_persistent_resume_error_keeps_the_business_record(
    isolated_database, tmp_path, monkeypatch, decision, expected_state, expected_reason
):
    job = submit(isolated_database.dsn, write_request(tmp_path))
    job_uuid = uuid.UUID(job["job_id"])
    workflow.run_worker(isolated_database.dsn, once=True)
    digest = pending_digest(isolated_database, job_uuid)
    recorded = state.record_review(
        isolated_database.dsn,
        job_uuid,
        plan_digest=digest,
        decision=decision,
        reviewer_id="reviewer-1",
    )
    assert recorded.state == expected_state

    fail_first(monkeypatch, "get_plan", times=2)
    failed = workflow.run_worker(isolated_database.dsn, once=True)

    assert failed["processed"] == 1
    current = state.load_job(isolated_database.dsn, job_uuid)
    assert current["state"] == expected_state
    assert current["reason_code"] == expected_reason
    assert current["workflow_synced"] is False
    assert current["lease_owner"] is not None
    assert scalar(
        isolated_database,
        "SELECT count(*) FROM jobs WHERE job_id = %s AND state = 'FAILED'",
        (job_uuid,),
    ) == 0
    assert_workflow_attempts(
        isolated_database, job["job_id"], [(1, "infra_error"), (2, "infra_error")]
    )
    assert_no_invalid_update(isolated_database, job_uuid)
    assert scalar(
        isolated_database,
        "SELECT count(*) FROM plans WHERE job_id = %s",
        (job_uuid,),
    ) == 1
    assert scalar(
        isolated_database,
        "SELECT count(*) FROM reviews WHERE job_id = %s",
        (job_uuid,),
    ) == 1

    # Leaving workflow_synced=false with a live lease is recoverable: once the
    # lease expires a new generation converges without the injected error.
    isolated_database.connection.execute(
        "UPDATE jobs SET lease_expires_at = now() - interval '1 second' "
        "WHERE job_id = %s",
        (job_uuid,),
    )
    recovered = workflow.run_worker(isolated_database.dsn, once=True)
    assert recovered["processed"] == 1
    assert recovered["state"] == expected_state
    current = state.load_job(isolated_database.dsn, job_uuid)
    assert current["state"] == expected_state
    assert current["reason_code"] == expected_reason
    assert current["workflow_synced"] is True
    assert current["lease_owner"] is None
    assert scalar(
        isolated_database,
        "SELECT count(*) FROM jobs WHERE job_id = %s AND state = 'FAILED'",
        (job_uuid,),
    ) == 0
    snapshot = checkpoint_snapshot(isolated_database, job["job_id"])
    assert snapshot.next == ()
    assert not snapshot.interrupts
    assert snapshot.values["generation"] == current["generation"]

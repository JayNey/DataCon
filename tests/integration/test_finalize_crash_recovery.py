"""Regression tests for a crash between the review interrupt and finalize.

The business record is authoritative. A worker that restarts while a job is
still awaiting review must complete the scheduling pass without stacking a
second interrupt, and a later approve/reject/expiry must converge without an
``InvalidUpdateError``.
"""

import uuid

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


def crash_after_interrupt_before_finalize(database, tmp_path, monkeypatch):
    """Run one worker pass that parks at review, then lose it before finalize."""
    job = submit(database.dsn, write_request(tmp_path))
    job_uuid = uuid.UUID(job["job_id"])
    real_finalize = state.finalize_workflow
    skipped = {"done": False}

    def crash_once(dsn, job_id, generation):
        if not skipped["done"]:
            skipped["done"] = True
            return False
        return real_finalize(dsn, job_id, generation)

    monkeypatch.setattr(state, "finalize_workflow", crash_once)

    first = workflow.run_worker(database.dsn, once=True, execute=False)
    assert first["processed"] == 1
    assert first["state"] == "AWAITING_REVIEW"
    assert first["workflow"] == "interrupted"

    crashed = state.load_job(database.dsn, job_uuid)
    assert crashed["state"] == "AWAITING_REVIEW"
    assert crashed["workflow_synced"] is False
    assert crashed["lease_owner"] is not None

    database.connection.execute(
        "UPDATE jobs SET lease_expires_at = now() - interval '1 second' "
        "WHERE job_id = %s",
        (job_uuid,),
    )
    restart = workflow.run_worker(database.dsn, once=True, execute=False)
    assert restart["processed"] == 1
    assert restart["state"] == "AWAITING_REVIEW"

    # A restart while still pending must not leave a second interrupt behind.
    assert restart["workflow"] == "completed"
    resumed = checkpoint_snapshot(database, job["job_id"])
    assert resumed.next == ()
    assert not resumed.interrupts

    return job, job_uuid


def pending_digest(database, job_uuid):
    digest = scalar(
        database,
        "SELECT plan_digest FROM plans WHERE job_id = %s",
        (job_uuid,),
    )
    assert digest is not None
    return digest


def assert_checkpoint_is_readable(database, job_id):
    snapshot = checkpoint_snapshot(database, job_id)
    assert snapshot.next == ()
    assert not snapshot.interrupts


def assert_not_failed(database, job_uuid):
    assert scalar(
        database,
        "SELECT count(*) FROM jobs WHERE job_id = %s AND state = 'FAILED'",
        (job_uuid,),
    ) == 0


def test_crash_before_finalize_then_approve_converges(
    isolated_database, tmp_path, monkeypatch
):
    job, job_uuid = crash_after_interrupt_before_finalize(
        isolated_database, tmp_path, monkeypatch
    )
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

    resumed = workflow.run_worker(isolated_database.dsn, once=True, execute=False)
    assert resumed["processed"] == 1
    assert resumed["state"] == "READY"
    assert resumed["workflow"] == "completed"

    current = state.load_job(isolated_database.dsn, job_uuid)
    assert current["state"] == "READY"
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
    assert_checkpoint_is_readable(isolated_database, job["job_id"])
    assert_not_failed(isolated_database, job_uuid)


def test_crash_before_finalize_then_reject_converges(
    isolated_database, tmp_path, monkeypatch
):
    job, job_uuid = crash_after_interrupt_before_finalize(
        isolated_database, tmp_path, monkeypatch
    )
    digest = pending_digest(isolated_database, job_uuid)

    outcome = state.record_review(
        isolated_database.dsn,
        job_uuid,
        plan_digest=digest,
        decision="reject",
        reviewer_id="reviewer-1",
    )
    assert outcome.status == "applied"
    assert outcome.state == "BLOCKED"

    resumed = workflow.run_worker(isolated_database.dsn, once=True, execute=False)
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
    assert_checkpoint_is_readable(isolated_database, job["job_id"])
    assert_not_failed(isolated_database, job_uuid)


def test_crash_before_finalize_then_review_expiry_converges(
    isolated_database, tmp_path, monkeypatch
):
    job, job_uuid = crash_after_interrupt_before_finalize(
        isolated_database, tmp_path, monkeypatch
    )
    digest = pending_digest(isolated_database, job_uuid)

    isolated_database.connection.execute(
        "UPDATE jobs SET review_deadline_at = now() - interval '1 second' "
        "WHERE job_id = %s",
        (job_uuid,),
    )

    expired = workflow.run_worker(isolated_database.dsn, once=True, execute=False)
    assert expired["processed"] == 1
    assert expired["state"] == "BLOCKED"
    assert expired["workflow"] == "completed"

    current = state.load_job(isolated_database.dsn, job_uuid)
    assert current["state"] == "BLOCKED"
    assert current["reason_code"] == "REVIEW_EXPIRED"
    assert scalar(
        isolated_database,
        "SELECT count(*) FROM reviews WHERE job_id = %s",
        (job_uuid,),
    ) == 0
    assert scalar(
        isolated_database,
        "SELECT count(*) FROM plans WHERE job_id = %s",
        (job_uuid,),
    ) == 1
    assert_checkpoint_is_readable(isolated_database, job["job_id"])
    assert_not_failed(isolated_database, job_uuid)

    # Expiring a review increments the generation, so the expiring worker
    # cannot finalize. The next worker claims the BLOCKED job and syncs it.
    synced = workflow.run_worker(isolated_database.dsn, once=True, execute=False)
    assert synced["processed"] == 1
    assert synced["state"] == "BLOCKED"
    assert synced["workflow"] == "completed"
    current = state.load_job(isolated_database.dsn, job_uuid)
    assert current["workflow_synced"] is True
    assert current["lease_owner"] is None
    assert current["lease_expires_at"] is None


def test_old_generation_cannot_finalize_after_pre_finalize_crash(
    isolated_database, tmp_path, monkeypatch
):
    job = submit(isolated_database.dsn, write_request(tmp_path))
    job_uuid = uuid.UUID(job["job_id"])
    real_finalize = state.finalize_workflow
    skipped = {"done": False}

    def crash_once(dsn, job_id, generation):
        if not skipped["done"]:
            skipped["done"] = True
            return False
        return real_finalize(dsn, job_id, generation)

    monkeypatch.setattr(state, "finalize_workflow", crash_once)
    first = workflow.run_worker(isolated_database.dsn, once=True, execute=False)
    assert first["state"] == "AWAITING_REVIEW"

    old_generation = state.load_job(isolated_database.dsn, job_uuid)["generation"]
    isolated_database.connection.execute(
        "UPDATE jobs SET lease_expires_at = now() - interval '1 second' "
        "WHERE job_id = %s",
        (job_uuid,),
    )
    restarted = state.claim_next(isolated_database.dsn, "worker-restart")
    assert restarted is not None
    assert restarted["generation"] == old_generation + 1

    assert state.finalize_workflow(
        isolated_database.dsn, job_uuid, old_generation
    ) is False
    current = state.load_job(isolated_database.dsn, job_uuid)
    assert current["workflow_synced"] is False
    assert current["lease_owner"] == "worker-restart"

from datetime import datetime, timedelta, timezone
import uuid

import pytest

from datacon import state
from datacon.workflow import build_graph
from support import review, scalar, status, submit, worker, write_request

pytestmark = pytest.mark.postgres



def checkpoint_snapshot(database, job_id):
    from langgraph.checkpoint.postgres import PostgresSaver

    with PostgresSaver.from_conn_string(database.dsn) as saver:
        graph = build_graph(database.dsn, saver)
        return graph.get_state(
            {"configurable": {"thread_id": job_id}},
        )


def test_process_exit_while_awaiting_review_keeps_one_plan_and_checkpoint(
    isolated_database, tmp_path
):
    request = write_request(tmp_path)
    job = submit(isolated_database.dsn, request)

    first = worker(isolated_database.dsn)
    assert first["state"] == "AWAITING_REVIEW"

    job_uuid = uuid.UUID(job["job_id"])
    plan_id = scalar(
        isolated_database,
        "SELECT plan_id FROM plans WHERE job_id = %s",
        (job_uuid,),
    )
    attempt_count = scalar(
        isolated_database,
        "SELECT count(*) FROM attempts WHERE job_id = %s",
        (job_uuid,),
    )

    pending = checkpoint_snapshot(isolated_database, job["job_id"])
    assert pending.next == ("await_review",)
    assert pending.interrupts

    # The worker process has exited. A fresh worker invocation must read the
    # existing records rather than re-running preparation.
    second = worker(isolated_database.dsn)
    assert second["processed"] == 0
    assert scalar(
        isolated_database,
        "SELECT plan_id FROM plans WHERE job_id = %s",
        (job_uuid,),
    ) == plan_id
    assert scalar(
        isolated_database,
        "SELECT count(*) FROM attempts WHERE job_id = %s",
        (job_uuid,),
    ) == attempt_count
    assert status(isolated_database.dsn, job["job_id"])["state"] == "AWAITING_REVIEW"
    after = checkpoint_snapshot(isolated_database, job["job_id"])
    assert after.next == ("await_review",)
    assert after.interrupts


def test_approval_persisted_before_workflow_resume_is_recovered(
    isolated_database, tmp_path
):
    request = write_request(tmp_path)
    job = submit(isolated_database.dsn, request)
    worker(isolated_database.dsn)
    digest = status(isolated_database.dsn, job["job_id"])["pending_plan"][
        "plan_digest"
    ]

    accepted = review(
        isolated_database.dsn,
        job["job_id"],
        digest,
        "approve",
        env_extra={"DATACON_OPERATOR_ID": "reviewer-1"},
    )
    assert accepted.returncode == 0, accepted.stderr

    # Business state is READY, but the graph checkpoint is still parked at the
    # review interrupt. This is the "decision committed, workflow not resumed"
    # window the recovery path must handle.
    assert status(isolated_database.dsn, job["job_id"])["state"] == "READY"
    before = checkpoint_snapshot(isolated_database, job["job_id"])
    assert before.next == ("await_review",)
    assert before.interrupts

    job_uuid = uuid.UUID(job["job_id"])
    assert scalar(
        isolated_database, "SELECT count(*) FROM plans WHERE job_id = %s", (job_uuid,)
    ) == 1
    assert scalar(
        isolated_database, "SELECT count(*) FROM reviews WHERE job_id = %s", (job_uuid,)
    ) == 1

    resumed = worker(isolated_database.dsn)
    assert resumed["processed"] == 1
    assert resumed["state"] == "READY"
    assert resumed["workflow"] == "completed"
    assert scalar(
        isolated_database, "SELECT count(*) FROM plans WHERE job_id = %s", (job_uuid,)
    ) == 1
    assert scalar(
        isolated_database, "SELECT count(*) FROM reviews WHERE job_id = %s", (job_uuid,)
    ) == 1
    after = checkpoint_snapshot(isolated_database, job["job_id"])
    assert after.next == ()
    assert not after.interrupts
    assert status(isolated_database.dsn, job["job_id"])["state"] == "READY"

    thread_ids = {
        row[0]
        for row in isolated_database.connection.execute(
            "SELECT DISTINCT thread_id FROM checkpoints"
        ).fetchall()
    }
    assert thread_ids == {job["job_id"]}

    again = worker(isolated_database.dsn)
    assert again["processed"] == 0


def test_old_worker_generation_cannot_write(isolated_database, tmp_path):
    request = write_request(tmp_path)
    job = submit(isolated_database.dsn, request)
    job_uuid = uuid.UUID(job["job_id"])

    first = state.claim_next(isolated_database.dsn, "worker-a")
    assert first is not None
    assert first["generation"] == 1
    assert state.claim_next(isolated_database.dsn, "worker-b") is None

    isolated_database.connection.execute(
        "UPDATE jobs SET lease_expires_at = now() - interval '1 second' "
        "WHERE job_id = %s",
        (job_uuid,),
    )
    second = state.claim_next(isolated_database.dsn, "worker-b")
    assert second is not None
    assert second["generation"] == 2

    assert state.finalize_workflow(isolated_database.dsn, job_uuid, 1) is False
    with pytest.raises(state.StaleGeneration):
        state.freeze_plan(
            isolated_database.dsn,
            job_uuid,
            generation=1,
            plan={"case_id": "stale"},
            plan_digest="sha256:" + "1" * 64,
            summary={},
            review_deadline=datetime.now(timezone.utc) + timedelta(hours=24),
        )
    assert scalar(
        isolated_database, "SELECT count(*) FROM plans WHERE job_id = %s", (job_uuid,)
    ) == 0

    assert state.finalize_workflow(isolated_database.dsn, job_uuid, 2) is True
    assert scalar(
        isolated_database,
        "SELECT workflow_synced FROM jobs WHERE job_id = %s",
        (job_uuid,),
    ) is True

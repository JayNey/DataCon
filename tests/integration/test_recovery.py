import threading
import uuid

import pytest

from datacon import state, workflow
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


def test_synced_await_review_interrupt_is_not_claimed_again(
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


def _run_worker_until_review_then_decide(
    database, job_id, decision, monkeypatch
):
    """Pause the worker after ``get_review`` returned ``None``.

    The real ``interrupt`` is called only after the review has been committed,
    reproducing the window in which a worker has already read ``review=None``
    while an operator decision lands.
    """
    reached = threading.Event()
    release = threading.Event()
    result = {}
    errors = []
    real_interrupt = workflow.interrupt

    def paused_interrupt(payload):
        reached.set()
        if not release.wait(timeout=30):
            raise AssertionError("the test did not release the paused worker")
        return real_interrupt(payload)

    monkeypatch.setattr(workflow, "interrupt", paused_interrupt)

    def run():
        try:
            result.update(workflow.run_worker(database.dsn, once=True))
        except BaseException as error:  # noqa: BLE001 - re-raised in the test
            errors.append(error)

    thread = threading.Thread(target=run, daemon=True)
    thread.start()
    assert reached.wait(timeout=30), "worker never reached await_review"
    digest = status(database.dsn, job_id)["pending_plan"]["plan_digest"]
    outcome = state.record_review(
        database.dsn,
        uuid.UUID(job_id),
        plan_digest=digest,
        decision=decision,
        reviewer_id="reviewer-race",
    )
    assert outcome.status == "applied"
    release.set()
    thread.join(timeout=60)
    assert not thread.is_alive(), "worker did not stop after the interrupt"
    if errors:
        raise errors[0]
    return result


def _assert_old_worker_cannot_sync(database, job_id, expected_state):
    job_uuid = uuid.UUID(job_id)
    job = state.load_job(database.dsn, job_uuid)
    assert job["state"] == expected_state
    assert job["workflow_synced"] is False
    before = checkpoint_snapshot(database, job_id)
    assert before.next == ("await_review",)
    assert before.interrupts
    assert scalar(
        database, "SELECT count(*) FROM plans WHERE job_id = %s", (job_uuid,)
    ) == 1
    assert scalar(
        database, "SELECT count(*) FROM reviews WHERE job_id = %s", (job_uuid,)
    ) == 1


def test_review_during_await_review_does_not_sync_old_worker(
    isolated_database, tmp_path, monkeypatch
):
    job = submit(isolated_database.dsn, write_request(tmp_path))

    result = _run_worker_until_review_then_decide(
        isolated_database, job["job_id"], "approve", monkeypatch
    )
    assert result["processed"] == 1
    assert result["state"] == "READY"
    assert result["workflow"] == "interrupted"

    _assert_old_worker_cannot_sync(isolated_database, job["job_id"], "READY")

    resumed = worker(isolated_database.dsn)
    assert resumed["processed"] == 1
    assert resumed["state"] == "READY"
    assert resumed["workflow"] == "completed"

    job = state.load_job(isolated_database.dsn, uuid.UUID(job["job_id"]))
    assert job["workflow_synced"] is True
    assert job["lease_owner"] is None
    assert job["lease_expires_at"] is None
    after = checkpoint_snapshot(isolated_database, resumed["job_id"])
    assert after.next == ()
    assert not after.interrupts


def test_reject_during_await_review_does_not_sync_old_worker(
    isolated_database, tmp_path, monkeypatch
):
    job = submit(isolated_database.dsn, write_request(tmp_path))

    result = _run_worker_until_review_then_decide(
        isolated_database, job["job_id"], "reject", monkeypatch
    )
    assert result["processed"] == 1
    assert result["state"] == "BLOCKED"
    assert result["workflow"] == "interrupted"

    _assert_old_worker_cannot_sync(isolated_database, job["job_id"], "BLOCKED")

    resumed = worker(isolated_database.dsn)
    assert resumed["processed"] == 1
    assert resumed["state"] == "BLOCKED"
    assert resumed["workflow"] == "completed"

    current = status(isolated_database.dsn, job["job_id"])
    assert current["state"] == "BLOCKED"
    assert current["reason_code"] == "REVIEW_REJECTED"
    assert current["review_state"]["decision"] == "reject"
    after = checkpoint_snapshot(isolated_database, resumed["job_id"])
    assert after.next == ()
    assert not after.interrupts


def test_stale_attempt_and_lease_writes_rejected(isolated_database, tmp_path):
    job = submit(isolated_database.dsn, write_request(tmp_path))
    job_uuid = uuid.UUID(job["job_id"])

    first = state.claim_next(isolated_database.dsn, "worker-a")
    assert first is not None
    assert first["generation"] == 1

    isolated_database.connection.execute(
        "UPDATE jobs SET lease_expires_at = now() - interval '1 second' "
        "WHERE job_id = %s",
        (job_uuid,),
    )

    # An expired lease is fencing even before another worker claims the job.
    with pytest.raises(state.StaleGeneration):
        state.freeze_plan(
            isolated_database.dsn,
            job_uuid,
            generation=1,
            plan={"case_id": "stale"},
            plan_digest="sha256:" + "1" * 64,
            summary={},
        )
    with pytest.raises(state.StaleGeneration):
        state.block_job(
            isolated_database.dsn,
            job_uuid,
            generation=1,
            reason_code="DEADLINE_EXCEEDED",
            message="stale write after the lease expired",
        )
    with pytest.raises(state.StaleGeneration):
        state.ensure_awaiting_review(
            isolated_database.dsn,
            job_uuid,
            generation=1,
        )
    assert state.finalize_workflow(isolated_database.dsn, job_uuid, 1) is False
    assert scalar(
        isolated_database,
        "SELECT count(*) FROM plans WHERE job_id = %s",
        (job_uuid,),
    ) == 0
    row = isolated_database.connection.execute(
        "SELECT state, workflow_synced, lease_expires_at IS NOT NULL "
        "FROM jobs WHERE job_id = %s",
        (job_uuid,),
    ).fetchone()
    assert row[0] == "PREPARING"
    assert row[1] is False
    assert row[2] is True, "a rejected finalize must not clear the lease"

    second = state.claim_next(isolated_database.dsn, "worker-b")
    assert second is not None
    assert second["generation"] == 2

    assert state.record_attempt(
        isolated_database.dsn,
        job_uuid,
        stage="prepare",
        step_key="stale-step",
        attempt_no=1,
        generation=1,
        input_digest="sha256:" + "2" * 64,
        status="completed",
    ) is False
    assert scalar(
        isolated_database,
        "SELECT count(*) FROM attempts WHERE job_id = %s AND step_key = %s",
        (job_uuid, "stale-step"),
    ) == 0

    with pytest.raises(state.StaleGeneration):
        state.freeze_plan(
            isolated_database.dsn,
            job_uuid,
            generation=1,
            plan={"case_id": "stale"},
            plan_digest="sha256:" + "1" * 64,
            summary={},
        )
    with pytest.raises(state.StaleGeneration):
        state.block_job(
            isolated_database.dsn,
            job_uuid,
            generation=1,
            reason_code="DEADLINE_EXCEEDED",
            message="stale block after another worker claimed the job",
        )
    assert state.finalize_workflow(isolated_database.dsn, job_uuid, 1) is False

    assert state.record_attempt(
        isolated_database.dsn,
        job_uuid,
        stage="prepare",
        step_key="stale-step",
        attempt_no=1,
        generation=2,
        input_digest="sha256:" + "2" * 64,
        status="completed",
    ) is True
    assert scalar(
        isolated_database,
        "SELECT count(*) FROM attempts WHERE job_id = %s AND step_key = %s",
        (job_uuid, "stale-step"),
    ) == 1
    assert state.finalize_workflow(isolated_database.dsn, job_uuid, 2) is True


def test_attempts_unique_includes_generation(isolated_database, tmp_path):
    job = submit(isolated_database.dsn, write_request(tmp_path))
    job_uuid = uuid.UUID(job["job_id"])

    assert state.claim_next(isolated_database.dsn, "worker-a")["generation"] == 1
    assert state.record_attempt(
        isolated_database.dsn,
        job_uuid,
        stage="prepare",
        step_key="same-step",
        attempt_no=1,
        generation=1,
        input_digest="sha256:" + "1" * 64,
        status="completed",
        result={"generation": 1},
    )
    isolated_database.connection.execute(
        "UPDATE jobs SET lease_expires_at = now() - interval '1 second' "
        "WHERE job_id = %s",
        (job_uuid,),
    )
    assert state.claim_next(isolated_database.dsn, "worker-b")["generation"] == 2
    assert state.record_attempt(
        isolated_database.dsn,
        job_uuid,
        stage="prepare",
        step_key="same-step",
        attempt_no=1,
        generation=2,
        input_digest="sha256:" + "2" * 64,
        status="completed",
        result={"generation": 2},
    )

    rows = isolated_database.connection.execute(
        "SELECT generation, result FROM attempts WHERE job_id = %s "
        "AND stage = 'prepare' AND step_key = 'same-step' AND attempt_no = 1 "
        "ORDER BY generation",
        (job_uuid,),
    ).fetchall()
    assert rows == [(1, {"generation": 1}), (2, {"generation": 2})]

    # Re-writing within the same generation updates that row instead of
    # creating a third history row.
    assert state.record_attempt(
        isolated_database.dsn,
        job_uuid,
        stage="prepare",
        step_key="same-step",
        attempt_no=1,
        generation=2,
        input_digest="sha256:" + "3" * 64,
        status="failed",
        result={"generation": 2, "retry": True},
    )
    rows = isolated_database.connection.execute(
        "SELECT generation, status FROM attempts WHERE job_id = %s "
        "AND stage = 'prepare' AND step_key = 'same-step' AND attempt_no = 1 "
        "ORDER BY generation",
        (job_uuid,),
    ).fetchall()
    assert rows == [(1, "completed"), (2, "failed")]


def test_finalize_after_block_succeeds(isolated_database, tmp_path):
    job = submit(isolated_database.dsn, write_request(tmp_path))
    job_uuid = uuid.UUID(job["job_id"])
    claimed = state.claim_next(isolated_database.dsn, "worker-a")
    assert claimed["generation"] == 1

    state.block_job(
        isolated_database.dsn,
        job_uuid,
        generation=1,
        reason_code="REVIEW_REJECTED",
        message="operator rejected the plan",
    )
    row = isolated_database.connection.execute(
        "SELECT state, workflow_synced, lease_owner, lease_expires_at "
        "FROM jobs WHERE job_id = %s",
        (job_uuid,),
    ).fetchone()
    assert row[0] == "BLOCKED"
    assert row[1] is False
    assert row[2] == "worker-a"
    assert row[3] is not None, "block_job must leave the lease for finalize to clear"

    assert state.finalize_workflow(isolated_database.dsn, job_uuid, 1) is True
    row = isolated_database.connection.execute(
        "SELECT state, workflow_synced, lease_owner, lease_expires_at "
        "FROM jobs WHERE job_id = %s",
        (job_uuid,),
    ).fetchone()
    assert row == ("BLOCKED", True, None, None)


def test_no_double_claim_under_two_connections(isolated_database, tmp_path):
    job = submit(isolated_database.dsn, write_request(tmp_path))
    barrier = threading.Barrier(2)
    results = []
    errors = []

    def claim(worker_id):
        try:
            barrier.wait(timeout=10)
            results.append(state.claim_next(isolated_database.dsn, worker_id))
        except BaseException as error:  # noqa: BLE001 - re-raised in the test
            errors.append(error)

    threads = [
        threading.Thread(target=claim, args=(f"worker-{index}",), daemon=True)
        for index in (1, 2)
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=30)
    assert not errors, errors
    assert all(not thread.is_alive() for thread in threads)

    claimed = [result for result in results if result is not None]
    assert len(claimed) == 1
    assert claimed[0]["generation"] == 1
    assert scalar(
        isolated_database,
        "SELECT generation FROM jobs WHERE job_id = %s",
        (uuid.UUID(job["job_id"]),),
    ) == 1


def test_block_before_plan_is_recovered_after_lease_expiry(
    isolated_database, tmp_path
):
    job = submit(isolated_database.dsn, write_request(tmp_path))
    job_uuid = uuid.UUID(job["job_id"])

    claimed = state.claim_next(isolated_database.dsn, "worker-a")
    assert claimed is not None
    assert claimed["generation"] == 1
    state.block_job(
        isolated_database.dsn,
        job_uuid,
        generation=claimed["generation"],
        reason_code="MATERIAL_MISSING",
        message="required source is missing before a plan exists",
    )
    assert scalar(
        isolated_database,
        "SELECT count(*) FROM plans WHERE job_id = %s",
        (job_uuid,),
    ) == 0
    crashed = isolated_database.connection.execute(
        "SELECT state, workflow_synced, lease_owner IS NOT NULL FROM jobs "
        "WHERE job_id = %s",
        (job_uuid,),
    ).fetchone()
    assert crashed == ("BLOCKED", False, True)

    # The worker exited after block_job but before finalize_workflow, so the
    # synced flag stays false until the lease expires and a worker retries.
    isolated_database.connection.execute(
        "UPDATE jobs SET lease_expires_at = now() - interval '1 second' "
        "WHERE job_id = %s",
        (job_uuid,),
    )
    result = workflow.run_worker(isolated_database.dsn, once=True)
    assert result["processed"] == 1
    assert result["state"] == "BLOCKED"
    assert result["workflow"] == "completed"

    current = state.load_job(isolated_database.dsn, job_uuid)
    assert current["state"] == "BLOCKED"
    assert current["reason_code"] == "MATERIAL_MISSING"
    assert current["workflow_synced"] is True
    assert current["lease_owner"] is None
    assert current["lease_expires_at"] is None
    assert scalar(
        isolated_database,
        "SELECT count(*) FROM plans WHERE job_id = %s",
        (job_uuid,),
    ) == 0
    snapshot = checkpoint_snapshot(isolated_database, job["job_id"])
    assert snapshot.next == ()
    assert not snapshot.interrupts

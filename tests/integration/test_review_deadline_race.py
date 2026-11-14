"""Regression tests for decisions that wait on the job row lock.

PostgreSQL ``now()`` is the transaction start time. A review transaction can
start before the review deadline and then block on ``SELECT ... FOR UPDATE``
until after the deadline; comparing with ``now()`` would approve the review.
Every decision-sensitive write must use ``clock_timestamp()`` after the lock
has actually been acquired.
"""

from __future__ import annotations

import threading
import time
from uuid import UUID

import psycopg
import pytest

from datacon import state, workflow
from support import scalar, submit, write_request

pytestmark = pytest.mark.postgres


def _awaiting_review(database, tmp_path):
    job = submit(database.dsn, write_request(tmp_path))
    result = workflow.run_worker(database.dsn, once=True)
    assert result["state"] == "AWAITING_REVIEW"
    job_uuid = UUID(job["job_id"])
    plan = state.get_plan(database.dsn, job_uuid)
    assert plan is not None
    return job_uuid, plan["plan_digest"]


def _hold_job_lock(dsn, job_id):
    connection = psycopg.connect(dsn, connect_timeout=5)
    try:
        connection.execute(
            "SELECT job_id FROM jobs WHERE job_id = %s FOR UPDATE", (job_id,)
        )
    except BaseException:  # pragma: no cover - defensive cleanup
        connection.close()
        raise
    return connection


def _wait_for_lock_wait(database, timeout=10.0):
    """Wait until a review transaction is actually waiting on the job row."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        waiting = scalar(
            database,
            "SELECT count(*) FROM pg_stat_activity "
            "WHERE wait_event_type = 'Lock' "
            "AND pid <> pg_backend_pid() "
            "AND query LIKE %s",
            ("%FROM jobs WHERE job_id%",),
        )
        if waiting:
            return
        time.sleep(0.02)
    raise AssertionError("the review transaction never waited on the job row lock")


def _run_in_thread(call):
    result = {}
    errors = []

    def runner():
        try:
            result["value"] = call()
        except BaseException as error:  # noqa: BLE001 - re-raised by caller
            errors.append(error)

    thread = threading.Thread(target=runner, daemon=True)
    thread.start()
    return thread, result, errors


def _join(thread, result, errors):
    thread.join(timeout=30)
    assert not thread.is_alive(), "the review thread did not finish"
    if errors:
        raise errors[0]
    return result.get("value")


def _release_after(connection, seconds=1.0):
    """Keep the row lock for a while, then commit and return the DB time."""
    time.sleep(seconds)
    released_at = connection.execute(
        "SELECT clock_timestamp() AS released_at"
    ).fetchone()[0]
    connection.commit()
    return released_at


def _pass_deadline_then_release(connection, job_id, column, seconds=1.0):
    """Move a deadline just past now, wait for it, then release the row lock.

    The holder already owns the row lock, so it may update the row while the
    review transaction is blocked. The blocked transaction started earlier;
    its ``now()`` remains before the new deadline, which is exactly the bug.
    """
    connection.execute(
        f"UPDATE jobs SET {column} = "
        "clock_timestamp() + make_interval(secs => %s) "
        "WHERE job_id = %s",
        (seconds, job_id),
    )
    remaining = connection.execute(
        f"SELECT extract(epoch FROM ({column} - clock_timestamp())) "
        "FROM jobs WHERE job_id = %s",
        (job_id,),
    ).fetchone()[0]
    assert remaining is not None
    time.sleep(float(remaining) + 0.2)
    released_at = connection.execute(
        "SELECT clock_timestamp() AS released_at"
    ).fetchone()[0]
    connection.commit()
    return released_at


def test_review_blocked_across_deadline_expires_without_a_decision(
    isolated_database, tmp_path
):
    job_uuid, digest = _awaiting_review(isolated_database, tmp_path)
    holder = _hold_job_lock(isolated_database.dsn, job_uuid)
    try:
        thread, result, errors = _run_in_thread(
            lambda: state.record_review(
                isolated_database.dsn,
                job_uuid,
                plan_digest=digest,
                decision="approve",
                reviewer_id="reviewer-lock-wait",
            )
        )
        _wait_for_lock_wait(isolated_database)
        released_at = _pass_deadline_then_release(
            holder, job_uuid, "review_deadline_at"
        )
    finally:
        holder.close()

    outcome = _join(thread, result, errors)
    assert outcome.status == "expired"
    assert outcome.reason_code == "REVIEW_EXPIRED"
    current = state.load_job(isolated_database.dsn, job_uuid)
    assert current["state"] == "BLOCKED"
    assert current["reason_code"] == "REVIEW_EXPIRED"
    assert scalar(
        isolated_database,
        "SELECT count(*) FROM reviews WHERE job_id = %s",
        (job_uuid,),
    ) == 0
    audit_created_at = scalar(
        isolated_database,
        "SELECT created_at FROM audit_events WHERE job_id = %s "
        "AND event_type = 'review_expired' ORDER BY event_id DESC LIMIT 1",
        (job_uuid,),
    )
    assert audit_created_at is not None
    assert audit_created_at >= released_at


def test_approve_timestamps_are_actual_decision_times(
    isolated_database, tmp_path
):
    job_uuid, digest = _awaiting_review(isolated_database, tmp_path)
    holder = _hold_job_lock(isolated_database.dsn, job_uuid)
    try:
        thread, result, errors = _run_in_thread(
            lambda: state.record_review(
                isolated_database.dsn,
                job_uuid,
                plan_digest=digest,
                decision="approve",
                reviewer_id="reviewer-lock-wait",
            )
        )
        _wait_for_lock_wait(isolated_database)
        released_at = _release_after(holder)
    finally:
        holder.close()

    outcome = _join(thread, result, errors)
    assert outcome.status == "applied"
    assert outcome.state == "READY"

    row = isolated_database.connection.execute(
        "SELECT r.decided_at, j.approved_at, "
        "(SELECT created_at FROM audit_events "
        " WHERE job_id = %s AND event_type = 'review_recorded' "
        " ORDER BY event_id DESC LIMIT 1) AS audit_created_at "
        "FROM reviews r JOIN jobs j ON j.job_id = r.job_id "
        "WHERE r.job_id = %s",
        (job_uuid, job_uuid),
    ).fetchone()
    assert row is not None
    decided_at, approved_at, audit_created_at = row
    assert decided_at >= released_at
    assert approved_at >= released_at
    assert audit_created_at >= released_at


def test_review_deadline_in_the_past_is_expired(
    isolated_database, tmp_path
):
    job_uuid, digest = _awaiting_review(isolated_database, tmp_path)
    isolated_database.connection.execute(
        "UPDATE jobs SET review_deadline_at = clock_timestamp() "
        "WHERE job_id = %s",
        (job_uuid,),
    )

    outcome = state.record_review(
        isolated_database.dsn,
        job_uuid,
        plan_digest=digest,
        decision="approve",
        reviewer_id="reviewer-boundary",
    )

    assert outcome.status == "expired"
    current = state.load_job(isolated_database.dsn, job_uuid)
    assert current["state"] == "BLOCKED"
    assert current["reason_code"] == "REVIEW_EXPIRED"
    assert scalar(
        isolated_database,
        "SELECT count(*) FROM reviews WHERE job_id = %s",
        (job_uuid,),
    ) == 0


def test_expire_review_blocked_across_deadline_still_expires(
    isolated_database, tmp_path
):
    job = submit(isolated_database.dsn, write_request(tmp_path))
    job_uuid = UUID(job["job_id"])
    claimed = state.claim_next(isolated_database.dsn, "worker-a")
    assert claimed is not None
    assert claimed["generation"] == 1
    assert state.freeze_plan(
        isolated_database.dsn,
        job_uuid,
        generation=1,
        plan={"case_id": "lock-wait"},
        plan_digest="sha256:" + "a" * 64,
        summary={},
    ) is True

    holder = _hold_job_lock(isolated_database.dsn, job_uuid)
    try:
        thread, result, errors = _run_in_thread(
            lambda: state.expire_review(
                isolated_database.dsn, job_uuid, generation=1
            )
        )
        _wait_for_lock_wait(isolated_database)
        released_at = _pass_deadline_then_release(
            holder, job_uuid, "review_deadline_at"
        )
    finally:
        holder.close()

    assert _join(thread, result, errors) is True
    current = state.load_job(isolated_database.dsn, job_uuid)
    assert current["state"] == "BLOCKED"
    assert current["reason_code"] == "REVIEW_EXPIRED"
    audit_created_at = scalar(
        isolated_database,
        "SELECT created_at FROM audit_events WHERE job_id = %s "
        "AND event_type = 'review_expired' ORDER BY event_id DESC LIMIT 1",
        (job_uuid,),
    )
    assert audit_created_at is not None
    assert audit_created_at >= released_at


def test_freeze_plan_observes_lock_wait_past_prepare_deadline(
    isolated_database, tmp_path
):
    job = submit(isolated_database.dsn, write_request(tmp_path))
    job_uuid = UUID(job["job_id"])
    claimed = state.claim_next(isolated_database.dsn, "worker-a")
    assert claimed is not None
    assert claimed["generation"] == 1

    holder = _hold_job_lock(isolated_database.dsn, job_uuid)
    try:
        thread, result, errors = _run_in_thread(
            lambda: state.freeze_plan(
                isolated_database.dsn,
                job_uuid,
                generation=1,
                plan={"case_id": "lock-wait"},
                plan_digest="sha256:" + "b" * 64,
                summary={},
            )
        )
        _wait_for_lock_wait(isolated_database)
        _pass_deadline_then_release(holder, job_uuid, "prepare_deadline_at")
    finally:
        holder.close()

    assert _join(thread, result, errors) is False
    current = state.load_job(isolated_database.dsn, job_uuid)
    assert current["state"] == "BLOCKED"
    assert current["reason_code"] == "DEADLINE_EXCEEDED"
    assert scalar(
        isolated_database,
        "SELECT count(*) FROM plans WHERE job_id = %s",
        (job_uuid,),
    ) == 0

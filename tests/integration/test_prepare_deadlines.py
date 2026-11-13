"""Regression tests for database-clock deadlines and the freeze guard."""

import ast
from pathlib import Path
import uuid

from psycopg.types.json import Jsonb
import pytest

from datacon import state, workflow
from datacon.agents.analysis import analyze_case as real_analyze_case
from support import scalar, submit, write_request

pytestmark = pytest.mark.postgres


REVIEW_WINDOW_SECONDS = 24 * 60 * 60
STATE_SOURCE = Path(state.__file__).read_text(encoding="utf-8")


def review_window_seconds(database, job_uuid):
    seconds = scalar(
        database,
        "SELECT extract(epoch FROM (review_deadline_at - now())) "
        "FROM jobs WHERE job_id = %s",
        (job_uuid,),
    )
    assert seconds is not None
    return float(seconds)


def assert_review_window_is_24_hours(database, job_uuid):
    seconds = review_window_seconds(database, job_uuid)
    assert REVIEW_WINDOW_SECONDS - 120 <= seconds <= REVIEW_WINDOW_SECONDS + 5


def test_review_deadline_sql_uses_the_database_clock():
    """Guard against a silent switch to the worker process clock.

    The old tests monkeypatched a nonexistent ``workflow.datetime`` attribute,
    so they stayed green even if the implementation used ``datetime.now()`` or
    ``time.time()``. This static guard inspects the real deadline SQL and
    rejects process-clock calls in the state module.
    """
    tree = ast.parse(STATE_SOURCE)
    deadline_sql = [
        node.value
        for node in ast.walk(tree)
        if isinstance(node, ast.Constant)
        and isinstance(node.value, str)
        and "review_deadline_at" in node.value
        and "UPDATE jobs" in node.value
    ]
    assert deadline_sql
    assert all("now()" in statement for statement in deadline_sql)
    assert "datetime" not in STATE_SOURCE
    assert "time.time" not in STATE_SOURCE
    assert "time.monotonic" not in STATE_SOURCE


def test_freeze_plan_review_window_uses_database_clock(
    isolated_database, tmp_path
):
    job = submit(isolated_database.dsn, write_request(tmp_path))
    job_uuid = uuid.UUID(job["job_id"])

    result = workflow.run_worker(isolated_database.dsn, once=True)

    assert result["state"] == "AWAITING_REVIEW"
    assert_review_window_is_24_hours(isolated_database, job_uuid)


def test_ensure_awaiting_review_window_uses_database_clock(
    isolated_database, tmp_path
):
    job = submit(isolated_database.dsn, write_request(tmp_path))
    job_uuid = uuid.UUID(job["job_id"])
    claimed = state.claim_next(isolated_database.dsn, "worker-a")
    assert claimed["generation"] == 1

    # Simulate a plan row written by an interrupted/failed reconciliation so
    # the worker takes the ensure_awaiting_review branch.
    isolated_database.connection.execute(
        "INSERT INTO plans (plan_id, job_id, plan_digest, plan, summary) "
        "VALUES (%s, %s, %s, %s, %s)",
        (
            uuid.uuid4(),
            job_uuid,
            "sha256:" + "a" * 64,
            Jsonb({}),
            Jsonb({}),
        ),
    )
    isolated_database.connection.execute(
        "UPDATE jobs SET lease_expires_at = now() - interval '1 second' "
        "WHERE job_id = %s",
        (job_uuid,),
    )

    result = workflow.run_worker(isolated_database.dsn, once=True)

    assert result["state"] == "AWAITING_REVIEW"
    assert result["workflow"] == "interrupted"
    assert_review_window_is_24_hours(isolated_database, job_uuid)


def test_default_lease_covers_the_maximum_prepare_budget():
    from datacon.contracts import DEFAULT_LIMITS

    assert state.LEASE_SECONDS >= DEFAULT_LIMITS["prepare_seconds"]


def test_claim_lease_is_not_shorter_than_the_prepare_deadline(
    isolated_database, tmp_path
):
    job = submit(isolated_database.dsn, write_request(tmp_path))
    claimed = state.claim_next(isolated_database.dsn, "worker-a")

    assert claimed["lease_expires_at"] >= claimed["prepare_deadline_at"]
    assert job["job_id"] == str(claimed["job_id"])


def test_prepare_deadline_passed_during_analysis_blocks_before_plan(
    isolated_database, tmp_path, monkeypatch
):
    job = submit(isolated_database.dsn, write_request(tmp_path))
    job_uuid = uuid.UUID(job["job_id"])

    def expires_during_analysis(request, **kwargs):
        analyzed = real_analyze_case(request, **kwargs)
        isolated_database.connection.execute(
            "UPDATE jobs SET prepare_deadline_at = now() - interval '1 second' "
            "WHERE job_id = %s",
            (job_uuid,),
        )
        return analyzed

    monkeypatch.setattr(workflow, "analyze_case", expires_during_analysis)
    result = workflow.run_worker(isolated_database.dsn, once=True)

    assert result["state"] == "BLOCKED"
    assert result["workflow"] == "completed"
    current = state.load_job(isolated_database.dsn, job_uuid)
    assert current["reason_code"] == "DEADLINE_EXCEEDED"
    assert current["workflow_synced"] is True
    assert current["lease_owner"] is None
    assert current["lease_expires_at"] is None
    assert scalar(
        isolated_database,
        "SELECT count(*) FROM plans WHERE job_id = %s",
        (job_uuid,),
    ) == 0
    assert scalar(
        isolated_database,
        "SELECT count(*) FROM attempts WHERE job_id = %s AND step_key = 'plan'",
        (job_uuid,),
    ) == 0

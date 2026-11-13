"""Regression tests for database-clock deadlines and the freeze guard."""

import datetime as dt
import uuid

from psycopg.types.json import Jsonb
import pytest

from datacon import state, workflow
from datacon.agents.analysis import analyze_case as real_analyze_case
from support import scalar, submit, write_request

pytestmark = pytest.mark.postgres


REVIEW_WINDOW_SECONDS = 24 * 60 * 60


def shift_process_clock(monkeypatch, days):
    """Shift only the Python wall clock used by the worker process."""

    class Shifted(dt.datetime):
        @classmethod
        def now(cls, tz=None):
            return dt.datetime.now(tz) + dt.timedelta(days=days)

    monkeypatch.setattr(workflow, "datetime", Shifted, raising=False)


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
    # Allow a few seconds for the worker pass and this query, but reject the
    # 48 hour / near-zero windows produced by a skewed process clock.
    assert REVIEW_WINDOW_SECONDS - 120 <= seconds <= REVIEW_WINDOW_SECONDS + 5


@pytest.mark.parametrize("days", [1, -1])
def test_freeze_plan_review_window_uses_database_clock(
    isolated_database, tmp_path, monkeypatch, days
):
    job = submit(isolated_database.dsn, write_request(tmp_path))
    job_uuid = uuid.UUID(job["job_id"])

    shift_process_clock(monkeypatch, days)
    result = workflow.run_worker(isolated_database.dsn, once=True)

    assert result["state"] == "AWAITING_REVIEW"
    assert_review_window_is_24_hours(isolated_database, job_uuid)


def test_ensure_awaiting_review_window_uses_database_clock(
    isolated_database, tmp_path, monkeypatch
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

    shift_process_clock(monkeypatch, 1)
    result = workflow.run_worker(isolated_database.dsn, once=True)

    assert result["state"] == "AWAITING_REVIEW"
    assert result["workflow"] == "interrupted"
    assert_review_window_is_24_hours(isolated_database, job_uuid)


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

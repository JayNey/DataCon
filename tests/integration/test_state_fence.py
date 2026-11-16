"""SQL state fences: lease extension and generation ownership (REQ-05/T05).

These tests deliberately exercise the real PostgreSQL predicates instead of a
fake connection. They are marked ``postgres`` and only run when
``DATACON_TEST_DATABASE_URL`` points at a migrated database.
"""

from __future__ import annotations

from uuid import UUID

import pytest

from datacon import state
from support import review, status, submit, worker, write_request

pytestmark = pytest.mark.postgres


def _approved_job(database, tmp_path) -> UUID:
    job = submit(database.dsn, write_request(tmp_path))
    worker(database.dsn)
    digest = status(database.dsn, job["job_id"])["pending_plan"]["plan_digest"]
    accepted = review(
        database.dsn,
        job["job_id"],
        digest,
        "approve",
        env_extra={"DATACON_OPERATOR_ID": "reviewer-1"},
    )
    assert accepted.returncode == 0, accepted.stderr
    worker(database.dsn)  # sync the graph and finalize READY
    return UUID(job["job_id"])


def _claim(database, job_id: UUID) -> dict:
    claimed = state.claim_next(database.dsn, "state-fence")
    assert claimed is not None
    assert claimed["job_id"] == job_id
    return claimed


def _lease_remaining(database, job_id: UUID) -> float:
    # The isolated fixture connection keeps psycopg's default tuple row
    # factory, so positional indexing is required here.
    row = database.connection.execute(
        "SELECT EXTRACT(EPOCH FROM (lease_expires_at - clock_timestamp())) "
        "AS remaining FROM jobs WHERE job_id = %s",
        (job_id,),
    ).fetchone()
    return float(row[0])


def _state_and_lease(database, job_id: UUID) -> tuple[str, float]:
    row = database.connection.execute(
        "SELECT state, "
        "EXTRACT(EPOCH FROM (lease_expires_at - clock_timestamp())) "
        "AS remaining FROM jobs WHERE job_id = %s",
        (job_id,),
    ).fetchone()
    return row[0], float(row[1])


def test_begin_execution_extends_the_lease_and_fences_the_generation(
    isolated_database, tmp_path
):
    job_id = _approved_job(isolated_database, tmp_path)
    claimed = _claim(isolated_database, job_id)
    generation = claimed["generation"]
    isolated_database.connection.execute(
        "UPDATE jobs SET state = 'READY', stage = 'prepare', "
        "lease_expires_at = clock_timestamp() + interval '5 seconds' "
        "WHERE job_id = %s",
        (job_id,),
    )
    assert _lease_remaining(isolated_database, job_id) < 10

    assert (
        state.begin_execution(
            isolated_database.dsn, job_id, generation=generation
        )
        is True
    )
    state_value, remaining = _state_and_lease(isolated_database, job_id)
    assert state_value == "RUNNING"
    # begin_execution extends the short lease to the approved execute budget.
    assert remaining > 600

    # The same live generation may resume and gets True again.
    assert (
        state.begin_execution(
            isolated_database.dsn, job_id, generation=generation
        )
        is True
    )
    with pytest.raises(state.StaleGeneration):
        state.begin_execution(
            isolated_database.dsn, job_id, generation=generation + 1
        )

    isolated_database.connection.execute(
        "UPDATE jobs SET lease_expires_at = clock_timestamp() - interval '1 second' "
        "WHERE job_id = %s",
        (job_id,),
    )
    with pytest.raises(state.StaleGeneration):
        state.begin_execution(
            isolated_database.dsn, job_id, generation=generation
        )


def test_archive_fence_extends_the_lease_and_rejects_stale_writers(
    isolated_database, tmp_path
):
    job_id = _approved_job(isolated_database, tmp_path)
    claimed = _claim(isolated_database, job_id)
    generation = claimed["generation"]

    assert (
        state.mark_archiving(
            isolated_database.dsn, job_id, generation=generation
        )
        is True
    )
    state_value, before = _state_and_lease(isolated_database, job_id)
    assert state_value == "ARCHIVING"
    # mark_archiving reserves at least 60 seconds, independent of the execute
    # deadline that may already have passed.
    assert before > 30

    # assert_archive_fence must extend a nearly expired archive lease rather
    # than merely observing it.
    isolated_database.connection.execute(
        "UPDATE jobs SET lease_expires_at = clock_timestamp() + interval '5 seconds' "
        "WHERE job_id = %s",
        (job_id,),
    )
    assert _lease_remaining(isolated_database, job_id) < 10
    assert (
        state.assert_archive_fence(
            isolated_database.dsn, job_id, generation=generation
        )
        is True
    )
    after = _lease_remaining(isolated_database, job_id)
    assert after > 30

    with pytest.raises(state.StaleGeneration):
        state.assert_archive_fence(
            isolated_database.dsn, job_id, generation=generation + 1
        )

    isolated_database.connection.execute(
        "UPDATE jobs SET lease_expires_at = clock_timestamp() - interval '1 second' "
        "WHERE job_id = %s",
        (job_id,),
    )
    with pytest.raises(state.StaleGeneration):
        state.assert_archive_fence(
            isolated_database.dsn, job_id, generation=generation
        )
    # An expired lease must never be revived by the fence.
    assert _lease_remaining(isolated_database, job_id) < 0

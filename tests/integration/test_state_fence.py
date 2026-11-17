"""SQL state fences: lease extension and generation ownership (REQ-05/T05).

These tests deliberately exercise the real PostgreSQL predicates instead of a
fake connection. They are marked ``postgres`` and only run when
``DATACON_TEST_DATABASE_URL`` points at a migrated database.
"""

from __future__ import annotations

from uuid import UUID

import pytest

from datacon import execution, state
from support import cli, review, status, submit, worker, write_request

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
    # Make the lease almost expire first. If mark_archiving merely observed
    # the lease (instead of renewing it), the assertions below would fail.
    isolated_database.connection.execute(
        "UPDATE jobs SET lease_expires_at = clock_timestamp() + interval '5 seconds', "
        "execute_deadline_at = clock_timestamp() - interval '1 second' "
        "WHERE job_id = %s",
        (job_id,),
    )
    assert _lease_remaining(isolated_database, job_id) < 10

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


# ---------------------------------------------------------------------------
# S8: archived evidence and the current verdict share one invariant.
# ---------------------------------------------------------------------------

DIGEST = "sha256:" + "a" * 64


def _running_generation(database, tmp_path) -> tuple[UUID, int]:
    job_id = _approved_job(database, tmp_path)
    claimed = _claim(database, job_id)
    generation = claimed["generation"]
    assert (
        state.begin_execution(database.dsn, job_id, generation=generation)
        is True
    )
    return job_id, generation


def _archive_reproduced(database, job_id: UUID, generation: int) -> None:
    assert state.finish_execution(
        database.dsn,
        job_id,
        generation=generation,
        state="REPRODUCED",
        reason_code=None,
        verdict="REPRODUCED",
        verdict_reason="ASAN_SIGNATURE_MATCHED",
        evidence_digest=DIGEST,
        evidence_path=f"/tmp/datacon-bundle-{job_id}",
        evidence_status="archived",
    )


def _revive(database, job_id: UUID) -> int:
    row = database.connection.execute(
        "SELECT generation FROM jobs WHERE job_id = %s", (job_id,)
    ).fetchone()
    generation = int(row[0])
    database.connection.execute(
        "UPDATE jobs SET state = 'RUNNING', lease_owner = 'test', "
        "lease_expires_at = clock_timestamp() + interval '1 hour' "
        "WHERE job_id = %s",
        (job_id,),
    )
    return generation


def test_archived_without_path_or_digest_is_rejected_by_finish_execution(
    isolated_database, tmp_path
):
    job_id, generation = _running_generation(isolated_database, tmp_path)
    with pytest.raises(state.StateError):
        state.finish_execution(
            isolated_database.dsn,
            job_id,
            generation=generation,
            state="FAILED",
            reason_code="EVIDENCE_WRITE_FAILED",
            verdict="REPRODUCED",
            verdict_reason="ASAN_SIGNATURE_MATCHED",
            evidence_status="archived",
            evidence_path=None,
            evidence_digest=None,
        )
    with pytest.raises(state.StateError):
        state.finish_execution(
            isolated_database.dsn,
            job_id,
            generation=generation,
            state="FAILED",
            reason_code="EVIDENCE_WRITE_FAILED",
            verdict="REPRODUCED",
            verdict_reason="ASAN_SIGNATURE_MATCHED",
            evidence_status="archived",
            evidence_path="/tmp/bundle",
            evidence_digest=None,
        )
    row = isolated_database.connection.execute(
        "SELECT state, verdict, evidence_status, evidence_path, evidence_digest "
        "FROM jobs WHERE job_id = %s",
        (job_id,),
    ).fetchone()
    assert row[0] == "RUNNING"
    assert row[1:] == (None, None, None, None)


def test_failed_terminal_clears_current_verdict_and_evidence_pointer(
    isolated_database, tmp_path
):
    job_id, generation = _running_generation(isolated_database, tmp_path)
    _archive_reproduced(isolated_database, job_id, generation)
    revived = _revive(isolated_database, job_id)
    assert state.finish_execution(
        isolated_database.dsn,
        job_id,
        generation=revived,
        state="FAILED",
        reason_code="EVIDENCE_WRITE_FAILED",
        verdict=None,
        verdict_reason=None,
        evidence_status="failed",
        evidence_error="archive failed",
    )
    row = isolated_database.connection.execute(
        "SELECT verdict, verdict_reason, evidence_status, evidence_path, "
        "evidence_digest FROM jobs WHERE job_id = %s",
        (job_id,),
    ).fetchone()
    assert row == (None, None, "failed", None, None)


def test_status_and_export_use_the_same_evidence_invariant(
    isolated_database, tmp_path
):
    job_id, generation = _running_generation(isolated_database, tmp_path)
    _archive_reproduced(isolated_database, job_id, generation)
    revived = _revive(isolated_database, job_id)
    assert state.finish_execution(
        isolated_database.dsn,
        job_id,
        generation=revived,
        state="FAILED",
        reason_code="EVIDENCE_WRITE_FAILED",
        verdict=None,
        verdict_reason=None,
        evidence_status="failed",
    )

    current = state.status(isolated_database.dsn, job_id)
    assert current["verdict"] is None
    assert current["verdict_current"] is False
    assert current["evidence"]["available"] is False

    exported = cli(
        "export",
        str(job_id),
        "--out",
        str(tmp_path / "exported"),
        database_url=isolated_database.dsn,
    )
    assert exported.returncode == 3
    assert "EVIDENCE_NOT_AVAILABLE" in exported.stderr


def test_blocked_context_none_cannot_resurrect_old_reproduced_verdict(
    isolated_database, tmp_path, monkeypatch
):
    job_id, generation = _running_generation(isolated_database, tmp_path)
    _archive_reproduced(isolated_database, job_id, generation)
    revived = _revive(isolated_database, job_id)

    def no_context(*args, **kwargs):
        raise execution.ExecutionBlocked("POLICY_DENIED", "blocked for test")

    monkeypatch.setattr(execution, "_load_context", no_context)
    result = execution._finish_blocked(
        isolated_database.dsn,
        job_id,
        revived,
        execution.ExecutionBlocked("POLICY_DENIED", "blocked for test"),
        context=None,
        case_root=None,
        run_root=tmp_path / "runs",
    )
    assert result.state == "BLOCKED"
    current = state.status(isolated_database.dsn, job_id)
    assert current["state"] == "BLOCKED"
    assert current["verdict"] is None
    assert current["verdict_current"] is False
    assert current["evidence"]["available"] is False
    row = isolated_database.connection.execute(
        "SELECT verdict, evidence_status, evidence_path, evidence_digest "
        "FROM jobs WHERE job_id = %s",
        (job_id,),
    ).fetchone()
    assert row == (None, "failed", None, None)

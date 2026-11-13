from uuid import UUID

import psycopg
import pytest

from datacon import state, workflow
from datacon.agents.analysis import (
    AnalysisBlocked,
    RetryableAnalysisError,
    analyze_case as real_analyze_case,
)
from support import scalar, submit, write_request

pytestmark = pytest.mark.postgres


def queue_job(database, tmp_path):
    return submit(database.dsn, write_request(tmp_path))


def analysis_attempts(database, job_id):
    return database.connection.execute(
        "SELECT attempt_no, status FROM attempts "
        "WHERE job_id = %s AND step_key = 'analysis' ORDER BY attempt_no",
        (UUID(job_id),),
    ).fetchall()


def test_transient_analysis_error_retries_once(
    isolated_database, tmp_path, monkeypatch
):
    job = queue_job(isolated_database, tmp_path)
    calls = []

    def flaky(request, **kwargs):
        calls.append(request)
        if len(calls) == 1:
            raise RetryableAnalysisError("git subprocess timed out")
        return real_analyze_case(request, **kwargs)

    monkeypatch.setattr(workflow, "analyze_case", flaky)

    result = workflow.run_worker(isolated_database.dsn, once=True)

    assert len(calls) == 2
    assert result["state"] == "AWAITING_REVIEW"
    assert analysis_attempts(isolated_database, job["job_id"]) == [
        (1, "infra_error"),
        (2, "completed"),
    ]
    assert scalar(
        isolated_database,
        "SELECT count(*) FROM plans WHERE job_id = %s",
        (UUID(job["job_id"]),),
    ) == 1
    assert scalar(
        isolated_database,
        "SELECT count(*) FROM jobs WHERE job_id = %s AND state = 'FAILED'",
        (UUID(job["job_id"]),),
    ) == 0


def test_persistent_transient_error_fails_after_one_retry(
    isolated_database, tmp_path, monkeypatch
):
    job = queue_job(isolated_database, tmp_path)
    calls = []

    def always_transient(request, **kwargs):
        calls.append(request)
        raise RetryableAnalysisError("checkpoint connection reset")

    monkeypatch.setattr(workflow, "analyze_case", always_transient)

    result = workflow.run_worker(isolated_database.dsn, once=True)

    assert len(calls) == 2, "exactly one extra attempt is allowed"
    assert result["state"] == "FAILED"
    assert analysis_attempts(isolated_database, job["job_id"]) == [
        (1, "infra_error"),
        (2, "infra_error"),
    ]
    assert scalar(
        isolated_database,
        "SELECT count(*) FROM attempts WHERE job_id = %s AND step_key = 'analysis'",
        (UUID(job["job_id"]),),
    ) == 2
    assert scalar(
        isolated_database,
        "SELECT count(*) FROM plans WHERE job_id = %s",
        (UUID(job["job_id"]),),
    ) == 0
    current = isolated_database.connection.execute(
        "SELECT reason_code FROM jobs WHERE job_id = %s",
        (UUID(job["job_id"]),),
    ).fetchone()
    assert current[0] == "ANALYSIS_ERROR"


def test_non_transient_analysis_error_does_not_retry(
    isolated_database, tmp_path, monkeypatch
):
    job = queue_job(isolated_database, tmp_path)
    calls = []

    def blocked(request, **kwargs):
        calls.append(request)
        raise AnalysisBlocked("MATERIAL_MISSING", "required source is missing")

    monkeypatch.setattr(workflow, "analyze_case", blocked)

    result = workflow.run_worker(isolated_database.dsn, once=True)

    assert len(calls) == 1
    assert result["state"] == "BLOCKED"
    # The attempt is reserved before analysis runs, so the durable history
    # still records the execution even though it ended in a business block.
    assert analysis_attempts(isolated_database, job["job_id"]) == [
        (1, "started")
    ]
    assert scalar(
        isolated_database,
        "SELECT count(*) FROM attempts WHERE job_id = %s AND status = 'infra_error'",
        (UUID(job["job_id"]),),
    ) == 0
    current = isolated_database.connection.execute(
        "SELECT reason_code FROM jobs WHERE job_id = %s",
        (UUID(job["job_id"]),),
    ).fetchone()
    assert current[0] == "MATERIAL_MISSING"


def test_retry_respects_prepare_deadline(
    isolated_database, tmp_path, monkeypatch
):
    job = queue_job(isolated_database, tmp_path)
    job_uuid = UUID(job["job_id"])
    calls = []

    def expires_then_fails(request, **kwargs):
        calls.append(request)
        isolated_database.connection.execute(
            "UPDATE jobs SET prepare_deadline_at = now() - interval '1 second' "
            "WHERE job_id = %s",
            (job_uuid,),
        )
        raise RetryableAnalysisError("git subprocess timed out")

    monkeypatch.setattr(workflow, "analyze_case", expires_then_fails)

    result = workflow.run_worker(isolated_database.dsn, once=True)

    assert len(calls) == 1
    assert result["state"] == "BLOCKED"
    assert analysis_attempts(isolated_database, job["job_id"]) == [
        (1, "infra_error")
    ]
    current = isolated_database.connection.execute(
        "SELECT reason_code FROM jobs WHERE job_id = %s", (job_uuid,)
    ).fetchone()
    assert current[0] == "DEADLINE_EXCEEDED"


def test_transient_workflow_error_retries_once(
    isolated_database, tmp_path, monkeypatch
):
    job = queue_job(isolated_database, tmp_path)
    real_build = workflow.build_graph

    class FlakyGraph:
        def __init__(self, inner):
            self.inner = inner
            self.state_calls = 0

        def get_state(self, config):
            self.state_calls += 1
            if self.state_calls == 1:
                raise psycopg.OperationalError("checkpoint connection reset")
            return self.inner.get_state(config)

        def invoke(self, *args, **kwargs):
            return self.inner.invoke(*args, **kwargs)

    def build(dsn, checkpointer, **kwargs):
        return FlakyGraph(real_build(dsn, checkpointer, **kwargs))

    monkeypatch.setattr(workflow, "build_graph", build)

    result = workflow.run_worker(isolated_database.dsn, once=True)

    assert result["state"] == "AWAITING_REVIEW"
    assert isolated_database.connection.execute(
        "SELECT attempt_no, status FROM attempts "
        "WHERE job_id = %s AND step_key = 'workflow' ORDER BY attempt_no",
        (UUID(job["job_id"]),),
    ).fetchall() == [(1, "infra_error"), (2, "completed")]
    assert scalar(
        isolated_database,
        "SELECT count(*) FROM jobs WHERE job_id = %s AND state = 'FAILED'",
        (UUID(job["job_id"]),),
    ) == 0


def test_workflow_retry_reuses_completed_analysis_and_keeps_history(
    isolated_database, tmp_path, monkeypatch
):
    job = queue_job(isolated_database, tmp_path)
    analysis_calls = []

    def flaky_analysis(request, **kwargs):
        analysis_calls.append(request)
        if len(analysis_calls) == 1:
            raise RetryableAnalysisError("first analysis attempt timed out")
        return real_analyze_case(request, **kwargs)

    original_freeze = workflow.state_store.freeze_plan
    freeze_calls = []

    def flaky_freeze(*args, **kwargs):
        freeze_calls.append(1)
        if len(freeze_calls) == 1:
            raise psycopg.OperationalError("checkpoint connection reset")
        return original_freeze(*args, **kwargs)

    monkeypatch.setattr(workflow, "analyze_case", flaky_analysis)
    monkeypatch.setattr(workflow.state_store, "freeze_plan", flaky_freeze)

    result = workflow.run_worker(isolated_database.dsn, once=True)

    job_uuid = UUID(job["job_id"])
    assert len(analysis_calls) == 2, "analysis must not run a third time"
    assert len(freeze_calls) == 2
    assert analysis_attempts(isolated_database, job["job_id"]) == [
        (1, "infra_error"),
        (2, "completed"),
    ]
    assert scalar(
        isolated_database,
        "SELECT count(*) FROM attempts WHERE job_id = %s "
        "AND step_key = 'analysis' AND attempt_no = 1 "
        "AND status = 'infra_error'",
        (job_uuid,),
    ) == 1, "the attempt 1 infra_error must not be overwritten"
    assert isolated_database.connection.execute(
        "SELECT attempt_no, status FROM attempts "
        "WHERE job_id = %s AND step_key = 'workflow' ORDER BY attempt_no",
        (job_uuid,),
    ).fetchall() == [(1, "infra_error"), (2, "completed")]
    assert result["state"] == "AWAITING_REVIEW"
    assert scalar(
        isolated_database,
        "SELECT count(*) FROM plans WHERE job_id = %s",
        (job_uuid,),
    ) == 1
    assert scalar(
        isolated_database,
        "SELECT count(*) FROM jobs WHERE job_id = %s AND state = 'FAILED'",
        (job_uuid,),
    ) == 0


def test_workflow_retry_after_freeze_failure_records_completion(
    isolated_database, tmp_path, monkeypatch
):
    job = queue_job(isolated_database, tmp_path)
    analysis_calls = []

    def counting_analysis(request, **kwargs):
        analysis_calls.append(request)
        return real_analyze_case(request, **kwargs)

    original_freeze = workflow.state_store.freeze_plan
    freeze_calls = []

    def flaky_freeze(*args, **kwargs):
        freeze_calls.append(1)
        if len(freeze_calls) == 1:
            raise psycopg.OperationalError("checkpoint connection reset")
        return original_freeze(*args, **kwargs)

    monkeypatch.setattr(workflow, "analyze_case", counting_analysis)
    monkeypatch.setattr(workflow.state_store, "freeze_plan", flaky_freeze)

    result = workflow.run_worker(isolated_database.dsn, once=True)

    job_uuid = UUID(job["job_id"])
    assert len(analysis_calls) == 1, "the retry must reuse the analysis draft"
    assert analysis_attempts(isolated_database, job["job_id"]) == [(1, "completed")]
    assert isolated_database.connection.execute(
        "SELECT attempt_no, status FROM attempts "
        "WHERE job_id = %s AND step_key = 'workflow' ORDER BY attempt_no",
        (job_uuid,),
    ).fetchall() == [(1, "infra_error"), (2, "completed")]
    assert result["state"] == "AWAITING_REVIEW"
    assert scalar(
        isolated_database,
        "SELECT count(*) FROM plans WHERE job_id = %s",
        (job_uuid,),
    ) == 1


def draft_writes(database, job_id, *, generation=None):
    query = (
        "SELECT attempt_no, status, result FROM attempts "
        "WHERE job_id = %s AND step_key = 'analysis' ORDER BY generation, attempt_no"
    )
    params = (UUID(job_id),)
    if generation is not None:
        query = (
            "SELECT attempt_no, status, result FROM attempts "
            "WHERE job_id = %s AND step_key = 'analysis' AND generation = %s "
            "ORDER BY attempt_no"
        )
        params = (UUID(job_id), generation)
    return database.connection.execute(query, params).fetchall()


def frozen_plan(database, job_uuid):
    return database.connection.execute(
        "SELECT plan, plan_digest, summary FROM plans WHERE job_id = %s",
        (job_uuid,),
    ).fetchone()


def test_draft_write_failure_retries_and_workflow_reuses_the_draft(
    isolated_database, tmp_path, monkeypatch
):
    job = queue_job(isolated_database, tmp_path)
    job_uuid = UUID(job["job_id"])
    analysis_calls = []

    def flaky_analysis(request, **kwargs):
        analysis_calls.append(request)
        if len(analysis_calls) == 1:
            raise RetryableAnalysisError("first analysis attempt timed out")
        return real_analyze_case(request, **kwargs)

    real_record = state.record_attempt
    draft_write_attempts = []

    def flaky_record(*args, **kwargs):
        if (
            kwargs.get("step_key") == "analysis"
            and kwargs.get("status") == "completed"
            and isinstance(kwargs.get("result"), dict)
            and "plan" in kwargs["result"]
        ):
            draft_write_attempts.append(kwargs.get("attempt_no"))
            if len(draft_write_attempts) == 1:
                raise psycopg.OperationalError(
                    "connection reset while writing the analysis draft"
                )
        return real_record(*args, **kwargs)

    real_freeze = state.freeze_plan
    freeze_calls = []

    def flaky_freeze(*args, **kwargs):
        freeze_calls.append(1)
        if len(freeze_calls) == 1:
            raise psycopg.OperationalError("connection reset while freezing")
        return real_freeze(*args, **kwargs)

    monkeypatch.setattr(workflow, "analyze_case", flaky_analysis)
    monkeypatch.setattr(workflow.state_store, "record_attempt", flaky_record)
    monkeypatch.setattr(workflow.state_store, "freeze_plan", flaky_freeze)

    result = workflow.run_worker(isolated_database.dsn, once=True)

    assert len(analysis_calls) == 2, "the draft retry must not rerun analysis"
    assert draft_write_attempts == [2, 2], "one bounded draft retry is allowed"
    assert len(freeze_calls) == 2
    assert result["state"] == "AWAITING_REVIEW"
    assert analysis_attempts(isolated_database, job["job_id"]) == [
        (1, "infra_error"),
        (2, "completed"),
    ]
    assert isolated_database.connection.execute(
        "SELECT attempt_no, status FROM attempts "
        "WHERE job_id = %s AND step_key = 'workflow' ORDER BY attempt_no",
        (job_uuid,),
    ).fetchall() == [(1, "infra_error"), (2, "completed")]
    assert scalar(
        isolated_database,
        "SELECT count(*) FROM plans WHERE job_id = %s",
        (job_uuid,),
    ) == 1

    rows = draft_writes(isolated_database, job["job_id"])
    assert [(row[0], row[1]) for row in rows] == [
        (1, "infra_error"),
        (2, "completed"),
    ]
    plan, digest, summary = frozen_plan(isolated_database, job_uuid)
    draft = rows[-1][2]
    assert draft["plan"] == plan
    assert draft["plan_digest"] == digest
    assert draft["summary"] == summary


def test_draft_write_failure_twice_fails_closed_without_third_analysis(
    isolated_database, tmp_path, monkeypatch
):
    job = queue_job(isolated_database, tmp_path)
    job_uuid = UUID(job["job_id"])
    analysis_calls = []

    def flaky_analysis(request, **kwargs):
        analysis_calls.append(request)
        if len(analysis_calls) == 1:
            raise RetryableAnalysisError("first analysis attempt timed out")
        return real_analyze_case(request, **kwargs)

    real_record = state.record_attempt
    draft_write_attempts = []

    def failing_record(*args, **kwargs):
        if (
            kwargs.get("step_key") == "analysis"
            and kwargs.get("status") == "completed"
            and isinstance(kwargs.get("result"), dict)
            and "plan" in kwargs["result"]
        ):
            draft_write_attempts.append(kwargs.get("attempt_no"))
            raise psycopg.OperationalError(
                "connection reset while writing the analysis draft"
            )
        return real_record(*args, **kwargs)

    real_freeze = state.freeze_plan
    freeze_calls = []

    def flaky_freeze(*args, **kwargs):
        freeze_calls.append(1)
        raise psycopg.OperationalError("connection reset while freezing")

    monkeypatch.setattr(workflow, "analyze_case", flaky_analysis)
    monkeypatch.setattr(workflow.state_store, "record_attempt", failing_record)
    monkeypatch.setattr(workflow.state_store, "freeze_plan", flaky_freeze)

    result = workflow.run_worker(isolated_database.dsn, once=True)

    assert len(analysis_calls) == 2, "analysis must never run a third time"
    assert draft_write_attempts == [2, 2]
    assert freeze_calls == [], "a missing draft must fail closed before freezing"
    assert result["state"] == "FAILED"
    current = isolated_database.connection.execute(
        "SELECT reason_code FROM jobs WHERE job_id = %s", (job_uuid,)
    ).fetchone()
    assert current[0] == "ANALYSIS_ERROR"
    assert scalar(
        isolated_database,
        "SELECT count(*) FROM plans WHERE job_id = %s",
        (job_uuid,),
    ) == 0
    rows = draft_writes(isolated_database, job["job_id"])
    assert [(row[0], row[1]) for row in rows] == [
        (1, "infra_error"),
        (2, "infra_error"),
    ]
    assert rows[-1][2]["phase"] == "analysis_draft"
    assert isolated_database.connection.execute(
        "SELECT count(*) FROM attempts WHERE job_id = %s "
        "AND step_key = 'analysis' AND status = 'completed'",
        (job_uuid,),
    ).fetchone()[0] == 0


def test_new_generation_reanalyzes_after_pre_freeze_process_exit(
    isolated_database, tmp_path, monkeypatch
):
    job = queue_job(isolated_database, tmp_path)
    job_uuid = UUID(job["job_id"])
    analysis_calls = []

    def flaky_analysis(request, **kwargs):
        analysis_calls.append(request)
        if len(analysis_calls) == 1:
            raise RetryableAnalysisError("first analysis attempt timed out")
        return real_analyze_case(request, **kwargs)

    real_freeze = state.freeze_plan

    def die(*args, **kwargs):
        raise SystemExit("simulated process exit after analysis before freeze")

    monkeypatch.setattr(workflow, "analyze_case", flaky_analysis)
    monkeypatch.setattr(workflow.state_store, "freeze_plan", die)
    with pytest.raises(SystemExit):
        workflow.run_worker(isolated_database.dsn, once=True)

    first_generation = scalar(
        isolated_database,
        "SELECT generation FROM jobs WHERE job_id = %s",
        (job_uuid,),
    )
    assert len(analysis_calls) == 2
    old_rows = draft_writes(
        isolated_database, job["job_id"], generation=first_generation
    )
    assert [(row[0], row[1]) for row in old_rows] == [
        (1, "infra_error"),
        (2, "completed"),
    ]

    isolated_database.connection.execute(
        "UPDATE jobs SET lease_expires_at = now() - interval '1 second' "
        "WHERE job_id = %s",
        (job_uuid,),
    )
    monkeypatch.setattr(workflow.state_store, "freeze_plan", real_freeze)
    resumed = workflow.run_worker(isolated_database.dsn, once=True)

    assert resumed["state"] == "AWAITING_REVIEW"
    new_generation = scalar(
        isolated_database,
        "SELECT generation FROM jobs WHERE job_id = %s",
        (job_uuid,),
    )
    assert new_generation == first_generation + 1
    assert len(analysis_calls) == 3, "the new generation runs one analysis"

    # Once a new generation owns the slot, the crashed generation can no
    # longer append attempts or finalize.
    assert state.record_attempt(
        isolated_database.dsn,
        job_uuid,
        stage="prepare",
        step_key="analysis",
        attempt_no=3,
        generation=first_generation,
        input_digest=None,
        status="completed",
    ) is False
    assert state.finalize_workflow(
        isolated_database.dsn, job_uuid, first_generation
    ) is False
    assert draft_writes(
        isolated_database, job["job_id"], generation=first_generation
    ) == old_rows, "the old generation's attempt history is preserved"
    new_rows = draft_writes(
        isolated_database, job["job_id"], generation=new_generation
    )
    assert [(row[0], row[1]) for row in new_rows] == [(1, "completed")]
    assert scalar(
        isolated_database,
        "SELECT count(*) FROM plans WHERE job_id = %s",
        (job_uuid,),
    ) == 1
    current = state.load_job(isolated_database.dsn, job_uuid)
    assert current["workflow_synced"] is True
    assert current["lease_owner"] is None


def analysis_rows(database, job_id):
    return database.connection.execute(
        "SELECT attempt_no, status, result FROM attempts "
        "WHERE job_id = %s AND step_key = 'analysis' ORDER BY attempt_no",
        (UUID(job_id),),
    ).fetchall()


def test_infra_error_write_failure_cannot_reset_the_attempt_counter(
    isolated_database, tmp_path, monkeypatch
):
    """Problem A: an unrecorded infra_error must not unlock a third analysis.

    The first execution fails and its ``infra_error`` write fails. The second
    execution also fails. Because the ``started`` row already reserved attempt
    1, the workflow retry consumes attempt 2 and fails closed instead of
    counting from zero and running a third analysis.
    """
    job = queue_job(isolated_database, tmp_path)
    job_uuid = UUID(job["job_id"])
    analysis_calls = []

    def flaky_analysis(request, **kwargs):
        analysis_calls.append(request)
        if len(analysis_calls) <= 2:
            raise RetryableAnalysisError("analysis timed out")
        return real_analyze_case(request, **kwargs)

    real_record = state.record_attempt
    failed_write = {"done": False}

    def failing_record(*args, **kwargs):
        if (
            kwargs.get("step_key") == "analysis"
            and kwargs.get("status") == "infra_error"
            and kwargs.get("attempt_no") == 1
            and not failed_write["done"]
        ):
            failed_write["done"] = True
            raise psycopg.OperationalError(
                "connection reset while recording the infra_error"
            )
        return real_record(*args, **kwargs)

    monkeypatch.setattr(workflow, "analyze_case", flaky_analysis)
    monkeypatch.setattr(workflow.state_store, "record_attempt", failing_record)

    result = workflow.run_worker(isolated_database.dsn, once=True)

    assert len(analysis_calls) == 2, "analysis must never run a third time"
    rows = analysis_rows(isolated_database, job["job_id"])
    assert [row[0] for row in rows] == [1, 2], (
        "every execution must be represented by its own attempt row"
    )
    assert rows[0][1] in ("started", "infra_error")
    assert rows[1][1] == "infra_error"
    assert result["state"] == "FAILED"
    current = isolated_database.connection.execute(
        "SELECT reason_code, workflow_synced, lease_owner "
        "FROM jobs WHERE job_id = %s",
        (job_uuid,),
    ).fetchone()
    assert current[0] == "ANALYSIS_ERROR"
    assert current[1] is True
    assert current[2] is None
    assert scalar(
        isolated_database,
        "SELECT count(*) FROM plans WHERE job_id = %s",
        (job_uuid,),
    ) == 0
    assert scalar(
        isolated_database,
        "SELECT count(*) FROM attempts WHERE job_id = %s "
        "AND result::text LIKE '%%InvalidUpdateError%%'",
        (job_uuid,),
    ) == 0


def test_infra_error_write_failure_reserves_attempt_two_for_the_retry(
    isolated_database, tmp_path, monkeypatch
):
    """The retry after a lost ``infra_error`` write is attempt 2, not attempt 1.

    Pre-fix the failed history write reset the counter, so the retry was
    recorded with ``attempt_no=1`` and the history no longer matched the two
    executions that actually ran.
    """
    job = queue_job(isolated_database, tmp_path)
    job_uuid = UUID(job["job_id"])
    analysis_calls = []

    def flaky_analysis(request, **kwargs):
        analysis_calls.append(request)
        if len(analysis_calls) == 1:
            raise RetryableAnalysisError("analysis timed out")
        return real_analyze_case(request, **kwargs)

    real_record = state.record_attempt
    failed_write = {"done": False}

    def failing_record(*args, **kwargs):
        if (
            kwargs.get("step_key") == "analysis"
            and kwargs.get("status") == "infra_error"
            and kwargs.get("attempt_no") == 1
            and not failed_write["done"]
        ):
            failed_write["done"] = True
            raise psycopg.OperationalError(
                "connection reset while recording the infra_error"
            )
        return real_record(*args, **kwargs)

    monkeypatch.setattr(workflow, "analyze_case", flaky_analysis)
    monkeypatch.setattr(workflow.state_store, "record_attempt", failing_record)

    result = workflow.run_worker(isolated_database.dsn, once=True)

    assert len(analysis_calls) == 2
    assert result["state"] == "AWAITING_REVIEW"
    rows = analysis_rows(isolated_database, job["job_id"])
    assert [(row[0], row[1]) for row in rows] == [
        (1, "started"),
        (2, "completed"),
    ]
    assert scalar(
        isolated_database,
        "SELECT count(*) FROM plans WHERE job_id = %s",
        (job_uuid,),
    ) == 1
    current = state.load_job(isolated_database.dsn, job_uuid)
    assert current["state"] == "AWAITING_REVIEW"
    assert current["workflow_synced"] is True
    assert current["lease_owner"] is None
    assert current["lease_expires_at"] is None
    assert scalar(
        isolated_database,
        "SELECT count(*) FROM jobs WHERE job_id = %s AND state = 'FAILED'",
        (job_uuid,),
    ) == 0


def test_draft_and_block_failures_cannot_run_a_third_analysis(
    isolated_database, tmp_path, monkeypatch
):
    """Problem B: fail-closed block failures must not unlock a third analysis.

    Attempt 1 fails and is recorded. Attempt 2 analyzes successfully, but the
    completed draft is never written, its ``infra_error`` marker fails, and the
    first ``block_job`` fails too. The bounded block retry still fails the job
    closed; a workflow retry must reuse the persisted attempts rather than run
    analysis a third time.
    """
    job = queue_job(isolated_database, tmp_path)
    job_uuid = UUID(job["job_id"])
    analysis_calls = []

    def flaky_analysis(request, **kwargs):
        analysis_calls.append(request)
        if len(analysis_calls) == 1:
            raise RetryableAnalysisError("analysis timed out")
        return real_analyze_case(request, **kwargs)

    real_record = state.record_attempt

    def failing_record(*args, **kwargs):
        if kwargs.get("step_key") != "analysis":
            return real_record(*args, **kwargs)
        if (
            kwargs.get("status") == "completed"
            and isinstance(kwargs.get("result"), dict)
            and "plan" in kwargs["result"]
        ):
            raise psycopg.OperationalError(
                "connection reset while writing the analysis draft"
            )
        if kwargs.get("status") == "infra_error" and kwargs.get("attempt_no") == 2:
            raise psycopg.OperationalError(
                "connection reset while recording the second failure"
            )
        return real_record(*args, **kwargs)

    real_block = state.block_job
    block_calls = []

    def flaky_block(*args, **kwargs):
        block_calls.append(kwargs)
        if len(block_calls) == 1:
            raise psycopg.OperationalError(
                "connection reset while blocking the job"
            )
        return real_block(*args, **kwargs)

    freeze_calls = []
    real_freeze = state.freeze_plan

    def counting_freeze(*args, **kwargs):
        freeze_calls.append(kwargs)
        return real_freeze(*args, **kwargs)

    monkeypatch.setattr(workflow, "analyze_case", flaky_analysis)
    monkeypatch.setattr(workflow.state_store, "record_attempt", failing_record)
    monkeypatch.setattr(workflow.state_store, "block_job", flaky_block)
    monkeypatch.setattr(workflow.state_store, "freeze_plan", counting_freeze)

    result = workflow.run_worker(isolated_database.dsn, once=True)

    assert len(analysis_calls) == 2, "analysis must never run a third time"
    assert freeze_calls == [], "a missing draft must never be frozen"
    assert len(block_calls) == 2, "the fail-closed block gets one bounded retry"
    rows = analysis_rows(isolated_database, job["job_id"])
    assert [row[0] for row in rows] == [1, 2]
    assert rows[0][1] == "infra_error"
    assert rows[1][1] in ("started", "infra_error")
    assert result["state"] == "FAILED"
    current = isolated_database.connection.execute(
        "SELECT reason_code, workflow_synced, lease_owner "
        "FROM jobs WHERE job_id = %s",
        (job_uuid,),
    ).fetchone()
    assert current[0] == "ANALYSIS_ERROR"
    assert current[1] is True
    assert current[2] is None
    assert scalar(
        isolated_database,
        "SELECT count(*) FROM plans WHERE job_id = %s",
        (job_uuid,),
    ) == 0
    assert scalar(
        isolated_database,
        "SELECT count(*) FROM jobs WHERE job_id = %s AND state = 'FAILED'",
        (job_uuid,),
    ) == 1


def test_committed_draft_is_not_downgraded_by_infra_error(
    isolated_database, tmp_path, monkeypatch
):
    """Problem C: a completed draft committed before a reset stays completed.

    Both draft writes commit and then raise, simulating a client that loses
    the connection after the server committed. The durable ``completed`` row
    must be reused; it must never be overwritten with ``infra_error``.
    """
    job = queue_job(isolated_database, tmp_path)
    job_uuid = UUID(job["job_id"])
    analysis_calls = []

    def counting_analysis(request, **kwargs):
        analysis_calls.append(request)
        return real_analyze_case(request, **kwargs)

    real_record = state.record_attempt
    committed = []

    def commit_then_reset(*args, **kwargs):
        if (
            kwargs.get("step_key") == "analysis"
            and kwargs.get("status") == "completed"
            and isinstance(kwargs.get("result"), dict)
            and "plan" in kwargs["result"]
        ):
            stored = real_record(*args, **kwargs)
            assert stored is True, "the draft row must be committed before reset"
            committed.append(kwargs.get("attempt_no"))
            raise psycopg.OperationalError(
                "connection reset after the draft was committed"
            )
        return real_record(*args, **kwargs)

    monkeypatch.setattr(workflow, "analyze_case", counting_analysis)
    monkeypatch.setattr(workflow.state_store, "record_attempt", commit_then_reset)

    result = workflow.run_worker(isolated_database.dsn, once=True)

    assert len(analysis_calls) == 1
    assert committed == [1, 1], "one bounded draft retry is allowed"
    rows = analysis_rows(isolated_database, job["job_id"])
    assert [(row[0], row[1]) for row in rows] == [(1, "completed")]
    assert rows[0][2]["plan_digest"].startswith("sha256:")
    assert scalar(
        isolated_database,
        "SELECT count(*) FROM attempts WHERE job_id = %s "
        "AND step_key = 'analysis' AND status = 'infra_error'",
        (job_uuid,),
    ) == 0, "a committed completed row must never be downgraded"
    assert result["state"] == "AWAITING_REVIEW"
    assert scalar(
        isolated_database,
        "SELECT count(*) FROM plans WHERE job_id = %s",
        (job_uuid,),
    ) == 1
    current = state.load_job(isolated_database.dsn, job_uuid)
    assert current["workflow_synced"] is True
    assert current["lease_owner"] is None


@pytest.mark.parametrize(
    ("phase", "expected_calls"),
    [
        ("started", 0),
        ("draft", 1),
        ("failure_marker", 1),
        ("tool", 1),
    ],
)
def test_record_attempt_false_stops_the_step_without_failing_the_job(
    isolated_database, tmp_path, monkeypatch, phase, expected_calls
):
    """A ``False`` attempt write is never treated as success.

    Whichever write is rejected (attempt reservation, tool audit row, draft,
    or failure marker), the step stops before a new analysis or a plan freeze,
    the job stays ``PREPARING`` rather than being overwritten as ``FAILED``,
    and the next generation converges.
    """
    job = queue_job(isolated_database, tmp_path)
    job_uuid = UUID(job["job_id"])
    analysis_calls = []

    def counting_analysis(request, **kwargs):
        analysis_calls.append(request)
        if phase == "failure_marker" and len(analysis_calls) == 1:
            raise RetryableAnalysisError("analysis timed out")
        return real_analyze_case(request, **kwargs)

    real_record = state.record_attempt
    rejected = {"done": False}

    def false_once(*args, **kwargs):
        if not rejected["done"]:
            matches = (
                phase == "started"
                and kwargs.get("step_key") == "analysis"
                and kwargs.get("status") == "started"
            ) or (
                phase == "draft"
                and kwargs.get("step_key") == "analysis"
                and kwargs.get("status") == "completed"
                and isinstance(kwargs.get("result"), dict)
                and "plan" in kwargs["result"]
            ) or (
                phase == "failure_marker"
                and kwargs.get("step_key") == "analysis"
                and kwargs.get("status") == "infra_error"
            ) or (
                phase == "tool"
                and isinstance(kwargs.get("step_key"), str)
                and kwargs["step_key"].startswith("git.")
                and kwargs.get("status") == "completed"
            )
            if matches:
                rejected["done"] = True
                return False
        return real_record(*args, **kwargs)

    freeze_calls = []
    real_freeze = state.freeze_plan

    def counting_freeze(*args, **kwargs):
        freeze_calls.append(kwargs)
        return real_freeze(*args, **kwargs)

    monkeypatch.setattr(workflow, "analyze_case", counting_analysis)
    monkeypatch.setattr(workflow.state_store, "record_attempt", false_once)
    monkeypatch.setattr(workflow.state_store, "freeze_plan", counting_freeze)

    first = workflow.run_worker(isolated_database.dsn, once=True)

    assert len(analysis_calls) == expected_calls, "no new analysis may start"
    assert freeze_calls == [], "a rejected attempt write must not freeze a plan"
    current = state.load_job(isolated_database.dsn, job_uuid)
    assert current["state"] == "PREPARING"
    assert current["reason_code"] is None
    assert current["workflow_synced"] is True
    assert current["lease_owner"] is None
    assert first["state"] == "PREPARING"
    assert scalar(
        isolated_database,
        "SELECT count(*) FROM plans WHERE job_id = %s",
        (job_uuid,),
    ) == 0
    assert scalar(
        isolated_database,
        "SELECT count(*) FROM jobs WHERE job_id = %s AND state = 'FAILED'",
        (job_uuid,),
    ) == 0
    if phase == "tool":
        # The rejected write was the first tool audit row. The analysis must
        # stop there instead of finishing its remaining tool calls.
        assert scalar(
            isolated_database,
            "SELECT count(*) FROM attempts WHERE job_id = %s "
            "AND step_key LIKE 'git.%%'",
            (job_uuid,),
        ) == 0
        assert scalar(
            isolated_database,
            "SELECT count(*) FROM attempts WHERE job_id = %s "
            "AND step_key LIKE 'tree_sitter.%%'",
            (job_uuid,),
        ) == 0

    # The rejected write is transient: the next generation converges.
    recovered = workflow.run_worker(isolated_database.dsn, once=True)
    assert recovered["state"] == "AWAITING_REVIEW"
    assert scalar(
        isolated_database,
        "SELECT count(*) FROM plans WHERE job_id = %s",
        (job_uuid,),
    ) == 1
    current = state.load_job(isolated_database.dsn, job_uuid)
    assert current["workflow_synced"] is True
    assert current["lease_owner"] is None


def checkpoint_snapshot(database, job_id):
    from langgraph.checkpoint.postgres import PostgresSaver

    from datacon.workflow import build_graph

    with PostgresSaver.from_conn_string(database.dsn) as saver:
        graph = build_graph(database.dsn, saver)
        return graph.get_state({"configurable": {"thread_id": job_id}})


def test_record_attempt_false_after_freeze_does_not_park_or_finalize(
    isolated_database, tmp_path, monkeypatch
):
    """A rejected plan-row write stops before the review interrupt.

    The plan is already frozen, so the next claim reads the existing plan.
    This worker must not write a checkpoint or finalize after its lease is
    gone, and the job must never become FAILED.
    """
    job = queue_job(isolated_database, tmp_path)
    job_uuid = UUID(job["job_id"])
    real_record = state.record_attempt
    rejected = {"done": False}

    def false_plan_write(*args, **kwargs):
        if (
            not rejected["done"]
            and kwargs.get("step_key") == "plan"
            and kwargs.get("status") == "completed"
        ):
            rejected["done"] = True
            isolated_database.connection.execute(
                "UPDATE jobs SET lease_expires_at = now() - interval '1 second' "
                "WHERE job_id = %s",
                (job_uuid,),
            )
            return False
        return real_record(*args, **kwargs)

    monkeypatch.setattr(workflow.state_store, "record_attempt", false_plan_write)

    expire_calls = []
    real_expire = state.expire_review

    def spy_expire(*args, **kwargs):
        expire_calls.append(args)
        return real_expire(*args, **kwargs)

    monkeypatch.setattr(workflow.state_store, "expire_review", spy_expire)

    first = workflow.run_worker(isolated_database.dsn, once=True)

    assert first["processed"] == 1
    assert expire_calls == [], "the rejected plan write must stop before await_review"
    assert scalar(
        isolated_database,
        "SELECT count(*) FROM plans WHERE job_id = %s",
        (job_uuid,),
    ) == 1
    current = state.load_job(isolated_database.dsn, job_uuid)
    assert current["state"] == "AWAITING_REVIEW"
    assert current["reason_code"] is None
    assert current["workflow_synced"] is False
    assert current["lease_expires_at"] is not None
    assert scalar(
        isolated_database,
        "SELECT count(*) FROM jobs WHERE job_id = %s AND state = 'FAILED'",
        (job_uuid,),
    ) == 0
    # The stale worker must not have parked a second scheduling pass at the
    # review interrupt after its plan write was rejected.
    assert not checkpoint_snapshot(isolated_database, job["job_id"]).interrupts

    # The lease is already expired; the next generation converges.
    recovered = workflow.run_worker(isolated_database.dsn, once=True)
    assert recovered["state"] == "AWAITING_REVIEW"
    current = state.load_job(isolated_database.dsn, job_uuid)
    assert current["workflow_synced"] is True
    assert current["lease_owner"] is None
    assert scalar(
        isolated_database,
        "SELECT count(*) FROM plans WHERE job_id = %s",
        (job_uuid,),
    ) == 1


class _FlakyGraph:
    """Wrap the real graph and fail the first ``get_state`` calls."""

    def __init__(self, inner, *, failures):
        self.inner = inner
        self.failures = failures
        self.state_calls = 0

    def get_state(self, config):
        self.state_calls += 1
        if self.state_calls <= self.failures:
            raise psycopg.OperationalError("checkpoint connection reset")
        return self.inner.get_state(config)

    def invoke(self, *args, **kwargs):
        return self.inner.invoke(*args, **kwargs)


def test_workflow_completion_write_false_does_not_finalize(
    isolated_database, tmp_path, monkeypatch
):
    """A rejected workflow ``completed`` row leaves the lease for a retry."""
    job = queue_job(isolated_database, tmp_path)
    job_uuid = UUID(job["job_id"])
    real_build = workflow.build_graph
    graphs = []

    def build(dsn, checkpointer, **kwargs):
        graph = _FlakyGraph(
            real_build(dsn, checkpointer, **kwargs), failures=1
        )
        graphs.append(graph)
        return graph

    real_record = state.record_attempt

    def reject_workflow_completed(*args, **kwargs):
        if (
            kwargs.get("step_key") == "workflow"
            and kwargs.get("status") == "completed"
        ):
            return False
        return real_record(*args, **kwargs)

    monkeypatch.setattr(workflow, "build_graph", build)
    monkeypatch.setattr(
        workflow.state_store, "record_attempt", reject_workflow_completed
    )

    first = workflow.run_worker(isolated_database.dsn, once=True)

    assert first["processed"] == 1
    assert scalar(
        isolated_database,
        "SELECT count(*) FROM plans WHERE job_id = %s",
        (job_uuid,),
    ) == 1
    rows = isolated_database.connection.execute(
        "SELECT attempt_no, status FROM attempts "
        "WHERE job_id = %s AND step_key = 'workflow' ORDER BY attempt_no",
        (job_uuid,),
    ).fetchall()
    assert rows == [(1, "infra_error")]
    current = state.load_job(isolated_database.dsn, job_uuid)
    assert current["state"] == "AWAITING_REVIEW"
    assert current["workflow_synced"] is False
    assert current["lease_owner"] is not None
    assert current["lease_expires_at"] is not None

    # The next claim syncs the parked review once the lease expires. It is a
    # fresh worker process, so the injected checkpoint failure is gone.
    monkeypatch.setattr(workflow, "build_graph", real_build)
    isolated_database.connection.execute(
        "UPDATE jobs SET lease_expires_at = now() - interval '1 second' "
        "WHERE job_id = %s",
        (job_uuid,),
    )
    recovered = workflow.run_worker(isolated_database.dsn, once=True)
    assert recovered["state"] == "AWAITING_REVIEW"
    current = state.load_job(isolated_database.dsn, job_uuid)
    assert current["workflow_synced"] is True
    assert current["lease_owner"] is None


def test_workflow_failure_write_false_stops_the_retry(
    isolated_database, tmp_path, monkeypatch
):
    """A rejected ``infra_error`` row means the lease is gone: do not retry."""
    job = queue_job(isolated_database, tmp_path)
    job_uuid = UUID(job["job_id"])
    real_build = workflow.build_graph
    graphs = []

    class FlakyInvoke:
        def __init__(self, inner):
            self.inner = inner
            self.invoke_calls = 0

        def get_state(self, config):
            return self.inner.get_state(config)

        def invoke(self, *args, **kwargs):
            self.invoke_calls += 1
            raise psycopg.OperationalError("checkpoint connection reset")

    def build(dsn, checkpointer, **kwargs):
        graph = FlakyInvoke(real_build(dsn, checkpointer, **kwargs))
        graphs.append(graph)
        return graph

    real_record = state.record_attempt

    def reject_workflow_failure(*args, **kwargs):
        if (
            kwargs.get("step_key") == "workflow"
            and kwargs.get("status") == "infra_error"
        ):
            isolated_database.connection.execute(
                "UPDATE jobs SET lease_expires_at = now() - interval '1 second' "
                "WHERE job_id = %s",
                (job_uuid,),
            )
            return False
        return real_record(*args, **kwargs)

    monkeypatch.setattr(workflow, "build_graph", build)
    monkeypatch.setattr(
        workflow.state_store, "record_attempt", reject_workflow_failure
    )

    first = workflow.run_worker(isolated_database.dsn, once=True)

    assert first["processed"] == 1
    assert graphs[0].invoke_calls == 1, "a lost lease must not be retried"
    assert scalar(
        isolated_database,
        "SELECT count(*) FROM attempts WHERE job_id = %s AND step_key = 'workflow'",
        (job_uuid,),
    ) == 0
    current = state.load_job(isolated_database.dsn, job_uuid)
    assert current["state"] == "PREPARING"
    assert current["reason_code"] is None
    assert scalar(
        isolated_database,
        "SELECT count(*) FROM jobs WHERE job_id = %s AND state = 'FAILED'",
        (job_uuid,),
    ) == 0


def test_record_attempt_rejects_downgrading_a_completed_row(
    isolated_database, tmp_path
):
    """State-level guard: ``infra_error`` cannot overwrite ``completed``."""
    job = queue_job(isolated_database, tmp_path)
    job_uuid = UUID(job["job_id"])
    claimed = state.claim_next(isolated_database.dsn, "worker-a")
    assert claimed is not None
    generation = claimed["generation"]

    assert state.record_attempt(
        isolated_database.dsn,
        job_uuid,
        stage="prepare",
        step_key="analysis",
        attempt_no=1,
        generation=generation,
        input_digest=None,
        status="completed",
        result={"plan_digest": "sha256:" + "1" * 64},
    ) is True
    assert state.record_attempt(
        isolated_database.dsn,
        job_uuid,
        stage="prepare",
        step_key="analysis",
        attempt_no=1,
        generation=generation,
        input_digest=None,
        status="infra_error",
        result={"error": "OperationalError"},
    ) is False
    assert analysis_attempts(isolated_database, job["job_id"]) == [
        (1, "completed")
    ]
    # An idempotent completed rewrite is still accepted.
    assert state.record_attempt(
        isolated_database.dsn,
        job_uuid,
        stage="prepare",
        step_key="analysis",
        attempt_no=1,
        generation=generation,
        input_digest=None,
        status="completed",
        result={"plan_digest": "sha256:" + "1" * 64},
    ) is True
    # A different completed result is not an idempotent rewrite.
    assert state.record_attempt(
        isolated_database.dsn,
        job_uuid,
        stage="prepare",
        step_key="analysis",
        attempt_no=1,
        generation=generation,
        input_digest=None,
        status="completed",
        result={"plan_digest": "sha256:" + "2" * 64},
    ) is False
    # Unknown statuses are contract errors, not silent downgrades.
    with pytest.raises(state.StateError):
        state.record_attempt(
            isolated_database.dsn,
            job_uuid,
            stage="prepare",
            step_key="analysis",
            attempt_no=1,
            generation=generation,
            input_digest=None,
            status="failed",
            result={"error": "not-a-real-status"},
        )
    row = isolated_database.connection.execute(
        "SELECT status, result FROM attempts WHERE job_id = %s "
        "AND stage = 'prepare' AND step_key = 'analysis' AND attempt_no = 1 "
        "AND generation = %s",
        (job_uuid, generation),
    ).fetchone()
    assert row == (
        "completed",
        {"plan_digest": "sha256:" + "1" * 64},
    )


def test_unwritable_block_keeps_preparing_without_a_third_analysis(
    isolated_database, tmp_path, monkeypatch
):
    """When the fail-closed block cannot be written, keep PREPARING.

    The bounded retries are exhausted, but the persisted attempts still prove
    that both analyses ran, so the workflow retry fails closed instead of
    running a third analysis.
    """
    job = queue_job(isolated_database, tmp_path)
    job_uuid = UUID(job["job_id"])
    analysis_calls = []

    def flaky_analysis(request, **kwargs):
        analysis_calls.append(request)
        if len(analysis_calls) == 1:
            raise RetryableAnalysisError("analysis timed out")
        return real_analyze_case(request, **kwargs)

    real_record = state.record_attempt

    def failing_record(*args, **kwargs):
        if kwargs.get("step_key") != "analysis":
            return real_record(*args, **kwargs)
        if (
            kwargs.get("status") == "completed"
            and isinstance(kwargs.get("result"), dict)
            and "plan" in kwargs["result"]
        ):
            raise psycopg.OperationalError(
                "connection reset while writing the analysis draft"
            )
        if kwargs.get("status") == "infra_error" and kwargs.get("attempt_no") == 2:
            raise psycopg.OperationalError(
                "connection reset while recording the second failure"
            )
        return real_record(*args, **kwargs)

    real_block = state.block_job
    block_calls = []

    def failing_block(*args, **kwargs):
        block_calls.append(kwargs)
        raise psycopg.OperationalError("block writes are unavailable")

    monkeypatch.setattr(workflow, "analyze_case", flaky_analysis)
    monkeypatch.setattr(workflow.state_store, "record_attempt", failing_record)
    monkeypatch.setattr(workflow.state_store, "block_job", failing_block)

    result = workflow.run_worker(isolated_database.dsn, once=True)

    assert len(analysis_calls) == 2, "analysis must never run a third time"
    assert block_calls, "the fail-closed block was attempted"
    assert result["state"] == "PREPARING"
    rows = analysis_rows(isolated_database, job["job_id"])
    assert [row[0] for row in rows] == [1, 2]
    assert scalar(
        isolated_database,
        "SELECT count(*) FROM plans WHERE job_id = %s",
        (job_uuid,),
    ) == 0
    assert scalar(
        isolated_database,
        "SELECT count(*) FROM jobs WHERE job_id = %s AND state = 'FAILED'",
        (job_uuid,),
    ) == 0
    current = state.load_job(isolated_database.dsn, job_uuid)
    assert current["state"] == "PREPARING"
    assert current["workflow_synced"] is False
    assert current["lease_owner"] is not None
    # A later claim runs against a fresh generation; this generation never
    # ran a third analysis.
    assert len(
        [
            row
            for row in isolated_database.connection.execute(
                "SELECT attempt_no FROM attempts WHERE job_id = %s "
                "AND step_key = 'workflow' ORDER BY attempt_no",
                (job_uuid,),
            ).fetchall()
        ]
    ) == 2
    monkeypatch.setattr(workflow.state_store, "block_job", real_block)
    monkeypatch.setattr(workflow.state_store, "record_attempt", real_record)
    isolated_database.connection.execute(
        "UPDATE jobs SET lease_expires_at = now() - interval '1 second' "
        "WHERE job_id = %s",
        (job_uuid,),
    )
    recovered = workflow.run_worker(isolated_database.dsn, once=True)
    assert recovered["state"] == "AWAITING_REVIEW"
    assert scalar(
        isolated_database,
        "SELECT count(*) FROM plans WHERE job_id = %s",
        (job_uuid,),
    ) == 1


def test_persistent_freeze_error_keeps_preparing_and_recovers(
    isolated_database, tmp_path, monkeypatch
):
    """A DB/checkpoint failure while freezing is not an analysis failure.

    The analysis has already completed, but the plan cannot be frozen twice.
    The job must stay PREPARING with workflow_synced=false and a live lease;
    the next generation retries and freezes the plan instead of the job
    becoming terminal FAILED/ANALYSIS_ERROR.
    """
    job = queue_job(isolated_database, tmp_path)
    job_uuid = UUID(job["job_id"])
    analysis_calls = []

    def counting_analysis(request, **kwargs):
        analysis_calls.append(request)
        return real_analyze_case(request, **kwargs)

    def failing_freeze(*args, **kwargs):
        raise psycopg.OperationalError("connection reset while freezing")

    real_freeze = state.freeze_plan
    monkeypatch.setattr(workflow, "analyze_case", counting_analysis)
    monkeypatch.setattr(workflow.state_store, "freeze_plan", failing_freeze)

    result = workflow.run_worker(isolated_database.dsn, once=True)

    assert result["state"] == "PREPARING"
    assert len(analysis_calls) == 1
    current = state.load_job(isolated_database.dsn, job_uuid)
    assert current["state"] == "PREPARING"
    assert current["workflow_synced"] is False
    assert current["lease_owner"] is not None
    assert current["reason_code"] is None
    assert scalar(
        isolated_database,
        "SELECT count(*) FROM jobs WHERE job_id = %s AND state = 'FAILED'",
        (job_uuid,),
    ) == 0
    assert scalar(
        isolated_database,
        "SELECT count(*) FROM plans WHERE job_id = %s",
        (job_uuid,),
    ) == 0
    assert analysis_attempts(isolated_database, job["job_id"]) == [
        (1, "completed")
    ]

    # The later generation retries preparation and freezes exactly one plan.
    monkeypatch.setattr(workflow.state_store, "freeze_plan", real_freeze)
    isolated_database.connection.execute(
        "UPDATE jobs SET lease_expires_at = now() - interval '1 second' "
        "WHERE job_id = %s",
        (job_uuid,),
    )
    recovered = workflow.run_worker(isolated_database.dsn, once=True)

    assert recovered["state"] == "AWAITING_REVIEW"
    assert len(analysis_calls) == 2
    assert scalar(
        isolated_database,
        "SELECT count(*) FROM plans WHERE job_id = %s",
        (job_uuid,),
    ) == 1
    current = state.load_job(isolated_database.dsn, job_uuid)
    assert current["state"] == "AWAITING_REVIEW"
    assert current["workflow_synced"] is True
    assert scalar(
        isolated_database,
        "SELECT count(*) FROM jobs WHERE job_id = %s AND state = 'FAILED'",
        (job_uuid,),
    ) == 0


def test_persistent_checkpoint_read_error_keeps_preparing(
    isolated_database, tmp_path, monkeypatch
):
    """A checkpoint read failure must not become FAILED/ANALYSIS_ERROR.

    No analysis has run yet; the escaped ``get_state`` error is a
    checkpoint/infrastructure failure. The job must remain claimable after
    the lease expires and then converge normally.
    """
    job = queue_job(isolated_database, tmp_path)
    job_uuid = UUID(job["job_id"])
    real_build_graph = workflow.build_graph
    analysis_calls = []

    def counting_analysis(request, **kwargs):
        analysis_calls.append(request)
        return real_analyze_case(request, **kwargs)

    class BrokenGraph:
        def get_state(self, config):
            raise psycopg.OperationalError("checkpoint read failed")

    monkeypatch.setattr(
        workflow, "build_graph", lambda *args, **kwargs: BrokenGraph()
    )
    monkeypatch.setattr(workflow, "analyze_case", counting_analysis)

    result = workflow.run_worker(isolated_database.dsn, once=True)

    assert result["state"] == "PREPARING"
    assert analysis_calls == []
    current = state.load_job(isolated_database.dsn, job_uuid)
    assert current["state"] == "PREPARING"
    assert current["workflow_synced"] is False
    assert current["lease_owner"] is not None
    assert scalar(
        isolated_database,
        "SELECT count(*) FROM jobs WHERE job_id = %s AND state = 'FAILED'",
        (job_uuid,),
    ) == 0
    assert scalar(
        isolated_database,
        "SELECT count(*) FROM attempts WHERE job_id = %s "
        "AND step_key = 'workflow' AND status = 'infra_error'",
        (job_uuid,),
    ) == 2

    monkeypatch.setattr(workflow, "build_graph", real_build_graph)
    isolated_database.connection.execute(
        "UPDATE jobs SET lease_expires_at = now() - interval '1 second' "
        "WHERE job_id = %s",
        (job_uuid,),
    )
    recovered = workflow.run_worker(isolated_database.dsn, once=True)

    assert recovered["state"] == "AWAITING_REVIEW"
    assert len(analysis_calls) == 1
    assert scalar(
        isolated_database,
        "SELECT count(*) FROM plans WHERE job_id = %s",
        (job_uuid,),
    ) == 1
    current = state.load_job(isolated_database.dsn, job_uuid)
    assert current["state"] == "AWAITING_REVIEW"
    assert current["workflow_synced"] is True
    assert scalar(
        isolated_database,
        "SELECT count(*) FROM jobs WHERE job_id = %s AND state = 'FAILED'",
        (job_uuid,),
    ) == 0


def test_non_retryable_graph_error_keeps_preparing(
    isolated_database, tmp_path, monkeypatch
):
    """A deterministic graph error is an infra failure, not an analysis failure."""
    job = queue_job(isolated_database, tmp_path)
    job_uuid = UUID(job["job_id"])
    real_build_graph = workflow.build_graph
    analysis_calls = []

    def counting_analysis(request, **kwargs):
        analysis_calls.append(request)
        return real_analyze_case(request, **kwargs)

    class BrokenGraph:
        def get_state(self, config):
            raise ValueError("graph checkpoint is inconsistent")

    monkeypatch.setattr(
        workflow, "build_graph", lambda *args, **kwargs: BrokenGraph()
    )
    monkeypatch.setattr(workflow, "analyze_case", counting_analysis)

    result = workflow.run_worker(isolated_database.dsn, once=True)

    assert result["state"] == "PREPARING"
    assert analysis_calls == []
    current = state.load_job(isolated_database.dsn, job_uuid)
    assert current["state"] == "PREPARING"
    assert current["reason_code"] is None
    assert current["workflow_synced"] is False
    assert current["lease_owner"] is not None
    assert scalar(
        isolated_database,
        "SELECT count(*) FROM jobs WHERE job_id = %s AND state = 'FAILED'",
        (job_uuid,),
    ) == 0
    assert isolated_database.connection.execute(
        "SELECT attempt_no, status, result FROM attempts "
        "WHERE job_id = %s AND step_key = 'workflow' ORDER BY attempt_no",
        (job_uuid,),
    ).fetchall() == [
        (1, "infra_error", {"error": "ValueError"}),
    ]

    monkeypatch.setattr(workflow, "build_graph", real_build_graph)
    isolated_database.connection.execute(
        "UPDATE jobs SET lease_expires_at = now() - interval '1 second' "
        "WHERE job_id = %s",
        (job_uuid,),
    )
    recovered = workflow.run_worker(isolated_database.dsn, once=True)

    assert recovered["state"] == "AWAITING_REVIEW"
    assert len(analysis_calls) == 1
    assert scalar(
        isolated_database,
        "SELECT count(*) FROM plans WHERE job_id = %s",
        (job_uuid,),
    ) == 1
    current = state.load_job(isolated_database.dsn, job_uuid)
    assert current["state"] == "AWAITING_REVIEW"
    assert current["workflow_synced"] is True

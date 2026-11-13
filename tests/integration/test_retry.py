from uuid import UUID

import psycopg
import pytest

from datacon import workflow
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
    assert analysis_attempts(isolated_database, job["job_id"]) == []
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

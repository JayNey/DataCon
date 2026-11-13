"""Regression tests for the append-only audit ledger.

The T03 contract requires auditable claims, plan freezes, review decisions,
review expiry and workflow synchronization. Rejected review attempts must be
visible too, without changing the authoritative plan/state.
"""

import json
from uuid import UUID

import pytest

from support import review, scalar, status, submit, worker, write_request

pytestmark = pytest.mark.postgres


def queue_job(database, tmp_path):
    return submit(database.dsn, write_request(tmp_path))


def events(database, job_id):
    return database.connection.execute(
        "SELECT event_type, reason_code, detail FROM audit_events "
        "WHERE job_id = %s ORDER BY event_id",
        (UUID(job_id),),
    ).fetchall()


def test_audit_events_record_the_full_review_flow(isolated_database, tmp_path):
    job = queue_job(isolated_database, tmp_path)
    worker(isolated_database.dsn)
    pending = status(isolated_database.dsn, job["job_id"])["pending_plan"]
    digest = pending["plan_digest"]

    approved = review(
        isolated_database.dsn,
        job["job_id"],
        digest,
        "approve",
        env_extra={"DATACON_OPERATOR_ID": "reviewer-1"},
    )
    assert approved.returncode == 0, approved.stderr
    worker(isolated_database.dsn)

    rows = events(isolated_database, job["job_id"])
    by_type = {}
    for event_type, reason_code, detail in rows:
        by_type.setdefault(event_type, []).append((reason_code, detail))

    assert len(by_type.get("claim", [])) == 2
    assert by_type["plan_frozen"] == [
        (None, {"generation": 1, "plan_digest": digest})
    ]
    assert len(by_type.get("workflow_synchronized", [])) == 2
    assert by_type["review_recorded"] == [
        (
            None,
            {
                "decision": "approve",
                "reviewer_id": "reviewer-1",
                "plan_digest": digest,
            },
        )
    ]
    assert all(
        record["worker_id"] for _, record in by_type["claim"]
    )


def test_rejected_review_attempts_are_audited(isolated_database, tmp_path):
    job = queue_job(isolated_database, tmp_path)
    worker(isolated_database.dsn)
    digest = status(isolated_database.dsn, job["job_id"])["pending_plan"][
        "plan_digest"
    ]
    wrong = "sha256:" + "0" * 64

    mismatch = review(
        isolated_database.dsn,
        job["job_id"],
        wrong,
        "approve",
        env_extra={"DATACON_OPERATOR_ID": "reviewer-1"},
    )
    assert mismatch.returncode == 3, mismatch.stderr
    assert json.loads(mismatch.stderr)["reason_code"] == "PLAN_MISMATCH"
    assert status(isolated_database.dsn, job["job_id"])["state"] == "AWAITING_REVIEW"
    assert scalar(
        isolated_database,
        "SELECT count(*) FROM reviews WHERE job_id = %s",
        (UUID(job["job_id"]),),
    ) == 0

    mismatch_events = [
        (reason, detail)
        for event_type, reason, detail in events(isolated_database, job["job_id"])
        if event_type == "review_refused"
    ]
    assert mismatch_events == [
        (
            "PLAN_MISMATCH",
            {
                "decision": "approve",
                "reviewer_id": "reviewer-1",
                "requested_digest": wrong,
                "frozen_digest": digest,
            },
        )
    ]

    approved = review(
        isolated_database.dsn,
        job["job_id"],
        digest,
        "approve",
        env_extra={"DATACON_OPERATOR_ID": "reviewer-1"},
    )
    assert approved.returncode == 0, approved.stderr
    conflict = review(
        isolated_database.dsn,
        job["job_id"],
        digest,
        "reject",
        env_extra={"DATACON_OPERATOR_ID": "reviewer-2"},
    )
    assert conflict.returncode == 3, conflict.stderr
    assert json.loads(conflict.stderr)["reason_code"] == "REVIEW_CONFLICT"
    assert status(isolated_database.dsn, job["job_id"])["state"] == "READY"

    conflict_events = [
        (reason, detail)
        for event_type, reason, detail in events(isolated_database, job["job_id"])
        if event_type == "review_refused" and reason == "REVIEW_CONFLICT"
    ]
    assert len(conflict_events) == 1
    detail = conflict_events[0][1]
    assert detail["requested_digest"] == digest
    assert detail["recorded_decision"] == "approve"
    assert detail["recorded_reviewer_id"] == "reviewer-1"


def test_review_expiry_audit_uses_the_frozen_plan_digest(
    isolated_database, tmp_path
):
    job = queue_job(isolated_database, tmp_path)
    worker(isolated_database.dsn)
    digest = status(isolated_database.dsn, job["job_id"])["pending_plan"][
        "plan_digest"
    ]
    wrong = "sha256:" + "0" * 64
    isolated_database.connection.execute(
        "UPDATE jobs SET review_deadline_at = now() - interval '1 second' "
        "WHERE job_id = %s",
        (UUID(job["job_id"]),),
    )

    expired = review(
        isolated_database.dsn,
        job["job_id"],
        wrong,
        "approve",
        env_extra={"DATACON_OPERATOR_ID": "reviewer-1"},
    )
    assert expired.returncode == 3, expired.stderr
    assert json.loads(expired.stderr)["reason_code"] == "REVIEW_EXPIRED"

    expiry_events = [
        (reason, detail)
        for event_type, reason, detail in events(isolated_database, job["job_id"])
        if event_type == "review_expired"
    ]
    assert expiry_events == [
        (
            "REVIEW_EXPIRED",
            {"requested_digest": wrong, "plan_digest": digest},
        )
    ]
    assert status(isolated_database.dsn, job["job_id"])["state"] == "BLOCKED"
    assert scalar(
        isolated_database,
        "SELECT count(*) FROM reviews WHERE job_id = %s",
        (UUID(job["job_id"]),),
    ) == 0

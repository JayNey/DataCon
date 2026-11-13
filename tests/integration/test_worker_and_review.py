import json
from uuid import UUID, uuid4

import pytest

from support import (
    cli,
    copy_cases,
    review,
    scalar,
    status,
    submit,
    worker,
    write_request,
)

pytestmark = pytest.mark.postgres


def queue_job(database, tmp_path, case_id="fixture-c-parser"):
    request = write_request(tmp_path, case_id=case_id)
    return submit(database.dsn, request)


def test_worker_freezes_exactly_one_plan_and_awaits_review(
    isolated_database, tmp_path
):
    job = queue_job(isolated_database, tmp_path)

    first = worker(isolated_database.dsn)
    assert first["processed"] == 1
    assert first["job_id"] == job["job_id"]
    assert first["state"] == "AWAITING_REVIEW"
    assert first["workflow"] == "interrupted"

    current = status(isolated_database.dsn, job["job_id"])
    assert current["state"] == "AWAITING_REVIEW"
    assert current["stage"] == "review"
    assert current["review_state"] is None
    assert current["reason_code"] is None
    assert current["evidence_refs"]

    pending = current["pending_plan"]
    assert pending["plan_digest"].startswith("sha256:")
    assert pending["summary"]["case_id"] == "fixture-c-parser"
    assert pending["summary"]["findings"]["facts"] >= 2
    assert pending["summary"]["revisions"]["vulnerable"] == (
        "07281ef141ece556cf9b0d37dd2233b6beceb566"
    )
    assert pending["plan"]["isolation"]["network"] == "none"
    assert pending["plan"]["analysis"]["changed_paths"] == ["parser.c"]

    assert scalar(
        isolated_database, "SELECT count(*) FROM plans WHERE job_id = %s",
        (UUID(job["job_id"]),),
    ) == 1
    assert scalar(
        isolated_database, "SELECT count(*) FROM reviews WHERE job_id = %s",
        (UUID(job["job_id"]),),
    ) == 0
    assert scalar(
        isolated_database,
        "SELECT count(*) FROM attempts WHERE job_id = %s",
        (UUID(job["job_id"]),),
    ) > 0
    tools = {
        row[0]
        for row in isolated_database.connection.execute(
            "SELECT split_part(step_key, ':', 1) FROM attempts WHERE job_id = %s",
            (UUID(job["job_id"]),),
        ).fetchall()
    }
    assert {"git.resolve", "git.diff", "tree_sitter.extract"} <= tools
    assert "sandbox.build" not in tools

    # A second worker pass without a decision must not create a second plan.
    second = worker(isolated_database.dsn)
    assert second["processed"] == 0
    assert scalar(
        isolated_database, "SELECT count(*) FROM plans WHERE job_id = %s",
        (UUID(job["job_id"]),),
    ) == 1
    assert status(isolated_database.dsn, job["job_id"])["state"] == "AWAITING_REVIEW"


def test_approval_sets_ready_and_duplicate_decisions_are_idempotent(
    isolated_database, tmp_path
):
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
    payload = json.loads(approved.stdout)
    assert payload["state"] == "READY"
    assert payload["idempotent"] is False

    current = status(isolated_database.dsn, job["job_id"])
    assert current["state"] == "READY"
    assert current["stage"] == "ready"
    assert current["review_state"] == {
        "decision": "approve",
        "reviewer_id": "reviewer-1",
        "plan_digest": digest,
        "decided_at": current["review_state"]["decided_at"],
    }
    assert current["pending_plan"]["plan_digest"] == digest
    assert scalar(
        isolated_database, "SELECT count(*) FROM reviews WHERE job_id = %s",
        (UUID(job["job_id"]),),
    ) == 1

    repeat = review(
        isolated_database.dsn,
        job["job_id"],
        digest,
        "approve",
        env_extra={"DATACON_OPERATOR_ID": "reviewer-1"},
    )
    assert repeat.returncode == 0, repeat.stderr
    assert json.loads(repeat.stdout)["idempotent"] is True
    assert scalar(
        isolated_database, "SELECT count(*) FROM reviews WHERE job_id = %s",
        (UUID(job["job_id"]),),
    ) == 1

    conflict = review(
        isolated_database.dsn,
        job["job_id"],
        digest,
        "reject",
        env_extra={"DATACON_OPERATOR_ID": "reviewer-2"},
    )
    assert conflict.returncode == 3
    assert json.loads(conflict.stderr)["reason_code"] == "REVIEW_CONFLICT"
    assert status(isolated_database.dsn, job["job_id"])["state"] == "READY"
    assert scalar(
        isolated_database, "SELECT count(*) FROM reviews WHERE job_id = %s",
        (UUID(job["job_id"]),),
    ) == 1


def test_rejection_blocks_without_any_execution(isolated_database, tmp_path):
    job = queue_job(isolated_database, tmp_path)
    worker(isolated_database.dsn)
    digest = status(isolated_database.dsn, job["job_id"])["pending_plan"][
        "plan_digest"
    ]

    rejected = review(
        isolated_database.dsn,
        job["job_id"],
        digest,
        "reject",
        env_extra={"DATACON_OPERATOR_ID": "reviewer-1"},
    )
    assert rejected.returncode == 0, rejected.stderr
    assert json.loads(rejected.stdout)["state"] == "BLOCKED"

    current = status(isolated_database.dsn, job["job_id"])
    assert current["state"] == "BLOCKED"
    assert current["reason_code"] == "REVIEW_REJECTED"
    assert current["review_state"]["decision"] == "reject"

    resumed = worker(isolated_database.dsn)
    assert resumed["processed"] == 1
    assert resumed["state"] == "BLOCKED"
    assert scalar(
        isolated_database, "SELECT count(*) FROM plans WHERE job_id = %s",
        (UUID(job["job_id"]),),
    ) == 1
    assert scalar(
        isolated_database, "SELECT count(*) FROM reviews WHERE job_id = %s",
        (UUID(job["job_id"]),),
    ) == 1
    assert scalar(
        isolated_database,
        "SELECT count(*) FROM attempts WHERE job_id = %s AND step_key LIKE %s",
        (UUID(job["job_id"]), "sandbox.%"),
    ) == 0


def test_digest_mismatch_keeps_the_pending_plan(isolated_database, tmp_path):
    job = queue_job(isolated_database, tmp_path)
    worker(isolated_database.dsn)
    before = status(isolated_database.dsn, job["job_id"])

    mismatch = review(
        isolated_database.dsn,
        job["job_id"],
        "sha256:" + "0" * 64,
        "approve",
        env_extra={"DATACON_OPERATOR_ID": "reviewer-1"},
    )
    assert mismatch.returncode == 3
    assert json.loads(mismatch.stderr)["reason_code"] == "PLAN_MISMATCH"

    after = status(isolated_database.dsn, job["job_id"])
    assert after["state"] == "AWAITING_REVIEW"
    assert after["pending_plan"] == before["pending_plan"]
    assert after["review_state"] is None
    assert scalar(
        isolated_database, "SELECT count(*) FROM reviews WHERE job_id = %s",
        (UUID(job["job_id"]),),
    ) == 0

    accepted = review(
        isolated_database.dsn,
        job["job_id"],
        before["pending_plan"]["plan_digest"],
        "approve",
        env_extra={"DATACON_OPERATOR_ID": "reviewer-1"},
    )
    assert accepted.returncode == 0, accepted.stderr
    assert status(isolated_database.dsn, job["job_id"])["state"] == "READY"


def test_expired_review_blocks_the_plan(isolated_database, tmp_path):
    job = queue_job(isolated_database, tmp_path)
    worker(isolated_database.dsn)
    digest = status(isolated_database.dsn, job["job_id"])["pending_plan"][
        "plan_digest"
    ]
    isolated_database.connection.execute(
        "UPDATE jobs SET review_deadline_at = now() - interval '1 second' "
        "WHERE job_id = %s",
        (UUID(job["job_id"]),),
    )

    expired = review(
        isolated_database.dsn,
        job["job_id"],
        digest,
        "approve",
        env_extra={"DATACON_OPERATOR_ID": "reviewer-1"},
    )
    assert expired.returncode == 3
    assert json.loads(expired.stderr)["reason_code"] == "REVIEW_EXPIRED"

    current = status(isolated_database.dsn, job["job_id"])
    assert current["state"] == "BLOCKED"
    assert current["reason_code"] == "REVIEW_EXPIRED"
    assert scalar(
        isolated_database, "SELECT count(*) FROM reviews WHERE job_id = %s",
        (UUID(job["job_id"]),),
    ) == 0

    again = review(
        isolated_database.dsn,
        job["job_id"],
        digest,
        "approve",
        env_extra={"DATACON_OPERATOR_ID": "reviewer-1"},
    )
    assert again.returncode == 3
    assert json.loads(again.stderr)["reason_code"] == "REVIEW_EXPIRED"


def test_expired_review_with_wrong_digest_blocks(isolated_database, tmp_path):
    job = queue_job(isolated_database, tmp_path)
    worker(isolated_database.dsn)
    digest = status(isolated_database.dsn, job["job_id"])["pending_plan"][
        "plan_digest"
    ]
    isolated_database.connection.execute(
        "UPDATE jobs SET review_deadline_at = now() - interval '1 second' "
        "WHERE job_id = %s",
        (UUID(job["job_id"]),),
    )

    expired = review(
        isolated_database.dsn,
        job["job_id"],
        "sha256:" + "0" * 64,
        "approve",
        env_extra={"DATACON_OPERATOR_ID": "reviewer-1"},
    )
    assert expired.returncode == 3
    assert json.loads(expired.stderr)["reason_code"] == "REVIEW_EXPIRED"

    current = status(isolated_database.dsn, job["job_id"])
    assert current["state"] == "BLOCKED"
    assert current["reason_code"] == "REVIEW_EXPIRED"
    assert scalar(
        isolated_database, "SELECT count(*) FROM reviews WHERE job_id = %s",
        (UUID(job["job_id"]),),
    ) == 0
    assert current["pending_plan"]["plan_digest"] == digest


def test_worker_expires_a_pending_review_after_restart(
    isolated_database, tmp_path
):
    job = queue_job(isolated_database, tmp_path)
    worker(isolated_database.dsn)
    isolated_database.connection.execute(
        "UPDATE jobs SET review_deadline_at = now() - interval '1 second' "
        "WHERE job_id = %s",
        (UUID(job["job_id"]),),
    )

    result = worker(isolated_database.dsn)
    assert result["processed"] == 1
    assert result["state"] == "BLOCKED"
    current = status(isolated_database.dsn, job["job_id"])
    assert current["reason_code"] == "REVIEW_EXPIRED"
    assert current["review_state"] is None
    assert scalar(
        isolated_database,
        "SELECT workflow_synced FROM jobs WHERE job_id = %s",
        (UUID(job["job_id"]),),
    ) is False

    # expire_review increments the generation, so the expiring worker cannot
    # finalize. The next worker claims the BLOCKED job and syncs the checkpoint.
    synced = worker(isolated_database.dsn)
    assert synced["processed"] == 1
    assert synced["state"] == "BLOCKED"
    assert synced["workflow"] == "completed"
    assert scalar(
        isolated_database,
        "SELECT workflow_synced FROM jobs WHERE job_id = %s",
        (UUID(job["job_id"]),),
    ) is True


def test_review_rejects_missing_jobs_bad_digests_and_premature_jobs(
    isolated_database, tmp_path
):
    missing = review(
        isolated_database.dsn,
        str(uuid4()),
        "sha256:" + "1" * 64,
        "approve",
    )
    assert missing.returncode == 3
    assert json.loads(missing.stderr)["reason_code"] == "JOB_NOT_FOUND"

    job = queue_job(isolated_database, tmp_path)
    malformed = review(
        isolated_database.dsn, job["job_id"], "not-a-digest", "approve"
    )
    assert malformed.returncode == 2
    assert json.loads(malformed.stderr)["reason_code"] == "INVALID_REQUEST"

    premature = review(
        isolated_database.dsn,
        job["job_id"],
        "sha256:" + "1" * 64,
        "approve",
        env_extra={"DATACON_OPERATOR_ID": "reviewer-1"},
    )
    assert premature.returncode == 3
    assert json.loads(premature.stderr)["reason_code"] == "INVALID_STATE"
    assert scalar(
        isolated_database, "SELECT count(*) FROM reviews WHERE job_id = %s",
        (UUID(job["job_id"]),),
    ) == 0


def test_analysis_block_is_visible_in_status_and_creates_no_plan(
    isolated_database, tmp_path
):
    case_root = copy_cases(tmp_path)
    (case_root / "harness.c").unlink()
    job = queue_job(isolated_database, tmp_path)

    result = worker(
        isolated_database.dsn,
        env_extra={"DATACON_CASE_ROOT": str(case_root)},
    )
    assert result["processed"] == 1
    assert result["state"] == "BLOCKED"

    current = status(isolated_database.dsn, job["job_id"])
    assert current["state"] == "BLOCKED"
    assert current["reason_code"] == "MATERIAL_MISSING"
    assert "harness" in current["last_error"]
    assert current["pending_plan"] is None
    assert scalar(
        isolated_database, "SELECT count(*) FROM plans WHERE job_id = %s",
        (UUID(job["job_id"]),),
    ) == 0


def test_binary_job_is_never_claimed_by_the_worker(isolated_database, tmp_path):
    request = tmp_path / "binary.json"
    request.write_text(
        '{"schema_version":1,"cve_id":"CVE-2099-0001",'
        '"target":{"kind":"binary","case_id":"fixture-c-parser","goal":"x"}}',
        encoding="utf-8",
    )
    job = submit(isolated_database.dsn, request)
    assert job["state"] == "BLOCKED"

    result = worker(isolated_database.dsn)
    assert result["processed"] == 0
    current = status(isolated_database.dsn, job["job_id"])
    assert current["reason_code"] == "UNSUPPORTED_TARGET"
    assert current["stage"] is None
    assert current["pending_plan"] is None


def test_worker_requires_database_configuration():
    result = cli("worker", "--once")
    assert result.returncode == 1
    assert json.loads(result.stderr)["reason_code"] == "DATABASE_NOT_CONFIGURED"

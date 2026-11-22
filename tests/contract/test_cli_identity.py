"""TC-11/T10: ``submit`` and ``review`` speak family identities.

The CLI façade is exercised against recording doubles so the assertions are
about the identity the command accepts and forwards, not about PostgreSQL.
The real family-scoped ``reviews`` / ``family_approvals`` writes are covered by
``tests/integration/test_review_locks.py``.
"""

import json
from uuid import uuid4

import pytest

from datacon import cli, state

FAMILY_ID = str(uuid4())
CHILD_ID = str(uuid4())
FIRST_PLAN_DIGEST = "sha256:" + "a" * 64
ENVELOPE_DIGEST = "sha256:" + "b" * 64

REQUEST_V2 = {
    "schema_version": 2,
    "cve_id": "CVE-2099-0001",
    "target": {
        "kind": "source",
        "case_id": "fixture-c-parser",
        "goal": "验证固定输入在缺陷版触发预期 ASan 异常",
    },
    "exploration": {
        "mode": "guided",
        "allowed_mutation_families": ["byte_flip", "length_boundary"],
        "max_rounds": 8,
        "max_total_seconds": 900,
        "max_fuzz_seconds": 300,
    },
}


def _write_request(tmp_path):
    path = tmp_path / "request-v2.json"
    path.write_text(json.dumps(REQUEST_V2), encoding="utf-8")
    return path


def _configure(monkeypatch):
    monkeypatch.setenv("DATACON_DATABASE_URL", "postgresql://unused")
    monkeypatch.setenv("DATACON_OPERATOR_ID", "reviewer-p1")


def test_submit_returns_family_job_id(monkeypatch, capsys, tmp_path):
    _configure(monkeypatch)
    captured = {}

    def fake_submit(dsn, request, *, operator_id=None):
        captured["request"] = request
        captured["operator_id"] = operator_id
        return {"job_id": FAMILY_ID, "state": "QUEUED"}

    monkeypatch.setattr(cli.store, "submit", fake_submit)

    code = cli.main(["submit", "--request", str(_write_request(tmp_path))])
    assert code == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["job_id"] == FAMILY_ID, "submit returned a child job id"
    assert captured["request"]["exploration"]["mode"] == "guided"

    # The returned identity is the one status and review must accept.
    seen = {}

    def fake_status(dsn, job_id):
        seen["status"] = job_id
        return {"job_id": str(job_id), "state": "AGGREGATING"}

    monkeypatch.setattr(cli.store, "status", fake_status)
    assert cli.main(["status", payload["job_id"]]) == 0
    capsys.readouterr()
    assert str(seen["status"]) == FAMILY_ID

    reviews = {}

    def fake_review(dsn, job_id, **kwargs):
        reviews["job_id"] = job_id
        reviews.update(kwargs)
        return state.ReviewOutcome(
            "applied",
            state="READY",
            review={
                "decision": kwargs["decision"],
                "reviewer_id": kwargs["reviewer_id"],
                "plan_digest": kwargs["plan_digest"],
                "decided_at": "2026-01-02T00:00:00.000000Z",
            },
        )

    monkeypatch.setattr(cli.state, "record_review", fake_review)
    assert (
        cli.main(
            [
                "review",
                payload["job_id"],
                "--plan-digest",
                FIRST_PLAN_DIGEST,
                "--decision",
                "approve",
            ]
        )
        == 0
    )
    assert str(reviews["job_id"]) == FAMILY_ID, (
        "review was written against the child job"
    )


def test_review_writes_family_scoped_review(monkeypatch, capsys):
    _configure(monkeypatch)
    captured = {}

    def fake_review(dsn, job_id, **kwargs):
        captured["job_id"] = job_id
        captured.update(kwargs)
        return state.ReviewOutcome(
            "applied",
            state="READY",
            review={
                "decision": kwargs["decision"],
                "reviewer_id": kwargs["reviewer_id"],
                "plan_digest": kwargs["plan_digest"],
                "decided_at": "2026-01-02T00:00:00.000000Z",
            },
        )

    monkeypatch.setattr(cli.state, "record_review", fake_review)

    try:
        code = cli.main(
            [
                "review",
                FAMILY_ID,
                "--plan-digest",
                FIRST_PLAN_DIGEST,
                "--envelope-digest",
                ENVELOPE_DIGEST,
                "--decision",
                "approve",
            ]
        )
    except SystemExit as error:  # argparse rejects an unknown option today
        pytest.fail(f"review does not accept --envelope-digest: {error}")

    assert code == 0
    assert captured["job_id"] != CHILD_ID
    assert str(captured["job_id"]) == FAMILY_ID, (
        "review was written against the child job"
    )
    assert captured["envelope_digest"] == ENVELOPE_DIGEST
    payload = json.loads(capsys.readouterr().out)
    assert payload["job_id"] == FAMILY_ID
    assert payload["reviewer_id"] == "reviewer-p1"

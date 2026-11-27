"""D43 T12: family archive crash recovery converges without a lease.

The sweep runs before every claim inside ``workflow.run_worker``. A family is
eligible only when it still is ``AGGREGATING``, has children, every child is
terminal (and any BLOCKED child is workflow-synced) and no envelope is pending.
The family index is written atomically and the existing bytes always win, so a
crash between the file write and ``complete_family`` retries only the pointer
write.
"""

from __future__ import annotations

import hashlib
import json
from uuid import uuid4

import pytest
from psycopg.types.json import Jsonb

from datacon import evidence, state, workflow

pytestmark = pytest.mark.postgres

APPROVAL_DIGEST = "sha256:" + "52" * 32
CAMPAIGN_PLAN = "sha256:" + "2f" * 32
ROUND1_PLAN = "sha256:" + "2e" * 32
ROUND2_PLAN = "sha256:" + "0d" * 32
CAMPAIGN_DIGEST = "sha256:" + "0e" * 32
ROUND1_DIGEST = "sha256:" + "53" * 32
ROUND2_DIGEST = "sha256:" + "54" * 32

BUDGET = {
    "max_total_seconds": 900,
    "max_fuzz_seconds": 300,
    "spent_seconds": 0,
    "spent_fuzz_seconds": 0,
    "remaining_seconds": 900,
    "remaining_fuzz_seconds": 300,
}

REQUEST = {
    "schema_version": 2,
    "cve_id": "CVE-2099-0001",
    "target": {"kind": "source", "case_id": "fixture-c-parser"},
    "exploration": {
        "mode": "guided",
        "allowed_mutation_families": ["byte_flip"],
        "max_rounds": 2,
        "max_total_seconds": 900,
        "max_fuzz_seconds": 300,
    },
}


def _insert_family(database):
    family_id = uuid4()
    database.connection.execute(
        "INSERT INTO jobs (job_id, request, state, stage, submitted_at, "
        "job_contract_version, family_id, job_kind, parent_job_id, round_no, "
        "workflow_synced) VALUES (%s, %s, 'AGGREGATING', 'family', "
        "clock_timestamp(), 2, %s, 'family', NULL, NULL, true)",
        (family_id, Jsonb(REQUEST), family_id),
    )
    return family_id


def _insert_child(
    database,
    family_id,
    *,
    job_kind,
    round_no,
    state_name,
    evidence_path,
    evidence_digest,
    verdict=None,
    reason_code=None,
):
    job_id = uuid4()
    database.connection.execute(
        "INSERT INTO jobs (job_id, request, state, stage, submitted_at, "
        "job_contract_version, family_id, job_kind, parent_job_id, round_no, "
        "workflow_synced, verdict, reason_code, evidence_status, "
        "evidence_path, evidence_digest) VALUES (%s, %s, %s, 'execute', "
        "clock_timestamp(), 2, %s, %s, %s, %s, true, %s, %s, 'archived', "
        "%s, %s)",
        (
            job_id,
            Jsonb(REQUEST),
            state_name,
            family_id,
            job_kind,
            family_id,
            round_no,
            verdict,
            reason_code,
            str(evidence_path),
            evidence_digest,
        ),
    )
    return job_id


def _insert_plan(database, job_id, digest):
    database.connection.execute(
        "INSERT INTO plans (plan_id, job_id, plan_digest, plan, summary) "
        "VALUES (%s, %s, %s, %s, %s)",
        (uuid4(), job_id, digest, Jsonb({}), Jsonb({})),
    )


def _insert_approval(database, family_id):
    database.connection.execute(
        "INSERT INTO family_approvals (approval_id, family_id, "
        "approval_digest, envelope_digest, first_plan_digest, reviewer_id, "
        "decided_at) VALUES (%s, %s, %s, %s, %s, 'reviewer-p1', "
        "clock_timestamp())",
        (
            uuid4(),
            family_id,
            APPROVAL_DIGEST,
            "sha256:" + "b" * 64,
            CAMPAIGN_PLAN,
        ),
    )


def _insert_ledger(database, family_id):
    database.connection.execute(
        "INSERT INTO budget_ledger (family_id, max_total_seconds, "
        "max_fuzz_seconds, remaining_total_seconds, remaining_fuzz_seconds) "
        "VALUES (%s, 900, 300, 900, 300)",
        (family_id,),
    )


def _family_row(database, family_id):
    return database.connection.execute(
        "SELECT state, verdict, reason_code, evidence_status, evidence_path, "
        "evidence_digest FROM jobs WHERE job_id = %s",
        (family_id,),
    ).fetchone()


def _setup_family(database, tmp_path):
    family_id = _insert_family(database)
    campaign_id = _insert_child(
        database,
        family_id,
        job_kind="campaign",
        round_no=None,
        state_name="COMPLETED",
        evidence_path=tmp_path / "campaign-bundle",
        evidence_digest=CAMPAIGN_DIGEST,
    )
    round1_id = _insert_child(
        database,
        family_id,
        job_kind="round",
        round_no=1,
        state_name="INCONCLUSIVE",
        evidence_path=tmp_path / "round-1-bundle",
        evidence_digest=ROUND1_DIGEST,
        verdict="INCONCLUSIVE",
        reason_code="EVIDENCE_INCOMPLETE",
    )
    round2_id = _insert_child(
        database,
        family_id,
        job_kind="round",
        round_no=2,
        state_name="INCONCLUSIVE",
        evidence_path=tmp_path / "round-2-bundle",
        evidence_digest=ROUND2_DIGEST,
        verdict="INCONCLUSIVE",
        reason_code="EVIDENCE_INCOMPLETE",
    )
    for job_id, digest in (
        (campaign_id, CAMPAIGN_PLAN),
        (round1_id, ROUND1_PLAN),
        (round2_id, ROUND2_PLAN),
    ):
        _insert_plan(database, job_id, digest)
    _insert_approval(database, family_id)
    _insert_ledger(database, family_id)
    return family_id, campaign_id, round1_id, round2_id


def _family_index(family_id, campaign_id, round1_id, round2_id):
    return evidence.build_family_index(
        family_id=family_id,
        created_at="2099-01-01T00:00:00Z",
        family_approval_digest=APPROVAL_DIGEST,
        rounds=[
            {
                "round_no": 1,
                "job_id": str(round1_id),
                "plan_digest": ROUND1_PLAN,
                "state": "INCONCLUSIVE",
                "evidence_digest": ROUND1_DIGEST,
            },
            {
                "round_no": 2,
                "job_id": str(round2_id),
                "plan_digest": ROUND2_PLAN,
                "state": "INCONCLUSIVE",
                "evidence_digest": ROUND2_DIGEST,
            },
        ],
        campaign={"job_id": str(campaign_id), "bundle_digest": CAMPAIGN_DIGEST},
        budget=BUDGET,
    )


def _digest(path):
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


def _audit_count(database, family_id, event_type):
    row = database.connection.execute(
        "SELECT count(*) FROM audit_events WHERE job_id = %s AND event_type = %s",
        (family_id, event_type),
    ).fetchone()
    return row[0]


def test_family_archive_recovery_writes_index_and_converges(
    isolated_database, tmp_path, monkeypatch
):
    evidence_root = tmp_path / "evidence"
    monkeypatch.setenv("DATACON_EVIDENCE_ROOT", str(evidence_root))
    family_id, campaign_id, round1_id, round2_id = _setup_family(
        isolated_database, tmp_path
    )

    result = workflow.run_worker(isolated_database.dsn, once=True, execute=False)

    path = evidence_root / str(family_id) / "family.json"
    assert path.is_file(), "family stayed AGGREGATING after the recovery scan"
    digest = _digest(path)
    assert _family_row(isolated_database, family_id) == (
        "COMPLETED",
        None,
        None,
        "archived",
        str(path.resolve()),
        digest,
    )
    assert result["families_converged"] == 1
    document = json.loads(path.read_bytes())
    assert document["schema_version"] == 2
    assert document["kind"] == "family_index"
    assert document["family_id"] == str(family_id)
    assert document["state"] == "COMPLETED"
    assert document["family_approval_digest"] == APPROVAL_DIGEST
    assert [entry["round_no"] for entry in document["rounds"]] == [1, 2]
    assert document["rounds"][0]["job_id"] == str(round1_id)
    assert document["rounds"][0]["evidence_digest"] == ROUND1_DIGEST
    assert document["rounds"][1]["job_id"] == str(round2_id)
    assert document["campaign"] == {
        "job_id": str(campaign_id),
        "bundle_digest": CAMPAIGN_DIGEST,
    }
    assert document["budget"] == BUDGET

    sources = state.family_export_sources(isolated_database.dsn, family_id)
    assert sources["family_path"] == str(path.resolve())
    assert sources["family_digest"] == digest
    assert sources["campaign"] == {
        "source": str(tmp_path / "campaign-bundle"),
        "digest": CAMPAIGN_DIGEST,
    }
    assert [entry["round_no"] for entry in sources["rounds"]] == [1, 2]

    before = path.read_bytes()
    workflow.run_worker(isolated_database.dsn, once=True, execute=False)
    assert path.read_bytes() == before
    assert _audit_count(isolated_database, family_id, "family_completed") == 1


def test_family_archive_recovery_reuses_existing_index_after_crash(
    isolated_database, tmp_path, monkeypatch
):
    evidence_root = tmp_path / "evidence"
    monkeypatch.setenv("DATACON_EVIDENCE_ROOT", str(evidence_root))
    family_id, campaign_id, round1_id, round2_id = _setup_family(
        isolated_database, tmp_path
    )
    path = evidence_root / str(family_id) / "family.json"
    # Crash point: the index was written before complete_family committed.
    evidence.finalize_family_index(
        path, _family_index(family_id, campaign_id, round1_id, round2_id)
    )
    written = path.read_bytes()

    workflow.run_worker(isolated_database.dsn, once=True, execute=False)

    assert path.read_bytes() == written
    digest = _digest(path)
    assert _family_row(isolated_database, family_id) == (
        "COMPLETED",
        None,
        None,
        "archived",
        str(path.resolve()),
        digest,
    )
    # The original created_at survives: the sweep must not rewrite the file.
    assert json.loads(path.read_bytes())["created_at"] == "2099-01-01T00:00:00Z"
    workflow.run_worker(isolated_database.dsn, once=True, execute=False)
    assert path.read_bytes() == written
    assert _audit_count(isolated_database, family_id, "family_completed") == 1


def test_family_archive_recovery_records_failure_and_retries(
    isolated_database, tmp_path, monkeypatch
):
    evidence_root = tmp_path / "evidence"
    monkeypatch.setenv("DATACON_EVIDENCE_ROOT", str(evidence_root))
    family_id = _insert_family(isolated_database)
    campaign_id = _insert_child(
        isolated_database,
        family_id,
        job_kind="campaign",
        round_no=None,
        state_name="COMPLETED",
        evidence_path=tmp_path / "campaign-bundle",
        evidence_digest=CAMPAIGN_DIGEST,
    )
    round1_id = _insert_child(
        isolated_database,
        family_id,
        job_kind="round",
        round_no=1,
        state_name="INCONCLUSIVE",
        evidence_path=tmp_path / "round-1-bundle",
        evidence_digest=ROUND1_DIGEST,
        verdict="INCONCLUSIVE",
        reason_code="EVIDENCE_INCOMPLETE",
    )
    _insert_plan(isolated_database, campaign_id, CAMPAIGN_PLAN)
    _insert_plan(isolated_database, round1_id, ROUND1_PLAN)
    _insert_approval(isolated_database, family_id)
    # No budget ledger: archiving fails, but the failure must be recorded and
    # the family must remain retryable in AGGREGATING.

    workflow.run_worker(isolated_database.dsn, once=True, execute=False)

    assert _family_row(isolated_database, family_id) == (
        "AGGREGATING",
        None,
        None,
        None,
        None,
        None,
    )
    assert not (evidence_root / str(family_id) / "family.json").exists()
    failure = isolated_database.connection.execute(
        "SELECT detail ->> 'message' FROM audit_events "
        "WHERE job_id = %s AND event_type = 'family_archive_failed'",
        (family_id,),
    ).fetchall()
    assert len(failure) == 1
    assert "budget ledger" in failure[0][0]

    _insert_ledger(isolated_database, family_id)
    workflow.run_worker(isolated_database.dsn, once=True, execute=False)

    assert _family_row(isolated_database, family_id)[0] == "COMPLETED"
    assert (evidence_root / str(family_id) / "family.json").is_file()

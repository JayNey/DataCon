"""T12/S-2/S-3/S-4/S-5/S-7: real PostgreSQL family ``status`` snapshots.

These coordinates exercise the SQL the recording double in
``tests/contract/test_cli_status.py`` cannot prove: the D42 approval-chain
tail envelope, the approve-only human admission, and the repeatable-read
snapshot that keeps family/children/reviews/admissions/ledger/charges on one
consistent view.
"""

from __future__ import annotations

import json
from uuid import uuid4

import psycopg
import pytest
from psycopg.types.json import Jsonb

from datacon import cli, state

pytestmark = pytest.mark.postgres

CAMPAIGN_PLAN = "sha256:" + "2f" * 32
ROUND1_PLAN = "sha256:" + "2e" * 32
ROUND2_PLAN = "sha256:" + "0d" * 32
CAMPAIGN_DIGEST = "sha256:" + "0e" * 32
ROUND1_DIGEST = "sha256:" + "53" * 32
ROUND2_DIGEST = "sha256:" + "54" * 32
APPROVAL_DIGEST = "sha256:" + "52" * 32
ENVELOPE1 = "sha256:" + "b" * 64
ENVELOPE2 = "sha256:" + "c" * 64
BUDGET = {
    "max_total_seconds": 900,
    "max_fuzz_seconds": 300,
    "spent_seconds": 540,
    "spent_fuzz_seconds": 180,
    "remaining_seconds": 360,
    "remaining_fuzz_seconds": 120,
}


def _guided_request(max_rounds=8):
    return {
        "schema_version": 2,
        "cve_id": "CVE-2099-0001",
        "target": {"kind": "source", "case_id": "fixture-c-parser"},
        "exploration": {
            "mode": "guided",
            "allowed_mutation_families": ["byte_flip"],
            "max_rounds": max_rounds,
            "max_total_seconds": 900,
            "max_fuzz_seconds": 300,
        },
    }


def _fixed_request():
    return {
        "schema_version": 2,
        "cve_id": "CVE-2099-0001",
        "target": {"kind": "source", "case_id": "fixture-c-parser"},
        "exploration": {"mode": "fixed"},
    }


def _insert_family(database, request):
    family_id = uuid4()
    database.connection.execute(
        "INSERT INTO jobs (job_id, request, state, stage, submitted_at, "
        "job_contract_version, family_id, job_kind, parent_job_id, round_no, "
        "workflow_synced) VALUES (%s, %s, 'AGGREGATING', 'family', "
        "clock_timestamp(), 2, %s, 'family', NULL, NULL, true)",
        (family_id, Jsonb(request), family_id),
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
            Jsonb(_guided_request()),
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


def _insert_review(database, family_id, *, plan_digest, decision):
    database.connection.execute(
        "INSERT INTO reviews (review_id, job_id, plan_digest, reviewer_id, "
        "decision, review_deadline_at, decided_at) VALUES (%s, %s, %s, "
        "'reviewer-p1', %s, clock_timestamp(), clock_timestamp())",
        (uuid4(), family_id, plan_digest, decision),
    )


def _insert_approval(database, family_id, *, envelope_digest, supersedes=None):
    approval_id = uuid4()
    database.connection.execute(
        "INSERT INTO family_approvals (approval_id, family_id, "
        "approval_digest, envelope_digest, first_plan_digest, supersedes, "
        "reviewer_id, decided_at) VALUES (%s, %s, %s, %s, %s, %s, "
        "'reviewer-p1', clock_timestamp())",
        (
            approval_id,
            family_id,
            "sha256:" + uuid4().hex * 2,
            envelope_digest,
            CAMPAIGN_PLAN,
            supersedes,
        ),
    )
    return approval_id


def _insert_envelope(database, family_id, *, envelope_digest, max_rounds):
    database.connection.execute(
        "INSERT INTO family_envelopes (envelope_id, family_id, envelope_digest, "
        "envelope_json, status) VALUES (%s, %s, %s, %s, 'approved')",
        (
            uuid4(),
            family_id,
            envelope_digest,
            Jsonb({"max_rounds": max_rounds}),
        ),
    )


def _insert_ledger(
    database,
    family_id,
    *,
    max_total=900,
    max_fuzz=300,
    remaining_total=360,
    remaining_fuzz=120,
):
    database.connection.execute(
        "INSERT INTO budget_ledger (family_id, max_total_seconds, "
        "max_fuzz_seconds, remaining_total_seconds, remaining_fuzz_seconds) "
        "VALUES (%s, %s, %s, %s, %s)",
        (family_id, max_total, max_fuzz, remaining_total, remaining_fuzz),
    )


def _insert_charge(database, family_id, job_id, *, step_key, kind, seconds, fuzz=0):
    database.connection.execute(
        "INSERT INTO budget_charges (charge_id, family_id, job_id, step_key, "
        "attempt_no, charge_kind, seconds, fuzz_seconds) "
        "VALUES (%s, %s, %s, %s, 1, %s, %s, %s)",
        (uuid4(), family_id, job_id, step_key, kind, seconds, fuzz),
    )


def _insert_admission(database, family_id, job_id, round_no):
    database.connection.execute(
        "INSERT INTO admissions (admission_id, job_id, parent_job_id, "
        "round_no, approval_kind, envelope_digest, parent_approval_digest, "
        "seed_digest, predicate_version, recomputable) "
        "VALUES (%s, %s, %s, %s, 'policy', %s, %s, %s, 'admission-v1', true)",
        (
            uuid4(),
            job_id,
            family_id,
            round_no,
            ENVELOPE1,
            APPROVAL_DIGEST,
            "sha256:" + "11" * 32,
        ),
    )


def _spend_budget(database, family_id, job_id):
    _insert_ledger(database, family_id)
    _insert_charge(
        database, family_id, job_id, step_key="execute:1", kind="general", seconds=360
    )
    _insert_charge(
        database,
        family_id,
        job_id,
        step_key="fuzz:1",
        kind="fuzz",
        seconds=180,
        fuzz=180,
    )


def _guided_family(database, tmp_path, *, decision="approve"):
    family_id = _insert_family(database, _guided_request(max_rounds=8))
    campaign_id = _insert_child(
        database,
        family_id,
        job_kind="campaign",
        round_no=None,
        state_name="COMPLETED",
        evidence_path=tmp_path / "campaign",
        evidence_digest=CAMPAIGN_DIGEST,
    )
    round1_id = _insert_child(
        database,
        family_id,
        job_kind="round",
        round_no=1,
        state_name="INCONCLUSIVE",
        evidence_path=tmp_path / "round-1",
        evidence_digest=ROUND1_DIGEST,
        verdict="INCONCLUSIVE",
        reason_code="EVIDENCE_INCOMPLETE",
    )
    _insert_plan(database, campaign_id, CAMPAIGN_PLAN)
    _insert_plan(database, round1_id, ROUND1_PLAN)
    _insert_review(
        database, family_id, plan_digest=CAMPAIGN_PLAN, decision=decision
    )
    _insert_approval(database, family_id, envelope_digest=ENVELOPE1)
    _spend_budget(database, family_id, round1_id)
    return family_id, campaign_id, round1_id


def test_guided_family_status_returns_campaign_rounds_and_budget(
    isolated_database, tmp_path
):
    family_id, campaign_id, round1_id = _guided_family(
        isolated_database, tmp_path
    )
    _insert_admission(isolated_database, family_id, round1_id, 1)

    payload = state.status(isolated_database.dsn, family_id)

    assert payload["state"] == "AGGREGATING"
    assert payload["family"] == {
        "family_id": str(family_id),
        "max_rounds": 8,
        "rounds_used": 1,
    }
    assert payload["campaign"]["job_id"] == str(campaign_id)
    assert payload["campaign"]["state"] == "COMPLETED"
    assert payload["campaign"]["admission_kind"] == "human"
    assert payload["rounds"][0]["job_id"] == str(round1_id)
    assert payload["rounds"][0]["admission_kind"] == "policy"
    assert payload["budget"] == BUDGET


def test_fixed_family_status_has_no_campaign_and_human_round1(
    isolated_database, tmp_path
):
    family_id = _insert_family(isolated_database, _fixed_request())
    round1_id = _insert_child(
        isolated_database,
        family_id,
        job_kind="round",
        round_no=1,
        state_name="REPRODUCED",
        evidence_path=tmp_path / "round-1",
        evidence_digest=ROUND1_DIGEST,
        verdict="REPRODUCED",
        reason_code="ASAN_SIGNATURE_MATCHED",
    )
    _insert_plan(isolated_database, round1_id, ROUND1_PLAN)
    _insert_review(
        isolated_database, family_id, plan_digest=ROUND1_PLAN, decision="approve"
    )
    _insert_ledger(isolated_database, family_id)
    _insert_charge(
        isolated_database,
        family_id,
        round1_id,
        step_key="execute:1",
        kind="general",
        seconds=360,
    )
    _insert_charge(
        isolated_database,
        family_id,
        round1_id,
        step_key="fuzz:1",
        kind="fuzz",
        seconds=180,
        fuzz=180,
    )

    payload = state.status(isolated_database.dsn, family_id)

    assert payload["family"]["max_rounds"] == 1
    assert payload["campaign"] is None
    assert payload["rounds"][0]["admission_kind"] == "human"
    assert payload["rounds"][0]["state"] == "REPRODUCED"


def test_rejected_first_plan_is_not_human_admitted_in_real_sql(
    isolated_database, tmp_path
):
    family_id, campaign_id, round1_id = _guided_family(
        isolated_database, tmp_path, decision="reject"
    )

    payload = state.status(isolated_database.dsn, family_id)

    assert payload["campaign"]["admission_kind"] is None
    assert payload["rounds"][0]["admission_kind"] is None


def test_status_uses_the_d42_approval_chain_tail_max_rounds(
    isolated_database, tmp_path
):
    family_id, campaign_id, round1_id = _guided_family(
        isolated_database, tmp_path
    )
    _insert_envelope(
        isolated_database, family_id, envelope_digest=ENVELOPE1, max_rounds=8
    )
    first = isolated_database.connection.execute(
        "SELECT approval_id FROM family_approvals WHERE family_id = %s",
        (family_id,),
    ).fetchone()[0]
    _insert_approval(
        isolated_database,
        family_id,
        envelope_digest=ENVELOPE2,
        supersedes=first,
    )
    _insert_envelope(
        isolated_database, family_id, envelope_digest=ENVELOPE2, max_rounds=4
    )

    payload = state.status(isolated_database.dsn, family_id)

    assert payload["family"]["max_rounds"] == 4, (
        "status ignored the tightened D42 envelope max_rounds"
    )


def test_inconsistent_ledger_is_a_state_error_and_cli_exit_3(
    isolated_database, tmp_path, monkeypatch, capsys
):
    family_id, campaign_id, round1_id = _guided_family(
        isolated_database, tmp_path
    )
    isolated_database.connection.execute(
        "UPDATE budget_ledger SET remaining_total_seconds = 500 "
        "WHERE family_id = %s",
        (family_id,),
    )

    with pytest.raises(state.StateError):
        state.status(isolated_database.dsn, family_id)

    monkeypatch.setenv("DATACON_DATABASE_URL", isolated_database.dsn)
    code = cli.main(["status", str(family_id)])

    assert code == 3
    payload = json.loads(capsys.readouterr().err)
    assert payload["reason_code"] == "STATE_ERROR"


def test_family_status_keeps_one_repeatable_read_snapshot(
    isolated_database, tmp_path, monkeypatch
):
    family_id, campaign_id, round1_id = _guided_family(
        isolated_database, tmp_path
    )
    real_review_plan = state._family_review_plan
    inserted = {}

    def _insert_between_reads(connection, family):
        # Commit an admission from a different connection *after* the family
        # snapshot has been established. A repeatable-read status must not see
        # it; a read-committed status would.
        with psycopg.connect(isolated_database.dsn, autocommit=True) as other:
            _insert_admission(other, family, round1_id, 1)
        inserted["done"] = True
        return real_review_plan(connection, family)

    monkeypatch.setattr(state, "_family_review_plan", _insert_between_reads)

    payload = state.status(isolated_database.dsn, family_id)

    assert inserted["done"] is True
    assert payload["rounds"][0]["admission_kind"] is None, (
        "the family status read mixed snapshots and saw a later admission"
    )

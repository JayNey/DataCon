"""TC-12/T12 step 1.5: Postgres policy-admission persistence.

The contract predicate lives in ``state.policy_admit_round``. These coordinates
exercise the real transaction in which a policy round is admitted: one
``admissions`` row plus one ``round_admitted`` audit event, or a denied event
with no admission row. Same-input readmission is an idempotent no-op; a different
decision for the same ``(parent_job_id, round_no)`` is a real denial.
"""

from __future__ import annotations

from typing import Any
from uuid import uuid4

import pytest
from psycopg.types.json import Jsonb

from datacon import contracts, jsonutil, state

pytestmark = pytest.mark.postgres
_UNSET = object()


def _digest(token: str) -> str:
    return "sha256:" + token * 64


TOOLCHAIN_IMAGE_DIGEST = _digest("a")
SEED_CORPUS_DIGEST = _digest("c")
HARNESS_DIGEST = _digest("d")
APPROVAL_DIGEST = _digest("e")
FIRST_PLAN_DIGEST = _digest("f")
REVIEWER_ID = "reviewer-t12"

SIGNATURE = {
    "error": "heap-buffer-overflow",
    "function": "parse_token",
    "source": "parser.c",
    "operation": "WRITE",
    "access_size": 1,
}

BUDGET_SNAPSHOT = {
    "remaining_total_seconds": 900,
    "remaining_fuzz_seconds": 300,
}


def _envelope(*, max_rounds: int = 8) -> dict:
    return contracts.guided_envelope(
        allowed_mutation_families=["byte_flip", "length_boundary"],
        mutation_limits={
            "allowed_ops": ["append", "truncate", "byte_flip"],
            "max_input_bytes": 4096,
        },
        seed_corpus_digest=SEED_CORPUS_DIGEST,
        toolchain_image_digest=TOOLCHAIN_IMAGE_DIGEST,
        harness_digest=HARNESS_DIGEST,
        max_rounds=max_rounds,
        max_total_seconds=900,
        max_fuzz_seconds=300,
        accepted_signature_set=[dict(SIGNATURE)],
        admission_predicate_version="admission-v1",
    )


def _seed_family(
    database,
    *,
    max_rounds: int = 8,
    round_no: int = 2,
    approval_digest: str = APPROVAL_DIGEST,
    plan_envelope_digest: str | None = None,
    plan_parent_approval_digest: Any = _UNSET,
    plan_experiment_digest: str | None = None,
    plan_seed_digest: str = SEED_CORPUS_DIGEST,
    plan_harness_digest: Any = _UNSET,
    envelope: dict | None = None,
    family_state: str = "AGGREGATING",
):
    family_id = uuid4()
    child_id = uuid4()
    envelope = _envelope(max_rounds=max_rounds) if envelope is None else envelope
    envelope_digest = contracts.envelope_digest(envelope)
    resolved_plan_parent = (
        approval_digest
        if plan_parent_approval_digest is _UNSET
        else plan_parent_approval_digest
    )
    resolved_plan_harness = (
        envelope["harness_digest"]
        if plan_harness_digest is _UNSET
        else plan_harness_digest
    )
    plan = {
        "schema_version": 2,
        "family_id": str(family_id),
        "parent_job_id": str(family_id),
        "round_no": round_no,
        "envelope_digest": plan_envelope_digest or envelope_digest,
        "parent_approval_digest": resolved_plan_parent,
        "harness_digest": resolved_plan_harness,
        "inputs": {
            "normal": _digest("1"),
            "candidate": plan_seed_digest,
        },
        "experiment_digest": plan_experiment_digest,
    }

    database.connection.execute(
        "INSERT INTO jobs (job_id, request, state, stage, submitted_at, "
        "job_contract_version, family_id, job_kind, parent_job_id, round_no, "
        "generation, workflow_synced) "
        "VALUES (%s, %s, 'AGGREGATING', 'family', clock_timestamp(), 2, %s, "
        "'family', NULL, NULL, 1, true)",
        (family_id, Jsonb({"schema_version": 2}), family_id),
    )
    database.connection.execute(
        "INSERT INTO jobs (job_id, request, state, stage, submitted_at, "
        "job_contract_version, family_id, job_kind, parent_job_id, round_no, "
        "generation) "
        "VALUES (%s, %s, 'QUEUED', 'admission', clock_timestamp(), 2, %s, "
        "'round', %s, %s, 1)",
        (child_id, Jsonb({"schema_version": 2}), family_id, family_id, round_no),
    )
    if family_state == "COMPLETED":
        database.connection.execute(
            "UPDATE jobs SET state = 'COMPLETED', evidence_status = 'archived', "
            "evidence_path = '/tmp/family.json', evidence_digest = %s "
            "WHERE job_id = %s",
            (_digest("8"), family_id),
        )
    elif family_state != "AGGREGATING":
        database.connection.execute(
            "UPDATE jobs SET state = %s WHERE job_id = %s",
            (family_state, family_id),
        )
    database.connection.execute(
        "INSERT INTO family_approvals (approval_id, family_id, approval_digest, "
        "envelope_digest, first_plan_digest, reviewer_id, decided_at, supersedes) "
        "VALUES (%s, %s, %s, %s, %s, %s, clock_timestamp(), NULL)",
        (
            uuid4(),
            family_id,
            approval_digest,
            envelope_digest,
            FIRST_PLAN_DIGEST,
            REVIEWER_ID,
        ),
    )
    database.connection.execute(
        "INSERT INTO plans (plan_id, job_id, plan_digest, plan, summary) "
        "VALUES (%s, %s, %s, %s, %s)",
        (
            uuid4(),
            child_id,
            jsonutil.digest_json(plan),
            Jsonb(plan),
            Jsonb({}),
        ),
    )
    state.initialize_budget_ledger(
        database.dsn,
        family_id,
        max_total_seconds=envelope["max_total_seconds"],
        max_fuzz_seconds=envelope["max_fuzz_seconds"],
    )
    return family_id, child_id, envelope


def _full_plan(
    family_id,
    envelope,
    approval_digest,
    *,
    round_no=2,
    harness_digest=_UNSET,
):
    resolved_harness_digest = (
        envelope["harness_digest"]
        if harness_digest is _UNSET
        else harness_digest
    )
    return {
        "schema_version": 2,
        "family_id": str(family_id),
        "parent_job_id": str(family_id),
        "round_no": round_no,
        "envelope_digest": contracts.envelope_digest(envelope),
        "parent_approval_digest": approval_digest,
        "harness_digest": resolved_harness_digest,
        "inputs": {
            "normal": _digest("1"),
            "candidate": SEED_CORPUS_DIGEST,
        },
        "experiment_digest": None,
    }


def _admit(
    database,
    seed,
    *,
    round_no: int = 2,
    envelope: dict | None = None,
    seed_digest: str = SEED_CORPUS_DIGEST,
    experiment: dict | None = None,
    recomputable: bool = True,
    campaign_bundle_digest: str | None = None,
    budget_snapshot: dict | None = None,
):
    family_id, child_id, approved_envelope = seed
    return state.record_admission(
        database.dsn,
        family_id=family_id,
        job_id=child_id,
        round_no=round_no,
        envelope=approved_envelope if envelope is None else envelope,
        seed_digest=seed_digest,
        budget_snapshot=BUDGET_SNAPSHOT if budget_snapshot is None else budget_snapshot,
        experiment=experiment,
        recomputable=recomputable,
        campaign_bundle_digest=campaign_bundle_digest,
    )


def _admissions(database, family_id, round_no):
    return database.connection.execute(
        "SELECT admission_id, job_id, parent_job_id, round_no, approval_kind, "
        "envelope_digest, parent_approval_digest, seed_digest, "
        "predicate_version, recomputable, supporting_bundle_digest, decided_at "
        "FROM admissions WHERE parent_job_id = %s AND round_no = %s",
        (family_id, round_no),
    ).fetchall()


def _events(database, job_id):
    return database.connection.execute(
        "SELECT event_type, reason_code, detail FROM audit_events "
        "WHERE job_id = %s ORDER BY event_id",
        (job_id,),
    ).fetchall()


def test_policy_admission_persists_one_row_and_one_event(isolated_database):
    seed = _seed_family(isolated_database)
    family_id, child_id, envelope = seed

    outcome = _admit(isolated_database, seed)

    assert outcome.admitted
    assert outcome.status == "admitted"
    assert outcome.event_type == "round_admitted"
    assert outcome.admission is not None

    rows = _admissions(isolated_database, family_id, 2)
    assert len(rows) == 1, "policy admission did not persist exactly one row"

    (
        admission_id,
        job_id,
        parent_job_id,
        round_no,
        approval_kind,
        envelope_digest,
        parent_approval_digest,
        seed_digest,
        predicate_version,
        recomputable,
        supporting_bundle_digest,
        decided_at,
    ) = rows[0]
    assert str(job_id) == str(child_id)
    assert str(parent_job_id) == str(family_id)
    assert round_no == 2
    assert approval_kind == "policy"
    assert envelope_digest == contracts.envelope_digest(envelope)
    assert parent_approval_digest == APPROVAL_DIGEST
    assert seed_digest == SEED_CORPUS_DIGEST
    assert predicate_version == "admission-v1"
    assert recomputable is True
    assert supporting_bundle_digest is None
    assert decided_at is not None
    assert str(admission_id) == outcome.admission["admission_id"]

    events = _events(isolated_database, child_id)
    assert [event[0] for event in events] == ["round_admitted"]

    reviews = isolated_database.connection.execute(
        "SELECT count(*) FROM reviews WHERE job_id IN (%s, %s)",
        (family_id, child_id),
    ).fetchone()[0]
    assert reviews == 0, "policy admission wrote a reviews row"
    approvals = isolated_database.connection.execute(
        "SELECT count(*) FROM family_approvals WHERE family_id = %s",
        (family_id,),
    ).fetchone()[0]
    assert approvals == 1, "policy admission modified family_approvals"


def test_predicate_denial_writes_round_admission_denied_event(isolated_database):
    seed = _seed_family(isolated_database, round_no=9)
    family_id, child_id, _envelope_value = seed

    outcome = _admit(isolated_database, seed, round_no=9)

    assert not outcome.admitted
    assert outcome.status == "denied"
    assert outcome.reason_code == "BUDGET_EXHAUSTED"
    assert outcome.sub_reason == "ROUND_BEYOND_MAX_ROUNDS"
    assert outcome.admission is None
    assert _admissions(isolated_database, family_id, 9) == []

    events = _events(isolated_database, child_id)
    assert [event[0] for event in events] == ["round_admission_denied"]
    assert events[0][1] == "BUDGET_EXHAUSTED"
    assert events[0][2]["sub_reason"] == "ROUND_BEYOND_MAX_ROUNDS"


def test_idempotent_readmission_writes_no_second_event(isolated_database):
    seed = _seed_family(isolated_database)
    family_id, child_id, _envelope_value = seed

    first = _admit(isolated_database, seed)
    assert first.admitted
    first_rows = _admissions(isolated_database, family_id, 2)
    assert len(first_rows) == 1
    first_row = first_rows[0]

    second = _admit(isolated_database, seed)

    assert not second.admitted
    assert second.status == "already_admitted"
    assert second.reason_code is None
    assert second.sub_reason == "ROUND_ALREADY_ADMITTED"
    assert second.event_type is None
    assert second.admission is not None
    assert str(first_row[0]) == second.admission["admission_id"]

    assert len(_admissions(isolated_database, family_id, 2)) == 1, (
        "idempotent readmission wrote a second admissions row"
    )
    events = _events(isolated_database, child_id)
    assert [event[0] for event in events] == ["round_admitted"], (
        "idempotent readmission wrote a second event"
    )


def test_conflicting_readmission_is_denied(isolated_database):
    seed = _seed_family(isolated_database)
    family_id, child_id, _envelope_value = seed

    first = _admit(isolated_database, seed)
    assert first.admitted
    first_rows = _admissions(isolated_database, family_id, 2)
    assert len(first_rows) == 1

    second = _admit(isolated_database, seed, seed_digest=_digest("9"))

    assert not second.admitted
    assert second.status == "denied"
    assert second.reason_code == "ADMISSION_DENIED"
    assert second.sub_reason == "ROUND_ALREADY_ADMITTED"
    assert second.admission is None

    rows = _admissions(isolated_database, family_id, 2)
    assert len(rows) == 1, "conflicting readmission wrote a second admissions row"
    assert rows[0][7] == SEED_CORPUS_DIGEST, (
        "conflicting readmission rewrote the admitted seed"
    )

    events = _events(isolated_database, child_id)
    assert [event[0] for event in events] == [
        "round_admitted",
        "round_admission_denied",
    ]
    assert events[-1][2]["sub_reason"] == "ROUND_ALREADY_ADMITTED"


def test_conflicting_budget_snapshot_is_denied(isolated_database):
    seed = _seed_family(isolated_database)
    family_id, child_id, _envelope_value = seed

    first = _admit(isolated_database, seed)
    assert first.admitted

    second = _admit(
        isolated_database,
        seed,
        budget_snapshot={
            "remaining_total_seconds": 899,
            "remaining_fuzz_seconds": 300,
        },
    )

    assert not second.admitted
    assert second.status == "denied"
    assert second.reason_code == "ADMISSION_DENIED"
    assert second.sub_reason == "ROUND_ALREADY_ADMITTED"
    assert second.admission is None

    rows = _admissions(isolated_database, family_id, 2)
    assert len(rows) == 1, "conflicting budget snapshot wrote a second admissions row"
    events = _events(isolated_database, child_id)
    assert [event[0] for event in events] == [
        "round_admitted",
        "round_admission_denied",
    ]
    assert events[-1][2]["budget_snapshot_digest"] != first.event_detail[
        "budget_snapshot_digest"
    ]


def test_unapproved_envelope_is_denied(isolated_database):
    seed = _seed_family(isolated_database)
    family_id, child_id, approved_envelope = seed
    unapproved_envelope = _envelope(max_rounds=7)
    assert contracts.envelope_digest(unapproved_envelope) != (
        contracts.envelope_digest(approved_envelope)
    )

    outcome = _admit(isolated_database, seed, envelope=unapproved_envelope)

    assert not outcome.admitted
    assert outcome.status == "denied"
    assert outcome.reason_code == "ADMISSION_DENIED"
    assert outcome.sub_reason == "PARENT_APPROVAL_ENVELOPE_MISMATCH"
    assert _admissions(isolated_database, family_id, 2) == []

    events = _events(isolated_database, child_id)
    assert [event[0] for event in events] == ["round_admission_denied"]
    assert events[0][2]["sub_reason"] == "PARENT_APPROVAL_ENVELOPE_MISMATCH"


def test_plan_envelope_mismatch_is_denied(isolated_database):
    family_id, child_id, _approved_envelope = _seed_family(
        isolated_database,
        plan_envelope_digest=_digest("7"),
    )

    outcome = _admit(isolated_database, (family_id, child_id, _approved_envelope))

    assert not outcome.admitted
    assert outcome.status == "denied"
    assert outcome.reason_code == "ADMISSION_DENIED"
    assert outcome.sub_reason == "PLAN_ENVELOPE_MISMATCH"
    assert _admissions(isolated_database, family_id, 2) == []

    events = _events(isolated_database, child_id)
    assert [event[0] for event in events] == ["round_admission_denied"]
    assert events[0][2]["sub_reason"] == "PLAN_ENVELOPE_MISMATCH"


def test_record_admission_denies_exhausted_ledger_even_with_forged_snapshot(
    isolated_database,
):
    seed = _seed_family(isolated_database)
    family_id, child_id, _envelope_value = seed
    campaign_id = uuid4()
    isolated_database.connection.execute(
        "INSERT INTO jobs (job_id, request, state, stage, submitted_at, "
        "job_contract_version, family_id, job_kind, parent_job_id, round_no, "
        "generation, lease_owner, lease_expires_at) "
        "VALUES (%s, %s, 'RUNNING', 'execute', clock_timestamp(), 2, %s, "
        "'campaign', %s, NULL, 1, 'worker-a', "
        "clock_timestamp() + interval '1 hour')",
        (campaign_id, Jsonb({"schema_version": 2}), family_id, family_id),
    )
    charge = state.charge_step_budget(
        isolated_database.dsn,
        family_id=family_id,
        job_id=campaign_id,
        generation=1,
        step_key="drain",
        attempt_no=1,
        charge_kind="general",
        elapsed_seconds=900,
    )
    assert charge.status == "budget_exhausted"

    outcome = _admit(
        isolated_database,
        seed,
        budget_snapshot={
            "remaining_total_seconds": 900,
            "remaining_fuzz_seconds": 300,
        },
    )

    assert not outcome.admitted
    assert outcome.status == "denied"
    assert outcome.reason_code == "BUDGET_EXHAUSTED"
    assert outcome.sub_reason == "BUDGET_EXHAUSTED"
    assert _admissions(isolated_database, family_id, 2) == []
    events = _events(isolated_database, child_id)
    assert [event[0] for event in events] == ["round_admission_denied"]
    assert events[0][1] == "BUDGET_EXHAUSTED"


def test_record_admission_rejects_snapshot_exceeding_ledger(isolated_database):
    seed = _seed_family(isolated_database)
    family_id, child_id, _envelope_value = seed
    campaign_id = uuid4()
    isolated_database.connection.execute(
        "INSERT INTO jobs (job_id, request, state, stage, submitted_at, "
        "job_contract_version, family_id, job_kind, parent_job_id, round_no, "
        "generation, lease_owner, lease_expires_at) "
        "VALUES (%s, %s, 'RUNNING', 'execute', clock_timestamp(), 2, %s, "
        "'campaign', %s, NULL, 1, 'worker-a', "
        "clock_timestamp() + interval '1 hour')",
        (campaign_id, Jsonb({"schema_version": 2}), family_id, family_id),
    )
    charge = state.charge_step_budget(
        isolated_database.dsn,
        family_id=family_id,
        job_id=campaign_id,
        generation=1,
        step_key="build",
        attempt_no=1,
        charge_kind="general",
        elapsed_seconds=100,
    )
    assert charge.status == "charged"

    with pytest.raises(state.StateError, match="budget_snapshot"):
        _admit(
            isolated_database,
            seed,
            budget_snapshot={
                "remaining_total_seconds": 900,
                "remaining_fuzz_seconds": 300,
            },
        )
    assert _admissions(isolated_database, family_id, 2) == []


def test_record_admission_rejects_non_aggregating_family_and_wrong_job_identity(
    isolated_database,
):
    blocked_seed = _seed_family(
        isolated_database,
        family_state="BLOCKED",
        approval_digest=_digest("1"),
    )
    with pytest.raises(state.StateError, match="AGGREGATING"):
        _admit(isolated_database, blocked_seed)
    assert _admissions(isolated_database, blocked_seed[0], 2) == []

    completed_seed = _seed_family(
        isolated_database,
        family_state="COMPLETED",
        approval_digest=_digest("2"),
    )
    with pytest.raises(state.StateError, match="AGGREGATING"):
        _admit(isolated_database, completed_seed)
    assert _admissions(isolated_database, completed_seed[0], 2) == []

    seed = _seed_family(isolated_database, approval_digest=_digest("3"))
    family_id, child_id, approved_envelope = seed

    # Mismatched round_no (child has round_no=2, request says round_no=3)
    with pytest.raises(state.StateError, match="round_no"):
        _admit(isolated_database, seed, round_no=3)

    # Child from another family cannot be admitted under family_id
    other_seed = _seed_family(isolated_database, approval_digest=_digest("6"))
    with pytest.raises(state.StateError, match="belong"):
        state.record_admission(
            isolated_database.dsn,
            family_id=family_id,
            job_id=other_seed[1],
            round_no=2,
            envelope=approved_envelope,
            seed_digest=SEED_CORPUS_DIGEST,
            budget_snapshot=BUDGET_SNAPSHOT,
        )

    # Campaign child cannot be policy-admitted
    campaign_id = uuid4()
    campaign_plan = {
        "schema_version": 2,
        "envelope_digest": contracts.envelope_digest(approved_envelope),
        "parent_approval_digest": _digest("3"),
    }
    isolated_database.connection.execute(
        "INSERT INTO jobs (job_id, request, state, stage, submitted_at, "
        "job_contract_version, family_id, job_kind, parent_job_id, round_no, "
        "generation) "
        "VALUES (%s, %s, 'QUEUED', 'admission', clock_timestamp(), 2, %s, "
        "'campaign', %s, NULL, 1)",
        (campaign_id, Jsonb({"schema_version": 2}), family_id, family_id),
    )
    isolated_database.connection.execute(
        "INSERT INTO plans (plan_id, job_id, plan_digest, plan, summary) "
        "VALUES (%s, %s, %s, %s, %s)",
        (
            uuid4(),
            campaign_id,
            jsonutil.digest_json(campaign_plan),
            Jsonb(campaign_plan),
            Jsonb({}),
        ),
    )
    with pytest.raises(state.StateError, match="round"):
        state.record_admission(
            isolated_database.dsn,
            family_id=family_id,
            job_id=campaign_id,
            round_no=1,
            envelope=approved_envelope,
            seed_digest=SEED_CORPUS_DIGEST,
            budget_snapshot=BUDGET_SNAPSHOT,
        )

    # Multiple approval chain tails fail closed
    isolated_database.connection.execute(
        "INSERT INTO family_approvals (approval_id, family_id, approval_digest, "
        "envelope_digest, first_plan_digest, reviewer_id, decided_at, supersedes) "
        "VALUES (%s, %s, %s, %s, %s, %s, clock_timestamp(), NULL)",
        (
            uuid4(),
            family_id,
            _digest("4"),
            _digest("5"),
            FIRST_PLAN_DIGEST,
            REVIEWER_ID,
        ),
    )
    with pytest.raises(state.StateError, match="tail"):
        _admit(isolated_database, seed)


def test_record_admission_denies_null_plan_parent_approval_and_fixed_envelope(
    isolated_database,
):
    null_parent_seed = _seed_family(
        isolated_database,
        approval_digest=_digest("1"),
        plan_parent_approval_digest=None,
    )
    outcome = _admit(isolated_database, null_parent_seed)
    assert not outcome.admitted
    assert outcome.reason_code == "ADMISSION_DENIED"
    assert outcome.sub_reason == "PLAN_PARENT_APPROVAL_MISSING"
    assert _admissions(isolated_database, null_parent_seed[0], 2) == []

    fixed = contracts.fixed_envelope(
        harness_digest=HARNESS_DIGEST,
        accepted_signature_set=[dict(SIGNATURE)],
        max_total_seconds=900,
        admission_predicate_version="admission-v1",
    )
    fixed_seed = _seed_family(
        isolated_database,
        round_no=1,
        approval_digest=_digest("2"),
        envelope=fixed,
        plan_parent_approval_digest=None,
    )
    fixed_outcome = _admit(
        isolated_database,
        fixed_seed,
        round_no=1,
        budget_snapshot={
            "remaining_total_seconds": 900,
            "remaining_fuzz_seconds": 0,
        },
    )
    assert not fixed_outcome.admitted
    assert fixed_outcome.reason_code == "ENVELOPE_VIOLATION"
    assert _admissions(isolated_database, fixed_seed[0], 1) == []


def test_idempotent_readmission_survives_envelope_reapproval(isolated_database):
    seed = _seed_family(isolated_database)
    family_id, child_id, envelope_1 = seed

    first = _admit(isolated_database, seed)
    assert first.admitted
    assert first.admission is not None

    # Legitimate envelope change appends a new chain tail A2 superseding A1.
    envelope_2 = _envelope(max_rounds=6)
    envelope_2_digest = contracts.envelope_digest(envelope_2)
    approval_1_id = isolated_database.connection.execute(
        "SELECT approval_id FROM family_approvals WHERE family_id = %s",
        (family_id,),
    ).fetchone()[0]
    isolated_database.connection.execute(
        "INSERT INTO family_approvals (approval_id, family_id, approval_digest, "
        "envelope_digest, first_plan_digest, reviewer_id, decided_at, supersedes) "
        "VALUES (%s, %s, %s, %s, %s, %s, clock_timestamp(), %s)",
        (
            uuid4(),
            family_id,
            _digest("b"),
            envelope_2_digest,
            FIRST_PLAN_DIGEST,
            "reviewer-2",
            approval_1_id,
        ),
    )

    retry = _admit(isolated_database, seed, envelope=envelope_1)

    assert not retry.admitted
    assert retry.status == "already_admitted"
    assert retry.reason_code is None
    assert retry.event_type is None
    assert retry.admission is not None
    assert retry.admission["admission_id"] == first.admission["admission_id"]
    assert len(_admissions(isolated_database, family_id, 2)) == 1
    assert [event[0] for event in _events(isolated_database, child_id)] == [
        "round_admitted"
    ]


def _valid_experiment(input_family: str = "length_boundary") -> dict:
    return {
        "input_family": input_family,
        "mutation_constraints": {
            "allowed_ops": ["append", "truncate"],
            "max_input_bytes": 2048,
        },
        "expected_signature": dict(SIGNATURE),
    }


def test_record_admission_rejects_new_round_while_pending_envelope_exists(
    isolated_database,
):
    seed = _seed_family(isolated_database)
    family_id, child_id, _envelope_value = seed
    pending_envelope = _envelope(max_rounds=6)
    isolated_database.connection.execute(
        "INSERT INTO family_envelopes (envelope_id, family_id, envelope_digest, "
        "envelope_json, status, review_deadline_at) "
        "VALUES (%s, %s, %s, %s, 'pending', clock_timestamp() + interval '24 hours')",
        (
            uuid4(),
            family_id,
            contracts.envelope_digest(pending_envelope),
            Jsonb(pending_envelope),
        ),
    )

    with pytest.raises(state.StateError, match="pending"):
        _admit(isolated_database, seed)
    assert _admissions(isolated_database, family_id, 2) == []
    assert _events(isolated_database, child_id) == []


def test_readmission_rejects_out_of_envelope_or_different_experiment(
    isolated_database,
):
    exp_a = _valid_experiment("length_boundary")
    exp_b = _valid_experiment("byte_flip")
    seed = _seed_family(
        isolated_database,
        plan_experiment_digest=jsonutil.digest_json(exp_a),
    )
    family_id, child_id, _envelope_value = seed

    first = _admit(isolated_database, seed, experiment=exp_a)
    assert first.admitted

    # Exact same experiment remains an idempotent no-op.
    same = _admit(isolated_database, seed, experiment=exp_a)
    assert same.status == "already_admitted"
    assert len(_events(isolated_database, child_id)) == 1

    # Out-of-envelope experiments must never return already_admitted.
    for bad_exp in ({"input_family": "FORBIDDEN"}, {}):
        denied = _admit(isolated_database, seed, experiment=bad_exp)
        assert not denied.admitted
        assert denied.status == "denied"
        assert denied.status != "already_admitted"

    # Different valid experiment or omitted experiment must also be denied.
    for other_exp in (exp_b, None):
        denied = _admit(isolated_database, seed, experiment=other_exp)
        assert not denied.admitted
        assert denied.status == "denied"
        assert denied.reason_code == "ADMISSION_DENIED"
        assert denied.sub_reason == "ROUND_ALREADY_ADMITTED"

    # Non-canonical JSON experiment fails closed with StateError.
    with pytest.raises(state.StateError):
        _admit(isolated_database, seed, experiment={"bad": float("nan")})

    # Round originally admitted with experiment=None must also reject bad/new experiments.
    seed_none = _seed_family(isolated_database, approval_digest=_digest("8"))
    assert _admit(isolated_database, seed_none, experiment=None).admitted
    for bad_exp in ({"input_family": "FORBIDDEN"}, {}, exp_a):
        denied = _admit(isolated_database, seed_none, experiment=bad_exp)
        assert not denied.admitted
        assert denied.status == "denied"


def test_readmission_rejects_plan_envelope_digest_mismatch(isolated_database):
    seed = _seed_family(isolated_database)
    family_id, child_id, _envelope_value = seed

    first = _admit(isolated_database, seed)
    assert first.admitted

    isolated_database.connection.execute(
        "UPDATE plans SET plan = jsonb_set(plan, '{envelope_digest}', to_jsonb(%s::text)) "
        "WHERE job_id = %s",
        (_digest("7"), child_id),
    )

    second = _admit(isolated_database, seed)
    assert not second.admitted
    assert second.status == "denied"
    assert second.reason_code == "ADMISSION_DENIED"
    assert len(_admissions(isolated_database, family_id, 2)) == 1


def test_record_admission_requires_valid_plan_harness_digest(
    isolated_database,
):
    seed = _seed_family(isolated_database)
    family_id, child_id, _envelope_value = seed

    isolated_database.connection.execute(
        "UPDATE plans SET plan = plan - 'harness_digest' WHERE job_id = %s",
        (child_id,),
    )
    with pytest.raises(state.StateError, match="harness_digest"):
        _admit(isolated_database, seed)
    assert _admissions(isolated_database, family_id, 2) == []
    assert _events(isolated_database, child_id) == []

    for bad_harness_digest in (None, "", "not-a-digest", 123):
        isolated_database.connection.execute(
            "UPDATE plans SET plan = jsonb_set(plan, '{harness_digest}', %s) "
            "WHERE job_id = %s",
            (Jsonb(bad_harness_digest), child_id),
        )
        with pytest.raises(state.StateError, match="harness_digest"):
            _admit(isolated_database, seed)
        assert _admissions(isolated_database, family_id, 2) == []
        assert _events(isolated_database, child_id) == []


def test_record_admission_denies_plan_harness_mismatch(isolated_database):
    mismatch_digest = _digest("9")
    seed = _seed_family(
        isolated_database, plan_harness_digest=mismatch_digest
    )
    family_id, child_id, envelope = seed
    reviews_before = isolated_database.connection.execute(
        "SELECT count(*) FROM reviews WHERE job_id IN (%s, %s)",
        (family_id, child_id),
    ).fetchone()[0]
    approvals_before = isolated_database.connection.execute(
        "SELECT count(*) FROM family_approvals WHERE family_id = %s",
        (family_id,),
    ).fetchone()[0]

    outcome = _admit(isolated_database, seed)

    assert not outcome.admitted
    assert outcome.status == "denied"
    assert outcome.reason_code == "HARNESS_REJECTED"
    assert outcome.sub_reason == "PLAN_HARNESS_MISMATCH"
    assert _admissions(isolated_database, family_id, 2) == []
    events = _events(isolated_database, child_id)
    assert [event[0] for event in events] == ["round_admission_denied"]
    assert events[0][1] == "HARNESS_REJECTED"
    assert events[0][2]["sub_reason"] == "PLAN_HARNESS_MISMATCH"
    assert (
        events[0][2]["expected_harness_digest"]
        == envelope["harness_digest"]
    )
    assert events[0][2]["actual_harness_digest"] == mismatch_digest

    reviews_after = isolated_database.connection.execute(
        "SELECT count(*) FROM reviews WHERE job_id IN (%s, %s)",
        (family_id, child_id),
    ).fetchone()[0]
    approvals_after = isolated_database.connection.execute(
        "SELECT count(*) FROM family_approvals WHERE family_id = %s",
        (family_id,),
    ).fetchone()[0]
    assert reviews_after == reviews_before
    assert approvals_after == approvals_before


def test_readmission_after_plan_harness_tamper_is_denied_not_already_admitted(
    isolated_database,
):
    seed = _seed_family(isolated_database)
    family_id, child_id, envelope = seed

    first = _admit(isolated_database, seed)
    assert first.admitted
    assert len(_admissions(isolated_database, family_id, 2)) == 1
    assert [event[0] for event in _events(isolated_database, child_id)] == [
        "round_admitted"
    ]

    tampered_digest = _digest("9")
    isolated_database.connection.execute(
        "UPDATE plans SET plan = jsonb_set(plan, '{harness_digest}', "
        "to_jsonb(%s::text)) WHERE job_id = %s",
        (tampered_digest, child_id),
    )

    second = _admit(isolated_database, seed)

    assert not second.admitted
    assert second.status == "denied"
    assert second.status != "already_admitted"
    assert second.reason_code == "HARNESS_REJECTED"
    assert second.sub_reason == "PLAN_HARNESS_MISMATCH"
    assert len(_admissions(isolated_database, family_id, 2)) == 1
    events = _events(isolated_database, child_id)
    assert [event[0] for event in events] == [
        "round_admitted",
        "round_admission_denied",
    ]
    assert events[1][1] == "HARNESS_REJECTED"
    assert (
        events[1][2]["expected_harness_digest"]
        == envelope["harness_digest"]
    )
    assert events[1][2]["actual_harness_digest"] == tampered_digest

    # Terminal protection still wins: no dirty denial audit is appended.
    isolated_database.connection.execute(
        "UPDATE jobs SET state = 'BLOCKED' WHERE job_id = %s",
        (family_id,),
    )
    with pytest.raises(state.StateError, match="AGGREGATING"):
        _admit(isolated_database, seed)
    assert len(_events(isolated_database, child_id)) == 2
    assert len(_admissions(isolated_database, family_id, 2)) == 1


@pytest.mark.parametrize("terminal_state", ["BLOCKED", "COMPLETED"])
def test_readmission_on_terminal_family_blocks_dirty_audit(
    isolated_database, terminal_state
):
    seed = _seed_family(isolated_database)
    family_id, child_id, _envelope_value = seed

    first = _admit(isolated_database, seed)
    assert first.admitted
    initial_events = _events(isolated_database, child_id)
    assert len(initial_events) == 1

    if terminal_state == "COMPLETED":
        isolated_database.connection.execute(
            "UPDATE jobs SET state = 'COMPLETED', evidence_status = 'archived', "
            "evidence_path = '/tmp/family.json', evidence_digest = %s "
            "WHERE job_id = %s",
            (_digest("8"), family_id),
        )
    else:
        isolated_database.connection.execute(
            "UPDATE jobs SET state = 'BLOCKED' WHERE job_id = %s",
            (family_id,),
        )

    # Same-input readmission remains a side-effect-free no-op.
    same = _admit(isolated_database, seed)
    assert same.status == "already_admitted"
    assert len(_events(isolated_database, child_id)) == 1

    # Conflicting readmission must fail closed without appending dirty audit events.
    with pytest.raises(state.StateError, match="AGGREGATING"):
        _admit(isolated_database, seed, seed_digest=_digest("9"))
    assert len(_events(isolated_database, child_id)) == 1


@pytest.mark.parametrize("round_state", ["BLOCKED", "COMPLETED"])
def test_record_admission_rejects_terminal_round_job(
    isolated_database, round_state
):
    seed = _seed_family(isolated_database)
    family_id, child_id, _envelope_value = seed
    if round_state == "COMPLETED":
        isolated_database.connection.execute(
            "UPDATE jobs SET state = 'COMPLETED', evidence_status = 'archived', "
            "evidence_path = '/tmp/round.json', evidence_digest = %s "
            "WHERE job_id = %s",
            (_digest("8"), child_id),
        )
    else:
        isolated_database.connection.execute(
            "UPDATE jobs SET state = 'BLOCKED' WHERE job_id = %s",
            (child_id,),
        )

    with pytest.raises(state.StateError, match=round_state):
        _admit(isolated_database, seed)
    assert _admissions(isolated_database, family_id, 2) == []
    assert _events(isolated_database, child_id) == []


@pytest.mark.parametrize("round_state", ["RUNNING", "ARCHIVING", "AWAITING_REVIEW"])
def test_record_admission_rejects_round_job_past_the_admission_phase(
    isolated_database, round_state
):
    seed = _seed_family(isolated_database)
    family_id, child_id, _envelope_value = seed
    isolated_database.connection.execute(
        "UPDATE jobs SET state = %s WHERE job_id = %s",
        (round_state, child_id),
    )

    with pytest.raises(state.StateError, match=round_state):
        _admit(isolated_database, seed)
    assert _admissions(isolated_database, family_id, 2) == []
    assert _events(isolated_database, child_id) == []


@pytest.mark.parametrize("round_state", ["QUEUED", "PREPARING", "READY"])
def test_record_admission_accepts_pre_execution_round_job(
    isolated_database, round_state
):
    seed = _seed_family(isolated_database)
    family_id, child_id, _envelope_value = seed
    isolated_database.connection.execute(
        "UPDATE jobs SET state = %s WHERE job_id = %s",
        (round_state, child_id),
    )

    outcome = _admit(isolated_database, seed)

    assert outcome.admitted
    assert len(_admissions(isolated_database, family_id, 2)) == 1
    assert [event[0] for event in _events(isolated_database, child_id)] == [
        "round_admitted"
    ]


def test_readmission_stays_idempotent_after_round_enters_running(isolated_database):
    seed = _seed_family(isolated_database)
    family_id, child_id, _envelope_value = seed
    first = _admit(isolated_database, seed)
    assert first.admitted
    isolated_database.connection.execute(
        "UPDATE jobs SET state = 'RUNNING' WHERE job_id = %s",
        (child_id,),
    )

    same = _admit(isolated_database, seed)

    assert same.status == "already_admitted"
    assert len(_admissions(isolated_database, family_id, 2)) == 1
    assert [event[0] for event in _events(isolated_database, child_id)] == [
        "round_admitted"
    ]


def test_record_admission_validates_plan_round_no_and_candidate_seed(
    isolated_database,
):
    # Mismatched candidate seed in plan -> denied with PLAN_SEED_MISMATCH
    seed_mismatch = _seed_family(isolated_database, approval_digest=_digest("1"))
    family_id_1, child_id_1, _ = seed_mismatch
    isolated_database.connection.execute(
        "UPDATE plans SET plan = plan || %s::jsonb WHERE job_id = %s",
        (
            jsonutil.canonical_bytes(
                {
                    "round_no": 2,
                    "inputs": {
                        "normal": _digest("1"),
                        "candidate": _digest("9"),
                    },
                }
            ).decode("utf-8"),
            child_id_1,
        ),
    )
    denied = _admit(isolated_database, seed_mismatch)
    assert not denied.admitted
    assert denied.status == "denied"
    assert denied.reason_code == "ADMISSION_DENIED"
    assert denied.sub_reason == "PLAN_SEED_MISMATCH"
    assert _admissions(isolated_database, family_id_1, 2) == []
    events = _events(isolated_database, child_id_1)
    assert [event[0] for event in events] == ["round_admission_denied"]
    assert events[0][2]["sub_reason"] == "PLAN_SEED_MISMATCH"

    # Mismatched round_no in plan -> StateError
    seed_round = _seed_family(isolated_database, approval_digest=_digest("2"))
    family_id_2, child_id_2, _ = seed_round
    isolated_database.connection.execute(
        "UPDATE plans SET plan = plan || %s::jsonb WHERE job_id = %s",
        (
            jsonutil.canonical_bytes({"round_no": 3}).decode("utf-8"),
            child_id_2,
        ),
    )
    with pytest.raises(state.StateError, match="round_no"):
        _admit(isolated_database, seed_round)
    assert _admissions(isolated_database, family_id_2, 2) == []

    # Matching round_no and candidate seed -> admitted cleanly
    seed_ok = _seed_family(isolated_database, approval_digest=_digest("3"))
    family_id_3, child_id_3, _ = seed_ok
    isolated_database.connection.execute(
        "UPDATE plans SET plan = plan || %s::jsonb WHERE job_id = %s",
        (
            jsonutil.canonical_bytes(
                {
                    "round_no": 2,
                    "inputs": {
                        "normal": _digest("1"),
                        "candidate": SEED_CORPUS_DIGEST,
                    },
                }
            ).decode("utf-8"),
            child_id_3,
        ),
    )
    admitted = _admit(isolated_database, seed_ok)
    assert admitted.admitted
    assert len(_admissions(isolated_database, family_id_3, 2)) == 1


def test_record_admission_rejects_non_mapping_budget_snapshot(isolated_database):
    seed = _seed_family(isolated_database)
    family_id, child_id, _ = seed

    with pytest.raises(state.StateError):
        _admit(
            isolated_database,
            seed,
            budget_snapshot=[("remaining_total_seconds", 100)],  # type: ignore[arg-type]
        )
    assert _admissions(isolated_database, family_id, 2) == []
    assert _events(isolated_database, child_id) == []


def test_readmission_rejects_over_cap_budget_snapshot_without_dirty_event(
    isolated_database,
):
    seed = _seed_family(isolated_database)
    family_id, child_id, envelope = seed

    first = _admit(isolated_database, seed)
    assert first.admitted
    assert [event[0] for event in _events(isolated_database, child_id)] == [
        "round_admitted"
    ]

    for bad_snapshot in (
        {
            "remaining_total_seconds": envelope["max_total_seconds"] + 1,
            "remaining_fuzz_seconds": 300,
        },
        {
            "remaining_total_seconds": 900,
            "remaining_fuzz_seconds": envelope["max_fuzz_seconds"] + 1,
        },
    ):
        with pytest.raises(state.StateError, match="exceeds"):
            _admit(isolated_database, seed, budget_snapshot=bad_snapshot)

    assert len(_admissions(isolated_database, family_id, 2)) == 1
    assert [event[0] for event in _events(isolated_database, child_id)] == [
        "round_admitted"
    ]


def test_record_admission_validates_plan_family_id_and_parent_job_id_when_present(
    isolated_database,
):
    other_id = str(uuid4())

    for token, key, bad_value in (
        ("1", "family_id", other_id),
        ("2", "family_id", 123),
        ("3", "parent_job_id", other_id),
        ("4", "parent_job_id", 123),
    ):
        seed = _seed_family(isolated_database, approval_digest=_digest(token))
        family_id, child_id, _ = seed
        isolated_database.connection.execute(
            "UPDATE plans SET plan = plan || %s::jsonb WHERE job_id = %s",
            (jsonutil.canonical_bytes({key: bad_value}).decode("utf-8"), child_id),
        )
        with pytest.raises(state.StateError, match=key):
            _admit(isolated_database, seed)
        assert _admissions(isolated_database, family_id, 2) == []
        assert _events(isolated_database, child_id) == []

    good_seed = _seed_family(isolated_database, approval_digest=_digest("5"))
    family_id, child_id, _ = good_seed
    isolated_database.connection.execute(
        "UPDATE plans SET plan = plan || %s::jsonb WHERE job_id = %s",
        (
            jsonutil.canonical_bytes(
                {
                    "family_id": str(family_id),
                    "parent_job_id": str(family_id),
                }
            ).decode("utf-8"),
            child_id,
        ),
    )
    admitted = _admit(isolated_database, good_seed)
    assert admitted.admitted
    assert len(_admissions(isolated_database, family_id, 2)) == 1


def test_record_admission_validates_plan_experiment_digest_when_present(
    isolated_database,
):
    exp_a = _valid_experiment("length_boundary")
    exp_b = _valid_experiment("byte_flip")
    exp_a_digest = jsonutil.digest_json(exp_a)
    exp_b_digest = jsonutil.digest_json(exp_b)
    assert exp_a_digest != exp_b_digest

    # 1. Frozen plan binds exp_a_digest, caller supplies exp_b -> denied
    seed_diff = _seed_family(isolated_database, approval_digest=_digest("1"))
    family_id_1, child_id_1, _ = seed_diff
    isolated_database.connection.execute(
        "UPDATE plans SET plan = plan || %s::jsonb WHERE job_id = %s",
        (
            jsonutil.canonical_bytes(
                {"experiment_digest": exp_a_digest}
            ).decode("utf-8"),
            child_id_1,
        ),
    )
    denied_diff = _admit(isolated_database, seed_diff, experiment=exp_b)
    assert not denied_diff.admitted
    assert denied_diff.status == "denied"
    assert denied_diff.reason_code == "ADMISSION_DENIED"
    assert denied_diff.sub_reason == "PLAN_EXPERIMENT_MISMATCH"
    assert _admissions(isolated_database, family_id_1, 2) == []
    events_1 = _events(isolated_database, child_id_1)
    assert [event[0] for event in events_1] == ["round_admission_denied"]
    assert events_1[0][2]["sub_reason"] == "PLAN_EXPERIMENT_MISMATCH"
    assert events_1[0][2]["expected_experiment_digest"] == exp_a_digest
    assert events_1[0][2]["actual_experiment_digest"] == exp_b_digest

    # 2. Frozen plan binds exp_a_digest, caller supplies experiment=None -> denied
    seed_none = _seed_family(isolated_database, approval_digest=_digest("2"))
    family_id_2, child_id_2, _ = seed_none
    isolated_database.connection.execute(
        "UPDATE plans SET plan = plan || %s::jsonb WHERE job_id = %s",
        (
            jsonutil.canonical_bytes(
                {"experiment_digest": exp_a_digest}
            ).decode("utf-8"),
            child_id_2,
        ),
    )
    denied_none = _admit(isolated_database, seed_none, experiment=None)
    assert not denied_none.admitted
    assert denied_none.status == "denied"
    assert denied_none.reason_code == "ADMISSION_DENIED"
    assert denied_none.sub_reason == "PLAN_EXPERIMENT_MISMATCH"
    assert _admissions(isolated_database, family_id_2, 2) == []
    events_2 = _events(isolated_database, child_id_2)
    assert [event[0] for event in events_2] == ["round_admission_denied"]
    assert events_2[0][2]["sub_reason"] == "PLAN_EXPERIMENT_MISMATCH"
    assert events_2[0][2]["expected_experiment_digest"] == exp_a_digest
    assert events_2[0][2]["actual_experiment_digest"] is None

    # 3. Frozen plan binds experiment_digest=null, caller supplies exp_a -> denied
    seed_null = _seed_family(isolated_database, approval_digest=_digest("3"))
    family_id_3, child_id_3, _ = seed_null
    isolated_database.connection.execute(
        "UPDATE plans SET plan = plan || %s::jsonb WHERE job_id = %s",
        (
            jsonutil.canonical_bytes({"experiment_digest": None}).decode("utf-8"),
            child_id_3,
        ),
    )
    denied_null = _admit(isolated_database, seed_null, experiment=exp_a)
    assert not denied_null.admitted
    assert denied_null.status == "denied"
    assert denied_null.reason_code == "ADMISSION_DENIED"
    assert denied_null.sub_reason == "PLAN_EXPERIMENT_MISMATCH"
    assert _admissions(isolated_database, family_id_3, 2) == []
    events_3 = _events(isolated_database, child_id_3)
    assert [event[0] for event in events_3] == ["round_admission_denied"]
    assert events_3[0][2]["sub_reason"] == "PLAN_EXPERIMENT_MISMATCH"
    assert events_3[0][2]["expected_experiment_digest"] is None
    assert events_3[0][2]["actual_experiment_digest"] == exp_a_digest

    # 4. Matching experiment -> admitted; identical retry -> already_admitted;
    #    mutated plans.plan experiment_digest -> retry must NOT return already_admitted
    seed_ok = _seed_family(isolated_database, approval_digest=_digest("4"))
    family_id_4, child_id_4, _ = seed_ok
    isolated_database.connection.execute(
        "UPDATE plans SET plan = plan || %s::jsonb WHERE job_id = %s",
        (
            jsonutil.canonical_bytes(
                {"experiment_digest": exp_a_digest}
            ).decode("utf-8"),
            child_id_4,
        ),
    )
    first = _admit(isolated_database, seed_ok, experiment=exp_a)
    assert first.admitted
    assert len(_admissions(isolated_database, family_id_4, 2)) == 1
    assert [event[0] for event in _events(isolated_database, child_id_4)] == [
        "round_admitted"
    ]

    same = _admit(isolated_database, seed_ok, experiment=exp_a)
    assert not same.admitted
    assert same.status == "already_admitted"
    assert len(_events(isolated_database, child_id_4)) == 1

    isolated_database.connection.execute(
        "UPDATE plans SET plan = jsonb_set(plan, '{experiment_digest}', "
        "to_jsonb(%s::text)) WHERE job_id = %s",
        (exp_b_digest, child_id_4),
    )
    tampered = _admit(isolated_database, seed_ok, experiment=exp_a)
    assert not tampered.admitted
    assert tampered.status == "denied"
    assert tampered.status != "already_admitted"
    assert tampered.reason_code == "ADMISSION_DENIED"
    assert len(_admissions(isolated_database, family_id_4, 2)) == 1
    assert [event[0] for event in _events(isolated_database, child_id_4)] == [
        "round_admitted",
        "round_admission_denied",
    ]


def test_record_admission_requires_plan_v2_binding_fields_and_fails_closed_uniformly(
    isolated_database,
):
    # 1. Missing required binding fields or null inputs fail closed on first admission.
    missing_cases = [
        ("missing_family_id", lambda p: p.pop("family_id")),
        ("missing_parent_job_id", lambda p: p.pop("parent_job_id")),
        ("missing_round_no", lambda p: p.pop("round_no")),
        ("missing_inputs", lambda p: p.pop("inputs")),
        ("null_inputs", lambda p: p.__setitem__("inputs", None)),
        ("missing_candidate", lambda p: p["inputs"].pop("candidate")),
        ("missing_experiment_digest", lambda p: p.pop("experiment_digest")),
        ("missing_envelope_digest", lambda p: p.pop("envelope_digest")),
        ("missing_parent_approval_digest", lambda p: p.pop("parent_approval_digest")),
        ("bad_experiment_digest_type", lambda p: p.__setitem__("experiment_digest", 123)),
        ("bool_round_no", lambda p: p.__setitem__("round_no", True)),
        ("bad_candidate_digest", lambda p: p["inputs"].__setitem__("candidate", "not-a-digest")),
        ("bad_envelope_digest_type", lambda p: p.__setitem__("envelope_digest", 123)),
        ("bad_parent_approval_type", lambda p: p.__setitem__("parent_approval_digest", 123)),
    ]
    for idx, (label, mutate) in enumerate(missing_cases):
        approval = f"sha256:{idx:064x}"
        seed = _seed_family(isolated_database, approval_digest=approval)
        family_id, child_id, envelope = seed
        plan = _full_plan(family_id, envelope, approval)
        mutate(plan)
        isolated_database.connection.execute(
            "UPDATE plans SET plan = %s WHERE job_id = %s",
            (Jsonb(plan), child_id),
        )
        with pytest.raises(state.StateError):
            _admit(isolated_database, seed)
        assert _admissions(isolated_database, family_id, 2) == [], label
        assert _events(isolated_database, child_id) == [], label

    # 2. Invalid type (experiment_digest=123) and missing field on readmission
    #    must ALSO raise StateError with zero dirty round_admission_denied events.
    seed_readmit = _seed_family(isolated_database, approval_digest=_digest("7"))
    family_id, child_id, envelope = seed_readmit
    valid_plan = _full_plan(family_id, envelope, _digest("7"))
    isolated_database.connection.execute(
        "UPDATE plans SET plan = %s WHERE job_id = %s",
        (Jsonb(valid_plan), child_id),
    )
    first = _admit(isolated_database, seed_readmit)
    assert first.admitted
    assert len(_admissions(isolated_database, family_id, 2)) == 1
    assert [event[0] for event in _events(isolated_database, child_id)] == [
        "round_admitted"
    ]

    for bad_plan in (
        {**valid_plan, "experiment_digest": 123},
        {k: v for k, v in valid_plan.items() if k != "experiment_digest"},
        {**valid_plan, "inputs": None},
    ):
        isolated_database.connection.execute(
            "UPDATE plans SET plan = %s WHERE job_id = %s",
            (Jsonb(bad_plan), child_id),
        )
        with pytest.raises(state.StateError):
            _admit(isolated_database, seed_readmit)
        assert len(_admissions(isolated_database, family_id, 2)) == 1
        assert [event[0] for event in _events(isolated_database, child_id)] == [
            "round_admitted"
        ]


def test_record_admission_rejects_unreconciled_or_unknown_key_budget_snapshot(
    isolated_database,
):
    seed = _seed_family(isolated_database)
    family_id, child_id, _ = seed
    bad_snapshots = [
        {"remaining_total_seconds": 100, "extra_unknown": 1},
        {
            "remaining_total_seconds": 100,
            "max_total_seconds": -999,
            "spent_seconds": -5,
        },
        {"remaining_total_seconds": 100, "max_total_seconds": True},
        {"remaining_total_seconds": 100, "spent_seconds": False},
        {
            "remaining_total_seconds": 800,
            "max_total_seconds": 900,
            "spent_seconds": 50,
        },
        {
            "remaining_total_seconds": 800,
            "remaining_fuzz_seconds": 200,
            "max_fuzz_seconds": 300,
            "spent_fuzz_seconds": 50,
        },
        {"remaining_total_seconds": 100, "family_id": "not-a-uuid"},
        {"remaining_total_seconds": 100, "updated_at": "not-a-timestamp"},
    ]
    for bad in bad_snapshots:
        with pytest.raises(state.StateError):
            _admit(isolated_database, seed, budget_snapshot=bad)
    assert _admissions(isolated_database, family_id, 2) == []
    assert _events(isolated_database, child_id) == []


def test_record_admission_binds_budget_snapshot_family_id_and_caps(
    isolated_database,
):
    seed = _seed_family(isolated_database)
    family_id, child_id, envelope = seed
    other_family_id = str(uuid4())

    # 1. Cross-family family_id and envelope cap mismatches fail closed with
    #    0 admissions rows and 0 dirty audit events.
    mismatched_snapshots = [
        {
            "family_id": other_family_id,
            "max_total_seconds": envelope["max_total_seconds"],
            "max_fuzz_seconds": envelope["max_fuzz_seconds"],
            "remaining_total_seconds": 900,
            "remaining_fuzz_seconds": 300,
            "updated_at": "2099-01-01T00:00:00Z",
        },
        {
            "family_id": str(family_id),
            "max_total_seconds": 800,
            "max_fuzz_seconds": 300,
            "remaining_total_seconds": 800,
            "remaining_fuzz_seconds": 300,
        },
        {
            "family_id": str(family_id),
            "max_total_seconds": 1000,
            "max_fuzz_seconds": 300,
            "remaining_total_seconds": 900,
            "remaining_fuzz_seconds": 300,
        },
        {
            "family_id": str(family_id),
            "max_total_seconds": 900,
            "max_fuzz_seconds": 200,
            "remaining_total_seconds": 900,
            "remaining_fuzz_seconds": 200,
        },
        {
            "family_id": str(family_id),
            "max_total_seconds": 900,
            "max_fuzz_seconds": 400,
            "remaining_total_seconds": 900,
            "remaining_fuzz_seconds": 300,
        },
    ]
    for bad in mismatched_snapshots:
        with pytest.raises(state.StateError):
            _admit(isolated_database, seed, budget_snapshot=bad)
    assert _admissions(isolated_database, family_id, 2) == []
    assert _events(isolated_database, child_id) == []

    # 2. Snapshot matching an unapproved envelope's caps but differing from
    #    the persisted budget_ledger max_* must also raise StateError with
    #    0 admissions rows and 0 dirty audit events.
    different_total_env = contracts.guided_envelope(
        allowed_mutation_families=["byte_flip", "length_boundary"],
        mutation_limits={
            "allowed_ops": ["append", "truncate", "byte_flip"],
            "max_input_bytes": 4096,
        },
        seed_corpus_digest=SEED_CORPUS_DIGEST,
        toolchain_image_digest=TOOLCHAIN_IMAGE_DIGEST,
        harness_digest=HARNESS_DIGEST,
        max_rounds=8,
        max_total_seconds=800,
        max_fuzz_seconds=300,
        accepted_signature_set=[dict(SIGNATURE)],
        admission_predicate_version="admission-v1",
    )
    with pytest.raises(state.StateError, match="max_total_seconds"):
        _admit(
            isolated_database,
            seed,
            envelope=different_total_env,
            budget_snapshot={
                "family_id": str(family_id),
                "max_total_seconds": 800,
                "max_fuzz_seconds": 300,
                "remaining_total_seconds": 800,
                "remaining_fuzz_seconds": 300,
            },
        )
    different_fuzz_env = contracts.guided_envelope(
        allowed_mutation_families=["byte_flip", "length_boundary"],
        mutation_limits={
            "allowed_ops": ["append", "truncate", "byte_flip"],
            "max_input_bytes": 4096,
        },
        seed_corpus_digest=SEED_CORPUS_DIGEST,
        toolchain_image_digest=TOOLCHAIN_IMAGE_DIGEST,
        harness_digest=HARNESS_DIGEST,
        max_rounds=8,
        max_total_seconds=900,
        max_fuzz_seconds=200,
        accepted_signature_set=[dict(SIGNATURE)],
        admission_predicate_version="admission-v1",
    )
    with pytest.raises(state.StateError, match="max_fuzz_seconds"):
        _admit(
            isolated_database,
            seed,
            envelope=different_fuzz_env,
            budget_snapshot={
                "family_id": str(family_id),
                "max_total_seconds": 900,
                "max_fuzz_seconds": 200,
                "remaining_total_seconds": 900,
                "remaining_fuzz_seconds": 200,
            },
        )
    assert _admissions(isolated_database, family_id, 2) == []
    assert _events(isolated_database, child_id) == []

    # 3. Full 6-field snapshot matching family_id, envelope, and ledger caps
    #    is admitted cleanly, and historical same-input re-entry remains
    #    already_admitted even after a later envelope/ledger cap change.
    full_snapshot = {
        "family_id": str(family_id),
        "max_total_seconds": 900,
        "max_fuzz_seconds": 300,
        "remaining_total_seconds": 900,
        "remaining_fuzz_seconds": 300,
        "updated_at": "2099-01-01T00:00:00Z",
    }
    admitted = _admit(isolated_database, seed, budget_snapshot=full_snapshot)
    assert admitted.admitted
    assert len(_admissions(isolated_database, family_id, 2)) == 1
    assert [event[0] for event in _events(isolated_database, child_id)] == [
        "round_admitted"
    ]

    isolated_database.connection.execute(
        "UPDATE budget_ledger SET max_total_seconds = 600, "
        "remaining_total_seconds = 600, max_fuzz_seconds = 200, "
        "remaining_fuzz_seconds = 200 WHERE family_id = %s",
        (family_id,),
    )
    reentered = _admit(isolated_database, seed, budget_snapshot=full_snapshot)
    assert not reentered.admitted
    assert reentered.status == "already_admitted"
    assert [event[0] for event in _events(isolated_database, child_id)] == [
        "round_admitted"
    ]


def _envelope_with_caps(*, max_total_seconds: int, max_fuzz_seconds: int) -> dict:
    return contracts.guided_envelope(
        allowed_mutation_families=["byte_flip", "length_boundary"],
        mutation_limits={
            "allowed_ops": ["append", "truncate", "byte_flip"],
            "max_input_bytes": 4096,
        },
        seed_corpus_digest=SEED_CORPUS_DIGEST,
        toolchain_image_digest=TOOLCHAIN_IMAGE_DIGEST,
        harness_digest=HARNESS_DIGEST,
        max_rounds=8,
        max_total_seconds=max_total_seconds,
        max_fuzz_seconds=max_fuzz_seconds,
        accepted_signature_set=[dict(SIGNATURE)],
        admission_predicate_version="admission-v1",
    )


def test_record_admission_reconciles_spent_when_snapshot_omits_max(
    isolated_database,
):
    # S-2: without max_* the snapshot is reconciled against the persisted
    # ledger caps (== approved envelope caps 900/300).
    seed = _seed_family(isolated_database)
    family_id, child_id, _ = seed
    bad_snapshots = [
        {
            "remaining_total_seconds": 500,
            "spent_seconds": 999999,
            "remaining_fuzz_seconds": 100,
            "spent_fuzz_seconds": 999999,
        },
        {"remaining_total_seconds": 900, "spent_seconds": 1},
        {
            "remaining_total_seconds": 900,
            "remaining_fuzz_seconds": 300,
            "spent_fuzz_seconds": 1,
        },
        {"remaining_total_seconds": 900, "spent_fuzz_seconds": 301},
    ]
    for bad in bad_snapshots:
        with pytest.raises(state.StateError):
            _admit(isolated_database, seed, budget_snapshot=bad)
    assert _admissions(isolated_database, family_id, 2) == []
    assert _events(isolated_database, child_id) == []

    admitted = _admit(
        isolated_database,
        seed,
        budget_snapshot={
            "remaining_total_seconds": 900,
            "spent_seconds": 0,
            "remaining_fuzz_seconds": 300,
            "spent_fuzz_seconds": 0,
        },
    )
    assert admitted.admitted
    assert len(_admissions(isolated_database, family_id, 2)) == 1


@pytest.mark.parametrize(
    ("max_total_seconds", "max_fuzz_seconds"),
    [(600, 300), (1200, 300), (900, 200)],
)
@pytest.mark.parametrize("snapshot_shape", ["ledger", "minimal"])
def test_record_admission_denies_unapproved_cap_change_with_real_snapshot(
    isolated_database, max_total_seconds, max_fuzz_seconds, snapshot_shape
):
    # S-3: the snapshot is the genuine family ledger; only the envelope is
    # unapproved. The decision must be a persisted ADMISSION_DENIED.
    seed = _seed_family(isolated_database)
    family_id, child_id, approved_envelope = seed
    unapproved = _envelope_with_caps(
        max_total_seconds=max_total_seconds, max_fuzz_seconds=max_fuzz_seconds
    )
    assert contracts.envelope_digest(unapproved) != contracts.envelope_digest(
        approved_envelope
    )
    if snapshot_shape == "ledger":
        snapshot = state.load_budget_ledger(isolated_database.dsn, family_id)
        assert snapshot is not None
        assert snapshot["max_total_seconds"] == 900
        assert snapshot["max_fuzz_seconds"] == 300
    else:
        snapshot = {"remaining_total_seconds": 900, "remaining_fuzz_seconds": 300}

    outcome = _admit(
        isolated_database, seed, envelope=unapproved, budget_snapshot=snapshot
    )

    assert outcome.status == "denied"
    assert not outcome.admitted
    assert outcome.reason_code == "ADMISSION_DENIED"
    assert outcome.sub_reason == "PARENT_APPROVAL_ENVELOPE_MISMATCH"
    assert _admissions(isolated_database, family_id, 2) == []
    events = _events(isolated_database, child_id)
    assert [event[0] for event in events] == ["round_admission_denied"]
    assert events[0][1] == "ADMISSION_DENIED"
    assert events[0][2]["sub_reason"] == "PARENT_APPROVAL_ENVELOPE_MISMATCH"


@pytest.mark.parametrize(
    ("max_total_seconds", "max_fuzz_seconds"),
    [(600, 300), (1200, 300), (900, 200)],
)
@pytest.mark.parametrize("snapshot_shape", ["ledger", "minimal"])
def test_readmission_denies_conflicting_cap_change_with_real_snapshot(
    isolated_database, max_total_seconds, max_fuzz_seconds, snapshot_shape
):
    # S-1: re-entering an already admitted round with a genuine family ledger
    # snapshot and a conflicting envelope that changes max_* caps must persist
    # ADMISSION_DENIED (ROUND_ALREADY_ADMITTED), not raise StateError.
    seed = _seed_family(isolated_database)
    family_id, child_id, approved_envelope = seed
    if snapshot_shape == "ledger":
        snapshot = state.load_budget_ledger(isolated_database.dsn, family_id)
        assert snapshot is not None
        assert snapshot["max_total_seconds"] == 900
        assert snapshot["max_fuzz_seconds"] == 300
    else:
        snapshot = {"remaining_total_seconds": 900, "remaining_fuzz_seconds": 300}

    first = _admit(isolated_database, seed, budget_snapshot=snapshot)
    assert first.admitted
    assert len(_admissions(isolated_database, family_id, 2)) == 1
    assert [event[0] for event in _events(isolated_database, child_id)] == [
        "round_admitted"
    ]

    conflicting = _envelope_with_caps(
        max_total_seconds=max_total_seconds, max_fuzz_seconds=max_fuzz_seconds
    )
    assert contracts.envelope_digest(conflicting) != contracts.envelope_digest(
        approved_envelope
    )

    second = _admit(
        isolated_database,
        seed,
        envelope=conflicting,
        budget_snapshot=snapshot,
    )

    assert not second.admitted
    assert second.status == "denied"
    assert second.reason_code == "ADMISSION_DENIED"
    assert second.sub_reason == "ROUND_ALREADY_ADMITTED"
    assert second.admission is None
    assert second.event_type == "round_admission_denied"

    rows = _admissions(isolated_database, family_id, 2)
    assert len(rows) == 1
    assert rows[0][5] == contracts.envelope_digest(approved_envelope)

    events = _events(isolated_database, child_id)
    assert [event[0] for event in events] == [
        "round_admitted",
        "round_admission_denied",
    ]
    assert events[-1][1] == "ADMISSION_DENIED"
    assert events[-1][2]["sub_reason"] == "ROUND_ALREADY_ADMITTED"
    assert events[-1][2]["envelope_digest"] == contracts.envelope_digest(
        conflicting
    )


def _make_round_ready(database, family_id, child_id, *, mode, workflow_synced):
    database.connection.execute(
        "UPDATE jobs SET request = %s WHERE job_id = %s",
        (
            Jsonb({"schema_version": 2, "exploration": {"mode": mode}}),
            family_id,
        ),
    )
    database.connection.execute(
        "UPDATE jobs SET state = 'READY', stage = 'ready', request = %s, "
        "workflow_synced = %s, lease_owner = NULL, lease_expires_at = NULL "
        "WHERE job_id = %s",
        (
            Jsonb({"schema_version": 2, "limits": {"execute_seconds": 600}}),
            workflow_synced,
            child_id,
        ),
    )


def _job_state(database, job_id):
    return database.connection.execute(
        "SELECT state FROM jobs WHERE job_id = %s", (job_id,)
    ).fetchone()[0]


def _assert_round_not_startable(database, family_id, child_id, *, mode):
    # claim_next must not promote the READY+synced round to RUNNING.
    _make_round_ready(database, family_id, child_id, mode=mode, workflow_synced=True)
    assert (
        state.claim_next(database.dsn, "v2-worker", job_contract_version=2)
        is None
    ), "claim_next started a round without a policy admission"
    assert _job_state(database, child_id) == "READY"

    # begin_execution under a live sync claim must refuse as well.
    _make_round_ready(database, family_id, child_id, mode=mode, workflow_synced=False)
    claimed = state.claim_next(database.dsn, "v2-worker", job_contract_version=2)
    assert claimed is not None and claimed["job_id"] == child_id
    assert claimed["state"] == "READY"
    with pytest.raises(state.StateError, match="policy-admitted"):
        state.begin_execution(
            database.dsn, child_id, generation=claimed["generation"]
        )
    assert _job_state(database, child_id) == "READY"


@pytest.mark.parametrize(
    ("mode", "round_no"), [("guided", 1), ("guided", 2), ("fixed", 2)]
)
@pytest.mark.parametrize("entry", ["claim_next", "begin_execution"])
def test_non_first_round_requires_policy_admission_before_running(
    isolated_database, tmp_path, monkeypatch, mode, round_no, entry
):
    # S-1: a policy-admitted round may only start once its admissions row is
    # persisted; a missing or denied admission keeps it READY.
    monkeypatch.setenv("DATACON_EVIDENCE_ROOT", str(tmp_path / "evidence"))
    seed = _seed_family(isolated_database, round_no=round_no)
    family_id, child_id, _approved = seed

    _assert_round_not_startable(isolated_database, family_id, child_id, mode=mode)

    denied = _admit(
        isolated_database,
        seed,
        round_no=round_no,
        envelope=_envelope(max_rounds=7),
    )
    assert denied.status == "denied"
    assert _admissions(isolated_database, family_id, round_no) == []
    _assert_round_not_startable(isolated_database, family_id, child_id, mode=mode)

    admitted = _admit(isolated_database, seed, round_no=round_no)
    assert admitted.admitted
    assert len(_admissions(isolated_database, family_id, round_no)) == 1

    if entry == "claim_next":
        _make_round_ready(
            isolated_database, family_id, child_id, mode=mode, workflow_synced=True
        )
        claimed = state.claim_next(
            isolated_database.dsn, "v2-worker", job_contract_version=2
        )
        assert claimed is not None and claimed["job_id"] == child_id
        assert claimed["state"] == "RUNNING"
    else:
        _make_round_ready(
            isolated_database, family_id, child_id, mode=mode, workflow_synced=False
        )
        claimed = state.claim_next(
            isolated_database.dsn, "v2-worker", job_contract_version=2
        )
        assert claimed is not None and claimed["state"] == "READY"
        assert state.begin_execution(
            isolated_database.dsn, child_id, generation=claimed["generation"]
        )
    assert _job_state(isolated_database, child_id) == "RUNNING"


def test_fixed_first_round_runs_without_admission_row(
    isolated_database, tmp_path, monkeypatch
):
    # Compatibility: a fixed round 1 is human-approved and needs no
    # admissions row.
    monkeypatch.setenv("DATACON_EVIDENCE_ROOT", str(tmp_path / "evidence"))
    family_id, child_id, _ = _seed_family(isolated_database, round_no=1)
    _make_round_ready(
        isolated_database, family_id, child_id, mode="fixed", workflow_synced=False
    )
    claimed = state.claim_next(
        isolated_database.dsn, "v2-worker", job_contract_version=2
    )
    assert claimed is not None and claimed["state"] == "READY"
    assert state.begin_execution(
        isolated_database.dsn, child_id, generation=claimed["generation"]
    )
    assert _job_state(isolated_database, child_id) == "RUNNING"
    assert _admissions(isolated_database, family_id, 1) == []

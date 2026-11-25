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
    plan = {
        "schema_version": 2,
        "envelope_digest": plan_envelope_digest or envelope_digest,
        "parent_approval_digest": resolved_plan_parent,
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
    assert outcome.reason_code == "ADMISSION_DENIED"
    assert outcome.sub_reason == "ROUND_BEYOND_MAX_ROUNDS"
    assert outcome.admission is None
    assert _admissions(isolated_database, family_id, 9) == []

    events = _events(isolated_database, child_id)
    assert [event[0] for event in events] == ["round_admission_denied"]
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
    charge = state.charge_step_budget(
        isolated_database.dsn,
        family_id=family_id,
        job_id=child_id,
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
    charge = state.charge_step_budget(
        isolated_database.dsn,
        family_id=family_id,
        job_id=child_id,
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
    seed = _seed_family(isolated_database)
    family_id, child_id, _envelope_value = seed
    exp_a = _valid_experiment("length_boundary")
    exp_b = _valid_experiment("byte_flip")

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

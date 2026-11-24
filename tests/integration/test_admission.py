"""TC-12/T12 step 1.5: Postgres policy-admission persistence.

The contract predicate lives in ``state.policy_admit_round``. These coordinates
exercise the real transaction in which a policy round is admitted: one
``admissions`` row plus one ``round_admitted`` audit event, or a denied event
with no admission row. Same-input readmission is an idempotent no-op; a different
decision for the same ``(parent_job_id, round_no)`` is a real denial.
"""

from __future__ import annotations

from uuid import uuid4

import pytest
from psycopg.types.json import Jsonb

from datacon import contracts, state

pytestmark = pytest.mark.postgres


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


def _seed_family(database, *, max_rounds: int = 8):
    family_id = uuid4()
    child_id = uuid4()
    envelope = _envelope(max_rounds=max_rounds)
    envelope_digest = contracts.envelope_digest(envelope)

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
        "'round', %s, 2, 1)",
        (child_id, Jsonb({"schema_version": 2}), family_id, family_id),
    )
    database.connection.execute(
        "INSERT INTO family_approvals (approval_id, family_id, approval_digest, "
        "envelope_digest, first_plan_digest, reviewer_id, decided_at, supersedes) "
        "VALUES (%s, %s, %s, %s, %s, %s, clock_timestamp(), NULL)",
        (
            uuid4(),
            family_id,
            APPROVAL_DIGEST,
            envelope_digest,
            FIRST_PLAN_DIGEST,
            REVIEWER_ID,
        ),
    )
    return family_id, child_id, envelope


def _admit(
    database,
    seed,
    *,
    round_no: int = 2,
    seed_digest: str = SEED_CORPUS_DIGEST,
    experiment: dict | None = None,
    recomputable: bool = True,
    campaign_bundle_digest: str | None = None,
):
    family_id, child_id, envelope = seed
    return state.record_admission(
        database.dsn,
        family_id=family_id,
        job_id=child_id,
        round_no=round_no,
        envelope=envelope,
        seed_digest=seed_digest,
        budget_snapshot=BUDGET_SNAPSHOT,
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
    seed = _seed_family(isolated_database)
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

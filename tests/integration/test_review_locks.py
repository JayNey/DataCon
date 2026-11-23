"""D36/D42 T10: review state machine, lock order and envelope identity.

Each test seeds a v2 family together with its first child and first plan, then
drives ``state.record_review`` / ``state.expire_review`` directly. Seeding by
SQL keeps the assertions on the review contract instead of on the still
unimplemented submit/worker family creation path.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import threading
import time
from uuid import uuid4

import psycopg
import pytest
from psycopg.types.json import Jsonb

from datacon import jsonutil, state

pytestmark = pytest.mark.postgres

ENVELOPE_1 = "sha256:" + "1" * 64
ENVELOPE_2 = "sha256:" + "2" * 64
UNKNOWN_ENVELOPE = "sha256:" + "9" * 64
FIRST_PLAN_DIGEST = "sha256:" + "a" * 64
OTHER_PLAN_DIGEST = "sha256:" + "b" * 64
APPROVAL_1 = "sha256:" + "c" * 64
REVIEWER_1 = "reviewer-first"
REVIEWER_2 = "reviewer-second"
BUILD_SPEC = {
    "kind": "cmake",
    "configure": ["cmake", "-S", ".", "-B", "build"],
    "build": ["cmake", "--build", "build", "--target", "parser"],
    "install": [],
    "env": {"CC": "clang", "CFLAGS": "-g"},
    "outputs": ["build/parser"],
    "declared_compile_flags": ["-g"],
    "shell_recipe_digest": None,
    "shell_face_digest": None,
    "shell_face_review": None,
}


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _insert_job(
    database,
    job_id,
    *,
    state_name,
    stage,
    family_id,
    job_kind,
    parent_job_id,
    round_no,
    workflow_synced=False,
    generation=1,
    review_deadline_at=None,
    lease_owner=None,
    lease_expires_at=None,
    request=None,
):
    database.connection.execute(
        "INSERT INTO jobs (job_id, request, state, stage, submitted_at, "
        "job_contract_version, family_id, job_kind, parent_job_id, round_no, "
        "generation, workflow_synced, review_deadline_at, lease_owner, "
        "lease_expires_at) VALUES (%s, %s, %s, %s, clock_timestamp(), 2, "
        "%s, %s, %s, %s, %s, %s, %s, %s, %s)",
        (
            job_id,
            Jsonb(request if request is not None else {"schema_version": 2}),
            state_name,
            stage,
            family_id,
            job_kind,
            parent_job_id,
            round_no,
            generation,
            workflow_synced,
            review_deadline_at,
            lease_owner,
            lease_expires_at,
        ),
    )


def _insert_envelope(
    database,
    family_id,
    envelope_digest,
    *,
    status_name,
    review_deadline_at,
    reviewer_id=None,
    decided_at=None,
):
    database.connection.execute(
        "INSERT INTO family_envelopes (envelope_id, family_id, envelope_digest, "
        "envelope_json, status, review_deadline_at, reviewer_id, decided_at) "
        "VALUES (%s, %s, %s, %s, %s, %s, %s, %s)",
        (
            uuid4(),
            family_id,
            envelope_digest,
            Jsonb({"mode": "guided", "envelope_digest": envelope_digest}),
            status_name,
            review_deadline_at,
            reviewer_id,
            decided_at,
        ),
    )


def _family_request(mode):
    return {
        "schema_version": 2,
        "cve_id": "CVE-2099-0001",
        "target": {
            "kind": "source",
            "case_id": "fixture-c-parser",
            "goal": "review lock test",
        },
        "exploration": (
            {
                "mode": "guided",
                "allowed_mutation_families": ["byte_flip", "length_boundary"],
                "max_rounds": 8,
                "max_total_seconds": 900,
                "max_fuzz_seconds": 300,
            }
            if mode == "guided"
            else {
                "mode": "fixed",
                "allowed_mutation_families": [],
                "max_rounds": 1,
                "max_total_seconds": 900,
                "max_fuzz_seconds": 0,
            }
        ),
    }


def _seed_family(
    database,
    *,
    mode="guided",
    review_deadline_at=None,
    lease=False,
    first_approval=False,
    pending_envelope=ENVELOPE_1,
    child_state=None,
):
    family_id = uuid4()
    child_id = uuid4()
    round_no = None if mode == "guided" else 1
    job_kind = "campaign" if mode == "guided" else "round"
    deadline = review_deadline_at or (_now() + timedelta(hours=24))
    if child_state is None:
        child_state = "READY" if first_approval else "AWAITING_REVIEW"

    _insert_job(
        database,
        family_id,
        state_name="AGGREGATING",
        stage="family",
        family_id=family_id,
        job_kind="family",
        parent_job_id=None,
        round_no=None,
        workflow_synced=True,
        request=_family_request(mode),
    )
    _insert_job(
        database,
        child_id,
        state_name=child_state,
        stage="review",
        family_id=family_id,
        job_kind=job_kind,
        parent_job_id=family_id,
        round_no=round_no,
        workflow_synced=False,
        generation=1,
        review_deadline_at=deadline,
        lease_owner="worker-p1" if lease else None,
        lease_expires_at=(_now() + timedelta(minutes=10)) if lease else None,
    )
    database.connection.execute(
        "INSERT INTO plans (plan_id, job_id, plan_digest, plan, summary) "
        "VALUES (%s, %s, %s, %s, %s)",
        (
            uuid4(),
            child_id,
            FIRST_PLAN_DIGEST,
            Jsonb(
                {
                    "schema_version": 2,
                    "family_id": str(family_id),
                    "parent_job_id": str(family_id),
                    "round_no": round_no,
                    "parent_approval_digest": APPROVAL_1 if first_approval else None,
                    "envelope_digest": ENVELOPE_1,
                    "build_ref": None,
                    "build_spec": BUILD_SPEC,
                    "compile_flags": ["-g"],
                    "experiment_digest": None,
                    "build_provenance_rules_version": "build-provenance-v1",
                    "inputs": (
                        None
                        if round_no is None
                        else {
                            "normal": "sha256:" + "1" * 64,
                            "candidate": "sha256:" + "2" * 64,
                        }
                    ),
                }
            ),
            Jsonb({}),
        ),
    )

    first_approval_id = None
    if first_approval:
        decided_at = _now()
        _insert_envelope(
            database,
            family_id,
            ENVELOPE_1,
            status_name="approved",
            review_deadline_at=deadline,
            reviewer_id=REVIEWER_1,
            decided_at=decided_at,
        )
        database.connection.execute(
            "INSERT INTO reviews (review_id, job_id, plan_digest, reviewer_id, "
            "decision, review_deadline_at, decided_at) "
            "VALUES (%s, %s, %s, %s, 'approve', %s, %s)",
            (uuid4(), family_id, FIRST_PLAN_DIGEST, REVIEWER_1, deadline, decided_at),
        )
        first_approval_id = uuid4()
        database.connection.execute(
            "INSERT INTO family_approvals (approval_id, family_id, "
            "approval_digest, envelope_digest, first_plan_digest, reviewer_id, "
            "decided_at, supersedes) VALUES (%s, %s, %s, %s, %s, %s, %s, NULL)",
            (
                first_approval_id,
                family_id,
                APPROVAL_1,
                ENVELOPE_1,
                FIRST_PLAN_DIGEST,
                REVIEWER_1,
                decided_at,
            ),
        )
        if pending_envelope is not None:
            _insert_envelope(
                database,
                family_id,
                pending_envelope,
                status_name="pending",
                review_deadline_at=deadline,
            )
    elif pending_envelope is not None:
        _insert_envelope(
            database,
            family_id,
            pending_envelope,
            status_name="pending",
            review_deadline_at=deadline,
        )

    return {
        "family_id": family_id,
        "child_id": child_id,
        "first_approval_id": first_approval_id,
        "deadline": deadline,
    }


def _review(database, seed, *, envelope_digest=ENVELOPE_1, plan_digest=FIRST_PLAN_DIGEST, decision="approve", reviewer_id=REVIEWER_2):
    kwargs = {
        "plan_digest": plan_digest,
        "decision": decision,
        "reviewer_id": reviewer_id,
    }
    if envelope_digest is not None:
        kwargs["envelope_digest"] = envelope_digest
    return state.record_review(database.dsn, seed["family_id"], **kwargs)


def _row(database, query, params=()):
    return database.connection.execute(query, params).fetchone()


def _run_in_thread(call):
    result = {}
    errors = []

    def runner():
        try:
            result["value"] = call()
        except BaseException as error:  # noqa: BLE001 - re-raised by the caller
            errors.append(error)

    thread = threading.Thread(target=runner, daemon=True)
    thread.start()
    return thread, result, errors


def _join(thread, result, errors):
    thread.join(timeout=30)
    assert not thread.is_alive(), "the review thread did not finish"
    if errors:
        raise errors[0]
    return result.get("value")


def _family_lock_is_held(database, family_id, timeout=10.0):
    """Return whether another transaction holds the family row lock."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        with psycopg.connect(database.dsn, autocommit=True, connect_timeout=5) as probe:
            try:
                probe.execute(
                    "SELECT job_id FROM jobs WHERE job_id = %s FOR UPDATE NOWAIT",
                    (family_id,),
                )
            except psycopg.errors.LockNotAvailable:
                return True
        time.sleep(0.02)
    return False


def test_review_locks_family_then_first_child(isolated_database, tmp_path, monkeypatch):
    monkeypatch.setenv("DATACON_EVIDENCE_ROOT", str(tmp_path / "evidence"))
    seed = _seed_family(isolated_database)

    holder = psycopg.connect(isolated_database.dsn, connect_timeout=5)
    try:
        holder.execute(
            "SELECT job_id FROM jobs WHERE job_id = %s FOR UPDATE",
            (seed["child_id"],),
        )
        thread, result, errors = _run_in_thread(lambda: _review(isolated_database, seed))
        assert _family_lock_is_held(isolated_database, seed["family_id"]), (
            "review locked the child before the family"
        )
    finally:
        holder.commit()
        holder.close()

    outcome = _join(thread, result, errors)
    assert outcome.status == "applied"
    review = _row(
        isolated_database,
        "SELECT job_id FROM reviews WHERE job_id = %s",
        (seed["family_id"],),
    )
    assert review is not None, "review was written against the child job"
    assert _row(
        isolated_database,
        "SELECT count(*) FROM reviews WHERE job_id = %s",
        (seed["child_id"],),
    )[0] == 0
    assert _row(
        isolated_database,
        "SELECT state FROM jobs WHERE job_id = %s",
        (seed["family_id"],),
    )[0] == "AGGREGATING"


def test_review_expiry_converges_family_and_child(
    isolated_database, tmp_path, monkeypatch
):
    monkeypatch.setenv("DATACON_EVIDENCE_ROOT", str(tmp_path / "evidence"))
    seed = _seed_family(
        isolated_database,
        review_deadline_at=_now() - timedelta(minutes=1),
        lease=True,
    )

    assert state.expire_review(isolated_database.dsn, seed["child_id"], 1) is True

    child_state, child_reason = _row(
        isolated_database,
        "SELECT state, reason_code FROM jobs WHERE job_id = %s",
        (seed["child_id"],),
    )
    family_state, family_reason = _row(
        isolated_database,
        "SELECT state, reason_code FROM jobs WHERE job_id = %s",
        (seed["family_id"],),
    )
    assert (child_state, child_reason) == ("BLOCKED", "REVIEW_EXPIRED")
    assert (family_state, family_reason) == ("BLOCKED", "REVIEW_EXPIRED"), (
        "family stayed AGGREGATING after review expiry"
    )
    assert _row(
        isolated_database,
        "SELECT count(*) FROM reviews WHERE job_id = %s",
        (seed["family_id"],),
    )[0] == 0
    assert _row(
        isolated_database,
        "SELECT detail FROM audit_events WHERE job_id = %s "
        "AND event_type = 'review_expired' ORDER BY event_id DESC LIMIT 1",
        (seed["family_id"],),
    ) is not None


def test_envelope_reapproval_only_appends_family_approvals(isolated_database):
    seed = _seed_family(
        isolated_database,
        first_approval=True,
        pending_envelope=ENVELOPE_2,
    )

    outcome = _review(isolated_database, seed, envelope_digest=ENVELOPE_2)
    assert outcome.status == "applied"

    approvals = isolated_database.connection.execute(
        "SELECT approval_id, envelope_digest, supersedes, first_plan_digest "
        "FROM family_approvals WHERE family_id = %s ORDER BY decided_at, approval_id",
        (seed["family_id"],),
    ).fetchall()
    assert len(approvals) == 2, "re-approval did not append a family_approvals row"
    _approval_id, envelope_digest, supersedes, first_plan_digest = approvals[-1]
    assert supersedes == seed["first_approval_id"], (
        "supersedes does not point at the previous approval"
    )
    assert envelope_digest == ENVELOPE_2
    assert first_plan_digest == FIRST_PLAN_DIGEST

    review_rows = isolated_database.connection.execute(
        "SELECT reviewer_id, plan_digest FROM reviews WHERE job_id = %s",
        (seed["family_id"],),
    ).fetchall()
    assert len(review_rows) == 1, "re-approval rewrote the reviews row"
    assert review_rows[0][0] == REVIEWER_1
    assert _row(
        isolated_database,
        "SELECT status FROM family_envelopes "
        "WHERE family_id = %s AND envelope_digest = %s",
        (seed["family_id"], ENVELOPE_2),
    )[0] == "approved"


def test_review_rejects_mismatched_first_plan_digest(isolated_database):
    seed = _seed_family(isolated_database)

    outcome = _review(isolated_database, seed, plan_digest=OTHER_PLAN_DIGEST)
    assert outcome.status != "applied", "mismatched first plan digest was accepted"
    assert _row(
        isolated_database,
        "SELECT count(*) FROM reviews WHERE job_id = %s",
        (seed["family_id"],),
    )[0] == 0
    assert _row(
        isolated_database,
        "SELECT count(*) FROM family_approvals WHERE family_id = %s",
        (seed["family_id"],),
    )[0] == 0
    assert _row(
        isolated_database,
        "SELECT state FROM jobs WHERE job_id = %s",
        (seed["child_id"],),
    )[0] == "AWAITING_REVIEW"
    assert _row(
        isolated_database,
        "SELECT state FROM jobs WHERE job_id = %s",
        (seed["family_id"],),
    )[0] == "AGGREGATING"


def test_review_requires_envelope_digest_for_reapproval(isolated_database):
    first = _seed_family(isolated_database)
    first_outcome = _review(isolated_database, first, envelope_digest=None)
    assert first_outcome.status == "applied", (
        "first human approval could not resolve the plan's envelope digest"
    )
    assert _row(
        isolated_database,
        "SELECT envelope_digest FROM family_approvals WHERE family_id = %s",
        (first["family_id"],),
    )[0] == ENVELOPE_1, "omitted --envelope-digest did not resolve to the plan"

    reapproval = _seed_family(
        isolated_database,
        first_approval=True,
        pending_envelope=ENVELOPE_2,
    )
    try:
        outcome = _review(isolated_database, reapproval, envelope_digest=None)
    except state.StateError:
        outcome = None
    assert outcome is None or outcome.status != "applied", (
        "re-approval without --envelope-digest was accepted"
    )
    assert _row(
        isolated_database,
        "SELECT count(*) FROM family_approvals WHERE family_id = %s",
        (reapproval["family_id"],),
    )[0] == 1
    assert _row(
        isolated_database,
        "SELECT count(*) FROM reviews WHERE job_id = %s",
        (reapproval["family_id"],),
    )[0] == 1


def test_review_envelope_digest_must_match_pending(isolated_database):
    seed = _seed_family(
        isolated_database,
        first_approval=True,
        pending_envelope=ENVELOPE_2,
    )

    outcome = _review(isolated_database, seed, envelope_digest=UNKNOWN_ENVELOPE)
    assert outcome.reason_code == "REVIEW_ENVELOPE_MISMATCH", (
        "non-pending envelope digest was accepted: " + outcome.reason_code
    )
    assert _row(
        isolated_database,
        "SELECT count(*) FROM reviews WHERE job_id = %s",
        (seed["family_id"],),
    )[0] == 1
    assert _row(
        isolated_database,
        "SELECT count(*) FROM family_approvals WHERE family_id = %s",
        (seed["family_id"],),
    )[0] == 1
    assert _row(
        isolated_database,
        "SELECT status FROM family_envelopes "
        "WHERE family_id = %s AND envelope_digest = %s",
        (seed["family_id"], ENVELOPE_2),
    )[0] == "pending"
    assert _row(
        isolated_database,
        "SELECT state FROM jobs WHERE job_id = %s",
        (seed["family_id"],),
    )[0] == "AGGREGATING"


def test_review_reject_marks_pending_envelope_rejected(
    isolated_database, tmp_path, monkeypatch
):
    monkeypatch.setenv("DATACON_EVIDENCE_ROOT", str(tmp_path / "evidence"))
    seed = _seed_family(isolated_database)

    outcome = _review(isolated_database, seed, decision="reject")
    assert outcome.status == "applied"
    assert _row(
        isolated_database,
        "SELECT status FROM family_envelopes WHERE family_id = %s",
        (seed["family_id"],),
    )[0] == "rejected", "pending envelope stayed pending after reject"
    child_state, child_reason = _row(
        isolated_database,
        "SELECT state, reason_code FROM jobs WHERE job_id = %s",
        (seed["child_id"],),
    )
    family_state, family_reason = _row(
        isolated_database,
        "SELECT state, reason_code FROM jobs WHERE job_id = %s",
        (seed["family_id"],),
    )
    assert (child_state, child_reason) == ("BLOCKED", "REVIEW_REJECTED")
    assert (family_state, family_reason) == ("BLOCKED", "REVIEW_REJECTED")
    assert _row(
        isolated_database,
        "SELECT count(*) FROM family_approvals WHERE family_id = %s",
        (seed["family_id"],),
    )[0] == 0

    expired_seed = _seed_family(
        isolated_database,
        review_deadline_at=_now() - timedelta(minutes=1),
    )
    expired = _review(isolated_database, expired_seed, decision="approve")
    assert expired.status == "expired"
    assert _row(
        isolated_database,
        "SELECT status FROM family_envelopes WHERE family_id = %s",
        (expired_seed["family_id"],),
    )[0] == "expired", "timed-out envelope stayed pending"
    assert _row(
        isolated_database,
        "SELECT state, reason_code FROM jobs WHERE job_id = %s",
        (expired_seed["family_id"],),
    ) == ("BLOCKED", "REVIEW_EXPIRED")


def test_review_idempotency_key_includes_envelope_digest(isolated_database):
    seed = _seed_family(
        isolated_database,
        first_approval=True,
        pending_envelope=ENVELOPE_2,
    )

    applied = _review(isolated_database, seed, envelope_digest=ENVELOPE_2)
    assert applied.status == "applied"
    again = _review(isolated_database, seed, envelope_digest=ENVELOPE_2)
    assert again.status == "idempotent"
    assert _row(
        isolated_database,
        "SELECT count(*) FROM family_approvals WHERE family_id = %s",
        (seed["family_id"],),
    )[0] == 2

    conflicting = _review(
        isolated_database, seed, envelope_digest=ENVELOPE_2, decision="reject"
    )
    assert conflicting.status == "conflict"
    assert _row(
        isolated_database,
        "SELECT count(*) FROM family_approvals WHERE family_id = %s",
        (seed["family_id"],),
    )[0] == 2

    same_reviewer = _review(
        isolated_database,
        seed,
        envelope_digest=ENVELOPE_1,
        reviewer_id=REVIEWER_1,
    )
    assert same_reviewer.status == "idempotent", (
        "reapproval with a new envelope was treated as idempotent"
    )
    other_reviewer = _review(
        isolated_database,
        seed,
        envelope_digest=ENVELOPE_1,
        reviewer_id="reviewer-third",
    )
    assert other_reviewer.status == "conflict"
    assert _row(
        isolated_database,
        "SELECT count(*) FROM family_approvals WHERE family_id = %s",
        (seed["family_id"],),
    )[0] == 2
    assert _row(
        isolated_database,
        "SELECT count(*) FROM reviews WHERE job_id = %s",
        (seed["family_id"],),
    )[0] == 1


def test_family_approval_digest_uses_microsecond_timestamp(isolated_database):
    seed = _seed_family(isolated_database)
    outcome = _review(isolated_database, seed)
    assert outcome.status == "applied"

    approval_digest, decided_at = _row(
        isolated_database,
        "SELECT approval_digest, decided_at FROM family_approvals "
        "WHERE family_id = %s",
        (seed["family_id"],),
    )
    material = {
        "family_id": str(seed["family_id"]),
        "first_plan_digest": FIRST_PLAN_DIGEST,
        "envelope_digest": ENVELOPE_1,
        "reviewer_id": REVIEWER_2,
        "decided_at": jsonutil.approval_timestamp(decided_at),
    }
    assert jsonutil.digest_json(material) == approval_digest, (
        "approval_digest does not use the persisted microsecond decided_at"
    )
    assert material["decided_at"].endswith("Z")
    assert len(material["decided_at"].split(".")[-1]) == 7
    seconds_material = dict(material)
    seconds_material["decided_at"] = jsonutil.timestamp(decided_at)
    if decided_at.microsecond:
        assert jsonutil.digest_json(seconds_material) != approval_digest, (
            "approval_digest truncated decided_at to seconds"
        )


def test_approval_timestamp_always_renders_six_digits():
    from datetime import datetime, timezone

    value = datetime(2099, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
    assert jsonutil.approval_timestamp(value) == "2099-01-01T00:00:00.000000Z"
    value = datetime(2099, 1, 1, 0, 0, 0, 123456, tzinfo=timezone.utc)
    assert jsonutil.approval_timestamp(value) == "2099-01-01T00:00:00.123456Z"


def test_expire_review_locks_family_then_first_child(
    isolated_database, tmp_path, monkeypatch
):
    monkeypatch.setenv("DATACON_EVIDENCE_ROOT", str(tmp_path / "evidence"))
    seed = _seed_family(
        isolated_database,
        review_deadline_at=_now() - timedelta(minutes=1),
        lease=True,
    )

    holder = psycopg.connect(isolated_database.dsn, connect_timeout=5)
    try:
        holder.execute("SET LOCAL lock_timeout = '10s'")
        holder.execute(
            "SELECT job_id FROM jobs WHERE job_id = %s FOR UPDATE",
            (seed["child_id"],),
        )
        thread, result, errors = _run_in_thread(
            lambda: state.expire_review(isolated_database.dsn, seed["child_id"], 1)
        )
        assert _family_lock_is_held(isolated_database, seed["family_id"]), (
            "expire_review locked the child before the family"
        )
    finally:
        holder.commit()
        holder.close()

    assert _join(thread, result, errors) is True
    child_state = _row(
        isolated_database,
        "SELECT state FROM jobs WHERE job_id = %s",
        (seed["child_id"],),
    )[0]
    family_state = _row(
        isolated_database,
        "SELECT state FROM jobs WHERE job_id = %s",
        (seed["family_id"],),
    )[0]
    assert child_state == "BLOCKED"
    assert family_state == "BLOCKED"


def test_review_first_reject_archives_blocked_bundles(
    isolated_database, tmp_path, monkeypatch
):
    monkeypatch.setenv("DATACON_EVIDENCE_ROOT", str(tmp_path / "evidence"))
    seed = _seed_family(isolated_database)

    outcome = _review(isolated_database, seed, decision="reject")
    assert outcome.status == "applied"

    for job_id in (seed["family_id"], seed["child_id"]):
        status, path, digest = _row(
            isolated_database,
            "SELECT evidence_status, evidence_path, evidence_digest "
            "FROM jobs WHERE job_id = %s",
            (job_id,),
        )
        assert status == "archived", "v2 reject left the BLOCKED row unarchived"
        assert path and digest
    assert _row(
        isolated_database,
        "SELECT count(*) FROM reviews WHERE job_id = %s",
        (seed["family_id"],),
    )[0] == 1


def test_review_first_timeout_archives_blocked_bundles(
    isolated_database, tmp_path, monkeypatch
):
    monkeypatch.setenv("DATACON_EVIDENCE_ROOT", str(tmp_path / "evidence"))
    seed = _seed_family(
        isolated_database,
        review_deadline_at=_now() - timedelta(minutes=1),
        lease=False,
    )

    outcome = _review(isolated_database, seed, decision="approve")
    assert outcome.status == "expired"

    for job_id in (seed["family_id"], seed["child_id"]):
        status, path, digest = _row(
            isolated_database,
            "SELECT evidence_status, evidence_path, evidence_digest "
            "FROM jobs WHERE job_id = %s",
            (job_id,),
        )
        assert status == "archived", "v2 timeout left the BLOCKED row unarchived"
        assert path and digest


def test_envelope_reapproval_reject_leaves_child_ready(
    isolated_database, tmp_path, monkeypatch
):
    monkeypatch.setenv("DATACON_EVIDENCE_ROOT", str(tmp_path / "evidence"))
    seed = _seed_family(
        isolated_database,
        first_approval=True,
        pending_envelope=ENVELOPE_2,
    )
    before = _row(
        isolated_database,
        "SELECT state, generation FROM jobs WHERE job_id = %s",
        (seed["child_id"],),
    )

    outcome = _review(
        isolated_database, seed, envelope_digest=ENVELOPE_2, decision="reject"
    )
    assert outcome.status == "applied"

    child = _row(
        isolated_database,
        "SELECT state, generation FROM jobs WHERE job_id = %s",
        (seed["child_id"],),
    )
    assert child == before, "re-approval reject changed the already-approved child"
    family = _row(
        isolated_database,
        "SELECT state, reason_code, evidence_status FROM jobs WHERE job_id = %s",
        (seed["family_id"],),
    )
    assert family == ("BLOCKED", "REVIEW_REJECTED", "archived")
    assert _row(
        isolated_database,
        "SELECT count(*) FROM reviews WHERE job_id = %s",
        (seed["family_id"],),
    )[0] == 1
    assert _row(
        isolated_database,
        "SELECT count(*) FROM family_approvals WHERE family_id = %s",
        (seed["family_id"],),
    )[0] == 1


def test_expire_pending_envelopes_skips_first_round(
    isolated_database, tmp_path, monkeypatch
):
    monkeypatch.setenv("DATACON_EVIDENCE_ROOT", str(tmp_path / "evidence"))
    past = _now() - timedelta(minutes=1)
    seed = _seed_family(
        isolated_database,
        review_deadline_at=past,
        lease=True,
    )
    isolated_database.connection.execute(
        "UPDATE family_envelopes SET review_deadline_at = %s WHERE family_id = %s",
        (past, seed["family_id"]),
    )

    assert state.expire_pending_envelopes(isolated_database.dsn) == 0
    assert _row(
        isolated_database,
        "SELECT status FROM family_envelopes WHERE family_id = %s",
        (seed["family_id"],),
    )[0] == "pending", "the sweep stole the first-round review"
    assert _row(
        isolated_database,
        "SELECT state FROM jobs WHERE job_id = %s",
        (seed["child_id"],),
    )[0] == "AWAITING_REVIEW"

    assert state.expire_review(isolated_database.dsn, seed["child_id"], 1) is True
    assert _row(
        isolated_database,
        "SELECT state FROM jobs WHERE job_id = %s",
        (seed["family_id"],),
    )[0] == "BLOCKED"


def test_expire_pending_envelopes_still_expires_reapproval(
    isolated_database, tmp_path, monkeypatch
):
    monkeypatch.setenv("DATACON_EVIDENCE_ROOT", str(tmp_path / "evidence"))
    past = _now() - timedelta(minutes=1)
    seed = _seed_family(
        isolated_database,
        first_approval=True,
        pending_envelope=ENVELOPE_2,
    )
    isolated_database.connection.execute(
        "UPDATE family_envelopes SET review_deadline_at = %s "
        "WHERE family_id = %s AND status = 'pending'",
        (past, seed["family_id"]),
    )

    assert state.expire_pending_envelopes(isolated_database.dsn) == 1
    assert _row(
        isolated_database,
        "SELECT state, reason_code FROM jobs WHERE job_id = %s",
        (seed["family_id"],),
    ) == ("BLOCKED", "REVIEW_EXPIRED")


GUIDED_ENVELOPE_BODY = {
    "mode": "guided",
    "allowed_mutation_families": ["byte_flip"],
    "mutation_limits": {"allowed_ops": ["append"], "max_input_bytes": 64},
    "seed_corpus_digest": "sha256:" + "a" * 64,
    "fuzz_image_digest": "sha256:" + "b" * 64,
    "harness_digest": "sha256:" + "c" * 64,
    "max_rounds": 2,
    "max_total_seconds": 100,
    "max_fuzz_seconds": 10,
    "accepted_signature_set": [
        {
            "error": "heap-buffer-overflow",
            "function": "parse_token",
            "source": "parser.c",
            "operation": "WRITE",
            "access_size": 1,
        }
    ],
    "admission_predicate_version": "admission-v1",
}


def _insert_plain_job(database, job_id, *, request, state_name, family_id=None,
                      job_kind="family", parent_job_id=None, round_no=None,
                      generation=1, lease=False, review_deadline_at=None,
                      submitted_at=None):
    database.connection.execute(
        "INSERT INTO jobs (job_id, request, state, stage, submitted_at, "
        "job_contract_version, family_id, job_kind, parent_job_id, round_no, "
        "generation, workflow_synced, lease_owner, lease_expires_at, "
        "review_deadline_at) VALUES (%s, %s, %s, 'review', %s, 2, %s, %s, "
        "%s, %s, %s, false, %s, %s, %s)",
        (
            job_id,
            Jsonb(request),
            state_name,
            submitted_at or _now(),
            family_id,
            job_kind,
            parent_job_id,
            round_no,
            generation,
            "worker-p1" if lease else None,
            (_now() + timedelta(minutes=10)) if lease else None,
            review_deadline_at,
        ),
    )


def _insert_plan(database, child_id, plan_digest, envelope_digest, round_no):
    plan = {
        "schema_version": 2,
        "family_id": None,
        "parent_job_id": None,
        "round_no": round_no,
        "parent_approval_digest": None,
        "envelope_digest": envelope_digest,
        "build_ref": None,
        "build_spec": BUILD_SPEC,
        "compile_flags": ["-g"],
        "experiment_digest": None,
        "inputs": None if round_no is None else {
            "normal": "sha256:" + "1" * 64,
            "candidate": "sha256:" + "2" * 64,
        },
        "build_provenance_rules_version": "build-provenance-v1",
    }
    database.connection.execute(
        "INSERT INTO plans (plan_id, job_id, plan_digest, plan, summary) "
        "VALUES (%s, %s, %s, %s, %s)",
        (uuid4(), child_id, plan_digest, Jsonb(plan), Jsonb({})),
    )


def test_first_plan_freeze_inserts_pending_envelope_end_to_end(
    isolated_database, tmp_path, monkeypatch
):
    monkeypatch.setenv("DATACON_EVIDENCE_ROOT", str(tmp_path / "evidence"))
    family_id = uuid4()
    _insert_plain_job(
        isolated_database,
        family_id,
        request=_family_request("guided"),
        state_name="AGGREGATING",
        family_id=family_id,
        job_kind="family",
        parent_job_id=None,
    )
    child_id = uuid4()
    _insert_plain_job(
        isolated_database,
        child_id,
        request=_family_request("guided"),
        state_name="PREPARING",
        family_id=family_id,
        job_kind="campaign",
        parent_job_id=family_id,
        round_no=None,
        lease=True,
    )
    body = dict(GUIDED_ENVELOPE_BODY)
    digest = jsonutil.digest_json(body)
    plan = {
        "schema_version": 2,
        "family_id": str(family_id),
        "parent_job_id": str(family_id),
        "round_no": None,
        "parent_approval_digest": None,
        "envelope_digest": digest,
        "build_ref": None,
        "build_spec": BUILD_SPEC,
        "compile_flags": ["-g"],
        "experiment_digest": None,
        "inputs": None,
    }
    plan_digest = "sha256:" + "d" * 64

    with pytest.raises(state.StateError):
        state.propose_envelope(
            isolated_database.dsn, family_id, dict(body)
        ), "propose-envelope accepted before the first approval"

    assert state.freeze_plan(
        isolated_database.dsn,
        child_id,
        generation=1,
        plan=plan,
        plan_digest=plan_digest,
        summary={},
        envelope=body,
    )
    envelope = _row(
        isolated_database,
        "SELECT envelope_digest, envelope_json, status, review_deadline_at "
        "FROM family_envelopes WHERE family_id = %s",
        (family_id,),
    )
    envelope_digest, envelope_json, envelope_status, envelope_deadline = envelope
    assert envelope_digest == digest
    assert envelope_json == body
    assert envelope_status == "pending"
    child_deadline = _row(
        isolated_database,
        "SELECT review_deadline_at FROM jobs WHERE job_id = %s",
        (child_id,),
    )[0]
    assert envelope_deadline == child_deadline

    outcome = state.record_review(
        isolated_database.dsn,
        family_id,
        plan_digest=plan_digest,
        decision="approve",
        reviewer_id="reviewer-e2e",
    )
    assert outcome.status == "applied"
    assert _row(
        isolated_database,
        "SELECT state FROM jobs WHERE job_id = %s",
        (child_id,),
    )[0] == "READY"
    assert _row(
        isolated_database,
        "SELECT count(*) FROM family_approvals WHERE family_id = %s",
        (family_id,),
    )[0] == 1

    # A first plan without its envelope body fails closed and writes nothing.
    family_2 = uuid4()
    _insert_plain_job(
        isolated_database,
        family_2,
        request=_family_request("guided"),
        state_name="AGGREGATING",
        family_id=family_2,
        job_kind="family",
    )
    child_2 = uuid4()
    _insert_plain_job(
        isolated_database,
        child_2,
        request=_family_request("guided"),
        state_name="PREPARING",
        family_id=family_2,
        job_kind="campaign",
        parent_job_id=family_2,
        round_no=None,
        lease=True,
    )
    with pytest.raises(state.StateError):
        state.freeze_plan(
            isolated_database.dsn,
            child_2,
            generation=1,
            plan=plan | {"envelope_digest": digest},
            plan_digest="sha256:" + "e" * 64,
            summary={},
        )
    assert _row(
        isolated_database,
        "SELECT count(*) FROM plans WHERE job_id = %s",
        (child_2,),
    )[0] == 0
    assert _row(
        isolated_database,
        "SELECT count(*) FROM family_envelopes WHERE family_id = %s",
        (family_2,),
    )[0] == 0


def test_fixed_first_child_is_round_one_even_when_round_two_is_earlier(
    isolated_database,
):
    family_id = uuid4()
    _insert_plain_job(
        isolated_database,
        family_id,
        request=_family_request("fixed"),
        state_name="AGGREGATING",
        family_id=family_id,
        job_kind="family",
    )
    round_two = uuid4()
    round_one = uuid4()
    _insert_plain_job(
        isolated_database,
        round_two,
        request=_family_request("fixed"),
        state_name="READY",
        family_id=family_id,
        job_kind="round",
        parent_job_id=family_id,
        round_no=2,
        submitted_at=_now() - timedelta(hours=1),
    )
    _insert_plain_job(
        isolated_database,
        round_one,
        request=_family_request("fixed"),
        state_name="AWAITING_REVIEW",
        family_id=family_id,
        job_kind="round",
        parent_job_id=family_id,
        round_no=1,
        review_deadline_at=_now() + timedelta(hours=1),
    )
    _insert_plan(isolated_database, round_two, "sha256:" + "2" * 64, ENVELOPE_1, 2)
    _insert_plan(isolated_database, round_one, "sha256:" + "1" * 64, ENVELOPE_1, 1)
    _insert_envelope(
        isolated_database,
        family_id,
        ENVELOPE_1,
        status_name="pending",
        review_deadline_at=_now() + timedelta(hours=1),
    )

    outcome = _review(
        isolated_database,
        {"family_id": family_id, "child_id": round_one},
        plan_digest="sha256:" + "1" * 64,
        envelope_digest=ENVELOPE_1,
    )
    assert outcome.status == "applied", "fixed review did not use round 1"
    assert _row(
        isolated_database,
        "SELECT state FROM jobs WHERE job_id = %s",
        (round_one,),
    )[0] == "READY"
    assert _row(
        isolated_database,
        "SELECT state FROM jobs WHERE job_id = %s",
        (round_two,),
    )[0] == "READY"


def test_guided_first_child_is_campaign_even_when_a_round_is_earlier(
    isolated_database,
):
    family_id = uuid4()
    _insert_plain_job(
        isolated_database,
        family_id,
        request=_family_request("guided"),
        state_name="AGGREGATING",
        family_id=family_id,
        job_kind="family",
    )
    round_one = uuid4()
    campaign = uuid4()
    _insert_plain_job(
        isolated_database,
        round_one,
        request=_family_request("guided"),
        state_name="READY",
        family_id=family_id,
        job_kind="round",
        parent_job_id=family_id,
        round_no=1,
        submitted_at=_now() - timedelta(hours=1),
    )
    _insert_plain_job(
        isolated_database,
        campaign,
        request=_family_request("guided"),
        state_name="AWAITING_REVIEW",
        family_id=family_id,
        job_kind="campaign",
        parent_job_id=family_id,
        round_no=None,
        review_deadline_at=_now() + timedelta(hours=1),
    )
    _insert_plan(isolated_database, round_one, "sha256:" + "6" * 64, ENVELOPE_1, 1)
    _insert_plan(isolated_database, campaign, "sha256:" + "7" * 64, ENVELOPE_1, None)
    _insert_envelope(
        isolated_database,
        family_id,
        ENVELOPE_1,
        status_name="pending",
        review_deadline_at=_now() + timedelta(hours=1),
    )

    outcome = _review(
        isolated_database,
        {"family_id": family_id, "child_id": campaign},
        plan_digest="sha256:" + "7" * 64,
        envelope_digest=ENVELOPE_1,
    )
    assert outcome.status == "applied", "guided review did not use the campaign"
    assert _row(
        isolated_database,
        "SELECT state FROM jobs WHERE job_id = %s",
        (campaign,),
    )[0] == "READY"


def test_envelope_reapproval_timeout_leaves_child_ready(
    isolated_database, tmp_path, monkeypatch
):
    monkeypatch.setenv("DATACON_EVIDENCE_ROOT", str(tmp_path / "evidence"))
    seed = _seed_family(
        isolated_database,
        first_approval=True,
        pending_envelope=ENVELOPE_2,
    )
    before = _row(
        isolated_database,
        "SELECT state, generation FROM jobs WHERE job_id = %s",
        (seed["child_id"],),
    )
    isolated_database.connection.execute(
        "UPDATE family_envelopes SET review_deadline_at = %s "
        "WHERE family_id = %s AND status = 'pending'",
        (_now() - timedelta(minutes=1), seed["family_id"]),
    )

    outcome = _review(
        isolated_database,
        seed,
        envelope_digest=ENVELOPE_2,
        decision="approve",
    )
    assert outcome.status == "expired"
    assert _row(
        isolated_database,
        "SELECT state, generation FROM jobs WHERE job_id = %s",
        (seed["child_id"],),
    ) == before, "changed-envelope timeout changed the approved child"
    assert _row(
        isolated_database,
        "SELECT state, evidence_status FROM jobs WHERE job_id = %s",
        (seed["family_id"],),
    ) == ("BLOCKED", "archived")

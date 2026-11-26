"""D36/D42 T10: review state machine, lock order and envelope identity.

Each test seeds a v2 family together with its first child and first plan, then
drives ``state.record_review`` / ``state.expire_review`` directly. Seeding by
SQL keeps the assertions on the review contract instead of on the still
unimplemented submit/worker family creation path.
"""

from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import threading
import time
from uuid import uuid4

import psycopg
import pytest
from psycopg.types.json import Jsonb

from datacon import contracts, evidence, execution, jsonutil, state

pytestmark = pytest.mark.postgres

ENVELOPE_1 = "sha256:" + "1" * 64
ENVELOPE_2 = "sha256:" + "2" * 64
UNKNOWN_ENVELOPE = "sha256:" + "9" * 64
# The seeded first plan and every stored envelope body share this harness so a
# review can prove the frozen plan's harness is the approved one.
ENVELOPE_HARNESS = "sha256:" + "c" * 64
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
    max_total_seconds=900,
    max_fuzz_seconds=300,
):
    database.connection.execute(
        "INSERT INTO family_envelopes (envelope_id, family_id, envelope_digest, "
        "envelope_json, status, review_deadline_at, reviewer_id, decided_at) "
        "VALUES (%s, %s, %s, %s, %s, %s, %s, %s)",
        (
            uuid4(),
            family_id,
            envelope_digest,
            Jsonb(
                {
                    "mode": "guided",
                    "allowed_mutation_families": ["byte_flip"],
                    "mutation_limits": {
                        "allowed_ops": ["append"],
                        "max_input_bytes": 64,
                    },
                    "seed_corpus_digest": "sha256:" + "a" * 64,
                    "fuzz_image_digest": "sha256:" + "b" * 64,
                    "harness_digest": ENVELOPE_HARNESS,
                    "max_rounds": 2,
                    "max_total_seconds": max_total_seconds,
                    "max_fuzz_seconds": max_fuzz_seconds,
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
            ),
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
    request=None,
):
    family_id = uuid4()
    child_id = uuid4()
    round_no = None if mode == "guided" else 1
    job_kind = "campaign" if mode == "guided" else "round"
    deadline = review_deadline_at or (_now() + timedelta(hours=24))
    if child_state is None:
        child_state = "READY" if first_approval else "AWAITING_REVIEW"
    request_document = request if request is not None else _family_request(mode)

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
        request=request_document,
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
                    "harness_digest": ENVELOPE_HARNESS,
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


def _job_lock_is_held(database, job_id, timeout=10.0):
    """Return whether another transaction holds one job row lock."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        with psycopg.connect(database.dsn, autocommit=True, connect_timeout=5) as probe:
            try:
                probe.execute(
                    "SELECT job_id FROM jobs WHERE job_id = %s FOR UPDATE NOWAIT",
                    (job_id,),
                )
            except psycopg.errors.LockNotAvailable:
                return True
        time.sleep(0.02)
    return False


def _family_lock_is_held(database, family_id, timeout=10.0):
    """Return whether another transaction holds the family row lock."""
    return _job_lock_is_held(database, family_id, timeout=timeout)


def _wait_for_a_row_lock_wait(database, timeout=10.0):
    """Wait until some backend on this database is blocked on a lock.

    ``pg_locks`` exposes a not-granted row lock while a backend waits. The
    holder transaction in the reverse-lock-order test is idle, so the only
    waiter is the freeze thread. Polling this catalog avoids a fixed sleep as
    the synchronization point.
    """
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        with psycopg.connect(database.dsn, autocommit=True, connect_timeout=5) as probe:
            waiting = probe.execute(
                "SELECT count(*) FROM pg_locks AS locks "
                "JOIN pg_stat_activity AS activity USING (pid) "
                "WHERE NOT locks.granted "
                "AND activity.datname = current_database()"
            ).fetchone()[0]
        if waiting:
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


def test_expire_review_rejects_a_stale_lease(
    isolated_database, tmp_path, monkeypatch
):
    monkeypatch.setenv("DATACON_EVIDENCE_ROOT", str(tmp_path / "evidence"))
    seed = _seed_family(
        isolated_database,
        review_deadline_at=_now() - timedelta(minutes=1),
        lease=False,
    )

    with pytest.raises(state.StaleGeneration):
        state.expire_review(isolated_database.dsn, seed["child_id"], 1)
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
    assert _row(
        isolated_database,
        "SELECT count(*) FROM reviews WHERE job_id = %s",
        (seed["family_id"],),
    )[0] == 0


def test_expire_review_rejects_a_wrong_generation(
    isolated_database, tmp_path, monkeypatch
):
    monkeypatch.setenv("DATACON_EVIDENCE_ROOT", str(tmp_path / "evidence"))
    seed = _seed_family(
        isolated_database,
        review_deadline_at=_now() - timedelta(minutes=1),
        lease=True,
    )

    with pytest.raises(state.StaleGeneration):
        state.expire_review(isolated_database.dsn, seed["child_id"], 999)
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
    assert _row(
        isolated_database,
        "SELECT status FROM family_envelopes WHERE family_id = %s "
        "AND envelope_digest = %s",
        (seed["family_id"], ENVELOPE_1),
    )[0] == "pending"


@pytest.mark.parametrize("decision", ["approve", "reject"])
@pytest.mark.parametrize("expired", [False, True])
def test_review_does_not_rewrite_a_child_verdict_terminal(
    isolated_database, tmp_path, monkeypatch, expired, decision
):
    monkeypatch.setenv("DATACON_EVIDENCE_ROOT", str(tmp_path / "evidence"))
    seed = _seed_family(
        isolated_database,
        review_deadline_at=(
            _now() - timedelta(minutes=1) if expired else None
        ),
    )
    isolated_database.connection.execute(
        "UPDATE jobs SET state = 'REPRODUCED', stage = 'archived', "
        "verdict = 'REPRODUCED', verdict_reason = 'ASAN_SIGNATURE_MATCHED', "
        "evidence_status = 'archived', evidence_path = %s, "
        "evidence_digest = %s, lease_owner = NULL, lease_expires_at = NULL "
        "WHERE job_id = %s",
        (
            f"evidence/{seed['child_id']}",
            "sha256:" + "d" * 64,
            seed["child_id"],
        ),
    )

    outcome = _review(isolated_database, seed, decision=decision)
    assert outcome.status == "invalid_state", (
        "a first-round review of a terminal child must fail before any write"
    )

    child_state, verdict, reason, evidence_path, evidence_digest = _row(
        isolated_database,
        "SELECT state, verdict, verdict_reason, evidence_path, "
        "evidence_digest FROM jobs WHERE job_id = %s",
        (seed["child_id"],),
    )
    assert (child_state, verdict, reason) == (
        "REPRODUCED",
        "REPRODUCED",
        "ASAN_SIGNATURE_MATCHED",
    ), "a verdict terminal child was rewritten by review reject/expiry"
    assert evidence_path == f"evidence/{seed['child_id']}"
    assert evidence_digest == "sha256:" + "d" * 64
    assert _row(
        isolated_database,
        "SELECT state FROM jobs WHERE job_id = %s",
        (seed["family_id"],),
    )[0] == "AGGREGATING", "a refused review blocked the family"
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
        "SELECT status FROM family_envelopes WHERE family_id = %s "
        "AND envelope_digest = %s",
        (seed["family_id"], ENVELOPE_1),
    )[0] == "pending"
    evidence_root = tmp_path / "evidence"
    assert not evidence_root.exists() or not any(evidence_root.iterdir()), (
        "a refused review archived a blocked bundle"
    )


def test_review_first_round_terminal_child_writes_nothing(
    isolated_database, tmp_path, monkeypatch
):
    monkeypatch.setenv("DATACON_EVIDENCE_ROOT", str(tmp_path / "evidence"))
    seed = _seed_family(isolated_database, first_approval=False)
    isolated_database.connection.execute(
        "UPDATE jobs SET state = 'REPRODUCED', stage = 'archived', "
        "verdict = 'REPRODUCED', verdict_reason = 'ASAN_SIGNATURE_MATCHED' "
        "WHERE job_id = %s",
        (seed["child_id"],),
    )

    outcome = _review(isolated_database, seed, decision="reject")
    assert outcome.status == "invalid_state"
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
        "SELECT count(*) FROM audit_events WHERE job_id = %s "
        "AND event_type = 'review_recorded'",
        (seed["family_id"],),
    )[0] == 0


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


def test_approval_digest_excludes_the_supersedes_chain_pointer(
    isolated_database,
):
    seed = _seed_family(
        isolated_database,
        first_approval=True,
        pending_envelope=ENVELOPE_2,
    )
    outcome = _review(isolated_database, seed, envelope_digest=ENVELOPE_2)
    assert outcome.status == "applied"

    (
        approval_digest,
        envelope_digest,
        first_plan_digest,
        reviewer_id,
        decided_at,
        supersedes,
    ) = isolated_database.connection.execute(
        "SELECT approval_digest, envelope_digest, first_plan_digest, "
        "reviewer_id, decided_at, supersedes FROM family_approvals "
        "WHERE family_id = %s ORDER BY decided_at DESC, approval_id DESC LIMIT 1",
        (seed["family_id"],),
    ).fetchone()
    assert supersedes is not None, "re-approval did not set the chain pointer"

    materials = {
        "family_id": str(seed["family_id"]),
        "first_plan_digest": first_plan_digest,
        "envelope_digest": envelope_digest,
        "reviewer_id": reviewer_id,
        "decided_at": jsonutil.approval_timestamp(decided_at),
    }
    assert jsonutil.digest_json(materials) == approval_digest, (
        "approval_digest cannot be recomputed from the persisted five fields"
    )
    materials_with_supersedes = dict(materials, supersedes=str(supersedes))
    assert jsonutil.digest_json(materials_with_supersedes) != approval_digest, (
        "supersedes leaked into the approval digest material"
    )


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


def _assert_v2_blocked_evidence(database, job_id):
    """Assert a job archived a verifiable v2 blocked bundle."""
    status_name, error, path, verdict = _row(
        database,
        "SELECT evidence_status, evidence_error, evidence_path, verdict "
        "FROM jobs WHERE job_id = %s",
        (job_id,),
    )
    assert status_name == "archived", (status_name, error)
    assert error is None
    assert verdict is None
    assert path is not None and Path(path).is_dir()
    verified = evidence.verify_bundle(path)
    assert verified.manifest["schema_version"] == 2
    assert verified.manifest["bundle_kind"] == "blocked"
    report = json.loads(verified.file_data["report.json"])
    assert report["schema_version"] == 2
    assert report["bundle_kind"] == "blocked"
    assert report["verdict"] == "BLOCKED"
    return verified


def test_v2_review_reject_archives_schema_2_blocked_bundles(
    isolated_database, tmp_path, monkeypatch
):
    monkeypatch.setenv("DATACON_EVIDENCE_ROOT", str(tmp_path / "evidence"))
    seed = _seed_family(isolated_database)
    # Replace the opaque first-plan row with a complete Plan v2 body and its
    # real digest so the blocked archiver can bind plan.json to the manifest.
    # The shared seed uses a constant digest for tests that never exercise the
    # archive path.
    complete_plan = _v2_plan(
        seed["family_id"], round_no=None, envelope_digest=ENVELOPE_1
    )
    real_digest = contracts.plan_digest(complete_plan)
    isolated_database.connection.execute(
        "UPDATE plans SET plan = %s, plan_digest = %s WHERE job_id = %s",
        (Jsonb(complete_plan), real_digest, seed["child_id"]),
    )

    outcome = _review(
        isolated_database, seed, decision="reject", plan_digest=real_digest
    )
    assert outcome.status == "applied"

    # The family and its first child are each BLOCKED by the reject; every
    # blocked row must own a v2 bundle, not a v1-shaped archive.
    verified_by_job = {
        job_id: _assert_v2_blocked_evidence(isolated_database, job_id)
        for job_id in (seed["family_id"], seed["child_id"])
    }
    for verified in verified_by_job.values():
        assert verified.manifest["reason_code"] == "REVIEW_REJECTED"
    child_bundle = verified_by_job[seed["child_id"]]
    child_report = json.loads(child_bundle.file_data["report.json"])
    assert child_report["plan_digest"] == real_digest
    # D36/§8: human reviews live on the family row, and the first child's
    # bundle carries a copy of review.json bound by plan_digest so offline
    # verification retains who rejected the plan and when.
    assert "plan.json" in child_bundle.file_data
    assert "review.json" in child_bundle.file_data
    child_review = json.loads(child_bundle.file_data["review.json"])
    assert child_review["decision"] == "reject"
    assert child_review["reviewer_id"] == REVIEWER_2
    assert child_review["plan_digest"] == real_digest
    jsonutil.require_rfc3339(child_review["decided_at"], "review.decided_at")
    assert child_report["review"] == child_review

    family_bundle = verified_by_job[seed["family_id"]]
    family_report = json.loads(family_bundle.file_data["report.json"])
    assert family_report["plan_digest"] is None
    assert family_report["review"] is None
    assert "plan.json" not in family_bundle.file_data
    assert "review.json" not in family_bundle.file_data


def test_v2_later_round_blocked_does_not_attach_first_round_review(
    isolated_database, tmp_path, monkeypatch
):
    """A later round's blocked bundle must never inherit the first-round review.

    ``reviews`` stores only the first human decision against ``family_id``. A
    subsequent round has its own ``plan_digest``, so ``record_blocked`` must
    keep ``review.json`` and ``report.review`` absent even though it consults
    the family's review row.
    """
    monkeypatch.setenv("DATACON_EVIDENCE_ROOT", str(tmp_path / "evidence"))
    seed = _seed_family(
        isolated_database, first_approval=True, pending_envelope=None
    )
    family_id = seed["family_id"]
    later_child = uuid4()
    _insert_plain_job(
        isolated_database,
        later_child,
        request=_family_request("guided"),
        state_name="BLOCKED",
        family_id=family_id,
        job_kind="round",
        parent_job_id=family_id,
        round_no=1,
    )
    isolated_database.connection.execute(
        "UPDATE jobs SET stage = 'blocked', reason_code = 'ENVELOPE_VIOLATION' "
        "WHERE job_id = %s",
        (later_child,),
    )
    later_plan = _v2_plan(
        family_id,
        round_no=1,
        envelope_digest=ENVELOPE_1,
        parent_approval_digest=APPROVAL_1,
    )
    later_digest = contracts.plan_digest(later_plan)
    isolated_database.connection.execute(
        "INSERT INTO plans (plan_id, job_id, plan_digest, plan, summary) "
        "VALUES (%s, %s, %s, %s, %s)",
        (uuid4(), later_child, later_digest, Jsonb(later_plan), Jsonb({})),
    )

    assert execution.record_blocked(
        isolated_database.dsn,
        later_child,
        reason_code="ENVELOPE_VIOLATION",
        message="round exceeded envelope mutation limits",
    )
    verified = _assert_v2_blocked_evidence(isolated_database, later_child)
    assert verified.manifest["reason_code"] == "ENVELOPE_VIOLATION"
    assert verified.manifest["plan_digest"] == later_digest
    report = json.loads(verified.file_data["report.json"])
    assert report["plan_digest"] == later_digest
    assert report["review"] is None
    assert "plan.json" in verified.file_data
    assert "review.json" not in verified.file_data


def test_v2_review_expiry_archives_schema_2_blocked_bundles(
    isolated_database, tmp_path, monkeypatch
):
    monkeypatch.setenv("DATACON_EVIDENCE_ROOT", str(tmp_path / "evidence"))
    seed = _seed_family(
        isolated_database,
        review_deadline_at=_now() - timedelta(minutes=1),
    )

    outcome = _review(isolated_database, seed, decision="approve")
    assert outcome.status == "expired"

    for job_id in (seed["family_id"], seed["child_id"]):
        verified = _assert_v2_blocked_evidence(isolated_database, job_id)
        assert verified.manifest["reason_code"] == "REVIEW_EXPIRED"


def test_v2_record_blocked_accepts_a_v2_only_reason(
    isolated_database, tmp_path, monkeypatch
):
    """A real v2 job must use the v2 reason table and write schema 2.

    ``record_blocked`` reads ``job_contract_version`` from the row; before the
    fix it always saw the default 1 and rejected v2-only terminal codes (or
    wrote a schema-1 bundle).
    """
    monkeypatch.setenv("DATACON_EVIDENCE_ROOT", str(tmp_path / "evidence"))
    seed = _seed_family(isolated_database)
    isolated_database.connection.execute(
        "UPDATE jobs SET state = 'BLOCKED', stage = 'blocked', "
        "reason_code = 'ENVELOPE_VIOLATION' WHERE job_id = %s",
        (seed["family_id"],),
    )

    assert execution.record_blocked(
        isolated_database.dsn,
        seed["family_id"],
        reason_code="ENVELOPE_VIOLATION",
        message="envelope exceeded the request ceiling",
    )
    verified = _assert_v2_blocked_evidence(isolated_database, seed["family_id"])
    assert verified.manifest["reason_code"] == "ENVELOPE_VIOLATION"


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
    verified = _assert_v2_blocked_evidence(isolated_database, seed["family_id"])
    assert verified.manifest["reason_code"] == "REVIEW_EXPIRED"
    family_report = json.loads(verified.file_data["report.json"])
    assert family_report["review"] is None
    assert "review.json" not in verified.file_data


FIXED_ENVELOPE_BODY = {
    "mode": "fixed",
    "allowed_mutation_families": [],
    "mutation_limits": {"allowed_ops": [], "max_input_bytes": 0},
    "seed_corpus_digest": None,
    "fuzz_image_digest": None,
    "harness_digest": "sha256:" + "c" * 64,
    "max_rounds": 1,
    "max_total_seconds": 100,
    "max_fuzz_seconds": 0,
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


def _fixed_request_without_exploration(*, execute_seconds=600):
    request = _family_request("fixed")
    request.pop("exploration")
    limits = dict(contracts.DEFAULT_LIMITS)
    limits["execute_seconds"] = execute_seconds
    request["limits"] = limits
    return request


def _fixed_envelope_body(*, max_total_seconds):
    body = deepcopy(FIXED_ENVELOPE_BODY)
    body["max_total_seconds"] = max_total_seconds
    return body


def _guided_request_with_mutation_limits(*, max_input_bytes, allowed_ops=("append",)):
    request = _family_request("guided")
    request["exploration"]["mutation_limits"] = {
        "allowed_ops": list(allowed_ops),
        "max_input_bytes": max_input_bytes,
    }
    return request


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
        "harness_digest": ENVELOPE_HARNESS,
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
    plan = _v2_plan(family_id, round_no=None, envelope_digest=digest)
    assert plan["harness_digest"] == body["harness_digest"]
    plan_digest = contracts.plan_digest(plan)

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
            plan=_v2_plan(family_2, round_no=None, envelope_digest=digest),
            plan_digest=contracts.plan_digest(
                _v2_plan(family_2, round_no=None, envelope_digest=digest)
            ),
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


def test_first_plan_freeze_rejects_harness_mismatch(isolated_database):
    family_id, child_id = _freeze_seed(
        isolated_database, _family_request("guided"), job_kind="campaign"
    )
    body = deepcopy(GUIDED_ENVELOPE_BODY)
    digest = jsonutil.digest_json(body)
    plan = _v2_plan(family_id, round_no=None, envelope_digest=digest)
    plan["harness_digest"] = "sha256:" + "2" * 64
    assert plan["harness_digest"] != body["harness_digest"]

    with pytest.raises(state.StateError, match="harness_digest"):
        state.freeze_plan(
            isolated_database.dsn,
            child_id,
            generation=1,
            plan=plan,
            plan_digest=contracts.plan_digest(plan),
            summary={},
            envelope=body,
        )
    _assert_no_freeze_rows(isolated_database, family_id, child_id)


def test_first_plan_freeze_rejects_plan_signature_outside_envelope(
    isolated_database,
):
    family_id, child_id = _freeze_seed(
        isolated_database, _family_request("guided"), job_kind="campaign"
    )
    body = deepcopy(GUIDED_ENVELOPE_BODY)
    digest = jsonutil.digest_json(body)
    plan = _v2_plan(family_id, round_no=None, envelope_digest=digest)
    plan["asan_signature"] = {
        **PLAN_BASE["asan_signature"],
        "function": "some_other_function",
        "operation": "READ",
        "access_size": 8,
    }

    with pytest.raises(state.StateError, match="asan_signature"):
        state.freeze_plan(
            isolated_database.dsn,
            child_id,
            generation=1,
            plan=plan,
            plan_digest=contracts.plan_digest(plan),
            summary={},
            envelope=body,
        )
    _assert_no_freeze_rows(isolated_database, family_id, child_id)


def test_later_plan_freeze_rejects_plan_signature_outside_envelope(
    isolated_database,
):
    seed = _seed_family(
        isolated_database, first_approval=True, pending_envelope=None
    )
    family_id = seed["family_id"]
    child_id = uuid4()
    _insert_plain_job(
        isolated_database,
        child_id,
        request=_family_request("guided"),
        state_name="PREPARING",
        family_id=family_id,
        job_kind="round",
        parent_job_id=family_id,
        round_no=1,
        lease=True,
    )
    plan = _v2_plan(
        family_id,
        round_no=1,
        envelope_digest=ENVELOPE_1,
        parent_approval_digest=APPROVAL_1,
    )
    plan["asan_signature"] = {
        **PLAN_BASE["asan_signature"],
        "function": "some_other_function",
        "operation": "READ",
        "access_size": 8,
    }

    with pytest.raises(state.StateError, match="asan_signature"):
        state.freeze_plan(
            isolated_database.dsn,
            child_id,
            generation=1,
            plan=plan,
            plan_digest=contracts.plan_digest(plan),
            summary={},
        )
    assert _row(
        isolated_database,
        "SELECT count(*) FROM plans WHERE job_id = %s",
        (child_id,),
    )[0] == 0


def test_first_plan_review_rejects_harness_mismatch(
    isolated_database, tmp_path, monkeypatch
):
    monkeypatch.setenv("DATACON_EVIDENCE_ROOT", str(tmp_path / "evidence"))
    seed = _seed_family(isolated_database)
    family_id = seed["family_id"]
    child_id = seed["child_id"]
    tampered_digest = "sha256:" + "2" * 64
    isolated_database.connection.execute(
        "UPDATE plans SET plan = jsonb_set(plan, '{harness_digest}', "
        "to_jsonb(%s::text)) WHERE job_id = %s",
        (tampered_digest, child_id),
    )

    with pytest.raises(state.StateError, match="harness_digest"):
        _review(isolated_database, seed, decision="approve")

    assert _row(
        isolated_database,
        "SELECT state FROM jobs WHERE job_id = %s",
        (family_id,),
    )[0] == "AGGREGATING"
    assert _row(
        isolated_database,
        "SELECT state FROM jobs WHERE job_id = %s",
        (child_id,),
    )[0] == "AWAITING_REVIEW"
    assert _row(
        isolated_database,
        "SELECT count(*) FROM reviews WHERE job_id = %s",
        (family_id,),
    )[0] == 0
    assert _row(
        isolated_database,
        "SELECT count(*) FROM family_approvals WHERE family_id = %s",
        (family_id,),
    )[0] == 0


def test_freeze_later_plan_rejects_harness_mismatch(isolated_database):
    seed = _seed_family(
        isolated_database, first_approval=True, pending_envelope=None
    )
    family_id = seed["family_id"]
    child_id = uuid4()
    _insert_plain_job(
        isolated_database,
        child_id,
        request=_family_request("guided"),
        state_name="PREPARING",
        family_id=family_id,
        job_kind="round",
        parent_job_id=family_id,
        round_no=1,
        lease=True,
    )
    plan = _v2_plan(
        family_id,
        round_no=1,
        envelope_digest=ENVELOPE_1,
        parent_approval_digest=APPROVAL_1,
    )
    plan["harness_digest"] = "sha256:" + "2" * 64

    with pytest.raises(state.StateError, match="harness_digest"):
        state.freeze_plan(
            isolated_database.dsn,
            child_id,
            generation=1,
            plan=plan,
            plan_digest=contracts.plan_digest(plan),
            summary={},
        )
    assert _row(
        isolated_database,
        "SELECT count(*) FROM plans WHERE job_id = %s",
        (child_id,),
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


# --- T10 blocker regressions: review retries, expiry, freeze identity -------


def test_reject_retry_returns_idempotent(isolated_database, tmp_path, monkeypatch):
    monkeypatch.setenv("DATACON_EVIDENCE_ROOT", str(tmp_path / "evidence"))
    seed = _seed_family(isolated_database)

    first = _review(isolated_database, seed, decision="reject")
    assert first.status == "applied"
    counts_after_first = (
        _row(
            isolated_database,
            "SELECT count(*) FROM reviews WHERE job_id = %s",
            (seed["family_id"],),
        )[0],
        _row(
            isolated_database,
            "SELECT count(*) FROM family_approvals WHERE family_id = %s",
            (seed["family_id"],),
        )[0],
        _row(
            isolated_database,
            "SELECT count(*) FROM family_envelopes WHERE family_id = %s",
            (seed["family_id"],),
        )[0],
    )

    retry = _review(isolated_database, seed, decision="reject")
    assert retry.status == "idempotent", (
        "a rejected first review must stay idempotent after the family is BLOCKED"
    )
    assert retry.review is not None
    assert retry.review["decision"] == "reject"
    assert counts_after_first == (1, 0, 1)
    assert (
        _row(
            isolated_database,
            "SELECT count(*) FROM reviews WHERE job_id = %s",
            (seed["family_id"],),
        )[0],
        _row(
            isolated_database,
            "SELECT count(*) FROM family_approvals WHERE family_id = %s",
            (seed["family_id"],),
        )[0],
        _row(
            isolated_database,
            "SELECT count(*) FROM family_envelopes WHERE family_id = %s",
            (seed["family_id"],),
        )[0],
    ) == counts_after_first, "the idempotent retry appended a review row"
    assert _row(
        isolated_database,
        "SELECT state, reason_code FROM jobs WHERE job_id = %s",
        (seed["family_id"],),
    ) == ("BLOCKED", "REVIEW_REJECTED")


def test_expiry_retry_returns_expired(isolated_database, tmp_path, monkeypatch):
    monkeypatch.setenv("DATACON_EVIDENCE_ROOT", str(tmp_path / "evidence"))
    seed = _seed_family(
        isolated_database,
        review_deadline_at=_now() - timedelta(minutes=1),
    )

    first = _review(isolated_database, seed, decision="approve")
    assert first.status == "expired"
    counts_after_first = (
        _row(
            isolated_database,
            "SELECT count(*) FROM reviews WHERE job_id = %s",
            (seed["family_id"],),
        )[0],
        _row(
            isolated_database,
            "SELECT count(*) FROM family_approvals WHERE family_id = %s",
            (seed["family_id"],),
        )[0],
        _row(
            isolated_database,
            "SELECT count(*) FROM family_envelopes WHERE family_id = %s",
            (seed["family_id"],),
        )[0],
    )

    retry = _review(isolated_database, seed, decision="approve")
    assert retry.status == "expired", (
        "an expired first review must stay expired after the family is BLOCKED"
    )
    assert counts_after_first == (0, 0, 1)
    assert (
        _row(
            isolated_database,
            "SELECT count(*) FROM reviews WHERE job_id = %s",
            (seed["family_id"],),
        )[0],
        _row(
            isolated_database,
            "SELECT count(*) FROM family_approvals WHERE family_id = %s",
            (seed["family_id"],),
        )[0],
        _row(
            isolated_database,
            "SELECT count(*) FROM family_envelopes WHERE family_id = %s",
            (seed["family_id"],),
        )[0],
    ) == counts_after_first, "the expired retry appended an envelope or review"
    assert _row(
        isolated_database,
        "SELECT status FROM family_envelopes WHERE family_id = %s",
        (seed["family_id"],),
    )[0] == "expired"


def test_reject_retry_other_reviewer_returns_conflict(
    isolated_database, tmp_path, monkeypatch
):
    monkeypatch.setenv("DATACON_EVIDENCE_ROOT", str(tmp_path / "evidence"))
    seed = _seed_family(isolated_database)

    first = _review(isolated_database, seed, decision="reject")
    assert first.status == "applied"

    retry = _review(
        isolated_database,
        seed,
        decision="reject",
        reviewer_id=REVIEWER_1,
    )
    assert retry.status == "conflict", (
        "a rejected envelope retried by another reviewer must conflict"
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
    )[0] == 0
    assert _row(
        isolated_database,
        "SELECT status FROM family_envelopes WHERE family_id = %s",
        (seed["family_id"],),
    )[0] == "rejected"


def test_expire_review_does_not_revert_completed_family(
    isolated_database, tmp_path, monkeypatch
):
    monkeypatch.setenv("DATACON_EVIDENCE_ROOT", str(tmp_path / "evidence"))
    seed = _seed_family(
        isolated_database,
        lease=True,
        review_deadline_at=_now() - timedelta(minutes=1),
    )
    # complete_family refuses a non-terminal child (S-1), so converge the
    # family with a terminal child first, then restore the stale child row that
    # the expiry path must not resurface.
    isolated_database.connection.execute(
        "UPDATE jobs SET state = 'COMPLETED', stage = 'done', "
        "evidence_status = 'archived', evidence_path = %s, evidence_digest = %s "
        "WHERE job_id = %s",
        (
            str(tmp_path / "child.json"),
            "sha256:" + "c" * 64,
            seed["child_id"],
        ),
    )
    # S-1 refuses to complete a family with a pending envelope. Seed the legal
    # approved state instead; expire_review must still not touch it.
    isolated_database.connection.execute(
        "UPDATE family_envelopes SET status = 'approved', "
        "reviewer_id = 'reviewer-first', decided_at = clock_timestamp() "
        "WHERE family_id = %s AND status = 'pending'",
        (seed["family_id"],),
    )
    family_path = tmp_path / "family.json"
    family_path.write_text('{"kind":"family_index","rounds":[]}', encoding="utf-8")
    family_digest = "sha256:" + "d" * 64
    assert state.complete_family(
        isolated_database.dsn,
        seed["family_id"],
        str(family_path),
        family_digest,
    )
    before = _row(
        isolated_database,
        "SELECT state, evidence_status, evidence_path, evidence_digest "
        "FROM jobs WHERE job_id = %s",
        (seed["family_id"],),
    )
    assert before == (
        "COMPLETED",
        "archived",
        str(family_path),
        family_digest,
    )

    isolated_database.connection.execute(
        "UPDATE jobs SET state = 'AWAITING_REVIEW', stage = 'review', "
        "generation = 1, lease_owner = 'worker-p1', "
        "lease_expires_at = now() + interval '10 minutes', "
        "review_deadline_at = now() - interval '1 minute' "
        "WHERE job_id = %s",
        (seed["child_id"],),
    )
    assert state.expire_review(isolated_database.dsn, seed["child_id"], 1) is False

    after = _row(
        isolated_database,
        "SELECT state, evidence_status, evidence_path, evidence_digest "
        "FROM jobs WHERE job_id = %s",
        (seed["family_id"],),
    )
    assert after == before, "expire_review overwrote a COMPLETED family pointer"
    assert _row(
        isolated_database,
        "SELECT state FROM jobs WHERE job_id = %s",
        (seed["child_id"],),
    )[0] == "AWAITING_REVIEW", "expire_review blocked the child of a COMPLETED family"
    assert _row(
        isolated_database,
        "SELECT status FROM family_envelopes WHERE family_id = %s",
        (seed["family_id"],),
    )[0] == "approved", "expire_review changed the envelope of a COMPLETED family"


# Complete Plan v2 fixture. ``contracts.plan_digest`` validates the full v1
# field set plus the eleven v2 additions, so a partial plan cannot be used to
# prove the freeze identity checks (B-3/B-4).
PLAN_ANALYSIS = {
    "diff_digest": "sha256:" + "9" * 64,
    "changed_paths": ["parser.c"],
    "symbols": [
        {
            "name": "parse_token",
            "path": "parser.c",
            "role": "definition",
            "revision": "vulnerable",
            "start_line": 5,
            "end_line": 18,
        },
    ],
    "findings": [
        {
            "kind": "fact",
            "statement": "the fix allocates one more byte",
            "confidence": "high",
            "evidence_refs": ["git:diff/a..b/parser.c"],
        },
    ],
}

PLAN_BASE = {
    "case_id": "fixture-c-parser",
    "cve_id": "CVE-2099-0001",
    "case_config_digest": "sha256:" + "a" * 64,
    "repository": {
        "origin": "fixture://datacon/B01",
        "bundle_digest": "sha256:" + "d" * 64,
        "patch_digest": "sha256:" + "e" * 64,
    },
    "revisions": {"vulnerable": "b" * 40, "fixed": "c" * 40},
    "dependencies_digest": "sha256:" + "f" * 64,
    "image_digest": "sha256:" + "0" * 64,
    "platform": "linux/amd64",
    "toolchain": {
        "compiler": "clang",
        "sanitizer": "address",
        "pinned_image_version": "19.1.7",
    },
    "asan_options": "detect_leaks=0:halt_on_error=1",
    "harness_digest": "sha256:" + "2" * 64,
    "expected_exit": {"normal": 0, "candidate_clean": 0, "candidate_asan": 86},
    "asan_signature": {
        "error": "heap-buffer-overflow",
        "operation": "WRITE",
        "access_size": 1,
        "function": "parse_token",
        "source": "parser.c",
    },
    "limits": contracts.DEFAULT_LIMITS,
    "isolation": {
        "network": "none",
        "user": "65534:65534",
        "read_only_root": True,
        "cap_drop": ["ALL"],
        "no_new_privileges": True,
        "seccomp": "runtime/default",
    },
    "intel": {
        "snapshot": "advisory.json",
        "collected_at": "2026-01-02T00:00:00Z",
        "content_digest": "sha256:" + "5" * 64,
        "sources": ["https://nvd.invalid/1"],
    },
    "analysis": PLAN_ANALYSIS,
    "analysis_digest": contracts.analysis_digest(PLAN_ANALYSIS),
    "policy_version": "1",
}

PLAN_BUILD_RECIPE_DIGEST = (
    "sha256:" + hashlib.sha256(jsonutil.canonical_bytes(BUILD_SPEC)).hexdigest()
)


def _v1_plan() -> dict:
    plan = deepcopy(PLAN_BASE)
    plan.update(
        {
            "build_recipe_digest": PLAN_BUILD_RECIPE_DIGEST,
            "inputs": {
                "candidate": "sha256:" + "3" * 64,
                "normal": "sha256:" + "4" * 64,
            },
        }
    )
    return plan


def _v2_plan(
    family_id,
    *,
    round_no,
    envelope_digest,
    parent_approval_digest=None,
) -> dict:
    plan = _v1_plan()
    plan.update(
        {
            "schema_version": 2,
            "family_id": str(family_id),
            "parent_job_id": str(family_id),
            "round_no": round_no,
            "parent_approval_digest": parent_approval_digest,
            "envelope_digest": envelope_digest,
            "harness_digest": ENVELOPE_HARNESS,
            "build_ref": None,
            "build_spec": deepcopy(BUILD_SPEC),
            "compile_flags": ["-g"],
            "experiment_digest": None,
            "build_provenance_rules_version": "build-provenance-v1",
            "build_recipe_digest": PLAN_BUILD_RECIPE_DIGEST,
            "inputs": (
                None
                if round_no is None
                else {
                    "candidate": "sha256:" + "3" * 64,
                    "normal": "sha256:" + "4" * 64,
                }
            ),
        }
    )
    return plan


def _freeze_seed(
    database,
    request,
    *,
    job_kind="campaign",
    state_name="PREPARING",
    round_no=None,
):
    family_id = uuid4()
    _insert_plain_job(
        database,
        family_id,
        request=request,
        state_name="AGGREGATING",
        family_id=family_id,
        job_kind="family",
        parent_job_id=None,
    )
    child_id = uuid4()
    if round_no is None:
        round_no = None if job_kind == "campaign" else 1
    _insert_plain_job(
        database,
        child_id,
        request=request,
        state_name=state_name,
        family_id=family_id,
        job_kind=job_kind,
        parent_job_id=family_id,
        round_no=round_no,
        lease=True,
    )
    return family_id, child_id


def _assert_no_freeze_rows(database, family_id, child_id, state_name="PREPARING"):
    assert _row(
        database,
        "SELECT count(*) FROM plans WHERE job_id = %s",
        (child_id,),
    )[0] == 0
    assert _row(
        database,
        "SELECT count(*) FROM family_envelopes WHERE family_id = %s "
        "AND status = 'pending'",
        (family_id,),
    )[0] == 0
    assert _row(
        database,
        "SELECT state FROM jobs WHERE job_id = %s",
        (child_id,),
    )[0] == state_name


def _insert_approval(
    database,
    family_id,
    *,
    approval_digest,
    envelope_digest,
    supersedes=None,
    reviewer_id=REVIEWER_1,
):
    approval_id = uuid4()
    database.connection.execute(
        "INSERT INTO family_approvals (approval_id, family_id, "
        "approval_digest, envelope_digest, first_plan_digest, reviewer_id, "
        "decided_at, supersedes) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)",
        (
            approval_id,
            family_id,
            approval_digest,
            envelope_digest,
            FIRST_PLAN_DIGEST,
            reviewer_id,
            _now(),
            supersedes,
        ),
    )
    # A later plan's freeze reads the approved envelope body to bind the plan
    # harness, so a hand-seeded approval must also seed the body it approved.
    if _row(
        database,
        "SELECT envelope_id FROM family_envelopes WHERE family_id = %s "
        "AND envelope_digest = %s",
        (family_id, envelope_digest),
    ) is None:
        _insert_envelope(
            database,
            family_id,
            envelope_digest,
            status_name="approved",
            review_deadline_at=_now() + timedelta(hours=24),
            reviewer_id=reviewer_id,
            decided_at=_now(),
        )
    return approval_id


def test_freeze_guided_round_one_does_not_enter_review(isolated_database):
    family_id, child_id = _freeze_seed(
        isolated_database, _family_request("guided"), job_kind="round"
    )
    _insert_approval(
        isolated_database,
        family_id,
        approval_digest=APPROVAL_1,
        envelope_digest=ENVELOPE_1,
    )
    plan = _v2_plan(
        family_id,
        round_no=1,
        envelope_digest=ENVELOPE_1,
        parent_approval_digest=APPROVAL_1,
    )
    plan["experiment_digest"] = "sha256:" + "3" * 64
    digest = contracts.plan_digest(plan)

    assert state.freeze_plan(
        isolated_database.dsn,
        child_id,
        generation=1,
        plan=plan,
        plan_digest=digest,
        summary={},
    ) is True

    state_name, review_deadline_at = _row(
        isolated_database,
        "SELECT state, review_deadline_at FROM jobs WHERE job_id = %s",
        (child_id,),
    )
    assert state_name == "PREPARING"
    assert state_name != "AWAITING_REVIEW"
    assert review_deadline_at is None, (
        "a non-first v2 plan must not open a review window"
    )
    assert _row(
        isolated_database,
        "SELECT count(*) FROM family_envelopes WHERE family_id = %s "
        "AND status = 'pending'",
        (family_id,),
    )[0] == 0
    assert _row(
        isolated_database,
        "SELECT count(*) FROM plans WHERE job_id = %s",
        (child_id,),
    )[0] == 1


def test_freeze_guided_round_one_rejects_null_parent_approval(isolated_database):
    family_id, child_id = _freeze_seed(
        isolated_database, _family_request("guided"), job_kind="round"
    )
    plan = _v2_plan(
        family_id,
        round_no=1,
        envelope_digest=ENVELOPE_1,
        parent_approval_digest=None,
    )
    assert plan["experiment_digest"] is None
    digest = contracts.plan_digest(plan)

    with pytest.raises(state.StateError, match="parent_approval_digest"):
        state.freeze_plan(
            isolated_database.dsn,
            child_id,
            generation=1,
            plan=plan,
            plan_digest=digest,
            summary={},
        )
    _assert_no_freeze_rows(isolated_database, family_id, child_id)


def test_freeze_guided_later_round_rejects_null_parent_approval(isolated_database):
    family_id, child_id = _freeze_seed(
        isolated_database,
        _family_request("guided"),
        job_kind="round",
        round_no=2,
    )
    plan = _v2_plan(
        family_id,
        round_no=2,
        envelope_digest=ENVELOPE_1,
        parent_approval_digest=None,
    )
    with pytest.raises(state.StateError, match="parent_approval_digest"):
        state.freeze_plan(
            isolated_database.dsn,
            child_id,
            generation=1,
            plan=plan,
            plan_digest="sha256:" + "e" * 64,
            summary={},
        )
    _assert_no_freeze_rows(isolated_database, family_id, child_id)


def test_freeze_fixed_round_one_rejects_parent_approval(isolated_database):
    family_id, child_id = _freeze_seed(
        isolated_database, _family_request("fixed"), job_kind="round"
    )
    body = _fixed_envelope_body(max_total_seconds=900)
    envelope_digest = jsonutil.digest_json(body)
    plan = _v2_plan(
        family_id,
        round_no=1,
        envelope_digest=envelope_digest,
        parent_approval_digest=APPROVAL_1,
    )
    digest = contracts.plan_digest(plan)

    with pytest.raises(state.StateError, match="parent_approval_digest"):
        state.freeze_plan(
            isolated_database.dsn,
            child_id,
            generation=1,
            plan=plan,
            plan_digest=digest,
            summary={},
            envelope=body,
        )
    _assert_no_freeze_rows(isolated_database, family_id, child_id)


def test_freeze_fixed_round_one_without_parent_approval_enters_review(
    isolated_database,
):
    family_id, child_id = _freeze_seed(
        isolated_database, _family_request("fixed"), job_kind="round"
    )
    body = _fixed_envelope_body(max_total_seconds=900)
    envelope_digest = jsonutil.digest_json(body)
    plan = _v2_plan(family_id, round_no=1, envelope_digest=envelope_digest)
    digest = contracts.plan_digest(plan)

    assert state.freeze_plan(
        isolated_database.dsn,
        child_id,
        generation=1,
        plan=plan,
        plan_digest=digest,
        summary={},
        envelope=body,
    ) is True

    state_name, review_deadline_at = _row(
        isolated_database,
        "SELECT state, review_deadline_at FROM jobs WHERE job_id = %s",
        (child_id,),
    )
    assert state_name == "AWAITING_REVIEW"
    assert review_deadline_at is not None
    assert _row(
        isolated_database,
        "SELECT status FROM family_envelopes WHERE family_id = %s",
        (family_id,),
    )[0] == "pending"


def test_freeze_fixed_later_round_does_not_enter_review(isolated_database):
    family_id = uuid4()
    _insert_plain_job(
        isolated_database,
        family_id,
        request=_family_request("fixed"),
        state_name="AGGREGATING",
        family_id=family_id,
        job_kind="family",
        parent_job_id=None,
    )
    child_id = uuid4()
    _insert_plain_job(
        isolated_database,
        child_id,
        request=_family_request("fixed"),
        state_name="PREPARING",
        family_id=family_id,
        job_kind="round",
        parent_job_id=family_id,
        round_no=2,
        lease=True,
    )
    _insert_approval(
        isolated_database,
        family_id,
        approval_digest=APPROVAL_1,
        envelope_digest=ENVELOPE_1,
    )
    plan = _v2_plan(
        family_id,
        round_no=2,
        envelope_digest=ENVELOPE_1,
        parent_approval_digest=APPROVAL_1,
    )
    assert state.freeze_plan(
        isolated_database.dsn,
        child_id,
        generation=1,
        plan=plan,
        plan_digest=contracts.plan_digest(plan),
        summary={},
    ) is True

    state_name, review_deadline_at = _row(
        isolated_database,
        "SELECT state, review_deadline_at FROM jobs WHERE job_id = %s",
        (child_id,),
    )
    assert state_name == "PREPARING"
    assert review_deadline_at is None


def test_freeze_non_first_plan_rejects_forged_approval_without_family_approval(
    isolated_database,
):
    family_id, child_id = _freeze_seed(
        isolated_database, _family_request("guided"), job_kind="round"
    )
    plan = _v2_plan(
        family_id,
        round_no=1,
        envelope_digest=ENVELOPE_1,
        parent_approval_digest=APPROVAL_1,
    )
    digest = contracts.plan_digest(plan)

    with pytest.raises(state.StateError, match="family_approvals"):
        state.freeze_plan(
            isolated_database.dsn,
            child_id,
            generation=1,
            plan=plan,
            plan_digest=digest,
            summary={},
        )
    _assert_no_freeze_rows(isolated_database, family_id, child_id)


def test_freeze_non_first_plan_rejects_superseded_approval_digest(
    isolated_database,
):
    family_id, child_id = _freeze_seed(
        isolated_database, _family_request("guided"), job_kind="round"
    )
    approval_2 = "sha256:" + "d" * 64
    first_id = _insert_approval(
        isolated_database,
        family_id,
        approval_digest=APPROVAL_1,
        envelope_digest=ENVELOPE_1,
    )
    _insert_approval(
        isolated_database,
        family_id,
        approval_digest=approval_2,
        envelope_digest=ENVELOPE_2,
        supersedes=first_id,
        reviewer_id=REVIEWER_2,
    )
    stale_plan = _v2_plan(
        family_id,
        round_no=1,
        envelope_digest=ENVELOPE_1,
        parent_approval_digest=APPROVAL_1,
    )
    with pytest.raises(state.StateError, match="parent_approval_digest"):
        state.freeze_plan(
            isolated_database.dsn,
            child_id,
            generation=1,
            plan=stale_plan,
            plan_digest=contracts.plan_digest(stale_plan),
            summary={},
        )
    _assert_no_freeze_rows(isolated_database, family_id, child_id)

    tail_plan = _v2_plan(
        family_id,
        round_no=1,
        envelope_digest=ENVELOPE_2,
        parent_approval_digest=approval_2,
    )
    assert state.freeze_plan(
        isolated_database.dsn,
        child_id,
        generation=1,
        plan=tail_plan,
        plan_digest=contracts.plan_digest(tail_plan),
        summary={},
    ) is True


def test_freeze_non_first_plan_rejects_envelope_mismatch_with_approval_tail(
    isolated_database,
):
    family_id, child_id = _freeze_seed(
        isolated_database, _family_request("guided"), job_kind="round"
    )
    _insert_approval(
        isolated_database,
        family_id,
        approval_digest=APPROVAL_1,
        envelope_digest=ENVELOPE_1,
    )
    mismatched_plan = _v2_plan(
        family_id,
        round_no=1,
        envelope_digest=ENVELOPE_2,
        parent_approval_digest=APPROVAL_1,
    )
    with pytest.raises(state.StateError, match="envelope_digest"):
        state.freeze_plan(
            isolated_database.dsn,
            child_id,
            generation=1,
            plan=mismatched_plan,
            plan_digest=contracts.plan_digest(mismatched_plan),
            summary={},
        )
    _assert_no_freeze_rows(isolated_database, family_id, child_id)


def test_real_reapproval_unlocks_the_next_plan_with_the_new_chain_tail(
    isolated_database, tmp_path, monkeypatch
):
    """§9.1 end-to-end: approve -> propose -> re-approve -> next freeze.

    Unlike the chain-tail fixtures above, this drives the real
    ``propose_envelope`` and ``record_review`` write paths instead of inserting
    ``family_approvals`` rows by hand.
    """
    monkeypatch.setenv("DATACON_EVIDENCE_ROOT", str(tmp_path / "evidence"))
    seed = _seed_family(
        isolated_database,
        first_approval=True,
        pending_envelope=None,
    )
    family_id = seed["family_id"]

    # A changed (tightened) envelope is proposed through the real path.
    new_body = deepcopy(GUIDED_ENVELOPE_BODY)
    new_body["max_total_seconds"] = 90
    new_envelope_digest = jsonutil.digest_json(new_body)
    proposed = state.propose_envelope(
        isolated_database.dsn, family_id, new_body
    )
    assert proposed["envelope_digest"] == new_envelope_digest

    outcome = state.record_review(
        isolated_database.dsn,
        family_id,
        plan_digest=FIRST_PLAN_DIGEST,
        decision="approve",
        reviewer_id=REVIEWER_2,
        envelope_digest=new_envelope_digest,
    )
    assert outcome.status == "applied"
    assert _row(
        isolated_database,
        "SELECT status FROM family_envelopes WHERE family_id = %s "
        "AND envelope_digest = %s",
        (family_id, new_envelope_digest),
    )[0] == "approved"

    tails = isolated_database.connection.execute(
        "SELECT approval_digest, envelope_digest "
        "FROM family_approvals AS prior "
        "WHERE prior.family_id = %s AND NOT EXISTS ("
        "SELECT 1 FROM family_approvals AS later "
        "WHERE later.supersedes = prior.approval_id)",
        (family_id,),
    ).fetchall()
    assert len(tails) == 1, "re-approval left more than one chain tail"
    tail_approval_digest, tail_envelope_digest = tails[0]
    assert tail_envelope_digest == new_envelope_digest
    assert _row(
        isolated_database,
        "SELECT count(*) FROM reviews WHERE job_id = %s",
        (family_id,),
    )[0] == 1, "re-approval rewrote the first-round reviews row"

    def _insert_guided_round_child(round_no=1):
        child = uuid4()
        _insert_plain_job(
            isolated_database,
            child,
            request=_family_request("guided"),
            state_name="PREPARING",
            family_id=family_id,
            job_kind="round",
            parent_job_id=family_id,
            round_no=round_no,
            lease=True,
        )
        return child

    # A later guided round plan bound to the new tail freezes successfully.
    good_child = _insert_guided_round_child()
    good_plan = _v2_plan(
        family_id,
        round_no=1,
        envelope_digest=tail_envelope_digest,
        parent_approval_digest=tail_approval_digest,
    )
    assert state.freeze_plan(
        isolated_database.dsn,
        good_child,
        generation=1,
        plan=good_plan,
        plan_digest=contracts.plan_digest(good_plan),
        summary={},
    ) is True

    # The old (superseded) approval is rejected even though the envelope is
    # the new one, and no plan row is written.
    bad_child = _insert_guided_round_child(round_no=2)
    stale_plan = _v2_plan(
        family_id,
        round_no=2,
        envelope_digest=tail_envelope_digest,
        parent_approval_digest=APPROVAL_1,
    )
    with pytest.raises(state.StateError, match="parent_approval_digest"):
        state.freeze_plan(
            isolated_database.dsn,
            bad_child,
            generation=1,
            plan=stale_plan,
            plan_digest=contracts.plan_digest(stale_plan),
            summary={},
        )
    assert _row(
        isolated_database,
        "SELECT count(*) FROM plans WHERE job_id = %s",
        (bad_child,),
    )[0] == 0
    assert _row(
        isolated_database,
        "SELECT state FROM jobs WHERE job_id = %s",
        (bad_child,),
    )[0] == "PREPARING"


def test_freeze_plan_locks_family_then_child(isolated_database):
    family_id, child_id = _freeze_seed(
        isolated_database, _family_request("guided")
    )
    body = dict(GUIDED_ENVELOPE_BODY)
    digest = jsonutil.digest_json(body)
    plan = _v2_plan(family_id, round_no=None, envelope_digest=digest)
    plan_digest = contracts.plan_digest(plan)

    holder = psycopg.connect(isolated_database.dsn, connect_timeout=5)
    try:
        holder.execute(
            "SELECT job_id FROM jobs WHERE job_id = %s FOR UPDATE",
            (child_id,),
        )
        thread, result, errors = _run_in_thread(
            lambda: state.freeze_plan(
                isolated_database.dsn,
                child_id,
                generation=1,
                plan=plan,
                plan_digest=plan_digest,
                summary={},
                envelope=body,
            )
        )
        assert _family_lock_is_held(isolated_database, family_id), (
            "freeze locked the child before the family"
        )
    finally:
        holder.commit()
        holder.close()

    assert _join(thread, result, errors) is True


def test_freeze_plan_does_not_lock_the_child_before_the_family(
    isolated_database,
):
    family_id, child_id = _freeze_seed(
        isolated_database, _family_request("guided")
    )
    body = dict(GUIDED_ENVELOPE_BODY)
    digest = jsonutil.digest_json(body)
    plan = _v2_plan(family_id, round_no=None, envelope_digest=digest)
    plan_digest = contracts.plan_digest(plan)

    holder = psycopg.connect(isolated_database.dsn, connect_timeout=5)
    try:
        holder.execute(
            "SELECT job_id FROM jobs WHERE job_id = %s FOR UPDATE",
            (family_id,),
        )
        thread, result, errors = _run_in_thread(
            lambda: state.freeze_plan(
                isolated_database.dsn,
                child_id,
                generation=1,
                plan=plan,
                plan_digest=plan_digest,
                summary={},
                envelope=body,
            )
        )
        # The freeze backend must actually be waiting before we inspect the
        # child. Waiting on pg_locks (not a fixed sleep) makes the ordering
        # observable even on a slow CI host.
        freeze_waited = _wait_for_a_row_lock_wait(isolated_database)
        child_held = _job_lock_is_held(
            isolated_database, child_id, timeout=0.5
        )
    finally:
        holder.commit()
        holder.close()

    value = _join(thread, result, errors)
    assert freeze_waited, "freeze never attempted the family row lock"
    assert child_held is False, (
        "freeze locked the child before the family; the fixed order is "
        "family -> child"
    )
    assert value is True
    assert _family_lock_is_held(isolated_database, family_id, timeout=0.0) is False
    assert _row(
        isolated_database,
        "SELECT count(*) FROM plans WHERE job_id = %s",
        (child_id,),
    )[0] == 1


def _install_slow_envelope_trigger(database):
    database.connection.execute(
        "DROP TRIGGER IF EXISTS test_slow_envelope ON family_envelopes"
    )
    database.connection.execute(
        "DROP FUNCTION IF EXISTS test_slow_envelope_fn()"
    )
    database.connection.execute(
        "CREATE FUNCTION test_slow_envelope_fn() RETURNS trigger "
        "LANGUAGE plpgsql AS $$ BEGIN PERFORM pg_sleep(0.5); RETURN NEW; END $$"
    )
    database.connection.execute(
        "CREATE TRIGGER test_slow_envelope BEFORE INSERT ON family_envelopes "
        "FOR EACH ROW EXECUTE FUNCTION test_slow_envelope_fn()"
    )


def _drop_slow_envelope_trigger(database):
    database.connection.execute(
        "DROP TRIGGER IF EXISTS test_slow_envelope ON family_envelopes"
    )
    database.connection.execute(
        "DROP FUNCTION IF EXISTS test_slow_envelope_fn()"
    )


def test_freeze_plan_and_record_review_do_not_deadlock(isolated_database):
    """Exercise one concrete freeze-then-review timing without a deadlock.

    This covers the case where freeze already holds the child while its
    envelope trigger sleeps and record_review queues on the family. It is not
    a proof of the global lock order: the deterministic ordering guard is
    ``test_freeze_plan_does_not_lock_the_child_before_the_family``. The final
    state assertions below are the real evidence; a permissive status alone
    would not be.
    """
    family_id, child_id = _freeze_seed(
        isolated_database, _family_request("guided")
    )
    body = dict(GUIDED_ENVELOPE_BODY)
    envelope_digest = jsonutil.digest_json(body)
    plan = _v2_plan(family_id, round_no=None, envelope_digest=envelope_digest)
    plan_digest = contracts.plan_digest(plan)

    _install_slow_envelope_trigger(isolated_database)
    freeze_thread = review_thread = None
    try:
        freeze_thread, freeze_result, freeze_errors = _run_in_thread(
            lambda: state.freeze_plan(
                isolated_database.dsn,
                child_id,
                generation=1,
                plan=plan,
                plan_digest=plan_digest,
                summary={},
                envelope=body,
            )
        )
        # Wait until freeze holds the child lock while the BEFORE INSERT
        # trigger is sleeping; record_review must then queue on the family,
        # never on the child first.
        assert _job_lock_is_held(isolated_database, child_id), (
            "freeze never reached the child lock"
        )
        review_thread, review_result, review_errors = _run_in_thread(
            lambda: state.record_review(
                isolated_database.dsn,
                family_id,
                plan_digest=plan_digest,
                decision="approve",
                reviewer_id="reviewer-race",
            )
        )
        try:
            assert _join(freeze_thread, freeze_result, freeze_errors) is True
            outcome = _join(review_thread, review_result, review_errors)
        except psycopg.errors.DeadlockDetected as error:
            pytest.fail(f"freeze_plan/record_review hit 40P01: {error}")
        # With this timing the review starts only after freeze has committed,
        # so it must see AWAITING_REVIEW and apply. A broad status membership
        # would hide a regression that skipped the review.
        assert outcome.status == "applied"
    finally:
        for thread in (freeze_thread, review_thread):
            if thread is not None:
                thread.join(timeout=30)
        _drop_slow_envelope_trigger(isolated_database)

    family_state = _row(
        isolated_database,
        "SELECT state FROM jobs WHERE job_id = %s",
        (family_id,),
    )[0]
    child_state = _row(
        isolated_database,
        "SELECT state FROM jobs WHERE job_id = %s",
        (child_id,),
    )[0]
    review_count = _row(
        isolated_database,
        "SELECT count(*) FROM reviews WHERE job_id = %s",
        (family_id,),
    )[0]
    envelope_status = _row(
        isolated_database,
        "SELECT status FROM family_envelopes WHERE family_id = %s",
        (family_id,),
    )[0]
    assert family_state == "AGGREGATING"
    assert review_count == 1
    assert child_state == "READY"
    assert envelope_status == "approved"


def test_freeze_plan_rejects_a_contract_valid_foreign_family_identity(
    isolated_database,
):
    """Reject a plan that is internally valid but names another family.

    Plan v2 requires ``family_id == parent_job_id`` (contracts.plan_digest), so
    a "wrong parent only" input would fail in the contract before the state
    check. Mutating both identity fields keeps the plan contract-valid and
    moves the digest with it, which is the only shape that exercises
    ``freeze_plan``'s own family check. Deleting that check would freeze this
    plan instead of raising.
    """
    family_id, child_id = _freeze_seed(
        isolated_database, _family_request("guided")
    )
    foreign_family = str(uuid4())
    envelope_body = dict(GUIDED_ENVELOPE_BODY)
    plan = _v2_plan(
        family_id,
        round_no=None,
        envelope_digest=jsonutil.digest_json(envelope_body),
    )
    plan["family_id"] = foreign_family
    plan["parent_job_id"] = foreign_family
    digest = contracts.plan_digest(plan)

    with pytest.raises(state.StateError, match="family_id"):
        state.freeze_plan(
            isolated_database.dsn,
            child_id,
            generation=1,
            plan=plan,
            plan_digest=digest,
            summary={},
            envelope=envelope_body,
        )
    _assert_no_freeze_rows(isolated_database, family_id, child_id)


def test_freeze_plan_rejects_wrong_round_no(isolated_database):
    family_id, child_id = _freeze_seed(
        isolated_database, _family_request("guided")
    )
    plan = _v2_plan(
        family_id,
        round_no=2,
        envelope_digest=ENVELOPE_1,
        parent_approval_digest=APPROVAL_1,
    )
    digest = contracts.plan_digest(plan)

    with pytest.raises(state.StateError, match="round_no"):
        state.freeze_plan(
            isolated_database.dsn,
            child_id,
            generation=1,
            plan=plan,
            plan_digest=digest,
            summary={},
            envelope=dict(GUIDED_ENVELOPE_BODY),
        )
    _assert_no_freeze_rows(isolated_database, family_id, child_id)


def test_freeze_plan_rejects_tampered_plan_digest(isolated_database):
    family_id, child_id = _freeze_seed(
        isolated_database, _family_request("guided")
    )
    plan = _v2_plan(family_id, round_no=None, envelope_digest=ENVELOPE_1)
    tampered = dict(plan, policy_version="tampered-policy")
    tampered_digest = contracts.plan_digest(tampered)

    with pytest.raises(state.StateError, match="plan_digest"):
        state.freeze_plan(
            isolated_database.dsn,
            child_id,
            generation=1,
            plan=plan,
            plan_digest=tampered_digest,
            summary={},
            envelope=dict(GUIDED_ENVELOPE_BODY),
        )
    _assert_no_freeze_rows(isolated_database, family_id, child_id)


def test_freeze_plan_rejects_v1_plan_for_v2_job(isolated_database):
    family_id, child_id = _freeze_seed(
        isolated_database, _family_request("guided")
    )
    plan = _v1_plan()
    digest = contracts.plan_digest(plan)

    with pytest.raises(state.StateError, match="schema_version"):
        state.freeze_plan(
            isolated_database.dsn,
            child_id,
            generation=1,
            plan=plan,
            plan_digest=digest,
            summary={},
            envelope=dict(GUIDED_ENVELOPE_BODY),
        )
    _assert_no_freeze_rows(isolated_database, family_id, child_id)


def test_freeze_plan_rejects_v2_family_job(isolated_database):
    request = _family_request("guided")
    family_id = uuid4()
    _insert_plain_job(
        isolated_database,
        family_id,
        request=request,
        state_name="PREPARING",
        family_id=family_id,
        job_kind="family",
        parent_job_id=None,
        lease=True,
    )
    plan = _v2_plan(family_id, round_no=None, envelope_digest=ENVELOPE_1)
    digest = contracts.plan_digest(plan)

    with pytest.raises(state.StateError, match="campaign or round"):
        state.freeze_plan(
            isolated_database.dsn,
            family_id,
            generation=1,
            plan=plan,
            plan_digest=digest,
            summary={},
            envelope=dict(GUIDED_ENVELOPE_BODY),
        )
    _assert_no_freeze_rows(isolated_database, family_id, family_id)


def test_first_envelope_must_not_exceed_request_max_rounds(isolated_database):
    request = _family_request("guided")
    request["exploration"]["max_rounds"] = 1
    family_id, child_id = _freeze_seed(isolated_database, request)
    body = dict(GUIDED_ENVELOPE_BODY)
    body["max_rounds"] = 2
    digest = jsonutil.digest_json(body)
    plan = _v2_plan(family_id, round_no=None, envelope_digest=digest)
    plan_digest = contracts.plan_digest(plan)

    with pytest.raises(state.StateError, match="max_rounds"):
        state.freeze_plan(
            isolated_database.dsn,
            child_id,
            generation=1,
            plan=plan,
            plan_digest=plan_digest,
            summary={},
            envelope=body,
        )
    _assert_no_freeze_rows(isolated_database, family_id, child_id)


def test_first_envelope_must_not_exceed_case_registry(isolated_database):
    family_id, child_id = _freeze_seed(
        isolated_database, _family_request("guided")
    )
    body = deepcopy(GUIDED_ENVELOPE_BODY)
    body["mutation_limits"] = {
        "allowed_ops": ["append"],
        "max_input_bytes": 5000,
    }
    digest = jsonutil.digest_json(body)
    plan = _v2_plan(family_id, round_no=None, envelope_digest=digest)
    plan_digest = contracts.plan_digest(plan)

    with pytest.raises(state.StateError, match="case registry"):
        state.freeze_plan(
            isolated_database.dsn,
            child_id,
            generation=1,
            plan=plan,
            plan_digest=plan_digest,
            summary={},
            envelope=body,
        )
    _assert_no_freeze_rows(isolated_database, family_id, child_id)


def test_first_envelope_and_propose_reject_the_same_expansion(isolated_database):
    request = _family_request("guided")
    family_id, child_id = _freeze_seed(isolated_database, request)
    body = deepcopy(GUIDED_ENVELOPE_BODY)
    body["max_rounds"] = 9
    digest = jsonutil.digest_json(body)
    plan = _v2_plan(family_id, round_no=None, envelope_digest=digest)
    plan_digest = contracts.plan_digest(plan)

    with pytest.raises(state.StateError, match="max_rounds"):
        state.freeze_plan(
            isolated_database.dsn,
            child_id,
            generation=1,
            plan=plan,
            plan_digest=plan_digest,
            summary={},
            envelope=body,
        )
    _assert_no_freeze_rows(isolated_database, family_id, child_id)

    approved = _seed_family(
        isolated_database,
        first_approval=True,
        pending_envelope=None,
    )
    with pytest.raises(state.StateError, match="max_rounds"):
        state.propose_envelope(
            isolated_database.dsn,
            approved["family_id"],
            body,
        )


def test_fixed_envelope_without_exploration_cannot_exceed_execute_seconds(
    isolated_database,
):
    request = _fixed_request_without_exploration(execute_seconds=600)
    family_id, child_id = _freeze_seed(isolated_database, request)

    def freeze(body):
        digest = jsonutil.digest_json(body)
        plan = _v2_plan(family_id, round_no=None, envelope_digest=digest)
        return state.freeze_plan(
            isolated_database.dsn,
            child_id,
            generation=1,
            plan=plan,
            plan_digest=contracts.plan_digest(plan),
            summary={},
            envelope=body,
        )

    with pytest.raises(state.StateError, match="max_total_seconds"):
        freeze(_fixed_envelope_body(max_total_seconds=900))
    _assert_no_freeze_rows(isolated_database, family_id, child_id)

    assert freeze(_fixed_envelope_body(max_total_seconds=600)) is True
    assert _row(
        isolated_database,
        "SELECT count(*) FROM plans WHERE job_id = %s",
        (child_id,),
    )[0] == 1
    assert _row(
        isolated_database,
        "SELECT count(*) FROM family_envelopes WHERE family_id = %s",
        (family_id,),
    )[0] == 1


def test_propose_envelope_without_exploration_cannot_exceed_execute_seconds(
    isolated_database,
):
    request = _fixed_request_without_exploration(execute_seconds=600)
    seed = _seed_family(
        isolated_database,
        mode="fixed",
        first_approval=True,
        pending_envelope=None,
        request=request,
    )
    with pytest.raises(state.StateError, match="max_total_seconds"):
        state.propose_envelope(
            isolated_database.dsn,
            seed["family_id"],
            _fixed_envelope_body(max_total_seconds=900),
        )
    result = state.propose_envelope(
        isolated_database.dsn,
        seed["family_id"],
        _fixed_envelope_body(max_total_seconds=600),
    )
    assert result["status"] == "pending"


def test_guided_envelope_without_exploration_request_is_rejected(
    isolated_database,
):
    request = _fixed_request_without_exploration(execute_seconds=600)
    family_id, child_id = _freeze_seed(isolated_database, request)
    body = deepcopy(GUIDED_ENVELOPE_BODY)
    digest = jsonutil.digest_json(body)
    plan = _v2_plan(family_id, round_no=None, envelope_digest=digest)

    with pytest.raises(state.StateError, match="fixed envelope"):
        state.freeze_plan(
            isolated_database.dsn,
            child_id,
            generation=1,
            plan=plan,
            plan_digest=contracts.plan_digest(plan),
            summary={},
            envelope=body,
        )
    _assert_no_freeze_rows(isolated_database, family_id, child_id)


def test_envelope_max_input_bytes_cannot_expand_the_request(isolated_database):
    request = _guided_request_with_mutation_limits(max_input_bytes=64)
    family_id, child_id = _freeze_seed(isolated_database, request)

    def freeze(max_input_bytes):
        body = deepcopy(GUIDED_ENVELOPE_BODY)
        body["mutation_limits"] = {
            "allowed_ops": ["append"],
            "max_input_bytes": max_input_bytes,
        }
        digest = jsonutil.digest_json(body)
        plan = _v2_plan(family_id, round_no=None, envelope_digest=digest)
        return state.freeze_plan(
            isolated_database.dsn,
            child_id,
            generation=1,
            plan=plan,
            plan_digest=contracts.plan_digest(plan),
            summary={},
            envelope=body,
        )

    with pytest.raises(state.StateError, match="max_input_bytes"):
        freeze(4096)
    _assert_no_freeze_rows(isolated_database, family_id, child_id)

    assert freeze(64) is True


def test_propose_envelope_max_input_bytes_cannot_expand_the_request(
    isolated_database,
):
    request = _guided_request_with_mutation_limits(max_input_bytes=64)
    seed = _seed_family(
        isolated_database,
        first_approval=True,
        pending_envelope=None,
        request=request,
    )
    expanded = deepcopy(GUIDED_ENVELOPE_BODY)
    expanded["mutation_limits"] = {
        "allowed_ops": ["append"],
        "max_input_bytes": 4096,
    }
    with pytest.raises(state.StateError, match="max_input_bytes"):
        state.propose_envelope(
            isolated_database.dsn, seed["family_id"], expanded
        )

    tightened = deepcopy(GUIDED_ENVELOPE_BODY)
    tightened["mutation_limits"] = {
        "allowed_ops": ["append"],
        "max_input_bytes": 64,
    }
    result = state.propose_envelope(
        isolated_database.dsn, seed["family_id"], tightened
    )
    assert result["status"] == "pending"


def test_request_mutation_limits_take_the_intersection_and_minimum(
    isolated_database,
):
    request = _guided_request_with_mutation_limits(max_input_bytes=64)
    request["mutation_limits"] = {
        "allowed_ops": ["append"],
        "max_input_bytes": 32,
    }
    family_id, child_id = _freeze_seed(isolated_database, request)
    body = deepcopy(GUIDED_ENVELOPE_BODY)
    body["mutation_limits"] = {
        "allowed_ops": ["append"],
        "max_input_bytes": 64,
    }
    digest = jsonutil.digest_json(body)
    plan = _v2_plan(family_id, round_no=None, envelope_digest=digest)
    with pytest.raises(state.StateError, match="max_input_bytes"):
        state.freeze_plan(
            isolated_database.dsn,
            child_id,
            generation=1,
            plan=plan,
            plan_digest=contracts.plan_digest(plan),
            summary={},
            envelope=body,
        )
    _assert_no_freeze_rows(isolated_database, family_id, child_id)


def test_first_approve_retry_without_digest_is_idempotent(isolated_database):
    seed = _seed_family(isolated_database)
    first = _review(isolated_database, seed, envelope_digest=None)
    assert first.status == "applied"
    count_approvals = _row(
        isolated_database,
        "SELECT count(*) FROM family_approvals WHERE family_id = %s",
        (seed["family_id"],),
    )[0]

    retry = _review(isolated_database, seed, envelope_digest=None)
    assert retry.status == "idempotent", (
        "omitting --envelope-digest on the first-approve retry must resolve "
        "to the approved first plan envelope"
    )
    assert _row(
        isolated_database,
        "SELECT count(*) FROM family_approvals WHERE family_id = %s",
        (seed["family_id"],),
    )[0] == count_approvals
    assert _row(
        isolated_database,
        "SELECT count(*) FROM reviews WHERE job_id = %s",
        (seed["family_id"],),
    )[0] == 1


def test_first_reject_retry_without_digest_is_idempotent(
    isolated_database, tmp_path, monkeypatch
):
    monkeypatch.setenv("DATACON_EVIDENCE_ROOT", str(tmp_path / "evidence"))
    seed = _seed_family(isolated_database)
    first = _review(isolated_database, seed, decision="reject", envelope_digest=None)
    assert first.status == "applied"

    retry = _review(
        isolated_database, seed, decision="reject", envelope_digest=None
    )
    assert retry.status == "idempotent", (
        "omitting --envelope-digest on the first-reject retry must resolve "
        "to the rejected first plan envelope"
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
    )[0] == 0


def test_changed_envelope_reapproval_without_digest_is_mismatch(isolated_database):
    seed = _seed_family(
        isolated_database,
        first_approval=True,
        pending_envelope=ENVELOPE_2,
    )

    outcome = _review(isolated_database, seed, envelope_digest=None)
    assert outcome.status == "envelope_mismatch", (
        "a changed pending envelope without --envelope-digest must fail closed"
    )
    assert outcome.reason_code == "REVIEW_ENVELOPE_MISMATCH"
    assert _row(
        isolated_database,
        "SELECT count(*) FROM family_approvals WHERE family_id = %s",
        (seed["family_id"],),
    )[0] == 1
    assert _row(
        isolated_database,
        "SELECT status FROM family_envelopes WHERE family_id = %s "
        "AND envelope_digest = %s",
        (seed["family_id"], ENVELOPE_2),
    )[0] == "pending"


def test_explicit_digest_reapproval_still_idempotent(isolated_database):
    seed = _seed_family(
        isolated_database,
        first_approval=True,
        pending_envelope=ENVELOPE_2,
    )

    applied = _review(isolated_database, seed, envelope_digest=ENVELOPE_2)
    assert applied.status == "applied"
    retry = _review(isolated_database, seed, envelope_digest=ENVELOPE_2)
    assert retry.status == "idempotent"
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


def test_family_approval_initializes_budget_ledger(
    isolated_database, tmp_path, monkeypatch
):
    monkeypatch.setenv("DATACON_EVIDENCE_ROOT", str(tmp_path / "evidence"))
    seed = _seed_family(isolated_database)

    outcome = _review(isolated_database, seed)

    assert outcome.status == "applied", outcome.message
    ledger = state.load_budget_ledger(isolated_database.dsn, seed["family_id"])
    assert ledger is not None, "family approval did not initialize budget_ledger"
    assert ledger["max_total_seconds"] == 900
    assert ledger["max_fuzz_seconds"] == 300
    assert ledger["remaining_total_seconds"] == 900
    assert ledger["remaining_fuzz_seconds"] == 300

    isolated_database.connection.execute(
        "UPDATE jobs SET state = 'RUNNING', stage = 'execute', "
        "lease_owner = 'worker-a', "
        "lease_expires_at = clock_timestamp() + interval '10 minutes' "
        "WHERE job_id = %s",
        (seed["child_id"],),
    )
    charge = state.charge_step_budget(
        isolated_database.dsn,
        generation=2,
        family_id=seed["family_id"],
        job_id=seed["child_id"],
        step_key="build",
        attempt_no=1,
        charge_kind="general",
        elapsed_seconds=1,
    )
    assert charge.status == "charged", charge.status
    summary = state.family_budget_summary(
        isolated_database.dsn, seed["family_id"]
    )
    assert summary["remaining_seconds"] == 899

    repeated = _review(isolated_database, seed)
    assert repeated.status == "idempotent"
    assert _row(
        isolated_database,
        "SELECT count(*) FROM budget_ledger WHERE family_id = %s",
        (seed["family_id"],),
    )[0] == 1, "re-approval inserted a second budget ledger row"
    after = state.load_budget_ledger(isolated_database.dsn, seed["family_id"])
    assert after["remaining_total_seconds"] == 899, (
        "re-approval reset the spent budget"
    )
    assert state.family_budget_summary(
        isolated_database.dsn, seed["family_id"]
    )["spent_seconds"] == 1


def test_reapproval_tightens_budget_ledger_and_propose_rejects_below_spent(
    isolated_database, tmp_path, monkeypatch
):
    monkeypatch.setenv("DATACON_EVIDENCE_ROOT", str(tmp_path / "evidence"))
    seed = _seed_family(isolated_database)
    family_id = seed["family_id"]

    first_approval = _review(isolated_database, seed)
    assert first_approval.status == "applied", first_approval.message

    isolated_database.connection.execute(
        "UPDATE jobs SET state = 'RUNNING', stage = 'execute', "
        "lease_owner = 'worker-a', "
        "lease_expires_at = clock_timestamp() + interval '10 minutes' "
        "WHERE job_id = %s",
        (seed["child_id"],),
    )
    charge = state.charge_step_budget(
        isolated_database.dsn,
        generation=2,
        family_id=family_id,
        job_id=seed["child_id"],
        step_key="fuzz",
        attempt_no=1,
        charge_kind="fuzz",
        elapsed_seconds=10,
        elapsed_fuzz_seconds=5,
    )
    assert charge.status == "charged", charge.status

    # Move the child out of RUNNING/ARCHIVING before proposing a tightened cap.
    isolated_database.connection.execute(
        "UPDATE jobs SET state = 'READY', stage = 'ready' WHERE job_id = %s",
        (seed["child_id"],),
    )

    tightened = deepcopy(GUIDED_ENVELOPE_BODY)
    tightened["max_total_seconds"] = 600
    tightened["max_fuzz_seconds"] = 200
    tightened_digest = jsonutil.digest_json(tightened)
    proposed = state.propose_envelope(
        isolated_database.dsn, family_id, tightened
    )
    assert proposed["envelope_digest"] == tightened_digest

    reapproved = state.record_review(
        isolated_database.dsn,
        family_id,
        plan_digest=FIRST_PLAN_DIGEST,
        decision="approve",
        reviewer_id=REVIEWER_2,
        envelope_digest=tightened_digest,
    )
    assert reapproved.status == "applied", reapproved.message

    summary = state.family_budget_summary(isolated_database.dsn, family_id)
    assert summary == {
        "max_total_seconds": 600,
        "max_fuzz_seconds": 200,
        "spent_seconds": 10,
        "spent_fuzz_seconds": 5,
        "remaining_seconds": 590,
        "remaining_fuzz_seconds": 195,
    }

    too_small_total = deepcopy(GUIDED_ENVELOPE_BODY)
    too_small_total["max_total_seconds"] = 5
    too_small_total["max_fuzz_seconds"] = 2
    with pytest.raises(state.StateError, match="spent"):
        state.propose_envelope(
            isolated_database.dsn, family_id, too_small_total
        )

    too_small_fuzz = deepcopy(GUIDED_ENVELOPE_BODY)
    too_small_fuzz["max_total_seconds"] = 50
    too_small_fuzz["max_fuzz_seconds"] = 2
    with pytest.raises(state.StateError, match="spent"):
        state.propose_envelope(
            isolated_database.dsn, family_id, too_small_fuzz
        )

    assert _row(
        isolated_database,
        "SELECT count(*) FROM family_envelopes WHERE family_id = %s "
        "AND status = 'pending'",
        (family_id,),
    )[0] == 0, "unapprovable envelope left a stuck pending row"


def test_reapproval_raises_budget_ledger_after_spend(
    isolated_database, tmp_path, monkeypatch
):
    monkeypatch.setenv("DATACON_EVIDENCE_ROOT", str(tmp_path / "evidence"))
    seed = _seed_family(isolated_database)
    family_id = seed["family_id"]

    first_approval = _review(isolated_database, seed)
    assert first_approval.status == "applied", first_approval.message

    isolated_database.connection.execute(
        "UPDATE jobs SET state = 'RUNNING', stage = 'execute', "
        "lease_owner = 'worker-a', "
        "lease_expires_at = clock_timestamp() + interval '10 minutes' "
        "WHERE job_id = %s",
        (seed["child_id"],),
    )
    charge = state.charge_step_budget(
        isolated_database.dsn,
        generation=2,
        family_id=family_id,
        job_id=seed["child_id"],
        step_key="fuzz",
        attempt_no=1,
        charge_kind="fuzz",
        elapsed_seconds=10,
        elapsed_fuzz_seconds=5,
    )
    assert charge.status == "charged", charge.status

    # Tighten 900/300 -> 600/200 after 10/5 is already spent.
    isolated_database.connection.execute(
        "UPDATE jobs SET state = 'READY', stage = 'ready' WHERE job_id = %s",
        (seed["child_id"],),
    )
    tightened = deepcopy(GUIDED_ENVELOPE_BODY)
    tightened["max_total_seconds"] = 600
    tightened["max_fuzz_seconds"] = 200
    tightened_digest = jsonutil.digest_json(tightened)
    proposed = state.propose_envelope(
        isolated_database.dsn, family_id, tightened
    )
    assert proposed["envelope_digest"] == tightened_digest
    tightened_review = state.record_review(
        isolated_database.dsn,
        family_id,
        plan_digest=FIRST_PLAN_DIGEST,
        decision="approve",
        reviewer_id=REVIEWER_2,
        envelope_digest=tightened_digest,
    )
    assert tightened_review.status == "applied", tightened_review.message
    assert state.family_budget_summary(
        isolated_database.dsn, family_id
    ) == {
        "max_total_seconds": 600,
        "max_fuzz_seconds": 200,
        "spent_seconds": 10,
        "spent_fuzz_seconds": 5,
        "remaining_seconds": 590,
        "remaining_fuzz_seconds": 195,
    }

    # Raise 600/200 -> 900/300 again; the already-spent 10/5 must survive.
    raised = deepcopy(GUIDED_ENVELOPE_BODY)
    raised["max_total_seconds"] = 900
    raised["max_fuzz_seconds"] = 300
    raised_digest = jsonutil.digest_json(raised)
    proposed = state.propose_envelope(
        isolated_database.dsn, family_id, raised
    )
    assert proposed["envelope_digest"] == raised_digest
    raised_review = state.record_review(
        isolated_database.dsn,
        family_id,
        plan_digest=FIRST_PLAN_DIGEST,
        decision="approve",
        reviewer_id=REVIEWER_2,
        envelope_digest=raised_digest,
    )
    assert raised_review.status == "applied", raised_review.message

    assert state.family_budget_summary(
        isolated_database.dsn, family_id
    ) == {
        "max_total_seconds": 900,
        "max_fuzz_seconds": 300,
        "spent_seconds": 10,
        "spent_fuzz_seconds": 5,
        "remaining_seconds": 890,
        "remaining_fuzz_seconds": 295,
    }
    assert _row(
        isolated_database,
        "SELECT count(*) FROM budget_ledger WHERE family_id = %s",
        (family_id,),
    )[0] == 1, "raising caps inserted or dropped a budget ledger row"


def test_freeze_plan_rejects_unsupported_admission_predicate_version(
    isolated_database,
):
    family_id, child_id = _freeze_seed(
        isolated_database, _family_request("guided")
    )
    body = deepcopy(GUIDED_ENVELOPE_BODY)
    body["admission_predicate_version"] = "admission-v999"
    digest = jsonutil.digest_json(body)
    plan = _v2_plan(family_id, round_no=None, envelope_digest=digest)
    plan_digest = contracts.plan_digest(plan)

    with pytest.raises(state.StateError, match="admission_predicate_version"):
        state.freeze_plan(
            isolated_database.dsn,
            child_id,
            generation=1,
            plan=plan,
            plan_digest=plan_digest,
            summary={},
            envelope=body,
        )
    _assert_no_freeze_rows(isolated_database, family_id, child_id)


def test_charge_step_budget_concurrent_with_propose_envelope_and_record_review_no_deadlock(
    isolated_database, tmp_path, monkeypatch
):
    monkeypatch.setenv("DATACON_EVIDENCE_ROOT", str(tmp_path / "evidence"))
    seed = _seed_family(
        isolated_database,
        first_approval=True,
        pending_envelope=None,
        child_state="RUNNING",
        lease=True,
    )
    family_id = seed["family_id"]
    child_id = seed["child_id"]
    state.initialize_budget_ledger(
        isolated_database.dsn,
        family_id,
        max_total_seconds=900,
        max_fuzz_seconds=300,
    )

    for i in range(20):
        non_tightening = deepcopy(GUIDED_ENVELOPE_BODY)
        non_tightening["max_total_seconds"] = 900
        non_tightening["max_fuzz_seconds"] = 300
        non_tightening["mutation_limits"]["max_input_bytes"] = 4095 - i
        tightened = deepcopy(GUIDED_ENVELOPE_BODY)
        tightened["max_total_seconds"] = 899 - i
        tightened["max_fuzz_seconds"] = 299 - i

        # 1. Concurrent non-tightening propose_envelope + charge_step_budget
        #    on a RUNNING child.
        barrier = threading.Barrier(2)
        results: dict[str, object] = {}
        errors: list[BaseException] = []

        def run_propose() -> None:
            try:
                barrier.wait(timeout=10)
                results["propose"] = state.propose_envelope(
                    isolated_database.dsn, family_id, non_tightening
                )
            except BaseException as error:  # pragma: no cover - surfaced below
                errors.append(error)

        def run_charge() -> None:
            try:
                barrier.wait(timeout=10)
                results["charge"] = state.charge_step_budget(
                    isolated_database.dsn,
                    generation=1,
                    family_id=family_id,
                    job_id=child_id,
                    step_key=f"propose-race-{i}",
                    attempt_no=1,
                    charge_kind="general",
                    elapsed_seconds=1,
                )
            except BaseException as error:  # pragma: no cover - surfaced below
                errors.append(error)

        threads = [
            threading.Thread(target=run_propose),
            threading.Thread(target=run_charge),
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=30)
            assert not thread.is_alive(), (
                f"propose+charge iteration {i} deadlocked"
            )

        assert not errors, f"propose+charge iteration {i} failed: {errors!r}"
        proposed = results["propose"]
        assert isinstance(proposed, dict)
        assert proposed["status"] == "pending"
        assert results["charge"].status == "charged"  # type: ignore[attr-defined]
        pending_digest = proposed["envelope_digest"]

        # 2. Concurrent record_review(approve) + charge_step_budget on the same
        #    RUNNING child.
        barrier = threading.Barrier(2)
        results = {}
        errors = []

        def run_approve() -> None:
            try:
                barrier.wait(timeout=10)
                results["review"] = state.record_review(
                    isolated_database.dsn,
                    family_id,
                    plan_digest=FIRST_PLAN_DIGEST,
                    decision="approve",
                    reviewer_id=REVIEWER_2,
                    envelope_digest=pending_digest,
                )
            except BaseException as error:  # pragma: no cover - surfaced below
                errors.append(error)

        def run_charge_review() -> None:
            try:
                barrier.wait(timeout=10)
                results["charge"] = state.charge_step_budget(
                    isolated_database.dsn,
                    generation=1,
                    family_id=family_id,
                    job_id=child_id,
                    step_key=f"review-race-{i}",
                    attempt_no=1,
                    charge_kind="general",
                    elapsed_seconds=1,
                )
            except BaseException as error:  # pragma: no cover - surfaced below
                errors.append(error)

        threads = [
            threading.Thread(target=run_approve),
            threading.Thread(target=run_charge_review),
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=30)
            assert not thread.is_alive(), (
                f"review+charge iteration {i} deadlocked"
            )

        assert not errors, f"review+charge iteration {i} failed: {errors!r}"
        assert results["review"].status == "applied"  # type: ignore[attr-defined]
        assert results["charge"].status == "charged"  # type: ignore[attr-defined]

        # 3. Concurrent tightening propose_envelope (must be rejected while
        #    child is RUNNING) + charge_step_budget: zero deadlock and active
        #    child non-tightening invariant holds.
        barrier = threading.Barrier(2)
        results = {}
        tighten_errors: list[BaseException] = []
        charge_errors: list[BaseException] = []

        def run_tighten_propose() -> None:
            try:
                barrier.wait(timeout=10)
                results["tighten"] = state.propose_envelope(
                    isolated_database.dsn, family_id, tightened
                )
            except BaseException as error:  # noqa: BLE001 - asserted below
                tighten_errors.append(error)

        def run_charge_tighten() -> None:
            try:
                barrier.wait(timeout=10)
                results["charge"] = state.charge_step_budget(
                    isolated_database.dsn,
                    generation=1,
                    family_id=family_id,
                    job_id=child_id,
                    step_key=f"tighten-race-{i}",
                    attempt_no=1,
                    charge_kind="general",
                    elapsed_seconds=1,
                )
            except BaseException as error:  # pragma: no cover - surfaced below
                charge_errors.append(error)

        threads = [
            threading.Thread(target=run_tighten_propose),
            threading.Thread(target=run_charge_tighten),
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=30)
            assert not thread.is_alive(), (
                f"tighten+charge iteration {i} deadlocked"
            )

        assert not charge_errors, (
            f"tighten+charge iteration {i} charge failed: {charge_errors!r}"
        )
        assert results["charge"].status == "charged"  # type: ignore[attr-defined]
        assert len(tighten_errors) == 1
        assert isinstance(tighten_errors[0], state.StateError)
        assert "RUNNING" in str(tighten_errors[0])
        assert (
            _row(
                isolated_database,
                "SELECT count(*) FROM family_envelopes "
                "WHERE family_id = %s AND status = 'pending'",
                (family_id,),
            )[0]
            == 0
        )

        expected_spent = 3 * (i + 1)
        summary = state.family_budget_summary(isolated_database.dsn, family_id)
        assert summary == {
            "max_total_seconds": 900,
            "max_fuzz_seconds": 300,
            "spent_seconds": expected_spent,
            "spent_fuzz_seconds": 0,
            "remaining_seconds": 900 - expected_spent,
            "remaining_fuzz_seconds": 300,
        }


@pytest.mark.parametrize("active_state", ["RUNNING", "ARCHIVING"])
@pytest.mark.parametrize(
    ("tightened_total", "tightened_fuzz"),
    [
        (600, 300),
        (900, 200),
    ],
)
def test_reapproval_rejects_budget_tightening_while_child_active(
    isolated_database,
    tmp_path,
    monkeypatch,
    active_state,
    tightened_total,
    tightened_fuzz,
):
    monkeypatch.setenv("DATACON_EVIDENCE_ROOT", str(tmp_path / "evidence"))
    seed = _seed_family(
        isolated_database,
        first_approval=True,
        pending_envelope=None,
        child_state=active_state,
    )
    family_id = seed["family_id"]
    child_id = seed["child_id"]
    state.initialize_budget_ledger(
        isolated_database.dsn,
        family_id,
        max_total_seconds=900,
        max_fuzz_seconds=300,
    )
    _insert_envelope(
        isolated_database,
        family_id,
        ENVELOPE_2,
        status_name="pending",
        review_deadline_at=seed["deadline"],
        max_total_seconds=tightened_total,
        max_fuzz_seconds=tightened_fuzz,
    )

    # Hold FOR UPDATE on the active child on another connection to also verify
    # §9.1: changed-envelope re-approval only locks the family row and must not
    # lock child rows.
    with psycopg.connect(isolated_database.dsn, connect_timeout=5) as holder:
        holder.execute(
            "SELECT job_id FROM jobs WHERE job_id = %s FOR UPDATE",
            (child_id,),
        )
        with pytest.raises(state.StateError, match="RUNNING|ARCHIVING"):
            state.record_review(
                isolated_database.dsn,
                family_id,
                plan_digest=FIRST_PLAN_DIGEST,
                decision="approve",
                reviewer_id=REVIEWER_2,
                envelope_digest=ENVELOPE_2,
            )
        holder.rollback()

    ledger = state.load_budget_ledger(isolated_database.dsn, family_id)
    assert ledger is not None
    assert ledger["max_total_seconds"] == 900
    assert ledger["max_fuzz_seconds"] == 300
    assert ledger["remaining_total_seconds"] == 900
    assert ledger["remaining_fuzz_seconds"] == 300
    assert _row(
        isolated_database,
        "SELECT count(*) FROM family_approvals WHERE family_id = %s",
        (family_id,),
    )[0] == 1
    assert _row(
        isolated_database,
        "SELECT status FROM family_envelopes "
        "WHERE family_id = %s AND envelope_digest = %s",
        (family_id, ENVELOPE_2),
    )[0] == "pending"
    assert _row(
        isolated_database,
        "SELECT count(*) FROM audit_events "
        "WHERE job_id = %s AND event_type = 'review_recorded'",
        (family_id,),
    )[0] == 0


def test_freeze_plan_rejects_non_mapping_envelope_with_state_error(
    isolated_database,
):
    family_id, child_id = _freeze_seed(
        isolated_database, _family_request("guided")
    )
    digest = jsonutil.digest_json(GUIDED_ENVELOPE_BODY)
    plan = _v2_plan(family_id, round_no=None, envelope_digest=digest)
    plan_digest = contracts.plan_digest(plan)

    for bad_envelope in (123, "not-a-mapping", [("mode", "guided")]):
        with pytest.raises(state.StateError, match="envelope is invalid"):
            state.freeze_plan(
                isolated_database.dsn,
                child_id,
                generation=1,
                plan=plan,
                plan_digest=plan_digest,
                summary={},
                envelope=bad_envelope,  # type: ignore[arg-type]
            )
    _assert_no_freeze_rows(isolated_database, family_id, child_id)

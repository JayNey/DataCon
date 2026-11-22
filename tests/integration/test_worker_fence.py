"""D38/D40/D43 T10: v1/v2 worker fence, COMPLETED convergence, v1 read scope.

The rollback fence is a drain gate: while a v2 non-terminal job exists the v1
control plane may not take over, so every test here asserts that the gate sees
the residual row and blocks the switch. ``finish_execution`` and
``complete_family`` are the two no-shared-lease convergence paths.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import uuid4

import pytest
from psycopg.types.json import Jsonb

from datacon import release, state

pytestmark = pytest.mark.postgres

ROOT = Path(__file__).resolve().parents[2]
LATEST_MIGRATION = sorted((ROOT / "migrations").glob("*.sql"))[-1].name
DIGEST = "sha256:" + "a" * 64
OTHER_DIGEST = "sha256:" + "b" * 64
V2_NON_TERMINAL_STATES = [
    "QUEUED",
    "PREPARING",
    "AWAITING_REVIEW",
    "AGGREGATING",
    "READY",
    "RUNNING",
    "ARCHIVING",
]


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _insert_family(database, *, state_name="AGGREGATING", workflow_synced=True):
    family_id = uuid4()
    database.connection.execute(
        "INSERT INTO jobs (job_id, request, state, stage, submitted_at, "
        "job_contract_version, family_id, job_kind, parent_job_id, round_no, "
        "workflow_synced) VALUES (%s, %s, %s, 'family', clock_timestamp(), 2, "
        "%s, 'family', NULL, NULL, %s)",
        (family_id, Jsonb({"schema_version": 2}), state_name, family_id, workflow_synced),
    )
    return family_id


def _insert_child(
    database,
    family_id,
    *,
    state_name,
    round_no=1,
    workflow_synced=True,
    generation=1,
    lease_owner=None,
    lease_expires_at=None,
    verdict=None,
    reason_code=None,
    evidence_status=None,
    evidence_path=None,
    evidence_digest=None,
    submitted_at=None,
):
    job_id = uuid4()
    database.connection.execute(
        "INSERT INTO jobs (job_id, request, state, stage, submitted_at, "
        "job_contract_version, family_id, job_kind, parent_job_id, round_no, "
        "workflow_synced, generation, lease_owner, lease_expires_at, verdict, "
        "reason_code, evidence_status, evidence_path, evidence_digest) "
        "VALUES (%s, %s, %s, 'execute', %s, 2, %s, 'round', %s, %s, %s, %s, "
        "%s, %s, %s, %s, %s, %s, %s)",
        (
            job_id,
            Jsonb({"schema_version": 2}),
            state_name,
            submitted_at or _now(),
            family_id,
            family_id,
            round_no,
            workflow_synced,
            generation,
            lease_owner,
            lease_expires_at,
            verdict,
            reason_code,
            evidence_status,
            evidence_path,
            evidence_digest,
        ),
    )
    return job_id


def _delete_job(database, job_id):
    database.connection.execute("DELETE FROM jobs WHERE job_id = %s", (job_id,))


def _assert_drain_gate_blocks(database):
    store_handle = state.ReleaseStore(database.dsn)
    active_slots = store_handle.active_slots()
    assert active_slots >= 1, "v1 worker claimed a v2 non-terminal job"
    with pytest.raises(release.ReleaseGateError, match="not drained"):
        release._require_drained(store_handle, action="rollback")


def test_v1_worker_cannot_claim_v2_non_terminal_job(isolated_database):
    family_id = _insert_family(isolated_database)
    try:
        _assert_drain_gate_blocks(isolated_database)
        assert (
            state.ReleaseStore(isolated_database.dsn).active_slots() == 1
        ), "v1 worker claimed a v2 non-terminal job"
    finally:
        _delete_job(isolated_database, family_id)


def test_rollback_gate_drains_every_v2_non_terminal_state(isolated_database):
    store_handle = state.ReleaseStore(isolated_database.dsn)
    for state_name in V2_NON_TERMINAL_STATES:
        family_id = _insert_family(
            isolated_database,
            state_name="AGGREGATING" if state_name == "AGGREGATING" else "COMPLETED",
            workflow_synced=True,
        )
        child_id = None
        if state_name != "AGGREGATING":
            child_id = _insert_child(
                isolated_database,
                family_id,
                state_name=state_name,
                workflow_synced=True,
            )
        try:
            assert store_handle.active_slots() == 1, (
                f"rollback gate ignored a non-terminal v2 state: {state_name}"
            )
            with pytest.raises(release.ReleaseGateError, match="not drained"):
                release._require_drained(store_handle, action="rollback")
        finally:
            if child_id is not None:
                _delete_job(isolated_database, child_id)
            _delete_job(isolated_database, family_id)
        assert store_handle.active_slots() == 0

    family_id = _insert_family(isolated_database, state_name="COMPLETED")
    _insert_child(
        isolated_database,
        family_id,
        state_name="BLOCKED",
        workflow_synced=False,
        reason_code="REVIEW_REJECTED",
    )
    try:
        assert store_handle.active_slots() == 1, (
            "rollback gate ignored an unsynced BLOCKED v2 state"
        )
        with pytest.raises(release.ReleaseGateError, match="not drained"):
            release._require_drained(store_handle, action="rollback")
    finally:
        isolated_database.connection.execute(
            "DELETE FROM jobs WHERE parent_job_id = %s", (family_id,)
        )
        _delete_job(isolated_database, family_id)


def test_v1_worker_cannot_claim_v2_awaiting_review(isolated_database):
    family_id = _insert_family(isolated_database, state_name="AGGREGATING")
    child_id = _insert_child(
        isolated_database,
        family_id,
        state_name="AWAITING_REVIEW",
        workflow_synced=False,
    )
    try:
        _assert_drain_gate_blocks(isolated_database)
    finally:
        _delete_job(isolated_database, child_id)
        _delete_job(isolated_database, family_id)


def test_v1_worker_cannot_claim_v2_unsynced_blocked(isolated_database):
    family_id = _insert_family(isolated_database, state_name="AGGREGATING")
    child_id = _insert_child(
        isolated_database,
        family_id,
        state_name="BLOCKED",
        workflow_synced=False,
        reason_code="REVIEW_REJECTED",
    )
    store_handle = state.ReleaseStore(isolated_database.dsn)
    try:
        assert store_handle.active_slots() == 1, (
            "v1 worker claimed an unsynced BLOCKED v2 job"
        )
        with pytest.raises(release.ReleaseGateError, match="not drained"):
            release._require_drained(store_handle, action="rollback")

        isolated_database.connection.execute(
            "UPDATE jobs SET workflow_synced = true WHERE job_id = %s",
            (child_id,),
        )
        assert store_handle.active_slots() == 0, (
            "a synced BLOCKED v2 job was treated as a rollback residual"
        )
    finally:
        _delete_job(isolated_database, child_id)
        _delete_job(isolated_database, family_id)


def test_finish_execution_accepts_completed_terminal(isolated_database, tmp_path):
    family_id = _insert_family(isolated_database)
    child_id = _insert_child(
        isolated_database,
        family_id,
        state_name="RUNNING",
        generation=3,
        lease_owner="worker-p1",
        lease_expires_at=_now() + timedelta(minutes=10),
    )

    finished = state.finish_execution(
        isolated_database.dsn,
        child_id,
        generation=3,
        state="COMPLETED",
        reason_code=None,
        verdict=None,
        verdict_reason=None,
        evidence_status="archived",
        evidence_path=str(tmp_path / "campaign.json"),
        evidence_digest=DIGEST,
        stage="done",
    )
    assert finished is True, "finish_execution rejected COMPLETED"

    child_row = isolated_database.connection.execute(
        "SELECT state, verdict, reason_code, evidence_status, evidence_digest "
        "FROM jobs WHERE job_id = %s",
        (child_id,),
    ).fetchone()
    assert child_row == ("COMPLETED", None, None, "archived", DIGEST)

    family_path = tmp_path / "family.json"
    family_path.write_text('{"kind":"family_index","rounds":[]}', encoding="utf-8")
    completed = state.complete_family(
        isolated_database.dsn,
        family_id,
        str(family_path),
        OTHER_DIGEST,
    )
    assert completed is True, "complete_family did not converge AGGREGATING -> COMPLETED"
    family_row = isolated_database.connection.execute(
        "SELECT state, verdict, reason_code, evidence_status, evidence_path, "
        "evidence_digest FROM jobs WHERE job_id = %s",
        (family_id,),
    ).fetchone()
    assert family_row == (
        "COMPLETED",
        None,
        None,
        "archived",
        str(family_path),
        OTHER_DIGEST,
    ), "family COMPLETED left the evidence pointer null"
    assert state.claim_next(isolated_database.dsn, "worker-p1") is None, (
        "claim_next claimed a COMPLETED job"
    )


def test_rolled_back_v1_reads_only_v1_era_evidence(isolated_database, tmp_path):
    evidence_root = tmp_path / "evidence"
    v1_bundle = evidence_root / "v1" / "generation-1"
    v2_bundle = evidence_root / "v2" / "generation-1"
    v1_bundle.mkdir(parents=True)
    v2_bundle.mkdir(parents=True)

    store_handle = state.ReleaseStore(isolated_database.dsn)
    store_handle.bootstrap_release(
        image_id="sha256:" + "8" * 64,
        config={"policy_version": "1"},
        migration_version=LATEST_MIGRATION,
        evidence_root=str(evidence_root),
    )

    v1_job = uuid4()
    isolated_database.connection.execute(
        "INSERT INTO jobs (job_id, request, state, submitted_at, verdict, "
        "verdict_reason, evidence_status, evidence_path, evidence_digest) "
        "VALUES (%s, %s, 'REPRODUCED', %s, 'REPRODUCED', "
        "'ASAN_SIGNATURE_MATCHED', 'archived', %s, %s)",
        (
            v1_job,
            Jsonb({"schema_version": 1}),
            _now() - timedelta(hours=2),
            str(v1_bundle),
            DIGEST,
        ),
    )
    family_id = _insert_family(isolated_database, state_name="COMPLETED")
    isolated_database.connection.execute(
        "UPDATE jobs SET state = 'COMPLETED', verdict = NULL, reason_code = NULL, "
        "evidence_status = 'archived', evidence_path = %s, evidence_digest = %s, "
        "submitted_at = %s WHERE job_id = %s",
        (str(v2_bundle), OTHER_DIGEST, _now(), family_id),
    )

    found = store_handle.latest_evidence_bundle(strict=True)
    assert found is not None
    assert Path(found["path"]).resolve() == v1_bundle.resolve(), (
        "v1 control plane read v2 evidence"
    )

"""TDD integration tests for T08 / TC-10 promotion, rollback, and old evidence readability."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from uuid import UUID

import pytest

from datacon import evidence, execution, release, state, store
from support import review, status, submit, worker, write_request
from test_execution import FakeSandbox

pytestmark = pytest.mark.postgres

PREVIOUS_IMAGE = "sha256:" + "8" * 64
CANDIDATE_IMAGE = "sha256:" + "1" * 64


def _now() -> str:
    return (
        datetime.now(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )


def _approval(manifest: dict) -> dict:
    return {
        "approved_by": "release-maintainer",
        "approved_at": _now(),
        "candidate_digest": release.canonical_manifest_digest(manifest),
        "ci_passed": True,
        "contract_version": 1,
        "migration_compatible": True,
    }


def _manifest() -> dict:
    return release.build_release_candidate_manifest(
        source_commit="b" * 40,
        control_plane_image_id=CANDIDATE_IMAGE,
        wheel_digest="sha256:" + "2" * 64,
        migrations_dir=Path(__file__).resolve().parents[2] / "migrations",
        sbom_digest="sha256:" + "3" * 64,
        test_report_digest="sha256:" + "4" * 64,
        scan_report_digest="sha256:" + "5" * 64,
    )


def test_promotion_and_rollback_change_the_persisted_active_release(
    isolated_database, tmp_path, monkeypatch
):
    evidence_root = tmp_path / "evidence"
    run_root = tmp_path / "runs"
    monkeypatch.setenv("DATACON_EVIDENCE_ROOT", str(evidence_root))
    monkeypatch.setenv("DATACON_RUN_ROOT", str(run_root))
    monkeypatch.delenv("DATACON_JOURNAL_SECRET_FILE", raising=False)
    monkeypatch.delenv("DATACON_FAULT_AFTER_TOOL", raising=False)

    # 1. Completed job with archived evidence bundle before release upgrade.
    exec_dir = tmp_path / "exec"
    exec_dir.mkdir()
    completed = submit(
        isolated_database.dsn, write_request(exec_dir, case_id="fixture-c-parser")
    )
    completed_job_id = UUID(completed["job_id"])
    worker(isolated_database.dsn)
    approved_digest = status(isolated_database.dsn, completed["job_id"])["pending_plan"][
        "plan_digest"
    ]
    accepted = review(
        isolated_database.dsn,
        completed["job_id"],
        approved_digest,
        "approve",
        env_extra={"DATACON_OPERATOR_ID": "reviewer-1"},
    )
    assert accepted.returncode == 0, accepted.stderr
    worker(isolated_database.dsn)
    claimed = state.claim_next(isolated_database.dsn, "release-rollback-test")
    assert claimed is not None and claimed["state"] == "RUNNING"

    exec_outcome = execution.run_execution(
        isolated_database.dsn,
        completed_job_id,
        claimed["generation"],
        run_root=run_root,
        sandbox=FakeSandbox(),
    )
    assert exec_outcome.state == "REPRODUCED"

    before_status = store.status(isolated_database.dsn, completed_job_id)
    assert before_status is not None
    assert before_status["verdict"] == "REPRODUCED"
    assert before_status["evidence"]["available"] is True

    # 2. AWAITING_REVIEW job with frozen plan before upgrade.
    pending_dir = tmp_path / "pending"
    pending_dir.mkdir()
    pending = submit(
        isolated_database.dsn, write_request(pending_dir, case_id="fixture-c-parser")
    )
    pending_job_id = UUID(pending["job_id"])
    worker(isolated_database.dsn)
    pending_before = store.status(isolated_database.dsn, pending_job_id)
    assert pending_before is not None
    assert pending_before["state"] == "AWAITING_REVIEW"
    pending_digest = pending_before["pending_plan"]["plan_digest"]

    store_handle = state.ReleaseStore(isolated_database.dsn)
    previous = {
        "image_id": PREVIOUS_IMAGE,
        "config": {"policy_version": "1"},
        "migration_version": "007_execution_evidence_invariant.sql",
        "evidence_root": str(evidence_root),
    }
    store_handle.bootstrap_release(
        image_id=previous["image_id"],
        config=previous["config"],
        migration_version=previous["migration_version"],
        evidence_root=previous["evidence_root"],
    )
    manifest = _manifest()
    approval = _approval(manifest)

    def rollback_fn(prev):
        store_handle.switch(
            image_id=prev["image_id"],
            config=prev["config"],
            migration_version=prev["migration_version"],
            evidence_root=prev["evidence_root"],
            action="rollback",
            candidate_digest=approval["candidate_digest"],
        )
        return {"restored_image": prev["image_id"], "ok": True}

    # 3. Failed candidate smoke triggers a real rollback switch.
    outcome = release.promote_and_smoke(
        manifest=manifest,
        expected_manifest_digest=approval["candidate_digest"],
        approval=approval,
        backend=store_handle,
        smoke_checks={
            "cli_smoke": lambda: True,
            "db_readability": lambda: (
                store.status(isolated_database.dsn, completed_job_id) is not None
            ),
            "sandbox_probe": lambda: False,
            "synthetic_regression": lambda: True,
        },
        rollback_fn=rollback_fn,
    )
    assert outcome["status"] == "rolled_back"
    rolled_back = store_handle.active_release()
    assert rolled_back is not None
    assert rolled_back["image_id"] == previous["image_id"]
    assert rolled_back["migration_version"] == previous["migration_version"]
    assert rolled_back["config"] == previous["config"]
    assert [event["action"] for event in store_handle.events()] == ["bootstrap", "rollback"]

    # 4. A clean promotion switches the active image and is idempotent.
    promoted = release.promote_and_smoke(
        manifest=manifest,
        expected_manifest_digest=approval["candidate_digest"],
        approval=approval,
        backend=store_handle,
        smoke_checks={"cli_smoke": lambda: True},
        rollback_fn=rollback_fn,
    )
    assert promoted["status"] == "promoted"
    active = store_handle.active_release()
    assert active is not None
    assert active["image_id"] == CANDIDATE_IMAGE
    assert active["migration_version"] == manifest["migration_version"]
    events_after_promote = store_handle.events()
    assert [event["action"] for event in events_after_promote] == ["bootstrap", "rollback", "promote"]

    repeated = release.promote_and_smoke(
        manifest=manifest,
        expected_manifest_digest=approval["candidate_digest"],
        approval=approval,
        backend=store_handle,
        smoke_checks={"cli_smoke": lambda: True},
        rollback_fn=rollback_fn,
    )
    assert repeated == promoted
    assert store_handle.events() == events_after_promote

    # 5. An explicit rollback restores the previous image, config and migration.
    target = store_handle.release_for_image(PREVIOUS_IMAGE)
    assert target is not None
    assert target["config"] == previous["config"]
    rolled_back_again = release.rollback_release(
        target_release=target,
        backend=store_handle,
        smoke_checks={"cli_smoke": lambda: True},
        approved_by="reviewer-1",
        candidate_digest="sha256:" + "6" * 64,
    )
    assert rolled_back_again["status"] == "rolled_back"
    restored = store_handle.active_release()
    assert restored is not None
    assert restored["image_id"] == PREVIOUS_IMAGE
    assert restored["migration_version"] == previous["migration_version"]
    assert restored["config"] == previous["config"]

    # 6. TC-10 post-rollback invariants: pending plan, old review, and archived bundle still readable/verifiable.
    pending_after = store.status(isolated_database.dsn, pending_job_id)
    assert pending_after is not None
    assert pending_after["state"] == "AWAITING_REVIEW"
    assert pending_after["pending_plan"]["plan_digest"] == pending_digest

    old_review = state.get_review(isolated_database.dsn, completed_job_id)
    assert old_review is not None
    assert old_review["decision"] == "approve"

    after_status = store.status(isolated_database.dsn, completed_job_id)
    assert after_status is not None
    assert after_status["verdict"] == "REPRODUCED"
    assert after_status["evidence"]["available"] is True
    verified = evidence.verify_bundle(after_status["evidence"]["path"])
    assert verified.manifest_digest == after_status["evidence"]["digest"]

    exported = evidence.export_bundle(
        after_status["evidence"]["path"],
        tmp_path / "exported-after-rollback",
        expected_manifest_digest=after_status["evidence"]["digest"],
    )
    assert exported.manifest_digest == after_status["evidence"]["digest"]


def _manifest_with(image_id: str, commit: str) -> dict:
    return release.build_release_candidate_manifest(
        source_commit=commit,
        control_plane_image_id=image_id,
        wheel_digest="sha256:" + "2" * 64,
        migrations_dir=Path(__file__).resolve().parents[2] / "migrations",
        sbom_digest="sha256:" + "3" * 64,
        test_report_digest="sha256:" + "4" * 64,
        scan_report_digest="sha256:" + "5" * 64,
    )


def test_multiple_rollbacks_and_repeated_smoke_failures_preserve_all_audit_events(
    isolated_database,
):
    store_handle = state.ReleaseStore(isolated_database.dsn)
    baseline = {
        "image_id": PREVIOUS_IMAGE,
        "config": {"policy_version": "1"},
        "migration_version": "007_execution_evidence_invariant.sql",
        "evidence_root": "/var/lib/datacon/evidence",
    }
    store_handle.bootstrap_release(**baseline)

    m1_image = "sha256:" + "1" * 64
    m2_image = "sha256:" + "2" * 64
    m3_image = "sha256:" + "3" * 64
    m1 = _manifest_with(m1_image, "b" * 40)
    m2 = _manifest_with(m2_image, "c" * 40)
    m3 = _manifest_with(m3_image, "d" * 40)

    def make_rollback(candidate_digest: str):
        def _rb(prev):
            store_handle.switch(
                image_id=prev["image_id"],
                config=prev["config"],
                migration_version=prev["migration_version"],
                evidence_root=prev["evidence_root"],
                action="rollback",
                candidate_digest=candidate_digest,
            )
            return {"restored_image": prev["image_id"], "ok": True}

        return _rb

    # I0 -> promote(M1) -> rollback(I0) -> promote(M2) -> rollback(I0)
    a1 = _approval(m1)
    assert (
        release.promote_and_smoke(
            manifest=m1,
            expected_manifest_digest=a1["candidate_digest"],
            approval=a1,
            backend=store_handle,
            smoke_checks={"cli_smoke": lambda: True},
            rollback_fn=make_rollback(a1["candidate_digest"]),
        )["status"]
        == "promoted"
    )
    target_i0 = store_handle.release_for_image(PREVIOUS_IMAGE)
    assert target_i0 is not None
    assert (
        release.rollback_release(
            target_release=target_i0,
            backend=store_handle,
            smoke_checks={"cli_smoke": lambda: True},
            approved_by="reviewer-1",
            candidate_digest=PREVIOUS_IMAGE,
        )["status"]
        == "rolled_back"
    )

    a2 = _approval(m2)
    assert (
        release.promote_and_smoke(
            manifest=m2,
            expected_manifest_digest=a2["candidate_digest"],
            approval=a2,
            backend=store_handle,
            smoke_checks={"cli_smoke": lambda: True},
            rollback_fn=make_rollback(a2["candidate_digest"]),
        )["status"]
        == "promoted"
    )
    target_i0_again = store_handle.release_for_image(PREVIOUS_IMAGE)
    assert target_i0_again is not None
    assert (
        release.rollback_release(
            target_release=target_i0_again,
            backend=store_handle,
            smoke_checks={"cli_smoke": lambda: True},
            approved_by="reviewer-1",
            candidate_digest=PREVIOUS_IMAGE,
        )["status"]
        == "rolled_back"
    )

    events = store_handle.events()
    rollbacks = [e for e in events if e["action"] == "rollback"]
    assert len(rollbacks) == 2
    assert rollbacks[0]["previous_image_id"] == m1_image
    assert rollbacks[0]["active_image_id"] == PREVIOUS_IMAGE
    assert rollbacks[1]["previous_image_id"] == m2_image
    assert rollbacks[1]["active_image_id"] == PREVIOUS_IMAGE

    # Same candidate M3 fails smoke twice in a row -> both rollback audits persisted.
    a3 = _approval(m3)
    for _ in range(2):
        res = release.promote_and_smoke(
            manifest=m3,
            expected_manifest_digest=a3["candidate_digest"],
            approval=a3,
            backend=store_handle,
            smoke_checks={"cli_smoke": lambda: False},
            rollback_fn=make_rollback(a3["candidate_digest"]),
        )
        assert res["status"] == "rolled_back"

    events_after_smoke = store_handle.events()
    m3_rollbacks = [
        e
        for e in events_after_smoke
        if e["action"] == "rollback" and e["candidate_digest"] == a3["candidate_digest"]
    ]
    assert len(m3_rollbacks) == 2
    assert all(e["active_image_id"] == PREVIOUS_IMAGE for e in m3_rollbacks)

    # Subsequent clean promotion of M3 succeeds.
    assert (
        release.promote_and_smoke(
            manifest=m3,
            expected_manifest_digest=a3["candidate_digest"],
            approval=a3,
            backend=store_handle,
            smoke_checks={"cli_smoke": lambda: True},
            rollback_fn=make_rollback(a3["candidate_digest"]),
        )["status"]
        == "promoted"
    )


def test_release_store_transaction_rolls_back_switch_when_audit_fails(
    isolated_database, monkeypatch
):
    store_handle = state.ReleaseStore(isolated_database.dsn)
    store_handle.bootstrap_release(
        image_id=PREVIOUS_IMAGE,
        config={"policy_version": "1"},
        migration_version="007_execution_evidence_invariant.sql",
        evidence_root="/var/lib/datacon/evidence",
    )
    manifest = _manifest()
    approval = _approval(manifest)

    def broken_audit(_result):
        raise RuntimeError("simulated audit write failure")

    monkeypatch.setattr(store_handle, "record_audit", broken_audit)
    with pytest.raises(RuntimeError, match="simulated audit write failure"):
        release.promote_and_smoke(
            manifest=manifest,
            expected_manifest_digest=approval["candidate_digest"],
            approval=approval,
            backend=store_handle,
            smoke_checks={"cli_smoke": lambda: True},
            rollback_fn=lambda prev: {"restored_image": prev["image_id"], "ok": True},
        )
    active = store_handle.active_release()
    assert active is not None
    assert active["image_id"] == PREVIOUS_IMAGE
    assert [event["action"] for event in store_handle.events()] == ["bootstrap"]


def test_migration_008_upgrades_legacy_unique_constraint_idempotently(
    isolated_database,
):
    migration_sql = (
        Path(__file__).resolve().parents[2] / "migrations" / "008_release_events.sql"
    ).read_text(encoding="utf-8")
    isolated_database.connection.execute(
        "DROP INDEX IF EXISTS release_events_promote_unique_idx"
    )
    isolated_database.connection.execute(
        "ALTER TABLE release_events "
        "ADD CONSTRAINT release_events_environment_action_candidate_digest_key "
        "UNIQUE (environment, action, candidate_digest)"
    )
    isolated_database.connection.execute(migration_sql)
    isolated_database.connection.execute(migration_sql)
    old_constraint = isolated_database.connection.execute(
        "SELECT 1 FROM pg_constraint "
        "WHERE conrelid = 'release_events'::regclass "
        "AND conname = 'release_events_environment_action_candidate_digest_key'"
    ).fetchone()
    assert old_constraint is None
    new_index = isolated_database.connection.execute(
        "SELECT 1 FROM pg_indexes "
        "WHERE schemaname = current_schema() "
        "AND tablename = 'release_events' "
        "AND indexname = 'release_events_promote_unique_idx'"
    ).fetchone()
    assert new_index is not None


def test_release_for_image_skips_a_malformed_but_valid_looking_event(
    isolated_database,
):
    import uuid as uuid_mod

    store_handle = state.ReleaseStore(isolated_database.dsn)
    baseline = {
        "image_id": PREVIOUS_IMAGE,
        "config": {"policy_version": "1"},
        "migration_version": "007_execution_evidence_invariant.sql",
        "evidence_root": "/var/lib/datacon/evidence",
    }
    store_handle.bootstrap_release(**baseline)
    # A newer row with a structurally valid envelope but an unusable payload
    # must not become rollback provenance.
    isolated_database.connection.execute(
        "INSERT INTO release_events "
        "(event_id, environment, action, status, candidate_digest, "
        "manifest_digest, previous_image_id, active_image_id, payload) "
        "VALUES (%s, %s, 'rollback', 'rolled_back', %s, %s, NULL, %s, %s)",
        (
            uuid_mod.uuid4(),
            state.RELEASE_ENVIRONMENT,
            "sha256:" + "a" * 64,
            "sha256:" + "b" * 64,
            PREVIOUS_IMAGE,
            "{}",
        ),
    )
    record = store_handle.release_for_image(PREVIOUS_IMAGE)
    assert record is not None
    assert record["config"] == baseline["config"]
    assert record["evidence_root"] == baseline["evidence_root"]
    assert record["manifest_digest"].startswith("sha256:")


def test_migration_008_is_idempotent_with_existing_release_events(isolated_database):
    store_handle = state.ReleaseStore(isolated_database.dsn)
    baseline = {
        "image_id": PREVIOUS_IMAGE,
        "config": {"policy_version": "1"},
        "migration_version": "007_execution_evidence_invariant.sql",
        "evidence_root": "/var/lib/datacon/evidence",
    }
    store_handle.bootstrap_release(**baseline)
    manifest = _manifest_with(CANDIDATE_IMAGE, "b" * 40)
    approval = _approval(manifest)
    promoted = release.promote_and_smoke(
        manifest=manifest,
        expected_manifest_digest=approval["candidate_digest"],
        approval=approval,
        backend=store_handle,
        smoke_checks={"cli_smoke": lambda: True},
        rollback_fn=lambda prev: {
            "restored_image": prev["image_id"],
            "ok": True,
        },
    )
    assert promoted["status"] == "promoted"
    before = store_handle.events()
    assert [event["action"] for event in before] == ["bootstrap", "promote"]

    migration_sql = (
        Path(__file__).resolve().parents[2]
        / "migrations"
        / "008_release_events.sql"
    ).read_text(encoding="utf-8")
    isolated_database.connection.execute(migration_sql)
    isolated_database.connection.execute(migration_sql)

    assert store_handle.events() == before
    assert store_handle.active_release()["image_id"] == CANDIDATE_IMAGE
    bootstrap_index = isolated_database.connection.execute(
        "SELECT 1 FROM pg_indexes "
        "WHERE schemaname = current_schema() AND tablename = 'release_events' "
        "AND indexname = 'release_events_bootstrap_unique_idx'"
    ).fetchone()
    assert bootstrap_index is not None
    ledger_rows = isolated_database.connection.execute(
        "SELECT count(*) FROM schema_migrations"
    ).fetchone()[0]
    assert ledger_rows == len(
        list((Path(__file__).resolve().parents[2] / "migrations").glob("*.sql"))
    )


def test_bootstrap_is_idempotent_and_rejects_a_conflicting_baseline(
    isolated_database,
):
    store_handle = state.ReleaseStore(isolated_database.dsn)
    baseline = {
        "image_id": PREVIOUS_IMAGE,
        "config": {"policy_version": "1"},
        "migration_version": "007_execution_evidence_invariant.sql",
        "evidence_root": "/var/lib/datacon/evidence",
    }
    store_handle.bootstrap_release(**baseline)
    first = store_handle.events()
    store_handle.bootstrap_release(**baseline)
    assert store_handle.events() == first
    with pytest.raises(state.ReleaseStateError, match="conflicts"):
        store_handle.bootstrap_release(
            image_id="sha256:" + "1" * 64,
            config={"policy_version": "1"},
            migration_version="007_execution_evidence_invariant.sql",
            evidence_root="/var/lib/datacon/evidence",
        )

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
        "migration_version": "008_release_events.sql",
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
        "migration_version": "008_release_events.sql",
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
    i0_candidate_digest = target_i0.get("candidate_digest") or target_i0["manifest_digest"]
    assert (
        release.rollback_release(
            target_release=target_i0,
            backend=store_handle,
            smoke_checks={"cli_smoke": lambda: True},
            approved_by="reviewer-1",
            candidate_digest=i0_candidate_digest,
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
    i0_candidate_digest_again = (
        target_i0_again.get("candidate_digest") or target_i0_again["manifest_digest"]
    )
    assert (
        release.rollback_release(
            target_release=target_i0_again,
            backend=store_handle,
            smoke_checks={"cli_smoke": lambda: True},
            approved_by="reviewer-1",
            candidate_digest=i0_candidate_digest_again,
        )["status"]
        == "rolled_back"
    )

    events = store_handle.events()
    rollbacks = [e for e in events if e["action"] == "rollback"]
    assert len(rollbacks) == 2
    assert rollbacks[0]["previous_image_id"] == m1_image
    assert rollbacks[0]["active_image_id"] == PREVIOUS_IMAGE
    assert rollbacks[0]["candidate_digest"] == i0_candidate_digest
    assert rollbacks[0]["candidate_digest"] != PREVIOUS_IMAGE
    assert rollbacks[1]["previous_image_id"] == m2_image
    assert rollbacks[1]["active_image_id"] == PREVIOUS_IMAGE
    assert rollbacks[1]["candidate_digest"] == i0_candidate_digest_again

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
        migration_version="008_release_events.sql",
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
        "migration_version": "008_release_events.sql",
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
        "migration_version": "008_release_events.sql",
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
        "migration_version": "008_release_events.sql",
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
            migration_version="008_release_events.sql",
            evidence_root="/var/lib/datacon/evidence",
        )


def test_bootstrap_rejects_migration_not_in_schema_migrations(
    isolated_database, postgres_dsn
):
    import psycopg
    from psycopg import sql
    from psycopg.conninfo import conninfo_to_dict, make_conninfo
    import uuid as uuid_mod

    store_handle = state.ReleaseStore(isolated_database.dsn)
    with pytest.raises(state.ReleaseStateError, match="schema_migrations"):
        store_handle.bootstrap_release(
            image_id=PREVIOUS_IMAGE,
            config={"policy_version": "1"},
            migration_version="099_missing_migration.sql",
            evidence_root="/var/lib/datacon/evidence",
        )
    assert store_handle.active_release() is None

    # A schema where schema_migrations does not exist at all must also fail closed.
    empty_schema = f"datacon_no_ledger_{uuid_mod.uuid4().hex}"
    with psycopg.connect(postgres_dsn, autocommit=True, connect_timeout=5) as admin:
        admin.execute(sql.SQL("CREATE SCHEMA {}").format(sql.Identifier(empty_schema)))
    try:
        params = conninfo_to_dict(postgres_dsn)
        params["options"] = f"-csearch_path={empty_schema}"
        empty_dsn = make_conninfo(**params)
        no_ledger_store = state.ReleaseStore(empty_dsn)
        with pytest.raises(state.ReleaseStateError, match="schema_migrations"):
            no_ledger_store.bootstrap_release(
                image_id=PREVIOUS_IMAGE,
                config={"policy_version": "1"},
                migration_version="008_release_events.sql",
                evidence_root="/var/lib/datacon/evidence",
            )
    finally:
        with psycopg.connect(postgres_dsn, autocommit=True, connect_timeout=5) as admin:
            admin.execute(
                sql.SQL("DROP SCHEMA IF EXISTS {} CASCADE").format(
                    sql.Identifier(empty_schema)
                )
            )


def test_replaying_promoted_manifest_after_rollback_fails_closed(isolated_database):
    store_handle = state.ReleaseStore(isolated_database.dsn)
    store_handle.bootstrap_release(
        image_id=PREVIOUS_IMAGE,
        config={"policy_version": "1"},
        migration_version="008_release_events.sql",
        evidence_root="/var/lib/datacon/evidence",
    )
    m1 = _manifest_with(CANDIDATE_IMAGE, "b" * 40)
    a1 = _approval(m1)
    promoted = release.promote_and_smoke(
        manifest=m1,
        expected_manifest_digest=a1["candidate_digest"],
        approval=a1,
        backend=store_handle,
        smoke_checks={"cli_smoke": lambda: True},
        rollback_fn=lambda prev: {"restored_image": prev["image_id"], "ok": True},
    )
    assert promoted["status"] == "promoted"

    target = store_handle.release_for_image(PREVIOUS_IMAGE)
    assert target is not None
    rolled_back = release.rollback_release(
        target_release=target,
        backend=store_handle,
        smoke_checks={"cli_smoke": lambda: True},
        approved_by="reviewer-1",
        candidate_digest=target.get("candidate_digest") or target["manifest_digest"],
    )
    assert rolled_back["status"] == "rolled_back"

    with pytest.raises(release.ReleaseGateError, match="stale approval"):
        release.promote_and_smoke(
            manifest=m1,
            expected_manifest_digest=a1["candidate_digest"],
            approval=a1,
            backend=store_handle,
            smoke_checks={"cli_smoke": lambda: True},
            rollback_fn=lambda prev: {"restored_image": prev["image_id"], "ok": True},
        )
    active = store_handle.active_release()
    assert active is not None
    assert active["image_id"] == PREVIOUS_IMAGE


def test_cli_migrate_and_release_bootstrap_end_to_end(postgres_dsn):
    import json
    import psycopg
    from psycopg import sql
    from psycopg.conninfo import conninfo_to_dict, make_conninfo
    import uuid as uuid_mod
    from support import cli

    schema = f"datacon_cli_rel_{uuid_mod.uuid4().hex}"
    migrations_dir = Path(__file__).resolve().parents[2] / "migrations"
    with psycopg.connect(postgres_dsn, autocommit=True, connect_timeout=5) as admin:
        admin.execute(sql.SQL("CREATE SCHEMA {}").format(sql.Identifier(schema)))
    try:
        params = conninfo_to_dict(postgres_dsn)
        params["options"] = f"-csearch_path={schema}"
        schema_dsn = make_conninfo(**params)

        mig = cli(
            "migrate",
            "--migrations-dir",
            str(migrations_dir),
            database_url=schema_dsn,
        )
        assert mig.returncode == 0, mig.stderr
        mig_out = json.loads(mig.stdout)
        assert "008_release_events.sql" in mig_out["applied"]

        boot = cli(
            "release",
            "bootstrap",
            "--image-id",
            PREVIOUS_IMAGE,
            "--migration-version",
            "008_release_events.sql",
            "--evidence-root",
            "/var/lib/datacon/evidence",
            "--config",
            '{"policy_version":"1"}',
            database_url=schema_dsn,
        )
        assert boot.returncode == 0, boot.stderr
        boot_out = json.loads(boot.stdout)
        assert boot_out["baseline"] is True
        assert boot_out["image_id"] == PREVIOUS_IMAGE

        bad_env = cli(
            "release",
            "bootstrap",
            "--environment",
            "staging",
            "--image-id",
            PREVIOUS_IMAGE,
            "--migration-version",
            "008_release_events.sql",
            "--evidence-root",
            "/var/lib/datacon/evidence",
            database_url=schema_dsn,
        )
        assert bad_env.returncode == 2

        slots = cli("release", "slots", database_url=schema_dsn)
        assert slots.returncode == 0, slots.stderr
        slots_out = json.loads(slots.stdout)
        assert slots_out["active_release"]["image_id"] == PREVIOUS_IMAGE
    finally:
        with psycopg.connect(postgres_dsn, autocommit=True, connect_timeout=5) as admin:
            admin.execute(
                sql.SQL("DROP SCHEMA IF EXISTS {} CASCADE").format(
                    sql.Identifier(schema)
                )
            )


def test_latest_evidence_bundle_validates_containment_and_rejects_symlinks(
    isolated_database, tmp_path
):
    import uuid as uuid_mod
    from psycopg.types.json import Jsonb

    evidence_root = tmp_path / "evidence-root"
    evidence_root.mkdir()
    outside_dir = tmp_path / "outside-bundle"
    outside_dir.mkdir()
    valid_bundle = evidence_root / str(uuid_mod.uuid4()) / "generation-1"
    valid_bundle.mkdir(parents=True)

    store_handle = state.ReleaseStore(isolated_database.dsn)
    store_handle.bootstrap_release(
        image_id=PREVIOUS_IMAGE,
        config={"policy_version": "1"},
        migration_version="008_release_events.sql",
        evidence_root=str(evidence_root),
    )

    def _insert_archived_job(bundle_path: str):
        jid = uuid_mod.uuid4()
        digest = "sha256:" + "a" * 64
        isolated_database.connection.execute(
            "INSERT INTO jobs "
            "(job_id, request, state, stage, workflow_synced, evidence_status, "
            "evidence_path, evidence_digest, verdict, verdict_reason, submitted_at) "
            "VALUES (%s, %s, 'REPRODUCED', 'done', true, 'archived', %s, %s, "
            "'REPRODUCED', 'ASAN_SIGNATURE_MATCHED', clock_timestamp())",
            (jid, Jsonb({"schema_version": 1}), bundle_path, digest),
        )
        return jid

    # 1. Valid path inside evidence_root succeeds.
    _insert_archived_job(str(valid_bundle))
    latest = store_handle.latest_evidence_bundle()
    assert latest is not None
    assert Path(latest["path"]).resolve() == valid_bundle.resolve()

    # 2. Symlink inside evidence_root is rejected.
    sym_bundle = evidence_root / "sym-job"
    sym_bundle.symlink_to(outside_dir)
    _insert_archived_job(str(sym_bundle / "generation-1"))
    with pytest.raises(state.ReleaseStateError, match="symlink|evidence_path"):
        store_handle.latest_evidence_bundle()

    # 3. Parent traversal '..' is rejected.
    _insert_archived_job(str(evidence_root / ".." / "outside-bundle"))
    with pytest.raises(state.ReleaseStateError, match="evidence_path|escape"):
        store_handle.latest_evidence_bundle()

    # 4. Path completely outside evidence_root is rejected.
    _insert_archived_job(str(outside_dir))
    with pytest.raises(state.ReleaseStateError, match="evidence_path|inside"):
        store_handle.latest_evidence_bundle()


def test_promote_and_smoke_on_release_store_rejects_noop_rollback_fn(
    isolated_database,
):
    store_handle = state.ReleaseStore(isolated_database.dsn)
    store_handle.bootstrap_release(
        image_id=PREVIOUS_IMAGE,
        config={"policy_version": "1"},
        migration_version="008_release_events.sql",
        evidence_root="/var/lib/datacon/evidence",
    )
    manifest = _manifest()
    approval = _approval(manifest)
    with pytest.raises(release.ReleaseGateError, match="did not restore|state transition"):
        release.promote_and_smoke(
            manifest=manifest,
            expected_manifest_digest=approval["candidate_digest"],
            approval=approval,
            backend=store_handle,
            smoke_checks={"cli_smoke": lambda: False},
            rollback_fn=lambda prev: {"restored_image": prev["image_id"], "ok": True},
        )
    active = store_handle.active_release()
    assert active is not None
    assert active["image_id"] == PREVIOUS_IMAGE


def test_bootstrap_cli_on_unmigrated_schema_exits_2_and_rejects_stale_migration(
    isolated_database, postgres_dsn
):
    import json
    import psycopg
    from psycopg import sql
    from psycopg.conninfo import conninfo_to_dict, make_conninfo
    import uuid as uuid_mod
    from support import cli

    # S-5: On a database migrated through 008, passing 007 must fail closed.
    store_handle = state.ReleaseStore(isolated_database.dsn)
    with pytest.raises(state.ReleaseStateError, match="behind|latest|schema_migrations"):
        store_handle.bootstrap_release(
            image_id=PREVIOUS_IMAGE,
            config={"policy_version": "1"},
            migration_version="007_execution_evidence_invariant.sql",
            evidence_root="/var/lib/datacon/evidence",
        )
    assert store_handle.active_release() is None

    # B-1: CLI `release bootstrap` on an empty unmigrated schema must exit 2
    # (INVALID_RELEASE_STATE), not 1 (DATABASE_ERROR from UndefinedTable).
    empty_schema = f"datacon_cli_unmigrated_{uuid_mod.uuid4().hex}"
    with psycopg.connect(postgres_dsn, autocommit=True, connect_timeout=5) as admin:
        admin.execute(sql.SQL("CREATE SCHEMA {}").format(sql.Identifier(empty_schema)))
    try:
        params = conninfo_to_dict(postgres_dsn)
        params["options"] = f"-csearch_path={empty_schema}"
        empty_dsn = make_conninfo(**params)
        res = cli(
            "release",
            "bootstrap",
            "--image-id",
            PREVIOUS_IMAGE,
            "--migration-version",
            "008_release_events.sql",
            "--evidence-root",
            "/var/lib/datacon/evidence",
            database_url=empty_dsn,
        )
        assert res.returncode == 2, res.stderr
        err = json.loads(res.stderr)
        assert err["reason_code"] == "INVALID_RELEASE_STATE"
        assert "schema_migrations" in err["message"]
    finally:
        with psycopg.connect(postgres_dsn, autocommit=True, connect_timeout=5) as admin:
            admin.execute(
                sql.SQL("DROP SCHEMA IF EXISTS {} CASCADE").format(
                    sql.Identifier(empty_schema)
                )
            )


def test_latest_evidence_bundle_handles_cross_generation_roots_and_rejects_relative_path(
    isolated_database, tmp_path
):
    import uuid as uuid_mod
    from psycopg.types.json import Jsonb

    root_v1 = tmp_path / "evidence-v1"
    root_v2 = tmp_path / "evidence-v2"
    root_v1.mkdir()
    root_v2.mkdir()
    bundle_v1 = root_v1 / str(uuid_mod.uuid4()) / "generation-1"
    bundle_v1.mkdir(parents=True)
    bundle_v2 = root_v2 / str(uuid_mod.uuid4()) / "generation-1"
    bundle_v2.mkdir(parents=True)
    unregistered = tmp_path / "unregistered-outside"
    unregistered.mkdir()

    store_handle = state.ReleaseStore(isolated_database.dsn)
    store_handle.bootstrap_release(
        image_id=PREVIOUS_IMAGE,
        config={"policy_version": "1"},
        migration_version="008_release_events.sql",
        evidence_root=str(root_v1),
    )

    def _insert_archived_job(bundle_path: str):
        jid = uuid_mod.uuid4()
        digest = "sha256:" + "a" * 64
        isolated_database.connection.execute(
            "INSERT INTO jobs "
            "(job_id, request, state, stage, workflow_synced, evidence_status, "
            "evidence_path, evidence_digest, verdict, verdict_reason, submitted_at) "
            "VALUES (%s, %s, 'REPRODUCED', 'done', true, 'archived', %s, %s, "
            "'REPRODUCED', 'ASAN_SIGNATURE_MATCHED', clock_timestamp())",
            (jid, Jsonb({"schema_version": 1}), bundle_path, digest),
        )
        return jid

    # Archive job under v1, then switch release_state to v2 (simulating cross-gen root).
    _insert_archived_job(str(bundle_v1))
    with store_handle.transaction():
        store_handle.switch(
            image_id=CANDIDATE_IMAGE,
            config={"policy_version": "2"},
            migration_version="008_release_events.sql",
            evidence_root=str(root_v2),
            action="promote",
            candidate_digest="sha256:" + "c" * 64,
        )
        store_handle.record_audit(
            {
                "status": "promoted",
                "candidate_digest": "sha256:" + "c" * 64,
                "manifest_digest": "sha256:" + "c" * 64,
                "active_image_id": CANDIDATE_IMAGE,
                "previous_image_id": PREVIOUS_IMAGE,
                "config": {"policy_version": "2"},
                "migration_version": "008_release_events.sql",
                "evidence_root": str(root_v2),
            }
        )

    # Cross-generation historical bundle in v1 does not brick v2 promotion.
    assert store_handle.latest_evidence_bundle() is None

    # Once a bundle is archived in v2, it is returned; if a newer v1 bundle arrives,
    # latest_evidence_bundle still returns the v2 bundle.
    _insert_archived_job(str(bundle_v2))
    latest_v2 = store_handle.latest_evidence_bundle()
    assert latest_v2 is not None
    assert Path(latest_v2["path"]).resolve() == bundle_v2.resolve()

    _insert_archived_job(str(bundle_v1))
    latest_still_v2 = store_handle.latest_evidence_bundle()
    assert latest_still_v2 is not None
    assert Path(latest_still_v2["path"]).resolve() == bundle_v2.resolve()

    # Relative path is rejected instead of silently re-rooted under root_v2.
    _insert_archived_job(".datacon/evidence/job-rel/generation-1")
    with pytest.raises(state.ReleaseStateError, match="relative|absolute|evidence_path"):
        store_handle.latest_evidence_bundle()

    # Unregistered outside path still fails closed.
    _insert_archived_job(str(unregistered))
    with pytest.raises(state.ReleaseStateError, match="inside|evidence_path"):
        store_handle.latest_evidence_bundle()


def test_smoke_failure_auto_rollback_does_not_pollute_release_for_image_provenance(
    isolated_database,
):
    store_handle = state.ReleaseStore(isolated_database.dsn)
    store_handle.bootstrap_release(
        image_id=PREVIOUS_IMAGE,
        config={"policy_version": "1"},
        migration_version="008_release_events.sql",
        evidence_root="/var/lib/datacon/evidence",
    )
    m1_image = "sha256:" + "1" * 64
    m2_image = "sha256:" + "2" * 64
    m1 = _manifest_with(m1_image, "b" * 40)
    m2 = _manifest_with(m2_image, "c" * 40)
    a1 = _approval(m1)
    a2 = _approval(m2)

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

    # 1. Promote M1 successfully.
    p1 = release.promote_and_smoke(
        manifest=m1,
        expected_manifest_digest=a1["candidate_digest"],
        approval=a1,
        backend=store_handle,
        smoke_checks={"cli_smoke": lambda: True},
        rollback_fn=make_rollback(a1["candidate_digest"]),
    )
    assert p1["status"] == "promoted"

    # 2. Promote M2 fails smoke -> auto-rolls back to M1 (writing M2's digest/commit on rollback event).
    rb_m2 = release.promote_and_smoke(
        manifest=m2,
        expected_manifest_digest=a2["candidate_digest"],
        approval=a2,
        backend=store_handle,
        smoke_checks={"cli_smoke": lambda: False},
        rollback_fn=make_rollback(a2["candidate_digest"]),
    )
    assert rb_m2["status"] == "rolled_back"
    assert rb_m2["active_image_id"] == m1_image

    # 3. release_for_image(M1) must return M1's own promote provenance, NOT M2's failed rollback!
    m1_record = store_handle.release_for_image(m1_image)
    assert m1_record is not None
    assert m1_record["candidate_digest"] == a1["candidate_digest"]
    assert m1_record["manifest_digest"] == a1["candidate_digest"]
    assert m1_record["source_commit"] == "b" * 40


def test_release_store_transaction_sets_timeouts_and_rejects_fake_promote_rollback(
    isolated_database,
):
    store_handle = state.ReleaseStore(isolated_database.dsn)
    store_handle.bootstrap_release(
        image_id=PREVIOUS_IMAGE,
        config={"policy_version": "1"},
        migration_version="008_release_events.sql",
        evidence_root="/var/lib/datacon/evidence",
    )

    with store_handle.transaction() as conn:
        lock_to = conn.execute("SHOW lock_timeout").fetchone()["lock_timeout"]
        stmt_to = conn.execute("SHOW statement_timeout").fetchone()["statement_timeout"]
        assert lock_to != "0"
        assert stmt_to != "0"

    manifest = _manifest()
    approval = _approval(manifest)

    def fake_promote_rollback(prev):
        store_handle.switch(
            image_id=prev["image_id"],
            config=prev["config"],
            migration_version=prev["migration_version"],
            evidence_root=prev["evidence_root"],
            action="promote",
            candidate_digest=approval["candidate_digest"],
        )
        return {"restored_image": prev["image_id"], "ok": True}

    with pytest.raises(release.ReleaseGateError, match="state transition"):
        release.promote_and_smoke(
            manifest=manifest,
            expected_manifest_digest=approval["candidate_digest"],
            approval=approval,
            backend=store_handle,
            smoke_checks={"cli_smoke": lambda: False},
            rollback_fn=fake_promote_rollback,
        )
    active = store_handle.active_release()
    assert active is not None
    assert active["image_id"] == PREVIOUS_IMAGE
    assert [event["action"] for event in store_handle.events()] == ["bootstrap"]


def test_rollback_release_rejects_target_equal_to_active_in_postgres(
    isolated_database,
):
    store_handle = state.ReleaseStore(isolated_database.dsn)
    baseline = {
        "image_id": PREVIOUS_IMAGE,
        "config": {"policy_version": "1"},
        "migration_version": "008_release_events.sql",
        "evidence_root": "/var/lib/datacon/evidence",
    }
    store_handle.bootstrap_release(**baseline)
    target = store_handle.release_for_image(PREVIOUS_IMAGE)
    assert target is not None

    with pytest.raises(release.ReleaseGateError, match="already the active release"):
        release.rollback_release(
            target_release=target,
            backend=store_handle,
            smoke_checks={"cli_smoke": lambda: True},
            post_switch_checks={"active_release_restored": lambda: True},
            approved_by="reviewer-1",
            candidate_digest=target["candidate_digest"],
            manifest_digest=target["manifest_digest"],
        )

    active = store_handle.active_release()
    assert active is not None
    assert active["image_id"] == PREVIOUS_IMAGE
    assert active["config"] == baseline["config"]
    assert [event["action"] for event in store_handle.events()] == ["bootstrap"]


def test_latest_evidence_bundle_strict_requires_active_root_bundle(
    isolated_database, tmp_path
):
    import uuid as uuid_mod
    from psycopg.types.json import Jsonb

    evidence_root = tmp_path / "strict-evidence"
    evidence_root.mkdir()
    store_handle = state.ReleaseStore(isolated_database.dsn)
    store_handle.bootstrap_release(
        image_id=PREVIOUS_IMAGE,
        config={"policy_version": "1"},
        migration_version="008_release_events.sql",
        evidence_root=str(evidence_root),
    )

    assert store_handle.latest_evidence_bundle(strict=False) is None
    with pytest.raises(state.ReleaseStateError, match="no archived evidence bundle"):
        store_handle.latest_evidence_bundle(strict=True)

    bundle_dir = evidence_root / str(uuid_mod.uuid4()) / "generation-1"
    bundle_dir.mkdir(parents=True)
    digest = "sha256:" + "a" * 64
    isolated_database.connection.execute(
        "INSERT INTO jobs "
        "(job_id, request, state, stage, workflow_synced, evidence_status, "
        "evidence_path, evidence_digest, verdict, verdict_reason, submitted_at) "
        "VALUES (%s, %s, 'REPRODUCED', 'done', true, 'archived', %s, %s, "
        "'REPRODUCED', 'ASAN_SIGNATURE_MATCHED', clock_timestamp())",
        (uuid_mod.uuid4(), Jsonb({"schema_version": 1}), str(bundle_dir), digest),
    )

    found = store_handle.latest_evidence_bundle(strict=True)
    assert found is not None
    assert Path(found["path"]).resolve() == bundle_dir.resolve()
    assert found["digest"] == digest


def test_all_release_store_entrypoints_and_slots_cli_fail_closed_on_unmigrated_db(
    postgres_dsn,
):
    import json
    import psycopg
    from psycopg import sql
    from psycopg.conninfo import conninfo_to_dict, make_conninfo
    import uuid as uuid_mod
    from support import cli

    empty_schema = f"datacon_unmigrated_all_{uuid_mod.uuid4().hex}"
    with psycopg.connect(postgres_dsn, autocommit=True, connect_timeout=5) as admin:
        admin.execute(sql.SQL("CREATE SCHEMA {}").format(sql.Identifier(empty_schema)))
    try:
        params = conninfo_to_dict(postgres_dsn)
        params["options"] = f"-csearch_path={empty_schema}"
        empty_dsn = make_conninfo(**params)

        unmigrated = state.ReleaseStore(empty_dsn)
        for call in (
            unmigrated.active_slots,
            unmigrated.active_release,
            unmigrated.events,
            unmigrated.latest_evidence_bundle,
            lambda: unmigrated.promotion_for("sha256:" + "a" * 64),
            lambda: unmigrated.release_for_image("sha256:" + "a" * 64),
        ):
            with pytest.raises(state.ReleaseStateError, match="datacon migrate"):
                call()

        slots = cli(
            "release",
            "slots",
            "--environment",
            "internal-lab",
            database_url=empty_dsn,
        )
        assert slots.returncode == 2, slots.stderr
        err = json.loads(slots.stderr)
        assert err["reason_code"] == "INVALID_RELEASE_STATE"
        assert "datacon migrate" in err["message"]
    finally:
        with psycopg.connect(postgres_dsn, autocommit=True, connect_timeout=5) as admin:
            admin.execute(
                sql.SQL("DROP SCHEMA IF EXISTS {} CASCADE").format(
                    sql.Identifier(empty_schema)
                )
            )

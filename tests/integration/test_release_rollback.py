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
    assert [event["action"] for event in store_handle.events()] == ["rollback"]

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
    assert [event["action"] for event in events_after_promote] == ["rollback", "promote"]

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

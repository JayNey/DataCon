"""TDD integration tests for T08 / TC-10 promotion, rollback, and old evidence readability."""

from __future__ import annotations

from pathlib import Path
from uuid import UUID

import psycopg
import pytest

from datacon import evidence, execution, release, state, store
from support import review, status, submit, worker, write_request
from test_execution import FakeSandbox

pytestmark = pytest.mark.postgres


def test_rollback_preserves_awaiting_review_approved_review_and_old_evidence(
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

    # 3. Simulate failed candidate deployment (smoke failure) triggering rollback.
    previous = {
        "image_digest": "sha256:" + "8" * 64,
        "config": {"policy_version": "1"},
        "migration_version": "007_execution_evidence_invariant.sql",
        "evidence_root": str(evidence_root),
    }
    manifest = release.build_release_candidate_manifest(
        source_commit="b" * 40,
        control_plane_image_digest="sha256:" + "1" * 64,
        wheel_digest="sha256:" + "2" * 64,
        toolchain_image_digest="sha256:f5ce959d91f059acf5a4b3f1c19f46713c4b2881c7d7cd1d5143ca1d1412277f",
        migrations_dir=Path(__file__).resolve().parents[2] / "migrations",
        sbom_digest="sha256:" + "3" * 64,
        test_report_digest="sha256:" + "4" * 64,
        scan_report_digest="sha256:" + "5" * 64,
    )
    candidate_digest = release.canonical_manifest_digest(manifest)
    approval = {
        "approved_by": "release-maintainer",
        "approved_at": "2026-11-17T11:45:00Z",
        "candidate_digest": candidate_digest,
        "ci_passed": True,
        "contract_version": 1,
        "migration_compatible": True,
    }

    with psycopg.connect(isolated_database.dsn) as conn:
        active_slots = conn.execute(
            "SELECT COUNT(*) FROM jobs WHERE state IN ('PREPARING', 'RUNNING', 'ARCHIVING')"
        ).fetchone()[0]

    outcome = release.promote_and_smoke(
        manifest=manifest,
        expected_manifest_digest=candidate_digest,
        approval=approval,
        previous_release=previous,
        active_slots=active_slots,
        smoke_checks={
            "cli_smoke": lambda: True,
            "db_readability": lambda: (
                store.status(isolated_database.dsn, completed_job_id) is not None
            ),
            "sandbox_probe": lambda: False,
            "synthetic_regression": lambda: True,
        },
        rollback_fn=lambda prev: {"restored_image": prev["image_digest"], "ok": True},
    )
    assert outcome["status"] == "rolled_back"

    # 4. TC-10 post-rollback invariants: pending plan, old review, and archived bundle still readable/verifiable.
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

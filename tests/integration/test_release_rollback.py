"""TDD integration tests for T08 / TC-10 promotion, rollback, and old evidence readability."""

from __future__ import annotations

import json
from pathlib import Path
from uuid import UUID

import psycopg
import pytest

from datacon import evidence, release, state, store
from datacon.contracts import DEFAULT_LIMITS, parse_request
from tests.integration.support import clear_jobs_table, make_executed_job

pytestmark = pytest.mark.postgres


def test_rollback_preserves_awaiting_review_approved_review_and_old_evidence(
    db_dsn, tmp_path, monkeypatch
):
    clear_jobs_table(db_dsn)
    evidence_root = tmp_path / "evidence"
    run_root = tmp_path / "runs"
    secret_file = tmp_path / "journal-secret"
    monkeypatch.setenv("DATACON_EVIDENCE_ROOT", str(evidence_root))
    monkeypatch.setenv("DATACON_RUN_ROOT", str(run_root))
    monkeypatch.setenv("DATACON_JOURNAL_SECRET_FILE", str(secret_file))

    # 1. Completed job with archived evidence bundle before release upgrade.
    completed_job_id, _ = make_executed_job(db_dsn, tmp_path / "exec")
    before_status = store.status(db_dsn, completed_job_id)
    assert before_status["verdict"] == "REPRODUCED"
    assert before_status["evidence"]["available"] is True

    # 2. AWAITING_REVIEW job with frozen plan before upgrade.
    pending_req = parse_request(
        json.dumps(
            {
                "schema_version": 1,
                "cve_id": "CVE-2099-0001",
                "target": {
                    "kind": "source",
                    "case_id": "fixture-c-parser",
                    "goal": "pending review before release",
                },
                "limits": dict(DEFAULT_LIMITS),
            }
        )
    )
    pending_submitted = store.submit(db_dsn, pending_req, operator_id="ops-user")
    pending_job_id = UUID(pending_submitted["job_id"])
    from datacon import workflow

    workflow.run_worker(db_dsn, once=True, execute=False, run_root=str(run_root))
    pending_before = store.status(db_dsn, pending_job_id)
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

    with psycopg.connect(db_dsn) as conn:
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
            "db_readability": lambda: store.status(db_dsn, completed_job_id) is not None,
            "sandbox_probe": lambda: False,
            "synthetic_regression": lambda: True,
        },
        rollback_fn=lambda prev: {"restored_image": prev["image_digest"], "ok": True},
    )
    assert outcome["status"] == "rolled_back"

    # 4. TC-10 post-rollback invariants: pending plan, old review, and archived bundle still readable/verifiable.
    pending_after = store.status(db_dsn, pending_job_id)
    assert pending_after["state"] == "AWAITING_REVIEW"
    assert pending_after["pending_plan"]["plan_digest"] == pending_digest

    old_review = state.get_review(db_dsn, completed_job_id)
    assert old_review is not None
    assert old_review["decision"] == "approve"

    after_status = store.status(db_dsn, completed_job_id)
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

"""Static contract checks for the dedicated B03 acceptance migration."""

from __future__ import annotations

import hashlib
from pathlib import Path

from datacon import release, state

ROOT = Path(__file__).resolve().parents[2]
MIGRATION = ROOT / "migrations" / "009_b03_acceptance.sql"


def test_009_is_pinned_by_the_rollback_compatibility_map():
    digest = "sha256:" + hashlib.sha256(MIGRATION.read_bytes()).hexdigest()
    assert (
        release.ROLLBACK_COMPATIBLE_MIGRATIONS["009_b03_acceptance.sql"] == digest
    ), "ROLLBACK_COMPATIBLE_MIGRATIONS must pin the exact 009 file"


def test_009_is_a_serialized_idempotent_additive_table():
    sql = MIGRATION.read_text(encoding="utf-8")
    assert sql.startswith("BEGIN;")
    assert sql.rstrip().endswith("COMMIT;")
    assert "pg_advisory_xact_lock" in sql
    assert sql.index("pg_advisory_xact_lock") < sql.index(
        "CREATE TABLE IF NOT EXISTS b03_acceptance"
    )
    assert "CREATE TABLE IF NOT EXISTS b03_acceptance" in sql
    assert "PRIMARY KEY (environment, candidate_digest)" in sql
    assert "CHECK (status = 'passed')" in sql
    for column in (
        "environment",
        "candidate_digest",
        "control_plane_image_id",
        "b03_bundle_manifest_digest",
        "storage_ref",
        "run_id",
        "status",
        "accepted_at timestamptz",
        "payload jsonb",
    ):
        assert column in sql, column
    for constraint in (
        "b03_acceptance_candidate_digest_check",
        "b03_acceptance_control_plane_image_id_check",
        "b03_acceptance_bundle_manifest_digest_check",
    ):
        assert f"CONSTRAINT {constraint}" in sql, constraint
    # The new ledger must not widen the existing release_events action/status
    # CHECK constraints.
    executable = "\n".join(
        line.split("--", 1)[0] for line in sql.splitlines()
    )
    assert "release_events" not in executable
    assert "ALTER TABLE" not in executable


def test_release_store_exposes_the_b03_methods():
    assert hasattr(state.ReleaseStore, "record_b03_acceptance")
    assert hasattr(state.ReleaseStore, "b03_acceptance_for")

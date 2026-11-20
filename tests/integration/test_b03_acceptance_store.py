"""PostgreSQL tests for the dedicated B03 acceptance ledger."""

from __future__ import annotations

from pathlib import Path

import psycopg
import pytest

from datacon import state

pytestmark = pytest.mark.postgres

ROOT = Path(__file__).resolve().parents[2]
MIGRATION_009 = ROOT / "migrations" / "009_b03_acceptance.sql"

IMAGE = "sha256:" + "1" * 64
CANDIDATE = "sha256:" + "2" * 64
BUNDLE = "sha256:" + "3" * 64


def _record(store: state.ReleaseStore, **overrides):
    values = dict(
        candidate_digest=CANDIDATE,
        control_plane_image_id=IMAGE,
        b03_bundle_manifest_digest=BUNDLE,
        storage_ref="vault://datacon/b03/" + CANDIDATE.removeprefix("sha256:"),
        run_id="1234567890",
        payload={"cve_id": "CVE-2019-13224", "verdict": "REPRODUCED"},
    )
    values.update(overrides)
    return store.record_b03_acceptance(**values)


def test_record_and_read_b03_acceptance(isolated_database):
    store = state.ReleaseStore(isolated_database.dsn)
    recorded = _record(store)
    assert recorded["environment"] == "internal-lab"
    assert recorded["candidate_digest"] == CANDIDATE
    assert recorded["control_plane_image_id"] == IMAGE
    assert recorded["b03_bundle_manifest_digest"] == BUNDLE
    assert recorded["status"] == "passed"
    assert recorded["payload"]["verdict"] == "REPRODUCED"
    assert recorded["accepted_at"]

    fetched = store.b03_acceptance_for(CANDIDATE)
    assert fetched == recorded

    # Repeating the exact same acceptance is a no-op, not a second row.
    repeated = _record(store)
    assert repeated == recorded
    assert (
        isolated_database.connection.execute(
            "SELECT count(*) FROM b03_acceptance"
        ).fetchone()[0]
        == 1
    )


def test_b03_acceptance_rejects_conflicts_and_bad_status(isolated_database):
    store = state.ReleaseStore(isolated_database.dsn)
    _record(store)

    with pytest.raises(state.ReleaseStateError, match="conflicts"):
        _record(store, b03_bundle_manifest_digest="sha256:" + "4" * 64)
    with pytest.raises(state.ReleaseStateError, match="conflicts"):
        _record(store, payload={"cve_id": "CVE-2019-13224", "verdict": "NOT_REPRODUCED"})
    with pytest.raises(state.ReleaseStateError, match="status must be 'passed'"):
        _record(store, candidate_digest="sha256:" + "9" * 64, status="failed")
    with pytest.raises(state.ReleaseStateError, match="sha256"):
        _record(store, candidate_digest="not-a-digest")
    with pytest.raises(state.ReleaseStateError, match="run_id"):
        _record(store, candidate_digest="sha256:" + "9" * 64, run_id="bad run id")


def test_b03_acceptance_fails_closed_without_table(isolated_database):
    store = state.ReleaseStore(isolated_database.dsn)
    isolated_database.connection.execute("DROP TABLE b03_acceptance")
    with pytest.raises(state.ReleaseStateError, match="b03_acceptance table is missing"):
        _record(store)
    with pytest.raises(state.ReleaseStateError, match="b03_acceptance table is missing"):
        store.b03_acceptance_for(CANDIDATE)


def test_b03_acceptance_missing_record_fails_closed(isolated_database):
    store = state.ReleaseStore(isolated_database.dsn)
    with pytest.raises(state.ReleaseStateError, match="no B03 acceptance record"):
        store.b03_acceptance_for(CANDIDATE)


def test_009_is_idempotent_and_enforces_constraints(isolated_database):
    connection = isolated_database.connection
    migration = MIGRATION_009.read_text(encoding="utf-8")
    seed_candidate = "sha256:" + "5" * 64
    connection.execute(
        "INSERT INTO b03_acceptance "
        "(environment, candidate_digest, control_plane_image_id, "
        "b03_bundle_manifest_digest, storage_ref, run_id, status, payload) "
        "VALUES ('internal-lab', %s, %s, %s, 'vault://datacon/b03/seed', "
        "'run-1', 'passed', '{}'::jsonb)",
        (seed_candidate, IMAGE, BUNDLE),
    )
    connection.execute(migration)
    connection.execute(migration)
    assert connection.execute(
        "SELECT count(*) FROM b03_acceptance WHERE candidate_digest = %s",
        (seed_candidate,),
    ).fetchone()[0] == 1

    primary_key = connection.execute(
        "SELECT pg_get_constraintdef(oid) FROM pg_constraint "
        "WHERE conrelid = 'b03_acceptance'::regclass "
        "AND contype = 'p'"
    ).fetchone()[0]
    assert "environment, candidate_digest" in primary_key

    with pytest.raises(psycopg.errors.CheckViolation):
        connection.execute(
            "INSERT INTO b03_acceptance "
            "(environment, candidate_digest, control_plane_image_id, "
            "b03_bundle_manifest_digest, storage_ref, run_id, status) "
            "VALUES ('internal-lab', %s, %s, %s, 'ref', 'run-2', 'failed')",
            ("sha256:" + "6" * 64, IMAGE, BUNDLE),
        )
    connection.execute("ROLLBACK")

    with pytest.raises(psycopg.errors.CheckViolation):
        connection.execute(
            "INSERT INTO b03_acceptance "
            "(environment, candidate_digest, control_plane_image_id, "
            "b03_bundle_manifest_digest, storage_ref, run_id, status) "
            "VALUES ('internal-lab', 'not-a-digest', %s, %s, 'ref', 'run-2', 'passed')",
            (IMAGE, BUNDLE),
        )
    connection.execute("ROLLBACK")

    with pytest.raises(psycopg.errors.UniqueViolation):
        connection.execute(
            "INSERT INTO b03_acceptance "
            "(environment, candidate_digest, control_plane_image_id, "
            "b03_bundle_manifest_digest, storage_ref, run_id, status) "
            "VALUES ('internal-lab', %s, %s, %s, 'ref', 'run-2', 'passed')",
            (seed_candidate, IMAGE, BUNDLE),
        )
    connection.execute("ROLLBACK")

    environment, candidate, image, bundle, storage, run_id, status, accepted_at = (
        connection.execute(
            "SELECT environment, candidate_digest, control_plane_image_id, "
            "b03_bundle_manifest_digest, storage_ref, run_id, status, accepted_at "
            "FROM b03_acceptance WHERE candidate_digest = %s",
            (seed_candidate,),
        ).fetchone()
    )
    assert (environment, candidate, image, bundle, storage, run_id, status) == (
        "internal-lab",
        seed_candidate,
        IMAGE,
        BUNDLE,
        "vault://datacon/b03/seed",
        "run-1",
        "passed",
    )
    assert accepted_at is not None

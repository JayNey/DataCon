import json
from hashlib import sha256
from pathlib import Path
from uuid import uuid4

import psycopg
import pytest
from psycopg import sql
from psycopg.types.json import Jsonb

from datacon import evidence, release

pytestmark = pytest.mark.postgres

ROOT = Path(__file__).resolve().parents[2]
MIGRATION = ROOT / "migrations" / "001_create_jobs.sql"

LEGACY_JOBS_DDL = """
CREATE TABLE jobs (
    job_id uuid PRIMARY KEY,
    request jsonb NOT NULL,
    state text NOT NULL DEFAULT 'QUEUED',
    submitted_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX jobs_queue_idx ON jobs (state, submitted_at);
"""


def _relation_kind(connection, schema_name, relation_name):
    row = connection.execute(
        "SELECT c.relkind FROM pg_class c "
        "JOIN pg_namespace n ON n.oid = c.relnamespace "
        "WHERE n.nspname = %s AND c.relname = %s",
        (schema_name, relation_name),
    ).fetchone()
    return row[0] if row is not None else None


def test_legacy_jobs_table_is_upgraded_in_isolated_schema(postgres_dsn):
    """Exercise the upgrade path from a jobs table that predates reason_code.

    The session ``database`` fixture already applies the latest migration to
    ``public.jobs``, so re-running the migration there cannot prove that an old
    table is upgraded. This test builds the previous schema in its own schema
    and never reads or writes ``public.jobs``.
    """
    schema_name = f"datacon_migration_{uuid4().hex}"
    sentinel_id = uuid4()
    sentinel_request = {
        "sentinel": "legacy-jobs-upgrade",
        "target": {"kind": "source"},
        "note": "旧表行必须保留",
    }
    migration_sql = MIGRATION.read_text(encoding="utf-8")

    with psycopg.connect(
        postgres_dsn, autocommit=True, connect_timeout=5
    ) as connection:
        connection.execute(
            sql.SQL("CREATE SCHEMA {}").format(sql.Identifier(schema_name))
        )
        try:
            connection.execute(
                sql.SQL("SET search_path TO {}").format(sql.Identifier(schema_name))
            )
            connection.execute(LEGACY_JOBS_DDL)
            connection.execute(
                "INSERT INTO jobs (job_id, request) VALUES (%s, %s)",
                (sentinel_id, Jsonb(sentinel_request)),
            )

            assert connection.execute(
                "SELECT 1 FROM information_schema.columns "
                "WHERE table_schema = %s AND table_name = 'jobs' "
                "AND column_name = 'reason_code'",
                (schema_name,),
            ).fetchone() is None, "legacy table must not have reason_code before migration"

            connection.execute(migration_sql)
            connection.execute(migration_sql)

            row = connection.execute(
                sql.SQL(
                    "SELECT request, state, reason_code FROM {}.jobs "
                    "WHERE job_id = %s"
                ).format(sql.Identifier(schema_name)),
                (sentinel_id,),
            ).fetchone()
            assert row is not None, "re-running the migration deleted the legacy job"
            request, state, reason_code = row
            assert request == sentinel_request
            assert state == "QUEUED"
            assert reason_code is None

            assert connection.execute(
                "SELECT data_type, is_nullable FROM information_schema.columns "
                "WHERE table_schema = %s AND table_name = 'jobs' "
                "AND column_name = 'reason_code'",
                (schema_name,),
            ).fetchone() == ("text", "YES")
            assert _relation_kind(connection, schema_name, "jobs") == "r"
            assert _relation_kind(connection, schema_name, "jobs_queue_idx") == "i"
        finally:
            connection.rollback()
            connection.execute(
                sql.SQL("DROP SCHEMA IF EXISTS {} CASCADE").format(
                    sql.Identifier(schema_name)
                )
            )


def test_migration_can_be_applied_repeatedly(database, postgres_dsn):
    migration_sql = MIGRATION.read_text(encoding="utf-8")
    sentinel_id = uuid4()
    sentinel_request = {"sentinel": "migration-must-preserve-existing-job"}
    database.execute(
        "INSERT INTO jobs (job_id, request) VALUES (%s, %s)",
        (sentinel_id, Jsonb(sentinel_request)),
    )

    try:
        before = database.execute("SELECT count(*) FROM jobs").fetchone()[0]

        with psycopg.connect(
            postgres_dsn, autocommit=True, connect_timeout=5
        ) as connection:
            connection.execute(migration_sql)
            connection.execute(migration_sql)

        row = database.execute(
            "SELECT request, state, reason_code FROM jobs WHERE job_id = %s",
            (sentinel_id,),
        ).fetchone()
        assert row is not None, "re-running the migration deleted an existing job"
        request, state, reason_code = row
        assert request == sentinel_request
        assert state == "QUEUED"
        assert reason_code is None

        assert database.execute("SELECT count(*) FROM jobs").fetchone()[0] == before
        assert (
            database.execute("SELECT to_regclass('public.jobs')").fetchone()[0]
            == "jobs"
        )
        assert (
            database.execute("SELECT to_regclass('public.jobs_queue_idx')").fetchone()[0]
            == "jobs_queue_idx"
        )
        assert database.execute(
            "SELECT data_type, is_nullable FROM information_schema.columns "
            "WHERE table_schema = 'public' AND table_name = 'jobs' "
            "AND column_name = 'reason_code'"
        ).fetchone() == ("text", "YES")
    finally:
        database.execute("DELETE FROM jobs WHERE job_id = %s", (sentinel_id,))


# --- T10: jobs v2 identity, migration registration and COMPLETED evidence ---


def _insert_identity_job(
    database,
    job_id,
    *,
    job_contract_version=2,
    job_kind="round",
    family_id=None,
    parent_job_id=None,
    round_no=1,
    state_name="QUEUED",
):
    database.connection.execute(
        "INSERT INTO jobs (job_id, request, state, submitted_at, "
        "job_contract_version, family_id, job_kind, parent_job_id, round_no) "
        "VALUES (%s, %s, %s, clock_timestamp(), %s, %s, %s, %s, %s)",
        (
            job_id,
            Jsonb({"schema_version": 2}),
            state_name,
            job_contract_version,
            family_id,
            job_kind,
            parent_job_id,
            round_no,
        ),
    )


def _insert_family(database):
    family_id = uuid4()
    _insert_identity_job(
        database,
        family_id,
        job_kind="family",
        family_id=family_id,
        parent_job_id=None,
        round_no=None,
        state_name="AGGREGATING",
    )
    return family_id


def test_jobs_parent_round_unique_rejects_duplicate(isolated_database):
    family_id = _insert_family(isolated_database)
    round_one = uuid4()
    _insert_identity_job(
        isolated_database,
        round_one,
        job_kind="round",
        family_id=family_id,
        parent_job_id=family_id,
        round_no=1,
    )
    with pytest.raises(
        psycopg.errors.UniqueViolation, match="jobs_parent_round_key"
    ):
        _insert_identity_job(
            isolated_database,
            uuid4(),
            job_kind="round",
            family_id=family_id,
            parent_job_id=family_id,
            round_no=1,
        )


def test_jobs_parent_round_checks_reject_half_null(isolated_database):
    family_id = _insert_family(isolated_database)
    half_null_rows = [
        # round with no round_no
        dict(
            job_kind="round",
            family_id=family_id,
            parent_job_id=family_id,
            round_no=None,
        ),
        # round with no parent
        dict(
            job_kind="round",
            family_id=None,
            parent_job_id=None,
            round_no=1,
        ),
        # v1 row carrying a v2 identity column
        dict(
            job_contract_version=1,
            job_kind=None,
            family_id=family_id,
            parent_job_id=None,
            round_no=None,
        ),
    ]
    for fields in half_null_rows:
        with pytest.raises(psycopg.errors.CheckViolation, match="jobs_"):
            _insert_identity_job(isolated_database, uuid4(), **fields)


def test_jobs_round_no_rejects_zero(isolated_database):
    family_id = _insert_family(isolated_database)
    with pytest.raises(psycopg.errors.CheckViolation, match="jobs_"):
        _insert_identity_job(
            isolated_database,
            uuid4(),
            job_kind="round",
            family_id=family_id,
            parent_job_id=family_id,
            round_no=0,
        )


def test_jobs_v2_identity_columns_cannot_all_be_null(isolated_database):
    with pytest.raises(psycopg.errors.CheckViolation, match="jobs_"):
        _insert_identity_job(
            isolated_database,
            uuid4(),
            job_contract_version=2,
            job_kind=None,
            family_id=None,
            parent_job_id=None,
            round_no=None,
        )


def test_jobs_rejects_self_parent(isolated_database):
    job_id = uuid4()
    with pytest.raises(psycopg.errors.CheckViolation, match="jobs_"):
        _insert_identity_job(
            isolated_database,
            job_id,
            job_kind="round",
            family_id=job_id,
            parent_job_id=job_id,
            round_no=1,
        )


def test_new_migration_sequence_register_rollback_compatibility(isolated_database):
    migrations = sorted((ROOT / "migrations").glob("*.sql"))
    new_migrations = [
        migration for migration in migrations if int(migration.name[:3]) >= 10
    ]
    assert new_migrations, "migration 010 missing from rollback allowlist"

    registry = dict(release.ROLLBACK_COMPATIBLE_MIGRATIONS)
    for migration in new_migrations:
        expected = "sha256:" + sha256(migration.read_bytes()).hexdigest()
        assert migration.name in registry, (
            f"migration {migration.name} missing from rollback allowlist"
        )
        assert registry[migration.name] == expected, (
            f"migration {migration.name} rollback digest is not the reviewed file"
        )
        assert migration.name[:3] != "009"

    # Every migration is re-runnable; applying the whole sequence again must not
    # change the ledger or fail on an existing constraint.
    connection = isolated_database.connection
    for migration in migrations:
        connection.execute(migration.read_text(encoding="utf-8"))
    for migration in migrations:
        connection.execute(migration.read_text(encoding="utf-8"))
    applied = connection.execute("SELECT count(*) FROM schema_migrations").fetchone()[0]
    assert applied == len(migrations)


def test_family_completed_satisfies_archived_evidence_check(
    isolated_database, tmp_path
):
    family_id = uuid4()
    family_json = tmp_path / "family.json"
    family_json.write_text('{"kind":"family_index","rounds":[]}', encoding="utf-8")
    digest = "sha256:" + "a" * 64
    isolated_database.connection.execute(
        "INSERT INTO jobs (job_id, request, state, stage, submitted_at, verdict, "
        "reason_code, evidence_status, evidence_path, evidence_digest, "
        "job_contract_version, family_id, job_kind) "
        "VALUES (%s, %s, 'COMPLETED', 'done', clock_timestamp(), NULL, NULL, "
        "'archived', %s, %s, 2, %s, 'family')",
        (
            family_id,
            Jsonb({"schema_version": 2}),
            str(family_json),
            digest,
            family_id,
        ),
    )
    row = isolated_database.connection.execute(
        "SELECT state, verdict, reason_code, evidence_status, evidence_path "
        "FROM jobs WHERE job_id = %s",
        (family_id,),
    ).fetchone()
    assert row == (
        "COMPLETED",
        None,
        None,
        "archived",
        str(family_json),
    )

    with pytest.raises(
        psycopg.errors.CheckViolation, match="jobs_archived_evidence_check"
    ):
        isolated_database.connection.execute(
            "INSERT INTO jobs (job_id, request, state, submitted_at, verdict, "
            "reason_code, evidence_status, evidence_path, evidence_digest, "
            "job_contract_version, family_id, job_kind) "
            "VALUES (%s, %s, 'COMPLETED', clock_timestamp(), NULL, NULL, "
            "'archived', NULL, %s, 2, %s, 'family')",
            (uuid4(), Jsonb({"schema_version": 2}), digest, uuid4()),
        )

    manifest_dir = tmp_path / "family-bundle"
    manifest_dir.mkdir()
    (manifest_dir / "manifest.json").write_text(
        json.dumps(
            {
                "schema_version": 2,
                "bundle_kind": "family",
                "job_id": str(uuid4()),
                "plan_digest": None,
                "verdict": None,
                "reason_code": None,
                "files": [],
            }
        ),
        encoding="utf-8",
    )
    with pytest.raises(evidence.BundleError, match="bundle_kind"):
        evidence.verify_bundle(manifest_dir)


def test_jobs_parent_job_id_must_be_v2_family(isolated_database):
    family_id = _insert_family(isolated_database)

    v1_parent = uuid4()
    _insert_identity_job(
        isolated_database,
        v1_parent,
        job_contract_version=1,
        job_kind=None,
        family_id=None,
        parent_job_id=None,
        round_no=None,
    )
    with pytest.raises(psycopg.errors.CheckViolation, match="jobs_parent"):
        _insert_identity_job(
            isolated_database,
            uuid4(),
            job_kind="round",
            family_id=v1_parent,
            parent_job_id=v1_parent,
            round_no=1,
        )

    campaign_id = uuid4()
    _insert_identity_job(
        isolated_database,
        campaign_id,
        job_kind="campaign",
        family_id=family_id,
        parent_job_id=family_id,
        round_no=None,
    )
    with pytest.raises(psycopg.errors.CheckViolation, match="jobs_parent"):
        _insert_identity_job(
            isolated_database,
            uuid4(),
            job_kind="round",
            family_id=campaign_id,
            parent_job_id=campaign_id,
            round_no=1,
        )

    round_one = uuid4()
    _insert_identity_job(
        isolated_database,
        round_one,
        job_kind="round",
        family_id=family_id,
        parent_job_id=family_id,
        round_no=1,
    )
    with pytest.raises(psycopg.errors.CheckViolation, match="jobs_parent"):
        _insert_identity_job(
            isolated_database,
            uuid4(),
            job_kind="round",
            family_id=round_one,
            parent_job_id=round_one,
            round_no=2,
        )

    accepted = uuid4()
    _insert_identity_job(
        isolated_database,
        accepted,
        job_kind="round",
        family_id=family_id,
        parent_job_id=family_id,
        round_no=2,
    )
    assert isolated_database.connection.execute(
        "SELECT parent_job_id FROM jobs WHERE job_id = %s", (accepted,)
    ).fetchone()[0] == family_id


def test_jobs_parent_guard_rejects_update_to_non_family(isolated_database):
    family_id = _insert_family(isolated_database)
    campaign_id = uuid4()
    _insert_identity_job(
        isolated_database,
        campaign_id,
        job_kind="campaign",
        family_id=family_id,
        parent_job_id=family_id,
        round_no=None,
    )
    round_id = uuid4()
    _insert_identity_job(
        isolated_database,
        round_id,
        job_kind="round",
        family_id=family_id,
        parent_job_id=family_id,
        round_no=1,
    )

    with pytest.raises(psycopg.errors.CheckViolation, match="jobs_parent"):
        isolated_database.connection.execute(
            "UPDATE jobs SET parent_job_id = %s, family_id = %s "
            "WHERE job_id = %s",
            (campaign_id, campaign_id, round_id),
        )


def test_jobs_family_campaign_key_rejects_second_campaign(isolated_database):
    family_id = _insert_family(isolated_database)
    _insert_identity_job(
        isolated_database,
        uuid4(),
        job_kind="campaign",
        family_id=family_id,
        parent_job_id=family_id,
        round_no=None,
    )
    with pytest.raises(
        psycopg.errors.UniqueViolation, match="jobs_family_campaign_key"
    ):
        _insert_identity_job(
            isolated_database,
            uuid4(),
            job_kind="campaign",
            family_id=family_id,
            parent_job_id=family_id,
            round_no=None,
        )


# --- 012: demoting a family parent with live children ----------------------


def test_family_parent_cannot_be_demoted_with_live_child(isolated_database):
    family_id = _insert_family(isolated_database)
    child_id = uuid4()
    _insert_identity_job(
        isolated_database,
        child_id,
        job_kind="round",
        family_id=family_id,
        parent_job_id=family_id,
        round_no=1,
    )

    with pytest.raises(psycopg.errors.CheckViolation, match="parent_demot"):
        isolated_database.connection.execute(
            "UPDATE jobs SET job_contract_version = 1, family_id = NULL, "
            "job_kind = NULL, parent_job_id = NULL, round_no = NULL "
            "WHERE job_id = %s",
            (family_id,),
        )

    assert isolated_database.connection.execute(
        "SELECT job_contract_version, job_kind, family_id FROM jobs "
        "WHERE job_id = %s",
        (family_id,),
    ).fetchone() == (2, "family", family_id)
    assert isolated_database.connection.execute(
        "SELECT parent_job_id FROM jobs WHERE job_id = %s",
        (child_id,),
    ).fetchone()[0] == family_id, "the demotion attempt rewrote the child parent"


def test_family_parent_can_be_demoted_without_children(isolated_database):
    family_id = _insert_family(isolated_database)

    isolated_database.connection.execute(
        "UPDATE jobs SET job_contract_version = 1, family_id = NULL, "
        "job_kind = NULL, parent_job_id = NULL, round_no = NULL "
        "WHERE job_id = %s",
        (family_id,),
    )

    assert isolated_database.connection.execute(
        "SELECT job_contract_version, job_kind, family_id, parent_job_id, "
        "round_no FROM jobs WHERE job_id = %s",
        (family_id,),
    ).fetchone() == (1, None, None, None, None)


# --- 013: a child may only be inserted under an AGGREGATING family ---------


MIGRATION_013 = ROOT / "migrations" / "013_v2_child_insert_parent_state_guard.sql"


def test_013_parent_state_guard_is_reentrant_and_registered(isolated_database):
    sql = MIGRATION_013.read_text(encoding="utf-8")
    isolated_database.connection.execute(sql)
    isolated_database.connection.execute(sql)

    expected = "sha256:" + sha256(MIGRATION_013.read_bytes()).hexdigest()
    assert release.ROLLBACK_COMPATIBLE_MIGRATIONS[MIGRATION_013.name] == expected

    family_id = _insert_family(isolated_database)
    first_child = uuid4()
    _insert_identity_job(
        isolated_database,
        first_child,
        job_kind="round",
        family_id=family_id,
        parent_job_id=family_id,
        round_no=1,
    )
    isolated_database.connection.execute(
        "UPDATE jobs SET state = 'COMPLETED', stage = 'done' WHERE job_id = %s",
        (family_id,),
    )

    with pytest.raises(psycopg.errors.CheckViolation, match="aggregating_family"):
        _insert_identity_job(
            isolated_database,
            uuid4(),
            job_kind="round",
            family_id=family_id,
            parent_job_id=family_id,
            round_no=2,
        )

    other_family = _insert_family(isolated_database)
    other_child = uuid4()
    _insert_identity_job(
        isolated_database,
        other_child,
        job_kind="round",
        family_id=other_family,
        parent_job_id=other_family,
        round_no=1,
    )
    with pytest.raises(psycopg.errors.CheckViolation, match="aggregating_family"):
        isolated_database.connection.execute(
            "UPDATE jobs SET parent_job_id = %s, family_id = %s WHERE job_id = %s",
            (family_id, family_id, other_child),
        )


def test_rollback_gate_fails_closed_when_013_is_not_registered(
    isolated_database, monkeypatch
):
    from types import MappingProxyType

    import datacon.release as release_module

    migrations = sorted((ROOT / "migrations").glob("*.sql"))
    applied = {
        migration.name: "sha256:" + sha256(migration.read_bytes()).hexdigest()
        for migration in migrations
    }
    registry = {
        name: digest
        for name, digest in release_module.ROLLBACK_COMPATIBLE_MIGRATIONS.items()
        if not name.startswith("013_")
    }
    monkeypatch.setattr(
        release_module,
        "ROLLBACK_COMPATIBLE_MIGRATIONS",
        MappingProxyType(registry),
    )
    with pytest.raises(
        release.ReleaseGateError,
        match="without a declared.*013_v2_child_insert_parent_state_guard",
    ):
        release_module._verify_rollback_migrations(
            target_version="009_b03_acceptance.sql",
            current_version=migrations[-1].name,
            applied=applied,
        )


def test_budget_ledger_has_no_cross_remaining_check(isolated_database):
    """D41: bounds and max_fuzz <= max_total exist; no remaining cross CHECK.

    A general build/replay charge drains only the total budget, so a valid
    ledger can have remaining_fuzz_seconds > remaining_total_seconds. Adding
    that cross CHECK would reject legitimate rows.
    """
    from datacon import state

    family_id = _insert_family(isolated_database)
    child_id = uuid4()
    _insert_identity_job(
        isolated_database,
        child_id,
        job_kind="round",
        family_id=family_id,
        parent_job_id=family_id,
        round_no=1,
    )
    try:
        ledger = state.initialize_budget_ledger(
            isolated_database.dsn,
            family_id,
            max_total_seconds=100,
            max_fuzz_seconds=60,
        )
    except psycopg.errors.CheckViolation as error:
        pytest.fail(f"cross remaining check rejected a valid ledger: {error}")

    assert ledger["remaining_total_seconds"] == 100
    assert ledger["remaining_fuzz_seconds"] == 60

    try:
        first_charge = state.charge_step_budget(
            isolated_database.dsn,
            family_id=family_id,
            job_id=child_id,
            step_key="prepare-build",
            attempt_no=1,
            charge_kind="general",
            elapsed_seconds=80,
        )
    except psycopg.errors.CheckViolation as error:
        pytest.fail(f"cross remaining check rejected a valid ledger: {error}")
    assert first_charge.status == "charged", first_charge.status
    assert first_charge.ledger["remaining_total_seconds"] == 20
    assert first_charge.ledger["remaining_fuzz_seconds"] == 60

    outcome = state.charge_step_budget(
        isolated_database.dsn,
        family_id=family_id,
        job_id=child_id,
        step_key="build",
        attempt_no=1,
        charge_kind="general",
        elapsed_seconds=5,
    )
    assert outcome.status == "charged", outcome.status

    summary = state.family_budget_summary(isolated_database.dsn, family_id)
    assert summary["remaining_seconds"] == 15
    assert summary["remaining_fuzz_seconds"] == 60
    assert summary["spent_seconds"] == 85
    assert summary["spent_fuzz_seconds"] == 0

    checks = isolated_database.connection.execute(
        "SELECT conname, pg_get_constraintdef(oid) FROM pg_constraint "
        "WHERE conrelid = 'budget_ledger'::regclass AND contype = 'c'"
    ).fetchall()
    definitions = {name: definition for name, definition in checks}
    expected = {
        "budget_ledger_max_total_positive",
        "budget_ledger_max_fuzz_non_negative",
        "budget_ledger_total_non_negative",
        "budget_ledger_fuzz_non_negative",
        "budget_ledger_remaining_within_max_total",
        "budget_ledger_remaining_within_max_fuzz",
        "budget_ledger_fuzz_within_total",
    }
    assert expected <= set(definitions), sorted(set(definitions))
    for name, definition in definitions.items():
        if (
            "remaining_fuzz_seconds" in definition
            and "remaining_total_seconds" in definition
        ):
            pytest.fail(
                "cross remaining check rejected a valid ledger: "
                f"{name} {definition}"
            )

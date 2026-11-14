from pathlib import Path
from uuid import uuid4

import psycopg
from psycopg import sql
from psycopg.types.json import Jsonb
import pytest

pytestmark = pytest.mark.postgres

ROOT = Path(__file__).resolve().parents[2]
MIGRATION_001 = ROOT / "migrations" / "001_create_jobs.sql"
MIGRATION_002 = ROOT / "migrations" / "002_workflow.sql"
MIGRATION_003 = ROOT / "migrations" / "003_attempts_generation.sql"
MIGRATION_004 = ROOT / "migrations" / "004_legacy_binary_sync.sql"
MIGRATION_005 = ROOT / "migrations" / "005_execution_evidence.sql"


def _relation_kind(connection, schema_name, relation_name):
    row = connection.execute(
        "SELECT c.relkind FROM pg_class c "
        "JOIN pg_namespace n ON n.oid = c.relnamespace "
        "WHERE n.nspname = %s AND c.relname = %s",
        (schema_name, relation_name),
    ).fetchone()
    return row[0] if row is not None else None


def test_phase_one_jobs_survive_incremental_workflow_migration(postgres_dsn):
    schema_name = f"datacon_workflow_migration_{uuid4().hex}"
    job_id = uuid4()
    request = {
        "schema_version": 1,
        "cve_id": "CVE-2099-0001",
        "target": {
            "kind": "source",
            "case_id": "fixture-c-parser",
            "goal": "legacy phase one row",
        },
        "limits": {
            "prepare_seconds": 600,
            "execute_seconds": 1200,
            "replay_seconds": 10,
            "cpu": 2,
            "memory_mib": 2048,
            "pids": 128,
            "scratch_mib": 512,
        },
    }
    migration_001 = MIGRATION_001.read_text(encoding="utf-8")
    migration_002 = MIGRATION_002.read_text(encoding="utf-8")

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
            connection.execute(migration_001)
            connection.execute(
                "INSERT INTO jobs (job_id, request, state) VALUES (%s, %s, 'QUEUED')",
                (job_id, Jsonb(request)),
            )
            assert _relation_kind(connection, schema_name, "plans") is None
            assert _relation_kind(connection, schema_name, "reviews") is None

            connection.execute(migration_002)
            connection.execute(migration_002)

            row = connection.execute(
                sql.SQL(
                    "SELECT request, state, operator_id, state_version, generation, "
                    "workflow_synced FROM {}.jobs WHERE job_id = %s"
                ).format(sql.Identifier(schema_name)),
                (job_id,),
            ).fetchone()
            assert row is not None, "the incremental migration deleted a phase one job"
            stored_request, state, operator_id, version, generation, synced = row
            assert stored_request == request
            assert state == "QUEUED"
            assert operator_id is None
            assert version == 0
            assert generation == 0
            assert synced is False

            for relation in (
                "plans",
                "reviews",
                "attempts",
                "audit_events",
                "jobs_claim_idx",
                "reviews_job_idx",
                "attempts_job_idx",
                "audit_events_job_idx",
            ):
                assert _relation_kind(connection, schema_name, relation) is not None

            attempts_definition = connection.execute(
                "SELECT pg_get_constraintdef(oid) FROM pg_constraint "
                "WHERE conrelid = 'attempts'::regclass "
                "AND conname = 'attempts_step_unique'"
            ).fetchone()[0]
            assert "generation" in attempts_definition
            assert (
                "job_id, stage, step_key, attempt_no, generation"
                in attempts_definition
            )

            columns = {
                row[0]
                for row in connection.execute(
                    "SELECT column_name FROM information_schema.columns "
                    "WHERE table_schema = %s AND table_name = 'jobs'",
                    (schema_name,),
                ).fetchall()
            }
            assert {
                "operator_id",
                "stage",
                "state_version",
                "generation",
                "lease_owner",
                "lease_expires_at",
                "prepare_deadline_at",
                "review_deadline_at",
                "execute_deadline_at",
                "approved_at",
                "last_error",
                "workflow_synced",
                "updated_at",
            } <= columns

            # One plan and one review per job is enforced by the schema.
            connection.execute(
                "INSERT INTO plans (plan_id, job_id, plan_digest, plan, summary) "
                "VALUES (%s, %s, %s, %s, %s)",
                (uuid4(), job_id, "sha256:" + "a" * 64, Jsonb({"case_id": "x"}), Jsonb({})),
            )
            with pytest.raises(psycopg.errors.UniqueViolation):
                connection.execute(
                    "INSERT INTO plans (plan_id, job_id, plan_digest, plan, summary) "
                    "VALUES (%s, %s, %s, %s, %s)",
                    (
                        uuid4(),
                        job_id,
                        "sha256:" + "b" * 64,
                        Jsonb({"case_id": "y"}),
                        Jsonb({}),
                    ),
                )
            connection.execute("ROLLBACK")

            connection.execute(
                "INSERT INTO reviews "
                "(review_id, job_id, plan_digest, reviewer_id, decision, "
                "review_deadline_at) "
                "VALUES (%s, %s, %s, %s, 'approve', now() + interval '1 hour')",
                (uuid4(), job_id, "sha256:" + "a" * 64, "reviewer-1"),
            )
            with pytest.raises(psycopg.errors.UniqueViolation):
                connection.execute(
                    "INSERT INTO reviews "
                    "(review_id, job_id, plan_digest, reviewer_id, decision, "
                    "review_deadline_at) "
                    "VALUES (%s, %s, %s, %s, 'reject', now() + interval '1 hour')",
                    (uuid4(), job_id, "sha256:" + "a" * 64, "reviewer-2"),
                )
            connection.execute("ROLLBACK")
        finally:
            connection.rollback()
            connection.execute(
                sql.SQL("DROP SCHEMA IF EXISTS {} CASCADE").format(
                    sql.Identifier(schema_name)
                )
            )


def test_003_upgrades_attempts_unique_key_without_data_loss(postgres_dsn):
    schema_name = f"datacon_attempts_migration_{uuid4().hex}"
    job_id = uuid4()
    migration_001 = MIGRATION_001.read_text(encoding="utf-8")
    migration_002 = MIGRATION_002.read_text(encoding="utf-8")
    migration_003 = MIGRATION_003.read_text(encoding="utf-8")
    request = {
        "schema_version": 1,
        "cve_id": "CVE-2099-0001",
        "target": {
            "kind": "source",
            "case_id": "fixture-c-parser",
            "goal": "legacy attempts row",
        },
    }

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
            connection.execute(migration_001)
            connection.execute(migration_002)
            connection.execute(
                "INSERT INTO jobs (job_id, request, state) VALUES (%s, %s, 'QUEUED')",
                (job_id, Jsonb(request)),
            )
            connection.execute(
                "INSERT INTO attempts "
                "(attempt_id, job_id, stage, step_key, attempt_no, generation, "
                "status, result) VALUES (%s, %s, 'prepare', 'plan', 1, 1, "
                "'completed', %s)",
                (uuid4(), job_id, Jsonb({"generation": 1})),
            )

            # Simulate a database that applied the old 002: same step/no could
            # only have one row because generation was not part of the key.
            connection.execute(
                "ALTER TABLE attempts DROP CONSTRAINT attempts_step_unique"
            )
            connection.execute(
                "ALTER TABLE attempts ADD CONSTRAINT attempts_step_unique "
                "UNIQUE (job_id, stage, step_key, attempt_no)"
            )
            with pytest.raises(psycopg.errors.UniqueViolation):
                connection.execute(
                    "INSERT INTO attempts "
                    "(attempt_id, job_id, stage, step_key, attempt_no, generation, "
                    "status, result) VALUES (%s, %s, 'prepare', 'plan', 1, 2, "
                    "'completed', %s)",
                    (uuid4(), job_id, Jsonb({"generation": 2})),
                )
            connection.execute("ROLLBACK")

            connection.execute(migration_003)
            connection.execute(migration_003)

            definition = connection.execute(
                "SELECT pg_get_constraintdef(oid) FROM pg_constraint "
                "WHERE conrelid = 'attempts'::regclass "
                "AND conname = 'attempts_step_unique'"
            ).fetchone()[0]
            assert "generation" in definition
            assert "job_id, stage, step_key, attempt_no, generation" in definition

            connection.execute(
                "INSERT INTO attempts "
                "(attempt_id, job_id, stage, step_key, attempt_no, generation, "
                "status, result) VALUES (%s, %s, 'prepare', 'plan', 1, 2, "
                "'completed', %s)",
                (uuid4(), job_id, Jsonb({"generation": 2})),
            )
            rows = connection.execute(
                "SELECT generation, result FROM attempts "
                "WHERE job_id = %s AND stage = 'prepare' AND step_key = 'plan' "
                "AND attempt_no = 1 ORDER BY generation",
                (job_id,),
            ).fetchall()
            assert rows == [(1, {"generation": 1}), (2, {"generation": 2})]

            with pytest.raises(psycopg.errors.UniqueViolation):
                connection.execute(
                    "INSERT INTO attempts "
                    "(attempt_id, job_id, stage, step_key, attempt_no, generation, "
                    "status, result) VALUES (%s, %s, 'prepare', 'plan', 1, 2, "
                    "'completed', %s)",
                    (uuid4(), job_id, Jsonb({"generation": 2})),
                )
            connection.execute("ROLLBACK")
        finally:
            connection.rollback()
            connection.execute(
                sql.SQL("DROP SCHEMA IF EXISTS {} CASCADE").format(
                    sql.Identifier(schema_name)
                )
            )


def test_004_backfills_legacy_binary_and_is_rerunnable(postgres_dsn):
    schema_name = f"datacon_binary_migration_{uuid4().hex}"
    binary_id = uuid4()
    source_id = uuid4()
    binary_request = {
        "schema_version": 1,
        "cve_id": "CVE-2099-0001",
        "target": {
            "kind": "binary",
            "case_id": "fixture-c-parser",
            "goal": "legacy binary row",
        },
    }
    source_request = {
        "schema_version": 1,
        "cve_id": "CVE-2099-0001",
        "target": {
            "kind": "source",
            "case_id": "fixture-c-parser",
            "goal": "legacy source row",
        },
    }
    migration_001 = MIGRATION_001.read_text(encoding="utf-8")
    migration_002 = MIGRATION_002.read_text(encoding="utf-8")
    migration_003 = MIGRATION_003.read_text(encoding="utf-8")
    migration_004 = MIGRATION_004.read_text(encoding="utf-8")

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
            connection.execute(migration_001)
            connection.execute(
                "INSERT INTO jobs (job_id, request, state, reason_code) "
                "VALUES (%s, %s, 'BLOCKED', 'UNSUPPORTED_TARGET')",
                (binary_id, Jsonb(binary_request)),
            )
            connection.execute(
                "INSERT INTO jobs (job_id, request, state) "
                "VALUES (%s, %s, 'QUEUED')",
                (source_id, Jsonb(source_request)),
            )

            for migration in (migration_002, migration_003, migration_004, migration_004):
                connection.execute(migration)

            rows = connection.execute(
                "SELECT workflow_synced FROM jobs WHERE job_id = %s",
                (binary_id,),
            ).fetchall()
            assert rows == [(True,)]
            rows = connection.execute(
                "SELECT workflow_synced FROM jobs WHERE job_id = %s",
                (source_id,),
            ).fetchall()
            assert rows == [(False,)]

            # A pre-migration binary row still satisfies the claim query's
            # exclusion even if an operator applied 002 but not 004.
            claimed = connection.execute(
                "SELECT job_id FROM jobs WHERE job_id = %s "
                "AND state = 'BLOCKED' "
                "AND reason_code IS DISTINCT FROM 'UNSUPPORTED_TARGET'",
                (binary_id,),
            ).fetchall()
            assert claimed == []
        finally:
            connection.rollback()
            connection.execute(
                sql.SQL("DROP SCHEMA IF EXISTS {} CASCADE").format(
                    sql.Identifier(schema_name)
                )
            )


def test_005_execution_evidence_is_incremental_and_rerunnable(postgres_dsn):
    schema_name = f"datacon_execution_migration_{uuid4().hex}"
    job_id = uuid4()
    request = {
        "schema_version": 1,
        "cve_id": "CVE-2099-0001",
        "target": {
            "kind": "source",
            "case_id": "fixture-c-parser",
            "goal": "execution migration",
        },
        "limits": {
            "prepare_seconds": 600,
            "execute_seconds": 1200,
            "replay_seconds": 10,
            "cpu": 2,
            "memory_mib": 2048,
            "pids": 128,
            "scratch_mib": 512,
        },
    }
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
            for migration in (
                MIGRATION_001,
                MIGRATION_002,
                MIGRATION_003,
                MIGRATION_004,
                MIGRATION_005,
            ):
                connection.execute(migration.read_text(encoding="utf-8"))
            connection.execute(
                "INSERT INTO jobs (job_id, request, state) VALUES (%s, %s, 'READY')",
                (job_id, Jsonb(request)),
            )
            # Re-running 005 must preserve the row and its new NULL metadata.
            connection.execute(MIGRATION_005.read_text(encoding="utf-8"))
            columns = {
                row[0]
                for row in connection.execute(
                    "SELECT column_name FROM information_schema.columns "
                    "WHERE table_schema = %s AND table_name = 'jobs'",
                    (schema_name,),
                ).fetchall()
            }
            assert {
                "verdict",
                "verdict_reason",
                "evidence_digest",
                "evidence_path",
                "evidence_status",
                "evidence_error",
            } <= columns
            assert connection.execute(
                "SELECT count(*) FROM jobs WHERE job_id = %s", (job_id,)
            ).fetchone()[0] == 1
            connection.execute(
                "UPDATE jobs SET verdict = 'REPRODUCED', "
                "evidence_status = 'archived' WHERE job_id = %s",
                (job_id,),
            )
            with pytest.raises(psycopg.errors.CheckViolation):
                connection.execute(
                    "UPDATE jobs SET verdict = 'MAYBE' WHERE job_id = %s",
                    (job_id,),
                )
        finally:
            connection.execute(
                sql.SQL("DROP SCHEMA IF EXISTS {} CASCADE").format(
                    sql.Identifier(schema_name)
                )
            )

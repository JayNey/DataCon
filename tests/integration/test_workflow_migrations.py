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

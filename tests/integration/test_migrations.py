from pathlib import Path
from uuid import uuid4

import psycopg
import pytest
from psycopg import sql
from psycopg.types.json import Jsonb

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

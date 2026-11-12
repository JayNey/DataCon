from pathlib import Path
from uuid import uuid4

import psycopg
import pytest
from psycopg.types.json import Jsonb

pytestmark = pytest.mark.postgres

ROOT = Path(__file__).resolve().parents[2]
MIGRATION = ROOT / "migrations" / "001_create_jobs.sql"


def test_migration_can_be_applied_repeatedly(database, postgres_dsn):
    sql = MIGRATION.read_text(encoding="utf-8")
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
            connection.execute(sql)
            connection.execute(sql)

        row = database.execute(
            "SELECT request, state FROM jobs WHERE job_id = %s", (sentinel_id,)
        ).fetchone()
        assert row is not None, "re-running the migration deleted an existing job"
        request, state = row
        assert request == sentinel_request
        assert state == "QUEUED"

        assert database.execute("SELECT count(*) FROM jobs").fetchone()[0] == before
        assert (
            database.execute("SELECT to_regclass('public.jobs')").fetchone()[0]
            == "jobs"
        )
        assert (
            database.execute("SELECT to_regclass('public.jobs_queue_idx')").fetchone()[0]
            == "jobs_queue_idx"
        )
    finally:
        database.execute("DELETE FROM jobs WHERE job_id = %s", (sentinel_id,))

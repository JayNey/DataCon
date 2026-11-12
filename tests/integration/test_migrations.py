from pathlib import Path

import psycopg
import pytest

pytestmark = pytest.mark.postgres

ROOT = Path(__file__).resolve().parents[2]
MIGRATION = ROOT / "migrations" / "001_create_jobs.sql"


def test_migration_can_be_applied_repeatedly(database, postgres_dsn):
    sql = MIGRATION.read_text(encoding="utf-8")
    before = database.execute("SELECT count(*) FROM jobs").fetchone()[0]

    with psycopg.connect(postgres_dsn, autocommit=True, connect_timeout=5) as connection:
        connection.execute(sql)
        connection.execute(sql)

    assert database.execute("SELECT count(*) FROM jobs").fetchone()[0] == before
    assert database.execute("SELECT to_regclass('public.jobs')").fetchone()[0] == "jobs"
    assert (
        database.execute("SELECT to_regclass('public.jobs_queue_idx')").fetchone()[0]
        == "jobs_queue_idx"
    )

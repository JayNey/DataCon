import os
from pathlib import Path

import psycopg
import pytest

ROOT = Path(__file__).resolve().parents[2]
MIGRATION = ROOT / "migrations" / "001_create_jobs.sql"


@pytest.fixture(scope="session")
def postgres_dsn():
    dsn = os.getenv("DATACON_TEST_DATABASE_URL")
    if not dsn:
        pytest.skip("set DATACON_TEST_DATABASE_URL to run PostgreSQL integration tests")
    return dsn


@pytest.fixture(scope="session")
def database(postgres_dsn):
    sql = MIGRATION.read_text(encoding="utf-8")
    with psycopg.connect(postgres_dsn, autocommit=True, connect_timeout=5) as connection:
        connection.execute(sql)
    with psycopg.connect(postgres_dsn, autocommit=True, connect_timeout=5) as connection:
        yield connection

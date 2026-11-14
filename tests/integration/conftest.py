import os
from pathlib import Path
import uuid

import psycopg
from psycopg import sql
from psycopg.conninfo import conninfo_to_dict, make_conninfo
import pytest

ROOT = Path(__file__).resolve().parents[2]
MIGRATIONS = sorted((ROOT / "migrations").glob("*.sql"))


def ci_environment() -> bool:
    """Return whether this run must not silently skip required CI tests."""
    value = os.getenv("CI", "").strip().lower()
    return value not in ("", "0", "false", "no")


def apply_migrations(connection):
    for migration in MIGRATIONS:
        connection.execute(migration.read_text(encoding="utf-8"))


@pytest.fixture(scope="session")
def postgres_dsn():
    dsn = os.getenv("DATACON_TEST_DATABASE_URL")
    if not dsn:
        if ci_environment():
            pytest.fail(
                "CI requires DATACON_TEST_DATABASE_URL; PostgreSQL tests "
                "must not be skipped"
            )
        pytest.skip("set DATACON_TEST_DATABASE_URL to run PostgreSQL integration tests")
    return dsn


@pytest.fixture(scope="session")
def database(postgres_dsn):
    with psycopg.connect(postgres_dsn, autocommit=True, connect_timeout=5) as connection:
        apply_migrations(connection)
    with psycopg.connect(postgres_dsn, autocommit=True, connect_timeout=5) as connection:
        yield connection


class IsolatedDatabase:
    """A private schema so worker runs cannot consume another test's queue."""

    def __init__(self, dsn, schema, connection):
        self.dsn = dsn
        self.schema = schema
        self.connection = connection


@pytest.fixture
def isolated_database(postgres_dsn):
    schema = f"datacon_test_{uuid.uuid4().hex}"
    with psycopg.connect(
        postgres_dsn, autocommit=True, connect_timeout=5
    ) as admin:
        admin.execute(sql.SQL("CREATE SCHEMA {}").format(sql.Identifier(schema)))

    parameters = conninfo_to_dict(postgres_dsn)
    parameters["options"] = f"-csearch_path={schema}"
    dsn = make_conninfo(**parameters)

    connection = psycopg.connect(dsn, autocommit=True, connect_timeout=5)
    try:
        apply_migrations(connection)
        yield IsolatedDatabase(dsn, schema, connection)
    finally:
        connection.close()
        with psycopg.connect(
            postgres_dsn, autocommit=True, connect_timeout=5
        ) as admin:
            admin.execute(
                sql.SQL("DROP SCHEMA IF EXISTS {} CASCADE").format(
                    sql.Identifier(schema)
                )
            )

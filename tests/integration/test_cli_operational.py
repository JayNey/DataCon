import json
import os
from pathlib import Path
import subprocess
import sys
from uuid import uuid4

import pytest
from psycopg.errors import UndefinedTable

from datacon.cli import _database_error_message

ROOT = Path(__file__).resolve().parents[2]
EXAMPLE = ROOT / "examples" / "request.json"
UNREACHABLE_DATABASE_URL = (
    "postgresql://datacon@/datacon?host=/nonexistent-datacon-socket"
)
SENTINEL_PASSWORD = "sentinel-password-7c3e"
MALFORMED_DATABASE_URL = (
    f"postgresql://datacon:{SENTINEL_PASSWORD}@[::1/datacon"
)


def cli(*args, database_url=None):
    executable = Path(sys.executable).with_name("datacon")
    env = os.environ.copy()
    env.pop("DATACON_DATABASE_URL", None)
    if database_url is not None:
        env["DATACON_DATABASE_URL"] = database_url
    return subprocess.run(
        [str(executable), *args],
        capture_output=True,
        text=True,
        timeout=15,
        env=env,
    )


def test_missing_database_configuration_is_an_operational_error():
    result = cli("status", str(uuid4()))
    assert result.returncode == 1
    assert json.loads(result.stderr)["reason_code"] == "DATABASE_NOT_CONFIGURED"


@pytest.mark.parametrize(
    "args",
    [
        ("status", str(uuid4())),
        ("submit", "--request", str(EXAMPLE)),
    ],
    ids=["status", "submit"],
)
def test_database_operation_failure_is_an_operational_error(args):
    result = cli(*args, database_url=UNREACHABLE_DATABASE_URL)
    assert result.returncode == 1, result.stderr
    assert result.stdout == ""
    payload = json.loads(result.stderr)
    assert payload["reason_code"] == "DATABASE_ERROR"
    assert "database operation failed" in payload["message"]


@pytest.mark.parametrize(
    "args",
    [
        ("status", str(uuid4())),
        ("submit", "--request", str(EXAMPLE)),
    ],
    ids=["status", "submit"],
)
def test_database_error_does_not_echo_dsn_or_credentials(args):
    result = cli(*args, database_url=MALFORMED_DATABASE_URL)

    assert result.returncode == 1
    assert result.stdout == ""
    payload = json.loads(result.stderr)
    assert payload["reason_code"] == "DATABASE_ERROR"
    assert payload["message"] == "database operation failed"
    assert SENTINEL_PASSWORD not in result.stderr
    assert MALFORMED_DATABASE_URL not in result.stderr
    assert "postgresql://" not in result.stderr
    assert "[::1" not in result.stderr


def test_database_error_message_adds_only_sqlstate():
    error = UndefinedTable(MALFORMED_DATABASE_URL)

    message = _database_error_message(error)

    assert message == "database operation failed (sqlstate: 42P01)"
    assert SENTINEL_PASSWORD not in message
    assert MALFORMED_DATABASE_URL not in message

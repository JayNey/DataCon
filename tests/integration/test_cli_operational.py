import json
import os
from pathlib import Path
import subprocess
import sys
from uuid import uuid4

import pytest

ROOT = Path(__file__).resolve().parents[2]
EXAMPLE = ROOT / "examples" / "request.json"
UNREACHABLE_DATABASE_URL = (
    "postgresql://datacon@/datacon?host=/nonexistent-datacon-socket"
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

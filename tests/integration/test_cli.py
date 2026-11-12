import json
import os
from pathlib import Path
import subprocess
import sys
from uuid import UUID, uuid4

import pytest

pytestmark = pytest.mark.postgres

ROOT = Path(__file__).resolve().parents[2]
EXAMPLE = ROOT / "examples" / "request.json"
REQUEST = (
    '{"schema_version":1,"cve_id":"CVE-2099-0001",'
    '"target":{"kind":"source","case_id":"fixture-c-parser","goal":"验证 ASan"}}'
)
DEFAULTS = {
    "prepare_seconds": 600,
    "execute_seconds": 1200,
    "replay_seconds": 10,
    "cpu": 2,
    "memory_mib": 2048,
    "pids": 128,
    "scratch_mib": 512,
}


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


def submit(database_url, request_path):
    result = cli("submit", "--request", str(request_path), database_url=database_url)
    assert result.returncode == 0, result.stderr
    return json.loads(result.stdout)


def test_submit_and_status_in_separate_processes(database, postgres_dsn, tmp_path):
    request = tmp_path / "request.json"
    request.write_text(REQUEST, encoding="utf-8")

    first = submit(postgres_dsn, request)
    second = submit(postgres_dsn, request)

    assert first["state"] == "QUEUED"
    assert second["state"] == "QUEUED"
    assert str(UUID(first["job_id"])) == first["job_id"]
    assert first["job_id"] != second["job_id"]

    result = cli("status", first["job_id"], database_url=postgres_dsn)
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout) == {
        "job_id": first["job_id"],
        "state": "QUEUED",
        "stage": None,
        "pending_plan": None,
        "review_state": None,
        "reason_code": None,
        "last_error": None,
        "evidence_refs": [],
    }

    (stored,) = database.execute(
        "SELECT request FROM jobs WHERE job_id = %s", (UUID(first["job_id"]),)
    ).fetchone()
    assert stored == json.loads(REQUEST) | {"limits": DEFAULTS}


@pytest.mark.parametrize(
    "payload",
    [
        REQUEST.replace("CVE-2099-0001", "cve-2099-0001"),
        REQUEST[:-1] + ',"limits":{"cpu":3}}',
        REQUEST[:-1] + ',"unknown":1}',
        REQUEST.replace('"kind":"source"', '"kind":"source","kind":"source"'),
        REQUEST[:-1] + ',',
    ],
)
def test_invalid_request_has_no_database_side_effect(
    database, postgres_dsn, tmp_path, payload
):
    request = tmp_path / "invalid.json"
    request.write_text(payload, encoding="utf-8")
    before = database.execute("SELECT count(*) FROM jobs").fetchone()[0]

    result = cli("submit", "--request", str(request), database_url=postgres_dsn)

    assert result.returncode == 2, result.stderr
    assert result.stdout == ""
    assert json.loads(result.stderr)["reason_code"] == "INVALID_REQUEST"
    assert database.execute("SELECT count(*) FROM jobs").fetchone()[0] == before


def test_missing_request_file_has_no_database_side_effect(database, postgres_dsn, tmp_path):
    before = database.execute("SELECT count(*) FROM jobs").fetchone()[0]
    result = cli(
        "submit", "--request", str(tmp_path / "missing.json"), database_url=postgres_dsn
    )
    assert result.returncode == 2
    assert json.loads(result.stderr)["reason_code"] == "INVALID_REQUEST"
    assert database.execute("SELECT count(*) FROM jobs").fetchone()[0] == before


def test_missing_job_and_malformed_id(database, postgres_dsn):
    missing = cli("status", str(uuid4()), database_url=postgres_dsn)
    assert missing.returncode == 3
    assert json.loads(missing.stderr)["reason_code"] == "JOB_NOT_FOUND"

    malformed = cli("status", "not-a-uuid", database_url=postgres_dsn)
    assert malformed.returncode == 2
    assert json.loads(malformed.stderr)["reason_code"] == "INVALID_REQUEST"


def test_shipped_example_can_be_submitted(database, postgres_dsn):
    result = cli("submit", "--request", str(EXAMPLE), database_url=postgres_dsn)
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout)["state"] == "QUEUED"

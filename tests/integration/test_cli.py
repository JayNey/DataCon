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
BINARY_REQUEST = REQUEST.replace('"kind":"source"', '"kind":"binary"')
# This DSN cannot be reached. If the CLI tries to connect before validating the
# request it exits 1 (DATABASE_ERROR) instead of 2 (INVALID_REQUEST).
UNREACHABLE_DATABASE_URL = (
    "postgresql://datacon@/datacon?host=/nonexistent-datacon-socket"
)
INVALID_UTF8_REQUEST = (
    b'{"schema_version":1,"cve_id":"CVE-2099-0001",'
    b'"target":{"kind":"source","case_id":"fixture-c-parser","goal":"\xff"}}'
)
NAN_REQUEST = REQUEST.replace('"goal":"验证 ASan"', '"goal":NaN')
INFINITY_REQUEST = REQUEST.replace('"goal":"验证 ASan"', '"goal":Infinity')
OVERSIZED_REQUEST = REQUEST.replace('"goal":"验证 ASan"', '"goal":"' + "x" * 70000 + '"')
DEFAULTS = {
    "prepare_seconds": 600,
    "execute_seconds": 1200,
    "replay_seconds": 10,
    "cpu": 2,
    "memory_mib": 2048,
    "pids": 128,
    "scratch_mib": 512,
}


def cli(*args, database_url=None, env_extra=None):
    executable = Path(sys.executable).with_name("datacon")
    env = os.environ.copy()
    env.pop("DATACON_DATABASE_URL", None)
    env.pop("DATACON_CASE_ROOT", None)
    if database_url is not None:
        env["DATACON_DATABASE_URL"] = database_url
    if env_extra:
        env.update(env_extra)
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
        "verdict": None,
        "verdict_reason": None,
        "evidence": None,
    }

    (stored, stored_state, stored_reason) = database.execute(
        "SELECT request, state, reason_code FROM jobs WHERE job_id = %s",
        (UUID(first["job_id"]),),
    ).fetchone()
    assert stored == json.loads(REQUEST) | {"limits": DEFAULTS}
    assert stored_state == "QUEUED"
    assert stored_reason is None


def test_binary_submit_is_archived_as_blocked(database, postgres_dsn, tmp_path):
    request = tmp_path / "binary.json"
    request.write_text(BINARY_REQUEST, encoding="utf-8")

    first = submit(postgres_dsn, request)
    second = submit(postgres_dsn, request)

    assert first["state"] == "BLOCKED", first
    assert second["state"] == "BLOCKED", second
    assert str(UUID(first["job_id"])) == first["job_id"]
    assert first["job_id"] != second["job_id"]

    result = cli("status", first["job_id"], database_url=postgres_dsn)
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout) == {
        "job_id": first["job_id"],
        "state": "BLOCKED",
        "stage": None,
        "pending_plan": None,
        "review_state": None,
        "reason_code": "UNSUPPORTED_TARGET",
        "last_error": None,
        "evidence_refs": [],
        "verdict": None,
        "verdict_reason": None,
        "evidence": None,
    }

    row = database.execute(
        "SELECT state, reason_code FROM jobs WHERE job_id = %s",
        (UUID(first["job_id"]),),
    ).fetchone()
    assert row == ("BLOCKED", "UNSUPPORTED_TARGET"), row

    queued_binary = database.execute(
        "SELECT count(*) FROM jobs "
        "WHERE request->'target'->>'kind' = 'binary' AND state = 'QUEUED'"
    ).fetchone()[0]
    assert queued_binary == 0, "binary requests must never remain queued"


@pytest.mark.parametrize(
    "payload",
    [
        pytest.param(
            REQUEST.replace("CVE-2099-0001", "cve-2099-0001"), id="lowercase-cve"
        ),
        pytest.param(
            REQUEST[:-1] + ',"limits":{"cpu":3}}', id="budget-above-maximum"
        ),
        pytest.param(REQUEST[:-1] + ',"unknown":1}', id="unknown-field"),
        pytest.param(
            REQUEST.replace('"kind":"source"', '"kind":"source","kind":"source"'),
            id="duplicate-json-key",
        ),
        pytest.param(REQUEST[:-1] + ",", id="trailing-comma"),
        pytest.param(INVALID_UTF8_REQUEST, id="invalid-utf8"),
        pytest.param(NAN_REQUEST, id="nan"),
        pytest.param(INFINITY_REQUEST, id="infinity"),
        pytest.param(OVERSIZED_REQUEST, id="oversized"),
    ],
)
def test_invalid_request_is_rejected_before_database_connection(
    database, postgres_dsn, tmp_path, payload
):
    request = tmp_path / "invalid.json"
    if isinstance(payload, bytes):
        request.write_bytes(payload)
    else:
        request.write_text(payload, encoding="utf-8")
    before = database.execute("SELECT count(*) FROM jobs").fetchone()[0]

    result = cli(
        "submit", "--request", str(request), database_url=UNREACHABLE_DATABASE_URL
    )

    assert result.returncode == 2, result.stderr
    assert result.stdout == ""
    assert json.loads(result.stderr)["reason_code"] == "INVALID_REQUEST"

    # Re-run against the reachable database to confirm rejection stays free of
    # side effects; the unreachable run above proves validation wins over I/O.
    reachable = cli("submit", "--request", str(request), database_url=postgres_dsn)
    assert reachable.returncode == 2, reachable.stderr
    assert json.loads(reachable.stderr)["reason_code"] == "INVALID_REQUEST"
    assert database.execute("SELECT count(*) FROM jobs").fetchone()[0] == before


def test_unresolvable_case_root_is_rejected_before_database_connection(
    database, postgres_dsn, tmp_path
):
    """A symlink-loop case root is a request error, not an uncaught RuntimeError."""
    request = tmp_path / "request.json"
    request.write_text(REQUEST, encoding="utf-8")
    loop_root = tmp_path / "caseloop"
    loop_root.symlink_to("caseloop")
    env_extra = {"DATACON_CASE_ROOT": str(loop_root)}
    before = database.execute("SELECT count(*) FROM jobs").fetchone()[0]

    result = cli(
        "submit",
        "--request",
        str(request),
        database_url=UNREACHABLE_DATABASE_URL,
        env_extra=env_extra,
    )

    assert result.returncode == 2, result.stderr
    assert result.stdout == ""
    assert len(result.stderr.strip().splitlines()) == 1
    payload = json.loads(result.stderr)
    assert payload["reason_code"] == "INVALID_REQUEST"
    assert "Traceback" not in result.stderr
    assert "RuntimeError" not in result.stderr

    # Re-run against the reachable database to confirm rejection has no side
    # effects; the unreachable run above proves validation wins over I/O.
    reachable = cli(
        "submit",
        "--request",
        str(request),
        database_url=postgres_dsn,
        env_extra=env_extra,
    )
    assert reachable.returncode == 2, reachable.stderr
    assert json.loads(reachable.stderr)["reason_code"] == "INVALID_REQUEST"
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


def test_export_before_evidence_exists_is_blocked(database, postgres_dsn, tmp_path):
    request = tmp_path / "request.json"
    request.write_text(REQUEST, encoding="utf-8")
    job = submit(postgres_dsn, request)
    destination = tmp_path / "exported"
    result = cli(
        "export",
        job["job_id"],
        "--out",
        str(destination),
        database_url=postgres_dsn,
    )
    assert result.returncode == 3
    assert json.loads(result.stderr)["reason_code"] == "EVIDENCE_NOT_AVAILABLE"
    assert not destination.exists()


def test_verify_bundle_rejects_a_missing_directory(tmp_path):
    result = cli("verify-bundle", str(tmp_path / "missing"))
    assert result.returncode == 3
    assert json.loads(result.stderr)["reason_code"] == "MISSING_FILE"


def test_export_rejects_a_malformed_job_id(postgres_dsn, tmp_path):
    result = cli(
        "export",
        "not-a-uuid",
        "--out",
        str(tmp_path / "exported"),
        database_url=postgres_dsn,
    )
    assert result.returncode == 2
    assert json.loads(result.stderr)["reason_code"] == "INVALID_REQUEST"

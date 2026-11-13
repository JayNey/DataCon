import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]
CASES = ROOT / "tests" / "fixtures" / "cases"
REQUEST = (
    '{"schema_version":1,"cve_id":"CVE-2099-0001",'
    '"target":{"kind":"source","case_id":"fixture-c-parser",'
    '"goal":"验证固定输入在缺陷版触发预期 ASan 异常"}}'
)


def cli(*args, database_url=None, env_extra=None):
    executable = Path(sys.executable).with_name("datacon")
    env = os.environ.copy()
    env.pop("DATACON_DATABASE_URL", None)
    env.pop("DATACON_CASE_ROOT", None)
    env.pop("DATACON_OPERATOR_ID", None)
    if database_url is not None:
        env["DATACON_DATABASE_URL"] = database_url
    if env_extra:
        env.update(env_extra)
    return subprocess.run(
        [str(executable), *args],
        capture_output=True,
        text=True,
        timeout=60,
        env=env,
    )


def submit(database_url, request_path, *, env_extra=None):
    result = cli(
        "submit",
        "--request",
        str(request_path),
        database_url=database_url,
        env_extra=env_extra,
    )
    assert result.returncode == 0, result.stderr
    return json.loads(result.stdout)


def worker(database_url, *, env_extra=None):
    result = cli("worker", "--once", database_url=database_url, env_extra=env_extra)
    assert result.returncode == 0, result.stderr
    return json.loads(result.stdout)


def status(database_url, job_id):
    result = cli("status", job_id, database_url=database_url)
    assert result.returncode == 0, result.stderr
    return json.loads(result.stdout)


def review(database_url, job_id, plan_digest, decision, *, env_extra=None):
    return cli(
        "review",
        job_id,
        "--plan-digest",
        plan_digest,
        "--decision",
        decision,
        database_url=database_url,
        env_extra=env_extra,
    )


def write_request(tmp_path, case_id="fixture-c-parser", body=None):
    request = tmp_path / f"request-{case_id}.json"
    if body is None:
        body = REQUEST.replace("fixture-c-parser", case_id)
    request.write_text(body, encoding="utf-8")
    return request


def copy_cases(tmp_path):
    root = tmp_path / "cases"
    shutil.copytree(CASES, root)
    return root


def scalar(database, query, params=()):
    row = database.connection.execute(query, params).fetchone()
    return row[0] if row is not None else None

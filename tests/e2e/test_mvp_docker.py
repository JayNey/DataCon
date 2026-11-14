"""MVP-01..04 with the real CLI, PostgreSQL and the pinned Linux/amd64 image.

These tests are the Docker integration gate. They are skipped locally when the
Docker daemon is unavailable; CI fails instead of silently skipping.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import subprocess
import uuid

import pytest

from datacon import state
from datacon.evidence import verify_bundle
from datacon.tools.sandbox import (
    SECCOMP_PROFILE_DIGEST,
    DockerSandbox,
    IsolationPolicy,
    ResourceLimits,
    SandboxPolicyError,
)
import datacon.tools.sandbox as sandbox_module
from support import cli, review, status, submit, worker, write_request

pytestmark = [pytest.mark.postgres, pytest.mark.docker]


@pytest.fixture(autouse=True)
def require_docker():
    if shutil.which("docker") is None:
        if os.getenv("CI", "").lower() not in ("", "0", "false", "no"):
            pytest.fail("Docker is required for the Linux isolation gate")
        pytest.skip("Docker is not installed")
    result = subprocess.run(
        ["docker", "version", "--format", "{{.Server.Version}}"],
        capture_output=True,
        text=True,
        timeout=30,
    )
    if result.returncode != 0:
        if os.getenv("CI", "").lower() not in ("", "0", "false", "no"):
            pytest.fail(f"Docker is required for the Linux isolation gate: {result.stderr}")
        pytest.skip("Docker daemon is unavailable")


def env_for(tmp_path, **extra):
    values = {
        "DATACON_OPERATOR_ID": "e2e-reviewer",
        "DATACON_RUN_ROOT": str(tmp_path / "runs"),
        "DATACON_EVIDENCE_ROOT": str(tmp_path / "evidence"),
    }
    values.update(extra)
    return values


def approved(database, tmp_path, *, case_id="fixture-c-parser"):
    env = env_for(tmp_path)
    job = submit(database.dsn, write_request(tmp_path, case_id=case_id), env_extra=env)
    worker(database.dsn, env_extra=env)
    digest = status(database.dsn, job["job_id"])["pending_plan"]["plan_digest"]
    accepted = review(
        database.dsn, job["job_id"], digest, "approve", env_extra=env
    )
    assert accepted.returncode == 0, accepted.stderr
    return job, digest, env


def test_mvp01_reproduced_six_replays_export_and_verify(
    isolated_database, tmp_path
):
    job, digest, env = approved(isolated_database, tmp_path)
    result = worker(isolated_database.dsn, env_extra=env, execute=True)
    assert result["processed"] == 1
    assert result["state"] == "REPRODUCED", result

    current = status(isolated_database.dsn, job["job_id"])
    assert current["state"] == "REPRODUCED"
    assert current["verdict"] == "REPRODUCED"
    assert current["evidence"]["available"] is True
    bundle = Path(current["evidence"]["path"])
    verified = verify_bundle(bundle)
    report = json.loads(verified.file_data["report.json"])
    assert len(report["replays"]) == 6
    phases = sorted((item["version"], item["phase"]) for item in report["replays"])
    assert phases == sorted(
        (version, phase)
        for version in ("vulnerable", "fixed")
        for phase in ("normal", "candidate_1", "candidate_2")
    )
    for run in report["replays"]:
        assert run["status"] == "completed"
        assert run["container_id"]
    assert len({run["container_id"] for run in report["replays"]}) == 6

    assert report["environment"]["probe"]["checks"]["routes"] == ""
    assert report["environment"]["probe"]["checks"]["uid"] == "65534"
    assert report["environment"]["probe"]["checks"]["seccomp"] == "2"
    assert "-fsanitize=address" in report["environment"]["compile_args"]
    assert report["environment"]["image_digest"].startswith("sha256:")

    leftovers = subprocess.run(
        [
            "docker",
            "ps",
            "-aq",
            "--filter",
            f"label=datacon.job_id={job['job_id']}",
        ],
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert leftovers.returncode == 0
    assert leftovers.stdout.strip() == "", "sandbox containers were not removed"

    destination = tmp_path / "exported"
    exported = cli(
        "export",
        job["job_id"],
        "--out",
        str(destination),
        database_url=isolated_database.dsn,
    )
    assert exported.returncode == 0, exported.stderr
    payload = json.loads(exported.stdout)
    assert payload["manifest_digest"] == current["evidence"]["digest"]
    assert verify_bundle(destination).manifest_digest == current["evidence"]["digest"]

    # MVP-04: tampering and extra files fail offline verification.
    (destination / "report.json").write_text("{}", encoding="utf-8")
    tampered = cli("verify-bundle", str(destination))
    assert tampered.returncode == 3
    assert json.loads(tampered.stderr)["reason_code"] == "DIGEST_MISMATCH"

    # Use the pristine archive for the extra-file case.
    clean = tmp_path / "clean-bundle"
    shutil.copytree(bundle, clean)
    (clean / "unexpected.txt").write_text("extra", encoding="utf-8")
    extra_result = cli("verify-bundle", str(clean))
    assert extra_result.returncode == 3
    assert json.loads(extra_result.stderr)["reason_code"] == "EXTRA_FILE"


def test_mvp02_clean_candidate_is_not_reproduced(isolated_database, tmp_path):
    job, _, env = approved(
        isolated_database, tmp_path, case_id="fixture-c-parser-clean"
    )
    result = worker(isolated_database.dsn, env_extra=env, execute=True)
    assert result["state"] == "NOT_REPRODUCED", result
    current = status(isolated_database.dsn, job["job_id"])
    assert current["verdict"] == "NOT_REPRODUCED"
    report = json.loads(
        verify_bundle(current["evidence"]["path"]).file_data["report.json"]
    )
    assert report["rule"]["reason_code"] == "CANDIDATE_CLEAN"
    assert len(report["replays"]) == 6


def test_mvp03_rejected_review_never_starts_a_container(
    isolated_database, tmp_path
):
    env = env_for(tmp_path)
    job = submit(isolated_database.dsn, write_request(tmp_path), env_extra=env)
    worker(isolated_database.dsn, env_extra=env)
    digest = status(isolated_database.dsn, job["job_id"])["pending_plan"]["plan_digest"]

    mismatch = review(
        isolated_database.dsn,
        job["job_id"],
        "sha256:" + "0" * 64,
        "approve",
        env_extra=env,
    )
    assert mismatch.returncode == 3
    assert json.loads(mismatch.stderr)["reason_code"] == "PLAN_MISMATCH"

    rejected = review(
        isolated_database.dsn, job["job_id"], digest, "reject", env_extra=env
    )
    assert rejected.returncode == 0, rejected.stderr
    worker(isolated_database.dsn, env_extra=env, execute=True)
    current = status(isolated_database.dsn, job["job_id"])
    assert current["state"] == "BLOCKED"
    assert current["reason_code"] == "REVIEW_REJECTED"
    assert current["verdict"] is None
    row = isolated_database.connection.execute(
        "SELECT count(*) FROM attempts WHERE job_id = %s AND stage = 'execute'",
        (uuid.UUID(job["job_id"]),),
    ).fetchone()
    assert row[0] == 0


def test_mvp03_crash_after_tool_recovers_and_reuses_result(
    isolated_database, tmp_path
):
    job, _, env = approved(isolated_database, tmp_path)
    fault_env = {
        **env,
        "DATACON_FAULT_AFTER_TOOL": "build:vulnerable",
        "DATACON_TEST_MODE": "1",
    }
    crashed = cli(
        "worker",
        "--once",
        database_url=isolated_database.dsn,
        env_extra=fault_env,
    )
    assert crashed.returncode == 70, crashed.stderr
    job_uuid = uuid.UUID(job["job_id"])
    crashed_job = state.load_job(isolated_database.dsn, job_uuid)
    assert crashed_job["state"] == "RUNNING"
    old_generation = crashed_job["generation"]
    assert isolated_database.connection.execute(
        "SELECT count(*) FROM attempts WHERE job_id = %s AND stage = 'execute' "
        "AND step_key = 'build:vulnerable' AND generation = %s AND status = 'started'",
        (job_uuid, old_generation),
    ).fetchone()[0] == 1

    isolated_database.connection.execute(
        "UPDATE jobs SET lease_expires_at = now() - interval '1 second' "
        "WHERE job_id = %s",
        (job_uuid,),
    )
    recovered = worker(isolated_database.dsn, env_extra=env, execute=True)
    assert recovered["state"] == "REPRODUCED", recovered
    current = status(isolated_database.dsn, job["job_id"])
    assert current["verdict"] == "REPRODUCED"
    attempts = isolated_database.connection.execute(
        "SELECT result FROM attempts WHERE job_id = %s AND stage = 'execute' "
        "AND step_key = 'build:vulnerable' ORDER BY generation",
        (job_uuid,),
    ).fetchall()
    assert any(
        isinstance(row[0], dict) and row[0].get("reused") is True for row in attempts
    )
    assert state.record_attempt(
        isolated_database.dsn,
        job_uuid,
        stage="execute",
        step_key="build:vulnerable",
        attempt_no=99,
        generation=old_generation,
        input_digest=None,
        status="completed",
        result={"stale": True},
    ) is False


def _remove_option(args, option, count=1):
    index = args.index(option)
    del args[index : index + 1 + count]


def _set_option(args, option, value):
    index = args.index(option)
    args[index + 1] = value


def _remove_all(args, option, count=1):
    while option in args:
        _remove_option(args, option, count)


def _seccomp_unconfined(args):
    for index, item in enumerate(args):
        if item.startswith("seccomp="):
            args[index] = "seccomp=unconfined"


def _seccomp_missing(args):
    for index in range(len(args) - 1, -1, -1):
        if args[index] == "--security-opt" and args[index + 1].startswith(
            "seccomp="
        ):
            del args[index : index + 2]


def _tmpfs_unbounded(args):
    for index, item in enumerate(args):
        if item == "--tmpfs":
            target = args[index + 1].split(":", 1)[0]
            args[index + 1] = f"{target}:rw"


def _remove_security_opt(args, value):
    for index in range(len(args) - 2, -1, -1):
        if args[index] == "--security-opt" and args[index + 1] == value:
            del args[index : index + 2]
            return
    raise AssertionError(f"{value} security option not found")


NEGATIVE_MUTATIONS = [
    ("read-only-root", lambda args: args.remove("--read-only")),
    ("user-root", lambda args: _set_option(args, "--user", "0:0")),
    ("network-bridge", lambda args: _set_option(args, "--network", "bridge")),
    (
        "no-new-privileges",
        lambda args: _remove_security_opt(args, "no-new-privileges"),
    ),
    ("seccomp-missing", _seccomp_missing),
    ("seccomp-unconfined", _seccomp_unconfined),
    ("pids-limit", lambda args: _remove_option(args, "--pids-limit")),
    (
        "memory-limit",
        lambda args: (
            _remove_option(args, "--memory-swap"),
            _remove_option(args, "--memory"),
        ),
    ),
    ("cpu-limit", lambda args: _remove_option(args, "--cpus")),
    ("tmpfs-limit", _tmpfs_unbounded),
]


@pytest.mark.parametrize(
    "mutation", [item[1] for item in NEGATIVE_MUTATIONS], ids=[item[0] for item in NEGATIVE_MUTATIONS]
)
def test_mvp04_single_control_drift_is_rejected_and_cleaned_up(
    tmp_path, monkeypatch, mutation
):
    policy = IsolationPolicy(
        network="none",
        user="65534:65534",
        read_only_root=True,
        cap_drop=("ALL",),
        no_new_privileges=True,
        seccomp="runtime/default",
        seccomp_profile_digest=SECCOMP_PROFILE_DIGEST,
    )
    limits = ResourceLimits(cpu=2, memory_mib=2048, pids=128, scratch_mib=512)
    job_id = f"negative-{uuid.uuid4().hex}"
    sandbox = DockerSandbox(
        image=(
            "silkeh/clang:19-bookworm@sha256:"
            "f5ce959d91f059acf5a4b3f1c19f46713c4b2881c7d7cd1d5143ca1d1412277f"
        ),
        platform="linux/amd64",
        policy=policy,
        limits=limits,
        job_id=job_id,
        run_root=tmp_path / "runs",
    )
    fixture = tmp_path / "fixture"
    fixture.mkdir()
    (fixture / "marker.txt").write_text("read-only\n", encoding="utf-8")
    real_create_args = sandbox_module.container_create_args

    def drifted_create_args(**kwargs):
        command = real_create_args(**kwargs)
        mutation(command)
        return command

    monkeypatch.setattr(
        sandbox_module, "container_create_args", drifted_create_args
    )
    with pytest.raises(SandboxPolicyError):
        sandbox._create(
            suffix="negative",
            command=["/bin/true"],
            mounts=[(str(fixture), "/fixture", True)],
        )
    leftovers = subprocess.run(
        ["docker", "ps", "-aq", "--filter", f"label=datacon.job_id={job_id}"],
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert leftovers.returncode == 0
    assert leftovers.stdout.strip() == "", "a drifted container was not removed"

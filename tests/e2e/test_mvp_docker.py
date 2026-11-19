"""MVP-01..04 with the real CLI, PostgreSQL and the pinned Linux/amd64 image.

These tests are the Docker integration gate. They are skipped locally when the
Docker daemon is unavailable; CI fails instead of silently skipping.
"""

from __future__ import annotations

from dataclasses import replace
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
    (
        "read-only-root",
        lambda args: args.remove("--read-only"),
        "root filesystem",
    ),
    ("user-root", lambda args: _set_option(args, "--user", "0:0"), "user"),
    (
        "network-bridge",
        lambda args: _set_option(args, "--network", "bridge"),
        "network mode",
    ),
    (
        "no-new-privileges",
        lambda args: _remove_security_opt(args, "no-new-privileges"),
        "no-new-privileges",
    ),
    ("seccomp-missing", _seccomp_missing, "seccomp"),
    ("seccomp-unconfined", _seccomp_unconfined, "seccomp"),
    ("pids-limit", lambda args: _remove_option(args, "--pids-limit"), "PID limit"),
    (
        "memory-limit",
        lambda args: (
            _remove_option(args, "--memory-swap"),
            _remove_option(args, "--memory"),
        ),
        "memory",
    ),
    ("cpu-limit", lambda args: _remove_option(args, "--cpus"), "CPU limit"),
    ("tmpfs-limit", _tmpfs_unbounded, "bounded"),
]


@pytest.mark.parametrize(
    "label,mutation,expected",
    NEGATIVE_MUTATIONS,
    ids=[item[0] for item in NEGATIVE_MUTATIONS],
)
def test_mvp04_single_control_drift_is_rejected_and_cleaned_up(
    tmp_path, monkeypatch, label, mutation, expected
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
        generation=7,
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
    with pytest.raises(SandboxPolicyError) as caught:
        sandbox._create(
            suffix="negative",
            command=["/bin/true"],
            mounts=[(str(fixture), "/fixture", True)],
        )
    assert expected in str(caught.value), (
        f"{label} drift was rejected for the wrong reason: {caught.value}"
    )
    leftovers = subprocess.run(
        ["docker", "ps", "-aq", "--filter", f"label=datacon.job_id={job_id}"],
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert leftovers.returncode == 0
    assert leftovers.stdout.strip() == "", "a drifted container was not removed"


def test_reclaim_job_removes_only_older_generations_on_real_docker(
    isolated_database, tmp_path
):
    """Prove generation labels and reclaim semantics with the real daemon.

    The fake-docker contract test covers the label parsing; this test creates
    real containers for three generations and checks that ``reclaim_job``
    deletes only the older one while leaving the current and newer containers
    (and their labels) intact.
    """
    job_id = f"reclaim-{uuid.uuid4().hex}"
    image = (
        "silkeh/clang:19-bookworm@sha256:"
        "f5ce959d91f059acf5a4b3f1c19f46713c4b2881c7d7cd1d5143ca1d1412277f"
    )
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
    run_root = tmp_path / "reclaim-runs"

    def sandbox_for(generation):
        return DockerSandbox(
            image=image,
            platform="linux/amd64",
            policy=policy,
            limits=limits,
            job_id=job_id,
            run_root=run_root,
            generation=generation,
        )

    containers = {}
    try:
        for generation in (1, 2, 3):
            sandbox = sandbox_for(generation)
            sandbox.ensure_image()
            name, _ = sandbox._create(
                suffix=f"generation-{generation}",
                command=["/bin/sleep", "60"],
                mounts=[],
            )
            containers[generation] = name

        removed = sandbox_for(2).reclaim_job()
        assert removed == 1

        present = subprocess.run(
            ["docker", "inspect", containers[2], containers[3]],
            capture_output=True,
            text=True,
            timeout=30,
        )
        assert present.returncode == 0, present.stderr
        listed = json.loads(present.stdout)
        labels = {
            item["Name"].lstrip("/"): item["Config"]["Labels"] for item in listed
        }
        for generation in (2, 3):
            label = labels[containers[generation]]
            assert label["datacon.job_id"] == job_id
            assert label["datacon.generation"] == str(generation)

        removed_container = subprocess.run(
            ["docker", "inspect", containers[1]],
            capture_output=True,
            text=True,
            timeout=30,
        )
        assert removed_container.returncode != 0
    finally:
        if containers:
            subprocess.run(
                ["docker", "rm", "-f", *containers.values()],
                capture_output=True,
                text=True,
                timeout=60,
            )


# ---------------------------------------------------------------------------
# B3: target-written completion/exit files never decide the evidence.
# ---------------------------------------------------------------------------

PINNED_IMAGE = (
    "silkeh/clang:19-bookworm@sha256:"
    "f5ce959d91f059acf5a4b3f1c19f46713c4b2881c7d7cd1d5143ca1d1412277f"
)


def _sandbox(tmp_path, job_id):
    policy = IsolationPolicy(
        network="none",
        user="65534:65534",
        read_only_root=True,
        cap_drop=("ALL",),
        no_new_privileges=True,
        seccomp="runtime/default",
        seccomp_profile_digest=SECCOMP_PROFILE_DIGEST,
    )
    return DockerSandbox(
        image=PINNED_IMAGE,
        platform="linux/amd64",
        policy=policy,
        limits=ResourceLimits(cpu=2, memory_mib=2048, pids=128, scratch_mib=512),
        job_id=job_id,
        run_root=tmp_path / "runs",
        generation=1,
    )


def _write_target(tmp_path, body: str) -> tuple[Path, Path]:
    parser = tmp_path / "parser"
    parser.write_text("#!/bin/sh\n" + body, encoding="utf-8")
    parser.chmod(0o555)
    input_file = tmp_path / "input"
    input_file.write_text("ABCD\n", encoding="utf-8")
    input_file.chmod(0o444)
    return parser, input_file


def test_target_cannot_touch_done_early_and_hide_asan(tmp_path):
    parser, input_file = _write_target(
        tmp_path,
        "printf 'ABCD\\n' > /work/stdout\n"
        "printf '0\\n' > /work/exit_code\n"
        "touch /work/done\n"
        "sleep 2\n"
        "printf '==1==ERROR: AddressSanitizer: heap-buffer-overflow\\n"
        "WRITE of size 1\\n' >&2\n"
        "exit 1\n",
    )
    job_id = "b3-" + uuid.uuid4().hex
    sandbox = _sandbox(tmp_path, job_id)
    result = sandbox.replay(
        "fixed",
        "candidate_1",
        artifact_path=parser,
        input_path=input_file,
        asan_options="detect_leaks=0",
        timeout_seconds=60,
    )
    assert result.status == "completed"
    assert result.exit_code == 1
    assert b"AddressSanitizer" in result.stderr
    assert result.signature is not None
    # The replay is not clean regardless of what the target wrote to /work.
    assert not (
        result.exit_code == 0 and result.signature is None
    )
    leftovers = subprocess.run(
        [
            "docker",
            "ps",
            "-aq",
            "--filter",
            f"label=datacon.job_id={job_id}",
        ],
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert leftovers.stdout.strip() == ""


def test_replay_exit_code_comes_from_container_not_work_file(tmp_path):
    parser, input_file = _write_target(
        tmp_path,
        "printf '0\\n' > /work/exit_code\n"
        "printf 'fake clean\\n' > /work/stdout\n"
        "touch /work/done\n"
        "exit 7\n",
    )
    job_id = "b3-exit-" + uuid.uuid4().hex
    sandbox = _sandbox(tmp_path, job_id)
    result = sandbox.replay(
        "vulnerable",
        "candidate_1",
        artifact_path=parser,
        input_path=input_file,
        asan_options="detect_leaks=0",
        timeout_seconds=60,
    )
    assert result.exit_code == 7
    assert result.status == "completed"
    assert b"fake clean" not in result.stdout


def _six_runs_for_truncated_candidate(result):
    from datacon.verdict import observation_from_run

    obs = observation_from_run(result.as_dict())
    return [
        obs,
        replace(obs, phase="candidate_2"),
        replace(
            obs,
            phase="normal",
            status="completed",
            exit_code=0,
            stdout="OK\n",
            stderr="",
            signature=None,
            log_truncated=False,
        ),
        replace(
            obs,
            version="fixed",
            phase="normal",
            status="completed",
            exit_code=0,
            stdout="OK\n",
            stderr="",
            signature=None,
            log_truncated=False,
        ),
        replace(
            obs,
            version="fixed",
            phase="candidate_1",
            status="completed",
            exit_code=0,
            stdout="ABCD\n",
            stderr="",
            signature=None,
            log_truncated=False,
        ),
        replace(
            obs,
            version="fixed",
            phase="candidate_2",
            status="completed",
            exit_code=0,
            stdout="ABCD\n",
            stderr="",
            signature=None,
            log_truncated=False,
        ),
    ]


def _reproduced_policy():
    from datacon.verdict import VerdictPolicy

    return VerdictPolicy(
        signature={
            "error": "heap-buffer-overflow",
            "operation": "WRITE",
            "access_size": 1,
            "function": "parse_token",
            "source": "parser.c",
        },
        expected_exit={"normal": 0, "candidate_clean": 0, "candidate_asan": 86},
        expected_stdout={"normal": "OK\n", "candidate_clean": "ABCD\n"},
    )


def test_s3_real_docker_40mib_stderr_stream_truncation_blocks_reproduced(
    tmp_path,
):
    from datacon.verdict import decide_verdict

    parser, input_file = _write_target(
        tmp_path,
        "printf '==1==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x502000000014\n"
        "WRITE of size 1 at 0x502000000014 thread T0\n"
        "    #0 0x55555565fadf in parse_token /fixture/vulnerable/parser.c:22:17\n"
        "SUMMARY: AddressSanitizer: heap-buffer-overflow /fixture/vulnerable/parser.c:22:17 in parse_token\n' >&2\n"
        "dd if=/dev/zero bs=1048576 count=40 2>/dev/null | tr '\\0' 'X' >&2\n"
        "exit 86\n",
    )
    job_id = "s3-stream-" + uuid.uuid4().hex
    sandbox = _sandbox(tmp_path, job_id)
    result = sandbox.replay(
        "vulnerable",
        "candidate_1",
        artifact_path=parser,
        input_path=input_file,
        asan_options="detect_leaks=0",
        timeout_seconds=120,
    )
    assert result.exit_code == 86
    # The non-zero target status is a normal attached completion, not an
    # attach failure; only the stream budget is truncated.
    assert result.status == "completed"
    assert result.capture_error is None
    # 40 MiB on stderr exceeds the 16 MiB union budget: no rotation, just a
    # stream-level truncation with the over-budget role recorded explicitly.
    assert result.log_truncated is True
    assert "stderr" in result.truncated_roles
    assert "stdout" not in result.truncated_roles
    assert len(result.stderr) == sandbox_module.MAX_LOG_BYTES

    decision = decide_verdict(
        _reproduced_policy(), _six_runs_for_truncated_candidate(result)
    )
    assert decision.verdict == "INCONCLUSIVE"
    assert decision.reason_code == "EVIDENCE_INCOMPLETE"


def test_s3_real_docker_10mib_stdout_plus_10mib_stderr_union_cap(
    tmp_path,
):
    from datacon.verdict import decide_verdict

    parser, input_file = _write_target(
        tmp_path,
        "dd if=/dev/zero bs=1048576 count=10 2>/dev/null | tr '\\0' 'O'\n"
        # Let the stdout reader drain the first 10 MiB before stderr starts so
        # the split is deterministic: stdout fits, stderr takes the remainder.
        "sleep 1\n"
        "dd if=/dev/zero bs=1048576 count=10 2>/dev/null | tr '\\0' 'E' >&2\n"
        "exit 0\n",
    )
    job_id = "s3-union-" + uuid.uuid4().hex
    sandbox = _sandbox(tmp_path, job_id)
    result = sandbox.replay(
        "vulnerable",
        "candidate_1",
        artifact_path=parser,
        input_path=input_file,
        asan_options="detect_leaks=0",
        timeout_seconds=120,
    )
    # stdout fits in the union budget first; the later stderr bytes are capped
    # by the remaining budget and that specific role is reported.
    assert result.exit_code == 0
    assert result.status == "completed"
    assert result.capture_error is None
    assert result.log_truncated is True
    assert result.truncated_roles == ("stderr",)
    assert len(result.stdout) == 10 * 1024 * 1024
    assert len(result.stderr) == 6 * 1024 * 1024
    assert len(result.stdout) + len(result.stderr) == sandbox_module.MAX_LOG_BYTES

    decision = decide_verdict(
        _reproduced_policy(), _six_runs_for_truncated_candidate(result)
    )
    assert decision.verdict == "INCONCLUSIVE"
    assert decision.reason_code == "EVIDENCE_INCOMPLETE"


def test_start_attach_captures_first_stdout_and_stderr_bytes(tmp_path):
    parser, input_file = _write_target(
        tmp_path,
        "printf 'first-stdout\\n'\n"
        "printf 'first-stderr\\n' >&2\n"
        "exit 0\n",
    )
    job_id = "attach-first-" + uuid.uuid4().hex
    sandbox = _sandbox(tmp_path, job_id)
    result = sandbox.replay(
        "fixed",
        "normal",
        artifact_path=parser,
        input_path=input_file,
        asan_options="detect_leaks=0",
        timeout_seconds=60,
    )
    assert result.exit_code == 0
    assert result.status == "completed"
    assert result.log_truncated is False
    assert result.truncated_roles == ()
    assert result.capture_error is None
    assert b"first-stdout" in result.stdout
    assert b"first-stderr" in result.stderr

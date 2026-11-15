"""TC-05: the container command and inspect checks enforce REQ-05."""

from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import stat
from types import SimpleNamespace
from uuid import uuid4

import pytest

from datacon import execution
from datacon.tools.sandbox import (
    SECCOMP_PROFILE_DIGEST,
    SECCOMP_PROFILE_PATH,
    BuildResult,
    DockerSandbox,
    IsolationPolicy,
    ReplayResult,
    ResourceLimits,
    SandboxError,
    SandboxPolicyError,
    container_create_args,
    evaluate_probe_values,
    validate_host_config,
)

POLICY = IsolationPolicy(
    network="none",
    user="65534:65534",
    read_only_root=True,
    cap_drop=("ALL",),
    no_new_privileges=True,
    seccomp="runtime/default",
    seccomp_profile_digest=SECCOMP_PROFILE_DIGEST,
)
LIMITS = ResourceLimits(
    cpu=2,
    memory_mib=2048,
    pids=128,
    scratch_mib=512,
)
IMAGE = "silkeh/clang:19-bookworm@sha256:" + "a" * 64
MOUNT_SOURCE = str(Path(__file__).resolve())
SECCOMP_OPTION = "seccomp=" + SECCOMP_PROFILE_PATH.read_text(encoding="utf-8")


def args(**overrides):
    values = {
        "image": IMAGE,
        "platform": "linux/amd64",
        "policy": POLICY,
        "limits": LIMITS,
        "name": "datacon-test",
        "command": ["/bin/sh", "-c", "true"],
        "mounts": [(MOUNT_SOURCE, "/fixture", True)],
        "env": {"ASAN_OPTIONS": "detect_leaks=0"},
    }
    values.update(overrides)
    return container_create_args(**values)


def security_options(command):
    return [
        command[index + 1]
        for index, item in enumerate(command)
        if item == "--security-opt"
    ]


def test_container_command_enforces_every_isolation_control():
    command = args()
    assert command[:2] == ["docker", "create"]
    assert "--network" in command
    assert command[command.index("--network") + 1] == "none"
    assert command[command.index("--user") + 1] == "65534:65534"
    assert "--read-only" in command
    assert command[command.index("--cap-drop") + 1] == "ALL"
    options = security_options(command)
    assert "no-new-privileges" in options
    seccomp = [item for item in options if item.startswith("seccomp=")]
    assert seccomp == [f"seccomp={SECCOMP_PROFILE_PATH}"]
    assert "seccomp=unconfined" not in " ".join(command)
    assert command[command.index("--pids-limit") + 1] == "128"
    assert command[command.index("--memory") + 1] == "2048m"
    assert command[command.index("--memory-swap") + 1] == "2048m"
    assert command[command.index("--cpus") + 1] == "2"
    assert "--platform" in command
    assert command[command.index("--platform") + 1] == "linux/amd64"
    mount = command[command.index("--mount") + 1]
    assert "type=bind" in mount
    assert "readonly" in mount
    assert "docker.sock" not in " ".join(command)
    assert "--privileged" not in command
    assert all(item != "--env" for item in command if item.startswith("DATACON_"))


def test_writable_workspaces_are_bounded_and_total_within_scratch_budget():
    command = args()
    tmpfs = [command[index + 1] for index, item in enumerate(command) if item == "--tmpfs"]
    assert any(value.startswith("/work:") for value in tmpfs)
    assert any(value.startswith("/tmp:") for value in tmpfs)
    sizes = {}
    for value in tmpfs:
        target, options = value.split(":", 1)
        size = int(options.split("size=")[1].split(",")[0].rstrip("m"))
        sizes[target] = size
    assert sizes["/work"] + sizes["/tmp"] <= LIMITS.scratch_mib
    assert sizes["/tmp"] >= 16


@pytest.mark.parametrize(
    "policy",
    [
        replace(POLICY, network="bridge"),
        replace(POLICY, user="0:0"),
        replace(POLICY, read_only_root=False),
        replace(POLICY, cap_drop=()),
        replace(POLICY, no_new_privileges=False),
        replace(POLICY, seccomp="unconfined"),
        replace(POLICY, seccomp_profile_digest=None),
        replace(POLICY, seccomp_profile_digest="sha256:" + "0" * 64),
    ],
)
def test_invalid_isolation_policy_is_refused(policy):
    with pytest.raises(SandboxPolicyError):
        args(policy=policy)


def test_legacy_plan_without_seccomp_profile_digest_is_refused():
    with pytest.raises(SandboxPolicyError, match="seccomp profile digest"):
        IsolationPolicy.from_plan(
            {
                "network": "none",
                "user": "65534:65534",
                "read_only_root": True,
                "cap_drop": ["ALL"],
                "no_new_privileges": True,
                "seccomp": "runtime/default",
            }
        )


def host_config(**overrides):
    value = {
        "NetworkMode": "none",
        "User": "65534:65534",
        "ReadonlyRootfs": True,
        "CapDrop": ["ALL"],
        "CapAdd": [],
        "SecurityOpt": ["no-new-privileges", SECCOMP_OPTION],
        "Privileged": False,
        "PidsLimit": 128,
        "Memory": 2048 * 1024 * 1024,
        "MemorySwap": 2048 * 1024 * 1024,
        "NanoCpus": 2_000_000_000,
        "Binds": [f"{MOUNT_SOURCE}:/fixture:ro"],
        "Tmpfs": {"/work": "rw,exec,size=496m,mode=1777", "/tmp": "rw,exec,size=16m,mode=1777"},
        "IpcMode": "private",
        "Devices": [],
    }
    value.update(overrides)
    return value


def declared_mounts():
    return [(MOUNT_SOURCE, "/fixture", True)]


def test_host_config_must_show_the_requested_limits():
    validate_host_config(
        host_config(), POLICY, LIMITS, mounts=declared_mounts()
    )


@pytest.mark.parametrize(
    "change",
    [
        {"NetworkMode": "default"},
        {"User": "0"},
        {"ReadonlyRootfs": False},
        {"CapDrop": []},
        {"SecurityOpt": ["no-new-privileges", "seccomp=unconfined"]},
        {"SecurityOpt": ["no-new-privileges"]},
        {
            "SecurityOpt": [
                "no-new-privileges",
                "seccomp=" + json.dumps({"defaultAction": "SCMP_ACT_ALLOW"}),
            ]
        },
        {"Privileged": True},
        {"PidsLimit": 0},
        {"Memory": 4096 * 1024 * 1024},
        {"NanoCpus": 4_000_000_000},
        {"Binds": [f"{MOUNT_SOURCE}:/fixture"]},
        {"Binds": [f"{MOUNT_SOURCE}:/fixture:ro", "/etc:/extra:ro"]},
        {"Binds": [f"{MOUNT_SOURCE}:/materials:ro"]},
        {"Tmpfs": {}},
    ],
)
def test_drifted_or_unenforced_limits_are_refused(change):
    with pytest.raises(SandboxPolicyError):
        validate_host_config(
            host_config(**change), POLICY, LIMITS, mounts=declared_mounts()
        )


def test_extra_read_only_host_mount_is_refused():
    config = host_config(
        Binds=[f"{MOUNT_SOURCE}:/fixture:ro", "/etc:/host-etc:ro"]
    )
    with pytest.raises(SandboxPolicyError, match="undeclared"):
        validate_host_config(config, POLICY, LIMITS, mounts=declared_mounts())


def test_relative_or_symlinked_bind_sources_are_refused(tmp_path):
    link = tmp_path / "link"
    link.symlink_to(tmp_path)
    with pytest.raises(SandboxPolicyError):
        args(mounts=[("relative/path", "/fixture", True)])
    with pytest.raises(SandboxPolicyError):
        args(mounts=[(str(link), "/fixture", True)])


BASE_PROBE_VALUES = {
    "uid": "65534",
    "seccomp": "2",
    "seccomp_filters": "1",
    "no_new_privs": "1",
    "cap_eff": "0000000000000000",
    "cgroup_version": "2",
    "pids": "128",
    "memory": str(2048 * 1024 * 1024),
    "cpu": "200000 100000",
    "cpu_quota_us": "unknown",
    "cpu_period_us": "unknown",
    "work_mib": "496",
    "tmp_mib": "16",
    "links": "",
    "ipv6_links": "",
    "routes": "",
    "ipv6_routes": "",
    "oom_killed": False,
}


def probe(values=None, *, exit_code=0, oom_killed=False):
    merged = dict(BASE_PROBE_VALUES)
    if values:
        merged.update(values)
    return evaluate_probe_values(
        merged, POLICY, LIMITS, exit_code=exit_code, oom_killed=oom_killed
    )


def test_probe_accepts_provable_cgroup_v2_limits():
    ok, checks = probe()
    assert ok is True, checks


@pytest.mark.parametrize(
    "change",
    [
        {"pids": "max"},
        {"memory": "max"},
        {"cpu": "max 100000"},
        {"pids": "unknown"},
        {"memory": "unknown"},
        {"cgroup_version": "unknown", "memory": "unknown"},
    ],
)
def test_probe_rejects_unlimited_or_unknown_limits(change):
    ok, checks = probe(change)
    assert ok is False
    assert checks["errors"]


def test_probe_accepts_cgroup_v1_limits_when_v2_is_absent():
    ok, checks = probe(
        {
            "cgroup_version": "1",
            "cpu": "unknown",
            "cpu_quota_us": "200000",
            "cpu_period_us": "100000",
        }
    )
    assert ok is True, checks


def test_probe_rejects_unlimited_cgroup_v1_limits():
    ok, checks = probe(
        {
            "cgroup_version": "1",
            "cpu": "unknown",
            "cpu_quota_us": "-1",
            "cpu_period_us": "100000",
        }
    )
    assert ok is False, checks


@pytest.mark.parametrize(
    "change",
    [
        {"links": "eth0:up"},
        {"ipv6_links": "00000000000000000000000000000000 02 40 00 00 eth0"},
        {"routes": "00000000 00000000"},
        {"ipv6_routes": "00000000000000000000000000000000 00 0 00000000000000000000000000000000 00 00000000000000000000000000000000 00000000 00000002 00000000 00000000 eth0"},
        {"no_new_privs": "0"},
        {"cap_eff": "0000000000000001"},
        {"seccomp_filters": "0"},
        {"seccomp": "0"},
    ],
)
def test_probe_rejects_network_and_kernel_boundary_drift(change):
    ok, checks = probe(change)
    assert ok is False, checks


class RecordingSandbox(DockerSandbox):
    def __init__(self, tmp_path, inspect_payload, *, inspect_error=False, generation=None):
        options = dict(
            image=IMAGE,
            platform="linux/amd64",
            policy=POLICY,
            limits=LIMITS,
            docker="docker",
            job_id="job-1234",
            run_root=tmp_path,
        )
        if generation is not None:
            options["generation"] = generation
        super().__init__(**options)
        self.calls = []
        self.inspect_payload = inspect_payload
        self.inspect_error = inspect_error

    def _docker(self, command, *, timeout=60.0):
        self.calls.append(list(command))
        if command[0] == "create":
            return SimpleNamespace(returncode=0, stdout=b"cid", stderr=b"")
        if command[0] == "inspect":
            if self.inspect_error:
                return SimpleNamespace(returncode=1, stdout=b"", stderr=b"no such object")
            return SimpleNamespace(
                returncode=0,
                stdout=json.dumps([self.inspect_payload]).encode(),
                stderr=b"",
            )
        if command[0] == "rm":
            return SimpleNamespace(returncode=0, stdout=b"", stderr=b"")
        raise AssertionError(f"unexpected docker command: {command}")

    def removed(self):
        return [call for call in self.calls if call and call[0] == "rm"]


def _inspect_payload(**overrides):
    config = host_config()
    payload = {
        "Config": {"User": config["User"]},
        "HostConfig": {key: value for key, value in config.items() if key != "User"},
        "Mounts": [
            {
                "Type": "bind",
                "Source": MOUNT_SOURCE,
                "Destination": "/fixture",
                "RW": False,
            }
        ],
    }
    if overrides:
        payload["HostConfig"].update(overrides)
    return payload


def test_create_removes_the_container_when_validation_fails(tmp_path):
    sandbox = RecordingSandbox(
        tmp_path, _inspect_payload(ReadonlyRootfs=False)
    )
    with pytest.raises(SandboxPolicyError):
        sandbox._create(
            suffix="negative",
            command=["/bin/true"],
            mounts=[(MOUNT_SOURCE, "/fixture", True)],
        )
    assert sandbox.removed(), "created container was not removed"
    assert any(call[1] == "-f" for call in sandbox.removed())


def test_create_removes_the_container_when_inspect_fails(tmp_path):
    sandbox = RecordingSandbox(tmp_path, {}, inspect_error=True)
    with pytest.raises(SandboxError):
        sandbox._create(
            suffix="negative",
            command=["/bin/true"],
            mounts=[(MOUNT_SOURCE, "/fixture", True)],
        )
    assert sandbox.removed(), "created container was not removed"


def test_create_removes_the_container_when_create_is_rejected(tmp_path):
    sandbox = RecordingSandbox(tmp_path, _inspect_payload())

    def reject(command, *, timeout=60.0):
        sandbox.calls.append(list(command))
        return SimpleNamespace(returncode=1, stdout=b"", stderr=b"bad create")

    sandbox._docker = reject
    with pytest.raises(SandboxError):
        sandbox._create(
            suffix="negative",
            command=["/bin/true"],
            mounts=[(MOUNT_SOURCE, "/fixture", True)],
        )
    assert any(call and call[0] == "rm" for call in sandbox.calls)


def _label_values(command):
    return [
        command[index + 1]
        for index, item in enumerate(command)
        if item == "--label"
    ]


def test_container_labels_include_generation():
    command = args(job_id="job-1234", generation=3)
    labels = _label_values(command)
    assert "datacon.job_id=job-1234" in labels
    assert "datacon.generation=3" in labels


def test_docker_sandbox_create_labels_the_generation(tmp_path):
    sandbox = RecordingSandbox(tmp_path, _inspect_payload(), generation=3)
    sandbox._create(
        suffix="labelled",
        command=["/bin/true"],
        mounts=[(MOUNT_SOURCE, "/fixture", True)],
    )
    created = next(call for call in sandbox.calls if call and call[0] == "create")
    labels = _label_values(created)
    assert "datacon.generation=3" in labels


def test_reclaim_removes_only_older_generation(tmp_path):
    sandbox = DockerSandbox(
        image=IMAGE,
        platform="linux/amd64",
        policy=POLICY,
        limits=LIMITS,
        docker="docker",
        job_id="job-1234",
        run_root=tmp_path,
        generation=5,
    )
    removed = []
    containers = {
        "old": "2",
        "current": "5",
        "newer": "6",
        "legacy": None,
    }

    def fake_docker(command, *, timeout=60.0):
        if command[0] == "ps":
            return SimpleNamespace(
                returncode=0,
                stdout=(" ".join(containers) + "\n").encode(),
                stderr=b"",
            )
        if command[0] == "inspect":
            name = command[1]
            labels = {"datacon.job_id": "job-1234"}
            if containers[name] is not None:
                labels["datacon.generation"] = containers[name]
            return SimpleNamespace(
                returncode=0,
                stdout=json.dumps([{"Config": {"Labels": labels}}]).encode(),
                stderr=b"",
            )
        if command[0] == "rm":
            removed.append(command[-1])
            return SimpleNamespace(returncode=0, stdout=b"", stderr=b"")
        raise AssertionError(f"unexpected docker command: {command}")

    sandbox._docker = fake_docker
    assert sandbox.reclaim_job() == 2
    assert set(removed) == {"old", "legacy"}
    assert "current" not in removed and "newer" not in removed


# ---------------------------------------------------------------------------
# R1: containers mount staging copies, never bytes inside the run root.
# ---------------------------------------------------------------------------

STAGE_MATERIALS = {
    "harness.c": b"int main(void) { return 0; }\n",
    "build.sh": (
        b"#!/bin/sh\nset -eu\n"
        b"clang -std=c11 -g -O0 -fsanitize=address "
        b"/fixture/harness.c -o /work/parser\n"
    ),
    "dependencies.lock": b"clang=19.1.7\n",
    "vulnerable/parser.c": b"char *parse_token(void) { return 0; }\n",
    "fixed/parser.c": b"char *parse_token(void) { return 0; }\n",
    "inputs/normal.txt": b"normal\n",
    "inputs/candidate.txt": b"candidate\n",
}


def _sha(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _staging_context(tmp_path, monkeypatch):
    run_root = tmp_path / "runs"
    materials = run_root / "materials"
    for relative, data in STAGE_MATERIALS.items():
        path = materials / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
    material_digests = {
        relative: _sha(data) for relative, data in STAGE_MATERIALS.items()
    }
    monkeypatch.setenv("DATACON_RUN_ROOT", str(run_root))
    monkeypatch.setenv("DATACON_EVIDENCE_ROOT", str(tmp_path / "evidence"))
    monkeypatch.delenv("DATACON_STAGING_ROOT", raising=False)
    manifest = {
        "harness": "harness.c",
        "build_recipe": "build.sh",
        "dependencies": "dependencies.lock",
        "versions": {
            "vulnerable": "vulnerable/parser.c",
            "fixed": "fixed/parser.c",
        },
    }
    job_id = uuid4()
    context = SimpleNamespace(
        job_id=job_id,
        job_id_text=str(job_id),
        generation=1,
        plan_digest="sha256:" + "c" * 64,
        plan={
            "harness_digest": material_digests["harness.c"],
            "build_recipe_digest": material_digests["build.sh"],
            "dependencies_digest": material_digests["dependencies.lock"],
            "analysis_digest": "sha256:" + "d" * 64,
            "inputs": {
                "normal": material_digests["inputs/normal.txt"],
                "candidate": material_digests["inputs/candidate.txt"],
            },
            "asan_options": "detect_leaks=0",
            "image_digest": "sha256:" + "a" * 64,
        },
        case=SimpleNamespace(manifest=manifest),
        materials={
            "vulnerable/parser.c": material_digests["vulnerable/parser.c"],
            "fixed/parser.c": material_digests["fixed/parser.c"],
        },
        compile_args=("-std=c11",),
        run_root=run_root,
        deadline_at=datetime.now(timezone.utc) + timedelta(seconds=60),
        reserve_seconds=1.0,
    )
    return context, materials, material_digests


def _is_inside(path: Path, root: Path) -> bool:
    resolved = path.resolve()
    resolved_root = root.resolve()
    return resolved == resolved_root or resolved_root in resolved.parents


def test_build_mounts_staged_materials_after_run_root_tamper(
    tmp_path, monkeypatch
):
    context, materials, digests = _staging_context(tmp_path, monkeypatch)

    class StagingBuildSandbox:
        def build(
            self,
            version,
            *,
            materials_dir,
            compile_args,
            deadline_seconds,
            expected_materials=None,
        ):
            # Simulate a writer that owns only the run root and replaces the
            # source tree immediately after the executor finished staging.
            (materials / "build.sh").write_bytes(b"#!/bin/sh\nexit 1\n")
            (materials / "harness.c").write_bytes(b"tampered harness\n")
            self.materials_dir = Path(materials_dir)
            self.recipe = (self.materials_dir / "build.sh").read_bytes()
            self.harness = (self.materials_dir / "harness.c").read_bytes()
            artifact = b"staged-parser"
            return BuildResult(
                version=version,
                status="completed",
                exit_code=0,
                duration_seconds=0.01,
                container_id="cid",
                image_digest=context.plan["image_digest"],
                compile_args=tuple(compile_args),
                artifact_digest=_sha(artifact),
                log=b"",
                log_truncated=False,
                artifact=artifact,
                metadata={"build_recipe_digest": digests["build.sh"]},
            )

    captured = {}

    def persist(
        dsn, ctx, result, attempt_no, token, *, staged_materials=None
    ):
        captured["staged"] = staged_materials
        return {"status": result.status}

    monkeypatch.setattr(execution, "_persist_build", persist)
    sandbox = StagingBuildSandbox()
    execution._do_build(
        "unused-dsn",
        context,
        sandbox,
        materials,
        digests,
        "vulnerable",
        1,
        "token",
    )

    assert not _is_inside(sandbox.materials_dir, context.run_root)
    assert sandbox.recipe == STAGE_MATERIALS["build.sh"]
    assert sandbox.harness == STAGE_MATERIALS["harness.c"]
    assert captured["staged"] == digests
    # Staging is removed after the attempt; the tampered run-root copy remains.
    assert not sandbox.materials_dir.exists()
    assert (materials / "build.sh").read_bytes() == b"#!/bin/sh\nexit 1\n"


def test_replay_mounts_staged_parser_and_input_after_run_root_tamper(
    tmp_path, monkeypatch
):
    context, _, digests = _staging_context(tmp_path, monkeypatch)
    work = (
        context.run_root
        / str(context.job_id)
        / context.plan_digest.split(":")[1]
        / "run"
    )
    run_artifact = work / "generation-1" / "build" / "vulnerable" / "parser"
    run_input = work / "generation-1" / "inputs" / "candidate.txt"
    run_artifact.parent.mkdir(parents=True, exist_ok=True)
    run_input.parent.mkdir(parents=True, exist_ok=True)
    run_artifact.write_bytes(b"run-root-parser")
    run_input.write_bytes(STAGE_MATERIALS["inputs/candidate.txt"])

    class StagingReplaySandbox:
        def replay(
            self,
            version,
            phase,
            *,
            artifact_path,
            input_path,
            asan_options,
            timeout_seconds,
            deadline_seconds,
            expected_artifact_digest=None,
            expected_input_digest=None,
        ):
            # Replace both run-root sources after staging has completed.
            run_artifact.write_bytes(b"tampered parser")
            run_input.write_bytes(b"tampered input")
            self.artifact_path = Path(artifact_path)
            self.input_path = Path(input_path)
            self.artifact = self.artifact_path.read_bytes()
            self.input = self.input_path.read_bytes()
            self.expected_input_digest = expected_input_digest
            return ReplayResult(
                version=version,
                phase=phase,
                status="completed",
                exit_code=0,
                duration_seconds=0.01,
                container_id="cid",
                input_digest=expected_input_digest,
                stdout=b"clean\n",
                stderr=b"",
                signature=None,
                timed_out=False,
                quota_hit=False,
                log_truncated=False,
                metadata={},
            )

    def persist(dsn, ctx, result, attempt_no, token):
        return {"status": result.status}

    monkeypatch.setattr(execution, "_persist_replay", persist)
    sandbox = StagingReplaySandbox()
    execution._do_replay(
        "unused-dsn",
        context,
        sandbox,
        {
            "files": {"artifact": "generation-1/build/vulnerable/parser"},
            "artifact_digest": _sha(b"run-root-parser"),
        },
        "vulnerable",
        "candidate_1",
        run_input,
        10.0,
        1,
        "token",
    )

    assert not _is_inside(sandbox.artifact_path, context.run_root)
    assert not _is_inside(sandbox.input_path, context.run_root)
    assert sandbox.artifact == b"run-root-parser"
    assert sandbox.input == STAGE_MATERIALS["inputs/candidate.txt"]
    assert sandbox.expected_input_digest == digests["inputs/candidate.txt"]
    assert not sandbox.artifact_path.exists()
    assert not sandbox.input_path.exists()


def test_staging_root_inside_run_root_fails_closed(tmp_path, monkeypatch):
    context, _, _ = _staging_context(tmp_path, monkeypatch)
    configured = context.run_root / "staging"
    monkeypatch.setenv("DATACON_STAGING_ROOT", str(configured))
    with pytest.raises(execution.ExecutionFailed) as caught:
        execution._staging_root(context)
    assert caught.value.reason_code == "EVIDENCE_WRITE_FAILED"
    assert not configured.exists()


def test_symlinked_staging_root_fails_closed(tmp_path, monkeypatch):
    context, _, _ = _staging_context(tmp_path, monkeypatch)
    target = tmp_path / "outside"
    target.mkdir()
    link = tmp_path / "staging-link"
    link.symlink_to(target, target_is_directory=True)
    monkeypatch.setenv("DATACON_STAGING_ROOT", str(link))
    with pytest.raises(execution.ExecutionFailed) as caught:
        execution._staging_root(context)
    assert caught.value.reason_code == "EVIDENCE_WRITE_FAILED"


def test_replay_checks_input_digest_before_creating_a_container(
    tmp_path, monkeypatch
):
    artifact = tmp_path / "parser"
    input_file = tmp_path / "input"
    artifact.write_bytes(b"parser")
    input_file.write_bytes(b"input")
    sandbox = DockerSandbox(
        image=IMAGE,
        platform="linux/amd64",
        policy=POLICY,
        limits=LIMITS,
        docker="docker",
        job_id="job-1234",
        run_root=tmp_path,
    )
    calls = []

    def refuse_create(**kwargs):
        calls.append(kwargs)
        raise AssertionError("a container must not be created")

    monkeypatch.setattr(sandbox, "_create", refuse_create)
    with pytest.raises(SandboxError) as caught:
        sandbox.replay(
            "vulnerable",
            "candidate_1",
            artifact_path=artifact,
            input_path=input_file,
            asan_options="detect_leaks=0",
            timeout_seconds=5.0,
            expected_artifact_digest=_sha(b"parser"),
            expected_input_digest="sha256:" + "0" * 64,
        )
    assert caught.value.reason_code == "PLAN_MISMATCH"
    assert calls == []


def test_staging_root_is_private_and_outside_the_run_root(tmp_path, monkeypatch):
    context, _, _ = _staging_context(tmp_path, monkeypatch)
    root = execution._staging_root(context)
    assert not _is_inside(root, context.run_root)
    assert stat.S_IMODE(root.lstat().st_mode) == 0o700

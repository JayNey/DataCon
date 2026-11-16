"""TC-05: the container command and inspect checks enforce REQ-05."""

from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import stat
import sys
import threading
from types import SimpleNamespace
import unicodedata
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
    SandboxUnavailable,
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
    with pytest.raises(SandboxPolicyError) as caught:
        sandbox._create(
            suffix="negative",
            command=["/bin/true"],
            mounts=[(MOUNT_SOURCE, "/fixture", True)],
        )
    assert "root filesystem" in str(caught.value)
    assert sandbox.removed(), "created container was not removed"
    assert any(call[1] == "-f" for call in sandbox.removed())


def test_create_removes_the_container_when_inspect_fails(tmp_path):
    sandbox = RecordingSandbox(tmp_path, {}, inspect_error=True)
    with pytest.raises(SandboxError) as caught:
        sandbox._create(
            suffix="negative",
            command=["/bin/true"],
            mounts=[(MOUNT_SOURCE, "/fixture", True)],
        )
    assert "inspect" in str(caught.value)
    assert sandbox.removed(), "created container was not removed"


def test_create_removes_the_container_when_create_is_rejected(tmp_path):
    sandbox = RecordingSandbox(tmp_path, _inspect_payload())

    def reject(command, *, timeout=60.0):
        sandbox.calls.append(list(command))
        return SimpleNamespace(returncode=1, stdout=b"", stderr=b"bad create")

    sandbox._docker = reject
    with pytest.raises(SandboxError) as caught:
        sandbox._create(
            suffix="negative",
            command=["/bin/true"],
            mounts=[(MOUNT_SOURCE, "/fixture", True)],
        )
    assert "bad create" in str(caught.value)
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


def test_docker_sandbox_probe_labels_the_generation(tmp_path):
    sandbox = RecordingSandbox(tmp_path, _inspect_payload(), generation=7)
    payload = _inspect_payload()
    success = SimpleNamespace(returncode=0, stdout=b"", stderr=b"")

    def fake_docker(command, *, timeout=60.0):
        sandbox.calls.append(list(command))
        if command[0] == "image":
            return success
        if command[0] == "create":
            mount = command[command.index("--mount") + 1]
            source = next(
                part[4:] for part in mount.split(",") if part.startswith("src=")
            )
            payload["Mounts"] = [
                {
                    "Type": "bind",
                    "Source": source,
                    "Destination": "/fixture",
                    "RW": False,
                }
            ]
            return SimpleNamespace(returncode=0, stdout=b"cid", stderr=b"")
        if command[0] == "inspect":
            return SimpleNamespace(
                returncode=0,
                stdout=json.dumps([payload]).encode(),
                stderr=b"",
            )
        if command[0] == "start":
            return SimpleNamespace(returncode=1, stdout=b"", stderr=b"stop here")
        if command[0] == "rm":
            return success
        raise AssertionError(f"unexpected docker command: {command}")

    sandbox._docker = fake_docker
    with pytest.raises(SandboxUnavailable):
        sandbox.probe()
    created = next(call for call in sandbox.calls if call and call[0] == "create")
    labels = _label_values(created)
    assert "datacon.job_id=job-1234" in labels
    assert "datacon.run=probe" in labels
    assert "datacon.generation=7" in labels


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
        "newer_probe": "6",
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
            if name.endswith("probe"):
                labels["datacon.run"] = "probe"
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
    assert "newer_probe" not in removed


# ---------------------------------------------------------------------------
# R1: run-root readers reject oversized files before reading their contents.
# ---------------------------------------------------------------------------


def test_read_run_file_bounded_accepts_normal_files_and_rejects_oversize(tmp_path):
    path = tmp_path / "stderr.log"
    path.write_bytes(b"12345")
    assert execution._read_run_file_bounded(path, max_bytes=5) == b"12345"
    assert execution._read_run_file_bounded(path, max_bytes=4) is None


def test_read_run_file_bounded_rejects_symlinks_and_fifos(tmp_path):
    target = tmp_path / "target"
    target.write_bytes(b"12345")
    link = tmp_path / "link"
    link.symlink_to(target)
    assert execution._read_run_file_bounded(link, max_bytes=16) is None

    fifo = tmp_path / "fifo"
    os.mkfifo(fifo)
    results = []
    worker = threading.Thread(
        target=lambda: results.append(
            execution._read_run_file_bounded(fifo, max_bytes=16)
        ),
        daemon=True,
    )
    worker.start()
    worker.join(timeout=2)
    assert not worker.is_alive()
    assert results == [None]


def test_verified_run_file_rejects_oversized_artifact_before_read(
    tmp_path, monkeypatch
):
    monkeypatch.setattr(execution, "MAX_ARTIFACT_BYTES", 4)
    path = tmp_path / "generation-1" / "build" / "vulnerable" / "parser"
    path.parent.mkdir(parents=True)
    path.write_bytes(b"12345")
    payload = {
        "files": {"artifact": "generation-1/build/vulnerable/parser"},
        "file_digests": {"artifact": _sha(b"12345")},
    }

    def forbidden_read_bytes(self):
        raise AssertionError(f"read_bytes must not be used for {self}")

    def forbidden_open(self, *args, **kwargs):
        raise AssertionError(f"open must not be used for {self}")

    monkeypatch.setattr(Path, "read_bytes", forbidden_read_bytes)
    monkeypatch.setattr(Path, "open", forbidden_open)
    assert (
        execution._verified_run_file(
            tmp_path, payload, "artifact", "/parser"
        )
        is None
    )


def test_material_verifiers_reject_oversized_files_before_read(
    tmp_path, monkeypatch
):
    monkeypatch.setattr(execution, "MAX_MATERIAL_BYTES", 4)
    materials = tmp_path / "materials"
    materials.mkdir()
    (materials / "harness.c").write_bytes(b"12345")

    def forbidden_read_bytes(self):
        raise AssertionError(f"read_bytes must not be used for {self}")

    monkeypatch.setattr(Path, "read_bytes", forbidden_read_bytes)
    with pytest.raises(execution.ExecutionBlocked) as caught:
        execution._verify_materialized(
            materials, {"harness.c": b"12345"}
        )
    assert caught.value.reason_code == "MATERIAL_MISSING"
    with pytest.raises(execution.ExecutionBlocked) as caught:
        execution._verify_materialized_tree(
            materials, {"harness.c": _sha(b"12345")}
        )
    assert caught.value.reason_code == "MATERIAL_MISSING"


def test_stage_materials_rejects_oversized_material_before_read(
    tmp_path, monkeypatch
):
    context, materials, digests = _staging_context(tmp_path, monkeypatch)
    monkeypatch.setattr(execution, "MAX_MATERIAL_BYTES", 4)

    def forbidden_read_bytes(self):
        raise AssertionError(f"read_bytes must not be used for {self}")

    monkeypatch.setattr(Path, "read_bytes", forbidden_read_bytes)
    with pytest.raises(execution.ExecutionBlocked) as caught:
        execution._stage_materials(context, materials, digests, "bounded")
    assert caught.value.reason_code == "MATERIAL_MISSING"


def test_stage_replay_files_rejects_oversized_artifact_before_read(
    tmp_path, monkeypatch
):
    context, materials, _ = _staging_context(tmp_path, monkeypatch)
    artifact = tmp_path / "parser"
    artifact.write_bytes(b"12345")
    input_path = materials / "inputs" / "normal.txt"
    input_digest = _sha(input_path.read_bytes())
    monkeypatch.setattr(execution, "MAX_ARTIFACT_BYTES", 4)

    def forbidden_read_bytes(self):
        raise AssertionError(f"read_bytes must not be used for {self}")

    monkeypatch.setattr(Path, "read_bytes", forbidden_read_bytes)
    with pytest.raises(execution.ExecutionBlocked) as caught:
        execution._stage_replay_files(
            context,
            artifact,
            _sha(b"12345"),
            input_path,
            input_digest,
            "bounded",
        )
    assert caught.value.reason_code == "MATERIAL_MISSING"


def test_materialize_rechecks_an_existing_tree_with_bounded_reads(
    tmp_path, monkeypatch
):
    payloads = {
        "harness.c": b"harness-body",
        "build.sh": b"#!/bin/sh\n",
        "dependencies.lock": b"deps",
        "fix.patch": b"patch-body",
        "vulnerable/parser.c": b"vuln-body",
        "fixed/parser.c": b"fixed-body",
        "inputs/normal.txt": b"normal-body",
        "inputs/candidate.txt": b"candidate-body",
    }
    digests = {relative: _sha(data) for relative, data in payloads.items()}
    context = SimpleNamespace(
        case=SimpleNamespace(
            manifest={
                "harness": "harness.c",
                "build_recipe": "build.sh",
                "dependencies": "dependencies.lock",
                "versions": {
                    "vulnerable": "vulnerable/parser.c",
                    "fixed": "fixed/parser.c",
                },
            },
            repository={"patch": "fix.patch"},
            read_material=lambda relative, expected: (
                payloads[relative],
                digests[relative],
            ),
        ),
        manifest_case={
            "inputs": {
                "normal": "inputs/normal.txt",
                "candidate": "inputs/candidate.txt",
            }
        },
        plan={
            "harness_digest": digests["harness.c"],
            "build_recipe_digest": digests["build.sh"],
            "dependencies_digest": digests["dependencies.lock"],
            "repository": {"patch_digest": digests["fix.patch"]},
            "inputs": {
                "normal": digests["inputs/normal.txt"],
                "candidate": digests["inputs/candidate.txt"],
            },
        },
        materials={
            "vulnerable/parser.c": digests["vulnerable/parser.c"],
            "fixed/parser.c": digests["fixed/parser.c"],
        },
        material_payloads={},
    )
    generation = tmp_path / "generation-1"
    execution._materialize(context, generation)
    assert (generation / "materials" / "harness.c").is_file()

    monkeypatch.setattr(execution, "MAX_MATERIAL_BYTES", 4)

    def forbidden_read_bytes(self):
        raise AssertionError(f"read_bytes must not be used for {self}")

    monkeypatch.setattr(Path, "read_bytes", forbidden_read_bytes)
    with pytest.raises(execution.ExecutionBlocked) as caught:
        execution._materialize(context, generation)
    assert caught.value.reason_code == "MATERIAL_MISSING"


def test_do_replay_rejects_oversized_artifact_before_read(
    tmp_path, monkeypatch
):
    context, _, _ = _staging_context(tmp_path, monkeypatch)
    artifact = (
        execution._work_root(context)
        / "generation-1"
        / "build"
        / "vulnerable"
        / "parser"
    )
    artifact.parent.mkdir(parents=True)
    artifact.write_bytes(b"12345")
    monkeypatch.setattr(execution, "MAX_ARTIFACT_BYTES", 4)

    class ForbiddenSandbox:
        def replay(self, *args, **kwargs):
            raise AssertionError("a container must not be created")

    def forbidden_read_bytes(self):
        raise AssertionError(f"read_bytes must not be used for {self}")

    monkeypatch.setattr(Path, "read_bytes", forbidden_read_bytes)
    with pytest.raises(execution.ExecutionBlocked) as caught:
        execution._do_replay(
            "unused-dsn",
            context,
            ForbiddenSandbox(),
            {
                "files": {"artifact": "generation-1/build/vulnerable/parser"},
                "artifact_digest": _sha(b"12345"),
            },
            "vulnerable",
            "candidate_1",
            execution._work_root(context) / "inputs" / "candidate.txt",
            10.0,
            1,
            "token",
        )
    assert caught.value.reason_code == "MATERIAL_MISSING"


def test_run_root_paths_reject_absolute_paths(tmp_path):
    payload = {
        "files": {"artifact": "/tmp/x/parser"},
        "file_digests": {"artifact": _sha(b"x")},
    }
    assert (
        execution._verified_run_file(tmp_path, payload, "artifact", "/parser")
        is None
    )
    assert execution._reusable_build(tmp_path, {**payload, "status": "completed"}) is False
    replay_payload = {
        "files": {"stdout": "/tmp/x/stdout.log", "stderr": "/tmp/x/stderr.log"},
        "file_digests": {
            "stdout": _sha(b"x"),
            "stderr": _sha(b"x"),
        },
    }
    assert execution._reusable_replay(tmp_path, replay_payload) is False
    with pytest.raises(execution.ExecutionFailed) as caught:
        execution._replay_log_text(
            replay_payload, tmp_path, "stdout", "stdout"
        )
    assert caught.value.reason_code == "RUN_INCOMPLETE"


def test_do_replay_rejects_absolute_artifact_path(tmp_path, monkeypatch):
    context, _, _ = _staging_context(tmp_path, monkeypatch)
    with pytest.raises(execution.ExecutionBlocked) as caught:
        execution._do_replay(
            "unused-dsn",
            context,
            object(),
            {"files": {"artifact": "/tmp/x/parser"}},
            "vulnerable",
            "candidate_1",
            tmp_path / "input",
            10.0,
            1,
            "token",
        )
    assert caught.value.reason_code == "PLAN_MISMATCH"


def test_verified_run_file_rejects_oversized_file_before_read(tmp_path, monkeypatch):
    monkeypatch.setattr(execution, "MAX_LOG_BYTES", 4)
    path = tmp_path / "generation-1" / "stderr.log"
    path.parent.mkdir()
    path.write_bytes(b"12345")
    payload = {
        "files": {"stderr": "generation-1/stderr.log"},
        "file_digests": {"stderr": _sha(b"12345")},
    }

    def forbidden_read_bytes(self):
        raise AssertionError(f"read_bytes must not be used for {self}")

    def forbidden_open(self, *args, **kwargs):
        raise AssertionError(f"open must not be used for {self}")

    monkeypatch.setattr(Path, "read_bytes", forbidden_read_bytes)
    monkeypatch.setattr(Path, "open", forbidden_open)
    assert (
        execution._verified_run_file(tmp_path, payload, "stderr", "/stderr.log")
        is None
    )


def test_replay_log_text_rejects_oversized_file_before_read(tmp_path, monkeypatch):
    monkeypatch.setattr(execution, "MAX_LOG_BYTES", 4)
    path = tmp_path / "generation-1" / "stdout.log"
    path.parent.mkdir()
    path.write_bytes(b"12345")
    payload = {
        "files": {"stdout": "generation-1/stdout.log"},
        "file_digests": {"stdout": _sha(b"12345")},
    }

    def forbidden_read_bytes(self):
        raise AssertionError(f"read_bytes must not be used for {self}")

    monkeypatch.setattr(Path, "read_bytes", forbidden_read_bytes)
    with pytest.raises(execution.ExecutionFailed) as caught:
        execution._replay_log_text(payload, tmp_path, "stdout", "stdout")
    assert caught.value.reason_code == "RUN_INCOMPLETE"


def test_reusable_build_and_replay_reject_oversized_files(tmp_path, monkeypatch):
    monkeypatch.setattr(execution, "MAX_LOG_BYTES", 4)
    monkeypatch.setattr(execution, "MAX_ARTIFACT_BYTES", 4)
    build_dir = tmp_path / "generation-1" / "build" / "vulnerable"
    build_dir.mkdir(parents=True)
    (build_dir / "parser").write_bytes(b"12345")
    (build_dir / "build.log").write_bytes(b"12345")
    build_payload = {
        "status": "completed",
        "files": {
            "artifact": "generation-1/build/vulnerable/parser",
            "log": "generation-1/build/vulnerable/build.log",
        },
        "file_digests": {
            "artifact": _sha(b"12345"),
            "log": _sha(b"12345"),
        },
    }
    assert execution._reusable_build(tmp_path, build_payload) is False
    replay_dir = tmp_path / "generation-1" / "replay" / "vulnerable" / "normal"
    replay_dir.mkdir(parents=True)
    (replay_dir / "stdout.log").write_bytes(b"12345")
    (replay_dir / "stderr.log").write_bytes(b"12345")
    replay_payload = {
        "files": {
            "stdout": "generation-1/replay/vulnerable/normal/stdout.log",
            "stderr": "generation-1/replay/vulnerable/normal/stderr.log",
        },
        "file_digests": {
            "stdout": _sha(b"12345"),
            "stderr": _sha(b"12345"),
        },
    }
    assert execution._reusable_replay(tmp_path, replay_payload) is False


def test_find_reusable_journal_skips_oversized_file_before_read(tmp_path, monkeypatch):
    job_id = uuid4()
    plan_digest_value = "sha256:" + "a" * 64
    context = SimpleNamespace(
        run_root=tmp_path,
        job_id=job_id,
        job_id_text=str(job_id),
        plan_digest=plan_digest_value,
        generation=3,
    )
    work_root = execution._work_root(context)
    journal = execution._journal_path(work_root, "build:vulnerable", 1, 3)
    journal.parent.mkdir(parents=True)
    journal.write_bytes(b"12345")
    rows = [
        {
            "status": "completed",
            "input_digest": None,
            "attempt_token": "token",
            "attempt_no": 1,
            "generation": 3,
            "container_id": "cid",
        }
    ]
    monkeypatch.setattr(
        execution.state,
        "attempts_for_step_across_generations",
        lambda *args, **kwargs: rows,
    )
    monkeypatch.setattr(execution, "_journal_secret", lambda **kwargs: b"x" * 32)
    monkeypatch.setattr(execution, "_JOURNAL_MAX_BYTES", 4)

    def forbidden_read_text(self, *args, **kwargs):
        raise AssertionError(f"read_text must not be used for {self}")

    monkeypatch.setattr(Path, "read_text", forbidden_read_text)
    assert (
        execution._find_reusable_journal(
            "dsn",
            context,
            step_key="build:vulnerable",
            plan_digest=plan_digest_value,
            input_digest=None,
            verify=lambda payload: True,
        )
        is None
    )


def test_journal_secret_rejects_oversized_secret(tmp_path, monkeypatch):
    secret = tmp_path / "secret"
    secret.write_bytes(b"x" * 2048)
    secret.chmod(0o600)
    monkeypatch.setenv("DATACON_JOURNAL_SECRET_FILE", str(secret))
    monkeypatch.setenv("DATACON_EVIDENCE_ROOT", str(tmp_path / "evidence"))
    with pytest.raises(execution.ExecutionFailed) as caught:
        execution._journal_secret(create=False, run_root=tmp_path / "runs")
    assert caught.value.reason_code == "EVIDENCE_WRITE_FAILED"


def test_archive_refuses_nested_evidence_root_before_mark_or_write(
    tmp_path, monkeypatch
):
    run_root = tmp_path / "runs"
    evidence_root = run_root / "evidence"
    monkeypatch.setenv("DATACON_EVIDENCE_ROOT", str(evidence_root))
    marks = []
    monkeypatch.setattr(
        execution.state,
        "mark_archiving",
        lambda *args, **kwargs: marks.append((args, kwargs)),
    )
    context = SimpleNamespace(
        run_root=run_root,
        job_id=uuid4(),
        job_id_text="job-1234",
        generation=1,
        plan_digest="sha256:" + "a" * 64,
    )
    digest, path, error = execution._archive(
        "dsn",
        context,
        report={},
        report_markdown="",
        artifacts={},
        verdict=None,
    )
    assert (digest, path) == (None, None)
    assert error is not None
    assert error.startswith("EVIDENCE_WRITE_FAILED:")
    assert marks == []
    assert not evidence_root.exists()


# ---------------------------------------------------------------------------
# R1: run-root containment uses filesystem identity, not resolved strings.
# ---------------------------------------------------------------------------


def test_outside_run_root_rejects_the_run_root_itself(tmp_path):
    run_root = tmp_path / "run"
    run_root.mkdir()
    with pytest.raises(execution.ExecutionFailed) as caught:
        execution._outside_run_root(run_root, run_root, "evidence root")
    assert caught.value.reason_code == "EVIDENCE_WRITE_FAILED"


@pytest.mark.parametrize("variant", ["RUN", "Run"])
def test_outside_run_root_rejects_case_variants(tmp_path, variant):
    run_root = tmp_path / "run"
    run_root.mkdir()
    target = tmp_path / variant / "evidence"
    with pytest.raises(execution.ExecutionFailed) as caught:
        execution._outside_run_root(target, run_root, "evidence root")
    assert caught.value.reason_code == "EVIDENCE_WRITE_FAILED"


def test_outside_run_root_rejects_unicode_normalization_variants(tmp_path):
    nfc = unicodedata.normalize("NFC", "café")
    nfd = unicodedata.normalize("NFD", "café")
    assert nfc != nfd
    run_root = tmp_path / nfc
    run_root.mkdir()
    target = tmp_path / nfd / "evidence"
    with pytest.raises(execution.ExecutionFailed) as caught:
        execution._outside_run_root(target, run_root, "evidence root")
    assert caught.value.reason_code == "EVIDENCE_WRITE_FAILED"


def test_outside_run_root_rejects_parent_traversal_into_run_root(tmp_path):
    run_root = tmp_path / "run"
    run_root.mkdir()
    target = run_root / ".." / "run" / "evidence"
    with pytest.raises(execution.ExecutionFailed) as caught:
        execution._outside_run_root(target, run_root, "evidence root")
    assert caught.value.reason_code == "EVIDENCE_WRITE_FAILED"


def test_outside_run_root_rejects_relative_path_into_run_root(
    tmp_path, monkeypatch
):
    run_root = tmp_path / "run"
    run_root.mkdir()
    monkeypatch.chdir(tmp_path)
    with pytest.raises(execution.ExecutionFailed) as caught:
        execution._outside_run_root(
            Path("run/evidence"), run_root, "evidence root"
        )
    assert caught.value.reason_code == "EVIDENCE_WRITE_FAILED"
    outside = execution._outside_run_root(
        Path("outside-evidence"), run_root, "evidence root"
    )
    assert outside == (tmp_path / "outside-evidence").resolve()


def test_outside_run_root_rejects_a_symlink_into_the_run_root(tmp_path):
    run_root = tmp_path / "run"
    run_root.mkdir()
    link = tmp_path / "link"
    link.symlink_to(run_root, target_is_directory=True)
    with pytest.raises(execution.ExecutionFailed) as caught:
        execution._outside_run_root(link / "evidence", run_root, "evidence root")
    assert caught.value.reason_code == "EVIDENCE_WRITE_FAILED"


def test_outside_run_root_rejects_a_missing_target_below_the_run_root(tmp_path):
    run_root = tmp_path / "run"
    run_root.mkdir()
    target = run_root / "missing" / "evidence"
    with pytest.raises(execution.ExecutionFailed) as caught:
        execution._outside_run_root(target, run_root, "evidence root")
    assert caught.value.reason_code == "EVIDENCE_WRITE_FAILED"


def test_outside_run_root_accepts_a_real_outside_directory(tmp_path):
    run_root = tmp_path / "run"
    run_root.mkdir()
    target = tmp_path / "evidence"
    target.mkdir()
    assert (
        execution._outside_run_root(target, run_root, "evidence root")
        == target.resolve()
    )


def test_journal_secret_case_variant_inside_run_root_fails_closed(
    tmp_path, monkeypatch
):
    run_root = tmp_path / "run"
    run_root.mkdir()
    monkeypatch.setenv("DATACON_EVIDENCE_ROOT", str(tmp_path / "evidence"))
    monkeypatch.setenv(
        "DATACON_JOURNAL_SECRET_FILE", str(tmp_path / "RUN" / ".secret")
    )
    with pytest.raises(execution.ExecutionFailed) as caught:
        execution._journal_secret_path(run_root)
    assert caught.value.reason_code == "EVIDENCE_WRITE_FAILED"


def test_staging_root_case_variant_inside_run_root_fails_closed(
    tmp_path, monkeypatch
):
    context, _, _ = _staging_context(tmp_path, monkeypatch)
    configured = tmp_path / "RUNS" / "staging"
    monkeypatch.setenv("DATACON_STAGING_ROOT", str(configured))
    with pytest.raises(execution.ExecutionFailed) as caught:
        execution._staging_root(context)
    assert caught.value.reason_code == "EVIDENCE_WRITE_FAILED"


def test_archive_rejects_case_variant_evidence_root_before_mark(
    tmp_path, monkeypatch
):
    run_root = tmp_path / "runs"
    run_root.mkdir()
    evidence_root = tmp_path / "RUNS" / "evidence"
    monkeypatch.setenv("DATACON_EVIDENCE_ROOT", str(evidence_root))
    marks = []
    monkeypatch.setattr(
        execution.state,
        "mark_archiving",
        lambda *args, **kwargs: marks.append((args, kwargs)),
    )
    context = SimpleNamespace(
        run_root=run_root,
        job_id=uuid4(),
        job_id_text="job-1234",
        generation=1,
        plan_digest="sha256:" + "a" * 64,
    )
    digest, path, error = execution._archive(
        "dsn",
        context,
        report={},
        report_markdown="",
        artifacts={},
        verdict=None,
    )
    assert (digest, path) == (None, None)
    assert error is not None
    assert error.startswith("EVIDENCE_WRITE_FAILED:")
    assert marks == []
    assert not evidence_root.exists()


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

    def persist(dsn, ctx, result, attempt_no, token, *, artifact_digest=None):
        return {"status": result.status, "artifact_digest": artifact_digest}

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


def test_evidence_materials_use_the_verified_snapshot_not_the_case_source():
    payloads = {
        "harness.c": b"verified harness\n",
        "build.sh": b"#!/bin/sh\nexit 0\n",
        "dependencies.lock": b"clang=19.1.7\n",
        "fix.patch": b"patch\n",
        "vulnerable/parser.c": b"vulnerable\n",
        "fixed/parser.c": b"fixed\n",
        "inputs/normal.txt": b"normal\n",
        "inputs/candidate.txt": b"candidate\n",
    }

    def forbidden_read(relative, expected):
        raise AssertionError("case source must not be read after materialization")

    context = SimpleNamespace(
        case=SimpleNamespace(
            manifest={
                "harness": "harness.c",
                "build_recipe": "build.sh",
                "dependencies": "dependencies.lock",
                "versions": {
                    "vulnerable": "vulnerable/parser.c",
                    "fixed": "fixed/parser.c",
                },
            },
            repository={"patch": "fix.patch"},
            read_material=forbidden_read,
        ),
        manifest_case={
            "inputs": {
                "normal": "inputs/normal.txt",
                "candidate": "inputs/candidate.txt",
            }
        },
        plan={
            "harness_digest": _sha(payloads["harness.c"]),
            "build_recipe_digest": _sha(payloads["build.sh"]),
            "dependencies_digest": _sha(payloads["dependencies.lock"]),
            "repository": {"patch_digest": _sha(payloads["fix.patch"])},
            "inputs": {
                "normal": _sha(payloads["inputs/normal.txt"]),
                "candidate": _sha(payloads["inputs/candidate.txt"]),
            },
        },
        materials={
            "vulnerable/parser.c": _sha(payloads["vulnerable/parser.c"]),
            "fixed/parser.c": _sha(payloads["fixed/parser.c"]),
        },
        material_payloads=payloads,
    )
    materials = execution._case_materials(context)
    assert {relative: data for relative, (_, data) in materials.items()} == payloads


def test_probe_rejects_symlinked_legacy_directory_without_writing(tmp_path):
    external = tmp_path / "external"
    external.mkdir(mode=0o700)
    before = stat.S_IMODE(external.stat().st_mode)
    (tmp_path / "probe").symlink_to(external, target_is_directory=True)
    sandbox = RecordingSandbox(tmp_path, _inspect_payload())

    with pytest.raises(SandboxPolicyError):
        sandbox.probe()

    assert not (external / "marker.txt").exists()
    assert stat.S_IMODE(external.stat().st_mode) == before
    assert sandbox.calls == []


def test_write_run_file_rejects_a_planted_symlink(tmp_path):
    run_root = tmp_path / "runs"
    (run_root / "generation-1").mkdir(parents=True)
    outside = tmp_path / "outside.txt"
    outside.write_bytes(b"original")
    target = run_root / "generation-1" / "parser"
    target.symlink_to(outside)

    with pytest.raises(execution.ExecutionFailed) as caught:
        execution._write_run_file(run_root, target, b"tampered", 0o555)

    assert caught.value.reason_code == "EVIDENCE_WRITE_FAILED"
    assert outside.read_bytes() == b"original"


def test_write_run_file_replaces_a_read_only_legacy_file(tmp_path):
    run_root = tmp_path / "runs"
    (run_root / "generation-1").mkdir(parents=True)
    target = run_root / "generation-1" / "parser"
    execution._write_run_file(run_root, target, b"first", 0o555)
    assert stat.S_IMODE(target.stat().st_mode) == 0o555

    execution._write_run_file(run_root, target, b"second", 0o600)

    assert target.read_bytes() == b"second"
    assert stat.S_IMODE(target.stat().st_mode) == 0o600


def test_write_journal_does_not_follow_a_planted_tmp_symlink(tmp_path, monkeypatch):
    run_root = tmp_path / "runs"
    evidence_root = tmp_path / "evidence"
    monkeypatch.setenv("DATACON_EVIDENCE_ROOT", str(evidence_root))
    monkeypatch.delenv("DATACON_JOURNAL_SECRET_FILE", raising=False)
    path = execution._journal_path(run_root, "build:vulnerable", 1, 1)
    path.parent.mkdir(parents=True)
    outside = tmp_path / "outside.json"
    outside.write_bytes(b"original")
    temporary = path.with_suffix(".tmp")
    temporary.symlink_to(outside)

    written = execution._write_journal(
        run_root, "build:vulnerable", 1, 1, {"job_id": "job", "generation": 1}
    )

    assert written == path
    assert path.is_file()
    assert outside.read_bytes() == b"original"
    assert not temporary.is_symlink()


def _mountinfo(*lines: str) -> str:
    return "\n".join(("36 1 8:1 / / rw - ext4 /dev/sda1 rw", *lines)) + "\n"


def test_mountinfo_rejects_a_bind_mount_sourced_from_the_run_root():
    text = _mountinfo(
        "37 36 8:1 /data/runs/child /mnt/bind rw - ext4 /dev/sda1 rw"
    )
    assert execution._mountinfo_rejects(
        Path("/mnt/bind/evidence"), Path("/data/runs"), text
    )


def test_mountinfo_accepts_a_lexically_outside_target_on_the_same_device():
    text = _mountinfo()
    assert not execution._mountinfo_rejects(
        Path("/srv/evidence"), Path("/data/runs"), text
    )


def test_mountinfo_allows_a_different_device_with_no_run_root_mount():
    # A different device is only provably outside when the run root contains
    # no mount of that device.
    text = _mountinfo(
        "39 36 9:1 / /mnt/other rw - ext4 /dev/sdb1 rw"
    )
    assert not execution._mountinfo_rejects(
        Path("/mnt/other/evidence"), Path("/data/runs"), text
    )


def test_mountinfo_rejects_a_different_device_when_run_root_contains_it():
    # /data/runs/child is a mount of the same device as /mnt/other. Content
    # from below the run root can therefore be rebound at the target path even
    # though the device numbers differ.
    text = _mountinfo(
        "39 36 9:1 / /mnt/other rw - ext4 /dev/sdb1 rw",
        "41 36 9:1 / /data/runs/child rw - ext4 /dev/sdb1 rw",
    )
    assert execution._mountinfo_rejects(
        Path("/mnt/other/evidence"), Path("/data/runs"), text
    )


def test_mountinfo_rejects_a_nested_different_device_bind():
    text = _mountinfo(
        "41 36 9:1 / /data/runs/child rw - ext4 /dev/sdb1 rw",
        "42 36 9:1 /data/runs/child /mnt/ev rw - ext4 /dev/sdb1 rw",
    )
    assert execution._mountinfo_rejects(
        Path("/mnt/ev/evidence"), Path("/data/runs"), text
    )


def test_mountinfo_rejects_an_overmount_at_the_target_path():
    # The lower entry at /mnt/ev binds a run-root subtree; the upper entry is
    # an unrelated filesystem. The topmost (largest mount_id) mount alone
    # would look safe, so the lower entry must still be inspected.
    text = _mountinfo(
        "43 36 8:1 /data/runs/child /mnt/ev rw - ext4 /dev/sda1 rw",
        "44 43 9:1 / /mnt/ev rw - ext4 /dev/sdb1 rw",
    )
    assert execution._mountinfo_rejects(
        Path("/mnt/ev/evidence"), Path("/data/runs"), text
    )


def test_mountinfo_overmount_rejection_does_not_depend_on_line_order():
    text = _mountinfo(
        "44 43 9:1 / /mnt/ev rw - ext4 /dev/sdb1 rw",
        "43 36 8:1 /data/runs/child /mnt/ev rw - ext4 /dev/sda1 rw",
    )
    assert execution._mountinfo_rejects(
        Path("/mnt/ev/evidence"), Path("/data/runs"), text
    )


def test_mountinfo_escapes_mount_point_and_root():
    text = _mountinfo(
        "40 36 8:1 /data/runs/child\\040dir /mnt/a\\040b rw - ext4 /dev/sda1 rw"
    )
    assert execution._mountinfo_rejects(
        Path("/mnt/a b/evidence"), Path("/data/runs"), text
    )


def test_mountinfo_rejects_an_unparseable_document():
    assert execution._mountinfo_rejects(
        Path("/srv/evidence"), Path("/data/runs"), "not mountinfo\n"
    )


def test_mountinfo_checks_run_root_itself_through_its_mount():
    text = _mountinfo(
        "41 36 8:1 /srv/data /mnt/data rw - ext4 /dev/sda1 rw"
    )
    assert execution._mountinfo_rejects(
        Path("/mnt/data/runs/evidence"), Path("/mnt/data/runs"), text
    )


def test_write_run_file_rejects_a_fifo_without_blocking(tmp_path):
    run_root = tmp_path / "runs"
    (run_root / "generation-1").mkdir(parents=True)
    target = run_root / "generation-1" / "stdout.log"
    os.mkfifo(target)

    with pytest.raises(execution.ExecutionFailed) as caught:
        execution._write_run_file(run_root, target, b"tampered", 0o600)

    assert caught.value.reason_code == "EVIDENCE_WRITE_FAILED"


def test_mountinfo_tolerates_unrelated_pseudo_filesystem_roots():
    # nsfs reports a non-path root such as net:[4026532313]; it must not make
    # an unrelated target unverifiable.
    text = _mountinfo(
        "60 35 0:5 net:[4026532313] /run/docker/netns/abc rw - nsfs nsfs rw"
    )
    assert not execution._mountinfo_rejects(
        Path("/tmp/evidence"), Path("/tmp/runs"), text
    )


def test_mountinfo_rejects_a_pseudo_filesystem_ancestor():
    text = _mountinfo(
        "60 35 0:5 net:[4026532313] /run/docker/netns/abc rw - nsfs nsfs rw"
    )
    assert execution._mountinfo_rejects(
        Path("/run/docker/netns/abc/evidence"), Path("/tmp/runs"), text
    )


# ---------------------------------------------------------------------------
# SF2: Linux must not silently skip a missing mountinfo document.
# ---------------------------------------------------------------------------


def _missing_mountinfo(self, *args, **kwargs):
    raise FileNotFoundError("/proc/self/mountinfo")


def test_mountinfo_missing_fails_closed_on_linux(monkeypatch):
    monkeypatch.setattr(sys, "platform", "linux")
    monkeypatch.setattr(Path, "read_text", _missing_mountinfo)
    with pytest.raises(execution.ExecutionFailed) as caught:
        execution._mountinfo_document()
    assert caught.value.reason_code == "EVIDENCE_WRITE_FAILED"
    assert "mountinfo" in caught.value.message


def test_mountinfo_missing_is_optional_off_linux(monkeypatch):
    monkeypatch.setattr(sys, "platform", "darwin")
    monkeypatch.setattr(Path, "read_text", _missing_mountinfo)
    assert execution._mountinfo_document() is None


# ---------------------------------------------------------------------------
# SF4: hard links are not covered by O_NOFOLLOW.
# ---------------------------------------------------------------------------


def test_write_run_file_rejects_a_hardlink_to_an_external_file(tmp_path):
    run_root = tmp_path / "runs"
    (run_root / "generation-1").mkdir(parents=True)
    outside = tmp_path / "outside.txt"
    outside.write_bytes(b"original")
    target = run_root / "generation-1" / "parser"
    os.link(outside, target)

    with pytest.raises(execution.ExecutionFailed) as caught:
        execution._write_run_file(run_root, target, b"tampered", 0o555)

    assert caught.value.reason_code == "EVIDENCE_WRITE_FAILED"
    assert outside.read_bytes() == b"original"


def test_write_run_file_rejects_a_hardlink_inside_the_run_root(tmp_path):
    run_root = tmp_path / "runs"
    (run_root / "generation-1").mkdir(parents=True)
    sibling = run_root / "generation-1" / "sibling.log"
    sibling.write_bytes(b"original")
    target = run_root / "generation-1" / "parser"
    os.link(sibling, target)

    with pytest.raises(execution.ExecutionFailed) as caught:
        execution._write_run_file(run_root, target, b"tampered", 0o555)

    assert caught.value.reason_code == "EVIDENCE_WRITE_FAILED"
    assert sibling.read_bytes() == b"original"


# ---------------------------------------------------------------------------
# SF5: containment must be checked before mkdir follows a symlinked parent.
# ---------------------------------------------------------------------------


def test_write_run_file_checks_symlinked_parent_before_mkdir(tmp_path):
    run_root = tmp_path / "runs"
    (run_root / "generation-1").mkdir(parents=True)
    external = tmp_path / "external"
    external.mkdir()
    (run_root / "generation-1" / "logs").symlink_to(
        external, target_is_directory=True
    )
    target = run_root / "generation-1" / "logs" / "nested" / "stdout.log"

    with pytest.raises(execution.ExecutionFailed) as caught:
        execution._write_run_file(run_root, target, b"tampered", 0o600)

    assert caught.value.reason_code == "EVIDENCE_WRITE_FAILED"
    assert not (external / "nested").exists()


def test_write_journal_checks_symlinked_parent_before_mkdir(tmp_path, monkeypatch):
    run_root = tmp_path / "runs"
    (run_root / "steps").mkdir(parents=True)
    external = tmp_path / "external"
    external.mkdir()
    (run_root / "steps" / "build_parser").symlink_to(
        external, target_is_directory=True
    )
    monkeypatch.setenv("DATACON_EVIDENCE_ROOT", str(tmp_path / "evidence"))
    monkeypatch.delenv("DATACON_JOURNAL_SECRET_FILE", raising=False)

    with pytest.raises(execution.ExecutionFailed) as caught:
        execution._write_journal(
            run_root,
            "build:parser",
            1,
            1,
            {"job_id": "job", "generation": 1},
        )

    assert caught.value.reason_code == "EVIDENCE_WRITE_FAILED"
    assert not (external / "generation-1").exists()


# ---------------------------------------------------------------------------
# SF6: the journal secret must stay out of the evidence and staging roots.
# ---------------------------------------------------------------------------


def test_journal_secret_rejects_explicit_path_inside_evidence_root(
    tmp_path, monkeypatch
):
    evidence_root = tmp_path / "evidence"
    secret = evidence_root / "secret"
    monkeypatch.setenv("DATACON_EVIDENCE_ROOT", str(evidence_root))
    monkeypatch.setenv("DATACON_JOURNAL_SECRET_FILE", str(secret))

    with pytest.raises(execution.ExecutionFailed) as caught:
        execution._journal_secret_path(tmp_path / "runs")

    assert caught.value.reason_code == "EVIDENCE_WRITE_FAILED"
    assert "EVIDENCE_ROOT" in caught.value.message


def test_journal_secret_rejects_explicit_path_inside_staging_root(
    tmp_path, monkeypatch
):
    staging_root = tmp_path / "staging"
    secret = staging_root / "secret"
    monkeypatch.setenv("DATACON_EVIDENCE_ROOT", str(tmp_path / "evidence"))
    monkeypatch.setenv("DATACON_STAGING_ROOT", str(staging_root))
    monkeypatch.setenv("DATACON_JOURNAL_SECRET_FILE", str(secret))

    with pytest.raises(execution.ExecutionFailed) as caught:
        execution._journal_secret_path(tmp_path / "runs")

    assert caught.value.reason_code == "EVIDENCE_WRITE_FAILED"
    assert "staging root" in caught.value.message


def test_journal_secret_default_sibling_remains_usable(tmp_path, monkeypatch):
    evidence_root = tmp_path / "evidence"
    monkeypatch.setenv("DATACON_EVIDENCE_ROOT", str(evidence_root))
    monkeypatch.delenv("DATACON_JOURNAL_SECRET_FILE", raising=False)
    monkeypatch.delenv("DATACON_STAGING_ROOT", raising=False)

    path = execution._journal_secret_path(tmp_path / "runs")

    assert path.name == ".datacon-journal-secret"
    assert path.parent == evidence_root.resolve().parent


# ---------------------------------------------------------------------------
# SF9: DockerSandbox build/replay use bounded readers, not Path.read_bytes.
# ---------------------------------------------------------------------------


def _fake_docker_sandbox(tmp_path, files):
    sandbox = DockerSandbox(
        image=(
            "silkeh/clang:19-bookworm@sha256:"
            "f5ce959d91f059acf5a4b3f1c19f46713c4b2881c7d7cd1d5143ca1d1412277f"
        ),
        platform="linux/amd64",
        policy=IsolationPolicy(
            network="none",
            user="65534:65534",
            read_only_root=True,
            cap_drop=("ALL",),
            no_new_privileges=True,
            seccomp="runtime/default",
            seccomp_profile_digest=SECCOMP_PROFILE_DIGEST,
        ),
        limits=ResourceLimits(cpu=2, memory_mib=2048, pids=128, scratch_mib=512),
        job_id="job-sf9",
        run_root=tmp_path / "runs",
        generation=1,
    )
    sandbox._create = lambda **kwargs: ("fake-container", {})
    sandbox._remove = lambda name: None
    sandbox._start_and_wait = lambda *args, **kwargs: (
        dict(files),
        set(),
        {},
        False,
    )
    return sandbox


def _materials(tmp_path, recipe=b"#!/bin/sh\nexit 0\n"):
    materials = tmp_path / "materials"
    materials.mkdir()
    (materials / "build.sh").write_bytes(recipe)
    return materials


def test_docker_sandbox_build_does_not_call_path_read_bytes(tmp_path, monkeypatch):
    materials = _materials(tmp_path)
    recipe_digest = "sha256:" + hashlib.sha256(
        (materials / "build.sh").read_bytes()
    ).hexdigest()
    sandbox = _fake_docker_sandbox(
        tmp_path,
        {
            "/work/build.log": b"ok",
            "/work/exit_code": b"0",
            "/work/parser": b"parser-bytes",
        },
    )

    def forbid_read_bytes(self):
        raise AssertionError(f"build must not call Path.read_bytes: {self}")

    monkeypatch.setattr(Path, "read_bytes", forbid_read_bytes)
    result = sandbox.build(
        "vulnerable",
        materials_dir=materials,
        compile_args=("-std=c11",),
        deadline_seconds=5,
        expected_materials={"build.sh": recipe_digest},
    )

    assert result.status == "completed"
    assert result.artifact == b"parser-bytes"


def test_docker_sandbox_replay_does_not_call_path_read_bytes(tmp_path, monkeypatch):
    artifact = tmp_path / "parser"
    artifact.write_bytes(b"parser-bytes")
    input_file = tmp_path / "input"
    input_file.write_bytes(b"ABCD\n")
    sandbox = _fake_docker_sandbox(
        tmp_path,
        {
            "/work/stdout": b"",
            "/work/stderr": b"",
            "/work/exit_code": b"0",
        },
    )

    def forbid_read_bytes(self):
        raise AssertionError(f"replay must not call Path.read_bytes: {self}")

    monkeypatch.setattr(Path, "read_bytes", forbid_read_bytes)
    result = sandbox.replay(
        "vulnerable",
        "candidate_1",
        artifact_path=artifact,
        input_path=input_file,
        asan_options="detect_leaks=0",
        timeout_seconds=5,
        expected_artifact_digest="sha256:"
        + hashlib.sha256(b"parser-bytes").hexdigest(),
        expected_input_digest="sha256:" + hashlib.sha256(b"ABCD\n").hexdigest(),
    )

    assert result.status == "completed"
    assert result.input_digest == "sha256:" + hashlib.sha256(b"ABCD\n").hexdigest()


def test_docker_sandbox_rejects_oversized_material_before_reading(
    tmp_path, monkeypatch
):
    import datacon.tools.sandbox as sandbox_module

    materials = _materials(tmp_path, recipe=b"x" * 4096)
    created: list[str] = []
    sandbox = _fake_docker_sandbox(tmp_path, {})
    sandbox._create = lambda **kwargs: created.append("create") or ("cid", {})
    monkeypatch.setattr(sandbox_module, "MAX_MATERIAL_BYTES", 8)

    with pytest.raises(SandboxError) as caught:
        sandbox.build(
            "vulnerable",
            materials_dir=materials,
            compile_args=(),
            deadline_seconds=5,
            expected_materials={"build.sh": "sha256:" + "0" * 64},
        )

    assert caught.value.reason_code == "MATERIAL_MISSING"
    assert created == []


def test_docker_sandbox_rejects_oversized_replay_input_before_container(
    tmp_path, monkeypatch
):
    import datacon.tools.sandbox as sandbox_module

    artifact = tmp_path / "parser"
    artifact.write_bytes(b"parser-bytes")
    input_file = tmp_path / "input"
    input_file.write_bytes(b"x" * 4096)
    created: list[str] = []
    sandbox = _fake_docker_sandbox(tmp_path, {})
    sandbox._create = lambda **kwargs: created.append("create") or ("cid", {})
    monkeypatch.setattr(sandbox_module, "MAX_MATERIAL_BYTES", 8)

    with pytest.raises(SandboxError) as caught:
        sandbox.replay(
            "vulnerable",
            "candidate_1",
            artifact_path=artifact,
            input_path=input_file,
            asan_options="detect_leaks=0",
            timeout_seconds=5,
        )

    assert caught.value.reason_code == "MATERIAL_MISSING"
    assert created == []

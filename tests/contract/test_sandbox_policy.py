"""TC-05: the container command and inspect checks enforce REQ-05."""

from __future__ import annotations

from dataclasses import replace
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from datacon.tools.sandbox import (
    SECCOMP_PROFILE_DIGEST,
    SECCOMP_PROFILE_PATH,
    DockerSandbox,
    IsolationPolicy,
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
    def __init__(self, tmp_path, inspect_payload, *, inspect_error=False):
        super().__init__(
            image=IMAGE,
            platform="linux/amd64",
            policy=POLICY,
            limits=LIMITS,
            docker="docker",
            job_id="job-1234",
            run_root=tmp_path,
        )
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

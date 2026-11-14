"""TC-05: the container command and inspect checks enforce REQ-05."""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path

import pytest

from datacon.tools.sandbox import (
    IsolationPolicy,
    ResourceLimits,
    SandboxPolicyError,
    container_create_args,
    validate_host_config,
)

POLICY = IsolationPolicy(
    network="none",
    user="65534:65534",
    read_only_root=True,
    cap_drop=("ALL",),
    no_new_privileges=True,
    seccomp="runtime/default",
)
LIMITS = ResourceLimits(
    cpu=2,
    memory_mib=2048,
    pids=128,
    scratch_mib=512,
)
IMAGE = "silkeh/clang:19-bookworm@sha256:" + "a" * 64
MOUNT_SOURCE = str(Path(__file__).resolve())


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


def test_container_command_enforces_every_isolation_control():
    command = args()
    assert command[:2] == ["docker", "create"]
    assert "--network" in command
    assert command[command.index("--network") + 1] == "none"
    assert command[command.index("--user") + 1] == "65534:65534"
    assert "--read-only" in command
    assert command[command.index("--cap-drop") + 1] == "ALL"
    assert "no-new-privileges" in command
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
    ],
)
def test_invalid_isolation_policy_is_refused(policy):
    with pytest.raises(SandboxPolicyError):
        args(policy=policy)


def host_config(**overrides):
    value = {
        "NetworkMode": "none",
        "User": "65534:65534",
        "ReadonlyRootfs": True,
        "CapDrop": ["ALL"],
        "CapAdd": [],
        "SecurityOpt": ["no-new-privileges"],
        "Privileged": False,
        "PidsLimit": 128,
        "Memory": 2048 * 1024 * 1024,
        "MemorySwap": 2048 * 1024 * 1024,
        "NanoCpus": 2_000_000_000,
        "Binds": ["/tmp/material:/fixture:ro"],
        "Tmpfs": {"/work": "rw,exec,size=496m,mode=1777", "/tmp": "rw,exec,size=16m,mode=1777"},
        "IpcMode": "private",
        "Devices": [],
    }
    value.update(overrides)
    return value


def test_host_config_must_show_the_requested_limits():
    validate_host_config(host_config(), POLICY, LIMITS)


@pytest.mark.parametrize(
    "change",
    [
        {"NetworkMode": "default"},
        {"User": "0"},
        {"ReadonlyRootfs": False},
        {"CapDrop": []},
        {"SecurityOpt": ["no-new-privileges", "seccomp=unconfined"]},
        {"Privileged": True},
        {"PidsLimit": 0},
        {"Memory": 4096 * 1024 * 1024},
        {"NanoCpus": 4_000_000_000},
        {"Binds": ["/tmp/material:/fixture"]},
        {"Tmpfs": {}},
    ],
)
def test_drifted_or_unenforced_limits_are_refused(change):
    with pytest.raises(SandboxPolicyError):
        validate_host_config(host_config(**change), POLICY, LIMITS)


def test_relative_or_symlinked_bind_sources_are_refused(tmp_path):
    link = tmp_path / "link"
    link.symlink_to(tmp_path)
    with pytest.raises(SandboxPolicyError):
        args(mounts=[("relative/path", "/fixture", True)])
    with pytest.raises(SandboxPolicyError):
        args(mounts=[(str(link), "/fixture", True)])

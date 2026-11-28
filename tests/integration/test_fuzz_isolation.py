"""T12 B (改9): the real libFuzzer container profile and corpus isolation.

Marker group ``postgres and docker`` (D37 double label): a real Docker daemon
and the pinned toolchain image. The campaign build links the fixture's frozen
harness with the repository's fixed shim; the fuzz container runs it under the
same isolation baseline as build/replay with the seed corpus mounted
read-only. Coordinate registered in docs/spec/v0.2/test-plan-delta.md.
"""

from __future__ import annotations

from pathlib import Path
import shutil
import subprocess
from uuid import uuid4

import pytest

from datacon import fuzz, jsonutil
from datacon.tools.sandbox import (
    CORPUS_CONTAINER_PATH,
    FUZZER_CONTAINER_PATH,
    SECCOMP_PROFILE_DIGEST,
    DockerSandbox,
    IsolationPolicy,
    ResourceLimits,
    fuzz_runner_command,
)

pytestmark = [pytest.mark.postgres, pytest.mark.docker]

FIXTURE_CASES = Path(__file__).resolve().parents[1] / "fixtures" / "cases"
IMAGE = (
    "silkeh/clang:19-bookworm@sha256:"
    "f5ce959d91f059acf5a4b3f1c19f46713c4b2881c7d7cd1d5143ca1d1412277f"
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
LIMITS = ResourceLimits(cpu=2, memory_mib=2048, pids=128, scratch_mib=512)


def _docker_ready() -> bool:
    try:
        probe = subprocess.run(
            ["docker", "image", "inspect", IMAGE],
            capture_output=True,
            timeout=30,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return False
    return probe.returncode == 0


@pytest.fixture
def sandbox(tmp_path):
    if not _docker_ready():
        pytest.fail("the pinned toolchain image is required for this docker coordinate")
    return DockerSandbox(
        image=IMAGE,
        platform="linux/amd64",
        policy=POLICY,
        limits=LIMITS,
        job_id=str(uuid4()),
        run_root=tmp_path / "sandbox-run",
        generation=1,
    )


def _campaign_spec() -> dict:
    return {
        "kind": "shell",
        "build": ["sh", "./build.sh"],
        "install": [],
        "env": {"CC": "clang"},
        "outputs": ["parser", "fuzzer"],
        "declared_compile_flags": [
            "-fsanitize=address",
            "-g",
            "-O0",
            "-fno-omit-frame-pointer",
        ],
        "shell_recipe_digest": jsonutil.digest_bytes(
            (FIXTURE_CASES / "build.sh").read_bytes()
        ),
        "shell_face_digest": "sha256:" + "a" * 64,
        "shell_face_review": {
            "reviewer_id": "reviewer-01",
            "reviewed_at": "2099-01-01T00:00:00Z",
            "face_kind": "build_log",
        },
    }


def _record_creates(sandbox, monkeypatch):
    created: list[dict] = []
    original = sandbox._create

    def _recording(*, suffix, command, mounts, env=None):
        name, config = original(suffix=suffix, command=command, mounts=mounts, env=env)
        created.append(
            {"suffix": suffix, "command": list(command), "mounts": list(mounts), "config": config}
        )
        return name, config

    monkeypatch.setattr(sandbox, "_create", _recording)
    return created


def test_fuzz_container_profile_and_corpus_are_isolated(sandbox, tmp_path, monkeypatch):
    # One campaign build of the vulnerable version links parser + fuzzer from
    # the frozen harness and the reviewed shim staged next to the materials.
    materials = tmp_path / "materials"
    shutil.copytree(FIXTURE_CASES, materials)
    shutil.copyfile(fuzz.FUZZ_SHIM_PATH, materials / fuzz.FUZZ_SHIM_STAGED_NAME)
    built = sandbox.build(
        "vulnerable", materials_dir=materials, build_spec=_campaign_spec()
    )
    assert built.status == "completed", (built.metadata, built.log[-2000:])
    outputs = {item.relative_path: item for item in built.outputs}
    assert set(outputs) == {"parser", "fuzzer"}
    fuzzer = tmp_path / "fuzzer"
    fuzzer.write_bytes(outputs["fuzzer"].data)
    fuzzer.chmod(0o555)

    corpus = tmp_path / "corpus"
    corpus.mkdir()
    for name in ("normal.txt", "candidate.txt"):
        target = corpus / name
        target.write_bytes((FIXTURE_CASES / "inputs" / name).read_bytes())
        target.chmod(0o444)
    corpus.chmod(0o755)
    before = {path.name: path.read_bytes() for path in corpus.iterdir()}

    created = _record_creates(sandbox, monkeypatch)
    result = sandbox.fuzz(
        fuzzer_path=fuzzer,
        corpus_dir=corpus,
        rng_seed=fuzz.campaign_rng_seed("isolation", "sha256:" + "0" * 64),
        max_total_time=20,
        deadline_seconds=180,
        max_len=4096,
        asan_options="detect_leaks=0:halt_on_error=1:abort_on_error=0:exitcode=86",
        input_timeout_seconds=10,
        expected_fuzzer_digest=outputs["fuzzer"].digest,
    )

    assert result.status == "completed", (result.capture_error, result.log[-2000:])
    # The registered candidate seed overflows the vulnerable parser: libFuzzer
    # records it as a crash artifact (an observation, not a verdict).
    assert result.crashes, result.log[-2000:]
    assert b"AddressSanitizer: heap-buffer-overflow" in result.log
    assert b"INFO: Seed: %d" % result.rng_seed in result.log

    [fuzz_create] = [item for item in created if item["suffix"] == "fuzz"]
    config = fuzz_create["config"]
    assert config["NetworkMode"] == "none"
    assert config["User"] == "65534:65534"
    assert config["ReadonlyRootfs"] is True
    assert "ALL" in {item.upper() for item in config["CapDrop"]}
    assert not config.get("CapAdd") and not config.get("Privileged")
    security = [str(item) for item in config["SecurityOpt"]]
    assert any(item.startswith("no-new-privileges") for item in security)
    assert any(item.startswith("seccomp=") for item in security)
    mounts = {
        mount["Destination"]: mount for mount in config["Mounts"]
    }
    # Only the fuzzer and the corpus are mounted, both read-only; no Docker
    # socket, evidence directory or campaign directory.
    assert set(mounts) == {FUZZER_CONTAINER_PATH, CORPUS_CONTAINER_PATH}
    assert all(mount["RW"] is False for mount in mounts.values())
    assert all("docker.sock" not in mount["Source"] for mount in mounts.values())
    assert set(config["Tmpfs"]) == {"/work", "/tmp"}
    assert fuzz_create["command"][:2] == ["/bin/sh", "-c"]
    assert fuzz_create["command"][3:] == fuzz_runner_command(
        rng_seed=result.rng_seed,
        max_total_time=20,
        max_len=4096,
        rss_limit_mb=LIMITS.memory_mib - 256,
        input_timeout_seconds=10,
    )[3:]
    after = {path.name: path.read_bytes() for path in corpus.iterdir()}
    assert after == before, "fuzz corpus was writable"

    # The same profile proves the corpus mount refuses writes from inside.
    probe_name, _ = sandbox._create(
        suffix="corpus-probe",
        command=[
            "/bin/sh",
            "-c",
            "touch /corpus/new 2>/dev/null && echo WROTE; "
            "echo x > /corpus/normal.txt 2>/dev/null && echo CHANGED; "
            "touch /etc/datacon-probe 2>/dev/null && echo ROOTFS; echo done",
        ],
        mounts=[(str(corpus), CORPUS_CONTAINER_PATH, True)],
    )
    stdout, _stderr, *_rest = sandbox._start_and_wait(probe_name, deadline_seconds=60)
    assert b"done" in stdout
    assert b"WROTE" not in stdout and b"CHANGED" not in stdout, "fuzz corpus was writable"
    assert b"ROOTFS" not in stdout
    assert {path.name: path.read_bytes() for path in corpus.iterdir()} == before

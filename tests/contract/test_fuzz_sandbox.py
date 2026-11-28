"""T12 B (改9 增补, P2 review B1/B3/B4): the fuzz container result is fail-closed.

Contract group: no Docker daemon. ``DockerSandbox._create`` and
``_start_and_wait`` are replaced by recorded stand-ins, so these coordinates
prove how the host parses what a (possibly hostile) fuzz container reports.
Registered in docs/spec/v0.2/test-plan-delta.md (T12, 改9 增补).
"""

from __future__ import annotations

import hashlib
from pathlib import Path
from uuid import uuid4

import pytest

from datacon import fuzz
from datacon.tools import sandbox as sandbox_mod
from datacon.tools.sandbox import (
    FUZZ_MAX_CRASH_FILES,
    SECCOMP_PROFILE_DIGEST,
    DockerSandbox,
    IsolationPolicy,
    ResourceLimits,
    SandboxError,
    SandboxPolicyError,
    validate_fuzz_corpus_dir,
)

IMAGE = "silkeh/clang:19-bookworm@sha256:" + "a" * 64
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


def _hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _crash_line(index: int, data: bytes) -> bytes:
    return b"DATACON_FUZZ_CRASH index=%d size=%d sha256=%s\n" % (
        index,
        len(data),
        _hex(data).encode(),
    )


def _result_line(code: int, crashes: int) -> bytes:
    return b"DATACON_FUZZ_RESULT code=%d crashes=%d\n" % (code, crashes)


def _inputs(tmp_path: Path) -> tuple[Path, Path]:
    tmp_path.mkdir(parents=True, exist_ok=True)
    fuzzer = tmp_path / "fuzzer"
    fuzzer.write_bytes(b"ELF-fuzzer")
    corpus = tmp_path / "corpus"
    corpus.mkdir()
    seed = corpus / "normal.txt"
    seed.write_bytes(b"OK\n")
    seed.chmod(0o444)
    return fuzzer, corpus


class _Recorded:
    """Stand-in for one container run: what the host captured after it stopped."""

    def __init__(
        self,
        *,
        stderr: bytes,
        files: dict[str, bytes] | None = None,
        exit_code: int | None = 0,
        state: dict | None = None,
        truncated: set[str] | None = None,
        stdout: bytes = b"",
    ) -> None:
        self.stderr = stderr
        self.files = files or {}
        self.exit_code = exit_code
        self.state = state or {"OOMKilled": False}
        self.truncated = truncated or set()
        self.stdout = stdout


def _run(tmp_path: Path, monkeypatch, recorded: _Recorded):
    box = DockerSandbox(
        image=IMAGE,
        platform="linux/amd64",
        policy=POLICY,
        limits=LIMITS,
        job_id=str(uuid4()),
        run_root=tmp_path / "run",
        generation=1,
    )
    monkeypatch.setattr(box, "_create", lambda **_kwargs: ("fuzz-container", {}))
    monkeypatch.setattr(
        box,
        "_start_and_wait",
        lambda name, **_kwargs: (
            recorded.stdout,
            recorded.stderr,
            dict(recorded.files),
            set(recorded.truncated),
            dict(recorded.state),
            False,
            recorded.exit_code,
            None,
        ),
    )
    fuzzer, corpus = _inputs(tmp_path)
    return box.fuzz(
        fuzzer_path=fuzzer,
        corpus_dir=corpus,
        rng_seed=7,
        max_total_time=5,
        deadline_seconds=60,
        max_len=4096,
        asan_options="detect_leaks=0",
    )


CRASH = b"WXYZ\n"


@pytest.mark.parametrize(
    "case",
    ["forged_unanchored", "two_markers", "wrapper_exit_137", "bytes_drifted", "no_marker"],
)
def test_fuzz_result_parsing_fails_closed(tmp_path, monkeypatch, case):
    """Only one anchored marker from a wrapper that exited 0 is a completed search."""
    good = _crash_line(0, CRASH) + _result_line(1, 1)
    files = {"/work/crash-0": CRASH}
    exit_code = 0
    if case == "forged_unanchored":
        # The target prints a look-alike in the middle of a line.
        stderr = b"noise DATACON_FUZZ_RESULT code=0 crashes=0\n"
    elif case == "two_markers":
        stderr = _result_line(0, 0) + good
    elif case == "wrapper_exit_137":
        stderr = good
        exit_code = 137
    elif case == "bytes_drifted":
        stderr = good
        files = {"/work/crash-0": b"other bytes"}
    else:
        stderr = b"INFO: Seed: 7\n"
    result = _run(tmp_path, monkeypatch, _Recorded(stderr=stderr, files=files, exit_code=exit_code))
    assert result.status != "completed", (case, result)
    assert result.crashes == () or case == "wrapper_exit_137"


def test_fuzz_result_accepts_the_one_honest_marker_and_empty_crash(tmp_path, monkeypatch):
    stderr = (
        b"INFO: Seed: 7\n"
        + _crash_line(0, CRASH)
        + _crash_line(1, b"")
        + _result_line(1, 2)
    )
    files = {"/work/crash-0": CRASH, "/work/crash-1": b""}
    result = _run(tmp_path, monkeypatch, _Recorded(stderr=stderr, files=files))
    assert result.status == "completed", result
    # A zero-byte crash input is a real libFuzzer artifact, not an infra error.
    assert result.crashes == (CRASH, b"")
    assert result.crash_truncated is False


def test_fuzz_result_marks_crash_overflow_truncated(tmp_path, monkeypatch):
    total = FUZZ_MAX_CRASH_FILES + 3
    crashes = [b"crash-%d" % index for index in range(FUZZ_MAX_CRASH_FILES)]
    stderr = b"".join(_crash_line(i, data) for i, data in enumerate(crashes))
    stderr += _result_line(1, total)
    files = {f"/work/crash-{i}": data for i, data in enumerate(crashes)}
    result = _run(tmp_path, monkeypatch, _Recorded(stderr=stderr, files=files))
    assert result.crash_truncated is True
    assert len(result.crashes) == FUZZ_MAX_CRASH_FILES


@pytest.mark.parametrize("events", ["memory", "pids"])
def test_fuzz_cgroup_limit_hit_is_resource_limited(tmp_path, monkeypatch, events):
    files = {"/work/crash-0": CRASH}
    if events == "memory":
        files["/work/memory.events"] = b"low 0\nhigh 0\nmax 3\noom 1\noom_kill 1\n"
    else:
        files["/work/pids.events"] = b"max 4\n"
    stderr = _crash_line(0, CRASH) + _result_line(1, 1)
    result = _run(
        tmp_path,
        monkeypatch,
        _Recorded(stderr=stderr, files=files, state={"OOMKilled": False}),
    )
    assert result.status == "resource_limited", result


def test_fuzz_stdout_truncation_is_log_truncated(tmp_path, monkeypatch):
    stderr = _result_line(0, 0)
    result = _run(
        tmp_path,
        monkeypatch,
        _Recorded(stderr=stderr, truncated={"stdout"}, stdout=b"x" * 10),
    )
    assert result.log_truncated is True


def test_fuzz_rejects_unsafe_runtime_arguments(tmp_path, monkeypatch):
    for kwargs in (
        {"deadline_seconds": float("inf")},
        {"deadline_seconds": 0},
        {"asan_options": "detect_leaks=0\nexitcode=0"},
    ):
        box = DockerSandbox(
            image=IMAGE,
            platform="linux/amd64",
            policy=POLICY,
            limits=LIMITS,
            job_id=str(uuid4()),
            run_root=tmp_path / "run",
            generation=1,
        )
        monkeypatch.setattr(box, "_create", lambda **_kw: pytest.fail("reached create"))
        fuzzer, corpus = _inputs(tmp_path / str(uuid4()))
        call = {
            "fuzzer_path": fuzzer,
            "corpus_dir": corpus,
            "rng_seed": 7,
            "max_total_time": 5,
            "deadline_seconds": 60,
            "max_len": 4096,
            "asan_options": "detect_leaks=0",
            **kwargs,
        }
        with pytest.raises((SandboxPolicyError, SandboxError)):
            box.fuzz(**call)


def test_fuzz_corpus_boundary_enforces_byte_and_count_ceilings(tmp_path, monkeypatch):
    """The sandbox re-checks the §5 corpus ceilings before any container."""
    def _corpus(name: str, sizes: list[int]) -> Path:
        directory = tmp_path / name
        directory.mkdir()
        for index, size in enumerate(sizes):
            path = directory / f"seed-{index}"
            path.write_bytes(b"a" * size)
            path.chmod(0o444)
        return directory

    monkeypatch.setattr(fuzz, "CORPUS_MAX_FILE_BYTES", 4)
    monkeypatch.setattr(fuzz, "CORPUS_MAX_TOTAL_BYTES", 6)
    monkeypatch.setattr(fuzz, "CORPUS_MAX_FILE_COUNT", 3)
    validate_fuzz_corpus_dir(_corpus("ok", [4, 2]))
    for name, sizes in (
        ("file", [5]),
        ("total", [4, 3]),
        ("count", [1, 1, 1, 1]),
    ):
        with pytest.raises(SandboxPolicyError):
            validate_fuzz_corpus_dir(_corpus(name, sizes))
    # A symlinked corpus directory is refused even when its target is fine.
    real = _corpus("real", [1])
    link = tmp_path / "link"
    link.symlink_to(real, target_is_directory=True)
    with pytest.raises(SandboxPolicyError):
        validate_fuzz_corpus_dir(link)
    assert sandbox_mod.validate_fuzz_corpus_dir is validate_fuzz_corpus_dir

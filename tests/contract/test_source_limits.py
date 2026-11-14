"""Regression tests for hard output caps on Git subprocesses."""

from __future__ import annotations

import os
from pathlib import Path
import shutil
import subprocess
import threading

import pytest

from datacon.agents.analysis import AnalysisBlocked, analyze_case
from datacon.contracts import DEFAULT_LIMITS
from datacon.tools import source as source_module
from datacon.tools.source import GitRepository, SourceToolError, TransientSourceToolError

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "cases"


def _git(repository, *arguments, input_bytes=None):
    environment = os.environ.copy()
    environment.update(
        {
            "GIT_AUTHOR_NAME": "DataCon Test",
            "GIT_AUTHOR_EMAIL": "test@example.invalid",
            "GIT_COMMITTER_NAME": "DataCon Test",
            "GIT_COMMITTER_EMAIL": "test@example.invalid",
        }
    )
    return subprocess.run(
        ["git", *arguments],
        cwd=repository,
        input=input_bytes,
        capture_output=True,
        check=True,
        env=environment,
        timeout=60,
    )


def _repository_with_large_diff(tmp_path, size):
    repository = tmp_path / "repo.git"
    _git(tmp_path, "init", "--quiet", "--bare", "-b", "main", str(repository))
    empty_tree = _git(repository, "mktree", input_bytes=b"").stdout.strip()
    fixed = _git(
        repository, "commit-tree", empty_tree, "-m", "fixed"
    ).stdout.strip()
    blob = _git(
        repository,
        "hash-object",
        "-w",
        "--stdin",
        input_bytes=b"a" * size,
    ).stdout.strip()
    tree = _git(
        repository,
        "mktree",
        input_bytes=b"100644 blob " + blob + b"\tparser.c\n",
    ).stdout.strip()
    vulnerable = _git(
        repository,
        "commit-tree",
        tree,
        "-p",
        fixed,
        "-m",
        "vulnerable",
    ).stdout.strip()
    return repository, vulnerable.decode("ascii"), fixed.decode("ascii")


def test_large_git_diff_fails_fast_without_capturing_it_all(tmp_path):
    repository, vulnerable, fixed = _repository_with_large_diff(
        tmp_path, source_module.MAX_DIFF_BYTES + 1024 * 1024
    )
    git = GitRepository(repository, tmp_path / "empty-hooks")

    with pytest.raises(SourceToolError) as caught:
        git.diff(vulnerable, fixed)

    assert "cap" in caught.value.message


def test_tree_and_name_output_byte_caps_are_enforced(tmp_path, monkeypatch):
    bundle = FIXTURES / "fixture-repo.bundle"
    git = GitRepository.from_bundle(bundle, tmp_path / "repo")
    vulnerable = git.resolve_commit("refs/heads/vulnerable")
    fixed = git.resolve_commit("refs/heads/fixed")

    monkeypatch.setattr(source_module, "MAX_TREE_BYTES", 1)
    with pytest.raises(SourceToolError) as caught:
        git.list_paths(vulnerable)
    assert "tree" in caught.value.message and "cap" in caught.value.message

    monkeypatch.setattr(source_module, "MAX_TREE_BYTES", 32 * 1024 * 1024)
    monkeypatch.setattr(source_module, "MAX_DIFF_NAMES_BYTES", 1)
    with pytest.raises(SourceToolError) as caught:
        git.diff(vulnerable, fixed)
    assert "changed path" in caught.value.message and "cap" in caught.value.message


def test_analyze_case_maps_diff_cap_to_material_missing(tmp_path, monkeypatch):
    case_root = tmp_path / "cases"
    shutil.copytree(FIXTURES, case_root)
    monkeypatch.setattr(source_module, "MAX_DIFF_BYTES", 1)

    request = {
        "schema_version": 1,
        "cve_id": "CVE-2099-0001",
        "target": {
            "kind": "source",
            "case_id": "fixture-c-parser",
            "goal": "validate the Git output cap",
        },
        "limits": dict(DEFAULT_LIMITS),
    }
    with pytest.raises(AnalysisBlocked) as caught:
        analyze_case(request, case_root=case_root)

    assert caught.value.reason_code == "MATERIAL_MISSING"
    assert "cap" in caught.value.message


class _FakeStream:
    def __init__(self, chunks):
        self._chunks = list(chunks)

    def read(self, _size):
        return self._chunks.pop(0) if self._chunks else b""

    def close(self):
        pass


class _FakeProcess:
    def __init__(self):
        self.stdout = _FakeStream([b"x" * 32])
        self.stderr = _FakeStream([])
        self.pid = 2**31 - 1
        self.returncode = None
        self.killed = False
        self._done = threading.Event()

    def poll(self):
        return self.returncode if self._done.is_set() else None

    def kill(self):
        self.killed = True
        self.returncode = -9
        self._done.set()

    def wait(self, timeout=None):
        if not self._done.wait(timeout):
            raise subprocess.TimeoutExpired("git", timeout)
        return self.returncode


def test_stdout_overflow_kills_the_process_and_stops_reading(monkeypatch):
    process = _FakeProcess()
    monkeypatch.setattr(
        source_module.subprocess, "Popen", lambda *args, **kwargs: process
    )
    git = GitRepository(Path("/nonexistent"), Path("/nonexistent"))

    with pytest.raises(SourceToolError) as caught:
        git._run_limited(
            "ls-tree",
            "a" * 40,
            max_stdout_bytes=8,
            output_cap_message="repository tree output exceeds the analysis cap",
        )

    assert process.killed is True
    assert "cap" in caught.value.message
    assert process.stdout._chunks == []


def test_timeout_is_still_transient_and_kills_the_process(monkeypatch):
    class _HangingProcess(_FakeProcess):
        def __init__(self):
            super().__init__()
            self.stdout = _FakeStream([])
            self.stderr = _FakeStream([])

        def wait(self, timeout=None):
            if not self._done.is_set():
                raise subprocess.TimeoutExpired("git", timeout)
            return self.returncode

    process = _HangingProcess()
    monkeypatch.setattr(
        source_module.subprocess, "Popen", lambda *args, **kwargs: process
    )
    git = GitRepository(Path("/nonexistent"), Path("/nonexistent"))

    with pytest.raises(TransientSourceToolError):
        git._run_limited("diff", "a" * 40, max_stdout_bytes=8)

    assert process.killed is True

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


def _fixture_source(relative: str) -> bytes:
    return (FIXTURES / relative).read_bytes()


def test_tree_sitter_extracts_definitions_and_call_sites_in_a_subprocess():
    source = _fixture_source("vulnerable/parser.c")
    definitions = source_module.extract_symbols(
        source,
        path="vulnerable/parser.c",
        revision="vulnerable",
        function_name="parse_token",
        role="definition",
    )
    assert definitions == [
        {
            "name": "parse_token",
            "path": "vulnerable/parser.c",
            "role": "definition",
            "revision": "vulnerable",
            "start_line": 12,
            "end_line": 24,
        }
    ]

    call_sites = source_module.extract_symbols(
        _fixture_source("harness.c"),
        path="harness.c",
        revision="harness",
        function_name="parse_token",
        role="call_site",
    )
    assert [(item["path"], item["revision"], item["start_line"]) for item in call_sites] == [
        ("harness.c", "harness", 14)
    ]


def test_tree_sitter_rejects_syntax_errors_without_leaking_paths(tmp_path):
    source = b"int main( { this is not C"
    with pytest.raises(SourceToolError) as caught:
        source_module.extract_symbols(
            source,
            path="parser.c",
            revision="vulnerable",
            function_name="parse_token",
            role="definition",
        )
    assert caught.value.tool_id == "tree_sitter.extract"
    assert "syntax error" in caught.value.message
    assert str(tmp_path) not in caught.value.message
    assert "/Users/" not in caught.value.message


def test_tree_sitter_timeout_kills_the_worker(monkeypatch):
    import time

    monkeypatch.setattr(source_module, "TREE_SITTER_TIMEOUT_SECONDS", 0.000001)
    started = time.monotonic()
    with pytest.raises(SourceToolError) as caught:
        source_module.extract_symbols(
            _fixture_source("vulnerable/parser.c"),
            path="vulnerable/parser.c",
            revision="vulnerable",
            function_name="parse_token",
            role="definition",
        )
    elapsed = time.monotonic() - started
    assert caught.value.tool_id == "tree_sitter.extract"
    assert "timed out" in caught.value.message
    assert elapsed < 10, f"timeout path took {elapsed:.2f}s"


def test_tree_sitter_worker_crash_fails_closed(monkeypatch):
    monkeypatch.setattr(
        source_module, "TREE_SITTER_WORKER_MODULE", "datacon.tools._missing_worker"
    )
    with pytest.raises(SourceToolError) as caught:
        source_module.extract_symbols(
            _fixture_source("vulnerable/parser.c"),
            path="vulnerable/parser.c",
            revision="vulnerable",
            function_name="parse_token",
            role="definition",
        )
    assert caught.value.tool_id == "tree_sitter.extract"
    assert "worker failed" in caught.value.message
    assert "/Users/" not in caught.value.message


@pytest.mark.skipif(
    os.name != "posix" or not os.path.exists("/proc/self/status"),
    reason="RLIMIT_AS memory-limit enforcement is Linux-specific",
)
def test_tree_sitter_memory_limit_fails_closed(monkeypatch):
    monkeypatch.setattr(source_module, "TREE_SITTER_MEMORY_LIMIT_BYTES", 1)
    with pytest.raises(SourceToolError) as caught:
        source_module.extract_symbols(
            _fixture_source("vulnerable/parser.c"),
            path="vulnerable/parser.c",
            revision="vulnerable",
            function_name="parse_token",
            role="definition",
        )
    assert caught.value.tool_id == "tree_sitter.extract"
    assert any(
        marker in caught.value.message
        for marker in ("memory", "worker failed", "could not start")
    ), caught.value.message


def test_tree_sitter_rejects_a_worker_that_returns_a_host_path(monkeypatch):
    def fake_worker(_payload):
        return {
            "ok": True,
            "symbols": [
                {
                    "name": "parse_token",
                    "path": "/Users/operator/secret/parser.c",
                    "role": "definition",
                    "revision": "vulnerable",
                    "start_line": 1,
                    "end_line": 2,
                }
            ],
        }

    monkeypatch.setattr(source_module, "_run_tree_sitter_worker", fake_worker)
    with pytest.raises(SourceToolError) as caught:
        source_module.extract_symbols(
            _fixture_source("vulnerable/parser.c"),
            path="vulnerable/parser.c",
            revision="vulnerable",
            function_name="parse_token",
            role="definition",
        )
    assert caught.value.tool_id == "tree_sitter.extract"
    assert "invalid result" in caught.value.message
    assert "/Users/" not in caught.value.message

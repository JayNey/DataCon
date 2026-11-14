"""Constrained Git and Tree-sitter tools used during analysis."""

from __future__ import annotations

from dataclasses import dataclass
import os
from pathlib import Path
import re
import signal
import subprocess
import threading

from datacon import jsonutil

MAX_SOURCE_BYTES = 4 * 1024 * 1024
MAX_DIFF_BYTES = 8 * 1024 * 1024
# A tree entry is longer than a path (mode, type, object id and tab), so the
# byte cap is deliberately independent of MAX_TREE_PATHS. Both limits are
# enforced while the subprocess is still running.
MAX_TREE_BYTES = 32 * 1024 * 1024
MAX_TREE_PATHS = 100_000
MAX_DIFF_NAMES_BYTES = 4 * 1024 * 1024
MAX_CHANGED_PATHS = 10_000
MAX_SYMBOLS = 10_000
MAX_GIT_STDERR_BYTES = 64 * 1024
GIT_TIMEOUT_SECONDS = 30
_READ_CHUNK_BYTES = 64 * 1024
_REF = re.compile(r"refs/(?:heads|tags)/[A-Za-z0-9][A-Za-z0-9._/-]*")
_OID = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})")


class SourceToolError(ValueError):
    """A constrained Git or Tree-sitter call failed."""

    def __init__(self, tool_id: str, message: str):
        super().__init__(message)
        self.tool_id = tool_id
        self.message = message


class TransientSourceToolError(SourceToolError):
    """A Git call failed in a way that may succeed on one more attempt.

    Missing files, unsafe refs and semantic Git errors remain
    ``SourceToolError``. Timeouts, process failures and transient I/O use this
    subclass so the Supervisor can retry instead of blocking the job.
    """


def _decode_utf8(payload: bytes, *, tool_id: str, message: str) -> str:
    """Decode Git path metadata, blocking non-UTF-8 trees as material errors."""
    try:
        return payload.decode("utf-8")
    except UnicodeDecodeError as error:
        raise SourceToolError(tool_id, message) from error


@dataclass(frozen=True)
class GitDiff:
    patch: bytes
    changed_paths: tuple[str, ...]
    digest: str


_GIT_ENV_REMOVE = (
    "GIT_CONFIG_COUNT",
    "GIT_OBJECT_DIRECTORY",
    "GIT_ALTERNATE_OBJECT_DIRECTORIES",
    "GIT_SSH_COMMAND",
    "GIT_ASKPASS",
    "GIT_DIR",
    "GIT_WORK_TREE",
    "GIT_INDEX_FILE",
)
_GIT_ENV_PREFIXES = ("GIT_CONFIG_KEY_", "GIT_CONFIG_VALUE_")


def _git_environment(hooks: Path) -> dict[str, str]:
    environment = os.environ.copy()
    for key in list(environment):
        if key in _GIT_ENV_REMOVE or key.startswith(_GIT_ENV_PREFIXES):
            environment.pop(key, None)
    environment.update(
        {
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_ATTR_NOSYSTEM": "1",
            "GIT_TERMINAL_PROMPT": "0",
            "GIT_ALLOW_PROTOCOL": "file",
            "LC_ALL": "C",
            "LANG": "C",
        }
    )
    return environment


def _kill_process(process) -> None:
    """Kill a subprocess and, on POSIX, its whole process group.

    Killing only the parent is not enough: a Git helper can keep the stdout
    pipe open after its parent is gone, which would leave a reader thread
    blocked. Never let a cleanup failure mask the original limit error.
    """
    poll = getattr(process, "poll", None)
    if poll is not None and poll() is not None:
        return
    pid = getattr(process, "pid", None)
    if os.name == "posix" and pid is not None:
        try:
            os.killpg(os.getpgid(pid), signal.SIGKILL)
            return
        except (ProcessLookupError, PermissionError, OverflowError, OSError):
            pass
    kill = getattr(process, "kill", None)
    if kill is None:
        return
    try:
        kill()
    except (ProcessLookupError, OSError):
        pass


def _bounded_run(
    command: list[str],
    *,
    environment: dict[str, str],
    max_stdout_bytes: int,
    max_stderr_bytes: int,
    operation: str,
    output_cap_message: str,
    tool_id: str = "git.resolve",
    timeout: float = GIT_TIMEOUT_SECONDS,
) -> tuple[int, bytes, bytes]:
    """Run one Git command without ever buffering unbounded stdout/stderr.

    ``subprocess.run(capture_output=True)`` reads the whole pipe before the
    caller can enforce a cap. This path reads fixed-size chunks, kills the
    process group as soon as stdout exceeds ``max_stdout_bytes``, and keeps
    stderr bounded while still draining it so the child cannot block on a full
    stderr pipe. The timeout is measured from process start.
    """
    try:
        process = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=environment,
            start_new_session=True,
        )
    except (FileNotFoundError, PermissionError) as error:
        raise SourceToolError(
            tool_id,
            f"git {operation} could not start: {type(error).__name__}",
        ) from error
    except OSError as error:
        raise TransientSourceToolError(
            tool_id,
            f"git {operation} could not start: {type(error).__name__}",
        ) from error

    stdout = bytearray()
    stderr = bytearray()
    stdout_overflow = threading.Event()
    timed_out = threading.Event()

    def read_stdout() -> None:
        try:
            while True:
                chunk = process.stdout.read(_READ_CHUNK_BYTES)
                if not chunk:
                    return
                remaining = max_stdout_bytes - len(stdout)
                if remaining < len(chunk):
                    if remaining > 0:
                        stdout.extend(chunk[:remaining])
                    stdout_overflow.set()
                    _kill_process(process)
                    return
                stdout.extend(chunk)
        finally:
            try:
                process.stdout.close()
            except OSError:
                pass

    def read_stderr() -> None:
        try:
            while True:
                chunk = process.stderr.read(_READ_CHUNK_BYTES)
                if not chunk:
                    return
                remaining = max_stderr_bytes - len(stderr)
                if remaining > 0:
                    stderr.extend(chunk[:remaining])
                # Anything beyond the cap is drained and discarded, never kept
                # in memory. The child must not block on a full stderr pipe.
        finally:
            try:
                process.stderr.close()
            except OSError:
                pass

    # Daemon threads ensure a broken child cannot keep the worker alive even
    # if the operating system does not report EOF after the process exits.
    readers = [
        threading.Thread(target=read_stdout, daemon=True),
        threading.Thread(target=read_stderr, daemon=True),
    ]
    for reader in readers:
        reader.start()
    reader_stalled = False
    try:
        process.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        timed_out.set()
        _kill_process(process)
        process.wait()
    finally:
        for reader in readers:
            reader.join(timeout=5)
        reader_stalled = any(reader.is_alive() for reader in readers)

    if timed_out.is_set():
        raise TransientSourceToolError(
            tool_id, f"git {operation} timed out"
        )
    if stdout_overflow.is_set():
        raise SourceToolError(tool_id, output_cap_message)
    if reader_stalled:
        # Do not read buffers that a live reader can still mutate. Treat a
        # leaked pipe as a transient child-process failure.
        raise TransientSourceToolError(
            tool_id, f"git {operation} output reader did not stop"
        )
    return process.returncode, bytes(stdout), bytes(stderr)


def _git_failure(
    tool_id: str, operation: str, stderr: bytes, returncode: int
) -> SourceToolError:
    """Classify a non-zero Git exit, keeping the existing 500-char limit."""
    message = stderr.decode("utf-8", "replace").strip()[:500]
    error_type = (
        TransientSourceToolError if returncode < 0 else SourceToolError
    )
    return error_type(tool_id, f"git {operation} failed: {message}")


class GitRepository:
    """A read-only bare repository materialized from a pinned case bundle."""

    def __init__(self, path: Path, hooks: Path):
        self.path = path
        self._hooks = hooks

    @classmethod
    def from_bundle(
        cls,
        bundle: Path,
        destination: Path,
        *,
        refs: tuple[str, ...] = ("refs/heads/vulnerable", "refs/heads/fixed"),
    ) -> "GitRepository":
        if not bundle.is_file() or bundle.is_symlink():
            raise SourceToolError("git.resolve", "case repository bundle is missing")
        if not refs or any(
            not _REF.fullmatch(ref) or ".." in ref or "@{" in ref for ref in refs
        ):
            raise SourceToolError("git.resolve", "case repository refs are not allowed")
        hooks = destination.parent / "empty-hooks"
        hooks.mkdir(mode=0o700, parents=True, exist_ok=True)
        repository = destination
        repository.mkdir(mode=0o700, parents=True, exist_ok=True)
        environment = _git_environment(hooks)
        base = [
            "git",
            "-c",
            f"core.hooksPath={hooks}",
            "-c",
            "diff.external=",
            "-c",
            "core.fsmonitor=false",
            "-c",
            "color.ui=false",
            "-C",
            str(repository),
        ]
        commands = [
            ["init", "--quiet", "--bare", "-b", "main"],
            [
                "fetch",
                "--quiet",
                "--no-tags",
                "--no-write-fetch-head",
                str(bundle),
                *(f"+{ref}:{ref}" for ref in refs),
            ],
        ]
        for arguments in commands:
            returncode, _, stderr = _bounded_run(
                [*base, *arguments],
                environment=environment,
                max_stdout_bytes=1024 * 1024,
                max_stderr_bytes=MAX_GIT_STDERR_BYTES,
                operation=arguments[0],
                output_cap_message=(
                    f"git {arguments[0]} output exceeds the analysis cap"
                ),
            )
            if returncode != 0:
                raise _git_failure(
                    "git.resolve", arguments[0], stderr, returncode
                )
        return cls(repository, hooks)

    def _run(
        self,
        *arguments: str,
        binary: bool = True,
        max_stdout_bytes: int = MAX_DIFF_BYTES,
        max_stderr_bytes: int = MAX_GIT_STDERR_BYTES,
        output_cap_message: str = "Git output exceeds the analysis cap",
    ) -> bytes:
        """Run one repository command with an explicit bounded stdout path.

        ``_run`` itself is bounded; all production callers go through
        ``_run_limited``, which supplies the operation-specific cap. The
        defaults exist only so older tests/helpers can still monkeypatch or
        call ``_run`` directly without creating an unbounded path.
        """
        environment = _git_environment(self._hooks)
        command = [
            "git",
            "-c",
            f"core.hooksPath={self._hooks}",
            "-c",
            "diff.external=",
            "-c",
            "core.fsmonitor=false",
            "-c",
            "color.ui=false",
            "-c",
            "core.quotepath=false",
            "-C",
            str(self.path),
        ]
        returncode, stdout, stderr = _bounded_run(
            [*command, *arguments],
            environment=environment,
            max_stdout_bytes=max_stdout_bytes,
            max_stderr_bytes=max_stderr_bytes,
            operation=arguments[0],
            output_cap_message=output_cap_message,
        )
        if returncode != 0:
            raise _git_failure(
                "git.resolve", arguments[0], stderr, returncode
            )
        return stdout

    def _run_limited(
        self,
        *arguments: str,
        max_stdout_bytes: int,
        max_stderr_bytes: int = MAX_GIT_STDERR_BYTES,
        output_cap_message: str = "Git output exceeds the analysis cap",
    ) -> bytes:
        """Bounded Git call used for every potentially large output."""
        return self._run(
            *arguments,
            max_stdout_bytes=max_stdout_bytes,
            max_stderr_bytes=max_stderr_bytes,
            output_cap_message=output_cap_message,
        )

    def resolve_commit(self, ref: str, expected: str | None = None) -> str:
        if not isinstance(ref, str) or not _REF.fullmatch(ref):
            raise SourceToolError("git.resolve", "revision ref is not allowed")
        try:
            output = self._run_limited(
                "rev-parse",
                "--verify",
                f"{ref}^{{commit}}",
                max_stdout_bytes=1024,
                output_cap_message=(
                    "git rev-parse output exceeds the analysis cap"
                ),
            )
        except TransientSourceToolError:
            raise
        except SourceToolError as error:
            raise SourceToolError(
                "git.resolve", f"commit for {ref} is missing"
            ) from error
        oid = output.decode("ascii", "strict").strip()
        if not _OID.fullmatch(oid):
            raise SourceToolError("git.resolve", "resolved revision is not a commit")
        if expected is not None and oid != expected:
            raise SourceToolError(
                "git.resolve",
                f"{ref} resolves to {oid}, not the pinned commit {expected}",
            )
        return oid

    def read_blob(self, commit: str, path: str) -> bytes:
        if not _OID.fullmatch(commit):
            raise SourceToolError("git.resolve", "commit must be a full object ID")
        safe = jsonutil.safe_relative_path(path, "source path")
        if ":" in safe:
            raise SourceToolError("git.resolve", "source path must not contain ':'")
        object_name = f"{commit}:{safe}"
        try:
            raw_size = self._run_limited(
                "cat-file",
                "-s",
                object_name,
                max_stdout_bytes=1024,
                output_cap_message=(
                    "Git object size output exceeds the analysis cap"
                ),
            )
        except TransientSourceToolError:
            raise
        except SourceToolError as error:
            raise SourceToolError(
                "git.resolve", f"path {safe} is missing from commit {commit}"
            ) from error
        try:
            size = int(raw_size.decode("ascii", "strict").strip())
        except (UnicodeDecodeError, ValueError) as error:
            raise SourceToolError(
                "git.resolve", "Git object size is not an integer"
            ) from error
        if size > MAX_SOURCE_BYTES:
            raise SourceToolError("git.resolve", "source file exceeds the analysis cap")
        try:
            data = self._run_limited(
                "cat-file",
                "blob",
                object_name,
                max_stdout_bytes=MAX_SOURCE_BYTES,
                output_cap_message="source file exceeds the analysis cap",
            )
        except TransientSourceToolError:
            raise
        except SourceToolError as error:
            raise SourceToolError(
                "git.resolve", f"path {safe} is missing from commit {commit}"
            ) from error
        if len(data) > MAX_SOURCE_BYTES:
            raise SourceToolError("git.resolve", "source file exceeds the analysis cap")
        return data

    def list_paths(self, commit: str) -> frozenset[str]:
        """Return every file path in a commit so evidence refs can be resolved."""
        if not _OID.fullmatch(commit):
            raise SourceToolError("git.resolve", "commit must be a full object ID")
        output = self._run_limited(
            "ls-tree",
            "-r",
            "-z",
            commit,
            "--",
            max_stdout_bytes=MAX_TREE_BYTES,
            output_cap_message=(
                "repository tree output exceeds the analysis cap"
            ),
        )
        tree = _decode_utf8(
            output,
            tool_id="git.resolve",
            message="repository tree contains a non-UTF-8 path",
        )
        paths = set()
        for line in tree.split("\x00"):
            if not line:
                continue
            metadata, separator, raw = line.partition("\t")
            if not separator:
                raise SourceToolError(
                    "git.resolve", "repository tree entry is malformed"
                )
            fields = metadata.split()
            if len(fields) != 3:
                raise SourceToolError(
                    "git.resolve", "repository tree entry is malformed"
                )
            _, object_type, _ = fields
            if object_type != "blob":
                continue
            try:
                paths.add(jsonutil.safe_relative_path(raw, "repository path"))
            except ValueError as error:
                raise SourceToolError(
                    "git.resolve", f"repository path is not allowed: {error}"
                ) from error
        if len(paths) > MAX_TREE_PATHS:
            raise SourceToolError("git.resolve", "repository tree is too large")
        return frozenset(paths)

    def diff(self, vulnerable: str, fixed: str) -> GitDiff:
        for oid in (vulnerable, fixed):
            if not _OID.fullmatch(oid):
                raise SourceToolError("git.diff", "diff requires full commit IDs")
        patch = self._run_limited(
            "diff",
            "--no-ext-diff",
            "--no-textconv",
            "--no-color",
            "--no-renames",
            "--src-prefix=a/",
            "--dst-prefix=b/",
            vulnerable,
            fixed,
            "--",
            max_stdout_bytes=MAX_DIFF_BYTES,
            output_cap_message="diff exceeds the analysis cap",
        )
        if len(patch) > MAX_DIFF_BYTES:
            raise SourceToolError("git.diff", "diff exceeds the analysis cap")
        names = self._run_limited(
            "diff",
            "--name-only",
            "--no-renames",
            vulnerable,
            fixed,
            "--",
            max_stdout_bytes=MAX_DIFF_NAMES_BYTES,
            output_cap_message=(
                "changed path output exceeds the analysis cap"
            ),
        )
        path_text = _decode_utf8(
            names,
            tool_id="git.diff",
            message="changed paths contain a non-UTF-8 path",
        )
        paths = []
        for raw in path_text.splitlines():
            if raw:
                try:
                    paths.append(jsonutil.safe_relative_path(raw, "changed path"))
                except ValueError as error:
                    raise SourceToolError(
                        "git.diff", f"changed path is not allowed: {error}"
                    ) from error
                if len(paths) > MAX_CHANGED_PATHS:
                    raise SourceToolError(
                        "git.diff", "diff changes too many paths"
                    )
        if not paths:
            raise SourceToolError("git.diff", "the revisions have no changed paths")
        return GitDiff(
            patch=patch,
            changed_paths=tuple(sorted(set(paths))),
            digest=jsonutil.digest_bytes(patch),
        )


def _parser():
    import tree_sitter_c
    from tree_sitter import Language, Parser

    return Parser(Language(tree_sitter_c.language()))


def _function_name(node) -> str | None:
    declarator = node.child_by_field_name("declarator")
    while declarator is not None:
        if declarator.type == "function_declarator":
            inner = declarator.child_by_field_name("declarator")
            if inner is not None and inner.type == "identifier":
                return inner.text.decode("utf-8", "replace")
            return None
        if declarator.type == "identifier":
            return declarator.text.decode("utf-8", "replace")
        declarator = declarator.child_by_field_name("declarator")
    return None


def _walk(node):
    stack = [node]
    while stack:
        current = stack.pop()
        yield current
        stack.extend(reversed(current.children))


def extract_symbols(
    source: bytes,
    *,
    path: str,
    revision: str,
    function_name: str,
    role: str,
) -> list[dict]:
    """Extract a named function definition or its call sites with Tree-sitter."""
    if len(source) > MAX_SOURCE_BYTES:
        raise SourceToolError("tree_sitter.extract", "source file exceeds the analysis cap")
    jsonutil.require_text(function_name, "function_name")
    safe_path = jsonutil.safe_relative_path(path, "source path")
    try:
        tree = _parser().parse(source)
    except Exception as error:  # tree-sitter raises a mix of parser errors
        raise SourceToolError(
            "tree_sitter.extract", f"cannot parse {safe_path}: {error}"
        ) from error
    if tree.root_node.has_error:
        raise SourceToolError(
            "tree_sitter.extract", f"cannot parse {safe_path}: syntax error"
        )

    symbols: list[dict] = []
    for node in _walk(tree.root_node):
        if role == "definition" and node.type == "function_definition":
            if _function_name(node) != function_name:
                continue
        elif role == "call_site" and node.type == "call_expression":
            function = node.child_by_field_name("function")
            if function is None or function.type != "identifier":
                continue
            if function.text.decode("utf-8", "replace") != function_name:
                continue
        else:
            continue
        if len(symbols) >= MAX_SYMBOLS:
            raise SourceToolError(
                "tree_sitter.extract", "too many symbols in one source file"
            )
        symbols.append(
            {
                "name": function_name,
                "path": safe_path,
                "role": role,
                "revision": revision,
                "start_line": node.start_point.row + 1,
                "end_line": node.end_point.row + 1,
            }
        )
    return symbols


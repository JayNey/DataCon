"""Constrained Git and Tree-sitter tools used during analysis."""

from __future__ import annotations

from dataclasses import dataclass
import os
from pathlib import Path
import re
import subprocess

from datacon import jsonutil

MAX_SOURCE_BYTES = 4 * 1024 * 1024
MAX_DIFF_BYTES = 8 * 1024 * 1024
MAX_TREE_PATHS = 100_000
MAX_CHANGED_PATHS = 10_000
MAX_SYMBOLS = 10_000
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
            try:
                result = subprocess.run(
                    [*base, *arguments],
                    capture_output=True,
                    text=True,
                    encoding="utf-8",
                    errors="replace",
                    timeout=30,
                    env=environment,
                )
            except subprocess.TimeoutExpired as error:
                raise TransientSourceToolError(
                    "git.resolve", f"git {arguments[0]} timed out"
                ) from error
            except (FileNotFoundError, PermissionError) as error:
                raise SourceToolError(
                    "git.resolve",
                    f"git {arguments[0]} could not start: {type(error).__name__}",
                ) from error
            except OSError as error:
                raise TransientSourceToolError(
                    "git.resolve",
                    f"git {arguments[0]} could not start: {type(error).__name__}",
                ) from error
            if result.returncode != 0:
                error_type = (
                    TransientSourceToolError
                    if result.returncode < 0
                    else SourceToolError
                )
                raise error_type(
                    "git.resolve",
                    f"git {arguments[0]} failed: {result.stderr.strip()[:500]}",
                )
        return cls(repository, hooks)

    def _run(self, *arguments: str, binary: bool = True) -> bytes:
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
        try:
            result = subprocess.run(
                [*command, *arguments],
                capture_output=True,
                timeout=30,
                env=environment,
            )
        except subprocess.TimeoutExpired as error:
            raise TransientSourceToolError(
                "git.resolve", f"git {arguments[0]} timed out"
            ) from error
        except (FileNotFoundError, PermissionError) as error:
            raise SourceToolError(
                "git.resolve",
                f"git {arguments[0]} could not start: {type(error).__name__}",
            ) from error
        except OSError as error:
            raise TransientSourceToolError(
                "git.resolve",
                f"git {arguments[0]} could not start: {type(error).__name__}",
            ) from error
        if result.returncode != 0:
            message = result.stderr.decode("utf-8", "replace").strip()[:500]
            error_type = (
                TransientSourceToolError
                if result.returncode < 0
                else SourceToolError
            )
            raise error_type(
                "git.resolve", f"git {arguments[0]} failed: {message}"
            )
        return result.stdout

    def resolve_commit(self, ref: str, expected: str | None = None) -> str:
        if not isinstance(ref, str) or not _REF.fullmatch(ref):
            raise SourceToolError("git.resolve", "revision ref is not allowed")
        try:
            output = self._run("rev-parse", "--verify", f"{ref}^{{commit}}")
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
            raw_size = self._run("cat-file", "-s", object_name)
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
            data = self._run("cat-file", "blob", object_name)
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
        output = self._run("ls-tree", "-r", "-z", commit, "--")
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
        patch = self._run(
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
        )
        if len(patch) > MAX_DIFF_BYTES:
            raise SourceToolError("git.diff", "diff exceeds the analysis cap")
        names = self._run(
            "diff",
            "--name-only",
            "--no-renames",
            vulnerable,
            fixed,
            "--",
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


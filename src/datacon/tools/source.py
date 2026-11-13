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
_REF = re.compile(r"refs/(?:heads|tags)/[A-Za-z0-9][A-Za-z0-9._/-]*")
_OID = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})")


class SourceToolError(ValueError):
    """A constrained Git or Tree-sitter call failed."""

    def __init__(self, tool_id: str, message: str):
        super().__init__(message)
        self.tool_id = tool_id
        self.message = message


@dataclass(frozen=True)
class GitDiff:
    patch: bytes
    changed_paths: tuple[str, ...]
    digest: str


def _git_environment(hooks: Path) -> dict[str, str]:
    environment = os.environ.copy()
    environment.update(
        {
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_TERMINAL_PROMPT": "0",
            "GIT_ALLOW_PROTOCOL": "file",
            "LC_ALL": "C",
            "LANG": "C",
        }
    )
    environment.pop("GIT_DIR", None)
    environment.pop("GIT_WORK_TREE", None)
    environment.pop("GIT_INDEX_FILE", None)
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
            result = subprocess.run(
                [*base, *arguments],
                capture_output=True,
                text=True,
                timeout=30,
                env=environment,
            )
            if result.returncode != 0:
                raise SourceToolError(
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
        result = subprocess.run(
            [*command, *arguments],
            capture_output=True,
            timeout=30,
            env=environment,
        )
        if result.returncode != 0:
            message = result.stderr.decode("utf-8", "replace").strip()[:500]
            raise SourceToolError(
                "git.resolve", f"git {arguments[0]} failed: {message}"
            )
        return result.stdout

    def resolve_commit(self, ref: str, expected: str | None = None) -> str:
        if not isinstance(ref, str) or not _REF.fullmatch(ref):
            raise SourceToolError("git.resolve", "revision ref is not allowed")
        try:
            output = self._run("rev-parse", "--verify", f"{ref}^{{commit}}")
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
        try:
            data = self._run("cat-file", "blob", f"{commit}:{safe}")
        except SourceToolError as error:
            raise SourceToolError(
                "git.resolve", f"path {safe} is missing from commit {commit}"
            ) from error
        if len(data) > MAX_SOURCE_BYTES:
            raise SourceToolError("git.resolve", "source file exceeds the analysis cap")
        return data

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
        paths = []
        for raw in names.decode("utf-8", "strict").splitlines():
            if raw:
                paths.append(jsonutil.safe_relative_path(raw, "changed path"))
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


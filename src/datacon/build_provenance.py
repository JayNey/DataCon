"""Build provenance normalization, face parsing, freeze validation, and comparability checks.

Implements docs/spec/v0.2/interface-contract-delta.md §5 & §8 and ADR-005
under rule set ``build-provenance-v1``.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Iterable, Mapping, Sequence
from copy import deepcopy
from dataclasses import dataclass
import fnmatch
import hashlib
from pathlib import Path, PurePosixPath
import posixpath
import re
import shlex
from typing import Any, Final

from datacon import jsonutil

RULES_VERSION: Final[str] = "build-provenance-v1"
BUILD_PROVENANCE_MISSING: Final[str] = "BUILD_PROVENANCE_MISSING"
BUILD_PROVENANCE_ROLE: Final[str] = "build_provenance"

FACE_FILENAMES: Final[dict[str, str]] = {
    "cmake": "compile_commands.json",
    "make": "cc-shim.log",
    "shell": "shell-face.log",
}

_VALID_KINDS: Final[frozenset[str]] = frozenset(FACE_FILENAMES)
_VALID_VERSIONS: Final[frozenset[str]] = frozenset({"vulnerable", "fixed"})
_SOURCE_SUFFIXES: Final[frozenset[str]] = frozenset({".c", ".cc", ".cpp", ".cxx", ".C"})

_SHORT_OPTS: Final[frozenset[str]] = frozenset({"-I", "-L", "-l", "-D", "-U"})
_LONG_OPTS: Final[frozenset[str]] = frozenset({"-isystem", "-include"})
_PATH_OPTS: Final[frozenset[str]] = frozenset({"-I", "-L", "-isystem", "-include"})
_SEVEN_OPTS: Final[frozenset[str]] = _SHORT_OPTS | _LONG_OPTS

_COMMON_REQUIRED_SPEC_FIELDS: Final[frozenset[str]] = frozenset(
    {"kind", "build", "env", "outputs", "declared_compile_flags"}
)
_SHELL_ONLY_SPEC_FIELDS: Final[frozenset[str]] = frozenset(
    {"shell_recipe_digest", "shell_face_digest", "shell_face_review"}
)
_SHELL_REVIEW_FIELDS: Final[frozenset[str]] = frozenset(
    {"reviewer_id", "reviewed_at", "face_kind"}
)

_WS_RE: Final[re.Pattern[str]] = re.compile(r"\s+")
_SHELL_META_RE: Final[re.Pattern[str]] = re.compile(r"[\s;&|`$<>\"'\\()]")
_CONTROL_RE: Final[re.Pattern[str]] = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
_ENV_KEY_RE: Final[re.Pattern[str]] = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_CMAKE_FALSE_VALUES: Final[frozenset[str]] = frozenset(
    {"", "0", "off", "false", "no", "n", "ignore", "notfound"}
)
_TIMESTAMP_RE: Final[re.Pattern[str]] = re.compile(
    r"\b[0-9]{4}-[0-9]{2}-[0-9]{2}[Tt ][0-9]{2}:[0-9]{2}:[0-9]{2}"
    r"(?:\.[0-9]{1,9})?(?:[Zz]|[+-][0-9]{2}:?[0-9]{2})?"
)

CC_SHIM_BASENAMES: Final[frozenset[str]] = frozenset({"cc-shim"})
CXX_SHIM_BASENAMES: Final[frozenset[str]] = frozenset(
    {"cxx-shim", "cc-shim++", "c++-shim"}
)
FORBIDDEN_SHIM_MOUNT_PREFIXES: Final[tuple[str, ...]] = (
    "/fixture",
    "/work",
    "/tmp",
    "/proc",
    "/sys",
    "/dev",
)
FORBIDDEN_BUILD_ENV_KEYS: Final[frozenset[str]] = frozenset(
    {
        "PATH",
        "LD_PRELOAD",
        "LD_LIBRARY_PATH",
        "TMPDIR",
        "HOME",
        "ASAN_OPTIONS",
        "MAKEFLAGS",
        "GNUMAKEFLAGS",
        "MAKEOVERRIDES",
        "MAKEFILES",
        "MFLAGS",
        "SHELL",
        "BASH_ENV",
        "ENV",
    }
)
_CREDENTIAL_ENV_PREFIXES: Final[tuple[str, ...]] = (
    "DATACON_",
    "GITHUB_",
    "AWS_",
    "TOKEN",
    "SECRET",
)
_ALLOWED_TOOL_DIRS: Final[frozenset[str]] = frozenset(
    {"/usr/bin", "/usr/local/bin", "/bin"}
)
_CMAKE_TOOL_NAMES: Final[frozenset[str]] = frozenset({"cmake", "cmake3"})
_MAKE_TOOL_NAMES: Final[frozenset[str]] = frozenset({"make", "gmake"})
_SHELL_TOOL_PATHS: Final[frozenset[str]] = frozenset({"sh", "/bin/sh", "/usr/bin/sh"})
_FORBIDDEN_CMAKE_CONFIGURE_FLAGS: Final[frozenset[str]] = frozenset(
    {"-P", "-E", "--build", "--install", "--open"}
)
_FORBIDDEN_MAKE_CLI_VARS: Final[frozenset[str]] = frozenset(
    {
        "CC",
        "CXX",
        "CPP",
        "LD",
        "AS",
        "AR",
        "HOSTCC",
        "HOSTCXX",
        "BUILD_CC",
        "BUILD_CXX",
        "SHELL",
        "MAKESHELL",
        "MAKE",
        "MAKEFLAGS",
        "GNUMAKEFLAGS",
        "MAKEOVERRIDES",
        "MAKEFILES",
        "MFLAGS",
        "BASH_ENV",
        "ENV",
        "PATH",
        "LD_PRELOAD",
        "LD_LIBRARY_PATH",
        "TMPDIR",
        "HOME",
        "ASAN_OPTIONS",
        # Install-directory assignments are rejected by key on both sides;
        # the CLI additionally rejects the autoconf directory family, so
        # CLI >= env for this family. (#64 #3, SF-2)
        "DESTDIR",
        "prefix",
        "PREFIX",
        "exec_prefix",
        "bindir",
        "sbindir",
        "libdir",
        "includedir",
        "datadir",
        "sysconfdir",
        "INSTALL_ROOT",
    }
)
_MAKE_LONG_ARG_OPTS: Final[frozenset[str]] = frozenset(
    {
        "--directory",
        "--file",
        "--makefile",
        "--include-dir",
        "--old-file",
        "--assume-old",
        "--what-if",
        "--new-file",
        "--assume-new",
    }
)
_MAKE_PATH_LONG_OPTS: Final[dict[str, str]] = {
    "--directory": "make directory",
    "--file": "makefile",
    "--makefile": "makefile",
    "--include-dir": "make include directory",
    "--old-file": "make old-file",
    "--assume-old": "make old-file",
    "--what-if": "make what-if file",
    "--new-file": "make new-file",
    "--assume-new": "make new-file",
}
_CMAKE_OUTPUT_PATH_VARS: Final[frozenset[str]] = frozenset(
    {
        "CMAKE_INSTALL_PREFIX",
        "CMAKE_RUNTIME_OUTPUT_DIRECTORY",
        "CMAKE_ARCHIVE_OUTPUT_DIRECTORY",
        "CMAKE_LIBRARY_OUTPUT_DIRECTORY",
    }
)
_CMAKE_OUTPUT_DIR_PREFIXES: Final[tuple[str, ...]] = (
    "CMAKE_RUNTIME_OUTPUT_DIRECTORY_",
    "CMAKE_ARCHIVE_OUTPUT_DIRECTORY_",
    "CMAKE_LIBRARY_OUTPUT_DIRECTORY_",
)
_BUILD_ENV_PATH_VARS: Final[frozenset[str]] = frozenset(
    # Install-directory assignments are rejected on the env side too:
    # DESTDIR plus prefix/PREFIX (values must stay inside /work). The CLI
    # side rejects the same keys by name and additionally the autoconf
    # directory family, so CLI >= env for install-directory assignments.
    # The lookup compares upper-cased keys, so "PREFIX" is the effective
    # match; "prefix" documents the family.
    {"DESTDIR", "prefix", "PREFIX"} | set(_CMAKE_OUTPUT_PATH_VARS)
)


def _is_cmake_output_path_var(name: str) -> bool:
    """Return True for CMake install/output directory variables, including per-config forms."""
    return name in _CMAKE_OUTPUT_PATH_VARS or any(
        name.startswith(prefix) and len(name) > len(prefix)
        for prefix in _CMAKE_OUTPUT_DIR_PREFIXES
    )
_MAKE_VAR_ASSIGN_RE: Final[re.Pattern[str]] = re.compile(
    r"^\s*(?:(?:export|override)\s+)*([A-Za-z_][A-Za-z0-9_]*)\s*(?::::=|::=|:=|\?=|\+=|!=|=)"
)


def has_control_chars(value: str) -> bool:
    """Return True if ``value`` contains ASCII control characters (including NUL)."""
    return _CONTROL_RE.search(value) is not None


def has_shell_metachars(value: str) -> bool:
    """Return True if ``value`` contains shell metacharacters or whitespace."""
    return _SHELL_META_RE.search(value) is not None


class ProvenanceParseError(ValueError):
    """Raised when a provenance face cannot be parsed fail-closed."""


@dataclass(frozen=True)
class ParsedProvenanceFace:
    """Structured compile-unit provenance parsed from a CMake or Make face."""

    kind: str
    face_name: str
    units: dict[str, list[str]]
    effective_flags: list[str]
    raw_digest: str
    rules_version: str = RULES_VERSION


@dataclass(frozen=True)
class BuildProvenanceResult:
    """Two-version comparability decision produced by ``verify_build_provenance``."""

    comparable: bool
    reason_code: str | None
    error_detail: str
    normalized_declared: list[str]
    vulnerable_units: dict[str, list[str]]
    fixed_units: dict[str, list[str]]
    report_summary: dict[str, Any]
    rules_version: str = RULES_VERSION

    def diagnostic_summary(self) -> dict[str, Any]:
        """Return full diagnostic details separate from the closed §8 ``report_summary``."""
        return {
            "rules_version": self.rules_version,
            "comparable": self.comparable,
            "reason_code": self.reason_code,
            "error_detail": self.error_detail,
            "vulnerable_units": {
                unit: list(flags) for unit, flags in self.vulnerable_units.items()
            },
            "fixed_units": {
                unit: list(flags) for unit, flags in self.fixed_units.items()
            },
            "report_summary": deepcopy(self.report_summary),
        }


@dataclass(frozen=True)
class BuildSpecFreezeDecision:
    """Plan-freeze validation decision for a ``BuildSpec``."""

    ok: bool
    reason_code: str | None
    error_detail: str = ""
    rules_version: str = RULES_VERSION


@dataclass(frozen=True)
class ShellFaceVerificationResult:
    """Build-stage verification decision for a legacy ``shell`` face log."""

    comparable: bool
    reason_code: str | None
    error_detail: str = ""
    expected_digest: str | None = None
    actual_digest: str | None = None
    rules_version: str = RULES_VERSION


@dataclass(frozen=True)
class ArchiveFaceEntry:
    """Manifest metadata for an archived ``build_provenance`` face artifact.

    ``sha256`` is a bare 64-character lowercase hex digest matching
    ``manifest.files[].sha256`` in ``interface-contract-delta.md`` §8.
    """

    path: str
    role: str
    size_bytes: int
    sha256: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "role": self.role,
            "size_bytes": self.size_bytes,
            "sha256": self.sha256,
        }


def _normalize_posix_dir(path: str | Path, *, label: str) -> str:
    if not isinstance(path, (str, Path)):
        raise ValueError(f"{label} must be a path string or Path")
    text = str(path).replace("\\", "/").strip()
    if not text:
        raise ValueError(f"{label} must not be empty")
    normalized = posixpath.normpath(text)
    if normalized.startswith("//"):
        normalized = "/" + normalized.lstrip("/")
    return normalized


def _normalize_path_arg(
    raw_path: str,
    *,
    repo_root: str,
    cwd: str | None,
) -> str:
    text = raw_path.replace("\\", "/")
    if not text:
        return text
    if posixpath.isabs(text):
        full = posixpath.normpath(text)
    else:
        base = cwd if cwd is not None else repo_root
        full = posixpath.normpath(posixpath.join(base, text))
    if full.startswith("//"):
        full = "/" + full.lstrip("/")
    if full == repo_root:
        return "."
    prefix = "/" if repo_root == "/" else repo_root + "/"
    if full.startswith(prefix):
        rel = full[len(prefix) :]
        return rel if rel else "."
    return full


def _has_wrapping_quotes(text: str) -> bool:
    """Return True iff matching outer quotes wrap the entire argument."""
    if len(text) < 2 or text[0] != text[-1] or text[0] not in ('"', "'"):
        return False
    quote = text[0]
    if quote == "'":
        return "'" not in text[1:-1]
    escaped = False
    for ch in text[1:-1]:
        if escaped:
            escaped = False
            continue
        if ch == "\\":
            escaped = True
            continue
        if ch == '"':
            return False
    return not escaped


def _clean_token(raw: str) -> str:
    if not isinstance(raw, str):
        raise ValueError(f"compile flag token must be str, got {type(raw).__name__}")
    text = raw.strip()
    if _has_wrapping_quotes(text):
        text = text[1:-1]
    return _WS_RE.sub(" ", text).strip()


def normalize_compile_flags(
    flags: Sequence[str],
    *,
    repo_root: str | Path,
    cwd: str | Path | None = None,
) -> list[str]:
    """Normalize compile flags identically for declared and effective sides.

    Rules (interface-contract-delta.md §5):
    - Preserve original order (no global sort, no ``-D`` macro reordering).
    - Strip matching outer quotes wrapping an entire argument; collapse
      consecutive internal whitespace to a single space.
    - Apply connected/split equivalence ONLY to the closed 7-item set:
      ``-I``, ``-L``, ``-l``, ``-D``, ``-U`` -> single connected token;
      ``-isystem``, ``-include`` -> canonical 2-token split form.
    - Normalize path arguments for ``-I``, ``-L``, ``-isystem``, ``-include``
      (and standalone absolute repo paths) via ``cwd`` then relative to
      ``repo_root`` (``"."`` when equal to ``repo_root``; normalized absolute
      POSIX path when outside ``repo_root``).
    - Deduplicate ``-I`` keeping only the first occurrence; never deduplicate
      or reorder ``-L``, ``-l``, ``-isystem``, or ``-include``.
    """
    if isinstance(flags, (str, bytes)) or not isinstance(flags, Sequence):
        raise ValueError("flags must be a sequence of strings")

    norm_root = _normalize_posix_dir(repo_root, label="repo_root")
    norm_cwd: str | None = None
    if cwd is not None:
        raw_cwd = _normalize_posix_dir(cwd, label="cwd")
        if not posixpath.isabs(raw_cwd):
            norm_cwd = posixpath.normpath(posixpath.join(norm_root, raw_cwd))
        else:
            norm_cwd = raw_cwd

    tokens = [cleaned for item in flags if (cleaned := _clean_token(item))]
    result: list[str] = []
    seen_includes: set[str] = set()

    def _append_short_opt(opt: str, arg: str) -> None:
        if opt in _PATH_OPTS:
            arg = _normalize_path_arg(arg, repo_root=norm_root, cwd=norm_cwd)
        canonical = f"{opt}{arg}"
        if opt == "-I":
            if canonical in seen_includes:
                return
            seen_includes.add(canonical)
        result.append(canonical)

    i = 0
    total = len(tokens)
    while i < total:
        tok = tokens[i]

        # Long options in the closed 7-item set: split form ["-isystem", "<dir>"].
        if tok in _LONG_OPTS:
            if i + 1 < total:
                arg = _normalize_path_arg(
                    tokens[i + 1], repo_root=norm_root, cwd=norm_cwd
                )
                result.extend((tok, arg))
                i += 2
            else:
                result.append(tok)
                i += 1
            continue

        matched_long = False
        for opt in ("-isystem", "-include"):
            if tok.startswith(opt) and len(tok) > len(opt):
                # Never split distinct hyphenated flags like -include-pch,
                # -include-pth, or -isystem-after into ["-include", "-pth"].
                if tok.startswith(f"{opt}-"):
                    break
                arg = tok[len(opt) :].strip()
                if arg:
                    norm_arg = _normalize_path_arg(
                        arg, repo_root=norm_root, cwd=norm_cwd
                    )
                    result.extend((opt, norm_arg))
                    i += 1
                    matched_long = True
                break
        if matched_long:
            continue

        # Short options in the closed 7-item set: single connected token.
        if tok in _SHORT_OPTS:
            if i + 1 < total:
                _append_short_opt(tok, tokens[i + 1])
                i += 2
            else:
                result.append(tok)
                i += 1
            continue

        if len(tok) > 2 and tok[:2] in _SHORT_OPTS:
            opt = tok[:2]
            arg = tok[2:].strip()
            if arg:
                _append_short_opt(opt, arg)
                i += 1
                continue

        # Outside the closed 7-item set: preserve adjacent tokens as separate items.
        if tok.startswith("/"):
            tok = _normalize_path_arg(tok, repo_root=norm_root, cwd=norm_cwd)
        result.append(tok)
        i += 1

    return result


def _decode_raw_face(raw_face: bytes | str) -> tuple[bytes, str]:
    if isinstance(raw_face, bytes):
        raw_bytes = raw_face
        try:
            text = raw_face.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ProvenanceParseError(f"provenance face is not valid UTF-8: {exc}") from exc
    elif isinstance(raw_face, str):
        text = raw_face
        raw_bytes = raw_face.encode("utf-8")
    else:
        raise ProvenanceParseError(
            f"raw_face must be bytes or str, got {type(raw_face).__name__}"
        )
    if not raw_bytes or not text.strip():
        raise ProvenanceParseError("provenance face is empty")
    return raw_bytes, text


def _is_source_path(path: str) -> bool:
    return PurePosixPath(path).suffix in _SOURCE_SUFFIXES


def _is_in_repo_source_path(source_path: str) -> bool:
    """Return True iff ``source_path`` is a C/C++ source file inside ``repo_root``."""
    if not source_path or source_path == ".":
        return False
    if posixpath.isabs(source_path):
        return False
    if source_path == ".." or source_path.startswith("../"):
        return False
    return _is_source_path(source_path)


def _strip_compile_argv(
    argv: Sequence[str],
    *,
    repo_root: str,
    cwd: str,
    explicit_source: str | None = None,
) -> tuple[bool, bool, list[str], list[str]]:
    """Extract (is_compile, is_preprocess_only, source_paths, raw_compile_flags).

    Strips compiler argv[0], ``-c``, ``-E``/``-M``/``-MM``, ``-o <obj>`` /
    ``-o<obj>``, and source file path(s) while leaving all compile flags (and
    arguments of options in the closed 7-item set) intact.
    """
    if not argv:
        return False, False, [], []
    first_cleaned = _clean_token(argv[0])
    raw_args = list(argv[1:]) if not first_cleaned.startswith("-") else list(argv)
    args = [tok for tok in raw_args if _clean_token(tok)]

    has_compile_flag = False
    is_preprocess_only = False
    raw_flags: list[str] = []
    discovered_sources: list[str] = []

    j = 0
    total = len(args)
    while j < total:
        tok = args[j]
        cleaned = _clean_token(tok)
        if cleaned == "-c":
            has_compile_flag = True
            j += 1
            continue
        if cleaned in ("-E", "-M", "-MM"):
            is_preprocess_only = True
            j += 1
            continue
        if cleaned == "-o":
            j += 2
            continue
        if cleaned.startswith("-o") and len(cleaned) > 2:
            j += 1
            continue
        if cleaned in _SEVEN_OPTS:
            raw_flags.append(tok)
            if j + 1 < total:
                raw_flags.append(args[j + 1])
                j += 2
            else:
                j += 1
            continue
        if cleaned and not cleaned.startswith("-"):
            norm_candidate = _normalize_path_arg(
                cleaned, repo_root=repo_root, cwd=cwd
            )
            if explicit_source is not None and norm_candidate == explicit_source:
                discovered_sources.append(norm_candidate)
                j += 1
                continue
            if _is_source_path(norm_candidate):
                discovered_sources.append(norm_candidate)
                j += 1
                continue
        raw_flags.append(tok)
        j += 1

    return has_compile_flag, is_preprocess_only, discovered_sources, raw_flags


def _record_unit(
    units: dict[str, list[str]],
    source_path: str,
    normalized_flags: list[str],
) -> None:
    existing = units.get(source_path)
    if existing is not None and existing != normalized_flags:
        raise ProvenanceParseError(
            f"conflicting effective flags for duplicate compile unit {source_path!r}: "
            f"{existing!r} vs {normalized_flags!r}"
        )
    units[source_path] = normalized_flags


def _flag_items(flags: Sequence[str]) -> list[tuple[str, ...]]:
    """Group normalized tokens into atomic logical flag items.

    Two-token long options in the closed 7-item set (``-isystem <dir>`` and
    ``-include <file>``) are paired into a 2-tuple so multiset counting,
    effective-flag summarization, and diff classification never split or
    cross-match an option and its argument.
    """
    items: list[tuple[str, ...]] = []
    i = 0
    total = len(flags)
    while i < total:
        tok = flags[i]
        if tok in _LONG_OPTS and i + 1 < total:
            items.append((tok, flags[i + 1]))
            i += 2
        else:
            items.append((tok,))
            i += 1
    return items


def _summarize_effective_flags(units: Mapping[str, list[str]]) -> list[str]:
    """Build a deterministic flat effective-flag summary preserving per-unit order."""
    summary: list[str] = []
    summary_counts: Counter[tuple[str, ...]] = Counter()
    for unit_flags in units.values():
        seen_in_unit: Counter[tuple[str, ...]] = Counter()
        for item in _flag_items(unit_flags):
            seen_in_unit[item] += 1
            if seen_in_unit[item] > summary_counts[item]:
                summary.extend(item)
                summary_counts[item] += 1
    return summary


def _parse_cmake_face(
    raw_bytes: bytes,
    text: str,
    *,
    repo_root: str,
) -> ParsedProvenanceFace:
    try:
        document = jsonutil.loads_strict(text)
    except jsonutil.StrictJsonError as exc:
        raise ProvenanceParseError(
            f"malformed cmake compile_commands.json: {exc}"
        ) from exc

    if not isinstance(document, list):
        raise ProvenanceParseError(
            "cmake compile_commands.json root must be a JSON array"
        )

    units: dict[str, list[str]] = {}
    for index, entry in enumerate(document):
        if not isinstance(entry, dict):
            raise ProvenanceParseError(
                f"cmake compile_commands.json[{index}] must be a JSON object"
            )
        directory = entry.get("directory")
        file_field = entry.get("file")
        if not isinstance(directory, str) or not directory.strip():
            raise ProvenanceParseError(
                f"cmake compile_commands.json[{index}].directory must be a non-empty string"
            )
        if not isinstance(file_field, str) or not file_field.strip():
            raise ProvenanceParseError(
                f"cmake compile_commands.json[{index}].file must be a non-empty string"
            )

        argv: list[str]
        if "arguments" in entry and entry["arguments"] is not None:
            raw_args = entry["arguments"]
            if (
                not isinstance(raw_args, list)
                or not raw_args
                or not all(isinstance(arg, str) for arg in raw_args)
            ):
                raise ProvenanceParseError(
                    f"cmake compile_commands.json[{index}].arguments must be a non-empty list of strings"
                )
            argv = list(raw_args)
        elif "command" in entry and entry["command"] is not None:
            command_text = entry["command"]
            if not isinstance(command_text, str) or not command_text.strip():
                raise ProvenanceParseError(
                    f"cmake compile_commands.json[{index}].command must be a non-empty string"
                )
            try:
                argv = shlex.split(command_text, posix=True)
            except ValueError as exc:
                raise ProvenanceParseError(
                    f"cmake compile_commands.json[{index}].command shell split failed: {exc}"
                ) from exc
            if not argv:
                raise ProvenanceParseError(
                    f"cmake compile_commands.json[{index}].command produced empty argv"
                )
        else:
            raise ProvenanceParseError(
                f"cmake compile_commands.json[{index}] must define 'command' or 'arguments'"
            )

        norm_dir = _normalize_posix_dir(directory, label="directory")
        if not posixpath.isabs(norm_dir):
            norm_dir = posixpath.normpath(posixpath.join(repo_root, norm_dir))

        source_path = _normalize_path_arg(
            file_field.strip(), repo_root=repo_root, cwd=norm_dir
        )
        is_compile, is_preprocess_only, _sources, raw_flags = _strip_compile_argv(
            argv,
            repo_root=repo_root,
            cwd=norm_dir,
            explicit_source=source_path,
        )
        if (
            not is_compile
            or is_preprocess_only
            or not _is_in_repo_source_path(source_path)
        ):
            continue

        normalized = normalize_compile_flags(
            raw_flags, repo_root=repo_root, cwd=norm_dir
        )
        _record_unit(units, source_path, normalized)

    if not units:
        raise ProvenanceParseError(
            "cmake compile_commands.json contains no C/C++ compile units"
        )

    sorted_units = dict(sorted(units.items()))
    return ParsedProvenanceFace(
        kind="cmake",
        face_name=FACE_FILENAMES["cmake"],
        units=sorted_units,
        effective_flags=_summarize_effective_flags(sorted_units),
        raw_digest=jsonutil.digest_bytes(raw_bytes),
    )


def _parse_make_face(
    raw_bytes: bytes,
    text: str,
    *,
    repo_root: str,
) -> ParsedProvenanceFace:
    units: dict[str, list[str]] = {}
    for line_no, raw_line in enumerate(text.splitlines(), start=1):
        line = raw_line.strip()
        if not line:
            continue
        try:
            record = jsonutil.loads_strict(line)
        except jsonutil.StrictJsonError as exc:
            raise ProvenanceParseError(
                f"malformed make cc-shim.log line {line_no}: {exc}"
            ) from exc

        if not isinstance(record, dict):
            raise ProvenanceParseError(
                f"make cc-shim.log line {line_no} must be a JSON object"
            )
        cwd_val = record.get("cwd")
        compiler_val = record.get("compiler")
        argv_val = record.get("argv")

        if not isinstance(cwd_val, str) or not cwd_val.strip():
            raise ProvenanceParseError(
                f"make cc-shim.log line {line_no} requires non-empty string 'cwd'"
            )
        if not isinstance(compiler_val, str) or not compiler_val.strip():
            raise ProvenanceParseError(
                f"make cc-shim.log line {line_no} requires non-empty string 'compiler'"
            )
        if (
            not isinstance(argv_val, list)
            or not argv_val
            or not all(isinstance(arg, str) for arg in argv_val)
        ):
            raise ProvenanceParseError(
                f"make cc-shim.log line {line_no} requires non-empty list[str] 'argv'"
            )

        norm_cwd = _normalize_posix_dir(cwd_val, label="cwd")
        if not posixpath.isabs(norm_cwd):
            norm_cwd = posixpath.normpath(posixpath.join(repo_root, norm_cwd))

        _is_compile, is_preprocess_only, source_paths, raw_flags = _strip_compile_argv(
            argv_val,
            repo_root=repo_root,
            cwd=norm_cwd,
        )
        repo_sources = [p for p in source_paths if _is_in_repo_source_path(p)]
        if is_preprocess_only or not repo_sources:
            continue

        normalized = normalize_compile_flags(
            raw_flags, repo_root=repo_root, cwd=norm_cwd
        )
        for source_path in repo_sources:
            _record_unit(units, source_path, list(normalized))

    if not units:
        raise ProvenanceParseError(
            "make cc-shim.log contains no C/C++ compile units"
        )

    sorted_units = dict(sorted(units.items()))
    return ParsedProvenanceFace(
        kind="make",
        face_name=FACE_FILENAMES["make"],
        units=sorted_units,
        effective_flags=_summarize_effective_flags(sorted_units),
        raw_digest=jsonutil.digest_bytes(raw_bytes),
    )


def parse_provenance_face(
    *,
    kind: str,
    raw_face: bytes | str,
    repo_root: str | Path,
) -> ParsedProvenanceFace:
    """Parse a structured CMake or Make provenance face into sorted compile units."""
    if kind not in ("cmake", "make"):
        raise ProvenanceParseError(
            f"unsupported provenance face kind for compile-unit parsing: {kind!r}"
        )
    try:
        norm_root = _normalize_posix_dir(repo_root, label="repo_root")
    except ValueError as exc:
        raise ProvenanceParseError(str(exc)) from exc

    raw_bytes, text = _decode_raw_face(raw_face)
    if kind == "cmake":
        return _parse_cmake_face(raw_bytes, text, repo_root=norm_root)
    return _parse_make_face(raw_bytes, text, repo_root=norm_root)


def _build_report_summary(
    *,
    face_name: str,
    comparable: bool,
    normalized_declared: list[str],
    vuln_units: Mapping[str, list[str]],
    fixed_units: Mapping[str, list[str]],
) -> dict[str, Any]:
    """Build the closed §8 ``report.build_provenance`` payload."""
    return {
        "vulnerable": {
            "face": face_name,
            "declared": list(normalized_declared),
            "effective": _summarize_effective_flags(vuln_units),
        },
        "fixed": {
            "face": face_name,
            "declared": list(normalized_declared),
            "effective": _summarize_effective_flags(fixed_units),
        },
        "comparable": comparable,
    }


def verify_build_provenance(
    *,
    kind: str,
    declared_compile_flags: Sequence[str],
    vulnerable_face: bytes | str,
    fixed_face: bytes | str,
    repo_root: str | Path,
    patch_explained_units: Iterable[str] = (),
) -> BuildProvenanceResult:
    """Verify declared ⊆ effective (multiset) and two-version ordered CU equality."""
    face_name = FACE_FILENAMES.get(kind, str(kind))
    if kind not in ("cmake", "make"):
        detail = (
            f"unsupported provenance face kind {kind!r} "
            "(expected 'cmake' or 'make')"
        )
        return BuildProvenanceResult(
            comparable=False,
            reason_code=BUILD_PROVENANCE_MISSING,
            error_detail=detail,
            normalized_declared=[],
            vulnerable_units={},
            fixed_units={},
            report_summary=_build_report_summary(
                face_name=face_name,
                comparable=False,
                normalized_declared=[],
                vuln_units={},
                fixed_units={},
            ),
        )

    try:
        norm_root = _normalize_posix_dir(repo_root, label="repo_root")
        normalized_declared = normalize_compile_flags(
            declared_compile_flags, repo_root=norm_root
        )
    except ValueError as exc:
        detail = f"invalid declared_compile_flags or repo_root ({kind}/{face_name}): {exc}"
        return BuildProvenanceResult(
            comparable=False,
            reason_code=BUILD_PROVENANCE_MISSING,
            error_detail=detail,
            normalized_declared=[],
            vulnerable_units={},
            fixed_units={},
            report_summary=_build_report_summary(
                face_name=face_name,
                comparable=False,
                normalized_declared=[],
                vuln_units={},
                fixed_units={},
            ),
        )

    parse_errors: list[str] = []
    vuln_parsed: ParsedProvenanceFace | None = None
    fixed_parsed: ParsedProvenanceFace | None = None

    try:
        vuln_parsed = parse_provenance_face(
            kind=kind, raw_face=vulnerable_face, repo_root=norm_root
        )
    except ProvenanceParseError as exc:
        parse_errors.append(f"vulnerable ({kind}/{face_name}): {exc}")

    try:
        fixed_parsed = parse_provenance_face(
            kind=kind, raw_face=fixed_face, repo_root=norm_root
        )
    except ProvenanceParseError as exc:
        parse_errors.append(f"fixed ({kind}/{face_name}): {exc}")

    vuln_units = vuln_parsed.units if vuln_parsed is not None else {}
    fixed_units = fixed_parsed.units if fixed_parsed is not None else {}

    if parse_errors:
        detail = "; ".join(parse_errors)
        return BuildProvenanceResult(
            comparable=False,
            reason_code=BUILD_PROVENANCE_MISSING,
            error_detail=detail,
            normalized_declared=normalized_declared,
            vulnerable_units=vuln_units,
            fixed_units=fixed_units,
            report_summary=_build_report_summary(
                face_name=face_name,
                comparable=False,
                normalized_declared=normalized_declared,
                vuln_units=vuln_units,
                fixed_units=fixed_units,
            ),
        )

    explained: set[str] = set()
    for raw_unit in patch_explained_units:
        if not isinstance(raw_unit, str) or not raw_unit.strip():
            continue
        explained.add(
            _normalize_path_arg(raw_unit.strip(), repo_root=norm_root, cwd=None)
        )

    issues: list[str] = []

    # 1. Check declared ⊆ effective as one flat multiset per version.
    # §8 defines the effective set as the ordered aggregate across compile
    # units (``_summarize_effective_flags``), so a flag that appears in one CU
    # covers the declaration; per-CU enforcement would reject a valid two-CU
    # build that splits `-DFEATURE_A` / `-DFEATURE_B` across files.
    declared_items = _flag_items(normalized_declared)
    declared_counts = Counter(declared_items)
    ordered_unique_declared = list(dict.fromkeys(declared_items))
    for version_label, version_units in (
        ("vulnerable", vuln_units),
        ("fixed", fixed_units),
    ):
        effective_counts = Counter(
            _flag_items(_summarize_effective_flags(version_units))
        )
        missing_parts = [
            f"{' '.join(item)} (declared={declared_counts[item]}, "
            f"effective={effective_counts[item]})"
            for item in ordered_unique_declared
            if effective_counts[item] < declared_counts[item]
        ]
        if missing_parts:
            issues.append(
                f"{version_label} ({kind}/{face_name}) missing declared flag(s): "
                f"{', '.join(missing_parts)}"
            )

    # 2. Check missing units across versions unless explicitly patch-explained.
    vuln_keys = set(vuln_units)
    fixed_keys = set(fixed_units)
    unexplained_in_fixed = sorted((vuln_keys - fixed_keys) - explained)
    unexplained_in_vuln = sorted((fixed_keys - vuln_keys) - explained)

    if unexplained_in_fixed:
        issues.append(
            f"fixed ({kind}/{face_name}) missing unexplained compile unit(s) "
            f"present in vulnerable: {', '.join(unexplained_in_fixed)}"
        )
    if unexplained_in_vuln:
        issues.append(
            f"vulnerable ({kind}/{face_name}) missing unexplained compile unit(s) "
            f"present in fixed: {', '.join(unexplained_in_vuln)}"
        )

    # 3. Check strict ordered equality on all common compilation units.
    common_units = sorted(vuln_keys & fixed_keys)
    if not common_units:
        issues.append(
            f"no common compile units between vulnerable and fixed ({kind}/{face_name})"
        )
    else:
        for unit_path in common_units:
            v_flags = vuln_units[unit_path]
            f_flags = fixed_units[unit_path]
            if v_flags != f_flags:
                if Counter(_flag_items(v_flags)) == Counter(_flag_items(f_flags)):
                    issues.append(
                        f"effective flag order difference on unit {unit_path} "
                        f"({kind}/{face_name}): vulnerable={v_flags!r} != fixed={f_flags!r}"
                    )
                else:
                    issues.append(
                        f"effective flags differ on unit {unit_path} "
                        f"({kind}/{face_name}): vulnerable={v_flags!r} != fixed={f_flags!r}"
                    )

    comparable = not issues
    reason_code = None if comparable else BUILD_PROVENANCE_MISSING
    error_detail = "" if comparable else "; ".join(issues)

    return BuildProvenanceResult(
        comparable=comparable,
        reason_code=reason_code,
        error_detail=error_detail,
        normalized_declared=normalized_declared,
        vulnerable_units=vuln_units,
        fixed_units=fixed_units,
        report_summary=_build_report_summary(
            face_name=face_name,
            comparable=comparable,
            normalized_declared=normalized_declared,
            vuln_units=vuln_units,
            fixed_units=fixed_units,
        ),
    )


def _freeze_fail(detail: str) -> BuildSpecFreezeDecision:
    return BuildSpecFreezeDecision(
        ok=False,
        reason_code=BUILD_PROVENANCE_MISSING,
        error_detail=detail,
    )


def _validate_str_list(
    value: Any,
    *,
    label: str,
    allow_empty: bool,
) -> str | None:
    if not isinstance(value, list):
        return f"{label} must be a list of strings"
    if not allow_empty and not value:
        return f"{label} must be a non-empty list of strings"
    for index, item in enumerate(value):
        if not isinstance(item, str) or not item.strip() or _CONTROL_RE.search(item):
            return f"{label}[{index}] must be a non-empty string without control characters"
    return None


def _is_cmake_false_value(value: str) -> bool:
    raw_val = value.strip()
    if _has_wrapping_quotes(raw_val):
        raw_val = raw_val[1:-1].strip()
    lowered = raw_val.lower()
    return lowered in _CMAKE_FALSE_VALUES or lowered.endswith("-notfound")


def _iter_cmake_var_operations(
    configure: Sequence[str],
) -> list[tuple[str, str, str | None]]:
    """Return ordered ``(operation, variable, value)`` for CMake -D/-U tokens."""
    operations: list[tuple[str, str, str | None]] = []
    index = 0
    total = len(configure)
    while index < total:
        tok = _clean_token(configure[index])
        operation: str | None = None
        expression: str | None = None
        if tok in ("-D", "-U") and index + 1 < total:
            operation = tok[1]
            expression = _clean_token(configure[index + 1])
            index += 2
        elif (
            len(tok) > 2
            and tok[:2] in ("-D", "-U")
        ):
            operation = tok[1]
            expression = _clean_token(tok[2:])
            index += 1
        else:
            index += 1
            continue
        if operation == "D":
            raw_name, separator, value = expression.partition("=")
            name = raw_name.split(":", 1)[0]
            operations.append(("D", name, value if separator else ""))
        else:
            operations.append(("U", expression, None))
    return operations


def cmake_export_compile_commands_state(
    configure: Sequence[str],
) -> tuple[str, str | None] | None:
    """Return the final ``(-D|-U, value)`` operation for the export variable.

    ``-D`` and ``-U`` are applied in configure order. ``-D<VAR>:<TYPE>=<VAL>``
    strips ``:<TYPE>`` before matching, and ``-U<PATTERN>`` applies CMake
    glob matching (``fnmatchcase``). ``None`` means the variable was never
    touched. A trailing ``-U`` (or a falsey final ``-D``) means
    compile_commands.json is disabled for the effective configuration.
    """
    state: tuple[str, str | None] | None = None
    for operation, name, value in _iter_cmake_var_operations(configure):
        if operation == "D" and name == "CMAKE_EXPORT_COMPILE_COMMANDS":
            state = ("D", value)
        elif operation == "U" and fnmatch.fnmatchcase(
            "CMAKE_EXPORT_COMPILE_COMMANDS", name
        ):
            state = ("U", None)
    return state


def iter_cmake_export_compile_commands_values(
    configure: Sequence[str],
) -> list[str]:
    """Return all ``CMAKE_EXPORT_COMPILE_COMMANDS`` values in ``configure`` (quote-aware)."""
    return [
        value
        for operation, name, value in _iter_cmake_var_operations(configure)
        if operation == "D"
        and name == "CMAKE_EXPORT_COMPILE_COMMANDS"
        and value is not None
    ]


def cmake_has_export_compile_commands(configure: Sequence[str]) -> bool:
    """Return True if ``configure`` leaves ``CMAKE_EXPORT_COMPILE_COMMANDS`` enabled."""
    state = cmake_export_compile_commands_state(configure)
    if state is None:
        return False
    operation, value = state
    return operation == "D" and value is not None and not _is_cmake_false_value(value)


def cmake_disables_compile_commands(configure: Sequence[str]) -> bool:
    """Return True if the final export setting disables compile_commands.json.

    The check simulates ``-D``/``-U`` in configure order: ``-D...=ON`` followed
    by ``-U...`` is disabled, while ``-U...`` followed by ``-D...=ON`` is
    enabled. Earlier writes must not mask a later unset.
    """
    state = cmake_export_compile_commands_state(configure)
    if state is None:
        return False
    operation, value = state
    if operation == "U":
        return True
    assert value is not None
    return _is_cmake_false_value(value)



def extract_cmake_build_dir(configure: Sequence[str]) -> tuple[str, str]:
    """Extract and validate CMake ``-B`` build directory inside ``/work``.

    Returns ``(relative_build_dir, compile_commands_container_path)`` or raises
    ``ValueError`` if ``-B`` is missing its argument or escapes ``/work``.
    """
    raw_dir = "."
    i = 0
    total = len(configure)
    while i < total:
        tok = configure[i]
        if tok == "-B":
            if i + 1 >= total or configure[i + 1].startswith("-"):
                raise ValueError("cmake -B requires a build directory argument")
            raw_dir = configure[i + 1]
            i += 2
            continue
        if tok.startswith("-B") and len(tok) > 2:
            raw_dir = tok[2:]
            i += 1
            continue
        i += 1

    if (
        not raw_dir
        or not raw_dir.strip()
        or "\\" in raw_dir
        or has_control_chars(raw_dir)
        or has_shell_metachars(raw_dir)
    ):
        raise ValueError(f"unsafe cmake build directory: {raw_dir!r}")

    if raw_dir.startswith("/"):
        if raw_dir.startswith("//") or ".." in PurePosixPath(raw_dir).parts:
            raise ValueError(
                f"cmake build directory must not traverse parents: {raw_dir!r}"
            )
        norm = posixpath.normpath(raw_dir)
        if norm == "/work":
            return ".", "/work/compile_commands.json"
        if norm.startswith("/work/"):
            rel_dir = norm[len("/work/") :]
            return rel_dir, f"{norm}/compile_commands.json"
        raise ValueError(f"cmake build directory escapes /work: {raw_dir!r}")

    norm = posixpath.normpath(raw_dir)
    if norm == ".":
        return ".", "/work/compile_commands.json"
    if (
        norm.startswith("/")
        or norm == ".."
        or norm.startswith("../")
        or ".." in PurePosixPath(norm).parts
    ):
        raise ValueError(f"cmake build directory escapes /work: {raw_dir!r}")
    return norm, f"/work/{norm}/compile_commands.json"


def validate_work_path_arg(value: Any, *, label: str) -> str:
    """Validate one build path argument and return its normalized form.

    Only paths inside the container's writable ``/work`` tmpfs (``/work`` or
    ``/work/...``) and safe repository-relative paths are accepted. Absolute
    host paths, ``//`` prefix paths and any ``..`` traversal are rejected, so
    ``cmake --build /etc``, ``make -C /etc`` or ``DESTDIR=/tmp/evil`` cannot
    redirect the build outside the reviewed tree.
    """
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{label} must be a non-empty path string")
    if has_control_chars(value) or "\\" in value:
        raise ValueError(f"{label} must not contain control characters or backslashes")
    if value.strip().startswith(('"', "'")):
        raise ValueError(f"{label} must not be wrapped or prefixed with quotes: {value!r}")
    for candidate in (value, value.replace('"', "").replace("'", "")):
        if not candidate.strip():
            raise ValueError(f"{label} must be a non-empty path string")
        if candidate.startswith("/"):
            if candidate.startswith("//"):
                raise ValueError(f"{label} must not be a //-prefixed path: {value!r}")
            norm = posixpath.normpath(candidate)
            if norm != "/work" and not norm.startswith("/work/"):
                raise ValueError(f"{label} must stay inside /work: {value!r}")
        else:
            norm = posixpath.normpath(candidate)
            if (
                norm.startswith("/")
                or norm == ".."
                or norm.startswith("../")
                or ".." in PurePosixPath(norm).parts
            ):
                raise ValueError(f"{label} escapes /work: {value!r}")
    return posixpath.normpath(value)


def validate_build_spec_output_path(raw_output: str, index: int) -> tuple[str, str]:
    """Validate one ``build_spec.outputs[index]`` path and return ``(rel, /work/rel)``."""
    rel = jsonutil.safe_relative_path(raw_output, f"build_spec.outputs[{index}]")
    if has_control_chars(raw_output) or has_shell_metachars(raw_output):
        raise ValueError(
            f"build_spec.outputs[{index}] must not contain shell metacharacters: {raw_output!r}"
        )
    norm_rel = posixpath.normpath(rel)
    if (
        norm_rel in ("", ".")
        or norm_rel.startswith("/")
        or norm_rel == ".."
        or norm_rel.startswith("../")
        or ".." in PurePosixPath(norm_rel).parts
        or has_control_chars(norm_rel)
        or has_shell_metachars(norm_rel)
    ):
        raise ValueError(f"unsafe build_spec.outputs[{index}]: {raw_output!r}")
    if PurePosixPath(norm_rel).parts[0] in (
        "metadata.json",
        "build.log",
        "build_provenance",
    ):
        raise ValueError(
            f"build_spec.outputs[{index}] conflicts with reserved D39 build "
            f"artifact path: {raw_output!r}"
        )
    return norm_rel, f"/work/{norm_rel}"


def is_controlled_shim_path(
    value: Any,
    *,
    allowed_basenames: Iterable[str] = CC_SHIM_BASENAMES,
) -> bool:
    """Return True iff ``value`` is a safe read-only rootfs path for a controlled shim."""
    if not isinstance(value, str) or not value.strip():
        return False
    if has_control_chars(value) or has_shell_metachars(value):
        return False
    if not value.startswith("/") or value.startswith("//") or value.endswith("/"):
        return False
    parts = PurePosixPath(value).parts
    if ".." in parts:
        return False
    norm = posixpath.normpath(value)
    if (
        not norm.startswith("/")
        or norm.startswith("//")
        or norm == "/"
        or posixpath.dirname(norm) == "/"
        or any(
            norm == prefix or norm.startswith(prefix + "/")
            for prefix in FORBIDDEN_SHIM_MOUNT_PREFIXES
        )
    ):
        return False
    return posixpath.basename(norm) in frozenset(allowed_basenames)


def validate_build_spec_env(env: Any) -> str | None:
    """Validate ``build_spec.env`` keys/values, rejecting sensitive & credential-like vars."""
    if not isinstance(env, Mapping):
        return "build_spec.env must be a JSON object"
    for key, val in env.items():
        if not isinstance(key, str) or not _ENV_KEY_RE.fullmatch(key):
            return (
                "build_spec.env keys must be valid POSIX identifiers "
                f"(got {key!r})"
            )
        upper_key = key.upper()
        if upper_key in FORBIDDEN_BUILD_ENV_KEYS:
            return (
                f"build_spec.env must not override sensitive environment variable {key!r}"
            )
        if upper_key.startswith(_CREDENTIAL_ENV_PREFIXES):
            return (
                f"build_spec.env must not set credential-like environment variable {key!r}"
            )
        if not isinstance(val, str) or has_control_chars(val):
            return f"build_spec.env[{key!r}] must be a string without control characters"
        if upper_key in _BUILD_ENV_PATH_VARS or _is_cmake_output_path_var(upper_key):
            try:
                validate_work_path_arg(val, label=f"build_spec.env[{key!r}]")
            except ValueError as error:
                return str(error)
    return None


def validate_effective_build_env(
    env: Mapping[str, Any],
    *,
    allowed_executor_keys: Iterable[str] = (),
) -> str | None:
    """Defense-in-depth check of the final container environment.

    Executor-owned keys (``TMPDIR``/``HOME``/``ASAN_OPTIONS`` and the fixed
    ``DATACON_BUILD_VERSION``) are allowed; everything else is held to the
    same closed rule as ``build_spec.env``. This catches a future code path
    that merges an author-controlled mapping without re-validating it.
    """
    allowed = {key.upper() for key in allowed_executor_keys}
    for key, val in env.items():
        if not isinstance(key, str) or not _ENV_KEY_RE.fullmatch(key):
            return f"effective build env key is invalid: {key!r}"
        upper_key = key.upper()
        if upper_key in FORBIDDEN_BUILD_ENV_KEYS and upper_key not in allowed:
            return (
                f"effective build env must not override sensitive environment "
                f"variable {key!r}"
            )
        if upper_key.startswith(_CREDENTIAL_ENV_PREFIXES) and upper_key not in allowed:
            return f"effective build env has a credential-like variable {key!r}"
        if not isinstance(val, str) or has_control_chars(val):
            return f"effective build env[{key!r}] must be a string without control chars"
        if upper_key in _BUILD_ENV_PATH_VARS or _is_cmake_output_path_var(upper_key):
            try:
                validate_work_path_arg(val, label=f"effective build env[{key!r}]")
            except ValueError as error:
                return str(error)
    return None


def _is_allowed_system_tool(token: str, *, allowed_names: frozenset[str]) -> bool:
    if not isinstance(token, str) or not token:
        return False
    if has_control_chars(token) or has_shell_metachars(token):
        return False
    if "/" not in token:
        return token in allowed_names
    if not token.startswith("/") or token.startswith("//") or token.endswith("/"):
        return False
    if ".." in PurePosixPath(token).parts:
        return False
    norm = posixpath.normpath(token)
    if norm != token:
        return False
    return (
        posixpath.dirname(norm) in _ALLOWED_TOOL_DIRS
        and posixpath.basename(norm) in allowed_names
    )


def _validate_make_cli_args(args: Sequence[str], *, label: str) -> str | None:
    """Reject Make eval/env overrides and any path option that escapes /work."""
    after_double_dash = False
    index = 0
    total = len(args)
    while index < total:
        tok = args[index]
        if not after_double_dash:
            if tok == "--":
                after_double_dash = True
                index += 1
                continue
            if tok.startswith("--"):
                if tok.startswith(("--ev", "--en")):
                    return (
                        f"{label} must not pass eval or environment-override flag {tok!r}"
                    )
                name, separator, inline_value = tok.partition("=")
                path_label = _MAKE_PATH_LONG_OPTS.get(name)
                if path_label is not None:
                    if separator:
                        raw_path = inline_value
                    else:
                        if index + 1 >= total:
                            return f"{label} {name} requires a path argument"
                        index += 1
                        raw_path = args[index]
                    try:
                        validate_work_path_arg(raw_path, label=f"{label} {name}")
                    except ValueError as error:
                        return str(error)
                index += 1
                continue
            if tok.startswith("-E"):
                return (
                    f"{label} must not pass eval (-E) or environment-override "
                    f"(-e) flag in {tok!r}"
                )
            if tok.startswith("-") and len(tok) > 1:
                position = 1
                while position < len(tok):
                    character = tok[position]
                    if character in ("E", "e"):
                        return (
                            f"{label} must not pass eval (-E) or environment-override "
                            f"(-e) flag in {tok!r}"
                        )
                    if character in ("C", "f", "I", "o", "W"):
                        rest = tok[position + 1 :]
                        if rest:
                            raw_path = rest
                        else:
                            if index + 1 >= total:
                                return (
                                    f"{label} -{character} requires a path argument"
                                )
                            index += 1
                            raw_path = args[index]
                        try:
                            validate_work_path_arg(
                                raw_path, label=f"{label} -{character}"
                            )
                        except ValueError as error:
                            return str(error)
                        break
                    if character in ("j", "l", "O"):
                        break
                    position += 1
                index += 1
                continue

        match = _MAKE_VAR_ASSIGN_RE.match(tok)
        if match is not None:
            var_name = match.group(1)
            if (
                var_name in _FORBIDDEN_MAKE_CLI_VARS
                or var_name.upper() in FORBIDDEN_BUILD_ENV_KEYS
            ):
                return (
                    f"{label}[{index}] must not override {var_name!r} on the command line"
                )
        index += 1
    return None

def _validate_shell_command(argv: Sequence[str], *, label: str) -> str | None:
    for index, tok in enumerate(argv):
        if has_control_chars(tok) or has_shell_metachars(tok):
            return (
                f"{label}[{index}] must not contain control or shell metacharacters: {tok!r}"
            )
    first = argv[0]
    if first in _SHELL_TOOL_PATHS:
        if len(argv) < 2:
            return f"{label} using {first!r} requires a relative script path"
        script = argv[1]
        if script.startswith(("-", "+")):
            return f"{label} must not pass shell flags such as {script!r} (no sh -c)"
        try:
            jsonutil.safe_relative_path(script, f"{label}[1]")
        except ValueError as exc:
            return str(exc)
        return None

    if "/" in first and not first.startswith(("/", "-", "+")):
        try:
            jsonutil.safe_relative_path(first, f"{label}[0]")
        except ValueError as exc:
            return str(exc)
        return None

    return (
        f"{label}[0] must invoke sh/bin/sh with a relative script or an audited "
        f"relative script path (got {first!r})"
    )


def _validate_cmake_command_paths(
    configure: Sequence[str],
    build: Sequence[str],
    install: Sequence[str],
) -> str | None:
    """Constrain every CMake directory/install/output path to /work."""
    index = 0
    total = len(configure)
    while index < total:
        tok = configure[index]
        value: str | None = None
        label = "configure"
        if tok in ("-S", "-B"):
            if index + 1 >= total:
                return f"build_spec.configure (cmake) {tok} requires a directory"
            value = configure[index + 1]
            label = f"configure {tok}"
            index += 2
        elif tok.startswith("-S") and len(tok) > 2:
            value = tok[2:]
            label = "configure -S"
            index += 1
        elif tok.startswith("-B") and len(tok) > 2:
            value = tok[2:]
            label = "configure -B"
            index += 1
        elif tok == "--install-prefix":
            if index + 1 >= total:
                return (
                    "build_spec.configure (cmake) --install-prefix requires a directory"
                )
            value = configure[index + 1]
            label = "configure --install-prefix"
            index += 2
        elif tok.startswith("--install-prefix="):
            value = tok.split("=", 1)[1]
            label = "configure --install-prefix"
            index += 1
        elif tok in ("-D", "-U") and index + 1 < total:
            expression = _clean_token(configure[index + 1])
            index += 2
            if tok == "-D":
                raw_name, _separator, raw_value = expression.partition("=")
                name = raw_name.split(":", 1)[0]
                if _is_cmake_output_path_var(name):
                    try:
                        validate_work_path_arg(
                            raw_value, label=f"configure -D{name}"
                        )
                    except ValueError as error:
                        return str(error)
            continue
        elif (tok.startswith("-D") or tok.startswith("-U")) and len(tok) > 2:
            expression = _clean_token(tok[2:])
            index += 1
            if tok.startswith("-D"):
                raw_name, _separator, raw_value = expression.partition("=")
                name = raw_name.split(":", 1)[0]
                if _is_cmake_output_path_var(name):
                    try:
                        validate_work_path_arg(
                            raw_value, label=f"configure -D{name}"
                        )
                    except ValueError as error:
                        return str(error)
            continue
        else:
            index += 1
            continue
        if value is not None:
            try:
                validate_work_path_arg(value, label=f"build_spec.{label}")
            except ValueError as error:
                return str(error)
    if len(build) >= 3:
        try:
            validate_work_path_arg(
                build[2], label="build_spec.build cmake --build directory"
            )
        except ValueError as error:
            return str(error)
        cursor = 3
        while cursor < len(build):
            if build[cursor] == "--":
                native_err = _validate_make_cli_args(
                    build[cursor + 1 :], label="build_spec.build"
                )
                if native_err is not None:
                    return native_err
                break
            if build[cursor] == "--target" and cursor + 1 < len(build):
                cursor += 2
                continue
            if build[cursor] == "--config" and cursor + 1 < len(build):
                cursor += 2
                continue
            cursor += 1
    if install:
        if len(install) >= 3:
            try:
                validate_work_path_arg(
                    install[2], label="build_spec.install cmake --install directory"
                )
            except ValueError as error:
                return str(error)
        cursor = 3
        while cursor < len(install):
            if install[cursor] == "--prefix":
                if cursor + 1 >= len(install):
                    return "build_spec.install cmake --prefix requires a directory"
                try:
                    validate_work_path_arg(
                        install[cursor + 1], label="build_spec.install --prefix"
                    )
                except ValueError as error:
                    return str(error)
                cursor += 2
                continue
            if install[cursor].startswith("--prefix="):
                try:
                    validate_work_path_arg(
                        install[cursor].split("=", 1)[1],
                        label="build_spec.install --prefix",
                    )
                except ValueError as error:
                    return str(error)
            cursor += 1
    return None


def validate_build_spec_commands(
    kind: str,
    *,
    configure: Sequence[str] | None = None,
    build: Sequence[str],
    install: Sequence[str] = (),
) -> str | None:
    """Enforce closed per-``kind`` command allowlists on ``configure``/``build``/``install``."""
    if kind == "cmake":
        if not configure or not _is_allowed_system_tool(
            configure[0], allowed_names=_CMAKE_TOOL_NAMES
        ):
            got = configure[0] if configure else None
            return (
                "build_spec.configure (cmake) must invoke a controlled cmake binary "
                f"(got {got!r})"
            )
        for tok in configure[1:]:
            if tok in _FORBIDDEN_CMAKE_CONFIGURE_FLAGS or tok.startswith("-P"):
                return (
                    f"build_spec.configure (cmake) must not use execution mode flag {tok!r}"
                )
        path_err = _validate_cmake_command_paths(configure, build, install)
        if path_err is not None:
            return path_err
        if not build or not _is_allowed_system_tool(
            build[0], allowed_names=_CMAKE_TOOL_NAMES
        ):
            got = build[0] if build else None
            return (
                "build_spec.build (cmake) must invoke a controlled cmake binary "
                f"(got {got!r})"
            )
        if len(build) < 3 or build[1] != "--build" or build[2].startswith("-"):
            return (
                "build_spec.build (cmake) must use 'cmake --build <dir> ...'"
            )
        if "--" in build[3:]:
            dash_idx = build.index("--", 3)
            native_err = _validate_make_cli_args(
                build[dash_idx + 1 :], label="build_spec.build"
            )
            if native_err is not None:
                return native_err
        if install:
            if not _is_allowed_system_tool(
                install[0], allowed_names=_CMAKE_TOOL_NAMES
            ):
                return (
                    "build_spec.install (cmake) must invoke a controlled cmake binary "
                    f"(got {install[0]!r})"
                )
            if len(install) < 3 or install[1] != "--install" or install[2].startswith("-"):
                return (
                    "build_spec.install (cmake) must use 'cmake --install <dir> ...'"
                )
        return None

    if kind == "make":
        if not build or not _is_allowed_system_tool(
            build[0], allowed_names=_MAKE_TOOL_NAMES
        ):
            got = build[0] if build else None
            return (
                "build_spec.build (make) must invoke make or gmake "
                f"(got {got!r})"
            )
        build_err = _validate_make_cli_args(build[1:], label="build_spec.build")
        if build_err is not None:
            return build_err
        if install:
            if not _is_allowed_system_tool(
                install[0], allowed_names=_MAKE_TOOL_NAMES
            ):
                return (
                    "build_spec.install (make) must invoke make or gmake "
                    f"(got {install[0]!r})"
                )
            install_err = _validate_make_cli_args(
                install[1:], label="build_spec.install"
            )
            if install_err is not None:
                return install_err
        return None

    if kind == "shell":
        build_err = _validate_shell_command(build, label="build_spec.build")
        if build_err is not None:
            return build_err
        if install:
            install_err = _validate_shell_command(install, label="build_spec.install")
            if install_err is not None:
                return install_err
        return None

    return f"unsupported build_spec.kind {kind!r}"


def validate_build_spec_for_freeze(
    build_spec: Mapping[str, Any],
) -> BuildSpecFreezeDecision:
    """Validate a ``BuildSpec`` at plan-freeze time (fail-closed)."""
    if not isinstance(build_spec, Mapping):
        return _freeze_fail("build_spec must be a JSON object")

    actual_keys = set(build_spec.keys())
    if "make_env" in actual_keys:
        return _freeze_fail(
            "build_spec field 'make_env' has been deleted; inject Make CC shim via env.CC"
        )

    kind = build_spec.get("kind")
    if not isinstance(kind, str) or kind not in _VALID_KINDS:
        return _freeze_fail(
            f"build_spec.kind must be one of {sorted(_VALID_KINDS)}, got {kind!r}"
        )

    allowed_keys = set(_COMMON_REQUIRED_SPEC_FIELDS) | {"install"} | set(_SHELL_ONLY_SPEC_FIELDS)
    required_keys = set(_COMMON_REQUIRED_SPEC_FIELDS)
    if kind == "cmake":
        allowed_keys.add("configure")
        required_keys.add("configure")
    elif kind == "shell":
        required_keys |= _SHELL_ONLY_SPEC_FIELDS

    unknown_keys = sorted(actual_keys - allowed_keys)
    if unknown_keys:
        return _freeze_fail(
            f"build_spec ({kind}) has unknown field(s): {', '.join(unknown_keys)}"
        )

    missing_keys = sorted(required_keys - actual_keys)
    if missing_keys:
        return _freeze_fail(
            f"build_spec ({kind}) is missing required field(s): {', '.join(missing_keys)}"
        )

    # Validate common fields.
    build_err = _validate_str_list(
        build_spec["build"], label="build_spec.build", allow_empty=False
    )
    if build_err is not None:
        return _freeze_fail(build_err)

    install_argv: list[str] = []
    if "install" in build_spec:
        install_err = _validate_str_list(
            build_spec["install"], label="build_spec.install", allow_empty=True
        )
        if install_err is not None:
            return _freeze_fail(install_err)
        install_argv = list(build_spec["install"])

    outputs = build_spec["outputs"]
    outputs_err = _validate_str_list(
        outputs, label="build_spec.outputs", allow_empty=False
    )
    if outputs_err is not None:
        return _freeze_fail(outputs_err)
    for index, out_path in enumerate(outputs):
        try:
            validate_build_spec_output_path(out_path, index)
        except ValueError as exc:
            return _freeze_fail(str(exc))

    flags_err = _validate_str_list(
        build_spec["declared_compile_flags"],
        label="build_spec.declared_compile_flags",
        allow_empty=True,
    )
    if flags_err is not None:
        return _freeze_fail(flags_err)

    env = build_spec["env"]
    env_err = validate_build_spec_env(env)
    if env_err is not None:
        return _freeze_fail(env_err)

    if kind != "shell":
        for shell_field in sorted(_SHELL_ONLY_SPEC_FIELDS):
            if build_spec.get(shell_field) is not None:
                return _freeze_fail(
                    f"build_spec ({kind}) must not set shell-only field {shell_field!r}"
                )

    configure_argv: list[str] | None = None
    if kind == "cmake":
        configure = build_spec["configure"]
        configure_err = _validate_str_list(
            configure, label="build_spec.configure", allow_empty=False
        )
        if configure_err is not None:
            return _freeze_fail(configure_err)
        configure_argv = list(configure)

    cmd_err = validate_build_spec_commands(
        kind,
        configure=configure_argv,
        build=build_spec["build"],
        install=install_argv,
    )
    if cmd_err is not None:
        return _freeze_fail(cmd_err)

    # Kind-specific provenance face validation.
    if kind == "cmake":
        assert configure_argv is not None
        try:
            extract_cmake_build_dir(configure_argv)
        except ValueError as exc:
            return _freeze_fail(str(exc))
        if cmake_disables_compile_commands(configure_argv):
            return _freeze_fail(
                "build_spec (cmake) explicitly disables CMAKE_EXPORT_COMPILE_COMMANDS"
            )
        if "CMAKE_EXPORT_COMPILE_COMMANDS" in env and _is_cmake_false_value(
            env["CMAKE_EXPORT_COMPILE_COMMANDS"]
        ):
            return _freeze_fail(
                "build_spec (cmake) explicitly disables CMAKE_EXPORT_COMPILE_COMMANDS via env"
            )

    elif kind == "make":
        cc_value = env.get("CC")
        if not is_controlled_shim_path(
            cc_value, allowed_basenames=CC_SHIM_BASENAMES
        ):
            return _freeze_fail(
                "build_spec (make) requires env.CC pointing to a controlled cc-shim "
                f"(got {cc_value!r})"
            )
        if "CXX" in env:
            cxx_value = env["CXX"]
            if not is_controlled_shim_path(
                cxx_value, allowed_basenames=CXX_SHIM_BASENAMES
            ):
                return _freeze_fail(
                    "build_spec (make) requires env.CXX (when set) pointing to a "
                    f"controlled cxx-shim (got {cxx_value!r})"
                )

    elif kind == "shell":
        recipe_digest = build_spec.get("shell_recipe_digest")
        if not jsonutil.is_digest(recipe_digest):
            return _freeze_fail(
                "build_spec (shell) requires a valid sha256 shell_recipe_digest"
            )
        face_digest = build_spec.get("shell_face_digest")
        if not jsonutil.is_digest(face_digest):
            return _freeze_fail(
                "build_spec (shell) requires a valid sha256 shell_face_digest "
                "(shell_recipe_digest cannot substitute for a reviewed face)"
            )
        review = build_spec.get("shell_face_review")
        if not isinstance(review, Mapping):
            return _freeze_fail(
                "build_spec (shell) requires a non-null shell_face_review object"
            )
        review_keys = set(review.keys())
        missing_review = sorted(_SHELL_REVIEW_FIELDS - review_keys)
        if missing_review:
            return _freeze_fail(
                "build_spec.shell_face_review is missing field(s): "
                f"{', '.join(missing_review)}"
            )
        unknown_review = sorted(review_keys - _SHELL_REVIEW_FIELDS)
        if unknown_review:
            return _freeze_fail(
                "build_spec.shell_face_review has unknown field(s): "
                f"{', '.join(unknown_review)}"
            )
        try:
            jsonutil.require_text(
                review["reviewer_id"], "build_spec.shell_face_review.reviewer_id"
            )
            jsonutil.require_rfc3339(
                review["reviewed_at"], "build_spec.shell_face_review.reviewed_at"
            )
            jsonutil.require_text(
                review["face_kind"], "build_spec.shell_face_review.face_kind"
            )
        except ValueError as exc:
            return _freeze_fail(str(exc))

    return BuildSpecFreezeDecision(ok=True, reason_code=None, error_detail="")


def shell_face_digest(raw_log: bytes | str, *, repo_root: str | Path) -> str:
    """Normalize line endings, repo_root prefixes, and timestamps, then SHA-256."""
    if isinstance(raw_log, bytes):
        try:
            text = raw_log.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ValueError(f"shell face log is not valid UTF-8: {exc}") from exc
    elif isinstance(raw_log, str):
        text = raw_log
    else:
        raise ValueError(
            f"raw_log must be bytes or str, got {type(raw_log).__name__}"
        )

    norm_root = _normalize_posix_dir(repo_root, label="repo_root")
    normalized = text.replace("\r\n", "\n").replace("\r", "\n")

    if norm_root != "/":
        root_pattern = re.compile(re.escape(norm_root) + r"(?=/|$|[^A-Za-z0-9._-])")
        normalized = root_pattern.sub("<REPO_ROOT>", normalized)

    normalized = _TIMESTAMP_RE.sub("<TIMESTAMP>", normalized)
    return jsonutil.digest_bytes(normalized.encode("utf-8"))


def verify_shell_face(
    *,
    build_spec: Mapping[str, Any],
    actual_log: bytes | str,
    repo_root: str | Path,
) -> ShellFaceVerificationResult:
    """Run freeze validation then verify normalized actual log against shell_face_digest."""
    freeze = validate_build_spec_for_freeze(build_spec)
    if not freeze.ok:
        return ShellFaceVerificationResult(
            comparable=False,
            reason_code=BUILD_PROVENANCE_MISSING,
            error_detail=(
                f"shell build_spec failed freeze validation (shell/shell-face.log): "
                f"{freeze.error_detail}"
            ),
        )
    if build_spec.get("kind") != "shell":
        return ShellFaceVerificationResult(
            comparable=False,
            reason_code=BUILD_PROVENANCE_MISSING,
            error_detail=(
                "verify_shell_face requires build_spec.kind == 'shell', "
                f"got {build_spec.get('kind')!r}"
            ),
        )

    expected_digest = str(build_spec["shell_face_digest"])
    if isinstance(actual_log, bytes):
        if not actual_log or not actual_log.strip():
            return ShellFaceVerificationResult(
                comparable=False,
                reason_code=BUILD_PROVENANCE_MISSING,
                error_detail="actual shell face log (shell/shell-face.log) is empty",
                expected_digest=expected_digest,
            )
    elif isinstance(actual_log, str):
        if not actual_log.strip():
            return ShellFaceVerificationResult(
                comparable=False,
                reason_code=BUILD_PROVENANCE_MISSING,
                error_detail="actual shell face log (shell/shell-face.log) is empty",
                expected_digest=expected_digest,
            )
    else:
        return ShellFaceVerificationResult(
            comparable=False,
            reason_code=BUILD_PROVENANCE_MISSING,
            error_detail=(
                "actual_log (shell/shell-face.log) must be bytes or str, "
                f"got {type(actual_log).__name__}"
            ),
            expected_digest=expected_digest,
        )

    try:
        actual_digest = shell_face_digest(actual_log, repo_root=repo_root)
    except ValueError as exc:
        return ShellFaceVerificationResult(
            comparable=False,
            reason_code=BUILD_PROVENANCE_MISSING,
            error_detail=f"failed to normalize shell face log (shell/shell-face.log): {exc}",
            expected_digest=expected_digest,
        )

    if actual_digest != expected_digest:
        return ShellFaceVerificationResult(
            comparable=False,
            reason_code=BUILD_PROVENANCE_MISSING,
            error_detail=(
                f"shell face digest mismatch (shell/shell-face.log): "
                f"expected {expected_digest}, got {actual_digest}"
            ),
            expected_digest=expected_digest,
            actual_digest=actual_digest,
        )

    return ShellFaceVerificationResult(
        comparable=True,
        reason_code=None,
        error_detail="",
        expected_digest=expected_digest,
        actual_digest=actual_digest,
    )


def archive_face_entry(
    *,
    kind: str,
    version: str,
    raw_face: bytes,
) -> ArchiveFaceEntry:
    """Return fixed D39 manifest entry metadata for a raw provenance face."""
    if not isinstance(kind, str) or kind not in _VALID_KINDS:
        raise ValueError(
            f"unsupported build provenance kind {kind!r} (expected one of {sorted(_VALID_KINDS)})"
        )
    if not isinstance(version, str) or version not in _VALID_VERSIONS:
        raise ValueError(
            f"unsupported build version {version!r} (expected 'vulnerable' or 'fixed')"
        )
    if not isinstance(raw_face, bytes) or not raw_face:
        raise ValueError("raw_face must be non-empty bytes")

    return ArchiveFaceEntry(
        path=f"build/{version}/build_provenance/{FACE_FILENAMES[kind]}",
        role=BUILD_PROVENANCE_ROLE,
        size_bytes=len(raw_face),
        sha256=hashlib.sha256(raw_face).hexdigest(),
    )

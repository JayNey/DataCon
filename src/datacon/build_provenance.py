"""Build provenance normalization, face parsing, freeze validation, and comparability checks.

Implements docs/spec/v0.2/interface-contract-delta.md §5 & §8 and ADR-005
under rule set ``build-provenance-v1``.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Iterable, Mapping, Sequence
from copy import deepcopy
from dataclasses import dataclass
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
_CMAKE_EXPORT_RE: Final[re.Pattern[str]] = re.compile(
    r"^CMAKE_EXPORT_COMPILE_COMMANDS(?::[A-Za-z0-9_]+)?=(.*)$",
    re.IGNORECASE,
)
_CMAKE_FALSE_VALUES: Final[frozenset[str]] = frozenset(
    {"", "0", "off", "false", "no", "n", "ignore", "notfound"}
)
_TIMESTAMP_RE: Final[re.Pattern[str]] = re.compile(
    r"\b[0-9]{4}-[0-9]{2}-[0-9]{2}[Tt ][0-9]{2}:[0-9]{2}:[0-9]{2}"
    r"(?:\.[0-9]{1,9})?(?:[Zz]|[+-][0-9]{2}:?[0-9]{2})?"
)


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

    tokens = [_clean_token(item) for item in flags]
    result: list[str] = []
    seen_includes: set[str] = set()

    i = 0
    total = len(tokens)
    while i < total:
        tok = tokens[i]
        if not tok:
            i += 1
            continue

        # Long options in the closed 7-item set: split form ["-isystem", "<dir>"].
        if tok in _LONG_OPTS:
            if i + 1 < total and tokens[i + 1]:
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
                if opt == "-include" and tok.startswith("-include-pch"):
                    break
                if opt == "-isystem" and tok.startswith("-isystem-after"):
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
            if i + 1 < total and tokens[i + 1]:
                arg = tokens[i + 1]
                if tok in _PATH_OPTS:
                    arg = _normalize_path_arg(arg, repo_root=norm_root, cwd=norm_cwd)
                canonical = f"{tok}{arg}"
                i += 2
                if tok == "-I":
                    if canonical in seen_includes:
                        continue
                    seen_includes.add(canonical)
                result.append(canonical)
            else:
                result.append(tok)
                i += 1
            continue

        if len(tok) > 2 and tok[:2] in _SHORT_OPTS:
            opt = tok[:2]
            arg = tok[2:].strip()
            if arg:
                if opt in _PATH_OPTS:
                    arg = _normalize_path_arg(arg, repo_root=norm_root, cwd=norm_cwd)
                canonical = f"{opt}{arg}"
                i += 1
                if opt == "-I":
                    if canonical in seen_includes:
                        continue
                    seen_includes.add(canonical)
                result.append(canonical)
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


def _strip_compile_argv(
    argv: Sequence[str],
    *,
    repo_root: str,
    cwd: str,
    explicit_source: str | None = None,
) -> tuple[bool, bool, list[str], list[str]]:
    """Extract (is_compile, is_preprocess_only, source_paths, raw_compile_flags).

    Strips compiler argv[0], ``-c``, ``-E``, ``-o <obj>`` / ``-o<obj>``, and
    source file path(s) while leaving all compile flags (and arguments of
    options in the closed 7-item set) intact.
    """
    if not argv:
        return False, False, [], []
    first_cleaned = _clean_token(argv[0])
    args = list(argv[1:]) if not first_cleaned.startswith("-") else list(argv)

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
        if cleaned == "-E":
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
        if not is_compile or is_preprocess_only or not _is_source_path(source_path):
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
        if is_preprocess_only or not source_paths:
            continue

        normalized = normalize_compile_flags(
            raw_flags, repo_root=repo_root, cwd=norm_cwd
        )
        for source_path in source_paths:
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

    # 1. Check declared ⊆ effective (multiset inclusion) for BOTH versions per CU.
    declared_items = _flag_items(normalized_declared)
    declared_counts = Counter(declared_items)
    ordered_unique_declared = list(dict.fromkeys(declared_items))
    for version_label, version_units in (
        ("vulnerable", vuln_units),
        ("fixed", fixed_units),
    ):
        for unit_path, unit_flags in version_units.items():
            effective_counts = Counter(_flag_items(unit_flags))
            missing_parts = [
                f"{' '.join(item)} (declared={declared_counts[item]}, effective={effective_counts[item]})"
                for item in ordered_unique_declared
                if effective_counts[item] < declared_counts[item]
            ]
            if missing_parts:
                issues.append(
                    f"{version_label} ({kind}/{face_name}) unit {unit_path} "
                    f"missing declared flag(s): {', '.join(missing_parts)}"
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


def _cmake_disables_compile_commands(configure: Sequence[str]) -> bool:
    i = 0
    total = len(configure)
    while i < total:
        tok = _clean_token(configure[i])
        define_expr: str | None = None
        if tok == "-D" and i + 1 < total:
            define_expr = _clean_token(configure[i + 1])
            i += 2
        elif tok.startswith("-D") and len(tok) > 2:
            define_expr = tok[2:].strip()
            i += 1
        else:
            i += 1
            continue

        match = _CMAKE_EXPORT_RE.fullmatch(define_expr)
        if match is not None and _is_cmake_false_value(match.group(1)):
            return True
    return False


def _is_controlled_cc_shim(cc_value: Any) -> bool:
    if not isinstance(cc_value, str) or not cc_value.strip():
        return False
    if _CONTROL_RE.search(cc_value) or _SHELL_META_RE.search(cc_value):
        return False
    if not cc_value.startswith("/"):
        return False
    parts = PurePosixPath(cc_value).parts
    if ".." in parts:
        return False
    return posixpath.basename(cc_value) == "cc-shim"


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

    if "install" in build_spec:
        install_err = _validate_str_list(
            build_spec["install"], label="build_spec.install", allow_empty=True
        )
        if install_err is not None:
            return _freeze_fail(install_err)

    outputs = build_spec["outputs"]
    outputs_err = _validate_str_list(
        outputs, label="build_spec.outputs", allow_empty=False
    )
    if outputs_err is not None:
        return _freeze_fail(outputs_err)
    for index, out_path in enumerate(outputs):
        try:
            jsonutil.safe_relative_path(out_path, f"build_spec.outputs[{index}]")
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
    if not isinstance(env, Mapping):
        return _freeze_fail("build_spec.env must be a JSON object")
    for key, val in env.items():
        if not isinstance(key, str) or not key.strip() or _CONTROL_RE.search(key):
            return _freeze_fail("build_spec.env keys must be non-empty strings")
        if not isinstance(val, str) or _CONTROL_RE.search(val):
            return _freeze_fail(f"build_spec.env[{key!r}] must be a string")

    # Kind-specific provenance face validation.
    if kind == "cmake":
        for shell_field in sorted(_SHELL_ONLY_SPEC_FIELDS):
            if build_spec.get(shell_field) is not None:
                return _freeze_fail(
                    f"build_spec (cmake) must not set shell-only field {shell_field!r}"
                )
        configure = build_spec["configure"]
        configure_err = _validate_str_list(
            configure, label="build_spec.configure", allow_empty=False
        )
        if configure_err is not None:
            return _freeze_fail(configure_err)
        if _cmake_disables_compile_commands(configure):
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
        for shell_field in sorted(_SHELL_ONLY_SPEC_FIELDS):
            if build_spec.get(shell_field) is not None:
                return _freeze_fail(
                    f"build_spec (make) must not set shell-only field {shell_field!r}"
                )
        cc_value = env.get("CC")
        if not _is_controlled_cc_shim(cc_value):
            return _freeze_fail(
                "build_spec (make) requires env.CC pointing to a controlled cc-shim "
                f"(got {cc_value!r})"
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

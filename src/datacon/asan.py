"""Parse AddressSanitizer output into a reviewable signature.

Raw sanitizer logs are untrusted data. Only the structured fields used by the
verdict rule are extracted, and the raw log is retained separately as evidence.
"""

from __future__ import annotations

from dataclasses import dataclass
import posixpath
import re
from typing import Any, Mapping

_ERROR = re.compile(r"ERROR:\s*AddressSanitizer:\s*([A-Za-z0-9_.-]+)")
_SUMMARY = re.compile(r"SUMMARY:\s*AddressSanitizer:\s*([A-Za-z0-9_.-]+)")
_ACCESS = re.compile(r"\b(READ|WRITE)\s+of\s+size\s+([0-9]+)\b")
_FRAME = re.compile(
    r"^\s*#(?P<index>[0-9]+)\s+0x[0-9a-fA-F]+\s+in\s+"
    r"(?P<function>[^\s]+)\s+(?P<source>[^\s:][^:]*):(?P<line>[0-9]+)",
    re.MULTILINE,
)
_HAS_DIAGNOSTIC = re.compile(r"(?:ERROR|SUMMARY):\s*AddressSanitizer:")
MAX_SOURCE_LENGTH = 1024
MAX_FUNCTION_LENGTH = 512


@dataclass(frozen=True)
class ASanSignature:
    error: str
    operation: str | None
    access_size: int | None
    function: str | None
    source: str | None

    def as_dict(self) -> dict[str, Any]:
        result: dict[str, Any] = {"error": self.error}
        if self.operation is not None:
            result["operation"] = self.operation
        if self.access_size is not None:
            result["access_size"] = self.access_size
        if self.function is not None:
            result["function"] = self.function
        if self.source is not None:
            result["source"] = self.source
        return result


def has_asan_diagnostic(text: str | None) -> bool:
    return bool(text and _HAS_DIAGNOSTIC.search(text))


def parse_asan(text: str | None) -> ASanSignature | None:
    """Return the first ASan diagnostic signature, or ``None``.

    The first frame with a source location is the faulting frame. Function and
    source fields are truncated defensively so a hostile log cannot inflate the
    report or planning digest.
    """
    if not text or not _HAS_DIAGNOSTIC.search(text):
        return None
    match = _ERROR.search(text) or _SUMMARY.search(text)
    if match is None:
        return None
    error = match.group(1)[:128]
    access = _ACCESS.search(text)
    operation = access.group(1) if access else None
    access_size = int(access.group(2)) if access else None
    function = None
    source = None
    frame = _FRAME.search(text)
    if frame is not None:
        function = frame.group("function")[:MAX_FUNCTION_LENGTH]
        source = frame.group("source")[:MAX_SOURCE_LENGTH]
    return ASanSignature(
        error=error,
        operation=operation,
        access_size=access_size,
        function=function,
        source=source,
    )


def _normalize_source(value: str) -> str:
    normalized = value.replace("\\", "/").strip()
    while normalized.startswith("./"):
        normalized = normalized[2:]
    return posixpath.normpath(normalized)


def _source_matches(expected: str, observed: str | None) -> bool:
    """Match a reviewed source path without accepting an arbitrary prefix.

    The rule is deliberately narrow:

    * the normalized paths must be equal;
    * a reviewed basename matches only a bare observed basename or an absolute
      ASan frame path, never a relative path with a forged directory prefix;
    * a reviewed relative path may match an absolute frame path that ends with
      the reviewed path.

    An observed basename also matches a reviewed path with directories, which
    is the documented basename rule. ASan text is observable behavior, not an
    authenticity proof; see the README.
    """
    if not observed:
        return False
    expected_path = _normalize_source(expected)
    observed_path = _normalize_source(observed)
    if expected_path.startswith("../") or observed_path.startswith("../"):
        return False
    if observed_path == expected_path:
        return True
    expected_base = posixpath.basename(expected_path)
    observed_base = posixpath.basename(observed_path)
    if expected_path == expected_base:
        # Reviewed as a basename: accept the same bare basename or an absolute
        # frame path. A relative path with extra components is a forged prefix.
        return observed_base == expected_base and (
            observed_path == observed_base or posixpath.isabs(observed_path)
        )
    if observed_path == observed_base:
        return observed_base == expected_base
    return observed_path.endswith("/" + expected_path)


def signature_matches(
    observed: ASanSignature | Mapping[str, Any] | None,
    expected: Mapping[str, Any],
) -> bool:
    """Return whether an observed signature matches the reviewed signature.

    ``operation`` and ``access_size`` are optional in the plan; when present
    they must match exactly. A missing function or source frame never matches.
    """
    if observed is None or not isinstance(expected, Mapping):
        return False
    if isinstance(observed, Mapping):
        observed = ASanSignature(
            error=str(observed.get("error", "")),
            operation=observed.get("operation"),
            access_size=observed.get("access_size"),
            function=observed.get("function"),
            source=observed.get("source"),
        )
    expected_error = expected.get("error")
    if not isinstance(expected_error, str) or observed.error != expected_error:
        return False
    expected_function = expected.get("function")
    if not isinstance(expected_function, str) or observed.function != expected_function:
        return False
    expected_source = expected.get("source")
    if not isinstance(expected_source, str) or not _source_matches(
        expected_source, observed.source
    ):
        return False
    if "operation" in expected:
        if observed.operation != expected["operation"]:
            return False
    if "access_size" in expected:
        if observed.access_size != expected["access_size"]:
            return False
    return True

"""Small, dependency-free helpers shared by contracts and persistence."""

from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any

_DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
_CONTROL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
_RFC3339 = re.compile(
    r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}"
    r"(?:\.[0-9]{1,9})?(?:Z|[+-][0-9]{2}:[0-9]{2})"
)


class StrictJsonError(ValueError):
    """The document is not a strict UTF-8 JSON object graph."""


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _reject_constant(value: str) -> None:
    raise ValueError(f"non-finite JSON number is not allowed: {value}")


def loads_strict(payload: str | bytes) -> Any:
    """Decode strict UTF-8 JSON, rejecting duplicate keys and NaN/Infinity."""
    try:
        if isinstance(payload, bytes):
            payload = payload.decode("utf-8")
        if not isinstance(payload, str):
            raise ValueError("document must be text or UTF-8 bytes")
        return json.loads(
            payload,
            object_pairs_hook=_unique_object,
            parse_constant=_reject_constant,
        )
    except (ValueError, RecursionError) as error:
        raise StrictJsonError(str(error)) from error


def canonical_bytes(value: Any) -> bytes:
    """Return the contract's canonical JSON encoding."""
    return json.dumps(
        value,
        sort_keys=True,
        ensure_ascii=False,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def digest_bytes(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def digest_json(value: Any) -> str:
    return digest_bytes(canonical_bytes(value))


def is_digest(value: Any) -> bool:
    return isinstance(value, str) and _DIGEST.fullmatch(value) is not None


def require_digest(value: Any, label: str) -> str:
    if not is_digest(value):
        raise ValueError(f"{label} must be a sha256 digest")
    return value


def require_text(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{label} must be a non-empty string")
    if _CONTROL.search(value):
        raise ValueError(f"{label} must not contain control characters")
    value.encode("utf-8")
    return value


def require_bool(value: Any, label: str) -> bool:
    if type(value) is not bool:
        raise ValueError(f"{label} must be a boolean")
    return value


def require_int(value: Any, label: str, *, minimum: int, maximum: int) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        raise ValueError(f"{label} must be an integer between {minimum} and {maximum}")
    return value


def require_object(
    value: Any, *, required: set[str], optional: set[str] = frozenset(), label: str = "value"
) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ValueError(f"{label} must be a JSON object")
    actual = set(value)
    missing = required - actual
    unknown = actual - required - optional
    if missing:
        raise ValueError(f"{label} is missing field(s): {', '.join(sorted(missing))}")
    if unknown:
        raise ValueError(f"{label} has unknown field(s): {', '.join(sorted(unknown))}")
    return value


def require_rfc3339(value: Any, label: str) -> str:
    text = require_text(value, label)
    if not _RFC3339.fullmatch(text):
        raise ValueError(f"{label} must be an RFC 3339 timestamp")
    parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError(f"{label} must include a UTC offset")
    parsed = parsed.astimezone(timezone.utc)
    return parsed.strftime("%Y-%m-%dT%H:%M:%SZ")


def timestamp(value: datetime) -> str:
    if not isinstance(value, datetime) or value.tzinfo is None:
        raise ValueError("timestamp requires a timezone-aware datetime")
    return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def safe_relative_path(value: Any, label: str, *, allow_dot: bool = False) -> str:
    text = require_text(value, label)
    if "\\" in text:
        raise ValueError(f"{label} must use POSIX separators")
    path = PurePosixPath(text)
    if path.is_absolute() or ".." in path.parts:
        raise ValueError(f"{label} must stay inside the case directory")
    if text == ".":
        if allow_dot:
            return text
        raise ValueError(f"{label} must name a file")
    if not path.parts:
        raise ValueError(f"{label} must name a file")
    return str(path)


def resolve_inside(root: Path, relative: str, *, allow_dot: bool = False) -> Path:
    """Resolve a contract path below ``root`` without following symlinks."""
    text = safe_relative_path(relative, "material path", allow_dot=allow_dot)
    root = root.resolve()
    candidate = (root / text).resolve()
    if candidate != root and root not in candidate.parents:
        raise ValueError("material path escapes the case directory")
    current = root
    for part in PurePosixPath(text).parts:
        if part == ".":
            continue
        current = current / part
        if current.is_symlink():
            raise ValueError("material path must not contain symlinks")
    return candidate


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return "sha256:" + digest.hexdigest()

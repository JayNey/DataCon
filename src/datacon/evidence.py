"""Evidence bundle creation, offline verification and export (REQ-08).

A bundle is a directory whose ``manifest.json`` lists every other regular file
with its role, byte count and SHA-256. Verification is intentionally offline:
it never trusts the database or the network. Symlinks, absolute paths, parent
traversal, duplicates, missing files and extra files are rejected.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import uuid
from typing import Any, Mapping

from datacon import jsonutil

SCHEMA_VERSION = 1
MAX_MANIFEST_BYTES = 4 * 1024 * 1024
MAX_FILE_BYTES = 128 * 1024 * 1024
MAX_FILES = 4096
MAX_ROLE_LENGTH = 64
import re

_SHA256_HEX = re.compile(r"[0-9a-f]{64}")
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
_REQUIRED_ROLES = frozenset(
    {"report_json", "report_markdown", "plan", "review"}
)
_ROLE_NAMES = frozenset(
    {
        "report_json",
        "report_markdown",
        "plan",
        "review",
        "execution_metadata",
        "probe",
        "build_log",
        "build_metadata",
        "build_artifact",
        "normal_output",
        "normal_error",
        "asan_log",
        "replay_stdout",
        "replay_stderr",
        "replay_metadata",
        "material_harness",
        "material_build_recipe",
        "material_dependencies",
        "material_input_normal",
        "material_input_candidate",
        "material_source_vulnerable",
        "material_source_fixed",
        "symbolizer_log",
    }
)
_ENTRY_FIELDS = frozenset({"path", "role", "size_bytes", "sha256"})


class BundleError(RuntimeError):
    """A bundle violates the evidence contract."""

    def __init__(self, reason_code: str, message: str):
        super().__init__(message)
        self.reason_code = reason_code
        self.message = message


@dataclass(frozen=True)
class BundleInfo:
    root: Path
    manifest: dict[str, Any]
    manifest_digest: str


@dataclass(frozen=True)
class BundleVerification:
    root: Path
    manifest: dict[str, Any]
    manifest_digest: str
    file_data: dict[str, bytes]


def canonical_manifest_bytes(manifest: Mapping[str, Any]) -> bytes:
    return jsonutil.canonical_bytes(manifest)


def canonical_manifest_digest(manifest: Mapping[str, Any]) -> str:
    return "sha256:" + hashlib.sha256(canonical_manifest_bytes(manifest)).hexdigest()


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace(
        "+00:00", "Z"
    )


def _normalize_file_path(value: Any) -> str:
    if not isinstance(value, str) or not value or "\x00" in value:
        raise BundleError("UNSAFE_PATH", "bundle path must be a non-empty string")
    if len(value) > 512:
        raise BundleError("UNSAFE_PATH", "bundle path is too long")
    if value.startswith("/") or value.startswith("\\") or value.startswith("./") or "/./" in value:
        raise BundleError("UNSAFE_PATH", f"absolute or dot bundle path is not allowed: {value}")
    if "\\" in value:
        raise BundleError("UNSAFE_PATH", f"backslash path is not allowed: {value}")
    pure = PurePosixPath(value)
    if pure.is_absolute() or any(part in ("", ".", "..") for part in pure.parts):
        raise BundleError("UNSAFE_PATH", f"unsafe bundle path: {value}")
    return pure.as_posix()


def _entry(path: str, role: str, data: bytes) -> dict[str, Any]:
    if role not in _ROLE_NAMES:
        raise BundleError("INVALID_MANIFEST", f"unknown evidence role: {role}")
    return {
        "path": _normalize_file_path(path),
        "role": role,
        "size_bytes": len(data),
        "sha256": _sha256(data),
    }


def _read_artifact(value: bytes | bytearray | memoryview | Path | str) -> bytes:
    if isinstance(value, (bytes, bytearray, memoryview)):
        data = bytes(value)
    else:
        path = Path(value)
        if path.is_symlink():
            raise BundleError("SYMLINK", f"artifact is a symlink: {path}")
        try:
            data = path.read_bytes()
        except OSError as error:
            raise BundleError("MISSING_FILE", f"artifact is not readable: {error}") from error
    if len(data) > MAX_FILE_BYTES:
        raise BundleError("FILE_TOO_LARGE", "bundle file exceeds the size cap")
    return data


def write_bundle(
    root: Path | str,
    *,
    job_id: str | uuid.UUID,
    plan_digest: str,
    report: Mapping[str, Any],
    report_markdown: str,
    artifacts: Mapping[str, tuple[str, bytes | bytearray | memoryview | Path | str]] | None = None,
    verdict: str | None = None,
    created_at: str | None = None,
) -> BundleInfo:
    """Create a new bundle directory and its manifest.

    The caller supplies role-labelled artifacts. report.json and report.md are
    added by this function. The directory must not already exist.
    """
    job_text = str(uuid.UUID(str(job_id)))
    if not isinstance(plan_digest, str) or not _DIGEST.fullmatch(plan_digest):
        raise BundleError("INVALID_MANIFEST", "plan digest is invalid")
    if not isinstance(report, Mapping):
        raise BundleError("INVALID_MANIFEST", "report must be an object")
    if not isinstance(report_markdown, str):
        raise BundleError("INVALID_MANIFEST", "report markdown must be text")
    if report.get("job_id") != job_text:
        raise BundleError("INVALID_MANIFEST", "report job_id does not match")
    if report.get("plan_digest") != plan_digest:
        raise BundleError("INVALID_MANIFEST", "report plan_digest does not match")

    target = Path(root)
    if target.exists() or target.is_symlink():
        raise BundleError("BUNDLE_EXISTS", "bundle destination already exists")
    parent = target.parent
    parent.mkdir(parents=True, exist_ok=True)
    temporary = parent / f".{target.name}.tmp-{uuid.uuid4().hex}"
    # A possibly pre-existing symlink at the temp name is never followed.
    if temporary.exists() or temporary.is_symlink():
        raise BundleError("BUNDLE_EXISTS", "temporary bundle path already exists")
    temporary.mkdir(mode=0o700)
    try:
        entries: list[dict[str, Any]] = []
        payloads: dict[str, bytes] = {
            "report.json": jsonutil.canonical_bytes(report) + b"\n",
            "report.md": report_markdown.encode("utf-8"),
        }
        for path, (role, value) in (artifacts or {}).items():
            normalized = _normalize_file_path(path)
            if normalized in payloads:
                raise BundleError("INVALID_MANIFEST", f"duplicate bundle file: {path}")
            payloads[normalized] = _read_artifact(value)
        if len(payloads) > MAX_FILES:
            raise BundleError("INVALID_MANIFEST", "bundle has too many files")

        for path, data in payloads.items():
            destination = temporary / PurePosixPath(path)
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(data)
            destination.chmod(0o600)
            role = (
                "report_json"
                if path == "report.json"
                else "report_markdown"
                if path == "report.md"
                else artifacts[path][0]  # type: ignore[index]
            )
            entries.append(_entry(path, role, data))
        entries.sort(key=lambda item: item["path"])

        roles = {entry["role"] for entry in entries}
        if not _REQUIRED_ROLES <= roles:
            missing = sorted(_REQUIRED_ROLES - roles)
            raise BundleError(
                "INVALID_MANIFEST",
                "bundle is missing required roles: " + ", ".join(missing),
            )

        manifest = {
            "schema_version": SCHEMA_VERSION,
            "job_id": job_text,
            "plan_digest": plan_digest,
            "verdict": verdict if isinstance(verdict, str) else report.get("verdict"),
            "created_at": created_at or _utc_now(),
            "files": entries,
        }
        manifest_bytes = canonical_manifest_bytes(manifest) + b"\n"
        (temporary / "manifest.json").write_bytes(manifest_bytes)
        (temporary / "manifest.json").chmod(0o600)
        for directory in sorted(
            (item for item in temporary.rglob("*") if item.is_dir()),
            key=lambda item: len(item.parts),
            reverse=True,
        ):
            directory.chmod(0o700)
        temporary.chmod(0o700)
        temporary.rename(target)
    except BaseException:
        shutil.rmtree(temporary, ignore_errors=True)
        raise
    return BundleInfo(
        root=target,
        manifest=manifest,
        manifest_digest=canonical_manifest_digest(manifest),
    )


def _load_manifest(root: Path) -> tuple[dict[str, Any], bytes]:
    path = root / "manifest.json"
    if path.is_symlink():
        raise BundleError("SYMLINK", "manifest.json must not be a symlink")
    if not path.is_file():
        raise BundleError("MISSING_FILE", "manifest.json is missing")
    size = path.stat().st_size
    if size > MAX_MANIFEST_BYTES:
        raise BundleError("INVALID_MANIFEST", "manifest.json is too large")
    data = path.read_bytes()
    try:
        manifest = jsonutil.loads_strict(data)
    except jsonutil.StrictJsonError as error:
        raise BundleError("INVALID_MANIFEST", f"manifest.json is invalid: {error}") from error
    if not isinstance(manifest, dict):
        raise BundleError("INVALID_MANIFEST", "manifest.json must be an object")
    return manifest, data


def _validate_manifest_header(manifest: Mapping[str, Any]) -> tuple[str, str, list[dict[str, Any]]]:
    if manifest.get("schema_version") != SCHEMA_VERSION:
        raise BundleError("INVALID_MANIFEST", "manifest schema_version must be 1")
    try:
        job_id = str(uuid.UUID(str(manifest.get("job_id"))))
    except (TypeError, ValueError, AttributeError) as error:
        raise BundleError("INVALID_MANIFEST", "manifest job_id must be a UUID") from error
    plan_digest = manifest.get("plan_digest")
    if not isinstance(plan_digest, str) or not _DIGEST.fullmatch(plan_digest):
        raise BundleError("INVALID_MANIFEST", "manifest plan_digest is invalid")
    files = manifest.get("files")
    if not isinstance(files, list):
        raise BundleError("INVALID_MANIFEST", "manifest files must be a list")
    if len(files) > MAX_FILES:
        raise BundleError("INVALID_MANIFEST", "manifest lists too many files")
    return job_id, plan_digest, files


def _validate_entry(entry: Any, seen: set[str]) -> dict[str, Any]:
    if not isinstance(entry, dict):
        raise BundleError("INVALID_MANIFEST", "manifest entry must be an object")
    if set(entry) != _ENTRY_FIELDS:
        raise BundleError(
            "INVALID_MANIFEST", "manifest entry has missing or unknown fields"
        )
    path = _normalize_file_path(entry["path"])
    if path == "manifest.json":
        raise BundleError("INVALID_MANIFEST", "manifest must not list itself")
    if path in seen:
        raise BundleError("DUPLICATE_ENTRY", f"duplicate manifest entry: {path}")
    seen.add(path)
    role = entry["role"]
    if not isinstance(role, str) or not role or len(role) > MAX_ROLE_LENGTH:
        raise BundleError("INVALID_MANIFEST", f"invalid role for {path}")
    if role not in _ROLE_NAMES:
        raise BundleError("INVALID_MANIFEST", f"unknown evidence role: {role}")
    size = entry["size_bytes"]
    if type(size) is not int or not 0 <= size <= MAX_FILE_BYTES:
        raise BundleError("INVALID_MANIFEST", f"invalid size for {path}")
    sha = entry["sha256"]
    if not isinstance(sha, str) or not _SHA256_HEX.fullmatch(sha):
        raise BundleError("INVALID_MANIFEST", f"invalid sha256 for {path}")
    return {"path": path, "role": role, "size_bytes": size, "sha256": sha}


def verify_bundle(root: Path | str) -> BundleVerification:
    """Verify a bundle without database or network access."""
    path = Path(root)
    if path.is_symlink():
        raise BundleError("SYMLINK", "bundle root must not be a symlink")
    try:
        root_path = path.resolve(strict=True)
    except OSError as error:
        raise BundleError("MISSING_FILE", f"bundle root is not readable: {error}") from error
    if not root_path.is_dir():
        raise BundleError("INVALID_MANIFEST", "bundle root must be a directory")

    manifest, _ = _load_manifest(root_path)
    job_id, plan_digest, files = _validate_manifest_header(manifest)
    entries = []
    seen: set[str] = set()
    for entry in files:
        entries.append(_validate_entry(entry, seen))
    roles = {entry["role"] for entry in entries}
    if not _REQUIRED_ROLES <= roles:
        missing = sorted(_REQUIRED_ROLES - roles)
        raise BundleError(
            "INVALID_MANIFEST",
            "manifest is missing required roles: " + ", ".join(missing),
        )

    listed = {entry["path"]: entry for entry in entries}
    actual: dict[str, Path] = {}
    for current_root, directories, filenames in os.walk(root_path, followlinks=False):
        current = Path(current_root)
        for name in directories:
            child = current / name
            if child.is_symlink():
                raise BundleError("SYMLINK", f"bundle contains a symlink: {child}")
        for name in filenames:
            child = current / name
            if child.is_symlink():
                raise BundleError("SYMLINK", f"bundle contains a symlink: {child}")
            if not child.is_file():
                raise BundleError(
                    "INVALID_MANIFEST", f"bundle contains a special file: {child}"
                )
            relative = child.relative_to(root_path).as_posix()
            if relative == "manifest.json":
                continue
            if relative not in listed:
                raise BundleError("EXTRA_FILE", f"bundle contains an extra file: {relative}")
            actual[relative] = child
    missing = sorted(set(listed) - set(actual))
    if missing:
        raise BundleError("MISSING_FILE", "bundle is missing: " + ", ".join(missing))

    data: dict[str, bytes] = {}
    for relative, entry in listed.items():
        content = actual[relative].read_bytes()
        if len(content) != entry["size_bytes"]:
            raise BundleError("DIGEST_MISMATCH", f"size mismatch for {relative}")
        if _sha256(content) != entry["sha256"]:
            raise BundleError("DIGEST_MISMATCH", f"sha256 mismatch for {relative}")
        data[relative] = content

    try:
        report = jsonutil.loads_strict(data["report.json"])
    except (KeyError, jsonutil.StrictJsonError) as error:
        raise BundleError("INVALID_MANIFEST", "report.json is invalid") from error
    if not isinstance(report, dict):
        raise BundleError("INVALID_MANIFEST", "report.json must be an object")
    if report.get("job_id") != job_id:
        raise BundleError("INVALID_MANIFEST", "report job_id does not match manifest")
    if report.get("plan_digest") != plan_digest:
        raise BundleError("INVALID_MANIFEST", "report plan_digest does not match manifest")
    if not isinstance(report.get("verdict"), str):
        raise BundleError("INVALID_MANIFEST", "report verdict is missing")

    return BundleVerification(
        root=root_path,
        manifest=manifest,
        manifest_digest=canonical_manifest_digest(manifest),
        file_data=data,
    )


def export_bundle(source: Path | str, destination: Path | str) -> BundleInfo:
    """Copy a verified bundle to a new directory, verifying the copy."""
    verified = verify_bundle(source)
    target = Path(destination)
    if target.is_symlink():
        raise BundleError("EXPORT_TARGET_NOT_EMPTY", "export target is a symlink")
    if target.exists():
        if not target.is_dir():
            raise BundleError("EXPORT_TARGET_NOT_EMPTY", "export target is not a directory")
        if any(target.iterdir()):
            raise BundleError(
                "EXPORT_TARGET_NOT_EMPTY", "export target is not empty"
            )
    try:
        target_resolved = target.resolve()
        source_resolved = verified.root
        if target_resolved == source_resolved or source_resolved in target_resolved.parents:
            raise BundleError(
                "EXPORT_TARGET_NOT_EMPTY", "export target must be outside the bundle"
            )
    except OSError as error:
        raise BundleError("EXPORT_TARGET_NOT_EMPTY", str(error)) from error

    parent = target.parent
    parent.mkdir(parents=True, exist_ok=True)
    temporary = parent / f".{target.name}.export-{uuid.uuid4().hex}"
    temporary.mkdir(mode=0o700)
    try:
        for relative in sorted(verified.file_data):
            output = temporary / PurePosixPath(relative)
            output.parent.mkdir(parents=True, exist_ok=True)
            output.write_bytes(verified.file_data[relative])
            output.chmod(0o600)
        shutil.copyfile(
            verified.root / "manifest.json", temporary / "manifest.json"
        )
        (temporary / "manifest.json").chmod(0o600)
        copied = verify_bundle(temporary)
        if copied.manifest_digest != verified.manifest_digest:
            raise BundleError("DIGEST_MISMATCH", "exported manifest digest changed")
        if target.exists():
            target.rmdir()
        temporary.rename(target)
    except BaseException:
        shutil.rmtree(temporary, ignore_errors=True)
        raise
    return BundleInfo(
        root=target,
        manifest=copied.manifest,
        manifest_digest=copied.manifest_digest,
    )

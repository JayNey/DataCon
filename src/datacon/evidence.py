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
import stat
import uuid
from typing import Any, Callable, Mapping

from datacon import contracts, fileio, jsonutil
from datacon.asan import has_asan_diagnostic, parse_asan, signature_matches
from datacon.verdict import (
    reason_allowed,
    replay_status_allowed,
)

SCHEMA_VERSION = 1
MAX_MANIFEST_BYTES = 4 * 1024 * 1024
MAX_FILE_BYTES = 128 * 1024 * 1024
# A bundle is bounded per file and in aggregate, so a manifest cannot make an
# offline verifier allocate MAX_FILES * MAX_FILE_BYTES.
MAX_TOTAL_BYTES = 256 * 1024 * 1024
MAX_FILES = 4096
# ``os.walk`` sees directories as well as files, and a verifier must not
# traverse an unbounded tree before reporting an extra entry. A small margin
# above the manifest cap keeps legitimate bundles with helper directories
# verifiable while still failing fast.
MAX_BUNDLE_ENTRIES = MAX_FILES + 64
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
        "material_patch",
        "case_config",
        "symbolizer_log",
    }
)
_ENTRY_FIELDS = frozenset({"path", "role", "size_bytes", "sha256"})
_VERDICTS = frozenset(
    {"REPRODUCED", "NOT_REPRODUCED", "INCONCLUSIVE", "BLOCKED", "FAILED"}
)
_FULL_EVIDENCE_VERDICTS = frozenset(
    {"REPRODUCED", "NOT_REPRODUCED", "INCONCLUSIVE"}
)
_REPLAY_VERSIONS = ("vulnerable", "fixed")
_REPLAY_PHASES = ("normal", "candidate_1", "candidate_2")
_CANDIDATE_PHASES = ("candidate_1", "candidate_2")
# The probe report only carries the resource fields the container actually
# observed; the plan additionally contains timing budgets.
_PROBE_LIMIT_FIELDS = ("cpu", "memory_mib", "pids", "scratch_mib")
# A completed probe must prove the controls the executor relies on. Extra
# fields are allowed so the probe can grow, but these cannot be omitted.
_PROBE_CHECK_FIELDS = (
    "uid",
    "seccomp",
    "no_new_privs",
    "cap_eff",
    "cgroup_version",
)
_REASON_CODE = re.compile(r"[A-Z][A-Z0-9_]{0,63}")
_WINDOWS_DRIVE = re.compile(r"^[A-Za-z]:")


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
    manifest_bytes: bytes
    file_data: dict[str, bytes]


def canonical_manifest_bytes(manifest: Mapping[str, Any]) -> bytes:
    return jsonutil.canonical_bytes(manifest)


def canonical_manifest_digest(manifest: Mapping[str, Any]) -> str:
    return "sha256:" + hashlib.sha256(canonical_manifest_bytes(manifest)).hexdigest()


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _digest(data: bytes) -> str:
    return "sha256:" + _sha256(data)


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
    if value.startswith("//") or _WINDOWS_DRIVE.match(value):
        raise BundleError("UNSAFE_PATH", f"drive or UNC bundle path is not allowed: {value}")
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
        # Bound the read from the actual inode instead of calling
        # ``read_bytes`` first: a huge artifact must not be loaded into memory
        # just to be rejected against the size cap.
        try:
            info = path.lstat()
        except OSError as error:
            raise BundleError(
                "MISSING_FILE", f"artifact is not readable: {error}"
            ) from error
        if stat.S_ISLNK(info.st_mode):
            raise BundleError("SYMLINK", f"artifact is a symlink: {path}")
        if not stat.S_ISREG(info.st_mode):
            raise BundleError(
                "MISSING_FILE", f"artifact is not a regular file: {path}"
            )
        if info.st_size > MAX_FILE_BYTES:
            raise BundleError("FILE_TOO_LARGE", "bundle file exceeds the size cap")
        data = _read_bounded(path, expected_size=info.st_size)
        if len(data) != info.st_size:
            raise BundleError(
                "DIGEST_MISMATCH", f"artifact changed while reading: {path}"
            )
    if len(data) > MAX_FILE_BYTES:
        raise BundleError("FILE_TOO_LARGE", "bundle file exceeds the size cap")
    return data


def _read_bounded(path: Path, *, expected_size: int) -> bytes:
    """Read at most ``expected_size + 1`` bytes from a regular file.

    Callers stat the file first, but a concurrent writer can still swap the
    path for a FIFO or grow it. The shared ``fileio`` helper opens with
    ``O_NOFOLLOW|O_NONBLOCK`` and checks ``fstat`` before reading, so a FIFO can
    never block the offline verifier and a symlink is rejected outright. The
    bounded read guarantees the verifier never buffers more than the manifest
    declares (plus one byte to detect growth).
    """
    try:
        return fileio.read_regular_file_bounded(path, max_bytes=expected_size)
    except fileio.UnsafeFileError as error:
        if error.kind == "SYMLINK":
            raise BundleError("SYMLINK", f"file is a symlink: {path}") from error
        if error.kind == "NOT_REGULAR":
            raise BundleError(
                "INVALID_MANIFEST", f"file is not a regular file: {path}"
            ) from error
        if error.kind in ("TOO_LARGE", "CHANGED"):
            raise BundleError(
                "DIGEST_MISMATCH", f"file changed while reading: {path}"
            ) from error
        raise BundleError(
            "MISSING_FILE", f"file is not readable: {path}"
        ) from error


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
    verify: Callable[[Path], object] | None = None,
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
    report_verdict = report.get("verdict")
    if report_verdict not in _VERDICTS:
        raise BundleError("INVALID_MANIFEST", "report verdict must be a known value")
    report_reason = report.get("reason_code")
    if report_reason is not None and (
        not isinstance(report_reason, str)
        or not _REASON_CODE.fullmatch(report_reason)
    ):
        raise BundleError("INVALID_MANIFEST", "report reason_code is invalid")

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
            # report.json / report.md are generated here rather than read from
            # disk; they still have to obey the same evidence size cap.
            if len(data) > MAX_FILE_BYTES:
                raise BundleError(
                    "FILE_TOO_LARGE", f"bundle file exceeds the size cap: {path}"
                )
        if sum(len(data) for data in payloads.values()) > MAX_TOTAL_BYTES:
            raise BundleError(
                "FILE_TOO_LARGE", "bundle exceeds the total evidence size cap"
            )

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
            "verdict": verdict if isinstance(verdict, str) else report_verdict,
            "reason_code": report_reason,
            "created_at": created_at or _utc_now(),
            "files": entries,
        }
        if manifest["verdict"] not in _VERDICTS:
            raise BundleError("INVALID_MANIFEST", "manifest verdict is invalid")
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
        if verify is not None:
            # Sample the completed staging directory before it becomes the
            # archived bundle. A bundle that cannot verify offline must never
            # be published as evidence.
            verify(temporary)
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
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode):
        raise BundleError("INVALID_MANIFEST", "manifest.json must be a regular file")
    size = info.st_size
    if size > MAX_MANIFEST_BYTES:
        raise BundleError("INVALID_MANIFEST", "manifest.json is too large")
    data = _read_bounded(path, expected_size=size)
    if len(data) != size:
        raise BundleError("DIGEST_MISMATCH", "manifest.json size changed while reading")
    try:
        manifest = jsonutil.loads_strict(data)
    except jsonutil.StrictJsonError as error:
        raise BundleError("INVALID_MANIFEST", f"manifest.json is invalid: {error}") from error
    if not isinstance(manifest, dict):
        raise BundleError("INVALID_MANIFEST", "manifest.json must be an object")
    return manifest, data


def _validate_manifest_header(
    manifest: Mapping[str, Any],
) -> tuple[str, str, list[dict[str, Any]], str, str | None]:
    if manifest.get("schema_version") != SCHEMA_VERSION:
        raise BundleError("INVALID_MANIFEST", "manifest schema_version must be 1")
    try:
        job_id = str(uuid.UUID(str(manifest.get("job_id"))))
    except (TypeError, ValueError, AttributeError) as error:
        raise BundleError("INVALID_MANIFEST", "manifest job_id must be a UUID") from error
    plan_digest = manifest.get("plan_digest")
    if not isinstance(plan_digest, str) or not _DIGEST.fullmatch(plan_digest):
        raise BundleError("INVALID_MANIFEST", "manifest plan_digest is invalid")
    verdict = manifest.get("verdict")
    if verdict not in _VERDICTS:
        raise BundleError("INVALID_MANIFEST", "manifest verdict is invalid")
    reason_code = manifest.get("reason_code")
    if reason_code is not None and (
        not isinstance(reason_code, str)
        or not _REASON_CODE.fullmatch(reason_code)
    ):
        raise BundleError("INVALID_MANIFEST", "manifest reason_code is invalid")
    files = manifest.get("files")
    if not isinstance(files, list):
        raise BundleError("INVALID_MANIFEST", "manifest files must be a list")
    if len(files) > MAX_FILES:
        raise BundleError("INVALID_MANIFEST", "manifest lists too many files")
    return job_id, plan_digest, files, verdict, reason_code


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


def _parse_json_file(data: Mapping[str, bytes], relative: str) -> dict[str, Any]:
    try:
        content = data[relative]
    except KeyError as error:
        raise BundleError(
            "INVALID_MANIFEST", f"required evidence file is missing: {relative}"
        ) from error
    try:
        parsed = jsonutil.loads_strict(content)
    except jsonutil.StrictJsonError as error:
        raise BundleError(
            "INVALID_MANIFEST", f"{relative} is invalid JSON: {error}"
        ) from error
    if not isinstance(parsed, dict):
        raise BundleError("INVALID_MANIFEST", f"{relative} must be an object")
    return parsed


def _reason_code_valid(report: Mapping[str, Any]) -> str | None:
    reason = report.get("reason_code")
    if reason is None:
        return None
    if not isinstance(reason, str) or not _REASON_CODE.fullmatch(reason):
        raise BundleError("INVALID_MANIFEST", "report reason_code is invalid")
    return reason


def _require_evidence_roles(
    listed: Mapping[str, Mapping[str, Any]],
    expected: Mapping[str, frozenset[str]],
) -> None:
    for path, allowed_roles in expected.items():
        entry = listed.get(path)
        if entry is None:
            raise BundleError(
                "INVALID_MANIFEST", f"required execution evidence is missing: {path}"
            )
        if entry.get("role") not in allowed_roles:
            raise BundleError(
                "INVALID_MANIFEST",
                f"evidence {path} has role {entry.get('role')!r}, "
                f"expected one of {sorted(allowed_roles)}",
            )


def _mapping(value: Any, label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise BundleError("INVALID_MANIFEST", f"{label} must be an object")
    return value


def _material_entries(
    listed: Mapping[str, Mapping[str, Any]],
) -> dict[str, Mapping[str, Any]]:
    return {
        path[len("materials/") :]: entry
        for path, entry in listed.items()
        if path.startswith("materials/")
    }


def _single_role_path(
    listed: Mapping[str, Mapping[str, Any]], role: str
) -> tuple[str, Mapping[str, Any]]:
    matches = [
        (path, entry)
        for path, entry in listed.items()
        if entry["role"] == role
    ]
    if len(matches) != 1:
        raise BundleError(
            "INVALID_MANIFEST",
            f"expected exactly one {role} evidence file, found {len(matches)}",
        )
    return matches[0]


def _case_binding(
    plan: Mapping[str, Any],
    listed: Mapping[str, Mapping[str, Any]],
    data: Mapping[str, bytes],
) -> tuple[Mapping[str, Any], Mapping[str, str], bytes]:
    """Rebuild the case-config digest that the approved plan froze.

    The plan's ``case_config_digest`` covers the registry entry, the
    case-specific manifest fragment, every used material digest, the image,
    platform, toolchain, ASan options and the reviewed signature. Shipping
    that exact document lets an offline verifier bind source materials (which
    have no standalone plan field) back to the plan instead of trusting
    report.json.
    """
    entry = listed.get("metadata/case.json")
    if entry is None:
        raise BundleError(
            "INVALID_MANIFEST", "metadata/case.json is required for complete evidence"
        )
    if entry["role"] != "case_config":
        raise BundleError(
            "INVALID_MANIFEST",
            "metadata/case.json must carry the case_config role",
        )
    document = _parse_json_file(data, "metadata/case.json")
    case_config = _mapping(document.get("case_config"), "case_config")
    try:
        computed = jsonutil.digest_json(case_config)
    except (ValueError, UnicodeError, RecursionError) as error:
        raise BundleError(
            "INVALID_MANIFEST", f"case config is not canonical JSON: {error}"
        ) from error
    if computed != plan.get("case_config_digest"):
        raise BundleError(
            "DIGEST_MISMATCH",
            "metadata/case.json does not match plan.case_config_digest",
        )
    if case_config.get("case_id") != plan.get("case_id"):
        raise BundleError("INVALID_MANIFEST", "case config names a different case")
    if case_config.get("cve_id") != plan.get("cve_id"):
        raise BundleError("INVALID_MANIFEST", "case config names a different CVE")
    image = case_config.get("image")
    if (
        not isinstance(image, str)
        or not image.endswith("@" + str(plan.get("image_digest")))
    ):
        raise BundleError("INVALID_MANIFEST", "case config image does not match the plan")
    for field in ("platform", "toolchain", "asan_options", "asan_signature"):
        if case_config.get(field) != plan.get(field):
            raise BundleError(
                "INVALID_MANIFEST", f"case config {field} does not match the plan"
            )
    registry_entry = _mapping(case_config.get("registry_entry"), "registry_entry")
    repository = _mapping(registry_entry.get("repository"), "registry repository")
    if repository.get("commits") != plan.get("revisions"):
        raise BundleError(
            "INVALID_MANIFEST", "case registry revisions do not match the plan"
        )
    if repository.get("bundle_digest") != plan.get("repository", {}).get(
        "bundle_digest"
    ):
        raise BundleError(
            "INVALID_MANIFEST", "case registry bundle digest does not match the plan"
        )
    materials = _mapping(case_config.get("materials"), "case materials")
    manifest_case = _mapping(case_config.get("manifest_case"), "manifest_case")
    inputs = _mapping(manifest_case.get("inputs"), "manifest_case.inputs")
    normal_input = inputs.get("normal")
    candidate_input = inputs.get("candidate")
    if not isinstance(normal_input, str) or not isinstance(candidate_input, str):
        raise BundleError(
            "INVALID_MANIFEST",
            "manifest_case.inputs.normal and .candidate must be strings",
        )
    if materials.get(normal_input) != plan.get("inputs", {}).get("normal"):
        raise BundleError(
            "INVALID_MANIFEST", "case normal input digest does not match the plan"
        )
    if materials.get(candidate_input) != plan.get("inputs", {}).get(
        "candidate"
    ):
        raise BundleError(
            "INVALID_MANIFEST", "case candidate input digest does not match the plan"
        )
    recipe_path, _ = _single_role_path(listed, "material_build_recipe")
    recipe = data[recipe_path]
    if _digest(recipe) != plan.get("build_recipe_digest"):
        raise BundleError(
            "DIGEST_MISMATCH", "build recipe does not match plan.build_recipe_digest"
        )
    return case_config, materials, recipe


def _verify_materials(
    plan: Mapping[str, Any],
    listed: Mapping[str, Mapping[str, Any]],
    data: Mapping[str, bytes],
    case_config: Mapping[str, Any],
    materials: Mapping[str, str],
) -> None:
    bundle_materials = _material_entries(listed)
    for relative, entry in bundle_materials.items():
        if relative not in materials:
            raise BundleError(
                "INVALID_MANIFEST",
                f"materials/{relative} is not pinned by the plan case config",
            )
        content = data[f"materials/{relative}"]
        if _digest(content) != materials[relative]:
            raise BundleError(
                "DIGEST_MISMATCH",
                f"material digest does not match plan case config: {relative}",
            )
    expected_plan_digests = {
        "material_harness": plan.get("harness_digest"),
        "material_build_recipe": plan.get("build_recipe_digest"),
        "material_dependencies": plan.get("dependencies_digest"),
        "material_patch": plan.get("repository", {}).get("patch_digest"),
        "material_input_normal": plan.get("inputs", {}).get("normal"),
        "material_input_candidate": plan.get("inputs", {}).get("candidate"),
    }
    for role, expected in expected_plan_digests.items():
        path, entry = _single_role_path(listed, role)
        if not path.startswith("materials/"):
            raise BundleError(
                "INVALID_MANIFEST", f"{role} must be a materials/* evidence file"
            )
        relative = path[len("materials/") :]
        content = data[path]
        if expected is not None and _digest(content) != expected:
            raise BundleError(
                "DIGEST_MISMATCH", f"{role} does not match the approved plan"
            )
        if materials.get(relative) != _digest(content):
            raise BundleError(
                "DIGEST_MISMATCH",
                f"{role} path is not pinned by the plan case config",
            )
    for role in ("material_source_vulnerable", "material_source_fixed"):
        path, entry = _single_role_path(listed, role)
        if not path.startswith("materials/"):
            raise BundleError(
                "INVALID_MANIFEST", f"{role} must be a materials/* evidence file"
            )
        relative = path[len("materials/") :]
        if materials.get(relative) != _digest(data[path]):
            raise BundleError(
                "DIGEST_MISMATCH",
                f"{role} is not pinned by the plan case config",
            )


def _compile_args_from_recipe(recipe: bytes) -> list[str]:
    from datacon.tools.sandbox import _extract_compile_args

    return list(_extract_compile_args(recipe))


def _build_evidence_path(version: str, name: str) -> str:
    return f"build/{version}/{name}"


def _replay_evidence_path(version: str, phase: str, name: str) -> str:
    return f"replay/{version}/{phase}/{name}"


def _require_path_suffix(value: Any, suffix: str, label: str) -> None:
    if not isinstance(value, str) or ".." in Path(value).parts:
        raise BundleError("INVALID_MANIFEST", f"{label} path is invalid")
    if not value.endswith(suffix):
        raise BundleError("INVALID_MANIFEST", f"{label} has an unexpected path")


def _truncation_allowed(verdict: str, report: Mapping[str, Any]) -> bool:
    """Only an inconclusive reason may legitimately archive a truncated log."""
    return verdict == "INCONCLUSIVE" and report.get("reason_code") in {
        "NOT_COMPARABLE",
        "EVIDENCE_INCOMPLETE",
    }


def _require_untruncated(value: Any, *, allowed: bool, label: str) -> None:
    if value is False:
        return
    if allowed and value is True:
        return
    raise BundleError("INVALID_MANIFEST", f"{label} is truncated")


def _verify_builds(
    plan: Mapping[str, Any],
    verdict: str,
    report: Mapping[str, Any],
    data: Mapping[str, bytes],
    expected_compile_args: list[str],
    *,
    job_id: str,
    plan_digest: str,
    materials: Mapping[str, str],
) -> None:
    truncation_allowed = _truncation_allowed(verdict, report)
    builds = report.get("builds")
    if not isinstance(builds, list):
        raise BundleError("INVALID_MANIFEST", "report builds must be a list")
    if len(builds) != 2:
        raise BundleError(
            "INVALID_MANIFEST", "complete evidence requires exactly two builds"
        )
    seen: set[str] = set()
    for build in builds:
        if not isinstance(build, Mapping):
            raise BundleError("INVALID_MANIFEST", "report build must be an object")
        version = build.get("version")
        if version not in _REPLAY_VERSIONS or version in seen:
            raise BundleError(
                "INVALID_MANIFEST", f"report build has an invalid version: {version}"
            )
        seen.add(version)
        if build.get("status") != "completed":
            raise BundleError(
                "INVALID_MANIFEST", f"{version} build did not complete"
            )
        if build.get("plan_digest") != plan_digest or build.get("job_id") != job_id:
            raise BundleError(
                "INVALID_MANIFEST",
                f"{version} build provenance does not match",
            )
        if build.get("input_digest") != plan.get("analysis_digest"):
            raise BundleError(
                "DIGEST_MISMATCH", f"{version} build input does not match the plan"
            )
        if build.get("image_digest") != plan.get("image_digest"):
            raise BundleError(
                "DIGEST_MISMATCH", f"{version} build image does not match the plan"
            )
        if build.get("build_recipe_digest") != plan.get("build_recipe_digest"):
            raise BundleError(
                "DIGEST_MISMATCH", f"{version} build recipe does not match the plan"
            )
        staged = _mapping(
            build.get("staged_materials"), f"{version} staged_materials"
        )
        expected_staged = dict(materials)
        # Execution copies each reviewed input to a stable replay name, so the
        # staged tree deliberately contains two extra aliases. They must equal
        # the plan inputs; every other key must match the case config exactly.
        plan_inputs = plan.get("inputs")
        normal_alias = (
            plan_inputs.get("normal") if isinstance(plan_inputs, Mapping) else None
        )
        candidate_alias = (
            plan_inputs.get("candidate")
            if isinstance(plan_inputs, Mapping)
            else None
        )
        if not isinstance(normal_alias, str) or not isinstance(
            candidate_alias, str
        ):
            raise BundleError(
                "INVALID_MANIFEST",
                "plan inputs must record normal/candidate digests",
            )
        expected_staged["inputs/normal.txt"] = normal_alias
        expected_staged["inputs/candidate.txt"] = candidate_alias
        for alias, expected_alias in (
            ("inputs/normal.txt", normal_alias),
            ("inputs/candidate.txt", candidate_alias),
        ):
            if alias in materials and materials[alias] != expected_alias:
                raise BundleError(
                    "DIGEST_MISMATCH",
                    f"{version} build staged input alias conflicts with the "
                    f"case config: {alias}",
                )
        if set(staged) != set(expected_staged):
            missing = sorted(set(expected_staged) - set(staged))
            extra = sorted(set(staged) - set(expected_staged))
            raise BundleError(
                "DIGEST_MISMATCH",
                f"{version} build staged materials do not match the plan; "
                f"missing={missing} extra={extra}",
            )
        for relative, digest in expected_staged.items():
            if staged.get(relative) != digest:
                raise BundleError(
                    "DIGEST_MISMATCH",
                    f"{version} build staged material does not match plan: "
                    f"{relative}",
                )
        if list(build.get("compile_args") or []) != expected_compile_args:
            raise BundleError(
                "INVALID_MANIFEST",
                f"{version} compile args do not match the reviewed recipe",
            )
        _require_untruncated(
            build.get("log_truncated"),
            allowed=truncation_allowed,
            label=f"{version} build log",
        )
        files = _mapping(build.get("files"), f"{version} build files")
        digests = _mapping(build.get("file_digests"), f"{version} build digests")
        _require_path_suffix(files.get("log"), "/build.log", f"{version} build log")
        _require_path_suffix(
            files.get("artifact"), "/parser", f"{version} build artifact"
        )
        log_path = _build_evidence_path(version, "build.log")
        artifact_path = _build_evidence_path(version, "parser")
        log = data[log_path]
        artifact = data[artifact_path]
        if _digest(log) != build.get("log_digest"):
            raise BundleError(
                "DIGEST_MISMATCH", f"{version} build log digest does not match"
            )
        if _digest(artifact) != build.get("artifact_digest"):
            raise BundleError(
                "DIGEST_MISMATCH", f"{version} build artifact digest does not match"
            )
        if digests.get("log") != _digest(log):
            raise BundleError(
                "DIGEST_MISMATCH", f"{version} build file_digests.log does not match"
            )
        if digests.get("artifact") != _digest(artifact):
            raise BundleError(
                "DIGEST_MISMATCH",
                f"{version} build file_digests.artifact does not match",
            )
        metadata = _parse_json_file(
            data, _build_evidence_path(version, "metadata.json")
        )
        if dict(metadata) != dict(build):
            raise BundleError(
                "INVALID_MANIFEST",
                f"{version} build metadata does not match report.builds",
            )
    if seen != set(_REPLAY_VERSIONS):
        raise BundleError(
            "INVALID_MANIFEST", "report builds do not cover both versions"
        )


def _verify_replays(
    plan: Mapping[str, Any],
    verdict: str,
    report: Mapping[str, Any],
    data: Mapping[str, bytes],
    *,
    job_id: str,
    plan_digest: str,
) -> dict[tuple[str, str], dict[str, Any]]:
    replays = report.get("replays")
    if not isinstance(replays, list):
        raise BundleError("INVALID_MANIFEST", "report replays must be a list")
    builds = report.get("builds")
    build_artifacts = (
        {
            build.get("version"): build.get("artifact_digest")
            for build in builds
            if isinstance(build, Mapping)
        }
        if isinstance(builds, list)
        else {}
    )
    truncation_allowed = _truncation_allowed(verdict, report)
    observations: dict[tuple[str, str], dict[str, Any]] = {}
    for item in replays:
        if not isinstance(item, Mapping):
            raise BundleError("INVALID_MANIFEST", "report replay must be an object")
        version = item.get("version")
        phase = item.get("phase")
        if version not in _REPLAY_VERSIONS or phase not in _REPLAY_PHASES:
            raise BundleError(
                "INVALID_MANIFEST",
                f"report replay has an unknown version/phase: {version}/{phase}",
            )
        key = (version, phase)
        if key in observations:
            raise BundleError(
                "INVALID_MANIFEST",
                f"report contains a duplicate replay: {version}/{phase}",
            )
        status = item.get("status")
        if not isinstance(status, str) or not replay_status_allowed(verdict, status):
            raise BundleError(
                "INVALID_MANIFEST",
                f"replay {version}/{phase} has a status {status!r} that is not "
                f"allowed for verdict {verdict}",
            )
        exit_code = item.get("exit_code")
        if exit_code is not None and type(exit_code) is not int:
            raise BundleError(
                "INVALID_MANIFEST",
                f"replay {version}/{phase} exit_code must be an integer or null",
            )
        if status == "completed" and type(exit_code) is not int:
            raise BundleError(
                "INVALID_MANIFEST",
                f"completed replay {version}/{phase} must record an integer exit_code",
            )
        for field in ("stdout_bytes", "stderr_bytes"):
            value = item.get(field)
            if type(value) is not int or value < 0:
                raise BundleError(
                    "INVALID_MANIFEST",
                    f"replay {version}/{phase} {field} must be a "
                    f"non-negative integer",
                )
        if type(item.get("timed_out")) is not bool:
            raise BundleError(
                "INVALID_MANIFEST",
                f"replay {version}/{phase} timed_out must be a boolean",
            )
        if item.get("plan_digest") != plan_digest or item.get("job_id") != job_id:
            raise BundleError(
                "INVALID_MANIFEST",
                f"replay {version}/{phase} provenance does not match",
            )
        if item.get("image_digest") != plan.get("image_digest"):
            raise BundleError(
                "DIGEST_MISMATCH",
                f"replay {version}/{phase} image does not match plan",
            )
        if item.get("asan_options") != plan.get("asan_options"):
            raise BundleError(
                "INVALID_MANIFEST",
                f"replay {version}/{phase} ASan options do not match plan",
            )
        expected_input = (
            plan.get("inputs", {}).get("normal")
            if phase == "normal"
            else plan.get("inputs", {}).get("candidate")
        )
        if item.get("input_digest") != expected_input:
            raise BundleError(
                "DIGEST_MISMATCH",
                f"replay {version}/{phase} input does not match the plan",
            )
        recorded_artifact = item.get("artifact_digest")
        if not isinstance(recorded_artifact, str):
            raise BundleError(
                "INVALID_MANIFEST",
                f"replay {version}/{phase} has no artifact_digest binding",
            )
        if recorded_artifact != build_artifacts.get(version):
            raise BundleError(
                "DIGEST_MISMATCH",
                f"replay {version}/{phase} artifact does not match the "
                f"{version} build",
            )
        _require_untruncated(
            item.get("log_truncated"),
            allowed=truncation_allowed,
            label=f"replay {version}/{phase} log",
        )
        files = _mapping(item.get("files"), f"{version}/{phase} files")
        digests = _mapping(item.get("file_digests"), f"{version}/{phase} digests")
        _require_path_suffix(files.get("stdout"), "/stdout.log", "replay stdout")
        _require_path_suffix(files.get("stderr"), "/stderr.log", "replay stderr")
        stdout = data[_replay_evidence_path(version, phase, "stdout.log")]
        stderr = data[_replay_evidence_path(version, phase, "stderr.log")]
        if item.get("stdout_sha256") != _digest(stdout):
            raise BundleError(
                "DIGEST_MISMATCH",
                f"replay {version}/{phase} stdout digest does not match",
            )
        if item.get("stderr_sha256") != _digest(stderr):
            raise BundleError(
                "DIGEST_MISMATCH",
                f"replay {version}/{phase} stderr digest does not match",
            )
        if item.get("stdout_bytes") != len(stdout):
            raise BundleError(
                "DIGEST_MISMATCH",
                f"replay {version}/{phase} stdout size does not match",
            )
        if item.get("stderr_bytes") != len(stderr):
            raise BundleError(
                "DIGEST_MISMATCH",
                f"replay {version}/{phase} stderr size does not match",
            )
        if digests.get("stdout") != _digest(stdout):
            raise BundleError(
                "DIGEST_MISMATCH",
                f"replay {version}/{phase} file_digests.stdout does not match",
            )
        if digests.get("stderr") != _digest(stderr):
            raise BundleError(
                "DIGEST_MISMATCH",
                f"replay {version}/{phase} file_digests.stderr does not match",
            )
        stderr_text = stderr.decode("utf-8", "replace")
        parsed = parse_asan(stderr_text)
        expected_signature = parsed.as_dict() if parsed else None
        if item.get("signature") != expected_signature:
            raise BundleError(
                "INVALID_MANIFEST",
                f"replay {version}/{phase} signature does not match the raw log",
            )
        if bool(item.get("timed_out")) != (status == "timeout"):
            raise BundleError(
                "INVALID_MANIFEST",
                f"replay {version}/{phase} timeout flag does not match status",
            )
        metadata = _parse_json_file(
            data, _replay_evidence_path(version, phase, "metadata.json")
        )
        if dict(metadata) != dict(item):
            raise BundleError(
                "INVALID_MANIFEST",
                f"replay {version}/{phase} metadata does not match report.replays",
            )
        observations[key] = {
            "status": status,
            "exit_code": item.get("exit_code"),
            "stderr": stderr_text,
            "signature": parsed,
            "stdout": stdout.decode("utf-8", "replace"),
            "log_truncated": bool(item.get("log_truncated")),
        }
    required = {
        (version, phase)
        for version in _REPLAY_VERSIONS
        for phase in _REPLAY_PHASES
    }
    if set(observations) != required:
        missing = sorted(required - set(observations))
        extra = sorted(set(observations) - required)
        raise BundleError(
            "INVALID_MANIFEST",
            "report replays do not match the six required runs; "
            f"missing={missing} extra={extra}",
        )
    return observations


def _exit_code_matches(actual: Any, expected: Any) -> bool:
    """Match planned exit codes with the same strict predicate as verdict.py."""
    return type(expected) is int and type(actual) is int and actual == expected


def _candidate_kind(
    plan: Mapping[str, Any],
    observation: Mapping[str, Any],
    expected_stdout: Mapping[str, str],
) -> str:
    signature = observation.get("signature")
    expected_exit = plan.get("expected_exit") or {}
    if (
        signature is not None
        and signature_matches(signature, plan.get("asan_signature") or {})
        and _exit_code_matches(
            observation.get("exit_code"), expected_exit.get("candidate_asan")
        )
    ):
        return "target_signature"
    if (
        _exit_code_matches(
            observation.get("exit_code"), expected_exit.get("candidate_clean")
        )
        and observation.get("stdout") == expected_stdout.get("candidate_clean")
        and not has_asan_diagnostic(observation.get("stderr"))
    ):
        return "clean"
    return "other"


def _control_mismatch(
    control: Mapping[str, Any],
    expected_exit: Mapping[str, Any],
    expected_stdout: Mapping[str, str],
) -> str | None:
    """Return the first abnormal field for a completed normal control."""
    if control.get("status") != "completed":
        return "status"
    if not _exit_code_matches(control.get("exit_code"), expected_exit.get("normal")):
        return "exit"
    if control.get("stdout") != expected_stdout.get("normal"):
        return "stdout"
    if has_asan_diagnostic(control.get("stderr")):
        return "asan"
    return None


def _require_normal_control(
    version: str,
    control: Mapping[str, Any],
    expected_exit: Mapping[str, Any],
    expected_stdout: Mapping[str, str],
) -> None:
    mismatch = _control_mismatch(control, expected_exit, expected_stdout)
    if mismatch is not None:
        raise BundleError(
            "INVALID_MANIFEST",
            f"{version} normal control does not match the plan ({mismatch})",
        )


def _verify_outcome(
    plan: Mapping[str, Any],
    verdict: str,
    report: Mapping[str, Any],
    observations: Mapping[tuple[str, str], Mapping[str, Any]],
    expected_stdout: Mapping[str, str],
) -> None:
    expected_exit = plan.get("expected_exit") or {}
    reason = report.get("reason_code")
    normal_stdout = expected_stdout.get("normal")
    if not isinstance(normal_stdout, str):
        raise BundleError(
            "INVALID_MANIFEST", "case config has no normal expected stdout"
        )

    if verdict in ("REPRODUCED", "NOT_REPRODUCED"):
        # A positive outcome must never be supported by a degraded control.
        for version in _REPLAY_VERSIONS:
            _require_normal_control(
                version,
                observations[(version, "normal")],
                expected_exit,
                expected_stdout,
            )
    elif reason == "CONTROL_FAILED":
        # CONTROL_FAILED is only meaningful when at least one normal control
        # actually failed on exit, stdout or an ASan diagnostic.
        failed = False
        for version in _REPLAY_VERSIONS:
            control = observations[(version, "normal")]
            mismatch = _control_mismatch(control, expected_exit, expected_stdout)
            if mismatch == "status":
                raise BundleError(
                    "INVALID_MANIFEST",
                    f"{version} normal control did not complete under CONTROL_FAILED",
                )
            if mismatch is not None:
                failed = True
        if not failed:
            raise BundleError(
                "INVALID_MANIFEST",
                "CONTROL_FAILED has no failed normal control",
            )
    elif reason in ("TIMEOUT", "RESOURCE_LIMITED", "EVIDENCE_INCOMPLETE"):
        statuses = {item["status"] for item in observations.values()}
        if reason == "TIMEOUT" and "timeout" not in statuses:
            raise BundleError(
                "INVALID_MANIFEST", "TIMEOUT verdict has no timeout replay"
            )
        if reason == "RESOURCE_LIMITED" and "resource_limited" not in statuses:
            raise BundleError(
                "INVALID_MANIFEST",
                "RESOURCE_LIMITED verdict has no resource-limited replay",
            )
        allowed_noncompleted = {
            "TIMEOUT": frozenset({"timeout"}),
            "RESOURCE_LIMITED": frozenset({"resource_limited"}),
            "EVIDENCE_INCOMPLETE": frozenset(
                {"infra_error", "timeout", "resource_limited"}
            ),
        }[reason]
        truncation_allowed = _truncation_allowed(verdict, report)
        for version in _REPLAY_VERSIONS:
            control = observations[(version, "normal")]
            status = control.get("status")
            if status == "completed":
                # A completed control still has to prove the planned exit.
                if not _exit_code_matches(
                    control.get("exit_code"), expected_exit.get("normal")
                ):
                    raise BundleError(
                        "INVALID_MANIFEST",
                        f"{version} normal control exit does not match",
                    )
                if control.get("log_truncated") and truncation_allowed:
                    # The stream is intentionally incomplete; its digest and
                    # byte count were already checked above.
                    continue
                if control.get("stdout") != normal_stdout:
                    raise BundleError(
                        "INVALID_MANIFEST",
                        f"{version} normal control stdout does not match",
                    )
                if has_asan_diagnostic(control.get("stderr")):
                    raise BundleError(
                        "INVALID_MANIFEST",
                        f"{version} normal control emitted an ASan diagnostic",
                    )
            elif status not in allowed_noncompleted:
                raise BundleError(
                    "INVALID_MANIFEST",
                    f"{version} normal control status {status!r} is not "
                    f"allowed for {reason}",
                )
    else:
        for version in _REPLAY_VERSIONS:
            _require_normal_control(
                version,
                observations[(version, "normal")],
                expected_exit,
                expected_stdout,
            )

    if verdict == "REPRODUCED":
        # The rule engine only classifies target_signature with an integer
        # planned candidate exit code. A plan without one can never support a
        # REPRODUCED verdict, even when an ASan log and a null exit code line
        # up by accident.
        if type(expected_exit.get("candidate_asan")) is not int:
            raise BundleError(
                "INVALID_MANIFEST",
                "REPRODUCED requires an integer planned candidate ASan exit code",
            )
        for version in _REPLAY_VERSIONS:
            for phase in _CANDIDATE_PHASES:
                kind = _candidate_kind(
                    plan, observations[(version, phase)], expected_stdout
                )
                if version == "vulnerable" and kind != "target_signature":
                    raise BundleError(
                        "INVALID_MANIFEST",
                        f"vulnerable {phase} is not the reviewed ASan hit",
                    )
                if version == "fixed" and kind != "clean":
                    raise BundleError(
                        "INVALID_MANIFEST",
                        f"fixed {phase} is not clean",
                    )
        return
    if verdict == "NOT_REPRODUCED":
        for version in _REPLAY_VERSIONS:
            for phase in _CANDIDATE_PHASES:
                if _candidate_kind(
                    plan, observations[(version, phase)], expected_stdout
                ) != "clean":
                    raise BundleError(
                        "INVALID_MANIFEST",
                        f"{version} {phase} is not a clean candidate run",
                    )
        return


def _expected_stdout_from_case_config(
    case_config: Mapping[str, Any],
) -> Mapping[str, str]:
    manifest_case = _mapping(
        case_config.get("manifest_case"), "case_config.manifest_case"
    )
    expected = _mapping(
        manifest_case.get("expected_stdout"),
        "case_config.manifest_case.expected_stdout",
    )
    for key in ("normal", "candidate_clean"):
        if not isinstance(expected.get(key), str):
            raise BundleError(
                "INVALID_MANIFEST",
                f"case config expected stdout assertion {key} is missing",
            )
    return expected



def _verify_semantics(
    *,
    job_id: str,
    plan_digest: str,
    verdict: str,
    manifest_reason: str | None,
    listed: Mapping[str, Mapping[str, Any]],
    data: Mapping[str, bytes],
) -> None:
    """Cross-check the manifest against the plan, review and report content.

    The manifest digest only proves internal byte consistency. This step
    re-derives the plan digest and requires an approved review, a consistent
    report and (for outcome verdicts) the complete execution evidence tree.
    """
    report = _parse_json_file(data, "report.json")
    if report.get("job_id") != job_id:
        raise BundleError("INVALID_MANIFEST", "report job_id does not match manifest")
    if report.get("plan_digest") != plan_digest:
        raise BundleError(
            "INVALID_MANIFEST", "report plan_digest does not match manifest"
        )
    report_verdict = report.get("verdict")
    if report_verdict not in _VERDICTS:
        raise BundleError("INVALID_MANIFEST", "report verdict must be a known value")
    if report_verdict != verdict:
        raise BundleError(
            "INVALID_MANIFEST", "manifest verdict does not match report verdict"
        )
    report_reason = _reason_code_valid(report)
    if manifest_reason != report_reason:
        raise BundleError(
            "INVALID_MANIFEST", "manifest reason_code does not match report"
        )
    rule = report.get("rule")
    if rule is not None and not isinstance(rule, Mapping):
        raise BundleError(
            "INVALID_MANIFEST", "report rule trace must be an object or null"
        )
    if rule is None:
        if report_verdict in ("REPRODUCED", "NOT_REPRODUCED"):
            raise BundleError(
                "INVALID_MANIFEST",
                "report rule trace is required for outcome verdicts",
            )
    elif (
        rule.get("verdict") != report_verdict
        or rule.get("reason_code") != report_reason
    ):
        raise BundleError(
            "INVALID_MANIFEST", "report rule trace does not match report verdict"
        )
    if verdict in _FULL_EVIDENCE_VERDICTS:
        if report_reason is None or not reason_allowed(verdict, report_reason):
            raise BundleError(
                "INVALID_MANIFEST",
                f"reason_code {report_reason!r} is not allowed for {verdict}",
            )
    elif report_reason is not None and not reason_allowed(verdict, report_reason):
        raise BundleError(
            "INVALID_MANIFEST",
            f"reason_code {report_reason!r} is not allowed for {verdict}",
        )

    plan = _parse_json_file(data, "plan.json")
    try:
        computed_plan_digest = contracts.plan_digest(plan)
    except (KeyError, TypeError, ValueError, UnicodeError) as error:
        raise BundleError(
            "INVALID_MANIFEST", f"plan.json cannot be validated: {error}"
        ) from error
    if computed_plan_digest != plan_digest:
        raise BundleError(
            "INVALID_MANIFEST",
            "plan.json content does not match the manifest plan_digest",
        )

    review = _parse_json_file(data, "review.json")
    if review.get("decision") != "approve":
        raise BundleError(
            "INVALID_MANIFEST", "review.json must record an approve decision"
        )
    if review.get("plan_digest") != plan_digest:
        raise BundleError(
            "INVALID_MANIFEST", "review.json is bound to a different plan"
        )

    if verdict not in _FULL_EVIDENCE_VERDICTS:
        return

    expected: dict[str, frozenset[str]] = {
        "metadata/execution.json": frozenset({"execution_metadata"}),
        "metadata/probe.json": frozenset({"probe"}),
        "metadata/case.json": frozenset({"case_config"}),
    }
    for version in _REPLAY_VERSIONS:
        expected[f"build/{version}/build.log"] = frozenset({"build_log"})
        expected[f"build/{version}/parser"] = frozenset({"build_artifact"})
        expected[f"build/{version}/metadata.json"] = frozenset({"build_metadata"})
        for phase in _REPLAY_PHASES:
            directory = f"replay/{version}/{phase}"
            expected[f"{directory}/stdout.log"] = frozenset(
                {"replay_stdout", "normal_output"}
            )
            expected[f"{directory}/stderr.log"] = frozenset(
                {"asan_log", "replay_stderr", "normal_error"}
            )
            expected[f"{directory}/metadata.json"] = frozenset(
                {"replay_metadata"}
            )
    _require_evidence_roles(listed, expected)
    execution_metadata = _parse_json_file(data, "metadata/execution.json")
    if (
        execution_metadata.get("job_id") != job_id
        or execution_metadata.get("plan_digest") != plan_digest
    ):
        raise BundleError(
            "INVALID_MANIFEST",
            "execution metadata does not match manifest job_id/plan_digest",
        )
    probe = _parse_json_file(data, "metadata/probe.json")
    if probe.get("status") != "completed":
        raise BundleError(
            "INVALID_MANIFEST",
            "probe metadata does not record a completed isolation probe",
        )
    for field in ("job_id", "plan_digest"):
        if probe.get(field) != execution_metadata.get(field):
            raise BundleError(
                "INVALID_MANIFEST",
                f"probe metadata {field} does not match execution metadata",
            )
    # A completed probe is only evidence of the approved environment if every
    # observed control is bound to the frozen plan. A probe that merely ran is
    # not enough: image, resource limits and the security checks must match.
    probe_image = probe.get("image_digest")
    if probe_image != plan.get("image_digest"):
        raise BundleError(
            "DIGEST_MISMATCH",
            "probe metadata image_digest does not match the plan",
        )
    probe_limits = probe.get("limits")
    if not isinstance(probe_limits, Mapping) or set(probe_limits) != set(
        _PROBE_LIMIT_FIELDS
    ):
        raise BundleError(
            "INVALID_MANIFEST",
            "probe metadata limits must contain exactly "
            + ", ".join(_PROBE_LIMIT_FIELDS),
        )
    plan_limits = plan.get("limits")
    if not isinstance(plan_limits, Mapping):
        raise BundleError("INVALID_MANIFEST", "plan limits are missing")
    for field in _PROBE_LIMIT_FIELDS:
        if (
            type(probe_limits[field]) is not int
            or probe_limits[field] != plan_limits.get(field)
        ):
            raise BundleError(
                "INVALID_MANIFEST",
                f"probe metadata limit {field} does not match the plan",
            )
    probe_checks = probe.get("checks")
    if not isinstance(probe_checks, Mapping) or not probe_checks:
        raise BundleError(
            "INVALID_MANIFEST", "probe metadata checks must be a non-empty object"
        )
    missing_checks = [
        field for field in _PROBE_CHECK_FIELDS if field not in probe_checks
    ]
    if missing_checks:
        raise BundleError(
            "INVALID_MANIFEST",
            "probe metadata is missing security checks: "
            + ", ".join(missing_checks),
        )
    if "errors" in probe_checks and probe_checks["errors"] != []:
        raise BundleError(
            "INVALID_MANIFEST",
            "probe metadata records failed security checks",
        )
    plan_isolation = plan.get("isolation")
    if not isinstance(plan_isolation, Mapping):
        raise BundleError("INVALID_MANIFEST", "plan isolation is missing")
    expected_uid = str(plan_isolation.get("user", "")).split(":")[0]
    if probe_checks["uid"] != expected_uid:
        raise BundleError(
            "INVALID_MANIFEST", "probe metadata uid does not match the plan"
        )
    if probe_checks["seccomp"] != "2":
        raise BundleError(
            "INVALID_MANIFEST", "probe metadata seccomp mode is not enabled"
        )
    if probe_checks["no_new_privs"] != "1":
        raise BundleError(
            "INVALID_MANIFEST",
            "probe metadata no_new_privs is not effective",
        )
    try:
        effective_capabilities = int(str(probe_checks["cap_eff"]), 16)
    except (TypeError, ValueError) as error:
        raise BundleError(
            "INVALID_MANIFEST",
            "probe metadata cap_eff is not a hexadecimal value",
        ) from error
    if effective_capabilities != 0:
        raise BundleError(
            "INVALID_MANIFEST", "probe metadata cap_eff is not empty"
        )
    if str(probe_checks["cgroup_version"]) not in ("1", "2"):
        raise BundleError(
            "INVALID_MANIFEST", "probe metadata cgroup_version is not supported"
        )
    if (
        "probe" in execution_metadata
        and execution_metadata["probe"] is not None
        and execution_metadata["probe"] != probe
    ):
        raise BundleError(
            "INVALID_MANIFEST",
            "execution metadata probe does not match metadata/probe.json",
        )

    report_repository = report.get("repository")
    if report_repository != plan.get("repository"):
        raise BundleError(
            "INVALID_MANIFEST", "report repository does not match the plan"
        )
    if report.get("versions") != plan.get("revisions"):
        raise BundleError(
            "INVALID_MANIFEST", "report revisions do not match the plan"
        )
    if report.get("inputs") != plan.get("inputs"):
        raise BundleError("INVALID_MANIFEST", "report inputs do not match the plan")
    if report.get("signature") != plan.get("asan_signature"):
        raise BundleError(
            "INVALID_MANIFEST", "report signature does not match the plan"
        )
    environment = _mapping(report.get("environment"), "report environment")
    if environment.get("image_digest") != plan.get("image_digest"):
        raise BundleError(
            "INVALID_MANIFEST", "report environment image does not match the plan"
        )
    if environment.get("platform") != plan.get("platform"):
        raise BundleError(
            "INVALID_MANIFEST", "report environment platform does not match the plan"
        )
    if environment.get("toolchain") != plan.get("toolchain"):
        raise BundleError(
            "INVALID_MANIFEST", "report environment toolchain does not match the plan"
        )
    if environment.get("asan_options") != plan.get("asan_options"):
        raise BundleError(
            "INVALID_MANIFEST", "report environment ASan options do not match the plan"
        )
    if environment.get("isolation") != plan.get("isolation"):
        raise BundleError(
            "INVALID_MANIFEST",
            "report environment isolation does not match the plan",
        )

    case_config, materials, recipe = _case_binding(plan, listed, data)
    expected_stdout = _expected_stdout_from_case_config(case_config)
    _verify_materials(plan, listed, data, case_config, materials)
    expected_compile_args = _compile_args_from_recipe(recipe)
    if list(environment.get("compile_args") or []) != expected_compile_args:
        raise BundleError(
            "INVALID_MANIFEST",
            "report environment compile args do not match the reviewed recipe",
        )
    _verify_builds(
        plan,
        verdict,
        report,
        data,
        expected_compile_args,
        job_id=job_id,
        plan_digest=plan_digest,
        materials=materials,
    )
    observations = _verify_replays(
        plan, verdict, report, data, job_id=job_id, plan_digest=plan_digest
    )
    _verify_outcome(plan, verdict, report, observations, expected_stdout)


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

    manifest, manifest_bytes = _load_manifest(root_path)
    job_id, plan_digest, files, verdict, manifest_reason = _validate_manifest_header(
        manifest
    )
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
    entries_seen = 0
    for current_root, directories, filenames in os.walk(root_path, followlinks=False):
        current = Path(current_root)
        # Count directories and files as we descend. A tree crafted with
        # thousands of empty directories must fail before the walk finishes,
        # not after every entry has been enumerated.
        entries_seen += len(directories) + len(filenames)
        if entries_seen > MAX_BUNDLE_ENTRIES:
            raise BundleError(
                "INVALID_MANIFEST",
                f"bundle contains more than {MAX_BUNDLE_ENTRIES} directory entries",
            )
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

    if sum(entry["size_bytes"] for entry in listed.values()) > MAX_TOTAL_BYTES:
        raise BundleError(
            "FILE_TOO_LARGE", "bundle exceeds the total evidence size cap"
        )

    data: dict[str, bytes] = {}
    total = 0
    for relative, entry in listed.items():
        path = actual[relative]
        # Stat again immediately before reading. The os.walk pass happened
        # earlier, so a file could have been replaced with a symlink or grown
        # past the manifest's declaration in the meantime.
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode):
            raise BundleError(
                "INVALID_MANIFEST", f"evidence is not a regular file: {relative}"
            )
        if info.st_size != entry["size_bytes"]:
            raise BundleError("DIGEST_MISMATCH", f"size mismatch for {relative}")
        if info.st_size > MAX_FILE_BYTES:
            raise BundleError("FILE_TOO_LARGE", f"file is too large: {relative}")
        total += info.st_size
        if total > MAX_TOTAL_BYTES:
            raise BundleError(
                "FILE_TOO_LARGE", "bundle exceeds the total evidence size cap"
            )
        content = _read_bounded(path, expected_size=entry["size_bytes"])
        if len(content) != entry["size_bytes"]:
            raise BundleError("DIGEST_MISMATCH", f"size mismatch for {relative}")
        if _sha256(content) != entry["sha256"]:
            raise BundleError("DIGEST_MISMATCH", f"sha256 mismatch for {relative}")
        data[relative] = content

    _verify_semantics(
        job_id=job_id,
        plan_digest=plan_digest,
        verdict=verdict,
        manifest_reason=manifest_reason,
        listed=listed,
        data=data,
    )

    return BundleVerification(
        root=root_path,
        manifest=manifest,
        manifest_digest=canonical_manifest_digest(manifest),
        manifest_bytes=manifest_bytes,
        file_data=data,
    )


def _confirm_source_manifest(root: Path, expected_digest: str) -> None:
    """Re-read the source manifest immediately before copying.

    ``export_bundle`` copies from the verified in-memory data, but the source
    manifest is the identity of the bundle. If the source directory was
    replaced after verification the copied bytes would belong to a different
    bundle, so the identity is confirmed again before any output is written.
    """
    manifest, _ = _load_manifest(root)
    if canonical_manifest_digest(manifest) != expected_digest:
        raise BundleError(
            "DIGEST_MISMATCH",
            "the source manifest changed after verification",
        )


def export_bundle(
    source: Path | str,
    destination: Path | str,
    *,
    expected_manifest_digest: str | None = None,
) -> BundleInfo:
    """Copy a verified bundle to a new directory, verifying the copy."""
    if expected_manifest_digest is not None and not _DIGEST.fullmatch(
        expected_manifest_digest
    ):
        raise BundleError("INVALID_MANIFEST", "expected manifest digest is invalid")
    verified = verify_bundle(source)
    if (
        expected_manifest_digest is not None
        and verified.manifest_digest != expected_manifest_digest
    ):
        raise BundleError(
            "DIGEST_MISMATCH",
            "the archived bundle digest does not match the trusted task record",
        )
    _confirm_source_manifest(verified.root, verified.manifest_digest)

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
    temporary_resolved = temporary.resolve()
    try:
        for relative in sorted(verified.file_data):
            if relative == "manifest.json":
                raise BundleError(
                    "INVALID_MANIFEST", "manifest must not be copied as an artifact"
                )
            output = temporary / PurePosixPath(relative)
            output.parent.mkdir(parents=True, exist_ok=True)
            if output.is_symlink():
                raise BundleError("SYMLINK", "export output path is a symlink")
            try:
                resolved_output = output.resolve(strict=False)
            except OSError as error:
                raise BundleError("UNSAFE_PATH", str(error)) from error
            if (
                resolved_output != temporary_resolved
                and temporary_resolved not in resolved_output.parents
            ):
                raise BundleError(
                    "UNSAFE_PATH", f"export path escapes the bundle: {relative}"
                )
            output.write_bytes(verified.file_data[relative])
            output.chmod(0o600)
        # Copy the exact bytes that were verified and hashed, never a reread
        # from the mutable source directory.
        (temporary / "manifest.json").write_bytes(verified.manifest_bytes)
        (temporary / "manifest.json").chmod(0o600)
        copied = verify_bundle(temporary)
        if copied.manifest_digest != verified.manifest_digest:
            raise BundleError("DIGEST_MISMATCH", "exported manifest digest changed")
        if expected_manifest_digest is not None and (
            copied.manifest_digest != expected_manifest_digest
        ):
            raise BundleError(
                "DIGEST_MISMATCH",
                "exported manifest digest does not match the trusted task record",
            )
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

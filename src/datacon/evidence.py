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
import os
from pathlib import Path, PurePosixPath
import posixpath
import re
import shlex
import shutil
import stat
import uuid
from typing import Any, Callable, Mapping, Sequence

from datacon import build_provenance, contracts, fileio, jsonutil
from datacon.asan import has_asan_diagnostic, parse_asan, signature_matches
from datacon.verdict import (
    RunObservation,
    VerdictPolicy,
    decide_verdict,
    reason_allowed,
    reason_allowed_v2,
    replay_status_allowed,
)

SCHEMA_VERSION = 1
MAX_MANIFEST_BYTES = 4 * 1024 * 1024
MAX_FILE_BYTES = 128 * 1024 * 1024
# A bundle is bounded per file and in aggregate, so a manifest cannot make an
# offline verifier allocate MAX_FILES * MAX_FILE_BYTES.
MAX_TOTAL_BYTES = 256 * 1024 * 1024
MAX_FILES = 4096
# Directories are budgeted separately from regular files. A legitimate bundle
# may need many helper directories (one per build/replay phase), so charging
# directories against the file allowance would reject a valid 4096-file
# bundle. The total cap still lets the scan abort before enumerating a
# pathological flat tree.
MAX_DIRECTORIES = 1024
MAX_BUNDLE_ENTRIES = MAX_FILES + MAX_DIRECTORIES + 1  # + manifest.json
MAX_ROLE_LENGTH = 64

_SHA256_HEX = re.compile(r"[0-9a-f]{64}")
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
_REQUIRED_ROLES = frozenset(
    {"report_json", "report_markdown", "plan", "review"}
)
# A role alone is not enough: each base document must exist at its fixed path
# with the matching role so replacing report.md with a differently named file
# cannot satisfy the bundle contract.
_REQUIRED_PATHS = {
    "report.json": "report_json",
    "report.md": "report_markdown",
    "plan.json": "plan",
    "review.json": "review",
}
# A blocked bundle is produced before an execution plan exists (submit-time
# rejection, analysis failure) or before execution starts (review rejection or
# expiry). It still carries the two report documents, but plan.json and
# review.json are stage-dependent: the review window may close without a
# decision, and preparation may block before a plan is frozen.
_BLOCKED_REQUIRED_ROLES = frozenset({"report_json", "report_markdown"})
_BLOCKED_REQUIRED_PATHS = {
    "report.json": "report_json",
    "report.md": "report_markdown",
}
_BUNDLE_KINDS = frozenset({"execution", "blocked"})
# v2 adds campaign as a third archive shape. ``family`` is deliberately absent:
# a family index is not a bundle and must never be accepted by verify_bundle.
_V2_BUNDLE_KINDS = frozenset({"execution", "blocked", "campaign"})
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
        "material_repository_bundle",
        "material_advisory",
        "case_config",
        "symbolizer_log",
    }
)
# The v2 verifier accepts the frozen v0.1 role set plus the roles archived by
# the v0.2 execution, campaign and policy paths. The table is additive: every
# v1 bundle keeps verifying with the v1 branch, and a v2 bundle may carry any
# role from either generation.
_V2_ROLE_NAMES = _ROLE_NAMES | frozenset(
    {
        "envelope",
        "budget_snapshot",
        "build_provenance",
        "admission",
        "budget_ledger",
        "budget_charge",
        "experiment_spec",
        "model_audit",
        "fuzz_log",
        "crash_seed",
        "fuzz_provenance",
        "intel_snapshot",
        "license_record",
    }
)
# Public alias used by contract tests and later v2 producers. Keep the private
# name as well so existing internal imports do not change.
V2_ROLE_NAMES = _V2_ROLE_NAMES
# Roles a v2 bundle must carry today. T13 activates ``build_provenance`` as a
# mandatory role for full v2 execution and campaign bundles; roles introduced
# for T14/T15 (model_audit, intel_snapshot, license_record) are accepted by
# _V2_ROLE_NAMES until their producers land.
# crash_seed is conditionally required only when a campaign records at least
# one candidate seed; a zero-crash campaign legitimately has none
# (enforced in ``_verify_v2_campaign_crash_seeds`` rather than the unconditional
# role table so ``test_campaign_bundle_allows_zero_crash_seed`` passes).
_V2_EXECUTION_REQUIRED_ROLES = frozenset(
    {
        "report_json",
        "report_markdown",
        "plan",
        "envelope",
        "budget_snapshot",
        "execution_metadata",
        "probe",
        "case_config",
        "build_metadata",
        "build_log",
        "build_artifact",
        "build_provenance",
        "normal_output",
        "normal_error",
        "asan_log",
        "replay_stdout",
        # ``replay_stderr`` remains an allowed v0.1 role but the fixed
        # 18-file replay layout uses ``asan_log`` for candidate stderr.
        "replay_metadata",
    }
)
_V2_CAMPAIGN_REQUIRED_ROLES = frozenset(
    {
        "report_json",
        "report_markdown",
        "plan",
        "review",
        "envelope",
        "budget_snapshot",
        "execution_metadata",
        "probe",
        "case_config",
        "build_metadata",
        "build_log",
        "build_artifact",
        "build_provenance",
        "fuzz_log",
        "fuzz_provenance",
    }
)
_V2_REQUIRED_ROLES = {
    "execution": _V2_EXECUTION_REQUIRED_ROLES,
    "blocked": _BLOCKED_REQUIRED_ROLES,
    "campaign": _V2_CAMPAIGN_REQUIRED_ROLES,
}
_V2_REQUIRED_PATHS = {
    "execution": {
        "report.json": "report_json",
        "report.md": "report_markdown",
        "plan.json": "plan",
        "envelope.json": "envelope",
        "budget/snapshot.json": "budget_snapshot",
    },
    "campaign": {
        "report.json": "report_json",
        "report.md": "report_markdown",
        "plan.json": "plan",
        "review.json": "review",
        "envelope.json": "envelope",
        "budget/snapshot.json": "budget_snapshot",
    },
}
# A FAILED or pre-rule INCONCLUSIVE execution bundle is allowed to archive
# only the evidence that was actually produced. It still carries the fixed
# documents needed to interpret the partial run, but build/replay roles are
# required only when their paths exist (and are always validated when they do).
# This is deliberately narrower than the full execution role table: a complete
# REPRODUCED/NOT_REPRODUCED/rule-backed INCONCLUSIVE bundle keeps the strict
# table, and empty replay/build files never satisfy the partial layout.
_V2_PARTIAL_EXECUTION_REQUIRED_ROLES = frozenset(
    {
        "report_json",
        "report_markdown",
        "plan",
        "envelope",
        "budget_snapshot",
        "execution_metadata",
        "case_config",
    }
)
_V2_PARTIAL_EXECUTION_REQUIRED_PATHS = {
    "report.json": "report_json",
    "report.md": "report_markdown",
    "plan.json": "plan",
    "envelope.json": "envelope",
    "budget/snapshot.json": "budget_snapshot",
    "metadata/execution.json": "execution_metadata",
    "metadata/case.json": "case_config",
}
# Pre-rule INCONCLUSIVE reasons that can legitimately occur before a complete
# 6-replay verdict decision. Rule-backed 6-replay reasons (CONTROL_FAILED,
# FIXED_STILL_VULNERABLE, INTERMITTENT, OTHER_CRASH, VERDICT_UNCLASSIFIED)
# must always carry the complete execution layout.
_V2_PARTIAL_INCONCLUSIVE_REASONS = frozenset(
    {
        "BUDGET_EXHAUSTED",
        "EVIDENCE_INCOMPLETE",
        "NOT_COMPARABLE",
        "RESOURCE_LIMITED",
        "RUN_INCOMPLETE",
        "TIMEOUT",
    }
)
_ENTRY_FIELDS = frozenset({"path", "role", "size_bytes", "sha256"})
# Closed top-level key set for Manifest v2 (§8 / §12.5). Blocked bundles may
# omit nullable identity keys (§12.2), but unknown top-level keys are always
# rejected. TODO(T12/T13): a new manifest field (for example execution_kind)
# must be added here in the same change as its writer/verifier; otherwise the
# verifier would reject every bundle that carries it.
_V2_MANIFEST_FIELDS = frozenset(
    {
        "schema_version",
        "bundle_kind",
        "job_id",
        "family_id",
        "parent_job_id",
        "round_no",
        "plan_digest",
        "envelope_digest",
        "experiment_digest",
        "build_provenance_rules_version",
        "verdict",
        "reason_code",
        "created_at",
        "build_ref",
        "reuse_origin",
        "files",
    }
)
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
# report.md is a rendering of report.json, not an independent conclusion.
# These patterns are intentionally anchored: a missing line, a second line,
# differing case/spacing, or any extra decoration around the value fails
# closed instead of being "close enough".
_REPORT_VERDICT_LINE = re.compile(
    r"^- Verdict: \*\*(?P<verdict>[A-Z_]+|PENDING)\*\*$"
)
_REPORT_REASON_LINE = re.compile(r"^- Reason: `(?P<reason>[A-Z0-9_]*)`$")


class BundleError(RuntimeError):
    """A bundle violates the evidence contract."""

    def __init__(self, reason_code: str, message: str):
        super().__init__(message)
        self.reason_code = reason_code
        self.message = message


class EvidenceRefError(BundleError):
    """A v2 log evidence reference cannot be resolved from bundle bytes.

    ``reason_code`` is one of ``INVALID_REFERENCE`` (malformed/unsupported
    syntax or non-UTF-8 log), ``MISSING_LOG`` (manifest role/path missing or
    ambiguous), ``DIGEST_MISMATCH`` (bytes changed after the manifest was
    signed) or ``LINE_OUT_OF_RANGE`` (start/end outside the 1-based line
    count).
    """


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


def _entry(
    path: str,
    role: str,
    data: bytes,
    *,
    role_names: frozenset[str] = _ROLE_NAMES,
) -> dict[str, Any]:
    if role not in role_names:
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


def _map_unsafe_file_error(
    error: fileio.UnsafeFileError, label: Path | str
) -> BundleError:
    if error.kind == "SYMLINK":
        return BundleError("SYMLINK", f"file is a symlink: {label}")
    if error.kind == "NOT_REGULAR":
        return BundleError(
            "INVALID_MANIFEST", f"file is not a regular file: {label}"
        )
    if error.kind in ("TOO_LARGE", "CHANGED"):
        return BundleError(
            "DIGEST_MISMATCH", f"file changed while reading: {label}"
        )
    return BundleError("MISSING_FILE", f"file is not readable: {label}")


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
        raise _map_unsafe_file_error(error, path) from error


def _read_bounded_under_root(
    root: Path, relative_path: str, *, expected_size: int
) -> bytes:
    """Read a bundle file step-by-step from ``root`` without following symlinks."""
    try:
        return fileio.read_regular_file_under_root_bounded(
            root, relative_path, max_bytes=expected_size
        )
    except fileio.UnsafeFileError as error:
        raise _map_unsafe_file_error(error, root / PurePosixPath(relative_path)) from error


def _apply_bundle_modes(
    root: Path, *, dir_mode: int, file_mode: int
) -> None:
    """Apply explicit directory/file permissions bottom-up, overriding process umask."""
    for directory in sorted(
        (item for item in root.rglob("*") if item.is_dir() and not item.is_symlink()),
        key=lambda item: len(item.parts),
        reverse=True,
    ):
        directory.chmod(dir_mode)
    for item in root.rglob("*"):
        if item.is_file() and not item.is_symlink():
            item.chmod(file_mode)
    root.chmod(dir_mode)


def write_bundle(
    root: Path | str,
    *,
    job_id: str | uuid.UUID,
    plan_digest: str | None,
    report: Mapping[str, Any],
    report_markdown: str,
    artifacts: Mapping[str, tuple[str, bytes | bytearray | memoryview | Path | str]] | None = None,
    verdict: str | None = None,
    created_at: str | None = None,
    bundle_kind: str = "execution",
    verify: Callable[[Path], object] | None = None,
    dir_mode: int = 0o755,
    file_mode: int = 0o644,
    schema_version: int = SCHEMA_VERSION,
) -> BundleInfo:
    """Create a new bundle directory and its manifest.

    The caller supplies role-labelled artifacts. report.json and report.md are
    added by this function. The directory must not already exist.

    ``bundle_kind`` is ``execution`` for the full evidence tree produced by an
    execution attempt and ``blocked`` for a terminal non-execution block. An
    execution bundle keeps every historical invariant (plan, approved review,
    full file hashes). A blocked bundle may omit the plan and review, but it
    must still bind the report, every file hash and a safe path.
    """
    job_text = str(uuid.UUID(str(job_id)))
    if not isinstance(bundle_kind, str) or bundle_kind not in _BUNDLE_KINDS:
        raise BundleError("INVALID_MANIFEST", "bundle_kind is invalid")
    if type(schema_version) is not int or schema_version not in (1, 2):
        raise BundleError("INVALID_MANIFEST", "evidence schema_version is invalid")
    if schema_version == 2 and bundle_kind != "blocked":
        # T10 only needs the v2 blocked archive path (review expiry/rejection
        # and policy blocks). The execution/campaign writers are later tasks;
        # refusing them here is safer than emitting a manifest missing their
        # required identity fields.
        raise BundleError(
            "INVALID_MANIFEST",
            "the v2 bundle writer currently supports only blocked bundles",
        )
    if plan_digest is not None and (
        not isinstance(plan_digest, str) or not _DIGEST.fullmatch(plan_digest)
    ):
        raise BundleError("INVALID_MANIFEST", "plan digest is invalid")
    if bundle_kind == "execution" and plan_digest is None:
        raise BundleError(
            "INVALID_MANIFEST", "an execution bundle requires a plan digest"
        )
    if not isinstance(report, Mapping):
        raise BundleError("INVALID_MANIFEST", "report must be an object")
    if not isinstance(report_markdown, str):
        raise BundleError("INVALID_MANIFEST", "report markdown must be text")
    if report.get("job_id") != job_text:
        raise BundleError("INVALID_MANIFEST", "report job_id does not match")
    if report.get("plan_digest") != plan_digest:
        raise BundleError("INVALID_MANIFEST", "report plan_digest does not match")
    report_verdict = report.get("verdict")
    if not isinstance(report_verdict, str) or report_verdict not in _VERDICTS:
        raise BundleError("INVALID_MANIFEST", "report verdict must be a known value")
    report_reason = report.get("reason_code")
    if report_reason is not None and (
        not isinstance(report_reason, str)
        or not _REASON_CODE.fullmatch(report_reason)
    ):
        raise BundleError("INVALID_MANIFEST", "report reason_code is invalid")
    if (
        type(report.get("schema_version")) is not int
        or report.get("schema_version") != schema_version
    ):
        raise BundleError(
            "INVALID_MANIFEST", f"report schema_version must be {schema_version}"
        )
    if report.get("state") != report_verdict:
        raise BundleError(
            "INVALID_MANIFEST", "report state must equal report verdict"
        )
    missing = report.get("missing")
    if not isinstance(missing, list) or not all(
        isinstance(item, str) for item in missing
    ):
        raise BundleError("INVALID_MANIFEST", "report missing must be a list of strings")
    error = report.get("error")
    if error is not None and not isinstance(error, str):
        raise BundleError("INVALID_MANIFEST", "report error must be text or null")
    evidence_complete = report.get("evidence_complete")
    if evidence_complete is not None and type(evidence_complete) is not bool:
        raise BundleError(
            "INVALID_MANIFEST", "report evidence_complete must be a boolean"
        )
    if bundle_kind == "blocked":
        # A blocked bundle is a terminal non-execution record. It must not be
        # able to claim an outcome verdict, and a plan digest without the plan
        # document (or vice versa) is an inconsistent bundle.
        if report_verdict != "BLOCKED":
            raise BundleError(
                "INVALID_MANIFEST", "a blocked bundle must record verdict BLOCKED"
            )
        reason_is_allowed = (
            reason_allowed_v2
            if schema_version == contracts.SCHEMA_VERSION_V2
            else reason_allowed
        )
        if report_reason is None or not reason_is_allowed(
            "BLOCKED", report_reason
        ):
            raise BundleError(
                "INVALID_MANIFEST",
                "a blocked bundle requires an allowed BLOCKED reason_code",
            )
        if plan_digest is None and report.get("review") is not None:
            raise BundleError(
                "INVALID_MANIFEST",
                "a review requires a plan digest in a blocked bundle",
            )
        if schema_version == contracts.SCHEMA_VERSION_V2:
            # A v2 blocked report carries the bundle kind and the created_at
            # the verifier binds (§8 report table, §12.2). Read them as
            # required here too so the writer cannot emit a bundle its own
            # strict verifier would reject.
            if report.get("bundle_kind") != "blocked":
                raise BundleError(
                    "INVALID_MANIFEST",
                    "a v2 blocked report requires bundle_kind=blocked",
                )
            try:
                jsonutil.require_rfc3339(
                    report.get("created_at"), "report.created_at"
                )
            except ValueError as invalid_created_at:
                raise BundleError(
                    "INVALID_MANIFEST", str(invalid_created_at)
                ) from invalid_created_at
    if report_verdict in ("REPRODUCED", "NOT_REPRODUCED"):
        if evidence_complete is False:
            raise BundleError(
                "INVALID_MANIFEST",
                "conclusive evidence must not record evidence_complete=false",
            )
        if missing:
            raise BundleError(
                "INVALID_MANIFEST",
                "conclusive evidence must not record missing inputs",
            )
        if error is not None:
            raise BundleError(
                "INVALID_MANIFEST",
                "conclusive evidence must not record an error",
            )

    target = Path(root)
    if target.exists() or target.is_symlink():
        raise BundleError("BUNDLE_EXISTS", "bundle destination already exists")
    parent = target.parent
    parent.mkdir(parents=True, exist_ok=True)
    temporary = parent / f".{target.name}.tmp-{uuid.uuid4().hex}"
    # A possibly pre-existing symlink at the temp name is never followed.
    if temporary.exists() or temporary.is_symlink():
        raise BundleError("BUNDLE_EXISTS", "temporary bundle path already exists")
    temporary.mkdir(mode=dir_mode)
    temporary.chmod(dir_mode)
    try:
        entries: list[dict[str, Any]] = []
        markdown_bytes = report_markdown.encode("utf-8")
        # report.md is a rendering of report.json, not an independent
        # conclusion. Refuse to publish a bundle whose human-readable
        # conclusion disagrees with the machine-readable one, even though the
        # producer could have hashed the divergent markdown consistently.
        _verify_report_markdown(
            markdown_bytes, report_verdict, report_reason
        )
        # Bind the human-readable report to report.json. The manifest digest
        # already covers both files, but an attacker who rewrites the whole
        # bundle (manifest included) would otherwise be free to swap
        # report.md for a different verdict. The digest is written into
        # report.json before it is serialized so the two cannot diverge.
        report_document = dict(report)
        report_document["report_markdown_sha256"] = _sha256(markdown_bytes)
        payloads: dict[str, bytes] = {
            "report.json": jsonutil.canonical_bytes(report_document) + b"\n",
            "report.md": markdown_bytes,
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

        allowed_roles = (
            _V2_ROLE_NAMES
            if schema_version == contracts.SCHEMA_VERSION_V2
            else _ROLE_NAMES
        )
        for path, data in payloads.items():
            destination = temporary / PurePosixPath(path)
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(data)
            destination.chmod(file_mode)
            role = (
                "report_json"
                if path == "report.json"
                else "report_markdown"
                if path == "report.md"
                else artifacts[path][0]  # type: ignore[index]
            )
            entries.append(_entry(path, role, data, role_names=allowed_roles))
        entries.sort(key=lambda item: item["path"])

        roles = {entry["role"] for entry in entries}
        listed = {entry["path"]: entry for entry in entries}
        partial_execution = False
        if schema_version == contracts.SCHEMA_VERSION_V2:
            payload_verdict = (
                verdict if isinstance(verdict, str) else report.get("verdict")
            )
            payload_reason = report.get("reason_code")
            partial_execution = _is_partial_execution(
                bundle_kind,
                payload_verdict,
                payload_reason if isinstance(payload_reason, str) else None,
                report,
                listed,
            )
            required_roles, required_paths = _v2_required_roles_and_paths(
                bundle_kind, partial_execution
            )
        else:
            required_paths = _REQUIRED_PATHS
            required_roles = (
                _REQUIRED_ROLES
                if bundle_kind == "execution"
                else _BLOCKED_REQUIRED_ROLES
            )
        if not required_roles <= roles:
            missing = sorted(required_roles - roles)
            raise BundleError(
                "INVALID_MANIFEST",
                "bundle is missing required roles: " + ", ".join(missing),
            )
        if schema_version == contracts.SCHEMA_VERSION_V2:
            if bundle_kind == "blocked":
                _require_blocked_paths(listed)
                _verify_v2_layout(listed, bundle_kind)
                _validate_blocked_artifacts(
                    payloads, plan_digest=plan_digest, report=report
                )
            else:
                _require_required_paths(listed, required_paths)
                _verify_v2_layout(
                    listed,
                    bundle_kind,
                    partial_execution=partial_execution,
                )
        elif bundle_kind == "execution":
            _require_required_paths(listed, _REQUIRED_PATHS)
        else:
            _require_blocked_paths(listed)
            _validate_blocked_artifacts(
                payloads, plan_digest=plan_digest, report=report
            )

        manifest = {
            "schema_version": schema_version,
            "bundle_kind": bundle_kind,
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
        (temporary / "manifest.json").chmod(file_mode)
        _apply_bundle_modes(temporary, dir_mode=dir_mode, file_mode=file_mode)
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
) -> tuple[str, str, str | None, list[dict[str, Any]], str, str | None]:
    if (
        type(manifest.get("schema_version")) is not int
        or manifest.get("schema_version") != SCHEMA_VERSION
    ):
        raise BundleError("INVALID_MANIFEST", "manifest schema_version must be 1")
    # Old bundles predate bundle_kind. They were all produced by execution, so
    # a missing field keeps the historical (strict) meaning. A present field
    # must be one of the two supported kinds.
    bundle_kind = manifest.get("bundle_kind", "execution")
    if not isinstance(bundle_kind, str) or bundle_kind not in _BUNDLE_KINDS:
        raise BundleError("INVALID_MANIFEST", "manifest bundle_kind is invalid")
    try:
        job_id = str(uuid.UUID(str(manifest.get("job_id"))))
    except (TypeError, ValueError, AttributeError) as error:
        raise BundleError("INVALID_MANIFEST", "manifest job_id must be a UUID") from error
    plan_digest = manifest.get("plan_digest")
    if bundle_kind == "execution":
        if not isinstance(plan_digest, str) or not _DIGEST.fullmatch(plan_digest):
            raise BundleError("INVALID_MANIFEST", "manifest plan_digest is invalid")
    elif plan_digest is not None and (
        not isinstance(plan_digest, str) or not _DIGEST.fullmatch(plan_digest)
    ):
        raise BundleError("INVALID_MANIFEST", "manifest plan_digest is invalid")
    verdict = manifest.get("verdict")
    if not isinstance(verdict, str) or verdict not in _VERDICTS:
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
    return job_id, bundle_kind, plan_digest, files, verdict, reason_code


def _v2_uuid(value: Any, label: str, *, allow_none: bool = False) -> str | None:
    if value is None and allow_none:
        return None
    try:
        return str(uuid.UUID(str(value)))
    except (TypeError, ValueError, AttributeError) as error:
        raise BundleError(
            "INVALID_MANIFEST", f"manifest {label} must be a UUID"
        ) from error


def _v2_digest(value: Any, label: str, *, allow_none: bool = False) -> str | None:
    if value is None and allow_none:
        return None
    if not isinstance(value, str) or not _DIGEST.fullmatch(value):
        raise BundleError(
            "INVALID_MANIFEST", f"manifest {label} must be a sha256 digest"
        )
    return value


def _v2_text(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise BundleError(
            "INVALID_MANIFEST", f"manifest {label} must be a non-empty string"
        )
    return value


def _v2_artifacts(value: Any, label: str) -> dict[str, dict[str, str]]:
    if not isinstance(value, dict) or set(value) != set(_REPLAY_VERSIONS):
        raise BundleError(
            "INVALID_MANIFEST",
            f"{label} must contain exactly vulnerable and fixed",
        )
    result: dict[str, dict[str, str]] = {}
    for version in _REPLAY_VERSIONS:
        artifact = value.get(version)
        if not isinstance(artifact, dict) or set(artifact) != {
            "artifact_digest",
            "build_log_digest",
        }:
            raise BundleError(
                "INVALID_MANIFEST",
                f"{label}.{version} must contain artifact_digest and build_log_digest",
            )
        entry: dict[str, str] = {}
        for field in ("artifact_digest", "build_log_digest"):
            digest = _v2_digest(
                artifact.get(field), f"{label}.{version}.{field}"
            )
            if digest is None:
                raise BundleError(
                    "INVALID_MANIFEST", f"{label}.{version}.{field} is required"
                )
            entry[field] = digest
        result[version] = entry
    return result


def _v2_build_ref(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != {
        "source_job_id",
        "generation",
        "build_inputs_digest",
        "artifacts",
    }:
        raise BundleError(
            "INVALID_MANIFEST", f"{label} has missing or unknown fields"
        )
    generation = value.get("generation")
    if type(generation) is not int or generation < 0:
        raise BundleError(
            "INVALID_MANIFEST", f"{label}.generation must be a non-negative integer"
        )
    return {
        "source_job_id": _v2_uuid(value.get("source_job_id"), f"{label}.source_job_id"),
        "generation": generation,
        "build_inputs_digest": _v2_digest(
            value.get("build_inputs_digest"), f"{label}.build_inputs_digest"
        ),
        "artifacts": _v2_artifacts(value.get("artifacts"), f"{label}.artifacts"),
    }


def _v2_reuse_origin(
    value: Any, label: str, build_ref: Mapping[str, Any]
) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != {
        "source_job_id",
        "generation",
        "campaign_bundle_digest",
        "artifacts",
    }:
        raise BundleError(
            "INVALID_MANIFEST", f"{label} has missing or unknown fields"
        )
    generation = value.get("generation")
    if type(generation) is not int or generation < 0:
        raise BundleError(
            "INVALID_MANIFEST", f"{label}.generation must be a non-negative integer"
        )
    origin = {
        "source_job_id": _v2_uuid(value.get("source_job_id"), f"{label}.source_job_id"),
        "generation": generation,
        "campaign_bundle_digest": _v2_digest(
            value.get("campaign_bundle_digest"), f"{label}.campaign_bundle_digest"
        ),
        "artifacts": _v2_artifacts(value.get("artifacts"), f"{label}.artifacts"),
    }
    if origin["generation"] != build_ref["generation"]:
        raise BundleError(
            "REUSE_MISMATCH",
            "reuse_origin.generation must equal build_ref.generation",
        )
    if origin["source_job_id"] != build_ref["source_job_id"]:
        raise BundleError(
            "REUSE_MISMATCH",
            "reuse_origin.source_job_id must equal build_ref.source_job_id",
        )
    if origin["artifacts"] != build_ref["artifacts"]:
        raise BundleError(
            "REUSE_MISMATCH",
            "reuse_origin.artifacts must equal build_ref.artifacts",
        )
    return origin


def _validate_v2_manifest_header(
    manifest: Mapping[str, Any],
) -> tuple[str, str, str | None, list[dict[str, Any]], str | None, str | None]:
    """Validate the version-2 manifest identity and conditional fields.

    v2 is stricter than v1: the family identity, round shape, envelope,
    provenance rules version, reuse conditions and fixed paths are all part of
    the manifest contract. Semantic replay of report/plan belongs to later
    evidence tasks; this header is the T10/T12 dispatch surface.
    """
    if (
        type(manifest.get("schema_version")) is not int
        or manifest.get("schema_version") != contracts.SCHEMA_VERSION_V2
    ):
        raise BundleError("INVALID_MANIFEST", "manifest schema_version must be 2")
    unknown_fields = sorted(set(manifest) - _V2_MANIFEST_FIELDS)
    if unknown_fields:
        raise BundleError(
            "INVALID_MANIFEST",
            "manifest contains unknown fields: " + ", ".join(unknown_fields),
        )
    bundle_kind = manifest.get("bundle_kind")
    if not isinstance(bundle_kind, str) or bundle_kind not in _V2_BUNDLE_KINDS:
        raise BundleError("INVALID_MANIFEST", "manifest bundle_kind is invalid")
    job_id = _v2_uuid(manifest.get("job_id"), "job_id")
    if job_id is None:
        raise BundleError("INVALID_MANIFEST", "manifest job_id is required")
    identity_kind = bundle_kind in ("execution", "campaign")
    family_id = _v2_uuid(
        manifest.get("family_id"), "family_id", allow_none=not identity_kind
    )
    parent_job_id = _v2_uuid(
        manifest.get("parent_job_id"),
        "parent_job_id",
        allow_none=not identity_kind,
    )
    if identity_kind and family_id != parent_job_id:
        raise BundleError(
            "INVALID_MANIFEST", "manifest family_id must equal parent_job_id"
        )
    round_no = manifest.get("round_no")
    if bundle_kind == "campaign":
        if round_no is not None:
            raise BundleError(
                "INVALID_MANIFEST", "campaign manifest round_no must be null"
            )
    elif bundle_kind == "execution":
        if type(round_no) is not int or round_no < 1:
            raise BundleError(
                "INVALID_MANIFEST", "execution manifest round_no must be positive"
            )
    elif round_no is not None and (type(round_no) is not int or round_no < 1):
        raise BundleError("INVALID_MANIFEST", "manifest round_no is invalid")

    plan_digest = manifest.get("plan_digest")
    if identity_kind:
        plan_digest = _v2_digest(plan_digest, "plan_digest")
    else:
        _v2_digest(plan_digest, "plan_digest", allow_none=True)
    envelope_digest = manifest.get("envelope_digest")
    if identity_kind:
        _v2_digest(envelope_digest, "envelope_digest")
    else:
        _v2_digest(envelope_digest, "envelope_digest", allow_none=True)
    experiment_digest = manifest.get("experiment_digest")
    _v2_digest(experiment_digest, "experiment_digest", allow_none=True)
    if bundle_kind == "campaign" and experiment_digest is not None:
        raise BundleError(
            "INVALID_MANIFEST", "campaign manifest experiment_digest must be null"
        )

    rules_version = manifest.get("build_provenance_rules_version")
    if identity_kind:
        _v2_text(rules_version, "build_provenance_rules_version")
    elif rules_version is not None:
        _v2_text(rules_version, "build_provenance_rules_version")
    try:
        jsonutil.require_rfc3339(manifest.get("created_at"), "manifest.created_at")
    except ValueError as error:
        raise BundleError("INVALID_MANIFEST", str(error)) from error

    build_ref_value = manifest.get("build_ref")
    reuse_origin_value = manifest.get("reuse_origin")
    if bundle_kind == "campaign":
        if build_ref_value is not None or reuse_origin_value is not None:
            raise BundleError(
                "INVALID_MANIFEST",
                "campaign manifest build_ref/reuse_origin must be null",
            )
    elif bundle_kind == "execution":
        if reuse_origin_value is None:
            if build_ref_value is not None:
                raise BundleError(
                    "INVALID_MANIFEST",
                    "a non-reuse execution must not carry build_ref",
                )
            # TODO(T13): a fixed execution must carry experiment_digest=null
            # (§8 manifest / §12.3 report). A non-reuse manifest cannot tell a
            # fixed run from a guided validation-only run: both omit build_ref
            # and both may carry a non-null experiment_digest here. Deciding it
            # needs the report/plan semantic replay (execution mode + report
            # experiment_digest), which belongs to T13. Do not add a new
            # manifest field (for example execution_kind) to shortcut it; that
            # would be a spec change. T13 must reject fixed + non-null
            # experiment_digest and add the fixed/validation matrix tests.
        else:
            if build_ref_value is None:
                raise BundleError(
                    "INVALID_MANIFEST",
                    "a reuse execution requires build_ref",
                )
            if experiment_digest is None:
                raise BundleError(
                    "INVALID_MANIFEST",
                    "a reuse execution requires experiment_digest",
                )
            build_ref = _v2_build_ref(build_ref_value, "build_ref")
            _v2_reuse_origin(reuse_origin_value, "reuse_origin", build_ref)
    elif bundle_kind == "blocked":
        # §12.2 relaxes the *identity* fields a blocked bundle must carry; it
        # does not make a present build_ref/reuse_origin unvalidated. Apply
        # the same schema checks as an execution bundle when they appear, so
        # a malformed or inconsistent provenance record fails closed instead
        # of riding along on a blocked archive. (T12 must still decide whether
        # it may write blocked+build_ref at all; T10 only refuses garbage.)
        if reuse_origin_value is not None:
            if build_ref_value is None:
                raise BundleError(
                    "INVALID_MANIFEST",
                    "a blocked bundle with reuse_origin requires build_ref",
                )
            build_ref = _v2_build_ref(build_ref_value, "build_ref")
            _v2_reuse_origin(reuse_origin_value, "reuse_origin", build_ref)
        elif build_ref_value is not None:
            _v2_build_ref(build_ref_value, "build_ref")

    verdict = manifest.get("verdict")
    if bundle_kind == "campaign":
        if verdict is not None:
            raise BundleError(
                "INVALID_MANIFEST", "campaign bundle must not carry a verdict"
            )
    elif not isinstance(verdict, str) or verdict not in _VERDICTS:
        raise BundleError("INVALID_MANIFEST", "manifest verdict is invalid")
    elif bundle_kind == "blocked" and verdict != "BLOCKED":
        raise BundleError(
            "INVALID_MANIFEST", "blocked bundle verdict must be BLOCKED"
        )
    reason_code = manifest.get("reason_code")
    if bundle_kind == "campaign":
        if reason_code is not None:
            raise BundleError(
                "INVALID_MANIFEST", "campaign bundle must not carry a reason_code"
            )
    elif bundle_kind == "blocked":
        # A blocked bundle is a terminal non-execution record: its reason must
        # be one of the closed BLOCKED codes. This is the same table the v1
        # writer and the execution archiver consult.
        if (
            not isinstance(reason_code, str)
            or not _REASON_CODE.fullmatch(reason_code)
        ):
            raise BundleError("INVALID_MANIFEST", "manifest reason_code is invalid")
        if not reason_allowed_v2("BLOCKED", reason_code):
            raise BundleError(
                "INVALID_MANIFEST",
                "manifest reason_code is not allowed for BLOCKED",
            )
    else:
        if reason_code is not None and (
            not isinstance(reason_code, str)
            or not _REASON_CODE.fullmatch(reason_code)
        ):
            raise BundleError("INVALID_MANIFEST", "manifest reason_code is invalid")
        if reason_code is not None and not reason_allowed_v2(
            verdict, reason_code
        ):
            raise BundleError(
                "INVALID_MANIFEST",
                f"manifest reason_code is not allowed for {verdict}",
            )
    files = manifest.get("files")
    if not isinstance(files, list):
        raise BundleError("INVALID_MANIFEST", "manifest files must be a list")
    if len(files) > MAX_FILES:
        raise BundleError("INVALID_MANIFEST", "manifest lists too many files")
    return job_id, bundle_kind, plan_digest, files, verdict, reason_code


def _validate_entry(
    entry: Any,
    seen: set[str],
    role_names: frozenset[str] = _ROLE_NAMES,
) -> dict[str, Any]:
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
    if role not in role_names:
        raise BundleError("INVALID_MANIFEST", f"unknown evidence role: {role}")
    size = entry["size_bytes"]
    if type(size) is not int or not 0 <= size <= MAX_FILE_BYTES:
        raise BundleError("INVALID_MANIFEST", f"invalid size for {path}")
    sha = entry["sha256"]
    if not isinstance(sha, str) or not _SHA256_HEX.fullmatch(sha):
        raise BundleError("INVALID_MANIFEST", f"invalid sha256 for {path}")
    return {"path": path, "role": role, "size_bytes": size, "sha256": sha}


def resolve_evidence_ref(bundle_root: Path | str, ref: str) -> list[str]:
    """Resolve a v2 ``log/build``/``log/fuzz`` reference from verified bytes.

    Resolution is fail-closed and follows interface-contract-delta §11:

    1. parse the reference with the frozen grammar (``contracts`` remains the
       single parser, so ``analysis_digest`` and this resolver cannot drift);
    2. read the bundle manifest and locate the role/path: ``build_log`` at
       ``build/{version}/build.log`` for ``log/build``, the unique
       ``fuzz_log`` entry for ``log/fuzz``. Only ``log/fuzz:0`` is defined
       today (the campaign fuzz log); a non-zero selector is reserved for
       future per-round fuzz and fails closed instead of silently resolving
       to the campaign log;
    3. read the file without following symlinks and require its byte count and
       SHA-256 to equal the manifest entry;
    4. require ``1 <= start <= end <= line_count``.

    Returns the selected lines as UTF-8 text **without** their trailing line
    terminators, in ascending order (``["line 3", "line 4"]``). A single-line
    reference returns a one-element list; blank lines are returned as ``""``.

    Raises :class:`EvidenceRefError` with a fixed ``reason_code`` for malformed
    syntax/non-UTF-8 (``INVALID_REFERENCE``), missing or ambiguous role/path
    (``MISSING_LOG``), digest/size mismatch (``DIGEST_MISMATCH``) and an
    out-of-range start/end (``LINE_OUT_OF_RANGE``).

    T13 handoff: the v2 report/plan semantic replay must call this resolver
    (or a wrapper) before claiming that a report line reference is backed by
    verified bytes. When it does, a ``log/fuzz`` reference must be resolved
    against the campaign bundle: this resolver rejects a fuzz log carried by
    an execution or blocked bundle (or a campaign with a non-null round), so
    T13 cannot silently replay the wrong archive. T10 ships the API and its
    fail-closed tests but does not wire it into the not-yet-implemented v2
    report replay; the API must not be deleted as "dead code" before T13
    connects it.
    """
    try:
        parsed = contracts.parse_log_evidence_ref(ref)
    except (TypeError, ValueError) as error:
        raise EvidenceRefError("INVALID_REFERENCE", str(error)) from error
    if parsed is None:
        raise EvidenceRefError(
            "INVALID_REFERENCE",
            "only log/build and log/fuzz references can be resolved",
        )
    if parsed.kind == "fuzz" and parsed.selector != "0":
        raise EvidenceRefError(
            "INVALID_REFERENCE",
            f"log/fuzz:{parsed.selector} is reserved for future per-round "
            "fuzz logs and is not implemented",
        )
    root = Path(bundle_root)
    if root.is_symlink():
        raise EvidenceRefError("SYMLINK", "bundle root must not be a symlink")
    try:
        manifest, _ = _load_manifest(root)
    except BundleError as error:
        raise EvidenceRefError(
            error.reason_code, f"the bundle manifest is not readable: {error.message}"
        ) from error
    if manifest.get("schema_version") != contracts.SCHEMA_VERSION_V2:
        raise EvidenceRefError(
            "INVALID_REFERENCE",
            "log/build and log/fuzz references require a v2 manifest",
        )
    if manifest.get("bundle_kind") not in _V2_BUNDLE_KINDS:
        raise EvidenceRefError(
            "INVALID_REFERENCE",
            "log/build and log/fuzz references require a v2 bundle_kind",
        )
    if parsed.kind == "fuzz" and (
        manifest.get("bundle_kind") != "campaign"
        or manifest.get("round_no") is not None
    ):
        # §11: log/fuzz:0 is the campaign fuzz log, not any bundle that happens
        # to carry a fuzz_log role. An execution/blocked bundle (or a campaign
        # row with a round) cannot back a campaign line reference.
        raise EvidenceRefError(
            "INVALID_REFERENCE",
            "log/fuzz references require a campaign bundle with round_no=null",
        )
    files = manifest.get("files")
    if not isinstance(files, list):
        raise EvidenceRefError("INVALID_REFERENCE", "manifest files must be a list")
    entries: list[dict[str, Any]] = []
    seen: set[str] = set()
    try:
        for entry in files:
            entries.append(_validate_entry(entry, seen, _V2_ROLE_NAMES))
    except BundleError as error:
        raise EvidenceRefError("INVALID_REFERENCE", error.message) from error

    if parsed.kind == "build":
        expected_path = f"build/{parsed.selector}/build.log"
        matches = [entry for entry in entries if entry["path"] == expected_path]
        if len(matches) != 1 or matches[0]["role"] != "build_log":
            raise EvidenceRefError(
                "MISSING_LOG",
                f"manifest has no build_log at {expected_path}",
            )
        entry = matches[0]
    else:
        matches = [entry for entry in entries if entry["role"] == "fuzz_log"]
        if len(matches) != 1:
            raise EvidenceRefError(
                "MISSING_LOG",
                "manifest must carry exactly one fuzz_log evidence entry",
            )
        entry = matches[0]

    try:
        data = _read_bounded_under_root(
            root,
            entry["path"],
            expected_size=entry["size_bytes"],
        )
    except BundleError as error:
        if error.reason_code == "DIGEST_MISMATCH":
            raise EvidenceRefError("DIGEST_MISMATCH", error.message) from error
        raise EvidenceRefError("MISSING_LOG", error.message) from error
    if len(data) != entry["size_bytes"] or _sha256(data) != entry["sha256"]:
        raise EvidenceRefError(
            "DIGEST_MISMATCH",
            f"{entry['path']} does not match its manifest digest",
        )
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as error:
        raise EvidenceRefError(
            "INVALID_REFERENCE", f"{entry['path']} is not valid UTF-8"
        ) from error
    lines = text.splitlines()
    if parsed.start < 1 or parsed.end < parsed.start or parsed.end > len(lines):
        raise EvidenceRefError(
            "LINE_OUT_OF_RANGE",
            f"{parsed.text} does not fit within {len(lines)} log lines",
        )
    return lines[parsed.start - 1 : parsed.end]


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


def _verify_report_markdown(
    markdown: bytes, verdict: str | None, reason_code: str | None
) -> None:
    """Require report.md to render exactly the machine-readable conclusion.

    The manifest digest binds report.md's bytes, but not its meaning: an
    attacker who rewrites report.md, report.json's ``report_markdown_sha256``
    and every manifest size/digest would otherwise be able to publish a clean
    rendering next to a REPRODUCED report.json. The rendered conclusion is
    therefore compared value-for-value with report.json.
    """
    try:
        text = markdown.decode("utf-8")
    except UnicodeDecodeError as error:
        raise BundleError(
            "INVALID_MANIFEST", "report.md is not valid UTF-8"
        ) from error
    verdict_values: list[str] = []
    reason_values: list[str] = []
    for line in text.splitlines():
        stripped = line.strip()
        verdict_match = _REPORT_VERDICT_LINE.fullmatch(stripped)
        if verdict_match is not None:
            verdict_values.append(verdict_match.group("verdict"))
            continue
        reason_match = _REPORT_REASON_LINE.fullmatch(stripped)
        if reason_match is not None:
            reason_values.append(reason_match.group("reason"))
    if len(verdict_values) != 1:
        raise BundleError(
            "INVALID_MANIFEST",
            "report.md must contain exactly one '- Verdict: **VALUE**' line",
        )
    if len(reason_values) != 1:
        raise BundleError(
            "INVALID_MANIFEST",
            "report.md must contain exactly one '- Reason: `VALUE`' line",
        )
    expected_verdict = verdict if verdict else "PENDING"
    expected_reason = reason_code if reason_code is not None else ""
    if verdict_values[0] != expected_verdict:
        raise BundleError(
            "INVALID_MANIFEST",
            "report.md verdict does not match report.json verdict",
        )
    if reason_values[0] != expected_reason:
        raise BundleError(
            "INVALID_MANIFEST",
            "report.md reason does not match report.json reason_code",
        )


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


def _require_required_paths(
    listed: Mapping[str, Mapping[str, Any]],
    required_paths: Mapping[str, str] | None = None,
) -> None:
    """Require each base evidence file at its fixed path.

    ``_REQUIRED_ROLES`` only proves that some file carries each role. A
    ``report_markdown`` role on ``notes.md``, or a rewritten ``report.md`` with
    another role, must not satisfy the contract: the path and the role are both
    part of the evidence identity.
    """
    for path, role in (required_paths or _REQUIRED_PATHS).items():
        entry = listed.get(path)
        if entry is None:
            raise BundleError(
                "INVALID_MANIFEST",
                f"manifest is missing required evidence path: {path}",
            )
        if entry.get("role") != role:
            raise BundleError(
                "INVALID_MANIFEST",
                f"evidence {path} must carry the {role} role, "
                f"not {entry.get('role')!r}",
            )


def _require_blocked_paths(
    listed: Mapping[str, Mapping[str, Any]],
) -> None:
    """Require the report files and, when present, bind optional plan/review."""
    _require_required_paths(listed, _BLOCKED_REQUIRED_PATHS)
    for path, role in (("plan.json", "plan"), ("review.json", "review")):
        entry = listed.get(path)
        if entry is not None and entry.get("role") != role:
            raise BundleError(
                "INVALID_MANIFEST",
                f"evidence {path} must carry the {role} role, "
                f"not {entry.get('role')!r}",
            )
    for entry in listed.values():
        if entry.get("role") in ("plan", "review") and entry.get("path") not in (
            "plan.json",
            "review.json",
        ):
            raise BundleError(
                "INVALID_MANIFEST",
                "a blocked plan/review must live at its fixed evidence path",
            )


def _validate_blocked_artifacts(
    payloads: Mapping[str, bytes],
    *,
    plan_digest: str | None,
    report: Mapping[str, Any],
) -> None:
    """Check the optional plan/review documents of a blocked bundle.

    A blocked bundle may omit both, carry only a frozen plan (review expiry),
    or carry a plan plus a review (approve or reject). The bundle kind, not
    the review decision, is what separates a blocked archive from an execution
    archive.
    """
    has_plan = "plan.json" in payloads
    has_review = "review.json" in payloads
    if plan_digest is None:
        if has_plan or has_review:
            raise BundleError(
                "INVALID_MANIFEST",
                "a blocked bundle without a plan digest must not ship plan/review",
            )
        return
    if not has_plan:
        raise BundleError(
            "INVALID_MANIFEST",
            "a blocked bundle with a plan digest must ship plan.json",
        )
    plan = _parse_json_file(payloads, "plan.json")
    try:
        computed = contracts.plan_digest(plan)
    except (KeyError, TypeError, ValueError, UnicodeError) as error:
        raise BundleError(
            "INVALID_MANIFEST", f"plan.json cannot be validated: {error}"
        ) from error
    if computed != plan_digest:
        raise BundleError(
            "INVALID_MANIFEST",
            "plan.json content does not match the manifest plan_digest",
        )
    if not has_review:
        if report.get("review") is not None:
            raise BundleError(
                "INVALID_MANIFEST",
                "report review must be null when review.json is absent",
            )
        return
    review = _parse_json_file(payloads, "review.json")
    if review.get("decision") not in ("approve", "reject"):
        raise BundleError(
            "INVALID_MANIFEST",
            "a blocked review.json must record approve or reject",
        )
    if review.get("plan_digest") != plan_digest:
        raise BundleError(
            "INVALID_MANIFEST", "review.json is bound to a different plan"
        )
    expected_review = {
        "reviewer_id": review.get("reviewer_id"),
        "decision": review.get("decision"),
        "plan_digest": review.get("plan_digest"),
        "decided_at": review.get("decided_at"),
    }
    if dict(report.get("review") or {}) != expected_review:
        raise BundleError(
            "INVALID_MANIFEST", "report review does not match review.json"
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


def _role_paths(
    listed: Mapping[str, Mapping[str, Any]], role: str
) -> list[tuple[str, Mapping[str, Any]]]:
    matches = [
        (path, entry)
        for path, entry in listed.items()
        if entry["role"] == role
    ]
    if not matches:
        raise BundleError(
            "INVALID_MANIFEST",
            f"expected at least one {role} evidence file, found 0",
        )
    return matches


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
    for role, prefix in (
        ("material_source_vulnerable", "vulnerable/"),
        ("material_source_fixed", "fixed/"),
    ):
        matches = _role_paths(listed, role)
        bundled_relatives: set[str] = set()
        for path, _entry in matches:
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
            bundled_relatives.add(relative)
        expected_relatives = {
            relative for relative in materials if relative.startswith(prefix)
        }
        missing_sources = sorted(expected_relatives - bundled_relatives)
        if missing_sources:
            raise BundleError(
                "INVALID_MANIFEST",
                f"{role} is missing pinned source files: {', '.join(missing_sources)}",
            )
    # A case config may pin the repository bundle and advisory snapshot as
    # materials (B03 does). When it does, the bundle must contain those exact
    # files at the named paths. B01/B02 case configs do not pin them, so their
    # older bundles keep verifying unchanged.
    registry_entry = case_config.get("registry_entry")
    if isinstance(registry_entry, Mapping):
        repository_entry = registry_entry.get("repository")
        if isinstance(repository_entry, Mapping):
            bundle_relative = repository_entry.get("bundle")
            if (
                isinstance(bundle_relative, str)
                and bundle_relative in materials
            ):
                _verify_named_material(
                    "materials/" + bundle_relative,
                    "material_repository_bundle",
                    plan.get("repository", {}).get("bundle_digest"),
                    listed,
                    data,
                    materials,
                    "repository bundle",
                )
        advisory_entry = registry_entry.get("advisory")
        if isinstance(advisory_entry, Mapping):
            snapshot = advisory_entry.get("path")
            if isinstance(snapshot, str) and snapshot in materials:
                intel = plan.get("intel")
                expected = intel.get("content_digest") if isinstance(intel, Mapping) else None
                _verify_named_material(
                    "materials/" + snapshot,
                    "material_advisory",
                    expected,
                    listed,
                    data,
                    materials,
                    "advisory snapshot",
                )


def _verify_named_material(
    path: str,
    role: str,
    expected_digest: Any,
    listed: Mapping[str, Mapping[str, Any]],
    data: Mapping[str, bytes],
    materials: Mapping[str, str],
    label: str,
) -> None:
    """Require one named material at its exact path with a matching digest."""
    entry = listed.get(path)
    if entry is None:
        raise BundleError(
            "INVALID_MANIFEST", f"required {label} is missing from the bundle: {path}"
        )
    if entry.get("role") != role:
        raise BundleError(
            "INVALID_MANIFEST",
            f"{label} {path} must carry the {role} role, not {entry.get('role')!r}",
        )
    content = data.get(path)
    if content is None:
        raise BundleError("MISSING_FILE", f"required {label} is not readable: {path}")
    actual = _digest(content)
    if actual != expected_digest:
        raise BundleError(
            "DIGEST_MISMATCH",
            f"{label} digest does not match the plan: {path}",
        )
    relative = path[len("materials/") :]
    if materials.get(relative) != actual:
        raise BundleError(
            "DIGEST_MISMATCH",
            f"{label} is not pinned by the plan case config: {relative}",
        )


def _extract_compile_args_v1(recipe: bytes) -> tuple[str, ...]:
    """Frozen copy of the v1 compile-argument extractor.

    §12.1 requires the v1 verifier to keep its own copy: a rollback must verify
    v1-era bundles with the baked semantics, not with whatever
    ``datacon.tools.sandbox`` happens to expose after a later change. Do not
    refactor this into a call to the v2 implementation.
    """
    try:
        text = recipe.decode("utf-8")
    except UnicodeError:
        return ()
    text = text.replace("\\\n", " ")
    for line in text.splitlines():
        stripped = line.strip()
        if "clang" not in stripped or stripped.startswith("#"):
            continue
        try:
            tokens = shlex.split(stripped)
        except ValueError:
            continue
        try:
            index = tokens.index("clang")
        except ValueError:
            continue
        return tuple(
            token
            for token in tokens[index + 1 :]
            if token.startswith("-")
        )
    return ()


def _compile_args_from_recipe_v1(recipe: bytes) -> list[str]:
    return list(_extract_compile_args_v1(recipe))


def _compile_args_from_recipe(recipe: bytes) -> list[str]:
    """v2 extractor: the live sandbox implementation.

    The v1 branch must not call this function; see ``_compile_args_from_recipe_v1``.
    """
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
        if build.get("capture_error") is not None:
            raise BundleError(
                "INVALID_MANIFEST",
                f"{version} completed build must not record capture_error",
            )
        # A completed build must have exited with the expected success code.
        # ``True`` is an int subclass, so use ``type(...) is int`` rather than
        # isinstance: a boolean or a string must never satisfy a build gate.
        if type(build.get("exit_code")) is not int or build.get("exit_code") != 0:
            raise BundleError(
                "INVALID_MANIFEST",
                f"{version} completed build must record integer exit_code 0",
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
        capture_error = item.get("capture_error")
        if capture_error is not None and (
            not isinstance(capture_error, str) or not capture_error.strip()
        ):
            raise BundleError(
                "INVALID_MANIFEST",
                f"replay {version}/{phase} capture_error must be a non-empty string or null",
            )
        if status == "completed" and capture_error is not None:
            raise BundleError(
                "INVALID_MANIFEST",
                f"completed replay {version}/{phase} must not record capture_error",
            )
        if (status == "infra_error" or capture_error is not None) and (
            verdict != "INCONCLUSIVE"
            or report.get("reason_code")
            not in ("EVIDENCE_INCOMPLETE", "NOT_COMPARABLE")
        ):
            raise BundleError(
                "INVALID_MANIFEST",
                f"replay {version}/{phase} infra_error/capture_error requires "
                "INCONCLUSIVE/EVIDENCE_INCOMPLETE",
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
            "capture_error": capture_error,
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
    """Re-derive the verdict from the six replays with the execution rule.

    The verifier must not maintain a second, subtly different copy of the
    priority rules: a report that ``decide_verdict`` would never produce is
    rejected, and any combination the executor can legitimately produce is
    accepted. ``_verify_builds`` and ``_verify_replays`` already checked every
    byte-level binding before this point.
    """
    expected_exit = plan.get("expected_exit")
    signature = plan.get("asan_signature")
    if not isinstance(expected_exit, Mapping) or not isinstance(
        signature, Mapping
    ):
        raise BundleError(
            "INVALID_MANIFEST", "plan rule inputs are missing or malformed"
        )
    policy = VerdictPolicy(
        signature=signature,
        expected_exit=expected_exit,
        expected_stdout=expected_stdout,
    )
    builds = {
        build.get("version"): build
        for build in report.get("builds") or []
        if isinstance(build, Mapping)
    }
    runs: list[RunObservation] = []
    replays = report.get("replays")
    if not isinstance(replays, list):
        raise BundleError("INVALID_MANIFEST", "report replays must be a list")
    for item in replays:
        if not isinstance(item, Mapping):
            raise BundleError("INVALID_MANIFEST", "report replay must be an object")
        key = (item.get("version"), item.get("phase"))
        observation = observations.get(key)
        if observation is None:
            raise BundleError(
                "INVALID_MANIFEST", f"replay evidence is missing for {key}"
            )
        runs.append(
            RunObservation(
                version=str(item.get("version")),
                phase=str(item.get("phase")),
                status=str(observation["status"]),
                exit_code=observation.get("exit_code"),
                stdout=str(observation.get("stdout", "")),
                stderr=str(observation.get("stderr", "")),
                signature=observation.get("signature"),
                input_digest=item.get("input_digest"),
                log_truncated=bool(observation.get("log_truncated")),
                capture_error=observation.get("capture_error"),
            )
        )
    try:
        decision = decide_verdict(policy, runs, builds=builds)
    except (KeyError, TypeError, ValueError) as error:
        raise BundleError(
            "INVALID_MANIFEST", f"outcome cannot be re-derived: {error}"
        ) from error
    if decision.verdict != verdict or decision.reason_code != report.get(
        "reason_code"
    ):
        raise BundleError(
            "INVALID_MANIFEST",
            "report verdict/reason contradicts the six replays: "
            f"re-derived {decision.verdict}/{decision.reason_code}",
        )


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





def _verify_probe_document(
    probe: Mapping[str, Any],
    plan: Mapping[str, Any],
    execution_metadata: Mapping[str, Any] | None,
    report: Mapping[str, Any],
    *,
    job_id: str,
    plan_digest: str,
) -> None:
    if probe.get("status") != "completed":
        raise BundleError(
            "INVALID_MANIFEST",
            "probe metadata does not record a completed isolation probe",
        )
    if probe.get("job_id") != job_id or probe.get("plan_digest") != plan_digest:
        raise BundleError(
            "INVALID_MANIFEST",
            "probe metadata job_id/plan_digest does not match manifest",
        )
    if execution_metadata is not None:
        for field in ("job_id", "plan_digest"):
            if field in execution_metadata and probe.get(field) != execution_metadata.get(field):
                raise BundleError(
                    "INVALID_MANIFEST",
                    f"probe metadata {field} does not match execution metadata",
                )
    if probe.get("image_digest") != plan.get("image_digest"):
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
        execution_metadata is not None
        and "probe" in execution_metadata
        and execution_metadata["probe"] is not None
        and execution_metadata["probe"] != probe
    ):
        raise BundleError(
            "INVALID_MANIFEST",
            "execution metadata probe does not match metadata/probe.json",
        )
    report_environment = _mapping(report.get("environment"), "report environment")
    if report_environment.get("probe") != probe:
        raise BundleError(
            "INVALID_MANIFEST",
            "report environment probe does not match metadata/probe.json",
        )


def _verify_partial_inconclusive(
    *,
    plan: Mapping[str, Any],
    verdict: str,
    report: Mapping[str, Any],
    listed: Mapping[str, Mapping[str, Any]],
    data: Mapping[str, bytes],
    job_id: str,
    plan_digest: str,
) -> None:
    """Verify an INCONCLUSIVE bundle archived from an incomplete execution.

    When execution fails mid-run with TIMEOUT, RUN_INCOMPLETE or NOT_COMPARABLE,
    fewer than two builds or six replays may exist and the probe may not have
    completed. The bundle is still bound to the approved plan, review,
    report.md conclusion, and every material, probe, build or replay artifact
    that was actually archived.
    """
    if report.get("repository") != plan.get("repository"):
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

    execution_metadata: dict[str, Any] | None = None
    if "metadata/execution.json" in listed:
        if listed["metadata/execution.json"].get("role") != "execution_metadata":
            raise BundleError(
                "INVALID_MANIFEST",
                "metadata/execution.json must carry the execution_metadata role",
            )
        execution_metadata = _parse_json_file(data, "metadata/execution.json")
        if execution_metadata:
            if (
                execution_metadata.get("job_id") != job_id
                or execution_metadata.get("plan_digest") != plan_digest
            ):
                raise BundleError(
                    "INVALID_MANIFEST",
                    "execution metadata does not match manifest job_id/plan_digest",
                )
            for field in ("builds", "replays"):
                if (
                    field in execution_metadata
                    and execution_metadata[field] != report.get(field)
                ):
                    raise BundleError(
                        "INVALID_MANIFEST",
                        f"execution metadata {field} do not match report.{field}",
                    )

    if "metadata/probe.json" in listed or environment.get("probe") is not None:
        _require_evidence_roles(
            listed, {"metadata/probe.json": frozenset({"probe"})}
        )
        probe = _parse_json_file(data, "metadata/probe.json")
        _verify_probe_document(
            probe,
            plan,
            execution_metadata,
            report,
            job_id=job_id,
            plan_digest=plan_digest,
        )

    materials: Mapping[str, str] | None = None
    expected_compile_args: list[str] | None = None
    if "metadata/case.json" in listed:
        case_config, materials, recipe = _case_binding(plan, listed, data)
        _expected_stdout_from_case_config(case_config)
        _verify_materials(plan, listed, data, case_config, materials)
        expected_compile_args = _compile_args_from_recipe_v1(recipe)
        if list(environment.get("compile_args") or []) != expected_compile_args:
            raise BundleError(
                "INVALID_MANIFEST",
                "report environment compile args do not match the reviewed recipe",
            )
    elif _material_entries(listed):
        raise BundleError(
            "INVALID_MANIFEST",
            "materials/* evidence requires metadata/case.json",
        )

    builds = report.get("builds")
    if not isinstance(builds, list) or len(builds) > 2:
        raise BundleError("INVALID_MANIFEST", "report builds must be a list of at most 2 items")
    seen_builds: set[str] = set()
    build_artifacts: dict[str, Any] = {}
    for build in builds:
        if not isinstance(build, Mapping):
            raise BundleError("INVALID_MANIFEST", "report build must be an object")
        version = build.get("version")
        if version not in _REPLAY_VERSIONS or version in seen_builds:
            raise BundleError(
                "INVALID_MANIFEST", f"report build has an invalid version: {version}"
            )
        seen_builds.add(version)
        if build.get("plan_digest") != plan_digest or build.get("job_id") != job_id:
            raise BundleError(
                "INVALID_MANIFEST", f"{version} build provenance does not match"
            )
        if build.get("image_digest") != plan.get("image_digest"):
            raise BundleError(
                "DIGEST_MISMATCH", f"{version} build image does not match the plan"
            )
        if build.get("build_recipe_digest") != plan.get("build_recipe_digest"):
            raise BundleError(
                "DIGEST_MISMATCH", f"{version} build recipe does not match the plan"
            )
        meta_path = _build_evidence_path(version, "metadata.json")
        if meta_path in data:
            metadata = _parse_json_file(data, meta_path)
            if dict(metadata) != dict(build):
                raise BundleError(
                    "INVALID_MANIFEST",
                    f"{version} build metadata does not match report.builds",
                )
        log_path = _build_evidence_path(version, "build.log")
        if log_path in data and _digest(data[log_path]) != build.get("log_digest"):
            raise BundleError(
                "DIGEST_MISMATCH", f"{version} build log digest does not match"
            )
        artifact_path = _build_evidence_path(version, "parser")
        if artifact_path in data and _digest(data[artifact_path]) != build.get("artifact_digest"):
            raise BundleError(
                "DIGEST_MISMATCH", f"{version} build artifact digest does not match"
            )
        build_artifacts[version] = build.get("artifact_digest")

    replays = report.get("replays")
    if not isinstance(replays, list) or len(replays) > 6:
        raise BundleError("INVALID_MANIFEST", "report replays must be a list of at most 6 items")
    seen_replays: set[tuple[str, str]] = set()
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
        if key in seen_replays:
            raise BundleError(
                "INVALID_MANIFEST",
                f"report contains a duplicate replay: {version}/{phase}",
            )
        seen_replays.add(key)
        status = item.get("status")
        if not isinstance(status, str) or not replay_status_allowed(verdict, status):
            raise BundleError(
                "INVALID_MANIFEST",
                f"replay {version}/{phase} has an invalid status: {status!r}",
            )
        capture_error = item.get("capture_error")
        if capture_error is not None and (
            not isinstance(capture_error, str) or not capture_error.strip()
        ):
            raise BundleError(
                "INVALID_MANIFEST",
                f"replay {version}/{phase} capture_error must be a non-empty string or null",
            )
        if status == "completed" and capture_error is not None:
            raise BundleError(
                "INVALID_MANIFEST",
                f"completed replay {version}/{phase} must not record capture_error",
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
        if version in build_artifacts and item.get("artifact_digest") != build_artifacts[version]:
            raise BundleError(
                "DIGEST_MISMATCH",
                f"replay {version}/{phase} artifact does not match the {version} build",
            )
        stdout_path = _replay_evidence_path(version, phase, "stdout.log")
        stderr_path = _replay_evidence_path(version, phase, "stderr.log")
        meta_path = _replay_evidence_path(version, phase, "metadata.json")
        if stdout_path in data and item.get("stdout_sha256") != _digest(data[stdout_path]):
            raise BundleError(
                "DIGEST_MISMATCH",
                f"replay {version}/{phase} stdout digest does not match",
            )
        if stderr_path in data and item.get("stderr_sha256") != _digest(data[stderr_path]):
            raise BundleError(
                "DIGEST_MISMATCH",
                f"replay {version}/{phase} stderr digest does not match",
            )
        if meta_path in data:
            metadata = _parse_json_file(data, meta_path)
            if dict(metadata) != dict(item):
                raise BundleError(
                    "INVALID_MANIFEST",
                    f"replay {version}/{phase} metadata does not match report.replays",
                )


def _verify_semantics(
    *,
    job_id: str,
    bundle_kind: str,
    plan_digest: str | None,
    verdict: str,
    manifest_reason: str | None,
    listed: Mapping[str, Mapping[str, Any]],
    data: Mapping[str, bytes],
) -> None:
    """Cross-check the manifest against the plan, review and report content.

    The manifest digest only proves internal byte consistency. For an
    execution bundle this step re-derives the plan digest and requires an
    approved review, a consistent report and (for outcome verdicts) the
    complete execution evidence tree. A blocked bundle keeps the report,
    markdown and reason checks but only validates the plan/review documents it
    actually carries.
    """
    report = _parse_json_file(data, "report.json")
    if (
        type(report.get("schema_version")) is not int
        or report.get("schema_version") != SCHEMA_VERSION
    ):
        raise BundleError(
            "INVALID_MANIFEST", "report schema_version must be 1"
        )
    if report.get("job_id") != job_id:
        raise BundleError("INVALID_MANIFEST", "report job_id does not match manifest")
    if report.get("plan_digest") != plan_digest:
        raise BundleError(
            "INVALID_MANIFEST", "report plan_digest does not match manifest"
        )
    report_verdict = report.get("verdict")
    if not isinstance(report_verdict, str) or report_verdict not in _VERDICTS:
        raise BundleError("INVALID_MANIFEST", "report verdict must be a known value")
    if report_verdict != verdict:
        raise BundleError(
            "INVALID_MANIFEST", "manifest verdict does not match report verdict"
        )
    if report.get("state") != report_verdict:
        raise BundleError(
            "INVALID_MANIFEST", "report state must equal report verdict"
        )
    report_reason = _reason_code_valid(report)
    if manifest_reason != report_reason:
        raise BundleError(
            "INVALID_MANIFEST", "manifest reason_code does not match report"
        )
    missing = report.get("missing")
    if not isinstance(missing, list) or not all(
        isinstance(item, str) for item in missing
    ):
        raise BundleError(
            "INVALID_MANIFEST", "report missing must be a list of strings"
        )
    report_error = report.get("error")
    if report_error is not None and not isinstance(report_error, str):
        raise BundleError("INVALID_MANIFEST", "report error must be text or null")
    evidence_complete = report.get("evidence_complete")
    if evidence_complete is not None and type(evidence_complete) is not bool:
        raise BundleError(
            "INVALID_MANIFEST", "report evidence_complete must be a boolean"
        )
    if report_verdict in ("REPRODUCED", "NOT_REPRODUCED"):
        if evidence_complete is False:
            raise BundleError(
                "INVALID_MANIFEST",
                "conclusive evidence must not record evidence_complete=false",
            )
        if missing:
            raise BundleError(
                "INVALID_MANIFEST",
                "conclusive evidence must not record missing inputs",
            )
        if report_error is not None:
            raise BundleError(
                "INVALID_MANIFEST",
                "conclusive evidence must not record an error",
            )
    markdown = data.get("report.md")
    if markdown is None:
        raise BundleError("INVALID_MANIFEST", "report.md is missing")
    expected_markdown = report.get("report_markdown_sha256")
    if (
        not isinstance(expected_markdown, str)
        or not _SHA256_HEX.fullmatch(expected_markdown)
    ):
        # Old bundles predate the binding. Fail closed rather than accepting a
        # report.md that report.json never committed to.
        raise BundleError(
            "INVALID_MANIFEST",
            "report report_markdown_sha256 is missing or invalid",
        )
    if _sha256(markdown) != expected_markdown:
        raise BundleError(
            "DIGEST_MISMATCH",
            "report.md digest does not match report.json",
        )
    _verify_report_markdown(markdown, report_verdict, report_reason)
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

    if bundle_kind == "blocked":
        if report_verdict != "BLOCKED":
            raise BundleError(
                "INVALID_MANIFEST", "a blocked bundle must record verdict BLOCKED"
            )
        if report_reason is None or not reason_allowed("BLOCKED", report_reason):
            raise BundleError(
                "INVALID_MANIFEST",
                "a blocked bundle requires an allowed BLOCKED reason_code",
            )
        has_plan = "plan.json" in listed
        has_review = "review.json" in listed
        if plan_digest is None:
            if has_plan or has_review:
                raise BundleError(
                    "INVALID_MANIFEST",
                    "a blocked bundle without a plan digest must not ship "
                    "plan/review",
                )
            if report.get("review") is not None:
                raise BundleError(
                    "INVALID_MANIFEST",
                    "report review must be null when review.json is absent",
                )
            return
        if not has_plan:
            raise BundleError(
                "INVALID_MANIFEST",
                "a blocked bundle with a plan digest must ship plan.json",
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
        for field in ("case_id", "cve_id"):
            if report.get(field) is not None and report.get(field) != plan.get(field):
                raise BundleError(
                    "INVALID_MANIFEST", f"report {field} does not match the plan"
                )
        if not has_review:
            if report.get("review") is not None:
                raise BundleError(
                    "INVALID_MANIFEST",
                    "report review must be null when review.json is absent",
                )
            return
        review = _parse_json_file(data, "review.json")
        if review.get("decision") not in ("approve", "reject"):
            raise BundleError(
                "INVALID_MANIFEST",
                "a blocked review.json must record approve or reject",
            )
        if review.get("plan_digest") != plan_digest:
            raise BundleError(
                "INVALID_MANIFEST", "review.json is bound to a different plan"
            )
        expected_review = {
            "reviewer_id": review.get("reviewer_id"),
            "decision": review.get("decision"),
            "plan_digest": review.get("plan_digest"),
            "decided_at": review.get("decided_at"),
        }
        if dict(report.get("review") or {}) != expected_review:
            raise BundleError(
                "INVALID_MANIFEST", "report review does not match review.json"
            )
        return

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

    # The case identity and budget are top-level report claims; bind them to
    # the frozen plan instead of trusting the report's own copy.
    for field in ("case_id", "cve_id"):
        if report.get(field) != plan.get(field):
            raise BundleError(
                "INVALID_MANIFEST",
                f"report {field} does not match the plan",
            )
    if report.get("budget") != plan.get("limits"):
        raise BundleError(
            "INVALID_MANIFEST", "report budget does not match the plan limits"
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
    # report.json repeats the review so the report is self-describing; it must
    # be byte-for-byte the decision shipped in review.json.
    report_review = report.get("review")
    if not isinstance(report_review, Mapping):
        raise BundleError(
            "INVALID_MANIFEST", "report review must be an object"
        )
    expected_review = {
        "reviewer_id": review.get("reviewer_id"),
        "decision": review.get("decision"),
        "plan_digest": review.get("plan_digest"),
        "decided_at": review.get("decided_at"),
    }
    if dict(report_review) != expected_review:
        raise BundleError(
            "INVALID_MANIFEST", "report review does not match review.json"
        )

    if verdict not in _FULL_EVIDENCE_VERDICTS:
        return

    partial_inconclusive = (
        verdict == "INCONCLUSIVE"
        and rule is None
        and (bool(missing) or report_error is not None)
    )
    if partial_inconclusive and evidence_complete is True:
        raise BundleError(
            "INVALID_MANIFEST",
            "partial inconclusive evidence must not record evidence_complete=true",
        )
    if not partial_inconclusive and evidence_complete is False:
        raise BundleError(
            "INVALID_MANIFEST",
            "complete evidence must not record evidence_complete=false",
        )
    has_full_runs = (
        isinstance(report.get("builds"), list)
        and len(report.get("builds")) == 2
        and all(
            isinstance(item, Mapping) and item.get("status") == "completed"
            for item in report.get("builds")
        )
        and isinstance(report.get("replays"), list)
        and len(report.get("replays")) == 6
        and "metadata/probe.json" in listed
        and "metadata/case.json" in listed
    )
    if partial_inconclusive and not has_full_runs:
        _verify_partial_inconclusive(
            plan=plan,
            verdict=verdict,
            report=report,
            listed=listed,
            data=data,
            job_id=job_id,
            plan_digest=plan_digest,
        )
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
    # execution.json duplicates the probe so consumers do not need a second
    # file; it must not become a second, unbound copy of the same facts.
    report_environment = _mapping(report.get("environment"), "report environment")
    if report_environment.get("probe") != probe:
        raise BundleError(
            "INVALID_MANIFEST",
            "report environment probe does not match metadata/probe.json",
        )
    # The builds/replays lists are repeated in execution.json for operational
    # diagnostics. Full evidence must carry both lists, and they must be
    # exactly the report's lists so one copy cannot be omitted or tampered
    # with independently.
    for field in ("builds", "replays"):
        if field not in execution_metadata:
            raise BundleError(
                "INVALID_MANIFEST",
                f"execution metadata is missing {field}",
            )
        if execution_metadata[field] != report.get(field):
            raise BundleError(
                "INVALID_MANIFEST",
                f"execution metadata {field} do not match report.{field}",
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
    expected_compile_args = _compile_args_from_recipe_v1(recipe)
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


def _resolve_bundle_root(root: Path | str) -> Path:
    path = Path(root)
    if path.is_symlink():
        raise BundleError("SYMLINK", "bundle root must not be a symlink")
    try:
        root_path = path.resolve(strict=True)
    except OSError as error:
        raise BundleError("MISSING_FILE", f"bundle root is not readable: {error}") from error
    if not root_path.is_dir():
        raise BundleError("INVALID_MANIFEST", "bundle root must be a directory")
    return root_path


def verify_bundle(root: Path | str) -> BundleVerification:
    """Verify a bundle without database or network access.

    The manifest's ``schema_version`` selects the verifier before any other
    field is interpreted: v1 bundles keep the frozen v1 validator, v2 bundles
    use the versioned validator. A manifest with an absent or non-integer
    version still follows the historical v1 error surface.
    """
    root_path = _resolve_bundle_root(root)
    manifest, manifest_bytes = _load_manifest(root_path)
    schema_version = manifest.get("schema_version")
    if (
        type(schema_version) is int
        and schema_version == contracts.SCHEMA_VERSION_V2
    ):
        return _verify_bundle_v2(root_path, manifest, manifest_bytes)
    return _verify_bundle_v1(root_path, manifest, manifest_bytes)


def _verify_bundle_v1(
    root_path: Path,
    manifest: dict[str, Any],
    manifest_bytes: bytes,
) -> BundleVerification:
    (
        job_id,
        bundle_kind,
        plan_digest,
        files,
        verdict,
        manifest_reason,
    ) = _validate_manifest_header(manifest)
    entries = []
    seen: set[str] = set()
    for entry in files:
        entries.append(_validate_entry(entry, seen))
    roles = {entry["role"] for entry in entries}
    required_roles = (
        _REQUIRED_ROLES if bundle_kind == "execution" else _BLOCKED_REQUIRED_ROLES
    )
    if not required_roles <= roles:
        missing = sorted(required_roles - roles)
        raise BundleError(
            "INVALID_MANIFEST",
            "manifest is missing required roles: " + ", ".join(missing),
        )

    listed = {entry["path"]: entry for entry in entries}
    if bundle_kind == "execution":
        _require_required_paths(listed)
    else:
        _require_blocked_paths(listed)
    data = _read_listed_files(root_path, listed)

    _verify_semantics(
        job_id=job_id,
        bundle_kind=bundle_kind,
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


def _read_listed_files(
    root_path: Path,
    listed: Mapping[str, Mapping[str, Any]],
) -> dict[str, bytes]:
    actual: dict[str, Path] = {}
    entries_seen = 0
    files_seen = 0
    directories_seen = 0
    # Walk with an explicit scandir stack instead of os.walk. os.walk collects
    # a directory's names into lists before the caller can count them, so a
    # single directory with millions of entries would exhaust memory before
    # the cap was observed. Files and directories have independent budgets:
    # charging helper directories against MAX_FILES would reject a legitimate
    # bundle that uses all 4096 file slots.
    stack: list[Path] = [root_path]
    while stack:
        current = stack.pop()
        try:
            iterator = os.scandir(current)
        except OSError as error:
            raise BundleError(
                "INVALID_MANIFEST", f"bundle cannot be enumerated: {error}"
            ) from error
        with iterator:
            for dirent in iterator:
                entries_seen += 1
                if entries_seen > MAX_BUNDLE_ENTRIES:
                    raise BundleError(
                        "INVALID_MANIFEST",
                        f"bundle contains more than {MAX_BUNDLE_ENTRIES} "
                        "directory entries",
                    )
                child = Path(dirent.path)
                # ``is_symlink`` never follows the link, matching the previous
                # os.walk(followlinks=False) behaviour.
                if dirent.is_symlink():
                    raise BundleError(
                        "SYMLINK", f"bundle contains a symlink: {child}"
                    )
                try:
                    is_directory = dirent.is_dir(follow_symlinks=False)
                    is_file = dirent.is_file(follow_symlinks=False)
                except OSError as error:
                    raise BundleError(
                        "INVALID_MANIFEST",
                        f"bundle entry cannot be inspected: {error}",
                    ) from error
                if is_directory:
                    directories_seen += 1
                    if directories_seen > MAX_DIRECTORIES:
                        raise BundleError(
                            "INVALID_MANIFEST",
                            f"bundle contains more than {MAX_DIRECTORIES} "
                            "directories",
                        )
                    stack.append(child)
                    continue
                if not is_file:
                    raise BundleError(
                        "INVALID_MANIFEST",
                        f"bundle contains a special file: {child}",
                    )
                relative = child.relative_to(root_path).as_posix()
                if relative == "manifest.json":
                    continue
                files_seen += 1
                if files_seen > MAX_FILES:
                    raise BundleError(
                        "INVALID_MANIFEST",
                        f"bundle contains more than {MAX_FILES} files",
                    )
                if relative not in listed:
                    raise BundleError(
                        "EXTRA_FILE",
                        f"bundle contains an extra file: {relative}",
                    )
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
    return data


_V2_FIXED_PATH_ROLES = {
    "report.json": "report_json",
    "report.md": "report_markdown",
    "plan.json": "plan",
    "envelope.json": "envelope",
    "budget/snapshot.json": "budget_snapshot",
    "budget/ledger.json": "budget_ledger",
    "budget/charges.json": "budget_charge",
    "metadata/execution.json": "execution_metadata",
    "metadata/probe.json": "probe",
    "metadata/case.json": "case_config",
    "review.json": "review",
    "admission.json": "admission",
    "model/audit.json": "model_audit",
    "intel/snapshot.json": "intel_snapshot",
    "intel/license.json": "license_record",
}
_V2_FIXED_ROLE_PATHS = {
    role: path for path, role in _V2_FIXED_PATH_ROLES.items()
}
_V2_BUILD_ROLES = frozenset(
    {"build_metadata", "build_log", "build_artifact", "build_provenance"}
)
_V2_REPLAY_ROLES = frozenset(
    {
        "normal_output",
        "normal_error",
        "asan_log",
        "replay_stdout",
        "replay_stderr",
        "replay_metadata",
    }
)


def _v2_replay_expected_paths() -> dict[str, str]:
    expected: dict[str, str] = {}
    for version in _REPLAY_VERSIONS:
        for phase in _REPLAY_PHASES:
            base = f"replay/{version}/{phase}/"
            if phase == "normal":
                expected[base + "stdout.log"] = "normal_output"
                expected[base + "stderr.log"] = "normal_error"
            else:
                expected[base + "stdout.log"] = "replay_stdout"
                expected[base + "stderr.log"] = "asan_log"
            expected[base + "metadata.json"] = "replay_metadata"
    return expected


def _v2_required_role_paths(
    listed: Mapping[str, Mapping[str, Any]], path: str, role: str
) -> None:
    entry = listed.get(path)
    if entry is None:
        raise BundleError(
            "INVALID_MANIFEST", f"manifest is missing required evidence path: {path}"
        )
    if entry.get("role") != role:
        raise BundleError(
            "INVALID_MANIFEST",
            f"evidence {path} must carry the {role} role, "
            f"not {entry.get('role')!r}",
        )


# D4: v2 build records describe build materials only. The two reviewed input
# aliases stay in the frozen v1 branch; a v2 build record that stages them is
# rejected rather than silently accepting an input digest in build provenance.
_V2_BUILD_INPUT_ALIASES = frozenset(
    {"inputs/normal.txt", "inputs/candidate.txt"}
)
# D39: only the three reviewed provenance faces are fixed build evidence.
_V2_BUILD_PROVENANCE_FACES = frozenset(
    {"compile_commands.json", "cc-shim.log", "shell-face.log"}
)


def _normalized_v2_staged_key(value: Any) -> str | None:
    """Normalize a staged-material key for the D4 alias comparison.

    ``staged_materials`` keys are POSIX paths. ``posixpath.normpath`` folds
    ``./`` and ``a/../`` spellings that would otherwise bypass an exact-key
    check; a leading slash is stripped so an absolute spelling cannot hide an
    input alias either.
    """
    if not isinstance(value, str):
        return None
    return posixpath.normpath(value.replace("\\", "/")).lstrip("/")


def _check_v2_build_record(record: Mapping[str, Any], label: str) -> None:
    """Reject a v1 input alias in one v2 build record.

    A record without ``staged_materials`` is not a build-material record and is
    left to the later semantic replay; when the map is present every key is
    normalized before comparison.
    """
    staged = record.get("staged_materials")
    if staged is None:
        return
    if not isinstance(staged, Mapping):
        raise BundleError(
            "INVALID_MANIFEST",
            f"{label}.staged_materials must be an object",
        )
    aliases = sorted(
        key
        for key in staged
        if _normalized_v2_staged_key(key) in _V2_BUILD_INPUT_ALIASES
    )
    if aliases:
        raise BundleError(
            "INVALID_MANIFEST",
            f"{label} must not stage v1 input aliases: " + ", ".join(aliases),
        )


def _check_v2_build_list(builds: Any, label: str) -> None:
    if not isinstance(builds, list):
        raise BundleError("INVALID_MANIFEST", f"{label} must be a list")
    for index, build in enumerate(builds):
        if not isinstance(build, Mapping):
            raise BundleError(
                "INVALID_MANIFEST", f"{label}[{index}] must be an object"
            )
        _check_v2_build_record(build, f"{label}[{index}]")


def _verify_v2_build_records(
    listed: Mapping[str, Mapping[str, Any]], data: Mapping[str, bytes]
) -> None:
    """Reject v1-only input aliases in every v2 build-record carrier.

    D4 applies to the archived build metadata and the execution metadata as
    well as ``report.json["builds"]``; checking only the report left a
    reproducible bypass. The scan is additive so a carrier without a build
    list or a record without ``staged_materials`` is not rejected here.
    """
    report = _parse_json_file(data, "report.json")
    if "builds" in report:
        _check_v2_build_list(report["builds"], "report.json.builds")

    execution_metadata = data.get("metadata/execution.json")
    if execution_metadata is not None:
        execution = _parse_json_file(data, "metadata/execution.json")
        if "builds" in execution:
            _check_v2_build_list(
                execution["builds"], "metadata/execution.json.builds"
            )

    # Scan every build_metadata role entry, not only the two fixed default
    # paths: a blocked bundle could otherwise place a build record elsewhere
    # and bypass both D4 and the D39 path check.
    for path, entry in listed.items():
        if entry["role"] == "build_metadata":
            _check_v2_build_record(_parse_json_file(data, path), path)


def _declared_build_outputs(plan_build_spec: Any) -> list[str]:
    """Return normalized ``build_spec.outputs`` paths when validly declared."""
    if not isinstance(plan_build_spec, Mapping):
        return []
    raw_outputs = plan_build_spec.get("outputs")
    if (
        not isinstance(raw_outputs, Sequence)
        or isinstance(raw_outputs, (str, bytes))
        or not raw_outputs
    ):
        return []
    normalized: list[str] = []
    for index, raw_output in enumerate(raw_outputs):
        if not isinstance(raw_output, str):
            return []
        try:
            norm_rel, _ = build_provenance.validate_build_spec_output_path(
                raw_output, index
            )
        except ValueError:
            return []
        normalized.append(norm_rel)
    return normalized


def _verify_v2_reuse_artifacts(
    plan_build_ref: Mapping[str, Any],
    data: Mapping[str, bytes],
    *,
    plan_build_spec: Any = None,
) -> None:
    """Bind the archived build bytes to the plan's per-version digests.

    A validation bundle is self-contained only when its own ``build.log`` and
    primary artifact bytes hash to the same digests declared in the plan's
    authoritative ``build_ref``. When ``plan_build_spec`` is provided, it must
    declare exactly one valid output path and the bundle must ship that exact
    path; multi-output or invalid ``build_spec.outputs`` fail closed. Only when
    ``plan_build_spec`` is ``None`` does verification fall back to the default
    ``parser`` path.
    """
    if plan_build_spec is None:
        expected_rel = "parser"
    else:
        declared_outputs = _declared_build_outputs(plan_build_spec)
        if len(declared_outputs) != 1:
            raise BundleError(
                "INVALID_MANIFEST",
                "reusable build_spec.outputs must declare exactly one valid "
                "output path (default parser or single custom output); "
                "multi-artifact reuse is not supported yet",
            )
        expected_rel = declared_outputs[0]
    artifacts = plan_build_ref["artifacts"]
    for version in _REPLAY_VERSIONS:
        prefix = f"build/{version}/"
        shipped_artifacts = sorted(
            path
            for path in data
            if path.startswith(prefix)
            and path
            not in (prefix + "metadata.json", prefix + "build.log")
            and not path.startswith(prefix + "build_provenance/")
        )
        expected_artifact = prefix + expected_rel
        if shipped_artifacts != [expected_artifact]:
            raise BundleError(
                "INVALID_MANIFEST",
                f"{version} build artifact layout does not match expected "
                f"{expected_artifact} (default parser / build_spec.outputs[0])",
            )
        bound_artifact = shipped_artifacts[0]
        expected = artifacts[version]
        for field, relative in (
            ("build_log_digest", prefix + "build.log"),
            ("artifact_digest", bound_artifact),
        ):
            actual = _digest(data[relative])
            if actual != expected[field]:
                raise BundleError(
                    "REUSE_MISMATCH",
                    f"{relative} sha256 does not match plan "
                    f"build_ref.{version}.{field}",
                )


def _verify_v2_reuse_plan(
    manifest: Mapping[str, Any], data: Mapping[str, bytes]
) -> None:
    """Bind a reusable validation bundle to the plan's authoritative build_ref.

    The plan's ``build_ref`` is the single authority (§8). The manifest copies
    it for offline inventory and ``reuse_origin`` points at the campaign; a
    disagreement between any of the three is a reuse mismatch, not a silent
    fallback. The plan itself is bound by ``plan_digest`` so copying its JSON
    fields into the manifest cannot launder a modified plan.
    """
    plan = _parse_json_file(data, "plan.json")
    if plan.get("schema_version") != contracts.SCHEMA_VERSION_V2:
        raise BundleError(
            "INVALID_MANIFEST",
            "a reuse execution plan requires schema_version=2",
        )
    try:
        actual_plan_digest = contracts.plan_digest(plan)
    except (KeyError, TypeError, ValueError) as error:
        raise BundleError(
            "INVALID_MANIFEST", f"plan.json is not a valid Plan v2: {error}"
        ) from error
    if actual_plan_digest != manifest.get("plan_digest"):
        raise BundleError(
            "DIGEST_MISMATCH",
            "manifest plan_digest does not match plan.json",
        )

    plan_build_ref = plan.get("build_ref")
    if not isinstance(plan_build_ref, Mapping):
        raise BundleError(
            "INVALID_MANIFEST", "a reuse execution plan requires build_ref"
        )
    normalized_plan_ref = _v2_build_ref(plan_build_ref, "plan.build_ref")
    normalized_manifest_ref = _v2_build_ref(
        manifest.get("build_ref"), "build_ref"
    )
    if normalized_plan_ref != normalized_manifest_ref:
        raise BundleError(
            "REUSE_MISMATCH",
            "manifest build_ref must equal plan.build_ref",
        )
    _v2_reuse_origin(
        manifest.get("reuse_origin"), "reuse_origin", normalized_plan_ref
    )
    _verify_v2_reuse_artifacts(
        normalized_plan_ref, data, plan_build_spec=plan.get("build_spec")
    )

    report = _parse_json_file(data, "report.json")
    if report.get("plan_digest") != manifest.get("plan_digest"):
        raise BundleError(
            "INVALID_MANIFEST",
            "report.plan_digest does not match manifest/plan",
        )
    if report.get("build_ref") != manifest.get("build_ref"):
        raise BundleError(
            "REUSE_MISMATCH", "report.build_ref does not match manifest"
        )
    if report.get("reuse_origin") != manifest.get("reuse_origin"):
        raise BundleError(
            "REUSE_MISMATCH", "report.reuse_origin does not match manifest"
        )


def _verify_v2_non_reuse(data: Mapping[str, bytes], bundle_kind: str) -> None:
    """A fixed/non-reuse plan and report must not claim a reused campaign."""
    plan = _parse_json_file(data, "plan.json")
    if plan.get("build_ref") is not None:
        raise BundleError(
            "INVALID_MANIFEST", "a non-reuse plan must not carry build_ref"
        )
    report = _parse_json_file(data, "report.json")
    if report.get("build_ref") is not None or report.get("reuse_origin") is not None:
        raise BundleError(
            "INVALID_MANIFEST",
            "a non-reuse report must not carry build_ref/reuse_origin",
        )
    if bundle_kind == "campaign":
        for field in ("verdict", "reason_code", "state"):
            if report.get(field) is not None:
                raise BundleError(
                    "INVALID_MANIFEST",
                    f"campaign report must not carry {field}",
                )


def _verify_v2_build_role_paths(
    listed: Mapping[str, Mapping[str, Any]]
) -> None:
    """D39 role+path check for every build role, including blocked bundles.

    A blocked bundle only relaxes identity fields; it does not allow a build
    role at an arbitrary path. Non-default artifact names are allowed at the
    path level because BuildSpec.outputs may name them; reuse byte binding
    rejects unsupported layouts separately.
    """
    for path, entry in listed.items():
        role = entry["role"]
        if role not in _V2_BUILD_ROLES:
            continue
        parts = PurePosixPath(path).parts
        if len(parts) < 3 or parts[0] != "build" or parts[1] not in _REPLAY_VERSIONS:
            raise BundleError(
                "INVALID_MANIFEST",
                f"build evidence {path} is not at a fixed build path",
            )
        relative = "/".join(parts[2:])
        if role == "build_metadata" and relative != "metadata.json":
            raise BundleError(
                "INVALID_MANIFEST",
                f"build metadata {path} must live at build/<version>/metadata.json",
            )
        if role == "build_log" and relative != "build.log":
            raise BundleError(
                "INVALID_MANIFEST",
                f"build log {path} must live at build/<version>/build.log",
            )
        if role == "build_artifact" and (
            relative in ("metadata.json", "build.log")
            or relative.startswith("build_provenance/")
        ):
            raise BundleError(
                "INVALID_MANIFEST",
                f"build artifact {path} collides with a non-artifact build role",
            )
        if role == "build_provenance":
            if not relative.startswith("build_provenance/"):
                raise BundleError(
                    "INVALID_MANIFEST",
                    f"build provenance {path} must live under build/<version>/build_provenance/",
                )
            face = relative[len("build_provenance/") :]
            if face not in _V2_BUILD_PROVENANCE_FACES:
                raise BundleError(
                    "INVALID_MANIFEST",
                    f"build provenance face {path} is not at a fixed face path",
                )


def _verify_v2_provenance_rules_version(
    manifest: Mapping[str, Any], data: Mapping[str, bytes]
) -> None:
    """Bind ``build_provenance_rules_version`` across manifest, plan and report."""
    expected = manifest.get("build_provenance_rules_version")
    if not isinstance(expected, str) or not expected.strip():
        raise BundleError(
            "INVALID_MANIFEST",
            "manifest build_provenance_rules_version must be a non-empty string",
        )
    report = _parse_json_file(data, "report.json")
    report_rules = report.get("build_provenance_rules_version")
    if not isinstance(report_rules, str) or report_rules != expected:
        raise BundleError(
            "INVALID_MANIFEST",
            "report.json build_provenance_rules_version is missing or does not "
            "match manifest",
        )
    plan = _parse_json_file(data, "plan.json")
    plan_rules = plan.get("build_provenance_rules_version")
    if not isinstance(plan_rules, str) or plan_rules != expected:
        raise BundleError(
            "INVALID_MANIFEST",
            "plan.json build_provenance_rules_version is missing or does not "
            "match manifest",
        )


def _records_candidate_crash_seeds(document: Mapping[str, Any]) -> bool:
    for list_key in ("candidate_seeds", "crash_seeds", "crashes"):
        value = document.get(list_key)
        if isinstance(value, list) and len(value) > 0:
            return True
    for count_key in ("crash_count", "candidate_seed_count"):
        value = document.get(count_key)
        if type(value) is int and value > 0:
            return True
    return False


def _verify_v2_campaign_crash_seeds(
    listed: Mapping[str, Mapping[str, Any]], data: Mapping[str, bytes]
) -> None:
    """Require a ``crash_seed`` role whenever a campaign records candidate crash seeds."""
    report = _parse_json_file(data, "report.json")
    has_candidate_seeds = _records_candidate_crash_seeds(report)
    if not has_candidate_seeds and "fuzz/provenance.json" in data:
        fuzz_prov = _parse_json_file(data, "fuzz/provenance.json")
        has_candidate_seeds = _records_candidate_crash_seeds(fuzz_prov)
    if has_candidate_seeds and "crash_seed" not in {
        entry["role"] for entry in listed.values()
    }:
        raise BundleError(
            "INVALID_MANIFEST",
            "campaign bundle records candidate crash seed(s) but is missing "
            "a crash_seed role entry",
        )


def _verify_v2_build_layout(
    listed: Mapping[str, Mapping[str, Any]], *, partial_execution: bool = False
) -> None:
    for version in _REPLAY_VERSIONS:
        prefix = f"build/{version}/"
        group = {
            path: entry for path, entry in listed.items() if path.startswith(prefix)
        }
        if partial_execution:
            # A partial execution bundle may have no build directory at all (a
            # pre-build block), or only the produce/build evidence that exists.
            # If a version group exists, its core log/metadata must be present;
            # a build_artifact is optional because a failed build may have no
            # verified artifact. Every present entry is still role/path checked.
            if group:
                _v2_required_role_paths(
                    listed, prefix + "metadata.json", "build_metadata"
                )
                _v2_required_role_paths(
                    listed, prefix + "build.log", "build_log"
                )
            provenance_faces = 0
            for path, entry in group.items():
                relative = path[len(prefix) :]
                if relative in ("metadata.json", "build.log"):
                    continue
                if relative.startswith("build_provenance/"):
                    if entry["role"] != "build_provenance":
                        raise BundleError(
                            "INVALID_MANIFEST",
                            f"evidence {path} must carry the build_provenance role",
                        )
                    face = relative[len("build_provenance/") :]
                    if face not in _V2_BUILD_PROVENANCE_FACES:
                        raise BundleError(
                            "INVALID_MANIFEST",
                            f"build provenance face {path} is not at a fixed face path",
                        )
                    provenance_faces += 1
                    continue
                if entry["role"] != "build_artifact":
                    raise BundleError(
                        "INVALID_MANIFEST",
                        f"evidence {path} must carry the build_artifact role",
                    )
            if provenance_faces > 1:
                raise BundleError(
                    "INVALID_MANIFEST",
                    f"manifest must carry at most one build_provenance face for build/{version}/",
                )
            continue
        if not group:
            raise BundleError(
                "INVALID_MANIFEST", f"manifest is missing build/{version}/ evidence"
            )
        _v2_required_role_paths(listed, prefix + "metadata.json", "build_metadata")
        _v2_required_role_paths(listed, prefix + "build.log", "build_log")
        artifacts = 0
        provenance_faces = 0
        for path, entry in group.items():
            relative = path[len(prefix) :]
            if relative in ("metadata.json", "build.log"):
                continue
            if relative.startswith("build_provenance/"):
                if entry["role"] != "build_provenance":
                    raise BundleError(
                        "INVALID_MANIFEST",
                        f"evidence {path} must carry the build_provenance role",
                    )
                face = relative[len("build_provenance/") :]
                if face not in _V2_BUILD_PROVENANCE_FACES:
                    raise BundleError(
                        "INVALID_MANIFEST",
                        f"build provenance face {path} is not at a fixed face path",
                    )
                provenance_faces += 1
                continue
            if entry["role"] != "build_artifact":
                raise BundleError(
                    "INVALID_MANIFEST",
                    f"evidence {path} must carry the build_artifact role",
                )
            artifacts += 1
        if artifacts == 0:
            raise BundleError(
                "INVALID_MANIFEST",
                f"manifest is missing a build_artifact for build/{version}/",
            )
        if provenance_faces == 0:
            raise BundleError(
                "INVALID_MANIFEST",
                f"manifest is missing a build_provenance face for build/{version}/",
            )
        if provenance_faces > 1:
            raise BundleError(
                "INVALID_MANIFEST",
                f"manifest must carry exactly one build_provenance face for build/{version}/",
            )
    for path, entry in listed.items():
        if entry["role"] in _V2_BUILD_ROLES and not (
            path.startswith("build/vulnerable/") or path.startswith("build/fixed/")
        ):
            raise BundleError(
                "INVALID_MANIFEST",
                f"build evidence {path} is not at a fixed build path",
            )


def _verify_v2_replay_layout(
    listed: Mapping[str, Mapping[str, Any]],
    bundle_kind: str,
    *,
    require_complete: bool = True,
) -> None:
    expected = _v2_replay_expected_paths()
    if bundle_kind == "execution" and require_complete:
        for path, role in expected.items():
            _v2_required_role_paths(listed, path, role)
    for path, entry in listed.items():
        if entry["role"] in _V2_REPLAY_ROLES:
            if bundle_kind == "campaign":
                raise BundleError(
                    "INVALID_MANIFEST",
                    "a campaign bundle must not carry replay evidence",
                )
            if path not in expected:
                raise BundleError(
                    "INVALID_MANIFEST",
                    f"replay evidence {path} is not at a fixed replay path",
                )
            if expected[path] != entry["role"]:
                raise BundleError(
                    "INVALID_MANIFEST",
                    f"evidence {path} must carry the {expected[path]} role, "
                    f"not {entry['role']!r}",
                )


def _is_partial_execution(
    bundle_kind: str,
    verdict: Any,
    reason_code: str | None,
    report: Mapping[str, Any],
    listed: Mapping[str, Mapping[str, Any]],
) -> bool:
    """Return True for a FAILED or legitimate pre-rule INCONCLUSIVE bundle.

    For ``INCONCLUSIVE``, requires an explicit ``"rule": null`` key in
    ``report.json`` (omitting ``"rule"`` is rejected), a pre-rule reason code
    from ``_V2_PARTIAL_INCONCLUSIVE_REASONS``, and either produced runtime
    evidence (probe/build/replay) or explicit pre-rule failure diagnostics
    (``missing`` or ``error``), blocking empty hollow shells.
    """
    if bundle_kind != "execution":
        return False
    if verdict == "FAILED":
        return True
    if verdict != "INCONCLUSIVE":
        return False
    if "rule" not in report or report["rule"] is not None:
        return False
    if reason_code not in _V2_PARTIAL_INCONCLUSIVE_REASONS:
        return False
    if "reason_code" in report and report["reason_code"] != reason_code:
        return False
    has_runtime_evidence = "metadata/probe.json" in listed or any(
        path.startswith(("build/", "replay/")) for path in listed
    )
    missing_list = report.get("missing")
    has_missing = isinstance(missing_list, list) and any(
        isinstance(item, str) and bool(item.strip()) for item in missing_list
    )
    report_error = report.get("error")
    has_error = isinstance(report_error, str) and bool(report_error.strip())
    return has_runtime_evidence or has_missing or has_error


def _v2_required_roles_and_paths(
    bundle_kind: str, partial_execution: bool
) -> tuple[frozenset[str], Mapping[str, str]]:
    if bundle_kind == "blocked":
        return _BLOCKED_REQUIRED_ROLES, {}
    if partial_execution:
        return (
            _V2_PARTIAL_EXECUTION_REQUIRED_ROLES,
            _V2_PARTIAL_EXECUTION_REQUIRED_PATHS,
        )
    return _V2_REQUIRED_ROLES[bundle_kind], _V2_REQUIRED_PATHS[bundle_kind]


def _verify_v2_layout(
    listed: Mapping[str, Mapping[str, Any]],
    bundle_kind: str,
    *,
    partial_execution: bool = False,
) -> None:
    if bundle_kind not in ("execution", "campaign"):
        # Blocked bundles do not run the build layout; keep D39's role/path
        # guard first so a build role cannot hide at an arbitrary path.
        _verify_v2_build_role_paths(listed)
    for path, role in _V2_FIXED_PATH_ROLES.items():
        entry = listed.get(path)
        if entry is not None and entry["role"] != role:
            raise BundleError(
                "INVALID_MANIFEST",
                f"evidence {path} must carry the {role} role, "
                f"not {entry['role']!r}",
            )
    for path, entry in listed.items():
        role = entry["role"]
        fixed_path = _V2_FIXED_ROLE_PATHS.get(role)
        if fixed_path is not None and fixed_path != path:
            raise BundleError(
                "INVALID_MANIFEST",
                f"evidence role {role} must live at {fixed_path}, not {path}",
            )
        if role == "experiment_spec" and not (
            path.startswith("experiments/") and path.endswith(".json")
        ):
            raise BundleError(
                "INVALID_MANIFEST",
                "experiment_spec evidence must live under experiments/*.json",
            )

    if bundle_kind in ("execution", "campaign"):
        fixed_metadata = [
            ("metadata/execution.json", "execution_metadata"),
            ("metadata/case.json", "case_config"),
        ]
        if not partial_execution:
            fixed_metadata.insert(1, ("metadata/probe.json", "probe"))
        for path, role in fixed_metadata:
            _v2_required_role_paths(listed, path, role)
        _verify_v2_build_layout(
            listed, partial_execution=partial_execution
        )
        # T13a's partial-build role errors keep precedence; D39 still rejects
        # any build role left at a non-fixed path after the layout check.
        _verify_v2_build_role_paths(listed)
        _verify_v2_replay_layout(
            listed,
            bundle_kind,
            require_complete=not partial_execution,
        )

    has_review = "review.json" in listed
    has_admission = "admission.json" in listed
    if bundle_kind == "execution":
        if has_review == has_admission:
            raise BundleError(
                "INVALID_MANIFEST",
                "an execution bundle must carry exactly one of "
                "review.json or admission.json",
            )
    elif bundle_kind == "campaign":
        if has_admission:
            raise BundleError(
                "INVALID_MANIFEST", "a campaign bundle must not carry admission.json"
            )
        if not has_review:
            raise BundleError(
                "INVALID_MANIFEST", "a campaign bundle requires review.json"
            )
    elif has_admission:
        raise BundleError(
            "INVALID_MANIFEST", "a blocked bundle must not carry admission.json"
        )


def _verify_v2_blocked_semantics(
    *,
    job_id: str,
    plan_digest: str | None,
    verdict: str | None,
    manifest_reason: str | None,
    data: Mapping[str, bytes],
) -> None:
    """Verify report.json, report.md and optional plan/review on v2 blocked bundles."""
    report = _parse_json_file(data, "report.json")
    if type(report.get("schema_version")) is not int or report.get(
        "schema_version"
    ) != contracts.SCHEMA_VERSION_V2:
        raise BundleError(
            "INVALID_MANIFEST", "report schema_version must be 2"
        )
    if report.get("bundle_kind") != "blocked":
        raise BundleError(
            "INVALID_MANIFEST", "report bundle_kind must be blocked"
        )
    try:
        jsonutil.require_rfc3339(report.get("created_at"), "report.created_at")
    except ValueError as error:
        raise BundleError("INVALID_MANIFEST", str(error)) from error
    if report.get("job_id") != job_id:
        raise BundleError(
            "INVALID_MANIFEST", "report job_id does not match manifest"
        )
    if report.get("plan_digest") != plan_digest:
        raise BundleError(
            "INVALID_MANIFEST", "report plan_digest does not match manifest"
        )
    report_verdict = report.get("verdict")
    if report_verdict != "BLOCKED" or report_verdict != verdict:
        raise BundleError(
            "INVALID_MANIFEST", "a blocked bundle must record verdict BLOCKED"
        )
    if report.get("state") != "BLOCKED":
        raise BundleError(
            "INVALID_MANIFEST", "report state must equal report verdict"
        )
    report_reason = _reason_code_valid(report)
    if manifest_reason != report_reason:
        raise BundleError(
            "INVALID_MANIFEST", "manifest reason_code does not match report"
        )
    if report_reason is None or not reason_allowed_v2("BLOCKED", report_reason):
        raise BundleError(
            "INVALID_MANIFEST",
            "a blocked bundle requires an allowed BLOCKED reason_code",
        )
    missing = report.get("missing")
    if not isinstance(missing, list) or not all(
        isinstance(item, str) for item in missing
    ):
        raise BundleError(
            "INVALID_MANIFEST", "report missing must be a list of strings"
        )
    report_error = report.get("error")
    if report_error is not None and not isinstance(report_error, str):
        raise BundleError(
            "INVALID_MANIFEST", "report error must be text or null"
        )
    evidence_complete = report.get("evidence_complete")
    if evidence_complete is not None and type(evidence_complete) is not bool:
        raise BundleError(
            "INVALID_MANIFEST", "report evidence_complete must be a boolean"
        )
    markdown = data.get("report.md")
    if markdown is None:
        raise BundleError("INVALID_MANIFEST", "report.md is missing")
    expected_markdown = report.get("report_markdown_sha256")
    if (
        not isinstance(expected_markdown, str)
        or not _SHA256_HEX.fullmatch(expected_markdown)
    ):
        raise BundleError(
            "INVALID_MANIFEST",
            "report report_markdown_sha256 is missing or invalid",
        )
    if _sha256(markdown) != expected_markdown:
        raise BundleError(
            "DIGEST_MISMATCH",
            "report.md digest does not match report.json",
        )
    _verify_report_markdown(markdown, "BLOCKED", report_reason)
    _validate_blocked_artifacts(data, plan_digest=plan_digest, report=report)
    if plan_digest is None:
        if report.get("review") is not None:
            raise BundleError(
                "INVALID_MANIFEST",
                "report review must be null when review.json is absent",
            )
        return
    plan = _parse_json_file(data, "plan.json")
    for field in ("case_id", "cve_id"):
        if report.get(field) is not None and report.get(field) != plan.get(
            field
        ):
            raise BundleError(
                "INVALID_MANIFEST", f"report {field} does not match the plan"
            )


def _verify_bundle_v2(
    root_path: Path,
    manifest: dict[str, Any],
    manifest_bytes: bytes,
) -> BundleVerification:
    """Verify the v2 manifest skeleton, the blocked semantics and roles.

    T10 owns dispatch, the v2 manifest header/role surface and the blocked
    bundle semantics: blocked bundles are replayed here by
    ``_verify_v2_blocked_semantics`` (report shape, plan/review binding and
    markdown digest). Execution/campaign report replay is still filled in by
    the later evidence-v2 tasks (T13/T14). The generic inventory walk and
    digest checks are shared with v1 so path traversal, symlinks, extra/missing
    files and digest tampering keep the same guarantees.

    T13a adds one narrow partial-execution layout: a ``FAILED`` execution or an
    ``INCONCLUSIVE`` execution whose report has no rule trace may archive only
    the evidence that was actually produced. The fixed documents (report, plan,
    envelope, budget, execution/case metadata) are still mandatory; build and
    replay roles are validated whenever present, but an absent build artifact
    or replay file is not fabricated to satisfy the full role table.
    """
    (
        job_id,
        bundle_kind,
        plan_digest,
        files,
        verdict,
        manifest_reason,
    ) = _validate_v2_manifest_header(manifest)
    entries = []
    seen: set[str] = set()
    for entry in files:
        entries.append(_validate_entry(entry, seen, _V2_ROLE_NAMES))
    listed = {entry["path"]: entry for entry in entries}
    roles = {entry["role"] for entry in entries}
    data: dict[str, bytes] | None = None
    partial_execution = False
    if bundle_kind == "execution" and verdict in ("FAILED", "INCONCLUSIVE"):
        # The partial decision depends on report.rule and reason_code, so read
        # the listed files once here and reuse the verified bytes below. A
        # malformed/missing report still fails closed before any layout is
        # accepted.
        data = _read_listed_files(root_path, listed)
        report = _parse_json_file(data, "report.json")
        partial_execution = _is_partial_execution(
            bundle_kind, verdict, manifest_reason, report, listed
        )
    required_roles, required_paths = _v2_required_roles_and_paths(
        bundle_kind, partial_execution
    )
    if not required_roles <= roles:
        missing = sorted(required_roles - roles)
        raise BundleError(
            "INVALID_MANIFEST",
            "manifest is missing required roles: " + ", ".join(missing),
        )

    if bundle_kind == "blocked":
        _require_blocked_paths(listed)
    else:
        _require_required_paths(listed, required_paths)
    _verify_v2_layout(
        listed, bundle_kind, partial_execution=partial_execution
    )
    if data is None:
        data = _read_listed_files(root_path, listed)
    _verify_v2_build_records(listed, data)
    if bundle_kind in ("execution", "campaign"):
        _verify_v2_provenance_rules_version(manifest, data)
    if bundle_kind == "execution":
        if manifest.get("reuse_origin") is not None:
            _verify_v2_reuse_plan(manifest, data)
        else:
            _verify_v2_non_reuse(data, bundle_kind)
    elif bundle_kind == "campaign":
        _verify_v2_non_reuse(data, bundle_kind)
        _verify_v2_campaign_crash_seeds(listed, data)
    if bundle_kind == "blocked":
        _verify_v2_blocked_semantics(
            job_id=job_id,
            plan_digest=plan_digest,
            verdict=verdict,
            manifest_reason=manifest_reason,
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
    dir_mode: int = 0o755,
    file_mode: int = 0o644,
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
    temporary.mkdir(mode=dir_mode)
    temporary.chmod(dir_mode)
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
            output.chmod(file_mode)
        # Copy the exact bytes that were verified and hashed, never a reread
        # from the mutable source directory.
        (temporary / "manifest.json").write_bytes(verified.manifest_bytes)
        (temporary / "manifest.json").chmod(file_mode)
        _apply_bundle_modes(temporary, dir_mode=dir_mode, file_mode=file_mode)
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


# ---------------------------------------------------------------------------
# Family archive index and aggregate export (D43, T12)
# ---------------------------------------------------------------------------

FAMILY_INDEX_FILENAME = "family.json"
FAMILY_INDEX_SCHEMA_VERSION = 2
FAMILY_INDEX_KIND = "family_index"
MAX_FAMILY_INDEX_BYTES = 4 * 1024 * 1024
# A round entry records the terminal job state, never an "archived" state:
# archival lives in jobs.evidence_status and must not leak into the enum.
# A round index entry is the terminal *job* state of a validation round.
# ``COMPLETED`` is the campaign/family terminal introduced by D40 and is not a
# validation-round verdict; allowing it here would let a campaign completion
# masquerade as a round conclusion.
_FAMILY_ROUND_STATES = frozenset(
    {
        "REPRODUCED",
        "NOT_REPRODUCED",
        "INCONCLUSIVE",
        "BLOCKED",
        "FAILED",
    }
)
_FAMILY_INDEX_FIELDS = frozenset(
    {
        "schema_version",
        "kind",
        "family_id",
        "state",
        "created_at",
        "family_approval_digest",
        "rounds",
        "campaign",
        "budget",
    }
)
_FAMILY_ROUND_FIELDS = frozenset(
    {"round_no", "job_id", "plan_digest", "state", "evidence_digest"}
)
_FAMILY_CAMPAIGN_FIELDS = frozenset({"job_id", "bundle_digest"})
_FAMILY_BUDGET_FIELDS = (
    "max_total_seconds",
    "max_fuzz_seconds",
    "spent_seconds",
    "spent_fuzz_seconds",
    "remaining_seconds",
    "remaining_fuzz_seconds",
)


@dataclass(frozen=True)
class FamilyIndexInfo:
    path: Path
    document: dict[str, Any]
    data: bytes
    digest: str


@dataclass(frozen=True)
class FamilyExportInfo:
    root: Path
    family: FamilyIndexInfo
    round_digests: dict[int, str]
    campaign_digest: str | None

    @property
    def family_digest(self) -> str:
        return self.family.digest


def _family_fail(message: str) -> None:
    raise BundleError("INVALID_MANIFEST", f"family index {message}")


def _family_uuid(value: Any, label: str) -> str:
    """Return ``value`` only when it is canonical lowercase provider text.

    ``uuid.UUID`` accepts braces, ``urn:uuid:`` prefixes and uppercase input;
    the family index schema requires the canonical provider representation so
    two spellings can never name the same family under a different digest.
    """
    if not isinstance(value, str):
        raise BundleError(
            "INVALID_MANIFEST", f"family index {label} must be a UUID"
        )
    try:
        parsed = uuid.UUID(value)
    except (TypeError, ValueError, AttributeError) as error:
        raise BundleError(
            "INVALID_MANIFEST", f"family index {label} must be a UUID"
        ) from error
    if str(parsed) != value:
        raise BundleError(
            "INVALID_MANIFEST",
            f"family index {label} must be a canonical lowercase UUID",
        )
    return value


def _family_digest(value: Any, label: str) -> str:
    if not isinstance(value, str) or not _DIGEST.fullmatch(value):
        raise BundleError(
            "INVALID_MANIFEST",
            f"family index {label} must be a sha256 digest",
        )
    return value


def _family_int(value: Any, label: str) -> int:
    if type(value) is not int:
        raise BundleError(
            "INVALID_MANIFEST", f"family index {label} must be an integer"
        )
    return value


def validate_family_index(document: Any) -> None:
    """Validate the D43 family index (not an evidence bundle).

    The schema is closed: an unknown or missing field fails closed. A round's
    ``state`` is the terminal job state; archived status never appears here.
    """
    if not isinstance(document, dict):
        _family_fail("must be a JSON object")
    if set(document) != _FAMILY_INDEX_FIELDS:
        missing = _FAMILY_INDEX_FIELDS - set(document)
        unknown = set(document) - _FAMILY_INDEX_FIELDS
        detail = []
        if missing:
            detail.append("missing " + ", ".join(sorted(missing)))
        if unknown:
            detail.append("unknown " + ", ".join(sorted(unknown)))
        _family_fail("fields are invalid: " + "; ".join(detail))
    if (
        type(document["schema_version"]) is not int
        or document["schema_version"] != FAMILY_INDEX_SCHEMA_VERSION
    ):
        _family_fail(f"schema_version must be integer {FAMILY_INDEX_SCHEMA_VERSION}")
    if document["kind"] != FAMILY_INDEX_KIND:
        _family_fail(f"kind must be {FAMILY_INDEX_KIND!r}")
    family_id = _family_uuid(document["family_id"], "family_id")
    if document["state"] != "COMPLETED":
        _family_fail("state must be 'COMPLETED'")
    created_at = document["created_at"]
    if not isinstance(created_at, str):
        _family_fail("created_at must be an RFC 3339 timestamp")
    try:
        normalized = jsonutil.require_rfc3339(created_at, "family index created_at")
    except ValueError as error:
        _family_fail(str(error))
    if normalized != created_at:
        _family_fail("created_at must be a UTC 'Z' RFC 3339 timestamp")
    _family_digest(
        document["family_approval_digest"], "family_approval_digest"
    )

    rounds = document["rounds"]
    if not isinstance(rounds, list):
        _family_fail("rounds must be a list")
    previous_round = 0
    seen_jobs: set[str] = set()
    for position, entry in enumerate(rounds):
        label = f"rounds[{position}]"
        if not isinstance(entry, dict) or set(entry) != _FAMILY_ROUND_FIELDS:
            _family_fail(f"{label} fields are invalid")
        round_no = entry["round_no"]
        if type(round_no) is not int or round_no < 1:
            _family_fail(f"{label}.round_no must be a positive integer")
        if round_no <= previous_round:
            _family_fail("rounds must be strictly ascending by round_no")
        previous_round = round_no
        job_id = _family_uuid(entry["job_id"], f"{label}.job_id")
        if job_id in seen_jobs:
            _family_fail(f"{label}.job_id is duplicated")
        seen_jobs.add(job_id)
        _family_digest(entry["plan_digest"], f"{label}.plan_digest")
        state = entry["state"]
        if not isinstance(state, str) or state not in _FAMILY_ROUND_STATES:
            _family_fail(f"{label}.state is not a terminal job state")
        _family_digest(entry["evidence_digest"], f"{label}.evidence_digest")

    campaign = document["campaign"]
    campaign_job_id: str | None = None
    if campaign is not None:
        if not isinstance(campaign, dict) or set(campaign) != _FAMILY_CAMPAIGN_FIELDS:
            _family_fail("campaign fields are invalid")
        campaign_job_id = _family_uuid(campaign["job_id"], "campaign.job_id")
        _family_digest(campaign["bundle_digest"], "campaign.bundle_digest")
    if campaign is None and not rounds:
        _family_fail("a fixed family must contain at least one round")
    if family_id in seen_jobs or (
        campaign_job_id is not None
        and (campaign_job_id == family_id or campaign_job_id in seen_jobs)
    ):
        _family_fail(
            "family_id, campaign.job_id and rounds[].job_id must be distinct"
        )

    budget = document["budget"]
    if not isinstance(budget, dict) or set(budget) != set(_FAMILY_BUDGET_FIELDS):
        _family_fail("budget fields are invalid")
    values = {
        field: _family_int(budget[field], f"budget.{field}")
        for field in _FAMILY_BUDGET_FIELDS
    }
    max_total = values["max_total_seconds"]
    max_fuzz = values["max_fuzz_seconds"]
    spent = values["spent_seconds"]
    spent_fuzz = values["spent_fuzz_seconds"]
    remaining = values["remaining_seconds"]
    remaining_fuzz = values["remaining_fuzz_seconds"]
    if max_total <= 0:
        _family_fail("budget.max_total_seconds must be positive")
    if not 0 <= max_fuzz <= max_total:
        _family_fail("budget.max_fuzz_seconds must be within max_total_seconds")
    if spent < 0 or spent_fuzz < 0 or spent_fuzz > spent:
        _family_fail("budget spent fields are invalid")
    if not 0 <= remaining <= max_total or not 0 <= remaining_fuzz <= max_fuzz:
        _family_fail("budget remaining fields are invalid")
    if spent + remaining != max_total or spent_fuzz + remaining_fuzz != max_fuzz:
        _family_fail("budget does not reconcile with the ledger")


def build_family_index(
    *,
    family_id: Any,
    created_at: str,
    family_approval_digest: str,
    rounds: Any,
    campaign: Mapping[str, Any] | None,
    budget: Mapping[str, Any],
) -> dict[str, Any]:
    """Assemble and validate one D43 family index document."""
    entries = []
    try:
        for entry in rounds:
            entries.append(
                {
                    "round_no": entry["round_no"],
                    "job_id": str(entry["job_id"]),
                    "plan_digest": entry["plan_digest"],
                    "state": entry["state"],
                    "evidence_digest": entry["evidence_digest"],
                }
            )
    except (KeyError, TypeError) as error:
        raise BundleError(
            "INVALID_MANIFEST", "family index round input is incomplete"
        ) from error
    entries.sort(key=lambda entry: entry["round_no"])
    campaign_document: dict[str, Any] | None = None
    if campaign is not None:
        try:
            campaign_document = {
                "job_id": str(campaign["job_id"]),
                "bundle_digest": campaign["bundle_digest"],
            }
        except (KeyError, TypeError) as error:
            raise BundleError(
                "INVALID_MANIFEST", "family index campaign input is incomplete"
            ) from error
    budget_document = {field: budget[field] for field in _FAMILY_BUDGET_FIELDS}
    document = {
        "schema_version": FAMILY_INDEX_SCHEMA_VERSION,
        "kind": FAMILY_INDEX_KIND,
        "family_id": str(family_id),
        "state": "COMPLETED",
        "created_at": created_at,
        "family_approval_digest": family_approval_digest,
        "rounds": entries,
        "campaign": campaign_document,
        "budget": budget_document,
    }
    validate_family_index(document)
    return document


def canonical_family_index_bytes(document: Any) -> bytes:
    validate_family_index(document)
    return jsonutil.canonical_bytes(document) + b"\n"


def _read_family_index(path: Path | str) -> tuple[dict[str, Any], bytes]:
    family_path = Path(path)
    if family_path.is_symlink():
        raise BundleError("SYMLINK", "family index must not be a symlink")
    try:
        data = family_path.read_bytes()
    except FileNotFoundError as error:
        raise BundleError(
            "INVALID_MANIFEST", "family index is missing"
        ) from error
    except OSError as error:
        raise BundleError(
            "EVIDENCE_NOT_AVAILABLE", f"family index cannot be read: {error}"
        ) from error
    if len(data) > MAX_FAMILY_INDEX_BYTES:
        raise BundleError(
            "INVALID_MANIFEST",
            f"family index exceeds {MAX_FAMILY_INDEX_BYTES} bytes",
        )
    try:
        document = jsonutil.loads_strict(data)
    except jsonutil.StrictJsonError as error:
        raise BundleError(
            "INVALID_MANIFEST", f"family index is not strict JSON: {error}"
        ) from error
    validate_family_index(document)
    if canonical_family_index_bytes(document) != data:
        raise BundleError(
            "INVALID_MANIFEST", "family index bytes are not canonical"
        )
    return document, data


def _atomic_write_family_index(
    path: Path, data: bytes, *, file_mode: int
) -> None:
    parent = path.parent
    try:
        parent.mkdir(mode=0o755, parents=True, exist_ok=True)
    except OSError as error:
        raise BundleError(
            "EVIDENCE_WRITE_FAILED", f"cannot create family evidence root: {error}"
        ) from error
    if parent.is_symlink():
        raise BundleError("SYMLINK", "family evidence root must not be a symlink")
    temporary = parent / f".{path.name}.tmp-{uuid.uuid4().hex}"
    try:
        with open(temporary, "xb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, file_mode)
        os.replace(temporary, path)
        try:
            directory = os.open(parent, os.O_RDONLY)
        except OSError:
            directory = None
        if directory is not None:
            try:
                os.fsync(directory)
            except OSError:
                pass
            finally:
                os.close(directory)
    except OSError as error:
        try:
            temporary.unlink()
        except OSError:
            pass
        raise BundleError(
            "EVIDENCE_WRITE_FAILED", f"cannot write family index: {error}"
        ) from error


def load_family_index(path: Path | str) -> FamilyIndexInfo:
    family_path = Path(path)
    document, data = _read_family_index(family_path)
    return FamilyIndexInfo(
        path=family_path,
        document=document,
        data=data,
        digest="sha256:" + hashlib.sha256(data).hexdigest(),
    )


def finalize_family_index(
    path: Path | str,
    document: Mapping[str, Any] | None = None,
    *,
    expected_digest: str | None = None,
    complete: Callable[[str, str], None] | None = None,
    replace_unprotected: bool = False,
    file_mode: int = 0o444,
) -> FamilyIndexInfo:
    """Ensure ``family.json`` exists and only then compute its digest.

    The existing file always wins, so a crash after the atomic write but before
    ``complete_family`` replays the same bytes instead of rewriting them with a
    new ``created_at``. When a rebuilt document is supplied, every field except
    the archive timestamp must still match the existing index; a stale or
    tampered file fails closed.

    ``replace_unprotected`` is only for a family that is still ``AGGREGATING``
    and has no database evidence pointer: a leftover ``family.json`` from an
    aborted attempt (for example with an older approval digest) is an orphan,
    not the authoritative index, so it may be atomically replaced. A completed
    family always passes ``False`` and can never be overwritten.
    ``complete`` is invoked only after validation and digest computation
    succeed.
    """
    family_path = Path(path)
    if family_path.name != FAMILY_INDEX_FILENAME:
        raise BundleError(
            "INVALID_MANIFEST",
            f"family index basename must be {FAMILY_INDEX_FILENAME}",
        )
    candidate: bytes | None = None
    candidate_document: dict[str, Any] | None = None
    if document is not None:
        validate_family_index(document)
        candidate_document = dict(document)
        candidate = canonical_family_index_bytes(candidate_document)

    if family_path.exists() or family_path.is_symlink():
        existing = load_family_index(family_path)
        replaced = False
        if candidate_document is not None and candidate is not None:
            mismatch = [
                field
                for field in _FAMILY_INDEX_FIELDS - {"created_at"}
                if existing.document[field] != candidate_document[field]
            ]
            if mismatch:
                if not replace_unprotected:
                    _family_fail(
                        f"existing {mismatch[0]} does not match the rebuilt index"
                    )
                _atomic_write_family_index(
                    family_path, candidate, file_mode=file_mode
                )
                replaced = True
            elif existing.document["state"] != "COMPLETED":
                _family_fail("existing state must be 'COMPLETED'")
        if replaced:
            info = FamilyIndexInfo(
                path=family_path,
                document=candidate_document,
                data=candidate,
                digest="sha256:" + hashlib.sha256(candidate).hexdigest(),
            )
        else:
            info = existing
    else:
        if candidate is None or candidate_document is None:
            raise BundleError("INVALID_MANIFEST", "family index is missing")
        _atomic_write_family_index(family_path, candidate, file_mode=file_mode)
        info = FamilyIndexInfo(
            path=family_path,
            document=candidate_document,
            data=candidate,
            digest="sha256:" + hashlib.sha256(candidate).hexdigest(),
        )

    if expected_digest is not None and info.digest != expected_digest:
        raise BundleError(
            "DIGEST_MISMATCH", "family index digest does not match the trusted record"
        )
    if complete is not None:
        complete(str(family_path), info.digest)
    return info


def export_family(
    family_index: Path | str,
    destination: Path | str,
    *,
    campaign_source: Path | str | None = None,
    rounds: Any = (),
    expected_family_digest: str | None = None,
    dir_mode: int = 0o755,
    file_mode: int = 0o644,
) -> FamilyExportInfo:
    """Aggregate-export a family without rewriting any bundle manifest.

    Layout is fixed by interface §9: ``family.json``, ``campaign/`` and
    ``rounds/<round_no>/``. Every round and the campaign are copied through
    :func:`export_bundle`, so each directory stays an independently verifiable
    bundle with the archived manifest bytes.
    """
    family = load_family_index(family_index)
    if expected_family_digest is not None and (
        family.digest != expected_family_digest
    ):
        raise BundleError(
            "DIGEST_MISMATCH",
            "the archived family index digest does not match the trusted record",
        )
    index = family.document
    round_sources: dict[int, Path] = {}
    try:
        for round_no, source in rounds:
            if type(round_no) is not int:
                raise BundleError(
                    "INVALID_MANIFEST", "family export round_no must be an integer"
                )
            if round_no in round_sources:
                raise BundleError(
                    "INVALID_MANIFEST",
                    f"family export round_no {round_no} is duplicated",
                )
            round_sources[round_no] = Path(source)
    except (TypeError, ValueError) as error:
        raise BundleError(
            "INVALID_MANIFEST", "family export rounds must be (round_no, source) pairs"
        ) from error
    index_rounds = {entry["round_no"]: entry for entry in index["rounds"]}
    if set(round_sources) != set(index_rounds):
        raise BundleError(
            "INVALID_MANIFEST",
            "family export round sources do not match the family index",
        )
    campaign_entry = index["campaign"]
    if (campaign_entry is None) != (campaign_source is None):
        raise BundleError(
            "INVALID_MANIFEST",
            "family export campaign source does not match the family index",
        )

    target = Path(destination)
    if target.is_symlink():
        raise BundleError("EXPORT_TARGET_NOT_EMPTY", "export target is a symlink")
    if target.exists():
        if not target.is_dir():
            raise BundleError(
                "EXPORT_TARGET_NOT_EMPTY", "export target is not a directory"
            )
        if any(target.iterdir()):
            raise BundleError("EXPORT_TARGET_NOT_EMPTY", "export target is not empty")
    try:
        target_resolved = target.resolve()
        family_resolved = family.path.parent.resolve()
        if (
            target_resolved == family_resolved
            or family_resolved in target_resolved.parents
        ):
            raise BundleError(
                "EXPORT_TARGET_NOT_EMPTY", "export target must be outside the family index"
            )
    except OSError as error:
        raise BundleError("EXPORT_TARGET_NOT_EMPTY", str(error)) from error

    parent = target.parent
    parent.mkdir(parents=True, exist_ok=True)
    temporary = parent / f".{target.name}.export-{uuid.uuid4().hex}"
    temporary.mkdir(mode=dir_mode)
    temporary.chmod(dir_mode)
    round_digests: dict[int, str] = {}
    campaign_digest: str | None = None
    try:
        (temporary / FAMILY_INDEX_FILENAME).write_bytes(family.data)
        (temporary / FAMILY_INDEX_FILENAME).chmod(file_mode)
        for round_no in sorted(round_sources):
            exported = export_bundle(
                round_sources[round_no],
                temporary / "rounds" / str(round_no),
                expected_manifest_digest=index_rounds[round_no]["evidence_digest"],
                dir_mode=dir_mode,
                file_mode=file_mode,
            )
            round_digests[round_no] = exported.manifest_digest
        if campaign_source is not None and campaign_entry is not None:
            exported = export_bundle(
                campaign_source,
                temporary / "campaign",
                expected_manifest_digest=campaign_entry["bundle_digest"],
                dir_mode=dir_mode,
                file_mode=file_mode,
            )
            campaign_digest = exported.manifest_digest
        if (temporary / FAMILY_INDEX_FILENAME).read_bytes() != family.data:
            raise BundleError("DIGEST_MISMATCH", "export rewrote the family index")
        if target.exists():
            target.rmdir()
        temporary.rename(target)
    except BaseException:
        shutil.rmtree(temporary, ignore_errors=True)
        raise
    return FamilyExportInfo(
        root=target,
        family=family,
        round_digests=round_digests,
        campaign_digest=campaign_digest,
    )

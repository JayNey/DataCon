"""Release candidate manifest, SBOM, promotion gate, smoke/rollback, and B03 acceptance (T07/T08)."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import shutil
import tomllib
from typing import Any, Callable, Mapping, Protocol, Sequence
import uuid

from datacon import contracts, evidence, jsonutil
from datacon.tools.sandbox import _extract_compile_args
from datacon.verdict import RunObservation, VerdictPolicy, decide_verdict

SCHEMA_VERSION = 1
CONTRACT_VERSION = contracts.SCHEMA_VERSION
# One source of truth for the pinned analysis toolchain. ci.yml and release.yml
# are checked against this constant by tests/contract/test_release_workflow.py;
# duplicating the literal in a second module is a release-blocking drift.
TOOLCHAIN_IMAGE = (
    "silkeh/clang:19-bookworm"
    "@sha256:f5ce959d91f059acf5a4b3f1c19f46713c4b2881c7d7cd1d5143ca1d1412277f"
)
TOOLCHAIN_IMAGE_DIGEST = TOOLCHAIN_IMAGE.split("@", 1)[1]
SECCOMP_PROFILE_DIGEST = (
    "sha256:885442dc08f21f8d60f99ea43d59af88b1c529103815fe24bbf9ce998d3a609d"
)
APPROVAL_MAX_AGE = timedelta(hours=24)
APPROVAL_FUTURE_SKEW = timedelta(minutes=5)
ACTIVE_JOB_STATES = ("PREPARING", "RUNNING", "ARCHIVING")
RELEASE_ENVIRONMENT = "internal-lab"
TEST_REPORT_FILES = (
    "junit-asan.xml",
    "junit-contract.xml",
    "junit-docker.xml",
    "junit-postgres.xml",
)
SCAN_REPORT_FILE = "trivy.json"
SBOM_REPORT_FILE = "sbom.cdx.json"
RELEASE_MANIFEST_FILE = "release-candidate-manifest.json"
CANDIDATE_IMAGE_TAR = "control-plane-image.tar"
PROMOTION_RESULT_FILE = "promotion-result.json"

_SHA256 = re.compile(r"sha256:[0-9a-f]{64}")
_GIT_SHA40 = re.compile(r"[0-9a-f]{40}")
_MIGRATION_NAME = re.compile(r"[0-9]{3}_[A-Za-z0-9_]+\.sql")

_REQUIRED_RC_FIELDS = frozenset(
    {
        "schema_version",
        "contract_version",
        "source_commit",
        "control_plane_image_id",
        "wheel_digest",
        "toolchain_image_digest",
        "migration_version",
        "migrations",
        "sbom_digest",
        "test_report_digest",
        "scan_report_digest",
        "created_at",
    }
)


class ReleaseGateError(RuntimeError):
    """Raised when a release candidate, promotion, or rollback gate fails closed."""


def _utc_now() -> str:
    return (
        datetime.now(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )


def _parse_instant(value: Any, label: str) -> datetime:
    if not isinstance(value, str):
        raise ReleaseGateError(f"{label} must be an RFC3339 timestamp")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise ReleaseGateError(f"{label} must be an RFC3339 timestamp") from error
    if parsed.tzinfo is None:
        raise ReleaseGateError(f"{label} must include a timezone")
    return parsed.astimezone(timezone.utc)


def _require_digest(value: Any, label: str) -> str:
    if not isinstance(value, str) or not _SHA256.fullmatch(value):
        raise ReleaseGateError(f"{label} must be a sha256 digest")
    return value


def _sha256_bytes(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _sha256_file(path: Path) -> str:
    return _sha256_bytes(path.read_bytes())


def canonical_manifest_digest(manifest: Mapping[str, Any]) -> str:
    return jsonutil.digest_json(manifest)


def build_release_candidate_manifest(
    *,
    source_commit: str,
    control_plane_image_id: str,
    wheel_digest: str,
    migrations_dir: Path,
    sbom_digest: str,
    test_report_digest: str,
    scan_report_digest: str,
    toolchain_image_digest: str = TOOLCHAIN_IMAGE_DIGEST,
    created_at: str | None = None,
) -> dict[str, Any]:
    """Construct a validated Release Candidate Manifest bound by immutable digests."""
    migration_files = sorted(migrations_dir.glob("*.sql"))
    if not migration_files:
        raise ReleaseGateError(f"no SQL migration files found in {migrations_dir}")
    migrations = [
        {"file": path.name, "sha256": _sha256_bytes(path.read_bytes())}
        for path in migration_files
    ]
    manifest = {
        "schema_version": SCHEMA_VERSION,
        "contract_version": CONTRACT_VERSION,
        "source_commit": source_commit,
        "control_plane_image_id": control_plane_image_id,
        "wheel_digest": wheel_digest,
        "toolchain_image_digest": toolchain_image_digest,
        "migration_version": migration_files[-1].name,
        "migrations": migrations,
        "sbom_digest": sbom_digest,
        "test_report_digest": test_report_digest,
        "scan_report_digest": scan_report_digest,
        "created_at": created_at or _utc_now(),
    }
    validate_release_candidate_manifest(manifest)
    return manifest


def validate_release_candidate_manifest(manifest: Mapping[str, Any]) -> None:
    """Validate RC manifest fields, ordering, and immutable digest bindings."""
    if not isinstance(manifest, Mapping):
        raise ReleaseGateError("release candidate manifest must be an object")
    missing = sorted(_REQUIRED_RC_FIELDS - set(manifest))
    if missing:
        raise ReleaseGateError(
            f"release candidate manifest missing required fields: {', '.join(missing)}"
        )
    extra = sorted(set(manifest) - _REQUIRED_RC_FIELDS)
    if extra:
        raise ReleaseGateError(
            f"release candidate manifest has unknown fields: {', '.join(extra)}"
        )
    if type(manifest["schema_version"]) is not int or manifest["schema_version"] != SCHEMA_VERSION:
        raise ReleaseGateError("release candidate schema_version must be 1")
    if type(manifest["contract_version"]) is not int or manifest["contract_version"] != CONTRACT_VERSION:
        raise ReleaseGateError("release candidate contract_version must be 1")
    commit = manifest["source_commit"]
    if not isinstance(commit, str) or not _GIT_SHA40.fullmatch(commit):
        raise ReleaseGateError("source_commit must be a 40-char lowercase Git SHA")
    for digest_field in (
        "control_plane_image_id",
        "wheel_digest",
        "toolchain_image_digest",
        "sbom_digest",
        "test_report_digest",
        "scan_report_digest",
    ):
        _require_digest(manifest[digest_field], digest_field)
    if manifest["toolchain_image_digest"] != TOOLCHAIN_IMAGE_DIGEST:
        raise ReleaseGateError(
            "toolchain_image_digest does not match the single pinned toolchain"
        )
    migrations = manifest["migrations"]
    if not isinstance(migrations, list) or not migrations:
        raise ReleaseGateError("migrations must be a non-empty list")
    names: list[str] = []
    for entry in migrations:
        if not isinstance(entry, Mapping):
            raise ReleaseGateError("migration entry must be an object")
        name = entry.get("file")
        if not isinstance(name, str) or not _MIGRATION_NAME.fullmatch(name):
            raise ReleaseGateError("migration entry file must be NNN_name.sql")
        if name in names:
            raise ReleaseGateError(f"duplicate migration entry: {name}")
        if names and name <= names[-1]:
            raise ReleaseGateError("migrations must be sorted in ascending order")
        names.append(name)
        _require_digest(entry.get("sha256"), "migration entry sha256")
    if set(entry.keys()) != {"file", "sha256"}:
        raise ReleaseGateError("migration entry has unknown fields")
    if manifest["migration_version"] != names[-1]:
        raise ReleaseGateError("migration_version must match the latest migration file")
    _parse_instant(manifest["created_at"], "created_at")


def verify_manifest_against_disk(
    manifest: Mapping[str, Any], migrations_dir: Path
) -> None:
    """Fail when the migrations on disk are not exactly the manifest's list."""
    validate_release_candidate_manifest(manifest)
    expected = {
        entry["file"]: entry["sha256"] for entry in manifest["migrations"]
    }
    actual_names = sorted(path.name for path in migrations_dir.glob("*.sql"))
    if sorted(expected) != actual_names:
        missing = sorted(set(expected) - set(actual_names))
        extra = sorted(set(actual_names) - set(expected))
        raise ReleaseGateError(
            f"migration files on disk do not match manifest; missing={missing} extra={extra}"
        )
    for name in actual_names:
        actual = _sha256_file(migrations_dir / name)
        if actual != expected[name]:
            raise ReleaseGateError(
                f"migration digest does not match manifest: {name}"
            )


def digest_test_reports(paths: Sequence[Path]) -> str:
    """Digest the four JUnit reports in filename order by concatenating bytes."""
    files = sorted((Path(path) for path in paths), key=lambda item: item.name)
    if len(files) != len(TEST_REPORT_FILES):
        raise ReleaseGateError(
            f"expected {len(TEST_REPORT_FILES)} JUnit reports, got {len(files)}"
        )
    names = [path.name for path in files]
    if names != sorted(TEST_REPORT_FILES):
        raise ReleaseGateError(
            "JUnit reports must be exactly: " + ", ".join(sorted(TEST_REPORT_FILES))
        )
    payload = b"".join(path.read_bytes() for path in files)
    return _sha256_bytes(payload)


def verify_manifest_evidence(
    manifest: Mapping[str, Any],
    artifacts_dir: Path,
    *,
    migrations_dir: Path | None = None,
) -> dict[str, str]:
    """Recompute every evidence digest from artifacts and compare to the manifest.

    The promote job calls this before switching traffic. A tampered JUnit XML,
    scanner JSON, SBOM, wheel, or migration therefore blocks promotion even
    when the manifest's own canonical digest still matches the approval.
    """
    validate_release_candidate_manifest(manifest)
    artifacts = Path(artifacts_dir)
    if not artifacts.is_dir():
        raise ReleaseGateError(f"artifact directory is missing: {artifacts}")

    report_paths = [artifacts / name for name in TEST_REPORT_FILES]
    for path in report_paths:
        if not path.is_file():
            raise ReleaseGateError(f"required JUnit report is missing: {path.name}")
    test_digest = digest_test_reports(report_paths)

    scan_path = artifacts / SCAN_REPORT_FILE
    if not scan_path.is_file():
        raise ReleaseGateError(f"required scanner report is missing: {SCAN_REPORT_FILE}")
    scan_digest = _sha256_file(scan_path)
    if test_digest == scan_digest:
        raise ReleaseGateError(
            "test_report_digest and scan_report_digest must come from distinct reports"
        )

    sbom_path = artifacts / SBOM_REPORT_FILE
    if not sbom_path.is_file():
        raise ReleaseGateError(f"required SBOM is missing: {SBOM_REPORT_FILE}")
    sbom_digest = _sha256_file(sbom_path)

    wheels = sorted(artifacts.glob("*.whl"))
    if len(wheels) != 1:
        raise ReleaseGateError(
            f"artifact directory must contain exactly one wheel, found {len(wheels)}"
        )
    wheel_digest = _sha256_file(wheels[0])

    computed = {
        "test_report_digest": test_digest,
        "scan_report_digest": scan_digest,
        "sbom_digest": sbom_digest,
        "wheel_digest": wheel_digest,
    }
    for field, value in computed.items():
        if manifest[field] != value:
            raise ReleaseGateError(
                f"{field} does not match the artifacts on disk "
                f"(manifest={manifest[field]}, artifacts={value})"
            )
    if migrations_dir is not None:
        verify_manifest_against_disk(manifest, migrations_dir)
    return computed


def generate_sbom(
    *,
    pyproject_path: Path,
    uv_lock_path: Path,
    out_path: Path | None = None,
) -> tuple[dict[str, Any], str]:
    """Generate a deterministic CycloneDX 1.5 SBOM from pyproject.toml and uv.lock."""
    pyproject = tomllib.loads(pyproject_path.read_text(encoding="utf-8"))
    lock_doc = tomllib.loads(uv_lock_path.read_text(encoding="utf-8"))
    project = pyproject.get("project", {})
    components: list[dict[str, Any]] = [
        {
            "type": "application",
            "name": str(project.get("name", "datacon")),
            "version": str(project.get("version", "0.1.0")),
        }
    ]
    for pkg in lock_doc.get("package", []):
        name = pkg.get("name")
        version = pkg.get("version")
        if not name or not version or name == "datacon":
            continue
        components.append(
            {
                "type": "library",
                "name": str(name),
                "version": str(version),
                "purl": f"pkg:pypi/{name}@{version}",
            }
        )
    components.sort(key=lambda item: (item["type"], item["name"], item["version"]))
    sbom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "metadata": {
            "component": {
                "type": "application",
                "name": str(project.get("name", "datacon")),
                "version": str(project.get("version", "0.1.0")),
            }
        },
        "components": components,
    }
    encoded = jsonutil.canonical_bytes(sbom) + b"\n"
    if out_path is not None:
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_bytes(encoded)
    return sbom, _sha256_bytes(encoded)


def _validate_approval(
    approval: Mapping[str, Any],
    *,
    candidate_digest: str,
    now: datetime | None = None,
) -> None:
    if not isinstance(approval, Mapping):
        raise ReleaseGateError("approval record must be an object")
    if approval.get("ci_passed") is not True:
        raise ReleaseGateError("promotion blocked: CI gates have not passed")
    if not isinstance(approval.get("approved_by"), str) or not approval["approved_by"].strip():
        raise ReleaseGateError("promotion blocked: approved_by is required")
    if approval.get("candidate_digest") != candidate_digest:
        raise ReleaseGateError("promotion blocked: approval digest does not match candidate")
    if approval.get("contract_version") != CONTRACT_VERSION:
        raise ReleaseGateError("promotion blocked: incompatible contract_version")
    if approval.get("migration_compatible") is not True:
        raise ReleaseGateError("promotion blocked: database migration compatibility not verified")
    approved_at = _parse_instant(approval.get("approved_at"), "approval.approved_at")
    reference = now or datetime.now(timezone.utc)
    if approved_at > reference + APPROVAL_FUTURE_SKEW:
        raise ReleaseGateError("promotion blocked: approval is from the future")
    if reference - approved_at > APPROVAL_MAX_AGE:
        raise ReleaseGateError("promotion blocked: approval has expired")


def verify_promotion_gate(
    manifest: Mapping[str, Any],
    *,
    expected_manifest_digest: str,
    approval: Mapping[str, Any],
    now: datetime | None = None,
) -> str:
    """Enforce Promotion Gate: immutable digest, CI status, approval, contract & migration compatibility."""
    validate_release_candidate_manifest(manifest)
    actual_digest = canonical_manifest_digest(manifest)
    if not _SHA256.fullmatch(expected_manifest_digest) or actual_digest != expected_manifest_digest:
        raise ReleaseGateError(
            f"candidate manifest digest mismatch: expected {expected_manifest_digest}, got {actual_digest}"
        )
    _validate_approval(approval, candidate_digest=actual_digest, now=now)
    return actual_digest


def validate_previous_release(previous: Mapping[str, Any]) -> dict[str, Any]:
    """Validate the persisted previous release before it is used for rollback."""
    if not isinstance(previous, Mapping):
        raise ReleaseGateError("previous release must be an object")
    required = {"image_id", "config", "migration_version", "evidence_root"}
    missing = sorted(required - set(previous))
    if missing:
        raise ReleaseGateError(
            f"previous release is missing required fields: {', '.join(missing)}"
        )
    _require_digest(previous["image_id"], "previous_release.image_id")
    if not isinstance(previous["config"], Mapping):
        raise ReleaseGateError("previous_release.config must be an object")
    if not isinstance(previous["migration_version"], str) or not previous[
        "migration_version"
    ].endswith(".sql"):
        raise ReleaseGateError(
            "previous_release.migration_version must be a .sql migration name"
        )
    if not isinstance(previous["evidence_root"], str) or not previous[
        "evidence_root"
    ].strip():
        raise ReleaseGateError("previous_release.evidence_root must be a path")
    return dict(previous)


def validate_rollback_outcome(
    outcome: Any, *, expected_image: str
) -> dict[str, Any]:
    """Require a rollback callable to prove it restored the expected image."""
    if not isinstance(outcome, Mapping):
        raise ReleaseGateError("rollback_fn must return an object")
    if outcome.get("ok") is not True:
        raise ReleaseGateError("rollback_fn reported ok != true")
    restored = outcome.get("restored_image")
    if restored != expected_image:
        raise ReleaseGateError(
            "rollback_fn did not restore the expected image "
            f"(expected {expected_image}, got {restored!r})"
        )
    return dict(outcome)


class PromotionBackend(Protocol):
    """State store used by promotion and rollback.

    The production implementation is PostgreSQL-backed (``state.ReleaseStore``).
    Tests use ``DictPromotionBackend`` and assert that ``switch`` is actually
    called, because a promotion result without a state transition is evidence
    of nothing.
    """

    def active_slots(self) -> int:
        ...

    def active_release(self) -> Mapping[str, Any] | None:
        ...

    def switch(
        self,
        *,
        image_id: str,
        config: Mapping[str, Any],
        migration_version: str,
        evidence_root: str,
        action: str,
        candidate_digest: str,
    ) -> None:
        ...

    def record_audit(self, result: Mapping[str, Any]) -> None:
        ...

    def promotion_for(self, candidate_digest: str) -> Mapping[str, Any] | None:
        ...


class DictPromotionBackend:
    """In-memory backend for contract tests; it records every state change."""

    def __init__(
        self,
        *,
        active_release: Mapping[str, Any],
        active_slots: int = 0,
        promotions: Mapping[str, Mapping[str, Any]] | None = None,
    ):
        self._active = validate_previous_release(active_release)
        self._slots = active_slots
        self.promotions = dict(promotions or {})
        self.switches: list[dict[str, Any]] = []
        self.audits: list[dict[str, Any]] = []

    def active_slots(self) -> int:
        return self._slots

    def active_release(self) -> Mapping[str, Any]:
        return dict(self._active)

    def switch(
        self,
        *,
        image_id: str,
        config: Mapping[str, Any],
        migration_version: str,
        evidence_root: str,
        action: str,
        candidate_digest: str,
    ) -> None:
        _require_digest(image_id, "switch.image_id")
        self.switches.append(
            {
                "image_id": image_id,
                "config": dict(config),
                "migration_version": migration_version,
                "evidence_root": evidence_root,
                "action": action,
                "candidate_digest": candidate_digest,
            }
        )
        self._active = {
            "image_id": image_id,
            "config": dict(config),
            "migration_version": migration_version,
            "evidence_root": evidence_root,
        }

    def record_audit(self, result: Mapping[str, Any]) -> None:
        self.audits.append(dict(result))
        candidate = result.get("candidate_digest")
        if isinstance(candidate, str):
            self.promotions.setdefault(candidate, dict(result))

    def promotion_for(self, candidate_digest: str) -> Mapping[str, Any] | None:
        found = self.promotions.get(candidate_digest)
        return dict(found) if found is not None else None


def _candidate_config(manifest: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "contract_version": manifest["contract_version"],
        "migration_version": manifest["migration_version"],
    }


def promote_and_smoke(
    *,
    manifest: Mapping[str, Any],
    expected_manifest_digest: str,
    approval: Mapping[str, Any],
    backend: PromotionBackend,
    smoke_checks: Mapping[str, Callable[[], bool]],
    rollback_fn: Callable[[Mapping[str, Any]], Mapping[str, Any]],
    now: datetime | None = None,
) -> dict[str, Any]:
    """Drain-check, promote, run smoke checks, switch state and audit.

    Promotion is idempotent for a candidate digest: a repeated call returns the
    already recorded result and never switches or audits twice. A smoke failure
    is not swallowed: the rollback callable must prove it restored the previous
    image, and the persisted active release must actually change back.
    """
    if not isinstance(smoke_checks, Mapping) or not smoke_checks:
        raise ReleaseGateError("promotion requires at least one smoke check")
    candidate_digest = verify_promotion_gate(
        manifest,
        expected_manifest_digest=expected_manifest_digest,
        approval=approval,
        now=now,
    )
    existing = backend.promotion_for(candidate_digest)
    if existing is not None:
        if existing.get("status") != "promoted":
            raise ReleaseGateError(
                "candidate already has a non-promoted audit record; refusing to replay"
            )
        return dict(existing)

    active_slots = backend.active_slots()
    if type(active_slots) is not int or active_slots != 0:
        raise ReleaseGateError(
            f"promotion blocked: execution slots not drained (active_slots={active_slots})"
        )
    previous = backend.active_release()
    if previous is None:
        raise ReleaseGateError(
            "promotion blocked: no persisted previous release; bootstrap the "
            "release_state row before promoting"
        )
    previous = validate_previous_release(previous)

    smoke_results: dict[str, bool] = {}
    failed_check: str | None = None
    for name, check_fn in smoke_checks.items():
        try:
            ok = bool(check_fn())
        except Exception:  # noqa: BLE001 - a failing smoke check is a gate failure
            ok = False
        smoke_results[name] = ok
        if not ok:
            failed_check = name
            break

    if failed_check is not None:
        try:
            rollback_outcome = rollback_fn(previous)
        except Exception as error:  # noqa: BLE001 - never swallow rollback failures
            raise ReleaseGateError(f"rollback failed: {error}") from error
        rollback_outcome = validate_rollback_outcome(
            rollback_outcome, expected_image=previous["image_id"]
        )
        restored = backend.active_release()
        if restored is None or restored.get("image_id") != previous["image_id"]:
            raise ReleaseGateError(
                "rollback callable returned success but the backend did not "
                "restore the previous image"
            )
        result = {
            "schema_version": SCHEMA_VERSION,
            "status": "rolled_back",
            "failed_check": failed_check,
            "candidate_digest": candidate_digest,
            "source_commit": manifest["source_commit"],
            "previous_image_id": previous["image_id"],
            "active_image_id": previous["image_id"],
            "approved_by": approval["approved_by"],
            "migration_version": previous["migration_version"],
            "config": dict(previous["config"]),
            "evidence_root": previous["evidence_root"],
            "smoke_results": smoke_results,
            "rollback": rollback_outcome,
            "recorded_at": _utc_now(),
        }
        backend.record_audit(result)
        return result

    candidate_image = manifest["control_plane_image_id"]
    config = _candidate_config(manifest)
    backend.switch(
        image_id=candidate_image,
        config=config,
        migration_version=manifest["migration_version"],
        evidence_root=previous["evidence_root"],
        action="promote",
        candidate_digest=candidate_digest,
    )
    active = backend.active_release()
    if active is None or active.get("image_id") != candidate_image:
        raise ReleaseGateError(
            "promotion switch did not make the candidate image active"
        )
    if active.get("migration_version") != manifest["migration_version"]:
        raise ReleaseGateError(
            "promotion switch did not apply the candidate migration_version"
        )
    result = {
        "schema_version": SCHEMA_VERSION,
        "status": "promoted",
        "failed_check": None,
        "candidate_digest": candidate_digest,
        "source_commit": manifest["source_commit"],
        "previous_image_id": previous["image_id"],
        "active_image_id": candidate_image,
        "approved_by": approval["approved_by"],
        "migration_version": manifest["migration_version"],
        "config": config,
        "evidence_root": previous["evidence_root"],
        "smoke_results": smoke_results,
        "rollback": None,
        "recorded_at": _utc_now(),
    }
    backend.record_audit(result)
    return result


def rollback_release(
    *,
    target_release: Mapping[str, Any],
    backend: PromotionBackend,
    smoke_checks: Mapping[str, Callable[[], bool]],
    approved_by: str,
    candidate_digest: str,
) -> dict[str, Any]:
    """Restore a persisted target release after the same smoke suite passes."""
    target = validate_previous_release(target_release)
    if not isinstance(approved_by, str) or not approved_by.strip():
        raise ReleaseGateError("rollback requires an approved_by identity")
    _require_digest(candidate_digest, "rollback candidate_digest")
    current = backend.active_release()
    if current is None:
        raise ReleaseGateError("rollback blocked: no persisted active release")
    smoke_results: dict[str, bool] = {}
    for name, check_fn in smoke_checks.items():
        try:
            ok = bool(check_fn())
        except Exception:  # noqa: BLE001 - rollback smoke failure blocks the switch
            ok = False
        smoke_results[name] = ok
        if not ok:
            raise ReleaseGateError(f"rollback blocked: smoke check failed: {name}")
    backend.switch(
        image_id=target["image_id"],
        config=target["config"],
        migration_version=target["migration_version"],
        evidence_root=target["evidence_root"],
        action="rollback",
        candidate_digest=candidate_digest,
    )
    active = backend.active_release()
    if active is None or active.get("image_id") != target["image_id"]:
        raise ReleaseGateError("rollback switch did not restore the target image")
    result = {
        "schema_version": SCHEMA_VERSION,
        "status": "rolled_back",
        "failed_check": None,
        "candidate_digest": candidate_digest,
        "source_commit": None,
        "previous_image_id": current["image_id"],
        "active_image_id": target["image_id"],
        "approved_by": approved_by,
        "migration_version": target["migration_version"],
        "config": dict(target["config"]),
        "evidence_root": target["evidence_root"],
        "smoke_results": smoke_results,
        "rollback": {
            "ok": True,
            "restored_image": target["image_id"],
        },
        "recorded_at": _utc_now(),
    }
    backend.record_audit(result)
    return result


# ---------------------------------------------------------------------------
# B03 authorized-environment acceptance
# ---------------------------------------------------------------------------

_B03_REQUIRED_FILES = (
    "harness.c",
    "build.sh",
    "dependencies.lock",
    "fix.patch",
    "b03-repo.bundle",
    "advisory.json",
)
_B03_REQUIRED_TREES = ("vulnerable", "fixed")
_MAX_B03_MATERIAL_BYTES = 128 * 1024 * 1024


def _safe_child(root: Path, relative: str, label: str) -> Path:
    normalized = jsonutil.safe_relative_path(relative, label)
    candidate = (root / PurePosixPath(normalized)).resolve()
    resolved_root = root.resolve()
    if candidate != resolved_root and resolved_root not in candidate.parents:
        raise ReleaseGateError(f"{label} escapes the B03 case root: {relative}")
    return candidate


def _read_material(path: Path, label: str) -> bytes:
    if path.is_symlink():
        raise ReleaseGateError(f"{label} must not be a symlink: {path}")
    if not path.is_file():
        raise ReleaseGateError(f"required B03 material is missing: {label}")
    if path.stat().st_size > _MAX_B03_MATERIAL_BYTES:
        raise ReleaseGateError(f"B03 material exceeds the size cap: {label}")
    return path.read_bytes()


@dataclass(frozen=True)
class B03CaseMaterials:
    """Real B03 case files loaded from an authorized case root.

    Every digest is computed from bytes on disk. No harness, recipe, patch,
    bundle or advisory content is embedded in this module.
    """

    root: Path
    harness: bytes
    build_recipe: bytes
    dependencies: bytes
    patch: bytes
    repository_bundle: bytes
    advisory: bytes
    vulnerable_sources: Mapping[str, bytes]
    fixed_sources: Mapping[str, bytes]

    @property
    def digests(self) -> dict[str, str]:
        materials: dict[str, str] = {
            "harness.c": _sha256_bytes(self.harness),
            "build.sh": _sha256_bytes(self.build_recipe),
            "dependencies.lock": _sha256_bytes(self.dependencies),
            "fix.patch": _sha256_bytes(self.patch),
            "b03-repo.bundle": _sha256_bytes(self.repository_bundle),
            "advisory.json": _sha256_bytes(self.advisory),
        }
        for prefix, sources in (
            ("vulnerable", self.vulnerable_sources),
            ("fixed", self.fixed_sources),
        ):
            for relative, data in sources.items():
                materials[f"{prefix}/{relative}"] = _sha256_bytes(data)
        return materials

    @classmethod
    def load(cls, case_root: Path | str) -> "B03CaseMaterials":
        root = Path(case_root)
        try:
            resolved = root.resolve(strict=True)
        except OSError as error:
            raise ReleaseGateError(
                f"B03 case root is not readable: {case_root}"
            ) from error
        if not resolved.is_dir():
            raise ReleaseGateError(f"B03 case root must be a directory: {resolved}")
        payload = {
            name: _read_material(_safe_child(resolved, name, name), name)
            for name in _B03_REQUIRED_FILES
        }
        trees: dict[str, dict[str, bytes]] = {}
        for tree in _B03_REQUIRED_TREES:
            tree_path = _safe_child(resolved, tree, tree)
            if not tree_path.is_dir() or tree_path.is_symlink():
                raise ReleaseGateError(f"required B03 material tree is missing: {tree}/")
            files: dict[str, bytes] = {}
            for path in sorted(tree_path.rglob("*")):
                if path.is_dir():
                    continue
                if path.is_symlink():
                    raise ReleaseGateError(f"B03 material tree contains a symlink: {path}")
                relative = path.relative_to(tree_path).as_posix()
                files[relative] = _read_material(path, f"{tree}/{relative}")
            if not files:
                raise ReleaseGateError(f"required B03 material tree is empty: {tree}/")
            trees[tree] = files
        try:
            advisory = jsonutil.loads_strict(payload["advisory.json"])
        except jsonutil.StrictJsonError as error:
            raise ReleaseGateError(f"B03 advisory.json is invalid JSON: {error}") from error
        if not isinstance(advisory, Mapping):
            raise ReleaseGateError("B03 advisory.json must be a JSON object")
        return cls(
            root=resolved,
            harness=payload["harness.c"],
            build_recipe=payload["build.sh"],
            dependencies=payload["dependencies.lock"],
            patch=payload["fix.patch"],
            repository_bundle=payload["b03-repo.bundle"],
            advisory=payload["advisory.json"],
            vulnerable_sources=trees["vulnerable"],
            fixed_sources=trees["fixed"],
        )

    @classmethod
    def from_environment(cls) -> "B03CaseMaterials":
        import os

        case_root = os.environ.get("DATACON_B03_CASE_ROOT")
        if not case_root:
            raise ReleaseGateError(
                "DATACON_B03_CASE_ROOT must name the authorized B03 case root"
            )
        return cls.load(Path(case_root))


def _validate_b03_admission(admission: Mapping[str, Any]) -> None:
    if not isinstance(admission, Mapping):
        raise ReleaseGateError("B03 admission must be an object")
    if admission.get("benchmark_id") != "B03":
        raise ReleaseGateError("B03 admission benchmark_id must be B03")
    signature = admission.get("asan_signature")
    if not isinstance(signature, Mapping):
        raise ReleaseGateError("B03 admission is missing asan_signature")
    status = signature.get("status")
    if status not in {"frozen", "verified"}:
        raise ReleaseGateError(
            "B03 admission asan_signature.status must be frozen; "
            f"got {status!r}"
        )
    verdict_status = admission.get("expected_verdict_status")
    if verdict_status not in {"frozen", "verified"}:
        raise ReleaseGateError(
            "B03 admission expected_verdict_status must be frozen; "
            f"got {verdict_status!r}"
        )
    try:
        versions = admission["versions"]
        for role in ("vulnerable", "fixed"):
            commit = versions[role]["commit"]
            if not isinstance(commit, str) or not re.fullmatch(r"[0-9a-f]{40}", commit):
                raise ReleaseGateError(
                    f"B03 admission {role} commit must be a 40-char lowercase Git SHA"
                )
    except (KeyError, TypeError) as error:
        raise ReleaseGateError(f"B03 admission versions are invalid: {error}") from error


def prepare_b03_plan(
    *,
    admission: Mapping[str, Any],
    materials: B03CaseMaterials,
    normal_input: bytes,
    candidate_input: bytes,
) -> dict[str, Any]:
    """Build the exact B03 plan that a reviewer must approve before replay."""
    _validate_b03_admission(admission)
    cve_id = str(admission["cve_id"])
    vuln_commit = str(admission["versions"]["vulnerable"]["commit"])
    fixed_commit = str(admission["versions"]["fixed"]["commit"])
    toolchain_image = str(admission["build"]["toolchain_image"])
    if "@" not in toolchain_image:
        raise ReleaseGateError("B03 toolchain image must be pinned by digest")
    image_digest = toolchain_image.split("@", 1)[1]
    _require_digest(image_digest, "B03 toolchain image digest")
    if image_digest != TOOLCHAIN_IMAGE_DIGEST:
        raise ReleaseGateError(
            "B03 admission toolchain image does not match the pinned toolchain"
        )
    asan_options = str(admission["harness"]["asan_options"])
    asan_sig = {
        "error": str(admission["asan_signature"]["error"]),
        "function": str(admission["asan_signature"]["function"]),
        "source": str(admission["asan_signature"]["source"]),
    }
    expected_exit = {
        "normal": int(admission["harness"]["normal_exit_code"]),
        "candidate_clean": 0,
        "candidate_asan": int(admission["harness"]["candidate_asan_exit_code"]),
    }
    expected_stdout = {
        "normal": "OK\n",
        "candidate_clean": "MISMATCH_REJECTED\n",
    }
    limits = dict(contracts.DEFAULT_LIMITS)
    isolation = {
        "network": "none",
        "user": "65534:65534",
        "read_only_root": True,
        "cap_drop": ["ALL"],
        "no_new_privileges": True,
        "seccomp": "runtime/default",
        "seccomp_profile_digest": SECCOMP_PROFILE_DIGEST,
    }
    compile_args = list(_extract_compile_args(materials.build_recipe))
    materials_map = dict(materials.digests)
    materials_map["inputs/normal.txt"] = _sha256_bytes(normal_input)
    materials_map["inputs/candidate.txt"] = _sha256_bytes(candidate_input)
    source_path = str(admission.get("repository", {}).get("source_path", "src/regext.c"))
    if not source_path or ".." in PurePosixPath(source_path).parts:
        raise ReleaseGateError("B03 repository.source_path is invalid")
    registry_entry = {
        "cve_id": cve_id,
        "benchmark_id": "B03",
        "repository": {
            "origin": str(admission["repository"]["url"]),
            "bundle": "b03-repo.bundle",
            "bundle_digest": _sha256_bytes(materials.repository_bundle),
            "source_path": source_path,
            "refs": {"vulnerable": "refs/heads/vulnerable", "fixed": "refs/heads/fixed"},
            "commits": {"vulnerable": vuln_commit, "fixed": fixed_commit},
            "patch": "fix.patch",
        },
        "advisory": {
            "path": "advisory.json",
            "digest": _sha256_bytes(materials.advisory),
        },
    }
    manifest_case = {
        "case_id": "b03-oniguruma-cve-2019-13224",
        "inputs": {
            "normal": "inputs/normal.txt",
            "candidate": "inputs/candidate.txt",
        },
        "expected_exit": expected_exit,
        "expected_stdout": expected_stdout,
        "expected_verdict": "REPRODUCED",
    }
    toolchain_meta = {
        "compiler": "clang",
        "sanitizer": "address",
        "pinned_image_version": "19.1.7",
    }
    case_config = {
        "case_id": "b03-oniguruma-cve-2019-13224",
        "cve_id": cve_id,
        "benchmark_id": "B03",
        "registry_entry": registry_entry,
        "manifest_case": manifest_case,
        "materials": materials_map,
        "image": toolchain_image,
        "platform": "linux/amd64",
        "toolchain": toolchain_meta,
        "asan_options": asan_options,
        "asan_signature": asan_sig,
    }
    case_config_digest = jsonutil.digest_json(case_config)
    analysis = {
        "diff_digest": _sha256_bytes(materials.patch),
        "changed_paths": [source_path],
        "symbols": [
            {
                "name": asan_sig["function"],
                "path": source_path,
                "role": "definition",
                "revision": "vulnerable",
                "start_line": 1,
                "end_line": max(1, len(materials.vulnerable_sources.get("regext.c", b"x").splitlines())),
            }
        ],
        "findings": [
            {
                "kind": "fact",
                "statement": f"Fix commit {fixed_commit} modifies {source_path}.",
                "confidence": "high",
                "evidence_refs": [f"git:diff/{vuln_commit}..{fixed_commit}/{source_path}"],
            }
        ],
    }
    analysis_digest = contracts.analysis_digest(analysis)
    plan = {
        "case_id": "b03-oniguruma-cve-2019-13224",
        "cve_id": cve_id,
        "case_config_digest": case_config_digest,
        "repository": {
            "origin": str(admission["repository"]["url"]),
            "bundle_digest": registry_entry["repository"]["bundle_digest"],
            "patch_digest": materials_map["fix.patch"],
        },
        "revisions": {"vulnerable": vuln_commit, "fixed": fixed_commit},
        "dependencies_digest": materials_map["dependencies.lock"],
        "image_digest": image_digest,
        "platform": "linux/amd64",
        "toolchain": toolchain_meta,
        "asan_options": asan_options,
        "build_recipe_digest": materials_map["build.sh"],
        "harness_digest": materials_map["harness.c"],
        "inputs": {
            "normal": materials_map["inputs/normal.txt"],
            "candidate": materials_map["inputs/candidate.txt"],
        },
        "expected_exit": expected_exit,
        "asan_signature": asan_sig,
        "limits": limits,
        "isolation": isolation,
        "intel": {
            "snapshot": "advisory.json",
            "collected_at": "2026-11-17T00:00:00Z",
            "content_digest": registry_entry["advisory"]["digest"],
            "sources": [str(admission["advisory"]["nvd"])],
        },
        "analysis": analysis,
        "analysis_digest": analysis_digest,
        "policy_version": "1",
    }
    return {
        "plan": plan,
        "plan_digest": contracts.plan_digest(plan),
        "case_config": case_config,
        "materials": materials_map,
        "compile_args": compile_args,
        "registry_entry": registry_entry,
        "expected_exit": expected_exit,
        "expected_stdout": expected_stdout,
        "asan_options": asan_options,
        "asan_signature": asan_sig,
        "image_digest": image_digest,
        "toolchain_image": toolchain_image,
        "toolchain_meta": toolchain_meta,
        "isolation": isolation,
        "limits": limits,
        "source_path": source_path,
    }


def _validate_b03_review(review: Mapping[str, Any], *, plan_digest: str) -> dict[str, Any]:
    if not isinstance(review, Mapping):
        raise ReleaseGateError("B03 review must be supplied by the reviewer")
    missing = sorted({"reviewer_id", "decision", "plan_digest", "decided_at"} - set(review))
    if missing:
        raise ReleaseGateError(
            f"B03 review is missing required fields: {', '.join(missing)}"
        )
    if review.get("decision") != "approve":
        raise ReleaseGateError("B03 review decision must be approve")
    if not isinstance(review.get("reviewer_id"), str) or not review["reviewer_id"].strip():
        raise ReleaseGateError("B03 review reviewer_id is required")
    if review.get("plan_digest") != plan_digest:
        raise ReleaseGateError("B03 review plan_digest does not match the plan")
    _parse_instant(review.get("decided_at"), "B03 review decided_at")
    return {
        "reviewer_id": review["reviewer_id"],
        "decision": "approve",
        "plan_digest": plan_digest,
        "decided_at": review["decided_at"],
    }


def _require_probe(report: Any) -> Any:
    if getattr(report, "ok", False) is not True:
        raise ReleaseGateError("B03 sandbox probe did not succeed")
    image_digest = getattr(report, "image_digest", None)
    _require_digest(image_digest, "B03 probe image_digest")
    limits = getattr(report, "limits", None)
    if not isinstance(limits, Mapping) or not limits:
        raise ReleaseGateError("B03 probe limits are missing")
    checks = getattr(report, "checks", None)
    required = {"uid", "seccomp", "no_new_privs", "cap_eff", "cgroup_version"}
    if not isinstance(checks, Mapping) or not required <= set(checks):
        raise ReleaseGateError("B03 probe checks are incomplete")
    return report


def _require_build(result: Any, version: str) -> None:
    if getattr(result, "status", None) != "completed":
        raise ReleaseGateError(f"B03 {version} build did not complete")
    artifact = getattr(result, "artifact", None)
    if not isinstance(artifact, (bytes, bytearray)) or not artifact:
        raise ReleaseGateError(f"B03 {version} build produced no artifact")
    _require_digest(getattr(result, "artifact_digest", None), f"B03 {version} artifact_digest")
    if _sha256_bytes(bytes(artifact)) != result.artifact_digest:
        raise ReleaseGateError(f"B03 {version} artifact digest does not match bytes")


def run_b03_acceptance(
    *,
    admission: Mapping[str, Any],
    sandbox: Any,
    normal_input: bytes,
    candidate_input: bytes,
    bundle_out: Path,
    storage_ref: str,
    review: Mapping[str, Any],
    case_root: Path | str | None = None,
) -> dict[str, Any]:
    """Execute B03 acceptance using real case files and a reviewer-supplied approval.

    All of these fail closed before replay: a pending admission signature, a
    missing/mismatched review, a failed probe, a failed build, missing bundle
    or advisory materials, or a material digest mismatch.
    """
    materials = (
        B03CaseMaterials.load(case_root)
        if case_root is not None
        else B03CaseMaterials.from_environment()
    )
    prepared = prepare_b03_plan(
        admission=admission,
        materials=materials,
        normal_input=normal_input,
        candidate_input=candidate_input,
    )
    plan = prepared["plan"]
    plan_digest = prepared["plan_digest"]
    accepted_review = _validate_b03_review(review, plan_digest=plan_digest)
    cve_id = plan["cve_id"]
    expected_exit = prepared["expected_exit"]
    expected_stdout = prepared["expected_stdout"]
    asan_options = prepared["asan_options"]
    asan_sig = prepared["asan_signature"]
    image_digest = prepared["image_digest"]
    toolchain_image = prepared["toolchain_image"]
    toolchain_meta = prepared["toolchain_meta"]
    isolation = prepared["isolation"]
    limits = prepared["limits"]
    materials_map = prepared["materials"]
    compile_args = prepared["compile_args"]

    probe_report = _require_probe(sandbox.probe(deadline_seconds=120.0))
    if probe_report.image_digest != image_digest:
        raise ReleaseGateError(
            "B03 probe image_digest does not match the approved toolchain"
        )
    job_id = str(uuid.uuid4())
    probe_doc = {
        "tool_id": "sandbox.probe",
        "job_id": job_id,
        "plan_digest": plan_digest,
        "generation": 1,
        "status": "completed",
        "container_id": None,
        "checks": dict(probe_report.checks),
        "compiler_version": probe_report.compiler_version,
        "image_digest": probe_report.image_digest,
        "limits": dict(probe_report.limits),
    }

    # Stage the exact reviewed material tree. The real DockerSandbox mounts
    # this directory at /fixture and runs build.sh against it; the fake sandbox
    # used by contract tests accepts the same keyword arguments.
    staging_root = bundle_out.parent / f".b03-materials-{uuid.uuid4().hex}"
    staging_root.mkdir(parents=True, exist_ok=True)
    try:
        (staging_root / "harness.c").write_bytes(materials.harness)
        (staging_root / "build.sh").write_bytes(materials.build_recipe)
        (staging_root / "dependencies.lock").write_bytes(materials.dependencies)
        (staging_root / "fix.patch").write_bytes(materials.patch)
        (staging_root / "b03-repo.bundle").write_bytes(materials.repository_bundle)
        (staging_root / "advisory.json").write_bytes(materials.advisory)
        for prefix, sources in (
            ("vulnerable", materials.vulnerable_sources),
            ("fixed", materials.fixed_sources),
        ):
            for relative, data in sources.items():
                destination = staging_root / prefix / relative
                destination.parent.mkdir(parents=True, exist_ok=True)
                destination.write_bytes(data)
        (staging_root / "inputs").mkdir(exist_ok=True)
        (staging_root / "inputs" / "normal.txt").write_bytes(normal_input)
        (staging_root / "inputs" / "candidate.txt").write_bytes(candidate_input)

        build_results: dict[str, Any] = {}
        artifact_paths: dict[str, Path] = {}
        for version in ("vulnerable", "fixed"):
            result = sandbox.build(
                version,
                materials_dir=staging_root,
                compile_args=compile_args,
                expected_materials=materials_map,
            )
            _require_build(result, version)
            build_results[version] = result
            artifact = bundle_out.parent / f".b03-artifact-{version}-{uuid.uuid4().hex}"
            artifact.write_bytes(bytes(result.artifact))
            artifact_paths[version] = artifact
    finally:
        shutil.rmtree(staging_root, ignore_errors=True)

    build_docs: dict[str, dict[str, Any]] = {}

    build_docs: dict[str, dict[str, Any]] = {}
    for version in ("vulnerable", "fixed"):
        res = build_results[version]
        build_docs[version] = {
            "tool_id": "sandbox.build",
            "job_id": job_id,
            "generation": 1,
            "plan_digest": plan_digest,
            "input_digest": plan["analysis_digest"],
            "status": res.status,
            "version": version,
            "exit_code": res.exit_code,
            "duration_seconds": res.duration_seconds,
            "container_id": res.container_id,
            "image_digest": image_digest,
            "build_recipe_digest": materials_map["build.sh"],
            "compile_args": compile_args,
            "artifact_digest": res.artifact_digest,
            "log_digest": _sha256_bytes(res.log),
            "log_truncated": res.log_truncated,
            "capture_error": res.capture_error,
            "staged_materials": dict(materials_map),
            "files": {
                "log": f"build/{version}/build.log",
                "artifact": f"build/{version}/parser",
            },
            "file_digests": {
                "log": _sha256_bytes(res.log),
                "artifact": res.artifact_digest,
            },
        }

    staging_inputs = bundle_out.parent / f".b03-inputs-{uuid.uuid4().hex}"
    staging_inputs.mkdir(parents=True, exist_ok=True)
    normal_file = staging_inputs / "normal.txt"
    candidate_file = staging_inputs / "candidate.txt"
    normal_file.write_bytes(normal_input)
    candidate_file.write_bytes(candidate_input)

    replay_docs: list[dict[str, Any]] = []
    replay_obs: list[RunObservation] = []
    replay_raw: dict[tuple[str, str], tuple[bytes, bytes]] = {}
    try:
        for version in ("vulnerable", "fixed"):
            for phase in ("normal", "candidate_1", "candidate_2"):
                in_path = normal_file if phase == "normal" else candidate_file
                r = sandbox.replay(
                    version,
                    phase,
                    artifact_path=artifact_paths[version],
                    input_path=in_path,
                    asan_options=asan_options,
                    timeout_seconds=float(limits["replay_seconds"]),
                    expected_artifact_digest=build_results[version].artifact_digest,
                    expected_input_digest=_sha256_bytes(in_path.read_bytes()),
                )
                replay_raw[(version, phase)] = (r.stdout, r.stderr)
                replay_docs.append(
                    {
                        "tool_id": "sandbox.replay",
                        "job_id": job_id,
                        "generation": 1,
                        "plan_digest": plan_digest,
                        "input_digest": r.input_digest,
                        "artifact_digest": build_results[version].artifact_digest,
                        "status": r.status,
                        "version": version,
                        "phase": phase,
                        "exit_code": r.exit_code,
                        "duration_seconds": r.duration_seconds,
                        "container_id": r.container_id,
                        "image_digest": image_digest,
                        "asan_options": asan_options,
                        "stdout_sha256": _sha256_bytes(r.stdout),
                        "stdout_bytes": len(r.stdout),
                        "stderr_sha256": _sha256_bytes(r.stderr),
                        "stderr_bytes": len(r.stderr),
                        "signature": r.signature.as_dict() if r.signature else None,
                        "timed_out": r.timed_out,
                        "quota_hit": r.quota_hit,
                        "log_truncated": r.log_truncated,
                        "capture_error": r.capture_error,
                        "files": {
                            "stdout": f"replay/{version}/{phase}/stdout.log",
                            "stderr": f"replay/{version}/{phase}/stderr.log",
                        },
                        "file_digests": {
                            "stdout": _sha256_bytes(r.stdout),
                            "stderr": _sha256_bytes(r.stderr),
                        },
                    }
                )
                replay_obs.append(
                    RunObservation(
                        version=version,
                        phase=phase,
                        status=r.status,
                        exit_code=r.exit_code,
                        stdout=r.stdout.decode("utf-8", "replace"),
                        stderr=r.stderr.decode("utf-8", "replace"),
                        signature=r.signature,
                        input_digest=r.input_digest,
                        duration_seconds=r.duration_seconds,
                        log_truncated=r.log_truncated,
                        capture_error=r.capture_error,
                    )
                )
    finally:
        normal_file.unlink(missing_ok=True)
        candidate_file.unlink(missing_ok=True)
        staging_inputs.rmdir()
        for artifact in artifact_paths.values():
            artifact.unlink(missing_ok=True)

    policy = VerdictPolicy(
        signature=asan_sig,
        expected_exit=expected_exit,
        expected_stdout=expected_stdout,
    )
    decision = decide_verdict(policy, replay_obs, builds=build_docs)

    execution_metadata = {
        "job_id": job_id,
        "plan_digest": plan_digest,
        "generation": 1,
        "probe": probe_doc,
        "builds": list(build_docs.values()),
        "replays": replay_docs,
    }
    report = {
        "schema_version": 1,
        "job_id": job_id,
        "plan_digest": plan_digest,
        "cve_id": cve_id,
        "case_id": "b03-oniguruma-cve-2019-13224",
        "state": decision.verdict,
        "verdict": decision.verdict,
        "reason_code": decision.reason_code,
        "target": {"kind": "source", "case_id": "b03-oniguruma-cve-2019-13224", "goal": "B03 acceptance"},
        "versions": plan["revisions"],
        "repository": plan["repository"],
        "environment": {
            "image": toolchain_image,
            "image_digest": image_digest,
            "platform": "linux/amd64",
            "toolchain": toolchain_meta,
            "asan_options": asan_options,
            "compile_args": compile_args,
            "isolation": isolation,
            "probe": probe_doc,
        },
        "budget": limits,
        "inputs": plan["inputs"],
        "review": accepted_review,
        "signature": asan_sig,
        "builds": list(build_docs.values()),
        "replays": replay_docs,
        "rule": decision.as_dict(),
        "evidence_refs": ["report.json", "report.md", "plan.json", "review.json", "metadata/execution.json"],
        "missing": [],
        "error": None,
        "evidence_complete": True,
        "created_at": accepted_review["decided_at"],
    }
    report_md = "\n".join(
        [
            "# DataCon B03 acceptance report",
            "",
            f"- Job: `{job_id}`",
            f"- Plan: `{plan_digest}`",
            f"- Verdict: **{decision.verdict}**",
            f"- Reason: `{decision.reason_code}`",
            "",
        ]
    )

    artifacts: dict[str, tuple[str, bytes]] = {
        "plan.json": ("plan", jsonutil.canonical_bytes(plan) + b"\n"),
        "review.json": ("review", jsonutil.canonical_bytes(accepted_review) + b"\n"),
        "metadata/execution.json": ("execution_metadata", jsonutil.canonical_bytes(execution_metadata) + b"\n"),
        "metadata/probe.json": ("probe", jsonutil.canonical_bytes(probe_doc) + b"\n"),
        "metadata/case.json": ("case_config", jsonutil.canonical_bytes({"case_config": prepared["case_config"]}) + b"\n"),
        "materials/harness.c": ("material_harness", materials.harness),
        "materials/build.sh": ("material_build_recipe", materials.build_recipe),
        "materials/dependencies.lock": ("material_dependencies", materials.dependencies),
        "materials/fix.patch": ("material_patch", materials.patch),
        "materials/b03-repo.bundle": ("material_repository_bundle", materials.repository_bundle),
        "materials/advisory.json": ("material_advisory", materials.advisory),
        "materials/inputs/normal.txt": ("material_input_normal", normal_input),
        "materials/inputs/candidate.txt": ("material_input_candidate", candidate_input),
    }
    for relative, data in materials.vulnerable_sources.items():
        artifacts[f"materials/vulnerable/{relative}"] = ("material_source_vulnerable", data)
    for relative, data in materials.fixed_sources.items():
        artifacts[f"materials/fixed/{relative}"] = ("material_source_fixed", data)
    for version in ("vulnerable", "fixed"):
        artifacts[f"build/{version}/build.log"] = ("build_log", build_results[version].log)
        artifacts[f"build/{version}/parser"] = ("build_artifact", build_results[version].artifact)
        artifacts[f"build/{version}/metadata.json"] = (
            "build_metadata",
            jsonutil.canonical_bytes(build_docs[version]) + b"\n",
        )
    for item in replay_docs:
        v = item["version"]
        p = item["phase"]
        out_b, err_b = replay_raw[(v, p)]
        artifacts[f"replay/{v}/{p}/stdout.log"] = (
            "normal_output" if p == "normal" else "replay_stdout",
            out_b,
        )
        artifacts[f"replay/{v}/{p}/stderr.log"] = (
            "asan_log" if item["signature"] else "replay_stderr",
            err_b,
        )
        artifacts[f"replay/{v}/{p}/metadata.json"] = (
            "replay_metadata",
            jsonutil.canonical_bytes(item) + b"\n",
        )

    info = evidence.write_bundle(
        bundle_out,
        job_id=job_id,
        plan_digest=plan_digest,
        report=report,
        report_markdown=report_md,
        artifacts=artifacts,
        verdict=decision.verdict,
        verify=evidence.verify_bundle,
    )
    verified = evidence.verify_bundle(bundle_out)
    return {
        "schema_version": SCHEMA_VERSION,
        "benchmark_id": "B03",
        "cve_id": cve_id,
        "verdict": decision.verdict,
        "reason_code": decision.reason_code,
        "replay_count": len(replay_docs),
        "bundle_verified": True,
        "manifest_digest": verified.manifest_digest,
        "storage_ref": storage_ref,
        "versions": {"vulnerable": plan["revisions"]["vulnerable"], "fixed": plan["revisions"]["fixed"]},
        "review": accepted_review,
        "accepted_at": info.manifest["created_at"],
    }


def build_b03_sandbox(
    plan: Mapping[str, Any],
    *,
    image: str,
    job_id: str,
    run_root: Path | str,
    docker: str = "docker",
):
    """Construct the real Docker sandbox from an approved B03 plan.

    Kept in the release module so the authorized-runner workflow cannot invent
    a weaker isolation policy than the one the verifier checks.
    """
    from datacon.tools.sandbox import DockerSandbox, IsolationPolicy, ResourceLimits

    budget = plan["limits"]
    policy = IsolationPolicy.from_plan(plan["isolation"])
    limits = ResourceLimits(
        cpu=int(budget["cpu"]),
        memory_mib=int(budget["memory_mib"]),
        pids=int(budget["pids"]),
        scratch_mib=int(budget["scratch_mib"]),
    )
    if not image.endswith("@" + str(plan["image_digest"])):
        raise ReleaseGateError(
            "B03 sandbox image does not match the approved plan digest"
        )
    return DockerSandbox(
        image=image,
        platform=str(plan["platform"]),
        policy=policy,
        limits=limits,
        docker=docker,
        job_id=job_id,
        run_root=run_root,
    )

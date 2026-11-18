"""Release candidate manifest, SBOM, promotion gate, smoke/rollback, and B03 acceptance (T07/T08)."""

from __future__ import annotations

from contextlib import contextmanager, nullcontext
import copy
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import tomllib
from typing import Any, Callable, Mapping, Protocol, Sequence
import uuid

from datacon import contracts, evidence, fileio, jsonutil
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
_MIGRATION_NUMBER = re.compile(r"^([0-9]{3})_")
# Migrations that may be crossed when rolling an image back. A rollback never
# reverts PostgreSQL DDL; it is only safe when every migration newer than the
# target is additive/backward-compatible for the older image. Anything not
# listed here fails closed so release_state.migration_version cannot lie about
# a schema the target image was not built for. 003 (unique-key replacement) and
# 007 (cleanup + constraints) are intentionally absent: rolling across them
# requires an explicit operator decision and a new compatibility entry.
ROLLBACK_COMPATIBLE_MIGRATIONS = frozenset(
    {
        "002_workflow.sql",
        "004_legacy_binary_sync.sql",
        "005_execution_evidence.sql",
        "006_attempt_journal_provenance.sql",
        "008_release_events.sql",
    }
)
_CVE_ID = re.compile(r"CVE-[0-9]{4}-[0-9]{4,}")
_HTTP_URL = re.compile(r"https?://\S+")
_B03_VERDICTS = frozenset({"REPRODUCED", "NOT_REPRODUCED", "INCONCLUSIVE"})

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
    numbers = [int(_MIGRATION_NUMBER.match(name).group(1)) for name in names]
    if numbers != list(range(1, len(numbers) + 1)):
        raise ReleaseGateError(
            "migrations must be numbered consecutively from 001"
        )
    if manifest["migration_version"] != names[-1]:
        raise ReleaseGateError("migration_version must match the latest migration file")
    created_at = _parse_instant(manifest["created_at"], "created_at")
    if created_at > datetime.now(timezone.utc) + APPROVAL_FUTURE_SKEW:
        raise ReleaseGateError("release candidate created_at is in the future")


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
    waivers_path: Path | None = None,
) -> dict[str, str]:
    """Recompute every evidence digest from artifacts and compare to the manifest.

    The promote job calls this before switching traffic. A tampered JUnit XML,
    scanner JSON, SBOM, wheel, or migration therefore blocks promotion even
    when the manifest's own canonical digest still matches the approval. A
    digest-only comparison is not enough: the four JUnit reports must prove
    that every test really ran with zero skips/failures, and the scanner report
    must be a real non-empty Trivy result that passes the waiver gate.
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

    # Content validation after the digest match: an attacker cannot satisfy
    # this by rewriting both the file and the manifest, because the manifest
    # digest is bound by the reviewer approval.
    from datacon import ci_gates

    for path in report_paths:
        try:
            ci_gates.check_junit_report(path, label=path.name)
        except ci_gates.GateError as error:
            raise ReleaseGateError(str(error)) from error
    if waivers_path is None:
        # The repository's structured waivers are authoritative when present;
        # an explicit path is still honored (and fails closed when missing).
        repository_waivers = Path(".github/security-waivers.json")
        if repository_waivers.is_file():
            waivers_path = repository_waivers
    try:
        ci_gates.evaluate_scan_report(scan_path, waivers_path=waivers_path)
    except ci_gates.GateError as error:
        raise ReleaseGateError(str(error)) from error
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
    if type(approval.get("contract_version")) is not int or approval.get(
        "contract_version"
    ) != CONTRACT_VERSION:
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
        migrations: Mapping[str, str] | None = None,
    ):
        self._active = validate_previous_release(active_release)
        self._slots = active_slots
        self.promotions = dict(promotions or {})
        self._migrations = dict(migrations or {})
        self.switches: list[dict[str, Any]] = []
        self.audits: list[dict[str, Any]] = []

    def applied_migrations(self) -> Mapping[str, str]:
        if not self._migrations:
            raise ReleaseGateError(
                "dict backend has no migration ledger; configure it in the test"
            )
        return dict(self._migrations)

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

    @contextmanager
    def transaction(self):
        snapshot = (
            copy.deepcopy(self._active),
            copy.deepcopy(self.promotions),
            copy.deepcopy(self.switches),
            copy.deepcopy(self.audits),
        )
        try:
            yield self
        except BaseException:
            self._active, self.promotions, self.switches, self.audits = snapshot
            raise

    def record_audit(self, result: Mapping[str, Any]) -> None:
        self.audits.append(dict(result))
        candidate = result.get("candidate_digest")
        # Mirror ReleaseStore.promotion_for(): only a successful promotion is
        # an idempotency key. A rolled-back smoke run must stay replayable.
        if isinstance(candidate, str) and result.get("status") == "promoted":
            self.promotions.setdefault(candidate, dict(result))

    def promotion_for(self, candidate_digest: str) -> Mapping[str, Any] | None:
        found = self.promotions.get(candidate_digest)
        return dict(found) if found is not None else None


def _candidate_config(manifest: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "contract_version": manifest["contract_version"],
        "migration_version": manifest["migration_version"],
    }


def _backend_transaction(backend: PromotionBackend):
    """Return the backend's atomic transaction scope when it provides one."""
    factory = getattr(backend, "transaction", None)
    if callable(factory):
        return factory()
    return nullcontext()


def _require_drained(backend: PromotionBackend, *, action: str) -> None:
    active_slots = backend.active_slots()
    if type(active_slots) is not int or active_slots != 0:
        raise ReleaseGateError(
            f"{action} blocked: execution slots not drained "
            f"(active_slots={active_slots})"
        )


def _same_release(left: Mapping[str, Any], right: Mapping[str, Any]) -> bool:
    if not isinstance(left, Mapping) or not isinstance(right, Mapping):
        return False
    return all(
        left.get(field) == right.get(field)
        for field in ("image_id", "config", "migration_version", "evidence_root")
    )


def _migration_ledger(backend: PromotionBackend) -> dict[str, str]:
    """Read and validate the target database's migration ledger.

    Promotion must prove the real schema matches the candidate manifest. A
    backend without a ledger fails closed rather than silently trusting the
    approval record's ``migration_compatible`` boolean.
    """
    getter = getattr(backend, "applied_migrations", None)
    if not callable(getter):
        raise ReleaseGateError(
            "release blocked: the promotion backend does not expose a "
            "schema_migrations ledger"
        )
    applied = getter()
    if not isinstance(applied, Mapping):
        raise ReleaseGateError("release blocked: the migration ledger is malformed")
    normalized: dict[str, str] = {}
    for name, digest in applied.items():
        if not isinstance(name, str) or not _MIGRATION_NAME.fullmatch(name):
            raise ReleaseGateError(
                f"release blocked: invalid migration ledger file name {name!r}"
            )
        _require_digest(digest, f"migration ledger digest for {name}")
        normalized[name] = digest
    return normalized


def _verify_manifest_migrations(
    manifest: Mapping[str, Any], applied: Mapping[str, str]
) -> dict[str, str]:
    """Require the ledger to contain exactly the manifest's files and digests."""
    expected = {entry["file"]: entry["sha256"] for entry in manifest["migrations"]}
    missing = sorted(set(expected) - set(applied))
    extra = sorted(set(applied) - set(expected))
    mismatched = sorted(
        name
        for name in expected
        if name in applied and applied[name] != expected[name]
    )
    if missing or extra or mismatched:
        raise ReleaseGateError(
            "promotion blocked: database migration ledger does not match the "
            f"candidate manifest (missing={missing} extra={extra} "
            f"mismatched={mismatched})"
        )
    return expected


def _migration_ordinal(name: str, label: str) -> int:
    match = _MIGRATION_NUMBER.match(name)
    if match is None:
        raise ReleaseGateError(f"{label} is not a NNN_*.sql migration: {name!r}")
    return int(match.group(1))


def _verify_rollback_migrations(
    *,
    target_version: str,
    current_version: str,
    applied: Mapping[str, str],
) -> int:
    """Enforce the forward-compatibility boundary for a rollback.

    PostgreSQL migrations are never reverted by a rollback. The target image is
    only safe when every migration newer than its version is declared
    rollback-compatible; otherwise this fails closed instead of letting
    ``release_state.migration_version`` claim a schema the image cannot use.
    """
    if target_version not in applied:
        raise ReleaseGateError(
            "rollback blocked: target migration_version is not in the applied "
            f"migration ledger: {target_version}"
        )
    if current_version not in applied:
        raise ReleaseGateError(
            "rollback blocked: active migration_version is not in the applied "
            f"migration ledger: {current_version}"
        )
    target_number = _migration_ordinal(target_version, "target migration_version")
    current_number = _migration_ordinal(
        current_version, "active migration_version"
    )
    if target_number > current_number:
        raise ReleaseGateError(
            "rollback blocked: target migration_version is newer than the "
            "active schema"
        )
    crossed = sorted(
        name
        for name in applied
        if _migration_ordinal(name, "migration ledger entry") > target_number
    )
    incompatible = [
        name for name in crossed if name not in ROLLBACK_COMPATIBLE_MIGRATIONS
    ]
    if incompatible:
        raise ReleaseGateError(
            "rollback blocked: target crosses migrations without a declared "
            f"backward-compatibility boundary: {', '.join(incompatible)}"
        )
    return target_number


def _release_record_digest(record: Mapping[str, Any]) -> str:
    return jsonutil.digest_json(
        {
            "image_id": record["image_id"],
            "config": dict(record["config"]),
            "migration_version": record["migration_version"],
            "evidence_root": record["evidence_root"],
        }
    )


def _persisted_manifest_digest(
    backend: PromotionBackend, record: Mapping[str, Any]
) -> str:
    """Return the target release's manifest digest, never its image id.

    Promoted releases have an approved manifest digest in the audit log. A
    bootstrapped baseline has no candidate manifest, so a digest of the
    baseline snapshot is used and remains clearly distinguishable from an RC
    manifest digest.
    """
    getter = getattr(backend, "release_for_image", None)
    if callable(getter):
        found = getter(record["image_id"])
        if isinstance(found, Mapping):
            digest = found.get("manifest_digest")
            if isinstance(digest, str) and _SHA256.fullmatch(digest):
                return digest
    return _release_record_digest(record)


def _existing_promotion(
    backend: PromotionBackend, existing: Mapping[str, Any]
) -> dict[str, Any]:
    if existing.get("status") != "promoted":
        raise ReleaseGateError(
            "candidate already has a non-promoted audit record; refusing to replay"
        )
    expected = validate_previous_release(
        {
            "image_id": existing.get("active_image_id"),
            "config": existing.get("config"),
            "migration_version": existing.get("migration_version"),
            "evidence_root": existing.get("evidence_root"),
        }
    )
    active = backend.active_release()
    if active is None or not _same_release(active, expected):
        raise ReleaseGateError(
            "candidate was previously promoted but the active release no longer "
            "matches its persisted image/config/migration/evidence_root; "
            "refusing to replay a stale approval"
        )
    return dict(existing)


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
    """Drain-check, switch to the candidate, smoke it, and audit the outcome.

    The candidate must become the active release *before* the smoke suite runs.
    A smoke failure is therefore a real transition back to the persisted
    previous release: ``rollback_fn`` must prove it restored every field and
    the backend must expose a real rollback state change. A no-op rollback
    callable fails closed. The candidate switch, smoke result, rollback switch
    and audit share one backend transaction, so a failure cannot leave
    ``release_state`` and ``release_events`` out of sync.
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
        return _existing_promotion(backend, existing)

    _require_drained(backend, action="promotion")
    previous = backend.active_release()
    if previous is None:
        raise ReleaseGateError(
            "promotion blocked: no persisted previous release; bootstrap the "
            "release_state row before promoting"
        )
    previous = validate_previous_release(previous)

    candidate_image = manifest["control_plane_image_id"]
    config = _candidate_config(manifest)
    candidate_record = {
        "image_id": candidate_image,
        "config": config,
        "migration_version": manifest["migration_version"],
        "evidence_root": previous["evidence_root"],
    }
    previous_manifest_digest = _persisted_manifest_digest(backend, previous)
    smoke_results: dict[str, bool] = {}
    failed_check: str | None = None

    with _backend_transaction(backend):
        # Re-read inside the transaction: another promotion may have finished
        # while the drain check ran, and this attempt must not overwrite it.
        existing = backend.promotion_for(candidate_digest)
        if existing is not None:
            return _existing_promotion(backend, existing)
        _require_drained(backend, action="promotion")
        current = backend.active_release()
        if current is None or not _same_release(current, previous):
            raise ReleaseGateError(
                "active release changed before the candidate switch; refusing "
                "to overwrite a concurrent promotion"
            )
        _verify_manifest_migrations(manifest, _migration_ledger(backend))
        backend.switch(
            image_id=candidate_image,
            config=config,
            migration_version=manifest["migration_version"],
            evidence_root=previous["evidence_root"],
            action="promote",
            candidate_digest=candidate_digest,
        )
        switched = backend.active_release()
        if switched is None or not _same_release(switched, candidate_record):
            raise ReleaseGateError(
                "promotion switch did not make the candidate release active with "
                "its exact image/config/migration/evidence_root"
            )

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
            before_rollback = (
                len(backend.switches)
                if isinstance(getattr(backend, "switches", None), list)
                else None
            )
            try:
                rollback_outcome = rollback_fn(previous)
            except Exception as error:  # noqa: BLE001 - never swallow rollback failures
                raise ReleaseGateError(f"rollback failed: {error}") from error
            rollback_outcome = validate_rollback_outcome(
                rollback_outcome, expected_image=previous["image_id"]
            )
            restored = backend.active_release()
            if restored is None or not _same_release(restored, previous):
                raise ReleaseGateError(
                    "rollback callable returned success but the backend did not "
                    "restore the previous release "
                    "(image/config/migration_version/evidence_root)"
                )
            if before_rollback is not None:
                for entry in backend.switches[before_rollback:]:
                    if entry.get("action") != "rollback":
                        continue
                    switched_release = {
                        field: entry.get(field)
                        for field in (
                            "image_id",
                            "config",
                            "migration_version",
                            "evidence_root",
                        )
                    }
                    if _same_release(switched_release, previous):
                        break
                else:
                    raise ReleaseGateError(
                        "rollback callable did not perform a real rollback state "
                        "transition"
                    )
            result = {
                "schema_version": SCHEMA_VERSION,
                "status": "rolled_back",
                "failed_check": failed_check,
                "candidate_digest": candidate_digest,
                "manifest_digest": previous_manifest_digest,
                "source_commit": manifest["source_commit"],
                "previous_image_id": candidate_image,
                "active_image_id": previous["image_id"],
                "approved_by": approval["approved_by"],
                "migration_version": previous["migration_version"],
                "previous_migration_version": candidate_record["migration_version"],
                "config": dict(previous["config"]),
                "evidence_root": previous["evidence_root"],
                "smoke_results": smoke_results,
                "rollback": rollback_outcome,
                "migration_ledger_verified": True,
                "recorded_at": _utc_now(),
            }
            backend.record_audit(result)
            return result

        result = {
            "schema_version": SCHEMA_VERSION,
            "status": "promoted",
            "failed_check": None,
            "candidate_digest": candidate_digest,
            "manifest_digest": candidate_digest,
            "source_commit": manifest["source_commit"],
            "previous_image_id": previous["image_id"],
            "active_image_id": candidate_image,
            "approved_by": approval["approved_by"],
            "migration_version": manifest["migration_version"],
            "config": config,
            "evidence_root": previous["evidence_root"],
            "smoke_results": smoke_results,
            "rollback": None,
            "migration_ledger_verified": True,
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
    manifest_digest: str | None = None,
) -> dict[str, Any]:
    """Restore a persisted target release after the same smoke suite passes."""
    if not isinstance(smoke_checks, Mapping) or not smoke_checks:
        raise ReleaseGateError("rollback requires at least one smoke check")
    target = validate_previous_release(target_release)
    if not isinstance(approved_by, str) or not approved_by.strip():
        raise ReleaseGateError("rollback requires an approved_by identity")
    _require_digest(candidate_digest, "rollback candidate_digest")
    current = backend.active_release()
    if current is None:
        raise ReleaseGateError("rollback blocked: no persisted active release")
    _require_drained(backend, action="rollback")

    resolved_manifest_digest = (
        manifest_digest if manifest_digest is not None else target.get("manifest_digest")
    )
    if not isinstance(resolved_manifest_digest, str) or not _SHA256.fullmatch(
        resolved_manifest_digest
    ):
        raise ReleaseGateError(
            "rollback requires the target release's manifest_digest from the "
            "persisted audit record; an image id is not a manifest digest"
        )

    smoke_results: dict[str, bool] = {}
    for name, check_fn in smoke_checks.items():
        try:
            ok = bool(check_fn())
        except Exception:  # noqa: BLE001 - rollback smoke failure blocks the switch
            ok = False
        smoke_results[name] = ok
        if not ok:
            raise ReleaseGateError(f"rollback blocked: smoke check failed: {name}")
    with _backend_transaction(backend):
        _require_drained(backend, action="rollback")
        latest = backend.active_release()
        if latest is None or not _same_release(latest, current):
            raise ReleaseGateError(
                "active release changed while rollback smoke checks ran; "
                "refusing to overwrite a concurrent promotion"
            )
        _verify_rollback_migrations(
            target_version=target["migration_version"],
            current_version=latest["migration_version"],
            applied=_migration_ledger(backend),
        )
        backend.switch(
            image_id=target["image_id"],
            config=target["config"],
            migration_version=target["migration_version"],
            evidence_root=target["evidence_root"],
            action="rollback",
            candidate_digest=candidate_digest,
        )
        active = backend.active_release()
        if active is None or not _same_release(active, target):
            raise ReleaseGateError(
                "rollback switch did not restore the target release "
                "(image/config/migration_version/evidence_root)"
            )
        result = {
            "schema_version": SCHEMA_VERSION,
            "status": "rolled_back",
            "failed_check": None,
            "candidate_digest": candidate_digest,
            "manifest_digest": resolved_manifest_digest,
            "source_commit": target.get("source_commit"),
            "previous_image_id": current["image_id"],
            "active_image_id": target["image_id"],
            "approved_by": approved_by,
            "migration_version": target["migration_version"],
            "previous_migration_version": latest["migration_version"],
            "config": dict(target["config"]),
            "evidence_root": target["evidence_root"],
            "smoke_results": smoke_results,
            "rollback": {
                "ok": True,
                "restored_image": target["image_id"],
            },
            "migration_ledger_verified": True,
            "recorded_at": _utc_now(),
        }
        backend.record_audit(result)
    return result


def write_smoke_evidence_bundle(
    bundle_dir: Path,
    *,
    cases_dir: Path,
) -> str:
    """Write a standard verified evidence bundle for candidate container smoke checks.

    Files are chmodded to 0o444 and directories to 0o755 so the unprivileged
    container user (65534:65534) can verify the mounted bundle read-only.
    """
    from datacon.agents.analysis import analyze_case
    from datacon.asan import parse_asan

    request = contracts.parse_request(
        json.dumps(
            {
                "schema_version": 1,
                "cve_id": "CVE-2099-0001",
                "target": {
                    "kind": "source",
                    "case_id": "fixture-c-parser",
                    "goal": "promotion smoke bundle verification",
                },
                "limits": dict(contracts.DEFAULT_LIMITS),
            }
        )
    )
    analyzed = analyze_case(request, case_root=str(cases_dir))
    plan = analyzed.plan
    plan_digest = analyzed.plan_digest
    job_id = str(uuid.uuid4())
    review = {
        "reviewer_id": "release-smoke",
        "decision": "approve",
        "plan_digest": plan_digest,
        "decided_at": "2026-11-17T00:00:00Z",
    }

    registry_doc = json.loads((cases_dir / "registry.json").read_text(encoding="utf-8"))
    manifest_doc = json.loads((cases_dir / "manifest.json").read_text(encoding="utf-8"))
    case_entry = registry_doc["cases"]["fixture-c-parser"]
    manifest_case = manifest_doc["cases"]["B01"]
    materials_digests = dict(manifest_doc["materials"])
    used_keys = {
        manifest_doc["harness"],
        manifest_doc["build_recipe"],
        manifest_doc["dependencies"],
        case_entry["repository"]["patch"],
        manifest_doc["versions"]["vulnerable"],
        manifest_doc["versions"]["fixed"],
        manifest_case["inputs"]["normal"],
        manifest_case["inputs"]["candidate"],
    }
    used_materials = {key: materials_digests[key] for key in used_keys}
    case_config = {
        "case_id": plan["case_id"],
        "cve_id": plan["cve_id"],
        "benchmark_id": "B01",
        "registry_entry": case_entry,
        "manifest_case": manifest_case,
        "materials": used_materials,
        "image": f"silkeh/clang:19-bookworm@{plan['image_digest']}",
        "platform": plan["platform"],
        "toolchain": plan["toolchain"],
        "asan_options": plan["asan_options"],
        "asan_signature": manifest_doc["asan_signature"],
    }

    build_recipe = (cases_dir / manifest_doc["build_recipe"]).read_bytes()
    compile_args = list(_extract_compile_args(build_recipe))
    staged_materials = dict(used_materials)
    staged_materials["inputs/normal.txt"] = plan["inputs"]["normal"]
    staged_materials["inputs/candidate.txt"] = plan["inputs"]["candidate"]

    probe_doc = {
        "tool_id": "sandbox.probe",
        "job_id": job_id,
        "plan_digest": plan_digest,
        "generation": 1,
        "status": "completed",
        "container_id": None,
        "checks": {
            "uid": "65534",
            "seccomp": "2",
            "no_new_privs": "1",
            "cap_eff": "0000000000000000",
            "cgroup_version": "2",
        },
        "compiler_version": "clang 19.1.7",
        "image_digest": plan["image_digest"],
        "limits": {
            key: int(plan["limits"][key])
            for key in ("cpu", "memory_mib", "pids", "scratch_mib")
        },
    }

    build_artifacts: dict[str, bytes] = {}
    build_logs: dict[str, bytes] = {}
    build_docs: dict[str, dict[str, Any]] = {}
    for version in ("vulnerable", "fixed"):
        art = f"smoke-parser-{version}".encode("utf-8")
        log = f"smoke build {version}\n".encode("utf-8")
        build_artifacts[version] = art
        build_logs[version] = log
        build_docs[version] = {
            "tool_id": "sandbox.build",
            "job_id": job_id,
            "generation": 1,
            "plan_digest": plan_digest,
            "input_digest": plan["analysis_digest"],
            "status": "completed",
            "version": version,
            "exit_code": 0,
            "duration_seconds": 0.1,
            "container_id": f"smoke-build-{version}",
            "image_digest": plan["image_digest"],
            "build_recipe_digest": plan["build_recipe_digest"],
            "compile_args": compile_args,
            "artifact_digest": _sha256_bytes(art),
            "log_digest": _sha256_bytes(log),
            "log_truncated": False,
            "capture_error": None,
            "staged_materials": staged_materials,
            "files": {
                "log": f"build/{version}/build.log",
                "artifact": f"build/{version}/parser",
            },
            "file_digests": {
                "log": _sha256_bytes(log),
                "artifact": _sha256_bytes(art),
            },
        }

    asan_stderr = (
        "==1==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x502000000014\n"
        "WRITE of size 1 at 0x502000000014 thread T0\n"
        "    #0 0x401234 in parse_token /fixture/vulnerable/parser.c:22:17\n"
    ).encode("utf-8")
    replay_docs: list[dict[str, Any]] = []
    replay_obs: list[RunObservation] = []
    replay_raw: dict[tuple[str, str], tuple[bytes, bytes]] = {}
    for version in ("vulnerable", "fixed"):
        for phase in ("normal", "candidate_1", "candidate_2"):
            if phase == "normal":
                out_b = manifest_case["expected_stdout"]["normal"].encode("utf-8")
                err_b = b""
                exit_code = int(plan["expected_exit"]["normal"])
                in_digest = plan["inputs"]["normal"]
            elif version == "vulnerable":
                out_b = b""
                err_b = asan_stderr
                exit_code = int(plan["expected_exit"]["candidate_asan"])
                in_digest = plan["inputs"]["candidate"]
            else:
                out_b = manifest_case["expected_stdout"]["candidate_clean"].encode("utf-8")
                err_b = b""
                exit_code = int(plan["expected_exit"]["candidate_clean"])
                in_digest = plan["inputs"]["candidate"]
            sig = parse_asan(err_b.decode("utf-8", "replace"))
            replay_raw[(version, phase)] = (out_b, err_b)
            replay_docs.append(
                {
                    "tool_id": "sandbox.replay",
                    "job_id": job_id,
                    "generation": 1,
                    "plan_digest": plan_digest,
                    "input_digest": in_digest,
                    "artifact_digest": build_docs[version]["artifact_digest"],
                    "status": "completed",
                    "version": version,
                    "phase": phase,
                    "exit_code": exit_code,
                    "duration_seconds": 0.1,
                    "container_id": f"smoke-{version}-{phase}",
                    "image_digest": plan["image_digest"],
                    "asan_options": plan["asan_options"],
                    "stdout_sha256": _sha256_bytes(out_b),
                    "stdout_bytes": len(out_b),
                    "stderr_sha256": _sha256_bytes(err_b),
                    "stderr_bytes": len(err_b),
                    "signature": sig.as_dict() if sig else None,
                    "timed_out": False,
                    "quota_hit": False,
                    "log_truncated": False,
                    "capture_error": None,
                    "files": {
                        "stdout": f"replay/{version}/{phase}/stdout.log",
                        "stderr": f"replay/{version}/{phase}/stderr.log",
                    },
                    "file_digests": {
                        "stdout": _sha256_bytes(out_b),
                        "stderr": _sha256_bytes(err_b),
                    },
                }
            )
            replay_obs.append(
                RunObservation(
                    version=version,
                    phase=phase,
                    status="completed",
                    exit_code=exit_code,
                    stdout=out_b.decode("utf-8", "replace"),
                    stderr=err_b.decode("utf-8", "replace"),
                    signature=sig,
                    input_digest=in_digest,
                    duration_seconds=0.1,
                    log_truncated=False,
                    capture_error=None,
                )
            )

    policy = VerdictPolicy(
        signature=plan["asan_signature"],
        expected_exit=plan["expected_exit"],
        expected_stdout=manifest_case["expected_stdout"],
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
        "cve_id": plan["cve_id"],
        "case_id": plan["case_id"],
        "state": decision.verdict,
        "verdict": decision.verdict,
        "reason_code": decision.reason_code,
        "target": request["target"],
        "versions": plan["revisions"],
        "repository": plan["repository"],
        "environment": {
            "image": case_config["image"],
            "image_digest": plan["image_digest"],
            "platform": plan["platform"],
            "toolchain": plan["toolchain"],
            "asan_options": plan["asan_options"],
            "compile_args": compile_args,
            "isolation": plan["isolation"],
            "probe": probe_doc,
        },
        "budget": plan["limits"],
        "inputs": plan["inputs"],
        "review": review,
        "signature": plan["asan_signature"],
        "builds": list(build_docs.values()),
        "replays": replay_docs,
        "rule": decision.as_dict(),
        "evidence_refs": [
            "report.json",
            "report.md",
            "plan.json",
            "review.json",
            "metadata/execution.json",
        ],
        "missing": [],
        "error": None,
        "evidence_complete": True,
        "created_at": review["decided_at"],
    }
    report_md = "\n".join(
        [
            "# DataCon smoke verification report",
            "",
            f"- Job: `{job_id}`",
            f"- Plan: `{plan_digest}`",
            f"- Verdict: **{decision.verdict}**",
            f"- Reason: `{decision.reason_code}`",
            "",
        ]
    )
    role_map = {
        manifest_doc["harness"]: "material_harness",
        manifest_doc["build_recipe"]: "material_build_recipe",
        manifest_doc["dependencies"]: "material_dependencies",
        case_entry["repository"]["patch"]: "material_patch",
        manifest_doc["versions"]["vulnerable"]: "material_source_vulnerable",
        manifest_doc["versions"]["fixed"]: "material_source_fixed",
        manifest_case["inputs"]["normal"]: "material_input_normal",
        manifest_case["inputs"]["candidate"]: "material_input_candidate",
    }
    artifacts: dict[str, tuple[str, bytes]] = {
        "plan.json": ("plan", jsonutil.canonical_bytes(plan) + b"\n"),
        "review.json": ("review", jsonutil.canonical_bytes(review) + b"\n"),
        "metadata/execution.json": (
            "execution_metadata",
            jsonutil.canonical_bytes(execution_metadata) + b"\n",
        ),
        "metadata/probe.json": ("probe", jsonutil.canonical_bytes(probe_doc) + b"\n"),
        "metadata/case.json": (
            "case_config",
            jsonutil.canonical_bytes({"case_config": case_config}) + b"\n",
        ),
    }
    for rel, role in role_map.items():
        artifacts[f"materials/{rel}"] = (role, (cases_dir / rel).read_bytes())
    for version in ("vulnerable", "fixed"):
        artifacts[f"build/{version}/build.log"] = ("build_log", build_logs[version])
        artifacts[f"build/{version}/parser"] = ("build_artifact", build_artifacts[version])
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
        bundle_dir,
        job_id=job_id,
        plan_digest=plan_digest,
        report=report,
        report_markdown=report_md,
        artifacts=artifacts,
        verdict=decision.verdict,
        verify=evidence.verify_bundle,
    )
    for item in sorted(bundle_dir.rglob("*"), key=lambda p: len(p.parts)):
        if item.is_dir():
            item.chmod(0o755)
        else:
            item.chmod(0o444)
    bundle_dir.chmod(0o755)
    return info.manifest_digest


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
_MAX_B03_TOTAL_FILES = 4096
_MAX_B03_TOTAL_BYTES = 256 * 1024 * 1024


def _safe_child(root: Path, relative: str, label: str) -> Path:
    try:
        return jsonutil.resolve_inside(root, relative)
    except ValueError as error:
        raise ReleaseGateError(
            f"{label} is not a safe B03 path: {error}"
        ) from error


def _read_material(path: Path, label: str) -> bytes:
    """Read one B03 material through the bounded, symlink-safe helper.

    ``read_regular_file_bounded`` opens with ``O_NOFOLLOW`` and re-checks
    ``fstat``, so a symlink or a file that changes/grows during the read is
    rejected instead of being silently followed (the old
    ``is_symlink()`` + ``read_bytes()`` pair was a TOCTOU window).
    """
    try:
        return fileio.read_regular_file_bounded(
            path, max_bytes=_MAX_B03_MATERIAL_BYTES
        )
    except fileio.UnsafeFileError as error:
        raise ReleaseGateError(
            f"unsafe B03 material {label}: {error.kind}: {error.message}"
        ) from error


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
    normal_input: bytes
    candidate_input: bytes
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
        file_count = 0
        total_bytes = 0

        def load_file(relative: str, label: str) -> bytes:
            nonlocal file_count, total_bytes
            data = _read_material(_safe_child(resolved, relative, label), label)
            file_count += 1
            total_bytes += len(data)
            if file_count > _MAX_B03_TOTAL_FILES:
                raise ReleaseGateError(
                    f"B03 case root exceeds the {_MAX_B03_TOTAL_FILES}-file cap"
                )
            if total_bytes > _MAX_B03_TOTAL_BYTES:
                raise ReleaseGateError(
                    f"B03 case root exceeds the {_MAX_B03_TOTAL_BYTES}-byte cap"
                )
            return data

        payload = {
            name: load_file(name, name) for name in _B03_REQUIRED_FILES
        }
        trees: dict[str, dict[str, bytes]] = {}
        for tree in _B03_REQUIRED_TREES:
            tree_path = _safe_child(resolved, tree, tree)
            if not tree_path.is_dir():
                raise ReleaseGateError(f"required B03 material tree is missing: {tree}/")
            files: dict[str, bytes] = {}
            for path in sorted(tree_path.rglob("*")):
                if path.is_dir():
                    continue
                relative = path.relative_to(tree_path).as_posix()
                files[relative] = load_file(f"{tree}/{relative}", f"{tree}/{relative}")
            if not files:
                raise ReleaseGateError(f"required B03 material tree is empty: {tree}/")
            trees[tree] = files
        normal_input = load_file("inputs/normal.txt", "inputs/normal.txt")
        candidate_input = load_file("inputs/candidate.txt", "inputs/candidate.txt")
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
            normal_input=normal_input,
            candidate_input=candidate_input,
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


def _b03_string(container: Any, key: str, label: str) -> str:
    if not isinstance(container, Mapping):
        raise ReleaseGateError(f"B03 admission {label} must be an object")
    value = container.get(key)
    if not isinstance(value, str) or not value.strip():
        raise ReleaseGateError(
            f"B03 admission {label}.{key} must be a non-empty string"
        )
    return value


def _b03_url(container: Any, key: str, label: str) -> str:
    value = _b03_string(container, key, label)
    if not _HTTP_URL.fullmatch(value):
        raise ReleaseGateError(f"B03 admission {label}.{key} must be an HTTP(S) URL")
    return value


def _b03_exit_code(container: Any, key: str, label: str) -> int:
    if not isinstance(container, Mapping):
        raise ReleaseGateError(f"B03 admission {label} must be an object")
    value = container.get(key)
    if type(value) is not int:
        raise ReleaseGateError(f"B03 admission {label}.{key} must be an integer")
    return value


_B03_DEFERRED_CHECK_OWNER_FIELD = "owner_task"


def _validate_b03_checks(checks: Any) -> None:
    """Reject an admission whose critical checks failed or are not deferred."""
    if isinstance(checks, Mapping):
        entries = []
        for check_id, value in checks.items():
            if isinstance(value, Mapping):
                entries.append(dict(value, id=check_id))
            else:
                entries.append({"id": check_id, "status": value})
    elif isinstance(checks, list):
        entries = checks
    else:
        raise ReleaseGateError("B03 admission checks must be a list or object")
    if not entries:
        raise ReleaseGateError("B03 admission checks must not be empty")
    for index, entry in enumerate(entries):
        if not isinstance(entry, Mapping):
            raise ReleaseGateError(
                f"B03 admission checks[{index}] must be an object"
            )
        check_id = entry.get("id")
        if not isinstance(check_id, str) or not check_id.strip():
            raise ReleaseGateError(
                f"B03 admission checks[{index}] is missing a non-empty id"
            )
        status = entry.get("status")
        if status not in {"pass", "deferred"}:
            raise ReleaseGateError(
                f"B03 admission check {check_id!r} has status {status!r}; only "
                "'pass' or an explicit deferred check is allowed"
            )
        if status == "deferred":
            owner = entry.get(_B03_DEFERRED_CHECK_OWNER_FIELD)
            if not isinstance(owner, str) or not owner.strip():
                raise ReleaseGateError(
                    f"B03 admission check {check_id!r} is deferred without an "
                    f"{_B03_DEFERRED_CHECK_OWNER_FIELD}"
                )


def _validate_b03_admission(admission: Mapping[str, Any]) -> dict[str, Any]:
    """Validate every B03 admission field the plan copies, without KeyError."""
    if not isinstance(admission, Mapping):
        raise ReleaseGateError("B03 admission must be an object")
    if admission.get("benchmark_id") != "B03":
        raise ReleaseGateError("B03 admission benchmark_id must be B03")
    if admission.get("decision") != "admit_to_planning":
        raise ReleaseGateError(
            "B03 admission decision must be admit_to_planning"
        )
    admission_status = admission.get("status")
    if not isinstance(admission_status, str) or not admission_status.strip():
        raise ReleaseGateError("B03 admission status must be a non-empty string")
    if admission_status.strip().lower() in {"rejected", "denied", "blocked"}:
        raise ReleaseGateError(
            f"B03 admission status is not admissible: {admission_status!r}"
        )
    _validate_b03_checks(admission.get("checks"))
    _b03_string(admission, "usage_boundary", "admission")
    cve_id = _b03_string(admission, "cve_id", "admission")
    if not _CVE_ID.fullmatch(cve_id):
        raise ReleaseGateError("B03 admission cve_id must be a CVE identifier")
    signature = admission.get("asan_signature")
    if not isinstance(signature, Mapping):
        raise ReleaseGateError("B03 admission is missing asan_signature")
    status = signature.get("status")
    if status not in {"frozen", "verified"}:
        raise ReleaseGateError(
            "B03 admission asan_signature.status must be frozen; "
            f"got {status!r}"
        )
    asan_signature: dict[str, Any] = {
        "error": _b03_string(signature, "error", "asan_signature"),
        "function": _b03_string(signature, "function", "asan_signature"),
        "source": _b03_string(signature, "source", "asan_signature"),
    }
    operation = signature.get("operation")
    if operation is not None:
        if not isinstance(operation, str) or not operation.strip():
            raise ReleaseGateError(
                "B03 admission asan_signature.operation must be a non-empty string"
            )
        asan_signature["operation"] = operation
    access_size = signature.get("access_size")
    if access_size is not None:
        if type(access_size) is not int or access_size <= 0:
            raise ReleaseGateError(
                "B03 admission asan_signature.access_size must be a positive integer"
            )
        asan_signature["access_size"] = access_size
    verdict_status = admission.get("expected_verdict_status")
    if verdict_status not in {"frozen", "verified"}:
        raise ReleaseGateError(
            "B03 admission expected_verdict_status must be frozen; "
            f"got {verdict_status!r}"
        )
    expected_verdict = admission.get("expected_verdict", "REPRODUCED")
    if expected_verdict not in _B03_VERDICTS:
        raise ReleaseGateError(
            "B03 admission expected_verdict must be a known verdict"
        )
    versions = admission.get("versions")
    if not isinstance(versions, Mapping):
        raise ReleaseGateError("B03 admission versions must be an object")
    commits: dict[str, str] = {}
    for role in ("vulnerable", "fixed"):
        entry = versions.get(role)
        if not isinstance(entry, Mapping):
            raise ReleaseGateError(
                f"B03 admission versions.{role} must be an object"
            )
        commit = _b03_string(entry, "commit", f"versions.{role}")
        if not _GIT_SHA40.fullmatch(commit):
            raise ReleaseGateError(
                f"B03 admission {role} commit must be a 40-char lowercase Git SHA"
            )
        commits[role] = commit
    build = admission.get("build")
    toolchain_image = _b03_string(build, "toolchain_image", "build")
    harness = admission.get("harness")
    asan_options = _b03_string(harness, "asan_options", "harness")
    expected_exit = {
        "normal": _b03_exit_code(harness, "normal_exit_code", "harness"),
        "candidate_clean": 0,
        "candidate_asan": _b03_exit_code(
            harness, "candidate_asan_exit_code", "harness"
        ),
    }
    repository = admission.get("repository")
    repository_url = _b03_url(repository, "url", "repository")
    source_path = repository.get("source_path", "src/regext.c")
    if (
        not isinstance(source_path, str)
        or not source_path.strip()
        or ".." in PurePosixPath(source_path).parts
    ):
        raise ReleaseGateError("B03 repository.source_path is invalid")
    advisory = admission.get("advisory")
    advisory_url = _b03_url(advisory, "nvd", "advisory")
    return {
        "cve_id": cve_id,
        "asan_signature": asan_signature,
        "expected_verdict": expected_verdict,
        "vulnerable_commit": commits["vulnerable"],
        "fixed_commit": commits["fixed"],
        "toolchain_image": toolchain_image,
        "asan_options": asan_options,
        "expected_exit": expected_exit,
        "repository_url": repository_url,
        "source_path": source_path,
        "advisory_url": advisory_url,
    }


def _validate_b03_advisory(
    advisory: Mapping[str, Any],
    *,
    cve_id: str,
    vulnerable_commit: str,
    fixed_commit: str,
) -> None:
    """Reject an empty or contradictory case advisory.

    An empty ``{}`` is not evidence: the advisory must name the CVE and at
    least one of the vulnerable/fixed commits, and every commit it does name
    must match the admission record.
    """
    if not isinstance(advisory, Mapping):
        raise ReleaseGateError("B03 advisory.json must be a JSON object")
    advisory_cve = advisory.get("cve_id")
    if advisory_cve != cve_id:
        raise ReleaseGateError(
            "B03 advisory.json must contain a cve_id matching the admission"
        )
    matched_commits = 0
    for key, expected in (
        ("vulnerable_commit", vulnerable_commit),
        ("fixed_commit", fixed_commit),
    ):
        value = advisory.get(key)
        if value is not None:
            if value != expected:
                raise ReleaseGateError(
                    f"B03 advisory.json {key} does not match the admission"
                )
            matched_commits += 1
    if matched_commits == 0:
        raise ReleaseGateError(
            "B03 advisory.json must record at least one of vulnerable_commit "
            "or fixed_commit"
        )
    sources = advisory.get("sources")
    if sources is not None:
        if not isinstance(sources, list):
            raise ReleaseGateError("B03 advisory.json sources must be a list")
        for index, source in enumerate(sources):
            if not isinstance(source, Mapping):
                raise ReleaseGateError(
                    "B03 advisory.json sources entries must be objects"
                )
            for key, expected in (
                ("vulnerable_commit", vulnerable_commit),
                ("fixed_commit", fixed_commit),
            ):
                value = source.get(key)
                if value is not None and value != expected:
                    raise ReleaseGateError(
                        f"B03 advisory.json sources[{index}].{key} does not "
                        "match the admission"
                    )


def _b03_source_bytes(
    sources: Mapping[str, bytes], source_path: str
) -> bytes:
    """Return the exact approved source path; never fall back to a basename."""
    direct = sources.get(source_path)
    if direct is None:
        raise ReleaseGateError(
            "B03 repository.source_path is not present in the vulnerable tree: "
            f"{source_path}"
        )
    return direct


def prepare_b03_plan(
    *,
    admission: Mapping[str, Any],
    materials: B03CaseMaterials,
    normal_input: bytes,
    candidate_input: bytes,
) -> dict[str, Any]:
    """Build the exact B03 plan that a reviewer must approve before replay."""
    validated = _validate_b03_admission(admission)
    cve_id = validated["cve_id"]
    vuln_commit = validated["vulnerable_commit"]
    fixed_commit = validated["fixed_commit"]
    toolchain_image = validated["toolchain_image"]
    if "@" not in toolchain_image:
        raise ReleaseGateError("B03 toolchain image must be pinned by digest")
    image_digest = toolchain_image.split("@", 1)[1]
    _require_digest(image_digest, "B03 toolchain image digest")
    if image_digest != TOOLCHAIN_IMAGE_DIGEST:
        raise ReleaseGateError(
            "B03 admission toolchain image does not match the pinned toolchain"
        )
    advisory = jsonutil.loads_strict(materials.advisory)
    _validate_b03_advisory(
        advisory,
        cve_id=cve_id,
        vulnerable_commit=vuln_commit,
        fixed_commit=fixed_commit,
    )
    asan_options = validated["asan_options"]
    asan_sig = dict(validated["asan_signature"])
    expected_exit = dict(validated["expected_exit"])
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
    source_path = validated["source_path"]
    source_bytes = _b03_source_bytes(materials.vulnerable_sources, source_path)
    registry_entry = {
        "cve_id": cve_id,
        "benchmark_id": "B03",
        "repository": {
            "origin": validated["repository_url"],
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
        "expected_verdict": validated["expected_verdict"],
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
                "end_line": max(1, len(source_bytes.splitlines())),
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
            "origin": validated["repository_url"],
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
            "sources": [validated["advisory_url"]],
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
        "expected_verdict": validated["expected_verdict"],
        "asan_options": asan_options,
        "asan_signature": asan_sig,
        "image_digest": image_digest,
        "toolchain_image": toolchain_image,
        "toolchain_meta": toolchain_meta,
        "isolation": isolation,
        "limits": limits,
        "source_path": source_path,
    }


def _validate_b03_review(
    review: Mapping[str, Any],
    *,
    plan_digest: str,
    now: datetime | None = None,
) -> dict[str, Any]:
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
    decided_at = _parse_instant(review.get("decided_at"), "B03 review decided_at")
    reference = now or datetime.now(timezone.utc)
    if decided_at > reference + APPROVAL_FUTURE_SKEW:
        raise ReleaseGateError("B03 review is from the future")
    if reference - decided_at > APPROVAL_MAX_AGE:
        raise ReleaseGateError("B03 review has expired")
    return {
        "reviewer_id": review["reviewer_id"],
        "decision": "approve",
        "plan_digest": plan_digest,
        "decided_at": review["decided_at"],
    }


_B03_PROBE_CHECKS = {
    "uid": "65534",
    "seccomp": "2",
    "no_new_privs": "1",
    "cap_eff": "0000000000000000",
    "cgroup_version": "2",
}


def _require_probe(report: Any) -> Any:
    """Validate every isolation probe value before any build or replay runs."""
    if getattr(report, "ok", False) is not True:
        raise ReleaseGateError("B03 sandbox probe did not succeed")
    image_digest = getattr(report, "image_digest", None)
    _require_digest(image_digest, "B03 probe image_digest")
    limits = getattr(report, "limits", None)
    if not isinstance(limits, Mapping) or not limits:
        raise ReleaseGateError("B03 probe limits are missing")
    checks = getattr(report, "checks", None)
    if not isinstance(checks, Mapping):
        raise ReleaseGateError("B03 probe checks are incomplete")
    for key, expected in _B03_PROBE_CHECKS.items():
        actual = checks.get(key)
        if actual != expected:
            raise ReleaseGateError(
                "B03 probe isolation check failed: "
                f"{key}={actual!r} (expected {expected!r})"
            )
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


def _write_readonly_staged_file(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    path.chmod(0o444)


def _chmod_tree(root: Path, *, dir_mode: int = 0o755, file_mode: int = 0o444) -> None:
    for item in sorted(root.rglob("*"), key=lambda p: len(p.parts)):
        if item.is_dir():
            item.chmod(dir_mode)
        else:
            item.chmod(file_mode)
    root.chmod(dir_mode)


def _resolve_b03_job_id(sandbox: Any, job_id: str | uuid.UUID | None) -> str:
    sandbox_job_id = getattr(sandbox, "job_id", None)
    if job_id is not None:
        try:
            normalized = str(uuid.UUID(str(job_id)))
        except (TypeError, ValueError, AttributeError) as error:
            raise ReleaseGateError("B03 job_id must be a UUID") from error
        if sandbox_job_id is not None and str(sandbox_job_id) != normalized:
            raise ReleaseGateError(
                "B03 job_id does not match sandbox.job_id"
            )
        return normalized
    if sandbox_job_id is not None:
        try:
            return str(uuid.UUID(str(sandbox_job_id)))
        except (TypeError, ValueError, AttributeError) as error:
            raise ReleaseGateError("B03 sandbox.job_id must be a UUID") from error
    return str(uuid.uuid4())


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
    job_id: str | uuid.UUID | None = None,
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
    expected_verdict = prepared["expected_verdict"]
    asan_options = prepared["asan_options"]
    asan_sig = prepared["asan_signature"]
    image_digest = prepared["image_digest"]
    toolchain_image = prepared["toolchain_image"]
    toolchain_meta = prepared["toolchain_meta"]
    isolation = prepared["isolation"]
    limits = prepared["limits"]
    materials_map = prepared["materials"]
    compile_args = prepared["compile_args"]

    resolved_job_id = _resolve_b03_job_id(sandbox, job_id)
    probe_report = _require_probe(sandbox.probe(deadline_seconds=120.0))
    if probe_report.image_digest != image_digest:
        raise ReleaseGateError(
            "B03 probe image_digest does not match the approved toolchain"
        )
    probe_doc = {
        "tool_id": "sandbox.probe",
        "job_id": resolved_job_id,
        "plan_digest": plan_digest,
        "generation": 1,
        "status": "completed",
        "container_id": None,
        "checks": dict(probe_report.checks),
        "compiler_version": probe_report.compiler_version,
        "image_digest": probe_report.image_digest,
        "limits": dict(probe_report.limits),
    }

    bundle_out = Path(bundle_out)
    bundle_out.parent.mkdir(parents=True, exist_ok=True)
    # Stage the exact reviewed material tree with explicit 0o755/0o444 modes so
    # container uid 65534:65534 can read /fixture even under hardened umask 0077.
    staging_root = bundle_out.parent / f".b03-materials-{uuid.uuid4().hex}"
    staging_root.mkdir(parents=True, exist_ok=True)
    build_results: dict[str, Any] = {}
    artifact_paths: dict[str, Path] = {}
    staging_inputs: Path | None = None
    try:
        try:
            _write_readonly_staged_file(staging_root / "harness.c", materials.harness)
            _write_readonly_staged_file(staging_root / "build.sh", materials.build_recipe)
            _write_readonly_staged_file(
                staging_root / "dependencies.lock", materials.dependencies
            )
            _write_readonly_staged_file(staging_root / "fix.patch", materials.patch)
            _write_readonly_staged_file(
                staging_root / "b03-repo.bundle", materials.repository_bundle
            )
            _write_readonly_staged_file(staging_root / "advisory.json", materials.advisory)
            for prefix, sources in (
                ("vulnerable", materials.vulnerable_sources),
                ("fixed", materials.fixed_sources),
            ):
                for relative, data in sources.items():
                    _write_readonly_staged_file(staging_root / prefix / relative, data)
            _write_readonly_staged_file(
                staging_root / "inputs" / "normal.txt", normal_input
            )
            _write_readonly_staged_file(
                staging_root / "inputs" / "candidate.txt", candidate_input
            )
            _chmod_tree(staging_root, dir_mode=0o755, file_mode=0o444)

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
                artifact.chmod(0o555)
                artifact_paths[version] = artifact
        finally:
            shutil.rmtree(staging_root, ignore_errors=True)

        build_docs: dict[str, dict[str, Any]] = {}
        for version in ("vulnerable", "fixed"):
            res = build_results[version]
            build_docs[version] = {
                "tool_id": "sandbox.build",
                "job_id": resolved_job_id,
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
        _write_readonly_staged_file(normal_file, normal_input)
        _write_readonly_staged_file(candidate_file, candidate_input)
        _chmod_tree(staging_inputs, dir_mode=0o755, file_mode=0o444)

        replay_docs: list[dict[str, Any]] = []
        replay_obs: list[RunObservation] = []
        replay_raw: dict[tuple[str, str], tuple[bytes, bytes]] = {}
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
                        "job_id": resolved_job_id,
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
        if staging_inputs is not None:
            shutil.rmtree(staging_inputs, ignore_errors=True)
        for artifact in artifact_paths.values():
            artifact.unlink(missing_ok=True)

    policy = VerdictPolicy(
        signature=asan_sig,
        expected_exit=expected_exit,
        expected_stdout=expected_stdout,
    )
    decision = decide_verdict(policy, replay_obs, builds=build_docs)
    if decision.verdict != expected_verdict:
        raise ReleaseGateError(
            "B03 acceptance verdict does not match the admission's frozen "
            f"expected_verdict: {decision.verdict!r} != {expected_verdict!r}"
        )

    execution_metadata = {
        "job_id": resolved_job_id,
        "plan_digest": plan_digest,
        "generation": 1,
        "probe": probe_doc,
        "builds": list(build_docs.values()),
        "replays": replay_docs,
    }
    report = {
        "schema_version": 1,
        "job_id": resolved_job_id,
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
            f"- Job: `{resolved_job_id}`",
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
        job_id=resolved_job_id,
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

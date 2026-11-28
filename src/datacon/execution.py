"""Execution state machine for approved READY jobs (T05/T06).

The executor is deterministic. It re-verifies the approved review, plan and
material digests before every target container, materializes only pinned
inputs, records generation-scoped attempts, and archives a verifiable evidence
bundle before committing the terminal verdict.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
import hashlib
import hmac
import json
import logging
import math
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import sys
import time
import unicodedata
import uuid
from typing import Any, Callable, Mapping, Sequence
from uuid import UUID

import psycopg

from datacon import build_provenance, contracts, evidence, fileio, jsonutil, state
from datacon import fuzz as fuzz_rules
from datacon.cases import (
    MAX_MATERIAL_BYTES,
    CaseConfigurationError,
    CaseDefinition,
    load_registry,
)
from datacon.evidence import BundleError, verify_bundle, write_bundle
from datacon.tools.intel_evidence import (
    IntelDocuments,
    IntelEvidenceError,
    build_intel_documents,
    verify_intel_documents,
)
from datacon.tools.intel_provider import IntelSource
from datacon.tools.model_outlet import (
    build_model_audit,
    model_audit_summary,
    validate_model_audit_document,
    verify_model_audit_document,
)
from datacon.tools.sandbox import (
    MAX_ARTIFACT_BYTES,
    MAX_LOG_BYTES,
    MAX_PROVENANCE_FACE_BYTES,
    BuildOutput,
    BuildResult,
    DockerSandbox,
    FuzzResult,
    IsolationPolicy,
    ProbeReport,
    ReplayResult,
    ResourceLimits,
    SandboxError,
    SandboxPolicyError,
    SandboxUnavailable,
    _extract_compile_args,
)
from datacon.verdict import (
    PRIORITY,
    RunObservation,
    VerdictDecision,
    VerdictPolicy,
    decide_verdict,
    reason_allowed,
    reason_allowed_v2,
)

ARCHIVE_RESERVE_MAX = 60
ARCHIVE_RESERVE_RATIO = 0.1
BUILD_TIMEOUT = 300.0
PROBE_TIMEOUT = 120.0
logger = logging.getLogger(__name__)
MAX_ATTEMPTS_PER_STEP = 2
FAULT_ENV = "DATACON_FAULT_AFTER_TOOL"
TEST_MODE_ENV = "DATACON_TEST_MODE"
STAGING_ROOT_ENV = "DATACON_STAGING_ROOT"
# Journals and the HMAC key live inside/next to the run root, so their readers
# must reject oversized attacker-written files before loading them.
_JOURNAL_MAX_BYTES = 1024 * 1024
_JOURNAL_SECRET_MAX_BYTES = 1024


def test_hooks_enabled() -> bool:
    return os.getenv(TEST_MODE_ENV) == "1"


def validate_test_hooks() -> None:
    """Refuse fault-injection switches outside an explicit test run."""
    configured = [
        name
        for name in (FAULT_ENV, "DATACON_FAULT_DURING_ARCHIVE")
        if os.getenv(name)
    ]
    if configured and not test_hooks_enabled():
        raise RuntimeError(
            "test fault injection is disabled in production; set "
            f"{TEST_MODE_ENV}=1 and run only in tests (configured: "
            + ", ".join(configured)
            + ")"
        )


class ExecutionBlocked(RuntimeError):
    """The approved execution cannot start or continue; no target runs."""

    def __init__(self, reason_code: str, message: str, details: Mapping[str, Any] | None = None):
        super().__init__(message)
        self.reason_code = reason_code
        self.message = message
        self.details = dict(details or {})


class ExecutionFailed(RuntimeError):
    """An execution step failed for an infrastructure or build reason."""

    def __init__(self, reason_code: str, message: str):
        super().__init__(message)
        self.reason_code = reason_code
        self.message = message


@dataclass
class ExecutionContext:
    job_id: UUID
    generation: int
    job: dict[str, Any]
    plan: dict[str, Any]
    plan_digest: str
    review: dict[str, Any] | None
    case: CaseDefinition
    case_root: Path
    manifest_case: dict[str, Any]
    materials: dict[str, str]
    case_config: dict[str, Any]
    material_root: Path
    run_root: Path
    playbook: dict[str, Any]
    image: str
    isolation: IsolationPolicy
    limits: ResourceLimits
    compile_args: tuple[str, ...]
    deadline_at: datetime
    reserve_seconds: float
    material_payloads: dict[str, bytes] = field(default_factory=dict)
    cleanup_errors: list[str] = field(default_factory=list)
    envelope: dict[str, Any] | None = None
    budget_summary: dict[str, int] = field(default_factory=dict)
    admission: dict[str, Any] | None = None
    # T12 runtime budget (interface-contract-delta §7): the hard-timeout
    # ceiling granted by ``state.budget_gate`` for the container step that is
    # currently running, or None outside a budgeted step.
    step_ceiling_seconds: float | None = None
    # T12 C: a guided validation round reuses the campaign's build products
    # and takes its candidate from the campaign's frozen crash seed.
    reuse: Any = None

    @property
    def job_id_text(self) -> str:
        return str(self.job_id)


@dataclass
class ExecutionResult:
    state: str
    verdict: str | None = None
    verdict_reason: str | None = None
    evidence_digest: str | None = None
    evidence_path: str | None = None
    reason_code: str | None = None


@dataclass(frozen=True)
class _ProvenanceCheckOutcome:
    comparable: bool
    report_summary: dict[str, Any]
    error_detail: str = ""


def _is_v2_context(context: Any) -> bool:
    """Return True when the job or frozen plan uses contract version 2."""
    job = getattr(context, "job", None)
    if (
        isinstance(job, Mapping)
        and job.get("job_contract_version") == contracts.SCHEMA_VERSION_V2
    ):
        return True
    plan = getattr(context, "plan", None)
    if (
        isinstance(plan, Mapping)
        and plan.get("schema_version") == contracts.SCHEMA_VERSION_V2
    ):
        return True
    return False


def _request_mode(request: Any) -> str:
    """Return the request's exploration mode (v2); anything else is fixed."""
    exploration = request.get("exploration") if isinstance(request, Mapping) else None
    mode = exploration.get("mode") if isinstance(exploration, Mapping) else None
    return mode if mode in ("fixed", "guided") else "fixed"


def _is_guided_job(job: Any, plan: Any) -> bool:
    is_v2 = (
        isinstance(job, Mapping)
        and job.get("job_contract_version") == contracts.SCHEMA_VERSION_V2
    ) or (
        isinstance(plan, Mapping)
        and plan.get("schema_version") == contracts.SCHEMA_VERSION_V2
    )
    return bool(is_v2) and _request_mode(
        job.get("request") if isinstance(job, Mapping) else None
    ) == "guided"


def _is_campaign_context(context: Any) -> bool:
    job = getattr(context, "job", None)
    return (
        _is_v2_context(context)
        and isinstance(job, Mapping)
        and job.get("job_kind") == "campaign"
    )


def _harness_material_digest(context: Any) -> Any:
    """The digest of the harness *file* this execution builds.

    Fixed plans bind the harness file directly. A guided plan's
    ``harness_digest`` is the envelope's ``{harness, fuzz_shim}`` pair digest
    (delta §2 改9), so the file itself is pinned by the case registry and the
    pair is re-proven separately (``_load_context`` / campaign preflight).
    """
    if _is_guided_job(getattr(context, "job", None), getattr(context, "plan", None)):
        return context.materials.get(context.case.manifest["harness"])
    return context.plan["harness_digest"]


def _is_reuse_plan(plan: Any) -> bool:
    return isinstance(plan, Mapping) and plan.get("build_ref") is not None


def _build_spec_from_context(context: Any) -> Mapping[str, Any] | None:
    plan = getattr(context, "plan", None)
    if isinstance(plan, Mapping):
        spec = plan.get("build_spec")
        if isinstance(spec, Mapping):
            return spec
    return None


def _provenance_rules_version(context: Any) -> str:
    plan = getattr(context, "plan", None)
    if isinstance(plan, Mapping):
        value = plan.get("build_provenance_rules_version")
        if isinstance(value, str) and value.strip():
            return value
    return build_provenance.RULES_VERSION


def _build_provenance_repo_root(context: Any) -> str:
    custom = getattr(context, "provenance_repo_root", None)
    if isinstance(custom, str) and custom.strip():
        return custom
    return "/work"


def _input_material_paths(context: Any) -> set[str]:
    paths: set[str] = {"inputs/normal.txt", "inputs/candidate.txt"}
    manifest_case = getattr(context, "manifest_case", None)
    if isinstance(manifest_case, Mapping):
        inputs_map = manifest_case.get("inputs")
        if isinstance(inputs_map, Mapping):
            for key in ("normal", "candidate"):
                relative = inputs_map.get(key)
                if isinstance(relative, str) and relative.strip():
                    paths.add(relative.replace("\\", "/"))
    return paths


def _is_input_material_path(relative: str, input_paths: set[str]) -> bool:
    normalized = relative.replace("\\", "/")
    return normalized in input_paths or normalized.startswith("inputs/")


def _expected_build_recipe_digest_from_parts(
    *,
    is_v2: bool,
    plan: Mapping[str, Any],
    manifest: Mapping[str, Any],
    materials: Mapping[str, Any],
) -> Any:
    """Select the expected case build-recipe file digest for v1 or v2 plans."""
    if is_v2 and isinstance(plan.get("build_spec"), Mapping):
        return materials.get(manifest["build_recipe"])
    return plan["build_recipe_digest"]


def _expected_build_recipe_digest(context: ExecutionContext) -> Any:
    """Return the expected digest for ``context.case.manifest['build_recipe']``."""
    return _expected_build_recipe_digest_from_parts(
        is_v2=_is_v2_context(context),
        plan=context.plan,
        manifest=context.case.manifest,
        materials=context.materials,
    )


def _make_provenance_summary(
    *,
    face_name: str,
    declared: Sequence[str],
    vulnerable_effective: Sequence[str] = (),
    fixed_effective: Sequence[str] = (),
    comparable: bool = False,
) -> dict[str, Any]:
    """Build a strictly closed §8 3-key ``report.build_provenance`` payload."""
    return {
        "vulnerable": {
            "face": face_name,
            "declared": list(declared),
            "effective": list(vulnerable_effective),
        },
        "fixed": {
            "face": face_name,
            "declared": list(declared),
            "effective": list(fixed_effective),
        },
        "comparable": comparable,
    }


def _normalize_build_provenance_summary(
    summary: Mapping[str, Any],
) -> dict[str, Any]:
    """Return a strictly closed §8 3-key ``report.build_provenance`` payload."""
    normalized: dict[str, Any] = {}
    for version in ("vulnerable", "fixed"):
        entry = summary.get(version)
        if not isinstance(entry, Mapping):
            entry = {}
        face = entry.get("face")
        declared = entry.get("declared")
        effective = entry.get("effective")
        normalized[version] = {
            "face": str(face) if isinstance(face, str) else "",
            "declared": [str(item) for item in declared]
            if isinstance(declared, list)
            else [],
            "effective": [str(item) for item in effective]
            if isinstance(effective, list)
            else [],
        }
    normalized["comparable"] = bool(summary.get("comparable", False))
    return normalized


def _empty_build_provenance_summary(
    context: Any,
    *,
    comparable: bool = False,
) -> dict[str, Any]:
    build_spec = _build_spec_from_context(context)
    kind = build_spec.get("kind") if isinstance(build_spec, Mapping) else None
    face_name = (
        build_provenance.FACE_FILENAMES.get(str(kind), str(kind))
        if isinstance(kind, str) and kind
        else ""
    )
    plan = getattr(context, "plan", None)
    raw_declared: Any = None
    if isinstance(plan, Mapping):
        raw_declared = plan.get("compile_flags")
    if raw_declared is None and isinstance(build_spec, Mapping):
        raw_declared = build_spec.get("declared_compile_flags")
    declared_list: list[str] = []
    if isinstance(raw_declared, list) and all(
        isinstance(item, str) for item in raw_declared
    ):
        try:
            declared_list = build_provenance.normalize_compile_flags(
                raw_declared, repo_root=_build_provenance_repo_root(context)
            )
        except ValueError:
            declared_list = list(raw_declared)
    return _make_provenance_summary(
        face_name=face_name,
        declared=declared_list,
        comparable=comparable,
    )


def _verified_provenance_face(
    run_root: Path,
    build: Mapping[str, Any],
    *,
    expected_face_name: str | None = None,
) -> bytes | None:
    files = build.get("files")
    relative = files.get("provenance_face") if isinstance(files, Mapping) else None
    if not isinstance(relative, str) or not relative:
        return None
    face_name = expected_face_name or build.get("provenance_face_name")
    if not isinstance(face_name, str) or face_name not in build_provenance.FACE_FILENAMES.values():
        return None
    path = _run_root_path(run_root, relative, f"/build_provenance/{face_name}")
    if path is None:
        return None
    data = _read_run_file_bounded(path, max_bytes=MAX_PROVENANCE_FACE_BYTES)
    if data is None or not data:
        return None
    digests = build.get("file_digests")
    expected = digests.get("provenance_face") if isinstance(digests, Mapping) else None
    if not isinstance(expected, str) or _digest(data) != expected:
        return None
    return data


def _check_declared_compile_flags_consistency(
    context: ExecutionContext,
) -> tuple[bool, list[str], str]:
    """Verify ``plan.compile_flags`` matches ``build_spec.declared_compile_flags`` after normalization.

    Per interface-contract-delta.md §3 & §5, both sides must normalize to the
    exact same ordered flag sequence under ``build_provenance.normalize_compile_flags``.
    """
    build_spec = _build_spec_from_context(context)
    if build_spec is None:
        return (
            False,
            [],
            "v2 plan is missing build_spec for compile_flags consistency check",
        )
    repo_root = _build_provenance_repo_root(context)
    plan_flags = context.plan.get("compile_flags")
    spec_flags = build_spec.get("declared_compile_flags")
    if not isinstance(plan_flags, list) or not all(
        isinstance(item, str) for item in plan_flags
    ):
        return (
            False,
            [],
            "v2 plan.compile_flags must be a list of strings",
        )
    if not isinstance(spec_flags, list) or not all(
        isinstance(item, str) for item in spec_flags
    ):
        return (
            False,
            [],
            "v2 build_spec.declared_compile_flags must be a list of strings",
        )
    try:
        norm_plan = build_provenance.normalize_compile_flags(
            plan_flags, repo_root=repo_root
        )
    except ValueError as error:
        return (
            False,
            list(plan_flags),
            f"invalid plan.compile_flags: {error}",
        )
    try:
        norm_spec = build_provenance.normalize_compile_flags(
            spec_flags, repo_root=repo_root
        )
    except ValueError as error:
        return (
            False,
            norm_plan,
            f"invalid build_spec.declared_compile_flags: {error}",
        )
    if norm_plan != norm_spec:
        return (
            False,
            norm_plan,
            "plan.compile_flags does not match build_spec.declared_compile_flags "
            f"after normalization: plan={norm_plan!r} != build_spec={norm_spec!r}",
        )
    return True, norm_plan, ""


def _validate_v2_spec_and_flags(
    context: ExecutionContext,
    build_spec: Mapping[str, Any],
) -> tuple[bool, list[str], str]:
    """Validate v2 ``build_spec`` freeze rules and declared compile flag consistency."""
    freeze_decision = build_provenance.validate_build_spec_for_freeze(build_spec)
    if not freeze_decision.ok:
        return (
            False,
            [],
            freeze_decision.error_detail
            or "v2 build_spec failed provenance freeze validation",
        )
    return _check_declared_compile_flags_consistency(context)


def _patch_explained_units(context: ExecutionContext) -> tuple[str, ...]:
    """Return source paths changed by the reviewed patch/analysis.

    A compile unit that exists on only one side is legitimate when the patch
    adds or removes that source file. ``verify_build_provenance`` uses these
    paths to exempt only patch-explained differences; everything else still
    fails closed.
    """
    analysis = context.plan.get("analysis")
    if not isinstance(analysis, Mapping):
        return ()
    changed = analysis.get("changed_paths")
    if not isinstance(changed, list):
        return ()
    return tuple(item for item in changed if isinstance(item, str) and item.strip())


def _verify_v2_single_build_provenance(
    context: ExecutionContext,
    build_root: Path,
    builds: Mapping[str, Mapping[str, Any]],
) -> _ProvenanceCheckOutcome:
    """Validate provenance for a single completed v2 build during archive recovery.

    When only one version completed before archiving, a missing, corrupt,
    unparseable, or non-conforming provenance face must still fail closed as
    ``FAILED / BUILD_PROVENANCE_MISSING`` rather than masking as
    ``INCONCLUSIVE / EVIDENCE_INCOMPLETE``.
    """
    build_spec = _build_spec_from_context(context)
    if build_spec is None:
        return _ProvenanceCheckOutcome(
            comparable=False,
            report_summary=_empty_build_provenance_summary(context, comparable=False),
            error_detail="v2 plan is missing build_spec for build provenance verification",
        )

    kind = build_spec.get("kind")
    face_name = (
        build_provenance.FACE_FILENAMES.get(kind, str(kind))
        if isinstance(kind, str)
        else ""
    )
    spec_ok, normalized_declared, spec_error = _validate_v2_spec_and_flags(
        context, build_spec
    )
    if not spec_ok:
        summary = (
            _make_provenance_summary(
                face_name=face_name,
                declared=normalized_declared,
                comparable=False,
            )
            if normalized_declared
            else _empty_build_provenance_summary(context, comparable=False)
        )
        return _ProvenanceCheckOutcome(
            comparable=False,
            report_summary=summary,
            error_detail=spec_error,
        )

    present_versions = [
        version for version in ("vulnerable", "fixed") if version in builds
    ]
    if not present_versions:
        return _ProvenanceCheckOutcome(
            comparable=True,
            report_summary=_make_provenance_summary(
                face_name=face_name,
                declared=normalized_declared,
                comparable=False,
            ),
        )
    version = present_versions[0]
    build = builds[version]
    raw_face = (
        _verified_provenance_face(build_root, build, expected_face_name=face_name)
        if isinstance(build, Mapping) and face_name
        else None
    )
    if raw_face is None:
        return _ProvenanceCheckOutcome(
            comparable=False,
            report_summary=_make_provenance_summary(
                face_name=face_name,
                declared=normalized_declared,
                comparable=False,
            ),
            error_detail=(
                f"missing or empty provenance face ({kind}/{face_name}) for {version}"
            ),
        )

    repo_root = _build_provenance_repo_root(context)
    raw_declared = context.plan.get("compile_flags")
    if not isinstance(raw_declared, list):
        raw_declared = build_spec.get("declared_compile_flags", [])

    if kind in ("cmake", "make"):
        try:
            parsed = build_provenance.parse_provenance_face(
                kind=kind, raw_face=raw_face, repo_root=repo_root
            )
        except build_provenance.ProvenanceParseError as exc:
            return _ProvenanceCheckOutcome(
                comparable=False,
                report_summary=_make_provenance_summary(
                    face_name=face_name,
                    declared=normalized_declared,
                    comparable=False,
                ),
                error_detail=f"{version} ({kind}/{face_name}): {exc}",
            )
        prov_result = build_provenance.verify_build_provenance(
            kind=kind,
            declared_compile_flags=raw_declared,
            vulnerable_face=raw_face,
            fixed_face=raw_face,
            repo_root=repo_root,
            patch_explained_units=_patch_explained_units(context),
        )
        eff = list(parsed.effective_flags)
        summary = _make_provenance_summary(
            face_name=face_name,
            declared=normalized_declared,
            vulnerable_effective=eff if version == "vulnerable" else (),
            fixed_effective=eff if version == "fixed" else (),
            comparable=False,
        )
        if not prov_result.comparable:
            return _ProvenanceCheckOutcome(
                comparable=False,
                report_summary=summary,
                error_detail=prov_result.error_detail
                or f"{version} ({kind}/{face_name}) provenance verification failed",
            )
        return _ProvenanceCheckOutcome(comparable=True, report_summary=summary)

    if kind == "shell":
        res = build_provenance.verify_shell_face(
            build_spec=build_spec,
            actual_log=raw_face,
            repo_root=repo_root,
        )
        summary = _make_provenance_summary(
            face_name=build_provenance.FACE_FILENAMES["shell"],
            declared=normalized_declared,
            vulnerable_effective=(
                normalized_declared if (version == "vulnerable" and res.comparable) else ()
            ),
            fixed_effective=(
                normalized_declared if (version == "fixed" and res.comparable) else ()
            ),
            comparable=False,
        )
        if not res.comparable:
            return _ProvenanceCheckOutcome(
                comparable=False,
                report_summary=summary,
                error_detail=f"{version}: {res.error_detail}",
            )
        return _ProvenanceCheckOutcome(comparable=True, report_summary=summary)

    return _ProvenanceCheckOutcome(
        comparable=False,
        report_summary=_empty_build_provenance_summary(context, comparable=False),
        error_detail=f"unsupported build_spec.kind {kind!r} for build provenance verification",
    )


def _verify_v2_build_provenance(
    context: ExecutionContext,
    build_root: Path,
    builds: Mapping[str, Mapping[str, Any]],
) -> _ProvenanceCheckOutcome:
    """Verify two-version v2 build provenance before entering the replay phase."""
    build_spec = _build_spec_from_context(context)
    if build_spec is None:
        return _ProvenanceCheckOutcome(
            comparable=False,
            report_summary=_empty_build_provenance_summary(context, comparable=False),
            error_detail="v2 plan is missing build_spec for build provenance verification",
        )

    kind = build_spec.get("kind")
    face_name = (
        build_provenance.FACE_FILENAMES.get(kind, str(kind))
        if isinstance(kind, str)
        else ""
    )
    repo_root = _build_provenance_repo_root(context)
    spec_ok, normalized_declared, spec_error = _validate_v2_spec_and_flags(
        context, build_spec
    )
    if not spec_ok:
        summary = (
            _make_provenance_summary(
                face_name=face_name,
                declared=normalized_declared,
                comparable=False,
            )
            if normalized_declared
            else _empty_build_provenance_summary(context, comparable=False)
        )
        return _ProvenanceCheckOutcome(
            comparable=False,
            report_summary=summary,
            error_detail=spec_error,
        )

    raw_declared = context.plan.get("compile_flags")
    if not isinstance(raw_declared, list):
        raw_declared = build_spec.get("declared_compile_flags", [])

    version_faces: dict[str, bytes | None] = {}
    for version in ("vulnerable", "fixed"):
        build = builds.get(version)
        version_faces[version] = (
            _verified_provenance_face(
                build_root, build, expected_face_name=face_name
            )
            if isinstance(build, Mapping) and face_name
            else None
        )

    vuln_face = version_faces["vulnerable"]
    fixed_face = version_faces["fixed"]

    if kind in ("cmake", "make"):
        missing_versions = [
            version
            for version in ("vulnerable", "fixed")
            if version_faces[version] is None
        ]
        if missing_versions:
            effective_by_version: dict[str, list[str]] = {
                "vulnerable": [],
                "fixed": [],
            }
            for version in ("vulnerable", "fixed"):
                raw = version_faces[version]
                if raw is None:
                    continue
                try:
                    parsed = build_provenance.parse_provenance_face(
                        kind=kind, raw_face=raw, repo_root=repo_root
                    )
                    effective_by_version[version] = list(parsed.effective_flags)
                except build_provenance.ProvenanceParseError:
                    effective_by_version[version] = []
            summary = _make_provenance_summary(
                face_name=face_name,
                declared=normalized_declared,
                vulnerable_effective=effective_by_version["vulnerable"],
                fixed_effective=effective_by_version["fixed"],
                comparable=False,
            )
            return _ProvenanceCheckOutcome(
                comparable=False,
                report_summary=summary,
                error_detail=(
                    f"missing or empty provenance face ({kind}/{face_name}) for "
                    + ", ".join(missing_versions)
                ),
            )

        assert vuln_face is not None and fixed_face is not None
        prov_result = build_provenance.verify_build_provenance(
            kind=kind,
            declared_compile_flags=raw_declared,
            vulnerable_face=vuln_face,
            fixed_face=fixed_face,
            repo_root=repo_root,
            patch_explained_units=_patch_explained_units(context),
        )
        return _ProvenanceCheckOutcome(
            comparable=prov_result.comparable,
            report_summary=_normalize_build_provenance_summary(
                prov_result.report_summary
            ),
            error_detail=prov_result.error_detail,
        )

    if kind == "shell":
        issues: list[str] = []
        shell_results: dict[str, build_provenance.ShellFaceVerificationResult] = {}
        for version in ("vulnerable", "fixed"):
            raw = version_faces[version]
            res = build_provenance.verify_shell_face(
                build_spec=build_spec,
                actual_log=raw if raw is not None else b"",
                repo_root=repo_root,
            )
            shell_results[version] = res
            if not res.comparable:
                issues.append(f"{version}: {res.error_detail}")
        comparable = all(res.comparable for res in shell_results.values())
        summary = _make_provenance_summary(
            face_name=build_provenance.FACE_FILENAMES["shell"],
            declared=normalized_declared,
            vulnerable_effective=(
                normalized_declared if shell_results["vulnerable"].comparable else ()
            ),
            fixed_effective=(
                normalized_declared if shell_results["fixed"].comparable else ()
            ),
            comparable=comparable,
        )
        return _ProvenanceCheckOutcome(
            comparable=comparable,
            report_summary=summary,
            error_detail="" if comparable else "; ".join(issues),
        )

    return _ProvenanceCheckOutcome(
        comparable=False,
        report_summary=_empty_build_provenance_summary(context, comparable=False),
        error_detail=f"unsupported build_spec.kind {kind!r} for build provenance verification",
    )


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace(
        "+00:00", "Z"
    )


def _digest(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _read_run_file_bounded(path: Path, *, max_bytes: int) -> bytes | None:
    """Read a run-root file only after proving it is a small regular file.

    Everything below ``DATACON_RUN_ROOT`` is attacker-writable. The shared
    ``fileio`` helper opens the leaf with ``O_NOFOLLOW`` and ``O_NONBLOCK`` and
    then checks it with ``fstat`` so a symlink swap or FIFO can neither redirect
    the read nor block the worker. Rejecting an oversized or non-regular file
    *before* reading prevents a huge journal, log or artifact from exhausting
    memory ahead of digest/HMAC checks.
    """
    try:
        return fileio.read_regular_file_bounded(path, max_bytes=max_bytes)
    except fileio.UnsafeFileError:
        return None


def _stat_identity(path: Path, label: str) -> tuple[int, int] | None:
    """Return ``(st_dev, st_ino)`` or ``None`` when the path does not exist."""
    try:
        info = os.stat(path)
    except (FileNotFoundError, NotADirectoryError):
        return None
    except OSError as error:
        # An unreadable ancestor means containment cannot be proven.
        raise ExecutionFailed(
            "EVIDENCE_WRITE_FAILED", f"{label} cannot be inspected: {error}"
        ) from error
    return (info.st_dev, info.st_ino)


def _normalized_parts(path: Path) -> tuple[str, ...]:
    return tuple(
        unicodedata.normalize("NFC", part).casefold() for part in path.parts
    )


def _lexically_within_run_root(path: Path, run_root: Path) -> bool:
    """Conservative normalized comparison for paths whose identity is unknown.

    This is deliberately broader than a byte comparison: it also catches
    case-only and NFC/NFD-only variants that a case-insensitive or
    normalization-insensitive filesystem would resolve to the run root.
    """
    path_parts = _normalized_parts(path)
    root_parts = _normalized_parts(run_root)
    return (
        len(path_parts) >= len(root_parts)
        and path_parts[: len(root_parts)] == root_parts
    )


def _inside_run_root(path: Path, run_root: Path, label: str) -> bool:
    """Decide containment using filesystem identity, not resolved strings.

    ``path`` and ``run_root`` are already resolved lexically. For every
    existing ancestor of ``path`` we compare device/inode numbers with the run
    root, which is what makes a case-only or Unicode-normalization-only variant
    of the same directory indistinguishable from the original. A conservative
    normalized component comparison is applied as well, so a not-yet-created
    path nested under a case variant is still rejected on case-sensitive
    filesystems.
    """
    if _lexically_within_run_root(path, run_root):
        return True
    root_identity = _stat_identity(run_root, label)
    current = path
    while True:
        identity = _stat_identity(current, label)
        if identity is not None:
            break
        parent = current.parent
        if parent == current:
            return False
        current = parent
    if root_identity is None:
        return False
    probe = current
    while True:
        if _stat_identity(probe, label) == root_identity:
            return True
        parent = probe.parent
        if parent == probe:
            return False
        probe = parent


@dataclass(frozen=True)
class _MountPoint:
    """The subset of a ``/proc/self/mountinfo`` line used for containment.

    ``root`` is ``None`` for pseudo filesystems whose mount root is not a path
    (for example ``nsfs`` reports ``net:[4026532313]``). Such a mount cannot
    prove containment and is rejected when it is relevant to the target.
    """

    mount_id: int
    parent_id: int
    major_minor: str
    root: Path | None
    mount_point: Path


_MOUNTINFO_ESCAPE = re.compile(r"\\([0-7]{3})")


def _unescape_mountinfo(value: str) -> str:
    def replace(match: re.Match[str]) -> str:
        return chr(int(match.group(1), 8))

    return _MOUNTINFO_ESCAPE.sub(replace, value)


def _parse_mountinfo(text: str) -> tuple[_MountPoint, ...]:
    """Parse mount IDs, roots and mount points from ``/proc/self/mountinfo``.

    The parser is deliberately strict: a line that cannot be understood makes
    the caller fail closed instead of silently dropping a mount that might
    redirect the target under the run root.
    """
    entries: list[_MountPoint] = []
    for line in text.splitlines():
        if not line.strip():
            continue
        fields = line.split()
        try:
            separator = fields.index("-")
        except ValueError as error:
            raise ValueError("mountinfo line has no separator") from error
        if separator < 6 or len(fields) < 7:
            raise ValueError("mountinfo line is too short")
        try:
            mount_id = int(fields[0])
            parent_id = int(fields[1])
        except ValueError as error:
            raise ValueError("mountinfo mount IDs are not integers") from error
        major_minor = fields[2]
        if ":" not in major_minor:
            raise ValueError("mountinfo device is malformed")
        root_value = _unescape_mountinfo(fields[3])
        root = Path(root_value) if root_value.startswith("/") else None
        mount_point = Path(_unescape_mountinfo(fields[4]))
        if not mount_point.is_absolute():
            raise ValueError("mountinfo mount point is not absolute")
        entries.append(
            _MountPoint(
                mount_id=mount_id,
                parent_id=parent_id,
                major_minor=major_minor,
                root=root,
                mount_point=mount_point,
            )
        )
    return tuple(entries)


def _mount_point_for(
    entries: Sequence[_MountPoint], path: Path
) -> _MountPoint | None:
    """Return the topmost mount that contains ``path``, or ``None``.

    Overmounts share a mount point. The visible mount is the leaf of the
    ``parent_id`` chain rooted at the mount that was covered first, not the
    entry with the largest ``mount_id``: mount IDs are reused and are not
    ordered. Any ambiguity (duplicate IDs, multiple roots or leaves, a cycle,
    or a gap in the chain) makes containment unprovable, so the caller must
    fail closed instead of guessing.
    """
    if not entries:
        return None
    mount_ids = [entry.mount_id for entry in entries]
    if len(set(mount_ids)) != len(mount_ids):
        return None
    candidates = [
        entry
        for entry in entries
        if path == entry.mount_point or entry.mount_point in path.parents
    ]
    if not candidates:
        return None
    depth = max(len(entry.mount_point.parts) for entry in candidates)
    deepest = {
        entry.mount_point
        for entry in candidates
        if len(entry.mount_point.parts) == depth
    }
    if len(deepest) != 1:
        return None
    mount_point = next(iter(deepest))
    group = [entry for entry in candidates if entry.mount_point == mount_point]
    if len(group) == 1:
        return group[0]
    by_id = {entry.mount_id: entry for entry in group}
    children: dict[int, list[int]] = {}
    roots: list[int] = []
    for entry in group:
        if entry.parent_id in by_id:
            children.setdefault(entry.parent_id, []).append(entry.mount_id)
        else:
            roots.append(entry.mount_id)
    if len(roots) != 1:
        return None
    visited: list[int] = []
    seen: set[int] = set()
    current: int | None = roots[0]
    while current is not None:
        if current in seen:
            return None
        seen.add(current)
        visited.append(current)
        next_ids = children.get(current, [])
        if len(next_ids) > 1:
            return None
        current = next_ids[0] if next_ids else None
    if set(visited) != set(by_id):
        return None
    return by_id[visited[-1]]


def _mountinfo_rejects(path: Path, run_root: Path, text: str) -> bool:
    """Return whether mount relationships cannot prove ``path`` is outside.

    A bind mount whose source subtree lives below the run root can expose
    run-root content at a completely different path. For the mount that
    contains ``path`` and the mount that contains ``run_root`` we reconstruct
    each physical path from the mount root and compare them. A different
    device number is **not** proof of isolation: a nested mount below the run
    root can share that device and be rebound elsewhere, so that case is
    rejected whenever the run root contains any mount of the target's device.
    Anything unparseable or unprovable is rejected.
    """
    try:
        entries = _parse_mountinfo(text)
    except ValueError:
        return True
    if not entries:
        return True
    target_mount = _mount_point_for(entries, path)
    root_mount = _mount_point_for(entries, run_root)
    if target_mount is None or root_mount is None:
        return True
    if target_mount.root is None or root_mount.root is None:
        return True
    try:
        target_physical = target_mount.root / path.relative_to(
            target_mount.mount_point
        )
        root_physical = root_mount.root / run_root.relative_to(
            root_mount.mount_point
        )
    except ValueError:
        return True
    if _lexically_within_run_root(target_physical, root_physical):
        return True
    # The bind source itself may live below the run root even when the
    # reconstructed physical path is on another device.
    if _lexically_within_run_root(target_mount.root, run_root):
        return True
    # Check every mount that is an ancestor of the target, not only the
    # deepest one. An overmount at the same path can hide a lower bind whose
    # source is the run root, so every entry on every ancestor mount point is
    # inspected. A non-path root (for example nsfs) cannot prove anything.
    for entry in entries:
        if not (path == entry.mount_point or entry.mount_point in path.parents):
            continue
        if entry.root is None:
            return True
        if _lexically_within_run_root(entry.root, run_root):
            return True
        if entry.major_minor == root_mount.major_minor and (
            _lexically_within_run_root(entry.root, root_physical)
        ):
            return True
    # A mount strictly below the run root that shares the target's device can
    # expose run-root content at the target path, whether or not that device
    # matches the run root's own mount.
    for entry in entries:
        if entry.major_minor != target_mount.major_minor:
            continue
        if run_root in entry.mount_point.parents:
            return True
    return False


def _mountinfo_document() -> str | None:
    """Read Linux mountinfo, or return ``None`` where the kernel lacks it.

    Linux must always expose the document: a missing ``/proc/self/mountinfo``
    means containment cannot be proven, so the caller must fail closed. Only
    non-Linux platforms legitimately skip the check.
    """
    try:
        return Path("/proc/self/mountinfo").read_text(
            encoding="utf-8", errors="replace"
        )
    except FileNotFoundError as error:
        if sys.platform.startswith("linux"):
            raise ExecutionFailed(
                "EVIDENCE_WRITE_FAILED",
                "mount relationships cannot be inspected: "
                "/proc/self/mountinfo is missing",
            ) from error
        return None
    except OSError as error:
        raise ExecutionFailed(
            "EVIDENCE_WRITE_FAILED",
            f"mount relationships cannot be inspected: {error}",
        ) from error


def _safe_name(value: str) -> str:
    return "".join(
        character if character.isalnum() or character in "._-" else "_"
        for character in value
    )[:120]


def _reserve_seconds(execute_seconds: int) -> float:
    return float(min(ARCHIVE_RESERVE_MAX, max(1, int(execute_seconds * ARCHIVE_RESERVE_RATIO))))


def _remaining(context: ExecutionContext) -> float:
    now = datetime.now(timezone.utc)
    deadline = context.deadline_at
    if deadline.tzinfo is None:
        deadline = deadline.replace(tzinfo=timezone.utc)
    return (deadline - now).total_seconds()


def _assert_budget(context: ExecutionContext, *, purpose: str) -> float:
    remaining = _remaining(context)
    if remaining <= context.reserve_seconds + 0.5:
        raise ExecutionBlocked(
            "DEADLINE_EXCEEDED",
            f"execution budget exhausted before {purpose}; "
            f"only {remaining:.1f}s remains and the archive reserve is "
            f"{context.reserve_seconds:.0f}s",
        )
    return remaining


def _validate_policy_admission(
    admission: Mapping[str, Any],
    *,
    job: Mapping[str, Any],
    plan: Mapping[str, Any],
) -> str | None:
    """Return a mismatch reason if a policy admission does not bind ``(job, plan)``."""
    if admission.get("approval_kind") != "policy":
        return "the admission is not a policy admission"
    if admission.get("envelope_digest") != plan.get("envelope_digest"):
        return "the policy admission envelope differs from the frozen plan"
    expected_parent_approval = plan.get("parent_approval_digest")
    if (
        not isinstance(expected_parent_approval, str)
        or not expected_parent_approval
        or admission.get("parent_approval_digest") != expected_parent_approval
    ):
        return "the policy admission parent approval differs from the frozen plan"
    if (
        admission.get("parent_job_id") != str(job.get("parent_job_id"))
        or admission.get("round_no") != plan.get("round_no")
    ):
        return "the policy admission is bound to a different family round"
    plan_inputs = plan.get("inputs")
    if (
        isinstance(plan_inputs, Mapping)
        and admission.get("seed_digest") != plan_inputs.get("candidate")
    ):
        return "the policy admission seed differs from the frozen plan"
    return None


def _load_context(
    dsn: str,
    job_id: UUID,
    generation: int,
    *,
    case_root: str | None,
    run_root: Path | str | None,
) -> ExecutionContext:
    job = state.load_job(dsn, job_id)
    if job is None:
        raise ExecutionBlocked("JOB_NOT_FOUND", "job does not exist")
    if job["generation"] != generation:
        raise state.StaleGeneration("execution generation is no longer current")
    if job["state"] not in ("RUNNING", "ARCHIVING"):
        raise ExecutionBlocked(
            "INVALID_STATE", f"job is {job['state']}, not RUNNING"
        )
    plan_row = state.get_plan(dsn, job_id)
    review = state.get_review(dsn, job_id)
    if plan_row is None:
        raise ExecutionBlocked("PLAN_MISMATCH", "no frozen plan is available")
    plan = plan_row["plan"]
    is_v2 = (
        job.get("job_contract_version") == contracts.SCHEMA_VERSION_V2
        or plan.get("schema_version") == contracts.SCHEMA_VERSION_V2
    )
    if review is None and is_v2 and job.get("family_id") is not None:
        family_id = job["family_id"]
        review = state.get_review(
            dsn,
            UUID(family_id) if isinstance(family_id, str) else family_id,
        )
    try:
        computed_digest = contracts.plan_digest(plan)
    except ValueError as error:
        raise ExecutionBlocked("PLAN_MISMATCH", f"frozen plan is invalid: {error}") from error
    if computed_digest != plan_row["plan_digest"]:
        raise ExecutionBlocked(
            "PLAN_MISMATCH", "frozen plan digest does not match its content"
        )
    admission: dict[str, Any] | None = None
    review_binds_plan = (
        review is not None
        and review.get("decision") == "approve"
        and review.get("plan_digest") == plan_row["plan_digest"]
    )
    if not review_binds_plan and is_v2 and job.get("job_kind") == "round":
        # A family-scoped human review approves the first plan, not every
        # later round. If it does not bind this frozen plan, the round must
        # carry its own policy admission; the family review must never be
        # silently reused for a later round.
        try:
            admission = state.get_admission(dsn, job_id)
        except state.StateError as error:
            raise ExecutionBlocked(
                "MATERIAL_MISSING", f"the policy admission is unavailable: {error}"
            ) from error
        if admission is not None:
            mismatch = _validate_policy_admission(admission, job=job, plan=plan)
            if mismatch is not None:
                raise ExecutionBlocked("PLAN_MISMATCH", mismatch)
            review = None
    if admission is None:
        if review is None or review["decision"] != "approve":
            raise ExecutionBlocked(
                "PLAN_MISMATCH", "an approved review bound to the plan is required"
            )
        if review["plan_digest"] != plan_row["plan_digest"]:
            raise ExecutionBlocked(
                "PLAN_MISMATCH", "the approval is bound to a different plan"
            )

    request = job["request"]
    if request.get("limits") != plan["limits"]:
        raise ExecutionBlocked(
            "PLAN_MISMATCH", "request budget differs from the approved plan"
        )
    if job["request"].get("target", {}).get("case_id") != plan["case_id"]:
        raise ExecutionBlocked("PLAN_MISMATCH", "request case does not match the plan")
    if job["request"].get("cve_id") != plan["cve_id"]:
        raise ExecutionBlocked("PLAN_MISMATCH", "request CVE does not match the plan")

    try:
        registry = load_registry(case_root)
        case = registry.case(plan["case_id"])
    except CaseConfigurationError as error:
        raise ExecutionBlocked(error.reason_code, error.message) from error
    manifest = case.manifest
    manifest_case = case.manifest_case
    if registry.document.get("policy_version", "1") != plan["policy_version"]:
        raise ExecutionBlocked(
            "POLICY_DENIED",
            "the current case policy version differs from the approved plan",
        )
    try:
        current_isolation = IsolationPolicy.from_plan(
            registry.document.get("isolation") or {}
        )
        plan_isolation = IsolationPolicy.from_plan(plan["isolation"])
        if current_isolation != plan_isolation:
            raise ExecutionBlocked(
                "POLICY_DENIED",
                "the current isolation policy differs from the approved plan",
            )
        current_isolation.validate()
    except SandboxPolicyError as error:
        raise ExecutionBlocked("POLICY_DENIED", error.message) from error

    materials = manifest.get("materials")
    if not isinstance(materials, dict):
        raise ExecutionBlocked("MATERIAL_MISSING", "case manifest has no materials")
    source_vulnerable = manifest["versions"]["vulnerable"]
    source_fixed = manifest["versions"]["fixed"]
    has_v2_build_spec = is_v2 and isinstance(plan.get("build_spec"), Mapping)
    if has_v2_build_spec:
        try:
            spec_digest = jsonutil.digest_json(plan["build_spec"])
        except (ValueError, TypeError, UnicodeError, RecursionError) as error:
            raise ExecutionBlocked(
                "PLAN_MISMATCH", f"plan build_spec is not canonical: {error}"
            ) from error
        if spec_digest != plan["build_recipe_digest"]:
            raise ExecutionBlocked(
                "PLAN_MISMATCH",
                "plan build_recipe_digest does not match canonical build_spec",
            )
        if plan["build_spec"].get("kind") == "shell":
            recipe_relative = manifest["build_recipe"]
            try:
                recipe_bytes, _actual = case.read_material(
                    recipe_relative, materials.get(recipe_relative)
                )
            except CaseConfigurationError as error:
                raise ExecutionBlocked(error.reason_code, error.message) from error
            recipe_digest = jsonutil.digest_bytes(recipe_bytes)
            declared_recipe_digest = plan["build_spec"].get(
                "shell_recipe_digest"
            )
            if declared_recipe_digest != recipe_digest:
                raise ExecutionBlocked(
                    "BUILD_PROVENANCE_MISSING",
                    "build_spec.shell_recipe_digest does not match the executed "
                    f"build recipe {recipe_relative!r}: expected {recipe_digest}, "
                    f"got {declared_recipe_digest!r}",
                )
            build_argv = plan["build_spec"].get("build")
            script_operand: str | None = None
            if isinstance(build_argv, list) and build_argv:
                first = build_argv[0]
                if (
                    isinstance(first, str)
                    and first in ("sh", "/bin/sh", "/usr/bin/sh")
                    and len(build_argv) >= 2
                    and isinstance(build_argv[1], str)
                ):
                    script_operand = build_argv[1]
                elif isinstance(first, str):
                    script_operand = first
            try:
                script_relative = jsonutil.safe_relative_path(
                    script_operand, "build_spec.build script"
                )
            except ValueError as error:
                raise ExecutionBlocked(
                    "PLAN_MISMATCH",
                    f"build_spec.build script is not a safe relative path: {error}",
                ) from error
            if PurePosixPath(script_relative) != PurePosixPath(recipe_relative):
                raise ExecutionBlocked(
                    "PLAN_MISMATCH",
                    "build_spec.build script does not name the manifest "
                    f"build_recipe {recipe_relative!r}",
                )
    guided = _is_guided_job(job, plan)
    harness_file_digest: Any = plan["harness_digest"]
    if guided:
        # Guided plans bind the reviewed {harness, fuzz_shim} pair (改9). The
        # harness file is pinned by the registry; a plan pair that does not
        # bind exactly that file and the reviewed shim never executes.
        harness_file_digest = materials.get(manifest["harness"])
        if not isinstance(harness_file_digest, str):
            raise ExecutionBlocked(
                fuzz_rules.HARNESS_REJECTED,
                "the case harness is not a registered, reviewed material",
                {"sub_reason": "HARNESS_NOT_REVIEWED"},
            )
        expected_pair = fuzz_rules.guided_harness_digest(
            harness_file_digest, fuzz_rules.FUZZ_SHIM_REVIEWED_DIGEST
        )
        if plan["harness_digest"] != expected_pair:
            raise ExecutionBlocked(
                fuzz_rules.HARNESS_REJECTED,
                "the guided plan harness_digest does not bind the reviewed "
                "{harness, fuzz_shim} pair",
                {"sub_reason": "HARNESS_PAIR_MISMATCH"},
            )
    expected_materials: dict[str, tuple[str, Any]] = {
        "harness": (manifest["harness"], harness_file_digest),
        "build_recipe": (
            manifest["build_recipe"],
            _expected_build_recipe_digest_from_parts(
                is_v2=is_v2, plan=plan, manifest=manifest, materials=materials
            ),
        ),
        "dependencies": (manifest["dependencies"], plan["dependencies_digest"]),
        "patch": (case.repository["patch"], plan["repository"]["patch_digest"]),
        "source_vulnerable": (
            source_vulnerable,
            materials.get(source_vulnerable),
        ),
        "source_fixed": (source_fixed, materials.get(source_fixed)),
    }
    plan_inputs = plan.get("inputs")
    if isinstance(plan_inputs, Mapping):
        expected_materials["input_normal"] = (
            manifest_case["inputs"]["normal"],
            plan_inputs.get("normal"),
        )
        if not _is_reuse_plan(plan):
            # A reuse validation's candidate is a campaign crash seed, bound
            # by _load_campaign_reuse to the archived campaign bundle.
            expected_materials["input_candidate"] = (
                manifest_case["inputs"]["candidate"],
                plan_inputs.get("candidate"),
            )
    elif not is_v2:
        raise ExecutionBlocked("MATERIAL_MISSING", "plan has no inputs mapping")
    for label, (relative, expected_digest) in expected_materials.items():
        if not isinstance(expected_digest, str):
            raise ExecutionBlocked(
                "MATERIAL_MISSING", f"plan has no digest for {label}"
            )
        try:
            _, actual = case.read_material(relative, expected_digest)
        except CaseConfigurationError as error:
            if guided and label == "harness":
                # A guided harness that no longer matches the reviewed bytes
                # (for example rewritten by a model) is HARNESS_REJECTED.
                raise ExecutionBlocked(
                    fuzz_rules.HARNESS_REJECTED,
                    f"the frozen harness is not the reviewed one: {error.message}",
                    {"sub_reason": "HARNESS_NOT_REVIEWED"},
                ) from error
            raise ExecutionBlocked(error.reason_code, error.message) from error
        if actual != expected_digest:
            raise ExecutionBlocked(
                "MATERIAL_MISSING", f"actual material digest for {label} drifted"
            )
    for relative, digest in materials.items():
        if not isinstance(digest, str):
            raise ExecutionBlocked(
                "MATERIAL_MISSING", f"case material {relative} has no digest"
            )
    for label, relative, expected_digest in (
        (
            "advisory snapshot",
            case.advisory["path"],
            plan["intel"]["content_digest"],
        ),
        (
            "repository bundle",
            case.repository["bundle"],
            plan["repository"]["bundle_digest"],
        ),
    ):
        try:
            _, actual = case.read_material(relative, expected_digest)
        except CaseConfigurationError as error:
            raise ExecutionBlocked(error.reason_code, error.message) from error
        if actual != expected_digest:
            raise ExecutionBlocked(
                "MATERIAL_MISSING", f"{label} digest drifted"
            )

    if plan["revisions"]["vulnerable"] != case.repository["commits"]["vulnerable"]:
        raise ExecutionBlocked(
            "PLAN_MISMATCH", "the vulnerable revision differs from the registered commit"
        )
    if plan["revisions"]["fixed"] != case.repository["commits"]["fixed"]:
        raise ExecutionBlocked(
            "PLAN_MISMATCH", "the fixed revision differs from the registered commit"
        )
    if plan["repository"]["bundle_digest"] != case.repository["bundle_digest"]:
        raise ExecutionBlocked(
            "PLAN_MISMATCH", "the repository bundle digest differs from the plan"
        )
    if plan["dependencies_digest"] != materials.get(manifest["dependencies"]):
        raise ExecutionBlocked("MATERIAL_MISSING", "dependency lock digest drifted")
    image = manifest.get("image")
    if not isinstance(image, str) or not image.endswith("@" + plan["image_digest"]):
        raise ExecutionBlocked("PLAN_MISMATCH", "the pinned image differs from the plan")
    if plan["platform"] != manifest.get("platform"):
        raise ExecutionBlocked("PLAN_MISMATCH", "the platform differs from the plan")

    # Recompute the analysis binding without rerunning Git: the case config
    # covers the registry entry, manifest case, pinned materials, image,
    # platform, toolchain, ASan options and signature.
    used_materials = {
        key: materials[key]
        for key in {
            manifest["harness"],
            manifest["build_recipe"],
            manifest["dependencies"],
            case.repository["patch"],
            source_vulnerable,
            source_fixed,
            manifest_case["inputs"]["candidate"],
            manifest_case["inputs"]["normal"],
        }
    }
    case_config = {
        "case_id": case.case_id,
        "cve_id": case.cve_id,
        "benchmark_id": case.benchmark_id,
        "registry_entry": case.entry,
        "manifest_case": manifest_case,
        "materials": used_materials,
        "image": image,
        "platform": manifest["platform"],
        "toolchain": manifest["toolchain"],
        "asan_options": manifest["asan_options"],
        "asan_signature": manifest["asan_signature"],
    }
    try:
        case_config_digest = jsonutil.digest_json(case_config)
    except (ValueError, UnicodeError, RecursionError) as error:
        raise ExecutionBlocked(
            "MATERIAL_MISSING", f"case configuration is not canonical: {error}"
        ) from error
    if case_config_digest != plan["case_config_digest"]:
        raise ExecutionBlocked(
            "PLAN_MISMATCH",
            "the registry or one of the actual case materials drifted from the plan",
        )

    if has_v2_build_spec:
        raw_flags = plan.get("compile_flags")
        if not isinstance(raw_flags, list) or not all(
            isinstance(item, str) for item in raw_flags
        ):
            raise ExecutionBlocked(
                "PLAN_MISMATCH", "v2 plan compile_flags must be a list of strings"
            )
        compile_args = tuple(raw_flags)
    else:
        try:
            compile_args = _extract_compile_args(
                case.read_material(
                    manifest["build_recipe"], plan["build_recipe_digest"]
                )[0]
            )
        except CaseConfigurationError as error:
            raise ExecutionBlocked(error.reason_code, error.message) from error

    deadline = job["execute_deadline_at"]
    if deadline is None:
        raise ExecutionBlocked("DEADLINE_EXCEEDED", "execution deadline is not fixed")
    if deadline.tzinfo is None:
        deadline = deadline.replace(tzinfo=timezone.utc)
    limits = plan["limits"]
    budget_summary: dict[str, int] = {}
    envelope_doc: dict[str, Any] | None = None
    if is_v2:
        family_id = job.get("family_id")
        if family_id is not None:
            try:
                budget_summary = state.family_budget_summary(dsn, family_id)
            except state.StateError as error:
                raise ExecutionBlocked(
                    "MATERIAL_MISSING",
                    f"the family budget ledger is unavailable: {error}",
                ) from error
        raw_envelope = job.get("envelope")
        if not isinstance(raw_envelope, Mapping):
            family_id = job.get("family_id")
            if family_id is not None:
                try:
                    raw_envelope = state.get_family_envelope(
                        dsn, family_id, plan["envelope_digest"]
                    )
                except state.StateError as error:
                    raise ExecutionBlocked(
                        "MATERIAL_MISSING",
                        f"the approved family envelope is unavailable: {error}",
                    ) from error
        if isinstance(raw_envelope, Mapping):
            try:
                normalized_envelope = contracts.normalize_envelope(raw_envelope)
            except ValueError as error:
                raise ExecutionBlocked(
                    "PLAN_MISMATCH", f"job envelope is invalid: {error}"
                ) from error
            if (
                contracts.envelope_digest(normalized_envelope)
                != plan.get("envelope_digest")
            ):
                raise ExecutionBlocked(
                    "PLAN_MISMATCH",
                    "job envelope body does not match the frozen plan envelope_digest",
                )
            envelope_doc = normalized_envelope
        elif job.get("job_kind") in ("round", "campaign"):
            raise ExecutionBlocked(
                "MATERIAL_MISSING",
                "the approved envelope body is not available to the executor",
            )
    context = ExecutionContext(
        job_id=job_id,
        generation=generation,
        job=job,
        plan=plan,
        plan_digest=plan_row["plan_digest"],
        review=review,
        admission=admission,
        case=case,
        case_root=registry.root,
        manifest_case=manifest_case,
        materials=materials,
        case_config=case_config,
        material_root=Path(case.material_root),
        run_root=Path(run_root)
        if run_root is not None
        else Path(os.getenv("DATACON_RUN_ROOT", ".datacon/runs")),
        playbook={
            "expected_exit": plan["expected_exit"],
            "expected_stdout": manifest_case.get("expected_stdout"),
            "asan_signature": plan["asan_signature"],
            "asan_options": plan["asan_options"],
            "inputs": {
                "normal": manifest_case["inputs"]["normal"],
                "candidate": manifest_case["inputs"]["candidate"],
            },
        },
        image=image,
        isolation=current_isolation,
        limits=ResourceLimits(
            cpu=limits["cpu"],
            memory_mib=limits["memory_mib"],
            pids=limits["pids"],
            scratch_mib=limits["scratch_mib"],
        ),
        compile_args=compile_args,
        deadline_at=deadline,
        reserve_seconds=_reserve_seconds(limits["execute_seconds"]),
        envelope=envelope_doc,
        budget_summary=budget_summary,
    )
    return context


def _assert_context_unchanged(
    dsn: str,
    context: ExecutionContext,
    *,
    materials_dir: Path | None = None,
    material_digests: Mapping[str, str] | None = None,
) -> None:
    """Re-check approval, plan, materials, policy and budget before a container."""
    _assert_budget(context, purpose="starting a target container")
    job = state.load_job(dsn, context.job_id)
    if job is None:
        raise ExecutionBlocked("JOB_NOT_FOUND", "job disappeared")
    if job["generation"] != context.generation:
        raise state.StaleGeneration("execution generation is no longer current")
    if job["state"] not in ("RUNNING", "ARCHIVING"):
        raise ExecutionBlocked(
            "INVALID_STATE", f"job is {job['state']}, not executable"
        )
    plan_row = state.get_plan(dsn, context.job_id)
    review = state.get_review(dsn, context.job_id)
    if (
        review is None
        and _is_v2_context(context)
        and context.job.get("family_id") is not None
    ):
        family_id = context.job["family_id"]
        review = state.get_review(
            dsn,
            UUID(family_id) if isinstance(family_id, str) else family_id,
        )
    if plan_row is None or plan_row["plan_digest"] != context.plan_digest:
        raise ExecutionBlocked("PLAN_MISMATCH", "the frozen plan changed")
    try:
        if contracts.plan_digest(plan_row["plan"]) != context.plan_digest:
            raise ExecutionBlocked(
                "PLAN_MISMATCH", "the frozen plan content no longer matches its digest"
            )
    except ValueError as error:
        raise ExecutionBlocked("PLAN_MISMATCH", f"the frozen plan is invalid: {error}") from error
    if getattr(context, "admission", None) is not None:
        try:
            admission = state.get_admission(dsn, context.job_id)
        except state.StateError as error:
            raise ExecutionBlocked(
                "MATERIAL_MISSING", f"the policy admission changed: {error}"
            ) from error
        if (
            admission is None
            or _validate_policy_admission(
                admission, job=job, plan=context.plan
            )
            is not None
        ):
            raise ExecutionBlocked("PLAN_MISMATCH", "the policy admission changed")
    elif (
        review is None
        or review["decision"] != "approve"
        or review["plan_digest"] != context.plan_digest
    ):
        raise ExecutionBlocked("PLAN_MISMATCH", "the approved review changed")
    # ``material_root`` is the directory containing case materials, not the
    # registry root. Reload from the registry root captured when the context
    # was built so a registry with material_root != "." is supported.
    try:
        registry = load_registry(str(context.case_root))
        case = registry.case(context.plan["case_id"])
    except CaseConfigurationError as error:
        raise ExecutionBlocked(error.reason_code, error.message) from error
    if case.case_id != context.case.case_id:
        raise ExecutionBlocked("PLAN_MISMATCH", "the registered case changed")
    if case.material_root != context.case.material_root:
        raise ExecutionBlocked(
            "MATERIAL_MISSING", "the case material root moved"
        )
    if registry.document.get("policy_version", "1") != context.plan["policy_version"]:
        raise ExecutionBlocked("POLICY_DENIED", "policy version drifted")
    try:
        current_isolation = IsolationPolicy.from_plan(
            registry.document.get("isolation") or {}
        )
        current_isolation.validate()
    except SandboxPolicyError as error:
        raise ExecutionBlocked("POLICY_DENIED", error.message) from error
    if current_isolation != context.isolation:
        raise ExecutionBlocked("POLICY_DENIED", "isolation policy drifted")
    plan_inputs = context.plan.get("inputs")
    expected_digests: dict[str, Any] = {
        "harness": _harness_material_digest(context),
        "build_recipe": _expected_build_recipe_digest(context),
        "dependencies": context.plan["dependencies_digest"],
        "source_vulnerable": context.materials.get(
            context.case.manifest["versions"]["vulnerable"]
        ),
        "source_fixed": context.materials.get(
            context.case.manifest["versions"]["fixed"]
        ),
        "advisory": context.plan["intel"]["content_digest"],
        "bundle": context.plan["repository"]["bundle_digest"],
    }
    material_checks: list[tuple[str, str]] = [
        ("harness", case.manifest["harness"]),
        ("build_recipe", case.manifest["build_recipe"]),
        ("dependencies", case.manifest["dependencies"]),
        ("source_vulnerable", case.manifest["versions"]["vulnerable"]),
        ("source_fixed", case.manifest["versions"]["fixed"]),
        ("advisory", case.advisory["path"]),
        ("bundle", case.repository["bundle"]),
    ]
    if isinstance(plan_inputs, Mapping):
        expected_digests["input_normal"] = plan_inputs.get("normal")
        expected_digests["input_candidate"] = plan_inputs.get("candidate")
        material_checks.append(
            ("input_normal", context.manifest_case["inputs"]["normal"])
        )
        if not _is_reuse_plan(context.plan):
            material_checks.append(
                ("input_candidate", context.manifest_case["inputs"]["candidate"])
            )
    for label, relative in material_checks:
        try:
            case.read_material(relative, expected_digests.get(label))
        except CaseConfigurationError as error:
            raise ExecutionBlocked(
                "MATERIAL_MISSING", f"{label} is no longer readable: {error.message}"
            ) from error


    if materials_dir is not None and material_digests is not None:
        _verify_materialized_tree(materials_dir, material_digests)


_GENERATION_COMPONENT = re.compile(r"generation-[0-9]+")


def _ensure_run_anchor(anchor: Path, label: str) -> None:
    """Create the trusted anchor if needed, but never accept a symlink."""
    try:
        anchor.mkdir(parents=True, exist_ok=True)
        info = anchor.lstat()
    except OSError as error:
        raise ExecutionFailed(
            "EVIDENCE_WRITE_FAILED", f"{label} is unavailable: {error}"
        ) from error
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
        raise ExecutionFailed(
            "EVIDENCE_WRITE_FAILED", f"{label} is not a real directory"
        )


def _generation_components(
    anchor: Path, path: Path, label: str
) -> tuple[tuple[str, ...], tuple[str, ...]]:
    """Split ``path`` into generation-scope components and the remainder.

    Every run-root write must be bound to a ``generation-<n>`` directory (for
    journals, ``steps/<key>/generation-<n>``). A path without one cannot be
    attributed to a single generation, so it is rejected rather than being
    written into the shared job directory.
    """
    try:
        relative = path.relative_to(anchor)
    except ValueError as error:
        raise ExecutionFailed(
            "EVIDENCE_WRITE_FAILED", f"{label} escaped the run root"
        ) from error
    parts = relative.parts
    if not parts or any(
        part in ("", ".", "..") or "/" in part or "\x00" in part
        for part in parts
    ):
        raise ExecutionFailed(
            "EVIDENCE_WRITE_FAILED", f"{label} has an unsafe run-root path"
        )
    for index, part in enumerate(parts):
        if _GENERATION_COMPONENT.fullmatch(part):
            return parts[: index + 1], parts[index + 1 :]
    raise ExecutionFailed(
        "EVIDENCE_WRITE_FAILED",
        f"{label} is not scoped to a generation directory",
    )


def _open_chain(
    anchor: Path,
    parts: Sequence[str],
    *,
    create: bool,
    label: str,
) -> tuple[int, Path]:
    """Open ``anchor/parts...`` one component at a time with no symlink following."""
    _ensure_run_anchor(anchor, label)
    flags = (
        os.O_RDONLY
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    try:
        descriptor = os.open(anchor, flags)
    except OSError as error:
        raise ExecutionFailed(
            "EVIDENCE_WRITE_FAILED", f"{label} cannot be opened: {error}"
        ) from error
    current = anchor
    try:
        for part in parts:
            if part in ("", ".", "..") or "/" in part or "\x00" in part:
                raise ExecutionFailed(
                    "EVIDENCE_WRITE_FAILED", f"{label} has an unsafe component"
                )
            try:
                child = os.open(part, flags, dir_fd=descriptor)
            except FileNotFoundError:
                if not create:
                    raise
                try:
                    os.mkdir(part, 0o700, dir_fd=descriptor)
                except FileExistsError:
                    pass
                child = os.open(part, flags, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
            current = current / part
        info = os.fstat(descriptor)
        by_path = os.lstat(current)
        if (info.st_dev, info.st_ino) != (by_path.st_dev, by_path.st_ino):
            raise ExecutionFailed(
                "EVIDENCE_WRITE_FAILED", f"{label} parent changed while opening"
            )
        return descriptor, current
    except ExecutionFailed:
        os.close(descriptor)
        raise
    except OSError as error:
        os.close(descriptor)
        raise ExecutionFailed(
            "EVIDENCE_WRITE_FAILED",
            f"{label} cannot be opened without following a symlink: {error}",
        ) from error
    except BaseException:
        os.close(descriptor)
        raise


def _prepare_shared_directory(anchor: Path, directory: Path, label: str) -> Path:
    """Create a shared (pre-generation) run-root directory safely."""
    try:
        relative = directory.relative_to(anchor)
    except ValueError as error:
        raise ExecutionFailed(
            "EVIDENCE_WRITE_FAILED", f"{label} escaped the run root"
        ) from error
    descriptor, _ = _open_chain(
        anchor, relative.parts, create=True, label=label
    )
    os.close(descriptor)
    return directory


def _prepare_run_directory(
    anchor: Path,
    directory: Path,
    label: str,
    *,
    scope_root: Path | None = None,
) -> Path:
    """Create a generation-scoped directory and prove it is a real directory."""
    if scope_root is None:
        scope_parts, _ = _generation_components(anchor, directory, label)
    else:
        scope_parts, _ = _generation_components(anchor, scope_root, label)
    try:
        relative = directory.relative_to(anchor)
    except ValueError as error:
        raise ExecutionFailed(
            "EVIDENCE_WRITE_FAILED", f"{label} escaped the run root"
        ) from error
    parts = relative.parts
    if parts[: len(scope_parts)] != scope_parts:
        raise ExecutionFailed(
            "EVIDENCE_WRITE_FAILED", f"{label} escaped its generation scope"
        )
    descriptor, _ = _open_chain(anchor, parts, create=True, label=label)
    os.close(descriptor)
    return directory


def _open_run_parent_fd(
    anchor: Path,
    path: Path,
    label: str,
    *,
    scope_root: Path | None = None,
) -> tuple[int, Path]:
    """Open ``path.parent`` relative to a generation-scoped trusted chain."""
    if scope_root is None:
        scope_parts, _ = _generation_components(anchor, path, label)
    else:
        scope_parts, _ = _generation_components(anchor, scope_root, label)
    try:
        relative = path.relative_to(anchor)
    except ValueError as error:
        raise ExecutionFailed(
            "EVIDENCE_WRITE_FAILED", f"{label} escaped the run root"
        ) from error
    parts = relative.parts
    if parts[: len(scope_parts)] != scope_parts:
        raise ExecutionFailed(
            "EVIDENCE_WRITE_FAILED", f"{label} escaped its generation scope"
        )
    parent_parts = parts[:-1]
    descriptor, parent = _open_chain(
        anchor, parent_parts, create=True, label=label
    )
    try:
        fileio._assert_dir_fd_matches_parent(descriptor, parent)
    except fileio.UnsafeFileError as error:
        os.close(descriptor)
        raise ExecutionFailed(
            "EVIDENCE_WRITE_FAILED", f"{label}: {error.message}"
        ) from error
    return descriptor, parent


def _write_tree_file(
    descriptor: int,
    root: Path,
    relative: str,
    data: bytes,
    mode: int,
    label: str,
) -> None:
    """Write ``relative`` below an already-open, trusted directory descriptor."""
    parts = Path(relative).parts
    if not parts or any(
        part in ("", ".", "..") or "/" in part for part in parts
    ):
        raise ExecutionFailed(
            "EVIDENCE_WRITE_FAILED", f"{label} has an unsafe path"
        )
    current = root
    flags = (
        os.O_RDONLY
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    fd = os.dup(descriptor)
    try:
        for part in parts[:-1]:
            try:
                child = os.open(part, flags, dir_fd=fd)
            except FileNotFoundError:
                os.mkdir(part, 0o755, dir_fd=fd)
                child = os.open(part, flags, dir_fd=fd)
            os.close(fd)
            fd = child
            current = current / part
        fileio.write_regular_file(
            parts[-1],
            data,
            mode=mode,
            dir_fd=fd,
            parent_path=current,
        )
    except fileio.UnsafeFileError as error:
        raise ExecutionFailed(
            "EVIDENCE_WRITE_FAILED", f"{label}: {error.message}"
        ) from error
    except OSError as error:
        raise ExecutionFailed(
            "EVIDENCE_WRITE_FAILED", f"{label}: {error}"
        ) from error
    finally:
        os.close(fd)


def _materialize(
    context: ExecutionContext,
    run_root: Path,
    *,
    anchor: Path | None = None,
) -> tuple[Path, dict[str, Path], dict[str, str]]:
    """Write approved materials into a generation-scoped, symlink-safe tree.

    ``run_root`` is the generation-scoped directory. The generation root and
    every parent below it are opened one component at a time with
    ``O_DIRECTORY|O_NOFOLLOW``; temporary files and the final rename are
    performed relative to those descriptors. A symlinked generation root or a
    parent directory swapped after the check therefore fails closed instead of
    redirecting reviewed bytes outside the run root.
    """
    generation_root = run_root
    trusted_anchor = anchor if anchor is not None else generation_root.parent
    _prepare_run_directory(
        trusted_anchor, generation_root, "materialized generation root"
    )
    scope_parts, _ = _generation_components(
        trusted_anchor, generation_root, "materialized generation root"
    )
    generation_fd, _ = _open_chain(
        trusted_anchor, scope_parts, create=False, label="materialized generation root"
    )
    try:
        return _materialize_into_generation(
            context, generation_root, generation_fd
        )
    finally:
        os.close(generation_fd)


def _materialize_into_generation(
    context: ExecutionContext, generation_root: Path, generation_fd: int
) -> tuple[Path, dict[str, Path], dict[str, str]]:
    is_v2 = _is_v2_context(context)
    target = generation_root / "materials"
    expected_build: dict[str, tuple[str, str | None]] = {
        "harness": (context.case.manifest["harness"], _harness_material_digest(context)),
        "build_recipe": (
            context.case.manifest["build_recipe"],
            _expected_build_recipe_digest(context),
        ),
        "dependencies": (
            context.case.manifest["dependencies"],
            context.plan["dependencies_digest"],
        ),
        "patch": (
            context.case.repository["patch"],
            context.plan["repository"]["patch_digest"],
        ),
        "source_vulnerable": (
            context.case.manifest["versions"]["vulnerable"],
            None,
        ),
        "source_fixed": (context.case.manifest["versions"]["fixed"], None),
    }
    plan_inputs = context.plan.get("inputs")
    expected_inputs: dict[str, tuple[str, str | None]] = {}
    if isinstance(plan_inputs, Mapping):
        expected_inputs = {
            "input_normal": (
                context.manifest_case["inputs"]["normal"],
                plan_inputs.get("normal"),
            ),
            "input_candidate": (
                context.manifest_case["inputs"]["candidate"],
                plan_inputs.get("candidate"),
            ),
        }
    elif not is_v2:
        raise ExecutionBlocked("MATERIAL_MISSING", "plan has no inputs mapping")

    build_payloads: dict[str, bytes] = {}
    input_payloads: dict[str, bytes] = {}
    for expected_group, target_payloads in (
        (expected_build, build_payloads),
        (expected_inputs, input_payloads),
    ):
        for label, (relative, digest) in expected_group.items():
            reuse = getattr(context, "reuse", None)
            if label == "input_candidate" and _is_reuse_plan(context.plan):
                if reuse is None or _digest(reuse.seed) != digest:
                    raise ExecutionBlocked(
                        "MATERIAL_MISSING",
                        "the campaign crash seed for this round is unavailable",
                    )
                target_payloads[relative] = reuse.seed
                continue
            try:
                data, actual = context.case.read_material(relative, digest)
            except CaseConfigurationError as error:
                raise ExecutionBlocked(error.reason_code, error.message) from error
            if digest is None:
                digest = context.materials.get(relative)
            if digest is not None and actual != digest:
                raise ExecutionBlocked(
                    "MATERIAL_MISSING",
                    f"material {label} digest drifted while materializing",
                )
            target_payloads[relative] = data

    if _is_campaign_context(context):
        # The fixed libFuzzer shim is reviewed repository material, staged
        # next to the frozen case materials so the one campaign build can
        # link the fuzzer. It is never generated per case.
        if fuzz_rules.FUZZ_SHIM_STAGED_NAME in context.materials:
            raise ExecutionBlocked(
                fuzz_rules.HARNESS_REJECTED,
                "a case material shadows the fixed fuzz shim",
                {"sub_reason": "FUZZ_SHIM_SHADOWED"},
            )
        try:
            build_payloads[fuzz_rules.FUZZ_SHIM_STAGED_NAME] = (
                fuzz_rules.load_fuzz_shim(fuzz_rules.FUZZ_SHIM_PATH)
            )
        except fuzz_rules.HarnessRejected as error:
            raise ExecutionBlocked(
                error.reason_code, error.message, {"sub_reason": error.sub_reason}
            ) from error

    payloads: dict[str, bytes] = (
        dict(build_payloads) if is_v2 else {**build_payloads, **input_payloads}
    )

    # Keep the exact bytes that were verified for this execution. Archiving
    # uses this snapshot instead of re-reading the case directory after the
    # target has run, so a later case-root replacement cannot become evidence.
    context.material_payloads = {**build_payloads, **input_payloads}

    if is_v2:
        # D4: v2 keeps replay inputs completely outside the build materials
        # directory; build staging mounts ONLY build materials.
        replay_inputs_dir = generation_root / "replay-inputs"
        candidate_path = replay_inputs_dir / "candidate.txt"
        normal_path = replay_inputs_dir / "normal.txt"
        if isinstance(plan_inputs, Mapping):
            for label, relative in (
                ("candidate", context.manifest_case["inputs"]["candidate"]),
                ("normal", context.manifest_case["inputs"]["normal"]),
            ):
                data = input_payloads[relative]
                if _digest(data) != plan_inputs[label]:
                    raise ExecutionBlocked(
                        "MATERIAL_MISSING", f"{label} input digest drifted"
                    )
            if replay_inputs_dir.is_symlink():
                raise ExecutionBlocked(
                    "MATERIAL_MISSING",
                    "materialized replay-inputs directory must not be a symlink",
                )
            if replay_inputs_dir.exists():
                for label, path, expected_digest in (
                    ("candidate", candidate_path, plan_inputs["candidate"]),
                    ("normal", normal_path, plan_inputs["normal"]),
                ):
                    data = _read_run_file_bounded(path, max_bytes=MAX_MATERIAL_BYTES)
                    if data is None:
                        raise ExecutionBlocked(
                            "MATERIAL_MISSING",
                            f"materialized {label} input is missing or too large",
                        )
                    if _digest(data) != expected_digest:
                        raise ExecutionBlocked(
                            "MATERIAL_MISSING", f"materialized {label} input drifted"
                        )
            else:
                tmp_inputs = generation_root / f".replay-inputs-tmp-{uuid.uuid4().hex}"
                tmp_inputs_name = tmp_inputs.name
                try:
                    os.mkdir(tmp_inputs_name, 0o755, dir_fd=generation_fd)
                except FileExistsError as error:
                    raise ExecutionBlocked(
                        "MATERIAL_MISSING", "temporary replay-inputs path exists"
                    ) from error
                tmp_inputs_fd: int | None = None
                try:
                    tmp_inputs_fd = os.open(
                        tmp_inputs_name,
                        os.O_RDONLY
                        | getattr(os, "O_DIRECTORY", 0)
                        | getattr(os, "O_NOFOLLOW", 0),
                        dir_fd=generation_fd,
                    )
                    for name, relative in (
                        ("candidate.txt", context.manifest_case["inputs"]["candidate"]),
                        ("normal.txt", context.manifest_case["inputs"]["normal"]),
                    ):
                        _write_tree_file(
                            tmp_inputs_fd,
                            tmp_inputs,
                            name,
                            input_payloads[relative],
                            0o444,
                            "materialized replay input",
                        )
                    os.chmod(
                        tmp_inputs_name,
                        0o755,
                        dir_fd=generation_fd,
                        follow_symlinks=False,
                    )
                    os.close(tmp_inputs_fd)
                    tmp_inputs_fd = None
                    os.replace(
                        tmp_inputs_name,
                        "replay-inputs",
                        src_dir_fd=generation_fd,
                        dst_dir_fd=generation_fd,
                    )
                except (ExecutionBlocked, ExecutionFailed):
                    if tmp_inputs_fd is not None:
                        os.close(tmp_inputs_fd)
                    shutil.rmtree(tmp_inputs, ignore_errors=True)
                    raise
                except OSError as error:
                    if tmp_inputs_fd is not None:
                        os.close(tmp_inputs_fd)
                    shutil.rmtree(tmp_inputs, ignore_errors=True)
                    raise ExecutionFailed(
                        "EVIDENCE_WRITE_FAILED",
                        f"cannot materialize replay inputs: {error}",
                    ) from error
                except BaseException:
                    if tmp_inputs_fd is not None:
                        os.close(tmp_inputs_fd)
                    shutil.rmtree(tmp_inputs, ignore_errors=True)
                    raise
    else:
        candidate_path = target / "inputs" / "candidate.txt"
        normal_path = target / "inputs" / "normal.txt"
        for label, destination, relative in (
            ("candidate", candidate_path, context.manifest_case["inputs"]["candidate"]),
            ("normal", normal_path, context.manifest_case["inputs"]["normal"]),
        ):
            data = payloads[relative]
            if _digest(data) != context.plan["inputs"][label]:
                raise ExecutionBlocked(
                    "MATERIAL_MISSING", f"{label} input digest drifted"
                )

    if target.is_symlink():
        raise ExecutionBlocked(
            "MATERIAL_MISSING", "materialized directory must not be a symlink"
        )
    if target.exists():
        try:
            os.chmod(
                "materials", 0o755, dir_fd=generation_fd, follow_symlinks=False
            )
        except OSError as error:
            raise ExecutionBlocked(
                "MATERIAL_MISSING", f"materialized directory is not accessible: {error}"
            ) from error
        _verify_materialized(target, payloads)
        if not is_v2:
            for label, path, expected_digest in (
                ("candidate", candidate_path, context.plan["inputs"]["candidate"]),
                ("normal", normal_path, context.plan["inputs"]["normal"]),
            ):
                data = _read_run_file_bounded(path, max_bytes=MAX_MATERIAL_BYTES)
                if data is None:
                    raise ExecutionBlocked(
                        "MATERIAL_MISSING",
                        f"materialized {label} input is missing or too large",
                    )
                if _digest(data) != expected_digest:
                    raise ExecutionBlocked("MATERIAL_MISSING", f"materialized {label} input drifted")
        return target, {
            "candidate": candidate_path,
            "normal": normal_path,
            "build_recipe": target / context.case.manifest["build_recipe"],
        }, _material_digests(context, payloads)

    temporary = generation_root / f".materials-tmp-{uuid.uuid4().hex}"
    temporary_name = temporary.name
    try:
        os.mkdir(temporary_name, 0o755, dir_fd=generation_fd)
    except FileExistsError as error:
        raise ExecutionBlocked(
            "MATERIAL_MISSING", "temporary material path exists"
        ) from error
    temporary_fd: int | None = None
    try:
        temporary_fd = os.open(
            temporary_name,
            os.O_RDONLY
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_NOFOLLOW", 0),
            dir_fd=generation_fd,
        )
        for relative, data in payloads.items():
            mode = (
                0o555
                if relative == context.case.manifest["build_recipe"]
                else 0o444
            )
            _write_tree_file(
                temporary_fd, temporary, relative, data, mode, "materialized file"
            )
        if not is_v2:
            for path, data in (
                (candidate_path, payloads[context.manifest_case["inputs"]["candidate"]]),
                (normal_path, payloads[context.manifest_case["inputs"]["normal"]]),
            ):
                _write_tree_file(
                    temporary_fd,
                    temporary,
                    str(path.relative_to(target)),
                    data,
                    0o444,
                    "materialized input",
                )
            os.chmod("inputs", 0o755, dir_fd=temporary_fd, follow_symlinks=False)
        os.chmod(temporary_name, 0o755, dir_fd=generation_fd, follow_symlinks=False)
        os.close(temporary_fd)
        temporary_fd = None
        os.replace(
            temporary_name,
            "materials",
            src_dir_fd=generation_fd,
            dst_dir_fd=generation_fd,
        )
    except (ExecutionBlocked, ExecutionFailed):
        if temporary_fd is not None:
            os.close(temporary_fd)
        shutil.rmtree(temporary, ignore_errors=True)
        raise
    except OSError as error:
        if temporary_fd is not None:
            os.close(temporary_fd)
        shutil.rmtree(temporary, ignore_errors=True)
        raise ExecutionFailed(
            "EVIDENCE_WRITE_FAILED", f"cannot materialize reviewed bytes: {error}"
        ) from error
    except BaseException:
        if temporary_fd is not None:
            os.close(temporary_fd)
        shutil.rmtree(temporary, ignore_errors=True)
        raise
    return target, {
        "candidate": candidate_path,
        "normal": normal_path,
        "build_recipe": target / context.case.manifest["build_recipe"],
    }, _material_digests(context, payloads)


def _material_digests(
    context: ExecutionContext, payloads: Mapping[str, bytes]
) -> dict[str, str]:
    if _is_v2_context(context):
        input_paths = _input_material_paths(context)
        return {
            relative: _digest(data)
            for relative, data in payloads.items()
            if not _is_input_material_path(relative, input_paths)
        }
    digests = {
        relative: _digest(data) for relative, data in payloads.items()
    }
    # Replay commands use stable names even when the manifest names the input
    # differently; both copies are part of the verified tree.
    digests["inputs/candidate.txt"] = context.plan["inputs"]["candidate"]
    digests["inputs/normal.txt"] = context.plan["inputs"]["normal"]
    return digests


def _verify_materialized(target: Path, payloads: Mapping[str, bytes]) -> None:
    for relative, expected in payloads.items():
        path = target / Path(relative)
        data = _read_run_file_bounded(path, max_bytes=MAX_MATERIAL_BYTES)
        if data is None:
            raise ExecutionBlocked(
                "MATERIAL_MISSING",
                f"materialized file is missing, not regular or too large: {relative}",
            )
        if data != expected:
            raise ExecutionBlocked(
                "MATERIAL_MISSING", f"materialized file drifted: {relative}"
            )


def _verify_materialized_tree(
    target: Path, expected: Mapping[str, str]
) -> None:
    """Fail closed on extra files, symlinks or changed bytes in the copy."""
    if target.is_symlink() or not target.is_dir():
        raise ExecutionBlocked("MATERIAL_MISSING", "materialized directory is missing")
    seen: set[str] = set()
    for current_root, directories, filenames in os.walk(target, followlinks=False):
        current = Path(current_root)
        for name in directories:
            child = current / name
            if child.is_symlink():
                raise ExecutionBlocked(
                    "MATERIAL_MISSING", "materialized tree contains a symlink"
                )
        for name in filenames:
            child = current / name
            relative = child.relative_to(target).as_posix()
            if child.is_symlink() or not child.is_file():
                raise ExecutionBlocked(
                    "MATERIAL_MISSING",
                    f"materialized file is not regular: {relative}",
                )
            seen.add(relative)
    if seen != set(expected):
        missing = sorted(set(expected) - seen)
        extra = sorted(seen - set(expected))
        raise ExecutionBlocked(
            "MATERIAL_MISSING",
            f"materialized tree changed; missing={missing} extra={extra}",
        )
    for relative, digest in expected.items():
        path = target / Path(relative)
        data = _read_run_file_bounded(path, max_bytes=MAX_MATERIAL_BYTES)
        if data is None:
            raise ExecutionBlocked(
                "MATERIAL_MISSING",
                f"materialized file is missing, not regular or too large: {relative}",
            )
        if _digest(data) != digest:
            raise ExecutionBlocked(
                "MATERIAL_MISSING", f"materialized file drifted: {relative}"
            )


def _attempts(context: ExecutionContext, dsn: str, step_key: str) -> list[dict[str, Any]]:
    return state.attempts_for_step(
        dsn,
        context.job_id,
        stage="execute",
        step_key=step_key,
        generation=context.generation,
    )


def _work_root(context: ExecutionContext) -> Path:
    return (
        context.run_root
        / context.job_id_text
        / context.plan_digest.split(":")[1]
        / "run"
    )


def _generation_root(context: ExecutionContext) -> Path:
    return _work_root(context) / f"generation-{context.generation}"


def _outside_run_root(path: Path, run_root: Path, label: str) -> Path:
    """Resolve ``path`` and reject anything inside the writable run root.

    Containment is decided from device/inode identities of the deepest
    existing ancestors (see ``_inside_run_root``), never from resolved strings
    alone. That catches ``target == run_root``, nested targets and case-only or
    Unicode-normalization variants of the run-root path on filesystems that
    treat them as the same directory.
    """
    try:
        resolved = path.expanduser().resolve()
        resolved_root = run_root.expanduser().resolve()
    except (OSError, RuntimeError) as error:
        raise ExecutionFailed(
            "EVIDENCE_WRITE_FAILED", f"{label} cannot be resolved: {error}"
        ) from error
    if _inside_run_root(resolved, resolved_root, label):
        raise ExecutionFailed(
            "EVIDENCE_WRITE_FAILED",
            f"{label} must live outside DATACON_RUN_ROOT",
        )
    mountinfo = _mountinfo_document()
    if mountinfo is not None and _mountinfo_rejects(
        resolved, resolved_root, mountinfo
    ):
        raise ExecutionFailed(
            "EVIDENCE_WRITE_FAILED",
            f"{label} mount relationships cannot prove it lives outside "
            "DATACON_RUN_ROOT",
        )
    return resolved


def _assert_evidence_root_outside_run_root(run_root: Path) -> Path:
    """Fail before any archive work when the evidence root is attacker-writable."""
    evidence_root = Path(
        os.getenv("DATACON_EVIDENCE_ROOT", ".datacon/evidence")
    ).expanduser()
    return _outside_run_root(evidence_root, run_root, "DATACON_EVIDENCE_ROOT")


def _staging_root(context: ExecutionContext) -> Path:
    """Return the private staging root used for every mounted byte.

    The run root is treated as attacker-writable. Materials, built parsers and
    replay inputs are copied here, re-hashed and only then mounted. The root
    itself is private (0700) and must live outside ``DATACON_RUN_ROOT``; the
    per-attempt directory is traversable by the non-root container user while
    the private parent stays hidden from other host users.
    """
    evidence_root = Path(
        os.getenv("DATACON_EVIDENCE_ROOT", ".datacon/evidence")
    ).expanduser()
    raw = _configured_staging_path(evidence_root)
    if raw.is_symlink():
        raise ExecutionFailed(
            "EVIDENCE_WRITE_FAILED", "staging root must not be a symlink"
        )
    resolved = _outside_run_root(raw, context.run_root, "staging root")
    try:
        resolved.mkdir(mode=0o700, parents=True, exist_ok=True)
        info = resolved.lstat()
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
            raise ExecutionFailed(
                "EVIDENCE_WRITE_FAILED", "staging root is not a directory"
            )
        if info.st_uid != os.getuid():
            raise ExecutionFailed(
                "EVIDENCE_WRITE_FAILED", "staging root is not owned by this user"
            )
        # Re-check the final directory. The pre-create check used the deepest
        # existing ancestor; only the created inode proves where it landed.
        resolved = _outside_run_root(resolved, context.run_root, "staging root")
        resolved.chmod(0o700)
    except ExecutionFailed:
        raise
    except OSError as error:
        raise ExecutionFailed(
            "EVIDENCE_WRITE_FAILED", f"staging root is unavailable: {error}"
        ) from error
    return resolved


def _new_staging_directory(
    context: ExecutionContext, label: str
) -> Path:
    root = _staging_root(context)
    directory = root / (
        f"{_safe_name(label)}-g{context.generation}-{uuid.uuid4().hex}"
    )
    try:
        directory.mkdir(mode=0o700)
    except OSError as error:
        raise ExecutionFailed(
            "EVIDENCE_WRITE_FAILED", f"staging directory is unavailable: {error}"
        ) from error
    return directory


def _discard_staging(directory: Path) -> OSError | None:
    """Best-effort removal that never raises into a caller's error path."""
    try:
        shutil.rmtree(directory)
    except OSError as error:
        return error
    return None


def _cleanup_staging(directory: Path, failure: BaseException | None) -> None:
    """Remove one attempt's staging copy without masking its real failure."""
    error = _discard_staging(directory)
    if error is None:
        return
    if failure is None:
        raise ExecutionFailed(
            "EVIDENCE_WRITE_FAILED", f"cannot remove staging directory: {error}"
        ) from error
    add_note = getattr(failure, "add_note", None)
    if callable(add_note):
        add_note(f"staging cleanup also failed: {error}")


def _write_staged_file(
    directory: Path, relative: str, data: bytes, mode: int
) -> Path:
    destination = directory / Path(relative)
    try:
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.parent.chmod(0o755)
        destination.write_bytes(data)
        destination.chmod(mode)
    except OSError as error:
        raise ExecutionFailed(
            "EVIDENCE_WRITE_FAILED",
            f"cannot write staging copy {relative}: {error}",
        ) from error
    return destination


def _make_staging_tree_readable(directory: Path) -> None:
    """Let the non-root container traverse the attempt directory.

    The 0700 staging root is the private boundary; bind mounts reference the
    attempt directory itself, so the container never walks the host parent.
    """
    try:
        for current, directories, filenames in os.walk(directory, topdown=False):
            for name in filenames:
                path = Path(current) / name
                path.chmod(0o555 if os.access(path, os.X_OK) else 0o444)
            for name in directories:
                (Path(current) / name).chmod(0o755)
        directory.chmod(0o755)
    except OSError as error:
        raise ExecutionFailed(
            "EVIDENCE_WRITE_FAILED", f"cannot finalize staging modes: {error}"
        ) from error


def _stage_materials(
    context: ExecutionContext,
    materials_dir: Path,
    material_digests: Mapping[str, str],
    label: str,
) -> tuple[Path, dict[str, str]]:
    """Copy the verified material tree outside the run root and re-hash it."""
    _verify_materialized_tree(materials_dir, material_digests)
    is_v2 = _is_v2_context(context)
    if is_v2:
        # D4: v2 build staging must never expose replay input aliases or any
        # input material files to build containers or staged_materials.
        input_paths = _input_material_paths(context)
        stage_digests = {
            relative: digest
            for relative, digest in material_digests.items()
            if not _is_input_material_path(relative, input_paths)
        }
    else:
        stage_digests = dict(material_digests)
    directory = _new_staging_directory(context, label)
    try:
        staged: dict[str, str] = {}
        for relative in sorted(stage_digests):
            source = materials_dir / Path(relative)
            data = _read_run_file_bounded(
                source, max_bytes=MAX_MATERIAL_BYTES
            )
            if data is None:
                raise ExecutionBlocked(
                    "MATERIAL_MISSING",
                    f"material disappeared, is not regular or is too large "
                    f"before staging: {relative}",
                )
            actual = _digest(data)
            if actual != stage_digests[relative]:
                raise ExecutionBlocked(
                    "MATERIAL_MISSING",
                    f"material changed while staging: {relative}",
                )
            _write_staged_file(directory, relative, data, 0o444)
            staged[relative] = actual
        recipe_rel = context.case.manifest.get("build_recipe")
        if not is_v2 or (isinstance(recipe_rel, str) and recipe_rel in stage_digests):
            recipe = directory / Path(context.case.manifest["build_recipe"])
            if recipe.is_symlink() or not recipe.is_file():
                raise ExecutionBlocked(
                    "MATERIAL_MISSING", "build recipe is missing from the staging copy"
                )
            recipe.chmod(0o555)
        _make_staging_tree_readable(directory)
        # Hash the staged copy, not the source, immediately before mounting.
        _verify_materialized_tree(directory, stage_digests)
        return directory, staged
    except (ExecutionBlocked, ExecutionFailed):
        _discard_staging(directory)
        raise
    except OSError as error:
        _discard_staging(directory)
        raise ExecutionFailed(
            "EVIDENCE_WRITE_FAILED", f"cannot stage reviewed materials: {error}"
        ) from error
    except BaseException:
        _discard_staging(directory)
        raise


def _stage_replay_files(
    context: ExecutionContext,
    artifact_path: Path,
    artifact_digest: str,
    input_path: Path,
    input_digest: str,
    label: str,
) -> tuple[Path, Path, Path]:
    """Copy the parser and input outside the run root and verify both copies."""
    directory = _new_staging_directory(context, label)
    try:
        for source, relative, expected, mode, kind, limit in (
            (artifact_path, "parser", artifact_digest, 0o555, "parser", MAX_ARTIFACT_BYTES),
            (input_path, "input", input_digest, 0o444, "input", MAX_MATERIAL_BYTES),
        ):
            data = _read_run_file_bounded(source, max_bytes=limit)
            if data is None:
                raise ExecutionBlocked(
                    "MATERIAL_MISSING",
                    f"replay {kind} is missing, not regular or too large "
                    f"before staging",
                )
            actual = _digest(data)
            if actual != expected:
                raise ExecutionBlocked(
                    "PLAN_MISMATCH",
                    f"replay {kind} changed before staging",
                )
            destination = _write_staged_file(directory, relative, data, mode)
            staged_data = _read_run_file_bounded(destination, max_bytes=limit)
            if staged_data is None:
                raise ExecutionFailed(
                    "EVIDENCE_WRITE_FAILED",
                    f"cannot read back staged replay {kind}",
                )
            staged_digest = _digest(staged_data)
            if staged_digest != expected:
                raise ExecutionBlocked(
                    "PLAN_MISMATCH",
                    f"staged replay {kind} does not match the approved digest",
                )
        _make_staging_tree_readable(directory)
        return directory, directory / "parser", directory / "input"
    except (ExecutionBlocked, ExecutionFailed):
        _discard_staging(directory)
        raise
    except OSError as error:
        _discard_staging(directory)
        raise ExecutionFailed(
            "EVIDENCE_WRITE_FAILED", f"cannot stage replay inputs: {error}"
        ) from error
    except BaseException:
        _discard_staging(directory)
        raise


def _configured_staging_path(evidence_root: Path) -> Path:
    """Return the configured staging root without creating it."""
    explicit = os.getenv(STAGING_ROOT_ENV)
    return (
        Path(explicit).expanduser()
        if explicit
        else evidence_root.parent / ".datacon-staging"
    )


def _journal_secret_path(run_root: Path) -> Path:
    """Return the HMAC key path, enforcing that it is outside sensitive roots.

    A journal secret must not be readable by the same-UID writer that can
    modify the run root, the evidence root, the staging root or the current
    working directory. The historical default
    (``evidence_root.parent/.datacon-journal-secret``) is only safe when the
    evidence root is absolute and outside CWD; with the default relative
    evidence root it would place the key inside CWD, so that configuration
    fails closed and requires an explicit secret path instead.
    """
    explicit = os.getenv("DATACON_JOURNAL_SECRET_FILE")
    raw_evidence = os.getenv("DATACON_EVIDENCE_ROOT", ".datacon/evidence")
    configured_evidence = Path(raw_evidence).expanduser()
    if explicit is None and not configured_evidence.is_absolute():
        raise ExecutionFailed(
            "EVIDENCE_WRITE_FAILED",
            "a relative DATACON_EVIDENCE_ROOT cannot derive a safe journal "
            "secret; set DATACON_JOURNAL_SECRET_FILE or an absolute evidence "
            "root outside the current working directory",
        )
    evidence_root = _assert_evidence_root_outside_run_root(run_root)
    path = (
        Path(explicit).expanduser()
        if explicit
        else evidence_root.parent / ".datacon-journal-secret"
    )
    if path.is_symlink():
        raise ExecutionFailed(
            "EVIDENCE_WRITE_FAILED", "journal secret path must not be a symlink"
        )
    resolved = _outside_run_root(path, run_root, "journal secret")
    try:
        resolved_cwd = Path.cwd().expanduser().resolve()
    except (OSError, RuntimeError) as error:
        raise ExecutionFailed(
            "EVIDENCE_WRITE_FAILED",
            f"journal secret current working directory cannot be resolved: {error}",
        ) from error
    if resolved_cwd.parent == resolved_cwd:
        raise ExecutionFailed(
            "EVIDENCE_WRITE_FAILED",
            "current working directory is the filesystem root ('/'), so no "
            "journal secret path can live outside current working directory; "
            "run datacon from a non-root working directory and set "
            "DATACON_JOURNAL_SECRET_FILE outside that directory",
        )
    protected_roots = [
        (evidence_root, "DATACON_EVIDENCE_ROOT"),
        (_configured_staging_path(evidence_root), "staging root"),
        (resolved_cwd, "current working directory"),
    ]
    for root, label in protected_roots:
        try:
            resolved_root = root.expanduser().resolve()
        except (OSError, RuntimeError) as error:
            raise ExecutionFailed(
                "EVIDENCE_WRITE_FAILED",
                f"journal secret {label} cannot be resolved: {error}",
            ) from error
        # Check both lexical normalization (case/NFC variants) and the final
        # inode identity. A symlinked ancestor must not turn the path into one
        # of the protected trees after the string comparison.
        if _lexically_within_run_root(resolved, resolved_root):
            raise ExecutionFailed(
                "EVIDENCE_WRITE_FAILED",
                f"journal secret must live outside {label}",
            )
        if _inside_run_root(resolved, resolved_root, "journal secret"):
            raise ExecutionFailed(
                "EVIDENCE_WRITE_FAILED",
                f"journal secret must live outside {label}",
            )
    return resolved


def _assert_journal_paths(run_root: Path) -> None:
    """Fail before any target container when the HMAC key is exposed."""
    path = _journal_secret_path(run_root)
    if path.exists():
        _journal_secret(create=False, run_root=run_root)


def _journal_secret(*, create: bool, run_root: Path) -> bytes | None:
    path = _journal_secret_path(run_root)
    if path.is_symlink():
        raise ExecutionFailed(
            "EVIDENCE_WRITE_FAILED", "journal secret path must not be a symlink"
        )
    if not path.exists():
        if not create:
            return None
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            # UUID4 is generated from the OS CSPRNG; 256 bits is enough for an
            # HMAC key that only has to stop a run-root writer from forging a
            # journal for an unrelated database row. O_EXCL + O_NOFOLLOW avoids
            # a concurrent-create or symlink race.
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
            descriptor = os.open(path, flags, 0o600)
            try:
                os.write(
                    descriptor, (uuid.uuid4().hex + uuid.uuid4().hex).encode("ascii")
                )
            finally:
                os.close(descriptor)
        except FileExistsError:
            pass
        except OSError as error:
            raise ExecutionFailed(
                "EVIDENCE_WRITE_FAILED",
                f"journal secret is unavailable: {error}",
            ) from error
    # The file may have been created (or its parent swapped) after the
    # path-level check. Re-run every protected-root check, then inspect the
    # final inode so a path that landed inside the run root, evidence root,
    # staging root or CWD is never read.
    path = _journal_secret_path(run_root)
    try:
        info = path.lstat()
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
            raise ExecutionFailed(
                "EVIDENCE_WRITE_FAILED", "journal secret is not a regular file"
            )
        if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) & 0o077:
            raise ExecutionFailed(
                "EVIDENCE_WRITE_FAILED", "journal secret is not private"
            )
        data = _read_run_file_bounded(
            path, max_bytes=_JOURNAL_SECRET_MAX_BYTES
        )
        if data is None:
            raise ExecutionFailed(
                "EVIDENCE_WRITE_FAILED",
                "journal secret is unreadable or too large",
            )
    except OSError as error:
        raise ExecutionFailed(
            "EVIDENCE_WRITE_FAILED", f"journal secret is unreadable: {error}"
        ) from error
    if len(data) < 32:
        raise ExecutionFailed(
            "EVIDENCE_WRITE_FAILED", "journal secret is too short"
        )
    return data


def _journal_hmac(payload: Mapping[str, Any], secret: bytes) -> str:
    body = {key: value for key, value in payload.items() if key != "hmac"}
    encoded = json.dumps(
        body, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")
    return hmac.new(secret, encoded, hashlib.sha256).hexdigest()


# Injectable step clock. The budget charge measures the wall time of the
# container step (including timeouts and failures) with this monotonic clock;
# tests replace it with a fake clock instead of sleeping.
STEP_CLOCK: Callable[[], float] = time.monotonic


def _budget_family_id(context: ExecutionContext) -> str | None:
    """Return the family whose ledger pays for this job's container steps.

    Only v2 campaign/round children spend the family budget (§7); v1 jobs and
    any other shape keep the v0.1 deadline-only behaviour.
    """
    job = context.job
    if job.get("job_contract_version") != 2:
        return None
    if job.get("job_kind") not in ("campaign", "round"):
        return None
    family_id = job.get("family_id")
    return None if family_id is None else str(family_id)


def _gate_step_budget(
    dsn: str, context: ExecutionContext, *, step_key: str, charge_kind: str
) -> float | None:
    """Check the family ledger before a container starts (§7 step 1).

    Returns the hard-timeout ceiling: the total balance for a ``general``
    step, ``min(remaining_total_seconds, remaining_fuzz_seconds)`` for a
    ``fuzz`` step. Less than one second raises ``BUDGET_EXHAUSTED`` before any
    container exists. Returns None for jobs without a family ledger.
    """
    family_id = _budget_family_id(context)
    if family_id is None:
        return None
    try:
        ledger = state.load_budget_ledger(dsn, family_id)
    except state.StateError as error:
        raise ExecutionBlocked(
            "MATERIAL_MISSING",
            f"the family budget ledger is unavailable: {error}",
        ) from error
    if ledger is None:
        raise ExecutionBlocked(
            "MATERIAL_MISSING", "the family budget ledger is unavailable"
        )
    decision = state.budget_gate(ledger, fuzz=charge_kind == "fuzz")
    if not decision.allowed:
        raise ExecutionFailed(
            state.BUDGET_EXHAUSTED,
            f"the family {charge_kind} budget is exhausted before {step_key}",
        )
    return float(decision.hard_timeout_seconds)


def _charge_step_budget(
    dsn: str,
    context: ExecutionContext,
    *,
    step_key: str,
    attempt_no: int,
    charge_kind: str,
    elapsed_seconds: float,
) -> state.BudgetChargeOutcome:
    """Charge one finished container step in its own short transaction (§7 step 2).

    Fuzz steps charge the same span against the fuzz sub-budget as well, so
    both balances move together. The idempotency key is
    ``(job_id, step_key, attempt_no)``.
    """
    family_id = _budget_family_id(context)
    assert family_id is not None
    elapsed = max(0.0, float(elapsed_seconds))
    return state.charge_step_budget(
        dsn,
        family_id=family_id,
        job_id=context.job_id,
        step_key=step_key,
        attempt_no=attempt_no,
        charge_kind=charge_kind,
        elapsed_seconds=elapsed,
        elapsed_fuzz_seconds=elapsed if charge_kind == "fuzz" else 0,
        generation=context.generation,
    )


def _refresh_budget_summary_before_archive(
    dsn: str, context: ExecutionContext
) -> None:
    """Recover prior-generation uncharged attempts for this child and rebuild budget_summary.

    B3: the child's archived ``budget/snapshot.json`` and ``report.budget`` must
    reflect the latest committed family charges, including any crashed attempt
    from an earlier generation of the same child.
    """
    family_id = _budget_family_id(context)
    if family_id is None:
        return
    state.recover_uncharged_attempts(dsn, job_id=context.job_id)
    context.budget_summary = state.family_budget_summary(dsn, family_id)


def _cap_to_step_budget(context: ExecutionContext, seconds: float) -> float:
    """Bound a container hard timeout by the ceiling the budget gate granted."""
    # Contexts built outside run_execution (unit doubles) may predate the
    # field; they have no budgeted step and keep the plain timeout.
    ceiling = getattr(context, "step_ceiling_seconds", None)
    if ceiling is None:
        return seconds
    return min(float(seconds), ceiling)


def _default_step_timeout_seconds(
    context: ExecutionContext, step_key: str
) -> float | None:
    """Derive a step's own hard-timeout cap when the caller did not pass one."""
    has_deadline = getattr(context, "deadline_at", None) is not None
    reserve = float(getattr(context, "reserve_seconds", 0.0))
    if step_key == "sandbox.probe":
        return (
            min(PROBE_TIMEOUT, _remaining(context))
            if has_deadline
            else PROBE_TIMEOUT
        )
    if step_key.startswith("build:"):
        return (
            min(BUILD_TIMEOUT, _remaining(context) - reserve)
            if has_deadline
            else BUILD_TIMEOUT
        )
    if step_key.startswith("replay:"):
        plan = getattr(context, "plan", None)
        limits = plan.get("limits") if isinstance(plan, Mapping) else None
        raw_replay = (
            limits.get("replay_seconds") if isinstance(limits, Mapping) else None
        )
        if isinstance(raw_replay, (int, float)) and not isinstance(
            raw_replay, bool
        ):
            replay_cap = float(raw_replay)
            return (
                min(replay_cap, _remaining(context) - reserve)
                if has_deadline
                else replay_cap
            )
    return None


def _run_step(
    dsn: str,
    context: ExecutionContext,
    *,
    step_key: str,
    input_digest: str | None,
    action: Callable[[int, str], Any],
    reusable: Callable[[Mapping[str, Any]], bool] | None = None,
    charge_kind: str = "general",
    step_timeout_seconds: float | None = None,
    budgeted: bool = True,
) -> tuple[Any, bool]:
    """Execute one logical step with generation fencing and crash recovery.

    ``budgeted=False`` is for steps that start no container (adopting the
    campaign build in a reuse round): no budget gate, no recovery ceiling on
    the started row and no charge.

    A completed attempt for this generation is reused only when its input
    digest matches. Otherwise a journal is adopted only when a database attempt
    row proves it belongs to this job, step, attempt and generation and the
    journal's one-time token and HMAC agree. Across generations a step may
    start at most two attempts; adopting an already finished tool result is
    explicitly exempt so a crash after the tool is not charged twice.
    """
    history = _attempts(context, dsn, step_key)
    for row in reversed(history):
        if row["status"] == "completed" and isinstance(row["result"], dict):
            if input_digest is not None and row.get("input_digest") != input_digest:
                # A completed result for different bytes is not a result for
                # this request. Do not reuse it; a bounded new attempt below
                # recomputes the step for the current input.
                continue
            if reusable is None or reusable(row["result"]):
                return row["result"], True
            raise ExecutionFailed(
                "RUN_INCOMPLETE",
                f"completed attempt for {step_key} no longer has verified evidence",
            )
    if any(
        row["status"] == "completed"
        and (input_digest is None or row.get("input_digest") == input_digest)
        for row in history
    ):
        raise ExecutionFailed(
            "RUN_INCOMPLETE", f"completed attempt for {step_key} has no reusable result"
        )

    all_history = state.attempts_for_step_across_generations(
        dsn, context.job_id, stage="execute", step_key=step_key
    )
    next_attempt_no = max(
        (row["attempt_no"] for row in all_history), default=0
    ) + 1
    if reusable is not None:
        journal = _find_reusable_journal(
            dsn,
            context,
            step_key=step_key,
            plan_digest=context.plan_digest,
            input_digest=input_digest,
            verify=reusable,
        )
        if journal is not None:
            adopted = {
                key: value
                for key, value in journal.items()
                if key not in ("attempt_token", "hmac")
            }
            adopted["reused"] = True
            adopted["reused_from_attempt"] = journal.get("attempt_no")
            adopted["reused_from_generation"] = journal.get("generation")
            recorded = state.record_attempt(
                dsn,
                context.job_id,
                stage="execute",
                step_key=step_key,
                attempt_no=next_attempt_no,
                generation=context.generation,
                input_digest=input_digest,
                status="completed",
                result=adopted,
                container_id=journal.get("container_id"),
                attempt_token=journal.get("attempt_token"),
            )
            if not recorded:
                raise state.StaleGeneration(
                    "the worker lease was lost while adopting a prior result"
                )
            return adopted, True

    if len(all_history) >= MAX_ATTEMPTS_PER_STEP:
        raise ExecutionFailed(
            "RUN_INCOMPLETE",
            f"step {step_key} consumed both attempts without a usable result",
        )
    # Attempt numbers are unique per generation; max(all)+1 keeps the journal
    # tree ordered without colliding with an adopted result.
    attempt_no = next_attempt_no
    # T12 §7: the budget gate runs before the attempt row and before any
    # container, so an exhausted family never starts the step. The recovery
    # ceiling recorded on the started row is the effective container hard
    # timeout: min(step timeout, remaining deadline, gate ceiling).
    gate_ceiling = (
        _gate_step_budget(dsn, context, step_key=step_key, charge_kind=charge_kind)
        if budgeted
        else None
    )
    ceiling: float | None = gate_ceiling
    if gate_ceiling is not None:
        resolved_timeout = (
            float(step_timeout_seconds)
            if step_timeout_seconds is not None
            else _default_step_timeout_seconds(context, step_key)
        )
        if resolved_timeout is not None:
            if not math.isfinite(resolved_timeout) or resolved_timeout <= 0:
                raise ExecutionBlocked(
                    "DEADLINE_EXCEEDED",
                    f"execution deadline exhausted before {step_key}",
                )
            ceiling = min(resolved_timeout, gate_ceiling)
    token = uuid.uuid4().hex
    stored = state.record_attempt(
        dsn,
        context.job_id,
        stage="execute",
        step_key=step_key,
        attempt_no=attempt_no,
        generation=context.generation,
        input_digest=input_digest,
        status="started",
        # The started row carries what a crash-recovery charge needs
        # (state.recover_uncharged_attempts): the charge kind and the
        # hard-timeout ceiling granted before the container started.
        result=(
            None
            if ceiling is None
            else {"budget": {"charge_kind": charge_kind, "ceiling_seconds": ceiling}}
        ),
        attempt_token=token,
    )
    if not stored:
        raise state.StaleGeneration("the worker lease was lost before the step")
    if ceiling is None:
        result = action(attempt_no, token)
    else:
        result = _run_budgeted_action(
            dsn,
            context,
            step_key=step_key,
            attempt_no=attempt_no,
            token=token,
            charge_kind=charge_kind,
            ceiling=ceiling,
            action=action,
        )
    if os.getenv(FAULT_ENV):
        prefixes = [item.strip() for item in os.getenv(FAULT_ENV, "").split(",") if item.strip()]
        if any(step_key.startswith(prefix) for prefix in prefixes):
            os._exit(70)
    recorded = state.record_attempt(
        dsn,
        context.job_id,
        stage="execute",
        step_key=step_key,
        attempt_no=attempt_no,
        generation=context.generation,
        input_digest=input_digest,
        status="completed",
        result=result,
        container_id=result.get("container_id") if isinstance(result, dict) else None,
        attempt_token=token,
    )
    if not recorded:
        raise state.StaleGeneration("the worker lease was lost before the result")
    return result, False


def _run_budgeted_action(
    dsn: str,
    context: ExecutionContext,
    *,
    step_key: str,
    attempt_no: int,
    token: str,
    charge_kind: str,
    ceiling: float,
    action: Callable[[int, str], Any],
) -> Any:
    """Run one container step under its budget ceiling and always charge it.

    The ceiling is visible to the step through ``context.step_ceiling_seconds``
    and caps its container hard timeout. After the container exits, whether
    the step completed, timed out, hit a limit or raised, the elapsed time is
    charged in an independent short transaction. A charge failure never masks
    the step's own exception.
    """
    context.step_ceiling_seconds = ceiling
    started = STEP_CLOCK()
    failure: BaseException | None = None
    try:
        return action(attempt_no, token)
    except BaseException as error:
        failure = error
        raise
    finally:
        context.step_ceiling_seconds = None
        elapsed = STEP_CLOCK() - started
        try:
            _charge_step_budget(
                dsn,
                context,
                step_key=step_key,
                attempt_no=attempt_no,
                charge_kind=charge_kind,
                elapsed_seconds=elapsed,
            )
            # The archived budget snapshot and report.budget must describe
            # the ledger after this charge, rebuilt from the family charges.
            family_id = _budget_family_id(context)
            assert family_id is not None
            context.budget_summary = state.family_budget_summary(
                dsn, family_id
            )
        except state.StaleGeneration:
            if failure is None:
                raise
            logger.warning(
                "budget charge lost lease after step %s raised %s",
                step_key,
                type(failure).__name__,
            )
        except (state.StateError, psycopg.Error) as charge_error:
            if failure is None:
                raise ExecutionFailed(
                    "RUN_INCOMPLETE",
                    f"the {step_key} budget charge could not be recorded: "
                    f"{charge_error}",
                ) from charge_error
            logger.warning(
                "budget charge failed after step %s raised %s: %s",
                step_key,
                type(failure).__name__,
                charge_error,
            )


def _journal_path(
    run_root: Path, step_key: str, attempt_no: int, generation: int
) -> Path:
    return (
        run_root
        / "steps"
        / _safe_name(step_key)
        / f"generation-{generation}"
        / f"attempt-{attempt_no}"
        / "run.json"
    )


def _prepare_run_parent(
    path: Path, run_root: Path, label: str
) -> Path:
    """Create ``path.parent`` only after proving it stays inside the run root.

    The check runs before ``mkdir`` so a symlinked parent is rejected without
    creating anything outside. ``resolve(strict=False)`` follows every existing
    ancestor, which is exactly the "deepest existing ancestor" rule used by
    ``_inside_run_root``. The parent is resolved again after creation to close
    the window between the check and the ``mkdir``.
    """
    root = run_root.resolve()
    try:
        before = path.parent.resolve()
    except (OSError, RuntimeError) as error:
        raise ExecutionFailed(
            "EVIDENCE_WRITE_FAILED", f"{label} cannot be resolved: {error}"
        ) from error
    if not _inside_run_root(before, root, label):
        raise ExecutionFailed(
            "EVIDENCE_WRITE_FAILED", f"{label} escaped the run root"
        )
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
    except OSError as error:
        raise ExecutionFailed(
            "EVIDENCE_WRITE_FAILED", f"{label} parent cannot be created: {error}"
        ) from error
    try:
        after = path.parent.resolve()
    except (OSError, RuntimeError) as error:
        raise ExecutionFailed(
            "EVIDENCE_WRITE_FAILED", f"{label} cannot be resolved: {error}"
        ) from error
    if not _inside_run_root(after, root, label):
        raise ExecutionFailed(
            "EVIDENCE_WRITE_FAILED", f"{label} escaped the run root"
        )
    return after


def _write_journal(
    run_root: Path,
    step_key: str,
    attempt_no: int,
    generation: int,
    payload: Mapping[str, Any],
    *,
    anchor: Path | None = None,
) -> Path:
    path = _journal_path(run_root, step_key, attempt_no, generation)
    trusted_anchor = anchor if anchor is not None else run_root
    scope_root = (
        run_root
        / "steps"
        / _safe_name(step_key)
        / f"generation-{generation}"
    )
    descriptor, parent = _open_run_parent_fd(
        trusted_anchor,
        path,
        "journal path",
        scope_root=scope_root,
    )
    try:
        secret = _journal_secret(create=True, run_root=run_root)
        if secret is None:
            raise ExecutionFailed(
                "EVIDENCE_WRITE_FAILED", "journal secret is unavailable"
            )
        document = dict(payload)
        document["hmac"] = _journal_hmac(document, secret)
        fileio.write_regular_file_atomic(
            path.name,
            json.dumps(document, ensure_ascii=False, sort_keys=True).encode(
                "utf-8"
            ),
            mode=0o600,
            dir_fd=descriptor,
            parent_path=parent,
        )
    except fileio.UnsafeFileError as error:
        raise ExecutionFailed(
            "EVIDENCE_WRITE_FAILED", f"cannot write journal: {error.message}"
        ) from error
    finally:
        os.close(descriptor)
    return path


def _find_reusable_journal(
    dsn: str,
    context: ExecutionContext,
    *,
    step_key: str,
    plan_digest: str,
    input_digest: str | None,
    verify: Callable[[Mapping[str, Any]], bool],
) -> dict[str, Any] | None:
    """Return a journal only when database provenance proves it is ours.

    The run root is treated as untrusted. Its files alone must never decide
    that a result is reused: the matching attempts row supplies the generation,
    attempt number, container id and one-time token, and the HMAC key lives
    outside ``DATACON_RUN_ROOT``.
    """
    rows = state.attempts_for_step_across_generations(
        dsn, context.job_id, stage="execute", step_key=step_key
    )
    if not rows:
        return None
    secret = _journal_secret(create=False, run_root=_work_root(context))
    if secret is None:
        return None
    run_root = _work_root(context)
    for row in rows:
        if row["status"] not in ("started", "completed"):
            continue
        if input_digest is not None and row.get("input_digest") != input_digest:
            continue
        token = row.get("attempt_token")
        if not isinstance(token, str) or not token:
            continue
        path = _journal_path(
            run_root, step_key, row["attempt_no"], row["generation"]
        )
        if path.is_symlink() or not path.is_file():
            continue
        data = _read_run_file_bounded(path, max_bytes=_JOURNAL_MAX_BYTES)
        if data is None:
            continue
        try:
            payload = json.loads(data.decode("utf-8"))
        except (ValueError, UnicodeError):
            continue
        if not isinstance(payload, dict):
            continue
        try:
            if payload.get("job_id") != context.job_id_text:
                continue
            if payload.get("generation") != row["generation"]:
                continue
            if payload.get("attempt_no") != row["attempt_no"]:
                continue
            if payload.get("plan_digest") != plan_digest:
                continue
            if payload.get("input_digest") != row.get("input_digest"):
                continue
            if payload.get("attempt_token") != token:
                continue
            if payload.get("container_id") != row.get("container_id"):
                continue
            body_hmac = payload.get("hmac")
            if not isinstance(body_hmac, str) or not hmac.compare_digest(
                body_hmac, _journal_hmac(payload, secret)
            ):
                continue
            if payload.get("status") not in (
                "completed",
                "build_failed",
                "timeout",
                "resource_limited",
            ):
                continue
            if verify(payload):
                return payload
        except (OSError, ValueError, KeyError, TypeError):
            continue
    return None


def _write_run_file(
    run_root: Path,
    path: Path,
    data: bytes,
    mode: int,
    *,
    scope_root: Path | None = None,
    anchor: Path | None = None,
) -> None:
    """Write a file under a generation scope without following a symlink.

    The parent is opened from the trusted run-root anchor one component at a
    time. The leaf open, write, chmod and replace all use the verified
    directory descriptor, so neither a pre-existing symlink nor a parent
    renamed after the check can redirect the write outside the generation.
    """
    trusted_anchor = anchor if anchor is not None else run_root
    descriptor, parent = _open_run_parent_fd(
        trusted_anchor,
        path,
        "run evidence path",
        scope_root=scope_root,
    )
    try:
        fileio.write_regular_file(
            path.name,
            data,
            mode=mode,
            dir_fd=descriptor,
            parent_path=parent,
        )
        # A parent swapped after the pre-write check cannot redirect the
        # descriptor write, but the operation is still reported as failed so
        # the worker does not treat a moved directory as the approved scope.
        fileio._assert_dir_fd_matches_parent(descriptor, parent)
    except fileio.UnsafeFileError as error:
        raise ExecutionFailed(
            "EVIDENCE_WRITE_FAILED", f"cannot write run evidence: {error.message}"
        ) from error
    finally:
        os.close(descriptor)


def _persist_build(
    dsn: str,
    context: ExecutionContext,
    result: BuildResult,
    attempt_no: int,
    token: str,
    *,
    staged_materials: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    run_root = _work_root(context)
    generation_root = _generation_root(context)
    directory = generation_root / "build" / result.version
    _prepare_run_directory(
        context.run_root, directory, "build evidence directory",
        scope_root=generation_root,
    )
    log_path = directory / "build.log"
    _write_run_file(
        run_root,
        log_path,
        result.log,
        0o600,
        scope_root=generation_root,
        anchor=context.run_root,
    )
    artifact_path = directory / "parser"
    outputs_map: dict[str, str] = {}
    output_digests: dict[str, str] = {}
    if result.outputs:
        primary_archive_path: str | None = None
        primary_output = result.metadata.get("primary_output")
        for output in result.outputs:
            try:
                archive_relative = jsonutil.safe_relative_path(
                    output.archive_path, "build output archive path"
                )
            except ValueError as error:
                raise ExecutionFailed(
                    "BUILD_FAILED", f"unusable build output archive path: {error}"
                ) from error
            output_path = directory / PurePosixPath(archive_relative)
            _write_run_file(
                run_root,
                output_path,
                output.data,
                0o555,
                scope_root=generation_root,
                anchor=context.run_root,
            )
            if _digest(output.data) != output.digest:
                raise ExecutionFailed(
                    "BUILD_FAILED",
                    f"build output {output.relative_path!r} digest changed",
                )
            outputs_map[output.relative_path] = str(
                output_path.relative_to(run_root)
            )
            output_digests[output.relative_path] = output.digest
            if output.relative_path == primary_output:
                primary_archive_path = str(output_path.relative_to(run_root))
        if primary_archive_path is None:
            raise ExecutionFailed(
                "BUILD_FAILED", "primary build output is missing from the result"
            )
        artifact_path = run_root / PurePosixPath(primary_archive_path)
    elif result.artifact is not None and result.artifact_digest is not None:
        _write_run_file(
            run_root,
            artifact_path,
            result.artifact,
            0o555,
            scope_root=generation_root,
            anchor=context.run_root,
        )
        if _digest(result.artifact) != result.artifact_digest:
            raise ExecutionFailed("BUILD_FAILED", "build artifact digest changed")
    provenance_face_path: Path | None = None
    provenance_face_digest: str | None = None
    if (
        result.provenance_face is not None
        and len(result.provenance_face) > MAX_PROVENANCE_FACE_BYTES
    ):
        raise ExecutionFailed(
            build_provenance.BUILD_PROVENANCE_MISSING,
            f"provenance face exceeds {MAX_PROVENANCE_FACE_BYTES} bytes "
            f"({len(result.provenance_face)} bytes)",
        )
    if (
        result.provenance_face is not None
        and result.provenance_face
        and isinstance(result.provenance_face_name, str)
        and result.provenance_face_name in build_provenance.FACE_FILENAMES.values()
    ):
        face_dir = directory / "build_provenance"
        _prepare_run_directory(
            context.run_root,
            face_dir,
            "build provenance directory",
            scope_root=generation_root,
        )
        provenance_face_path = face_dir / result.provenance_face_name
        _write_run_file(
            run_root,
            provenance_face_path,
            result.provenance_face,
            0o600,
            scope_root=generation_root,
            anchor=context.run_root,
        )
        provenance_face_digest = _digest(result.provenance_face)
    updated = state.record_attempt(
        dsn,
        context.job_id,
        stage="execute",
        step_key=f"build:{result.version}",
        attempt_no=attempt_no,
        generation=context.generation,
        input_digest=context.plan["analysis_digest"],
        status="started",
        container_id=result.container_id,
        attempt_token=token,
    )
    if not updated:
        raise state.StaleGeneration("the worker lease was lost after the build")
    files_map: dict[str, Any] = {
        "log": str(log_path.relative_to(run_root)),
        "artifact": str(artifact_path.relative_to(run_root))
        if artifact_path.is_file()
        else None,
    }
    file_digests_map: dict[str, Any] = {
        "log": _digest(result.log),
        "artifact": result.artifact_digest,
    }
    if outputs_map:
        files_map["outputs"] = outputs_map
        file_digests_map["outputs"] = output_digests
    if provenance_face_path is not None and provenance_face_digest is not None:
        files_map["provenance_face"] = str(provenance_face_path.relative_to(run_root))
        file_digests_map["provenance_face"] = provenance_face_digest
    payload = {
        "tool_id": "sandbox.build",
        "job_id": context.job_id_text,
        "generation": context.generation,
        "attempt_token": token,
        "plan_digest": context.plan_digest,
        "input_digest": context.plan["analysis_digest"],
        "status": result.status,
        "version": result.version,
        "container_id": result.container_id,
        "artifact_digest": result.artifact_digest,
        "attempt_no": attempt_no,
        "files": files_map,
        "file_digests": file_digests_map,
        **result.as_dict(),
    }
    if staged_materials is not None:
        # Bind the build result to the exact bytes copied out of the run root
        # and mounted for this attempt, not just to the case's current files.
        payload["staged_materials"] = dict(staged_materials)
    _write_journal(
        run_root,
        f"build:{result.version}",
        attempt_no,
        context.generation,
        payload,
        anchor=context.run_root,
    )
    return {
        key: value for key, value in payload.items() if key != "attempt_token"
    }


def _persist_replay(
    dsn: str,
    context: ExecutionContext,
    result: ReplayResult,
    attempt_no: int,
    token: str,
    *,
    artifact_digest: str | None = None,
) -> dict[str, Any]:
    run_root = _work_root(context)
    generation_root = _generation_root(context)
    directory = generation_root / "replay" / result.version / result.phase
    _prepare_run_directory(
        context.run_root, directory, "replay evidence directory",
        scope_root=generation_root,
    )
    stdout_path = directory / "stdout.log"
    stderr_path = directory / "stderr.log"
    _write_run_file(
        run_root,
        stdout_path,
        result.stdout,
        0o600,
        scope_root=generation_root,
        anchor=context.run_root,
    )
    _write_run_file(
        run_root,
        stderr_path,
        result.stderr,
        0o600,
        scope_root=generation_root,
        anchor=context.run_root,
    )
    updated = state.record_attempt(
        dsn,
        context.job_id,
        stage="execute",
        step_key=_replay_step(result.version, result.phase),
        attempt_no=attempt_no,
        generation=context.generation,
        input_digest=result.input_digest,
        status="started",
        container_id=result.container_id,
        attempt_token=token,
    )
    if not updated:
        raise state.StaleGeneration("the worker lease was lost after the replay")
    payload = {
        "tool_id": "sandbox.replay",
        "job_id": context.job_id_text,
        "generation": context.generation,
        "attempt_token": token,
        "plan_digest": context.plan_digest,
        "input_digest": result.input_digest,
        "artifact_digest": artifact_digest,
        "status": result.status,
        "version": result.version,
        "phase": result.phase,
        "container_id": result.container_id,
        "signature": result.signature.as_dict() if result.signature else None,
        "attempt_no": attempt_no,
        "files": {
            "stdout": str(stdout_path.relative_to(run_root)),
            "stderr": str(stderr_path.relative_to(run_root)),
        },
        "file_digests": {
            "stdout": _digest(result.stdout),
            "stderr": _digest(result.stderr),
        },
        **result.as_dict(),
    }
    # Keep the build binding authoritative even if a sandbox result happens to
    # carry a same-named metadata field.
    payload["artifact_digest"] = artifact_digest
    _write_journal(
        run_root,
        _replay_step(result.version, result.phase),
        attempt_no,
        context.generation,
        payload,
        anchor=context.run_root,
    )
    return {
        key: value for key, value in payload.items() if key != "attempt_token"
    }


def _replay_step(version: str, phase: str) -> str:
    return f"replay:{version}:{phase}"


def _offline_model_audit(context: ExecutionContext) -> dict[str, Any]:
    """Build the offline model audit record this bundle archives (delta §8).

    The analysis that produced this bundle called no external model, so the
    archive carries the honest offline record: the child job the bundle
    belongs to, the hypothesis-aggregator stage, the provider pinned to
    ``"offline"``, an empty sent-field set (nothing left the control plane)
    and the offline outcome. The record is constructed and validated through
    the model outlet's closed schema and re-verified against its own report
    summary; any failure there is an internal fault no bundle may paper
    over, so it propagates into the caller's existing failure path.
    """
    record = build_model_audit(
        job_id=context.job_id_text,
        stage="hypothesis_aggregator",
        provider="offline",
        allowed_fields=(),
        outcome="offline",
    )
    document = validate_model_audit_document(record)
    verify_model_audit_document(
        document,
        job_id=context.job_id_text,
        report_model_audit=model_audit_summary(document),
    )
    return document


def _intel_source_from_case(case: CaseDefinition) -> IntelSource:
    """Map the case registry's advisory entry to the provider's ``IntelSource``.

    The registry entry (#70) carries the five T15 keys and passes through
    ``CaseDefinition.advisory`` unchanged, so the adapter is a field-by-field
    rename onto the shape the snapshot provider and ``build_intel_documents``
    share. ``source_id`` has no registry anchor of its own; ``"<case>/advisory"``
    names the one advisory entry the case registers.
    """
    advisory = case.advisory
    return IntelSource(
        source_id=f"{case.case_id}/advisory",
        case_id=case.case_id,
        snapshot_path=advisory["path"],
        snapshot_digest=advisory["digest"],
        source_url=advisory["source_url"],
        license=advisory["license"],
        permitted_uses=tuple(advisory["permitted_uses"]),
    )


def _offline_intel_documents(
    context: ExecutionContext,
) -> tuple[IntelDocuments, dict[str, Any]]:
    """Build the offline intel documents this bundle archives (delta §8).

    An offline case's snapshot is the advisory bytes pinned in the case
    material, read through the registry's digest check; no collection was
    ever recorded for them, so the four collection fields stay null and the
    identity comes from the registry's advisory entry alone. The documents
    are constructed and validated through the intel evidence closed schemas
    and re-verified against their own report summary and the frozen plan's
    ``plan.intel``; any disagreement - including a plan whose ``sources`` do
    not include the snapshot's source URL - refuses the archive, and the
    refusal is raised as ``BundleError`` so it converges into the caller's
    existing bundle-failure path instead of escaping the finish functions.
    """
    source = _intel_source_from_case(context.case)
    body = context.case.read_material(source.snapshot_path, source.snapshot_digest)[0]
    # A v2 plan freezes through contracts._intel, which requires the intel
    # summary; a plan without one has no anchor for its snapshot, and the
    # archive refuses rather than writing unanchored intel documents.
    plan_intel = context.plan.get("intel")
    if not isinstance(plan_intel, Mapping):
        raise BundleError(
            "EVIDENCE_INCOMPLETE",
            "the frozen plan carries no intel summary to bind the snapshot to",
        )
    try:
        documents = build_intel_documents(
            None,
            body,
            case_id=source.case_id,
            source_id=source.source_id,
            source_url=source.source_url,
            snapshot_digest=source.snapshot_digest,
            license=source.license,
            permitted_uses=source.permitted_uses,
        )
        report_intel = {
            "snapshot_digest": documents.snapshot["snapshot_digest"],
            "license": documents.snapshot["license"],
            "redirect_chain_digest": documents.snapshot["redirect_chain_digest"],
        }
        verify_intel_documents(
            documents.snapshot,
            documents.license_record,
            case_id=context.case.case_id,
            report_intel=report_intel,
            plan_intel=plan_intel,
        )
    except (IntelEvidenceError, CaseConfigurationError) as error:
        message = getattr(error, "message", str(error))
        raise BundleError(
            "EVIDENCE_INCOMPLETE",
            f"the intel documents could not be bound into this bundle: {message}",
        ) from error
    return documents, report_intel


def _policy_from_context(context: ExecutionContext) -> VerdictPolicy:
    expected_stdout = context.playbook.get("expected_stdout")
    if not isinstance(expected_stdout, dict):
        raise ExecutionBlocked(
            "MATERIAL_MISSING", "the case manifest has no expected stdout assertions"
        )
    for key in ("normal", "candidate_clean"):
        if not isinstance(expected_stdout.get(key), str):
            raise ExecutionBlocked(
                "MATERIAL_MISSING", f"expected stdout assertion {key} is missing"
            )
    return VerdictPolicy(
        signature=context.plan["asan_signature"],
        expected_exit=context.plan["expected_exit"],
        expected_stdout=expected_stdout,
        # Only a reuse validation round (the candidate is a campaign crash
        # seed with no registered clean output) drops the candidate stdout.
        candidate_stdout_checked=getattr(context, "reuse", None) is None,
    )


def _build_report(
    context: ExecutionContext,
    *,
    verdict: str | None,
    verdict_reason: str | None,
    decision: VerdictDecision | None,
    builds: Mapping[str, Mapping[str, Any]],
    runs: Sequence[Mapping[str, Any]],
    probe: Mapping[str, Any] | None,
    evidence_refs: Sequence[str],
    missing: Sequence[str],
    error: str | None = None,
    build_provenance_summary: Mapping[str, Any] | None = None,
    bundle_kind: str = "execution",
) -> tuple[dict[str, Any], str]:
    is_v2 = _is_v2_context(context)
    context_review = getattr(context, "review", None)
    plan_inputs = context.plan.get("inputs")
    report_inputs: dict[str, Any] | None
    if isinstance(plan_inputs, Mapping):
        report_inputs = {
            "candidate": plan_inputs["candidate"],
            "normal": plan_inputs["normal"],
        }
    else:
        report_inputs = None
    effective_verdict = None if (is_v2 and bundle_kind == "campaign") else verdict
    effective_reason = None if (is_v2 and bundle_kind == "campaign") else verdict_reason
    report: dict[str, Any] = {
        "schema_version": contracts.SCHEMA_VERSION_V2 if is_v2 else 1,
        "job_id": context.job_id_text,
        "plan_digest": context.plan_digest,
        "cve_id": context.plan["cve_id"],
        "case_id": context.plan["case_id"],
        "state": effective_verdict,
        "verdict": effective_verdict,
        "reason_code": effective_reason,
        "target": context.job["request"]["target"],
        "versions": context.plan["revisions"],
        "repository": context.plan["repository"],
        "environment": {
            "image": context.image,
            "image_digest": context.plan["image_digest"],
            "platform": context.plan["platform"],
            "toolchain": context.plan["toolchain"],
            "asan_options": context.plan["asan_options"],
            "compile_args": list(context.compile_args),
            "isolation": context.plan["isolation"],
            "probe": probe,
        },
        "budget": (
            dict(context.budget_summary)
            if is_v2 and context.budget_summary
            else context.plan["limits"]
        ),
        "inputs": report_inputs,
        "review": (
            {
                "reviewer_id": context_review["reviewer_id"],
                "decision": context_review["decision"],
                "decided_at": jsonutil.timestamp(context_review["decided_at"]),
                "plan_digest": context_review["plan_digest"],
            }
            if context_review is not None
            else None
        ),
        "signature": context.plan["asan_signature"],
        "builds": [dict(item) for item in builds.values()],
        "replays": [dict(item) for item in runs],
        "rule": decision.as_dict() if decision else None,
        "evidence_refs": list(evidence_refs),
        "missing": list(missing),
        "error": error,
        "evidence_complete": (
            decision is not None and not missing and error is None
        ),
        "cleanup_errors": list(getattr(context, "cleanup_errors", [])),
        "created_at": _utc_now(),
    }
    if is_v2:
        report["bundle_kind"] = bundle_kind
        report["family_id"] = context.plan.get("family_id")
        report["parent_job_id"] = context.plan.get("parent_job_id")
        report["round_no"] = (
            None if bundle_kind == "campaign" else context.plan.get("round_no")
        )
        report["envelope_digest"] = context.plan.get("envelope_digest")
        report["experiment_digest"] = (
            None
            if bundle_kind == "campaign"
            else context.plan.get("experiment_digest")
        )
        report["build_ref"] = (
            None if bundle_kind == "campaign" else context.plan.get("build_ref")
        )
        report["reuse_origin"] = (
            _reuse_origin(context)
            if bundle_kind != "campaign" and getattr(context, "reuse", None) is not None
            else None
        )
        if bundle_kind in ("execution", "campaign"):
            report["build_provenance_rules_version"] = _provenance_rules_version(
                context
            )
            report["build_provenance"] = (
                _normalize_build_provenance_summary(build_provenance_summary)
                if build_provenance_summary is not None
                else _empty_build_provenance_summary(context, comparable=False)
            )
            # Delta §8: report.model_audit is the closed 6-field summary of
            # the model/audit.json archived next to this report. Offline runs
            # write it too (provider pinned to "offline", never omitted) - a
            # report may not describe another provider than the audit in its
            # own bundle. A blocked bundle carries neither the file nor the
            # summary.
            report["model_audit"] = model_audit_summary(
                _offline_model_audit(context)
            )
            # Delta §8: report.intel is the closed three-field summary of the
            # intel/snapshot.json archived next to this report. The same
            # offline construction feeds both, so a report may not describe
            # another snapshot than the one in its own bundle. A blocked
            # bundle carries neither the documents nor the summary.
            report["intel"] = _offline_intel_documents(context)[1]
    return report, render_report_markdown(report)


_REPORT_VERDICTS = frozenset(
    {"REPRODUCED", "NOT_REPRODUCED", "INCONCLUSIVE", "BLOCKED", "FAILED"}
)
_REPORT_REASON_TEXT = re.compile(r"[A-Z0-9_]*")
# report.md is a rendering of report.json. Every dynamic value is replaced by
# an HTML entity before it reaches the document, so a value can never open a
# heading, a code span, a table cell or another "- Verdict:" line. Entities are
# valid inside inline code and table cells and render as the original
# character.
_MARKDOWN_ENTITIES = {
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    '"': "&quot;",
    "`": "&#96;",
    "|": "&#124;",
    "\\": "&#92;",
    "*": "&#42;",
    "_": "&#95;",
    "[": "&#91;",
    "]": "&#93;",
    "#": "&#35;",
}


def _markdown_escape(value: Any) -> str:
    """Render one dynamic value as a single inert Markdown line."""
    text = "" if value is None else str(value)
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    escaped: list[str] = []
    for character in text:
        if character == "\n":
            # Keep the value on one source line. A real newline here could
            # promote injected text to an independent Markdown block.
            escaped.append("&#10;")
        else:
            escaped.append(_MARKDOWN_ENTITIES.get(character, character))
    return "".join(escaped)


def _markdown_code(value: Any) -> str:
    return f"`{_markdown_escape(value)}`"


def _markdown_block(value: Any) -> str:
    """Render untrusted prose as a block that cannot become Markdown syntax.

    Prefixing every physical line with ``> `` means ``line.strip()`` never
    starts with ``- Verdict:`` even when the error text contains an injected
    conclusion line.
    """
    text = "" if value is None else str(value)
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    return "\n".join(
        "> " + _markdown_escape(line) for line in text.split("\n")
    )


def render_report_markdown(report: Mapping[str, Any]) -> str:
    """Render report.md solely from report.json.

    There is exactly one producer for the human-readable report: this
    function. Its only conclusion lines are generated from the validated
    ``verdict`` and ``reason_code`` values; all other report fields are
    escaped before rendering.
    """
    verdict = report.get("verdict")
    verdict_text = (
        verdict
        if isinstance(verdict, str) and verdict in _REPORT_VERDICTS
        else "PENDING"
    )
    reason = report.get("reason_code")
    reason_text = (
        reason
        if isinstance(reason, str) and _REPORT_REASON_TEXT.fullmatch(reason)
        else ""
    )
    environment = report.get("environment")
    if not isinstance(environment, Mapping):
        environment = {}
    versions = report.get("versions")
    if not isinstance(versions, Mapping):
        versions = {}
    builds = report.get("builds")
    if not isinstance(builds, list):
        builds = []
    replays = report.get("replays")
    if not isinstance(replays, list):
        replays = []
    compile_args = environment.get("compile_args")
    if not isinstance(compile_args, (list, tuple)):
        compile_args = []
    evidence_refs = report.get("evidence_refs")
    if not isinstance(evidence_refs, list):
        evidence_refs = []
    missing = report.get("missing")
    if not isinstance(missing, list):
        missing = []
    cleanup_errors = report.get("cleanup_errors")
    if not isinstance(cleanup_errors, list):
        cleanup_errors = []

    lines = [
        "# DataCon evidence report",
        "",
        f"- Job: {_markdown_code(report.get('job_id'))}",
        f"- Plan: {_markdown_code(report.get('plan_digest'))}",
        f"- Case: {_markdown_code(report.get('case_id'))} / "
        f"{_markdown_code(report.get('cve_id'))}",
        f"- Verdict: **{verdict_text}**",
        f"- Reason: `{reason_text}`",
        f"- Image: {_markdown_code(environment.get('image') or environment.get('image_digest'))}",
        f"- Platform: {_markdown_code(environment.get('platform'))}",
        f"- ASan options: {_markdown_code(environment.get('asan_options'))}",
        f"- Compile args: {_markdown_code(' '.join(str(item) for item in compile_args))}",
        "",
        "## Revisions",
        "",
        f"- vulnerable: {_markdown_code(versions.get('vulnerable'))}",
        f"- fixed: {_markdown_code(versions.get('fixed'))}",
        "",
        "## Builds",
        "",
        "| Version | Status | Exit | Artifact |",
        "| --- | --- | ---: | --- |",
    ]
    by_version = {
        item.get("version"): item
        for item in builds
        if isinstance(item, Mapping)
    }
    for version in ("vulnerable", "fixed"):
        build = by_version.get(version, {})
        if not isinstance(build, Mapping):
            build = {}
        lines.append(
            "| {version} | {status} | {exit} | {artifact} |".format(
                version=_markdown_escape(version),
                status=_markdown_escape(build.get("status", "missing")),
                exit=_markdown_escape(build.get("exit_code", "")),
                artifact=_markdown_code(build.get("artifact_digest") or ""),
            )
        )
    lines.extend(
        [
            "",
            "## Replays",
            "",
            "| Version | Phase | Status | Exit | ASan |",
            "| --- | --- | --- | ---: | --- |",
        ]
    )
    for run in replays:
        if not isinstance(run, Mapping):
            continue
        signature = run.get("signature")
        if not isinstance(signature, Mapping):
            signature = {}
        lines.append(
            "| {version} | {phase} | {status} | {exit} | {asan} |".format(
                version=_markdown_escape(run.get("version", "")),
                phase=_markdown_escape(run.get("phase", "")),
                status=_markdown_escape(run.get("status", "")),
                exit=_markdown_escape(run.get("exit_code", "")),
                asan=_markdown_escape(signature.get("error", "")),
            )
        )
    lines.extend(["", "## Rule trace", ""])
    rule = report.get("rule")
    if rule is None:
        lines.append("> (no rule trace)")
    else:
        try:
            rule_text = json.dumps(rule, indent=2, sort_keys=True)
        except (TypeError, ValueError):
            rule_text = str(rule)
        lines.extend(_markdown_block(rule_text).splitlines())
    lines.extend(["", "## Evidence", ""])
    for reference in evidence_refs:
        lines.append(f"- {_markdown_code(reference)}")
    if missing:
        lines.extend(["", "## Missing", ""])
        for item in missing:
            lines.append(f"- {_markdown_code(item)}")
    if report.get("error"):
        lines.extend(["", "## Error", ""])
        lines.extend(_markdown_block(report.get("error")).splitlines())
    if cleanup_errors:
        lines.extend(["", "## Cleanup", ""])
        for item in cleanup_errors:
            lines.append(f"- {_markdown_code(item)}")
    lines.extend(
        [
            "",
            "The report is generated deterministically from persisted runs. "
            "Raw sanitizer logs and metadata are archived next to this report.",
            "",
        ]
    )
    return "\n".join(lines)


def _run_root_path(
    run_root: Path, relative: Any, suffix: str
) -> Path | None:
    """Map a journal-recorded path to a file strictly inside the run root.

    Journal payloads are attacker-writable. Absolute paths, parent traversal
    and paths that resolve outside the run root are rejected instead of being
    joined to ``run_root`` (where an absolute operand would silently replace
    the trusted prefix).
    """
    if not isinstance(relative, str) or not relative:
        return None
    candidate = Path(relative)
    if candidate.is_absolute() or candidate.drive:
        return None
    if relative.startswith(("\\", "//")):
        return None
    if ".." in candidate.parts:
        return None
    if not relative.endswith(suffix):
        return None
    try:
        root = run_root.resolve()
        path = (root / candidate).resolve()
    except (OSError, RuntimeError):
        return None
    if path == root or root not in path.parents:
        return None
    return path


def _verified_run_file(
    run_root: Path,
    payload: Mapping[str, Any],
    key: str,
    suffix: str,
) -> bytes | None:
    files = payload.get("files")
    relative = files.get(key) if isinstance(files, Mapping) else None
    path = _run_root_path(run_root, relative, suffix)
    if path is None:
        return None
    limit = MAX_ARTIFACT_BYTES if suffix == "/parser" else MAX_LOG_BYTES
    data = _read_run_file_bounded(path, max_bytes=limit)
    if data is None:
        return None
    digests = payload.get("file_digests")
    expected = digests.get(key) if isinstance(digests, Mapping) else None
    if expected is not None and _digest(data) != expected:
        return None
    return data


def _verified_build_output(
    run_root: Path,
    payload: Mapping[str, Any],
    relative_output: str,
) -> bytes | None:
    """Read one archived multi-output artifact and verify its recorded digest."""
    files = payload.get("files")
    digests = payload.get("file_digests")
    if not isinstance(files, Mapping) or not isinstance(digests, Mapping):
        return None
    recorded = files.get("outputs")
    expected = digests.get("outputs")
    if not isinstance(recorded, Mapping) or not isinstance(expected, Mapping):
        return None
    relative_path = recorded.get(relative_output)
    expected_digest = expected.get(relative_output)
    suffix = "/" + PurePosixPath(relative_output).name
    path = _run_root_path(run_root, relative_path, suffix)
    if path is None:
        return None
    data = _read_run_file_bounded(path, max_bytes=MAX_ARTIFACT_BYTES)
    if data is None or _digest(data) != expected_digest:
        return None
    return data


def _case_materials(
    context: ExecutionContext,
) -> dict[str, tuple[str, bytes]]:
    manifest = context.case.manifest
    entries: list[tuple[str, str, Any]] = [
        (manifest["harness"], "material_harness", _harness_material_digest(context)),
        (
            manifest["build_recipe"],
            "material_build_recipe",
            _expected_build_recipe_digest(context),
        ),
        (
            manifest["dependencies"],
            "material_dependencies",
            context.plan["dependencies_digest"],
        ),
        (
            context.case.repository["patch"],
            "material_patch",
            context.plan["repository"]["patch_digest"],
        ),
        (
            manifest["versions"]["vulnerable"],
            "material_source_vulnerable",
            context.materials.get(manifest["versions"]["vulnerable"]),
        ),
        (
            manifest["versions"]["fixed"],
            "material_source_fixed",
            context.materials.get(manifest["versions"]["fixed"]),
        ),
    ]
    plan_inputs = context.plan.get("inputs")
    if isinstance(plan_inputs, Mapping):
        entries.extend(
            [
                (
                    context.manifest_case["inputs"]["normal"],
                    "material_input_normal",
                    plan_inputs.get("normal"),
                ),
                (
                    context.manifest_case["inputs"]["candidate"],
                    "material_input_candidate",
                    plan_inputs.get("candidate"),
                ),
            ]
        )
    materials: dict[str, tuple[str, bytes]] = {}
    snapshot = getattr(context, "material_payloads", None)
    reuse = getattr(context, "reuse", None)
    if reuse is not None and isinstance(plan_inputs, Mapping):
        # A reuse round's candidate is the campaign crash seed, never a case
        # file: archive-only recovery (no materialization) must keep it.
        candidate_relative = context.manifest_case["inputs"]["candidate"]
        if not (isinstance(snapshot, Mapping) and candidate_relative in snapshot):
            snapshot = {**(snapshot or {}), candidate_relative: reuse.seed}
    for relative, role, expected in entries:
        if isinstance(snapshot, Mapping) and relative in snapshot:
            data = snapshot[relative]
            if expected is not None and _digest(data) != expected:
                continue
            materials[relative] = (role, data)
            continue
        try:
            data, actual = context.case.read_material(relative, expected)
        except CaseConfigurationError:
            continue
        if expected is not None and actual != expected:
            continue
        materials[relative] = (role, data)
    return materials


def _evidence_artifacts(
    context: ExecutionContext,
    run_root: Path,
    *,
    builds: Mapping[str, Mapping[str, Any]],
    runs: Sequence[Mapping[str, Any]],
    probe: Mapping[str, Any] | None,
    execution_metadata: Mapping[str, Any],
    blocked: bool = False,
) -> dict[str, tuple[str, bytes | Path]]:
    is_v2 = _is_v2_context(context)
    context_admission = getattr(context, "admission", None)
    context_review = getattr(context, "review", None)
    build_spec = _build_spec_from_context(context)
    artifacts: dict[str, tuple[str, bytes | Path]] = {
        "plan.json": ("plan", jsonutil.canonical_bytes(context.plan) + b"\n"),
        "metadata/execution.json": (
            "execution_metadata",
            jsonutil.canonical_bytes(execution_metadata) + b"\n",
        ),
        "metadata/case.json": (
            "case_config",
            jsonutil.canonical_bytes(
                {"case_config": context.case_config}
            )
            + b"\n",
        ),
    }
    if context_admission is not None:
        # A policy round is admitted by its admission, never by the
        # family's first-plan review: the elif below must not fire for it,
        # whatever ExecutionContext carries. On a blocked bundle the
        # admission is dropped too (the bundle contract in evidence.py
        # forbids admission.json there - an admission documents permission
        # for a round that was going to run, not the blocked outcome), so
        # a blocked policy round archives with neither approval document.
        if not blocked:
            artifacts["admission.json"] = (
                "admission",
                jsonutil.canonical_bytes(dict(context_admission)) + b"\n",
            )
    elif context_review is not None:
        artifacts["review.json"] = (
            "review",
            jsonutil.canonical_bytes(
                {
                    "reviewer_id": context_review["reviewer_id"],
                    "decision": context_review["decision"],
                    "plan_digest": context_review["plan_digest"],
                    "decided_at": jsonutil.timestamp(context_review["decided_at"]),
                }
            )
            + b"\n",
        )
    if is_v2:
        if context.envelope is None:
            raise BundleError(
                "EVIDENCE_INCOMPLETE",
                "the approved envelope body is not available to the executor; "
                "refusing to write a placeholder envelope.json",
            )
        artifacts["envelope.json"] = (
            "envelope",
            jsonutil.canonical_bytes(dict(context.envelope)) + b"\n",
        )
        if not context.budget_summary:
            raise BundleError(
                "EVIDENCE_INCOMPLETE",
                "the family budget ledger summary is not available; refusing to "
                "write a placeholder budget/snapshot.json",
            )
        artifacts["budget/snapshot.json"] = (
            "budget_snapshot",
            jsonutil.canonical_bytes(dict(context.budget_summary)) + b"\n",
        )
        if not blocked:
            # Delta §8: an execution or campaign bundle archives the offline
            # model audit under the fixed model_audit role - this round
            # called no model, and the archive says so. A blocked bundle
            # carries no audit (the role is required for execution/campaign
            # only), mirroring the admission gate above.
            artifacts["model/audit.json"] = (
                "model_audit",
                jsonutil.canonical_bytes(_offline_model_audit(context)) + b"\n",
            )
            # Delta §8: an execution or campaign bundle archives the case
            # registry's intel documents under the fixed intel_snapshot /
            # license_record roles - the snapshot is the advisory bytes the
            # case pins (read through the registry's digest check) and the
            # license is the grant the registry recorded; the offline fixed
            # snapshot records no collection, so its collection fields stay
            # null. The documents are re-verified against report.intel and
            # the frozen plan's intel before they enter the archive, so a
            # bundle cannot carry intel its plan does not anchor. A blocked
            # bundle carries neither document, mirroring the audit gate above.
            documents, _ = _offline_intel_documents(context)
            artifacts["intel/snapshot.json"] = (
                "intel_snapshot",
                jsonutil.canonical_bytes(documents.snapshot) + b"\n",
            )
            artifacts["intel/license.json"] = (
                "license_record",
                jsonutil.canonical_bytes(documents.license_record) + b"\n",
            )
    if probe is not None:
        artifacts["metadata/probe.json"] = (
            "probe",
            jsonutil.canonical_bytes(probe) + b"\n",
        )
    for version in ("vulnerable", "fixed"):
        build = builds.get(version)
        if not build:
            continue
        log = _verified_run_file(run_root, build, "log", "/build.log")
        if log is not None:
            artifacts[f"build/{version}/build.log"] = ("build_log", log)
        files = build.get("files")
        outputs = files.get("outputs") if isinstance(files, Mapping) else None
        if isinstance(outputs, Mapping) and outputs:
            for rel_out in sorted(outputs):
                data = _verified_build_output(run_root, build, str(rel_out))
                if data is not None:
                    artifacts[f"build/{version}/{rel_out}"] = (
                        "build_artifact",
                        data,
                    )
        else:
            artifact = _verified_run_file(
                run_root, build, "artifact", "/parser"
            )
            if artifact is not None:
                artifacts[f"build/{version}/parser"] = (
                    "build_artifact",
                    artifact,
                )
        artifacts[f"build/{version}/metadata.json"] = (
            "build_metadata",
            jsonutil.canonical_bytes(dict(build)) + b"\n",
        )
        if is_v2:
            kind = (
                build_spec.get("kind")
                if isinstance(build_spec, Mapping)
                else build.get("build_spec_kind")
            )
            if isinstance(kind, str) and kind in build_provenance.FACE_FILENAMES:
                raw_face = _verified_provenance_face(
                    run_root,
                    build,
                    expected_face_name=build_provenance.FACE_FILENAMES[kind],
                )
                if raw_face:
                    face_entry = build_provenance.archive_face_entry(
                        kind=kind,
                        version=version,
                        raw_face=raw_face,
                    )
                    artifacts[face_entry.path] = (face_entry.role, raw_face)
    for run in runs:
        version = run.get("version", "")
        phase = run.get("phase", "")
        if version not in ("vulnerable", "fixed") or phase not in (
            "normal",
            "candidate_1",
            "candidate_2",
        ):
            continue
        stdout = _verified_run_file(run_root, run, "stdout", "/stdout.log")
        stderr = _verified_run_file(run_root, run, "stderr", "/stderr.log")
        if stdout is not None:
            artifacts[f"replay/{version}/{phase}/stdout.log"] = (
                "replay_stdout" if phase != "normal" else "normal_output",
                stdout,
            )
        if stderr is not None:
            if is_v2:
                role = "normal_error" if phase == "normal" else "asan_log"
            else:
                role = "asan_log" if run.get("signature") else "replay_stderr"
            artifacts[f"replay/{version}/{phase}/stderr.log"] = (role, stderr)
        artifacts[f"replay/{version}/{phase}/metadata.json"] = (
            "replay_metadata",
            jsonutil.canonical_bytes(dict(run)) + b"\n",
        )
    for relative, (role, data) in _case_materials(context).items():
        artifacts[f"materials/{relative}"] = (role, data)
    return artifacts


def _report_evidence_refs(
    artifacts: Mapping[str, Any],
) -> list[str]:
    """Derive the report's document refs from the artifacts actually archived.

    ``report.json``/``report.md`` are always written next to this report;
    ``plan.json``/``review.json``/``admission.json`` and
    ``metadata/execution.json`` are listed only when the writer really
    archives them, so the refs can never name a document the bundle does not
    carry: a policy round (admitted by its admission, review cleared by
    ``_load_context``) lists ``admission.json``, and a blocked policy round
    lists neither approval document. This keeps the refs resolvable in the
    spirit of delta §8 - ``verify_bundle`` does not gate the report's
    top-level ``evidence_refs``, so deriving them from the archived
    artifacts is what keeps them truthful. Other artifacts (envelope,
    budget, ...) stay out: refs name the report, the plan, the approval
    document and the execution metadata only.
    """
    refs = ["report.json", "report.md"]
    for name in (
        "plan.json",
        "review.json",
        "admission.json",
        "metadata/execution.json",
    ):
        if name in artifacts:
            refs.append(name)
    return refs


def _discard_published_bundle(path: str | None) -> None:
    """Best-effort removal of a bundle this generation just published.

    Only a generation-scoped directory is removed. The shared job directory and
    other generations (including the legacy flat ``evidence/<job_id>`` layout)
    are never touched, so a stale worker can clean up after itself without
    racing a newer generation that is about to publish.
    """
    if not path:
        return
    try:
        target = Path(path)
        if not target.name.startswith("generation-"):
            return
        shutil.rmtree(target, ignore_errors=True)
    except OSError:
        pass


def _discard_blocked_bundle(path: str | None) -> None:
    """Best-effort removal of a just-published blocked bundle.

    Only a ``blocked-generation-*`` directory below the evidence root is
    removed. The shared job directory and other evidence are untouched.
    """
    if not path:
        return
    try:
        target = Path(path)
        if not target.name.startswith("blocked-generation-"):
            return
        shutil.rmtree(target, ignore_errors=True)
    except OSError:
        pass


def _blocked_evidence_root(run_root: Path | str | None) -> Path:
    """Resolve the evidence root for a path that has no execution context."""
    raw = Path(os.getenv("DATACON_EVIDENCE_ROOT", ".datacon/evidence")).expanduser()
    if run_root is not None:
        return _outside_run_root(
            raw, Path(run_root), "DATACON_EVIDENCE_ROOT"
        )
    return raw.resolve()


def _blocked_report(
    job: Mapping[str, Any],
    *,
    reason_code: str,
    message: str,
    plan: Mapping[str, Any] | None,
    review: Mapping[str, Any] | None,
    expected_plan_digest: str | None = None,
    schema_version: int = 1,
) -> tuple[dict[str, Any], str | None, dict[str, Any] | None, dict[str, Any] | None]:
    """Build a report for a terminal block that did not reach execution.

    The plan and review are optional. A plan/review pair is included only when
    the plan digest can be re-derived, matches the frozen digest (when the
    caller has one), and the review is bound to that plan. Otherwise the
    bundle records the block without pretending a complete plan existed (an
    expiry can leave only a plan, and submit-time rejection has neither).
    """
    if type(schema_version) is not int or schema_version not in (1, 2):
        # A report-shape error is a bundle error, not a programming ValueError:
        # it must surface with the same typed reason as the rest of the
        # blocked archive path.
        raise BundleError(
            "INVALID_MANIFEST", "blocked report schema_version must be 1 or 2"
        )
    plan_doc: dict[str, Any] | None = dict(plan) if isinstance(plan, Mapping) else None
    plan_digest: str | None = None
    if plan_doc is not None:
        try:
            plan_digest = contracts.plan_digest(plan_doc)
        except (KeyError, TypeError, ValueError, UnicodeError):
            # A legacy/partial plan row cannot be bound to a manifest digest.
            plan_doc = None
            plan_digest = None
        else:
            if (
                expected_plan_digest is not None
                and expected_plan_digest != plan_digest
            ):
                plan_doc = None
                plan_digest = None
    review_doc: dict[str, Any] | None = None
    if plan_doc is not None and isinstance(review, Mapping):
        if (
            review.get("decision") in ("approve", "reject")
            and review.get("plan_digest") == plan_digest
        ):
            review_doc = {
                "reviewer_id": review.get("reviewer_id"),
                "decision": review.get("decision"),
                "plan_digest": review.get("plan_digest"),
                "decided_at": (
                    jsonutil.timestamp(review["decided_at"])
                    if review.get("decided_at") is not None
                    and not isinstance(review.get("decided_at"), str)
                    else review.get("decided_at")
                ),
            }
    request = job.get("request")
    if not isinstance(request, Mapping):
        request = {}
    target = request.get("target")
    if not isinstance(target, Mapping):
        target = {}
    plan_map = plan_doc or {}
    environment = {
        "image": None,
        "image_digest": plan_map.get("image_digest"),
        "platform": plan_map.get("platform"),
        "toolchain": plan_map.get("toolchain"),
        "asan_options": plan_map.get("asan_options"),
        "compile_args": [],
        "isolation": plan_map.get("isolation"),
        "probe": None,
    }
    evidence_refs = ["report.json", "report.md"]
    if plan_doc is not None:
        evidence_refs.append("plan.json")
    if review_doc is not None:
        evidence_refs.append("review.json")
    report: dict[str, Any] = {
        "schema_version": schema_version,
        "job_id": str(job["job_id"]),
        "plan_digest": plan_digest,
        "cve_id": plan_map.get("cve_id") or request.get("cve_id"),
        "case_id": plan_map.get("case_id") or target.get("case_id"),
        "state": "BLOCKED",
        "verdict": "BLOCKED",
        "reason_code": reason_code,
        "target": dict(target),
        "versions": plan_map.get("revisions"),
        "repository": plan_map.get("repository"),
        "environment": environment,
        "budget": plan_map.get("limits") or request.get("limits"),
        "inputs": plan_map.get("inputs"),
        "review": review_doc,
        "signature": plan_map.get("asan_signature"),
        "builds": [],
        "replays": [],
        "rule": None,
        "evidence_refs": evidence_refs,
        "missing": ["execution did not complete"],
        "error": f"{reason_code}: {message}",
        "evidence_complete": False,
        "cleanup_errors": [],
        "created_at": _utc_now(),
    }
    if schema_version == contracts.SCHEMA_VERSION_V2:
        report["bundle_kind"] = "blocked"
    return report, plan_digest, plan_doc, review_doc


def archive_blocked(
    job: Mapping[str, Any],
    *,
    generation: int,
    reason_code: str,
    message: str,
    plan: Mapping[str, Any] | None = None,
    review: Mapping[str, Any] | None = None,
    expected_plan_digest: str | None = None,
    run_root: Path | str | None = None,
    job_contract_version: int | None = None,
) -> tuple[str | None, str | None, str | None]:
    """Archive a terminal block without a lease or execution context.

    This deliberately does not reuse ``_archive``: that helper requires the
    job to be RUNNING/ARCHIVING and fences the write with a live lease. Submit,
    review and analysis blocks have no such lease. The bundle still goes
    through ``write_bundle(verify=verify_bundle)`` so hashes, paths, manifest
    digest and report.md binding are enforced exactly like an execution
    bundle.
    """
    temporary: Path | None = None
    try:
        job_id = str(uuid.UUID(str(job["job_id"])))
        # The job contract version, not the evidence manifest version, decides
        # which reason-code table applies. A v1 job must not start producing
        # v0.2-only terminal codes just because this shared archiver can also
        # serve v2 jobs.
        version = (
            job.get("job_contract_version", 1)
            if job_contract_version is None
            else job_contract_version
        )
        if version not in (1, 2):
            raise BundleError(
                "INVALID_MANIFEST", "job_contract_version must be 1 or 2"
            )
        allowed = reason_allowed_v2 if version == 2 else reason_allowed
        if not isinstance(reason_code, str) or not allowed(
            "BLOCKED", reason_code
        ):
            raise BundleError(
                "INVALID_MANIFEST", f"reason_code {reason_code!r} is not a BLOCKED code"
            )
        evidence_root = _blocked_evidence_root(run_root)
        evidence_root.mkdir(mode=0o755, parents=True, exist_ok=True)
        if evidence_root.is_symlink() or not evidence_root.is_dir():
            raise BundleError("SYMLINK", "evidence root must be a real directory")
        evidence_root.chmod(0o755)
        job_root = evidence_root / job_id
        if job_root.is_symlink():
            raise BundleError("SYMLINK", "evidence job directory is a symlink")
        job_root.mkdir(mode=0o755, parents=True, exist_ok=True)
        if job_root.is_symlink() or not job_root.is_dir():
            raise BundleError(
                "SYMLINK", "evidence job directory must be a real directory"
            )
        job_root.chmod(0o755)
        bundle = job_root / (
            f"blocked-generation-{int(generation)}-{uuid.uuid4().hex}"
        )
        temporary = evidence_root / (
            f".{job_id}.blocked-{uuid.uuid4().hex}"
        )
        report, plan_digest, plan_doc, review_doc = _blocked_report(
            job,
            reason_code=reason_code,
            message=message,
            plan=plan,
            review=review,
            expected_plan_digest=expected_plan_digest,
            schema_version=version,
        )
        artifacts: dict[str, tuple[str, bytes]] = {}
        if plan_doc is not None:
            artifacts["plan.json"] = (
                "plan",
                jsonutil.canonical_bytes(plan_doc) + b"\n",
            )
        if review_doc is not None:
            artifacts["review.json"] = (
                "review",
                jsonutil.canonical_bytes(review_doc) + b"\n",
            )
        info = write_bundle(
            temporary,
            job_id=job_id,
            plan_digest=plan_digest,
            bundle_kind="blocked",
            report=report,
            report_markdown=render_report_markdown(report),
            artifacts=artifacts,
            verdict="BLOCKED",
            verify=verify_bundle,
            dir_mode=0o755,
            file_mode=0o444,
            schema_version=version,
        )
        temporary.rename(bundle)
        return info.manifest_digest, str(bundle.resolve()), None
    except (
        BundleError,
        OSError,
        ValueError,
        KeyError,
        TypeError,
        ExecutionFailed,
    ) as error:
        if temporary is not None:
            shutil.rmtree(temporary, ignore_errors=True)
        detail = getattr(error, "message", None) or str(error)
        return None, None, f"EVIDENCE_WRITE_FAILED: {detail}"


def record_blocked(
    dsn: str,
    job_id: UUID,
    *,
    reason_code: str,
    message: str,
    plan: Mapping[str, Any] | None = None,
    review: Mapping[str, Any] | None = None,
    generation: int | None = None,
    run_root: Path | str | None = None,
) -> bool:
    """Archive a blocked bundle and record it on the job.

    The row must still be BLOCKED at the expected generation. A filesystem or
    verification failure is stamped as FAILED/EVIDENCE_WRITE_FAILED by
    ``state.record_blocked_evidence``, so a blocked job can never be left with
    ``evidence_status='failed'``.
    """
    job = state.load_job(dsn, job_id)
    if job is None or job.get("state") != "BLOCKED":
        return False
    expected_generation = job["generation"] if generation is None else generation
    if job["generation"] != expected_generation:
        return False
    expected_plan_digest = None
    if plan is None:
        plan_row = state.get_plan(dsn, job_id)
        if plan_row is not None:
            plan = plan_row["plan"]
            expected_plan_digest = plan_row["plan_digest"]
    if review is None:
        review_job_id = job_id
        family_id = job.get("family_id")
        if (
            job.get("job_contract_version") == 2
            and job.get("job_kind") in ("campaign", "round")
            and family_id is not None
        ):
            # D36/§8: human reviews live on the family row while the first plan
            # lives on the first child. Look up the family's review so a
            # rejected first child archives review.json and report.review bound
            # by plan_digest; later rounds carry a different plan_digest, so
            # _blocked_report ignores the first-round review automatically.
            review_job_id = (
                UUID(family_id) if isinstance(family_id, str) else family_id
            )
        review = state.get_review(dsn, review_job_id)
    digest, path, error = archive_blocked(
        job,
        generation=expected_generation,
        reason_code=reason_code,
        message=message,
        plan=plan,
        review=review,
        expected_plan_digest=expected_plan_digest,
        run_root=run_root,
        job_contract_version=job.get("job_contract_version", 1),
    )
    recorded = state.record_blocked_evidence(
        dsn,
        job_id,
        generation=expected_generation,
        evidence_digest=digest,
        evidence_path=path,
        evidence_error=error,
        reason_code=reason_code,
    )
    if not recorded:
        # The row changed between the read and the terminal write. Do not
        # leave a bundle that no task record references.
        _discard_blocked_bundle(path)
    return recorded


def _write_v2_bundle_dir(
    target: Path,
    *,
    context: ExecutionContext,
    report: Mapping[str, Any],
    report_markdown: str,
    artifacts: Mapping[str, tuple[str, Any]],
    verdict: str | None,
    dir_mode: int = 0o755,
    file_mode: int = 0o444,
) -> evidence.BundleInfo:
    """Write and verify a v2 evidence bundle directory into ``target``."""
    bundle_kind = report.get("bundle_kind")
    if not isinstance(bundle_kind, str) or bundle_kind not in (
        "execution",
        "blocked",
        "campaign",
    ):
        raise BundleError("INVALID_MANIFEST", "v2 report bundle_kind is invalid")
    if (
        type(report.get("schema_version")) is not int
        or report.get("schema_version") != contracts.SCHEMA_VERSION_V2
    ):
        raise BundleError("INVALID_MANIFEST", "v2 report schema_version must be 2")
    if target.exists() or target.is_symlink():
        raise BundleError("BUNDLE_EXISTS", "temporary bundle path already exists")

    markdown_bytes = report_markdown.encode("utf-8")
    report_verdict = report.get("verdict")
    report_reason = report.get("reason_code")
    if bundle_kind != "campaign":
        if not isinstance(report_verdict, str):
            raise BundleError("INVALID_MANIFEST", "v2 report verdict is invalid")
        evidence._verify_report_markdown(
            markdown_bytes, report_verdict, report_reason
        )

    report_document = dict(report)
    report_document["report_markdown_sha256"] = hashlib.sha256(
        markdown_bytes
    ).hexdigest()
    payloads: dict[str, bytes] = {
        "report.json": jsonutil.canonical_bytes(report_document) + b"\n",
        "report.md": markdown_bytes,
    }
    roles_by_path: dict[str, str] = {
        "report.json": "report_json",
        "report.md": "report_markdown",
    }
    for path, (role, value) in artifacts.items():
        normalized = evidence._normalize_file_path(path)
        if normalized in payloads:
            raise BundleError("INVALID_MANIFEST", f"duplicate bundle file: {path}")
        if role not in evidence.V2_ROLE_NAMES:
            raise BundleError("INVALID_MANIFEST", f"unknown evidence role: {role}")
        payloads[normalized] = evidence._read_artifact(value)
        roles_by_path[normalized] = role

    if len(payloads) > evidence.MAX_FILES:
        raise BundleError("INVALID_MANIFEST", "bundle has too many files")
    for path, data in payloads.items():
        if len(data) > evidence.MAX_FILE_BYTES:
            raise BundleError(
                "FILE_TOO_LARGE", f"bundle file exceeds the size cap: {path}"
            )
    if sum(len(data) for data in payloads.values()) > evidence.MAX_TOTAL_BYTES:
        raise BundleError(
            "FILE_TOO_LARGE", "bundle exceeds the total evidence size cap"
        )

    target.mkdir(mode=dir_mode)
    target.chmod(dir_mode)
    try:
        entries: list[dict[str, Any]] = []
        for path, data in payloads.items():
            destination = target / PurePosixPath(path)
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(data)
            destination.chmod(file_mode)
            entries.append(
                {
                    "path": path,
                    "role": roles_by_path[path],
                    "size_bytes": len(data),
                    "sha256": hashlib.sha256(data).hexdigest(),
                }
            )
        entries.sort(key=lambda item: item["path"])

        effective_verdict = (
            None
            if bundle_kind == "campaign"
            else (verdict if isinstance(verdict, str) else report_verdict)
        )
        manifest: dict[str, Any] = {
            "schema_version": contracts.SCHEMA_VERSION_V2,
            "bundle_kind": bundle_kind,
            "job_id": context.job_id_text,
            "family_id": report.get("family_id"),
            "parent_job_id": report.get("parent_job_id"),
            "round_no": report.get("round_no"),
            "plan_digest": context.plan_digest,
            "envelope_digest": report.get("envelope_digest"),
            "experiment_digest": report.get("experiment_digest"),
            "build_provenance_rules_version": (
                None
                if bundle_kind == "blocked"
                else _provenance_rules_version(context)
            ),
            "verdict": effective_verdict,
            "reason_code": None if bundle_kind == "campaign" else report_reason,
            "created_at": report.get("created_at") or _utc_now(),
            "build_ref": report.get("build_ref"),
            "reuse_origin": report.get("reuse_origin"),
            "files": entries,
        }
        evidence._validate_v2_manifest_header(manifest)
        seen_paths: set[str] = set()
        for entry in entries:
            evidence._validate_entry(entry, seen_paths, evidence.V2_ROLE_NAMES)
            if entry["role"] == build_provenance.BUILD_PROVENANCE_ROLE:
                parts = PurePosixPath(entry["path"]).parts
                if (
                    len(parts) != 4
                    or parts[0] != "build"
                    or parts[1] not in ("vulnerable", "fixed")
                    or parts[2] != "build_provenance"
                    or parts[3] not in build_provenance.FACE_FILENAMES.values()
                ):
                    raise BundleError(
                        "INVALID_MANIFEST",
                        f"build_provenance must live at fixed D39 path, not {entry['path']}",
                    )

        manifest_bytes = evidence.canonical_manifest_bytes(manifest) + b"\n"
        (target / "manifest.json").write_bytes(manifest_bytes)
        (target / "manifest.json").chmod(file_mode)
        evidence._apply_bundle_modes(target, dir_mode=dir_mode, file_mode=file_mode)

        # Every published v2 bundle (full execution, partial FAILED / pre-rule
        # INCONCLUSIVE, blocked, or campaign) must pass the offline verifier.
        verify_bundle(target)
        return evidence.BundleInfo(
            root=target,
            manifest=manifest,
            manifest_digest=evidence.canonical_manifest_digest(manifest),
        )
    except BaseException:
        shutil.rmtree(target, ignore_errors=True)
        raise


def _archive(
    dsn: str,
    context: ExecutionContext,
    *,
    report: Mapping[str, Any],
    report_markdown: str,
    artifacts: Mapping[str, tuple[str, Any]],
    verdict: str | None,
) -> tuple[str | None, str | None, str | None]:
    # A lease/generation failure here must reach the caller so it can return
    # STALE; every filesystem/verification failure is contained below and
    # turned into an evidence error instead of escaping into the workflow.
    try:
        evidence_root = _assert_evidence_root_outside_run_root(context.run_root)
    except ExecutionFailed as error:
        # _finish_blocked/_finish_failed/_archive_only reach this helper after
        # loading a context; never publish a bundle into the run root even on
        # those recovery paths.
        return None, None, f"{error.reason_code}: {error.message}"
    state.mark_archiving(dsn, context.job_id, generation=context.generation)
    # Every generation publishes into its own directory below the job
    # directory. A worker that passed the fence and was then paused can only
    # ever replace its own generation; it can never overwrite a newer
    # generation's evidence path.
    job_root = evidence_root / context.job_id_text
    bundle = job_root / f"generation-{context.generation}"
    temporary = (
        evidence_root
        / f".{context.job_id_text}.generation-{context.generation}.tmp-{uuid.uuid4().hex}"
    )
    backup = (
        job_root
        / f".generation-{context.generation}.old-{uuid.uuid4().hex}"
    )
    try:
        evidence_root.mkdir(mode=0o755, parents=True, exist_ok=True)
        evidence_root.chmod(0o755)
        try:
            final_root = _outside_run_root(
                evidence_root, context.run_root, "DATACON_EVIDENCE_ROOT"
            )
        except ExecutionFailed as error:
            return None, None, f"{error.reason_code}: {error.message}"
        if final_root != evidence_root:
            return (
                None,
                None,
                "EVIDENCE_WRITE_FAILED: evidence root changed after creation",
            )
        if job_root.is_symlink():
            raise BundleError("SYMLINK", "evidence destination is a symlink")
        job_root.mkdir(mode=0o755, parents=True, exist_ok=True)
        job_root.chmod(0o755)
        job_info = job_root.lstat()
        if stat.S_ISLNK(job_info.st_mode) or not stat.S_ISDIR(job_info.st_mode):
            raise BundleError(
                "SYMLINK", "evidence destination is not a directory"
            )
        if bundle.is_symlink():
            raise BundleError("SYMLINK", "evidence generation is a symlink")
        if _is_v2_context(context):
            info = _write_v2_bundle_dir(
                temporary,
                context=context,
                report=report,
                report_markdown=report_markdown,
                artifacts=artifacts,
                verdict=verdict,
                dir_mode=0o755,
                file_mode=0o444,
            )
        else:
            info = write_bundle(
                temporary,
                job_id=context.job_id,
                plan_digest=context.plan_digest,
                report=report,
                report_markdown=report_markdown,
                artifacts=artifacts,
                verdict=verdict,
                # Verify the complete staging directory before it replaces any
                # previously archived bundle. An unverified bundle is never
                # published as evidence.
                verify=verify_bundle,
                dir_mode=0o755,
                file_mode=0o444,
            )
        # Verification can take time. Refuse to publish unless this exact
        # generation still owns an active lease; a stale worker must never
        # replace a newer generation's bundle.
        state.assert_archive_fence(
            dsn, context.job_id, generation=context.generation
        )
        if bundle.exists():
            if bundle.is_dir():
                bundle.rename(backup)
            else:
                bundle.unlink()
        temporary.rename(bundle)
        if backup.exists():
            shutil.rmtree(backup, ignore_errors=True)
        return info.manifest_digest, str(bundle.resolve()), None
    except BundleError as error:
        shutil.rmtree(temporary, ignore_errors=True)
        if backup.exists() and not bundle.exists():
            backup.rename(bundle)
        return None, None, f"{error.reason_code}: {error.message}"
    except OSError as error:
        shutil.rmtree(temporary, ignore_errors=True)
        if backup.exists() and not bundle.exists():
            backup.rename(bundle)
        return None, None, f"EVIDENCE_WRITE_FAILED: {error}"
    except (state.StateError, state.StaleGeneration):
        # The lease disappeared while the bundle was being verified. Remove
        # the staging directory and let the caller return STALE; a stale
        # worker must not touch the published evidence path.
        shutil.rmtree(temporary, ignore_errors=True)
        raise

def _archive_only(dsn: str, context: ExecutionContext) -> ExecutionResult:
    """Recover an ARCHIVING generation without starting any target container.

    The claim after an archive crash advances the generation, so the durable
    attempts and journals belong to previous generations. Only completed,
    digest-verified results are considered; a past execute deadline is
    irrelevant because nothing is executed.
    """
    build_root = _work_root(context)
    rows = state.execution_attempts_across_generations(dsn, context.job_id)
    completed: dict[str, dict[str, Any]] = {}
    for row in rows:
        if row["status"] == "completed" and isinstance(row["result"], dict):
            completed.setdefault(row["step_key"], row["result"])
    rejected: list[str] = []

    def plan_bound(result: Mapping[str, Any], step: str) -> bool:
        if result.get("plan_digest") != context.plan_digest:
            rejected.append(f"{step} belongs to a different frozen plan")
            return False
        return True

    probe = completed.get("sandbox.probe")
    if probe is not None:
        if not isinstance(probe, dict) or not plan_bound(probe, "probe"):
            probe = None
        elif probe.get("status") != "completed":
            probe = None
    v2_build_spec = (
        _build_spec_from_context(context) if _is_v2_context(context) else None
    )
    is_v2_spec = v2_build_spec is not None
    builds: dict[str, dict[str, Any]] = {}
    for version in ("vulnerable", "fixed"):
        result = completed.get(f"build:{version}")
        if result is None:
            continue
        if not isinstance(result, dict) or not plan_bound(
            result, f"build:{version}"
        ):
            continue
        if result.get("input_digest") != context.plan["analysis_digest"]:
            rejected.append(f"build:{version} input does not match the plan")
            continue
        if _reusable_build(
            build_root,
            result,
            check_provenance_face=not is_v2_spec,
            artifact_suffix=_primary_artifact_suffix(context),
        ):
            builds[version] = result
    runs: list[dict[str, Any]] = []
    plan_inputs = context.plan.get("inputs")
    if isinstance(plan_inputs, Mapping):
        for version in ("vulnerable", "fixed"):
            for phase in ("normal", "candidate_1", "candidate_2"):
                result = completed.get(_replay_step(version, phase))
                if result is None:
                    continue
                if not isinstance(result, dict) or not plan_bound(
                    result, _replay_step(version, phase)
                ):
                    continue
                expected_input = (
                    plan_inputs["normal"]
                    if phase == "normal"
                    else plan_inputs["candidate"]
                )
                if result.get("input_digest") != expected_input:
                    rejected.append(
                        f"{version}/{phase} input does not match the approved plan"
                    )
                    continue
                if _reusable_replay(build_root, result):
                    runs.append(result)

    # On v2 with BuildSpec, evaluate provenance BEFORE the generic completeness
    # check so a missing/corrupted/non-comparable provenance face or a
    # plan.compile_flags / freeze-rule violation ALWAYS fails closed as
    # FAILED / BUILD_PROVENANCE_MISSING and NEVER downgrades to INCONCLUSIVE or
    # NOT_REPRODUCED during ARCHIVING recovery.
    provenance_outcome: _ProvenanceCheckOutcome | None = None
    if is_v2_spec:
        assert v2_build_spec is not None
        if len(builds) == 2:
            provenance_outcome = _verify_v2_build_provenance(
                context, build_root, builds
            )
            if not provenance_outcome.comparable:
                return _finish_failed(
                    dsn,
                    context.job_id,
                    context.generation,
                    ExecutionFailed(
                        build_provenance.BUILD_PROVENANCE_MISSING,
                        provenance_outcome.error_detail
                        or "v2 build provenance verification failed",
                    ),
                    context=context,
                    probe=probe,
                    builds=builds,
                    runs=runs,
                    build_provenance_summary=provenance_outcome.report_summary,
                )
        elif len(builds) == 1:
            single_outcome = _verify_v2_single_build_provenance(
                context, build_root, builds
            )
            if not single_outcome.comparable:
                return _finish_failed(
                    dsn,
                    context.job_id,
                    context.generation,
                    ExecutionFailed(
                        build_provenance.BUILD_PROVENANCE_MISSING,
                        single_outcome.error_detail
                        or "v2 single-build provenance verification failed",
                    ),
                    context=context,
                    probe=probe,
                    builds=builds,
                    runs=runs,
                    build_provenance_summary=single_outcome.report_summary,
                )
        else:
            spec_ok, _norm_flags, spec_error = _validate_v2_spec_and_flags(
                context, v2_build_spec
            )
            if not spec_ok:
                return _finish_failed(
                    dsn,
                    context.job_id,
                    context.generation,
                    ExecutionFailed(
                        build_provenance.BUILD_PROVENANCE_MISSING,
                        spec_error,
                    ),
                    context=context,
                    probe=probe,
                    builds=builds,
                    runs=runs,
                    build_provenance_summary=_empty_build_provenance_summary(
                        context, comparable=False
                    ),
                )

    complete = (
        isinstance(probe, dict)
        and len(builds) == 2
        and len(runs) == 6
        and not rejected
    )
    missing: list[str] = list(rejected)
    if not complete:
        if not isinstance(probe, dict):
            missing.append("probe evidence is missing")
        for version in ("vulnerable", "fixed"):
            if version not in builds:
                missing.append(f"{version} build evidence is missing")
        for version in ("vulnerable", "fixed"):
            for phase in ("normal", "candidate_1", "candidate_2"):
                if all(
                    run.get("version") != version or run.get("phase") != phase
                    for run in runs
                ):
                    missing.append(f"{version}/{phase} replay evidence is missing")
        decision = VerdictDecision(
            "INCONCLUSIVE",
            "EVIDENCE_INCOMPLETE",
            "archive-only recovery found incomplete evidence",
            {"priority": list(PRIORITY), "missing": missing},
        )
    else:
        try:
            decision = decide_verdict(
                _policy_from_context(context),
                [_to_observation(run, build_root) for run in runs],
                builds=builds,
                expected_inputs={
                    "vulnerable": context.plan["inputs"]["candidate"],
                    "fixed": context.plan["inputs"]["candidate"],
                },
            )
        except ExecutionFailed as error:
            missing.append(error.message)
            decision = VerdictDecision(
                "INCONCLUSIVE",
                "EVIDENCE_INCOMPLETE",
                error.message,
                {"priority": list(PRIORITY), "missing": missing},
            )
        except ExecutionBlocked as error:
            missing.append(error.message)
            decision = VerdictDecision(
                "INCONCLUSIVE",
                "EVIDENCE_INCOMPLETE",
                error.message,
                {"priority": list(PRIORITY), "missing": missing},
            )

    if not complete:
        # There is no complete execution evidence tree, so no verifiable
        # outcome bundle can be published. Record the honest outcome and keep
        # any verdict already committed by a previous archive.
        reason = "EVIDENCE_INCOMPLETE: " + "; ".join(missing)
        try:
            finished = state.finish_execution(
                dsn,
                context.job_id,
                generation=context.generation,
                state="INCONCLUSIVE",
                reason_code="EVIDENCE_INCOMPLETE",
                verdict=None,
                verdict_reason=None,
                evidence_status="failed",
                evidence_error=reason,
                last_error="archive-only recovery found incomplete evidence",
                stage="failed",
            )
        except (state.StateError, state.StaleGeneration):
            return ExecutionResult("STALE")
        if not finished:
            return ExecutionResult("STALE")
        return ExecutionResult("INCONCLUSIVE", reason_code="EVIDENCE_INCOMPLETE")

    attempt_rows = []
    for row in rows:
        item = {
            key: value for key, value in row.items() if key != "attempt_token"
        }
        for column in ("started_at", "finished_at"):
            if item.get(column) is not None:
                item[column] = jsonutil.timestamp(item[column])
        attempt_rows.append(item)
    # Artifacts first, then the report: the refs must be derived from the
    # documents this writer really archives (SF-2), so a policy round lists
    # its admission instead of a review.json it never carried.
    artifacts = _evidence_artifacts(
        context,
        build_root,
        builds=builds,
        runs=runs,
        probe=probe,
        execution_metadata={
            "job_id": context.job_id_text,
            "plan_digest": context.plan_digest,
            "generation": context.generation,
            "recovered_archive_only": True,
            "probe": probe,
            # Duplicated in report.json for diagnostics. Keep the exact same
            # list shape so the verifier can require byte-level agreement
            # instead of maintaining two unbound copies.
            "builds": [dict(item) for item in builds.values()],
            "replays": [dict(item) for item in runs],
            "attempts": attempt_rows,
        },
    )
    report, report_markdown = _build_report(
        context,
        verdict=decision.verdict,
        verdict_reason=decision.reason_code,
        decision=decision,
        builds=builds,
        runs=runs,
        probe=probe,
        evidence_refs=_report_evidence_refs(artifacts),
        missing=missing,
        build_provenance_summary=(
            provenance_outcome.report_summary
            if provenance_outcome is not None
            else None
        ),
    )
    try:
        digest, path, archive_error = _archive(
            dsn,
            context,
            report=report,
            report_markdown=report_markdown,
            artifacts=artifacts,
            verdict=decision.verdict,
        )
    except (BundleError, OSError) as error:
        archive_error = f"EVIDENCE_WRITE_FAILED: {error}"
        digest = path = None
    except (state.StateError, state.StaleGeneration):
        return ExecutionResult("STALE")
    if archive_error is not None:
        try:
            finished = state.finish_execution(
                dsn,
                context.job_id,
                generation=context.generation,
                state="FAILED",
                reason_code="EVIDENCE_WRITE_FAILED",
                verdict=None,
                verdict_reason=None,
                evidence_status="failed",
                evidence_error=archive_error,
                last_error="evidence bundle could not be written during archive recovery",
                stage="failed",
            )
        except (state.StateError, state.StaleGeneration):
            return ExecutionResult("STALE")
        if not finished:
            return ExecutionResult("STALE")
        return ExecutionResult(
            "FAILED",
            verdict=None,
            verdict_reason=None,
            reason_code="EVIDENCE_WRITE_FAILED",
        )
    final_state = decision.verdict
    reason_code = (
        None
        if final_state in ("REPRODUCED", "NOT_REPRODUCED")
        else decision.reason_code
    )
    try:
        finished = state.finish_execution(
            dsn,
            context.job_id,
            generation=context.generation,
            state=final_state,
            reason_code=reason_code,
            verdict=decision.verdict,
            verdict_reason=decision.reason_code,
            evidence_digest=digest,
            evidence_path=path,
            evidence_status="archived",
            stage="done",
        )
    except (state.StateError, state.StaleGeneration):
        # The bundle was published but the terminal row was not committed.
        # Remove only this generation's directory so it cannot be cited as
        # evidence for a state the database never accepted.
        _discard_published_bundle(path)
        return ExecutionResult("STALE")
    if not finished:
        _discard_published_bundle(path)
        return ExecutionResult("STALE")
    return ExecutionResult(
        final_state,
        verdict=decision.verdict,
        verdict_reason=decision.reason_code,
        evidence_digest=digest,
        evidence_path=path,
        reason_code=reason_code,
    )


def _finish_evidence_path_failure(
    dsn: str,
    job_id: UUID,
    generation: int,
    error: ExecutionFailed,
) -> ExecutionResult:
    """Commit FAILED/EVIDENCE_WRITE_FAILED without archiving any bundle.

    The evidence destination itself is untrusted in this branch, so the
    failure must stay visible through ``status.evidence.error`` rather than
    being written into the run root or silently dropped.
    """
    try:
        finished = state.finish_execution(
            dsn,
            job_id,
            generation=generation,
            state="FAILED",
            reason_code=error.reason_code,
            verdict=None,
            verdict_reason=None,
            evidence_status="failed",
            evidence_error=f"{error.reason_code}: {error.message}",
            last_error=error.message,
            stage="failed",
        )
    except (state.StateError, state.StaleGeneration):
        return ExecutionResult("STALE")
    if not finished:
        return ExecutionResult("STALE")
    return ExecutionResult("FAILED", reason_code=error.reason_code)


# ---------------------------------------------------------------------------
# T12 B (改9): the campaign child - one dual-version build, one libFuzzer
# search, a campaign bundle and a COMPLETED terminal. Never a verdict.
# ---------------------------------------------------------------------------

CAMPAIGN_FUZZ_STEP = "campaign.fuzz"
#: Seconds kept between the fuzzer's own ``-max_total_time`` and the
#: container hard timeout for start-up, the crash copy and the release.
FUZZ_STARTUP_GRACE_SECONDS = 30.0


@dataclass(frozen=True)
class _CampaignPreflight:
    harness_pair: dict[str, str]
    corpus: tuple[tuple[str, bytes], ...]
    seed_corpus_digest: str
    max_len: int
    fuzzer_output: str
    parser_output: str


def _campaign_outputs(context: ExecutionContext) -> tuple[str, str]:
    """Return the plan's ``(parser, fuzzer)`` output paths or block the plan."""
    spec = _build_spec_from_context(context)
    raw_outputs = spec.get("outputs") if isinstance(spec, Mapping) else None
    if not isinstance(raw_outputs, list):
        raise ExecutionBlocked(
            "PLAN_MISMATCH", "a campaign plan requires build_spec.outputs"
        )
    by_name: dict[str, str] = {}
    for index, raw in enumerate(raw_outputs):
        try:
            relative = build_provenance.validate_build_spec_output_path(raw, index)[0]
        except (TypeError, ValueError) as error:
            raise ExecutionBlocked("PLAN_MISMATCH", str(error)) from error
        by_name.setdefault(PurePosixPath(relative).name, relative)
    parser = by_name.get(fuzz_rules.PARSER_OUTPUT)
    fuzzer = by_name.get(fuzz_rules.FUZZER_OUTPUT)
    if (
        parser is None
        or fuzzer is None
        or len(raw_outputs) != 2
        or set(by_name) != {fuzz_rules.PARSER_OUTPUT, fuzz_rules.FUZZER_OUTPUT}
    ):
        raise ExecutionBlocked(
            "PLAN_MISMATCH",
            "a campaign build_spec.outputs must list both the replay parser and "
            "the fuzzer (delta §5 改9)",
        )
    return parser, fuzzer


def _campaign_preflight(
    context: ExecutionContext, materials_dir: Path
) -> _CampaignPreflight:
    """Every campaign check that must pass before any container exists.

    The harness/shim pair is proven again on the exact bytes that will be
    mounted for the build (delta §2: the executor re-checks even after
    admission), the fuzz image must be the approved toolchain image, and the
    registered seed corpus must match the envelope and the §5 ceilings.
    """
    envelope = context.envelope
    if not isinstance(envelope, Mapping) or envelope.get("mode") != "guided":
        raise ExecutionBlocked(
            "ENVELOPE_VIOLATION", "a campaign requires an approved guided envelope"
        )
    if context.plan.get("inputs") is not None:
        raise ExecutionBlocked("PLAN_MISMATCH", "a campaign plan must have inputs=null")
    parser_output, fuzzer_output = _campaign_outputs(context)
    manifest = context.case.manifest
    harness_relative = manifest["harness"]
    harness_bytes = _read_run_file_bounded(
        materials_dir / Path(harness_relative), max_bytes=MAX_MATERIAL_BYTES
    )
    shim_bytes = _read_run_file_bounded(
        materials_dir / fuzz_rules.FUZZ_SHIM_STAGED_NAME,
        max_bytes=MAX_MATERIAL_BYTES,
    )
    try:
        if context.plan.get("harness_digest") != envelope.get("harness_digest"):
            raise fuzz_rules.HarnessRejected(
                "PLAN_HARNESS_MISMATCH",
                "the plan harness_digest is not the approved envelope harness_digest",
            )
        harness_pair = fuzz_rules.verify_frozen_harness(
            harness_bytes=harness_bytes,
            registered_harness_digest=str(context.materials.get(harness_relative)),
            envelope_harness_digest=envelope.get("harness_digest"),
            shim_bytes=shim_bytes,
        )
    except fuzz_rules.HarnessRejected as error:
        raise ExecutionBlocked(
            error.reason_code, error.message, {"sub_reason": error.sub_reason}
        ) from error
    if envelope.get("fuzz_image_digest") != context.plan.get("image_digest"):
        raise ExecutionBlocked(
            "POLICY_DENIED",
            "the campaign fuzzes in the approved toolchain image only; an "
            "independent fuzz image is not available to this executor",
            {"sub_reason": "FUZZ_IMAGE_NOT_TOOLCHAIN"},
        )
    try:
        registry = load_registry(str(context.case_root))
        ceilings = registry.exploration_ceilings(context.plan["case_id"])
    except CaseConfigurationError as error:
        raise ExecutionBlocked(error.reason_code, error.message) from error
    try:
        entries = fuzz_rules.registered_seed_corpus(
            ceilings,
            manifest_case=context.manifest_case,
            materials=context.materials,
        )
    except ValueError as error:
        raise ExecutionBlocked(
            "MATERIAL_MISSING", f"the registered seed corpus is invalid: {error}"
        ) from error
    sizes: list[int] = []
    for entry in entries:
        try:
            path = jsonutil.resolve_inside(Path(context.case.material_root), entry.path)
            info = path.lstat()
        except (OSError, ValueError) as error:
            raise ExecutionBlocked(
                "MATERIAL_MISSING", f"seed {entry.name} is not readable: {error}"
            ) from error
        if not stat.S_ISREG(info.st_mode):
            raise ExecutionBlocked(
                "MATERIAL_MISSING", f"seed {entry.name} is not a regular file"
            )
        sizes.append(info.st_size)
    try:
        fuzz_rules.check_corpus_limits(sizes)
    except fuzz_rules.CorpusPolicyDenied as error:
        raise ExecutionBlocked(
            error.reason_code, error.message, {"sub_reason": error.sub_reason}
        ) from error
    corpus: list[tuple[str, bytes]] = []
    for entry in entries:
        try:
            data, _actual = context.case.read_material(entry.path, entry.digest)
        except CaseConfigurationError as error:
            raise ExecutionBlocked(error.reason_code, error.message) from error
        corpus.append((entry.name, data))
    corpus_digest = fuzz_rules.seed_corpus_digest(entries)
    if corpus_digest != envelope.get("seed_corpus_digest"):
        raise ExecutionBlocked(
            "ENVELOPE_VIOLATION",
            "the registered seed corpus differs from the approved seed_corpus_digest",
            {"sub_reason": "SEED_CORPUS_MISMATCH"},
        )
    limits = envelope.get("mutation_limits")
    max_len = limits.get("max_input_bytes") if isinstance(limits, Mapping) else None
    if type(max_len) is not int or max_len < 1:
        raise ExecutionBlocked(
            "ENVELOPE_VIOLATION", "a campaign requires mutation_limits.max_input_bytes >= 1"
        )
    return _CampaignPreflight(
        harness_pair=harness_pair,
        corpus=tuple(corpus),
        seed_corpus_digest=corpus_digest,
        max_len=max_len,
        fuzzer_output=fuzzer_output,
        parser_output=parser_output,
    )


def _build_output_file(
    context: ExecutionContext, build: Mapping[str, Any], relative_output: str
) -> tuple[Path, str]:
    """Return the trusted run-root path and digest of one recorded build output."""
    files = build.get("files")
    digests = build.get("file_digests")
    recorded = files.get("outputs") if isinstance(files, Mapping) else None
    expected = digests.get("outputs") if isinstance(digests, Mapping) else None
    if not isinstance(recorded, Mapping) or not isinstance(expected, Mapping):
        raise ExecutionFailed(
            "BUILD_FAILED", f"the build did not record its {relative_output} output"
        )
    path = _run_root_path(
        _work_root(context),
        recorded.get(relative_output),
        "/" + PurePosixPath(relative_output).name,
    )
    digest = expected.get(relative_output)
    if path is None or not isinstance(digest, str):
        raise ExecutionFailed(
            "BUILD_FAILED", f"the build did not record its {relative_output} output"
        )
    return path, digest


def _fuzz_input_digest(
    fuzzer_digest: str, preflight: _CampaignPreflight, rng_seed: int
) -> str:
    return jsonutil.digest_json(
        {
            "fuzzer": fuzzer_digest,
            "seed_corpus_digest": preflight.seed_corpus_digest,
            "harness_digest": preflight.harness_pair,
            "rng_seed": rng_seed,
            "max_len": preflight.max_len,
        }
    )


def _stage_fuzz_files(
    context: ExecutionContext,
    fuzzer_path: Path,
    fuzzer_digest: str,
    corpus: Sequence[tuple[str, bytes]],
    label: str,
) -> tuple[Path, Path, Path]:
    """Copy the fuzzer and the seed corpus outside the run root, re-hashed."""
    directory = _new_staging_directory(context, label)
    try:
        data = _read_run_file_bounded(fuzzer_path, max_bytes=MAX_ARTIFACT_BYTES)
        if data is None or _digest(data) != fuzzer_digest:
            raise ExecutionBlocked(
                "PLAN_MISMATCH", "the built fuzzer changed before fuzzing"
            )
        staged_fuzzer = _write_staged_file(directory, "fuzzer", data, 0o555)
        corpus_dir = directory / "corpus"
        for name, seed in corpus:
            _write_staged_file(directory, f"corpus/{name}", seed, 0o444)
        _make_staging_tree_readable(directory)
        if _read_run_file_bounded(staged_fuzzer, max_bytes=MAX_ARTIFACT_BYTES) != data:
            raise ExecutionBlocked(
                "PLAN_MISMATCH", "the staged fuzzer does not match the build"
            )
        for name, seed in corpus:
            if _read_run_file_bounded(corpus_dir / name, max_bytes=MAX_MATERIAL_BYTES) != seed:
                raise ExecutionBlocked(
                    "MATERIAL_MISSING", f"staged seed {name} does not match"
                )
        return directory, staged_fuzzer, corpus_dir
    except (ExecutionBlocked, ExecutionFailed):
        _discard_staging(directory)
        raise
    except OSError as error:
        _discard_staging(directory)
        raise ExecutionFailed(
            "EVIDENCE_WRITE_FAILED", f"cannot stage the fuzz inputs: {error}"
        ) from error
    except BaseException:
        _discard_staging(directory)
        raise


def _persist_fuzz(
    dsn: str,
    context: ExecutionContext,
    result: FuzzResult,
    attempt_no: int,
    token: str,
    *,
    input_digest: str,
    fuzzer_digest: str,
) -> dict[str, Any]:
    run_root = _work_root(context)
    generation_root = _generation_root(context)
    directory = generation_root / "fuzz"
    _prepare_run_directory(
        context.run_root, directory / "crashes", "fuzz evidence directory",
        scope_root=generation_root,
    )
    log_path = directory / "fuzz.log"
    _write_run_file(
        run_root, log_path, result.log, 0o600,
        scope_root=generation_root, anchor=context.run_root,
    )
    crash_files: list[str] = []
    crash_digests: list[str] = []
    for index, data in enumerate(result.crashes):
        path = directory / "crashes" / f"crash-{index:03d}.bin"
        _write_run_file(
            run_root, path, data, 0o600,
            scope_root=generation_root, anchor=context.run_root,
        )
        crash_files.append(str(path.relative_to(run_root)))
        crash_digests.append(_digest(data))
    updated = state.record_attempt(
        dsn,
        context.job_id,
        stage="execute",
        step_key=CAMPAIGN_FUZZ_STEP,
        attempt_no=attempt_no,
        generation=context.generation,
        input_digest=input_digest,
        status="started",
        container_id=result.container_id,
        attempt_token=token,
    )
    if not updated:
        raise state.StaleGeneration("the worker lease was lost after the fuzz search")
    payload = {
        "tool_id": "sandbox.fuzz",
        "job_id": context.job_id_text,
        "generation": context.generation,
        "attempt_token": token,
        "plan_digest": context.plan_digest,
        "input_digest": input_digest,
        "fuzzer_digest": fuzzer_digest,
        "attempt_no": attempt_no,
        "files": {"log": str(log_path.relative_to(run_root)), "crashes": crash_files},
        "file_digests": {"log": _digest(result.log), "crashes": crash_digests},
        **result.as_dict(),
    }
    _write_journal(
        run_root, CAMPAIGN_FUZZ_STEP, attempt_no, context.generation, payload,
        anchor=context.run_root,
    )
    return {key: value for key, value in payload.items() if key != "attempt_token"}


def _fuzz_files(
    run_root: Path, payload: Mapping[str, Any]
) -> tuple[bytes, list[bytes]] | None:
    """Read back a fuzz journal's log and crash files, digest-checked."""
    files = payload.get("files")
    digests = payload.get("file_digests")
    if not isinstance(files, Mapping) or not isinstance(digests, Mapping):
        return None
    log_path = _run_root_path(run_root, files.get("log"), "/fuzz.log")
    if log_path is None:
        return None
    log = _read_run_file_bounded(log_path, max_bytes=MAX_LOG_BYTES)
    if log is None or _digest(log) != digests.get("log"):
        return None
    crash_files = files.get("crashes")
    crash_digests = digests.get("crashes")
    if (
        not isinstance(crash_files, list)
        or not isinstance(crash_digests, list)
        or len(crash_files) != len(crash_digests)
    ):
        return None
    crashes: list[bytes] = []
    for relative, expected in zip(crash_files, crash_digests):
        path = _run_root_path(run_root, relative, ".bin")
        if path is None:
            return None
        data = _read_run_file_bounded(path, max_bytes=fuzz_rules.CORPUS_MAX_FILE_BYTES)
        if data is None or _digest(data) != expected:
            return None
        crashes.append(data)
    return log, crashes


def _do_fuzz(
    dsn: str,
    context: ExecutionContext,
    sandbox: Any,
    build: Mapping[str, Any],
    preflight: _CampaignPreflight,
    *,
    rng_seed: int,
    input_digest: str,
    timeout_seconds: float,
    attempt_no: int,
    token: str,
) -> dict[str, Any]:
    deadline = _cap_to_step_budget(context, timeout_seconds)
    if deadline < 1:
        raise ExecutionFailed(
            state.BUDGET_EXHAUSTED, "no fuzz time remains for the campaign search"
        )
    max_total_time = max(1, int(math.floor(deadline - FUZZ_STARTUP_GRACE_SECONDS)))
    fuzzer_path, fuzzer_digest = _build_output_file(
        context, build, preflight.fuzzer_output
    )
    limits = context.plan.get("limits")
    raw_replay = limits.get("replay_seconds") if isinstance(limits, Mapping) else None
    input_timeout = (
        max(1, int(raw_replay))
        if isinstance(raw_replay, (int, float)) and not isinstance(raw_replay, bool)
        else 10
    )
    staging: Path | None = None
    failure: BaseException | None = None
    try:
        staging, staged_fuzzer, corpus_dir = _stage_fuzz_files(
            context,
            fuzzer_path,
            fuzzer_digest,
            preflight.corpus,
            f"fuzz-attempt-{attempt_no}",
        )
        result: FuzzResult = sandbox.fuzz(
            fuzzer_path=staged_fuzzer,
            corpus_dir=corpus_dir,
            rng_seed=rng_seed,
            max_total_time=max_total_time,
            deadline_seconds=deadline,
            max_len=preflight.max_len,
            asan_options=context.plan["asan_options"],
            input_timeout_seconds=input_timeout,
            expected_fuzzer_digest=fuzzer_digest,
        )
        return _persist_fuzz(
            dsn,
            context,
            result,
            attempt_no,
            token,
            input_digest=input_digest,
            fuzzer_digest=fuzzer_digest,
        )
    except BaseException as error:
        failure = error
        raise
    finally:
        if staging is not None:
            _cleanup_staging(staging, failure)


def _finish_campaign_failed(
    dsn: str,
    context: ExecutionContext,
    error: ExecutionFailed,
) -> ExecutionResult:
    """A campaign that cannot complete its search ends FAILED, never INCONCLUSIVE.

    A campaign bundle requires the fuzz log and provenance, and the execution
    bundle shape requires a round, so a failed campaign archives no bundle;
    the reason stays on the job and the family ends through convergence.
    """
    return _finish_failed_without_bundle(
        dsn,
        context.job_id,
        context.generation,
        error,
        explanation="a failed campaign has no campaign bundle",
    )


def _archive_only_campaign(dsn: str, context: ExecutionContext) -> ExecutionResult:
    """Recover a campaign whose generation crashed while ARCHIVING (P2 B5).

    Like ``_archive_only``: only completed, plan-bound, digest-verified step
    results from any generation are used; no budget gate, no step, no
    container and no charge. A past execute deadline is irrelevant because
    nothing runs. Anything missing fails closed without a bundle.
    """
    build_root = _work_root(context)
    completed: dict[str, dict[str, Any]] = {}
    for row in state.execution_attempts_across_generations(dsn, context.job_id):
        if row["status"] == "completed" and isinstance(row["result"], dict):
            completed.setdefault(row["step_key"], row["result"])

    def _fail(message: str) -> ExecutionResult:
        return _finish_campaign_failed(
            dsn,
            context,
            ExecutionFailed(
                "RUN_INCOMPLETE", f"campaign archive recovery: {message}"
            ),
        )

    def _bound(step: str) -> dict[str, Any] | None:
        result = completed.get(step)
        if isinstance(result, dict) and result.get("plan_digest") == context.plan_digest:
            return result
        return None

    probe = _bound("sandbox.probe")
    if probe is None or probe.get("status") != "completed":
        return _fail("no completed probe for this plan")
    try:
        parser_output, fuzzer_output = _campaign_outputs(context)
    except ExecutionBlocked as error:
        return _fail(error.message)
    builds: dict[str, dict[str, Any]] = {}
    for version in ("vulnerable", "fixed"):
        result = _bound(f"build:{version}")
        if (
            result is None
            or result.get("input_digest") != context.plan["analysis_digest"]
            or not _reusable_build(
                build_root,
                result,
                check_provenance_face=False,
                artifact_suffix=_primary_artifact_suffix(context),
            )
        ):
            return _fail(f"no verified {version} build")
        try:
            for output in (parser_output, fuzzer_output):
                _build_output_file(context, result, output)
        except ExecutionFailed as error:
            return _fail(error.message)
        builds[version] = result
    provenance_outcome = _verify_v2_build_provenance(context, build_root, builds)
    if not provenance_outcome.comparable:
        return _finish_campaign_failed(
            dsn,
            context,
            ExecutionFailed(
                build_provenance.BUILD_PROVENANCE_MISSING,
                provenance_outcome.error_detail or "v2 build provenance verification failed",
            ),
        )
    fuzz_payload = _bound(CAMPAIGN_FUZZ_STEP)
    if (
        fuzz_payload is None
        or fuzz_payload.get("status") != "completed"
        or fuzz_payload.get("log_truncated")
        or fuzz_payload.get("crash_truncated")
    ):
        return _fail("no complete fuzz search for this plan")
    read_back = _fuzz_files(build_root, fuzz_payload)
    if read_back is None:
        return _fail("the fuzz evidence no longer matches its journal")
    rng_seed = fuzz_rules.campaign_rng_seed(context.job_id_text, context.plan_digest)
    if fuzz_payload.get("rng_seed") != rng_seed:
        return _fail("the fuzz search used another RNG seed")
    envelope = context.envelope if isinstance(context.envelope, Mapping) else {}
    harness_relative = context.case.manifest["harness"]
    harness_pair = {
        "harness": str(context.materials.get(harness_relative)),
        "fuzz_shim": fuzz_rules.FUZZ_SHIM_REVIEWED_DIGEST,
    }
    if envelope.get("harness_digest") != fuzz_rules.guided_harness_digest(
        harness_pair["harness"], harness_pair["fuzz_shim"]
    ):
        return _fail("the approved harness pair no longer matches")
    fuzz_log, crashes = read_back
    try:
        return _archive_campaign_bundle(
            dsn,
            context,
            probe_payload=probe,
            builds=builds,
            fuzz_payload=fuzz_payload,
            fuzz_log=fuzz_log,
            crashes=crashes,
            rng_seed=rng_seed,
            harness_pair=harness_pair,
            seed_corpus_digest=str(envelope.get("seed_corpus_digest")),
            fuzzer_output=fuzzer_output,
            provenance_outcome=provenance_outcome,
        )
    except state.StaleGeneration:
        return ExecutionResult("STALE")


def _run_campaign(
    dsn: str,
    context: ExecutionContext,
    sandbox: Any,
    *,
    materials_dir: Path,
    material_digests: Mapping[str, str],
    build_root: Path,
) -> ExecutionResult:
    """Run the campaign child: preflight, one build per version, one search.

    A crashed ``ARCHIVING`` generation never comes here: it is recovered by
    ``_archive_only_campaign`` without any step, charge or container.
    """
    job_id = context.job_id
    generation = context.generation
    probe_payload: dict[str, Any] | None = None
    builds: dict[str, dict[str, Any]] = {}
    provenance_outcome: _ProvenanceCheckOutcome | None = None

    def _guard(step: str, action: Callable[[int, str], Any]) -> Callable[[int, str], Any]:
        del step
        return action

    try:
        preflight = _campaign_preflight(context, materials_dir)
        v2_build_spec = _build_spec_from_context(context)
        if v2_build_spec is None:
            raise ExecutionBlocked("PLAN_MISMATCH", "a campaign plan requires build_spec")
        spec_ok, _norm_flags, spec_error = _validate_v2_spec_and_flags(
            context, v2_build_spec
        )
        if not spec_ok:
            provenance_outcome = _ProvenanceCheckOutcome(
                comparable=False,
                report_summary=_empty_build_provenance_summary(context, comparable=False),
                error_detail=spec_error,
            )
            raise ExecutionFailed(build_provenance.BUILD_PROVENANCE_MISSING, spec_error)
        probe_timeout = min(PROBE_TIMEOUT, _remaining(context))
        probe_payload, _ = _run_step(
            dsn,
            context,
            step_key="sandbox.probe",
            input_digest=context.plan_digest,
            action=_guard(
                "probe",
                lambda attempt_no, token: _do_probe(
                    context, sandbox, deadline_seconds=probe_timeout
                ),
            ),
            reusable=lambda payload: payload.get("status") == "completed",
            step_timeout_seconds=probe_timeout,
        )
        # One build per version produces both the replay parser and the
        # fuzzer; validation rounds reuse these artifacts (C), never rebuild.
        for version in ("vulnerable", "fixed"):
            _assert_context_unchanged(
                dsn, context, materials_dir=materials_dir, material_digests=material_digests
            )
            _assert_budget(context, purpose=f"building {version}")
            build_timeout = min(BUILD_TIMEOUT, _remaining(context) - context.reserve_seconds)
            result, _reused = _run_step(
                dsn,
                context,
                step_key=f"build:{version}",
                input_digest=context.plan["analysis_digest"],
                action=_guard(
                    f"build:{version}",
                    lambda attempt_no, token, version=version, build_timeout=build_timeout: _do_build(
                        dsn,
                        context,
                        sandbox,
                        materials_dir,
                        material_digests,
                        version,
                        attempt_no,
                        token,
                        deadline_seconds=build_timeout,
                    ),
                ),
                reusable=lambda payload: _reusable_build(
                    build_root, payload, artifact_suffix=_primary_artifact_suffix(context)
                ),
                step_timeout_seconds=build_timeout,
            )
            builds[version] = result
            if result.get("status") != "completed":
                raise ExecutionFailed(
                    "BUILD_FAILED",
                    f"{version} build ended with status {result.get('status')}",
                )
            for output in (preflight.parser_output, preflight.fuzzer_output):
                _build_output_file(context, result, output)
        provenance_outcome = _verify_v2_build_provenance(context, build_root, builds)
        if not provenance_outcome.comparable:
            raise ExecutionFailed(
                build_provenance.BUILD_PROVENANCE_MISSING,
                provenance_outcome.error_detail or "v2 build provenance verification failed",
            )
        _assert_context_unchanged(
            dsn, context, materials_dir=materials_dir, material_digests=material_digests
        )
        rng_seed = fuzz_rules.campaign_rng_seed(context.job_id_text, context.plan_digest)
        _fuzzer_path, fuzzer_digest = _build_output_file(
            context, builds["vulnerable"], preflight.fuzzer_output
        )
        fuzz_input_digest = _fuzz_input_digest(fuzzer_digest, preflight, rng_seed)
        fuzz_timeout = _remaining(context) - context.reserve_seconds
        if fuzz_timeout < 1:
            raise ExecutionFailed(
                "TIMEOUT", "the execution deadline left no time for the fuzz search"
            )
        fuzz_payload, _ = _run_step(
            dsn,
            context,
            step_key=CAMPAIGN_FUZZ_STEP,
            input_digest=fuzz_input_digest,
            action=lambda attempt_no, token: _do_fuzz(
                dsn,
                context,
                sandbox,
                builds["vulnerable"],
                preflight,
                rng_seed=rng_seed,
                input_digest=fuzz_input_digest,
                timeout_seconds=fuzz_timeout,
                attempt_no=attempt_no,
                token=token,
            ),
            reusable=lambda payload: _fuzz_files(build_root, payload) is not None,
            charge_kind="fuzz",
            step_timeout_seconds=fuzz_timeout,
        )
        status = fuzz_payload.get("status")
        if status == "timeout":
            raise ExecutionFailed(
                "TIMEOUT", "the fuzz container exceeded its hard timeout"
            )
        if status != "completed":
            raise ExecutionFailed(
                "RUN_INCOMPLETE", f"the fuzz search ended with status {status}"
            )
        if fuzz_payload.get("log_truncated") or fuzz_payload.get("crash_truncated"):
            raise ExecutionFailed(
                "RUN_INCOMPLETE",
                "the fuzz log or a crash input was truncated; the campaign "
                "evidence would be incomplete",
            )
        read_back = _fuzz_files(build_root, fuzz_payload)
        if read_back is None:
            raise ExecutionFailed(
                "RUN_INCOMPLETE", "the fuzz evidence no longer matches its journal"
            )
        fuzz_log, crashes = read_back
    except ExecutionBlocked as error:
        return _finish_blocked(
            dsn, job_id, generation, error, context=context, probe=probe_payload, builds=builds, runs=[]
        )
    except ExecutionFailed as error:
        return _finish_campaign_failed(dsn, context, error)
    except SandboxPolicyError as error:
        return _finish_blocked(
            dsn,
            job_id,
            generation,
            ExecutionBlocked(error.reason_code, error.message),
            context=context,
            probe=probe_payload,
            builds=builds,
            runs=[],
        )
    except SandboxUnavailable as error:
        return _finish_blocked(
            dsn,
            job_id,
            generation,
            ExecutionBlocked("POLICY_DENIED", error.message),
            context=context,
            probe=probe_payload,
            builds=builds,
            runs=[],
        )
    except SandboxError as error:
        mapped = (
            build_provenance.BUILD_PROVENANCE_MISSING
            if error.reason_code == build_provenance.BUILD_PROVENANCE_MISSING
            else ("TIMEOUT" if error.reason_code == "TIMEOUT" else "RUN_INCOMPLETE")
        )
        return _finish_campaign_failed(dsn, context, ExecutionFailed(mapped, error.message))
    except state.StaleGeneration:
        return ExecutionResult("STALE")

    return _archive_campaign_bundle(
        dsn,
        context,
        probe_payload=probe_payload,
        builds=builds,
        fuzz_payload=fuzz_payload,
        fuzz_log=fuzz_log,
        crashes=crashes,
        rng_seed=rng_seed,
        harness_pair=preflight.harness_pair,
        seed_corpus_digest=preflight.seed_corpus_digest,
        fuzzer_output=preflight.fuzzer_output,
        provenance_outcome=provenance_outcome,
    )


def _archive_campaign_bundle(
    dsn: str,
    context: ExecutionContext,
    *,
    probe_payload: Mapping[str, Any] | None,
    builds: Mapping[str, Mapping[str, Any]],
    fuzz_payload: Mapping[str, Any],
    fuzz_log: bytes,
    crashes: Sequence[bytes],
    rng_seed: int,
    harness_pair: Mapping[str, str],
    seed_corpus_digest: str,
    fuzzer_output: str,
    provenance_outcome: "_ProvenanceCheckOutcome | None",
) -> ExecutionResult:
    """Write the campaign bundle from verified step results and land COMPLETED."""
    job_id = context.job_id
    generation = context.generation
    build_root = _work_root(context)
    fuzz_log_digest = _digest(fuzz_log)
    try:
        seed_records = fuzz_rules.crash_seed_records(
            crashes,
            campaign_job_id=context.job_id_text,
            fuzz_log_digest=fuzz_log_digest,
            rng_seed=rng_seed,
        )
    except ValueError as error:
        return _finish_campaign_failed(
            dsn, context, ExecutionFailed("RUN_INCOMPLETE", str(error))
        )
    seed_bytes = {jsonutil.digest_bytes(data): data for data in crashes}
    fuzzer_digests = {}
    for version in ("vulnerable", "fixed"):
        _path, digest = _build_output_file(context, builds[version], fuzzer_output)
        fuzzer_digests[version] = digest
    fuzz_provenance = fuzz_rules.fuzz_provenance_document(
        campaign_job_id=context.job_id_text,
        plan_digest=context.plan_digest,
        rng_seed=rng_seed,
        fuzz_log_digest=fuzz_log_digest,
        harness_pair=harness_pair,
        seed_corpus_digest_value=seed_corpus_digest,
        fuzzer_digests=fuzzer_digests,
        max_total_time_seconds=int(fuzz_payload.get("max_total_time_seconds") or 0),
        status=str(fuzz_payload.get("status")),
        exit_code=fuzz_payload.get("exit_code"),
        crash_seeds=seed_records,
    )
    attempt_rows = []
    for row in state.execution_attempts(dsn, job_id, generation):
        item = {key: value for key, value in row.items() if key != "attempt_token"}
        for column in ("started_at", "finished_at"):
            if item.get(column) is not None:
                item[column] = jsonutil.timestamp(item[column])
        attempt_rows.append(item)
    execution_metadata = {
        "job_id": context.job_id_text,
        "plan_digest": context.plan_digest,
        "generation": generation,
        "probe": probe_payload,
        "builds": [dict(item) for item in builds.values()],
        "replays": [],
        "fuzz": dict(fuzz_payload),
        "attempts": attempt_rows,
    }
    try:
        _refresh_budget_summary_before_archive(dsn, context)
    except (state.StateError, psycopg.Error):
        return ExecutionResult("STALE")
    try:
        artifacts = _evidence_artifacts(
            context,
            build_root,
            builds=builds,
            runs=[],
            probe=probe_payload,
            execution_metadata=execution_metadata,
        )
        artifacts[fuzz_rules.FUZZ_LOG_PATH] = ("fuzz_log", fuzz_log)
        artifacts[fuzz_rules.FUZZ_PROVENANCE_PATH] = (
            "fuzz_provenance",
            jsonutil.canonical_bytes(fuzz_provenance) + b"\n",
        )
        for record in seed_records:
            artifacts[record["path"]] = ("crash_seed", seed_bytes[record["sha256"]])
        report, report_markdown = _build_report(
            context,
            verdict=None,
            verdict_reason=None,
            decision=None,
            builds=builds,
            runs=[],
            probe=probe_payload,
            evidence_refs=_report_evidence_refs(artifacts),
            missing=[],
            build_provenance_summary=(
                provenance_outcome.report_summary if provenance_outcome is not None else None
            ),
            bundle_kind="campaign",
        )
        report["fuzz"] = {
            "engine": "libfuzzer",
            "status": fuzz_provenance["status"],
            "rng_seed": rng_seed,
            "fuzz_log_digest": fuzz_log_digest,
            "crash_count": len(seed_records),
            "crash_seeds": [
                {"path": record["path"], "sha256": record["sha256"]}
                for record in seed_records
            ],
        }
        report_markdown = render_report_markdown(report)
        digest, path, archive_error = _archive(
            dsn,
            context,
            report=report,
            report_markdown=report_markdown,
            artifacts=artifacts,
            verdict=None,
        )
    except (BundleError, OSError) as error:
        digest = path = None
        archive_error = f"EVIDENCE_WRITE_FAILED: {error}"
    except (state.StateError, state.StaleGeneration):
        return ExecutionResult("STALE")
    if archive_error is not None:
        try:
            finished = state.finish_execution(
                dsn,
                job_id,
                generation=generation,
                state="FAILED",
                reason_code="EVIDENCE_WRITE_FAILED",
                verdict=None,
                verdict_reason=None,
                evidence_status="failed",
                evidence_error=archive_error,
                last_error="campaign bundle could not be written",
                stage="failed",
            )
        except (state.StateError, state.StaleGeneration):
            return ExecutionResult("STALE")
        if not finished:
            return ExecutionResult("STALE")
        return ExecutionResult("FAILED", reason_code="EVIDENCE_WRITE_FAILED")
    try:
        finished = state.finish_execution(
            dsn,
            job_id,
            generation=generation,
            state="COMPLETED",
            reason_code=None,
            verdict=None,
            verdict_reason=None,
            evidence_digest=digest,
            evidence_path=path,
            evidence_status="archived",
            stage="done",
        )
    except (state.StateError, state.StaleGeneration):
        _discard_published_bundle(path)
        return ExecutionResult("STALE")
    if not finished:
        _discard_published_bundle(path)
        return ExecutionResult("STALE")
    return ExecutionResult(
        "COMPLETED", evidence_digest=digest, evidence_path=path
    )


# ---------------------------------------------------------------------------
# T12 C (改9): a guided validation round reuses the campaign build products.
# ---------------------------------------------------------------------------

REUSE_MISMATCH = "REUSE_MISMATCH"


@dataclass(frozen=True)
class _CampaignReuse:
    source_job_id: str
    generation: int
    campaign_bundle_digest: str
    artifacts: dict[str, dict[str, str]]
    builds: dict[str, BuildResult]
    seed: bytes


def _campaign_build_record(
    files: Mapping[str, bytes], version: str
) -> tuple[dict[str, Any], dict[str, str], bytes]:
    """Return one version's archived build payload, its output paths and log."""
    prefix = f"build/{version}/"
    raw_metadata = files.get(prefix + "metadata.json")
    log = files.get(prefix + "build.log")
    if raw_metadata is None or log is None:
        raise ValueError(f"the campaign bundle has no {version} build record")
    metadata = jsonutil.loads_strict(raw_metadata)
    if not isinstance(metadata, dict) or metadata.get("status") != "completed":
        raise ValueError(f"the campaign {version} build is not a completed build")
    record_files = metadata.get("files")
    outputs = record_files.get("outputs") if isinstance(record_files, Mapping) else None
    if not isinstance(outputs, Mapping):
        raise ValueError(f"the campaign {version} build lists no outputs")
    by_name = {
        PurePosixPath(str(relative)).name: str(relative) for relative in outputs
    }
    if set(by_name) != {fuzz_rules.PARSER_OUTPUT, fuzz_rules.FUZZER_OUTPUT}:
        raise ValueError(
            f"the campaign {version} build did not produce exactly parser and fuzzer"
        )
    return metadata, by_name, log


def campaign_build_ref(
    files: Mapping[str, bytes], *, campaign_job_id: str, plan: Mapping[str, Any]
) -> dict[str, Any]:
    """Derive a validation ``build_ref`` from a verified campaign bundle (D41).

    ``artifact_digest`` binds the replay parser, ``fuzzer_digest`` the fuzzer,
    both versions share the campaign build attempt's ``generation``, and
    ``build_inputs_digest`` covers the build materials, toolchain and
    BuildSpec only (never the inputs).
    """
    artifacts: dict[str, dict[str, str]] = {}
    generations: set[Any] = set()
    staged: dict[str, Any] = {}
    for version in ("vulnerable", "fixed"):
        metadata, by_name, log = _campaign_build_record(files, version)
        prefix = f"build/{version}/"
        parser = files.get(prefix + by_name[fuzz_rules.PARSER_OUTPUT])
        fuzzer = files.get(prefix + by_name[fuzz_rules.FUZZER_OUTPUT])
        if parser is None or fuzzer is None:
            raise ValueError(f"the campaign bundle lacks the {version} products")
        artifacts[version] = {
            "artifact_digest": _digest(parser),
            "build_log_digest": _digest(log),
            "fuzzer_digest": _digest(fuzzer),
        }
        generations.add(metadata.get("generation"))
        staged[version] = metadata.get("staged_materials")
    if len(generations) != 1 or type(next(iter(generations))) is not int:
        raise ValueError("both campaign builds must share one build generation")
    return {
        "source_job_id": campaign_job_id,
        "generation": next(iter(generations)),
        "build_inputs_digest": jsonutil.digest_json(
            {
                "build_recipe_digest": plan.get("build_recipe_digest"),
                "build_spec": plan.get("build_spec"),
                "compile_flags": plan.get("compile_flags"),
                "image_digest": plan.get("image_digest"),
                "staged_materials": staged,
            }
        ),
        "artifacts": artifacts,
    }


def _load_campaign_reuse(dsn: str, context: ExecutionContext) -> _CampaignReuse:
    """Bind a reuse round to the archived campaign; any drift is REUSE_MISMATCH.

    The plan's ``build_ref`` is the single authority: the source job must be
    this family's COMPLETED campaign, its bundle must verify offline and match
    the job's evidence digest, the recomputed ``build_ref`` must equal the
    plan's field by field, and the round's candidate must be one of the
    campaign's frozen crash seeds with complete provenance.
    """
    plan = context.plan
    build_ref = plan.get("build_ref")
    if not isinstance(build_ref, Mapping):
        raise ExecutionFailed(REUSE_MISMATCH, "the round plan has no build_ref")

    def _mismatch(message: str) -> ExecutionFailed:
        return ExecutionFailed(REUSE_MISMATCH, message)

    try:
        source_id = UUID(str(build_ref.get("source_job_id")))
    except ValueError as error:
        raise _mismatch("build_ref.source_job_id is not a job id") from error
    source = state.load_job(dsn, source_id)
    if (
        source is None
        or source.get("job_kind") != "campaign"
        or str(source.get("family_id")) != str(context.job.get("family_id"))
        or source.get("state") != "COMPLETED"
        or source.get("evidence_status") != "archived"
        or not isinstance(source.get("evidence_path"), str)
    ):
        raise _mismatch(
            "build_ref.source_job_id is not this family's archived COMPLETED campaign"
        )
    try:
        verified = verify_bundle(source["evidence_path"])
    except (BundleError, OSError) as error:
        raise _mismatch(f"the campaign bundle does not verify: {error}") from error
    bundle_digest = evidence.canonical_manifest_digest(verified.manifest)
    if bundle_digest != source.get("evidence_digest"):
        raise _mismatch("the campaign bundle differs from the archived evidence digest")
    files = verified.file_data
    try:
        campaign_plan = jsonutil.loads_strict(files["plan.json"])
        recomputed = campaign_build_ref(
            files, campaign_job_id=str(source_id), plan=campaign_plan
        )
    except (KeyError, ValueError) as error:
        raise _mismatch(f"the campaign build record is unusable: {error}") from error
    for name in ("build_recipe_digest", "build_spec", "compile_flags", "image_digest"):
        if campaign_plan.get(name) != plan.get(name):
            raise _mismatch(f"the round plan {name} differs from the campaign plan")
    for name in ("source_job_id", "generation", "build_inputs_digest"):
        if recomputed[name] != build_ref.get(name):
            raise _mismatch(
                f"build_ref.{name} does not match the campaign "
                f"(expected {recomputed[name]!r}, got {build_ref.get(name)!r})"
            )
    for version in ("vulnerable", "fixed"):
        planned = build_ref.get("artifacts", {}).get(version)
        if planned != recomputed["artifacts"][version]:
            raise _mismatch(
                f"build_ref.artifacts.{version} does not match the campaign "
                f"{version} products (expected {recomputed['artifacts'][version]}, "
                f"got {planned})"
            )
    plan_inputs = plan.get("inputs")
    candidate = plan_inputs.get("candidate") if isinstance(plan_inputs, Mapping) else None
    provenance_raw = files.get(fuzz_rules.FUZZ_PROVENANCE_PATH)
    seed: bytes | None = None
    try:
        provenance = jsonutil.loads_strict(provenance_raw or b"")
        for record in provenance.get("crash_seeds", []):
            path_value = record.get("path") if isinstance(record, Mapping) else None
            data = files.get(path_value) if isinstance(path_value, str) else None
            checked = fuzz_rules.validate_crash_seed_record(
                record, data=data, campaign_job_id=str(source_id)
            )
            if checked["sha256"] == candidate and data is not None:
                seed = data
                break
    except (AttributeError, ValueError) as error:
        raise _mismatch(f"the campaign crash seed provenance is invalid: {error}") from error
    if seed is None:
        raise _mismatch(
            "the round candidate is not a frozen crash seed of the referenced campaign"
        )
    builds: dict[str, BuildResult] = {}
    for version in ("vulnerable", "fixed"):
        metadata, by_name, log = _campaign_build_record(files, version)
        prefix = f"build/{version}/"
        outputs = tuple(
            BuildOutput(
                relative_path=relative,
                archive_path=relative,
                data=files[prefix + relative],
                digest=_digest(files[prefix + relative]),
            )
            for relative in sorted(by_name.values())
        )
        face_name = metadata.get("provenance_face_name")
        face = (
            files.get(f"{prefix}build_provenance/{face_name}")
            if isinstance(face_name, str)
            else None
        )
        carried = {
            key: value
            for key, value in metadata.items()
            if key
            not in (
                "tool_id", "job_id", "generation", "attempt_token", "plan_digest",
                "input_digest", "status", "version", "container_id",
                "artifact_digest", "attempt_no", "files", "file_digests",
                "exit_code", "duration_seconds", "image_digest", "compile_args",
                "log_digest", "log_truncated", "truncated_roles", "capture_error",
                "provenance_face_name", "provenance_face_size",
                "provenance_face_sha256", "staged_materials", "hmac",
            )
        }
        carried["reused_from"] = {
            "source_job_id": str(source_id),
            "generation": recomputed["generation"],
            "campaign_bundle_digest": bundle_digest,
        }
        builds[version] = BuildResult(
            version=version,
            status="completed",
            exit_code=metadata.get("exit_code"),
            duration_seconds=0.0,
            container_id=None,
            image_digest=str(metadata.get("image_digest")),
            compile_args=tuple(metadata.get("compile_args") or ()),
            artifact_digest=recomputed["artifacts"][version]["artifact_digest"],
            log=log,
            log_truncated=False,
            artifact=files[prefix + by_name[fuzz_rules.PARSER_OUTPUT]],
            metadata=carried,
            provenance_face=face,
            provenance_face_name=face_name if isinstance(face_name, str) else None,
            outputs=outputs,
        )
    return _CampaignReuse(
        source_job_id=str(source_id),
        generation=recomputed["generation"],
        campaign_bundle_digest=bundle_digest,
        artifacts={version: dict(recomputed["artifacts"][version]) for version in ("vulnerable", "fixed")},
        builds=builds,
        seed=seed,
    )


def _reuse_origin(context: Any) -> dict[str, Any] | None:
    reuse = getattr(context, "reuse", None)
    if reuse is None:
        return None
    return {
        "source_job_id": reuse.source_job_id,
        "generation": reuse.generation,
        "campaign_bundle_digest": reuse.campaign_bundle_digest,
        "artifacts": {version: dict(item) for version, item in reuse.artifacts.items()},
    }


def _finish_failed_without_bundle(
    dsn: str,
    job_id: UUID,
    generation: int,
    error: ExecutionFailed,
    *,
    explanation: str,
) -> ExecutionResult:
    """FAILED with the real reason when no verifiable bundle can be written."""
    try:
        finished = state.finish_execution(
            dsn,
            job_id,
            generation=generation,
            state="FAILED",
            reason_code=error.reason_code,
            verdict=None,
            verdict_reason=None,
            evidence_status="failed",
            evidence_error=f"{explanation}: {error.reason_code}: {error.message}",
            last_error=error.message,
            stage="failed",
        )
    except (state.StateError, state.StaleGeneration):
        return ExecutionResult("STALE")
    if not finished:
        return ExecutionResult("STALE")
    return ExecutionResult("FAILED", reason_code=error.reason_code)


def _do_reuse_build(
    dsn: str,
    context: ExecutionContext,
    version: str,
    attempt_no: int,
    token: str,
) -> dict[str, Any]:
    """Adopt the campaign's verified build for ``version``; no container runs."""
    reuse = context.reuse
    result = reuse.builds[version]
    result = BuildResult(
        **{
            **{name: getattr(result, name) for name in result.__dataclass_fields__},
            "metadata": {
                **result.metadata,
                "primary_output": next(
                    output.relative_path
                    for output in result.outputs
                    if PurePosixPath(output.relative_path).name
                    == fuzz_rules.PARSER_OUTPUT
                ),
            },
        }
    )
    return _persist_build(dsn, context, result, attempt_no, token)


def run_execution(
    dsn: str,
    job_id: UUID,
    generation: int,
    *,
    case_root: str | None = None,
    run_root: Path | str | None = None,
    sandbox: Any | None = None,
) -> ExecutionResult:
    """Run one claimed READY/RUNNING generation to a terminal state."""
    validate_test_hooks()
    try:
        context = _load_context(
            dsn, job_id, generation, case_root=case_root, run_root=run_root
        )
    except state.StaleGeneration:
        return ExecutionResult("STALE")
    except ExecutionBlocked as error:
        # The execution cannot start. The claim still has a lease, so archive
        # the blocking reason and commit BLOCKED. Reuse the caller's roots so
        # a reload cannot drift to environment defaults.
        return _finish_blocked(
            dsn,
            job_id,
            generation,
            error,
            case_root=case_root,
            run_root=run_root,
        )
    except ExecutionFailed as error:
        return _finish_blocked_failed(dsn, job_id, generation, error)

    if _is_v2_context(context) and _is_reuse_plan(context.plan):
        try:
            context.reuse = _load_campaign_reuse(dsn, context)
        except ExecutionFailed as error:
            return _finish_failed_without_bundle(
                dsn,
                job_id,
                generation,
                error,
                explanation="the validation round cannot reuse the campaign build",
            )
        except state.StaleGeneration:
            return ExecutionResult("STALE")

    # The evidence root must be outside the attacker-writable run root before
    # either archive recovery or the normal path can touch any bundle.
    try:
        _assert_evidence_root_outside_run_root(context.run_root)
    except ExecutionFailed as error:
        return _finish_evidence_path_failure(dsn, job_id, generation, error)

    campaign = _is_campaign_context(context)
    if context.job["state"] == "ARCHIVING":
        if campaign:
            return _archive_only_campaign(dsn, context)
        return _archive_only(dsn, context)

    try:
        _assert_journal_paths(context.run_root)
        # The staging root holds the bytes that containers actually mount, so
        # a bad location must fail before any probe/build/replay container.
        _staging_root(context)
    except ExecutionFailed as error:
        # The HMAC key and staging copies must live outside the writable run
        # root; fail before any probe/build/replay container exists. Do not
        # archive: the evidence destination itself may be inside the untrusted
        # run root, and the failure must remain visible via
        # status.evidence.error.
        return _finish_evidence_path_failure(dsn, job_id, generation, error)

    try:
        _assert_budget(context, purpose="starting isolated execution")
    except ExecutionBlocked as error:
        return _finish_blocked(dsn, job_id, generation, error, context=context)

    work_root = context.run_root / context.job_id_text / context.plan_digest.split(":")[1]
    try:
        _prepare_shared_directory(context.run_root, work_root, "work root")
        build_root = work_root / "run"
        _prepare_shared_directory(context.run_root, build_root, "sandbox run root")
        generation_root = _generation_root(context)
        _prepare_run_directory(
            context.run_root, generation_root, "generation root",
            scope_root=generation_root,
        )
    except ExecutionFailed as error:
        return _finish_evidence_path_failure(dsn, job_id, generation, error)
    try:
        materials_dir, inputs, material_digests = _materialize(
            context, generation_root, anchor=context.run_root
        )
    except ExecutionBlocked as error:
        return _finish_blocked(dsn, job_id, generation, error, context=context)

    if sandbox is None:
        sandbox = DockerSandbox(
            image=context.image,
            platform=context.plan["platform"],
            policy=context.isolation,
            limits=context.limits,
            job_id=context.job_id_text,
            run_root=build_root,
            generation=generation,
        )
    reclaim = getattr(sandbox, "reclaim_job", None)
    if callable(reclaim):
        try:
            reclaim()
        except SandboxError as error:
            # Cleanup failure is not a reason to silently continue: record it
            # on the context so the archived report exposes the condition, and
            # keep the current generation's containers untouched.
            context.cleanup_errors.append(f"reclaim: {error.message}")

    if campaign:
        return _run_campaign(
            dsn,
            context,
            sandbox,
            materials_dir=materials_dir,
            material_digests=material_digests,
            build_root=build_root,
        )

    probe_payload: dict[str, Any] | None = None
    builds: dict[str, dict[str, Any]] = {}
    runs: list[dict[str, Any]] = []
    decision: VerdictDecision | None = None
    missing: list[str] = []
    provenance_outcome: _ProvenanceCheckOutcome | None = None
    try:
        plan_inputs = context.plan.get("inputs")
        if (
            not isinstance(plan_inputs, Mapping)
            or not isinstance(plan_inputs.get("normal"), str)
            or not isinstance(plan_inputs.get("candidate"), str)
        ):
            raise ExecutionBlocked(
                "MATERIAL_MISSING",
                "execution plan has no replay inputs mapping",
            )
        v2_build_spec = (
            _build_spec_from_context(context) if _is_v2_context(context) else None
        )
        if v2_build_spec is not None:
            spec_ok, _norm_flags, spec_error = _validate_v2_spec_and_flags(
                context, v2_build_spec
            )
            if not spec_ok:
                provenance_outcome = _ProvenanceCheckOutcome(
                    comparable=False,
                    report_summary=_empty_build_provenance_summary(
                        context, comparable=False
                    ),
                    error_detail=spec_error,
                )
                raise ExecutionFailed(
                    build_provenance.BUILD_PROVENANCE_MISSING,
                    spec_error,
                )
        probe_timeout = min(PROBE_TIMEOUT, _remaining(context))
        probe_result, _ = _run_step(
            dsn,
            context,
            step_key="sandbox.probe",
            input_digest=context.plan_digest,
            action=lambda attempt_no, token: _do_probe(
                context, sandbox, deadline_seconds=probe_timeout
            ),
            reusable=lambda payload: payload.get("status") == "completed",
            step_timeout_seconds=probe_timeout,
        )
        probe_payload = probe_result
        for version in ("vulnerable", "fixed"):
            _assert_context_unchanged(
                dsn,
                context,
                materials_dir=materials_dir,
                material_digests=material_digests,
            )
            _assert_budget(context, purpose=f"building {version}")
            build_timeout = min(
                BUILD_TIMEOUT, _remaining(context) - context.reserve_seconds
            )
            result, reused = _run_step(
                dsn,
                context,
                step_key=f"build:{version}",
                input_digest=context.plan["analysis_digest"],
                action=(
                    (lambda attempt_no, token, version=version: _do_reuse_build(
                        dsn, context, version, attempt_no, token
                    ))
                    if getattr(context, "reuse", None) is not None
                    else (lambda attempt_no, token, version=version, build_timeout=build_timeout: _do_build(
                        dsn,
                        context,
                        sandbox,
                        materials_dir,
                        material_digests,
                        version,
                        attempt_no,
                        token,
                        deadline_seconds=build_timeout,
                    ))
                ),
                reusable=lambda payload: _reusable_build(
                    build_root,
                    payload,
                    artifact_suffix=_primary_artifact_suffix(context),
                ),
                step_timeout_seconds=build_timeout,
                budgeted=getattr(context, "reuse", None) is None,
            )
            builds[version] = result
            if result.get("status") != "completed":
                raise ExecutionFailed(
                    "BUILD_FAILED",
                    f"{version} build ended with status {result.get('status')}",
                )
        if _is_v2_context(context) and _build_spec_from_context(context) is not None:
            provenance_outcome = _verify_v2_build_provenance(
                context, build_root, builds
            )
            if not provenance_outcome.comparable:
                raise ExecutionFailed(
                    build_provenance.BUILD_PROVENANCE_MISSING,
                    provenance_outcome.error_detail
                    or "v2 build provenance verification failed",
                )
        for version in ("vulnerable", "fixed"):
            for phase in ("normal", "candidate_1", "candidate_2"):
                _assert_context_unchanged(
                    dsn,
                    context,
                    materials_dir=materials_dir,
                    material_digests=material_digests,
                )
                _assert_budget(context, purpose=f"replaying {version}/{phase}")
                input_path = inputs["normal"] if phase == "normal" else inputs["candidate"]
                step_key = _replay_step(version, phase)
                remaining = _remaining(context) - context.reserve_seconds
                replay_timeout = min(
                    float(context.plan["limits"]["replay_seconds"]),
                    remaining,
                )
                result, reused = _run_step(
                    dsn,
                    context,
                    step_key=step_key,
                    input_digest=plan_inputs[
                        "normal" if phase == "normal" else "candidate"
                    ],
                    action=lambda attempt_no, token, version=version, phase=phase, input_path=input_path, replay_timeout=replay_timeout: _do_replay(
                        dsn,
                        context,
                        sandbox,
                        builds[version],
                        version,
                        phase,
                        input_path,
                        replay_timeout,
                        attempt_no,
                        token,
                    ),
                    reusable=lambda payload: _reusable_replay(build_root, payload),
                    step_timeout_seconds=replay_timeout,
                )
                runs.append(result)
        input_mismatch = False
        for run in runs:
            expected = (
                plan_inputs["normal"]
                if run.get("phase") == "normal"
                else plan_inputs["candidate"]
            )
            if run.get("input_digest") != expected:
                input_mismatch = True
                missing.append(
                    f"input digest mismatch for {run.get('version')}/{run.get('phase')}"
                )
        if input_mismatch:
            # The completed result does not describe the approved bytes.
            # Never archive it as a full six-replay bundle: the verifier
            # rejects plan-mismatched inputs, and there is no verifiable
            # outcome. B3/B6 require an inconclusive state with no
            # authoritative verdict.
            try:
                finished = state.finish_execution(
                    dsn,
                    context.job_id,
                    generation=context.generation,
                    state="INCONCLUSIVE",
                    reason_code="EVIDENCE_INCOMPLETE",
                    verdict=None,
                    verdict_reason=None,
                    evidence_status="failed",
                    evidence_error=(
                        "replay input digest does not match the approved plan"
                    ),
                    last_error="required input digests do not match the approved plan",
                    stage="done",
                )
            except (state.StateError, state.StaleGeneration):
                return ExecutionResult("STALE")
            if not finished:
                return ExecutionResult("STALE")
            return ExecutionResult(
                "INCONCLUSIVE",
                verdict=None,
                verdict_reason=None,
                reason_code="EVIDENCE_INCOMPLETE",
            )
        policy = _policy_from_context(context)
        decision = decide_verdict(
            policy, [_to_observation(run, build_root) for run in runs], builds=builds
        )
    except ExecutionBlocked as error:
        return _finish_blocked(
            dsn, job_id, generation, error, context=context, probe=probe_payload, builds=builds, runs=runs
        )
    except ExecutionFailed as error:
        return _finish_failed(
            dsn,
            job_id,
            generation,
            error,
            context=context,
            probe=probe_payload,
            builds=builds,
            runs=runs,
            build_provenance_summary=(
                provenance_outcome.report_summary
                if provenance_outcome is not None
                else None
            ),
        )
    except SandboxPolicyError as error:
        return _finish_blocked(
            dsn,
            job_id,
            generation,
            ExecutionBlocked(error.reason_code, error.message),
            context=context,
            probe=probe_payload,
            builds=builds,
            runs=runs,
        )
    except SandboxUnavailable as error:
        return _finish_blocked(
            dsn,
            job_id,
            generation,
            ExecutionBlocked("POLICY_DENIED", error.message),
            context=context,
            probe=probe_payload,
            builds=builds,
            runs=runs,
        )
    except SandboxError as error:
        mapped_reason = (
            build_provenance.BUILD_PROVENANCE_MISSING
            if error.reason_code == build_provenance.BUILD_PROVENANCE_MISSING
            else ("TIMEOUT" if error.reason_code == "TIMEOUT" else "RUN_INCOMPLETE")
        )
        return _finish_failed(
            dsn,
            job_id,
            generation,
            ExecutionFailed(mapped_reason, error.message),
            context=context,
            probe=probe_payload,
            builds=builds,
            runs=runs,
            build_provenance_summary=(
                provenance_outcome.report_summary
                if provenance_outcome is not None
                else None
            ),
        )
    except state.StaleGeneration:
        return ExecutionResult("STALE")

    attempt_rows = []
    for row in state.execution_attempts(dsn, job_id, generation):
        item = {
            key: value for key, value in row.items() if key != "attempt_token"
        }
        for column in ("started_at", "finished_at"):
            if item.get(column) is not None:
                item[column] = jsonutil.timestamp(item[column])
        attempt_rows.append(item)
    execution_metadata = {
        "job_id": context.job_id_text,
        "plan_digest": context.plan_digest,
        "generation": generation,
        "probe": probe_payload,
        # Mirror the report's list shapes exactly; _verify_semantics rejects a
        # bundle whose execution metadata and report disagree.
        "builds": [dict(item) for item in builds.values()],
        "replays": [dict(item) for item in runs],
        "attempts": attempt_rows,
    }
    try:
        _refresh_budget_summary_before_archive(dsn, context)
    except (state.StateError, psycopg.Error):
        return ExecutionResult("STALE")
    # Artifacts first, then the report: the refs must be derived from the
    # documents this writer really archives (SF-2), so a policy round lists
    # its admission instead of a review.json it never carried.
    artifacts = _evidence_artifacts(
        context,
        build_root,
        builds=builds,
        runs=runs,
        probe=probe_payload,
        execution_metadata=execution_metadata,
    )
    report, report_markdown = _build_report(
        context,
        verdict=decision.verdict,
        verdict_reason=decision.reason_code,
        decision=decision,
        builds=builds,
        runs=runs,
        probe=probe_payload,
        evidence_refs=_report_evidence_refs(artifacts),
        missing=missing,
        build_provenance_summary=(
            provenance_outcome.report_summary
            if provenance_outcome is not None
            else None
        ),
    )
    try:
        digest, path, archive_error = _archive(
            dsn,
            context,
            report=report,
            report_markdown=report_markdown,
            artifacts=artifacts,
            verdict=decision.verdict,
        )
    except (BundleError, OSError) as error:
        archive_error = f"EVIDENCE_WRITE_FAILED: {error}"
    except (state.StateError, state.StaleGeneration):
        return ExecutionResult("STALE")
    if archive_error is not None:
        try:
            # The computed decision is not published as authoritative until a
            # verifiable bundle exists. finish_execution clears any prior
            # verdict and evidence pointer on this FAILED terminal; the error
            # is preserved in evidence_error/last_error.
            finished = state.finish_execution(
                dsn,
                job_id,
                generation=context.generation,
                state="FAILED",
                reason_code="EVIDENCE_WRITE_FAILED",
                verdict=None,
                verdict_reason=None,
                evidence_status="failed",
                evidence_error=archive_error,
                last_error="evidence bundle could not be written",
                stage="failed",
            )
        except (state.StateError, state.StaleGeneration):
            # Another generation owns the job now (or the lease expired while
            # archiving). Never let this escape to the workflow's generic
            # handler, which would leave the job looking recoverable RUNNING.
            return ExecutionResult("STALE")
        if not finished:
            return ExecutionResult("STALE")
        return ExecutionResult("FAILED", reason_code="EVIDENCE_WRITE_FAILED")
    final_state = decision.verdict
    reason_code = None if final_state in ("REPRODUCED", "NOT_REPRODUCED") else decision.reason_code
    try:
        finished = state.finish_execution(
            dsn,
            job_id,
            generation=context.generation,
            state=final_state,
            reason_code=reason_code,
            verdict=decision.verdict,
            verdict_reason=decision.reason_code,
            evidence_digest=digest,
            evidence_path=path,
            evidence_status="archived",
            stage="done",
        )
    except (state.StateError, state.StaleGeneration):
        _discard_published_bundle(path)
        return ExecutionResult("STALE")
    if not finished:
        _discard_published_bundle(path)
        return ExecutionResult("STALE")
    return ExecutionResult(
        final_state,
        verdict=decision.verdict,
        verdict_reason=decision.reason_code,
        evidence_digest=digest,
        evidence_path=path,
        reason_code=reason_code,
    )


def _replay_log_text(
    payload: Mapping[str, Any], run_root: Path, key: str, digest_key: str
) -> str:
    """Load a replay stream from its evidence file, never from report text."""
    files = payload.get("files")
    relative = files.get(key) if isinstance(files, Mapping) else None
    if isinstance(relative, str):
        path = _run_root_path(run_root, relative, f"/{key}.log")
        if path is None:
            raise ExecutionFailed("RUN_INCOMPLETE", f"unsafe {key} evidence path")
        data = _read_run_file_bounded(path, max_bytes=MAX_LOG_BYTES)
        if data is None:
            raise ExecutionFailed(
                "RUN_INCOMPLETE", f"{key} evidence file is missing or too large"
            )
        expected = payload.get("file_digests", {}).get(key) if isinstance(
            payload.get("file_digests"), Mapping
        ) else None
        if expected is not None and _digest(data) != expected:
            raise ExecutionFailed("RUN_INCOMPLETE", f"{key} evidence file changed")
        return data.decode("utf-8", "replace")
    # Legacy journals stored the text inline. Only a bounded preview is trusted
    # here; full logs always come from the evidence file.
    return str(payload.get(f"{key}_preview") or payload.get(key) or "")


def _to_observation(payload: Mapping[str, Any], run_root: Path) -> RunObservation:
    from datacon.asan import ASanSignature

    signature = payload.get("signature")
    parsed = None
    if isinstance(signature, Mapping):
        parsed = ASanSignature(
            error=str(signature.get("error", "")),
            operation=signature.get("operation"),
            access_size=signature.get("access_size"),
            function=signature.get("function"),
            source=signature.get("source"),
        )
    capture_error = payload.get("capture_error")
    return RunObservation(
        version=str(payload.get("version", "")),
        phase=str(payload.get("phase", "")),
        status=str(payload.get("status", "infra_error")),
        exit_code=payload.get("exit_code"),
        stdout=_replay_log_text(payload, run_root, "stdout", "stdout"),
        stderr=_replay_log_text(payload, run_root, "stderr", "stderr"),
        signature=parsed,
        input_digest=payload.get("input_digest"),
        duration_seconds=payload.get("duration_seconds"),
        log_truncated=bool(payload.get("log_truncated", False)),
        capture_error=(
            str(capture_error) if capture_error is not None else None
        ),
    )


def _primary_artifact_suffix(context: ExecutionContext) -> str:
    """Return the trusted run-root suffix for the primary build artifact.

    The suffix derives from the frozen plan (``context.plan``'s
    ``build_spec.outputs``), never from the journal payload: the payload is
    attacker-writable evidence of a past run, so a record that omits
    ``files.outputs`` cannot downgrade a custom-output plan back to the
    legacy ``/parser`` path. v1 jobs and plans without usable outputs keep
    the fail-closed ``/parser`` fallback.
    """
    build_spec = _build_spec_from_context(context) if _is_v2_context(context) else None
    if not isinstance(build_spec, Mapping):
        return "/parser"
    raw_outputs = build_spec.get("outputs")
    if (
        not isinstance(raw_outputs, Sequence)
        or isinstance(raw_outputs, (str, bytes))
        or not raw_outputs
    ):
        return "/parser"
    normalized_outputs: list[str] = []
    for index, raw_output in enumerate(raw_outputs):
        if not isinstance(raw_output, str):
            return "/parser"
        try:
            norm_rel, _ = build_provenance.validate_build_spec_output_path(
                raw_output, index
            )
        except ValueError:
            return "/parser"
        normalized_outputs.append(norm_rel)
    if "parser" in normalized_outputs:
        primary = "parser"
    else:
        primary = next(
            (
                item
                for item in normalized_outputs
                if PurePosixPath(item).name == "parser"
            ),
            normalized_outputs[0],
        )
    return f"/{primary}"


def _reusable_build(
    run_root: Path,
    payload: Mapping[str, Any],
    *,
    check_provenance_face: bool = True,
    artifact_suffix: str = "/parser",
) -> bool:
    if payload.get("status") != "completed":
        return False
    files = payload.get("files")
    digests = payload.get("file_digests")
    if not isinstance(files, Mapping) or not isinstance(digests, Mapping):
        return False
    for key, suffix in (("artifact", artifact_suffix), ("log", "/build.log")):
        relative = files.get(key)
        path = _run_root_path(run_root, relative, suffix)
        if path is None:
            return False
        limit = MAX_ARTIFACT_BYTES if key == "artifact" else MAX_LOG_BYTES
        data = _read_run_file_bounded(path, max_bytes=limit)
        if data is None or _digest(data) != digests.get(key):
            return False
    outputs = files.get("outputs")
    if isinstance(outputs, Mapping) and outputs:
        for relative_output in outputs:
            if (
                _verified_build_output(run_root, payload, str(relative_output))
                is None
            ):
                return False
    if check_provenance_face and files.get("provenance_face") is not None:
        if _verified_provenance_face(run_root, payload) is None:
            return False
    return True


def _reusable_replay(run_root: Path, payload: Mapping[str, Any]) -> bool:
    files = payload.get("files")
    digests = payload.get("file_digests")
    if not isinstance(files, Mapping) or not isinstance(digests, Mapping):
        return False
    for key, suffix in (("stdout", "/stdout.log"), ("stderr", "/stderr.log")):
        relative = files.get(key)
        path = _run_root_path(run_root, relative, suffix)
        if path is None:
            return False
        data = _read_run_file_bounded(path, max_bytes=MAX_LOG_BYTES)
        if data is None or _digest(data) != digests.get(key):
            return False
    return True


def _do_probe(
    context: ExecutionContext,
    sandbox: Any,
    *,
    deadline_seconds: float | None = None,
) -> dict[str, Any]:
    raw_deadline = (
        min(PROBE_TIMEOUT, _remaining(context))
        if deadline_seconds is None
        else deadline_seconds
    )
    try:
        report: ProbeReport = sandbox.probe(
            deadline_seconds=_cap_to_step_budget(context, raw_deadline)
        )
    except SandboxPolicyError:
        raise
    except SandboxUnavailable:
        raise
    if not report.ok:
        raise ExecutionBlocked(
            "POLICY_DENIED", "the isolation probe did not confirm the policy"
        )
    return {
        "tool_id": "sandbox.probe",
        "job_id": context.job_id_text,
        "plan_digest": context.plan_digest,
        "generation": context.generation,
        "status": "completed" if report.ok else "policy_denied",
        "container_id": None,
        "checks": report.checks,
        "compiler_version": report.compiler_version,
        "image_digest": report.image_digest,
        "limits": report.limits,
        "raw": report.raw[-64 * 1024 :],
        "cleanup_errors": list(report.cleanup_errors),
    }


def _expected_build_materials(context: ExecutionContext) -> dict[str, str]:
    manifest = context.case.manifest
    source_vulnerable = manifest["versions"]["vulnerable"]
    source_fixed = manifest["versions"]["fixed"]
    expected: dict[str, str] = {
        manifest["harness"]: _harness_material_digest(context),
        manifest["dependencies"]: context.plan["dependencies_digest"],
    }
    if _is_campaign_context(context):
        expected[fuzz_rules.FUZZ_SHIM_STAGED_NAME] = (
            fuzz_rules.FUZZ_SHIM_REVIEWED_DIGEST
        )
    recipe_digest = _expected_build_recipe_digest(context)
    if isinstance(recipe_digest, str):
        expected[manifest["build_recipe"]] = recipe_digest
    for relative in (source_vulnerable, source_fixed):
        digest = context.materials.get(relative)
        if isinstance(digest, str):
            expected[relative] = digest
    return expected


def _do_build(
    dsn: str,
    context: ExecutionContext,
    sandbox: Any,
    materials_dir: Path,
    material_digests: Mapping[str, str],
    version: str,
    attempt_no: int,
    token: str,
    *,
    deadline_seconds: float | None = None,
) -> dict[str, Any]:
    raw_deadline = (
        min(BUILD_TIMEOUT, _remaining(context) - context.reserve_seconds)
        if deadline_seconds is None
        else deadline_seconds
    )
    deadline = _cap_to_step_budget(context, raw_deadline)
    # Hash the exact tree that will be mounted immediately before the
    # container is created. A replaced recipe/source aborts the step.
    _verify_materialized_tree(materials_dir, material_digests)
    staging: Path | None = None
    failure: BaseException | None = None
    try:
        # The container only ever mounts this copy. A writer limited to the
        # run root cannot replace the bytes after this point.
        staging, staged_materials = _stage_materials(
            context,
            materials_dir,
            material_digests,
            f"build-{version}-attempt-{attempt_no}",
        )
        build_spec = (
            _build_spec_from_context(context) if _is_v2_context(context) else None
        )
        if build_spec is not None:
            try:
                result: BuildResult = sandbox.build(
                    version,
                    materials_dir=staging,
                    compile_args=context.compile_args,
                    deadline_seconds=deadline,
                    expected_materials=_expected_build_materials(context),
                    build_spec=build_spec,
                )
            except SandboxError as error:
                if error.reason_code == build_provenance.BUILD_PROVENANCE_MISSING:
                    raise ExecutionFailed(
                        build_provenance.BUILD_PROVENANCE_MISSING,
                        error.message,
                    ) from error
                raise
        else:
            result = sandbox.build(
                version,
                materials_dir=staging,
                compile_args=context.compile_args,
                deadline_seconds=deadline,
                expected_materials=_expected_build_materials(context),
            )
        return _persist_build(
            dsn,
            context,
            result,
            attempt_no,
            token,
            staged_materials=staged_materials,
        )
    except BaseException as error:
        failure = error
        raise
    finally:
        if staging is not None:
            _cleanup_staging(staging, failure)


def _do_replay(
    dsn: str,
    context: ExecutionContext,
    sandbox: Any,
    build: Mapping[str, Any],
    version: str,
    phase: str,
    input_path: Path,
    timeout_seconds: float,
    attempt_no: int,
    token: str,
) -> dict[str, Any]:
    timeout_seconds = _cap_to_step_budget(context, timeout_seconds)
    files = build.get("files") if isinstance(build.get("files"), Mapping) else {}
    relative = files.get("artifact") if isinstance(files, Mapping) else None
    artifact_path = _run_root_path(
        _work_root(context),
        relative,
        _primary_artifact_suffix(context),
    )
    if artifact_path is None:
        raise ExecutionBlocked(
            "PLAN_MISMATCH", "the build result has no trusted parser path"
        )
    expected_artifact = build.get("artifact_digest")
    if not isinstance(expected_artifact, str):
        raise ExecutionBlocked(
            "PLAN_MISMATCH", "the build result has no trusted parser digest"
        )
    artifact = _read_run_file_bounded(
        artifact_path, max_bytes=MAX_ARTIFACT_BYTES
    )
    if artifact is None:
        raise ExecutionBlocked(
            "MATERIAL_MISSING",
            "the built parser is missing, not regular or too large",
        )
    if _digest(artifact) != expected_artifact:
        raise ExecutionBlocked(
            "PLAN_MISMATCH", "the built parser changed before replay"
        )
    plan_inputs = context.plan.get("inputs")
    if not isinstance(plan_inputs, Mapping):
        raise ExecutionBlocked(
            "MATERIAL_MISSING", "execution plan has no replay inputs mapping"
        )
    expected_input = plan_inputs[
        "normal" if phase == "normal" else "candidate"
    ]
    staging: Path | None = None
    failure: BaseException | None = None
    try:
        # Parser and input are copied out of the run root, re-hashed, and only
        # then mounted. The sandbox also re-checks both digests before create.
        staging, staged_artifact, staged_input = _stage_replay_files(
            context,
            artifact_path,
            expected_artifact,
            input_path,
            expected_input,
            f"replay-{version}-{phase}-attempt-{attempt_no}",
        )
        try:
            result: ReplayResult = sandbox.replay(
                version,
                phase,
                artifact_path=staged_artifact,
                input_path=staged_input,
                asan_options=context.plan["asan_options"],
                timeout_seconds=timeout_seconds,
                deadline_seconds=timeout_seconds,
                expected_artifact_digest=expected_artifact,
                expected_input_digest=expected_input,
            )
        except SandboxError as error:
            if error.reason_code != "TIMEOUT":
                raise
            # A docker exec/wait timeout is replay evidence, not an infrastructure
            # failure: persist a timeout observation so the verdict layer can
            # return INCONCLUSIVE/TIMEOUT instead of FAILED.
            result = ReplayResult(
                version=version,
                phase=phase,
                status="timeout",
                exit_code=None,
                duration_seconds=0.0,
                container_id=None,
                input_digest=expected_input,
                stdout=b"",
                stderr=b"",
                signature=None,
                timed_out=True,
                quota_hit=False,
                log_truncated=False,
                metadata={
                    "image_digest": context.plan["image_digest"],
                    "asan_options": context.plan["asan_options"],
                    "timeout_seconds": timeout_seconds,
                    "error": error.message,
                },
            )
        return _persist_replay(
            dsn,
            context,
            result,
            attempt_no,
            token,
            artifact_digest=expected_artifact,
        )
    except BaseException as error:
        failure = error
        raise
    finally:
        if staging is not None:
            _cleanup_staging(staging, failure)


def _audit_detail_kwargs(error: ExecutionBlocked) -> dict[str, Any]:
    """Forward a block's fine-grained detail (``sub_reason``) to its audit row."""
    details = getattr(error, "details", None)
    return {"audit_detail": dict(details)} if details else {}


def _finish_blocked(
    dsn: str,
    job_id: UUID,
    generation: int,
    error: ExecutionBlocked,
    *,
    case_root: str | None = None,
    run_root: Path | str | None = None,
    context: ExecutionContext | None = None,
    probe: Mapping[str, Any] | None = None,
    builds: Mapping[str, Mapping[str, Any]] | None = None,
    runs: Sequence[Mapping[str, Any]] | None = None,
) -> ExecutionResult:
    """Archive the blocking reason, then commit BLOCKED.

    A block before the plan can be loaded still has a claimed RUNNING job; the
    context is loaded again if possible so the report carries the target. The
    caller's ``case_root``/``run_root`` are reused here: falling back to the
    environment defaults would make ``_archive`` compare the evidence root
    against a different run root and could publish a BLOCKED bundle into the
    real run root.
    """
    if context is None:
        try:
            context = _load_context(
                dsn,
                job_id,
                generation,
                case_root=case_root,
                run_root=run_root,
            )
        except state.StaleGeneration:
            return ExecutionResult("STALE")
        except ExecutionFailed as reload_error:
            # The blocking context could not be reconstructed with the caller's
            # roots. Never archive against guessed roots; keep the failure
            # visible instead of publishing a bundle to the wrong tree.
            return _finish_evidence_path_failure(
                dsn,
                job_id,
                generation,
                ExecutionFailed(
                    "EVIDENCE_WRITE_FAILED",
                    "execution context could not be reconstructed: "
                    f"{reload_error.message}",
                ),
            )
        except ExecutionBlocked:
            # The same (or another) business block prevents reconstruction.
            # There is no archive to misplace, so the original reason stands.
            context = None
    if context is None:
        try:
            finished = state.finish_execution(
                dsn,
                job_id,
                generation=generation,
                state="BLOCKED",
                reason_code=error.reason_code,
                verdict=None,
                verdict_reason=None,
                evidence_status="failed",
                evidence_error=error.message,
                last_error=error.message,
                stage="blocked",
                **_audit_detail_kwargs(error),
            )
        except (state.StateError, state.StaleGeneration):
            return ExecutionResult("STALE")
        if not finished:
            return ExecutionResult("STALE")
        return ExecutionResult("BLOCKED", reason_code=error.reason_code)
    work_root = context.run_root / context.job_id_text / context.plan_digest.split(":")[1]
    build_root = work_root / "run"
    build_root.mkdir(parents=True, exist_ok=True)
    if getattr(context, "budget_summary", None):
        try:
            _refresh_budget_summary_before_archive(dsn, context)
        except (state.StateError, psycopg.Error):
            return ExecutionResult("STALE")
    # One decision, two consumers: the report's bundle_kind and the
    # writer's approval gate must not drift apart.
    bundle_kind = "blocked" if _is_v2_context(context) else "execution"
    try:
        # The artifacts and the report are built inside the archive try
        # (SF-1): _evidence_artifacts refuses a placeholder envelope or
        # budget snapshot with BundleError, and that must converge to
        # FAILED(EVIDENCE_WRITE_FAILED) like every other bundle error
        # instead of escaping the finish path. The refs are derived from
        # the documents this writer really archives, so a blocked policy
        # round claims no approval document.
        artifacts = _evidence_artifacts(
            context,
            build_root,
            builds=builds or {},
            runs=runs or [],
            probe=probe,
            execution_metadata={},
            # The verifier rejects a blocked bundle that still carries
            # the policy admission, so the writer drops it here (v1
            # has no admission row and is unchanged).
            blocked=bundle_kind == "blocked",
        )
        report, markdown = _build_report(
            context,
            verdict="BLOCKED",
            verdict_reason=error.reason_code,
            decision=None,
            builds=builds or {},
            runs=runs or [],
            probe=probe,
            evidence_refs=_report_evidence_refs(artifacts),
            missing=[
                "target execution blocked"
            ],
            error=f"{error.reason_code}: {error.message}",
            bundle_kind=bundle_kind,
        )
        digest, path, archive_error = _archive(
            dsn,
            context,
            report=report,
            report_markdown=markdown,
            artifacts=artifacts,
            verdict="BLOCKED",
        )
    except state.StaleGeneration:
        return ExecutionResult("STALE")
    except (BundleError, state.StateError) as archive_failure:
        archive_error = str(archive_failure)
        digest = path = None
    if archive_error is not None:
        kwargs: dict[str, Any] = {
            "evidence_status": "failed",
            "evidence_error": archive_error,
            "last_error": error.message,
        }
        try:
            finished = state.finish_execution(
                dsn,
                job_id,
                generation=generation,
                state="FAILED",
                reason_code="EVIDENCE_WRITE_FAILED",
                verdict=None,
                verdict_reason=None,
                stage="failed",
                **_audit_detail_kwargs(error),
                **kwargs,
            )
        except (state.StateError, state.StaleGeneration):
            return ExecutionResult("STALE")
        if not finished:
            return ExecutionResult("STALE")
        return ExecutionResult("FAILED", reason_code="EVIDENCE_WRITE_FAILED")
    try:
        finished = state.finish_execution(
            dsn,
            job_id,
            generation=generation,
            state="BLOCKED",
            reason_code=error.reason_code,
            verdict=None,
            verdict_reason=None,
            evidence_digest=digest,
            evidence_path=path,
            evidence_status="archived",
            last_error=error.message,
            stage="blocked",
            **_audit_detail_kwargs(error),
        )
    except (state.StateError, state.StaleGeneration):
        _discard_published_bundle(path)
        return ExecutionResult("STALE")
    if not finished:
        _discard_published_bundle(path)
        return ExecutionResult("STALE")
    return ExecutionResult(
        "BLOCKED",
        reason_code=error.reason_code,
        evidence_digest=digest,
        evidence_path=path,
    )


def _finish_blocked_failed(
    dsn: str, job_id: UUID, generation: int, error: ExecutionFailed
) -> ExecutionResult:
    try:
        finished = state.finish_execution(
            dsn,
            job_id,
            generation=generation,
            state="FAILED",
            reason_code=error.reason_code,
            verdict=None,
            verdict_reason=None,
            evidence_status="failed",
            evidence_error=error.message,
            last_error=error.message,
            stage="failed",
        )
    except (state.StateError, state.StaleGeneration):
        return ExecutionResult("STALE")
    if not finished:
        return ExecutionResult("STALE")
    return ExecutionResult("FAILED", reason_code=error.reason_code)


def _finish_failed(
    dsn: str,
    job_id: UUID,
    generation: int,
    error: ExecutionFailed,
    *,
    context: ExecutionContext,
    probe: Mapping[str, Any] | None,
    builds: Mapping[str, Mapping[str, Any]],
    runs: Sequence[Mapping[str, Any]],
    build_provenance_summary: Mapping[str, Any] | None = None,
) -> ExecutionResult:
    work_root = context.run_root / context.job_id_text / context.plan_digest.split(":")[1]
    build_root = work_root / "run"
    build_root.mkdir(parents=True, exist_ok=True)
    if getattr(context, "budget_summary", None):
        try:
            _refresh_budget_summary_before_archive(dsn, context)
        except (state.StateError, psycopg.Error):
            return ExecutionResult("STALE")
    incomplete = error.reason_code in (
        "RUN_INCOMPLETE",
        "NOT_COMPARABLE",
        "TIMEOUT",
    ) or (
        # §10: an exhausted budget is INCONCLUSIVE once replays exist and
        # FAILED before any replay; no new reason code is introduced.
        error.reason_code == state.BUDGET_EXHAUSTED
        and bool(runs)
    )
    terminal = "INCONCLUSIVE" if incomplete else "FAILED"
    try:
        # The artifacts and the report are built inside the archive try
        # (SF-1): _evidence_artifacts refuses a placeholder envelope or
        # budget snapshot with BundleError, and that must converge to
        # FAILED(EVIDENCE_WRITE_FAILED) instead of escaping the finish
        # path. The refs are derived from the documents this writer really
        # archives, so a policy round lists its admission instead of a
        # review.json it never carried.
        artifacts = _evidence_artifacts(
            context,
            build_root,
            builds=builds,
            runs=runs,
            probe=probe,
            execution_metadata={
                "job_id": context.job_id_text,
                "plan_digest": context.plan_digest,
                "generation": generation,
                "probe": probe,
                "builds": [dict(item) for item in builds.values()],
                "replays": [dict(item) for item in runs],
            },
        )
        report, markdown = _build_report(
            context,
            verdict=terminal,
            verdict_reason=error.reason_code,
            decision=None,
            builds=builds,
            runs=runs,
            probe=probe,
            evidence_refs=_report_evidence_refs(artifacts),
            missing=["required replay evidence is incomplete"] if incomplete else ["execution failed"],
            error=f"{error.reason_code}: {error.message}",
            build_provenance_summary=build_provenance_summary,
        )
        digest, path, archive_error = _archive(
            dsn,
            context,
            report=report,
            report_markdown=markdown,
            artifacts=artifacts,
            verdict=terminal,
        )
    except state.StaleGeneration:
        return ExecutionResult("STALE")
    except (BundleError, state.StateError) as archive_failure:
        digest = path = None
        archive_error = str(archive_failure)
    if archive_error is not None:
        try:
            finished = state.finish_execution(
                dsn,
                job_id,
                generation=generation,
                state="FAILED",
                reason_code="EVIDENCE_WRITE_FAILED",
                verdict=None,
                verdict_reason=None,
                evidence_status="failed",
                evidence_error=archive_error,
                last_error=error.message,
                stage="failed",
            )
        except (state.StateError, state.StaleGeneration):
            return ExecutionResult("STALE")
        if not finished:
            return ExecutionResult("STALE")
        return ExecutionResult(
            "FAILED",
            verdict=None,
            verdict_reason=None,
            reason_code="EVIDENCE_WRITE_FAILED",
        )
    try:
        finished = state.finish_execution(
            dsn,
            job_id,
            generation=generation,
            state=terminal,
            reason_code=error.reason_code,
            verdict=terminal if incomplete else None,
            verdict_reason=error.reason_code if incomplete else None,
            evidence_digest=digest,
            evidence_path=path,
            evidence_status="archived",
            last_error=error.message,
            stage="failed",
        )
    except (state.StateError, state.StaleGeneration):
        _discard_published_bundle(path)
        return ExecutionResult("STALE")
    if not finished:
        _discard_published_bundle(path)
        return ExecutionResult("STALE")
    return ExecutionResult(
        terminal,
        verdict=terminal if incomplete else None,
        verdict_reason=error.reason_code if incomplete else None,
        reason_code=error.reason_code,
        evidence_digest=digest,
        evidence_path=path,
    )

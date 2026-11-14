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
import os
from pathlib import Path
import shutil
import stat
import uuid
from typing import Any, Callable, Mapping, Sequence
from uuid import UUID

from datacon import contracts, jsonutil, state
from datacon.cases import CaseConfigurationError, CaseDefinition, load_registry
from datacon.evidence import BundleError, verify_bundle, write_bundle
from datacon.tools.sandbox import (
    BuildResult,
    DockerSandbox,
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
)

ARCHIVE_RESERVE_MAX = 60
ARCHIVE_RESERVE_RATIO = 0.1
BUILD_TIMEOUT = 300.0
PROBE_TIMEOUT = 120.0
MAX_ATTEMPTS_PER_STEP = 2
FAULT_ENV = "DATACON_FAULT_AFTER_TOOL"
TEST_MODE_ENV = "DATACON_TEST_MODE"


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
    review: dict[str, Any]
    case: CaseDefinition
    case_root: Path
    manifest_case: dict[str, Any]
    materials: dict[str, str]
    material_root: Path
    run_root: Path
    playbook: dict[str, Any]
    image: str
    isolation: IsolationPolicy
    limits: ResourceLimits
    compile_args: tuple[str, ...]
    deadline_at: datetime
    reserve_seconds: float

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


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace(
        "+00:00", "Z"
    )


def _digest(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


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
    try:
        computed_digest = contracts.plan_digest(plan)
    except ValueError as error:
        raise ExecutionBlocked("PLAN_MISMATCH", f"frozen plan is invalid: {error}") from error
    if computed_digest != plan_row["plan_digest"]:
        raise ExecutionBlocked(
            "PLAN_MISMATCH", "frozen plan digest does not match its content"
        )
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
    expected_materials = {
        "harness": (manifest["harness"], plan["harness_digest"]),
        "build_recipe": (manifest["build_recipe"], plan["build_recipe_digest"]),
        "dependencies": (manifest["dependencies"], plan["dependencies_digest"]),
        "patch": (case.repository["patch"], plan["repository"]["patch_digest"]),
        "source_vulnerable": (
            source_vulnerable,
            materials.get(source_vulnerable),
        ),
        "source_fixed": (source_fixed, materials.get(source_fixed)),
        "input_normal": (
            manifest_case["inputs"]["normal"],
            plan["inputs"]["normal"],
        ),
        "input_candidate": (
            manifest_case["inputs"]["candidate"],
            plan["inputs"]["candidate"],
        ),
    }
    for label, (relative, expected_digest) in expected_materials.items():
        if not isinstance(expected_digest, str):
            raise ExecutionBlocked(
                "MATERIAL_MISSING", f"plan has no digest for {label}"
            )
        try:
            _, actual = case.read_material(relative, expected_digest)
        except CaseConfigurationError as error:
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

    try:
        compile_args = _extract_compile_args(
            case.read_material(manifest["build_recipe"], plan["build_recipe_digest"])[0]
        )
    except CaseConfigurationError as error:
        raise ExecutionBlocked(error.reason_code, error.message) from error

    deadline = job["execute_deadline_at"]
    if deadline is None:
        raise ExecutionBlocked("DEADLINE_EXCEEDED", "execution deadline is not fixed")
    if deadline.tzinfo is None:
        deadline = deadline.replace(tzinfo=timezone.utc)
    limits = plan["limits"]
    context = ExecutionContext(
        job_id=job_id,
        generation=generation,
        job=job,
        plan=plan,
        plan_digest=plan_row["plan_digest"],
        review=review,
        case=case,
        case_root=registry.root,
        manifest_case=manifest_case,
        materials=materials,
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
    )
    return context


def _assert_context_unchanged(dsn: str, context: ExecutionContext) -> None:
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
    if plan_row is None or plan_row["plan_digest"] != context.plan_digest:
        raise ExecutionBlocked("PLAN_MISMATCH", "the frozen plan changed")
    try:
        if contracts.plan_digest(plan_row["plan"]) != context.plan_digest:
            raise ExecutionBlocked(
                "PLAN_MISMATCH", "the frozen plan content no longer matches its digest"
            )
    except ValueError as error:
        raise ExecutionBlocked("PLAN_MISMATCH", f"the frozen plan is invalid: {error}") from error
    if review is None or review["decision"] != "approve" or review["plan_digest"] != context.plan_digest:
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
    expected_digests = {
        "harness": context.plan["harness_digest"],
        "build_recipe": context.plan["build_recipe_digest"],
        "dependencies": context.plan["dependencies_digest"],
        "source_vulnerable": context.materials.get(
            context.case.manifest["versions"]["vulnerable"]
        ),
        "source_fixed": context.materials.get(
            context.case.manifest["versions"]["fixed"]
        ),
        "input_normal": context.plan["inputs"]["normal"],
        "input_candidate": context.plan["inputs"]["candidate"],
        "advisory": context.plan["intel"]["content_digest"],
        "bundle": context.plan["repository"]["bundle_digest"],
    }
    for label, relative in (
        ("harness", case.manifest["harness"]),
        ("build_recipe", case.manifest["build_recipe"]),
        ("dependencies", case.manifest["dependencies"]),
        ("source_vulnerable", case.manifest["versions"]["vulnerable"]),
        ("source_fixed", case.manifest["versions"]["fixed"]),
        ("input_normal", context.manifest_case["inputs"]["normal"]),
        ("input_candidate", context.manifest_case["inputs"]["candidate"]),
        ("advisory", case.advisory["path"]),
        ("bundle", case.repository["bundle"]),
    ):
        try:
            case.read_material(relative, expected_digests.get(label))
        except CaseConfigurationError as error:
            raise ExecutionBlocked(
                "MATERIAL_MISSING", f"{label} is no longer readable: {error.message}"
            ) from error


def _materialize(context: ExecutionContext, run_root: Path) -> tuple[Path, dict[str, Path]]:
    """Write the approved materials and inputs as read-only files."""
    target = run_root / "materials"
    expected = {
        "harness": (context.case.manifest["harness"], context.plan["harness_digest"]),
        "build_recipe": (
            context.case.manifest["build_recipe"],
            context.plan["build_recipe_digest"],
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
        "input_normal": (context.manifest_case["inputs"]["normal"], context.plan["inputs"]["normal"]),
        "input_candidate": (
            context.manifest_case["inputs"]["candidate"],
            context.plan["inputs"]["candidate"],
        ),
    }
    payloads: dict[str, bytes] = {}
    for label, (relative, digest) in expected.items():
        try:
            data, actual = context.case.read_material(relative, digest)
        except CaseConfigurationError as error:
            raise ExecutionBlocked(error.reason_code, error.message) from error
        if digest is None:
            digest = context.materials.get(relative)
        if digest is not None and actual != digest:
            raise ExecutionBlocked(
                "MATERIAL_MISSING", f"material {label} digest drifted while materializing"
            )
        payloads[relative] = data

    candidate_path = target / "inputs" / "candidate.txt"
    normal_path = target / "inputs" / "normal.txt"
    # Input paths from the manifest are preserved for evidence; the replay
    # command always uses these two stable names.
    for label, destination, relative in (
        ("candidate", candidate_path, context.manifest_case["inputs"]["candidate"]),
        ("normal", normal_path, context.manifest_case["inputs"]["normal"]),
    ):
        data = payloads[relative]
        if _digest(data) != context.plan["inputs"][label]:
            raise ExecutionBlocked(
                "MATERIAL_MISSING", f"{label} input digest drifted"
            )

    if target.exists():
        target.chmod(0o755)
        _verify_materialized(target, payloads)
        for label, path, expected in (
            ("candidate", candidate_path, context.plan["inputs"]["candidate"]),
            ("normal", normal_path, context.plan["inputs"]["normal"]),
        ):
            if path.is_symlink() or not path.is_file():
                raise ExecutionBlocked("MATERIAL_MISSING", f"materialized {label} input is missing")
            if _digest(path.read_bytes()) != expected:
                raise ExecutionBlocked("MATERIAL_MISSING", f"materialized {label} input drifted")
        return target, {
            "candidate": candidate_path,
            "normal": normal_path,
            "build_recipe": target / context.case.manifest["build_recipe"],
        }
    temporary = target.parent / f".materials-tmp-{uuid.uuid4().hex}"
    if temporary.exists():
        raise ExecutionBlocked("MATERIAL_MISSING", "temporary material path exists")
    temporary.mkdir(mode=0o755, parents=True)
    try:
        for relative, data in payloads.items():
            output = temporary / Path(relative)
            output.parent.mkdir(parents=True, exist_ok=True)
            output.write_bytes(data)
            output.chmod(0o444)
        build_recipe = temporary / context.case.manifest["build_recipe"]
        build_recipe.chmod(0o555)
        (temporary / "inputs").mkdir(parents=True, exist_ok=True)
        candidate_path = temporary / "inputs" / "candidate.txt"
        normal_path = temporary / "inputs" / "normal.txt"
        for path, data in (
            (candidate_path, payloads[context.manifest_case["inputs"]["candidate"]]),
            (normal_path, payloads[context.manifest_case["inputs"]["normal"]]),
        ):
            if path.exists():
                path.chmod(0o644)
            path.write_bytes(data)
            path.chmod(0o444)
        temporary.chmod(0o755)
        temporary.rename(target)
    except BaseException:
        shutil.rmtree(temporary, ignore_errors=True)
        raise
    return target, {
        "candidate": target / "inputs" / "candidate.txt",
        "normal": target / "inputs" / "normal.txt",
        "build_recipe": target / context.case.manifest["build_recipe"],
    }


def _verify_materialized(target: Path, payloads: Mapping[str, bytes]) -> None:
    for relative, expected in payloads.items():
        path = target / Path(relative)
        if path.is_symlink() or not path.is_file():
            raise ExecutionBlocked(
                "MATERIAL_MISSING", f"materialized file is missing: {relative}"
            )
        if path.read_bytes() != expected:
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


def _journal_secret_path() -> Path:
    """Return the HMAC key path, outside the writable run root."""
    explicit = os.getenv("DATACON_JOURNAL_SECRET_FILE")
    if explicit:
        return Path(explicit)
    evidence_root = Path(
        os.getenv("DATACON_EVIDENCE_ROOT", ".datacon/evidence")
    ).expanduser()
    return evidence_root.parent / ".datacon-journal-secret"


def _journal_secret(*, create: bool) -> bytes | None:
    path = _journal_secret_path()
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
        data = path.read_bytes()
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


def _run_step(
    dsn: str,
    context: ExecutionContext,
    *,
    step_key: str,
    input_digest: str | None,
    action: Callable[[int, str], Any],
    reusable: Callable[[Mapping[str, Any]], bool] | None = None,
) -> tuple[Any, bool]:
    """Execute one logical step with generation fencing and crash recovery.

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
        attempt_token=token,
    )
    if not stored:
        raise state.StaleGeneration("the worker lease was lost before the step")
    result = action(attempt_no, token)
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


def _write_journal(
    run_root: Path,
    step_key: str,
    attempt_no: int,
    generation: int,
    payload: Mapping[str, Any],
) -> Path:
    path = _journal_path(run_root, step_key, attempt_no, generation)
    root = run_root.resolve()
    path.parent.mkdir(parents=True, exist_ok=True)
    parent = path.parent.resolve()
    if parent != root and root not in parent.parents:
        raise ExecutionFailed(
            "EVIDENCE_WRITE_FAILED", "journal path escaped the run root"
        )
    secret = _journal_secret(create=True)
    assert secret is not None
    document = dict(payload)
    document["hmac"] = _journal_hmac(document, secret)
    temporary = path.with_suffix(".tmp")
    if temporary.is_symlink():
        temporary.unlink()
    temporary.write_text(
        json.dumps(document, ensure_ascii=False, sort_keys=True), encoding="utf-8"
    )
    temporary.replace(path)
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
    secret = _journal_secret(create=False)
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
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError, UnicodeError):
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
    run_root: Path, path: Path, data: bytes, mode: int
) -> None:
    """Write a file under the run root without following a planted symlink."""
    root = run_root.resolve()
    path.parent.mkdir(parents=True, exist_ok=True)
    parent = path.parent.resolve()
    if parent != root and root not in parent.parents:
        raise ExecutionFailed("EVIDENCE_WRITE_FAILED", "run evidence path escaped its root")
    if path.is_symlink():
        path.unlink()
    elif path.exists():
        if path.is_dir():
            raise ExecutionFailed(
                "EVIDENCE_WRITE_FAILED", "run evidence path is a directory"
            )
        # A prior attempt may have chmod 0555 evidence. Replacing it must not
        # follow a symlink or honour the old read-only mode.
        path.unlink()
    try:
        path.write_bytes(data)
        path.chmod(mode)
    except OSError as error:
        raise ExecutionFailed(
            "EVIDENCE_WRITE_FAILED", f"cannot write run evidence: {error}"
        ) from error


def _persist_build(
    dsn: str,
    context: ExecutionContext,
    run_root: Path,
    result: BuildResult,
    attempt_no: int,
    token: str,
) -> dict[str, Any]:
    directory = run_root / "build" / result.version
    directory.mkdir(parents=True, exist_ok=True)
    log_path = directory / "build.log"
    _write_run_file(run_root, log_path, result.log, 0o600)
    artifact_path = directory / "parser"
    if result.artifact is not None and result.artifact_digest is not None:
        _write_run_file(run_root, artifact_path, result.artifact, 0o555)
        if _digest(result.artifact) != result.artifact_digest:
            raise ExecutionFailed("BUILD_FAILED", "build artifact digest changed")
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
        "files": {
            "log": str(log_path.relative_to(run_root)),
            "artifact": str(artifact_path.relative_to(run_root))
            if artifact_path.is_file()
            else None,
        },
        "file_digests": {
            "log": _digest(result.log),
            "artifact": result.artifact_digest,
        },
        **result.as_dict(),
    }
    _write_journal(
        run_root,
        f"build:{result.version}",
        attempt_no,
        context.generation,
        payload,
    )
    return {
        key: value for key, value in payload.items() if key != "attempt_token"
    }


def _persist_replay(
    dsn: str,
    context: ExecutionContext,
    run_root: Path,
    result: ReplayResult,
    attempt_no: int,
    token: str,
) -> dict[str, Any]:
    directory = run_root / "replay" / result.version / result.phase
    directory.mkdir(parents=True, exist_ok=True)
    stdout_path = directory / "stdout.log"
    stderr_path = directory / "stderr.log"
    _write_run_file(run_root, stdout_path, result.stdout, 0o600)
    _write_run_file(run_root, stderr_path, result.stderr, 0o600)
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
    _write_journal(
        run_root,
        _replay_step(result.version, result.phase),
        attempt_no,
        context.generation,
        payload,
    )
    return {
        key: value for key, value in payload.items() if key != "attempt_token"
    }


def _replay_step(version: str, phase: str) -> str:
    return f"replay:{version}:{phase}"




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
) -> tuple[dict[str, Any], str]:
    report = {
        "schema_version": 1,
        "job_id": context.job_id_text,
        "plan_digest": context.plan_digest,
        "cve_id": context.plan["cve_id"],
        "case_id": context.plan["case_id"],
        "state": verdict,
        "verdict": verdict,
        "reason_code": verdict_reason,
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
        "budget": context.plan["limits"],
        "inputs": {
            "candidate": context.plan["inputs"]["candidate"],
            "normal": context.plan["inputs"]["normal"],
        },
        "review": {
            "reviewer_id": context.review["reviewer_id"],
            "decision": context.review["decision"],
            "decided_at": jsonutil.timestamp(context.review["decided_at"]),
            "plan_digest": context.review["plan_digest"],
        },
        "signature": context.plan["asan_signature"],
        "builds": [dict(item) for item in builds.values()],
        "replays": [dict(item) for item in runs],
        "rule": decision.as_dict() if decision else None,
        "evidence_refs": list(evidence_refs),
        "missing": list(missing),
        "error": error,
        "created_at": _utc_now(),
    }
    lines = [
        "# DataCon evidence report",
        "",
        f"- Job: `{context.job_id_text}`",
        f"- Plan: `{context.plan_digest}`",
        f"- Case: `{context.plan['case_id']}` / `{context.plan['cve_id']}`",
        f"- Verdict: **{verdict or 'PENDING'}**",
        f"- Reason: `{verdict_reason or ''}`",
        f"- Image: `{context.image}`",
        f"- Platform: `{context.plan['platform']}`",
        f"- ASan options: `{context.plan['asan_options']}`",
        f"- Compile args: `{' '.join(context.compile_args)}`",
        "",
        "## Revisions",
        "",
        f"- vulnerable: `{context.plan['revisions']['vulnerable']}`",
        f"- fixed: `{context.plan['revisions']['fixed']}`",
        "",
        "## Builds",
        "",
        "| Version | Status | Exit | Artifact |",
        "| --- | --- | ---: | --- |",
    ]
    for version in ("vulnerable", "fixed"):
        build = builds.get(version, {})
        lines.append(
            "| {version} | {status} | {exit} | `{artifact}` |".format(
                version=version,
                status=build.get("status", "missing"),
                exit=build.get("exit_code", ""),
                artifact=build.get("artifact_digest") or "",
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
    for run in runs:
        signature = run.get("signature") or {}
        lines.append(
            "| {version} | {phase} | {status} | {exit} | {asan} |".format(
                version=run.get("version", ""),
                phase=run.get("phase", ""),
                status=run.get("status", ""),
                exit=run.get("exit_code", ""),
                asan=signature.get("error", ""),
            )
        )
    lines.extend(
        [
            "",
            "## Rule trace",
            "",
            "```json",
            json.dumps(decision.as_dict() if decision else {}, indent=2, sort_keys=True),
            "```",
            "",
            "## Evidence",
            "",
        ]
    )
    for reference in evidence_refs:
        lines.append(f"- `{reference}`")
    if missing:
        lines.extend(["", "## Missing", ""])
        for item in missing:
            lines.append(f"- `{item}`")
    if error:
        lines.extend(["", "## Error", "", error])
    lines.extend(
        [
            "",
            "The report is generated deterministically from persisted runs. "
            "Raw sanitizer logs and metadata are archived next to this report.",
            "",
        ]
    )
    return report, "\n".join(lines)


def _evidence_artifacts(
    context: ExecutionContext,
    run_root: Path,
    *,
    builds: Mapping[str, Mapping[str, Any]],
    runs: Sequence[Mapping[str, Any]],
    probe: Mapping[str, Any] | None,
    execution_metadata: Mapping[str, Any],
) -> dict[str, tuple[str, bytes | Path]]:
    artifacts: dict[str, tuple[str, bytes | Path]] = {
        "plan.json": ("plan", jsonutil.canonical_bytes(context.plan) + b"\n"),
        "review.json": (
            "review",
            jsonutil.canonical_bytes(
                {
                    "reviewer_id": context.review["reviewer_id"],
                    "decision": context.review["decision"],
                    "plan_digest": context.review["plan_digest"],
                    "decided_at": jsonutil.timestamp(context.review["decided_at"]),
                }
            )
            + b"\n",
        ),
        "metadata/execution.json": (
            "execution_metadata",
            jsonutil.canonical_bytes(execution_metadata) + b"\n",
        ),
    }
    if probe is not None:
        artifacts["metadata/probe.json"] = (
            "probe",
            jsonutil.canonical_bytes(probe) + b"\n",
        )
    for version in ("vulnerable", "fixed"):
        build = builds.get(version) or {}
        directory = run_root / "build" / version
        if (directory / "build.log").is_file():
            artifacts[f"build/{version}/build.log"] = (
                "build_log",
                directory / "build.log",
            )
        if (directory / "metadata.json").is_file():
            artifacts[f"build/{version}/metadata.json"] = (
                "build_metadata",
                directory / "metadata.json",
            )
        if (directory / "parser").is_file() and build.get("artifact_digest"):
            artifacts[f"build/{version}/parser"] = (
                "build_artifact",
                directory / "parser",
            )
        metadata_path = directory / "metadata.json"
        if not metadata_path.is_file() and build:
            artifacts[f"build/{version}/metadata.json"] = (
                "build_metadata",
                jsonutil.canonical_bytes(dict(build)) + b"\n",
            )
    for run in runs:
        version = run.get("version", "")
        phase = run.get("phase", "")
        directory = run_root / "replay" / version / phase
        if (directory / "stdout.log").is_file():
            artifacts[f"replay/{version}/{phase}/stdout.log"] = (
                "replay_stdout",
                directory / "stdout.log",
            )
        if (directory / "stderr.log").is_file():
            role = "asan_log" if run.get("signature") else "replay_stderr"
            artifacts[f"replay/{version}/{phase}/stderr.log"] = (
                role,
                directory / "stderr.log",
            )
        artifacts[f"replay/{version}/{phase}/metadata.json"] = (
            "replay_metadata",
            jsonutil.canonical_bytes(dict(run)) + b"\n",
        )
    manifest = context.case.manifest
    for relative, role in (
        (manifest["harness"], "material_harness"),
        (manifest["build_recipe"], "material_build_recipe"),
        (manifest["dependencies"], "material_dependencies"),
        (context.manifest_case["inputs"]["normal"], "material_input_normal"),
        (context.manifest_case["inputs"]["candidate"], "material_input_candidate"),
        (manifest["versions"]["vulnerable"], "material_source_vulnerable"),
        (manifest["versions"]["fixed"], "material_source_fixed"),
    ):
        path = run_root / "materials" / Path(relative)
        if path.is_file():
            artifacts[f"materials/{relative}"] = (role, path)
    return artifacts


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
    state.mark_archiving(dsn, context.job_id, generation=context.generation)
    evidence_root = Path(
        os.getenv("DATACON_EVIDENCE_ROOT", ".datacon/evidence")
    ).resolve()
    temporary = evidence_root / f".{context.job_id_text}.tmp-{uuid.uuid4().hex}"
    backup = evidence_root / f".{context.job_id_text}.old-{uuid.uuid4().hex}"
    try:
        evidence_root.mkdir(mode=0o700, parents=True, exist_ok=True)
        evidence_root.chmod(0o700)
        bundle = evidence_root / context.job_id_text
        if bundle.is_symlink():
            raise BundleError("SYMLINK", "evidence destination is a symlink")
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
        bundle = evidence_root / context.job_id_text
        if backup.exists() and not bundle.exists():
            backup.rename(bundle)
        return None, None, f"{error.reason_code}: {error.message}"
    except OSError as error:
        shutil.rmtree(temporary, ignore_errors=True)
        bundle = evidence_root / context.job_id_text
        if backup.exists() and not bundle.exists():
            backup.rename(bundle)
        return None, None, f"EVIDENCE_WRITE_FAILED: {error}"

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
    probe = completed.get("sandbox.probe")
    builds: dict[str, dict[str, Any]] = {}
    for version in ("vulnerable", "fixed"):
        result = completed.get(f"build:{version}")
        if result is not None and _reusable_build(build_root, result):
            builds[version] = result
    runs: list[dict[str, Any]] = []
    for version in ("vulnerable", "fixed"):
        for phase in ("normal", "candidate_1", "candidate_2"):
            result = completed.get(_replay_step(version, phase))
            if result is not None and _reusable_replay(build_root, result):
                runs.append(result)
    complete = (
        isinstance(probe, dict)
        and len(builds) == 2
        and len(runs) == 6
    )
    missing: list[str] = []
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
            state.finish_execution(
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
        return ExecutionResult("INCONCLUSIVE", reason_code="EVIDENCE_INCOMPLETE")

    report, report_markdown = _build_report(
        context,
        verdict=decision.verdict,
        verdict_reason=decision.reason_code,
        decision=decision,
        builds=builds,
        runs=runs,
        probe=probe,
        evidence_refs=["report.json", "report.md", "plan.json", "review.json"],
        missing=missing,
    )
    attempt_rows = []
    for row in rows:
        item = {
            key: value for key, value in row.items() if key != "attempt_token"
        }
        for field in ("started_at", "finished_at"):
            if item.get(field) is not None:
                item[field] = jsonutil.timestamp(item[field])
        attempt_rows.append(item)
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
            "builds": builds,
            "replays": runs,
            "attempts": attempt_rows,
        },
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
            state.finish_execution(
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
        return ExecutionResult("FAILED", reason_code="EVIDENCE_WRITE_FAILED")
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
    except state.StaleGeneration:
        return ExecutionResult("STALE")
    if not finished:
        return ExecutionResult("STALE")
    return ExecutionResult(
        final_state,
        verdict=decision.verdict,
        verdict_reason=decision.reason_code,
        evidence_digest=digest,
        evidence_path=path,
        reason_code=reason_code,
    )


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
        # the blocking reason and commit BLOCKED.
        return _finish_blocked(dsn, job_id, generation, error)
    except ExecutionFailed as error:
        return _finish_blocked_failed(dsn, job_id, generation, error)

    if context.job["state"] == "ARCHIVING":
        return _archive_only(dsn, context)

    try:
        _assert_budget(context, purpose="starting isolated execution")
    except ExecutionBlocked as error:
        return _finish_blocked(dsn, job_id, generation, error, context=context)

    work_root = context.run_root / context.job_id_text / context.plan_digest.split(":")[1]
    work_root.mkdir(parents=True, exist_ok=True)
    work_root.chmod(0o700)
    build_root = work_root / "run"
    build_root.mkdir(parents=True, exist_ok=True)
    build_root.chmod(0o700)
    try:
        materials_dir, inputs = _materialize(context, build_root)
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
        )
    reclaim = getattr(sandbox, "reclaim_job", None)
    if callable(reclaim):
        try:
            reclaim()
        except SandboxError:
            pass

    probe_payload: dict[str, Any] | None = None
    builds: dict[str, dict[str, Any]] = {}
    runs: list[dict[str, Any]] = []
    decision: VerdictDecision | None = None
    missing: list[str] = []
    try:
        probe_result, _ = _run_step(
            dsn,
            context,
            step_key="sandbox.probe",
            input_digest=context.plan_digest,
            action=lambda attempt_no, token: _do_probe(context, sandbox),
            reusable=lambda payload: payload.get("status") == "completed",
        )
        probe_payload = probe_result
        for version in ("vulnerable", "fixed"):
            _assert_context_unchanged(dsn, context)
            _assert_budget(context, purpose=f"building {version}")
            result, reused = _run_step(
                dsn,
                context,
                step_key=f"build:{version}",
                input_digest=context.plan["analysis_digest"],
                action=lambda attempt_no, token, version=version: _do_build(
                    dsn, context, sandbox, materials_dir, version, attempt_no, token
                ),
                reusable=lambda payload: _reusable_build(build_root, payload),
            )
            builds[version] = result
            if result.get("status") != "completed":
                raise ExecutionFailed(
                    "BUILD_FAILED",
                    f"{version} build ended with status {result.get('status')}",
                )
        for version in ("vulnerable", "fixed"):
            for phase in ("normal", "candidate_1", "candidate_2"):
                _assert_context_unchanged(dsn, context)
                _assert_budget(context, purpose=f"replaying {version}/{phase}")
                input_path = inputs["normal"] if phase == "normal" else inputs["candidate"]
                step_key = _replay_step(version, phase)
                remaining = _remaining(context) - context.reserve_seconds
                replay_timeout = min(
                    float(context.plan["limits"]["replay_seconds"]),
                    max(1.0, remaining),
                )
                result, reused = _run_step(
                    dsn,
                    context,
                    step_key=step_key,
                    input_digest=_digest(input_path.read_bytes()),
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
                )
                runs.append(result)
        for run in runs:
            expected = (
                context.plan["inputs"]["normal"]
                if run.get("phase") == "normal"
                else context.plan["inputs"]["candidate"]
            )
            if run.get("input_digest") != expected:
                missing.append(f"input digest mismatch for {run.get('version')}/{run.get('phase')}")
        policy = _policy_from_context(context)
        if missing:
            decision = VerdictDecision(
                "INCONCLUSIVE",
                "NOT_COMPARABLE",
                "required input digests do not match the approved plan",
                {"priority": list(PRIORITY)},
            )
        else:
            decision = decide_verdict(
                policy, [_to_observation(run, build_root) for run in runs], builds=builds
            )
        verdict = decision.verdict
        verdict_reason = decision.reason_code
    except ExecutionBlocked as error:
        return _finish_blocked(
            dsn, job_id, generation, error, context=context, probe=probe_payload, builds=builds, runs=runs
        )
    except ExecutionFailed as error:
        return _finish_failed(
            dsn, job_id, generation, error, context=context, probe=probe_payload, builds=builds, runs=runs
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
        return _finish_failed(
            dsn,
            job_id,
            generation,
            ExecutionFailed(
                "TIMEOUT" if error.reason_code == "TIMEOUT" else "RUN_INCOMPLETE",
                error.message,
            ),
            context=context,
            probe=probe_payload,
            builds=builds,
            runs=runs,
        )
    except state.StaleGeneration:
        return ExecutionResult("STALE")

    attempt_rows = []
    for row in state.execution_attempts(dsn, job_id, generation):
        item = {
            key: value for key, value in row.items() if key != "attempt_token"
        }
        for field in ("started_at", "finished_at"):
            if item.get(field) is not None:
                item[field] = jsonutil.timestamp(item[field])
        attempt_rows.append(item)
    execution_metadata = {
        "job_id": context.job_id_text,
        "plan_digest": context.plan_digest,
        "generation": generation,
        "probe": probe_payload,
        "builds": builds,
        "replays": runs,
        "attempts": attempt_rows,
    }
    evidence_refs = [
        "report.json",
        "report.md",
        "plan.json",
        "review.json",
        "metadata/execution.json",
    ]
    report, report_markdown = _build_report(
        context,
        verdict=decision.verdict,
        verdict_reason=decision.reason_code,
        decision=decision,
        builds=builds,
        runs=runs,
        probe=probe_payload,
        evidence_refs=evidence_refs,
        missing=missing,
    )
    artifacts = _evidence_artifacts(
        context,
        build_root,
        builds=builds,
        runs=runs,
        probe=probe_payload,
        execution_metadata=execution_metadata,
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
    except (state.StateError, state.StaleGeneration) as error:
        return ExecutionResult("STALE")
    if archive_error is not None:
        try:
            state.finish_execution(
                dsn,
                job_id,
                generation=context.generation,
                state="FAILED",
                reason_code="EVIDENCE_WRITE_FAILED",
                verdict=decision.verdict,
                verdict_reason=decision.reason_code,
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
        return ExecutionResult(
            "FAILED",
            verdict=decision.verdict,
            verdict_reason=decision.reason_code,
            reason_code="EVIDENCE_WRITE_FAILED",
        )
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
    except state.StaleGeneration:
        return ExecutionResult("STALE")
    if not finished:
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
        if ".." in Path(relative).parts or not relative.startswith("replay/"):
            raise ExecutionFailed("RUN_INCOMPLETE", f"unsafe {key} evidence path")
        path = run_root / relative
        if path.is_symlink() or not path.is_file():
            raise ExecutionFailed("RUN_INCOMPLETE", f"{key} evidence file is missing")
        data = path.read_bytes()
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
    )


def _reusable_build(run_root: Path, payload: Mapping[str, Any]) -> bool:
    if payload.get("status") != "completed":
        return False
    files = payload.get("files")
    digests = payload.get("file_digests")
    if not isinstance(files, Mapping) or not isinstance(digests, Mapping):
        return False
    for key, prefix in (("artifact", "build/"), ("log", "build/")):
        relative = files.get(key)
        if not isinstance(relative, str) or not relative.startswith(prefix):
            return False
        path = run_root / relative
        if path.is_symlink() or not path.is_file():
            return False
        if _digest(path.read_bytes()) != digests.get(key):
            return False
    return True


def _reusable_replay(run_root: Path, payload: Mapping[str, Any]) -> bool:
    files = payload.get("files")
    digests = payload.get("file_digests")
    if not isinstance(files, Mapping) or not isinstance(digests, Mapping):
        return False
    for key in ("stdout", "stderr"):
        relative = files.get(key)
        if not isinstance(relative, str) or not relative.startswith("replay/"):
            return False
        path = run_root / relative
        if path.is_symlink() or not path.is_file():
            return False
        if _digest(path.read_bytes()) != digests.get(key):
            return False
    return True


def _do_probe(context: ExecutionContext, sandbox: Any) -> dict[str, Any]:
    try:
        report: ProbeReport = sandbox.probe(deadline_seconds=min(PROBE_TIMEOUT, _remaining(context)))
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
        "status": "completed" if report.ok else "policy_denied",
        "container_id": None,
        "checks": report.checks,
        "compiler_version": report.compiler_version,
        "image_digest": report.image_digest,
        "limits": report.limits,
        "raw": report.raw[-64 * 1024 :],
    }


def _do_build(
    dsn: str,
    context: ExecutionContext,
    sandbox: Any,
    materials_dir: Path,
    version: str,
    attempt_no: int,
    token: str,
) -> dict[str, Any]:
    deadline = max(1.0, min(BUILD_TIMEOUT, _remaining(context) - context.reserve_seconds))
    result: BuildResult = sandbox.build(
        version,
        materials_dir=materials_dir,
        compile_args=context.compile_args,
        deadline_seconds=deadline,
    )
    return _persist_build(
        dsn, context, materials_dir.parent, result, attempt_no, token
    )


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
    artifact_path = context.run_root / context.job_id_text / context.plan_digest.split(":")[1] / "run" / "build" / version / "parser"
    try:
        result: ReplayResult = sandbox.replay(
            version,
            phase,
            artifact_path=artifact_path,
            input_path=input_path,
            asan_options=context.plan["asan_options"],
            timeout_seconds=timeout_seconds,
            deadline_seconds=timeout_seconds,
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
            input_digest=_digest(input_path.read_bytes()),
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
        context.run_root / context.job_id_text / context.plan_digest.split(":")[1] / "run",
        result,
        attempt_no,
        token,
    )


def _finish_blocked(
    dsn: str,
    job_id: UUID,
    generation: int,
    error: ExecutionBlocked,
    *,
    context: ExecutionContext | None = None,
    probe: Mapping[str, Any] | None = None,
    builds: Mapping[str, Mapping[str, Any]] | None = None,
    runs: Sequence[Mapping[str, Any]] | None = None,
) -> ExecutionResult:
    """Archive the blocking reason, then commit BLOCKED.

    A block before the plan can be loaded still has a claimed RUNNING job; the
    context is loaded again if possible so the report carries the target.
    """
    if context is None:
        try:
            context = _load_context(
                dsn, job_id, generation, case_root=None, run_root=None
            )
        except (ExecutionBlocked, ExecutionFailed, state.StaleGeneration):
            context = None
    if context is None:
        try:
            state.finish_execution(
                dsn,
                job_id,
                generation=generation,
                state="BLOCKED",
                reason_code=error.reason_code,
                verdict=None,
                verdict_reason=None,
                last_error=error.message,
                stage="blocked",
            )
        except (state.StateError, state.StaleGeneration):
            return ExecutionResult("STALE")
        return ExecutionResult("BLOCKED", reason_code=error.reason_code)
    work_root = context.run_root / context.job_id_text / context.plan_digest.split(":")[1]
    build_root = work_root / "run"
    build_root.mkdir(parents=True, exist_ok=True)
    report, markdown = _build_report(
        context,
        verdict="BLOCKED",
        verdict_reason=error.reason_code,
        decision=None,
        builds=builds or {},
        runs=runs or [],
        probe=probe,
        evidence_refs=["report.json", "report.md", "plan.json", "review.json"],
        missing=[
            "target execution blocked"
        ],
        error=f"{error.reason_code}: {error.message}",
    )
    try:
        digest, path, archive_error = _archive(
            dsn,
            context,
            report=report,
            report_markdown=markdown,
            artifacts=_evidence_artifacts(
                context,
                build_root,
                builds=builds or {},
                runs=runs or [],
                probe=probe,
                execution_metadata={},
            ),
            verdict="BLOCKED",
        )
    except (BundleError, state.StateError, state.StaleGeneration) as archive_failure:
        archive_error = str(archive_failure)
        digest = path = None
    if archive_error is not None:
        kwargs: dict[str, Any] = {
            "evidence_status": "failed",
            "evidence_error": archive_error,
            "last_error": error.message,
        }
        try:
            state.finish_execution(
                dsn,
                job_id,
                generation=generation,
                state="FAILED",
                reason_code="EVIDENCE_WRITE_FAILED",
                verdict=None,
                verdict_reason=None,
                stage="failed",
                **kwargs,
            )
        except (state.StateError, state.StaleGeneration):
            pass
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
        )
    except state.StaleGeneration:
        return ExecutionResult("STALE")
    if not finished:
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
        state.finish_execution(
            dsn,
            job_id,
            generation=generation,
            state="FAILED",
            reason_code=error.reason_code,
            verdict=None,
            verdict_reason=None,
            last_error=error.message,
            stage="failed",
        )
    except (state.StateError, state.StaleGeneration):
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
) -> ExecutionResult:
    work_root = context.run_root / context.job_id_text / context.plan_digest.split(":")[1]
    build_root = work_root / "run"
    build_root.mkdir(parents=True, exist_ok=True)
    incomplete = error.reason_code in (
        "RUN_INCOMPLETE",
        "NOT_COMPARABLE",
        "TIMEOUT",
    )
    terminal = "INCONCLUSIVE" if incomplete else "FAILED"
    report, markdown = _build_report(
        context,
        verdict=terminal,
        verdict_reason=error.reason_code,
        decision=None,
        builds=builds,
        runs=runs,
        probe=probe,
        evidence_refs=["report.json", "report.md", "plan.json", "review.json"],
        missing=["required replay evidence is incomplete"] if incomplete else ["execution failed"],
        error=f"{error.reason_code}: {error.message}",
    )
    try:
        digest, path, archive_error = _archive(
            dsn,
            context,
            report=report,
            report_markdown=markdown,
            artifacts=_evidence_artifacts(
                context,
                build_root,
                builds=builds,
                runs=runs,
                probe=probe,
                execution_metadata={},
            ),
            verdict=terminal,
        )
    except (BundleError, state.StateError, state.StaleGeneration) as archive_failure:
        digest = path = None
        archive_error = str(archive_failure)
    if archive_error is not None:
        try:
            state.finish_execution(
                dsn,
                job_id,
                generation=generation,
                state="FAILED",
                reason_code="EVIDENCE_WRITE_FAILED",
                verdict=terminal if incomplete else None,
                verdict_reason=error.reason_code if incomplete else None,
                evidence_status="failed",
                evidence_error=archive_error,
                last_error=error.message,
                stage="failed",
            )
        except (state.StateError, state.StaleGeneration):
            pass
        return ExecutionResult("FAILED", reason_code="EVIDENCE_WRITE_FAILED")
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
    except state.StaleGeneration:
        return ExecutionResult("STALE")
    return ExecutionResult(
        (terminal if finished else "STALE"),
        verdict=terminal if incomplete else None,
        verdict_reason=error.reason_code if incomplete else None,
        reason_code=error.reason_code,
        evidence_digest=digest,
        evidence_path=path,
    )

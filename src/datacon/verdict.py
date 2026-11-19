"""Deterministic verdict rules from the SRS (REQ-07).

The rule is intentionally small and data-driven. It never asks a model and it
never treats a plain exit code or a model hypothesis as reproduction evidence.
"""

from __future__ import annotations

from dataclasses import dataclass
import json
from typing import Any, Mapping, Sequence

from datacon.asan import ASanSignature, has_asan_diagnostic, signature_matches

VERSIONS = ("vulnerable", "fixed")
CANDIDATE_PHASES = ("candidate_1", "candidate_2")
REQUIRED_PHASES = ("normal", *CANDIDATE_PHASES)
# Single source of truth for the reason codes each verdict may carry. The
# evidence verifier imports these sets instead of hard-coding a second copy.
REPRODUCED_REASONS = frozenset({"ASAN_SIGNATURE_MATCHED"})
NOT_REPRODUCED_REASONS = frozenset({"CANDIDATE_CLEAN"})
INCONCLUSIVE_REASONS = frozenset(
    {
        "CONTROL_FAILED",
        "EVIDENCE_INCOMPLETE",
        "FIXED_STILL_VULNERABLE",
        "INTERMITTENT",
        "NOT_COMPARABLE",
        "OTHER_CRASH",
        "RESOURCE_LIMITED",
        "RUN_INCOMPLETE",
        "TIMEOUT",
        "VERDICT_UNCLASSIFIED",
    }
)
# BLOCKED/FAILED codes are the closed sets execution.py can actually return.
BLOCKED_REASONS = frozenset(
    {
        "DEADLINE_EXCEEDED",
        "INVALID_REQUEST",
        "INVALID_STATE",
        "JOB_NOT_FOUND",
        "MATERIAL_IO_ERROR",
        "MATERIAL_MISSING",
        "PLAN_MISMATCH",
        "POLICY_DENIED",
        "SOURCE_CONFLICT",
    }
)
FAILED_REASONS = frozenset({"BUILD_FAILED", "EVIDENCE_WRITE_FAILED"})
VERDICT_REASONS = {
    "REPRODUCED": REPRODUCED_REASONS,
    "NOT_REPRODUCED": NOT_REPRODUCED_REASONS,
    "INCONCLUSIVE": INCONCLUSIVE_REASONS,
    "BLOCKED": BLOCKED_REASONS,
    "FAILED": FAILED_REASONS,
}

# Completed is the only status that can support a positive outcome. The other
# values are the concrete ReplayResult/execution states that may appear in an
# inconclusive bundle.
REPLAY_STATUSES = frozenset(
    {"completed", "timeout", "resource_limited", "infra_error"}
)


def reason_allowed(verdict: str, reason: str | None) -> bool:
    """Return whether ``reason`` belongs to the closed set for ``verdict``."""
    allowed = VERDICT_REASONS.get(verdict)
    return allowed is not None and reason in allowed


def replay_status_allowed(verdict: str, status: str) -> bool:
    if status not in REPLAY_STATUSES:
        return False
    if verdict in ("REPRODUCED", "NOT_REPRODUCED"):
        return status == "completed"
    return True


PRIORITY = (
    "INCONCLUSIVE: missing/incomparable evidence or truncated logs",
    "INCONCLUSIVE: timeout or resource exhaustion (including a control that "
    "did not complete)",
    "INCONCLUSIVE: abnormal completed normal control "
    "(wrong exit, stdout or an ASan diagnostic)",
    "INCONCLUSIVE: intermittent trigger, other crash or fixed still vulnerable",
    "REPRODUCED: vulnerable hits the reviewed signature twice and fixed is clean twice",
    "NOT_REPRODUCED: both versions are clean on the candidate twice",
    "INCONCLUSIVE: every other complete combination",
)


@dataclass(frozen=True)
class VerdictPolicy:
    signature: Mapping[str, Any]
    expected_exit: Mapping[str, int]
    expected_stdout: Mapping[str, str]

    def as_dict(self) -> dict[str, Any]:
        return {
            "signature": dict(self.signature),
            "expected_exit": dict(self.expected_exit),
            "expected_stdout": dict(self.expected_stdout),
        }


@dataclass(frozen=True)
class RunObservation:
    version: str
    phase: str
    status: str
    exit_code: int | None
    stdout: str
    stderr: str
    signature: ASanSignature | None
    input_digest: str | None = None
    duration_seconds: float | None = None
    log_truncated: bool = False
    log_unverified: bool = False
    capture_error: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "version": self.version,
            "phase": self.phase,
            "status": self.status,
            "exit_code": self.exit_code,
            "stdout": self.stdout,
            "stderr_digest": None,
            "signature": self.signature.as_dict() if self.signature else None,
            "input_digest": self.input_digest,
            "duration_seconds": self.duration_seconds,
            "log_truncated": self.log_truncated,
            "log_unverified": self.log_unverified,
            "capture_error": self.capture_error,
        }


@dataclass(frozen=True)
class VerdictDecision:
    verdict: str
    reason_code: str
    message: str
    checks: dict[str, Any]

    def as_dict(self) -> dict[str, Any]:
        return {
            "verdict": self.verdict,
            "reason_code": self.reason_code,
            "message": self.message,
            "checks": self.checks,
            "priority": list(PRIORITY),
        }


def _inconclusive(reason_code: str, message: str, checks: dict[str, Any]) -> VerdictDecision:
    return VerdictDecision("INCONCLUSIVE", reason_code, message, checks)


def _exit_matches(actual: int | None, expected: Any) -> bool:
    return type(expected) is int and type(actual) is int and actual == expected


def _stdout_matches(actual: str, expected: Any) -> bool:
    return isinstance(expected, str) and actual == expected


def _compare_builds(builds: Mapping[str, Mapping[str, Any]] | None) -> str | None:
    """Return a non-comparable reason, or ``None`` when both builds agree."""
    if not builds:
        return None
    for version in VERSIONS:
        build = builds.get(version)
        if not isinstance(build, Mapping) or build.get("status") != "completed":
            return f"{version} build did not complete"
        if build.get("capture_error"):
            return f"{version} build log or exit capture failed"
        if build.get("log_truncated"):
            if build.get("log_unverified"):
                return (
                    f"{version} build log completeness could not be verified"
                    " (docker LogPath not accessible from the host)"
                )
            return f"{version} build log was truncated"
    vulnerable = builds["vulnerable"]
    fixed = builds["fixed"]
    for field in ("image_digest", "build_recipe_digest", "compile_args"):
        if field in vulnerable or field in fixed:
            if vulnerable.get(field) != fixed.get(field):
                return f"builds differ on {field}"
    if not vulnerable.get("artifact_digest"):
        return "vulnerable build artifact digest is missing"
    if not fixed.get("artifact_digest"):
        return "fixed build artifact digest is missing"
    return None


def classify_candidate(policy: VerdictPolicy, run: RunObservation) -> str:
    signature = run.signature
    if (
        signature is not None
        and signature_matches(signature, policy.signature)
        and _exit_matches(run.exit_code, policy.expected_exit.get("candidate_asan"))
    ):
        return "target_signature"
    if (
        _exit_matches(run.exit_code, policy.expected_exit.get("candidate_clean"))
        and _stdout_matches(run.stdout, policy.expected_stdout.get("candidate_clean"))
        and not has_asan_diagnostic(run.stderr)
    ):
        return "clean"
    return "other"


def decide_verdict(
    policy: VerdictPolicy,
    runs: Sequence[RunObservation],
    *,
    builds: Mapping[str, Mapping[str, Any]] | None = None,
    expected_inputs: Mapping[str | tuple[str, str], str] | None = None,
) -> VerdictDecision:
    """Apply the SRS priority order to the six required observations."""
    checks: dict[str, Any] = {
        "priority": list(PRIORITY),
        "runs": len(runs),
        "vulnerable_candidates": [],
        "fixed_candidates": [],
        "controls": {},
    }

    comparable_error = _compare_builds(builds)
    if comparable_error is not None:
        return _inconclusive("NOT_COMPARABLE", comparable_error, checks)

    by_key: dict[tuple[str, str], RunObservation] = {}
    for run in runs:
        key = (run.version, run.phase)
        if key in by_key:
            return _inconclusive(
                "EVIDENCE_INCOMPLETE",
                f"duplicate run for {run.version}/{run.phase}",
                checks,
            )
        by_key[key] = run
    required = {(version, phase) for version in VERSIONS for phase in REQUIRED_PHASES}
    missing = sorted(required - set(by_key))
    if missing:
        checks["missing"] = [f"{version}/{phase}" for version, phase in missing]
        return _inconclusive(
            "EVIDENCE_INCOMPLETE",
            "required run evidence is missing: "
            + ", ".join(checks["missing"]),
            checks,
        )

    if expected_inputs:
        for run in runs:
            # Normal controls use the normal input; only candidate replays are
            # compared against the candidate digest supplied by the caller.
            if run.phase == "normal":
                continue
            expected = expected_inputs.get((run.version, run.phase))
            if expected is None:
                expected = expected_inputs.get(run.version)
            if expected is not None and run.input_digest != expected:
                checks["input_mismatch"] = {
                    "version": run.version,
                    "phase": run.phase,
                    "expected": expected,
                    "actual": run.input_digest,
                }
                return _inconclusive(
                    "NOT_COMPARABLE",
                    f"input digest mismatch for {run.version}/{run.phase}",
                    checks,
                )

    for run in runs:
        if run.capture_error:
            checks["capture_error"] = f"{run.version}/{run.phase}"
            return _inconclusive(
                "EVIDENCE_INCOMPLETE",
                f"{run.version}/{run.phase} log or exit capture failed: "
                f"{run.capture_error}",
                checks,
            )
        if run.log_truncated:
            if run.log_unverified:
                return _inconclusive(
                    "EVIDENCE_INCOMPLETE",
                    f"{run.version}/{run.phase} log completeness could not"
                    " be verified (docker LogPath not accessible from the"
                    " host)",
                    checks,
                )
            return _inconclusive(
                "EVIDENCE_INCOMPLETE",
                f"{run.version}/{run.phase} log was truncated",
                checks,
            )
        if run.status == "timeout":
            checks["timeout"] = f"{run.version}/{run.phase}"
            return _inconclusive(
                "TIMEOUT", f"{run.version}/{run.phase} timed out", checks
            )
        if run.status == "resource_limited":
            checks["resource_limited"] = f"{run.version}/{run.phase}"
            return _inconclusive(
                "RESOURCE_LIMITED",
                f"{run.version}/{run.phase} hit a resource limit",
                checks,
            )
        if run.status != "completed":
            checks["incomplete"] = f"{run.version}/{run.phase}"
            return _inconclusive(
                "EVIDENCE_INCOMPLETE",
                f"{run.version}/{run.phase} did not complete ({run.status})",
                checks,
            )

    for version in VERSIONS:
        run = by_key[(version, "normal")]
        if not _exit_matches(run.exit_code, policy.expected_exit.get("normal")):
            checks["controls"][version] = "exit"
            return _inconclusive(
                "CONTROL_FAILED",
                f"{version} normal control exited with {run.exit_code}",
                checks,
            )
        if not _stdout_matches(run.stdout, policy.expected_stdout.get("normal")):
            checks["controls"][version] = "stdout"
            return _inconclusive(
                "CONTROL_FAILED",
                f"{version} normal control stdout did not match",
                checks,
            )
        if has_asan_diagnostic(run.stderr):
            checks["controls"][version] = "asan"
            return _inconclusive(
                "CONTROL_FAILED",
                f"{version} normal control emitted an ASan diagnostic",
                checks,
            )
        checks["controls"][version] = "ok"

    classifications = {
        version: [
            classify_candidate(policy, by_key[(version, phase)])
            for phase in CANDIDATE_PHASES
        ]
        for version in VERSIONS
    }
    checks["vulnerable_candidates"] = classifications["vulnerable"]
    checks["fixed_candidates"] = classifications["fixed"]

    if any(item == "other" for item in classifications["vulnerable"]):
        return _inconclusive(
            "OTHER_CRASH",
            "a vulnerable candidate produced an unexpected result",
            checks,
        )
    if any(item == "other" for item in classifications["fixed"]):
        return _inconclusive(
            "OTHER_CRASH",
            "a fixed candidate produced an unexpected result",
            checks,
        )
    if "target_signature" in classifications["fixed"]:
        return _inconclusive(
            "FIXED_STILL_VULNERABLE",
            "the fixed revision still hit the reviewed ASan signature",
            checks,
        )
    if (
        "target_signature" in classifications["vulnerable"]
        and "clean" in classifications["vulnerable"]
    ) or (
        "target_signature" in classifications["fixed"]
        and "clean" in classifications["fixed"]
    ):
        return _inconclusive(
            "INTERMITTENT", "the candidate result was intermittent", checks
        )

    if classifications["vulnerable"] == ["target_signature", "target_signature"]:
        if classifications["fixed"] == ["clean", "clean"]:
            return VerdictDecision(
                "REPRODUCED",
                "ASAN_SIGNATURE_MATCHED",
                "the vulnerable revision hit the reviewed signature twice and "
                "the fixed revision was clean twice",
                checks,
            )
        return _inconclusive(
            "FIXED_STILL_VULNERABLE",
            "the fixed revision did not complete cleanly twice",
            checks,
        )

    if classifications["vulnerable"] == ["clean", "clean"]:
        if classifications["fixed"] == ["clean", "clean"]:
            return VerdictDecision(
                "NOT_REPRODUCED",
                "CANDIDATE_CLEAN",
                "both revisions completed the candidate cleanly twice",
                checks,
            )
        return _inconclusive(
            "FIXED_STILL_VULNERABLE",
            "the fixed revision did not complete cleanly twice",
            checks,
        )

    return _inconclusive(
        "VERDICT_UNCLASSIFIED",
        "the complete run combination does not satisfy a reviewed rule",
        checks,
    )


def observation_from_run(run: Mapping[str, Any]) -> RunObservation:
    """Build an observation from a persisted run metadata document."""
    signature = run.get("signature")
    parsed = None
    if isinstance(signature, Mapping):
        parsed = ASanSignature(
            error=str(signature.get("error", "")),
            operation=signature.get("operation"),
            access_size=signature.get("access_size"),
            function=signature.get("function"),
            source=signature.get("source"),
        )
    capture_error = run.get("capture_error")
    return RunObservation(
        version=str(run.get("version", "")),
        phase=str(run.get("phase", "")),
        status=str(run.get("status", "infra_error")),
        exit_code=run.get("exit_code"),
        stdout=str(run.get("stdout", "")),
        stderr=str(run.get("stderr", "")),
        signature=parsed,
        input_digest=run.get("input_digest"),
        duration_seconds=run.get("duration_seconds"),
        log_truncated=bool(run.get("log_truncated", False)),
        log_unverified=bool(run.get("log_unverified", False)),
        capture_error=(
            str(capture_error) if capture_error is not None else None
        ),
    )


def dumps(decision: VerdictDecision) -> str:
    return json.dumps(decision.as_dict(), ensure_ascii=False, sort_keys=True)

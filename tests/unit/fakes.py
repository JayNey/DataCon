"""Deterministic test doubles and fault injectors for DataCon v0.2 unit tests.

This module intentionally provides pure in-memory test support only (fake UTC
clock, recording sandbox with fault injection, and review/envelope stubs for
T11 orchestration edges #15/#16/#17). It does not start Docker, does not touch
PostgreSQL, and does not implement production contract logic.
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
import hashlib
import math
from pathlib import Path
import threading
from typing import Any, Mapping, Sequence

import psycopg

from datacon import jsonutil
from datacon import state as state_store
from datacon.asan import ASanSignature, parse_asan
from datacon.tools.sandbox import (
    BuildResult,
    ProbeReport,
    ReplayResult,
    SandboxPolicyError,
    SandboxUnavailable,
)

DEFAULT_IMAGE_DIGEST = "sha256:" + "a" * 64
DEFAULT_START_UTC = datetime(2099, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
VALID_FAULT_KINDS = frozenset(
    {
        "retryable_build_failure",
        "build_diagnose_failure",
        "container_start_error",
        "timeout",
        "oom",
        "log_truncated",
        "lease_expired",
        "stale_generation",
        "transient_db_error",
    }
)
PROBE_FAULT_KINDS = frozenset(
    {
        "container_start_error",
        "timeout",
        "oom",
        "log_truncated",
        "lease_expired",
        "stale_generation",
        "transient_db_error",
    }
)
BUILD_FAULT_KINDS = VALID_FAULT_KINDS
REPLAY_FAULT_KINDS = frozenset(
    {
        "container_start_error",
        "timeout",
        "oom",
        "log_truncated",
        "lease_expired",
        "stale_generation",
        "transient_db_error",
    }
)


def _sha256_digest(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


class FakeClock:
    """Controllable UTC clock for deterministic tests; never calls sleep."""

    def __init__(self, start: datetime = DEFAULT_START_UTC) -> None:
        if start.tzinfo is None:
            start = start.replace(tzinfo=timezone.utc)
        self._now = start.astimezone(timezone.utc)
        self._monotonic = 0.0
        self._lock = threading.Lock()

    def now(self) -> datetime:
        with self._lock:
            return self._now

    def monotonic(self) -> float:
        with self._lock:
            return self._monotonic

    def advance(self, seconds: float | int) -> datetime:
        if isinstance(seconds, bool) or not isinstance(seconds, (int, float)):
            raise ValueError("seconds must be a finite non-negative number")
        if not math.isfinite(seconds) or seconds < 0:
            raise ValueError("seconds must be a finite non-negative number")
        with self._lock:
            self._now = self._now + timedelta(seconds=float(seconds))
            self._monotonic += float(seconds)
            return self._now

    def timestamp(self, *, microseconds: bool = False) -> str:
        with self._lock:
            current = self._now
        if microseconds:
            return current.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        return current.replace(microsecond=0).isoformat().replace("+00:00", "Z")


@dataclass(frozen=True)
class SandboxCall:
    """Recorded invocation against FakeSandbox."""

    seq: int
    operation: str
    version: str | None
    phase: str | None
    input_digest: str | None
    compile_args: tuple[str, ...]
    container_name: str
    timestamp: str
    fault_injected: str | None
    outcome_status: str


class FakeSandbox:
    """Recording sandbox double with deterministic results and fault injection.

    Returns real ``ProbeReport``, ``BuildResult`` and ``ReplayResult`` shapes
    without invoking Docker. Every call is recorded in ``self.calls`` with its
    order, input digest summary, compile arguments, container name and fault.
    """

    def __init__(
        self,
        *,
        clock: FakeClock | None = None,
        image_digest: str = DEFAULT_IMAGE_DIGEST,
        retryable_build_failures: int = 0,
        build_faults: Sequence[str] = (),
        replay_faults: Sequence[str] = (),
        probe_faults: Sequence[str] = (),
        build_duration_seconds: float = 1.0,
        replay_duration_seconds: float = 0.5,
        asan_stderr_by_version_phase: Mapping[tuple[str, str], bytes] | None = None,
        provenance_faces: Mapping[str, bytes] | None = None,
    ) -> None:
        if retryable_build_failures < 0:
            raise ValueError("retryable_build_failures must be non-negative")
        self.clock = clock or FakeClock()
        self.image_digest = image_digest
        self.build_duration_seconds = float(build_duration_seconds)
        self.replay_duration_seconds = float(replay_duration_seconds)
        self.asan_stderr_by_version_phase: dict[tuple[str, str], bytes] = dict(
            asan_stderr_by_version_phase or {}
        )
        self.provenance_faces: dict[str, bytes] = dict(provenance_faces or {})

        self._build_faults: deque[str] = deque(
            ["retryable_build_failure"] * retryable_build_failures
        )
        self.inject_build_faults(build_faults)
        self._replay_faults: deque[str] = deque()
        self.inject_replay_faults(replay_faults)
        self._probe_faults: deque[str] = deque()
        self.inject_probe_faults(probe_faults)

        self._lock = threading.Lock()
        self.calls: list[SandboxCall] = []
        self._seq = 0

    @property
    def build_calls(self) -> list[SandboxCall]:
        return [call for call in self.calls if call.operation == "build"]

    @property
    def replay_calls(self) -> list[SandboxCall]:
        return [call for call in self.calls if call.operation == "replay"]

    @property
    def probe_calls(self) -> list[SandboxCall]:
        return [call for call in self.calls if call.operation == "probe"]

    @staticmethod
    def _validate_fault(
        fault: str, allowed: frozenset[str] = VALID_FAULT_KINDS
    ) -> str:
        if fault not in allowed:
            raise ValueError(
                f"unsupported fault kind {fault!r}; expected one of {sorted(allowed)}"
            )
        return fault

    def inject_build_faults(self, faults: Sequence[str]) -> None:
        for fault in faults:
            self._build_faults.append(self._validate_fault(fault, BUILD_FAULT_KINDS))

    def inject_replay_faults(self, faults: Sequence[str]) -> None:
        for fault in faults:
            self._replay_faults.append(self._validate_fault(fault, REPLAY_FAULT_KINDS))

    def inject_probe_faults(self, faults: Sequence[str]) -> None:
        for fault in faults:
            self._probe_faults.append(self._validate_fault(fault, PROBE_FAULT_KINDS))

    def get_provenance_face_bytes(self, version: str) -> bytes | None:
        """Return raw provenance face bytes for ``version`` without embedding bytes in metadata."""
        return self.provenance_faces.get(version)

    def _next_container(self, suffix: str) -> tuple[int, str]:
        with self._lock:
            self._seq += 1
            return self._seq, f"fake-datacon-{suffix}-{self._seq:03d}"

    def _pop_fault(self, queue: deque[str]) -> str | None:
        with self._lock:
            return queue.popleft() if queue else None

    def _record(
        self,
        *,
        seq: int,
        operation: str,
        version: str | None,
        phase: str | None,
        input_digest: str | None,
        compile_args: tuple[str, ...],
        container_name: str,
        fault: str | None,
        outcome_status: str,
    ) -> None:
        call = SandboxCall(
            seq=seq,
            operation=operation,
            version=version,
            phase=phase,
            input_digest=input_digest,
            compile_args=compile_args,
            container_name=container_name,
            timestamp=self.clock.timestamp(),
            fault_injected=fault,
            outcome_status=outcome_status,
        )
        with self._lock:
            self.calls.append(call)

    def _maybe_raise_exception_fault(self, fault: str | None) -> None:
        if fault == "container_start_error":
            raise SandboxUnavailable("simulated container start failure")
        if fault == "lease_expired":
            raise state_store.StaleGeneration("simulated worker lease expired")
        if fault == "stale_generation":
            raise state_store.StaleGeneration(
                "simulated stale generation writeback"
            )
        if fault == "transient_db_error":
            raise psycopg.OperationalError("simulated transient PostgreSQL error")

    def probe(self, *, deadline_seconds: float = 120.0) -> ProbeReport:
        seq, container = self._next_container("probe")
        fault = self._pop_fault(self._probe_faults)
        if fault in (
            "container_start_error",
            "lease_expired",
            "stale_generation",
            "transient_db_error",
        ):
            self._record(
                seq=seq,
                operation="probe",
                version=None,
                phase=None,
                input_digest=None,
                compile_args=(),
                container_name=container,
                fault=fault,
                outcome_status="raised",
            )
            self._maybe_raise_exception_fault(fault)
        if fault in ("timeout", "oom", "log_truncated"):
            advance_by = (
                float(deadline_seconds)
                if fault == "timeout"
                else min(0.1, deadline_seconds)
            )
            self.clock.advance(advance_by)
            self._record(
                seq=seq,
                operation="probe",
                version=None,
                phase=None,
                input_digest=None,
                compile_args=(),
                container_name=container,
                fault=fault,
                outcome_status="raised",
            )
            messages = {
                "timeout": "isolation probe timed out",
                "oom": "isolation probe was OOM-killed",
                "log_truncated": "isolation probe output exceeded the capture budget",
            }
            raise SandboxPolicyError(messages[fault])
        self.clock.advance(min(0.1, deadline_seconds))
        self._record(
            seq=seq,
            operation="probe",
            version=None,
            phase=None,
            input_digest=None,
            compile_args=(),
            container_name=container,
            fault=fault,
            outcome_status="completed",
        )
        return ProbeReport(
            ok=True,
            checks={
                "uid": "65534",
                "seccomp": "2",
                "seccomp_filters": "1",
                "no_new_privs": "1",
                "cap_eff": "0",
                "cgroup_version": "2",
                "errors": [],
            },
            compiler_version="clang version 19.1.7 (fake)",
            image_digest=self.image_digest,
            raw="uid=65534\nseccomp=2\n",
            limits={"cpu": 2, "memory_mib": 2048, "pids": 128, "scratch_mib": 512},
            cleanup_errors=(),
        )

    def build(
        self,
        version: str,
        *,
        materials_dir: Path | str = "/fake/materials",
        compile_args: Sequence[str] = (),
        deadline_seconds: float = 300.0,
        expected_materials: Mapping[str, str] | None = None,
    ) -> BuildResult:
        seq, container = self._next_container(f"build-{version}")
        args_tuple = tuple(compile_args)
        input_digest = (
            jsonutil.digest_json(dict(expected_materials))
            if expected_materials is not None
            else _sha256_digest(f"{materials_dir}:{version}".encode("utf-8"))
        )
        fault = self._pop_fault(self._build_faults)
        if fault in (
            "container_start_error",
            "lease_expired",
            "stale_generation",
            "transient_db_error",
        ):
            self._record(
                seq=seq,
                operation="build",
                version=version,
                phase=None,
                input_digest=input_digest,
                compile_args=args_tuple,
                container_name=container,
                fault=fault,
                outcome_status="raised",
            )
            self._maybe_raise_exception_fault(fault)

        duration = self.build_duration_seconds
        status = "completed"
        exit_code: int | None = 0
        artifact: bytes | None = f"fake-artifact-{version}-seq-{seq}".encode("utf-8")
        log = f"[{self.clock.timestamp()}] fake build {version} ok\n".encode("utf-8")
        log_truncated = False
        truncated_roles: tuple[str, ...] = ()
        metadata: dict[str, Any] = {
            "build_command": ["cmake", "--build", "build"],
            "exit_code": 0,
            "timed_out": False,
            "oom_killed": False,
            "limits_hit": [],
            "truncated_roles": [],
            "retryable": False,
        }
        if version in self.provenance_faces:
            face_bytes = self.provenance_faces[version]
            metadata["provenance_face_digest"] = _sha256_digest(face_bytes)
            metadata["provenance_face_size"] = len(face_bytes)

        if fault == "retryable_build_failure":
            status = "build_failed"
            exit_code = 2
            artifact = None
            log = (
                f"[{self.clock.timestamp()}] fake retryable build failure "
                f"({fault}) for {version}\n"
            ).encode("utf-8")
            metadata["exit_code"] = 2
            metadata["retryable"] = True
            metadata["fault"] = fault
        elif fault == "build_diagnose_failure":
            status = "build_failed"
            exit_code = 2
            artifact = None
            log = (
                f"[{self.clock.timestamp()}] fake non-retryable build diagnose failure "
                f"({fault}) for {version}\n"
            ).encode("utf-8")
            metadata["exit_code"] = 2
            metadata["retryable"] = False
            metadata["diagnose_failed"] = True
            metadata["fault"] = fault
        elif fault == "timeout":
            duration = float(deadline_seconds)
            status = "timeout"
            exit_code = None
            artifact = None
            log = f"[{self.clock.timestamp()}] fake build timeout for {version}\n".encode(
                "utf-8"
            )
            metadata["exit_code"] = None
            metadata["timed_out"] = True
        elif fault == "oom":
            status = "resource_limited"
            exit_code = 137
            artifact = None
            log = f"[{self.clock.timestamp()}] fake build OOM for {version}\n".encode(
                "utf-8"
            )
            metadata["exit_code"] = 137
            metadata["oom_killed"] = True
            metadata["limits_hit"] = ["memory"]
        elif fault == "log_truncated":
            log_truncated = True
            truncated_roles = ("stderr",)
            metadata["truncated_roles"] = ["stderr"]
            log = b"fake truncated build log...\n"

        self.clock.advance(duration)
        artifact_digest = _sha256_digest(artifact) if artifact is not None else None
        self._record(
            seq=seq,
            operation="build",
            version=version,
            phase=None,
            input_digest=input_digest,
            compile_args=args_tuple,
            container_name=container,
            fault=fault,
            outcome_status=status,
        )
        return BuildResult(
            version=version,
            status=status,
            exit_code=exit_code,
            duration_seconds=duration,
            container_id=container,
            image_digest=self.image_digest,
            compile_args=args_tuple,
            artifact_digest=artifact_digest,
            log=log,
            log_truncated=log_truncated,
            artifact=artifact,
            metadata=metadata,
            capture_error=None,
            truncated_roles=truncated_roles,
        )

    def replay(
        self,
        version: str,
        phase: str,
        *,
        artifact_path: Path | str = "/fake/artifact/parser",
        input_path: Path | str = "/fake/input/seed",
        asan_options: str = "detect_leaks=0:halt_on_error=1",
        timeout_seconds: float = 10.0,
        deadline_seconds: float | None = None,
        expected_artifact_digest: str | None = None,
        expected_input_digest: str | None = None,
    ) -> ReplayResult:
        seq, container = self._next_container(f"replay-{version}-{phase}")
        input_digest = expected_input_digest or _sha256_digest(
            f"{input_path}:{version}:{phase}".encode("utf-8")
        )
        fault = self._pop_fault(self._replay_faults)
        if fault in (
            "container_start_error",
            "lease_expired",
            "stale_generation",
            "transient_db_error",
        ):
            self._record(
                seq=seq,
                operation="replay",
                version=version,
                phase=phase,
                input_digest=input_digest,
                compile_args=(),
                container_name=container,
                fault=fault,
                outcome_status="raised",
            )
            self._maybe_raise_exception_fault(fault)

        duration = self.replay_duration_seconds
        status = "completed"
        timed_out = False
        quota_hit = False
        log_truncated = False
        truncated_roles: tuple[str, ...] = ()
        stdout = b"OK\n"
        stderr = self.asan_stderr_by_version_phase.get((version, phase), b"")
        signature: ASanSignature | None = (
            parse_asan(stderr.decode("utf-8", "replace")) if stderr else None
        )
        exit_code: int | None = 86 if signature is not None else 0
        metadata: dict[str, Any] = {
            "image_digest": self.image_digest,
            "asan_options": asan_options,
            "artifact_path": str(artifact_path),
            "expected_artifact_digest": expected_artifact_digest,
            "oom_killed": False,
            "limits_hit": [],
            "timeout_seconds": timeout_seconds,
            "truncated_roles": [],
        }

        if fault == "timeout":
            duration = (
                min(timeout_seconds, deadline_seconds)
                if deadline_seconds is not None
                else timeout_seconds
            )
            status = "timeout"
            timed_out = True
            exit_code = None
            stdout = b""
            stderr = b"replay timed out\n"
            signature = None
        elif fault == "oom":
            status = "resource_limited"
            quota_hit = True
            exit_code = 137
            stdout = b""
            stderr = b"killed (OOM)\n"
            signature = None
            metadata["oom_killed"] = True
            metadata["limits_hit"] = ["memory"]
        elif fault == "log_truncated":
            log_truncated = True
            truncated_roles = ("stderr",)
            metadata["truncated_roles"] = ["stderr"]

        self.clock.advance(duration)
        self._record(
            seq=seq,
            operation="replay",
            version=version,
            phase=phase,
            input_digest=input_digest,
            compile_args=(),
            container_name=container,
            fault=fault,
            outcome_status=status,
        )
        return ReplayResult(
            version=version,
            phase=phase,
            status=status,
            exit_code=exit_code,
            duration_seconds=duration,
            container_id=container,
            input_digest=input_digest,
            stdout=stdout,
            stderr=stderr,
            signature=signature,
            timed_out=timed_out,
            quota_hit=quota_hit,
            log_truncated=log_truncated,
            metadata=metadata,
            capture_error=None,
            truncated_roles=truncated_roles,
        )


@dataclass(frozen=True)
class ReviewDecisionStub:
    """Result returned by FakeReviewGate for T11 review-node edges #15/#17."""

    edge: str
    decision: str
    reason_code: str | None
    approval_digest: str | None
    envelope_digest: str
    first_plan_digest: str
    decided_at: str


class FakeReviewGate:
    """In-memory test double for human approval of the first plan + envelope.

    Supports T11 unit tests for ``review`` node edges #15 (``review -> build``)
    and #17 (``review -> archive``) without writing to PostgreSQL or replacing
    the real ``reviews`` / ``family_approvals`` implementation.
    """

    def __init__(
        self,
        *,
        clock: FakeClock | None = None,
        decision: str = "approve",
        reviewer_id: str = "reviewer-test",
        expected_first_plan_digest: str | None = None,
        expected_envelope_digest: str | None = None,
        review_deadline_at: datetime | None = None,
    ) -> None:
        if decision not in ("approve", "reject"):
            raise ValueError("decision must be 'approve' or 'reject'")
        self.clock = clock or FakeClock()
        self.decision = decision
        self.reviewer_id = reviewer_id
        self.expected_first_plan_digest = expected_first_plan_digest
        self.expected_envelope_digest = expected_envelope_digest
        self.review_deadline_at = review_deadline_at
        self.checks: list[dict[str, Any]] = []
        self.review_writes: int = 0

    def evaluate_first_plan(
        self,
        *,
        family_id: str,
        first_plan_digest: str,
        envelope_digest: str,
    ) -> ReviewDecisionStub:
        decided_at = self.clock.timestamp(microseconds=True)
        record = {
            "family_id": family_id,
            "first_plan_digest": first_plan_digest,
            "envelope_digest": envelope_digest,
            "decided_at": decided_at,
        }
        self.checks.append(record)

        if (
            self.expected_first_plan_digest is not None
            and first_plan_digest != self.expected_first_plan_digest
        ):
            return ReviewDecisionStub(
                edge="archive",
                decision="plan_mismatch",
                reason_code="PLAN_MISMATCH",
                approval_digest=None,
                envelope_digest=envelope_digest,
                first_plan_digest=first_plan_digest,
                decided_at=decided_at,
            )

        if (
            self.review_deadline_at is not None
            and self.clock.now() >= self.review_deadline_at
        ):
            return ReviewDecisionStub(
                edge="archive",
                decision="expired",
                reason_code="REVIEW_EXPIRED",
                approval_digest=None,
                envelope_digest=envelope_digest,
                first_plan_digest=first_plan_digest,
                decided_at=decided_at,
            )

        if (
            self.expected_envelope_digest is not None
            and envelope_digest != self.expected_envelope_digest
        ):
            return ReviewDecisionStub(
                edge="await_review",
                decision="envelope_mismatch",
                reason_code="REVIEW_ENVELOPE_MISMATCH",
                approval_digest=None,
                envelope_digest=envelope_digest,
                first_plan_digest=first_plan_digest,
                decided_at=decided_at,
            )

        self.review_writes += 1
        if self.decision == "reject":
            return ReviewDecisionStub(
                edge="archive",
                decision="reject",
                reason_code="REVIEW_REJECTED",
                approval_digest=None,
                envelope_digest=envelope_digest,
                first_plan_digest=first_plan_digest,
                decided_at=decided_at,
            )

        approval_digest = jsonutil.digest_json(
            {
                "family_id": family_id,
                "envelope_digest": envelope_digest,
                "first_plan_digest": first_plan_digest,
                "reviewer_id": self.reviewer_id,
                "decided_at": decided_at,
            }
        )
        return ReviewDecisionStub(
            edge="build",
            decision="approve",
            reason_code=None,
            approval_digest=approval_digest,
            envelope_digest=envelope_digest,
            first_plan_digest=first_plan_digest,
            decided_at=decided_at,
        )


@dataclass(frozen=True)
class AdmissionDecisionStub:
    """Result returned by FakeEnvelopePolicy for T11 review-node edges #16/#17."""

    edge: str
    admitted: bool
    approval_kind: str
    reason_code: str | None
    admission_id: str | None
    decided_at: str


@dataclass
class FakeEnvelopePolicy:
    """In-memory test double for in-round policy admission callbacks.

    Supports T11 unit tests for ``review`` node edges #16 (``review -> build``
    via policy admission) and #17 (``review -> archive`` on denial/violation)
    without writing to PostgreSQL or touching ``reviews``.
    """

    clock: FakeClock = field(default_factory=FakeClock)
    default_admit: bool = True
    denial_reason_by_round: dict[int, str] = field(default_factory=dict)
    evaluations: list[dict[str, Any]] = field(default_factory=list)
    admissions: list[dict[str, Any]] = field(default_factory=list)
    review_writes: int = 0

    def admit_round(
        self,
        *,
        family_id: str,
        job_id: str,
        round_no: int,
        envelope_digest: str,
        parent_approval_digest: str | None,
        seed_digest: str,
    ) -> AdmissionDecisionStub:
        decided_at = self.clock.timestamp()
        entry = {
            "family_id": family_id,
            "job_id": job_id,
            "round_no": round_no,
            "envelope_digest": envelope_digest,
            "parent_approval_digest": parent_approval_digest,
            "seed_digest": seed_digest,
            "decided_at": decided_at,
        }
        self.evaluations.append(entry)

        if round_no in self.denial_reason_by_round:
            return AdmissionDecisionStub(
                edge="archive",
                admitted=False,
                approval_kind="policy",
                reason_code=self.denial_reason_by_round[round_no],
                admission_id=None,
                decided_at=decided_at,
            )

        if not parent_approval_digest:
            return AdmissionDecisionStub(
                edge="archive",
                admitted=False,
                approval_kind="policy",
                reason_code="ADMISSION_DENIED",
                admission_id=None,
                decided_at=decided_at,
            )

        if not self.default_admit:
            return AdmissionDecisionStub(
                edge="archive",
                admitted=False,
                approval_kind="policy",
                reason_code="ENVELOPE_VIOLATION",
                admission_id=None,
                decided_at=decided_at,
            )

        admission_id = f"fake-admission-{round_no:03d}"
        self.admissions.append(
            {
                **entry,
                "admission_id": admission_id,
                "approval_kind": "policy",
            }
        )
        return AdmissionDecisionStub(
            edge="build",
            admitted=True,
            approval_kind="policy",
            reason_code=None,
            admission_id=admission_id,
            decided_at=decided_at,
        )

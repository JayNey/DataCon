"""DataCon v0.2 target orchestration graph, protocols, and deterministic runner.

Implements the 14-node, 26-edge orchestration topology defined in
``docs/spec/v0.2/README.md`` §5 and invariants 16-21 in §7, while leaving the
v0.1 two-node Supervisor graph in ``datacon.workflow`` untouched.
"""

from __future__ import annotations

import copy
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from functools import partial
import hashlib
import inspect
import math
import threading
from typing import (
    Any,
    Callable,
    Literal,
    Mapping,
    NamedTuple,
    Protocol,
    Sequence,
    TypedDict,
    runtime_checkable,
)
from uuid import uuid4

from langgraph.graph import END, START, StateGraph

from datacon import jsonutil
from datacon import verdict as verdict_mod
from datacon.tools.sandbox import BuildResult, ProbeReport, ReplayResult

DEFAULT_UTC_START = datetime(2099, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
DEFAULT_VULNERABLE_COMMIT = "1" * 40
DEFAULT_FIXED_COMMIT = "2" * 40
DEFAULT_VERDICT_POLICY = verdict_mod.VerdictPolicy(
    signature={"error": "heap-buffer-overflow"},
    expected_exit={"normal": 0, "candidate_clean": 0, "candidate_asan": 86},
    expected_stdout={"normal": "OK\n", "candidate_clean": "OK\n"},
)

ORCHESTRATION_NODES: tuple[str, ...] = (
    "prepare",
    "AGGREGATING",
    "intel",
    "version",
    "route",
    "patch",
    "source",
    "hypothesis_aggregator",
    "review",
    "build",
    "build_diagnose",
    "campaign",
    "verify",
    "archive",
)


@dataclass(frozen=True)
class OrchestrationEdge:
    """Single edge entry from the v0.2 README §5 complete edge table (#1-#26)."""

    edge_no: int
    source: str
    target: str
    kind: str
    condition: str
    scope: Literal["job", "family"]


ORCHESTRATION_EDGES: tuple[OrchestrationEdge, ...] = (
    OrchestrationEdge(
        1,
        "prepare",
        "intel",
        "child_plan",
        "ordinary child job planning path",
        "job",
    ),
    OrchestrationEdge(
        2,
        "prepare",
        "AGGREGATING",
        "family_aggregate",
        "job_kind=family enters unclaimable AGGREGATING branch",
        "job",
    ),
    OrchestrationEdge(
        3,
        "prepare",
        "archive",
        "prepare_blocked",
        "material missing, invalid request, or prepare-stage block",
        "job",
    ),
    OrchestrationEdge(
        4,
        "AGGREGATING",
        "archive",
        "family_complete",
        "all children finished, budget exhausted, or stop condition met",
        "job",
    ),
    OrchestrationEdge(
        5,
        "intel",
        "version",
        "intel_ready",
        "immutable intel snapshot available without source conflict",
        "job",
    ),
    OrchestrationEdge(
        6,
        "intel",
        "archive",
        "intel_blocked",
        "intel snapshot missing (MATERIAL_MISSING) or conflicting (SOURCE_CONFLICT)",
        "job",
    ),
    OrchestrationEdge(
        7,
        "version",
        "route",
        "version_resolved",
        "both vulnerable and fixed full Git object IDs resolved",
        "job",
    ),
    OrchestrationEdge(
        8,
        "version",
        "archive",
        "version_blocked",
        "version unresolvable or deadline exceeded",
        "job",
    ),
    OrchestrationEdge(
        9,
        "route",
        "patch",
        "target_patch",
        "target_kind is patch",
        "job",
    ),
    OrchestrationEdge(
        10,
        "route",
        "source",
        "target_source",
        "target_kind is source",
        "job",
    ),
    OrchestrationEdge(
        11,
        "route",
        "archive",
        "target_reverse_unsupported",
        "reverse placeholder or binary target (UNSUPPORTED_TARGET)",
        "job",
    ),
    OrchestrationEdge(
        12,
        "patch",
        "hypothesis_aggregator",
        "patch_hypotheses",
        "patch facts produce candidate root causes and evidence refs",
        "job",
    ),
    OrchestrationEdge(
        13,
        "source",
        "hypothesis_aggregator",
        "source_hypotheses",
        "source structure produces candidate symbols, callsites and evidence refs",
        "job",
    ),
    OrchestrationEdge(
        14,
        "hypothesis_aggregator",
        "review",
        "candidate_experiment",
        "aggregated hypotheses produce candidate ExperimentSpec",
        "job",
    ),
    OrchestrationEdge(
        15,
        "review",
        "build",
        "human_approve",
        "human approves exploration envelope and first plan (campaign or fixed round 1)",
        "job",
    ),
    OrchestrationEdge(
        16,
        "review",
        "build",
        "policy_admit",
        "in-round policy admission persisted to admissions without writing reviews",
        "job",
    ),
    OrchestrationEdge(
        17,
        "review",
        "archive",
        "review_blocked",
        "review rejected, expired, or out-of-envelope / admission denied",
        "job",
    ),
    OrchestrationEdge(
        18,
        "build",
        "build_diagnose",
        "build_complete",
        "two-version build completed or campaign build reuse verified",
        "job",
    ),
    OrchestrationEdge(
        19,
        "build_diagnose",
        "build",
        "retryable_build_failure",
        "retryable build failure (at most one extra retry per logical build step)",
        "job",
    ),
    OrchestrationEdge(
        20,
        "build_diagnose",
        "campaign",
        "campaign_search",
        "job_kind=campaign enters fuzz search after build diagnosis passes",
        "job",
    ),
    OrchestrationEdge(
        21,
        "build_diagnose",
        "verify",
        "fixed_or_reuse_verify",
        "fixed mode or campaign-reusing validation round enters six-replay verification",
        "job",
    ),
    OrchestrationEdge(
        22,
        "build_diagnose",
        "archive",
        "build_or_provenance_failed",
        "build retries exhausted or provenance check failed (BUILD_FAILED / BUILD_PROVENANCE_MISSING)",
        "job",
    ),
    OrchestrationEdge(
        23,
        "campaign",
        "hypothesis_aggregator",
        "family_next_round",
        "family-level transition: spawn next job_kind=round child after campaign archives",
        "family",
    ),
    OrchestrationEdge(
        24,
        "campaign",
        "archive",
        "campaign_bundle",
        "campaign search finished or fuzz budget reached; archive campaign bundle",
        "job",
    ),
    OrchestrationEdge(
        25,
        "verify",
        "archive",
        "verify_terminal",
        "verdict is REPRODUCED or NOT_REPRODUCED, or termination condition reached",
        "job",
    ),
    OrchestrationEdge(
        26,
        "verify",
        "hypothesis_aggregator",
        "family_next_round",
        "family-level transition: inconclusive with remaining max_rounds and budget spawns next round child after current child archives",
        "family",
    ),
)

IN_JOB_ORCHESTRATION_EDGES: tuple[OrchestrationEdge, ...] = tuple(
    edge for edge in ORCHESTRATION_EDGES if edge.scope == "job"
)
FAMILY_ORCHESTRATION_EDGES: tuple[OrchestrationEdge, ...] = tuple(
    edge for edge in ORCHESTRATION_EDGES if edge.scope == "family"
)

class StepKey(NamedTuple):
    """Idempotency key ``(job_id, stage, step_key, attempt_no, generation)``.

    As a ``NamedTuple``, ``StepKey`` is value- and hash-equal to the legacy
    5-tuple ``IdempotencyKey`` while exposing named fields for readability.
    """

    job_id: str
    stage: str
    step_key: str
    attempt_no: int
    generation: int


IdempotencyKey = tuple[str, str, str, int, int]


@runtime_checkable
class AttemptStore(Protocol):
    """Minimal persistence contract for completed node outcomes keyed by :class:`StepKey`."""

    def get_completed(self, key: StepKey) -> dict[str, Any] | None: ...

    def record_completed(
        self,
        key: StepKey,
        result: Mapping[str, Any],
    ) -> dict[str, Any]: ...


def run_idempotent(
    store: AttemptStore,
    key: StepKey,
    action: Callable[[], dict[str, Any]],
    *,
    should_cache: Callable[[dict[str, Any]], bool] | None = None,
) -> dict[str, Any]:
    """Return cached outcome for ``key``, or run ``action`` and persist if cacheable."""
    cached = store.get_completed(key)
    if cached is not None:
        return cached
    result = action()
    if should_cache is None or should_cache(result):
        return store.record_completed(key, result)
    return result


def _sha256_bytes(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


# ---------------------------------------------------------------------------
# Injectable Protocols and default deterministic implementations
# ---------------------------------------------------------------------------


@runtime_checkable
class ClockProtocol(Protocol):
    """Deterministic UTC clock interface (no wall-clock sleep)."""

    def now(self) -> datetime: ...

    def advance(self, seconds: float | int) -> datetime: ...

    def timestamp(self, *, microseconds: bool = False) -> str: ...


class DeterministicClock:
    """In-memory UTC clock used when no explicit clock is injected."""

    def __init__(self, start: datetime = DEFAULT_UTC_START) -> None:
        if start.tzinfo is None:
            start = start.replace(tzinfo=timezone.utc)
        self._now = start.astimezone(timezone.utc)
        self._lock = threading.Lock()

    def now(self) -> datetime:
        with self._lock:
            return self._now

    def advance(self, seconds: float | int) -> datetime:
        if isinstance(seconds, bool) or not isinstance(seconds, (int, float)):
            raise ValueError("seconds must be a finite non-negative number")
        if not math.isfinite(seconds) or seconds < 0:
            raise ValueError("seconds must be a finite non-negative number")
        with self._lock:
            self._now = self._now + timedelta(seconds=float(seconds))
            return self._now

    def timestamp(self, *, microseconds: bool = False) -> str:
        with self._lock:
            current = self._now
        if microseconds:
            return current.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        return current.replace(microsecond=0).isoformat().replace("+00:00", "Z")


@runtime_checkable
class SandboxProtocol(Protocol):
    """Minimal sandbox surface consumed by v2 ``build`` and ``verify`` nodes."""

    def probe(self, *, deadline_seconds: float = 120.0) -> ProbeReport: ...

    def build(
        self,
        version: str,
        *,
        compile_args: Sequence[str] = (),
        deadline_seconds: float = 300.0,
        expected_materials: Mapping[str, str] | None = None,
    ) -> BuildResult: ...

    def replay(
        self,
        version: str,
        phase: str,
        *,
        timeout_seconds: float = 10.0,
        deadline_seconds: float | None = None,
        expected_artifact_digest: str | None = None,
        expected_input_digest: str | None = None,
    ) -> ReplayResult: ...


@dataclass(frozen=True)
class IntelResult:
    """Outcome of the ``intel`` node (edges #5 and #6)."""

    status: Literal["ready", "blocked"]
    snapshot_digest: str | None = None
    reason_code: str | None = None
    message: str | None = None
    summary: Mapping[str, Any] = field(default_factory=dict)


@runtime_checkable
class IntelProvider(Protocol):
    """Injectable intel snapshot resolver for the ``intel`` node (P3 T15)."""

    def resolve_intel(
        self,
        *,
        job_id: str,
        family_id: str,
        request: Mapping[str, Any],
    ) -> IntelResult: ...


class DefaultIntelProvider:
    """Offline default intel provider honoring request-declared block states."""

    def resolve_intel(
        self,
        *,
        job_id: str,
        family_id: str,
        request: Mapping[str, Any],
    ) -> IntelResult:
        blocked_reason = request.get("intel_blocked_reason")
        if isinstance(blocked_reason, str) and blocked_reason:
            return IntelResult(
                status="blocked",
                snapshot_digest=None,
                reason_code=blocked_reason,
                message=f"intel snapshot blocked with {blocked_reason}",
                summary={"blocked_reason": blocked_reason},
            )
        summary = {
            "source": str(request.get("intel_source", "offline_snapshot")),
            "job_id": job_id,
            "family_id": family_id,
        }
        return IntelResult(
            status="ready",
            snapshot_digest=jsonutil.digest_json(summary),
            reason_code=None,
            message=None,
            summary=summary,
        )


@dataclass(frozen=True)
class HypothesisAggregationResult:
    """Candidate ExperimentSpec emitted by ``hypothesis_aggregator`` (edge #14)."""

    experiment_spec: Mapping[str, Any]
    experiment_digest: str
    hypotheses: tuple[Mapping[str, Any], ...] = ()
    model_audit: Mapping[str, Any] = field(default_factory=dict)


@runtime_checkable
class HypothesisAggregator(Protocol):
    """Injectable hypothesis aggregator for ``hypothesis_aggregator`` (P3 T14)."""

    def aggregate(
        self,
        *,
        job_id: str,
        family_id: str,
        job_kind: str,
        round_no: int | None,
        target_kind: str,
        route_facts: Mapping[str, Any],
        seed_bytes: bytes | None = None,
    ) -> HypothesisAggregationResult: ...


class DefaultHypothesisAggregator:
    """Offline deterministic aggregator producing a canonical ExperimentSpec stub."""

    def aggregate(
        self,
        *,
        job_id: str,
        family_id: str,
        job_kind: str,
        round_no: int | None,
        target_kind: str,
        route_facts: Mapping[str, Any],
        seed_bytes: bytes | None = None,
    ) -> HypothesisAggregationResult:
        spec = {
            "family_id": family_id,
            "job_kind": job_kind,
            "round_no": round_no,
            "target_kind": target_kind,
            "seed_digest": _sha256_bytes(seed_bytes) if seed_bytes is not None else None,
            "evidence_refs": list(route_facts.get("evidence_refs", ())),
        }
        return HypothesisAggregationResult(
            experiment_spec=spec,
            experiment_digest=jsonutil.digest_json(spec),
            hypotheses=(),
            model_audit={"provider": "offline"},
        )


@runtime_checkable
class ReviewDecision(Protocol):
    """Decision contract returned by ``ReviewGate.evaluate_first_plan``."""

    @property
    def edge(self) -> str: ...

    @property
    def decision(self) -> str: ...

    @property
    def reason_code(self) -> str | None: ...

    @property
    def approval_digest(self) -> str | None: ...


@runtime_checkable
class ReviewGate(Protocol):
    """Injectable human first-plan approval gate (edges #15 and #17)."""

    def evaluate_first_plan(
        self,
        *,
        family_id: str,
        first_plan_digest: str,
        envelope_digest: str,
    ) -> ReviewDecision: ...


@dataclass(frozen=True)
class DefaultReviewDecision:
    edge: str
    decision: str
    reason_code: str | None
    approval_digest: str | None
    envelope_digest: str
    first_plan_digest: str
    decided_at: str


class DefaultReviewGate:
    """Default in-memory human approval gate for tests that omit one."""

    def __init__(self, *, clock: ClockProtocol | None = None) -> None:
        self._clock = clock or DeterministicClock()
        self.review_writes: int = 0

    def evaluate_first_plan(
        self,
        *,
        family_id: str,
        first_plan_digest: str,
        envelope_digest: str,
    ) -> DefaultReviewDecision:
        decided_at = self._clock.timestamp(microseconds=True)
        self.review_writes += 1
        approval_digest = jsonutil.digest_json(
            {
                "family_id": family_id,
                "envelope_digest": envelope_digest,
                "first_plan_digest": first_plan_digest,
                "reviewer_id": "default-reviewer",
                "decided_at": decided_at,
            }
        )
        return DefaultReviewDecision(
            edge="build",
            decision="approve",
            reason_code=None,
            approval_digest=approval_digest,
            envelope_digest=envelope_digest,
            first_plan_digest=first_plan_digest,
            decided_at=decided_at,
        )


@runtime_checkable
class AdmissionDecision(Protocol):
    """Decision contract returned by ``EnvelopePolicy.admit_round``."""

    @property
    def edge(self) -> str: ...

    @property
    def admitted(self) -> bool: ...

    @property
    def reason_code(self) -> str | None: ...

    @property
    def admission_id(self) -> str | None: ...


@runtime_checkable
class EnvelopePolicy(Protocol):
    """Injectable in-round policy admission hook (edges #16 and #17; never writes reviews)."""

    def admit_round(
        self,
        *,
        family_id: str,
        job_id: str,
        round_no: int,
        envelope_digest: str,
        parent_approval_digest: str | None,
        seed_digest: str,
    ) -> AdmissionDecision: ...


@dataclass(frozen=True)
class DefaultAdmissionDecision:
    edge: str
    admitted: bool
    approval_kind: str
    reason_code: str | None
    admission_id: str | None
    decided_at: str


class DefaultEnvelopePolicy:
    """Default in-memory policy admission stub."""

    def __init__(self, *, clock: ClockProtocol | None = None) -> None:
        self._clock = clock or DeterministicClock()
        self.admissions: list[dict[str, Any]] = []

    def admit_round(
        self,
        *,
        family_id: str,
        job_id: str,
        round_no: int,
        envelope_digest: str,
        parent_approval_digest: str | None,
        seed_digest: str,
    ) -> DefaultAdmissionDecision:
        decided_at = self._clock.timestamp()
        if not parent_approval_digest:
            return DefaultAdmissionDecision(
                edge="archive",
                admitted=False,
                approval_kind="policy",
                reason_code="ADMISSION_DENIED",
                admission_id=None,
                decided_at=decided_at,
            )
        admission_id = f"admission-{round_no:03d}"
        self.admissions.append(
            {
                "family_id": family_id,
                "job_id": job_id,
                "round_no": round_no,
                "envelope_digest": envelope_digest,
                "parent_approval_digest": parent_approval_digest,
                "seed_digest": seed_digest,
                "admission_id": admission_id,
                "decided_at": decided_at,
            }
        )
        return DefaultAdmissionDecision(
            edge="build",
            admitted=True,
            approval_kind="policy",
            reason_code=None,
            admission_id=admission_id,
            decided_at=decided_at,
        )


@dataclass(frozen=True)
class BuildDiagnosis:
    """Outcome emitted by ``BuildDiagnoser`` for ``build_diagnose``."""

    outcome: Literal["ok", "retry", "failed", "provenance_missing"]
    reason_code: str | None = None
    message: str | None = None


@runtime_checkable
class BuildDiagnoser(Protocol):
    """Injectable build diagnosis and provenance check hook (edges #19/#20/#21/#22)."""

    def diagnose(
        self,
        *,
        job_id: str,
        job_kind: str,
        build_artifacts: Mapping[str, Mapping[str, Any]],
        retry_count: int,
        max_retries: int,
        reused_build_ref: Mapping[str, Any] | None = None,
    ) -> BuildDiagnosis: ...


class DefaultBuildDiagnoser:
    """Default diagnoser bounding retryable failures to at most ``max_retries``."""

    def diagnose(
        self,
        *,
        job_id: str,
        job_kind: str,
        build_artifacts: Mapping[str, Mapping[str, Any]],
        retry_count: int,
        max_retries: int,
        reused_build_ref: Mapping[str, Any] | None = None,
    ) -> BuildDiagnosis:
        del job_id, job_kind
        if reused_build_ref is not None:
            if "artifacts" in reused_build_ref and not isinstance(
                reused_build_ref.get("artifacts"), Mapping
            ):
                return BuildDiagnosis(
                    outcome="failed",
                    reason_code="REUSE_MISMATCH",
                    message="reused build_ref.artifacts must be a mapping",
                )
            ref_source: Mapping[str, Any] = (
                reused_build_ref["artifacts"]
                if isinstance(reused_build_ref.get("artifacts"), Mapping)
                else reused_build_ref
            )
            for version in verdict_mod.VERSIONS:
                entry = build_artifacts.get(version)
                ref_entry = ref_source.get(version)
                entry_digest = (
                    entry.get("artifact_digest")
                    if isinstance(entry, Mapping)
                    else None
                )
                ref_digest = (
                    ref_entry.get("artifact_digest")
                    if isinstance(ref_entry, Mapping)
                    else None
                )
                if (
                    not isinstance(entry_digest, str)
                    or not entry_digest.strip()
                    or not isinstance(ref_digest, str)
                    or not ref_digest.strip()
                    or entry_digest != ref_digest
                ):
                    return BuildDiagnosis(
                        outcome="failed",
                        reason_code="REUSE_MISMATCH",
                        message=f"reused build artifact missing for {version}",
                    )
            return BuildDiagnosis(outcome="ok")

        for version in verdict_mod.VERSIONS:
            entry = build_artifacts.get(version)
            if not isinstance(entry, Mapping):
                return BuildDiagnosis(
                    outcome="failed",
                    reason_code="BUILD_FAILED",
                    message=f"missing build result for {version}",
                )
            if entry.get("provenance_missing"):
                return BuildDiagnosis(
                    outcome="provenance_missing",
                    reason_code="BUILD_PROVENANCE_MISSING",
                    message=f"build provenance missing for {version}",
                )
            if entry.get("status") != "completed":
                if entry.get("diagnose_failed"):
                    return BuildDiagnosis(
                        outcome="failed",
                        reason_code="BUILD_FAILED",
                        message=f"non-retryable build diagnose failure for {version}",
                    )
                if entry.get("retryable") and retry_count < max_retries:
                    return BuildDiagnosis(
                        outcome="retry",
                        reason_code=None,
                        message=f"retrying build for {version}",
                    )
                return BuildDiagnosis(
                    outcome="failed",
                    reason_code="BUILD_FAILED",
                    message=f"build failed for {version} after {retry_count} retry(s)",
                )
            if entry.get("log_truncated") or entry.get("capture_error"):
                return BuildDiagnosis(
                    outcome="failed",
                    reason_code="BUILD_FAILED",
                    message=f"build capture invalid for {version}",
                )
        return BuildDiagnosis(outcome="ok")


@dataclass(frozen=True)
class CampaignResult:
    """Output of ``CampaignRunner.run_campaign`` (edges #20/#23/#24; never produces a verdict)."""

    candidate_seeds: tuple[bytes, ...]
    campaign_bundle_digest: str
    fuzz_seconds_used: float = 1.0
    metadata: Mapping[str, Any] = field(default_factory=dict)


@runtime_checkable
class CampaignRunner(Protocol):
    """Injectable campaign fuzz runner for the ``campaign`` node."""

    def run_campaign(
        self,
        *,
        job_id: str,
        family_id: str,
        build_artifacts: Mapping[str, Mapping[str, Any]],
        candidate_seeds: Sequence[bytes] = (),
    ) -> CampaignResult: ...


class DefaultCampaignRunner:
    """Deterministic campaign runner advancing the injected clock without sleeping."""

    def __init__(
        self,
        *,
        clock: ClockProtocol | None = None,
        fuzz_duration_seconds: float = 1.0,
    ) -> None:
        self._clock = clock
        self._fuzz_duration_seconds = float(fuzz_duration_seconds)

    def run_campaign(
        self,
        *,
        job_id: str,
        family_id: str,
        build_artifacts: Mapping[str, Mapping[str, Any]],
        candidate_seeds: Sequence[bytes] = (),
    ) -> CampaignResult:
        if self._clock is not None and self._fuzz_duration_seconds > 0:
            self._clock.advance(self._fuzz_duration_seconds)
        seeds = tuple(candidate_seeds)
        bundle_payload = {
            "job_id": job_id,
            "family_id": family_id,
            "seed_digests": [_sha256_bytes(seed) for seed in seeds],
            "build_digests": {
                version: build_artifacts.get(version, {}).get("artifact_digest")
                for version in verdict_mod.VERSIONS
            },
        }
        return CampaignResult(
            candidate_seeds=seeds,
            campaign_bundle_digest=jsonutil.digest_json(bundle_payload),
            fuzz_seconds_used=self._fuzz_duration_seconds,
            metadata={"seed_count": len(seeds)},
        )


@dataclass(frozen=True)
class IterationDecision:
    """Capacity decision for family-level edge #26 (``verify -> hypothesis_aggregator``)."""

    should_continue: bool
    reason_code: str | None = None
    remaining_rounds: int | None = None
    remaining_budget_seconds: float | None = None


@runtime_checkable
class IterationGate(Protocol):
    """Injectable capacity gate for edge #26 (consumed by P1 T12)."""

    def check_capacity(
        self,
        *,
        family_id: str,
        completed_round_no: int,
        max_rounds: int,
        last_verdict: str | None,
        remaining_budget_seconds: float | None = None,
        remaining_fuzz_seconds: float | None = None,
        remaining_seeds: int | None = None,
    ) -> IterationDecision: ...


MIN_STEP_BUDGET_SECONDS = 1


def _has_budget_capacity(remaining: float | None) -> bool:
    """Return whether an optional remaining balance can start one more step.

    ``None`` means the caller does not track that budget. Otherwise the
    balance must be at least ``MIN_STEP_BUDGET_SECONDS`` (the ``>= 1`` rule of
    ``state.budget_gate``); ``0 < remaining < 1`` is exhausted.
    """
    return remaining is None or remaining >= MIN_STEP_BUDGET_SECONDS


class DefaultIterationGate:
    """Checks verdict conclusiveness, ``max_rounds``, budget, and seed capacity."""

    def check_capacity(
        self,
        *,
        family_id: str,
        completed_round_no: int,
        max_rounds: int,
        last_verdict: str | None,
        remaining_budget_seconds: float | None = None,
        remaining_fuzz_seconds: float | None = None,
        remaining_seeds: int | None = None,
    ) -> IterationDecision:
        del family_id, remaining_fuzz_seconds
        remaining_rounds = max(0, max_rounds - completed_round_no)
        if last_verdict in ("REPRODUCED", "NOT_REPRODUCED"):
            return IterationDecision(
                should_continue=False,
                reason_code=None,
                remaining_rounds=remaining_rounds,
                remaining_budget_seconds=remaining_budget_seconds,
            )
        if last_verdict != "INCONCLUSIVE":
            return IterationDecision(
                should_continue=False,
                reason_code=None,
                remaining_rounds=remaining_rounds,
                remaining_budget_seconds=remaining_budget_seconds,
            )
        if completed_round_no >= max_rounds:
            return IterationDecision(
                should_continue=False,
                reason_code="BUDGET_EXHAUSTED",
                remaining_rounds=0,
                remaining_budget_seconds=remaining_budget_seconds,
            )
        # Round derivation checks max_rounds and the total budget only
        # (ADR-004 #7): guided validation rounds run general steps, never fuzz,
        # so an exhausted fuzz sub-budget must not block validation.
        if not _has_budget_capacity(remaining_budget_seconds):
            return IterationDecision(
                should_continue=False,
                reason_code="BUDGET_EXHAUSTED",
                remaining_rounds=remaining_rounds,
                remaining_budget_seconds=remaining_budget_seconds,
            )
        if remaining_seeds is not None and remaining_seeds <= 0:
            return IterationDecision(
                should_continue=False,
                reason_code="NO_REMAINING_SEEDS",
                remaining_rounds=remaining_rounds,
                remaining_budget_seconds=remaining_budget_seconds,
            )
        return IterationDecision(
            should_continue=True,
            reason_code=None,
            remaining_rounds=remaining_rounds,
            remaining_budget_seconds=remaining_budget_seconds,
        )


# ---------------------------------------------------------------------------
# Node re-entry ledger, budget charges, and archive accounting
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class BudgetChargeRecord:
    """Idempotent budget charge keyed by ``(job_id, step_key, attempt_no)``."""

    job_id: str
    family_id: str
    step_key: str
    attempt_no: int
    seconds: float
    fuzz_seconds: float
    charge_kind: str
    recorded_at: str


@dataclass(frozen=True)
class ArchiveRecord:
    """Recorded archive write for a job or family index."""

    job_id: str
    family_id: str
    job_kind: str
    state: str
    verdict: str | None
    reason_code: str | None
    archive_digest: str
    recorded_at: str
    intel_summary: Mapping[str, Any] | None = None


@dataclass(frozen=True)
class AuditEventRecord:
    """Idempotent audit event keyed by ``(job_id, stage, step_key, attempt_no, event_type)``."""

    job_id: str
    family_id: str
    stage: str
    step_key: str
    attempt_no: int
    event_type: str
    reason_code: str | None
    detail: Mapping[str, Any]
    recorded_at: str


@runtime_checkable
class AuditEventStore(Protocol):
    """Minimal persistence contract for idempotent orchestration audit events."""

    def record_audit_event(
        self,
        *,
        job_id: str,
        family_id: str,
        stage: str,
        step_key: str,
        attempt_no: int,
        event_type: str,
        reason_code: str | None,
        detail: Mapping[str, Any] | None = None,
        recorded_at: str,
    ) -> bool: ...

    def audit_events_for_job(self, job_id: str) -> tuple[AuditEventRecord, ...]: ...


@runtime_checkable
class ChargeArchiveStore(Protocol):
    """Minimal persistence contract for budget charge and archive accounting."""

    def record_charge(
        self,
        *,
        job_id: str,
        family_id: str,
        step_key: str,
        attempt_no: int,
        seconds: float,
        recorded_at: str,
        fuzz_seconds: float = 0.0,
        charge_kind: str = "general",
    ) -> bool: ...

    def charge_count(self, job_id: str) -> int: ...

    def total_charged_seconds(self, family_id: str) -> float: ...

    def total_fuzz_seconds(self, family_id: str) -> float: ...

    def record_archive(
        self,
        *,
        job_id: str,
        family_id: str,
        job_kind: str,
        state: str,
        verdict: str | None,
        reason_code: str | None,
        archive_digest: str,
        recorded_at: str,
    ) -> ArchiveRecord: ...

    def archive_count(self, job_id: str) -> int: ...


class NodeReentryLedger:
    """In-memory persistence ledger enforcing node re-entry no-op semantics.

    Satisfies :class:`AttemptStore`, :class:`ChargeArchiveStore`, and
    :class:`AuditEventStore`.
    Node outcomes are keyed by ``(job_id, stage, step_key, attempt_no, generation)``
    per ``test-plan-delta.md`` §3. Budget charges are additionally deduplicated on
    ``(job_id, step_key, attempt_no)`` per ``README.md`` §7 invariant 7, audit
    events are deduplicated on ``(job_id, stage, step_key, attempt_no, event_type)``,
    and archive writes are first-write-wins per ``job_id``.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._node_results: dict[StepKey, dict[str, Any]] = {}
        self._charge_keys: set[tuple[str, str, int]] = set()
        self._charges_by_job: dict[str, list[BudgetChargeRecord]] = {}
        self._charges_by_family: dict[str, list[BudgetChargeRecord]] = {}
        self._archives_by_job: dict[str, list[ArchiveRecord]] = {}
        self._audit_keys: set[tuple[str, str, str, int, str]] = set()
        self._audit_events_by_job: dict[str, list[AuditEventRecord]] = {}

    def get_completed(self, key: StepKey) -> dict[str, Any] | None:
        step_key = key if isinstance(key, StepKey) else StepKey(*key)
        with self._lock:
            cached = self._node_results.get(step_key)
            if cached is None:
                return None
            return copy.deepcopy(cached)

    def record_completed(
        self,
        key: StepKey,
        result: Mapping[str, Any],
    ) -> dict[str, Any]:
        step_key = key if isinstance(key, StepKey) else StepKey(*key)
        snapshot = copy.deepcopy(dict(result))
        with self._lock:
            existing = self._node_results.get(step_key)
            if existing is not None:
                return copy.deepcopy(existing)
            self._node_results[step_key] = snapshot
        return copy.deepcopy(snapshot)

    def get(self, key: IdempotencyKey) -> dict[str, Any] | None:
        return self.get_completed(key if isinstance(key, StepKey) else StepKey(*key))

    def record(self, key: IdempotencyKey, result: Mapping[str, Any]) -> dict[str, Any]:
        return self.record_completed(
            key if isinstance(key, StepKey) else StepKey(*key),
            result,
        )

    def record_charge(
        self,
        *,
        job_id: str,
        family_id: str,
        step_key: str,
        attempt_no: int,
        seconds: float,
        recorded_at: str,
        fuzz_seconds: float = 0.0,
        charge_kind: str = "general",
    ) -> bool:
        charge_key = (job_id, step_key, attempt_no)
        with self._lock:
            if charge_key in self._charge_keys:
                return False
            self._charge_keys.add(charge_key)
            entry = BudgetChargeRecord(
                job_id=job_id,
                family_id=family_id,
                step_key=step_key,
                attempt_no=attempt_no,
                seconds=float(seconds),
                fuzz_seconds=float(fuzz_seconds),
                charge_kind=charge_kind,
                recorded_at=recorded_at,
            )
            self._charges_by_job.setdefault(job_id, []).append(entry)
            self._charges_by_family.setdefault(family_id, []).append(entry)
            return True

    def charge_count(self, job_id: str) -> int:
        with self._lock:
            return len(self._charges_by_job.get(job_id, ()))

    def charges_for_job(self, job_id: str) -> tuple[BudgetChargeRecord, ...]:
        with self._lock:
            return tuple(self._charges_by_job.get(job_id, ()))

    def total_charged_seconds(self, family_id: str) -> float:
        with self._lock:
            return sum(item.seconds for item in self._charges_by_family.get(family_id, ()))

    def total_fuzz_seconds(self, family_id: str) -> float:
        with self._lock:
            return sum(
                item.fuzz_seconds for item in self._charges_by_family.get(family_id, ())
            )

    def record_archive(
        self,
        *,
        job_id: str,
        family_id: str,
        job_kind: str,
        state: str,
        verdict: str | None,
        reason_code: str | None,
        archive_digest: str,
        recorded_at: str,
        intel_summary: Mapping[str, Any] | None = None,
    ) -> ArchiveRecord:
        intel_snapshot = (
            copy.deepcopy(dict(intel_summary)) if intel_summary is not None else None
        )
        entry = ArchiveRecord(
            job_id=job_id,
            family_id=family_id,
            job_kind=job_kind,
            state=state,
            verdict=verdict,
            reason_code=reason_code,
            archive_digest=archive_digest,
            recorded_at=recorded_at,
            intel_summary=intel_snapshot,
        )
        with self._lock:
            existing = self._archives_by_job.get(job_id)
            if existing:
                return copy.deepcopy(existing[0])
            self._archives_by_job[job_id] = [entry]
        return copy.deepcopy(entry)

    def archive_count(self, job_id: str) -> int:
        with self._lock:
            return len(self._archives_by_job.get(job_id, ()))

    def archives_for_job(self, job_id: str) -> tuple[ArchiveRecord, ...]:
        with self._lock:
            return tuple(
                copy.deepcopy(record)
                for record in self._archives_by_job.get(job_id, ())
            )

    def record_audit_event(
        self,
        *,
        job_id: str,
        family_id: str,
        stage: str,
        step_key: str,
        attempt_no: int,
        event_type: str,
        reason_code: str | None,
        detail: Mapping[str, Any] | None = None,
        recorded_at: str,
    ) -> bool:
        audit_key = (job_id, stage, step_key, attempt_no, event_type)
        detail_snapshot = copy.deepcopy(dict(detail)) if detail is not None else {}
        with self._lock:
            if audit_key in self._audit_keys:
                return False
            self._audit_keys.add(audit_key)
            entry = AuditEventRecord(
                job_id=job_id,
                family_id=family_id,
                stage=stage,
                step_key=step_key,
                attempt_no=attempt_no,
                event_type=event_type,
                reason_code=reason_code,
                detail=detail_snapshot,
                recorded_at=recorded_at,
            )
            self._audit_events_by_job.setdefault(job_id, []).append(entry)
            return True

    def audit_events_for_job(self, job_id: str) -> tuple[AuditEventRecord, ...]:
        with self._lock:
            return tuple(
                copy.deepcopy(event)
                for event in self._audit_events_by_job.get(job_id, ())
            )


# ---------------------------------------------------------------------------
# LangGraph v2 state & compiled 14-node graph
# ---------------------------------------------------------------------------


class OrchestrationState(TypedDict, total=False):
    job_id: str
    family_id: str
    parent_job_id: str | None
    job_kind: str
    round_no: int | None
    generation: int
    target_kind: str
    request: dict[str, Any]
    is_first_plan: bool
    envelope_digest: str
    first_plan_digest: str
    parent_approval_digest: str | None
    approval_digest: str | None
    admission_id: str | None
    admission_kind: str | None
    seed_bytes: bytes | None
    seed_digest: str | None
    candidate_seeds: tuple[bytes, ...]
    build_ref: dict[str, Any] | None
    build_artifacts: dict[str, dict[str, Any]]
    build_retry_count: int
    max_build_retries: int
    intel_summary: dict[str, Any] | None
    version_pair: dict[str, str]
    route_facts: dict[str, Any]
    experiment_spec: dict[str, Any]
    experiment_digest: str | None
    campaign_bundle_digest: str | None
    verdict: str | None
    state: str
    reason_code: str | None
    error_message: str | None
    next_route: str | None
    terminal_node: str | None
    archive_digest: str | None
    family_summary: dict[str, Any]
    visited_nodes: list[str]
    step_key_override: str | None
    attempt_no_override: int | None


@dataclass(frozen=True)
class NodeContext:
    """Immutable dependency bundle injected into all 14 v0.2 LangGraph nodes."""

    sandbox: SandboxProtocol | None
    clock: ClockProtocol
    intel_provider: IntelProvider
    hypothesis_aggregator: HypothesisAggregator
    review_gate: ReviewGate
    envelope_policy: EnvelopePolicy
    build_diagnoser: BuildDiagnoser
    campaign_runner: CampaignRunner
    verdict_policy: verdict_mod.VerdictPolicy
    ledger: ChargeArchiveStore
    attempt_store: AttemptStore
    audit_store: AuditEventStore | None = None


def _resolve_audit_store(
    audit_store: AuditEventStore | None,
    ledger: ChargeArchiveStore,
    attempt_store: AttemptStore,
) -> AuditEventStore:
    if audit_store is not None:
        return audit_store
    if isinstance(ledger, AuditEventStore):
        return ledger
    if isinstance(attempt_store, AuditEventStore):
        return attempt_store
    return NodeReentryLedger()


def _accepts_keyword_arg(fn: Callable[..., Any], arg_name: str) -> bool:
    try:
        sig = inspect.signature(fn)
    except (TypeError, ValueError):
        return False
    for param in sig.parameters.values():
        if param.kind is inspect.Parameter.VAR_KEYWORD:
            return True
        if param.name == arg_name and param.kind in (
            inspect.Parameter.POSITIONAL_OR_KEYWORD,
            inspect.Parameter.KEYWORD_ONLY,
        ):
            return True
    return False


NodeFn = Callable[[OrchestrationState], dict[str, Any]]
NodeHandler = Callable[[NodeContext, OrchestrationState], dict[str, Any]]


def _append_visited(state: OrchestrationState, node_name: str) -> list[str]:
    visited = list(state.get("visited_nodes", ()))
    visited.append(node_name)
    return visited


def _node_key(
    state: OrchestrationState,
    stage: str,
    *,
    default_step_key: str,
    default_attempt_no: int = 1,
) -> StepKey:
    job_id = state["job_id"]
    step_key = state.get("step_key_override") or default_step_key
    attempt_no = state.get("attempt_no_override")
    if attempt_no is None:
        attempt_no = default_attempt_no
    generation = state.get("generation", 1)
    return StepKey(job_id, stage, step_key, attempt_no, generation)


def _validate_max_build_retries(value: Any) -> int:
    if type(value) is not int or value < 0 or value > 1:
        raise ValueError(
            "max_build_retries must be an int in [0, 1] "
            "(README §5 edge #19 bounds build_diagnose to at most 1 extra retry)"
        )
    return value


def _validate_non_negative_budget(
    name: str,
    value: float | int | None,
) -> float | None:
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"{name} must be a finite non-negative number")
    if not math.isfinite(value) or value < 0:
        raise ValueError(f"{name} must be a finite non-negative number")
    return float(value)


def _extract_reused_build_artifacts(
    reused_ref: Mapping[str, Any],
) -> dict[str, dict[str, Any]]:
    """Unpack T10 nested ``build_ref['artifacts']`` (or flat legacy map) for verify."""
    if "artifacts" in reused_ref:
        nested_artifacts = reused_ref.get("artifacts")
        if not isinstance(nested_artifacts, Mapping):
            return {}
        source_map: Mapping[str, Any] = nested_artifacts
    else:
        source_map = reused_ref

    reused_artifacts: dict[str, dict[str, Any]] = {}
    for version in verdict_mod.VERSIONS:
        raw_entry = source_map.get(version)
        if isinstance(raw_entry, Mapping):
            entry = dict(raw_entry)
            entry.setdefault("status", "completed")
            reused_artifacts[version] = entry
    return reused_artifacts


def _build_ref_from_campaign_state(
    state: OrchestrationState,
    build_artifacts: Mapping[str, Mapping[str, Any]],
) -> dict[str, Any]:
    """Construct a closed 4-key T10 ``build_ref`` matching ``contracts._build_ref``."""
    artifacts: dict[str, dict[str, Any]] = {}
    inputs_summary: dict[str, Any] = {
        "family_id": state["family_id"],
        "version_pair": dict(state.get("version_pair") or {}),
        "builds": {},
    }
    for version in verdict_mod.VERSIONS:
        entry = build_artifacts.get(version) or {}
        artifact_digest = entry.get("artifact_digest")
        build_log_digest = entry.get("build_log_digest")
        if not isinstance(build_log_digest, str) or not build_log_digest:
            build_log_digest = jsonutil.digest_json(
                {"version": version, "artifact_digest": artifact_digest}
            )
        artifacts[version] = {
            "artifact_digest": artifact_digest,
            "build_log_digest": build_log_digest,
        }
        inputs_summary["builds"][version] = {
            "image_digest": entry.get("image_digest"),
            "compile_args": list(entry.get("compile_args") or ()),
        }
    return {
        "source_job_id": state["job_id"],
        "generation": state.get("generation", 1),
        "build_inputs_digest": jsonutil.digest_json(inputs_summary),
        "artifacts": artifacts,
    }


def _serialize_build_result(result: BuildResult) -> dict[str, Any]:
    return {
        "version": result.version,
        "status": result.status,
        "exit_code": result.exit_code,
        "duration_seconds": result.duration_seconds,
        "container_id": result.container_id,
        "image_digest": result.image_digest,
        "compile_args": list(result.compile_args),
        "artifact_digest": result.artifact_digest,
        "build_log_digest": _sha256_bytes(result.log),
        "log_truncated": result.log_truncated,
        "capture_error": result.capture_error,
        "retryable": bool(result.metadata.get("retryable", False)),
        "diagnose_failed": bool(result.metadata.get("diagnose_failed", False)),
        "provenance_missing": bool(result.metadata.get("provenance_missing", False)),
        "metadata": dict(result.metadata),
    }


def _observation_from_replay(result: ReplayResult) -> verdict_mod.RunObservation:
    return verdict_mod.RunObservation(
        version=result.version,
        phase=result.phase,
        status=result.status,
        exit_code=result.exit_code,
        stdout=result.stdout.decode("utf-8", "replace"),
        stderr=result.stderr.decode("utf-8", "replace"),
        signature=result.signature,
        input_digest=result.input_digest,
        duration_seconds=result.duration_seconds,
        log_truncated=result.log_truncated,
        capture_error=result.capture_error,
    )


def _node_prepare(ctx: NodeContext, state: OrchestrationState) -> dict[str, Any]:
    key = _node_key(state, "prepare", default_step_key="prepare")

    def _action() -> dict[str, Any]:
        request = state.get("request") or {}
        job_kind = state.get("job_kind", "round")
        blocked_reason = request.get("prepare_blocked_reason")
        if isinstance(blocked_reason, str) and blocked_reason:
            return {
                "state": "BLOCKED",
                "reason_code": blocked_reason,
                "next_route": "archive",
                "visited_nodes": _append_visited(state, "prepare"),
            }
        if job_kind not in ("family", "campaign", "round"):
            return {
                "state": "BLOCKED",
                "reason_code": "INVALID_REQUEST",
                "next_route": "archive",
                "visited_nodes": _append_visited(state, "prepare"),
            }
        if job_kind == "family":
            return {
                "state": "AGGREGATING",
                "next_route": "AGGREGATING",
                "visited_nodes": _append_visited(state, "prepare"),
            }
        return {
            "state": "PREPARING",
            "next_route": "intel",
            "visited_nodes": _append_visited(state, "prepare"),
        }

    return run_idempotent(ctx.attempt_store, key, _action)


def _node_aggregating(ctx: NodeContext, state: OrchestrationState) -> dict[str, Any]:
    key = _node_key(state, "AGGREGATING", default_step_key="aggregating")

    def _action() -> dict[str, Any]:
        summary = dict(state.get("family_summary") or {})
        summary.setdefault("kind", "family_index")
        summary.setdefault("family_id", state["family_id"])
        return {
            "state": summary.get("final_state", "COMPLETED"),
            "verdict": None,
            "reason_code": summary.get("final_reason_code"),
            "family_summary": summary,
            "next_route": "archive",
            "visited_nodes": _append_visited(state, "AGGREGATING"),
        }

    return run_idempotent(ctx.attempt_store, key, _action)


def _node_intel(ctx: NodeContext, state: OrchestrationState) -> dict[str, Any]:
    key = _node_key(state, "intel", default_step_key="intel")

    def _action() -> dict[str, Any]:
        request = state.get("request") or {}
        job_id = state["job_id"]
        family_id = state["family_id"]
        audit_store = _resolve_audit_store(
            ctx.audit_store, ctx.ledger, ctx.attempt_store
        )
        try:
            result = ctx.intel_provider.resolve_intel(
                job_id=job_id,
                family_id=family_id,
                request=request,
            )
        except Exception as error:  # noqa: BLE001 - normalize intel block reasons
            reason = getattr(error, "reason_code", None)
            if not isinstance(reason, str) or not reason.strip():
                raise
            normalized_reason = reason.strip()
            error_summary: dict[str, Any] = {}
            sub_reason = getattr(error, "sub_reason", None)
            if isinstance(sub_reason, str) and sub_reason.strip():
                error_summary["sub_reason"] = sub_reason.strip()
            source_id = getattr(error, "source_id", None)
            if isinstance(source_id, str) and source_id.strip():
                error_summary["source_id"] = source_id.strip()
            result = IntelResult(
                status="blocked",
                snapshot_digest=None,
                reason_code=normalized_reason,
                message=f"intel blocked with {normalized_reason}",
                summary=error_summary,
            )

        snapshot_digest = (
            result.snapshot_digest.strip()
            if isinstance(result.snapshot_digest, str)
            else ""
        )
        if result.status != "ready" or not snapshot_digest:
            blocked_summary: dict[str, Any] = (
                copy.deepcopy(dict(result.summary))
                if isinstance(result.summary, Mapping)
                else {}
            )
            if result.status != "ready":
                raw_reason = result.reason_code
                reason_code = (
                    raw_reason.strip()
                    if isinstance(raw_reason, str) and raw_reason.strip()
                    else "MATERIAL_MISSING"
                )
                error_message = result.message
            else:
                # Edge #6 fail-closed: ready status without a valid snapshot_digest
                # must never enter version with unverified content.
                reason_code = "MATERIAL_MISSING"
                error_message = (
                    result.message or "intel snapshot_digest is missing or blank"
                )
                existing_sub = blocked_summary.get("sub_reason")
                if not isinstance(existing_sub, str) or not existing_sub.strip():
                    blocked_summary["sub_reason"] = "SNAPSHOT_DIGEST_MISSING"
            audit_store.record_audit_event(
                job_id=job_id,
                family_id=family_id,
                stage="intel",
                step_key=key.step_key,
                attempt_no=key.attempt_no,
                event_type="intel_blocked",
                reason_code=reason_code,
                detail=blocked_summary,
                recorded_at=ctx.clock.timestamp(),
            )
            return {
                "state": "BLOCKED",
                "reason_code": reason_code,
                "error_message": error_message,
                "intel_summary": blocked_summary,
                "next_route": "archive",
                "visited_nodes": _append_visited(state, "intel"),
            }

        summary: dict[str, Any] = (
            copy.deepcopy(dict(result.summary))
            if isinstance(result.summary, Mapping)
            else {}
        )
        summary["snapshot_digest"] = snapshot_digest
        audit_store.record_audit_event(
            job_id=job_id,
            family_id=family_id,
            stage="intel",
            step_key=key.step_key,
            attempt_no=key.attempt_no,
            event_type="intel_resolved",
            reason_code=None,
            detail=summary,
            recorded_at=ctx.clock.timestamp(),
        )
        return {
            "intel_summary": summary,
            "next_route": "version",
            "visited_nodes": _append_visited(state, "intel"),
        }

    return run_idempotent(ctx.attempt_store, key, _action)


def _node_version(ctx: NodeContext, state: OrchestrationState) -> dict[str, Any]:
    key = _node_key(state, "version", default_step_key="version")

    def _action() -> dict[str, Any]:
        request = state.get("request") or {}
        blocked_reason = request.get("version_blocked_reason")
        if isinstance(blocked_reason, str) and blocked_reason:
            return {
                "state": "BLOCKED",
                "reason_code": blocked_reason,
                "next_route": "archive",
                "visited_nodes": _append_visited(state, "version"),
            }
        vulnerable_commit = str(
            request.get("vulnerable_commit", DEFAULT_VULNERABLE_COMMIT)
        )
        fixed_commit = str(request.get("fixed_commit", DEFAULT_FIXED_COMMIT))
        return {
            "version_pair": {
                "vulnerable": vulnerable_commit,
                "fixed": fixed_commit,
            },
            "next_route": "route",
            "visited_nodes": _append_visited(state, "version"),
        }

    return run_idempotent(ctx.attempt_store, key, _action)


def _node_route(ctx: NodeContext, state: OrchestrationState) -> dict[str, Any]:
    key = _node_key(state, "route", default_step_key="route")

    def _action() -> dict[str, Any]:
        target_kind = state.get("target_kind", "source")
        if target_kind in ("patch", "source"):
            return {
                "next_route": target_kind,
                "visited_nodes": _append_visited(state, "route"),
            }
        # Edge #11: reverse placeholder / binary target archives immediately.
        return {
            "state": "BLOCKED",
            "reason_code": "UNSUPPORTED_TARGET",
            "next_route": "archive",
            "visited_nodes": _append_visited(state, "route"),
        }

    return run_idempotent(ctx.attempt_store, key, _action)


def _node_patch(ctx: NodeContext, state: OrchestrationState) -> dict[str, Any]:
    key = _node_key(state, "patch", default_step_key="patch")

    def _action() -> dict[str, Any]:
        return {
            "route_facts": {
                "target_kind": "patch",
                "evidence_refs": ["patch:diff#L1"],
            },
            "next_route": "hypothesis_aggregator",
            "visited_nodes": _append_visited(state, "patch"),
        }

    return run_idempotent(ctx.attempt_store, key, _action)


def _node_source(ctx: NodeContext, state: OrchestrationState) -> dict[str, Any]:
    key = _node_key(state, "source", default_step_key="source")

    def _action() -> dict[str, Any]:
        return {
            "route_facts": {
                "target_kind": "source",
                "evidence_refs": ["source:target.c#L1"],
            },
            "next_route": "hypothesis_aggregator",
            "visited_nodes": _append_visited(state, "source"),
        }

    return run_idempotent(ctx.attempt_store, key, _action)


def _compute_first_plan_digest(
    *,
    family_id: str,
    job_kind: str,
    envelope_digest: str,
    experiment_digest: str | None,
) -> str:
    return jsonutil.digest_json(
        {
            "family_id": family_id,
            "job_kind": job_kind,
            "envelope_digest": envelope_digest,
            "experiment_digest": experiment_digest,
        }
    )


def _node_hypothesis_aggregator(
    ctx: NodeContext,
    state: OrchestrationState,
) -> dict[str, Any]:
    key = _node_key(
        state,
        "hypothesis_aggregator",
        default_step_key="hypothesis_aggregator",
    )

    def _action() -> dict[str, Any]:
        aggregated = ctx.hypothesis_aggregator.aggregate(
            job_id=state["job_id"],
            family_id=state["family_id"],
            job_kind=state.get("job_kind", "round"),
            round_no=state.get("round_no"),
            target_kind=state.get("target_kind", "source"),
            route_facts=state.get("route_facts") or {},
            seed_bytes=state.get("seed_bytes"),
        )
        envelope_digest = state.get("envelope_digest") or jsonutil.digest_json(
            {"family_id": state["family_id"], "kind": "envelope"}
        )
        first_plan_digest = state.get("first_plan_digest") or _compute_first_plan_digest(
            family_id=state["family_id"],
            job_kind=state.get("job_kind", "round"),
            envelope_digest=envelope_digest,
            experiment_digest=aggregated.experiment_digest,
        )
        return {
            "experiment_spec": dict(aggregated.experiment_spec),
            "experiment_digest": aggregated.experiment_digest,
            "envelope_digest": envelope_digest,
            "first_plan_digest": first_plan_digest,
            "next_route": "review",
            "visited_nodes": _append_visited(state, "hypothesis_aggregator"),
        }

    result = run_idempotent(ctx.attempt_store, key, _action)
    # Preserve explicit caller-provided digests on cache hit (e.g. corrected
    # envelope_digest after a D42 REVIEW_ENVELOPE_MISMATCH retry), and keep
    # derived first_plan_digest consistent with the updated envelope_digest.
    explicit_envelope = state.get("envelope_digest")
    explicit_first_plan = state.get("first_plan_digest")
    if explicit_envelope or explicit_first_plan:
        result = dict(result)
        cached_envelope = result.get("envelope_digest")
        if explicit_envelope:
            result["envelope_digest"] = explicit_envelope
        if explicit_first_plan:
            result["first_plan_digest"] = explicit_first_plan
        elif explicit_envelope and explicit_envelope != cached_envelope:
            result["first_plan_digest"] = _compute_first_plan_digest(
                family_id=state["family_id"],
                job_kind=state.get("job_kind", "round"),
                envelope_digest=explicit_envelope,
                experiment_digest=result.get("experiment_digest"),
            )
    return result


def _node_review(ctx: NodeContext, state: OrchestrationState) -> dict[str, Any]:
    """Evaluate human first-plan approval (#15/#17) or policy admission (#16/#17).

    In v2 unit-level graph execution, non-terminal review parking (e.g.
    ``REVIEW_ENVELOPE_MISMATCH``) routes ``await_review -> END`` without caching
    in :class:`AttemptStore` so a later invocation replays from persisted node
    outcomes. PostgreSQL ``PostgresSaver`` / ``run_worker`` integration will
    bridge review parking via LangGraph ``interrupt()``.
    """
    key = _node_key(state, "review", default_step_key="review")

    def _action() -> dict[str, Any]:
        family_id = state["family_id"]
        job_id = state["job_id"]
        job_kind = state.get("job_kind", "round")
        round_no = state.get("round_no")
        parent_approval_digest = state.get("parent_approval_digest")
        envelope_digest = state.get("envelope_digest") or jsonutil.digest_json(
            {"family_id": family_id, "kind": "envelope"}
        )
        first_plan_digest = state.get("first_plan_digest") or jsonutil.digest_json(
            {
                "family_id": family_id,
                "job_id": job_id,
                "envelope_digest": envelope_digest,
            }
        )
        is_first_plan = state.get("is_first_plan")
        if is_first_plan is None:
            is_first_plan = job_kind == "campaign" or (
                round_no in (None, 1) and parent_approval_digest is None
            )

        if is_first_plan:
            decision = ctx.review_gate.evaluate_first_plan(
                family_id=family_id,
                first_plan_digest=first_plan_digest,
                envelope_digest=envelope_digest,
            )
            if decision.edge == "build":
                return {
                    "state": "READY",
                    "approval_digest": decision.approval_digest,
                    "admission_kind": "human",
                    "reason_code": None,
                    "next_route": "human_approve",
                    "visited_nodes": _append_visited(state, "review"),
                }
            if decision.edge == "await_review":
                return {
                    "state": "AWAITING_REVIEW",
                    "reason_code": decision.reason_code,
                    "terminal_node": None,
                    "next_route": "await_review",
                    "visited_nodes": _append_visited(state, "review"),
                }
            return {
                "state": "BLOCKED",
                "reason_code": decision.reason_code or "REVIEW_REJECTED",
                "next_route": "review_blocked",
                "visited_nodes": _append_visited(state, "review"),
            }

        seed_bytes = state.get("seed_bytes")
        seed_digest = state.get("seed_digest") or (
            _sha256_bytes(seed_bytes) if seed_bytes is not None else _sha256_bytes(b"")
        )
        admission = ctx.envelope_policy.admit_round(
            family_id=family_id,
            job_id=job_id,
            round_no=round_no or 1,
            envelope_digest=envelope_digest,
            parent_approval_digest=parent_approval_digest,
            seed_digest=seed_digest,
        )
        if admission.edge == "build" and admission.admitted:
            return {
                "state": "READY",
                "admission_id": admission.admission_id,
                "admission_kind": "policy",
                "reason_code": None,
                "next_route": "policy_admit",
                "visited_nodes": _append_visited(state, "review"),
            }
        return {
            "state": "BLOCKED",
            "reason_code": admission.reason_code or "ADMISSION_DENIED",
            "next_route": "review_blocked",
            "visited_nodes": _append_visited(state, "review"),
        }

    # D42: Non-terminal parked review (await_review / REVIEW_ENVELOPE_MISMATCH)
    # is not cached so a subsequent review with a corrected envelope_digest
    # under the same generation can proceed.
    return run_idempotent(
        ctx.attempt_store,
        key,
        _action,
        should_cache=lambda u: u.get("next_route") != "await_review",
    )


def _node_build(ctx: NodeContext, state: OrchestrationState) -> dict[str, Any]:
    retry_count = state.get("build_retry_count", 0)
    key = _node_key(
        state,
        "build",
        default_step_key="build",
        default_attempt_no=retry_count + 1,
    )

    def _action() -> dict[str, Any]:
        reused_ref = state.get("build_ref")
        if reused_ref is not None:
            # Validation round reusing campaign build artifacts: never rebuild.
            reused_artifacts = _extract_reused_build_artifacts(reused_ref)
            return {
                "state": "RUNNING",
                "build_artifacts": reused_artifacts,
                "next_route": "build_diagnose",
                "visited_nodes": _append_visited(state, "build"),
            }

        if ctx.sandbox is None:
            raise RuntimeError("sandbox is required to execute the build node")

        artifacts: dict[str, dict[str, Any]] = {
            ver: dict(meta)
            for ver, meta in (state.get("build_artifacts") or {}).items()
            if isinstance(meta, Mapping)
        }
        total_duration = 0.0
        for version in verdict_mod.VERSIONS:
            existing = artifacts.get(version)
            if existing is not None and existing.get("status") == "completed":
                continue
            built = ctx.sandbox.build(version)
            total_duration += built.duration_seconds
            artifacts[version] = _serialize_build_result(built)
            if built.status != "completed":
                # Fail fast on this attempt so build_diagnose decides retry vs archive.
                break

        ctx.ledger.record_charge(
            job_id=state["job_id"],
            family_id=state["family_id"],
            step_key=key.step_key,
            attempt_no=key.attempt_no,
            seconds=total_duration,
            recorded_at=ctx.clock.timestamp(),
            charge_kind="general",
        )
        return {
            "state": "RUNNING",
            "build_artifacts": artifacts,
            "next_route": "build_diagnose",
            "visited_nodes": _append_visited(state, "build"),
        }

    return run_idempotent(ctx.attempt_store, key, _action)


def _node_build_diagnose(ctx: NodeContext, state: OrchestrationState) -> dict[str, Any]:
    retry_count = state.get("build_retry_count", 0)
    key = _node_key(
        state,
        "build_diagnose",
        default_step_key="build_diagnose",
        default_attempt_no=retry_count + 1,
    )

    def _action() -> dict[str, Any]:
        max_retries = _validate_max_build_retries(state.get("max_build_retries", 1))
        job_kind = state.get("job_kind", "round")
        diagnosis = ctx.build_diagnoser.diagnose(
            job_id=state["job_id"],
            job_kind=job_kind,
            build_artifacts=state.get("build_artifacts") or {},
            retry_count=retry_count,
            max_retries=max_retries,
            reused_build_ref=state.get("build_ref"),
        )
        if diagnosis.outcome == "retry" and retry_count < max_retries:
            return {
                "build_retry_count": retry_count + 1,
                "next_route": "build",
                "visited_nodes": _append_visited(state, "build_diagnose"),
            }
        if diagnosis.outcome == "ok":
            next_node = "campaign" if job_kind == "campaign" else "verify"
            return {
                "next_route": next_node,
                "visited_nodes": _append_visited(state, "build_diagnose"),
            }
        if diagnosis.outcome == "provenance_missing":
            return {
                "state": "FAILED",
                "reason_code": diagnosis.reason_code or "BUILD_PROVENANCE_MISSING",
                "error_message": diagnosis.message,
                "next_route": "archive",
                "visited_nodes": _append_visited(state, "build_diagnose"),
            }
        return {
            "state": "FAILED",
            "reason_code": diagnosis.reason_code or "BUILD_FAILED",
            "error_message": diagnosis.message,
            "next_route": "archive",
            "visited_nodes": _append_visited(state, "build_diagnose"),
        }

    return run_idempotent(ctx.attempt_store, key, _action)


def _node_campaign(ctx: NodeContext, state: OrchestrationState) -> dict[str, Any]:
    key = _node_key(state, "campaign", default_step_key="campaign")

    def _action() -> dict[str, Any]:
        build_artifacts = state.get("build_artifacts") or {}
        result = ctx.campaign_runner.run_campaign(
            job_id=state["job_id"],
            family_id=state["family_id"],
            build_artifacts=build_artifacts,
            candidate_seeds=state.get("candidate_seeds", ()),
        )
        ctx.ledger.record_charge(
            job_id=state["job_id"],
            family_id=state["family_id"],
            step_key=key.step_key,
            attempt_no=key.attempt_no,
            seconds=result.fuzz_seconds_used,
            fuzz_seconds=result.fuzz_seconds_used,
            recorded_at=ctx.clock.timestamp(),
            charge_kind="fuzz",
        )
        return {
            "candidate_seeds": tuple(result.candidate_seeds),
            "campaign_bundle_digest": result.campaign_bundle_digest,
            "build_ref": _build_ref_from_campaign_state(state, build_artifacts),
            "state": "COMPLETED",
            "verdict": None,
            "reason_code": None,
            "next_route": "archive",
            "visited_nodes": _append_visited(state, "campaign"),
        }

    return run_idempotent(ctx.attempt_store, key, _action)


def _node_verify(ctx: NodeContext, state: OrchestrationState) -> dict[str, Any]:
    key = _node_key(state, "verify", default_step_key="verify")

    def _action() -> dict[str, Any]:
        if ctx.sandbox is None:
            raise RuntimeError("sandbox is required to execute the verify node")

        seed_bytes = state.get("seed_bytes")
        candidate_digest = state.get("seed_digest") or (
            _sha256_bytes(seed_bytes)
            if seed_bytes is not None
            else _sha256_bytes(b"default-candidate")
        )
        normal_digest = _sha256_bytes(b"default-normal")
        build_artifacts = state.get("build_artifacts") or {}
        observations: list[verdict_mod.RunObservation] = []
        total_duration = 0.0
        for version in verdict_mod.VERSIONS:
            artifact_digest = build_artifacts.get(version, {}).get("artifact_digest")
            for phase in verdict_mod.REQUIRED_PHASES:
                input_digest = (
                    normal_digest if phase == "normal" else candidate_digest
                )
                replay_result = ctx.sandbox.replay(
                    version,
                    phase,
                    expected_artifact_digest=artifact_digest,
                    expected_input_digest=input_digest,
                )
                total_duration += replay_result.duration_seconds
                observations.append(_observation_from_replay(replay_result))

        comparable_builds: Mapping[str, Mapping[str, Any]] | None = None
        if all(version in build_artifacts for version in verdict_mod.VERSIONS):
            comparable_builds = build_artifacts

        decision = verdict_mod.decide_verdict(
            ctx.verdict_policy,
            observations,
            builds=comparable_builds,
            expected_inputs={
                "vulnerable": candidate_digest,
                "fixed": candidate_digest,
            },
        )
        ctx.ledger.record_charge(
            job_id=state["job_id"],
            family_id=state["family_id"],
            step_key=key.step_key,
            attempt_no=key.attempt_no,
            seconds=total_duration,
            recorded_at=ctx.clock.timestamp(),
            charge_kind="general",
        )
        return {
            "state": decision.verdict,
            "verdict": decision.verdict,
            "reason_code": decision.reason_code,
            "next_route": "archive",
            "visited_nodes": _append_visited(state, "verify"),
        }

    return run_idempotent(ctx.attempt_store, key, _action)


def _node_archive(ctx: NodeContext, state: OrchestrationState) -> dict[str, Any]:
    key = _node_key(state, "archive", default_step_key="archive")

    def _action() -> dict[str, Any]:
        job_kind = state.get("job_kind", "round")
        final_state = state.get("state")
        if not final_state:
            final_state = (
                "COMPLETED" if job_kind in ("family", "campaign") else "INCONCLUSIVE"
            )
        final_verdict = (
            None if job_kind in ("family", "campaign") else state.get("verdict")
        )
        final_reason = state.get("reason_code")
        if job_kind in ("family", "campaign") and final_state == "COMPLETED":
            final_verdict = None
            final_reason = None

        raw_intel = state.get("intel_summary")
        intel_summary: dict[str, Any] | None = (
            copy.deepcopy(dict(raw_intel))
            if job_kind != "family"
            and isinstance(raw_intel, Mapping)
            and len(raw_intel) > 0
            else None
        )

        archive_payload = {
            "job_id": state["job_id"],
            "family_id": state["family_id"],
            "job_kind": job_kind,
            "round_no": state.get("round_no"),
            "state": final_state,
            "verdict": final_verdict,
            "reason_code": final_reason,
            "campaign_bundle_digest": state.get("campaign_bundle_digest"),
            "family_summary": state.get("family_summary"),
            "intel": intel_summary,
        }
        archive_digest = jsonutil.digest_json(archive_payload)
        archive_kwargs: dict[str, Any] = {
            "job_id": state["job_id"],
            "family_id": state["family_id"],
            "job_kind": job_kind,
            "state": final_state,
            "verdict": final_verdict,
            "reason_code": final_reason,
            "archive_digest": archive_digest,
            "recorded_at": ctx.clock.timestamp(),
        }
        if _accepts_keyword_arg(ctx.ledger.record_archive, "intel_summary"):
            archive_kwargs["intel_summary"] = intel_summary
        record_archive_fn: Callable[..., ArchiveRecord] = ctx.ledger.record_archive
        recorded = record_archive_fn(**archive_kwargs)
        if isinstance(recorded.intel_summary, Mapping):
            recorded_intel: dict[str, Any] | None = (
                copy.deepcopy(dict(recorded.intel_summary))
                if len(recorded.intel_summary) > 0
                else None
            )
        elif recorded.archive_digest == archive_digest and intel_summary is not None:
            recorded_intel = copy.deepcopy(intel_summary)
        else:
            recorded_intel = None
        return {
            "state": recorded.state,
            "verdict": recorded.verdict,
            "reason_code": recorded.reason_code,
            "intel_summary": recorded_intel,
            "terminal_node": "archive",
            "archive_digest": recorded.archive_digest,
            "next_route": "done",
            "visited_nodes": _append_visited(state, "archive"),
        }

    return run_idempotent(ctx.attempt_store, key, _action)


_V2_NODE_HANDLERS: Mapping[str, NodeHandler] = {
    "prepare": _node_prepare,
    "AGGREGATING": _node_aggregating,
    "intel": _node_intel,
    "version": _node_version,
    "route": _node_route,
    "patch": _node_patch,
    "source": _node_source,
    "hypothesis_aggregator": _node_hypothesis_aggregator,
    "review": _node_review,
    "build": _node_build,
    "build_diagnose": _node_build_diagnose,
    "campaign": _node_campaign,
    "verify": _node_verify,
    "archive": _node_archive,
}


def _bind_v2_node_map(ctx: NodeContext) -> dict[str, NodeFn]:
    """Bind the 14 module-level v2 node handlers to an immutable ``NodeContext``."""
    return {
        name: partial(_V2_NODE_HANDLERS[name], ctx)
        for name in ORCHESTRATION_NODES
    }


# Non-terminal parking routes that exit the compiled unit-level graph to END
# without introducing extra inter-node edges beyond IN_JOB_ORCHESTRATION_EDGES.
_NON_TERMINAL_PARK_ROUTES: Mapping[str, Mapping[str, Any]] = {
    "review": {"await_review": END},
}


def _default_branch_fallback(branch_map: Mapping[str, Any]) -> str:
    for route_key, target in branch_map.items():
        if target == "archive":
            return route_key
    return next(iter(branch_map))


def _compile_v2_graph(
    nodes: Mapping[str, NodeFn],
    *,
    checkpointer: Any = None,
) -> Any:
    """Compile the v0.2 14-node LangGraph ``StateGraph`` from ``IN_JOB_ORCHESTRATION_EDGES``."""

    def _route_from_state(default: str) -> Callable[[OrchestrationState], str]:
        def _router(state: OrchestrationState) -> str:
            route_value = state.get("next_route")
            if isinstance(route_value, str) and route_value:
                return route_value
            return default

        return _router

    builder: Any = StateGraph(OrchestrationState)
    for name in ORCHESTRATION_NODES:
        builder.add_node(name, nodes[name])

    builder.add_edge(START, "prepare")

    edges_by_source: dict[str, list[OrchestrationEdge]] = {}
    for edge in IN_JOB_ORCHESTRATION_EDGES:
        edges_by_source.setdefault(edge.source, []).append(edge)

    for source, outgoing in edges_by_source.items():
        park_routes = _NON_TERMINAL_PARK_ROUTES.get(source, {})
        if len(outgoing) == 1 and not park_routes:
            builder.add_edge(source, outgoing[0].target)
            continue

        targets = [edge.target for edge in outgoing]
        has_duplicate_targets = len(targets) != len(set(targets))
        branch_map: dict[str, Any] = {
            (edge.kind if has_duplicate_targets else edge.target): edge.target
            for edge in outgoing
        }
        branch_map.update(park_routes)
        fallback = _default_branch_fallback(branch_map)
        builder.add_conditional_edges(
            source,
            _route_from_state(fallback),
            branch_map,
        )

    builder.add_edge("archive", END)
    return builder.compile(checkpointer=checkpointer)


def build_v2_graph(
    dsn: str | None = None,
    checkpointer: Any = None,
    *,
    case_root: str | None = None,
    sandbox: SandboxProtocol | None = None,
    clock: ClockProtocol | None = None,
    intel_provider: IntelProvider | None = None,
    hypothesis_aggregator: HypothesisAggregator | None = None,
    review_gate: ReviewGate | None = None,
    envelope_policy: EnvelopePolicy | None = None,
    build_diagnoser: BuildDiagnoser | None = None,
    campaign_runner: CampaignRunner | None = None,
    verdict_policy: verdict_mod.VerdictPolicy | None = None,
    ledger: ChargeArchiveStore | None = None,
    attempt_store: AttemptStore | None = None,
    audit_store: AuditEventStore | None = None,
    node_map: Mapping[str, NodeFn] | None = None,
) -> Any:
    """Compile the v0.2 14-node LangGraph ``StateGraph`` (24 in-job edges).

    In v2 unit-level execution, review parking routes ``await_review -> END``
    and relies on :class:`AttemptStore` for re-entry replay on subsequent
    invocations. PostgreSQL ``PostgresSaver`` / ``run_worker`` integration will
    bridge review parking via LangGraph ``interrupt()``.
    """
    del dsn, case_root
    if node_map is not None:
        return _compile_v2_graph(node_map, checkpointer=checkpointer)
    active_clock = clock or DeterministicClock()
    active_ledger: ChargeArchiveStore = (
        ledger if ledger is not None else NodeReentryLedger()
    )
    active_attempt_store: AttemptStore = (
        attempt_store
        if attempt_store is not None
        else (
            active_ledger
            if isinstance(active_ledger, AttemptStore)
            else NodeReentryLedger()
        )
    )
    active_audit_store = _resolve_audit_store(
        audit_store, active_ledger, active_attempt_store
    )
    ctx = NodeContext(
        sandbox=sandbox,
        clock=active_clock,
        intel_provider=intel_provider or DefaultIntelProvider(),
        hypothesis_aggregator=hypothesis_aggregator or DefaultHypothesisAggregator(),
        review_gate=review_gate or DefaultReviewGate(clock=active_clock),
        envelope_policy=envelope_policy or DefaultEnvelopePolicy(clock=active_clock),
        build_diagnoser=build_diagnoser or DefaultBuildDiagnoser(),
        campaign_runner=campaign_runner or DefaultCampaignRunner(clock=active_clock),
        verdict_policy=verdict_policy or DEFAULT_VERDICT_POLICY,
        ledger=active_ledger,
        attempt_store=active_attempt_store,
        audit_store=active_audit_store,
    )
    return _compile_v2_graph(_bind_v2_node_map(ctx), checkpointer=checkpointer)


# ---------------------------------------------------------------------------
# Graph-driven OrchestrationRunner
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ChildExecutionWindow:
    """Deterministic execution window for a single family child."""

    job_id: str
    job_kind: str
    round_no: int | None
    started_at: datetime
    finished_at: datetime


@dataclass(frozen=True)
class ChildRunOutcome:
    """Outcome of running a single child job through the compiled v2 graph."""

    job_id: str
    family_id: str
    parent_job_id: str | None
    job_kind: str
    round_no: int | None
    state: str
    verdict: str | None
    reason_code: str | None
    terminal_node: str | None
    visited_nodes: tuple[str, ...]
    approval_digest: str | None = None
    admission_id: str | None = None
    admission_kind: str | None = None
    build_ref: Mapping[str, Any] | None = None
    candidate_seeds: tuple[bytes, ...] = ()
    archive_digest: str | None = None
    started_at: datetime | None = None
    finished_at: datetime | None = None
    intel_summary: Mapping[str, Any] | None = None
    audit_events: tuple[AuditEventRecord, ...] = ()


@dataclass(frozen=True)
class FamilyRunOutcome:
    """Outcome of running a guided family (campaign + serial rounds + AGGREGATING)."""

    family_id: str
    state: str
    verdict: str | None
    reason_code: str | None
    terminal_node: str | None
    visited_nodes: tuple[str, ...]
    campaign_child: ChildRunOutcome
    round_children: tuple[ChildRunOutcome, ...]
    family_transitions: tuple[dict[str, Any], ...]
    family_states_observed: tuple[str, ...]
    max_concurrent_children: int
    child_execution_windows: tuple[ChildExecutionWindow, ...]
    family_index_digest: str | None = None
    stop_reason_code: str | None = None


class OrchestrationRunner:
    """Graph-driven runner executing the compiled v0.2 LangGraph topology."""

    def __init__(
        self,
        *,
        sandbox: SandboxProtocol | None = None,
        clock: ClockProtocol | None = None,
        intel_provider: IntelProvider | None = None,
        hypothesis_aggregator: HypothesisAggregator | None = None,
        review_gate: ReviewGate | None = None,
        envelope_policy: EnvelopePolicy | None = None,
        build_diagnoser: BuildDiagnoser | None = None,
        campaign_runner: CampaignRunner | None = None,
        iteration_gate: IterationGate | None = None,
        verdict_policy: verdict_mod.VerdictPolicy | None = None,
        ledger: ChargeArchiveStore | None = None,
        attempt_store: AttemptStore | None = None,
        audit_store: AuditEventStore | None = None,
        max_build_retries: int = 1,
    ) -> None:
        self.clock: ClockProtocol = clock or DeterministicClock()
        self.sandbox = sandbox
        self.intel_provider: IntelProvider = intel_provider or DefaultIntelProvider()
        self.hypothesis_aggregator: HypothesisAggregator = (
            hypothesis_aggregator or DefaultHypothesisAggregator()
        )
        self.review_gate: ReviewGate = review_gate or DefaultReviewGate(clock=self.clock)
        self.envelope_policy: EnvelopePolicy = (
            envelope_policy or DefaultEnvelopePolicy(clock=self.clock)
        )
        self.build_diagnoser: BuildDiagnoser = (
            build_diagnoser or DefaultBuildDiagnoser()
        )
        self.campaign_runner: CampaignRunner = (
            campaign_runner or DefaultCampaignRunner(clock=self.clock)
        )
        self.iteration_gate: IterationGate = iteration_gate or DefaultIterationGate()
        self.verdict_policy: verdict_mod.VerdictPolicy = (
            verdict_policy or DEFAULT_VERDICT_POLICY
        )
        self.max_build_retries = _validate_max_build_retries(max_build_retries)
        self.ledger: ChargeArchiveStore = (
            ledger if ledger is not None else NodeReentryLedger()
        )
        self.attempt_store: AttemptStore = (
            attempt_store
            if attempt_store is not None
            else (
                self.ledger
                if isinstance(self.ledger, AttemptStore)
                else NodeReentryLedger()
            )
        )
        self.audit_store: AuditEventStore = _resolve_audit_store(
            audit_store, self.ledger, self.attempt_store
        )
        self._slot_table_lock = threading.Lock()
        self._family_locks: dict[str, threading.Lock] = {}
        self._active_children_by_family: dict[str, int] = {}
        self._max_concurrent_by_family: dict[str, int] = {}
        self._context = NodeContext(
            sandbox=self.sandbox,
            clock=self.clock,
            intel_provider=self.intel_provider,
            hypothesis_aggregator=self.hypothesis_aggregator,
            review_gate=self.review_gate,
            envelope_policy=self.envelope_policy,
            build_diagnoser=self.build_diagnoser,
            campaign_runner=self.campaign_runner,
            verdict_policy=self.verdict_policy,
            ledger=self.ledger,
            attempt_store=self.attempt_store,
            audit_store=self.audit_store,
        )
        self._node_map = _bind_v2_node_map(self._context)
        self.graph = build_v2_graph(node_map=self._node_map)

    def charge_count(self, job_id: str) -> int:
        return self.ledger.charge_count(job_id)

    def archive_count(self, job_id: str) -> int:
        return self.ledger.archive_count(job_id)

    def audit_events(self, job_id: str) -> tuple[AuditEventRecord, ...]:
        return self.audit_store.audit_events_for_job(job_id)

    def _family_slot_lock(self, family_id: str) -> threading.Lock:
        with self._slot_table_lock:
            lock = self._family_locks.get(family_id)
            if lock is None:
                lock = threading.Lock()
                self._family_locks[family_id] = lock
            return lock

    def max_concurrent_children(self, family_id: str) -> int:
        with self._slot_table_lock:
            return self._max_concurrent_by_family.get(family_id, 0)

    def execute_node(
        self,
        *,
        family_id: str,
        idempotency_key: IdempotencyKey,
        job_kind: str = "round",
        round_no: int | None = 1,
        target_kind: str = "source",
        is_first_plan: bool | None = None,
        envelope_digest: str | None = None,
        first_plan_digest: str | None = None,
        parent_approval_digest: str | None = None,
        seed_bytes: bytes | None = None,
        request: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Execute one v2 graph node with ``idempotency_key`` re-entry protection."""
        job_id, stage, step_key, attempt_no, generation = idempotency_key
        node_fn = self._node_map.get(stage)
        if node_fn is None:
            raise ValueError(f"unknown v0.2 orchestration node: {stage!r}")
        state: OrchestrationState = {
            "job_id": job_id,
            "family_id": family_id,
            "parent_job_id": None if job_kind == "family" else family_id,
            "job_kind": job_kind,
            "round_no": round_no,
            "generation": generation,
            "target_kind": target_kind,
            "request": dict(request or {}),
            "parent_approval_digest": parent_approval_digest,
            "seed_bytes": seed_bytes,
            "max_build_retries": self.max_build_retries,
            "build_retry_count": max(0, attempt_no - 1),
            "visited_nodes": [],
            "step_key_override": step_key,
            "attempt_no_override": attempt_no,
        }
        if is_first_plan is not None:
            state["is_first_plan"] = is_first_plan
        if envelope_digest is not None:
            state["envelope_digest"] = envelope_digest
        if first_plan_digest is not None:
            state["first_plan_digest"] = first_plan_digest
        return node_fn(state)

    def run_child(
        self,
        *,
        job_id: str,
        family_id: str,
        job_kind: str = "round",
        round_no: int | None = 1,
        parent_job_id: str | None = None,
        target_kind: str = "source",
        generation: int = 1,
        is_first_plan: bool | None = None,
        envelope_digest: str | None = None,
        first_plan_digest: str | None = None,
        parent_approval_digest: str | None = None,
        build_ref: Mapping[str, Any] | None = None,
        seed_bytes: bytes | None = None,
        candidate_seeds: Sequence[bytes] = (),
        request: Mapping[str, Any] | None = None,
    ) -> ChildRunOutcome:
        """Execute a single child job via the compiled 14-node LangGraph."""
        resolved_parent = (
            parent_job_id
            if parent_job_id is not None
            else (None if job_kind == "family" else family_id)
        )
        initial: OrchestrationState = {
            "job_id": job_id,
            "family_id": family_id,
            "parent_job_id": resolved_parent,
            "job_kind": job_kind,
            "round_no": round_no,
            "generation": generation,
            "target_kind": target_kind,
            "request": dict(request or {}),
            "parent_approval_digest": parent_approval_digest,
            "build_ref": copy.deepcopy(dict(build_ref)) if build_ref is not None else None,
            "seed_bytes": seed_bytes,
            "seed_digest": _sha256_bytes(seed_bytes) if seed_bytes is not None else None,
            "candidate_seeds": tuple(candidate_seeds),
            "build_retry_count": 0,
            "max_build_retries": self.max_build_retries,
            "visited_nodes": [],
        }
        if is_first_plan is not None:
            initial["is_first_plan"] = is_first_plan
        if envelope_digest is not None:
            initial["envelope_digest"] = envelope_digest
        if first_plan_digest is not None:
            initial["first_plan_digest"] = first_plan_digest

        slot_lock = self._family_slot_lock(family_id)
        with slot_lock:
            with self._slot_table_lock:
                active = self._active_children_by_family.get(family_id, 0) + 1
                self._active_children_by_family[family_id] = active
                self._max_concurrent_by_family[family_id] = max(
                    self._max_concurrent_by_family.get(family_id, 0),
                    active,
                )
            try:
                started_at = self.clock.now()
                final_state: Mapping[str, Any] = self.graph.invoke(initial)
                if self.clock.now() <= started_at:
                    self.clock.advance(0.001)
                finished_at = self.clock.now()
            finally:
                with self._slot_table_lock:
                    self._active_children_by_family[family_id] -= 1

        raw_intel_summary = final_state.get("intel_summary")
        outcome_intel_summary = (
            copy.deepcopy(dict(raw_intel_summary))
            if isinstance(raw_intel_summary, Mapping) and len(raw_intel_summary) > 0
            else None
        )
        return ChildRunOutcome(
            job_id=job_id,
            family_id=family_id,
            parent_job_id=resolved_parent,
            job_kind=job_kind,
            round_no=round_no,
            state=str(final_state.get("state", "FAILED")),
            verdict=final_state.get("verdict"),
            reason_code=final_state.get("reason_code"),
            terminal_node=final_state.get("terminal_node"),
            visited_nodes=tuple(final_state.get("visited_nodes", ())),
            approval_digest=final_state.get("approval_digest"),
            admission_id=final_state.get("admission_id"),
            admission_kind=final_state.get("admission_kind"),
            build_ref=final_state.get("build_ref"),
            candidate_seeds=tuple(final_state.get("candidate_seeds", ())),
            archive_digest=final_state.get("archive_digest"),
            started_at=started_at,
            finished_at=finished_at,
            intel_summary=outcome_intel_summary,
            audit_events=self.audit_events(job_id),
        )

    def run_family_guided(
        self,
        *,
        family_id: str,
        candidate_seeds: Sequence[bytes] = (),
        max_rounds: int = 2,
        max_total_seconds: float | None = None,
        max_fuzz_seconds: float | None = None,
        target_kind: str = "source",
        envelope_digest: str | None = None,
        request: Mapping[str, Any] | None = None,
    ) -> FamilyRunOutcome:
        """Execute a guided family: campaign child + serial validation rounds + AGGREGATING.

        Enforces the single execution slot invariant (D29): at most one child
        executes at any point in time, and every child finishes ``archive``
        before the next child is spawned via family-level transition #23 or #26.
        """
        if type(max_rounds) is not int or max_rounds < 0:
            raise ValueError("max_rounds must be a non-negative integer")
        validated_max_total = _validate_non_negative_budget(
            "max_total_seconds", max_total_seconds
        )
        validated_max_fuzz = _validate_non_negative_budget(
            "max_fuzz_seconds", max_fuzz_seconds
        )

        family_states: list[str] = ["AGGREGATING"]
        transitions: list[dict[str, Any]] = []
        windows: list[ChildExecutionWindow] = []
        round_children: list[ChildRunOutcome] = []
        active_children = 0
        max_concurrent = 0
        resolved_envelope = envelope_digest or jsonutil.digest_json(
            {"family_id": family_id, "mode": "guided"}
        )

        # Step 1: Run campaign child (human-approved first plan; archives to COMPLETED).
        campaign_job_id = str(uuid4())
        active_children += 1
        max_concurrent = max(max_concurrent, active_children)
        try:
            campaign_child = self.run_child(
                job_id=campaign_job_id,
                family_id=family_id,
                parent_job_id=family_id,
                job_kind="campaign",
                round_no=None,
                target_kind=target_kind,
                is_first_plan=True,
                envelope_digest=resolved_envelope,
                candidate_seeds=candidate_seeds,
                request=request,
            )
        finally:
            active_children -= 1
        assert campaign_child.started_at is not None
        assert campaign_child.finished_at is not None
        windows.append(
            ChildExecutionWindow(
                job_id=campaign_child.job_id,
                job_kind="campaign",
                round_no=None,
                started_at=campaign_child.started_at,
                finished_at=campaign_child.finished_at,
            )
        )

        def _remaining_total() -> float | None:
            if validated_max_total is None:
                return None
            return max(
                0.0, validated_max_total - self.ledger.total_charged_seconds(family_id)
            )

        def _remaining_fuzz() -> float | None:
            if validated_max_fuzz is None:
                return None
            return max(
                0.0, validated_max_fuzz - self.ledger.total_fuzz_seconds(family_id)
            )

        stop_reason_code: str | None = None

        # Step 2: Edge #23 (campaign -> hypothesis_aggregator) and edge #26
        # (verify -> hypothesis_aggregator) spawn serial round children after
        # each predecessor has archived itself.
        seeds = campaign_child.candidate_seeds
        if (
            campaign_child.state == "COMPLETED"
            and campaign_child.terminal_node == "archive"
        ):
            if not seeds:
                stop_reason_code = "NO_REMAINING_SEEDS"
            elif (
                max_rounds == 0
                or not _has_budget_capacity(_remaining_total())
            ):
                stop_reason_code = "BUDGET_EXHAUSTED"
            else:
                round_no = 1
                transitions.append(
                    {
                        "edge_no": 23,
                        "source": "campaign",
                        "target": "hypothesis_aggregator",
                        "from_job_id": campaign_child.job_id,
                        "next_round_no": round_no,
                    }
                )
                while True:
                    seed_bytes = seeds[round_no - 1]
                    round_job_id = str(uuid4())
                    active_children += 1
                    max_concurrent = max(max_concurrent, active_children)
                    try:
                        round_outcome = self.run_child(
                            job_id=round_job_id,
                            family_id=family_id,
                            parent_job_id=family_id,
                            job_kind="round",
                            round_no=round_no,
                            target_kind=target_kind,
                            is_first_plan=False,
                            envelope_digest=resolved_envelope,
                            parent_approval_digest=campaign_child.approval_digest,
                            build_ref=campaign_child.build_ref,
                            seed_bytes=seed_bytes,
                            request=request,
                        )
                    finally:
                        active_children -= 1
                    assert round_outcome.started_at is not None
                    assert round_outcome.finished_at is not None
                    windows.append(
                        ChildExecutionWindow(
                            job_id=round_outcome.job_id,
                            job_kind="round",
                            round_no=round_no,
                            started_at=round_outcome.started_at,
                            finished_at=round_outcome.finished_at,
                        )
                    )
                    round_children.append(round_outcome)

                    if (
                        round_outcome.state == "AWAITING_REVIEW"
                        or round_outcome.terminal_node is None
                    ):
                        break

                    remaining_seeds = max(0, len(seeds) - round_no)
                    decision = self.iteration_gate.check_capacity(
                        family_id=family_id,
                        completed_round_no=round_no,
                        max_rounds=max_rounds,
                        last_verdict=round_outcome.verdict,
                        remaining_budget_seconds=_remaining_total(),
                        remaining_fuzz_seconds=_remaining_fuzz(),
                        remaining_seeds=remaining_seeds,
                    )
                    if not decision.should_continue:
                        stop_reason_code = decision.reason_code
                        if stop_reason_code is None and round_outcome.state in (
                            "BLOCKED",
                            "FAILED",
                        ):
                            stop_reason_code = round_outcome.reason_code
                        break
                    if remaining_seeds <= 0:
                        stop_reason_code = "NO_REMAINING_SEEDS"
                        break

                    round_no += 1
                    transitions.append(
                        {
                            "edge_no": 26,
                            "source": "verify",
                            "target": "hypothesis_aggregator",
                            "from_job_id": round_outcome.job_id,
                            "next_round_no": round_no,
                        }
                    )

        # Parked / non-terminal child keeps the family in AGGREGATING without
        # invoking prepare -> AGGREGATING -> archive or converging to COMPLETED.
        parked_child: ChildRunOutcome | None = None
        if (
            campaign_child.state == "AWAITING_REVIEW"
            or campaign_child.terminal_node is None
        ):
            parked_child = campaign_child
        else:
            for child in round_children:
                if child.state == "AWAITING_REVIEW" or child.terminal_node is None:
                    parked_child = child
                    break

        if parked_child is not None:
            max_concurrent = max(max_concurrent, self.max_concurrent_children(family_id))
            return FamilyRunOutcome(
                family_id=family_id,
                state="AGGREGATING",
                verdict=None,
                reason_code=None,
                terminal_node=None,
                visited_nodes=(),
                campaign_child=campaign_child,
                round_children=tuple(round_children),
                family_transitions=tuple(transitions),
                family_states_observed=("AGGREGATING",),
                max_concurrent_children=max_concurrent,
                child_execution_windows=tuple(windows),
                family_index_digest=None,
                stop_reason_code=parked_child.reason_code,
            )

        # Step 3: Run the family job itself through prepare -> AGGREGATING -> archive
        # under the family slot lock so no concurrent child can interleave.
        family_final_state = "COMPLETED"
        family_final_reason: str | None = None
        if campaign_child.state == "BLOCKED":
            family_final_state = "BLOCKED"
            family_final_reason = campaign_child.reason_code
            stop_reason_code = campaign_child.reason_code
        elif campaign_child.state == "FAILED":
            # v2 families have no FAILED state (AGGREGATING/COMPLETED/BLOCKED/CANCELLED);
            # converge to COMPLETED while recording campaign_state & stop_reason_code.
            family_final_state = "COMPLETED"
            family_final_reason = None
            stop_reason_code = campaign_child.reason_code
        elif campaign_child.state != "COMPLETED":
            stop_reason_code = campaign_child.reason_code

        family_request = {
            key: value
            for key, value in (request or {}).items()
            if key != "prepare_blocked_reason"
        }
        with self._family_slot_lock(family_id):
            family_graph_state: Mapping[str, Any] = self.graph.invoke(
                {
                    "job_id": family_id,
                    "family_id": family_id,
                    "parent_job_id": None,
                    "job_kind": "family",
                    "round_no": None,
                    "generation": 1,
                    "request": family_request,
                    "family_summary": {
                        "kind": "family_index",
                        "family_id": family_id,
                        "campaign_job_id": campaign_child.job_id,
                        "campaign_state": campaign_child.state,
                        "rounds": [
                            {
                                "job_id": child.job_id,
                                "round_no": child.round_no,
                                "state": child.state,
                                "verdict": child.verdict,
                                "reason_code": child.reason_code,
                            }
                            for child in round_children
                        ],
                        "family_approval_digest": campaign_child.approval_digest,
                        "final_state": family_final_state,
                        "final_reason_code": family_final_reason,
                        "stop_reason_code": stop_reason_code,
                    },
                    "visited_nodes": [],
                }
            )
        terminal_family_state = str(family_graph_state.get("state", family_final_state))
        family_states.append(terminal_family_state)

        max_concurrent = max(max_concurrent, self.max_concurrent_children(family_id))
        return FamilyRunOutcome(
            family_id=family_id,
            state=terminal_family_state,
            verdict=None,
            reason_code=family_graph_state.get("reason_code"),
            terminal_node=family_graph_state.get("terminal_node"),
            visited_nodes=tuple(family_graph_state.get("visited_nodes", ())),
            campaign_child=campaign_child,
            round_children=tuple(round_children),
            family_transitions=tuple(transitions),
            family_states_observed=tuple(family_states),
            max_concurrent_children=max_concurrent,
            child_execution_windows=tuple(windows),
            family_index_digest=family_graph_state.get("archive_digest"),
            stop_reason_code=stop_reason_code,
        )


__all__ = [
    "AdmissionDecision",
    "ArchiveRecord",
    "AttemptStore",
    "AuditEventRecord",
    "AuditEventStore",
    "BudgetChargeRecord",
    "BuildDiagnoser",
    "BuildDiagnosis",
    "CampaignResult",
    "CampaignRunner",
    "ChargeArchiveStore",
    "ChildExecutionWindow",
    "ChildRunOutcome",
    "ClockProtocol",
    "DEFAULT_VERDICT_POLICY",
    "DefaultAdmissionDecision",
    "DefaultBuildDiagnoser",
    "DefaultCampaignRunner",
    "DefaultEnvelopePolicy",
    "DefaultHypothesisAggregator",
    "DefaultIntelProvider",
    "DefaultIterationGate",
    "DefaultReviewDecision",
    "DefaultReviewGate",
    "DeterministicClock",
    "EnvelopePolicy",
    "FAMILY_ORCHESTRATION_EDGES",
    "FamilyRunOutcome",
    "HypothesisAggregationResult",
    "HypothesisAggregator",
    "IN_JOB_ORCHESTRATION_EDGES",
    "IdempotencyKey",
    "IntelProvider",
    "IntelResult",
    "IterationDecision",
    "IterationGate",
    "NodeContext",
    "NodeReentryLedger",
    "ORCHESTRATION_EDGES",
    "ORCHESTRATION_NODES",
    "OrchestrationEdge",
    "OrchestrationRunner",
    "OrchestrationState",
    "ReviewDecision",
    "ReviewGate",
    "SandboxProtocol",
    "StepKey",
    "build_v2_graph",
    "run_idempotent",
]

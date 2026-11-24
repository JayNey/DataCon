"""DataCon v0.2 target orchestration graph, protocols, and deterministic runner.

Implements the 14-node, 26-edge orchestration topology defined in
``docs/spec/v0.2/README.md`` §5 and invariants 16-21 in §7, while leaving the
v0.1 two-node Supervisor graph in ``datacon.workflow`` untouched.
"""

from __future__ import annotations

import copy
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
import hashlib
import math
from typing import Any, Callable, Literal, Mapping, Protocol, Sequence, TypedDict, runtime_checkable
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

IdempotencyKey = tuple[str, str, str, int, int]


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

    def now(self) -> datetime:
        return self._now

    def advance(self, seconds: float | int) -> datetime:
        if isinstance(seconds, bool) or not isinstance(seconds, (int, float)):
            raise ValueError("seconds must be a finite non-negative number")
        if not math.isfinite(seconds) or seconds < 0:
            raise ValueError("seconds must be a finite non-negative number")
        self._now = self._now + timedelta(seconds=float(seconds))
        return self._now

    def timestamp(self, *, microseconds: bool = False) -> str:
        if microseconds:
            return self._now.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        return self._now.replace(microsecond=0).isoformat().replace("+00:00", "Z")


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
            for version in verdict_mod.VERSIONS:
                entry = build_artifacts.get(version)
                if not isinstance(entry, Mapping) or not entry.get("artifact_digest"):
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
        remaining_seeds: int = 0,
    ) -> IterationDecision: ...


class DefaultIterationGate:
    """Checks verdict conclusiveness, ``max_rounds``, and remaining budget capacity."""

    def check_capacity(
        self,
        *,
        family_id: str,
        completed_round_no: int,
        max_rounds: int,
        last_verdict: str | None,
        remaining_budget_seconds: float | None = None,
        remaining_fuzz_seconds: float | None = None,
        remaining_seeds: int = 0,
    ) -> IterationDecision:
        del family_id, remaining_fuzz_seconds, remaining_seeds
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
        if remaining_budget_seconds is not None and remaining_budget_seconds <= 0:
            return IterationDecision(
                should_continue=False,
                reason_code="BUDGET_EXHAUSTED",
                remaining_rounds=remaining_rounds,
                remaining_budget_seconds=0.0,
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


class NodeReentryLedger:
    """In-memory persistence ledger enforcing node re-entry no-op semantics.

    Node outcomes are keyed by ``(job_id, stage, step_key, attempt_no, generation)``
    per ``test-plan-delta.md`` §3. Budget charges are additionally deduplicated on
    ``(job_id, step_key, attempt_no)`` per ``README.md`` §7 invariant 7.
    """

    def __init__(self) -> None:
        self._node_results: dict[IdempotencyKey, dict[str, Any]] = {}
        self._charge_keys: set[tuple[str, str, int]] = set()
        self._charges_by_job: dict[str, list[BudgetChargeRecord]] = {}
        self._charges_by_family: dict[str, list[BudgetChargeRecord]] = {}
        self._archives_by_job: dict[str, list[ArchiveRecord]] = {}

    def get(self, key: IdempotencyKey) -> dict[str, Any] | None:
        cached = self._node_results.get(key)
        if cached is None:
            return None
        return copy.deepcopy(cached)

    def record(self, key: IdempotencyKey, result: Mapping[str, Any]) -> dict[str, Any]:
        snapshot = copy.deepcopy(dict(result))
        self._node_results[key] = snapshot
        return copy.deepcopy(snapshot)

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
        return len(self._charges_by_job.get(job_id, ()))

    def charges_for_job(self, job_id: str) -> tuple[BudgetChargeRecord, ...]:
        return tuple(self._charges_by_job.get(job_id, ()))

    def total_charged_seconds(self, family_id: str) -> float:
        return sum(item.seconds for item in self._charges_by_family.get(family_id, ()))

    def total_fuzz_seconds(self, family_id: str) -> float:
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
    ) -> ArchiveRecord:
        entry = ArchiveRecord(
            job_id=job_id,
            family_id=family_id,
            job_kind=job_kind,
            state=state,
            verdict=verdict,
            reason_code=reason_code,
            archive_digest=archive_digest,
            recorded_at=recorded_at,
        )
        self._archives_by_job.setdefault(job_id, []).append(entry)
        return entry

    def archive_count(self, job_id: str) -> int:
        return len(self._archives_by_job.get(job_id, ()))

    def archives_for_job(self, job_id: str) -> tuple[ArchiveRecord, ...]:
        return tuple(self._archives_by_job.get(job_id, ()))


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
    intel_summary: dict[str, Any]
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


NodeFn = Callable[[OrchestrationState], dict[str, Any]]


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
) -> IdempotencyKey:
    job_id = state["job_id"]
    step_key = state.get("step_key_override") or default_step_key
    attempt_no = state.get("attempt_no_override")
    if attempt_no is None:
        attempt_no = default_attempt_no
    generation = state.get("generation", 1)
    return (job_id, stage, step_key, attempt_no, generation)


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


def _build_v2_node_map(
    *,
    sandbox: SandboxProtocol | None,
    clock: ClockProtocol,
    intel_provider: IntelProvider,
    hypothesis_aggregator: HypothesisAggregator,
    review_gate: ReviewGate,
    envelope_policy: EnvelopePolicy,
    build_diagnoser: BuildDiagnoser,
    campaign_runner: CampaignRunner,
    verdict_policy: verdict_mod.VerdictPolicy,
    ledger: NodeReentryLedger,
) -> dict[str, NodeFn]:
    """Construct the 14 LangGraph v2 node callables backed by ``ledger``."""

    def prepare(state: OrchestrationState) -> dict[str, Any]:
        key = _node_key(state, "prepare", default_step_key="prepare")
        cached = ledger.get(key)
        if cached is not None:
            return cached

        request = state.get("request") or {}
        job_kind = state.get("job_kind", "round")
        blocked_reason = request.get("prepare_blocked_reason")
        if isinstance(blocked_reason, str) and blocked_reason:
            update: dict[str, Any] = {
                "state": "BLOCKED",
                "reason_code": blocked_reason,
                "next_route": "archive",
                "visited_nodes": _append_visited(state, "prepare"),
            }
        elif job_kind not in ("family", "campaign", "round"):
            update = {
                "state": "BLOCKED",
                "reason_code": "INVALID_REQUEST",
                "next_route": "archive",
                "visited_nodes": _append_visited(state, "prepare"),
            }
        elif job_kind == "family":
            update = {
                "state": "AGGREGATING",
                "next_route": "AGGREGATING",
                "visited_nodes": _append_visited(state, "prepare"),
            }
        else:
            update = {
                "state": "PREPARING",
                "next_route": "intel",
                "visited_nodes": _append_visited(state, "prepare"),
            }
        return ledger.record(key, update)

    def aggregating(state: OrchestrationState) -> dict[str, Any]:
        key = _node_key(state, "AGGREGATING", default_step_key="aggregating")
        cached = ledger.get(key)
        if cached is not None:
            return cached

        summary = dict(state.get("family_summary") or {})
        summary.setdefault("kind", "family_index")
        summary.setdefault("family_id", state["family_id"])
        final_state = summary.get("final_state", "COMPLETED")
        final_reason = summary.get("final_reason_code")
        update: dict[str, Any] = {
            "state": final_state,
            "verdict": None,
            "reason_code": final_reason,
            "family_summary": summary,
            "next_route": "archive",
            "visited_nodes": _append_visited(state, "AGGREGATING"),
        }
        return ledger.record(key, update)

    def intel(state: OrchestrationState) -> dict[str, Any]:
        key = _node_key(state, "intel", default_step_key="intel")
        cached = ledger.get(key)
        if cached is not None:
            return cached

        request = state.get("request") or {}
        try:
            result = intel_provider.resolve_intel(
                job_id=state["job_id"],
                family_id=state["family_id"],
                request=request,
            )
        except Exception as error:  # noqa: BLE001 - normalize intel block reasons
            reason = getattr(error, "reason_code", None)
            if not isinstance(reason, str) or not reason:
                raise
            result = IntelResult(
                status="blocked",
                snapshot_digest=None,
                reason_code=reason,
                message=str(error),
            )

        if result.status != "ready":
            update: dict[str, Any] = {
                "state": "BLOCKED",
                "reason_code": result.reason_code or "MATERIAL_MISSING",
                "error_message": result.message,
                "intel_summary": dict(result.summary),
                "next_route": "archive",
                "visited_nodes": _append_visited(state, "intel"),
            }
        else:
            summary = dict(result.summary)
            if result.snapshot_digest is not None:
                summary["snapshot_digest"] = result.snapshot_digest
            update = {
                "intel_summary": summary,
                "next_route": "version",
                "visited_nodes": _append_visited(state, "intel"),
            }
        return ledger.record(key, update)

    def version(state: OrchestrationState) -> dict[str, Any]:
        key = _node_key(state, "version", default_step_key="version")
        cached = ledger.get(key)
        if cached is not None:
            return cached

        request = state.get("request") or {}
        blocked_reason = request.get("version_blocked_reason")
        if isinstance(blocked_reason, str) and blocked_reason:
            update: dict[str, Any] = {
                "state": "BLOCKED",
                "reason_code": blocked_reason,
                "next_route": "archive",
                "visited_nodes": _append_visited(state, "version"),
            }
        else:
            vulnerable_commit = str(
                request.get("vulnerable_commit", DEFAULT_VULNERABLE_COMMIT)
            )
            fixed_commit = str(request.get("fixed_commit", DEFAULT_FIXED_COMMIT))
            update = {
                "version_pair": {
                    "vulnerable": vulnerable_commit,
                    "fixed": fixed_commit,
                },
                "next_route": "route",
                "visited_nodes": _append_visited(state, "version"),
            }
        return ledger.record(key, update)

    def route(state: OrchestrationState) -> dict[str, Any]:
        key = _node_key(state, "route", default_step_key="route")
        cached = ledger.get(key)
        if cached is not None:
            return cached

        target_kind = state.get("target_kind", "source")
        if target_kind == "patch":
            update: dict[str, Any] = {
                "next_route": "patch",
                "visited_nodes": _append_visited(state, "route"),
            }
        elif target_kind == "source":
            update = {
                "next_route": "source",
                "visited_nodes": _append_visited(state, "route"),
            }
        else:
            # Edge #11: reverse placeholder / binary target archives immediately.
            update = {
                "state": "BLOCKED",
                "reason_code": "UNSUPPORTED_TARGET",
                "next_route": "archive",
                "visited_nodes": _append_visited(state, "route"),
            }
        return ledger.record(key, update)

    def patch(state: OrchestrationState) -> dict[str, Any]:
        key = _node_key(state, "patch", default_step_key="patch")
        cached = ledger.get(key)
        if cached is not None:
            return cached

        update = {
            "route_facts": {
                "target_kind": "patch",
                "evidence_refs": ["patch:diff#L1"],
            },
            "next_route": "hypothesis_aggregator",
            "visited_nodes": _append_visited(state, "patch"),
        }
        return ledger.record(key, update)

    def source(state: OrchestrationState) -> dict[str, Any]:
        key = _node_key(state, "source", default_step_key="source")
        cached = ledger.get(key)
        if cached is not None:
            return cached

        update = {
            "route_facts": {
                "target_kind": "source",
                "evidence_refs": ["source:target.c#L1"],
            },
            "next_route": "hypothesis_aggregator",
            "visited_nodes": _append_visited(state, "source"),
        }
        return ledger.record(key, update)

    def hypothesis_aggregator_node(state: OrchestrationState) -> dict[str, Any]:
        key = _node_key(
            state,
            "hypothesis_aggregator",
            default_step_key="hypothesis_aggregator",
        )
        cached = ledger.get(key)
        if cached is not None:
            return cached

        aggregated = hypothesis_aggregator.aggregate(
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
        first_plan_digest = state.get("first_plan_digest") or jsonutil.digest_json(
            {
                "family_id": state["family_id"],
                "job_kind": state.get("job_kind", "round"),
                "envelope_digest": envelope_digest,
                "experiment_digest": aggregated.experiment_digest,
            }
        )
        update = {
            "experiment_spec": dict(aggregated.experiment_spec),
            "experiment_digest": aggregated.experiment_digest,
            "envelope_digest": envelope_digest,
            "first_plan_digest": first_plan_digest,
            "next_route": "review",
            "visited_nodes": _append_visited(state, "hypothesis_aggregator"),
        }
        return ledger.record(key, update)

    def review(state: OrchestrationState) -> dict[str, Any]:
        key = _node_key(state, "review", default_step_key="review")
        cached = ledger.get(key)
        if cached is not None:
            return cached

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
            decision = review_gate.evaluate_first_plan(
                family_id=family_id,
                first_plan_digest=first_plan_digest,
                envelope_digest=envelope_digest,
            )
            if decision.edge == "build":
                update: dict[str, Any] = {
                    "state": "READY",
                    "approval_digest": decision.approval_digest,
                    "admission_kind": "human",
                    "reason_code": None,
                    "next_route": "human_approve",
                    "visited_nodes": _append_visited(state, "review"),
                }
            elif decision.edge == "await_review":
                # D42: REVIEW_ENVELOPE_MISMATCH stays non-terminal.
                update = {
                    "state": "AWAITING_REVIEW",
                    "reason_code": decision.reason_code,
                    "terminal_node": None,
                    "next_route": "await_review",
                    "visited_nodes": _append_visited(state, "review"),
                }
            else:
                update = {
                    "state": "BLOCKED",
                    "reason_code": decision.reason_code or "REVIEW_REJECTED",
                    "next_route": "review_blocked",
                    "visited_nodes": _append_visited(state, "review"),
                }
        else:
            seed_bytes = state.get("seed_bytes")
            seed_digest = (
                state.get("seed_digest")
                or (_sha256_bytes(seed_bytes) if seed_bytes is not None else _sha256_bytes(b""))
            )
            admission = envelope_policy.admit_round(
                family_id=family_id,
                job_id=job_id,
                round_no=round_no or 1,
                envelope_digest=envelope_digest,
                parent_approval_digest=parent_approval_digest,
                seed_digest=seed_digest,
            )
            if admission.edge == "build" and admission.admitted:
                update = {
                    "state": "READY",
                    "admission_id": admission.admission_id,
                    "admission_kind": "policy",
                    "reason_code": None,
                    "next_route": "policy_admit",
                    "visited_nodes": _append_visited(state, "review"),
                }
            else:
                update = {
                    "state": "BLOCKED",
                    "reason_code": admission.reason_code or "ADMISSION_DENIED",
                    "next_route": "review_blocked",
                    "visited_nodes": _append_visited(state, "review"),
                }
        return ledger.record(key, update)

    def build(state: OrchestrationState) -> dict[str, Any]:
        retry_count = state.get("build_retry_count", 0)
        attempt_no = state.get("attempt_no_override")
        if attempt_no is None:
            attempt_no = retry_count + 1
        key = _node_key(
            state,
            "build",
            default_step_key="build",
            default_attempt_no=attempt_no,
        )
        cached = ledger.get(key)
        if cached is not None:
            return cached

        reused_ref = state.get("build_ref")
        if reused_ref is not None:
            # Validation round reusing campaign build artifacts: never rebuild.
            reused_artifacts = {
                version: dict(reused_ref[version])
                for version in verdict_mod.VERSIONS
                if isinstance(reused_ref.get(version), Mapping)
            }
            update: dict[str, Any] = {
                "state": "RUNNING",
                "build_artifacts": reused_artifacts,
                "next_route": "build_diagnose",
                "visited_nodes": _append_visited(state, "build"),
            }
            return ledger.record(key, update)

        if sandbox is None:
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
            built = sandbox.build(version)
            total_duration += built.duration_seconds
            artifacts[version] = _serialize_build_result(built)
            if built.status != "completed":
                # Fail fast on this attempt so build_diagnose decides retry vs archive.
                break

        ledger.record_charge(
            job_id=state["job_id"],
            family_id=state["family_id"],
            step_key=key[2],
            attempt_no=key[3],
            seconds=total_duration,
            recorded_at=clock.timestamp(),
            charge_kind="general",
        )
        update = {
            "state": "RUNNING",
            "build_artifacts": artifacts,
            "next_route": "build_diagnose",
            "visited_nodes": _append_visited(state, "build"),
        }
        return ledger.record(key, update)

    def build_diagnose(state: OrchestrationState) -> dict[str, Any]:
        retry_count = state.get("build_retry_count", 0)
        attempt_no = state.get("attempt_no_override")
        if attempt_no is None:
            attempt_no = retry_count + 1
        key = _node_key(
            state,
            "build_diagnose",
            default_step_key="build_diagnose",
            default_attempt_no=attempt_no,
        )
        cached = ledger.get(key)
        if cached is not None:
            return cached

        max_retries = state.get("max_build_retries", 1)
        job_kind = state.get("job_kind", "round")
        diagnosis = build_diagnoser.diagnose(
            job_id=state["job_id"],
            job_kind=job_kind,
            build_artifacts=state.get("build_artifacts") or {},
            retry_count=retry_count,
            max_retries=max_retries,
            reused_build_ref=state.get("build_ref"),
        )
        if diagnosis.outcome == "retry" and retry_count < max_retries:
            update: dict[str, Any] = {
                "build_retry_count": retry_count + 1,
                "next_route": "build",
                "visited_nodes": _append_visited(state, "build_diagnose"),
            }
        elif diagnosis.outcome == "ok":
            next_node = "campaign" if job_kind == "campaign" else "verify"
            update = {
                "next_route": next_node,
                "visited_nodes": _append_visited(state, "build_diagnose"),
            }
        elif diagnosis.outcome == "provenance_missing":
            update = {
                "state": "FAILED",
                "reason_code": diagnosis.reason_code or "BUILD_PROVENANCE_MISSING",
                "error_message": diagnosis.message,
                "next_route": "archive",
                "visited_nodes": _append_visited(state, "build_diagnose"),
            }
        else:
            update = {
                "state": "FAILED",
                "reason_code": diagnosis.reason_code or "BUILD_FAILED",
                "error_message": diagnosis.message,
                "next_route": "archive",
                "visited_nodes": _append_visited(state, "build_diagnose"),
            }
        return ledger.record(key, update)

    def campaign(state: OrchestrationState) -> dict[str, Any]:
        key = _node_key(state, "campaign", default_step_key="campaign")
        cached = ledger.get(key)
        if cached is not None:
            return cached

        build_artifacts = state.get("build_artifacts") or {}
        result = campaign_runner.run_campaign(
            job_id=state["job_id"],
            family_id=state["family_id"],
            build_artifacts=build_artifacts,
            candidate_seeds=state.get("candidate_seeds", ()),
        )
        ledger.record_charge(
            job_id=state["job_id"],
            family_id=state["family_id"],
            step_key=key[2],
            attempt_no=key[3],
            seconds=result.fuzz_seconds_used,
            fuzz_seconds=result.fuzz_seconds_used,
            recorded_at=clock.timestamp(),
            charge_kind="fuzz",
        )
        update = {
            "candidate_seeds": tuple(result.candidate_seeds),
            "campaign_bundle_digest": result.campaign_bundle_digest,
            "build_ref": copy.deepcopy(build_artifacts),
            "state": "COMPLETED",
            "verdict": None,
            "reason_code": None,
            "next_route": "archive",
            "visited_nodes": _append_visited(state, "campaign"),
        }
        return ledger.record(key, update)

    def verify(state: OrchestrationState) -> dict[str, Any]:
        key = _node_key(state, "verify", default_step_key="verify")
        cached = ledger.get(key)
        if cached is not None:
            return cached

        if sandbox is None:
            raise RuntimeError("sandbox is required to execute the verify node")

        seed_bytes = state.get("seed_bytes")
        candidate_digest = (
            state.get("seed_digest")
            or (
                _sha256_bytes(seed_bytes)
                if seed_bytes is not None
                else _sha256_bytes(b"default-candidate")
            )
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
                replay_result = sandbox.replay(
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
            verdict_policy,
            observations,
            builds=comparable_builds,
            expected_inputs={
                "vulnerable": candidate_digest,
                "fixed": candidate_digest,
            },
        )
        ledger.record_charge(
            job_id=state["job_id"],
            family_id=state["family_id"],
            step_key=key[2],
            attempt_no=key[3],
            seconds=total_duration,
            recorded_at=clock.timestamp(),
            charge_kind="general",
        )
        update = {
            "state": decision.verdict,
            "verdict": decision.verdict,
            "reason_code": decision.reason_code,
            "next_route": "archive",
            "visited_nodes": _append_visited(state, "verify"),
        }
        return ledger.record(key, update)

    def archive(state: OrchestrationState) -> dict[str, Any]:
        key = _node_key(state, "archive", default_step_key="archive")
        cached = ledger.get(key)
        if cached is not None:
            return cached

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
        }
        archive_digest = jsonutil.digest_json(archive_payload)
        ledger.record_archive(
            job_id=state["job_id"],
            family_id=state["family_id"],
            job_kind=job_kind,
            state=final_state,
            verdict=final_verdict,
            reason_code=final_reason,
            archive_digest=archive_digest,
            recorded_at=clock.timestamp(),
        )
        update = {
            "state": final_state,
            "verdict": final_verdict,
            "reason_code": final_reason,
            "terminal_node": "archive",
            "archive_digest": archive_digest,
            "next_route": "done",
            "visited_nodes": _append_visited(state, "archive"),
        }
        return ledger.record(key, update)

    return {
        "prepare": prepare,
        "AGGREGATING": aggregating,
        "intel": intel,
        "version": version,
        "route": route,
        "patch": patch,
        "source": source,
        "hypothesis_aggregator": hypothesis_aggregator_node,
        "review": review,
        "build": build,
        "build_diagnose": build_diagnose,
        "campaign": campaign,
        "verify": verify,
        "archive": archive,
    }


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
    ledger: NodeReentryLedger | None = None,
) -> Any:
    """Compile the v0.2 14-node LangGraph ``StateGraph`` (24 in-job edges)."""
    del dsn, case_root
    active_clock = clock or DeterministicClock()
    active_ledger = ledger or NodeReentryLedger()
    nodes = _build_v2_node_map(
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
    )

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
    builder.add_conditional_edges(
        "prepare",
        _route_from_state("archive"),
        {
            "intel": "intel",
            "AGGREGATING": "AGGREGATING",
            "archive": "archive",
        },
    )
    builder.add_edge("AGGREGATING", "archive")
    builder.add_conditional_edges(
        "intel",
        _route_from_state("archive"),
        {
            "version": "version",
            "archive": "archive",
        },
    )
    builder.add_conditional_edges(
        "version",
        _route_from_state("archive"),
        {
            "route": "route",
            "archive": "archive",
        },
    )
    builder.add_conditional_edges(
        "route",
        _route_from_state("archive"),
        {
            "patch": "patch",
            "source": "source",
            "archive": "archive",
        },
    )
    builder.add_edge("patch", "hypothesis_aggregator")
    builder.add_edge("source", "hypothesis_aggregator")
    builder.add_edge("hypothesis_aggregator", "review")
    builder.add_conditional_edges(
        "review",
        _route_from_state("review_blocked"),
        {
            "human_approve": "build",
            "policy_admit": "build",
            "review_blocked": "archive",
            "await_review": END,
        },
    )
    builder.add_edge("build", "build_diagnose")
    builder.add_conditional_edges(
        "build_diagnose",
        _route_from_state("archive"),
        {
            "build": "build",
            "campaign": "campaign",
            "verify": "verify",
            "archive": "archive",
        },
    )
    builder.add_edge("campaign", "archive")
    builder.add_edge("verify", "archive")
    builder.add_edge("archive", END)
    return builder.compile(checkpointer=checkpointer)


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
        self.max_build_retries = max_build_retries
        self.ledger = NodeReentryLedger()
        self._node_map = _build_v2_node_map(
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
        )
        self.graph = build_v2_graph(
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
        )

    def charge_count(self, job_id: str) -> int:
        return self.ledger.charge_count(job_id)

    def archive_count(self, job_id: str) -> int:
        return self.ledger.archive_count(job_id)

    def execute_node(
        self,
        *,
        family_id: str,
        idempotency_key: IdempotencyKey,
        job_kind: str = "round",
        round_no: int | None = 1,
        target_kind: str = "source",
        is_first_plan: bool | None = None,
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

        started_at = self.clock.now()
        final_state: Mapping[str, Any] = self.graph.invoke(initial)
        if self.clock.now() <= started_at:
            self.clock.advance(0.001)
        finished_at = self.clock.now()

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
        if max_rounds < 0:
            raise ValueError("max_rounds must be non-negative")

        family_states: list[str] = ["PREPARING", "AGGREGATING"]
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
            if max_total_seconds is None:
                return None
            return max(0.0, max_total_seconds - self.ledger.total_charged_seconds(family_id))

        def _remaining_fuzz() -> float | None:
            if max_fuzz_seconds is None:
                return None
            return max(0.0, max_fuzz_seconds - self.ledger.total_fuzz_seconds(family_id))

        # Step 2: Edge #23 (campaign -> hypothesis_aggregator) and edge #26
        # (verify -> hypothesis_aggregator) spawn serial round children after
        # each predecessor has archived itself.
        seeds = campaign_child.candidate_seeds
        if (
            campaign_child.state == "COMPLETED"
            and campaign_child.terminal_node == "archive"
            and seeds
            and max_rounds > 0
            and (_remaining_total() is None or (_remaining_total() or 0.0) > 0.0)
        ):
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
                seed_index = min(round_no - 1, len(seeds) - 1)
                seed_bytes = seeds[seed_index]
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

                decision = self.iteration_gate.check_capacity(
                    family_id=family_id,
                    completed_round_no=round_no,
                    max_rounds=max_rounds,
                    last_verdict=round_outcome.verdict,
                    remaining_budget_seconds=_remaining_total(),
                    remaining_fuzz_seconds=_remaining_fuzz(),
                    remaining_seeds=max(0, len(seeds) - round_no),
                )
                if not decision.should_continue:
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

        # Step 3: Run the family job itself through prepare -> AGGREGATING -> archive.
        family_final_state = "COMPLETED"
        family_final_reason: str | None = None
        if campaign_child.state == "BLOCKED" and campaign_child.reason_code in (
            "REVIEW_REJECTED",
            "REVIEW_EXPIRED",
        ):
            family_final_state = "BLOCKED"
            family_final_reason = campaign_child.reason_code

        family_graph_state: Mapping[str, Any] = self.graph.invoke(
            {
                "job_id": family_id,
                "family_id": family_id,
                "parent_job_id": None,
                "job_kind": "family",
                "round_no": None,
                "generation": 1,
                "request": dict(request or {}),
                "family_summary": {
                    "kind": "family_index",
                    "family_id": family_id,
                    "campaign_job_id": campaign_child.job_id,
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
                },
                "visited_nodes": [],
            }
        )
        terminal_family_state = str(family_graph_state.get("state", family_final_state))
        family_states.append(terminal_family_state)

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
        )


__all__ = [
    "AdmissionDecision",
    "ArchiveRecord",
    "BudgetChargeRecord",
    "BuildDiagnoser",
    "BuildDiagnosis",
    "CampaignResult",
    "CampaignRunner",
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
    "NodeReentryLedger",
    "ORCHESTRATION_EDGES",
    "ORCHESTRATION_NODES",
    "OrchestrationEdge",
    "OrchestrationRunner",
    "OrchestrationState",
    "ReviewDecision",
    "ReviewGate",
    "SandboxProtocol",
    "build_v2_graph",
]

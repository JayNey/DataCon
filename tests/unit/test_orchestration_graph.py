"""T11 / TC-11 / TC-04: v0.2 target orchestration graph, loops and node idempotency.

Test coordinates are anchored to docs/spec/v0.2/test-plan-delta.md §2 (T11) and
docs/spec/v0.2/README.md §5 (14 nodes and 26 edges).
"""

from __future__ import annotations

from dataclasses import replace
from datetime import timedelta
import threading
from typing import Any, Mapping, Sequence
from uuid import uuid4

from fakes import FakeClock, FakeEnvelopePolicy, FakeReviewGate, FakeSandbox
import pytest

from datacon import contracts
from datacon import jsonutil
from datacon import orchestration
from datacon import state as state_store
from datacon import verdict as verdict_mod
from datacon import workflow
from datacon.tools.sandbox import SandboxPolicyError

EXPECTED_NODES_V02 = frozenset(
    {
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
    }
)

# Complete 26-edge specification from docs/spec/v0.2/README.md §5 (#1-#26).
# Each entry is (edge_no, source, target, edge_kind).
EXPECTED_EDGES_V02: tuple[tuple[int, str, str, str], ...] = (
    (1, "prepare", "intel", "child_plan"),
    (2, "prepare", "AGGREGATING", "family_aggregate"),
    (3, "prepare", "archive", "prepare_blocked"),
    (4, "AGGREGATING", "archive", "family_complete"),
    (5, "intel", "version", "intel_ready"),
    (6, "intel", "archive", "intel_blocked"),
    (7, "version", "route", "version_resolved"),
    (8, "version", "archive", "version_blocked"),
    (9, "route", "patch", "target_patch"),
    (10, "route", "source", "target_source"),
    (11, "route", "archive", "target_reverse_unsupported"),
    (12, "patch", "hypothesis_aggregator", "patch_hypotheses"),
    (13, "source", "hypothesis_aggregator", "source_hypotheses"),
    (14, "hypothesis_aggregator", "review", "candidate_experiment"),
    (15, "review", "build", "human_approve"),
    (16, "review", "build", "policy_admit"),
    (17, "review", "archive", "review_blocked"),
    (18, "build", "build_diagnose", "build_complete"),
    (19, "build_diagnose", "build", "retryable_build_failure"),
    (20, "build_diagnose", "campaign", "campaign_search"),
    (21, "build_diagnose", "verify", "fixed_or_reuse_verify"),
    (22, "build_diagnose", "archive", "build_or_provenance_failed"),
    (23, "campaign", "hypothesis_aggregator", "family_next_round"),
    (24, "campaign", "archive", "campaign_bundle"),
    (25, "verify", "archive", "verify_terminal"),
    (26, "verify", "hypothesis_aggregator", "family_next_round"),
)


def _graph_nodes_and_edges(compiled) -> tuple[set[str], set[tuple[str, str]]]:
    drawable = compiled.get_graph()
    nodes = {name for name in drawable.nodes if name not in ("__start__", "__end__")}
    edges = {
        (edge.source, edge.target)
        for edge in drawable.edges
        if edge.source != "__start__" and edge.target != "__end__"
    }
    return nodes, edges


def _compiled_graph_nodes_and_edges() -> tuple[set[str], set[tuple[str, str]]]:
    compiled = workflow.build_v2_graph("postgresql://unused", None)
    return _graph_nodes_and_edges(compiled)


def test_graph_nodes_and_edges_match_v02_readme():
    nodes, compiled_edges = _compiled_graph_nodes_and_edges()

    missing_nodes = sorted(EXPECTED_NODES_V02 - nodes)
    extra_nodes = sorted(nodes - EXPECTED_NODES_V02)
    assert not missing_nodes, (
        f"missing node(s) in datacon.workflow graph (README §5 requires 14 nodes, "
        f"including 'hypothesis_aggregator'): missing={missing_nodes}, actual={sorted(nodes)}"
    )
    assert not extra_nodes, (
        f"unexpected node(s) in datacon.workflow graph: extra={extra_nodes}"
    )

    orchestration_edges = getattr(workflow, "ORCHESTRATION_EDGES", None)
    assert orchestration_edges is not None, (
        "datacon.workflow must export ORCHESTRATION_EDGES enumerating all 26 edges "
        "from docs/spec/v0.2/README.md §5"
    )
    assert len(orchestration_edges) == 26, (
        f"expected 26 orchestration edges (#1-#26), got {len(orchestration_edges)}"
    )

    actual_edge_pairs = {(edge.source, edge.target) for edge in orchestration_edges}
    expected_edge_pairs = {(src, dst) for _, src, dst, _ in EXPECTED_EDGES_V02}
    assert actual_edge_pairs == expected_edge_pairs, (
        f"ORCHESTRATION_EDGES pair mismatch: missing={sorted(expected_edge_pairs - actual_edge_pairs)}, "
        f"extra={sorted(actual_edge_pairs - expected_edge_pairs)}"
    )
    assert ("build_diagnose", "archive") in actual_edge_pairs, (
        "missing required edge #22 build_diagnose -> archive"
    )
    assert ("prepare", "AGGREGATING") in actual_edge_pairs and (
        "AGGREGATING",
        "archive",
    ) in actual_edge_pairs, "missing required family AGGREGATING branch edges #2/#4"

    review_to_build = [
        edge
        for edge in orchestration_edges
        if edge.source == "review" and edge.target == "build"
    ]
    assert len(review_to_build) == 2, (
        "expected 2 distinct review -> build edges (#15 human first plan and #16 in-round policy), "
        f"got {len(review_to_build)}"
    )
    review_edge_tokens = [repr(edge).lower() for edge in review_to_build]
    assert len(set(review_edge_tokens)) == 2, (
        f"review -> build edges #15 and #16 must be distinct, got {review_to_build!r}"
    )
    assert any(
        "human" in token or "first" in token for token in review_edge_tokens
    ), (
        f"review -> build edge #15 must identify human first-plan approval: {review_to_build!r}"
    )
    assert any(
        "policy" in token or "admit" in token for token in review_edge_tokens
    ), (
        f"review -> build edge #16 must identify in-round policy admission: {review_to_build!r}"
    )

    in_job_expected_pairs = {
        (src, dst)
        for _, src, dst, kind in EXPECTED_EDGES_V02
        if kind != "family_next_round"
    }
    missing_compiled = sorted(in_job_expected_pairs - compiled_edges)
    assert not missing_compiled, (
        f"compiled LangGraph is missing in-job edges from README §5: {missing_compiled}"
    )
    extra_compiled = sorted(compiled_edges - in_job_expected_pairs)
    assert not extra_compiled, (
        "compiled LangGraph contains unexpected or non-in-job edges "
        f"(family-level #23/#26 must not be wired as in-job edges): {extra_compiled}"
    )

    # build_graph(..., contract_version=2) must match build_v2_graph(...),
    # while default build_graph(..., contract_version=1) stays 2-node v1.
    v2_dispatch_nodes, v2_dispatch_edges = _graph_nodes_and_edges(
        workflow.build_graph("postgresql://unused", None, contract_version=2)
    )
    assert v2_dispatch_nodes == nodes
    assert v2_dispatch_edges == compiled_edges

    v1_nodes, v1_edges = _graph_nodes_and_edges(
        workflow.build_graph("postgresql://unused", None)
    )
    assert v1_nodes == {"prepare", "await_review"}
    assert v1_edges == {("prepare", "await_review")}

    # Edge #6 (intel -> archive) must fail closed if an IntelProvider claims
    # status="ready" with a missing or blank snapshot_digest.
    for bad_digest in (None, "", "   "):

        class _UnverifiedIntelProvider:
            def __init__(self, digest: str | None) -> None:
                self._digest = digest

            def resolve_intel(
                self,
                *,
                job_id: str,
                family_id: str,
                request: Mapping[str, Any],
            ) -> workflow.IntelResult:
                del job_id, family_id, request
                return workflow.IntelResult(
                    status="ready",
                    snapshot_digest=self._digest,
                    summary={"source": "unverified"},
                )

        intel_clock = FakeClock()
        intel_sandbox = FakeSandbox(clock=intel_clock)
        intel_runner = workflow.OrchestrationRunner(
            sandbox=intel_sandbox,
            clock=intel_clock,
            intel_provider=_UnverifiedIntelProvider(bad_digest),
        )
        intel_outcome = intel_runner.run_child(
            job_id=str(uuid4()),
            family_id=str(uuid4()),
            job_kind="round",
            round_no=1,
            target_kind="source",
        )
        assert intel_outcome.terminal_node == "archive"
        assert intel_outcome.state == "BLOCKED"
        assert intel_outcome.reason_code == "MATERIAL_MISSING"
        assert "version" not in intel_outcome.visited_nodes
        assert len(intel_sandbox.build_calls) == 0


def test_build_diagnose_retry_is_bounded_to_once():
    clock = FakeClock()
    sandbox = FakeSandbox(clock=clock, retryable_build_failures=3)
    review_gate = FakeReviewGate(clock=clock, decision="approve")
    envelope_policy = FakeEnvelopePolicy(clock=clock, default_admit=True)

    runner_cls = getattr(workflow, "OrchestrationRunner", None)
    assert runner_cls is not None, (
        "datacon.workflow.OrchestrationRunner is missing (T11): cannot verify "
        "build_diagnose retry loop is bounded to at most 1 extra retry"
    )

    runner = runner_cls(
        sandbox=sandbox,
        clock=clock,
        review_gate=review_gate,
        envelope_policy=envelope_policy,
    )
    outcome = runner.run_child(
        job_id=str(uuid4()),
        family_id=str(uuid4()),
        job_kind="round",
        round_no=1,
        target_kind="source",
    )

    assert len(sandbox.build_calls) == 2, (
        f"build invoked {len(sandbox.build_calls)} times, expected at most 2 "
        "(1 initial attempt + 1 bounded build_diagnose retry)"
    )
    assert outcome.terminal_node == "archive", (
        f"expected exhausted build retry to transition to 'archive', got {outcome.terminal_node!r}"
    )
    assert outcome.reason_code == "BUILD_FAILED", (
        f"expected reason_code='BUILD_FAILED' after retry exhaustion, got {outcome.reason_code!r}"
    )
    assert "verify" not in outcome.visited_nodes, (
        f"exhausted build retry must not enter verify: visited_nodes={outcome.visited_nodes}"
    )
    assert len(sandbox.replay_calls) == 0, (
        f"exhausted build retry must never invoke sandbox.replay, got {len(sandbox.replay_calls)} call(s)"
    )

    # README §5 edge #19 bounds max_build_retries to int in [0, 1].
    for invalid_retries in (-1, 2, True, False, 1.0):
        with pytest.raises(ValueError, match="max_build_retries"):
            runner_cls(
                sandbox=sandbox,
                clock=clock,
                max_build_retries=invalid_retries,  # type: ignore[arg-type]
            )

    zero_retry_sandbox = FakeSandbox(clock=clock, retryable_build_failures=2)
    zero_retry_runner = runner_cls(
        sandbox=zero_retry_sandbox,
        clock=clock,
        review_gate=FakeReviewGate(clock=clock, decision="approve"),
        envelope_policy=FakeEnvelopePolicy(clock=clock, default_admit=True),
        max_build_retries=0,
    )
    zero_retry_outcome = zero_retry_runner.run_child(
        job_id=str(uuid4()),
        family_id=str(uuid4()),
        job_kind="round",
        round_no=1,
        target_kind="source",
    )
    assert len(zero_retry_sandbox.build_calls) == 1
    assert zero_retry_outcome.terminal_node == "archive"
    assert zero_retry_outcome.reason_code == "BUILD_FAILED"

    # Non-retryable build_diagnose_failure metadata from FakeSandbox archives
    # immediately without retrying.
    diag_fail_sandbox = FakeSandbox(
        clock=clock,
        build_faults=("build_diagnose_failure",),
    )
    diag_fail_runner = runner_cls(
        sandbox=diag_fail_sandbox,
        clock=clock,
        review_gate=FakeReviewGate(clock=clock, decision="approve"),
        envelope_policy=FakeEnvelopePolicy(clock=clock, default_admit=True),
    )
    diag_fail_outcome = diag_fail_runner.run_child(
        job_id=str(uuid4()),
        family_id=str(uuid4()),
        job_kind="round",
        round_no=1,
        target_kind="source",
    )
    assert len(diag_fail_sandbox.build_calls) == 1
    assert len(diag_fail_sandbox.replay_calls) == 0
    assert diag_fail_outcome.terminal_node == "archive"
    assert diag_fail_outcome.state == "FAILED"
    assert diag_fail_outcome.reason_code == "BUILD_FAILED"

    # Edge #22: provenance_missing routes directly build_diagnose -> archive
    # with BUILD_PROVENANCE_MISSING (0 retries, 0 replays, never enters verify).
    prov_clock = FakeClock()
    prov_delegate = FakeSandbox(clock=prov_clock)

    class _ProvenanceMissingSandbox:
        def probe(self, *, deadline_seconds: float = 120.0):
            return prov_delegate.probe(deadline_seconds=deadline_seconds)

        def build(
            self,
            version: str,
            *,
            compile_args: Sequence[str] = (),
            deadline_seconds: float = 300.0,
            expected_materials: Mapping[str, str] | None = None,
        ):
            built = prov_delegate.build(
                version,
                compile_args=compile_args,
                deadline_seconds=deadline_seconds,
                expected_materials=expected_materials,
            )
            return replace(
                built,
                metadata={**built.metadata, "provenance_missing": True},
            )

        def replay(
            self,
            version: str,
            phase: str,
            *,
            timeout_seconds: float = 10.0,
            deadline_seconds: float | None = None,
            expected_artifact_digest: str | None = None,
            expected_input_digest: str | None = None,
        ):
            return prov_delegate.replay(
                version,
                phase,
                timeout_seconds=timeout_seconds,
                deadline_seconds=deadline_seconds,
                expected_artifact_digest=expected_artifact_digest,
                expected_input_digest=expected_input_digest,
            )

    prov_runner = runner_cls(
        sandbox=_ProvenanceMissingSandbox(),
        clock=prov_clock,
        review_gate=FakeReviewGate(clock=prov_clock, decision="approve"),
        envelope_policy=FakeEnvelopePolicy(clock=prov_clock, default_admit=True),
    )
    prov_outcome = prov_runner.run_child(
        job_id=str(uuid4()),
        family_id=str(uuid4()),
        job_kind="round",
        round_no=1,
        target_kind="source",
    )
    assert prov_outcome.visited_nodes.count("build") == 1
    assert prov_outcome.visited_nodes.count("build_diagnose") == 1
    assert len(prov_delegate.build_calls) == 2
    assert len(prov_delegate.replay_calls) == 0
    assert "verify" not in prov_outcome.visited_nodes
    assert prov_outcome.terminal_node == "archive"
    assert prov_outcome.state == "FAILED"
    assert prov_outcome.reason_code == "BUILD_PROVENANCE_MISSING"


def test_node_reentry_is_a_noop():
    clock = FakeClock()
    sandbox = FakeSandbox(clock=clock)
    review_gate = FakeReviewGate(
        clock=clock,
        decision="approve",
        review_deadline_at=clock.now() + timedelta(hours=24),
    )
    envelope_policy = FakeEnvelopePolicy(clock=clock, default_admit=True)

    runner_cls = getattr(workflow, "OrchestrationRunner", None)
    assert runner_cls is not None, (
        "datacon.workflow.OrchestrationRunner is missing (T11): cannot verify "
        "node re-entry no-op for prepare/review/build/verify/archive"
    )

    runner = runner_cls(
        sandbox=sandbox,
        clock=clock,
        review_gate=review_gate,
        envelope_policy=envelope_policy,
    )
    job_id = str(uuid4())
    family_id = str(uuid4())
    reentry_nodes = ("prepare", "review", "build", "verify", "archive")

    for stage in reentry_nodes:
        idempotency_key = (job_id, stage, f"{stage}_step", 1, 1)
        builds_before = len(sandbox.build_calls)
        replays_before = len(sandbox.replay_calls)
        reviews_before = review_gate.review_writes
        admissions_before = len(envelope_policy.admissions)
        archives_before = runner.archive_count(job_id)

        first = runner.execute_node(
            family_id=family_id,
            idempotency_key=idempotency_key,
        )
        builds_after_first = len(sandbox.build_calls)
        replays_after_first = len(sandbox.replay_calls)
        reviews_after_first = review_gate.review_writes
        admissions_after_first = len(envelope_policy.admissions)
        charges_after_first = runner.charge_count(job_id)
        archives_after_first = runner.archive_count(job_id)

        if stage == "build":
            assert builds_after_first > builds_before, (
                "first entry to 'build' must perform at least one build call "
                "(re-entry test must not pass vacuously)"
            )
        elif stage == "verify":
            assert replays_after_first > replays_before, (
                "first entry to 'verify' must perform at least one replay call "
                "(re-entry test must not pass vacuously)"
            )
        elif stage == "review":
            assert (reviews_after_first > reviews_before) or (
                admissions_after_first > admissions_before
            ), (
                "first entry to 'review' must record a human review or policy admission "
                "(re-entry test must not pass vacuously)"
            )
        elif stage == "archive":
            assert archives_after_first > archives_before, (
                "first entry to 'archive' must record an archive write "
                "(re-entry test must not pass vacuously)"
            )

        second = runner.execute_node(
            family_id=family_id,
            idempotency_key=idempotency_key,
        )

        assert second == first, (
            f"re-entering node {stage!r} with key {idempotency_key} did not return "
            f"the persisted result: first={first!r}, second={second!r}"
        )
        assert len(sandbox.build_calls) == builds_after_first, (
            f"duplicate build attempt on node re-entry for stage={stage!r}"
        )
        assert len(sandbox.replay_calls) == replays_after_first, (
            f"duplicate replay attempt on node re-entry for stage={stage!r}"
        )
        assert review_gate.review_writes == reviews_after_first, (
            f"duplicate review write on node re-entry for stage={stage!r}"
        )
        assert len(envelope_policy.admissions) == admissions_after_first, (
            f"duplicate admission on node re-entry for stage={stage!r}"
        )
        assert runner.charge_count(job_id) == charges_after_first, (
            f"duplicate budget charge on node re-entry for stage={stage!r}"
        )
        assert runner.archive_count(job_id) == archives_after_first, (
            f"duplicate archive write on node re-entry for stage={stage!r}"
        )

    # A new generation or attempt_no is a distinct execution key and runs normally.
    builds_before_retry = len(sandbox.build_calls)
    charges_before_retry = runner.charge_count(job_id)
    runner.execute_node(
        family_id=family_id,
        idempotency_key=(job_id, "build", "build_step", 2, 1),
    )
    assert len(sandbox.build_calls) > builds_before_retry
    assert runner.charge_count(job_id) == charges_before_retry + 1

    builds_before_new_gen = len(sandbox.build_calls)
    runner.execute_node(
        family_id=family_id,
        idempotency_key=(job_id, "build", "build_step", 2, 2),
    )
    assert len(sandbox.build_calls) > builds_before_new_gen
    # Same (job_id, step_key, attempt_no) on a new generation does not double-charge.
    assert runner.charge_count(job_id) == charges_before_retry + 1

    # First-write-wins record_completed + idempotent record_archive across generations.
    fww_ledger = workflow.NodeReentryLedger()
    fww_key = workflow.StepKey(str(uuid4()), "prepare", "fww_step", 1, 1)
    assert fww_ledger.record_completed(fww_key, {"marker": "first"}) == {
        "marker": "first"
    }
    assert fww_ledger.record_completed(fww_key, {"marker": "second"}) == {
        "marker": "first"
    }
    assert fww_ledger.get_completed(fww_key) == {"marker": "first"}

    # Re-entering archive under a new generation still deduplicates by job_id.
    gen2_archive = runner.execute_node(
        family_id=family_id,
        idempotency_key=(job_id, "archive", "archive_step", 1, 2),
    )
    assert runner.archive_count(job_id) == 1
    assert gen2_archive["archive_digest"] == first["archive_digest"]

    # D42: Non-terminal parked review (await_review / REVIEW_ENVELOPE_MISMATCH)
    # must NOT be cached as a completed no-op in NodeReentryLedger, so a retry
    # with the corrected envelope_digest under the same generation succeeds
    # (and hypothesis_aggregator recomputes first_plan_digest consistently on
    # cache hit), after which decided review outcomes remain cached as no-ops.
    expected_envelope = "sha256:" + "e" * 64
    wrong_envelope = "sha256:" + "f" * 64
    parked_clock = FakeClock()
    parked_sandbox = FakeSandbox(clock=parked_clock)
    parked_review_gate = FakeReviewGate(
        clock=parked_clock,
        decision="approve",
        expected_envelope_digest=expected_envelope,
        review_deadline_at=parked_clock.now() + timedelta(hours=24),
    )

    class _CountingAggregator:
        def __init__(self) -> None:
            self.calls = 0
            self.last_experiment_digest: str | None = None

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
        ) -> workflow.HypothesisAggregationResult:
            self.calls += 1
            spec = {
                "family_id": family_id,
                "job_kind": job_kind,
                "round_no": round_no,
                "target_kind": target_kind,
                "seed_bytes": seed_bytes.hex() if seed_bytes is not None else None,
                "evidence_refs": list(route_facts.get("evidence_refs", ())),
            }
            digest = jsonutil.digest_json(spec)
            self.last_experiment_digest = digest
            return workflow.HypothesisAggregationResult(
                experiment_spec=spec,
                experiment_digest=digest,
            )

    counting_aggregator = _CountingAggregator()
    parked_runner = runner_cls(
        sandbox=parked_sandbox,
        clock=parked_clock,
        hypothesis_aggregator=counting_aggregator,
        review_gate=parked_review_gate,
        envelope_policy=FakeEnvelopePolicy(clock=parked_clock, default_admit=True),
    )
    parked_job_id = str(uuid4())
    parked_family_id = str(uuid4())
    parked_outcome = parked_runner.run_child(
        job_id=parked_job_id,
        family_id=parked_family_id,
        job_kind="round",
        round_no=1,
        generation=1,
        is_first_plan=True,
        envelope_digest=wrong_envelope,
    )
    assert parked_outcome.state == "AWAITING_REVIEW"
    assert parked_outcome.reason_code == "REVIEW_ENVELOPE_MISMATCH"
    assert parked_outcome.terminal_node is None
    assert parked_review_gate.review_writes == 0
    assert len(parked_sandbox.build_calls) == 0
    assert counting_aggregator.calls == 1
    assert counting_aggregator.last_experiment_digest is not None

    expected_recomputed_first_plan = jsonutil.digest_json(
        {
            "family_id": parked_family_id,
            "job_kind": "round",
            "envelope_digest": expected_envelope,
            "experiment_digest": counting_aggregator.last_experiment_digest,
        }
    )
    parked_review_gate.expected_first_plan_digest = expected_recomputed_first_plan

    approved_outcome = parked_runner.run_child(
        job_id=parked_job_id,
        family_id=parked_family_id,
        job_kind="round",
        round_no=1,
        generation=1,
        is_first_plan=True,
        envelope_digest=expected_envelope,
    )
    assert approved_outcome.terminal_node == "archive"
    assert approved_outcome.approval_digest is not None
    assert parked_review_gate.review_writes == 1
    assert counting_aggregator.calls == 1
    assert (
        parked_review_gate.checks[0]["first_plan_digest"]
        != parked_review_gate.checks[1]["first_plan_digest"]
    )
    assert (
        parked_review_gate.checks[1]["first_plan_digest"]
        == expected_recomputed_first_plan
    )
    builds_after_approval = len(parked_sandbox.build_calls)
    assert builds_after_approval > 0

    replayed_outcome = parked_runner.run_child(
        job_id=parked_job_id,
        family_id=parked_family_id,
        job_kind="round",
        round_no=1,
        generation=1,
        is_first_plan=True,
        envelope_digest=expected_envelope,
    )
    assert replayed_outcome.approval_digest == approved_outcome.approval_digest
    assert parked_review_gate.review_writes == 1
    assert len(parked_sandbox.build_calls) == builds_after_approval

    # StepKey NamedTuple compatibility + injectable AttemptStore protocol.
    step_key = workflow.StepKey(job_id, "prepare", "custom_prepare", 1, 1)
    assert step_key == (job_id, "prepare", "custom_prepare", 1, 1)
    assert hash(step_key) == hash((job_id, "prepare", "custom_prepare", 1, 1))

    class _CustomAttemptStore:
        def __init__(self) -> None:
            self.records: dict[workflow.StepKey, dict[str, object]] = {}
            self.get_calls: list[workflow.StepKey] = []
            self.record_calls: list[workflow.StepKey] = []

        def get_completed(self, key: workflow.StepKey) -> dict[str, object] | None:
            self.get_calls.append(key)
            cached = self.records.get(key)
            return dict(cached) if cached is not None else None

        def record_completed(
            self,
            key: workflow.StepKey,
            result: dict[str, object],
        ) -> dict[str, object]:
            self.record_calls.append(key)
            self.records[key] = dict(result)
            return dict(result)

    custom_store = _CustomAttemptStore()
    assert isinstance(custom_store, workflow.AttemptStore)
    assert isinstance(runner.ledger, workflow.AttemptStore)
    assert isinstance(runner.ledger, workflow.ChargeArchiveStore)

    custom_sandbox = FakeSandbox(clock=FakeClock())
    custom_runner = runner_cls(
        sandbox=custom_sandbox,
        clock=FakeClock(),
        attempt_store=custom_store,
    )
    first_custom = custom_runner.execute_node(
        family_id=family_id,
        idempotency_key=step_key,
    )
    second_custom = custom_runner.execute_node(
        family_id=family_id,
        idempotency_key=(job_id, "prepare", "custom_prepare", 1, 1),
    )
    assert second_custom == first_custom
    assert custom_store.record_calls == [step_key]
    assert custom_store.get_calls == [step_key, step_key]

    # Custom ChargeArchiveStore-only injection (distinct from AttemptStore).
    class _CustomChargeArchiveStore:
        def __init__(self) -> None:
            self.charge_keys: set[tuple[str, str, int]] = set()
            self.charges: list[tuple[str, str, float, float]] = []
            self.archives: dict[str, workflow.ArchiveRecord] = {}

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
            del recorded_at, charge_kind
            ck = (job_id, step_key, attempt_no)
            if ck in self.charge_keys:
                return False
            self.charge_keys.add(ck)
            self.charges.append((job_id, family_id, float(seconds), float(fuzz_seconds)))
            return True

        def charge_count(self, job_id: str) -> int:
            return sum(1 for item in self.charges if item[0] == job_id)

        def total_charged_seconds(self, family_id: str) -> float:
            return sum(item[2] for item in self.charges if item[1] == family_id)

        def total_fuzz_seconds(self, family_id: str) -> float:
            return sum(item[3] for item in self.charges if item[1] == family_id)

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
        ) -> workflow.ArchiveRecord:
            if job_id in self.archives:
                return self.archives[job_id]
            rec = workflow.ArchiveRecord(
                job_id=job_id,
                family_id=family_id,
                job_kind=job_kind,
                state=state,
                verdict=verdict,
                reason_code=reason_code,
                archive_digest=archive_digest,
                recorded_at=recorded_at,
            )
            self.archives[job_id] = rec
            return rec

        def archive_count(self, job_id: str) -> int:
            return 1 if job_id in self.archives else 0

    custom_ca_store = _CustomChargeArchiveStore()
    assert isinstance(custom_ca_store, workflow.ChargeArchiveStore)
    assert not isinstance(custom_ca_store, workflow.AttemptStore)
    ca_clock = FakeClock()
    ca_sandbox = FakeSandbox(clock=ca_clock)
    ca_runner = runner_cls(
        sandbox=ca_sandbox,
        clock=ca_clock,
        ledger=custom_ca_store,
    )
    assert isinstance(ca_runner.attempt_store, workflow.AttemptStore)
    assert ca_runner.attempt_store is not custom_ca_store
    ca_job_id = str(uuid4())
    ca_family_id = str(uuid4())
    ca_outcome = ca_runner.run_child(
        job_id=ca_job_id,
        family_id=ca_family_id,
        job_kind="round",
        round_no=1,
        is_first_plan=True,
    )
    assert ca_outcome.terminal_node == "archive"
    assert custom_ca_store.charge_count(ca_job_id) >= 2
    assert custom_ca_store.archive_count(ca_job_id) == 1
    assert custom_ca_store.total_charged_seconds(ca_family_id) > 0.0
    assert workflow.build_v2_graph(
        sandbox=ca_sandbox, clock=ca_clock, ledger=custom_ca_store
    ) is not None

    # StaleGeneration + oom/log_truncated policy exceptions must NOT poison
    # AttemptStore, allowing subsequent recovery under the same StepKey.
    stale_clock = FakeClock()
    stale_sandbox = FakeSandbox(clock=stale_clock, build_faults=("stale_generation",))
    stale_runner = runner_cls(sandbox=stale_sandbox, clock=stale_clock)
    stale_key = workflow.StepKey(str(uuid4()), "build", "build_step", 1, 1)
    with pytest.raises(state_store.StaleGeneration):
        stale_runner.execute_node(family_id=family_id, idempotency_key=stale_key)
    assert stale_runner.attempt_store.get_completed(stale_key) is None
    assert stale_runner.charge_count(stale_key.job_id) == 0
    recovered_stale = stale_runner.execute_node(
        family_id=family_id, idempotency_key=stale_key
    )
    assert recovered_stale["build_artifacts"]["vulnerable"]["status"] == "completed"
    assert stale_runner.charge_count(stale_key.job_id) == 1

    for policy_fault in ("oom", "log_truncated"):
        fault_clock = FakeClock()
        fault_delegate = FakeSandbox(clock=fault_clock, probe_faults=(policy_fault,))

        class _FaultingBuildSandbox:
            def __init__(self, delegate: FakeSandbox) -> None:
                self._delegate = delegate
                self._failed_once = False

            def probe(self, *, deadline_seconds: float = 120.0):
                return self._delegate.probe(deadline_seconds=deadline_seconds)

            def build(
                self,
                version: str,
                *,
                compile_args: Sequence[str] = (),
                deadline_seconds: float = 300.0,
                expected_materials: Mapping[str, str] | None = None,
            ):
                if not self._failed_once:
                    self._failed_once = True
                    # Triggers SandboxPolicyError from FakeSandbox.probe for oom/log_truncated.
                    self._delegate.probe()
                return self._delegate.build(
                    version,
                    compile_args=compile_args,
                    deadline_seconds=deadline_seconds,
                    expected_materials=expected_materials,
                )

            def replay(
                self,
                version: str,
                phase: str,
                *,
                timeout_seconds: float = 10.0,
                deadline_seconds: float | None = None,
                expected_artifact_digest: str | None = None,
                expected_input_digest: str | None = None,
            ):
                return self._delegate.replay(
                    version,
                    phase,
                    timeout_seconds=timeout_seconds,
                    deadline_seconds=deadline_seconds,
                    expected_artifact_digest=expected_artifact_digest,
                    expected_input_digest=expected_input_digest,
                )

        fault_runner = runner_cls(
            sandbox=_FaultingBuildSandbox(fault_delegate),
            clock=fault_clock,
        )
        fault_key = workflow.StepKey(str(uuid4()), "build", f"{policy_fault}_step", 1, 1)
        with pytest.raises(SandboxPolicyError):
            fault_runner.execute_node(family_id=family_id, idempotency_key=fault_key)
        assert fault_runner.attempt_store.get_completed(fault_key) is None
        assert fault_runner.charge_count(fault_key.job_id) == 0
        recovered_fault = fault_runner.execute_node(
            family_id=family_id, idempotency_key=fault_key
        )
        assert recovered_fault["build_artifacts"]["vulnerable"]["status"] == "completed"
        assert fault_runner.charge_count(fault_key.job_id) == 1

    # Also verify non-raising oom/log_truncated replay faults produce deterministic
    # INCONCLUSIVE reason codes without duplicating side effects on re-entry.
    for replay_fault, expected_reason in (
        ("oom", "RESOURCE_LIMITED"),
        ("log_truncated", "EVIDENCE_INCOMPLETE"),
    ):
        rf_clock = FakeClock()
        rf_sandbox = FakeSandbox(clock=rf_clock, replay_faults=(replay_fault,))
        rf_runner = runner_cls(sandbox=rf_sandbox, clock=rf_clock)
        rf_job_id = str(uuid4())
        rf_first = rf_runner.run_child(
            job_id=rf_job_id,
            family_id=family_id,
            job_kind="round",
            round_no=1,
            generation=1,
            is_first_plan=True,
        )
        assert rf_first.state == "INCONCLUSIVE"
        assert rf_first.reason_code == expected_reason
        replays_after_rf = len(rf_sandbox.replay_calls)
        rf_second = rf_runner.run_child(
            job_id=rf_job_id,
            family_id=family_id,
            job_kind="round",
            round_no=1,
            generation=1,
            is_first_plan=True,
        )
        assert rf_second.reason_code == expected_reason
        assert len(rf_sandbox.replay_calls) == replays_after_rf
        assert rf_runner.archive_count(rf_job_id) == 1

    # Verify run_idempotent skips record_completed when should_cache returns False.
    ephemeral_key = workflow.StepKey(job_id, "review", "ephemeral", 1, 1)
    action_runs = 0

    def _ephemeral_action() -> dict[str, object]:
        nonlocal action_runs
        action_runs += 1
        return {"next_route": "await_review", "run": action_runs}

    first_ephemeral = workflow.run_idempotent(
        custom_store,
        ephemeral_key,
        _ephemeral_action,
        should_cache=lambda u: u.get("next_route") != "await_review",
    )
    second_ephemeral = workflow.run_idempotent(
        custom_store,
        ephemeral_key,
        _ephemeral_action,
        should_cache=lambda u: u.get("next_route") != "await_review",
    )
    assert first_ephemeral["run"] == 1 and second_ephemeral["run"] == 2
    assert ephemeral_key not in custom_store.records


def test_reverse_route_archives_as_unsupported():
    clock = FakeClock()
    sandbox = FakeSandbox(clock=clock)

    runner_cls = getattr(workflow, "OrchestrationRunner", None)
    assert runner_cls is not None, (
        "datacon.workflow.OrchestrationRunner is missing (T11): cannot verify "
        "route -> archive placeholder for reverse/binary targets"
    )

    runner = runner_cls(sandbox=sandbox, clock=clock)
    outcome = runner.run_child(
        job_id=str(uuid4()),
        family_id=str(uuid4()),
        job_kind="round",
        round_no=1,
        target_kind="binary",
    )

    assert "route" in outcome.visited_nodes, (
        f"reverse target must pass through 'route' (edge #11), got visited_nodes={outcome.visited_nodes}"
    )
    assert "hypothesis_aggregator" not in outcome.visited_nodes, (
        f"reverse route must not enter hypothesis_aggregator: visited_nodes={outcome.visited_nodes}"
    )
    assert "build" not in outcome.visited_nodes, (
        f"reverse route reached build: visited_nodes={outcome.visited_nodes}"
    )
    assert outcome.terminal_node == "archive", (
        f"expected reverse route to end at 'archive', got {outcome.terminal_node!r}"
    )
    assert outcome.state == "BLOCKED", (
        f"expected reverse route state='BLOCKED', got {outcome.state!r}"
    )
    assert outcome.reason_code == "UNSUPPORTED_TARGET", (
        f"expected reason_code='UNSUPPORTED_TARGET', got {outcome.reason_code!r}"
    )
    assert len(sandbox.build_calls) == 0, (
        f"reverse route must never invoke sandbox.build, got {len(sandbox.build_calls)} call(s)"
    )


def test_campaign_branch_is_mounted_in_graph():
    nodes, compiled_edges = _compiled_graph_nodes_and_edges()

    assert "campaign" in nodes, (
        f"campaign branch missing from datacon.workflow graph: actual nodes={sorted(nodes)}"
    )
    assert ("build_diagnose", "campaign") in compiled_edges, (
        f"missing edge #20 build_diagnose -> campaign in compiled edges={sorted(compiled_edges)}"
    )
    assert ("campaign", "archive") in compiled_edges, (
        f"missing edge #24 campaign -> archive in compiled edges={sorted(compiled_edges)}"
    )
    assert ("campaign", "verify") not in compiled_edges, (
        "campaign must never connect directly to verify (campaign does not replace validation)"
    )
    assert ("campaign", "hypothesis_aggregator") not in compiled_edges, (
        "campaign -> hypothesis_aggregator (#23) is a family-level transition, not an in-job edge"
    )

    orchestration_edges = getattr(workflow, "ORCHESTRATION_EDGES", None)
    assert orchestration_edges is not None, (
        "datacon.workflow.ORCHESTRATION_EDGES must be defined to enumerate campaign branch edges"
    )
    campaign_family_edges = [
        edge
        for edge in orchestration_edges
        if edge.source == "campaign" and edge.target == "hypothesis_aggregator"
    ]
    assert len(campaign_family_edges) == 1, (
        "expected exactly one family-level edge #23 campaign -> hypothesis_aggregator, "
        f"got {len(campaign_family_edges)}"
    )


def test_family_level_transitions_create_next_round_child():
    clock = FakeClock()
    # Inject a deterministic inconclusive round-1 replay outcome (TIMEOUT -> INCONCLUSIVE)
    # so edge #26 (verify -> hypothesis_aggregator) is genuinely triggered per README §5,
    # rather than terminating after round 1 with NOT_REPRODUCED (edge #25).
    sandbox = FakeSandbox(clock=clock, replay_faults=("timeout",))
    review_gate = FakeReviewGate(clock=clock, decision="approve")
    envelope_policy = FakeEnvelopePolicy(clock=clock, default_admit=True)

    runner_cls = getattr(workflow, "OrchestrationRunner", None)
    assert runner_cls is not None, (
        "datacon.workflow.OrchestrationRunner is missing (T11): cannot verify "
        "family-level transitions (#23/#26) spawn new child jobs after archiving"
    )

    runner = runner_cls(
        sandbox=sandbox,
        clock=clock,
        review_gate=review_gate,
        envelope_policy=envelope_policy,
    )
    family_id = str(uuid4())
    family_run = runner.run_family_guided(
        family_id=family_id,
        candidate_seeds=[b"seed-round-1", b"seed-round-2"],
        max_rounds=2,
    )

    campaign_child = family_run.campaign_child
    round_children = family_run.round_children

    assert campaign_child.job_kind == "campaign" and campaign_child.round_no is None, (
        f"campaign child must have job_kind='campaign' and round_no=None, got {campaign_child!r}"
    )
    assert campaign_child.parent_job_id == family_id, (
        f"campaign child must belong to family {family_id}, got {campaign_child!r}"
    )
    assert "verify" not in campaign_child.visited_nodes, (
        f"campaign child must never run verify in-place (edge #23): {campaign_child.visited_nodes}"
    )
    assert campaign_child.terminal_node == "archive", (
        "campaign child must archive itself before next round child is created"
    )
    assert campaign_child.state == "COMPLETED" and campaign_child.verdict is None, (
        f"campaign child must finish with state='COMPLETED' and verdict=None, got {campaign_child!r}"
    )
    assert len(round_children) >= 2, (
        f"expected family transitions (#23 and #26) to spawn at least 2 round children, "
        f"got {len(round_children)}"
    )

    child_ids = [campaign_child.job_id, *(child.job_id for child in round_children)]
    assert len(set(child_ids)) == len(child_ids), (
        f"next round reused a finished child job id: child_ids={child_ids}"
    )
    assert [child.round_no for child in round_children[:2]] == [1, 2], (
        f"expected round_no sequence [1, 2], got {[child.round_no for child in round_children]}"
    )
    for child in round_children:
        assert child.job_kind == "round", (
            f"each spawned round child must have job_kind='round': {child!r}"
        )
        assert child.parent_job_id == family_id and child.terminal_node == "archive", (
            f"each spawned round child must belong to family {family_id} and archive itself: {child!r}"
        )

    # Conclusive round-2 verdict (NOT_REPRODUCED) completes with no stop_reason_code.
    assert family_run.state == "COMPLETED"
    assert family_run.reason_code is None
    assert family_run.stop_reason_code is None

    # Budget exhaustion keeps family COMPLETED (reason_code=None) while
    # surfacing stop_reason_code="BUDGET_EXHAUSTED" and stopping before round 2.
    budget_clock = FakeClock()
    budget_runner = runner_cls(
        sandbox=FakeSandbox(clock=budget_clock, replay_faults=("timeout",)),
        clock=budget_clock,
        review_gate=FakeReviewGate(clock=budget_clock, decision="approve"),
        envelope_policy=FakeEnvelopePolicy(clock=budget_clock, default_admit=True),
    )
    budget_run = budget_runner.run_family_guided(
        family_id=str(uuid4()),
        candidate_seeds=[b"seed-budget-1", b"seed-budget-2"],
        max_rounds=2,
        max_total_seconds=5.0,
    )
    assert len(budget_run.round_children) == 1
    assert budget_run.state == "COMPLETED"
    assert budget_run.reason_code is None
    assert budget_run.stop_reason_code == "BUDGET_EXHAUSTED"

    # Non-review campaign blocks (e.g. MATERIAL_MISSING in intel or prepare)
    # propagate BLOCKED + reason_code + stop_reason_code to the family job.
    for req_key in ("intel_blocked_reason", "prepare_blocked_reason"):
        blk_clock = FakeClock()
        blk_runner = runner_cls(
            sandbox=FakeSandbox(clock=blk_clock),
            clock=blk_clock,
            review_gate=FakeReviewGate(clock=blk_clock, decision="approve"),
            envelope_policy=FakeEnvelopePolicy(clock=blk_clock, default_admit=True),
        )
        blk_run = blk_runner.run_family_guided(
            family_id=str(uuid4()),
            candidate_seeds=[b"seed-1"],
            max_rounds=2,
            request={req_key: "MATERIAL_MISSING"},
        )
        assert blk_run.campaign_child.state == "BLOCKED"
        assert blk_run.campaign_child.reason_code == "MATERIAL_MISSING"
        assert blk_run.state == "BLOCKED"
        assert blk_run.reason_code == "MATERIAL_MISSING"
        assert blk_run.stop_reason_code == "MATERIAL_MISSING"
        assert blk_run.round_children == ()
        assert blk_run.visited_nodes == ("prepare", "AGGREGATING", "archive")
        assert blk_run.family_states_observed == ("AGGREGATING", "BLOCKED")

    # Campaign FAILED converges the v2 family to COMPLETED (families have no
    # FAILED state) while recording stop_reason_code="BUILD_FAILED".
    fail_clock = FakeClock()
    fail_runner = runner_cls(
        sandbox=FakeSandbox(clock=fail_clock, build_faults=("build_diagnose_failure",)),
        clock=fail_clock,
        review_gate=FakeReviewGate(clock=fail_clock, decision="approve"),
        envelope_policy=FakeEnvelopePolicy(clock=fail_clock, default_admit=True),
    )
    fail_run = fail_runner.run_family_guided(
        family_id=str(uuid4()),
        candidate_seeds=[b"seed-1"],
        max_rounds=2,
    )
    assert fail_run.campaign_child.state == "FAILED"
    assert fail_run.campaign_child.reason_code == "BUILD_FAILED"
    assert fail_run.state == "COMPLETED"
    assert fail_run.reason_code is None
    assert fail_run.stop_reason_code == "BUILD_FAILED"
    assert fail_run.round_children == ()

    # 1 candidate seed with max_rounds=3 must stop after 1 round instead of
    # repeating the same seed, with stop_reason_code="NO_REMAINING_SEEDS".
    one_seed_clock = FakeClock()
    one_seed_runner = runner_cls(
        sandbox=FakeSandbox(clock=one_seed_clock, replay_faults=("timeout",)),
        clock=one_seed_clock,
        review_gate=FakeReviewGate(clock=one_seed_clock, decision="approve"),
        envelope_policy=FakeEnvelopePolicy(clock=one_seed_clock, default_admit=True),
    )
    one_seed_run = one_seed_runner.run_family_guided(
        family_id=str(uuid4()),
        candidate_seeds=[b"only-seed"],
        max_rounds=3,
    )
    assert len(one_seed_run.round_children) == 1
    assert one_seed_run.state == "COMPLETED"
    assert one_seed_run.reason_code is None
    assert one_seed_run.stop_reason_code == "NO_REMAINING_SEEDS"

    # DefaultIterationGate callers omitting remaining_seeds stay unaffected.
    gate_decision = one_seed_runner.iteration_gate.check_capacity(
        family_id=one_seed_run.family_id,
        completed_round_no=1,
        max_rounds=3,
        last_verdict="INCONCLUSIVE",
    )
    assert gate_decision.should_continue is True
    assert gate_decision.reason_code is None

    # P1 #2: campaign_child.build_ref must match T10's exact closed 4-key
    # contracts._build_ref schema and pass contracts._build_ref validation.
    assert campaign_child.build_ref is not None
    assert set(campaign_child.build_ref.keys()) == {
        "source_job_id",
        "generation",
        "build_inputs_digest",
        "artifacts",
    }
    assert campaign_child.build_ref["source_job_id"] == campaign_child.job_id
    assert campaign_child.build_ref["generation"] == 1
    assert set(campaign_child.build_ref["artifacts"].keys()) == {"vulnerable", "fixed"}
    for version in ("vulnerable", "fixed"):
        assert set(campaign_child.build_ref["artifacts"][version].keys()) == {
            "artifact_digest",
            "build_log_digest",
        }
    validated_build_ref = contracts._build_ref(campaign_child.build_ref)
    assert validated_build_ref == campaign_child.build_ref

    # Pure T10-shaped build_ref (only artifact_digest + build_log_digest, no
    # status key) passed directly into run_child must reach verify -> archive
    # with 0 sandbox.build calls and reproduce cleanly (no REUSE_MISMATCH or
    # INCONCLUSIVE "build did not complete").
    asan_stderr = (
        b"==1==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x602000000014\n"
        b"WRITE of size 4 at 0x602000000014 thread T0\n"
        b"    #0 0x401234 in parse_frame parser.c:42\n"
    )
    t10_clock = FakeClock()
    t10_sandbox = FakeSandbox(
        clock=t10_clock,
        asan_stderr_by_version_phase={
            ("vulnerable", "candidate_1"): asan_stderr,
            ("vulnerable", "candidate_2"): asan_stderr,
        },
    )
    t10_runner = runner_cls(
        sandbox=t10_sandbox,
        clock=t10_clock,
        review_gate=FakeReviewGate(clock=t10_clock, decision="approve"),
        envelope_policy=FakeEnvelopePolicy(clock=t10_clock, default_admit=True),
        verdict_policy=verdict_mod.VerdictPolicy(
            signature={
                "error": "heap-buffer-overflow",
                "function": "parse_frame",
                "source": "parser.c",
            },
            expected_exit={"normal": 0, "candidate_clean": 0, "candidate_asan": 86},
            expected_stdout={"normal": "OK\n", "candidate_clean": "OK\n"},
        ),
    )
    pure_t10_build_ref: dict[str, Any] = {
        "source_job_id": str(uuid4()),
        "generation": 1,
        "build_inputs_digest": "sha256:" + "1" * 64,
        "artifacts": {
            "vulnerable": {
                "artifact_digest": "sha256:" + "2" * 64,
                "build_log_digest": "sha256:" + "3" * 64,
            },
            "fixed": {
                "artifact_digest": "sha256:" + "4" * 64,
                "build_log_digest": "sha256:" + "5" * 64,
            },
        },
    }
    assert contracts._build_ref(pure_t10_build_ref) == pure_t10_build_ref
    t10_reuse_outcome = t10_runner.run_child(
        job_id=str(uuid4()),
        family_id=str(uuid4()),
        job_kind="round",
        round_no=1,
        is_first_plan=False,
        parent_approval_digest="sha256:" + "6" * 64,
        build_ref=pure_t10_build_ref,
        seed_bytes=b"t10-seed",
    )
    assert len(t10_sandbox.build_calls) == 0
    assert len(t10_sandbox.replay_calls) == 6
    assert "verify" in t10_reuse_outcome.visited_nodes
    assert t10_reuse_outcome.terminal_node == "archive"
    assert t10_reuse_outcome.state == "REPRODUCED"
    assert t10_reuse_outcome.verdict == "REPRODUCED"
    assert t10_reuse_outcome.reason_code == "ASAN_SIGNATURE_MATCHED"

    # Malformed T10 build_ref with empty artifact_digest must be rejected by
    # DefaultBuildDiagnoser with REUSE_MISMATCH (0 builds, 0 replays).
    bad_t10_build_ref = {
        "source_job_id": str(uuid4()),
        "generation": 1,
        "build_inputs_digest": "sha256:" + "1" * 64,
        "artifacts": {
            "vulnerable": {
                "artifact_digest": "",
                "build_log_digest": "sha256:" + "3" * 64,
            },
            "fixed": {
                "artifact_digest": "sha256:" + "4" * 64,
                "build_log_digest": "sha256:" + "5" * 64,
            },
        },
    }
    bad_reuse_outcome = t10_runner.run_child(
        job_id=str(uuid4()),
        family_id=str(uuid4()),
        job_kind="round",
        round_no=1,
        is_first_plan=False,
        parent_approval_digest="sha256:" + "6" * 64,
        build_ref=bad_t10_build_ref,
        seed_bytes=b"t10-bad-seed",
    )
    assert len(t10_sandbox.build_calls) == 0
    assert "verify" not in bad_reuse_outcome.visited_nodes
    assert bad_reuse_outcome.terminal_node == "archive"
    assert bad_reuse_outcome.state == "FAILED"
    assert bad_reuse_outcome.reason_code == "REUSE_MISMATCH"

    # P1 #1: Parked non-terminal campaign child (await_review /
    # REVIEW_ENVELOPE_MISMATCH) must keep family in AGGREGATING without
    # invoking prepare -> AGGREGATING -> archive or converging to COMPLETED.
    parked_fam_clock = FakeClock()
    parked_fam_sandbox = FakeSandbox(clock=parked_fam_clock)
    parked_fam_review = FakeReviewGate(
        clock=parked_fam_clock,
        decision="approve",
        expected_envelope_digest="sha256:" + "a" * 64,
        review_deadline_at=parked_fam_clock.now() + timedelta(hours=24),
    )
    parked_fam_runner = runner_cls(
        sandbox=parked_fam_sandbox,
        clock=parked_fam_clock,
        review_gate=parked_fam_review,
        envelope_policy=FakeEnvelopePolicy(clock=parked_fam_clock, default_admit=True),
    )
    parked_fam_id = str(uuid4())
    parked_fam_run = parked_fam_runner.run_family_guided(
        family_id=parked_fam_id,
        candidate_seeds=[b"seed-parked"],
        max_rounds=2,
        envelope_digest="sha256:" + "b" * 64,
    )
    assert parked_fam_run.campaign_child.state == "AWAITING_REVIEW"
    assert parked_fam_run.campaign_child.terminal_node is None
    assert parked_fam_run.campaign_child.reason_code == "REVIEW_ENVELOPE_MISMATCH"
    assert parked_fam_run.state == "AGGREGATING"
    assert parked_fam_run.verdict is None
    assert parked_fam_run.reason_code is None
    assert parked_fam_run.terminal_node is None
    assert parked_fam_run.visited_nodes == ()
    assert parked_fam_run.family_states_observed == ("AGGREGATING",)
    assert parked_fam_run.family_index_digest is None
    assert parked_fam_run.stop_reason_code == "REVIEW_ENVELOPE_MISMATCH"
    assert parked_fam_run.round_children == ()
    assert parked_fam_run.max_concurrent_children == 1
    assert len(parked_fam_run.child_execution_windows) == 1
    assert parked_fam_runner.archive_count(parked_fam_id) == 0
    assert len(parked_fam_sandbox.build_calls) == 0

    # Minor #3: run_family_guided rejects invalid max_rounds, max_total_seconds,
    # and max_fuzz_seconds (negative, NaN, inf, -inf, bool, non-numeric).
    for invalid_rounds in (-1, True, False, 1.5):
        with pytest.raises(ValueError, match="max_rounds"):
            parked_fam_runner.run_family_guided(
                family_id=str(uuid4()),
                candidate_seeds=[b"seed-invalid"],
                max_rounds=invalid_rounds,  # type: ignore[arg-type]
            )
    for invalid_budget in (-0.1, -1, float("nan"), float("inf"), float("-inf"), True, False):
        with pytest.raises(ValueError, match="max_total_seconds"):
            parked_fam_runner.run_family_guided(
                family_id=str(uuid4()),
                candidate_seeds=[b"seed-invalid"],
                max_total_seconds=invalid_budget,  # type: ignore[arg-type]
            )
        with pytest.raises(ValueError, match="max_fuzz_seconds"):
            parked_fam_runner.run_family_guided(
                family_id=str(uuid4()),
                candidate_seeds=[b"seed-invalid"],
                max_fuzz_seconds=invalid_budget,  # type: ignore[arg-type]
            )


def test_family_children_execute_serially():
    clock = FakeClock()
    # Deterministic round-1 INCONCLUSIVE ensures campaign + round 1 + round 2 execute
    # so serial single-slot scheduling is observed across >= 3 child execution windows.
    sandbox = FakeSandbox(clock=clock, replay_faults=("timeout",))
    review_gate = FakeReviewGate(clock=clock, decision="approve")
    envelope_policy = FakeEnvelopePolicy(clock=clock, default_admit=True)

    runner_cls = getattr(workflow, "OrchestrationRunner", None)
    assert runner_cls is not None, (
        "datacon.workflow.OrchestrationRunner is missing (T11): cannot verify "
        "single execution slot serial scheduling across family children"
    )

    runner = runner_cls(
        sandbox=sandbox,
        clock=clock,
        review_gate=review_gate,
        envelope_policy=envelope_policy,
    )
    family_id = str(uuid4())
    family_run = runner.run_family_guided(
        family_id=family_id,
        candidate_seeds=[b"seed-1", b"seed-2"],
        max_rounds=2,
    )

    assert family_run.max_concurrent_children == 1, (
        f"two family children ran concurrently: max_concurrent_children={family_run.max_concurrent_children}"
    )
    assert "RUNNING" not in family_run.family_states_observed, (
        f"family job must use AGGREGATING rather than RUNNING: observed={family_run.family_states_observed}"
    )
    assert "PREPARING" not in family_run.family_states_observed, (
        f"v2 family job starts in AGGREGATING rather than PREPARING: observed={family_run.family_states_observed}"
    )
    assert "AGGREGATING" in family_run.family_states_observed, (
        f"family job must enter AGGREGATING while children run: observed={family_run.family_states_observed}"
    )
    assert family_run.family_states_observed == ("AGGREGATING", "COMPLETED"), (
        f"expected family lifecycle ('AGGREGATING', 'COMPLETED'), got {family_run.family_states_observed}"
    )

    timeline = family_run.child_execution_windows
    assert len(timeline) >= 3, (
        f"expected execution windows for campaign + 2 rounds, got {len(timeline)}"
    )
    for prev, nxt in zip(timeline, timeline[1:]):
        assert nxt.started_at >= prev.finished_at, (
            f"child {nxt.job_id} started at {nxt.started_at} before previous child "
            f"{prev.job_id} finished at {prev.finished_at}"
        )

    # Real multi-threaded mutual exclusion (D29): concurrent run_child calls on
    # the same family_id must serialize (max_concurrent_children == 1), while
    # independent family_ids are allowed to execute concurrently.
    same_family_clock = FakeClock()
    same_family_delegate = FakeSandbox(clock=same_family_clock)
    first_entered = threading.Event()
    second_entered = threading.Event()
    release_first = threading.Event()
    concurrency_lock = threading.Lock()
    active_same_family = 0
    peak_same_family = 0
    first_thread_id: int | None = None

    class _SameFamilyConcurrencySandbox:
        def probe(self, *, deadline_seconds: float = 120.0):
            return same_family_delegate.probe(deadline_seconds=deadline_seconds)

        def build(
            self,
            version: str,
            *,
            compile_args: Sequence[str] = (),
            deadline_seconds: float = 300.0,
            expected_materials: Mapping[str, str] | None = None,
        ):
            nonlocal active_same_family, peak_same_family, first_thread_id
            current_tid = threading.get_ident()
            is_first_call = False
            with concurrency_lock:
                if first_thread_id is None:
                    first_thread_id = current_tid
                    is_first_call = True
                elif current_tid != first_thread_id:
                    second_entered.set()
                active_same_family += 1
                peak_same_family = max(peak_same_family, active_same_family)
            try:
                if is_first_call:
                    first_entered.set()
                    assert release_first.wait(timeout=5.0)
                return same_family_delegate.build(
                    version,
                    compile_args=compile_args,
                    deadline_seconds=deadline_seconds,
                    expected_materials=expected_materials,
                )
            finally:
                with concurrency_lock:
                    active_same_family -= 1

        def replay(
            self,
            version: str,
            phase: str,
            *,
            timeout_seconds: float = 10.0,
            deadline_seconds: float | None = None,
            expected_artifact_digest: str | None = None,
            expected_input_digest: str | None = None,
        ):
            return same_family_delegate.replay(
                version,
                phase,
                timeout_seconds=timeout_seconds,
                deadline_seconds=deadline_seconds,
                expected_artifact_digest=expected_artifact_digest,
                expected_input_digest=expected_input_digest,
            )

    concurrent_runner = runner_cls(
        sandbox=_SameFamilyConcurrencySandbox(),
        clock=same_family_clock,
        review_gate=FakeReviewGate(clock=same_family_clock, decision="approve"),
        envelope_policy=FakeEnvelopePolicy(clock=same_family_clock, default_admit=True),
    )
    shared_family_id = str(uuid4())
    outcomes: list[workflow.ChildRunOutcome] = []
    errors: list[BaseException] = []
    outcomes_lock = threading.Lock()
    second_started = threading.Event()

    def _run_one(round_no: int, signal_start: threading.Event | None = None) -> None:
        try:
            if signal_start is not None:
                signal_start.set()
            result = concurrent_runner.run_child(
                job_id=str(uuid4()),
                family_id=shared_family_id,
                job_kind="round",
                round_no=round_no,
                is_first_plan=True,
            )
            with outcomes_lock:
                outcomes.append(result)
        except BaseException as exc:  # noqa: BLE001
            with outcomes_lock:
                errors.append(exc)

    t1 = threading.Thread(target=_run_one, args=(1,))
    t2 = threading.Thread(target=_run_one, args=(2, second_started))
    t1.start()
    assert first_entered.wait(timeout=5.0)
    t2.start()
    assert second_started.wait(timeout=5.0)
    assert not second_entered.wait(timeout=0.05), (
        "second child of the same family entered build while first child held the slot"
    )
    release_first.set()
    t1.join(timeout=5.0)
    t2.join(timeout=5.0)
    assert not errors, f"concurrent same-family run_child raised: {errors!r}"
    assert len(outcomes) == 2
    assert peak_same_family == 1
    assert concurrent_runner.max_concurrent_children(shared_family_id) == 1
    ordered = sorted(outcomes, key=lambda item: item.started_at or same_family_clock.now())
    assert ordered[0].finished_at is not None and ordered[1].started_at is not None
    assert ordered[1].started_at >= ordered[0].finished_at

    # Independent family_ids must NOT block one another on a global lock.
    indep_clock = FakeClock()
    indep_delegate = FakeSandbox(clock=indep_clock)
    barrier = threading.Barrier(2, timeout=5.0)
    indep_first_per_thread = threading.local()

    class _IndependentFamiliesBarrierSandbox:
        def probe(self, *, deadline_seconds: float = 120.0):
            return indep_delegate.probe(deadline_seconds=deadline_seconds)

        def build(
            self,
            version: str,
            *,
            compile_args: Sequence[str] = (),
            deadline_seconds: float = 300.0,
            expected_materials: Mapping[str, str] | None = None,
        ):
            if not getattr(indep_first_per_thread, "synced", False):
                indep_first_per_thread.synced = True
                barrier.wait()
            return indep_delegate.build(
                version,
                compile_args=compile_args,
                deadline_seconds=deadline_seconds,
                expected_materials=expected_materials,
            )

        def replay(
            self,
            version: str,
            phase: str,
            *,
            timeout_seconds: float = 10.0,
            deadline_seconds: float | None = None,
            expected_artifact_digest: str | None = None,
            expected_input_digest: str | None = None,
        ):
            return indep_delegate.replay(
                version,
                phase,
                timeout_seconds=timeout_seconds,
                deadline_seconds=deadline_seconds,
                expected_artifact_digest=expected_artifact_digest,
                expected_input_digest=expected_input_digest,
            )

    indep_runner = runner_cls(
        sandbox=_IndependentFamiliesBarrierSandbox(),
        clock=indep_clock,
        review_gate=FakeReviewGate(clock=indep_clock, decision="approve"),
        envelope_policy=FakeEnvelopePolicy(clock=indep_clock, default_admit=True),
    )
    indep_errors: list[BaseException] = []

    def _run_independent(fam_id: str) -> None:
        try:
            indep_runner.run_child(
                job_id=str(uuid4()),
                family_id=fam_id,
                job_kind="round",
                round_no=1,
                is_first_plan=True,
            )
        except BaseException as exc:  # noqa: BLE001
            indep_errors.append(exc)

    fam_a, fam_b = str(uuid4()), str(uuid4())
    ta = threading.Thread(target=_run_independent, args=(fam_a,))
    tb = threading.Thread(target=_run_independent, args=(fam_b,))
    ta.start()
    tb.start()
    ta.join(timeout=5.0)
    tb.join(timeout=5.0)
    assert not indep_errors, (
        f"independent family_ids failed to run concurrently: {indep_errors!r}"
    )
    assert indep_runner.max_concurrent_children(fam_a) == 1
    assert indep_runner.max_concurrent_children(fam_b) == 1


@pytest.mark.parametrize(
    ("reason_code", "sub_reason", "source_id"),
    [
        ("MATERIAL_MISSING", "FETCH_TIMEOUT", "nvd-api"),
        ("MATERIAL_MISSING", "REDIRECT_LIMIT_EXCEEDED", "github-advisory"),
        ("SOURCE_CONFLICT", "DIGEST_MISMATCH", "debian-tracker"),
        ("POLICY_DENIED", "LICENSE_REJECTED", "proprietary-feed"),
    ],
)
def test_intel_blocked_preserves_sub_reason_in_archive_and_audit(
    reason_code: str,
    sub_reason: str,
    source_id: str,
):
    class _BlockedIntelProvider:
        def resolve_intel(
            self,
            *,
            job_id: str,
            family_id: str,
            request: Mapping[str, Any],
        ) -> workflow.IntelResult:
            del job_id, family_id, request
            return workflow.IntelResult(
                status="blocked",
                snapshot_digest=None,
                reason_code=reason_code,
                message=f"intel blocked: {reason_code}",
                summary={"sub_reason": sub_reason, "source_id": source_id},
            )

    clock = FakeClock()
    sandbox = FakeSandbox(clock=clock)
    ledger = workflow.NodeReentryLedger()
    runner = workflow.OrchestrationRunner(
        sandbox=sandbox,
        clock=clock,
        intel_provider=_BlockedIntelProvider(),
        ledger=ledger,
    )
    job_id = str(uuid4())
    family_id = str(uuid4())
    outcome = runner.run_child(
        job_id=job_id,
        family_id=family_id,
        job_kind="round",
        round_no=1,
        target_kind="source",
    )

    assert outcome.terminal_node == "archive"
    assert outcome.state == "BLOCKED"
    assert outcome.reason_code == reason_code
    assert "version" not in outcome.visited_nodes
    assert len(sandbox.build_calls) == 0

    expected_summary = {"sub_reason": sub_reason, "source_id": source_id}
    assert outcome.intel_summary == expected_summary

    archives = ledger.archives_for_job(job_id)
    assert len(archives) == 1
    assert archives[0].intel_summary == expected_summary

    events = runner.audit_events(job_id)
    assert len(events) == 1
    assert outcome.audit_events == events
    event = events[0]
    assert isinstance(event, workflow.AuditEventRecord)
    assert event.job_id == job_id
    assert event.family_id == family_id
    assert event.stage == "intel"
    assert event.step_key == "intel"
    assert event.attempt_no == 1
    assert event.event_type == "intel_blocked"
    assert event.reason_code == reason_code
    assert event.detail == expected_summary
    assert event.recorded_at

    # Mutating returned snapshots must not corrupt ledger internals.
    assert isinstance(outcome.intel_summary, dict)
    outcome.intel_summary["sub_reason"] = "MUTATED"
    assert isinstance(event.detail, dict)
    event.detail["sub_reason"] = "MUTATED"
    assert ledger.archives_for_job(job_id)[0].intel_summary == expected_summary
    assert runner.audit_events(job_id)[0].detail == expected_summary


def test_intel_ready_preserves_summary_digest_and_audit():
    digest_a = "sha256:" + "a" * 64
    digest_b = "sha256:" + "b" * 64
    redirect_digest = "sha256:" + "c" * 64

    class _ReadyIntelProvider:
        def __init__(self, snapshot_digest: str, license_id: str) -> None:
            self._snapshot_digest = snapshot_digest
            self._license_id = license_id

        def resolve_intel(
            self,
            *,
            job_id: str,
            family_id: str,
            request: Mapping[str, Any],
        ) -> workflow.IntelResult:
            del job_id, family_id, request
            return workflow.IntelResult(
                status="ready",
                snapshot_digest=self._snapshot_digest,
                summary={
                    "license": self._license_id,
                    "source_url": "https://advisories.example.org/cve-2099-0001",
                    "redirect_chain_digest": redirect_digest,
                },
            )

    job_id = str(uuid4())
    family_id = str(uuid4())

    def _run_with(snapshot_digest: str, license_id: str):
        clock = FakeClock()
        sandbox = FakeSandbox(clock=clock)
        ledger = workflow.NodeReentryLedger()
        runner = workflow.OrchestrationRunner(
            sandbox=sandbox,
            clock=clock,
            intel_provider=_ReadyIntelProvider(snapshot_digest, license_id),
            review_gate=FakeReviewGate(clock=clock, decision="approve"),
            envelope_policy=FakeEnvelopePolicy(clock=clock, default_admit=True),
            ledger=ledger,
        )
        outcome = runner.run_child(
            job_id=job_id,
            family_id=family_id,
            job_kind="round",
            round_no=1,
            target_kind="source",
            is_first_plan=True,
        )
        return runner, ledger, outcome

    runner_a, ledger_a, outcome_a = _run_with(digest_a, "MIT")
    expected_summary_a = {
        "snapshot_digest": digest_a,
        "license": "MIT",
        "source_url": "https://advisories.example.org/cve-2099-0001",
        "redirect_chain_digest": redirect_digest,
    }
    assert outcome_a.terminal_node == "archive"
    assert "version" in outcome_a.visited_nodes
    assert "verify" in outcome_a.visited_nodes
    assert outcome_a.intel_summary == expected_summary_a

    archives_a = ledger_a.archives_for_job(job_id)
    assert len(archives_a) == 1
    assert archives_a[0].intel_summary == expected_summary_a

    events_a = runner_a.audit_events(job_id)
    assert len(events_a) == 1
    assert outcome_a.audit_events == events_a
    assert events_a[0].event_type == "intel_resolved"
    assert events_a[0].reason_code is None
    assert events_a[0].stage == "intel"
    assert events_a[0].detail == expected_summary_a

    # Deterministic archive_digest changes when intel_summary changes and stays
    # identical when intel_summary is unchanged.
    _, _, outcome_a_repeat = _run_with(digest_a, "MIT")
    assert outcome_a_repeat.archive_digest == outcome_a.archive_digest

    _, _, outcome_b = _run_with(digest_b, "Apache-2.0")
    assert outcome_b.archive_digest != outcome_a.archive_digest
    assert outcome_b.intel_summary is not None
    assert outcome_b.intel_summary["snapshot_digest"] == digest_b
    assert outcome_b.intel_summary["license"] == "Apache-2.0"


def test_intel_exception_and_blank_snapshot_digest_fail_closed():
    sensitive_body = "RAW_ADVISORY_SECRET_BODY_TOKEN_98765"

    class _StructuredIntelError(RuntimeError):
        def __init__(
            self,
            message: str,
            *,
            reason_code: str | None = None,
            sub_reason: Any = None,
            source_id: Any = None,
        ) -> None:
            super().__init__(message)
            self.reason_code = reason_code
            self.sub_reason = sub_reason
            self.source_id = source_id

    class _RaisingIntelProvider:
        def __init__(self, exc: Exception) -> None:
            self._exc = exc

        def resolve_intel(
            self,
            *,
            job_id: str,
            family_id: str,
            request: Mapping[str, Any],
        ) -> workflow.IntelResult:
            del job_id, family_id, request
            raise self._exc

    clock = FakeClock()
    sandbox = FakeSandbox(clock=clock)
    ledger = workflow.NodeReentryLedger()
    runner = workflow.OrchestrationRunner(
        sandbox=sandbox,
        clock=clock,
        intel_provider=_RaisingIntelProvider(
            _StructuredIntelError(
                f"upstream rejected payload: {sensitive_body}",
                reason_code="POLICY_DENIED",
                sub_reason="LICENSE_REJECTED",
                source_id="restricted-mirror",
            )
        ),
        ledger=ledger,
    )
    job_id = str(uuid4())
    outcome = runner.run_child(
        job_id=job_id,
        family_id=str(uuid4()),
        job_kind="round",
        round_no=1,
        target_kind="source",
    )
    assert outcome.terminal_node == "archive"
    assert outcome.state == "BLOCKED"
    assert outcome.reason_code == "POLICY_DENIED"
    assert outcome.intel_summary == {
        "sub_reason": "LICENSE_REJECTED",
        "source_id": "restricted-mirror",
    }
    archives = ledger.archives_for_job(job_id)
    assert len(archives) == 1
    assert archives[0].intel_summary == outcome.intel_summary
    assert len(outcome.audit_events) == 1
    event = outcome.audit_events[0]
    assert event.event_type == "intel_blocked"
    assert event.reason_code == "POLICY_DENIED"
    assert event.detail == {
        "sub_reason": "LICENSE_REJECTED",
        "source_id": "restricted-mirror",
    }
    assert sensitive_body not in repr(outcome.intel_summary)
    assert sensitive_body not in repr(archives[0].intel_summary)
    assert sensitive_body not in repr(event.detail)

    # Blank/non-string sub_reason and source_id are omitted without leaking str(error).
    blank_ledger = workflow.NodeReentryLedger()
    blank_runner = workflow.OrchestrationRunner(
        sandbox=FakeSandbox(clock=FakeClock()),
        clock=FakeClock(),
        intel_provider=_RaisingIntelProvider(
            _StructuredIntelError(
                f"timeout with body {sensitive_body}",
                reason_code="MATERIAL_MISSING",
                sub_reason="   ",
                source_id=None,
            )
        ),
        ledger=blank_ledger,
    )
    blank_job_id = str(uuid4())
    blank_outcome = blank_runner.run_child(
        job_id=blank_job_id,
        family_id=str(uuid4()),
        job_kind="round",
        round_no=1,
        target_kind="source",
    )
    assert blank_outcome.state == "BLOCKED"
    assert blank_outcome.reason_code == "MATERIAL_MISSING"
    assert blank_outcome.intel_summary is None
    assert len(blank_outcome.audit_events) == 1
    assert blank_outcome.audit_events[0].detail == {}
    assert sensitive_body not in repr(blank_outcome.audit_events[0].detail)

    # Unstructured exception without reason_code propagates.
    unstructured_runner = workflow.OrchestrationRunner(
        sandbox=FakeSandbox(clock=FakeClock()),
        clock=FakeClock(),
        intel_provider=_RaisingIntelProvider(RuntimeError("unexpected crash")),
    )
    with pytest.raises(RuntimeError, match="unexpected crash"):
        unstructured_runner.run_child(
            job_id=str(uuid4()),
            family_id=str(uuid4()),
            job_kind="round",
            round_no=1,
            target_kind="source",
        )

    # status="ready" with missing/blank snapshot_digest fails closed with
    # MATERIAL_MISSING, preserves existing summary fields, and populates
    # detail["sub_reason"] == "SNAPSHOT_DIGEST_MISSING".
    for bad_digest in (None, "", "   "):

        class _BlankDigestProvider:
            def __init__(self, digest: str | None) -> None:
                self._digest = digest

            def resolve_intel(
                self,
                *,
                job_id: str,
                family_id: str,
                request: Mapping[str, Any],
            ) -> workflow.IntelResult:
                del job_id, family_id, request
                return workflow.IntelResult(
                    status="ready",
                    snapshot_digest=self._digest,
                    summary={"source": "unverified", "license": "MIT"},
                )

        bd_ledger = workflow.NodeReentryLedger()
        bd_runner = workflow.OrchestrationRunner(
            sandbox=FakeSandbox(clock=FakeClock()),
            clock=FakeClock(),
            intel_provider=_BlankDigestProvider(bad_digest),
            ledger=bd_ledger,
        )
        bd_job_id = str(uuid4())
        bd_outcome = bd_runner.run_child(
            job_id=bd_job_id,
            family_id=str(uuid4()),
            job_kind="round",
            round_no=1,
            target_kind="source",
        )
        expected_bd_summary = {
            "source": "unverified",
            "license": "MIT",
            "sub_reason": "SNAPSHOT_DIGEST_MISSING",
        }
        assert bd_outcome.terminal_node == "archive"
        assert bd_outcome.state == "BLOCKED"
        assert bd_outcome.reason_code == "MATERIAL_MISSING"
        assert bd_outcome.intel_summary == expected_bd_summary
        assert bd_ledger.archives_for_job(bd_job_id)[0].intel_summary == expected_bd_summary
        assert len(bd_outcome.audit_events) == 1
        assert bd_outcome.audit_events[0].event_type == "intel_blocked"
        assert bd_outcome.audit_events[0].reason_code == "MATERIAL_MISSING"
        assert bd_outcome.audit_events[0].detail == expected_bd_summary


def test_intel_and_archive_reentry_deduplicates_audit_and_preserves_first_write():
    digest_1 = "sha256:" + "1" * 64
    digest_2 = "sha256:" + "2" * 64

    class _CountingIntelProvider:
        def __init__(self) -> None:
            self.calls = 0
            self.current_digest = digest_1
            self.current_license = "MIT"

        def resolve_intel(
            self,
            *,
            job_id: str,
            family_id: str,
            request: Mapping[str, Any],
        ) -> workflow.IntelResult:
            del job_id, family_id, request
            self.calls += 1
            return workflow.IntelResult(
                status="ready",
                snapshot_digest=self.current_digest,
                summary={"license": self.current_license, "call": self.calls},
            )

    provider = _CountingIntelProvider()
    clock = FakeClock()
    sandbox = FakeSandbox(clock=clock)
    ledger = workflow.NodeReentryLedger()
    runner = workflow.OrchestrationRunner(
        sandbox=sandbox,
        clock=clock,
        intel_provider=provider,
        review_gate=FakeReviewGate(clock=clock, decision="approve"),
        envelope_policy=FakeEnvelopePolicy(clock=clock, default_admit=True),
        ledger=ledger,
    )
    job_id = str(uuid4())
    family_id = str(uuid4())

    first = runner.run_child(
        job_id=job_id,
        family_id=family_id,
        job_kind="round",
        round_no=1,
        generation=1,
        is_first_plan=True,
    )
    assert provider.calls == 1
    assert len(runner.audit_events(job_id)) == 1
    assert runner.archive_count(job_id) == 1
    assert first.intel_summary == {
        "snapshot_digest": digest_1,
        "license": "MIT",
        "call": 1,
    }

    # Same StepKey re-entry must be a pure no-op: no duplicate audit event,
    # no second resolve_intel call, and identical archive digest/summary.
    second = runner.run_child(
        job_id=job_id,
        family_id=family_id,
        job_kind="round",
        round_no=1,
        generation=1,
        is_first_plan=True,
    )
    assert provider.calls == 1
    assert len(runner.audit_events(job_id)) == 1
    assert runner.archive_count(job_id) == 1
    assert second.archive_digest == first.archive_digest
    assert second.intel_summary == first.intel_summary
    assert second.audit_events == first.audit_events

    # Cross-generation re-entry with changed provider output still preserves
    # first-write-wins archive_digest, ArchiveRecord.intel_summary, and
    # deduplicates audit_events on (job_id, stage, step_key, attempt_no, event_type).
    provider.current_digest = digest_2
    provider.current_license = "BSD-3-Clause"
    gen2 = runner.run_child(
        job_id=job_id,
        family_id=family_id,
        job_kind="round",
        round_no=1,
        generation=2,
        is_first_plan=True,
    )
    assert provider.calls == 2
    assert len(runner.audit_events(job_id)) == 1
    assert runner.audit_events(job_id)[0].detail == first.intel_summary
    assert runner.archive_count(job_id) == 1
    assert gen2.archive_digest == first.archive_digest
    assert gen2.intel_summary == first.intel_summary
    assert ledger.archives_for_job(job_id)[0].intel_summary == first.intel_summary

    # Direct execute_node re-entry on intel and archive with same StepKey.
    node_job_id = str(uuid4())
    intel_key = (node_job_id, "intel", "intel_step", 1, 1)
    first_intel = runner.execute_node(family_id=family_id, idempotency_key=intel_key)
    second_intel = runner.execute_node(family_id=family_id, idempotency_key=intel_key)
    assert second_intel == first_intel
    assert len(runner.audit_events(node_job_id)) == 1

    # Direct AuditEventStore idempotency contract on NodeReentryLedger.
    direct_job = str(uuid4())
    assert (
        ledger.record_audit_event(
            job_id=direct_job,
            family_id=family_id,
            stage="intel",
            step_key="intel",
            attempt_no=1,
            event_type="intel_resolved",
            reason_code=None,
            detail={"snapshot_digest": digest_1},
            recorded_at=clock.timestamp(),
        )
        is True
    )
    assert (
        ledger.record_audit_event(
            job_id=direct_job,
            family_id=family_id,
            stage="intel",
            step_key="intel",
            attempt_no=1,
            event_type="intel_resolved",
            reason_code=None,
            detail={"snapshot_digest": digest_2},
            recorded_at=clock.timestamp(),
        )
        is False
    )
    assert len(ledger.audit_events_for_job(direct_job)) == 1
    assert ledger.audit_events_for_job(direct_job)[0].detail == {
        "snapshot_digest": digest_1
    }

    # Regression: first-write-wins when gen 1 archives with intel_summary=None
    # (blocked with empty summary) and gen 2 re-enters with non-empty intel_summary.
    class _ToggleIntelProvider:
        def __init__(self) -> None:
            self.ready = False

        def resolve_intel(
            self,
            *,
            job_id: str,
            family_id: str,
            request: Mapping[str, Any],
        ) -> workflow.IntelResult:
            del job_id, family_id, request
            if not self.ready:
                return workflow.IntelResult(
                    status="blocked",
                    snapshot_digest=None,
                    reason_code="MATERIAL_MISSING",
                    summary={},
                )
            return workflow.IntelResult(
                status="ready",
                snapshot_digest=digest_2,
                summary={"license": "MIT"},
            )

    toggle_provider = _ToggleIntelProvider()
    toggle_clock = FakeClock()
    toggle_ledger = workflow.NodeReentryLedger()
    toggle_runner = workflow.OrchestrationRunner(
        sandbox=FakeSandbox(clock=toggle_clock),
        clock=toggle_clock,
        intel_provider=toggle_provider,
        review_gate=FakeReviewGate(clock=toggle_clock, decision="approve"),
        envelope_policy=FakeEnvelopePolicy(clock=toggle_clock, default_admit=True),
        ledger=toggle_ledger,
    )
    toggle_job_id = str(uuid4())
    toggle_gen1 = toggle_runner.run_child(
        job_id=toggle_job_id,
        family_id=family_id,
        job_kind="round",
        round_no=1,
        generation=1,
        is_first_plan=True,
    )
    assert toggle_gen1.state == "BLOCKED"
    assert toggle_gen1.intel_summary is None
    assert toggle_ledger.archives_for_job(toggle_job_id)[0].intel_summary is None

    toggle_provider.ready = True
    toggle_gen2 = toggle_runner.run_child(
        job_id=toggle_job_id,
        family_id=family_id,
        job_kind="round",
        round_no=1,
        generation=2,
        is_first_plan=True,
    )
    assert toggle_gen2.archive_digest == toggle_gen1.archive_digest
    assert toggle_gen2.state == toggle_gen1.state
    assert toggle_gen2.intel_summary is None
    assert toggle_ledger.archives_for_job(toggle_job_id)[0].intel_summary is None


def test_intel_archive_audit_backward_compatibility_and_exports():
    # Export parity between orchestration and workflow.
    assert workflow.AuditEventRecord is orchestration.AuditEventRecord
    assert workflow.AuditEventStore is orchestration.AuditEventStore
    assert "AuditEventRecord" in orchestration.__all__
    assert "AuditEventStore" in orchestration.__all__
    assert isinstance(workflow.NodeReentryLedger(), workflow.AuditEventStore)

    # Legacy 8-positional-arg ArchiveRecord construction still defaults intel_summary=None.
    legacy_rec = workflow.ArchiveRecord(
        "job-1",
        "fam-1",
        "round",
        "REPRODUCED",
        "REPRODUCED",
        "ASAN_SIGNATURE_MATCHED",
        "sha256:" + "0" * 64,
        "2099-01-01T00:00:00Z",
    )
    assert legacy_rec.intel_summary is None

    # 1. Legacy ChargeArchiveStore (no AuditEventStore, no intel_summary param)
    #    paired with a custom AttemptStore (no AuditEventStore) -> falls back
    #    cleanly to a fresh AuditEventStore.
    class _LegacyChargeArchiveStore:
        def __init__(self) -> None:
            self.archives: dict[str, workflow.ArchiveRecord] = {}
            self.charges: list[tuple[str, float]] = []

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
            del family_id, step_key, attempt_no, recorded_at, fuzz_seconds, charge_kind
            self.charges.append((job_id, float(seconds)))
            return True

        def charge_count(self, job_id: str) -> int:
            return sum(1 for jid, _ in self.charges if jid == job_id)

        def total_charged_seconds(self, family_id: str) -> float:
            del family_id
            return sum(sec for _, sec in self.charges)

        def total_fuzz_seconds(self, family_id: str) -> float:
            del family_id
            return 0.0

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
        ) -> workflow.ArchiveRecord:
            rec = workflow.ArchiveRecord(
                job_id=job_id,
                family_id=family_id,
                job_kind=job_kind,
                state=state,
                verdict=verdict,
                reason_code=reason_code,
                archive_digest=archive_digest,
                recorded_at=recorded_at,
            )
            self.archives.setdefault(job_id, rec)
            return self.archives[job_id]

        def archive_count(self, job_id: str) -> int:
            return 1 if job_id in self.archives else 0

    class _AttemptOnlyStore:
        def __init__(self) -> None:
            self.records: dict[workflow.StepKey, dict[str, Any]] = {}

        def get_completed(self, key: workflow.StepKey) -> dict[str, Any] | None:
            cached = self.records.get(key)
            return dict(cached) if cached is not None else None

        def record_completed(
            self,
            key: workflow.StepKey,
            result: Mapping[str, Any],
        ) -> dict[str, Any]:
            self.records[key] = dict(result)
            return dict(result)

    legacy_store = _LegacyChargeArchiveStore()
    attempt_only = _AttemptOnlyStore()
    assert not isinstance(legacy_store, workflow.AuditEventStore)
    assert not isinstance(attempt_only, workflow.AuditEventStore)
    legacy_clock = FakeClock()
    legacy_runner = workflow.OrchestrationRunner(
        sandbox=FakeSandbox(clock=legacy_clock),
        clock=legacy_clock,
        ledger=legacy_store,
        attempt_store=attempt_only,
    )
    legacy_job = str(uuid4())
    legacy_outcome = legacy_runner.run_child(
        job_id=legacy_job,
        family_id=str(uuid4()),
        job_kind="round",
        round_no=1,
        is_first_plan=True,
    )
    assert legacy_outcome.terminal_node == "archive"
    assert legacy_store.archive_count(legacy_job) == 1
    assert legacy_outcome.intel_summary is not None
    assert "snapshot_digest" in legacy_outcome.intel_summary
    assert len(legacy_outcome.audit_events) == 1
    assert legacy_outcome.audit_events[0].event_type == "intel_resolved"

    # Tier-2 fallback: ledger is NOT AuditEventStore, attempt_store IS AuditEventStore ->
    # audit events land on attempt_store.
    tier2_legacy_store = _LegacyChargeArchiveStore()
    tier2_attempt_ledger = workflow.NodeReentryLedger()
    tier2_clock = FakeClock()
    tier2_runner = workflow.OrchestrationRunner(
        sandbox=FakeSandbox(clock=tier2_clock),
        clock=tier2_clock,
        ledger=tier2_legacy_store,
        attempt_store=tier2_attempt_ledger,
    )
    assert tier2_runner.audit_store is tier2_attempt_ledger
    tier2_job = str(uuid4())
    tier2_outcome = tier2_runner.run_child(
        job_id=tier2_job,
        family_id=str(uuid4()),
        job_kind="round",
        round_no=1,
        is_first_plan=True,
    )
    assert len(tier2_attempt_ledger.audit_events_for_job(tier2_job)) == 1
    assert tier2_outcome.audit_events == tier2_attempt_ledger.audit_events_for_job(
        tier2_job
    )

    # 2. NodeReentryLedger subclass overriding record_archive WITHOUT intel_summary
    #    (matching PR #45 _RecordingLedger pattern) must work seamlessly.
    class _RecordingLedger(workflow.NodeReentryLedger):
        def __init__(self) -> None:
            super().__init__()
            self.recorded_archives: list[str] = []

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
        ) -> workflow.ArchiveRecord:
            self.recorded_archives.append(job_id)
            return super().record_archive(
                job_id=job_id,
                family_id=family_id,
                job_kind=job_kind,
                state=state,
                verdict=verdict,
                reason_code=reason_code,
                archive_digest=archive_digest,
                recorded_at=recorded_at,
            )

    rec_ledger = _RecordingLedger()
    rec_clock = FakeClock()
    rec_runner = workflow.OrchestrationRunner(
        sandbox=FakeSandbox(clock=rec_clock),
        clock=rec_clock,
        ledger=rec_ledger,
    )
    rec_job = str(uuid4())
    rec_outcome = rec_runner.run_child(
        job_id=rec_job,
        family_id=str(uuid4()),
        job_kind="round",
        round_no=1,
        is_first_plan=True,
    )
    assert rec_outcome.terminal_node == "archive"
    assert rec_ledger.recorded_archives == [rec_job]
    assert rec_outcome.intel_summary is not None
    assert "snapshot_digest" in rec_outcome.intel_summary
    assert len(rec_runner.audit_events(rec_job)) == 1

    # 3. Standalone injected AuditEventStore receives events instead of ledger.
    class _StandaloneAuditStore:
        def __init__(self) -> None:
            self._keys: set[tuple[str, str, str, int, str]] = set()
            self._events: dict[str, list[workflow.AuditEventRecord]] = {}

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
            key = (job_id, stage, step_key, attempt_no, event_type)
            if key in self._keys:
                return False
            self._keys.add(key)
            rec = workflow.AuditEventRecord(
                job_id=job_id,
                family_id=family_id,
                stage=stage,
                step_key=step_key,
                attempt_no=attempt_no,
                event_type=event_type,
                reason_code=reason_code,
                detail=dict(detail or {}),
                recorded_at=recorded_at,
            )
            self._events.setdefault(job_id, []).append(rec)
            return True

        def audit_events_for_job(
            self, job_id: str
        ) -> tuple[workflow.AuditEventRecord, ...]:
            return tuple(self._events.get(job_id, ()))

    standalone_audit = _StandaloneAuditStore()
    assert isinstance(standalone_audit, workflow.AuditEventStore)
    sa_ledger = workflow.NodeReentryLedger()
    sa_clock = FakeClock()
    sa_runner = workflow.OrchestrationRunner(
        sandbox=FakeSandbox(clock=sa_clock),
        clock=sa_clock,
        ledger=sa_ledger,
        audit_store=standalone_audit,
    )
    sa_job = str(uuid4())
    sa_outcome = sa_runner.run_child(
        job_id=sa_job,
        family_id=str(uuid4()),
        job_kind="round",
        round_no=1,
        is_first_plan=True,
    )
    assert len(standalone_audit.audit_events_for_job(sa_job)) == 1
    assert sa_outcome.audit_events == standalone_audit.audit_events_for_job(sa_job)
    assert sa_runner.audit_events(sa_job) == sa_outcome.audit_events
    assert sa_ledger.audit_events_for_job(sa_job) == ()
    assert (
        workflow.build_v2_graph(
            sandbox=FakeSandbox(clock=sa_clock),
            clock=sa_clock,
            ledger=legacy_store,
            audit_store=standalone_audit,
        )
        is not None
    )

    # 4. Family node archive must NOT pollute intel_summary (stays None).
    fam_clock = FakeClock()
    fam_ledger = workflow.NodeReentryLedger()
    fam_runner = workflow.OrchestrationRunner(
        sandbox=FakeSandbox(clock=fam_clock),
        clock=fam_clock,
        review_gate=FakeReviewGate(clock=fam_clock, decision="approve"),
        envelope_policy=FakeEnvelopePolicy(clock=fam_clock, default_admit=True),
        ledger=fam_ledger,
    )
    fam_id = str(uuid4())
    fam_run = fam_runner.run_family_guided(
        family_id=fam_id,
        candidate_seeds=[b"seed-family-1"],
        max_rounds=1,
    )
    assert fam_run.state == "COMPLETED"
    fam_archives = fam_ledger.archives_for_job(fam_id)
    assert len(fam_archives) == 1
    assert fam_archives[0].intel_summary is None
    assert fam_run.campaign_child.intel_summary is not None
    assert "snapshot_digest" in fam_run.campaign_child.intel_summary
    assert len(fam_run.round_children) == 1
    assert fam_run.round_children[0].intel_summary is not None

    # Even if a family graph state carries a stale intel_summary, _node_archive
    # must ignore it for job_kind="family".
    stale_fam_id = str(uuid4())
    stale_fam_state = fam_runner.graph.invoke(
        {
            "job_id": stale_fam_id,
            "family_id": stale_fam_id,
            "parent_job_id": None,
            "job_kind": "family",
            "round_no": None,
            "generation": 1,
            "intel_summary": {"snapshot_digest": "sha256:" + "9" * 64},
            "family_summary": {"kind": "family_index", "family_id": stale_fam_id},
            "visited_nodes": [],
        }
    )
    assert stale_fam_state["intel_summary"] is None
    assert fam_ledger.archives_for_job(stale_fam_id)[0].intel_summary is None

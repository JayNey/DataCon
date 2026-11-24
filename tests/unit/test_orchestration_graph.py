"""T11 / TC-11 / TC-04: v0.2 target orchestration graph, loops and node idempotency.

Test coordinates are anchored to docs/spec/v0.2/test-plan-delta.md §2 (T11) and
docs/spec/v0.2/README.md §5 (14 nodes and 26 edges).
"""

from __future__ import annotations

from datetime import timedelta
import threading
from typing import Any, Mapping, Sequence
from uuid import uuid4

from fakes import FakeClock, FakeEnvelopePolicy, FakeReviewGate, FakeSandbox
import pytest

from datacon import workflow

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

    # D42: Non-terminal parked review (await_review / REVIEW_ENVELOPE_MISMATCH)
    # must NOT be cached as a completed no-op in NodeReentryLedger, so a retry
    # with the corrected envelope_digest under the same generation succeeds,
    # after which decided review outcomes remain cached as no-ops.
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
    parked_runner = runner_cls(
        sandbox=parked_sandbox,
        clock=parked_clock,
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

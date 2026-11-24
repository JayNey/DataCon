"""T11 / TC-11 / TC-04: v0.2 target orchestration graph, loops and node idempotency.

Test coordinates are anchored to docs/spec/v0.2/test-plan-delta.md §2 (T11) and
docs/spec/v0.2/README.md §5 (14 nodes and 26 edges).
"""

from __future__ import annotations

from datetime import timedelta
from uuid import uuid4

from fakes import FakeClock, FakeEnvelopePolicy, FakeReviewGate, FakeSandbox

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
    assert "AGGREGATING" in family_run.family_states_observed, (
        f"family job must enter AGGREGATING while children run: observed={family_run.family_states_observed}"
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

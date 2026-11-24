"""TC-12/T12 step 1: the exploration envelope and pre-build admission gate.

These are pure contract tests. They build the envelope directly from the
interface-contract-delta §2 field set and exercise the policy boundary with
recording doubles: no PostgreSQL, no Docker, no sleep. The injected fake clock
supplies every timestamp. Budget charging, reuse and status/export belong to
later T12 steps and are deliberately not exercised here.
"""

from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timedelta, timezone
import hashlib
import uuid

from test_plan import PLAN as BASE_PLAN

import pytest

from datacon import contracts, jsonutil, state


def _digest(token: str) -> str:
    return "sha256:" + token * 64


TOOLCHAIN_IMAGE_DIGEST = _digest("a")
EXPLICIT_FUZZ_IMAGE_DIGEST = _digest("b")
SEED_CORPUS_DIGEST = _digest("c")
HARNESS_DIGEST = _digest("d")
APPROVAL_DIGEST = _digest("e")
CAMPAIGN_BUNDLE_DIGEST = _digest("f")
FAMILY_ID = "2f1c0f5e-3d7a-4b6c-9f10-2a4b6c8d0e11"
JOB_ID = "0f8fad5b-d9cb-469f-a165-70867728950e"
ADMISSION_ID = uuid.UUID("7c9e6679-7425-40de-944b-e07fc1f90ae7")
DECIDED_AT = datetime(2099, 1, 1, tzinfo=timezone.utc)

SIGNATURE = {
    "error": "heap-buffer-overflow",
    "function": "parse_token",
    "source": "parser.c",
    "operation": "WRITE",
    "access_size": 1,
}

BUILD_SPEC = {
    "kind": "cmake",
    "configure": [],
    "build": [],
    "install": [],
    "env": {},
    "outputs": [],
    "declared_compile_flags": [],
    "shell_recipe_digest": None,
    "shell_face_digest": None,
    "shell_face_review": None,
}


class FakeClock:
    """A controllable UTC clock; no wall-clock reads and no sleeping."""

    def __init__(self, now: datetime = DECIDED_AT) -> None:
        self.now = now

    def __call__(self) -> datetime:
        return self.now

    def advance(self, seconds: int) -> None:
        self.now += timedelta(seconds=seconds)


class RecordingAdmissionStore:
    """Record every write a policy admission attempts.

    The store exposes review/family-approval methods on purpose: the policy
    path must never call them, so a regression is visible as an unexpected
    call rather than as an unobservable absence.
    """

    def __init__(self) -> None:
        self.calls: list[str] = []
        self.admissions: list[dict] = []
        self.events: list[dict] = []
        self.reviews: list[dict] = []
        self.family_approvals: list[dict] = []
        self.rounds: list[dict] = []

    def record_admission(self, admission) -> None:
        self.calls.append("record_admission")
        self.admissions.append(dict(admission))

    def append_event(self, event) -> None:
        self.calls.append("append_event")
        self.events.append(dict(event))

    def insert_review(self, review) -> None:
        self.calls.append("insert_review")
        self.reviews.append(dict(review))

    def update_family_approval(self, approval) -> None:
        self.calls.append("update_family_approval")
        self.family_approvals.append(dict(approval))

    def create_round(self, round_record) -> None:
        self.calls.append("create_round")
        self.rounds.append(dict(round_record))


def _guided_envelope(**overrides) -> dict:
    body = {
        "allowed_mutation_families": ["byte_flip", "length_boundary"],
        "mutation_limits": {
            "allowed_ops": ["append", "truncate", "byte_flip"],
            "max_input_bytes": 4096,
        },
        "seed_corpus_digest": SEED_CORPUS_DIGEST,
        "toolchain_image_digest": TOOLCHAIN_IMAGE_DIGEST,
        "harness_digest": HARNESS_DIGEST,
        "max_rounds": 8,
        "max_total_seconds": 900,
        "max_fuzz_seconds": 300,
        "accepted_signature_set": [dict(SIGNATURE)],
        "admission_predicate_version": "admission-v1",
    }
    body.update(overrides)
    return contracts.guided_envelope(**body)


def _fixed_envelope() -> dict:
    return contracts.fixed_envelope(
        harness_digest=HARNESS_DIGEST,
        accepted_signature_set=[dict(SIGNATURE)],
        max_total_seconds=900,
        admission_predicate_version="admission-v1",
    )


def _experiment(**overrides) -> dict:
    experiment = {
        "input_family": "length_boundary",
        "mutation_constraints": {
            "allowed_ops": ["append", "truncate"],
            "max_input_bytes": 2048,
        },
        "expected_signature": deepcopy(SIGNATURE),
    }
    experiment.update(overrides)
    return experiment


def _budget_snapshot() -> dict:
    return {
        "remaining_total_seconds": 900,
        "remaining_fuzz_seconds": 300,
    }


def _admit(
    store: RecordingAdmissionStore | None = None,
    *,
    clock: FakeClock | None = None,
    envelope: dict | None = None,
    experiment: dict | None = None,
    round_no: int = 2,
    parent_approval_digest: str | None = APPROVAL_DIGEST,
    approval_chain_tail_digest: str | None = APPROVAL_DIGEST,
    recomputable: bool = True,
    campaign_bundle_digest: str | None = None,
    existing_rounds: tuple[int, ...] = (),
):
    return state.policy_admit_round(
        store=store,
        clock=clock or FakeClock(),
        job_id=JOB_ID,
        parent_job_id=FAMILY_ID,
        envelope=envelope or _guided_envelope(),
        parent_approval_digest=parent_approval_digest,
        approval_chain_tail_digest=approval_chain_tail_digest,
        seed_digest=SEED_CORPUS_DIGEST,
        round_no=round_no,
        budget_snapshot=_budget_snapshot(),
        experiment=experiment,
        recomputable=recomputable,
        campaign_bundle_digest=campaign_bundle_digest,
        admission_id=ADMISSION_ID,
        existing_rounds=existing_rounds,
    )


def _v2_round_plan(envelope_digest: str) -> dict:
    """A valid Plan v2 whose only envelope input is ``envelope_digest``."""
    plan = deepcopy(BASE_PLAN)
    plan.update(
        {
            "schema_version": 2,
            "family_id": FAMILY_ID,
            "parent_job_id": FAMILY_ID,
            "round_no": 2,
            "parent_approval_digest": APPROVAL_DIGEST,
            "envelope_digest": envelope_digest,
            "build_ref": None,
            "build_spec": deepcopy(BUILD_SPEC),
            "compile_flags": [],
            "experiment_digest": None,
            "build_provenance_rules_version": "build-provenance-v1",
            "build_recipe_digest": "sha256:"
            + hashlib.sha256(jsonutil.canonical_bytes(BUILD_SPEC)).hexdigest(),
        }
    )
    return plan


def test_policy_admission_never_writes_review():
    store = RecordingAdmissionStore()
    outcome = _admit(store=store)

    assert outcome.admitted, outcome.reason_code
    assert not store.reviews, "reviews row created for policy admission"
    assert len(store.admissions) == 1, (
        "policy admission did not write exactly one admissions row"
    )
    assert not store.family_approvals, (
        "policy admission modified family_approvals"
    )
    assert "insert_review" not in store.calls
    assert "update_family_approval" not in store.calls
    assert set(store.calls) <= {"record_admission", "append_event"}, (
        "policy admission attempted a non-admission write"
    )

    admission = store.admissions[0]
    assert admission["approval_kind"] == "policy"
    assert admission["parent_approval_digest"] == APPROVAL_DIGEST
    assert admission["decided_at"] == "2099-01-01T00:00:00Z"


def test_out_of_envelope_experiment_is_denied_before_build():
    out_of_envelope = {
        "input_family": "race_window",
        "mutation_constraints": {
            "allowed_ops": ["append"],
            "max_input_bytes": 1024,
        },
        "expected_signature": deepcopy(SIGNATURE),
    }
    signature_outside_set = _experiment(
        expected_signature={**SIGNATURE, "function": "other_function"}
    )

    for label, experiment in (
        ("mutation family", out_of_envelope),
        ("signature set", signature_outside_set),
    ):
        store = RecordingAdmissionStore()
        built: list[str] = []

        outcome = _admit(store=store, experiment=experiment)
        if outcome.admitted:
            # The admission predicate is the only pre-build gate: if it lets
            # this round through, the round would reach the builder.
            built.append(label)

        assert not built, "out-of-envelope round reached build"
        assert outcome.reason_code == "ENVELOPE_VIOLATION"
        assert not store.admissions, (
            f"out-of-envelope {label} wrote an admission row"
        )
        assert store.events[-1]["event_type"] == "round_admission_denied"


def test_experiment_mutation_constraints_must_be_subset():
    envelope = _guided_envelope()
    accepted = _experiment()
    contracts.check_experiment_against_envelope(accepted, envelope)

    outside_ops = _experiment(
        mutation_constraints={
            "allowed_ops": ["append", "freeform"],
            "max_input_bytes": 2048,
        }
    )
    too_many_bytes = _experiment(
        mutation_constraints={
            "allowed_ops": ["append"],
            "max_input_bytes": 4097,
        }
    )

    for label, experiment in (
        ("allowed_ops", outside_ops),
        ("max_input_bytes", too_many_bytes),
    ):
        with pytest.raises(contracts.EnvelopeViolation) as raised:
            contracts.check_experiment_against_envelope(experiment, envelope)
        assert raised.value.reason_code == "ENVELOPE_VIOLATION"
        assert label in str(raised.value), (
            "mutation beyond envelope accepted without naming the field"
        )


def test_envelope_digest_binds_mutation_limits():
    base = _guided_envelope()
    base_digest = contracts.envelope_digest(base)
    assert base_digest.startswith("sha256:")

    self_described = deepcopy(base)
    self_described["envelope_digest"] = base_digest
    assert contracts.envelope_digest(self_described) == base_digest, (
        "envelope_digest did not exclude itself from the hashed body"
    )

    mutations = {
        "mutation_limits.max_input_bytes": lambda envelope: envelope[
            "mutation_limits"
        ].__setitem__("max_input_bytes", 4097),
        "mutation_limits.allowed_ops": lambda envelope: envelope[
            "mutation_limits"
        ]["allowed_ops"].append("freeform"),
        "allowed_mutation_families": lambda envelope: envelope[
            "allowed_mutation_families"
        ].append("freeform"),
        "max_total_seconds": lambda envelope: envelope.__setitem__(
            "max_total_seconds", 901
        ),
        "max_fuzz_seconds": lambda envelope: envelope.__setitem__(
            "max_fuzz_seconds", 301
        ),
    }

    for field, mutate in mutations.items():
        changed = deepcopy(base)
        mutate(changed)
        changed_digest = contracts.envelope_digest(changed)
        assert changed_digest != base_digest, (
            f"mutation_limits not covered by envelope_digest: {field}"
        )

        base_plan = _v2_round_plan(base_digest)
        changed_plan = _v2_round_plan(changed_digest)
        assert contracts.plan_digest(changed_plan) != contracts.plan_digest(
            base_plan
        ), f"plan_digest does not bind envelope change in {field}"


def test_fixed_envelope_sets_null_fuzz_fields():
    envelope = _fixed_envelope()

    assert envelope["mode"] == "fixed"
    assert envelope["max_fuzz_seconds"] == 0, "fixed envelope kept fuzz limits"
    assert envelope["allowed_mutation_families"] == []
    assert envelope["mutation_limits"] == {
        "allowed_ops": [],
        "max_input_bytes": 0,
    }
    assert envelope["seed_corpus_digest"] is None
    assert envelope["fuzz_image_digest"] is None
    assert envelope["max_rounds"] == 1
    assert envelope["harness_digest"] == HARNESS_DIGEST
    assert envelope["accepted_signature_set"] == [SIGNATURE]
    assert contracts.envelope_digest(envelope).startswith("sha256:")


def test_guided_fuzz_image_defaults_to_toolchain_image():
    envelope = _guided_envelope()

    assert envelope["fuzz_image_digest"] == TOOLCHAIN_IMAGE_DIGEST, (
        "fuzz image was not bound to toolchain image"
    )

    explicit = _guided_envelope(
        fuzz_image_digest=EXPLICIT_FUZZ_IMAGE_DIGEST
    )
    assert explicit["fuzz_image_digest"] == EXPLICIT_FUZZ_IMAGE_DIGEST
    assert contracts.envelope_digest(explicit) != contracts.envelope_digest(
        envelope
    ), "explicit fuzz image did not change envelope_digest"

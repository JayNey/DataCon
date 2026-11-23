"""TC-11/T10: Plan v2 binds family, round, envelope, build_ref and approvals.

These are pure contract tests: they build one v2 plan literal from the frozen
v0.1 plan fixture plus the eleven fields from interface-contract-delta §3, then
require ``plan_digest`` / ``canonical_plan_bytes`` to accept it and to bind
every identity field. The database side of the same coordinates lives in
``tests/integration/test_review_locks.py`` and ``test_migrations.py``.
"""

from copy import deepcopy
import hashlib

from test_plan import PLAN as BASE_PLAN

import pytest

from datacon import jsonutil
from datacon.contracts import canonical_plan_bytes, plan_digest


def _digest(token: str) -> str:
    return "sha256:" + token * 64


FAMILY_ID = "2f1c0f5e-3d7a-4b6c-9f10-2a4b6c8d0e11"
OTHER_FAMILY_ID = "3f1c0f5e-3d7a-4b6c-9f10-2a4b6c8d0e22"
SOURCE_JOB_ID = "9a1b2c3d-4e5f-4a6b-8c7d-9e0f1a2b3c4d"
ENVELOPE_DIGEST = _digest("5")
OTHER_ENVELOPE_DIGEST = _digest("f")
APPROVAL_DIGEST = _digest("4")
OTHER_APPROVAL_DIGEST = _digest("e")
EXPERIMENT_DIGEST = _digest("3")
OTHER_EXPERIMENT_DIGEST = _digest("d")
FIRST_PLAN_DIGEST = _digest("2")

COMPILE_FLAGS = [
    "-fsanitize=address",
    "-g",
    "-O1",
    "-Iinclude",
    "-D_GNU_SOURCE",
]

BUILD_SPEC = {
    "kind": "cmake",
    "configure": [
        "cmake",
        "-S",
        ".",
        "-B",
        "build",
        "-DCMAKE_BUILD_TYPE=RelWithDebInfo",
        "-DCMAKE_C_COMPILER=clang",
    ],
    "build": ["cmake", "--build", "build", "--target", "parser"],
    "install": [],
    "env": {
        "CC": "clang",
        "CFLAGS": "-fsanitize=address -g -O1 -Iinclude -D_GNU_SOURCE",
    },
    "outputs": ["build/parser"],
    "declared_compile_flags": COMPILE_FLAGS,
    "shell_recipe_digest": None,
    "shell_face_digest": None,
    "shell_face_review": None,
}

# v2 keeps the v0.1 field and freezes it to the canonical build_spec digest.
BUILD_RECIPE_DIGEST = (
    "sha256:" + hashlib.sha256(jsonutil.canonical_bytes(BUILD_SPEC)).hexdigest()
)

BUILD_REF = {
    "source_job_id": SOURCE_JOB_ID,
    "generation": 3,
    "build_inputs_digest": _digest("8"),
    "artifacts": {
        "vulnerable": {
            "artifact_digest": _digest("6"),
            "build_log_digest": _digest("7"),
        },
        "fixed": {
            "artifact_digest": _digest("1"),
            "build_log_digest": _digest("2"),
        },
    },
}

V2_IDENTITY = {
    "schema_version": 2,
    "family_id": FAMILY_ID,
    "parent_job_id": FAMILY_ID,
    "round_no": 2,
    "parent_approval_digest": APPROVAL_DIGEST,
    "envelope_digest": ENVELOPE_DIGEST,
    "build_ref": deepcopy(BUILD_REF),
    "build_spec": deepcopy(BUILD_SPEC),
    "compile_flags": list(COMPILE_FLAGS),
    "experiment_digest": EXPERIMENT_DIGEST,
    "build_provenance_rules_version": "build-provenance-v1",
    "build_recipe_digest": BUILD_RECIPE_DIGEST,
}


def _round_plan(**overrides) -> dict:
    """A reuse-validation round plan: the only plan shape with build_ref."""
    plan = deepcopy(BASE_PLAN)
    plan.update(deepcopy(V2_IDENTITY))
    plan.update(overrides)
    return plan


def _campaign_plan() -> dict:
    """The first plan of a guided family: campaign child, round_no=null."""
    plan = deepcopy(BASE_PLAN)
    plan.update(deepcopy(V2_IDENTITY))
    plan.update(
        {
            "round_no": None,
            "parent_approval_digest": None,
            "build_ref": None,
            "inputs": None,
            "experiment_digest": None,
        }
    )
    return plan


ROUND_PLAN_V2 = _round_plan()
CAMPAIGN_PLAN_V2 = _campaign_plan()


def test_round_plan_binds_parent_round_envelope_and_build_ref():
    base_digest = plan_digest(ROUND_PLAN_V2)
    assert base_digest.startswith("sha256:")

    mutations = {
        # parent_job_id is bound together with family_id: changing only one
        # side is now rejected by the cross-field invariant, so the digest
        # sensitivity of both identity fields is exercised on a valid pair.
        "parent_job_id": lambda plan: plan.update(
            family_id=OTHER_FAMILY_ID, parent_job_id=OTHER_FAMILY_ID
        ),
        "round_no": lambda plan: plan.__setitem__("round_no", 3),
        "envelope_digest": lambda plan: plan.__setitem__(
            "envelope_digest", OTHER_ENVELOPE_DIGEST
        ),
        "build_ref": lambda plan: plan["build_ref"].__setitem__(
            "generation", plan["build_ref"]["generation"] + 1
        ),
    }
    for field, mutate in mutations.items():
        changed = deepcopy(ROUND_PLAN_V2)
        mutate(changed)
        assert plan_digest(changed) != base_digest, (
            f"plan_digest does not bind {field}"
        )


def test_first_plan_has_null_parent_approval_digest():
    first = CAMPAIGN_PLAN_V2
    assert first["parent_approval_digest"] is None, (
        "first plan required a parent approval digest"
    )
    canonical = canonical_plan_bytes(first)
    assert b'"parent_approval_digest":null' in canonical, (
        "the explicit null parent approval digest is not part of the canonical plan"
    )
    first_digest = plan_digest(first)

    later = _round_plan()
    assert later["parent_approval_digest"] is not None
    assert b'"parent_approval_digest":null' not in canonical_plan_bytes(later)
    assert plan_digest(later) != first_digest, (
        "a later round with a parent approval digest reused the first plan digest"
    )


def test_round_plan_binds_both_version_artifacts():
    base_digest = plan_digest(ROUND_PLAN_V2)
    assert ROUND_PLAN_V2["build_ref"]["artifacts"].keys() == {
        "vulnerable",
        "fixed",
    }

    for version in ("vulnerable", "fixed"):
        for field in ("artifact_digest", "build_log_digest"):
            changed = deepcopy(ROUND_PLAN_V2)
            changed["build_ref"]["artifacts"][version][field] = _digest("9")
            assert plan_digest(changed) != base_digest, (
                f"plan_digest does not bind build_ref.artifacts.{version}.{field}"
            )


def test_campaign_identity_is_special_child():
    campaign = CAMPAIGN_PLAN_V2
    assert campaign["round_no"] is None, "campaign treated as ordinary round"
    assert campaign["inputs"] is None, "campaign inputs must stay explicitly null"
    campaign_digest = plan_digest(campaign)

    ordinary = deepcopy(campaign)
    ordinary["round_no"] = 1
    ordinary["inputs"] = deepcopy(BASE_PLAN["inputs"])
    assert plan_digest(ordinary) != campaign_digest, (
        "campaign treated as ordinary round: round_no=null is not bound"
    )

    round_one = _round_plan(
        round_no=1,
        parent_approval_digest=None,
        build_ref=None,
        experiment_digest=None,
    )
    assert round_one["family_id"] == campaign["family_id"]
    assert round_one["parent_job_id"] == campaign["parent_job_id"]
    assert plan_digest(round_one) != campaign_digest, (
        "campaign plan and round plan share a digest inside one family"
    )


def test_campaign_plan_is_human_approved_first_plan():
    campaign = CAMPAIGN_PLAN_V2
    assert campaign["parent_approval_digest"] is None, (
        "campaign plan bypassed human review"
    )
    assert campaign["envelope_digest"] is not None, (
        "campaign plan is not bound to the envelope a human approves"
    )
    first_digest = plan_digest(campaign)

    changed_envelope = deepcopy(campaign)
    changed_envelope["envelope_digest"] = OTHER_ENVELOPE_DIGEST
    assert plan_digest(changed_envelope) != first_digest, (
        "the first approved plan does not bind its envelope"
    )

    later = _round_plan()
    assert later["parent_approval_digest"] != campaign["parent_approval_digest"]
    assert plan_digest(later) != first_digest


def test_family_approval_chain_supersedes_on_envelope_change():
    old_round = _round_plan(parent_approval_digest=APPROVAL_DIGEST)
    old_digest = plan_digest(old_round)

    # Re-approval after an envelope change appends a new approval whose
    # ``supersedes`` points at the old chain tail. ``supersedes`` is a chain
    # pointer outside the hashed material; only the new approval digest and the
    # new envelope digest reach the next round plan.
    new_round = _round_plan(
        parent_approval_digest=OTHER_APPROVAL_DIGEST,
        envelope_digest=OTHER_ENVELOPE_DIGEST,
    )
    assert new_round["parent_approval_digest"] != old_round["parent_approval_digest"]
    new_digest = plan_digest(new_round)
    assert new_digest != old_digest, (
        "a re-approved envelope did not produce a new round plan digest"
    )
    assert plan_digest(old_round) == old_digest, (
        "re-approval rewrote an already frozen round plan"
    )
    assert old_digest != FIRST_PLAN_DIGEST


def test_parent_job_aggregates_without_rerun():
    campaign = CAMPAIGN_PLAN_V2
    assert campaign["round_no"] is None
    # The parent/first campaign plan never carries build or replay artifacts;
    # only a reuse-validation child round may reference a campaign build.
    assert campaign["build_ref"] is None, "parent job executed a child step"
    assert campaign["inputs"] is None, "parent job froze replay inputs"
    assert campaign["experiment_digest"] is None, (
        "parent job froze an ExperimentSpec"
    )
    plan_digest(campaign)

    with_build = deepcopy(campaign)
    with_build["build_ref"] = deepcopy(BUILD_REF)
    with pytest.raises(ValueError):
        plan_digest(with_build)


def test_plan_digest_binds_experiment_and_provenance_version():
    base_digest = plan_digest(ROUND_PLAN_V2)
    mutations = {
        "experiment_digest": lambda plan: plan.__setitem__(
            "experiment_digest", OTHER_EXPERIMENT_DIGEST
        ),
        "build_provenance_rules_version": lambda plan: plan.__setitem__(
            "build_provenance_rules_version", "build-provenance-v2"
        ),
    }
    for field, mutate in mutations.items():
        changed = deepcopy(ROUND_PLAN_V2)
        mutate(changed)
        assert plan_digest(changed) != base_digest, (
            f"plan_digest does not bind {field}"
        )


@pytest.mark.parametrize(
    "mutate",
    [
        lambda plan: plan.__setitem__("family_id", OTHER_FAMILY_ID),
        lambda plan: plan.__setitem__("family_id", "not-a-uuid"),
        lambda plan: plan.__setitem__("parent_approval_digest", None),
        lambda plan: plan.__setitem__("inputs", None),
    ],
)
def test_round_plan_rejects_cross_field_violations(mutate):
    plan = _round_plan()
    mutate(plan)
    with pytest.raises(ValueError):
        plan_digest(plan)


def test_campaign_plan_rejects_non_null_inputs():
    plan = _campaign_plan()
    plan["inputs"] = deepcopy(BASE_PLAN["inputs"])
    with pytest.raises(ValueError):
        plan_digest(plan)


def test_campaign_plan_rejects_build_ref():
    plan = _campaign_plan()
    plan["build_ref"] = deepcopy(BUILD_REF)
    with pytest.raises(ValueError):
        plan_digest(plan)


def test_first_round_rejects_parent_approval_digest():
    plan = _round_plan(
        round_no=1,
        parent_approval_digest=APPROVAL_DIGEST,
        build_ref=None,
        experiment_digest=None,
    )
    with pytest.raises(ValueError):
        plan_digest(plan)


def test_build_ref_and_experiment_digest_are_coupled():
    with_build_without_experiment = _round_plan(experiment_digest=None)
    with pytest.raises(ValueError):
        plan_digest(with_build_without_experiment)

    without_build_with_experiment = _round_plan(
        build_ref=None, experiment_digest=EXPERIMENT_DIGEST
    )
    with pytest.raises(ValueError):
        plan_digest(without_build_with_experiment)

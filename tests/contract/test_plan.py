from copy import deepcopy

import pytest

from datacon.contracts import DEFAULT_LIMITS, canonical_plan_bytes, plan_digest

PLAN = {
    "case_id": "fixture-c-parser",
    "case_config_digest": "sha256:" + "a" * 64,
    "revisions": {"vulnerable": "b" * 40, "fixed": "c" * 40},
    "dependencies_digest": "sha256:" + "d" * 64,
    "image_digest": "sha256:" + "e" * 64,
    "build_recipe_digest": "sha256:" + "f" * 64,
    "harness_digest": "sha256:" + "1" * 64,
    "inputs": {"candidate": "sha256:" + "2" * 64, "normal": "sha256:" + "3" * 64},
    "asan_signature": {
        "error": "heap-buffer-overflow",
        "function": "parse_token",
        "source": "parser.c",
    },
    "limits": DEFAULT_LIMITS,
    "policy_version": "1",
}

CANONICAL = (
    '{"asan_signature":{"error":"heap-buffer-overflow","function":"parse_token","source":"parser.c"},'
    '"build_recipe_digest":"sha256:' + "f" * 64 + '",'
    '"case_config_digest":"sha256:' + "a" * 64 + '","case_id":"fixture-c-parser",'
    '"dependencies_digest":"sha256:' + "d" * 64 + '",'
    '"harness_digest":"sha256:' + "1" * 64 + '",'
    '"image_digest":"sha256:' + "e" * 64 + '",'
    '"inputs":{"candidate":"sha256:' + "2" * 64 + '","normal":"sha256:' + "3" * 64 + '"},'
    '"limits":{"cpu":2,"execute_seconds":1200,"memory_mib":2048,"pids":128,'
    '"prepare_seconds":600,"replay_seconds":10,"scratch_mib":512},"policy_version":"1",'
    '"revisions":{"fixed":"' + "c" * 40 + '","vulnerable":"' + "b" * 40 + '"}}'
).encode("utf-8")


def test_canonical_bytes_and_digest_are_frozen():
    reordered = dict(reversed(list(PLAN.items())))
    reordered["inputs"] = dict(reversed(list(PLAN["inputs"].items())))
    reordered["revisions"] = dict(reversed(list(PLAN["revisions"].items())))

    assert canonical_plan_bytes(reordered) == CANONICAL
    assert plan_digest(reordered) == (
        "sha256:f665f40825aba856c07ff3f882eddfb6b65cfe5ac904745ca71408da4e301df7"
    )


def test_non_ascii_values_are_encoded_as_utf8():
    changed = deepcopy(PLAN)
    changed["asan_signature"]["function"] = "解析"
    assert canonical_plan_bytes(changed).decode("utf-8").count("解析") == 1
    assert plan_digest(changed) == (
        "sha256:c6db7da66e9dcc86135327c7adcc8ea72508f7f4ab487889bafe14538f3a9a53"
    )


@pytest.mark.parametrize(
    "mutate",
    [
        lambda plan: plan["inputs"].__setitem__("candidate", "sha256:" + "4" * 64),
        lambda plan: plan["revisions"].__setitem__("fixed", "d" * 40),
        lambda plan: plan["limits"].__setitem__("cpu", 1),
        lambda plan: plan.__setitem__("policy_version", "2"),
    ],
)
def test_digest_binds_material_revisions_budget_and_policy(mutate):
    changed = deepcopy(PLAN)
    mutate(changed)
    assert plan_digest(changed) != plan_digest(PLAN)


@pytest.mark.parametrize(
    "mutate",
    [
        lambda plan: plan.pop("case_id"),
        lambda plan: plan.__setitem__("extra", "x"),
        lambda plan: plan["inputs"].pop("normal"),
        lambda plan: plan["inputs"].__setitem__("extra", "sha256:" + "4" * 64),
        lambda plan: plan["revisions"].pop("fixed"),
        lambda plan: plan["revisions"].__setitem__("fixed", "c" * 41),
        lambda plan: plan["revisions"].__setitem__("fixed", "C" * 40),
        lambda plan: plan["revisions"].__setitem__("fixed", "c" * 64),
        lambda plan: plan["inputs"].__setitem__("candidate", "sha256:" + "4" * 63),
        lambda plan: plan["inputs"].__setitem__("candidate", "sha256:" + "G" * 64),
        lambda plan: plan["asan_signature"].__setitem__("function", ""),
        lambda plan: plan["asan_signature"].__setitem__("extra", "x"),
        lambda plan: plan["asan_signature"].pop("source"),
        lambda plan: plan["revisions"].__setitem__("extra", "b" * 40),
        lambda plan: plan["limits"].__setitem__("extra", 1),
        lambda plan: plan["limits"].__setitem__("cpu", True),
        lambda plan: plan["limits"].__setitem__("cpu", 3),
        lambda plan: plan["limits"].__setitem__("execute_seconds", 9),
        lambda plan: plan["limits"].pop("pids"),
        lambda plan: plan.__setitem__("case_id", ""),
        lambda plan: plan.__setitem__("policy_version", " "),
    ],
)
def test_plan_rejects_missing_unknown_or_invalid_fields(mutate):
    changed = deepcopy(PLAN)
    mutate(changed)
    with pytest.raises(ValueError):
        plan_digest(changed)


def test_both_revisions_must_use_the_same_git_object_format():
    changed = deepcopy(PLAN)
    changed["revisions"]["vulnerable"] = "b" * 64
    with pytest.raises(ValueError):
        plan_digest(changed)

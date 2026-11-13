from copy import deepcopy
import json

import pytest

from datacon.contracts import (
    DEFAULT_LIMITS,
    analysis_digest,
    canonical_plan_bytes,
    plan_digest,
)

ANALYSIS = {
    "diff_digest": "sha256:" + "9" * 64,
    "changed_paths": ["parser.c"],
    "symbols": [
        {
            "name": "parse_token",
            "path": "parser.c",
            "role": "definition",
            "revision": "vulnerable",
            "start_line": 5,
            "end_line": 18,
        },
        {
            "name": "parse_token",
            "path": "harness.c",
            "role": "call_site",
            "revision": "harness",
            "start_line": 11,
            "end_line": 11,
        },
    ],
    "findings": [
        {
            "kind": "fact",
            "statement": "the fix allocates one more byte",
            "confidence": "high",
            "evidence_refs": ["git:diff/a..b/parser.c"],
        },
        {
            "kind": "hypothesis",
            "statement": "the terminator write is the root cause",
            "confidence": "medium",
            "evidence_refs": ["git:blob/a/parser.c"],
        },
    ],
}

PLAN = {
    "case_id": "fixture-c-parser",
    "cve_id": "CVE-2099-0001",
    "case_config_digest": "sha256:" + "a" * 64,
    "repository": {
        "origin": "fixture://datacon/B01",
        "bundle_digest": "sha256:" + "d" * 64,
        "patch_digest": "sha256:" + "e" * 64,
    },
    "revisions": {"vulnerable": "b" * 40, "fixed": "c" * 40},
    "dependencies_digest": "sha256:" + "f" * 64,
    "image_digest": "sha256:" + "0" * 64,
    "platform": "linux/amd64",
    "toolchain": {
        "compiler": "clang",
        "sanitizer": "address",
        "pinned_image_version": "19.1.7",
    },
    "asan_options": "detect_leaks=0:halt_on_error=1",
    "build_recipe_digest": "sha256:" + "1" * 64,
    "harness_digest": "sha256:" + "2" * 64,
    "inputs": {"candidate": "sha256:" + "3" * 64, "normal": "sha256:" + "4" * 64},
    "expected_exit": {"normal": 0, "candidate_clean": 0, "candidate_asan": 86},
    "asan_signature": {
        "error": "heap-buffer-overflow",
        "function": "parse_token",
        "source": "parser.c",
    },
    "limits": DEFAULT_LIMITS,
    "isolation": {
        "network": "none",
        "user": "65534:65534",
        "read_only_root": True,
        "cap_drop": ["ALL"],
        "no_new_privileges": True,
        "seccomp": "runtime/default",
    },
    "intel": {
        "snapshot": "advisory.json",
        "collected_at": "2026-01-02T00:00:00Z",
        "content_digest": "sha256:" + "5" * 64,
        "sources": ["https://nvd.invalid/1", "https://vendor.invalid/2"],
    },
    "analysis": ANALYSIS,
    "analysis_digest": analysis_digest(ANALYSIS),
    "policy_version": "1",
}

EXPECTED = {
    "analysis_digest": analysis_digest(ANALYSIS),
    "asan_options": "detect_leaks=0:halt_on_error=1",
    "asan_signature": {
        "error": "heap-buffer-overflow",
        "function": "parse_token",
        "source": "parser.c",
    },
    "build_recipe_digest": "sha256:" + "1" * 64,
    "case_config_digest": "sha256:" + "a" * 64,
    "case_id": "fixture-c-parser",
    "cve_id": "CVE-2099-0001",
    "dependencies_digest": "sha256:" + "f" * 64,
    "expected_exit": {"normal": 0, "candidate_clean": 0, "candidate_asan": 86},
    "harness_digest": "sha256:" + "2" * 64,
    "image_digest": "sha256:" + "0" * 64,
    "inputs": {"candidate": "sha256:" + "3" * 64, "normal": "sha256:" + "4" * 64},
    "intel": {
        "snapshot": "advisory.json",
        "collected_at": "2026-01-02T00:00:00Z",
        "content_digest": "sha256:" + "5" * 64,
        "sources": ["https://nvd.invalid/1", "https://vendor.invalid/2"],
    },
    "isolation": {
        "network": "none",
        "user": "65534:65534",
        "read_only_root": True,
        "cap_drop": ["ALL"],
        "no_new_privileges": True,
        "seccomp": "runtime/default",
    },
    "limits": DEFAULT_LIMITS,
    "platform": "linux/amd64",
    "policy_version": "1",
    "repository": {
        "origin": "fixture://datacon/B01",
        "bundle_digest": "sha256:" + "d" * 64,
        "patch_digest": "sha256:" + "e" * 64,
    },
    "revisions": {"vulnerable": "b" * 40, "fixed": "c" * 40},
    "toolchain": {
        "compiler": "clang",
        "sanitizer": "address",
        "pinned_image_version": "19.1.7",
    },
}

EXPECTED_DIGEST = "sha256:bc4a62de4573e6ec3adb5b792ce9b98cf60fd10f4a73ced5b662426f8707524d"


def test_canonical_bytes_and_digest_are_frozen():
    reordered = dict(reversed(list(PLAN.items())))
    reordered["inputs"] = dict(reversed(list(PLAN["inputs"].items())))
    reordered["revisions"] = dict(reversed(list(PLAN["revisions"].items())))
    reordered["analysis"] = deepcopy(PLAN["analysis"])
    reordered["analysis"]["symbols"] = list(reversed(PLAN["analysis"]["symbols"]))
    reordered["analysis"]["findings"] = list(reversed(PLAN["analysis"]["findings"]))

    canonical = canonical_plan_bytes(reordered)
    assert canonical == (
        json.dumps(
            EXPECTED,
            sort_keys=True,
            ensure_ascii=False,
            separators=(",", ":"),
        ).encode("utf-8")
    )
    assert plan_digest(reordered) == EXPECTED_DIGEST


ANALYSIS_DIGEST = "sha256:45f59ba07c381c56c19e2e913f752256aa93b7cc2185288fd015b449420f8757"


def test_analysis_digest_is_frozen():
    assert analysis_digest(ANALYSIS) == ANALYSIS_DIGEST


def test_non_ascii_values_are_encoded_as_utf8():
    changed = deepcopy(PLAN)
    changed["asan_signature"]["function"] = "解析"
    assert canonical_plan_bytes(changed).decode("utf-8").count("解析") == 1
    assert plan_digest(changed) != plan_digest(PLAN)


@pytest.mark.parametrize(
    "mutate",
    [
        lambda plan: plan["inputs"].__setitem__("candidate", "sha256:" + "6" * 64),
        lambda plan: plan["revisions"].__setitem__("fixed", "d" * 40),
        lambda plan: plan["limits"].__setitem__("cpu", 1),
        lambda plan: plan.__setitem__("platform", "linux/arm64"),
        lambda plan: plan["toolchain"].__setitem__("compiler", "gcc"),
        lambda plan: plan.__setitem__("asan_options", "detect_leaks=1"),
        lambda plan: plan.__setitem__("policy_version", "2"),
        lambda plan: plan["isolation"].__setitem__("user", "1000:1000"),
        lambda plan: plan["repository"].__setitem__("patch_digest", "sha256:" + "7" * 64),
        lambda plan: plan["analysis"]["findings"][0].__setitem__(
            "statement", "changed"
        ),
    ],
)
def test_digest_binds_materials_budget_policy_isolation_and_analysis(mutate):
    changed = deepcopy(PLAN)
    mutate(changed)
    changed["analysis_digest"] = analysis_digest(changed["analysis"])
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
        lambda plan: plan.__setitem__("cve_id", "cve-2099-0001"),
        lambda plan: plan["repository"].__setitem__("origin", "http://insecure"),
        lambda plan: plan["repository"].__setitem__("bundle_digest", "sha256:abc"),
        lambda plan: plan["isolation"].__setitem__("network", "bridge"),
        lambda plan: plan["isolation"].__setitem__("read_only_root", False),
        lambda plan: plan["isolation"].__setitem__("cap_drop", []),
        lambda plan: plan["isolation"].__setitem__("no_new_privileges", False),
        lambda plan: plan["intel"].__setitem__("collected_at", "2026-01-02"),
        lambda plan: plan["intel"].__setitem__("sources", ["http://insecure"]),
        lambda plan: plan.__setitem__("analysis_digest", "sha256:" + "8" * 64),
        lambda plan: plan["expected_exit"].__setitem__("normal", 256),
        lambda plan: plan["expected_exit"].__setitem__("candidate_asan", True),
        lambda plan: plan["analysis"]["changed_paths"].append("../etc/passwd"),
        lambda plan: plan["analysis"]["symbols"][0].__setitem__("role", "unknown"),
        lambda plan: plan["analysis"]["symbols"][0].__setitem__("start_line", 0),
        lambda plan: plan["analysis"]["findings"][0].__setitem__("evidence_refs", []),
        lambda plan: plan["analysis"]["findings"][0].__setitem__("kind", "rumour"),
        lambda plan: plan["analysis"]["findings"][0].__setitem__(
            "confidence", "certain"
        ),
        lambda plan: plan["analysis"].pop("diff_digest"),
        lambda plan: plan["analysis"]["symbols"][0].__setitem__("extra", 1),
        lambda plan: plan["analysis"]["findings"][0].__setitem__("extra", 1),
        lambda plan: plan["analysis"]["findings"][0]["evidence_refs"].append(
            "bad\nref"
        ),
        lambda plan: plan.__setitem__("analysis", {}),
        lambda plan: plan["limits"].__setitem__("cpu", True),
        lambda plan: plan["limits"].__setitem__("cpu", 3),
        lambda plan: plan["limits"].__setitem__("execute_seconds", 9),
        lambda plan: plan["limits"].pop("pids"),
        lambda plan: plan.__setitem__("case_id", ""),
        lambda plan: plan.pop("platform"),
        lambda plan: plan.__setitem__("platform", ""),
        lambda plan: plan.pop("asan_options"),
        lambda plan: plan.__setitem__("asan_options", " "),
        lambda plan: plan.__setitem__("toolchain", {}),
        lambda plan: plan["toolchain"].__setitem__("ratio", 1.5),
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


def test_hypothesis_requires_evidence_in_the_plan():
    changed = deepcopy(PLAN)
    changed["analysis"]["findings"][1]["evidence_refs"] = []
    with pytest.raises(ValueError, match="evidence reference"):
        analysis_digest(changed["analysis"])
    with pytest.raises(ValueError, match="evidence reference"):
        plan_digest(changed)

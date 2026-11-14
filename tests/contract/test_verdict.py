"""TC-07: verdict priority and comparability rules (REQ-07).

The verdict is deterministic code. These tests pin the SRS priority order so a
missing, intermittent, timed-out or non-comparable run can never be promoted to
REPRODUCED.
"""

from dataclasses import replace
import json

import pytest

from datacon.asan import ASanSignature, parse_asan, signature_matches
from datacon.verdict import (
    RunObservation,
    VerdictPolicy,
    decide_verdict,
)

SIGNATURE = {
    "error": "heap-buffer-overflow",
    "operation": "WRITE",
    "access_size": 1,
    "function": "parse_token",
    "source": "parser.c",
}
POLICY = VerdictPolicy(
    signature=SIGNATURE,
    expected_exit={
        "normal": 0,
        "candidate_clean": 0,
        "candidate_asan": 86,
    },
    expected_stdout={"normal": "OK\n", "candidate_clean": "ABCD\n"},
)
NOT_REPRODUCED_POLICY = VerdictPolicy(
    signature=SIGNATURE,
    expected_exit={"normal": 0, "candidate_clean": 0},
    expected_stdout={"normal": "OK\n", "candidate_clean": "ABC\n"},
)
VULNERABLE_ASAN = """\
==7==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x502000000014
WRITE of size 1 at 0x502000000014 thread T0
    #0 0x55555565fadf in parse_token /fixture/vulnerable/parser.c:22:17
    #1 0x55555565fc67 in main /fixture/harness.c:14:19
SUMMARY: AddressSanitizer: heap-buffer-overflow /fixture/vulnerable/parser.c:22:17 in parse_token
"""


def run(version, phase, *, exit_code, stdout, stderr=""):
    return RunObservation(
        version=version,
        phase=phase,
        status="completed",
        exit_code=exit_code,
        stdout=stdout,
        stderr=stderr,
        signature=parse_asan(stderr),
        input_digest="sha256:" + ("1" * 64),
        duration_seconds=0.05,
    )


def six_runs(*, vulnerable_clean=False):
    runs = []
    for version in ("vulnerable", "fixed"):
        runs.append(run(version, "normal", exit_code=0, stdout="OK\n"))
    for index in (1, 2):
        if vulnerable_clean:
            runs.append(
                run("vulnerable", f"candidate_{index}", exit_code=0, stdout="ABC\n")
            )
        else:
            runs.append(
                run(
                    "vulnerable",
                    f"candidate_{index}",
                    exit_code=86,
                    stdout="",
                    stderr=VULNERABLE_ASAN,
                )
            )
        runs.append(
            run(
                "fixed",
                f"candidate_{index}",
                exit_code=0,
                stdout="ABC\n" if vulnerable_clean else "ABCD\n",
            )
        )
    return runs


def builds():
    return {
        "vulnerable": {
            "status": "completed",
            "image_digest": "sha256:" + ("a" * 64),
            "artifact_digest": "sha256:" + ("b" * 64),
            "compile_args": ["-std=c11", "-g", "-O0", "-fsanitize=address"],
        },
        "fixed": {
            "status": "completed",
            "image_digest": "sha256:" + ("a" * 64),
            "artifact_digest": "sha256:" + ("c" * 64),
            "compile_args": ["-std=c11", "-g", "-O0", "-fsanitize=address"],
        },
    }


def test_parse_asan_extracts_the_reviewed_signature_fields():
    signature = parse_asan(VULNERABLE_ASAN)
    assert signature == ASanSignature(
        error="heap-buffer-overflow",
        operation="WRITE",
        access_size=1,
        function="parse_token",
        source="/fixture/vulnerable/parser.c",
    )
    assert signature_matches(signature, SIGNATURE)
    assert signature_matches(
        signature,
        {"error": "heap-buffer-overflow", "function": "parse_token", "source": "parser.c"},
    )
    assert not signature_matches(
        signature, {**SIGNATURE, "function": "other_function"}
    )
    assert not signature_matches(
        signature, {**SIGNATURE, "operation": "READ"}
    )
    assert not signature_matches(
        signature, {**SIGNATURE, "access_size": 2}
    )
    assert parse_asan("plain crash\n") is None


def test_reproduced_requires_both_vulnerable_hits_and_both_fixed_clean():
    decision = decide_verdict(POLICY, six_runs(), builds=builds())
    assert decision.verdict == "REPRODUCED"
    assert decision.reason_code == "ASAN_SIGNATURE_MATCHED"
    assert decision.checks["vulnerable_candidates"] == ["target_signature", "target_signature"]
    assert decision.checks["fixed_candidates"] == ["clean", "clean"]


def test_both_versions_clean_is_not_reproduced():
    decision = decide_verdict(
        NOT_REPRODUCED_POLICY,
        six_runs(vulnerable_clean=True),
        builds=builds(),
    )
    assert decision.verdict == "NOT_REPRODUCED"
    assert decision.reason_code == "CANDIDATE_CLEAN"


def test_fixed_still_hits_the_target_signature_is_inconclusive():
    runs = six_runs()
    runs = [
        replace(item, exit_code=86, stdout="", stderr=VULNERABLE_ASAN, signature=parse_asan(VULNERABLE_ASAN))
        if item.version == "fixed" and item.phase == "candidate_1"
        else item
        for item in runs
    ]
    decision = decide_verdict(POLICY, runs, builds=builds())
    assert decision.verdict == "INCONCLUSIVE"
    assert decision.reason_code == "FIXED_STILL_VULNERABLE"


def test_intermittent_trigger_is_inconclusive():
    runs = six_runs()
    runs = [
        replace(item, exit_code=0, stdout="ABCD\n", signature=None, stderr="")
        if item.version == "vulnerable" and item.phase == "candidate_2"
        else item
        for item in runs
    ]
    decision = decide_verdict(POLICY, runs, builds=builds())
    assert decision.verdict == "INCONCLUSIVE"
    assert decision.reason_code == "INTERMITTENT"


def test_missing_required_replay_is_inconclusive():
    runs = six_runs()[:-1]
    decision = decide_verdict(POLICY, runs, builds=builds())
    assert decision.verdict == "INCONCLUSIVE"
    assert decision.reason_code == "EVIDENCE_INCOMPLETE"
    assert "run" in decision.message


def test_timeout_or_resource_limit_is_inconclusive():
    runs = six_runs()
    runs = [
        replace(item, status="timeout", exit_code=None)
        if item.version == "vulnerable" and item.phase == "candidate_1"
        else item
        for item in runs
    ]
    decision = decide_verdict(POLICY, runs, builds=builds())
    assert decision.verdict == "INCONCLUSIVE"
    assert decision.reason_code == "TIMEOUT"

    runs = six_runs()
    runs = [
        replace(item, status="resource_limited", exit_code=137)
        if item.version == "fixed" and item.phase == "candidate_2"
        else item
        for item in runs
    ]
    decision = decide_verdict(POLICY, runs, builds=builds())
    assert decision.verdict == "INCONCLUSIVE"
    assert decision.reason_code == "RESOURCE_LIMITED"


def test_control_failure_is_inconclusive():
    runs = six_runs()
    runs = [
        replace(item, exit_code=2, stdout="")
        if item.version == "vulnerable" and item.phase == "normal"
        else item
        for item in runs
    ]
    decision = decide_verdict(POLICY, runs, builds=builds())
    assert decision.verdict == "INCONCLUSIVE"
    assert decision.reason_code == "CONTROL_FAILED"


def test_other_crash_is_inconclusive():
    runs = six_runs()
    other = "==7==ERROR: AddressSanitizer: stack-buffer-overflow\n"
    runs = [
        replace(item, exit_code=1, stdout="", stderr=other, signature=parse_asan(other))
        if item.version == "vulnerable" and item.phase == "candidate_1"
        else item
        for item in runs
    ]
    decision = decide_verdict(POLICY, runs, builds=builds())
    assert decision.verdict == "INCONCLUSIVE"
    assert decision.reason_code == "OTHER_CRASH"


def test_non_comparable_builds_are_inconclusive():
    drifted = builds()
    drifted["fixed"] = {
        **drifted["fixed"],
        "image_digest": "sha256:" + ("d" * 64),
    }
    decision = decide_verdict(POLICY, six_runs(), builds=drifted)
    assert decision.verdict == "INCONCLUSIVE"
    assert decision.reason_code == "NOT_COMPARABLE"


def test_truncated_or_missing_evidence_is_inconclusive():
    runs = six_runs()
    runs[0] = replace(runs[0], log_truncated=True)
    decision = decide_verdict(POLICY, runs, builds=builds())
    assert decision.verdict == "INCONCLUSIVE"
    assert decision.reason_code == "EVIDENCE_INCOMPLETE"


def test_decision_is_json_serializable_for_reports():
    decision = decide_verdict(POLICY, six_runs(), builds=builds())
    payload = decision.as_dict()
    assert json.loads(json.dumps(payload))["verdict"] == "REPRODUCED"
    assert payload["priority"][0].startswith("INCONCLUSIVE")

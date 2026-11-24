"""TC-13: hypothesis text never changes the deterministic verdict (REQ-13).

RED-phase contract test for T14. The verdict entry point
``datacon.verdict.decide_verdict`` exists, but it does not accept the
hypothesis set yet, so the coordinate fails on its own missing keyword: the
GREEN face takes the same six replay observations plus whatever hypotheses
the model produced and must return the identical decision. The verdict
stays a product of the six replays and deterministic rules only; quality
reporting on hypotheses is B04-H's job, never the verdict's.
"""

from __future__ import annotations

from datacon.asan import parse_asan
from datacon.verdict import RunObservation, VerdictPolicy, decide_verdict

SIGNATURE = {
    "error": "heap-buffer-overflow",
    "operation": "WRITE",
    "access_size": 1,
    "function": "parse_token",
    "source": "parser.c",
}
POLICY = VerdictPolicy(
    signature=SIGNATURE,
    expected_exit={"normal": 0, "candidate_clean": 0, "candidate_asan": 86},
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

HYPOTHESES = (
    {
        "kind": "hypothesis",
        "statement": "the terminator write can overrun the buffer",
        "confidence": "medium",
        "evidence_refs": ["git:commit/" + "a" * 40],
    },
    {
        "kind": "hypothesis",
        "statement": "a negative length bypasses the bound check",
        "confidence": "low",
        "evidence_refs": ["patch:fix.patch#hunk-2"],
    },
)
REWRITTEN_HYPOTHESIS = {
    "kind": "hypothesis",
    "statement": "REWRITTEN: claim the fixed build crashes instead",
    "confidence": "high",
    "evidence_refs": ["git:commit/" + "b" * 40],
}


def _run(version, phase, *, exit_code, stdout, stderr=""):
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


def _six_runs(*, vulnerable_clean=False):
    runs = []
    for version in ("vulnerable", "fixed"):
        runs.append(_run(version, "normal", exit_code=0, stdout="OK\n"))
    for index in (1, 2):
        if vulnerable_clean:
            runs.append(
                _run("vulnerable", f"candidate_{index}", exit_code=0, stdout="ABC\n")
            )
        else:
            runs.append(
                _run(
                    "vulnerable",
                    f"candidate_{index}",
                    exit_code=86,
                    stdout="",
                    stderr=VULNERABLE_ASAN,
                )
            )
        runs.append(
            _run(
                "fixed",
                f"candidate_{index}",
                exit_code=0,
                stdout="ABC\n" if vulnerable_clean else "ABCD\n",
            )
        )
    return runs


def test_hypothesis_does_not_change_deterministic_verdict():
    cases = (
        (POLICY, False, "REPRODUCED", "ASAN_SIGNATURE_MATCHED"),
        (NOT_REPRODUCED_POLICY, True, "NOT_REPRODUCED", "CANDIDATE_CLEAN"),
    )
    for policy, vulnerable_clean, verdict, reason in cases:
        runs = _six_runs(vulnerable_clean=vulnerable_clean)
        base = decide_verdict(policy, runs)
        assert (base.verdict, base.reason_code) == (verdict, reason)

        # The same six replay observations with hypotheses added, deleted
        # or rewritten must return the identical decision.
        with_hypotheses = decide_verdict(policy, runs, hypotheses=HYPOTHESES)
        without = decide_verdict(policy, runs, hypotheses=())
        rewritten = decide_verdict(
            policy, runs, hypotheses=(REWRITTEN_HYPOTHESIS,)
        )
        for variant in (with_hypotheses, without, rewritten):
            assert variant.verdict == base.verdict, (
                "verdict changed with hypothesis text"
            )
            assert variant.reason_code == base.reason_code

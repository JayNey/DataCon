"""TC-09/TC-13: AgentOutput v2 model-outlet finding kind (REQ-13).

RED-phase contract test for T14. ``parse_model_output`` does not exist in
``datacon.agent_contracts`` yet, so the coordinate imports the contract face
inside the test function and fails at its own missing entry point. The v0.1
parser (``AgentOutput.from_mapping``) keeps its frozen semantics: a stored
v1 ``kind=fact`` record stays parseable read-only.
"""

from __future__ import annotations

import pytest

EVIDENCE = "git:commit/" + "a" * 40


def _model_payload(kind):
    return {
        "outcome": "ok",
        "artifacts": {},
        "findings": [
            {
                "kind": kind,
                "statement": "the terminator write can overrun the buffer",
                "confidence": "medium",
                "evidence_refs": [EVIDENCE],
            }
        ],
        "reason_code": None,
    }


def test_model_finding_must_be_hypothesis():
    from datacon.agent_contracts import (
        AgentOutput,
        ContractError,
        parse_model_output,
    )

    # Model-sourced kind=fact is blocked on the v2 port; the error names
    # the only allowed kind.
    with pytest.raises(ContractError, match="hypothesis"):
        parse_model_output(_model_payload("fact"))

    parsed = parse_model_output(_model_payload("hypothesis"))
    assert isinstance(parsed, AgentOutput)
    assert parsed.findings[0].kind == "hypothesis"

    # v1 compatibility must not regress: the frozen v0.1 parser still
    # accepts the same fact payload read-only.
    legacy = AgentOutput.from_mapping(_model_payload("fact"))
    assert legacy.findings[0].kind == "fact"

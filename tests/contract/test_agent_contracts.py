import pytest

from datacon.agent_contracts import (
    AgentInput,
    AgentOutput,
    ContractError,
    Finding,
    validate_findings,
)

EVIDENCE = "git:commit/" + "a" * 40


def test_agent_input_requires_exact_contract_fields():
    value = {
        "job_id": "4d6f7f56-1e0d-4d9f-9a4f-2a2cbf5d4d3f",
        "stage": "prepare",
        "state_version": 3,
        "deadline_at": "2026-01-02T00:00:00Z",
        "plan_digest": None,
        "inputs": {"case": "fixture-c-parser"},
        "policy_version": "1",
    }
    parsed = AgentInput.from_mapping(value)
    assert parsed.job_id == value["job_id"]
    assert parsed.inputs == {"case": "fixture-c-parser"}

    with pytest.raises(ContractError):
        AgentInput.from_mapping(value | {"unknown": 1})
    missing = dict(value)
    missing.pop("policy_version")
    with pytest.raises(ContractError):
        AgentInput.from_mapping(missing)
    with pytest.raises(ContractError):
        AgentInput.from_mapping(value | {"state_version": True})
    with pytest.raises(ContractError):
        AgentInput.from_mapping(value | {"deadline_at": "tomorrow"})
    with pytest.raises(ContractError):
        AgentInput.from_mapping(value | {"plan_digest": "not-a-digest"})


def test_finding_contract_rejects_unknown_enums_and_empty_text():
    with pytest.raises(ContractError):
        Finding.from_mapping(
            {
                "kind": "rumour",
                "statement": "x",
                "confidence": "high",
                "evidence_refs": [EVIDENCE],
            }
        )
    with pytest.raises(ContractError):
        Finding.from_mapping(
            {
                "kind": "fact",
                "statement": " ",
                "confidence": "high",
                "evidence_refs": [EVIDENCE],
            }
        )
    with pytest.raises(ContractError):
        Finding.from_mapping(
            {
                "kind": "hypothesis",
                "statement": "x",
                "confidence": "certain",
                "evidence_refs": [EVIDENCE],
            }
        )
    with pytest.raises(ContractError):
        Finding.from_mapping(
            {
                "kind": "fact",
                "statement": "x",
                "confidence": "high",
                "evidence_refs": [EVIDENCE],
                "extra": 1,
            }
        )


def test_findings_require_resolvable_evidence():
    fact = Finding("fact", "parse_token is patched", "high", (EVIDENCE,))
    hypothesis = Finding(
        "hypothesis", "the write is the root cause", "medium", (EVIDENCE,)
    )

    assert validate_findings([fact, hypothesis], {EVIDENCE}) == (fact, hypothesis)

    with pytest.raises(ContractError):
        validate_findings(
            [Finding("fact", "unsupported", "high", ())], {EVIDENCE}
        )
    with pytest.raises(ContractError):
        validate_findings(
            [Finding("hypothesis", "unsupported inference", "low", ())],
            {EVIDENCE},
        )
    with pytest.raises(ContractError):
        validate_findings(
            [Finding("fact", "forged", "high", ("git:commit/" + "b" * 40,))],
            {EVIDENCE},
        )
    with pytest.raises(ContractError):
        validate_findings(
            [Finding("hypothesis", "bad ref", "low", ("intel/\x00",))], {EVIDENCE}
        )


def test_hypothesis_without_evidence_is_rejected_by_the_wire_contract():
    with pytest.raises(ContractError):
        Finding.from_mapping(
            {
                "kind": "hypothesis",
                "statement": "a hypothesis with no evidence",
                "confidence": "low",
                "evidence_refs": [],
            }
        )


def test_agent_output_requires_reason_for_non_ok_outcomes():
    base = {
        "outcome": "ok",
        "artifacts": {},
        "findings": [],
        "reason_code": None,
    }
    output = AgentOutput.from_mapping(base)
    assert output.outcome == "ok"

    with pytest.raises(ContractError):
        AgentOutput.from_mapping(base | {"outcome": "maybe"})
    with pytest.raises(ContractError):
        AgentOutput.from_mapping(base | {"outcome": "blocked"})
    with pytest.raises(ContractError):
        AgentOutput.from_mapping(
            base
            | {
                "outcome": "ok",
                "findings": [
                    {
                        "kind": "fact",
                        "statement": "x",
                        "confidence": "high",
                        "evidence_refs": [],
                    }
                ],
            }
        )
    with pytest.raises(ContractError):
        AgentOutput.from_mapping(base | {"artifacts": []})

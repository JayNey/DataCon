"""TC-13: ExperimentSpec closed nine-field contract (REQ-13).

RED-phase contract tests for T14. ``datacon.experiment_spec`` does not exist
yet, so each coordinate imports the contract face inside the test function:
every test then fails at its own missing module instead of one shared
module-level collection error. The valid payload below is the ExperimentSpec
example from interface-contract-delta section 4, used verbatim as fixture.
"""

from __future__ import annotations

import pytest

SPEC_FIELDS = (
    "target_symbol",
    "target_path",
    "target_line",
    "input_family",
    "mutation_constraints",
    "expected_signature",
    "rationale",
    "evidence_refs",
    "confidence",
)


def _valid_spec_payload():
    return {
        "target_symbol": "parse_token",
        "target_path": "src/parser.c",
        "target_line": 42,
        "input_family": "length_boundary",
        "mutation_constraints": {
            "max_input_bytes": 4096,
            "allowed_ops": ["append", "truncate"],
        },
        "expected_signature": {
            "error": "heap-buffer-overflow",
            "function": "parse_token",
            "source": "parser.c",
            "operation": "WRITE",
            "access_size": 1,
        },
        "rationale": "补丁在终止符写入前增加了长度检查，长度边界输入可复核该假设。",
        "evidence_refs": [
            "log/build:fixed#L10-12",
            "patch:fix.patch#hunk-2",
        ],
        "confidence": "medium",
    }


def test_experiment_spec_has_closed_nine_fields():
    from datacon.experiment_spec import (
        ExperimentSpecError,
        parse_experiment_spec,
    )

    payload = _valid_spec_payload()
    spec = parse_experiment_spec(payload)
    assert spec.target_symbol == "parse_token"
    assert spec.target_line == 42
    assert spec.confidence == "medium"

    # Missing any one of the nine required fields is rejected.
    for field in SPEC_FIELDS:
        missing = {
            key: value for key, value in payload.items() if key != field
        }
        with pytest.raises(ExperimentSpecError):
            parse_experiment_spec(missing)

    # An unknown tenth field is rejected.
    with pytest.raises(ExperimentSpecError):
        parse_experiment_spec(payload | {"tenth_field": "extra"})

    # Free command or shell material has no field to hide in: the closed
    # set rejects a command string as well as a concatenated shell recipe.
    with pytest.raises(ExperimentSpecError):
        parse_experiment_spec(payload | {"command": "sh -c ./run.sh"})
    with pytest.raises(ExperimentSpecError):
        parse_experiment_spec(
            payload | {"shell": "bash" + " -c 'gcc exploit.c'"}
        )

    # confidence outside {low, medium, high} is rejected.
    with pytest.raises(ExperimentSpecError):
        parse_experiment_spec(payload | {"confidence": "certain"})


def test_expected_signature_matches_full_accepted_signature():
    from datacon.experiment_spec import signature_matches

    full = {
        "error": "heap-buffer-overflow",
        "function": "parse_token",
        "source": "parser.c",
        "operation": "WRITE",
        "access_size": 1,
    }
    without_optional = {
        "error": "heap-buffer-overflow",
        "function": "parse_token",
        "source": "parser.c",
    }

    # Exact full-field equality matches, with and without optional fields.
    assert signature_matches(full, dict(full)) is True
    assert signature_matches(without_optional, dict(without_optional)) is True

    # The error string alone is not enough: a READ/WRITE difference or a
    # different access_size must not match.
    assert signature_matches(full, full | {"operation": "READ"}) is False
    assert signature_matches(full, full | {"access_size": 2}) is False

    # Presence of the optional fields participates in the comparison on
    # either side.
    assert signature_matches(full, dict(without_optional)) is False
    assert signature_matches(without_optional, dict(full)) is False

    # A missing required field never matches.
    incomplete = dict(without_optional)
    incomplete.pop("source")
    assert signature_matches(without_optional, incomplete) is False


def test_unresolvable_evidence_refs_block_experiment_spec():
    from datacon.experiment_spec import build_from_hypothesis

    payload = _valid_spec_payload()
    refs = list(payload["evidence_refs"])

    def deny_all(ref):
        return False

    def resolve_first(ref):
        return ref == refs[0]

    # No resolvable evidence ref: the hypothesis stays a lead on the caller
    # side; no spec is produced and nothing raises.
    assert build_from_hypothesis(payload, resolver=deny_all) is None

    # Any single resolvable ref is enough to build the spec, and the
    # evidence refs are preserved verbatim.
    spec = build_from_hypothesis(payload, resolver=resolve_first)
    assert spec is not None
    assert list(spec.evidence_refs) == refs

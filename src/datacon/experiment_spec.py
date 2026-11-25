"""ExperimentSpec: the closed nine-field experiment plan (REQ-13, TC-13).

A model only proposes hypotheses. ``build_from_hypothesis`` is the
deterministic bridge: a nine-field hypothesis payload becomes an
``ExperimentSpec`` only when at least one of its evidence references
resolves, otherwise the hypothesis stays a lead on the caller side.

The spec face is closed: exactly nine fields, and the two structured
fields are closed key sets of their own. ``mutation_constraints`` admits
``max_input_bytes`` and ``allowed_ops``, ``expected_signature`` the five
signature fields. Every value is checked before it is stored, type
included - a boolean or a float never passes for an integer, and an
explicit ``null`` never passes for an absent optional field - so no free
command, shell or other executable material has a field to hide in.

The envelope cross-checks (mutation_limits subset,
allowed_mutation_families membership, target range) are not enforced by
this parser: they compare the spec against an envelope the parser never
sees.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Callable

from datacon import jsonutil
from datacon.agent_contracts import CONFIDENCE_LEVELS, MAX_REF, MAX_STATEMENT

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
_SPEC_REQUIRED: set[str] = set(SPEC_FIELDS)
SIGNATURE_REQUIRED_FIELDS = ("error", "function", "source")
SIGNATURE_OPTIONAL_FIELDS = ("operation", "access_size")
_MUTATION_CONSTRAINT_FIELDS: set[str] = {"max_input_bytes", "allowed_ops"}

_MAX_TARGET_SYMBOL = 200
_MAX_TARGET_LINE = 2**31 - 1
# The envelope's ceilings, so a signature this module accepts is one the
# envelope can accept as well (state._ENVELOPE_MAX_ACCESS_SIZE). A contract
# test keeps the two rule sets aligned instead of a production import.
_MAX_ACCESS_SIZE = 2**31 - 1
_MAX_INPUT_BYTES = 2**31 - 1
_SIGNATURE_OPERATIONS = ("READ", "WRITE")
_MAX_TEXT = 200
_MAX_IDENTIFIER = 64
_MAX_LIST_ITEMS = 64
# A lower-case identifier: an input family or a mutation operation.
_IDENTIFIER = re.compile(r"[a-z][a-z0-9_]*")
# Unicode control characters (general category Cc): C0, DEL and C1.
# ``jsonutil.require_text`` rejects only C0 and DEL, so every text field
# of this module is checked again here.
_CONTROL = re.compile(r"[\x00-\x1f\x7f-\x9f]")


class ExperimentSpecError(ValueError):
    """An experiment spec payload violates the closed nine-field contract."""


def _plain_text(value: Any, label: str, maximum: int) -> str:
    """Require non-empty text: no control character, at most ``maximum`` long."""
    text = _text(value, label)
    if _CONTROL.search(text):
        raise ExperimentSpecError(f"{label} must not contain control characters")
    if len(text) > maximum:
        raise ExperimentSpecError(f"{label} must be at most {maximum} characters")
    return text


def _text(value: Any, label: str) -> str:
    """Require non-empty text through ``jsonutil.require_text``."""
    try:
        return jsonutil.require_text(value, label)
    except ValueError as error:
        raise ExperimentSpecError(str(error)) from error


def _ref(value: Any) -> str:
    text = _plain_text(value, "evidence_ref", MAX_REF)
    if any(character.isspace() for character in text):
        raise ExperimentSpecError("evidence_ref must not contain whitespace")
    return text


@dataclass(frozen=True)
class ExperimentSpec:
    target_symbol: str
    target_path: str
    target_line: int
    input_family: str
    mutation_constraints: dict[str, Any]
    expected_signature: dict[str, Any]
    rationale: str
    evidence_refs: tuple[str, ...]
    confidence: str


def validate_target_symbol(value: Any, label: str = "target_symbol") -> str:
    """Require a source symbol: non-empty, no whitespace or control characters.

    A symbol is at most 200 characters long. It has no identifier rule of
    its own, unlike ``validate_input_family``: scope resolution and
    template characters are ordinary symbol material (``NS::readHeader2``).
    """
    text = _text(value, label)
    if len(text) > _MAX_TARGET_SYMBOL:
        raise ExperimentSpecError(
            f"{label} must be at most {_MAX_TARGET_SYMBOL} characters"
        )
    if any(character.isspace() for character in text):
        raise ExperimentSpecError(f"{label} must not contain whitespace")
    if _CONTROL.search(text):
        raise ExperimentSpecError(f"{label} must not contain control characters")
    return text


def validate_target_path(value: Any, label: str = "target_path") -> str:
    """Require a repository-relative POSIX path.

    An absolute path, any ``..`` segment, a backslash and whitespace are
    all rejected, through ``jsonutil.safe_relative_path``; so is a control
    character.
    """
    try:
        text = jsonutil.safe_relative_path(value, label)
    except ValueError as error:
        raise ExperimentSpecError(str(error)) from error
    if _CONTROL.search(text):
        raise ExperimentSpecError(f"{label} must not contain control characters")
    return text


def validate_input_family(value: Any, label: str = "input_family") -> str:
    """Require a lower-case identifier such as ``length_boundary``."""
    if not isinstance(value, str) or _IDENTIFIER.fullmatch(value) is None:
        raise ExperimentSpecError(f"{label} must be a lower-case identifier")
    if len(value) > _MAX_IDENTIFIER:
        raise ExperimentSpecError(
            f"{label} must be at most {_MAX_IDENTIFIER} characters"
        )
    return value


def validate_case_id(value: Any, label: str = "case_id") -> str:
    """Require the identifier of the case an annotation or spec belongs to."""
    return _plain_text(value, label, _MAX_TEXT)


def validate_signature(signature: Any) -> dict[str, Any]:
    """Validate one signature and return a checked copy of it.

    ``error``/``function``/``source`` are required non-empty text.
    ``operation`` (``READ`` or ``WRITE``) and ``access_size`` (an integer
    from 1 to 2**31 - 1, where neither a boolean nor a float is an integer)
    are optional, but a key that is present must carry a valid value: an
    explicit ``null`` is rejected, never read as absent. No other key is
    accepted. Value and type rules are the envelope's for an accepted
    signature (``state._envelope_signature_set``), because a spec signature
    only ever counts by equalling one of them; text fields are held to two
    stricter rules on purpose, no control character and 200 characters at
    most. A contract test keeps the two rule sets in step.
    This is the one signature validation, shared by
    ``parse_experiment_spec`` and ``b04_eval``; the values are returned as
    given, never coerced. Raises ``ExperimentSpecError``.
    """
    try:
        document = jsonutil.require_object(
            signature,
            required=set(SIGNATURE_REQUIRED_FIELDS),
            optional=frozenset(SIGNATURE_OPTIONAL_FIELDS),
            label="expected_signature",
        )
        checked: dict[str, Any] = {
            name: _plain_text(
                document[name], f"expected_signature.{name}", _MAX_TEXT
            )
            for name in SIGNATURE_REQUIRED_FIELDS
        }
        if "operation" in document:
            operation = _plain_text(
                document["operation"], "expected_signature.operation", _MAX_TEXT
            )
            if operation not in _SIGNATURE_OPERATIONS:
                raise ValueError(
                    "expected_signature.operation must be READ or WRITE"
                )
            checked["operation"] = operation
        if "access_size" in document:
            access_size = document["access_size"]
            if type(access_size) is not int or not 1 <= access_size <= _MAX_ACCESS_SIZE:
                raise ValueError(
                    "expected_signature.access_size must be an integer between"
                    f" 1 and {_MAX_ACCESS_SIZE}"
                )
            checked["access_size"] = access_size
    except ValueError as error:
        raise ExperimentSpecError(str(error)) from error
    return checked


def _mutation_constraints(value: Any, label: str) -> dict[str, Any]:
    """Require the closed ``{max_input_bytes, allowed_ops}`` object."""
    try:
        constraints = jsonutil.require_object(
            value, required=_MUTATION_CONSTRAINT_FIELDS, label=label
        )
        max_input_bytes = constraints["max_input_bytes"]
        if (
            type(max_input_bytes) is not int
            or not 0 <= max_input_bytes <= _MAX_INPUT_BYTES
        ):
            raise ValueError(
                f"{label}.max_input_bytes must be an integer between 0 and"
                f" {_MAX_INPUT_BYTES}"
            )
        allowed_ops = constraints["allowed_ops"]
        if not isinstance(allowed_ops, list) or len(allowed_ops) > _MAX_LIST_ITEMS:
            raise ValueError(
                f"{label}.allowed_ops must be a list of at most"
                f" {_MAX_LIST_ITEMS} operations"
            )
        for index, operation in enumerate(allowed_ops):
            if (
                not isinstance(operation, str)
                or len(operation) > _MAX_IDENTIFIER
                or _IDENTIFIER.fullmatch(operation) is None
            ):
                raise ValueError(
                    f"{label}.allowed_ops[{index}] must be a lower-case"
                    f" identifier of at most {_MAX_IDENTIFIER} characters"
                )
    except ValueError as error:
        raise ExperimentSpecError(str(error)) from error
    return {
        "max_input_bytes": max_input_bytes,
        "allowed_ops": list(allowed_ops),
    }


def parse_experiment_spec(payload: dict[str, Any]) -> ExperimentSpec:
    """Parse a nine-field ExperimentSpec; every field is checked.

    The field set is closed and so are the key sets of
    ``mutation_constraints`` and ``expected_signature`` (the latter through
    ``validate_signature``). ``target_path`` is a repository-relative POSIX
    path, ``target_symbol`` a symbol of at most 200 characters,
    ``input_family`` a lower-case identifier and ``rationale`` a statement
    of at most ``agent_contracts.MAX_STATEMENT`` characters. The stored
    sub-objects are copies: the spec shares no mutable value with
    ``payload``.
    """
    try:
        document = jsonutil.require_object(
            payload, required=_SPEC_REQUIRED, label="ExperimentSpec"
        )
        target_symbol = validate_target_symbol(
            document["target_symbol"], "ExperimentSpec.target_symbol"
        )
        target_path = validate_target_path(
            document["target_path"], "ExperimentSpec.target_path"
        )
        target_line = jsonutil.require_int(
            document["target_line"],
            "ExperimentSpec.target_line",
            minimum=1,
            maximum=_MAX_TARGET_LINE,
        )
        input_family = validate_input_family(
            document["input_family"], "ExperimentSpec.input_family"
        )
        mutation_constraints = _mutation_constraints(
            document["mutation_constraints"], "ExperimentSpec.mutation_constraints"
        )
        expected_signature = validate_signature(document["expected_signature"])
        rationale = _plain_text(
            document["rationale"], "ExperimentSpec.rationale", MAX_STATEMENT
        )
        refs = document["evidence_refs"]
        if not isinstance(refs, list) or len(refs) > _MAX_LIST_ITEMS:
            raise ExperimentSpecError(
                "ExperimentSpec.evidence_refs must be a list of at most"
                f" {_MAX_LIST_ITEMS} references"
            )
        evidence_refs = tuple(_ref(ref) for ref in refs)
        confidence = document["confidence"]
        if not isinstance(confidence, str) or confidence not in CONFIDENCE_LEVELS:
            raise ExperimentSpecError(
                "ExperimentSpec.confidence must be low, medium or high"
            )
        return ExperimentSpec(
            target_symbol,
            target_path,
            target_line,
            input_family,
            mutation_constraints,
            expected_signature,
            rationale,
            evidence_refs,
            confidence,
        )
    except ExperimentSpecError:
        raise
    except ValueError as error:
        raise ExperimentSpecError(str(error)) from error


def signature_matches(
    expected_signature: dict[str, Any], accepted_item: dict[str, Any]
) -> bool:
    """Strict full-field match of an expected signature against one accepted item.

    ``error``/``function``/``source`` are required on both sides;
    ``operation``/``access_size`` are optional but their presence or
    absence participates in the comparison on either side. A key matches
    only when both sides carry the same value with the same type: ``True``
    is not ``1``, and ``1.0`` is not ``1``.
    """
    if not isinstance(expected_signature, dict) or not isinstance(accepted_item, dict):
        return False
    for name in SIGNATURE_REQUIRED_FIELDS:
        if name not in expected_signature or name not in accepted_item:
            return False
    if set(expected_signature) != set(accepted_item):
        return False
    return all(
        type(expected_signature[name]) is type(accepted_item[name])
        and expected_signature[name] == accepted_item[name]
        for name in expected_signature
    )


def build_from_hypothesis(
    payload: dict[str, Any], *, resolver: Callable[[str], bool]
) -> ExperimentSpec | None:
    """Build a spec from a hypothesis payload when any evidence ref resolves.

    A hypothesis whose evidence references are all unresolvable stays a
    lead on the caller side: no spec is produced and nothing raises. When
    at least one reference resolves, the spec is built with its
    ``evidence_refs`` preserved verbatim.
    """
    spec = parse_experiment_spec(payload)
    if not any(resolver(reference) for reference in spec.evidence_refs):
        return None
    return spec

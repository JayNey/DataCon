"""ExperimentSpec: the closed nine-field experiment plan (REQ-13, TC-13).

A model only proposes hypotheses. ``build_from_hypothesis`` is the
deterministic bridge: a nine-field hypothesis payload becomes an
``ExperimentSpec`` only when at least one of its evidence references
resolves, otherwise the hypothesis stays a lead on the caller side. The
spec face is closed—nine fields, no free command, shell or other
executable material has a field to hide in. The envelope cross-checks
(mutation_limits subset, target range, input_family membership) land with
the T10 envelope in T14 and are not enforced by this parser yet.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable

from datacon import jsonutil
from datacon.agent_contracts import CONFIDENCE_LEVELS, MAX_REF

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


class ExperimentSpecError(ValueError):
    """An experiment spec payload violates the closed nine-field contract."""


def _text(value: Any, label: str) -> str:
    return jsonutil.require_text(value, label)


def _ref(value: Any) -> str:
    text = jsonutil.require_text(value, "evidence_ref")
    if len(text) > MAX_REF:
        raise ExperimentSpecError("evidence_ref is too long")
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


def parse_experiment_spec(payload: dict[str, Any]) -> ExperimentSpec:
    """Parse a nine-field ExperimentSpec; the field set is closed."""
    try:
        document = jsonutil.require_object(
            payload, required=_SPEC_REQUIRED, label="ExperimentSpec"
        )
        target_symbol = _text(document["target_symbol"], "ExperimentSpec.target_symbol")
        target_path = _text(document["target_path"], "ExperimentSpec.target_path")
        target_line = jsonutil.require_int(
            document["target_line"],
            "ExperimentSpec.target_line",
            minimum=1,
            maximum=2**31 - 1,
        )
        input_family = _text(document["input_family"], "ExperimentSpec.input_family")
        mutation_constraints = document["mutation_constraints"]
        if not isinstance(mutation_constraints, dict):
            raise ExperimentSpecError(
                "ExperimentSpec.mutation_constraints must be an object"
            )
        expected_signature = document["expected_signature"]
        if not isinstance(expected_signature, dict):
            raise ExperimentSpecError(
                "ExperimentSpec.expected_signature must be an object"
            )
        rationale = _text(document["rationale"], "ExperimentSpec.rationale")
        refs = document["evidence_refs"]
        if not isinstance(refs, list):
            raise ExperimentSpecError("ExperimentSpec.evidence_refs must be a list")
        evidence_refs = tuple(_ref(ref) for ref in refs)
        confidence = document["confidence"]
        if confidence not in CONFIDENCE_LEVELS:
            raise ExperimentSpecError(
                "ExperimentSpec.confidence must be low, medium or high"
            )
        return ExperimentSpec(
            target_symbol,
            target_path,
            target_line,
            input_family,
            dict(mutation_constraints),
            dict(expected_signature),
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
    absence participates in the comparison on either side.
    """
    if not isinstance(expected_signature, dict) or not isinstance(accepted_item, dict):
        return False
    for name in SIGNATURE_REQUIRED_FIELDS:
        if name not in expected_signature or name not in accepted_item:
            return False
    if set(expected_signature) != set(accepted_item):
        return False
    return bool(expected_signature == accepted_item)


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

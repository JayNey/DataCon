"""Typed AgentInput/AgentOutput contracts and evidence validation."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable

from datacon import jsonutil

FINDING_KINDS = frozenset({"fact", "hypothesis"})
CONFIDENCE_LEVELS = frozenset({"low", "medium", "high"})
OUTCOMES = frozenset({"ok", "blocked", "error"})
MAX_STATEMENT = 2000
MAX_REF = 512


class ContractError(ValueError):
    """A typed agent value does not satisfy the interface contract."""


def _text(value: Any, label: str, *, maximum: int = MAX_STATEMENT) -> str:
    text = jsonutil.require_text(value, label)
    if len(text) > maximum:
        raise ContractError(f"{label} exceeds {maximum} characters")
    return text


def _ref(value: Any) -> str:
    text = jsonutil.require_text(value, "evidence_ref")
    if len(text) > MAX_REF:
        raise ContractError("evidence_ref is too long")
    if any(character.isspace() for character in text):
        raise ContractError("evidence_ref must not contain whitespace")
    return text


@dataclass(frozen=True)
class Finding:
    kind: str
    statement: str
    confidence: str
    evidence_refs: tuple[str, ...]

    @classmethod
    def from_mapping(cls, value: Any) -> "Finding":
        try:
            document = jsonutil.require_object(
                value,
                required={"kind", "statement", "confidence", "evidence_refs"},
                label="finding",
            )
            kind = document["kind"]
            if kind not in FINDING_KINDS:
                raise ContractError("finding.kind must be fact or hypothesis")
            statement = _text(document["statement"], "finding.statement")
            confidence = document["confidence"]
            if confidence not in CONFIDENCE_LEVELS:
                raise ContractError(
                    "finding.confidence must be low, medium or high"
                )
            refs = document["evidence_refs"]
            if not isinstance(refs, list):
                raise ContractError("finding.evidence_refs must be a list")
            evidence_refs = tuple(_ref(ref) for ref in refs)
            if kind == "fact" and not evidence_refs:
                raise ContractError("a fact requires at least one evidence reference")
            return cls(kind, statement, confidence, evidence_refs)
        except ContractError:
            raise
        except ValueError as error:
            raise ContractError(str(error)) from error

    def as_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "statement": self.statement,
            "confidence": self.confidence,
            "evidence_refs": list(self.evidence_refs),
        }


@dataclass(frozen=True)
class ModelContext:
    cve_id: str
    advisory: dict[str, Any]
    diff: dict[str, Any]
    symbols: tuple[dict[str, Any], ...]
    evidence_refs: frozenset[str]


@dataclass(frozen=True)
class ModelSuggestion:
    findings: tuple[Finding, ...] = ()


class AnalysisModel:
    """Optional typed model port; the default implementation is offline."""

    def propose(self, context: ModelContext) -> ModelSuggestion:
        return ModelSuggestion()


def validate_findings(
    findings: Iterable[Finding], allowed_refs: set[str] | frozenset[str]
) -> tuple[Finding, ...]:
    """Validate evidence references; facts may not rest on missing evidence."""
    validated: list[Finding] = []
    for finding in findings:
        if not isinstance(finding, Finding):
            raise ContractError("finding must be a Finding instance")
        if finding.kind not in FINDING_KINDS:
            raise ContractError("finding.kind must be fact or hypothesis")
        if finding.confidence not in CONFIDENCE_LEVELS:
            raise ContractError("finding.confidence is invalid")
        try:
            _text(finding.statement, "finding.statement")
        except ValueError as error:
            raise ContractError(str(error)) from error
        if finding.kind == "fact" and not finding.evidence_refs:
            raise ContractError("a fact requires at least one evidence reference")
        for reference in finding.evidence_refs:
            try:
                _ref(reference)
            except ValueError as error:
                raise ContractError(str(error)) from error
            if reference not in allowed_refs:
                raise ContractError(
                    f"evidence reference is not resolvable: {reference}"
                )
        validated.append(finding)
    return tuple(validated)


@dataclass(frozen=True)
class AgentInput:
    job_id: str
    stage: str
    state_version: int
    deadline_at: str
    plan_digest: str | None
    inputs: dict[str, str]
    policy_version: str

    @classmethod
    def from_mapping(cls, value: Any) -> "AgentInput":
        try:
            document = jsonutil.require_object(
                value,
                required={
                    "job_id",
                    "stage",
                    "state_version",
                    "deadline_at",
                    "plan_digest",
                    "inputs",
                    "policy_version",
                },
                label="AgentInput",
            )
            job_id = _text(document["job_id"], "AgentInput.job_id", maximum=128)
            stage = _text(document["stage"], "AgentInput.stage", maximum=64)
            state_version = jsonutil.require_int(
                document["state_version"],
                "AgentInput.state_version",
                minimum=0,
                maximum=2**63 - 1,
            )
            deadline_at = jsonutil.require_rfc3339(
                document["deadline_at"], "AgentInput.deadline_at"
            )
            plan_digest = document["plan_digest"]
            if plan_digest is not None:
                plan_digest = jsonutil.require_digest(
                    plan_digest, "AgentInput.plan_digest"
                )
            inputs = document["inputs"]
            if not isinstance(inputs, dict):
                raise ValueError("AgentInput.inputs must be an object")
            parsed_inputs = {
                _text(key, "AgentInput.inputs key", maximum=128): _text(
                    item, "AgentInput.inputs value", maximum=512
                )
                for key, item in inputs.items()
            }
            policy_version = _text(
                document["policy_version"], "AgentInput.policy_version", maximum=64
            )
            return cls(
                job_id,
                stage,
                state_version,
                deadline_at,
                plan_digest,
                parsed_inputs,
                policy_version,
            )
        except ContractError:
            raise
        except ValueError as error:
            raise ContractError(str(error)) from error


@dataclass(frozen=True)
class AgentOutput:
    outcome: str
    artifacts: dict[str, Any] = field(default_factory=dict)
    findings: tuple[Finding, ...] = ()
    reason_code: str | None = None

    @classmethod
    def from_mapping(cls, value: Any) -> "AgentOutput":
        try:
            document = jsonutil.require_object(
                value,
                required={"outcome", "artifacts", "findings", "reason_code"},
                label="AgentOutput",
            )
            outcome = document["outcome"]
            if outcome not in OUTCOMES:
                raise ContractError("AgentOutput.outcome is invalid")
            artifacts = document["artifacts"]
            if not isinstance(artifacts, dict):
                raise ContractError("AgentOutput.artifacts must be an object")
            if not isinstance(document["findings"], list):
                raise ContractError("AgentOutput.findings must be a list")
            findings = tuple(
                Finding.from_mapping(item) for item in document["findings"]
            )
            reason_code = document["reason_code"]
            if reason_code is not None:
                reason_code = _text(
                    reason_code, "AgentOutput.reason_code", maximum=64
                )
            if outcome != "ok" and reason_code is None:
                raise ContractError(
                    "AgentOutput.reason_code is required when outcome is not ok"
                )
            return cls(outcome, artifacts, findings, reason_code)
        except ContractError:
            raise
        except ValueError as error:
            raise ContractError(str(error)) from error

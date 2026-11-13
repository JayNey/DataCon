"""Version 1 request, analysis and plan contracts for DataCon."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from typing import Any

from datacon import cases as case_registry
from datacon import jsonutil

SCHEMA_VERSION = 1

DEFAULT_LIMITS: dict[str, int] = {
    "prepare_seconds": 600,
    "execute_seconds": 1200,
    "replay_seconds": 10,
    "cpu": 2,
    "memory_mib": 2048,
    "pids": 128,
    "scratch_mib": 512,
}

_CVE_ID = re.compile(r"CVE-[0-9]{4}-[0-9]{4,}")
_SHA256 = re.compile(r"sha256:[0-9a-f]{64}")
_GIT_OID = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})")
_TARGET_KEYS = frozenset({"kind", "case_id", "goal"})
_PLAN_FIELDS = frozenset(
    {
        "case_id",
        "cve_id",
        "case_config_digest",
        "repository",
        "revisions",
        "dependencies_digest",
        "image_digest",
        "platform",
        "toolchain",
        "asan_options",
        "build_recipe_digest",
        "harness_digest",
        "inputs",
        "expected_exit",
        "asan_signature",
        "limits",
        "isolation",
        "intel",
        "analysis",
        "analysis_digest",
        "policy_version",
    }
)
_ANALYSIS_FIELDS = frozenset(
    {"diff_digest", "changed_paths", "symbols", "findings"}
)
_SYMBOL_FIELDS = frozenset(
    {"name", "path", "role", "revision", "start_line", "end_line"}
)
_FINDING_FIELDS = frozenset(
    {"kind", "statement", "confidence", "evidence_refs"}
)
_ROLES = frozenset({"definition", "call_site"})
_REVISIONS = frozenset({"vulnerable", "fixed", "harness"})
_FINDING_KINDS = frozenset({"fact", "hypothesis"})
_CONFIDENCE = frozenset({"low", "medium", "high"})


class InvalidRequest(ValueError):
    """The request does not conform to the version 1 input contract."""


def _object(value: Any, *, required: set[str], optional: set[str] = frozenset()) -> Mapping:
    if not isinstance(value, dict):
        raise ValueError("expected a JSON object")
    actual = set(value)
    missing = required - actual
    unknown = actual - required - optional
    if missing:
        raise ValueError(f"missing required field(s): {', '.join(sorted(missing))}")
    if unknown:
        raise ValueError(f"unknown field(s): {', '.join(sorted(unknown))}")
    return value


def _text(value: Any, *, label: str) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{label} must be a string")
    if not value.strip():
        raise ValueError(f"{label} must not be empty")
    if "\x00" in value:
        raise ValueError(f"{label} must not contain NUL bytes")
    value.encode("utf-8")
    return value


def _limits(value: Any, *, require_all: bool) -> dict[str, int]:
    _object(
        value,
        required=set(DEFAULT_LIMITS) if require_all else set(),
        optional=set(DEFAULT_LIMITS),
    )
    limits = dict(DEFAULT_LIMITS)
    limits.update(value)
    for key, amount in limits.items():
        if type(amount) is not int or not 1 <= amount <= DEFAULT_LIMITS[key]:
            raise ValueError(
                f"{key} must be an integer between 1 and {DEFAULT_LIMITS[key]}"
            )
    if limits["replay_seconds"] > limits["execute_seconds"]:
        raise ValueError("replay_seconds must not exceed execute_seconds")
    return limits


def _git_oid(value: Any, *, label: str) -> str:
    oid = _text(value, label=label)
    if not _GIT_OID.fullmatch(oid):
        raise ValueError(f"{label} must be a full lowercase Git object ID")
    return oid


def _digest(value: Any, *, label: str) -> str:
    digest = _text(value, label=label)
    if not _SHA256.fullmatch(digest):
        raise ValueError(f"{label} must be a sha256 digest")
    return digest


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    return jsonutil._unique_object(pairs)


def _reject_constant(value: str) -> None:
    jsonutil._reject_constant(value)


def _registered_cases() -> Mapping[str, str]:
    try:
        return case_registry.registered_cves()
    except case_registry.CaseConfigurationError as error:
        raise ValueError(f"case registry is unavailable: {error.message}") from error


def _validate_request(request: Any) -> dict[str, Any]:
    _object(
        request,
        required={"schema_version", "cve_id", "target"},
        optional={"limits"},
    )
    version = request["schema_version"]
    if type(version) is not int or version != SCHEMA_VERSION:
        raise ValueError(f"schema_version must be {SCHEMA_VERSION}")

    cve_id = _text(request["cve_id"], label="cve_id")
    if not _CVE_ID.fullmatch(cve_id):
        raise ValueError("cve_id must match CVE-YYYY-NNNN")

    target = _object(
        request["target"],
        required=set(_TARGET_KEYS),
    )
    kind = target["kind"]
    if kind not in ("source", "binary"):
        raise ValueError("target.kind must be source or binary")
    case_id = _text(target["case_id"], label="target.case_id")
    goal = _text(target["goal"], label="target.goal")
    registered = _registered_cases().get(case_id)
    if registered is None:
        raise ValueError("target.case_id is not registered")
    if registered != cve_id:
        raise ValueError("target.case_id is not registered for cve_id")

    limits_value = request["limits"] if "limits" in request else {}
    limits = _limits(limits_value, require_all=False)
    return {
        "schema_version": version,
        "cve_id": cve_id,
        "target": {"kind": kind, "case_id": case_id, "goal": goal},
        "limits": limits,
    }


def parse_request(payload: str | bytes) -> dict[str, Any]:
    """Parse and validate a request, filling omitted budget fields.

    JSON is decoded as strict UTF-8. Duplicate object keys and non-finite
    numbers are rejected before any database connection is opened.
    """
    try:
        if isinstance(payload, bytes):
            payload = payload.decode("utf-8")
        if not isinstance(payload, str):
            raise ValueError("request payload must be text or UTF-8 bytes")
        document = json.loads(
            payload,
            object_pairs_hook=_unique_object,
            parse_constant=_reject_constant,
        )
        return _validate_request(document)
    except (ValueError, RecursionError) as error:
        raise InvalidRequest(str(error)) from error


def _evidence_ref(value: Any) -> str:
    text = _text(value, label="evidence_ref")
    if len(text) > 512:
        raise ValueError("evidence_ref is too long")
    if any(character.isspace() for character in text):
        raise ValueError("evidence_ref must not contain whitespace")
    return text


def _normalize_symbol(value: Any) -> dict[str, Any]:
    _object(value, required=set(_SYMBOL_FIELDS))
    name = _text(value["name"], label="symbol.name")
    path = jsonutil.safe_relative_path(value["path"], "symbol.path")
    role = value["role"]
    if role not in _ROLES:
        raise ValueError("symbol.role must be definition or call_site")
    revision = value["revision"]
    if revision not in _REVISIONS:
        raise ValueError("symbol.revision is invalid")
    start = value["start_line"]
    end = value["end_line"]
    if type(start) is not int or type(end) is not int:
        raise ValueError("symbol lines must be integers")
    if not 1 <= start <= end <= 10_000_000:
        raise ValueError("symbol line range is invalid")
    return {
        "name": name,
        "path": path,
        "role": role,
        "revision": revision,
        "start_line": start,
        "end_line": end,
    }


def _normalize_finding(value: Any) -> dict[str, Any]:
    _object(value, required=set(_FINDING_FIELDS))
    kind = value["kind"]
    if kind not in _FINDING_KINDS:
        raise ValueError("finding.kind must be fact or hypothesis")
    statement = _text(value["statement"], label="finding.statement")
    if len(statement) > 2000:
        raise ValueError("finding.statement is too long")
    confidence = value["confidence"]
    if confidence not in _CONFIDENCE:
        raise ValueError("finding.confidence is invalid")
    refs = value["evidence_refs"]
    if not isinstance(refs, list):
        raise ValueError("finding.evidence_refs must be a list")
    evidence_refs = sorted({_evidence_ref(ref) for ref in refs})
    if not evidence_refs:
        raise ValueError("a finding requires at least one evidence reference")
    return {
        "kind": kind,
        "statement": statement,
        "confidence": confidence,
        "evidence_refs": evidence_refs,
    }


def _normalize_analysis(analysis: Any) -> dict[str, Any]:
    _object(analysis, required=set(_ANALYSIS_FIELDS))
    diff_digest = _digest(analysis["diff_digest"], label="analysis.diff_digest")

    changed = analysis["changed_paths"]
    if not isinstance(changed, list) or not changed:
        raise ValueError("analysis.changed_paths must be a non-empty list")
    changed_paths = sorted(
        {
            jsonutil.safe_relative_path(path, "analysis.changed_paths")
            for path in changed
        }
    )

    symbols = analysis["symbols"]
    if not isinstance(symbols, list):
        raise ValueError("analysis.symbols must be a list")
    normalized_symbols = sorted(
        (_normalize_symbol(symbol) for symbol in symbols),
        key=lambda symbol: (
            symbol["path"],
            symbol["start_line"],
            symbol["role"],
            symbol["name"],
            symbol["revision"],
        ),
    )

    findings = analysis["findings"]
    if not isinstance(findings, list):
        raise ValueError("analysis.findings must be a list")
    normalized_findings = sorted(
        (_normalize_finding(finding) for finding in findings),
        key=lambda finding: (
            finding["kind"],
            finding["statement"],
            finding["confidence"],
            tuple(finding["evidence_refs"]),
        ),
    )

    return {
        "diff_digest": diff_digest,
        "changed_paths": changed_paths,
        "symbols": normalized_symbols,
        "findings": normalized_findings,
    }


def canonical_analysis_bytes(analysis: Mapping[str, Any]) -> bytes:
    """Return the canonical analysis encoding bound by the plan digest."""
    return jsonutil.canonical_bytes(_normalize_analysis(analysis))


def analysis_digest(analysis: Mapping[str, Any]) -> str:
    return "sha256:" + hashlib.sha256(canonical_analysis_bytes(analysis)).hexdigest()


def _isolation(value: Any) -> dict[str, Any]:
    _object(
        value,
        required={
            "network",
            "user",
            "read_only_root",
            "cap_drop",
            "no_new_privileges",
            "seccomp",
        },
    )
    network = _text(value["network"], label="isolation.network")
    if network != "none":
        raise ValueError("isolation.network must be none")
    user = _text(value["user"], label="isolation.user")
    if not value["read_only_root"] is True:
        raise ValueError("isolation.read_only_root must be true")
    caps = value["cap_drop"]
    if (
        not isinstance(caps, list)
        or not caps
        or any(not isinstance(cap, str) or not cap.strip() for cap in caps)
        or "ALL" not in caps
    ):
        raise ValueError("isolation.cap_drop must include ALL")
    if not value["no_new_privileges"] is True:
        raise ValueError("isolation.no_new_privileges must be true")
    seccomp = _text(value["seccomp"], label="isolation.seccomp")
    return {
        "network": network,
        "user": user,
        "read_only_root": True,
        "cap_drop": sorted(set(caps)),
        "no_new_privileges": True,
        "seccomp": seccomp,
    }


def _intel(value: Any) -> dict[str, Any]:
    _object(
        value,
        required={"snapshot", "collected_at", "content_digest", "sources"},
    )
    snapshot = jsonutil.safe_relative_path(value["snapshot"], "intel.snapshot")
    collected_at = jsonutil.require_rfc3339(
        value["collected_at"], "intel.collected_at"
    )
    content_digest = _digest(value["content_digest"], label="intel.content_digest")
    sources = value["sources"]
    if not isinstance(sources, list) or not sources:
        raise ValueError("intel.sources must be a non-empty list")
    normalized_sources = []
    for source in sources:
        text = _text(source, label="intel.sources")
        if not text.startswith("https://") or any(c.isspace() for c in text):
            raise ValueError("intel.sources must contain https URLs")
        normalized_sources.append(text)
    return {
        "snapshot": snapshot,
        "collected_at": collected_at,
        "content_digest": content_digest,
        "sources": sorted(set(normalized_sources)),
    }


def _expected_exit(value: Any) -> dict[str, int]:
    _object(
        value,
        required={"normal", "candidate_clean"},
        optional={"candidate_asan"},
    )
    result = {}
    for key, amount in value.items():
        if type(amount) is not int or not 0 <= amount <= 255:
            raise ValueError(f"expected_exit.{key} must be an exit code")
        result[key] = amount
    return result


def _toolchain_value(value: Any, label: str) -> Any:
    """Validate the case toolchain as a small, JSON-safe object graph."""
    if value is None or type(value) in (str, bool, int):
        return value
    if isinstance(value, float):
        raise ValueError(f"{label} must not contain a floating-point value")
    if isinstance(value, list):
        return [
            _toolchain_value(item, f"{label}[{index}]")
            for index, item in enumerate(value)
        ]
    if isinstance(value, dict):
        if not value:
            raise ValueError(f"{label} must not be empty")
        result = {}
        for key, item in value.items():
            if not isinstance(key, str) or not key.strip():
                raise ValueError(f"{label} keys must be non-empty strings")
            result[key] = _toolchain_value(item, f"{label}.{key}")
        return result
    raise ValueError(f"{label} contains an unsupported value")


def _normalize_plan(plan: Mapping[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    _object(plan, required=set(_PLAN_FIELDS))
    case_id = _text(plan["case_id"], label="case_id")
    cve_id = _text(plan["cve_id"], label="cve_id")
    if not _CVE_ID.fullmatch(cve_id):
        raise ValueError("cve_id must match CVE-YYYY-NNNN")

    repository = _object(
        plan["repository"],
        required={"origin", "bundle_digest", "patch_digest"},
    )
    origin = _text(repository["origin"], label="repository.origin")
    if not origin.startswith(("https://", "fixture://")):
        raise ValueError("repository.origin must be https:// or fixture://")
    if any(character.isspace() for character in origin):
        raise ValueError("repository.origin must not contain whitespace")

    revisions = _object(
        plan["revisions"],
        required={"vulnerable", "fixed"},
    )
    vulnerable = _git_oid(revisions["vulnerable"], label="revisions.vulnerable")
    fixed = _git_oid(revisions["fixed"], label="revisions.fixed")
    if len(vulnerable) != len(fixed):
        raise ValueError("revisions must use the same Git object format")

    inputs = _object(plan["inputs"], required={"candidate", "normal"})
    candidate = _digest(inputs["candidate"], label="inputs.candidate")
    normal = _digest(inputs["normal"], label="inputs.normal")

    signature = _object(
        plan["asan_signature"],
        required={"error", "function", "source"},
    )
    asan_signature = {
        "error": _text(signature["error"], label="asan_signature.error"),
        "function": _text(signature["function"], label="asan_signature.function"),
        "source": _text(signature["source"], label="asan_signature.source"),
    }

    platform = _text(plan["platform"], label="platform")
    toolchain = _toolchain_value(plan["toolchain"], "toolchain")
    asan_options = _text(plan["asan_options"], label="asan_options")

    analysis = _normalize_analysis(plan["analysis"])
    computed_analysis_digest = (
        "sha256:" + hashlib.sha256(jsonutil.canonical_bytes(analysis)).hexdigest()
    )
    declared_analysis_digest = _digest(
        plan["analysis_digest"], label="analysis_digest"
    )
    if declared_analysis_digest != computed_analysis_digest:
        raise ValueError("analysis_digest does not match the supplied analysis")

    normalized = {
        "case_id": case_id,
        "cve_id": cve_id,
        "case_config_digest": _digest(
            plan["case_config_digest"], label="case_config_digest"
        ),
        "repository": {
            "origin": origin,
            "bundle_digest": _digest(
                repository["bundle_digest"], label="repository.bundle_digest"
            ),
            "patch_digest": _digest(
                repository["patch_digest"], label="repository.patch_digest"
            ),
        },
        "revisions": {"vulnerable": vulnerable, "fixed": fixed},
        "dependencies_digest": _digest(
            plan["dependencies_digest"], label="dependencies_digest"
        ),
        "image_digest": _digest(plan["image_digest"], label="image_digest"),
        "platform": platform,
        "toolchain": toolchain,
        "asan_options": asan_options,
        "build_recipe_digest": _digest(
            plan["build_recipe_digest"], label="build_recipe_digest"
        ),
        "harness_digest": _digest(plan["harness_digest"], label="harness_digest"),
        "inputs": {"candidate": candidate, "normal": normal},
        "expected_exit": _expected_exit(plan["expected_exit"]),
        "asan_signature": asan_signature,
        "limits": _limits(plan["limits"], require_all=True),
        "isolation": _isolation(plan["isolation"]),
        "intel": _intel(plan["intel"]),
        "analysis_digest": computed_analysis_digest,
        "policy_version": _text(plan["policy_version"], label="policy_version"),
    }
    return normalized, analysis


def canonical_plan_bytes(plan: Mapping[str, Any]) -> bytes:
    """Validate plan fields and return sorted, compact, UTF-8 JSON bytes.

    The digest rule is intentionally explicit: only the normalized fields are
    included, keys are sorted, there is no insignificant whitespace, and
    non-ASCII text is encoded as UTF-8. The full analysis document is bound by
    ``analysis_digest`` rather than inlined into this encoding.
    """
    normalized, _ = _normalize_plan(plan)
    return jsonutil.canonical_bytes(normalized)


def plan_digest(plan: Mapping[str, Any]) -> str:
    return "sha256:" + hashlib.sha256(canonical_plan_bytes(plan)).hexdigest()


def plan_summary(plan: Mapping[str, Any]) -> dict[str, Any]:
    """Return the concise, review-facing summary stored with a frozen plan."""
    normalized, analysis = _normalize_plan(plan)
    facts = sum(1 for finding in analysis["findings"] if finding["kind"] == "fact")
    hypotheses = len(analysis["findings"]) - facts
    return {
        "case_id": normalized["case_id"],
        "cve_id": normalized["cve_id"],
        "revisions": normalized["revisions"],
        "changed_paths": analysis["changed_paths"],
        "findings": {"facts": facts, "hypotheses": hypotheses},
        "inputs": normalized["inputs"],
        "expected_exit": normalized["expected_exit"],
        "platform": normalized["platform"],
        "toolchain": normalized["toolchain"],
        "asan_options": normalized["asan_options"],
        "asan_signature": normalized["asan_signature"],
        "limits": normalized["limits"],
        "isolation": normalized["isolation"],
        "intel": {
            "snapshot": normalized["intel"]["snapshot"],
            "collected_at": normalized["intel"]["collected_at"],
            "content_digest": normalized["intel"]["content_digest"],
        },
        "analysis_digest": normalized["analysis_digest"],
        "policy_version": normalized["policy_version"],
    }

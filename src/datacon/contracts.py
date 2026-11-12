"""Version 1 request and plan contracts for the DataCon task entry point."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from typing import Any

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

# The MVP entry point accepts only cases that are registered locally. T04
# replaces this table with the full material registry.
CASE_REGISTRY: dict[str, str] = {
    "fixture-c-parser": "CVE-2099-0001",
    "fixture-c-parser-clean": "CVE-2099-0001",
}

_CVE_ID = re.compile(r"CVE-[0-9]{4}-[0-9]{4,}")
_SHA256 = re.compile(r"sha256:[0-9a-f]{64}")
_GIT_OID = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})")
_TARGET_KEYS = frozenset({"kind", "case_id", "goal"})
_PLAN_FIELDS = frozenset(
    {
        "case_id",
        "case_config_digest",
        "revisions",
        "dependencies_digest",
        "image_digest",
        "build_recipe_digest",
        "harness_digest",
        "inputs",
        "asan_signature",
        "limits",
        "policy_version",
    }
)


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
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _reject_constant(value: str) -> None:
    raise ValueError(f"non-finite JSON number is not allowed: {value}")


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
    registered = CASE_REGISTRY.get(case_id)
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


def canonical_plan_bytes(plan: Mapping[str, Any]) -> bytes:
    """Validate plan fields and return sorted, compact, UTF-8 JSON bytes.

    The digest rule is intentionally explicit: only the fields below are
    included, keys are sorted, there is no insignificant whitespace, and
    non-ASCII text is encoded as UTF-8. Contract tests freeze the result.
    """
    _object(plan, required=set(_PLAN_FIELDS))
    case_id = _text(plan["case_id"], label="case_id")

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

    normalized = {
        "case_id": case_id,
        "case_config_digest": _digest(
            plan["case_config_digest"], label="case_config_digest"
        ),
        "revisions": {"vulnerable": vulnerable, "fixed": fixed},
        "dependencies_digest": _digest(
            plan["dependencies_digest"], label="dependencies_digest"
        ),
        "image_digest": _digest(plan["image_digest"], label="image_digest"),
        "build_recipe_digest": _digest(
            plan["build_recipe_digest"], label="build_recipe_digest"
        ),
        "harness_digest": _digest(plan["harness_digest"], label="harness_digest"),
        "inputs": {"candidate": candidate, "normal": normal},
        "asan_signature": asan_signature,
        "limits": _limits(plan["limits"], require_all=True),
        "policy_version": _text(plan["policy_version"], label="policy_version"),
    }
    return json.dumps(
        normalized,
        sort_keys=True,
        ensure_ascii=False,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def plan_digest(plan: Mapping[str, Any]) -> str:
    return "sha256:" + hashlib.sha256(canonical_plan_bytes(plan)).hexdigest()

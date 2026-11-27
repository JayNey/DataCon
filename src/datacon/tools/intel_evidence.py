"""Evidence documents for online intel: the snapshot and the license record.

Security design delta 3.5 archives a fetched snapshot as ``intel_snapshot``
and its license as ``license_record``; interface contract delta 8 fixes
their paths (``intel/snapshot.json``, ``intel/license.json``) and the
three-field ``report.intel`` summary, and leaves the two documents' content
to T15. This module is that content:

- ``build_intel_documents`` turns the case registration, the persisted fetch
  record and the snapshot bytes into the two documents, refusing any input
  whose parts disagree;
- ``validate_snapshot_document`` and ``validate_license_document`` re-check
  one archived document offline;
- ``verify_intel_documents`` binds the two to each other and to the
  ``report.intel`` and ``plan.intel`` summaries, so the evidence verifier
  re-derives the intel verdict from the bundle alone.

A snapshot document is the registration's identity, the collection facts
and the exact snapshot bytes. The bytes ride base64-encoded because a
snapshot is whatever the source served - not necessarily text - and
``snapshot_digest`` has to hash exactly those bytes. A snapshot pinned
before any collection was recorded keeps its four collection fields null
rather than inventing them.

Sizing and duplication, recorded per the spec owner's review: the body
ceiling is the collection ceiling (32 MiB), so the worst-case document is
about 43 MiB of base64 - within the bundle reader's 128 MiB per-file cap -
and an offline case's document duplicates the bytes already archived as
``materials/advisory``, which is the price of a self-verifying bundle.

The document shapes are T15's proposal pending the spec owner's blessing.
The module imports only ``jsonutil`` and ``intel_fetch`` on purpose:
``evidence.py`` will import it, and it must not pull in the orchestration
graph, the provider that depends on it, or the executor.
"""

from __future__ import annotations

import base64
import binascii
from typing import Any, Mapping, NamedTuple, Sequence

from datacon import contracts, jsonutil
from datacon.tools.intel_fetch import (
    MAX_DECOMPRESSED_BYTES,
    IntelFetchError,
    license_rejection,
    public_source_url,
    strip_url_credentials,
)

__all__ = [
    "LICENSE_DOCUMENT_FIELDS",
    "MAX_SNAPSHOT_BYTES",
    "REPORT_INTEL_FIELDS",
    "SNAPSHOT_DOCUMENT_FIELDS",
    "IntelDocuments",
    "IntelEvidenceError",
    "build_intel_documents",
    "license_verdict",
    "snapshot_body",
    "validate_license_document",
    "validate_snapshot_document",
    "verify_intel_documents",
]

# The largest body a snapshot may hold is the largest body a fetch may
# yield (security design delta 3.4): a document may not carry more in.
MAX_SNAPSHOT_BYTES = MAX_DECOMPRESSED_BYTES

# intel/snapshot.json: who registered the snapshot, what it holds, and how
# it was collected. The last four fields are null together when no
# collection was ever recorded for the pinned bytes.
SNAPSHOT_DOCUMENT_FIELDS = (
    "case_id",
    "source_id",
    "snapshot_digest",
    "source_url",
    "license",
    "fetched_at",
    "http_status",
    "redirect_chain_digest",
    "tool_version",
    "body_base64",
)
# intel/license.json: what the registration granted over one snapshot.
LICENSE_DOCUMENT_FIELDS = (
    "case_id",
    "source_id",
    "source_url",
    "snapshot_digest",
    "license",
    "permitted_uses",
)
# report.intel summarizes the snapshot document in exactly these fields.
REPORT_INTEL_FIELDS = frozenset(
    {"snapshot_digest", "license", "redirect_chain_digest"}
)
# The closed fetch record ``intel_fetch.build_snapshot`` writes.
_FETCH_RECORD_FIELDS = frozenset(
    {
        "source_url",
        "http_status",
        "content_digest",
        "license",
        "redirect_chain_digest",
        "fetched_at",
        "tool_version",
    }
)
# The fields both documents take from the same registration.
_SHARED_FIELDS = ("case_id", "source_id", "source_url", "snapshot_digest", "license")


class IntelEvidenceError(ValueError):
    """An intel evidence document could not be built, read or bound.

    ``reason_code`` stays inside the closed v0.2 sets and follows the T15
    attribution of interface contract delta section 10: unreadable or
    mismatched material is ``MATERIAL_MISSING``, a record that contradicts
    the registration is ``SOURCE_CONFLICT``, an unattributable or unlicensed
    source is ``POLICY_DENIED``. ``sub_reason`` is the stable audit token;
    the message is for humans and never repeats a URL, which may still
    carry credentials.
    """

    def __init__(
        self,
        message: str,
        *,
        reason_code: str = "MATERIAL_MISSING",
        sub_reason: str,
    ) -> None:
        super().__init__(message)
        self.message = message
        self.reason_code = reason_code
        self.sub_reason = sub_reason


class IntelDocuments(NamedTuple):
    """The two intel documents one registered snapshot fills."""

    snapshot: dict[str, Any]
    license_record: dict[str, Any]


def _require_text(value: Any, label: str, sub_reason: str) -> str:
    try:
        return jsonutil.require_text(value, label)
    except ValueError as error:
        raise IntelEvidenceError(str(error), sub_reason=sub_reason) from error


def _optional_license(value: Any, label: str, sub_reason: str) -> str | None:
    """A license identifier, or ``None`` when none is registered.

    The gap stays visible rather than being filled in: whether it blocks the
    material is the license verdict's call, not the document's.
    """
    if value is None:
        return None
    return _require_text(value, label, sub_reason)


def _require_digest(value: Any, label: str, sub_reason: str) -> str:
    if not jsonutil.is_digest(value):
        raise IntelEvidenceError(
            f"{label} must be a sha256 digest", sub_reason=sub_reason
        )
    return value


def _require_rfc3339(value: Any, label: str, sub_reason: str) -> str:
    try:
        return jsonutil.require_rfc3339(value, label)
    except ValueError as error:
        raise IntelEvidenceError(str(error), sub_reason=sub_reason) from error


def _public_url(value: Any, label: str, missing: IntelEvidenceError) -> str:
    """One source URL without credentials, through the shared URL rule."""
    if not isinstance(value, str):
        raise missing
    try:
        return public_source_url(value)
    except IntelFetchError as error:
        raise IntelEvidenceError(
            f"{label} is not a usable source URL: {error.message}",
            reason_code="POLICY_DENIED",
            sub_reason=error.sub_reason,
        ) from error


def _closed_object(
    value: Any, fields: tuple[str, ...] | frozenset[str], label: str, sub_reason: str
) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise IntelEvidenceError(f"{label} must be a JSON object", sub_reason=sub_reason)
    keys = set(value)
    missing = sorted(set(fields) - keys)
    unknown = sorted(str(key) for key in keys - set(fields))
    if missing:
        raise IntelEvidenceError(
            f"{label} is missing field(s): {', '.join(missing)}",
            sub_reason=sub_reason,
        )
    if unknown:
        raise IntelEvidenceError(
            f"{label} has unknown field(s): {', '.join(unknown)}",
            sub_reason=sub_reason,
        )
    return dict(value)


def _permitted_uses(value: Any, sub_reason: str) -> list[str]:
    """Permitted uses as a JSON array of distinct use names.

    An archived document carries them as the array they are. Text and bytes
    are never a list of names: ``in`` on them is a substring test or a
    ``TypeError``, so they would grant nothing readable.
    """
    if not isinstance(value, list):
        raise IntelEvidenceError(
            "permitted_uses must be a JSON array of use names", sub_reason=sub_reason
        )
    uses: list[str] = []
    for index, use in enumerate(value):
        text = _require_text(use, f"permitted_uses[{index}]", sub_reason)
        if text in uses:
            raise IntelEvidenceError(
                f"permitted_uses must not repeat {text!r}", sub_reason=sub_reason
            )
        uses.append(text)
    return uses


def _decode_body(value: Any, sub_reason: str) -> bytes:
    """The snapshot bytes behind ``body_base64``, in their one spelling."""
    text = _require_text(value, "body_base64", sub_reason)
    if len(text) > 4 * ((MAX_SNAPSHOT_BYTES + 2) // 3):
        raise IntelEvidenceError(
            "the snapshot body exceeds the snapshot size ceiling", sub_reason=sub_reason
        )
    try:
        body = base64.b64decode(text, validate=True)
    except (binascii.Error, ValueError) as error:
        raise IntelEvidenceError(
            "body_base64 is not base64", sub_reason=sub_reason
        ) from error
    if base64.b64encode(body).decode("ascii") != text:
        raise IntelEvidenceError(
            "body_base64 is not the canonical base64 spelling of its bytes",
            sub_reason=sub_reason,
        )
    if len(body) > MAX_SNAPSHOT_BYTES:
        raise IntelEvidenceError(
            "the snapshot body exceeds the snapshot size ceiling", sub_reason=sub_reason
        )
    return body


def _collection_fields(
    record: Any,
    *,
    snapshot_digest: str,
    source_url: str,
    license_id: str | None,
) -> dict[str, Any]:
    """The collection facts one fetch record contributes to the snapshot."""
    if record is None:
        # Pinned bytes without a recorded collection: nothing is invented.
        return {
            "fetched_at": None,
            "http_status": None,
            "redirect_chain_digest": None,
            "tool_version": None,
        }
    invalid = "SNAPSHOT_DOCUMENT_INVALID"
    record = _closed_object(record, _FETCH_RECORD_FIELDS, "the fetch record", invalid)
    if record["content_digest"] != snapshot_digest:
        raise IntelEvidenceError(
            "the fetch record describes other bytes than the registered snapshot",
            sub_reason="DIGEST_MISMATCH",
        )
    recorded_url = _public_url(
        record["source_url"],
        "the fetch record's source URL",
        IntelEvidenceError(
            "the fetch record registers no source URL", sub_reason=invalid
        ),
    )
    if recorded_url != source_url:
        raise IntelEvidenceError(
            "the fetch record names another source URL than the registration",
            reason_code="SOURCE_CONFLICT",
            sub_reason="SOURCE_URL_MISMATCH",
        )
    if record["license"] != license_id:
        raise IntelEvidenceError(
            "the fetch record names another license than the registration",
            reason_code="SOURCE_CONFLICT",
            sub_reason="LICENSE_MISMATCH",
        )
    http_status = record["http_status"]
    if type(http_status) is not int or not 100 <= http_status <= 599:
        raise IntelEvidenceError(
            "the fetch record's http_status must be an integer between 100 and 599",
            sub_reason=invalid,
        )
    redirect_chain_digest = record["redirect_chain_digest"]
    if redirect_chain_digest is not None:
        redirect_chain_digest = _require_digest(
            redirect_chain_digest, "the fetch record's redirect_chain_digest", invalid
        )
    return {
        "fetched_at": _require_rfc3339(
            record["fetched_at"], "the fetch record's fetched_at", invalid
        ),
        "http_status": http_status,
        "redirect_chain_digest": redirect_chain_digest,
        "tool_version": _require_text(
            record["tool_version"], "the fetch record's tool_version", invalid
        ),
    }


def build_intel_documents(
    record: Mapping[str, Any] | None,
    body: bytes,
    *,
    case_id: str,
    source_id: str,
    source_url: str,
    snapshot_digest: str,
    license: str | None,
    permitted_uses: Sequence[str],
) -> IntelDocuments:
    """Build the two intel documents one registered snapshot fills.

    ``record`` is the fetch record ``intel_fetch.build_snapshot`` wrote (as
    persisted beside the bytes by the snapshot store), or ``None`` for a
    snapshot pinned before any collection was recorded. The rest is the
    case registration: the ``IntelSource`` shape. Every part has to agree -
    the registration's digest with the bytes, the record with the
    registration - and the result validates offline as archived.
    """
    registration_invalid = "INTEL_REGISTRATION_INVALID"
    identity: dict[str, Any] = {
        "case_id": _require_text(case_id, "case_id", registration_invalid),
        "source_id": _require_text(source_id, "source_id", registration_invalid),
        "source_url": _public_url(
            source_url,
            "the registered source URL",
            IntelEvidenceError(
                "the registration carries no source URL", sub_reason=registration_invalid
            ),
        ),
        "snapshot_digest": _require_digest(
            snapshot_digest, "snapshot_digest", registration_invalid
        ),
        "license": _optional_license(license, "license", registration_invalid),
    }
    if not isinstance(body, bytes):
        raise IntelEvidenceError(
            "the snapshot body must be bytes", sub_reason=registration_invalid
        )
    if jsonutil.digest_bytes(body) != identity["snapshot_digest"]:
        raise IntelEvidenceError(
            "the registered snapshot digest does not describe the snapshot bytes",
            sub_reason="DIGEST_MISMATCH",
        )
    # A registration may hand its grant over as a tuple, set or frozenset
    # (the ``IntelSource`` shape); the document archives it as the array it
    # is, in a deterministic order for unordered containers.
    if isinstance(permitted_uses, (tuple, list)):
        registered_uses: object = list(permitted_uses)
    elif isinstance(permitted_uses, (set, frozenset)):
        registered_uses = sorted(permitted_uses)
    else:
        registered_uses = permitted_uses  # let _permitted_uses refuse it
    uses = _permitted_uses(registered_uses, "LICENSE_DOCUMENT_INVALID")

    snapshot_document: dict[str, Any] = {
        **identity,
        **_collection_fields(
            record,
            snapshot_digest=identity["snapshot_digest"],
            source_url=identity["source_url"],
            license_id=identity["license"],
        ),
        "body_base64": base64.b64encode(body).decode("ascii"),
    }
    license_document: dict[str, Any] = {**identity, "permitted_uses": uses}
    # What was built is what can be read back: the builder answers only
    # with documents that pass the offline validators.
    return IntelDocuments(
        validate_snapshot_document(snapshot_document),
        validate_license_document(license_document),
    )


def validate_snapshot_document(value: Any) -> dict[str, Any]:
    """Re-check one archived ``intel/snapshot.json``; returns it normalized.

    The key set is closed, the identity is text, the source URL passes the
    shared URL rule, the collection facts are recorded as a whole, and the
    decoded body hashes to ``snapshot_digest`` - a document whose bytes do
    not match its digest is unreadable material (``DIGEST_MISMATCH``), never
    a snapshot.
    """
    invalid = "SNAPSHOT_DOCUMENT_INVALID"
    document = _closed_object(
        value, SNAPSHOT_DOCUMENT_FIELDS, "intel/snapshot.json", invalid
    )
    normalized: dict[str, Any] = {
        "case_id": _require_text(document["case_id"], "snapshot.case_id", invalid),
        "source_id": _require_text(
            document["source_id"], "snapshot.source_id", invalid
        ),
        "snapshot_digest": _require_digest(
            document["snapshot_digest"], "snapshot.snapshot_digest", invalid
        ),
        "source_url": _public_url(
            document["source_url"],
            "snapshot.source_url",
            IntelEvidenceError(
                "snapshot.source_url is missing", sub_reason=invalid
            ),
        ),
        "license": _optional_license(document["license"], "snapshot.license", invalid),
    }
    fetched_at = document["fetched_at"]
    http_status = document["http_status"]
    tool_version = document["tool_version"]
    redirect_chain_digest = document["redirect_chain_digest"]
    collection = (fetched_at, http_status, tool_version)
    if any(item is None for item in collection) and not all(
        item is None for item in collection
    ):
        raise IntelEvidenceError(
            "snapshot fetched_at, http_status and tool_version record one"
            " collection together: all three or none",
            sub_reason=invalid,
        )
    if fetched_at is None and redirect_chain_digest is not None:
        # No collection was recorded, so no redirect was followed either.
        raise IntelEvidenceError(
            "snapshot.redirect_chain_digest requires a recorded collection",
            sub_reason=invalid,
        )
    if fetched_at is not None:
        if type(http_status) is not int or not 100 <= http_status <= 599:
            raise IntelEvidenceError(
                "snapshot.http_status must be an integer between 100 and 599",
                sub_reason=invalid,
            )
        fetched_at = _require_rfc3339(fetched_at, "snapshot.fetched_at", invalid)
        tool_version = _require_text(tool_version, "snapshot.tool_version", invalid)
    if redirect_chain_digest is not None:
        redirect_chain_digest = _require_digest(
            redirect_chain_digest, "snapshot.redirect_chain_digest", invalid
        )
    normalized.update(
        {
            "fetched_at": fetched_at,
            "http_status": http_status,
            "redirect_chain_digest": redirect_chain_digest,
            "tool_version": tool_version,
            "body_base64": document["body_base64"],
        }
    )
    body = _decode_body(document["body_base64"], invalid)
    if jsonutil.digest_bytes(body) != normalized["snapshot_digest"]:
        raise IntelEvidenceError(
            "intel/snapshot.json holds bytes its snapshot_digest does not"
            " describe",
            sub_reason="DIGEST_MISMATCH",
        )
    return normalized


def validate_license_document(value: Any) -> dict[str, Any]:
    """Re-check one archived ``intel/license.json``; returns it normalized.

    Only the shape is checked here. A grant that permits nothing is still a
    well-formed record of that fact; whether it blocks the material is
    ``license_verdict``'s call.
    """
    invalid = "LICENSE_DOCUMENT_INVALID"
    document = _closed_object(
        value, LICENSE_DOCUMENT_FIELDS, "intel/license.json", invalid
    )
    return {
        "case_id": _require_text(document["case_id"], "license.case_id", invalid),
        "source_id": _require_text(
            document["source_id"], "license.source_id", invalid
        ),
        "source_url": _public_url(
            document["source_url"],
            "license.source_url",
            IntelEvidenceError(
                "license.source_url is missing", sub_reason=invalid
            ),
        ),
        "snapshot_digest": _require_digest(
            document["snapshot_digest"], "license.snapshot_digest", invalid
        ),
        "license": _optional_license(document["license"], "license.license", invalid),
        "permitted_uses": _permitted_uses(document["permitted_uses"], invalid),
    }


def snapshot_body(document: Mapping[str, Any]) -> bytes:
    """The snapshot bytes of a document that verified; never of one that did not."""
    return _decode_body(
        validate_snapshot_document(document)["body_base64"],
        "SNAPSHOT_DOCUMENT_INVALID",
    )


def license_verdict(document: Mapping[str, Any]) -> str | None:
    """Why the archived license refuses the system use, or ``None`` if it permits.

    The verdict is derived from the document alone, by the same rule the
    snapshot provider applies at admission, so an offline reader reaches the
    same conclusion without the case registry.
    """
    validated = validate_license_document(document)
    return license_rejection(validated["license"], validated["permitted_uses"])


def verify_intel_documents(
    snapshot: Mapping[str, Any],
    license_record: Mapping[str, Any],
    *,
    case_id: str,
    report_intel: Mapping[str, Any],
    plan_intel: Mapping[str, Any],
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Verify a bundle's intel material and re-derive its verdict offline.

    Called for ``execution`` and ``campaign`` bundles; ``blocked`` bundles
    carry neither document and never call this. Everything is required on
    purpose: a caller that forgets an input must fail loudly, not silently
    skip a check.

    Both documents must validate, describe one registered source and one
    snapshot, and be anchored to the bundle's own ``case_id``: the two
    documents agreeing with each other is not enough, because both could
    describe another case's material (``SOURCE_CONFLICT`` /
    ``SOURCE_CASE_MISMATCH``). ``source_id`` has no offline anchor - the
    case registry is not in the bundle - so it is display-only here until
    a registration digest is archived with the plan.

    ``report_intel`` is the closed three-field summary, and ``plan_intel``
    is validated by the same closed rule the plan itself is frozen under
    (``contracts._intel``: four fields, non-empty https ``sources``, no
    unknown keys), then bound: ``content_digest`` and ``collected_at`` must
    name this snapshot's collection, and ``sources`` - the sources this
    analysis relies on - must include the snapshot's ``source_url``,
    compared after credential stripping on both sides.

    The archived grant must finally permit the system use: a bundle whose
    license record does not allow what was done with the material cannot
    stand as evidence that it was allowed in (``POLICY_DENIED`` /
    ``LICENSE_REJECTED``). Returns the two normalized documents.
    """

    def mismatch(message: str) -> IntelEvidenceError:
        return IntelEvidenceError(message, sub_reason="INTEL_BINDING_MISMATCH")

    snapshot_document = validate_snapshot_document(snapshot)
    license_document = validate_license_document(license_record)
    for field in _SHARED_FIELDS:
        if snapshot_document[field] != license_document[field]:
            raise mismatch(
                f"intel/snapshot.json and intel/license.json disagree on {field}"
            )
    if snapshot_document["case_id"] != case_id:
        # The anchor outside the two documents: material filed for another
        # case is a factual mismatch, not a binding fault.
        raise IntelEvidenceError(
            "intel/snapshot.json and intel/license.json are filed for case"
            f" {snapshot_document['case_id']!r}, not {case_id!r}",
            reason_code="SOURCE_CONFLICT",
            sub_reason="SOURCE_CASE_MISMATCH",
        )
    if not isinstance(report_intel, Mapping):
        raise mismatch("report.intel must be a JSON object")
    if set(report_intel) != REPORT_INTEL_FIELDS:
        raise mismatch(
            "report.intel must contain exactly "
            + ", ".join(sorted(REPORT_INTEL_FIELDS))
        )
    for field in sorted(REPORT_INTEL_FIELDS):
        if report_intel[field] != snapshot_document[field]:
            raise mismatch(
                f"report.intel.{field} does not match intel/snapshot.json"
            )
    if not isinstance(plan_intel, Mapping):
        raise mismatch("plan.intel must be a JSON object")
    try:
        # The plan freezes intel through this very rule; verifying the
        # bundle against anything looser would not be binding to the plan.
        normalized_plan_intel = contracts._intel(plan_intel)
    except ValueError as error:
        raise mismatch(f"plan.intel is not the frozen shape: {error}") from error
    if normalized_plan_intel["content_digest"] != snapshot_document["snapshot_digest"]:
        raise mismatch(
            "plan.intel.content_digest does not match the archived snapshot"
        )
    collected_at = normalized_plan_intel["collected_at"]
    if (
        snapshot_document["fetched_at"] is not None
        and snapshot_document["fetched_at"] != collected_at
    ):
        raise mismatch(
            "plan.intel.collected_at does not match the snapshot's fetched_at"
        )
    # Sources are compared after credential stripping on both sides: the
    # plan may carry a credentialled spelling of the same origin.
    stripped_sources = {
        strip_url_credentials(source) for source in normalized_plan_intel["sources"]
    }
    if snapshot_document["source_url"] not in stripped_sources:
        raise mismatch(
            "plan.intel.sources does not include the snapshot's source URL"
        )
    rejected = license_rejection(
        license_document["license"], license_document["permitted_uses"]
    )
    if rejected is not None:
        raise IntelEvidenceError(
            f"the archived license does not permit the system use: {rejected}",
            reason_code="POLICY_DENIED",
            sub_reason="LICENSE_REJECTED",
        )
    return snapshot_document, license_document

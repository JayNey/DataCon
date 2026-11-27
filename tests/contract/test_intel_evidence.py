"""T15 evidence documents: the archived snapshot and its license record.

RED-phase contract tests for ``datacon.tools.intel_evidence``: the content
of the two intel roles that interface-contract-delta §8 fixes by path only
(``intel/snapshot.json`` as ``intel_snapshot`` and ``intel/license.json``
as ``license_record``). A snapshot document carries the collection record
of security-design-delta §3.5 and the exact snapshot bytes; a license
document carries what the registration granted. Both are closed key sets,
both re-validate offline, and one call binds them to each other and to the
``report.intel`` / ``plan.intel`` summaries so the intel verdict can be
re-derived from the bundle alone.

The document shapes are T15's proposal pending the spec owner's blessing.
Nothing here touches the network: the fetch record comes from the real
``intel_fetch.build_snapshot`` over a fixed fetch result.
"""

from __future__ import annotations

import base64
import hashlib
import json
import subprocess
import sys

import pytest

CASE_ID = "cve-2099-0001"
SOURCE_ID = "advisory-primary"
SOURCE_URL = "https://advisory.example.com/cve-2099-0001.txt"
LICENSE = "CC-BY-4.0"
PERMITTED_USES = ("research", "reproduction")
# Deliberately not valid UTF-8: a snapshot is whatever the source served,
# and the document has to carry these exact bytes, not a decoding of them.
BODY = b"\xff\xfeCVE-2099-0001 advisory \x80\x81 - pinned bytes\n"
SNAPSHOT_DIGEST = "sha256:" + hashlib.sha256(BODY).hexdigest()
REDIRECT_CHAIN_DIGEST = "sha256:" + "16" * 32
FETCHED_AT = "2026-11-26T00:00:00Z"
TOOL_VERSION = "datacon.intel_fetch/0.1.0"

SNAPSHOT_DOCUMENT_FIELDS = frozenset(
    {
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
    }
)
LICENSE_DOCUMENT_FIELDS = frozenset(
    {
        "case_id",
        "source_id",
        "source_url",
        "snapshot_digest",
        "license",
        "permitted_uses",
    }
)
REPORT_INTEL_FIELDS = frozenset({"snapshot_digest", "license", "redirect_chain_digest"})
_UNSET = object()


def _record(**overrides: object) -> dict:
    """The seven-field fetch record as ``intel_fetch.build_snapshot`` writes it."""
    from datacon.tools.intel_fetch import FetchResult, build_snapshot

    fetch = FetchResult(body=BODY, status=200, hops=(SOURCE_URL,))
    record = dict(build_snapshot(fetch, LICENSE))
    # Pin the fields a wall clock or the hop list would otherwise vary.
    record["fetched_at"] = FETCHED_AT
    record["redirect_chain_digest"] = REDIRECT_CHAIN_DIGEST
    return {**record, **overrides}


def _registration(**overrides: object) -> dict:
    """What the case registry records for the source (the ``IntelSource`` shape)."""
    registration = {
        "case_id": CASE_ID,
        "source_id": SOURCE_ID,
        "source_url": SOURCE_URL,
        "snapshot_digest": SNAPSHOT_DIGEST,
        "license": LICENSE,
        "permitted_uses": PERMITTED_USES,
    }
    registration.update(overrides)
    return registration


def _build(record=_UNSET, **registration_overrides: object):
    from datacon.tools.intel_evidence import build_intel_documents

    if record is _UNSET:
        record = _record()
    return build_intel_documents(record, BODY, **_registration(**registration_overrides))


def _snapshot_document(record=_UNSET, **registration_overrides: object) -> dict:
    return dict(_build(record, **registration_overrides).snapshot)


def _license_document(record=_UNSET, **registration_overrides: object) -> dict:
    return dict(_build(record, **registration_overrides).license_record)


OTHER_BODY = b"another advisory, pinned separately"


def _other_source(record=None, **registration_overrides: object):
    """Both documents, well built, for another snapshot of the same case."""
    from datacon.tools.intel_evidence import build_intel_documents

    registration = _registration(
        snapshot_digest="sha256:" + hashlib.sha256(OTHER_BODY).hexdigest(),
        **registration_overrides,
    )
    return build_intel_documents(record, OTHER_BODY, **registration)


def _report_intel(**overrides: object) -> dict:
    return {
        "snapshot_digest": SNAPSHOT_DIGEST,
        "license": LICENSE,
        "redirect_chain_digest": REDIRECT_CHAIN_DIGEST,
        **overrides,
    }


def _plan_intel(**overrides: object) -> dict:
    plan_intel = {
        "snapshot": "advisories/cve-2099-0001.txt",
        "collected_at": FETCHED_AT,
        "content_digest": SNAPSHOT_DIGEST,
        "sources": [SOURCE_URL],
    }
    plan_intel.update(overrides)
    return plan_intel


def _verify(snapshot=None, license_record=None, report_intel=None, plan_intel=_UNSET):
    from datacon.tools.intel_evidence import verify_intel_documents

    arguments = {
        "snapshot": _snapshot_document() if snapshot is None else snapshot,
        "license_record": _license_document() if license_record is None else license_record,
        "report_intel": _report_intel() if report_intel is None else report_intel,
    }
    if plan_intel is not _UNSET:
        arguments["plan_intel"] = plan_intel
    return verify_intel_documents(**arguments)


def _refused(**arguments) -> Exception:
    """Run ``verify_intel_documents`` over the defaults plus ``arguments``."""
    verify_arguments = {
        "snapshot": _snapshot_document(),
        "license_record": _license_document(),
        "report_intel": _report_intel(),
    }
    verify_arguments.update(arguments)
    from datacon.tools.intel_evidence import verify_intel_documents

    with pytest.raises(Exception) as excinfo:
        verify_intel_documents(**verify_arguments)
    return excinfo.value


# --- the snapshot document -------------------------------------------------


def test_snapshot_document_carries_the_record_and_the_exact_bytes():
    from datacon.tools.intel_evidence import (
        snapshot_body,
        validate_snapshot_document,
    )

    document = _snapshot_document()

    assert set(document) == SNAPSHOT_DOCUMENT_FIELDS
    # Identity is the registration's; the collection facts are the record's.
    assert document["case_id"] == CASE_ID
    assert document["source_id"] == SOURCE_ID
    assert document["snapshot_digest"] == SNAPSHOT_DIGEST
    assert document["source_url"] == SOURCE_URL
    assert document["license"] == LICENSE
    assert document["fetched_at"] == FETCHED_AT
    assert document["http_status"] == 200
    assert document["redirect_chain_digest"] == REDIRECT_CHAIN_DIGEST
    assert document["tool_version"] == TOOL_VERSION
    # The bytes are the document's payload, byte for byte, and the digest
    # is over exactly those bytes.
    assert document["body_base64"] == base64.b64encode(BODY).decode("ascii")
    assert snapshot_body(document) == BODY
    # A document that round-trips through JSON validates to the same shape.
    assert validate_snapshot_document(document) == document
    assert validate_snapshot_document(json.loads(json.dumps(document))) == document


def test_snapshot_document_without_a_collection_record_keeps_the_gap_visible():
    # A snapshot pinned before any collection was recorded still has a
    # registration, so it can be attributed; the document leaves the
    # collection facts null instead of inventing them.
    document = _snapshot_document(record=None)
    assert document["snapshot_digest"] == SNAPSHOT_DIGEST
    assert document["source_url"] == SOURCE_URL
    assert document["license"] == LICENSE
    for field in (
        "fetched_at",
        "http_status",
        "redirect_chain_digest",
        "tool_version",
    ):
        assert document[field] is None, field


def test_snapshot_document_builder_fails_closed_on_a_dishonest_record():
    from datacon.tools.intel_evidence import IntelEvidenceError

    def refused(record=_UNSET, **registration_overrides) -> IntelEvidenceError:
        with pytest.raises(IntelEvidenceError) as excinfo:
            _build(record, **registration_overrides)
        return excinfo.value

    # The record may not describe other bytes than the ones stored beside it.
    error = refused(_record(content_digest="sha256:" + "00" * 32))
    assert (error.reason_code, error.sub_reason) == ("MATERIAL_MISSING", "DIGEST_MISMATCH")
    # Nor may the registration pin bytes the record does not describe.
    error = refused(snapshot_digest="sha256:" + "00" * 32)
    assert (error.reason_code, error.sub_reason) == ("MATERIAL_MISSING", "DIGEST_MISMATCH")
    # The record and the registration must name the same source and license.
    error = refused(_record(source_url="https://other.example.org/x.txt"))
    assert (error.reason_code, error.sub_reason) == ("SOURCE_CONFLICT", "SOURCE_URL_MISMATCH")
    error = refused(_record(license="MIT"))
    assert (error.reason_code, error.sub_reason) == ("SOURCE_CONFLICT", "LICENSE_MISMATCH")
    # The record is the closed seven-field fetch record, recorded as a whole.
    for label, record in (
        ("unknown", _record(extra="field")),
        ("missing", {k: v for k, v in _record().items() if k != "tool_version"}),
        ("half-recorded", {"http_status": 200}),
        ("not an object", [_record()]),
    ):
        error = refused(record)
        assert error.sub_reason == "SNAPSHOT_DOCUMENT_INVALID", label
    assert "extra" in str(refused(_record(extra="field")))
    assert "tool_version" in str(
        refused({k: v for k, v in _record().items() if k != "tool_version"})
    )
    # Identity comes from the registration; a registration that cannot be
    # recorded is not a document fault of either side.
    registration_invalid = ("MATERIAL_MISSING", "INTEL_REGISTRATION_INVALID")
    for label, registration_overrides in (
        ("case blank", {"case_id": ""}),
        ("case not text", {"case_id": 7}),
        ("case missing", {"case_id": None}),
        ("source blank", {"source_id": " "}),
        ("source missing", {"source_id": None}),
        ("license blank", {"license": "  "}),
        ("license not text", {"license": 3}),
        ("source URL missing", {"source_url": None}),
        ("digest is not a digest", {"snapshot_digest": "nope"}),
    ):
        error = refused(None, **registration_overrides)
        assert (error.reason_code, error.sub_reason) == registration_invalid, label


def test_snapshot_document_builder_refuses_an_unattributable_source():
    from datacon.tools.intel_evidence import IntelEvidenceError

    # Material that cannot be attributed to a trustworthy https origin is
    # policy, not content: the same verdict the provider gives, and the
    # message never repeats a URL that may still carry credentials.
    for bad_url in (
        "",
        "not-a-url",
        "http://advisory.example.com/x.txt",
        "javascript:alert(1)",
        "https://advisory.example.com:notaport/x.txt",
        "https://advisory.example.com/x y.txt",
    ):
        with pytest.raises(IntelEvidenceError) as excinfo:
            _build(source_url=bad_url)
        assert (excinfo.value.reason_code, excinfo.value.sub_reason) == (
            "POLICY_DENIED",
            "SOURCE_URL_INVALID",
        ), bad_url


def test_intel_documents_strip_url_credentials():
    from datacon.tools.intel_evidence import validate_snapshot_document

    # A registered URL may still carry credentials. They are never sent and
    # never archived: both documents, the record and the registration agree
    # on the URL without them, and nothing written repeats them.
    credentialed = "https://user:pw@advisory.example.com/cve-2099-0001.txt"
    documents = _build(_record(source_url=credentialed), source_url=credentialed)
    assert documents.snapshot["source_url"] == SOURCE_URL
    assert documents.license_record["source_url"] == SOURCE_URL
    assert "pw" not in json.dumps(documents._asdict())
    documents_snapshot = validate_snapshot_document(documents.snapshot)
    assert documents_snapshot["source_url"] == SOURCE_URL


def test_snapshot_document_validation_fails_closed(monkeypatch):
    from datacon.tools import intel_evidence
    from datacon.tools.intel_evidence import (
        IntelEvidenceError,
        validate_snapshot_document,
    )

    valid = _snapshot_document()
    broken = {
        "unknown field": valid | {"extra": 1},
        "missing field": {k: v for k, v in valid.items() if k != "license"},
        "not an object": [valid],
        "not a digest": valid | {"snapshot_digest": "md5:abc"},
        "body not base64": valid | {"body_base64": "not base64!"},
        "body not text": valid | {"body_base64": 7},
        "status below 100": valid | {"http_status": 99},
        "status above 599": valid | {"http_status": 600},
        "status is a bool": valid | {"http_status": True},
        "status is a float": valid | {"http_status": 200.0},
        "timestamp not RFC 3339": valid | {"fetched_at": "yesterday"},
        "timestamp without offset": valid | {"fetched_at": "2026-11-26T00:00:00"},
        "timestamp is a number": valid | {"fetched_at": 20261126},
        "half-recorded collection": valid | {"fetched_at": None, "http_status": None},
        "other half": valid | {"tool_version": ""},
        "blank license": valid | {"license": "  "},
        "license is a number": valid | {"license": 7},
        "redirect digest not a digest": valid
        | {"redirect_chain_digest": "sha256:short"},
        "blank case": valid | {"case_id": ""},
        "blank source": valid | {"source_id": " "},
    }
    for label, document in broken.items():
        with pytest.raises(IntelEvidenceError) as excinfo:
            validate_snapshot_document(document)
        assert (excinfo.value.reason_code, excinfo.value.sub_reason) == (
            "MATERIAL_MISSING",
            "SNAPSHOT_DOCUMENT_INVALID",
        ), label
    # Bytes that do not hash to the declared digest are material that cannot
    # be verified, not a malformed document.
    with pytest.raises(IntelEvidenceError) as excinfo:
        validate_snapshot_document(valid | {"snapshot_digest": "sha256:" + "00" * 32})
    assert (excinfo.value.reason_code, excinfo.value.sub_reason) == (
        "MATERIAL_MISSING",
        "DIGEST_MISMATCH",
    )

    # A source URL problem is a policy hit, not unreadable material.
    for bad_url in (
        "javascript:alert(1)",
        "http://advisory.example.com/x.txt",
        "https://advisory.example.com:notaport/x.txt",
    ):
        with pytest.raises(IntelEvidenceError) as excinfo:
            validate_snapshot_document(valid | {"source_url": bad_url})
        assert (excinfo.value.reason_code, excinfo.value.sub_reason) == (
            "POLICY_DENIED",
            "SOURCE_URL_INVALID",
        ), bad_url
    with pytest.raises(IntelEvidenceError) as excinfo:
        validate_snapshot_document(valid | {"source_url": None})
    assert excinfo.value.sub_reason == "SNAPSHOT_DOCUMENT_INVALID"

    # An offset spelling of the collection time normalizes to UTC.
    offset = valid | {"fetched_at": "2026-11-26T08:00:00+08:00"}
    assert validate_snapshot_document(offset)["fetched_at"] == FETCHED_AT
    # A body may not exceed the collection's own size ceiling.
    monkeypatch.setattr(intel_evidence, "MAX_SNAPSHOT_BYTES", 64)
    oversized = valid | {
        "body_base64": base64.b64encode(b"x" * 65).decode("ascii"),
        "snapshot_digest": "sha256:" + hashlib.sha256(b"x" * 65).hexdigest(),
    }
    with pytest.raises(IntelEvidenceError) as excinfo:
        validate_snapshot_document(oversized)
    assert excinfo.value.sub_reason == "SNAPSHOT_DOCUMENT_INVALID"


def test_snapshot_body_refuses_to_decode_an_unverified_document():
    from datacon.tools.intel_evidence import IntelEvidenceError, snapshot_body

    # Bytes are only handed out for a document that verified: a caller can
    # never read a body whose digest it did not check.
    lying = _snapshot_document() | {"snapshot_digest": "sha256:" + "00" * 32}
    with pytest.raises(IntelEvidenceError):
        snapshot_body(lying)


# --- the license document --------------------------------------------------


def test_license_document_records_the_grant_and_its_verdict():
    from datacon.tools.intel_evidence import (
        license_verdict,
        validate_license_document,
    )

    document = _license_document()
    assert set(document) == LICENSE_DOCUMENT_FIELDS
    assert document["permitted_uses"] == ["research", "reproduction"]
    assert validate_license_document(document) == document
    assert validate_license_document(json.loads(json.dumps(document))) == document
    assert license_verdict(document) is None

    # The archived grant alone re-derives the license verdict.
    for label, registration_overrides in (
        ("no license", {"record": None, "license": None}),
        ("use not granted", {"permitted_uses": ("research",)}),
        ("nothing granted", {"permitted_uses": ()}),
    ):
        record = registration_overrides.pop("record", _UNSET)
        verdict = license_verdict(
            _license_document(record, **registration_overrides)
        )
        assert verdict, label
    # A verdict is only derived from a document that is well formed.
    with pytest.raises(Exception) as excinfo:
        license_verdict(_license_document() | {"permitted_uses": "reproduction"})
    assert getattr(excinfo.value, "sub_reason", None) == "LICENSE_DOCUMENT_INVALID"


def test_license_document_builder_fails_closed_on_a_malformed_grant():
    from datacon.tools.intel_evidence import IntelEvidenceError

    # A grant that is not a list of distinct use names is never written as
    # a license record: the document would not say what was granted.
    for label, registration_overrides in (
        ("bare string grant", {"permitted_uses": "reproduction"}),
        ("bytes grant", {"permitted_uses": b"reproduction"}),
        ("duplicate uses", {"permitted_uses": ("reproduction", "reproduction")}),
        ("empty use name", {"permitted_uses": ("reproduction", " ")}),
        ("use is not text", {"permitted_uses": ("reproduction", 1)}),
        ("use names are a number", {"permitted_uses": 3}),
    ):
        with pytest.raises(IntelEvidenceError) as excinfo:
            _build(**registration_overrides)
        assert (excinfo.value.reason_code, excinfo.value.sub_reason) == (
            "MATERIAL_MISSING",
            "LICENSE_DOCUMENT_INVALID",
        ), label


def test_license_document_validation_fails_closed():
    from datacon.tools.intel_evidence import (
        IntelEvidenceError,
        validate_license_document,
    )

    valid = _license_document()
    broken = {
        "unknown field": valid | {"extra": 1},
        "missing field": {k: v for k, v in valid.items() if k != "permitted_uses"},
        "not an object": [valid],
        "uses not a list": valid | {"permitted_uses": ("reproduction",)},
        "uses is a string": valid | {"permitted_uses": "reproduction"},
        "duplicate uses": valid | {"permitted_uses": ["reproduction", "reproduction"]},
        "empty use name": valid | {"permitted_uses": ["reproduction", " "]},
        "use is not text": valid | {"permitted_uses": ["reproduction", 1]},
        "license is a number": valid | {"license": 7},
        "blank license": valid | {"license": " "},
        "digest not a digest": valid | {"snapshot_digest": "sha256:zz"},
        "case id blank": valid | {"case_id": ""},
        "source id blank": valid | {"source_id": " "},
        "source URL missing": valid | {"source_url": None},
    }
    for label, document in broken.items():
        with pytest.raises(IntelEvidenceError) as excinfo:
            validate_license_document(document)
        assert excinfo.value.sub_reason == "LICENSE_DOCUMENT_INVALID", label
    # An unusable grant is still a well-formed record of it: the verdict is
    # the verifier's call, not the document's.
    assert validate_license_document(valid | {"permitted_uses": []}) == valid | {
        "permitted_uses": []
    }


# --- binding the two documents to each other and to the summaries ----------


def test_intel_documents_bind_to_each_other_and_to_the_report():
    snapshot = _snapshot_document()
    license_record = _license_document()

    verified_snapshot, verified_license = _verify()
    assert verified_snapshot == snapshot
    assert verified_license == license_record

    # With the plan's own intel summary the archived snapshot is the one the
    # plan was frozen against, collected when the plan says it was.
    _verify(plan_intel=_plan_intel())
    _verify(plan_intel=_plan_intel(collected_at="2026-11-26T08:00:00+08:00"))
    # A snapshot without a collection record has no time to compare, and
    # the report says no redirect chain was followed.
    _verify(
        snapshot=_snapshot_document(record=None),
        report_intel=_report_intel(redirect_chain_digest=None),
        plan_intel=_plan_intel(),
    )


def test_intel_documents_refuse_every_binding_mismatch():
    report_intel = _report_intel()
    binding = ("MATERIAL_MISSING", "INTEL_BINDING_MISMATCH")

    # The two documents describe one registered source. Each document below
    # is well formed on its own; only the pairing is wrong.
    for change in (
        {"case_id": "cve-2099-0002"},
        {"source_id": "advisory-secondary"},
        {"source_url": "https://other.example.org/x"},
    ):
        error = _refused(license_record=_license_document(None, **change))
        assert (error.reason_code, error.sub_reason) == binding, change
    # The license record covers exactly this snapshot.
    error = _refused(license_record=dict(_other_source().license_record))
    assert (error.reason_code, error.sub_reason) == binding
    # Both documents name one license, whichever side departs from it.
    under_another_license = _build(None, license="MIT")
    for arguments in (
        {"snapshot": dict(under_another_license.snapshot)},
        {"license_record": dict(under_another_license.license_record)},
        {"report_intel": _report_intel(license=None)},
    ):
        error = _refused(**arguments)
        assert (error.reason_code, error.sub_reason) == binding
    # report.intel is the closed three-field summary of these documents.
    for change in (
        {"snapshot_digest": "sha256:" + "00" * 32},
        {"redirect_chain_digest": None},
        {"license": "MIT"},
        {"extra": 1},
    ):
        error = _refused(report_intel=_report_intel(**change))
        assert (error.reason_code, error.sub_reason) == binding, change
    error = _refused(
        report_intel={k: v for k, v in report_intel.items() if k != "license"}
    )
    assert (error.reason_code, error.sub_reason) == binding
    for not_an_object in (None, [], "intel"):
        error = _refused(report_intel=not_an_object)
        assert (error.reason_code, error.sub_reason) == binding

    # The plan's summary must agree whenever one is archived with the bundle.
    other_digest = "sha256:" + "00" * 32
    for change in (
        {"content_digest": other_digest},
        {"collected_at": "2020-01-01T00:00:00Z"},
        {"sources": None},
        {"sources": "https://advisory.example.com/x"},
        {"collected_at": "not a time"},
    ):
        error = _refused(plan_intel=_plan_intel(**change))
        assert (error.reason_code, error.sub_reason) == binding, change
    for not_an_object in ("intel", ["intel"]):
        error = _refused(plan_intel=not_an_object)
        assert (error.reason_code, error.sub_reason) == binding


def test_intel_documents_refuse_a_license_that_does_not_permit_the_use():
    # The archived grant does not cover what the system does with the
    # material: the bundle cannot claim the material was allowed in.
    for label, arguments in (
        ("use not granted", {"license_record": _license_document(permitted_uses=("research",))}),
        (
            "no license at all",
            {
                "snapshot": _snapshot_document(None, license=None),
                "license_record": _license_document(None, license=None),
                "report_intel": _report_intel(
                    license=None, redirect_chain_digest=None
                ),
            },
        ),
    ):
        error = _refused(**arguments)
        assert (error.reason_code, error.sub_reason) == (
            "POLICY_DENIED",
            "LICENSE_REJECTED",
        ), label


def test_intel_documents_survive_the_archive_round_trip():
    # The documents are JSON text in the bundle: whatever JSON does to the
    # values on the way out and back must not change what verification sees.
    documents = _build()
    archived = json.loads(
        json.dumps(
            {
                "snapshot": documents.snapshot,
                "license_record": documents.license_record,
                "report_intel": _report_intel(),
                "plan_intel": _plan_intel(),
            }
        )
    )
    _verify(
        archived["snapshot"],
        archived["license_record"],
        archived["report_intel"],
        archived["plan_intel"],
    )


def test_intel_evidence_imports_without_the_execution_graph():
    # evidence.py will import this module to verify bundles. It must not
    # drag the orchestration graph, the provider that depends on it, or the
    # executor along: those own the write side, not the read side.
    code = (
        "import sys; import datacon.tools.intel_evidence; "
        "print(sorted(m for m in sys.modules if m in ("
        "'datacon.orchestration', 'datacon.tools.intel_provider',"
        " 'datacon.execution', 'datacon.evidence', 'datacon.tools.model_outlet')))"
    )
    completed = subprocess.run(
        [sys.executable, "-c", code], capture_output=True, text=True, check=True
    )
    assert completed.stdout.strip() == "[]"

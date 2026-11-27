"""D43 T12: the family index validator must fail closed.

The family index is *not* an evidence bundle (no ``bundle_kind``, no
``family_index`` role); it has its own closed schema in interface §8. These
negative cases pin the fail-open holes found in review: strict
``schema_version`` typing, canonical UUID text, the empty fixed family, and
cross-identity uniqueness.
"""

from __future__ import annotations

import copy
from uuid import UUID

import pytest

from datacon import evidence
from datacon.evidence import BundleError

FAMILY_ID = UUID("2f1c0f5e-3d7a-4b6c-9f10-2a4b6c8d0e11")
CAMPAIGN_ID = UUID("9a1b2c3d-4e5f-4a6b-8c7d-9e0f1a2b3c4d")
ROUND1_ID = UUID("3b7e1f2a-5c6d-4e8f-9012-3456789abcde")
ROUND2_ID = UUID("0f8fad5b-d9cb-469f-a165-70867728950e")
APPROVAL_DIGEST = "sha256:" + "52" * 32
PLAN_DIGEST = "sha256:" + "2e" * 32
DIGEST = "sha256:" + "53" * 32
BUDGET = {
    "max_total_seconds": 900,
    "max_fuzz_seconds": 300,
    "spent_seconds": 540,
    "spent_fuzz_seconds": 180,
    "remaining_seconds": 360,
    "remaining_fuzz_seconds": 120,
}


def _round(round_no, job_id, state="INCONCLUSIVE"):
    return {
        "round_no": round_no,
        "job_id": str(job_id),
        "plan_digest": PLAN_DIGEST,
        "state": state,
        "evidence_digest": DIGEST,
    }


def _document(*, rounds=None, campaign=None):
    rounds = [_round(1, ROUND1_ID)] if rounds is None else rounds
    if campaign is None and rounds:
        campaign = {"job_id": str(CAMPAIGN_ID), "bundle_digest": DIGEST}
    return {
        "schema_version": 2,
        "kind": "family_index",
        "family_id": str(FAMILY_ID),
        "state": "COMPLETED",
        "created_at": "2099-01-01T00:00:00Z",
        "family_approval_digest": APPROVAL_DIGEST,
        "rounds": rounds,
        "campaign": campaign,
        "budget": BUDGET,
    }


def _assert_invalid(document):
    with pytest.raises(BundleError) as raised:
        evidence.validate_family_index(document)
    assert raised.value.reason_code == "INVALID_MANIFEST"


@pytest.mark.parametrize("version", [2.0, True, "2", None])
def test_schema_version_requires_a_real_integer(version):
    document = _document()
    document["schema_version"] = version
    _assert_invalid(document)


@pytest.mark.parametrize(
    "family_id",
    [
        str(FAMILY_ID).upper(),
        "urn:uuid:" + str(FAMILY_ID),
        "{" + str(FAMILY_ID) + "}",
        "2f1c0f5e3d7a4b6c9f102a4b6c8d0e11",
    ],
)
def test_family_id_requires_canonical_provider_text(family_id):
    document = _document()
    document["family_id"] = family_id
    _assert_invalid(document)


def test_empty_fixed_family_is_rejected():
    document = _document(rounds=[], campaign=None)
    assert document["campaign"] is None and document["rounds"] == []
    _assert_invalid(document)


def test_campaign_without_rounds_is_allowed():
    document = _document(
        rounds=[],
        campaign={"job_id": str(CAMPAIGN_ID), "bundle_digest": DIGEST},
    )

    evidence.validate_family_index(document)


@pytest.mark.parametrize(
    "mutate",
    [
        lambda document: document.__setitem__("campaign", {
            "job_id": document["family_id"],
            "bundle_digest": DIGEST,
        }),
        lambda document: document["rounds"][0].__setitem__(
            "job_id", document["family_id"]
        ),
        lambda document: document["rounds"][0].__setitem__(
            "job_id", document["campaign"]["job_id"]
        ),
    ],
)
def test_family_campaign_and_round_identities_are_distinct(mutate):
    document = _document()
    mutate(document)
    _assert_invalid(document)


def test_completed_is_not_a_round_state():
    document = _document(rounds=[_round(1, ROUND1_ID, state="COMPLETED")])
    _assert_invalid(document)


def test_valid_guided_document_still_passes():
    evidence.validate_family_index(copy.deepcopy(_document()))


def test_build_family_index_rejects_duplicate_identity():
    with pytest.raises(BundleError):
        evidence.build_family_index(
            family_id=FAMILY_ID,
            created_at="2099-01-01T00:00:00Z",
            family_approval_digest=APPROVAL_DIGEST,
            rounds=[_round(1, CAMPAIGN_ID)],
            campaign={"job_id": str(CAMPAIGN_ID), "bundle_digest": DIGEST},
            budget=BUDGET,
        )

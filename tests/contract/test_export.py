"""D43/TC-16 T12: ``export --family`` keeps rounds and campaign byte-stable.

Each round directory must stay an independent bundle whose manifest is copied
verbatim; the root ``family.json`` must be byte-identical to the archived
family index. No PostgreSQL is involved: the bundles are built with the same
v2 fixtures used by ``test_evidence_v2.py``.
"""

from __future__ import annotations

from uuid import uuid4

import pytest

from test_evidence_v2 import _base_files, _manifest, _write_v2_bundle

from datacon import evidence
from datacon.evidence import verify_bundle

APPROVAL_DIGEST = "sha256:" + "52" * 32
PLAN_DIGEST = "sha256:" + "2e" * 32
BUDGET = {
    "max_total_seconds": 900,
    "max_fuzz_seconds": 300,
    "spent_seconds": 540,
    "spent_fuzz_seconds": 180,
    "remaining_seconds": 360,
    "remaining_fuzz_seconds": 120,
}


def _bundle(tmp_path, *, kind, name):
    if kind == "campaign":
        manifest = _manifest("campaign", verdict=None, reason=None)
        files = _base_files(execution=False, campaign=True)
    else:
        manifest = _manifest("execution")
        files = _base_files(execution=True, campaign=False)
    root = _write_v2_bundle(tmp_path, manifest, files, name=name)
    return root, verify_bundle(root).manifest_digest


def _index(*, campaign_digest, round_digests):
    return evidence.build_family_index(
        family_id=str(uuid4()),
        created_at="2099-01-01T00:00:00Z",
        family_approval_digest=APPROVAL_DIGEST,
        rounds=[
            {
                "round_no": round_no,
                "job_id": str(uuid4()),
                "plan_digest": PLAN_DIGEST,
                "state": "INCONCLUSIVE",
                "evidence_digest": digest,
            }
            for round_no, digest in round_digests
        ],
        campaign=(
            {"job_id": str(uuid4()), "bundle_digest": campaign_digest}
            if campaign_digest is not None
            else None
        ),
        budget=BUDGET,
    )


def _archive(tmp_path, index, *, name="archive"):
    family_json = tmp_path / name / "family.json"
    evidence.finalize_family_index(family_json, index)
    return family_json


def test_export_family_keeps_campaign_and_rounds(tmp_path):
    campaign, campaign_digest = _bundle(
        tmp_path, kind="campaign", name="campaign"
    )
    round1, digest1 = _bundle(tmp_path, kind="execution", name="round-1")
    round2, digest2 = _bundle(tmp_path, kind="execution", name="round-2")
    family_json = _archive(
        tmp_path,
        _index(campaign_digest=campaign_digest, round_digests=[(1, digest1), (2, digest2)]),
    )

    info = evidence.export_family(
        family_json,
        tmp_path / "export",
        campaign_source=campaign,
        rounds=[(1, round1), (2, round2)],
    )

    exported = tmp_path / "export"
    assert (exported / "family.json").is_file()
    assert (exported / "campaign").is_dir()
    assert (exported / "rounds" / "1").is_dir()
    assert (exported / "rounds" / "2").is_dir()
    assert verify_bundle(exported / "campaign").manifest_digest == campaign_digest
    assert verify_bundle(exported / "rounds" / "1").manifest_digest == digest1
    assert verify_bundle(exported / "rounds" / "2").manifest_digest == digest2
    assert info.round_digests == {1: digest1, 2: digest2}
    assert info.campaign_digest == campaign_digest


def test_family_index_is_byte_identical_to_export(tmp_path):
    campaign, campaign_digest = _bundle(
        tmp_path, kind="campaign", name="campaign"
    )
    round1, digest1 = _bundle(tmp_path, kind="execution", name="round-1")
    family_json = _archive(
        tmp_path,
        _index(campaign_digest=campaign_digest, round_digests=[(1, digest1)]),
    )
    archived = family_json.read_bytes()

    evidence.export_family(
        family_json,
        tmp_path / "export",
        campaign_source=campaign,
        rounds=[(1, round1)],
    )

    exported = tmp_path / "export"
    assert (exported / "family.json").read_bytes() == archived, (
        "export rewrote the family index"
    )
    assert (
        exported / "rounds" / "1" / "manifest.json"
    ).read_bytes() == (round1 / "manifest.json").read_bytes(), (
        "export rewrote a round manifest"
    )
    assert (
        exported / "campaign" / "manifest.json"
    ).read_bytes() == (campaign / "manifest.json").read_bytes(), (
        "export rewrote the campaign manifest"
    )


def test_export_family_rejects_duplicate_round_numbers(tmp_path):
    round1, digest1 = _bundle(tmp_path, kind="execution", name="dup-round-1")
    round1b, digest1b = _bundle(tmp_path, kind="execution", name="dup-round-1b")
    family_json = _archive(
        tmp_path,
        _index(campaign_digest=None, round_digests=[(1, digest1)]),
    )

    with pytest.raises(evidence.BundleError, match="round_no"):
        evidence.export_family(
            family_json,
            tmp_path / "export",
            rounds=[(1, round1), (1, round1b)],
        )
    assert not (tmp_path / "export").exists()
    assert digest1b


def test_export_family_rejects_a_non_empty_target(tmp_path):
    round1, digest1 = _bundle(tmp_path, kind="execution", name="non-empty-round")
    family_json = _archive(
        tmp_path,
        _index(campaign_digest=None, round_digests=[(1, digest1)]),
    )
    target = tmp_path / "export"
    target.mkdir()
    (target / "keep.txt").write_text("occupied", encoding="utf-8")

    with pytest.raises(evidence.BundleError, match="not empty"):
        evidence.export_family(family_json, target, rounds=[(1, round1)])


def test_export_family_rejects_a_symlink_target(tmp_path):
    round1, digest1 = _bundle(tmp_path, kind="execution", name="symlink-round")
    family_json = _archive(
        tmp_path,
        _index(campaign_digest=None, round_digests=[(1, digest1)]),
    )
    real = tmp_path / "real-target"
    real.mkdir()
    link = tmp_path / "linked-target"
    link.symlink_to(real, target_is_directory=True)

    with pytest.raises(evidence.BundleError, match="symlink"):
        evidence.export_family(family_json, link, rounds=[(1, round1)])


def test_export_family_rejects_a_trusted_digest_mismatch(tmp_path):
    round1, digest1 = _bundle(tmp_path, kind="execution", name="digest-round")
    family_json = _archive(
        tmp_path,
        _index(campaign_digest=None, round_digests=[(1, digest1)]),
    )

    with pytest.raises(evidence.BundleError) as raised:
        evidence.export_family(
            family_json,
            tmp_path / "export",
            rounds=[(1, round1)],
            expected_family_digest="sha256:" + "0" * 64,
        )
    assert raised.value.reason_code == "DIGEST_MISMATCH"
    assert not (tmp_path / "export").exists()


def test_export_family_rejects_campaign_source_mismatch(tmp_path):
    round1, digest1 = _bundle(tmp_path, kind="execution", name="campaign-round")
    campaign, campaign_digest = _bundle(
        tmp_path, kind="campaign", name="campaign-extra"
    )
    # The index has no campaign, but the caller supplies one.
    family_json = _archive(
        tmp_path,
        _index(campaign_digest=None, round_digests=[(1, digest1)]),
    )

    with pytest.raises(evidence.BundleError, match="campaign"):
        evidence.export_family(
            family_json,
            tmp_path / "export",
            campaign_source=campaign,
            rounds=[(1, round1)],
        )

    # The index has a campaign, but the caller omits it.
    with_campaign = _archive(
        tmp_path,
        _index(campaign_digest=campaign_digest, round_digests=[(1, digest1)]),
        name="archive-with-campaign",
    )
    with pytest.raises(evidence.BundleError, match="campaign"):
        evidence.export_family(with_campaign, tmp_path / "export2", rounds=[(1, round1)])


def test_export_family_fixed_family_has_no_campaign(tmp_path):
    round1, digest1 = _bundle(
        tmp_path, kind="execution", name="fixed-round-1"
    )
    family_json = _archive(
        tmp_path,
        _index(campaign_digest=None, round_digests=[(1, digest1)]),
    )

    info = evidence.export_family(
        family_json, tmp_path / "export", rounds=[(1, round1)]
    )

    assert not (tmp_path / "export" / "campaign").exists()
    assert (tmp_path / "export" / "rounds" / "1").is_dir()
    assert info.campaign_digest is None
    assert verify_bundle(tmp_path / "export" / "rounds" / "1").manifest_digest == digest1

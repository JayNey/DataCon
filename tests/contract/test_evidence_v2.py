"""TC-08/TC-16 T10: evidence v2 schema dispatch, role table and campaign gaps.

The full v2 bundle payload is built by later tasks; these contract tests pin
the parts T10 must expose first: the v2 role names, manifest schema dispatch,
the frozen v1 branch, and the campaign bundle's lack of a verdict or crash
seed requirement. They assert on the verifier's error surface rather than
pretending a full campaign bundle already exists.
"""

import json
from pathlib import Path
from uuid import uuid4

import pytest
from test_evidence import make_bundle

from datacon import contracts, evidence
from datacon.evidence import BundleError, export_bundle, verify_bundle

V2_ROLES = {
    # v0.1 roles the v2 table must keep.
    "normal_output",
    "normal_error",
    "asan_log",
    "case_config",
    "symbolizer_log",
    # v0.2 roles required by T12/T13/T14/T15.
    "envelope",
    "budget_snapshot",
    "build_provenance",
}


def _v2_manifest(*, bundle_kind, verdict):
    return {
        "schema_version": 2,
        "bundle_kind": bundle_kind,
        "job_id": str(uuid4()),
        "family_id": str(uuid4()),
        "parent_job_id": str(uuid4()),
        "round_no": None,
        "plan_digest": None if bundle_kind == "campaign" else "sha256:" + "a" * 64,
        "envelope_digest": "sha256:" + "b" * 64,
        "verdict": verdict,
        "reason_code": None,
        "files": [],
    }


def _write_manifest(tmp_path: Path, manifest):
    root = tmp_path / f"bundle-{uuid4().hex}"
    root.mkdir()
    (root / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    return root


def test_v2_role_table_contains_v01_roles():
    role_names = getattr(evidence, "V2_ROLE_NAMES", None)
    if role_names is None:
        role_names = evidence._ROLE_NAMES
    missing = sorted(V2_ROLES - set(role_names))
    assert not missing, f"v2 role table is missing required roles: {missing}"


def test_verify_bundle_dispatches_v1_and_v2_by_manifest_schema(tmp_path):
    v1 = make_bundle(tmp_path, name="v1")
    verified = verify_bundle(v1.root)
    assert verified.manifest["schema_version"] == 1, (
        "v1 bundle was not read by the frozen v1 branch"
    )

    v2_root = _write_manifest(
        tmp_path, _v2_manifest(bundle_kind="execution", verdict="REPRODUCED")
    )
    with pytest.raises(BundleError) as info:
        verify_bundle(v2_root)
    message = str(info.value)
    assert "schema_version must be 1" not in message, (
        "schema_version 2 bundle was routed to the frozen v1 validator"
    )


def test_v1_job_cannot_be_rerun_with_v2_semantics(tmp_path):
    assert contracts.SCHEMA_VERSION == 1
    assert getattr(contracts, "SCHEMA_VERSION_V2", None) == 2, (
        "contracts.SCHEMA_VERSION_V2 is missing; v2 semantics cannot be fenced"
    )

    v1 = make_bundle(tmp_path, name="v1-frozen")
    assert verify_bundle(v1.root).manifest["schema_version"] == 1
    exported = export_bundle(
        v1.root,
        tmp_path / "v1-exported",
        expected_manifest_digest=v1.manifest_digest,
    )
    assert exported.manifest["schema_version"] == 1, (
        "v1 job re-ran under v2 plan"
    )
    assert exported.manifest_digest == v1.manifest_digest, (
        "v1 read-only export rewrote the manifest"
    )


def test_campaign_bundle_allows_zero_crash_seed(tmp_path):
    root = _write_manifest(
        tmp_path, _v2_manifest(bundle_kind="campaign", verdict=None)
    )
    with pytest.raises(BundleError) as info:
        verify_bundle(root)
    message = str(info.value)
    assert "schema_version must be 1" not in message, (
        "campaign bundle was routed to the frozen v1 validator"
    )
    assert "crash_seed" not in message, (
        "zero-crash campaign required a crash_seed"
    )


def test_campaign_bundle_has_no_verdict(tmp_path):
    root = _write_manifest(
        tmp_path, _v2_manifest(bundle_kind="campaign", verdict=None)
    )
    with pytest.raises(BundleError) as info:
        verify_bundle(root)
    message = str(info.value)
    assert "schema_version must be 1" not in message, (
        "campaign bundle was routed to the frozen v1 validator"
    )
    assert "verdict" not in message, (
        "campaign report requires a verdict"
    )

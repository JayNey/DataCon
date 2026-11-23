"""TC-08/TC-16 T10: evidence v2 schema dispatch, role table and bundle shapes.

T10 owns the v2 dispatch and the fixed-path/role surface. Full semantic replay
of report/plan belongs to later evidence tasks, so these bundles carry valid
manifests and raw bytes; the verifier must accept them without T13/T14/T15
roles and must fail closed on the conditional shapes.
"""

import hashlib
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
DIGEST = "sha256:" + "a" * 64
OTHER_DIGEST = "sha256:" + "b" * 64
VERSIONS = ("vulnerable", "fixed")
PHASES = ("normal", "candidate_1", "candidate_2")


def _write_v2_bundle(tmp_path: Path, manifest, files, *, name="v2-bundle"):
    root = tmp_path / f"{name}-{uuid4().hex}"
    root.mkdir()
    entries = []
    for relative, (role, data) in sorted(files.items()):
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        entries.append(
            {
                "path": relative,
                "role": role,
                "size_bytes": len(data),
                "sha256": hashlib.sha256(data).hexdigest(),
            }
        )
    document = dict(manifest)
    document["files"] = entries
    (root / "manifest.json").write_text(
        json.dumps(document), encoding="utf-8"
    )
    return root


def _base_files(*, execution, campaign):
    files = {
        "report.json": ("report_json", b'{"report":true}\n'),
        "report.md": ("report_markdown", b"# report\n"),
        "plan.json": ("plan", b'{"plan":true}\n'),
        "envelope.json": ("envelope", b'{"envelope":true}\n'),
        "budget/snapshot.json": ("budget_snapshot", b'{"budget":true}\n'),
        "metadata/execution.json": ("execution_metadata", b"{}\n"),
        "metadata/probe.json": ("probe", b"{}\n"),
        "metadata/case.json": ("case_config", b"{}\n"),
    }
    for version in VERSIONS:
        prefix = f"build/{version}/"
        files[prefix + "metadata.json"] = ("build_metadata", b"{}\n")
        files[prefix + "build.log"] = ("build_log", b"build ok\n")
        files[prefix + "parser"] = ("build_artifact", b"binary\n")
        files[prefix + "build_provenance/compile_commands.json"] = (
            "build_provenance",
            b"[]\n",
        )
    if execution:
        for version in VERSIONS:
            for phase in PHASES:
                base = f"replay/{version}/{phase}/"
                if phase == "normal":
                    files[base + "stdout.log"] = ("normal_output", b"ok\n")
                    files[base + "stderr.log"] = ("normal_error", b"\n")
                else:
                    files[base + "stdout.log"] = ("replay_stdout", b"ok\n")
                    files[base + "stderr.log"] = ("asan_log", b"asan\n")
                files[base + "metadata.json"] = ("replay_metadata", b"{}\n")
        files["review.json"] = ("review", b'{"decision":"approve"}\n')
    if campaign:
        files["fuzz/fuzz.log"] = ("fuzz_log", b"fuzz log\n")
        files["fuzz/provenance.json"] = ("fuzz_provenance", b"{}\n")
        files["review.json"] = ("review", b'{"decision":"approve"}\n')
    return files


def _manifest(bundle_kind, *, verdict="INCONCLUSIVE", reason="EVIDENCE_INCOMPLETE"):
    family_id = str(uuid4())
    common = {
        "schema_version": 2,
        "bundle_kind": bundle_kind,
        "job_id": str(uuid4()),
        "created_at": "2099-01-01T00:00:00Z",
        "files": [],
    }
    if bundle_kind == "blocked":
        common.update(
            {
                "family_id": None,
                "parent_job_id": None,
                "round_no": None,
                "plan_digest": None,
                "envelope_digest": None,
                "experiment_digest": None,
                "build_provenance_rules_version": None,
                "verdict": "BLOCKED",
                "reason_code": "REVIEW_REJECTED",
                "build_ref": None,
                "reuse_origin": None,
            }
        )
        return common
    common.update(
        {
            "family_id": family_id,
            "parent_job_id": family_id,
            "round_no": None if bundle_kind == "campaign" else 2,
            "plan_digest": DIGEST,
            "envelope_digest": OTHER_DIGEST,
            "experiment_digest": None,
            "build_provenance_rules_version": "build-provenance-v1",
            "verdict": verdict,
            "reason_code": reason,
            "build_ref": None,
            "reuse_origin": None,
        }
    )
    return common


def test_v2_role_table_contains_v01_roles():
    missing = sorted(V2_ROLES - set(evidence.V2_ROLE_NAMES))
    assert not missing, f"v2 role table is missing required roles: {missing}"


def test_verify_bundle_dispatches_v1_and_v2_by_manifest_schema(tmp_path):
    v1 = make_bundle(tmp_path, name="v1")
    verified = verify_bundle(v1.root)
    assert verified.manifest["schema_version"] == 1, (
        "v1 bundle was not read by the frozen v1 branch"
    )

    root = _write_v2_bundle(
        tmp_path,
        _manifest("execution"),
        _base_files(execution=True, campaign=False),
        name="dispatch",
    )
    assert verify_bundle(root).manifest["schema_version"] == 2


def test_v2_execution_bundle_verifies_with_fixed_paths(tmp_path):
    root = _write_v2_bundle(
        tmp_path,
        _manifest("execution"),
        _base_files(execution=True, campaign=False),
    )
    verified = verify_bundle(root)
    assert verified.manifest["bundle_kind"] == "execution"


def test_v2_execution_requires_exactly_one_review_or_admission(tmp_path):
    manifest = _manifest("execution")
    files = _base_files(execution=True, campaign=False)
    del files["review.json"]
    root = _write_v2_bundle(tmp_path, manifest, files, name="no-review")
    with pytest.raises(BundleError, match="exactly one"):
        verify_bundle(root)

    files = _base_files(execution=True, campaign=False)
    files["admission.json"] = ("admission", b'{"approval_kind":"policy"}\n')
    root = _write_v2_bundle(tmp_path, manifest, files, name="both")
    with pytest.raises(BundleError, match="exactly one"):
        verify_bundle(root)


def test_v2_replay_roles_must_live_at_fixed_paths(tmp_path):
    manifest = _manifest("execution")
    files = _base_files(execution=True, campaign=False)
    files["replay/vulnerable/normal/sideways.log"] = ("normal_output", b"ok\n")
    root = _write_v2_bundle(tmp_path, manifest, files, name="bad-replay")
    with pytest.raises(BundleError, match="fixed replay path"):
        verify_bundle(root)


def test_campaign_bundle_allows_zero_crash_seed(tmp_path):
    root = _write_v2_bundle(
        tmp_path,
        _manifest("campaign", verdict=None, reason=None),
        _base_files(execution=False, campaign=True),
        name="campaign",
    )
    verified = verify_bundle(root)
    assert verified.manifest["bundle_kind"] == "campaign"
    assert "crash_seed" not in {entry["role"] for entry in verified.manifest["files"]}


def test_campaign_bundle_requires_fuzz_provenance(tmp_path):
    files = _base_files(execution=False, campaign=True)
    del files["fuzz/provenance.json"]
    root = _write_v2_bundle(
        tmp_path, _manifest("campaign", verdict=None, reason=None), files
    )
    with pytest.raises(BundleError, match="fuzz_provenance"):
        verify_bundle(root)


def test_campaign_bundle_has_no_verdict(tmp_path):
    files = _base_files(execution=False, campaign=True)
    for verdict, reason in (("REPRODUCED", None), (None, "EVIDENCE_INCOMPLETE")):
        root = _write_v2_bundle(
            tmp_path,
            _manifest("campaign", verdict=verdict, reason=reason),
            dict(files),
        )
        with pytest.raises(BundleError, match="verdict|reason_code"):
            verify_bundle(root)


def test_blocked_bundle_only_requires_the_two_reports(tmp_path):
    files = {
        "report.json": ("report_json", b'{"report":true}\n'),
        "report.md": ("report_markdown", b"# blocked\n"),
    }
    root = _write_v2_bundle(tmp_path, _manifest("blocked"), files, name="blocked")
    verified = verify_bundle(root)
    assert verified.manifest["bundle_kind"] == "blocked"


def test_family_bundle_kind_is_not_a_bundle(tmp_path):
    manifest = _manifest("blocked")
    manifest["bundle_kind"] = "family"
    root = _write_v2_bundle(
        tmp_path,
        manifest,
        {
            "report.json": ("report_json", b"{}"),
            "report.md": ("report_markdown", b"# family\n"),
        },
        name="family",
    )
    with pytest.raises(BundleError, match="bundle_kind"):
        verify_bundle(root)


def test_v1_job_cannot_be_rerun_with_v2_semantics(tmp_path):
    """There is no re-run entry point; v1 stays export/verify-only.

    The repository exposes submit/worker/status/review/export/verify only, so
    this test pins both halves of the boundary: a v1 bundle exports unchanged,
    and the v2 manifest schema cannot be pointed at a v1 job that has no
    family/round identity.
    """
    assert contracts.SCHEMA_VERSION == 1
    assert contracts.SCHEMA_VERSION_V2 == 2

    v1 = make_bundle(tmp_path, name="v1-frozen")
    assert verify_bundle(v1.root).manifest["schema_version"] == 1
    exported = export_bundle(
        v1.root,
        tmp_path / "v1-exported",
        expected_manifest_digest=v1.manifest_digest,
    )
    assert exported.manifest["schema_version"] == 1
    assert exported.manifest_digest == v1.manifest_digest

    v2_manifest = _manifest("execution")
    v2_manifest["job_id"] = v1.manifest["job_id"]
    v2_manifest["family_id"] = None
    v2_manifest["parent_job_id"] = None
    v2_manifest["round_no"] = None
    root = _write_v2_bundle(
        tmp_path,
        v2_manifest,
        _base_files(execution=True, campaign=False),
        name="v2-on-v1-job",
    )
    with pytest.raises(BundleError):
        verify_bundle(root)


def test_v1_verification_uses_frozen_compile_args_extractor(tmp_path, monkeypatch):
    from datacon.tools import sandbox

    monkeypatch.setattr(
        sandbox, "_extract_compile_args", lambda recipe: ("-evil-flag",)
    )

    # The v1 branch must not observe the live sandbox implementation.
    v1 = make_bundle(tmp_path, name="v1-frozen-extractor")
    assert verify_bundle(v1.root).manifest["schema_version"] == 1

    # v2 does not call the frozen v1 extractor at all; its verifier still
    # passes the fixed-path surface.
    v2_root = _write_v2_bundle(
        tmp_path,
        _manifest("execution"),
        _base_files(execution=True, campaign=False),
        name="v2-after-monkeypatch",
    )
    assert verify_bundle(v2_root).manifest["schema_version"] == 2

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
from test_evidence import (
    MATERIAL_DIGESTS,
    _rewrite_manifested_file,
    _update_build,
    make_bundle,
)

from datacon import contracts, evidence
from datacon.evidence import BundleError, export_bundle, verify_bundle

# The complete frozen v0.1 role table. It is listed explicitly rather than
# reflected from ``evidence._ROLE_NAMES`` so deleting a production role makes
# this contract test fail instead of shrinking its own expectation.
V1_ROLES = {
    "report_json",
    "report_markdown",
    "plan",
    "review",
    "execution_metadata",
    "probe",
    "build_log",
    "build_metadata",
    "build_artifact",
    "normal_output",
    "normal_error",
    "asan_log",
    "replay_stdout",
    "replay_stderr",
    "replay_metadata",
    "material_harness",
    "material_build_recipe",
    "material_dependencies",
    "material_input_normal",
    "material_input_candidate",
    "material_source_vulnerable",
    "material_source_fixed",
    "material_patch",
    "material_repository_bundle",
    "material_advisory",
    "case_config",
    "symbolizer_log",
}
# The thirteen additive v0.2 roles accepted by the v2 verifier.
V2_NEW_ROLES = {
    "envelope",
    "budget_snapshot",
    "build_provenance",
    "admission",
    "budget_ledger",
    "budget_charge",
    "experiment_spec",
    "model_audit",
    "fuzz_log",
    "crash_seed",
    "fuzz_provenance",
    "intel_snapshot",
    "license_record",
}
V2_ROLES = V1_ROLES | V2_NEW_ROLES
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


def _report_build_provenance(
    face: str = "compile_commands.json", *, comparable: bool = True
) -> dict:
    return {
        "vulnerable": {"face": face, "declared": [], "effective": []},
        "fixed": {"face": face, "declared": [], "effective": []},
        "comparable": comparable,
    }


def _base_files(*, execution, campaign):
    files = {
        "report.json": (
            "report_json",
            json.dumps(
                {
                    "report": True,
                    "build_provenance_rules_version": "build-provenance-v1",
                    "build_provenance": _report_build_provenance(),
                },
                sort_keys=True,
            ).encode("utf-8")
            + b"\n",
        ),
        "report.md": ("report_markdown", b"# report\n"),
        "plan.json": (
            "plan",
            b'{"plan":true,"build_provenance_rules_version":"build-provenance-v1"}\n',
        ),
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


def test_v1_role_table_stays_frozen():
    # The v1 table is frozen: v0.2 roles must live only in the v2 additive
    # table, otherwise a v1 bundle could carry v0.2-only evidence roles.
    assert set(evidence._ROLE_NAMES) == V1_ROLES
    assert len(evidence._ROLE_NAMES) == 27
    assert set(evidence._REQUIRED_ROLES) == {
        "report_json",
        "report_markdown",
        "plan",
        "review",
    }
    assert set(evidence._BLOCKED_REQUIRED_ROLES) == {
        "report_json",
        "report_markdown",
    }


def test_v2_role_table_contains_v01_roles():
    # Exact equality in both directions: every registered v1/v2 role is
    # accepted, and the implementation may not invent an unregistered role.
    assert set(evidence.V2_ROLE_NAMES) == V2_ROLES
    assert len(evidence.V2_ROLE_NAMES) == 40


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


def test_manifest_uses_fixed_evidence_paths(tmp_path):
    """T12/TC-16 (D39): every v2 role lives at its canonical fixed path."""
    files = _base_files(execution=True, campaign=False)
    root = _write_v2_bundle(tmp_path, _manifest("execution"), files)
    verified = verify_bundle(root)
    listed = {
        entry["path"]: entry["role"] for entry in verified.manifest["files"]
    }

    expected = {
        "metadata/execution.json": "execution_metadata",
        "metadata/probe.json": "probe",
        "metadata/case.json": "case_config",
        "plan.json": "plan",
        "review.json": "review",
        "envelope.json": "envelope",
        "budget/snapshot.json": "budget_snapshot",
    }
    for version in VERSIONS:
        prefix = f"build/{version}/"
        expected[prefix + "metadata.json"] = "build_metadata"
        expected[prefix + "build.log"] = "build_log"
        expected[prefix + "parser"] = "build_artifact"
        expected[prefix + "build_provenance/compile_commands.json"] = (
            "build_provenance"
        )
        for phase in PHASES:
            replay = f"replay/{version}/{phase}/"
            expected[replay + "stdout.log"] = (
                "normal_output" if phase == "normal" else "replay_stdout"
            )
            expected[replay + "stderr.log"] = (
                "normal_error" if phase == "normal" else "asan_log"
            )
            expected[replay + "metadata.json"] = "replay_metadata"
    for path, role in expected.items():
        assert listed.get(path) == role, (
            f"manifest must list fixed evidence path {path} with role {role}, "
            f"got {listed.get(path)!r}"
        )
    assert len([path for path in listed if path.startswith("replay/")]) == 18, (
        "the fixed replay layout is two versions x three phases x three files"
    )

    # A v2 role may not escape its fixed path: an alias for execution metadata
    # must fail closed instead of being accepted as an ad-hoc location.
    ad_hoc = _base_files(execution=True, campaign=False)
    ad_hoc["metadata/execution-notes.json"] = ("execution_metadata", b"{}\n")
    alias_root = _write_v2_bundle(
        tmp_path,
        _manifest("execution"),
        ad_hoc,
        name="ad-hoc-execution-metadata",
    )
    with pytest.raises(BundleError, match="must live at metadata/execution.json"):
        verify_bundle(alias_root)


@pytest.mark.parametrize("relative", ["envelope.json", "budget/snapshot.json"])
def test_v2_execution_requires_envelope_and_budget_snapshot(tmp_path, relative):
    files = _base_files(execution=True, campaign=False)
    del files[relative]
    root = _write_v2_bundle(
        tmp_path,
        _manifest("execution"),
        files,
        name="missing-" + relative.replace("/", "-"),
    )
    with pytest.raises(BundleError, match="missing required roles"):
        verify_bundle(root)


def test_v2_execution_accepts_admission_instead_of_review(tmp_path):
    files = _base_files(execution=True, campaign=False)
    del files["review.json"]
    files["admission.json"] = ("admission", b'{"approval_kind":"policy"}\n')
    root = _write_v2_bundle(
        tmp_path,
        _manifest("execution"),
        files,
        name="admission-only",
    )
    verified = verify_bundle(root)
    assert "admission.json" in verified.file_data
    assert "review.json" not in verified.file_data


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


def _blocked_files(
    manifest,
    *,
    report_overrides=None,
    markdown_override=None,
    extra_files=None,
):
    reason = manifest["reason_code"]
    markdown_text = (
        markdown_override
        if markdown_override is not None
        else (
            "# DataCon evidence report\n\n"
            "- Verdict: **BLOCKED**\n"
            f"- Reason: `{reason or ''}`\n"
        )
    )
    markdown_bytes = markdown_text.encode("utf-8")
    report = {
        "schema_version": 2,
        "bundle_kind": "blocked",
        "job_id": manifest["job_id"],
        "plan_digest": manifest["plan_digest"],
        "state": "BLOCKED",
        "verdict": "BLOCKED",
        "reason_code": reason,
        "review": None,
        "missing": ["execution did not complete"],
        "error": f"{reason}: blocked" if reason else None,
        "evidence_complete": False,
        "created_at": "2099-01-01T00:00:00Z",
        "report_markdown_sha256": hashlib.sha256(markdown_bytes).hexdigest(),
    }
    if report_overrides:
        report.update(report_overrides)
    files = {
        "report.json": ("report_json", json.dumps(report).encode("utf-8") + b"\n"),
        "report.md": ("report_markdown", markdown_bytes),
    }
    if extra_files:
        files.update(extra_files)
    return files


def test_blocked_bundle_only_requires_the_two_reports(tmp_path):
    manifest = _manifest("blocked")
    root = _write_v2_bundle(
        tmp_path, manifest, _blocked_files(manifest), name="blocked"
    )
    verified = verify_bundle(root)
    assert verified.manifest["bundle_kind"] == "blocked"
    # The fixture ships only the two reports. Pinning the absence of the
    # execution-only artifacts keeps this coordinate from silently growing
    # into a bundle that requires them.
    assert set(verified.file_data) == {"report.json", "report.md"}
    for absent in ("plan.json", "review.json", "envelope.json", "budget/snapshot.json"):
        assert absent not in verified.file_data


def _build_artifacts():
    return {
        "vulnerable": {
            "artifact_digest": DIGEST,
            "build_log_digest": OTHER_DIGEST,
        },
        "fixed": {
            "artifact_digest": OTHER_DIGEST,
            "build_log_digest": DIGEST,
        },
    }


def _build_ref():
    return {
        "source_job_id": str(uuid4()),
        "generation": 3,
        "build_inputs_digest": DIGEST,
        "artifacts": _build_artifacts(),
    }


def test_v2_blocked_accepts_a_schema_valid_build_ref_and_reuse_origin(tmp_path):
    manifest = _manifest("blocked")
    build_ref = _build_ref()
    reuse_origin = {
        "source_job_id": build_ref["source_job_id"],
        "generation": build_ref["generation"],
        "campaign_bundle_digest": OTHER_DIGEST,
        "artifacts": _build_artifacts(),
    }
    manifest["build_ref"] = build_ref
    manifest["reuse_origin"] = reuse_origin
    root = _write_v2_bundle(
        tmp_path, manifest, _blocked_files(manifest), name="blocked-provenance"
    )
    verified = verify_bundle(root)
    assert verified.manifest["build_ref"] == build_ref


@pytest.mark.parametrize(
    "build_ref,reuse_origin,reason_code",
    [
        ({"bad": 1}, None, "INVALID_MANIFEST"),
        (None, {"bad": 1}, "INVALID_MANIFEST"),
        # A reuse_origin whose source/generation/artifacts disagree with the
        # build_ref is a reuse mismatch, not silent provenance.
        (
            "valid",
            {
                "source_job_id": str(uuid4()),
                "generation": 9,
                "campaign_bundle_digest": OTHER_DIGEST,
                "artifacts": _build_artifacts(),
            },
            "REUSE_MISMATCH",
        ),
    ],
    ids=["bad-build-ref", "reuse-without-build-ref", "inconsistent-reuse"],
)
def test_v2_blocked_rejects_malformed_or_inconsistent_provenance(
    tmp_path, build_ref, reuse_origin, reason_code
):
    manifest = _manifest("blocked")
    manifest["build_ref"] = _build_ref() if build_ref == "valid" else build_ref
    manifest["reuse_origin"] = reuse_origin
    root = _write_v2_bundle(
        tmp_path, manifest, _blocked_files(manifest), name="blocked-bad-provenance"
    )
    with pytest.raises(BundleError) as raised:
        verify_bundle(root)
    assert raised.value.reason_code == reason_code


@pytest.mark.parametrize(
    "reason",
    [
        "ENVELOPE_VIOLATION",
        "ADMISSION_DENIED",
        "HARNESS_REJECTED",
        "BUILD_PROVENANCE_MISSING",
    ],
)
def test_v2_blocked_bundle_accepts_new_blocked_reason(tmp_path, reason):
    manifest = _manifest("blocked")
    manifest["reason_code"] = reason
    root = _write_v2_bundle(
        tmp_path,
        manifest,
        _blocked_files(manifest),
        name=f"blocked-{reason.lower()}",
    )

    verified = verify_bundle(root)
    assert verified.manifest["reason_code"] == reason
    assert verified.manifest["verdict"] == "BLOCKED"


def _mutate_blocked_report(files, mutate):
    updated = dict(files)
    report = json.loads(updated["report.json"][1])
    mutate(report)
    updated["report.json"] = (
        "report_json",
        json.dumps(report).encode("utf-8") + b"\n",
    )
    return updated


def _without_bundle_kind(report):
    del report["bundle_kind"]


def _without_created_at(report):
    del report["created_at"]


def _invalid_created_at(report):
    report["created_at"] = "not-a-timestamp"


@pytest.mark.parametrize(
    "mutate",
    [_without_bundle_kind, _without_created_at, _invalid_created_at],
    ids=["no-bundle-kind", "no-created-at", "bad-created-at"],
)
def test_v2_blocked_verify_requires_report_bundle_kind_and_created_at(
    tmp_path, mutate
):
    manifest = _manifest("blocked")
    files = _mutate_blocked_report(_blocked_files(manifest), mutate)
    root = _write_v2_bundle(tmp_path, manifest, files, name="blocked-report")

    with pytest.raises(BundleError) as raised:
        verify_bundle(root)
    assert raised.value.reason_code == "INVALID_MANIFEST"


def _write_blocked_report(tmp_path, report, name):
    return evidence.write_bundle(
        tmp_path / name,
        job_id=report["job_id"],
        plan_digest=None,
        bundle_kind="blocked",
        report=report,
        report_markdown=(
            "# DataCon evidence report\n\n"
            "- Verdict: **BLOCKED**\n"
            "- Reason: `ADMISSION_DENIED`\n"
        ),
        verdict="BLOCKED",
        schema_version=2,
    )


def _v2_blocked_report():
    return {
        "schema_version": 2,
        "bundle_kind": "blocked",
        "job_id": str(uuid4()),
        "plan_digest": None,
        "state": "BLOCKED",
        "verdict": "BLOCKED",
        "reason_code": "ADMISSION_DENIED",
        "review": None,
        "missing": ["execution did not complete"],
        "error": "ADMISSION_DENIED: denied",
        "evidence_complete": False,
        "created_at": "2099-01-01T00:00:00Z",
    }


@pytest.mark.parametrize(
    "mutate",
    [_without_bundle_kind, _without_created_at, _invalid_created_at],
    ids=["no-bundle-kind", "no-created-at", "bad-created-at"],
)
def test_write_bundle_v2_blocked_requires_report_bundle_kind_and_created_at(
    tmp_path, mutate
):
    report = _v2_blocked_report()
    mutate(report)

    with pytest.raises(BundleError) as raised:
        _write_blocked_report(tmp_path, report, "blocked-report")
    assert raised.value.reason_code == "INVALID_MANIFEST"
    assert not (tmp_path / "blocked-report").exists()


def test_write_bundle_v2_blocked_accepts_v2_roles_and_enforces_layout(tmp_path):
    report = _v2_blocked_report()
    markdown = (
        "# DataCon evidence report\n\n"
        "- Verdict: **BLOCKED**\n"
        "- Reason: `ADMISSION_DENIED`\n"
    )
    info = evidence.write_bundle(
        tmp_path / "v2-with-envelope",
        job_id=report["job_id"],
        plan_digest=None,
        bundle_kind="blocked",
        report=report,
        report_markdown=markdown,
        artifacts={"envelope.json": ("envelope", b'{"mode":"fixed"}\n')},
        verdict="BLOCKED",
        verify=verify_bundle,
        schema_version=2,
    )
    verified = verify_bundle(info.root)
    roles_by_path = {
        entry["path"]: entry["role"] for entry in verified.manifest["files"]
    }
    assert roles_by_path["envelope.json"] == "envelope"

    # v2 layout rules must also reject misplaced v2 roles and admission.json at
    # write time, even when verify=None.
    for name, artifacts in (
        ("wrong-path", {"other.json": ("envelope", b'{"mode":"fixed"}\n')}),
        ("blocked-admission", {"admission.json": ("admission", b"{}\n")}),
    ):
        with pytest.raises(BundleError) as raised:
            evidence.write_bundle(
                tmp_path / name,
                job_id=report["job_id"],
                plan_digest=None,
                bundle_kind="blocked",
                report=report,
                report_markdown=markdown,
                artifacts=artifacts,
                verdict="BLOCKED",
                schema_version=2,
            )
        assert raised.value.reason_code == "INVALID_MANIFEST"
        assert not (tmp_path / name).exists()

    # v1 boundary: schema_version=1 must still reject v2-only roles.
    v1_report = dict(report)
    v1_report["schema_version"] = 1
    v1_report["reason_code"] = "POLICY_DENIED"
    v1_report.pop("bundle_kind")
    v1_markdown = (
        "# DataCon evidence report\n\n"
        "- Verdict: **BLOCKED**\n"
        "- Reason: `POLICY_DENIED`\n"
    )
    with pytest.raises(BundleError, match="unknown evidence role: envelope") as v1_err:
        evidence.write_bundle(
            tmp_path / "v1-rejects-v2-role",
            job_id=v1_report["job_id"],
            plan_digest=None,
            bundle_kind="blocked",
            report=v1_report,
            report_markdown=v1_markdown,
            artifacts={"envelope.json": ("envelope", b'{"mode":"fixed"}\n')},
            verdict="BLOCKED",
            schema_version=1,
        )
    assert v1_err.value.reason_code == "INVALID_MANIFEST"
    assert not (tmp_path / "v1-rejects-v2-role").exists()


@pytest.mark.parametrize(
    "verdict,reason",
    [
        ("FAILED", "REUSE_MISMATCH"),
        ("FAILED", "BUILD_PROVENANCE_MISSING"),
        ("INCONCLUSIVE", "BUDGET_EXHAUSTED"),
        ("FAILED", "BUDGET_EXHAUSTED"),
    ],
)
def test_v2_execution_accepts_new_verdict_reason_codes(tmp_path, verdict, reason):
    root = _write_v2_bundle(
        tmp_path,
        _manifest("execution", verdict=verdict, reason=reason),
        _base_files(execution=True, campaign=False),
        name=f"execution-{reason.lower()}-{verdict.lower()}",
    )

    assert verify_bundle(root).manifest["reason_code"] == reason


@pytest.mark.parametrize(
    "verdict,reason",
    [
        # BLOCKED is a closed set: a FAILED-only code cannot leak into it.
        ("BLOCKED", "BUILD_FAILED"),
        ("BLOCKED", "REUSE_MISMATCH"),
        ("BLOCKED", "REVIEW_ENVELOPE_MISMATCH"),
        # A review-call rejection code is not a job terminal reason.
        ("INCONCLUSIVE", "ENVELOPE_VIOLATION"),
        ("INCONCLUSIVE", "REVIEW_ENVELOPE_MISMATCH"),
        ("FAILED", "ENVELOPE_VIOLATION"),
    ],
)
def test_v2_manifest_rejects_reason_outside_verdict_closed_set(
    tmp_path, verdict, reason
):
    root = _write_v2_bundle(
        tmp_path,
        _manifest("execution", verdict=verdict, reason=reason),
        _base_files(execution=True, campaign=False),
        name=f"bad-{reason.lower()}-{verdict.lower()}",
    )

    with pytest.raises(BundleError) as raised:
        verify_bundle(root)
    assert raised.value.reason_code == "INVALID_MANIFEST"


def test_v2_blocked_bundle_rejects_missing_reason(tmp_path):
    manifest = _manifest("blocked")
    manifest["reason_code"] = None
    root = _write_v2_bundle(
        tmp_path,
        manifest,
        {
            "report.json": ("report_json", b'{"report":true}\n'),
            "report.md": ("report_markdown", b"# blocked\n"),
        },
        name="blocked-no-reason",
    )

    with pytest.raises(BundleError) as raised:
        verify_bundle(root)
    assert raised.value.reason_code == "INVALID_MANIFEST"


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


def test_v2_non_reuse_validation_accepts_experiment_digest_without_build_ref(tmp_path):
    manifest = _manifest("execution")
    manifest["experiment_digest"] = "sha256:" + "c" * 64
    manifest["build_ref"] = None
    manifest["reuse_origin"] = None
    root = _write_v2_bundle(
        tmp_path,
        manifest,
        _base_files(execution=True, campaign=False),
        name="non-reuse-validation",
    )
    verified = verify_bundle(root)
    assert verified.manifest["experiment_digest"] == "sha256:" + "c" * 64
    assert verified.manifest["build_ref"] is None
    assert verified.manifest["reuse_origin"] is None


def test_v2_non_reuse_execution_still_rejects_build_ref_without_reuse_origin(tmp_path):
    manifest = _manifest("execution")
    manifest["experiment_digest"] = "sha256:" + "c" * 64
    manifest["reuse_origin"] = None
    manifest["build_ref"] = {
        "source_job_id": str(uuid4()),
        "generation": 1,
        "build_inputs_digest": DIGEST,
        "artifacts": {
            "vulnerable": {
                "artifact_digest": DIGEST,
                "build_log_digest": OTHER_DIGEST,
            },
            "fixed": {
                "artifact_digest": OTHER_DIGEST,
                "build_log_digest": DIGEST,
            },
        },
    }
    root = _write_v2_bundle(
        tmp_path,
        manifest,
        _base_files(execution=True, campaign=False),
        name="non-reuse-with-build-ref",
    )
    with pytest.raises(BundleError, match="build_ref") as raised:
        verify_bundle(root)
    assert raised.value.reason_code == "INVALID_MANIFEST"


def test_fixed_execution_has_envelope_but_no_reuse_origin(tmp_path):
    """T12/TC-12: a fixed round has a non-empty envelope but no reuse pointer."""
    manifest = _manifest("execution")
    assert manifest["envelope_digest"] is not None
    root = _write_v2_bundle(
        tmp_path,
        manifest,
        _base_files(execution=True, campaign=False),
        name="fixed-execution",
    )
    verified = verify_bundle(root)
    assert verified.manifest["envelope_digest"] == OTHER_DIGEST
    assert verified.manifest["build_ref"] is None
    assert verified.manifest["reuse_origin"] is None


@pytest.mark.parametrize("missing", ["build_ref", "reuse_origin"])
def test_reuse_validation_requires_build_ref_and_reuse_origin(tmp_path, missing):
    """T12/TC-16: a reused validation round needs both provenance halves."""
    manifest = _manifest("execution")
    build_ref = _build_ref()
    manifest["experiment_digest"] = DIGEST
    manifest["build_ref"] = build_ref
    manifest["reuse_origin"] = {
        "source_job_id": build_ref["source_job_id"],
        "generation": build_ref["generation"],
        "campaign_bundle_digest": OTHER_DIGEST,
        "artifacts": _build_artifacts(),
    }
    if missing == "build_ref":
        manifest["build_ref"] = None
        expected = "requires build_ref"
    else:
        manifest["reuse_origin"] = None
        expected = "must not carry build_ref"
    root = _write_v2_bundle(
        tmp_path,
        manifest,
        _base_files(execution=True, campaign=False),
        name="reuse-missing-" + missing,
    )
    with pytest.raises(BundleError, match=expected) as raised:
        verify_bundle(root)
    assert raised.value.reason_code == "INVALID_MANIFEST"


def test_v2_build_record_rejects_input_aliases(tmp_path):
    """T12 (D4): v2 build records only stage build materials, never inputs."""
    files = _base_files(execution=True, campaign=False)
    report = {
        "schema_version": 2,
        "builds": [
            {
                "version": version,
                "staged_materials": {
                    "harness.c": DIGEST,
                    "inputs/normal.txt": DIGEST,
                    "inputs/candidate.txt": OTHER_DIGEST,
                },
            }
            for version in VERSIONS
        ],
    }
    files["report.json"] = (
        "report_json",
        json.dumps(report).encode() + b"\n",
    )
    root = _write_v2_bundle(
        tmp_path,
        _manifest("execution"),
        files,
        name="v2-build-input-aliases",
    )
    with pytest.raises(BundleError, match="input alias"):
        verify_bundle(root)


def test_v1_build_record_still_requires_input_aliases(tmp_path):
    """T12 (D4): the frozen v1 branch keeps its two staged input aliases."""
    info = make_bundle(tmp_path, name="v1-input-aliases")
    assert verify_bundle(info.root).manifest["schema_version"] == 1

    for version in VERSIONS:
        staged = dict(MATERIAL_DIGESTS)
        staged.pop("inputs/normal.txt")
        staged.pop("inputs/candidate.txt")
        _update_build(info.root, version, staged_materials=staged)

    with pytest.raises(BundleError) as raised:
        verify_bundle(info.root)
    assert raised.value.reason_code in ("DIGEST_MISMATCH", "INVALID_MANIFEST")
    assert "missing=" in raised.value.message


@pytest.mark.parametrize(
    "alias",
    [
        "inputs/normal.txt",
        "inputs/candidate.txt",
        "./inputs/normal.txt",
        "inputs/./candidate.txt",
        "a/../inputs/normal.txt",
        "/inputs/normal.txt",
    ],
)
def test_v2_build_metadata_rejects_input_alias_variants(tmp_path, alias):
    """D4 must cover the archived build metadata, not only report.json."""
    files = _base_files(execution=True, campaign=False)
    root = _write_v2_bundle(
        tmp_path,
        _manifest("execution"),
        files,
        name="v2-build-metadata-alias",
    )
    metadata = {
        "version": "vulnerable",
        "staged_materials": {"harness.c": DIGEST, alias: OTHER_DIGEST},
    }
    _rewrite_manifested_file(
        root,
        "build/vulnerable/metadata.json",
        json.dumps(metadata).encode() + b"\n",
    )
    with pytest.raises(BundleError, match="input aliases"):
        verify_bundle(root)


def test_v2_execution_metadata_rejects_input_aliases(tmp_path):
    """The execution metadata is another carrier of the v2 build list."""
    files = _base_files(execution=True, campaign=False)
    root = _write_v2_bundle(
        tmp_path,
        _manifest("execution"),
        files,
        name="v2-execution-metadata-alias",
    )
    execution = {
        "builds": [
            {
                "version": "vulnerable",
                "staged_materials": {
                    "harness.c": DIGEST,
                    "a/../inputs/candidate.txt": OTHER_DIGEST,
                },
            }
        ]
    }
    _rewrite_manifested_file(
        root,
        "metadata/execution.json",
        json.dumps(execution).encode() + b"\n",
    )
    with pytest.raises(BundleError, match="input aliases"):
        verify_bundle(root)


def test_v2_blocked_build_metadata_rejects_input_aliases(tmp_path):
    """A blocked v2 bundle may not smuggle a v1 build record either."""
    manifest = _manifest("blocked")
    files = _blocked_files(manifest)
    files["build/vulnerable/metadata.json"] = (
        "build_metadata",
        json.dumps(
            {
                "version": "vulnerable",
                "staged_materials": {"inputs/normal.txt": DIGEST},
            }
        ).encode()
        + b"\n",
    )
    root = _write_v2_bundle(
        tmp_path, manifest, files, name="blocked-build-metadata-alias"
    )
    with pytest.raises(BundleError, match="input aliases"):
        verify_bundle(root)


def test_v2_blocked_build_metadata_rejects_arbitrary_path(tmp_path):
    """D39 applies to blocked bundles: build roles belong under build/<version>/."""
    manifest = _manifest("blocked")
    files = _blocked_files(manifest)
    files["evil/metadata.json"] = (
        "build_metadata",
        json.dumps(
            {
                "version": "vulnerable",
                "staged_materials": {"inputs/normal.txt": DIGEST},
            }
        ).encode()
        + b"\n",
    )
    root = _write_v2_bundle(
        tmp_path, manifest, files, name="blocked-arbitrary-build-path"
    )
    with pytest.raises(BundleError, match="fixed build path"):
        verify_bundle(root)


@pytest.mark.parametrize("bundle_kind", ["execution", "campaign"])
def test_v2_execution_and_campaign_reject_arbitrary_build_path(
    tmp_path, bundle_kind
):
    """D39 stays enforced after the build layout for non-blocked bundles."""
    files = _base_files(
        execution=bundle_kind == "execution",
        campaign=bundle_kind == "campaign",
    )
    files["evil/metadata.json"] = (
        "build_metadata",
        json.dumps(
            {"version": "vulnerable", "staged_materials": {}}
        ).encode()
        + b"\n",
    )
    root = _write_v2_bundle(
        tmp_path,
        _manifest(
            bundle_kind,
            verdict=None if bundle_kind == "campaign" else "INCONCLUSIVE",
            reason=None if bundle_kind == "campaign" else "EVIDENCE_INCOMPLETE",
        ),
        files,
        name=f"{bundle_kind}-arbitrary-build-path",
    )
    with pytest.raises(BundleError, match="fixed build path"):
        verify_bundle(root)


def test_v2_build_record_with_material_only_is_accepted(tmp_path):
    """D4 only rejects the two aliases, not ordinary build materials."""
    files = _base_files(execution=True, campaign=False)
    root = _write_v2_bundle(
        tmp_path,
        _manifest("execution"),
        files,
        name="v2-build-material-only",
    )
    metadata = {
        "version": "vulnerable",
        "staged_materials": {"harness.c": DIGEST, "vulnerable/parser.c": OTHER_DIGEST},
    }
    _rewrite_manifested_file(
        root,
        "build/vulnerable/metadata.json",
        json.dumps(metadata).encode() + b"\n",
    )
    assert verify_bundle(root).manifest["bundle_kind"] == "execution"


def test_v2_non_reuse_plan_and_report_must_not_claim_build_ref(tmp_path):
    """Fixed/non-reuse execution must keep both provenance pointers null."""
    manifest = _manifest("execution")
    files = _base_files(execution=True, campaign=False)
    files["plan.json"] = (
        "plan",
        json.dumps(
            {
                "schema_version": 2,
                "build_provenance_rules_version": "build-provenance-v1",
                "build_ref": _build_ref(),
            }
        ).encode()
        + b"\n",
    )
    plan_root = _write_v2_bundle(
        tmp_path, manifest, files, name="non-reuse-plan-build-ref"
    )
    with pytest.raises(BundleError, match="non-reuse plan"):
        verify_bundle(plan_root)

    report_files = _base_files(execution=True, campaign=False)
    report_files["report.json"] = (
        "report_json",
        json.dumps(
            {
                "schema_version": 2,
                "build_provenance_rules_version": "build-provenance-v1",
                "build_provenance": _report_build_provenance(),
                "build_ref": _build_ref(),
            }
        ).encode()
        + b"\n",
    )
    report_root = _write_v2_bundle(
        tmp_path, manifest, report_files, name="non-reuse-report-build-ref"
    )
    with pytest.raises(BundleError, match="non-reuse report"):
        verify_bundle(report_root)


@pytest.mark.parametrize("field", ["verdict", "reason_code", "state"])
def test_campaign_report_must_not_carry_verdict_fields(tmp_path, field):
    """Campaign evidence must not carry a reproduction conclusion."""
    manifest = _manifest("campaign", verdict=None, reason=None)
    files = _base_files(execution=False, campaign=True)
    report = {
        "schema_version": 2,
        "bundle_kind": "campaign",
        "build_provenance_rules_version": "build-provenance-v1",
        "build_provenance": _report_build_provenance(),
        field: "REPRODUCED",
    }
    files["report.json"] = (
        "report_json",
        json.dumps(report).encode() + b"\n",
    )
    root = _write_v2_bundle(
        tmp_path, manifest, files, name="campaign-report-" + field
    )
    with pytest.raises(BundleError, match=field):
        verify_bundle(root)


def test_v2_build_provenance_faces_are_fixed(tmp_path):
    """D39 allows only the three reviewed provenance face names (one per version)."""
    for face_name, payload in (
        ("compile_commands.json", b"[]\n"),
        ("cc-shim.log", b"cc-shim\n"),
        ("shell-face.log", b"shell-face\n"),
    ):
        allowed = _base_files(execution=True, campaign=False)
        allowed["report.json"] = (
            "report_json",
            json.dumps(
                {
                    "report": True,
                    "build_provenance_rules_version": "build-provenance-v1",
                    "build_provenance": _report_build_provenance(face=face_name),
                },
                sort_keys=True,
            ).encode("utf-8")
            + b"\n",
        )
        for version in ("vulnerable", "fixed"):
            allowed.pop(f"build/{version}/build_provenance/compile_commands.json")
            allowed[f"build/{version}/build_provenance/{face_name}"] = (
                "build_provenance",
                payload,
            )
        root = _write_v2_bundle(
            tmp_path,
            _manifest("execution"),
            allowed,
            name="provenance-face-" + face_name.replace(".", "-"),
        )
        assert verify_bundle(root).manifest["bundle_kind"] == "execution"

    for bad_face in ("evil.txt", "nested/compile_commands.json"):
        files = _base_files(execution=True, campaign=False)
        files[f"build/vulnerable/build_provenance/{bad_face}"] = (
            "build_provenance",
            b"[]\n",
        )
        bad_root = _write_v2_bundle(
            tmp_path,
            _manifest("execution"),
            files,
            name="bad-provenance-" + bad_face.replace("/", "-"),
        )
        with pytest.raises(BundleError, match="fixed face path"):
            verify_bundle(bad_root)


@pytest.mark.parametrize("bundle_kind", ["execution", "campaign", "blocked"])
def test_v2_manifest_rejects_unknown_top_level_key(tmp_path, bundle_kind):
    if bundle_kind == "campaign":
        manifest = _manifest("campaign", verdict=None, reason=None)
        files = _base_files(execution=False, campaign=True)
    elif bundle_kind == "execution":
        manifest = _manifest("execution")
        files = _base_files(execution=True, campaign=False)
    else:
        manifest = _manifest("blocked")
        files = _blocked_files(manifest)
    manifest["unexpected_top_level_key"] = "smuggled"
    root = _write_v2_bundle(
        tmp_path, manifest, files, name=f"unknown-key-{bundle_kind}"
    )
    with pytest.raises(BundleError, match="unknown") as raised:
        verify_bundle(root)
    assert raised.value.reason_code == "INVALID_MANIFEST"


def test_write_bundle_v2_blocked_enforces_schema_version_and_plan_artifacts(tmp_path):
    job_id = str(uuid4())
    markdown = (
        "# DataCon evidence report\n\n"
        "- Verdict: **BLOCKED**\n"
        "- Reason: `ADMISSION_DENIED`\n"
    )
    base_report = {
        "schema_version": 1,
        "bundle_kind": "blocked",
        "job_id": job_id,
        "plan_digest": None,
        "state": "BLOCKED",
        "verdict": "BLOCKED",
        "reason_code": "ADMISSION_DENIED",
        "review": None,
        "missing": ["execution did not complete"],
        "error": "ADMISSION_DENIED: denied",
        "evidence_complete": False,
        "created_at": "2099-01-01T00:00:00Z",
    }

    with pytest.raises(BundleError, match="schema_version") as raised:
        evidence.write_bundle(
            tmp_path / "v2-blocked-v1-report",
            job_id=job_id,
            plan_digest=None,
            bundle_kind="blocked",
            report=base_report,
            report_markdown=markdown,
            verdict="BLOCKED",
            schema_version=2,
        )
    assert raised.value.reason_code == "INVALID_MANIFEST"

    v2_report = dict(base_report, schema_version=2)
    info = evidence.write_bundle(
        tmp_path / "v2-blocked-ok",
        job_id=job_id,
        plan_digest=None,
        bundle_kind="blocked",
        report=v2_report,
        report_markdown=markdown,
        verdict="BLOCKED",
        verify=verify_bundle,
        schema_version=2,
    )
    verified = verify_bundle(info.root)
    assert verified.manifest["schema_version"] == 2
    assert json.loads(verified.file_data["report.json"])["schema_version"] == 2

    with_plan_digest = dict(v2_report, plan_digest=DIGEST)
    with pytest.raises(BundleError, match="plan.json") as raised:
        evidence.write_bundle(
            tmp_path / "v2-blocked-missing-plan",
            job_id=job_id,
            plan_digest=DIGEST,
            bundle_kind="blocked",
            report=with_plan_digest,
            report_markdown=markdown,
            verdict="BLOCKED",
            schema_version=2,
        )
    assert raised.value.reason_code == "INVALID_MANIFEST"


def test_archive_blocked_v2_emits_schema_version_2_and_verifies(
    tmp_path, monkeypatch
):
    from datacon import execution

    evidence_root = tmp_path / "evidence"
    monkeypatch.setenv("DATACON_EVIDENCE_ROOT", str(evidence_root))
    job = {
        "job_id": str(uuid4()),
        "job_contract_version": 2,
        "request": {
            "schema_version": 2,
            "cve_id": "CVE-2099-0001",
            "target": {
                "kind": "source",
                "case_id": "fixture-c-parser",
                "goal": "v2 blocked archive test",
            },
            "limits": {
                "cpu": 1,
                "memory_mib": 512,
                "pids": 64,
                "scratch_mib": 256,
                "prepare_seconds": 60,
                "execute_seconds": 120,
            },
        },
    }
    digest, path, error = execution.archive_blocked(
        job,
        generation=1,
        reason_code="ENVELOPE_VIOLATION",
        message="envelope exceeded",
    )
    assert error is None, error
    assert digest is not None and path is not None
    verified = verify_bundle(path)
    assert verified.manifest["schema_version"] == 2
    assert verified.manifest["bundle_kind"] == "blocked"
    report = json.loads(verified.file_data["report.json"])
    assert report["schema_version"] == 2
    assert report["bundle_kind"] == "blocked"
    assert report["verdict"] == "BLOCKED"
    assert report["reason_code"] == "ENVELOPE_VIOLATION"


@pytest.mark.parametrize(
    "case_name,overrides,markdown_override,expected_reason",
    [
        (
            "verdict-mismatch",
            {"verdict": "REPRODUCED", "state": "REPRODUCED"},
            None,
            "INVALID_MANIFEST",
        ),
        (
            "reason-mismatch",
            {"reason_code": "POLICY_DENIED"},
            None,
            "INVALID_MANIFEST",
        ),
        (
            "plan-digest-mismatch",
            {"plan_digest": DIGEST},
            None,
            "INVALID_MANIFEST",
        ),
        (
            "report-schema-1",
            {"schema_version": 1},
            None,
            "INVALID_MANIFEST",
        ),
        (
            "review-without-plan",
            {"review": {"decision": "reject"}},
            None,
            "INVALID_MANIFEST",
        ),
        (
            "tampered-markdown-digest",
            {"report_markdown_sha256": "0" * 64},
            None,
            "DIGEST_MISMATCH",
        ),
        (
            "tampered-markdown-verdict",
            None,
            "# DataCon evidence report\n\n- Verdict: **REPRODUCED**\n- Reason: `REVIEW_REJECTED`\n",
            "INVALID_MANIFEST",
        ),
    ],
)
def test_v2_blocked_verify_rejects_inconsistent_report_or_markdown(
    tmp_path, case_name, overrides, markdown_override, expected_reason
):
    manifest = _manifest("blocked")
    files = _blocked_files(
        manifest,
        report_overrides=overrides,
        markdown_override=markdown_override,
    )
    root = _write_v2_bundle(tmp_path, manifest, files, name=f"bad-blocked-{case_name}")
    with pytest.raises(BundleError) as raised:
        verify_bundle(root)
    assert raised.value.reason_code == expected_reason


def test_v2_blocked_verify_checks_plan_and_review_consistency(tmp_path):
    from test_evidence import PLAN, PLAN_DIGEST, REVIEW

    manifest = _manifest("blocked")
    manifest["plan_digest"] = PLAN_DIGEST
    review = dict(REVIEW, decision="reject")
    plan_bytes = json.dumps(PLAN).encode("utf-8") + b"\n"
    review_bytes = json.dumps(review).encode("utf-8") + b"\n"

    valid_files = _blocked_files(
        manifest,
        report_overrides={
            "case_id": PLAN["case_id"],
            "cve_id": PLAN["cve_id"],
            "review": {
                "reviewer_id": review["reviewer_id"],
                "decision": review["decision"],
                "plan_digest": review["plan_digest"],
                "decided_at": review["decided_at"],
            },
        },
        extra_files={
            "plan.json": ("plan", plan_bytes),
            "review.json": ("review", review_bytes),
        },
    )
    ok_root = _write_v2_bundle(tmp_path, manifest, valid_files, name="blocked-plan-ok")
    assert verify_bundle(ok_root).manifest["plan_digest"] == PLAN_DIGEST

    mismatched_files = _blocked_files(
        manifest,
        report_overrides={
            "case_id": "other-case",
            "cve_id": PLAN["cve_id"],
            "review": {
                "reviewer_id": review["reviewer_id"],
                "decision": review["decision"],
                "plan_digest": review["plan_digest"],
                "decided_at": review["decided_at"],
            },
        },
        extra_files={
            "plan.json": ("plan", plan_bytes),
            "review.json": ("review", review_bytes),
        },
    )
    bad_root = _write_v2_bundle(
        tmp_path, manifest, mismatched_files, name="blocked-plan-case-mismatch"
    )
    with pytest.raises(BundleError, match="case_id") as raised:
        verify_bundle(bad_root)
    assert raised.value.reason_code == "INVALID_MANIFEST"


# ---------------------------------------------------------------------------
# S-1: the verify side must enforce the blocked plan/review binding itself,
# not only the writer. Each case below would pass verification if
# ``_verify_v2_blocked_semantics`` stopped calling ``_validate_blocked_artifacts``.
# ---------------------------------------------------------------------------


def _review_binding(review):
    return {
        "reviewer_id": review["reviewer_id"],
        "decision": review["decision"],
        "plan_digest": review["plan_digest"],
        "decided_at": review["decided_at"],
    }


def _blocked_plan_review_files(
    manifest, *, plan_doc, review_doc, report_review, include_plan=True
):
    extra_files = {
        "review.json": (
            "review",
            json.dumps(review_doc).encode("utf-8") + b"\n",
        )
    }
    if include_plan:
        extra_files["plan.json"] = (
            "plan",
            json.dumps(plan_doc).encode("utf-8") + b"\n",
        )
    return _blocked_files(
        manifest,
        report_overrides={
            "case_id": plan_doc.get("case_id"),
            "cve_id": plan_doc.get("cve_id"),
            "review": report_review,
        },
        extra_files=extra_files,
    )


def _blocked_plan_review_manifest():
    from test_evidence import PLAN_DIGEST

    manifest = _manifest("blocked")
    manifest["plan_digest"] = PLAN_DIGEST
    return manifest


def test_v2_blocked_verify_rejects_plan_content_not_matching_digest(tmp_path):
    from test_evidence import PLAN, REVIEW

    manifest = _blocked_plan_review_manifest()
    # Same case_id/cve_id, different body: only a recomputation of the plan
    # digest can catch this.
    tampered_plan = dict(PLAN, policy_version="policy-v2")
    review = dict(REVIEW, decision="reject")
    files = _blocked_plan_review_files(
        manifest,
        plan_doc=tampered_plan,
        review_doc=review,
        report_review=_review_binding(review),
    )
    root = _write_v2_bundle(
        tmp_path, manifest, files, name="blocked-plan-digest-mismatch"
    )
    with pytest.raises(BundleError) as raised:
        verify_bundle(root)
    assert raised.value.reason_code == "INVALID_MANIFEST"
    assert "plan_digest" in raised.value.message


def test_v2_blocked_verify_rejects_a_plan_digest_without_plan_json(tmp_path):
    from test_evidence import PLAN, REVIEW

    manifest = _blocked_plan_review_manifest()
    review = dict(REVIEW, decision="reject")
    files = _blocked_plan_review_files(
        manifest,
        plan_doc=PLAN,
        review_doc=review,
        report_review=_review_binding(review),
        include_plan=False,
    )
    root = _write_v2_bundle(
        tmp_path, manifest, files, name="blocked-plan-missing"
    )
    with pytest.raises(BundleError) as raised:
        verify_bundle(root)
    assert raised.value.reason_code == "INVALID_MANIFEST"
    assert "must ship plan.json" in raised.value.message


def test_v2_blocked_verify_rejects_review_bound_to_a_different_plan(tmp_path):
    from test_evidence import PLAN, REVIEW

    manifest = _blocked_plan_review_manifest()
    review = dict(REVIEW, decision="reject", plan_digest=OTHER_DIGEST)
    files = _blocked_plan_review_files(
        manifest,
        plan_doc=PLAN,
        review_doc=review,
        report_review=_review_binding(review),
    )
    root = _write_v2_bundle(
        tmp_path, manifest, files, name="blocked-review-plan-mismatch"
    )
    with pytest.raises(BundleError) as raised:
        verify_bundle(root)
    assert raised.value.reason_code == "INVALID_MANIFEST"
    assert "different plan" in raised.value.message


def test_v2_blocked_verify_rejects_report_review_not_matching_review_json(tmp_path):
    from test_evidence import PLAN, REVIEW

    manifest = _blocked_plan_review_manifest()
    review = dict(REVIEW, decision="reject")
    report_review = _review_binding(review)
    report_review["reviewer_id"] = "reviewer-other"
    files = _blocked_plan_review_files(
        manifest,
        plan_doc=PLAN,
        review_doc=review,
        report_review=report_review,
    )
    root = _write_v2_bundle(
        tmp_path, manifest, files, name="blocked-report-review-mismatch"
    )
    with pytest.raises(BundleError) as raised:
        verify_bundle(root)
    assert raised.value.reason_code == "INVALID_MANIFEST"
    assert "report review" in raised.value.message


def test_v2_blocked_verify_rejects_an_unknown_review_decision(tmp_path):
    from test_evidence import PLAN, REVIEW

    manifest = _blocked_plan_review_manifest()
    review = dict(REVIEW, decision="maybe")
    files = _blocked_plan_review_files(
        manifest,
        plan_doc=PLAN,
        review_doc=review,
        report_review=_review_binding(review),
    )
    root = _write_v2_bundle(
        tmp_path, manifest, files, name="blocked-review-decision"
    )
    with pytest.raises(BundleError) as raised:
        verify_bundle(root)
    assert raised.value.reason_code == "INVALID_MANIFEST"
    assert "approve or reject" in raised.value.message


def _partial_execution_files():
    """A FAILED execution bundle with only the produced vulnerable build."""
    files = _base_files(execution=True, campaign=False)
    for version in VERSIONS:
        for phase in PHASES:
            base = f"replay/{version}/{phase}/"
            for suffix in ("stdout.log", "stderr.log", "metadata.json"):
                files.pop(base + suffix, None)
    for relative in list(files):
        if relative.startswith("build/fixed/"):
            del files[relative]
    files["report.json"] = (
        "report_json",
        json.dumps(
            {
                "rule": None,
                "build_provenance_rules_version": "build-provenance-v1",
                "build_provenance": _report_build_provenance(comparable=False),
            },
            sort_keys=True,
        ).encode("utf-8")
        + b"\n",
    )
    files.pop("metadata/probe.json", None)
    return files


def test_verify_v2_failed_partial_bundle_accepts_produced_roles(tmp_path):
    """T13a: FAILED bundles require only the evidence that was produced."""
    root = _write_v2_bundle(
        tmp_path,
        _manifest("execution", verdict="FAILED", reason="BUILD_PROVENANCE_MISSING"),
        _partial_execution_files(),
        name="failed-partial",
    )
    verified = verify_bundle(root)
    assert verified.manifest["verdict"] == "FAILED"
    assert "build/vulnerable/build.log" in verified.file_data
    assert "build/fixed/build.log" not in verified.file_data
    assert not any(path.startswith("replay/") for path in verified.file_data)


def test_verify_v2_partial_inconclusive_without_rule_is_accepted(tmp_path):
    """T13a: INCONCLUSIVE + report.rule=None uses the partial layout."""
    files = _partial_execution_files()
    files["report.json"] = (
        "report_json",
        json.dumps(
            {
                "rule": None,
                "build_provenance_rules_version": "build-provenance-v1",
                "build_provenance": _report_build_provenance(comparable=False),
            },
            sort_keys=True,
        ).encode("utf-8")
        + b"\n",
    )
    root = _write_v2_bundle(
        tmp_path,
        _manifest("execution", verdict="INCONCLUSIVE", reason="EVIDENCE_INCOMPLETE"),
        files,
        name="inconclusive-partial",
    )
    verify_bundle(root)


def test_verify_v2_complete_inconclusive_still_requires_full_roles(tmp_path):
    """T13a: a rule-backed INCONCLUSIVE bundle keeps the strict role table."""
    files = _partial_execution_files()
    files["report.json"] = (
        "report_json",
        b'{"rule":{"verdict":"INCONCLUSIVE"},"build_provenance_rules_version":"build-provenance-v1"}\n',
    )
    root = _write_v2_bundle(
        tmp_path,
        _manifest("execution", verdict="INCONCLUSIVE", reason="EVIDENCE_INCOMPLETE"),
        files,
        name="inconclusive-complete",
    )
    with pytest.raises(BundleError, match="missing required roles"):
        verify_bundle(root)


def test_verify_v2_partial_bundle_rejects_misplaced_or_wrong_role_replay(tmp_path):
    """T13a: present replay bytes must still use the fixed path and role."""
    files = _partial_execution_files()
    files["replay/vulnerable/normal/stdout.log"] = ("asan_log", b"fake\n")
    root = _write_v2_bundle(
        tmp_path,
        _manifest("execution", verdict="FAILED", reason="BUILD_PROVENANCE_MISSING"),
        files,
        name="bad-replay-role",
    )
    with pytest.raises(BundleError, match="must carry the normal_output role"):
        verify_bundle(root)

    files = _partial_execution_files()
    files["fake/replay/stdout.log"] = ("normal_output", b"fake\n")
    root = _write_v2_bundle(
        tmp_path,
        _manifest("execution", verdict="FAILED", reason="BUILD_PROVENANCE_MISSING"),
        files,
        name="bad-replay-path",
    )
    with pytest.raises(BundleError, match="not at a fixed replay path"):
        verify_bundle(root)


def test_verify_v2_partial_bundle_rejects_wrong_build_role(tmp_path):
    """T13a: a produced build path cannot borrow an unrelated role."""
    files = _partial_execution_files()
    files["build/vulnerable/parser"] = ("build_log", b"fake\n")
    root = _write_v2_bundle(
        tmp_path,
        _manifest("execution", verdict="FAILED", reason="BUILD_PROVENANCE_MISSING"),
        files,
        name="bad-build-role",
    )
    with pytest.raises(BundleError, match="must carry the build_artifact role"):
        verify_bundle(root)


def test_verify_v2_partial_bundle_still_requires_envelope_and_budget(tmp_path):
    """T13a must not weaken the fixed documents required for interpretation."""
    for relative in ("envelope.json", "budget/snapshot.json"):
        files = _partial_execution_files()
        del files[relative]
        root = _write_v2_bundle(
            tmp_path,
            _manifest(
                "execution", verdict="FAILED", reason="BUILD_PROVENANCE_MISSING"
            ),
            files,
            name="partial-missing-" + relative.replace("/", "-"),
        )
        with pytest.raises(BundleError, match="missing required roles"):
            verify_bundle(root)


def test_family_export_keeps_each_round_independently_verifiable(tmp_path):
    """T12/TC-16: family export copies round bundles without rewriting them."""
    campaign_root = _write_v2_bundle(
        tmp_path,
        _manifest("campaign", verdict=None, reason=None),
        _base_files(execution=False, campaign=True),
        name="family-campaign",
    )
    round_roots = [
        _write_v2_bundle(
            tmp_path,
            _manifest("execution"),
            _base_files(execution=True, campaign=False),
            name=f"family-round-{round_no}",
        )
        for round_no in (1, 2)
    ]
    digests = [verify_bundle(root).manifest_digest for root in round_roots]
    campaign_digest = verify_bundle(campaign_root).manifest_digest
    index = evidence.build_family_index(
        family_id=str(uuid4()),
        created_at="2099-01-01T00:00:00Z",
        family_approval_digest="sha256:" + "52" * 32,
        rounds=[
            {
                "round_no": round_no,
                "job_id": str(uuid4()),
                "plan_digest": DIGEST,
                "state": "INCONCLUSIVE",
                "evidence_digest": digest,
            }
            for round_no, digest in zip((1, 2), digests)
        ],
        campaign={"job_id": str(uuid4()), "bundle_digest": campaign_digest},
        budget={
            "max_total_seconds": 900,
            "max_fuzz_seconds": 300,
            "spent_seconds": 540,
            "spent_fuzz_seconds": 180,
            "remaining_seconds": 360,
            "remaining_fuzz_seconds": 120,
        },
    )
    family_json = tmp_path / "family-archive" / "family.json"
    evidence.finalize_family_index(family_json, index)

    evidence.export_family(
        family_json,
        tmp_path / "family-export",
        campaign_source=campaign_root,
        rounds=list(zip((1, 2), round_roots)),
    )

    for round_no, source, digest in zip((1, 2), round_roots, digests):
        exported = tmp_path / "family-export" / "rounds" / str(round_no)
        assert verify_bundle(exported).manifest_digest == digest
        assert (exported / "manifest.json").read_bytes() == (
            source / "manifest.json"
        ).read_bytes(), "family export rewrote a round manifest"


def test_nb2_hollow_shell_inconclusive_bundle_rejected(tmp_path):
    """NB2: 0-probe/0-build/0-replay hollow INCONCLUSIVE shells are rejected."""
    base_hollow = {
        path: item
        for path, item in _partial_execution_files().items()
        if not path.startswith("build/")
    }

    # Case 1: omits the "rule" key altogether.
    omitted_rule = dict(base_hollow)
    omitted_rule["report.json"] = (
        "report_json",
        b'{"build_provenance_rules_version":"build-provenance-v1"}\n',
    )
    root_omitted = _write_v2_bundle(
        tmp_path,
        _manifest("execution", verdict="INCONCLUSIVE", reason="EVIDENCE_INCOMPLETE"),
        omitted_rule,
        name="hollow-omitted-rule",
    )
    with pytest.raises(BundleError, match="missing required roles"):
        verify_bundle(root_omitted)

    # Case 2: explicit "rule": null but 0 probe/build/replay and no missing/error diagnostics.
    empty_shell = dict(base_hollow)
    empty_shell["report.json"] = (
        "report_json",
        b'{"rule":null,"build_provenance_rules_version":"build-provenance-v1"}\n',
    )
    root_empty = _write_v2_bundle(
        tmp_path,
        _manifest("execution", verdict="INCONCLUSIVE", reason="TIMEOUT"),
        empty_shell,
        name="hollow-empty-shell",
    )
    with pytest.raises(BundleError, match="missing required roles"):
        verify_bundle(root_empty)

    # Case 3: explicit "rule": null with a 6-replay verdict reason (INTERMITTENT).
    bad_reason = _partial_execution_files()
    bad_reason["report.json"] = (
        "report_json",
        b'{"rule":null,"missing":["x"],"build_provenance_rules_version":"build-provenance-v1"}\n',
    )
    root_bad_reason = _write_v2_bundle(
        tmp_path,
        _manifest("execution", verdict="INCONCLUSIVE", reason="INTERMITTENT"),
        bad_reason,
        name="partial-bad-reason",
    )
    with pytest.raises(BundleError, match="missing required roles"):
        verify_bundle(root_bad_reason)

    # Case 4: partial bundle with invalid build_provenance filename is rejected.
    bad_face = _partial_execution_files()
    bad_face["build/vulnerable/build_provenance/arbitrary.txt"] = (
        "build_provenance",
        b"bogus\n",
    )
    root_bad_face = _write_v2_bundle(
        tmp_path,
        _manifest("execution", verdict="FAILED", reason="BUILD_PROVENANCE_MISSING"),
        bad_face,
        name="partial-bad-face-name",
    )
    with pytest.raises(BundleError, match="fixed face path"):
        verify_bundle(root_bad_face)


def test_campaign_bundle_with_candidate_seeds_requires_crash_seed_role(tmp_path):
    """T13: campaign recording candidate crash seeds without crash_seed role fails closed."""
    files = _base_files(execution=False, campaign=True)
    files["report.json"] = (
        "report_json",
        json.dumps(
            {
                "schema_version": 2,
                "bundle_kind": "campaign",
                "build_provenance_rules_version": "build-provenance-v1",
                "build_provenance": _report_build_provenance(),
                "candidate_seeds": [DIGEST],
            }
        ).encode("utf-8")
        + b"\n",
    )
    missing_seed_root = _write_v2_bundle(
        tmp_path,
        _manifest("campaign", verdict=None, reason=None),
        files,
        name="campaign-missing-crash-seed",
    )
    with pytest.raises(BundleError, match="crash_seed"):
        verify_bundle(missing_seed_root)

    files["fuzz/crashes/seed-001.bin"] = ("crash_seed", b"CRASH\n")
    ok_seed_root = _write_v2_bundle(
        tmp_path,
        _manifest("campaign", verdict=None, reason=None),
        files,
        name="campaign-with-crash-seed",
    )
    verified = verify_bundle(ok_seed_root)
    assert "crash_seed" in {entry["role"] for entry in verified.manifest["files"]}


@pytest.mark.parametrize("bundle_kind", ["execution", "campaign"])
def test_v2_build_layout_rejects_multiple_provenance_faces_per_version(
    tmp_path, bundle_kind
):
    """§8 requires exactly one build_provenance face per version (and at most one in partial)."""
    files = _base_files(
        execution=bundle_kind == "execution",
        campaign=bundle_kind == "campaign",
    )
    files["build/vulnerable/build_provenance/cc-shim.log"] = (
        "build_provenance",
        b'{"argv":["clang","-c","a.c"]}\n',
    )
    root = _write_v2_bundle(
        tmp_path,
        _manifest(
            bundle_kind,
            verdict=None if bundle_kind == "campaign" else "INCONCLUSIVE",
            reason=None if bundle_kind == "campaign" else "EVIDENCE_INCOMPLETE",
        ),
        files,
        name=f"{bundle_kind}-two-faces-one-version",
    )
    with pytest.raises(BundleError, match="exactly one build_provenance face"):
        verify_bundle(root)

    if bundle_kind == "execution":
        partial = _partial_execution_files()
        partial["build/vulnerable/build_provenance/compile_commands.json"] = (
            "build_provenance",
            b"[]\n",
        )
        partial["build/vulnerable/build_provenance/cc-shim.log"] = (
            "build_provenance",
            b'{"argv":["clang","-c","a.c"]}\n',
        )
        partial_root = _write_v2_bundle(
            tmp_path,
            _manifest(
                "execution", verdict="FAILED", reason="BUILD_PROVENANCE_MISSING"
            ),
            partial,
            name="partial-two-faces-one-version",
        )
        with pytest.raises(BundleError, match="at most one build_provenance face"):
            verify_bundle(partial_root)


def test_campaign_crash_seed_enforcement_covers_int_crashes_alt_paths_and_corrupt_json(
    tmp_path,
):
    """PR #62 B-1: int crashes, invalid types, non-default fuzz_provenance paths, and corrupt JSON."""
    # 1. Integer "crashes": 2 in fuzz/provenance.json or report.json requires crash_seed.
    for target in ("fuzz/provenance.json", "report.json"):
        files = _base_files(execution=False, campaign=True)
        payload = (
            {
                "schema_version": 2,
                "bundle_kind": "campaign",
                "build_provenance_rules_version": "build-provenance-v1",
                "build_provenance": _report_build_provenance(),
                "crashes": 2,
            }
            if target == "report.json"
            else {"crashes": 2}
        )
        role = "report_json" if target == "report.json" else "fuzz_provenance"
        files[target] = (role, json.dumps(payload).encode("utf-8") + b"\n")
        root = _write_v2_bundle(
            tmp_path,
            _manifest("campaign", verdict=None, reason=None),
            files,
            name="campaign-int-crashes-" + target.replace("/", "-"),
        )
        with pytest.raises(BundleError, match="crash_seed"):
            verify_bundle(root)

    # 2. Negative integer / invalid types fail closed as INVALID_MANIFEST.
    for label, bad_doc in (
        ("neg-crashes", {"crashes": -1}),
        ("bool-crashes", {"crashes": True}),
        ("str-crashes", {"crashes": "2"}),
        ("neg-crash-count", {"crash_count": -1}),
        ("bad-candidate-seeds", {"candidate_seeds": "not-a-list"}),
    ):
        files = _base_files(execution=False, campaign=True)
        files["fuzz/provenance.json"] = (
            "fuzz_provenance",
            json.dumps(bad_doc).encode("utf-8") + b"\n",
        )
        root = _write_v2_bundle(
            tmp_path,
            _manifest("campaign", verdict=None, reason=None),
            files,
            name=f"campaign-invalid-{label}",
        )
        with pytest.raises(BundleError) as raised:
            verify_bundle(root)
        assert raised.value.reason_code == "INVALID_MANIFEST", label

    # 3. fuzz_provenance at a non-default path is still inspected.
    alt_files = _base_files(execution=False, campaign=True)
    del alt_files["fuzz/provenance.json"]
    alt_files["fuzz/campaign_provenance.json"] = (
        "fuzz_provenance",
        b'{"crashes": 1}\n',
    )
    alt_root = _write_v2_bundle(
        tmp_path,
        _manifest("campaign", verdict=None, reason=None),
        alt_files,
        name="campaign-alt-fuzz-provenance",
    )
    with pytest.raises(BundleError, match="crash_seed"):
        verify_bundle(alt_root)

    # 4. Corrupt JSON in fuzz_provenance is never skipped even when report already lists seeds.
    corrupt_files = _base_files(execution=False, campaign=True)
    corrupt_files["report.json"] = (
        "report_json",
        json.dumps(
            {
                "schema_version": 2,
                "bundle_kind": "campaign",
                "build_provenance_rules_version": "build-provenance-v1",
                "build_provenance": _report_build_provenance(),
                "candidate_seeds": [DIGEST],
            }
        ).encode("utf-8")
        + b"\n",
    )
    corrupt_files["fuzz/crashes/seed-001.bin"] = ("crash_seed", b"CRASH\n")
    corrupt_files["fuzz/provenance.json"] = ("fuzz_provenance", b"{corrupt json")
    corrupt_root = _write_v2_bundle(
        tmp_path,
        _manifest("campaign", verdict=None, reason=None),
        corrupt_files,
        name="campaign-corrupt-fuzz-provenance",
    )
    with pytest.raises(BundleError):
        verify_bundle(corrupt_root)


def test_nb2_hollow_shell_and_campaign_reject_non_build_or_replay_roles_under_reserved_dirs(
    tmp_path,
):
    """PR #62 B-2: non-build/non-replay roles under build/ or replay/ cannot spoof runtime evidence."""
    base_hollow = {
        path: item
        for path, item in _partial_execution_files().items()
        if not path.startswith("build/")
    }
    base_hollow["report.json"] = (
        "report_json",
        b'{"rule":null,"build_provenance_rules_version":"build-provenance-v1"}\n',
    )

    for label, spoof_path, spoof_role in (
        ("build-dummy-symbolizer", "build/dummy.txt", "symbolizer_log"),
        ("replay-dummy-symbolizer", "replay/dummy.txt", "symbolizer_log"),
        (
            "replay-fixed-path-wrong-role",
            "replay/vulnerable/normal/stdout.log",
            "symbolizer_log",
        ),
        ("probe-wrong-role", "metadata/probe.json", "symbolizer_log"),
    ):
        files = dict(base_hollow)
        files[spoof_path] = (spoof_role, b"spoof\n")
        root = _write_v2_bundle(
            tmp_path,
            _manifest("execution", verdict="INCONCLUSIVE", reason="TIMEOUT"),
            files,
            name=f"nb2-spoof-{label}",
        )
        with pytest.raises(BundleError) as raised:
            verify_bundle(root)
        assert raised.value.reason_code == "INVALID_MANIFEST", label

    # Campaign carrying a non-replay role under replay/ is also rejected.
    camp_files = _base_files(execution=False, campaign=True)
    camp_files["replay/dummy.txt"] = ("symbolizer_log", b"spoof\n")
    camp_root = _write_v2_bundle(
        tmp_path,
        _manifest("campaign", verdict=None, reason=None),
        camp_files,
        name="campaign-spoof-replay-dir",
    )
    with pytest.raises(BundleError, match="replay"):
        verify_bundle(camp_root)


def test_v2_defensive_face_consistency_blocked_cap_and_partial_report_contradictions(
    tmp_path,
):
    """PR #62 non-blocking hardening: face consistency, build_spec.kind match, blocked cap, report checks."""
    # 1. Cross-version mismatched face names (compile_commands.json vs cc-shim.log) rejected.
    mismatch_files = _base_files(execution=True, campaign=False)
    del mismatch_files["build/fixed/build_provenance/compile_commands.json"]
    mismatch_files["build/fixed/build_provenance/cc-shim.log"] = (
        "build_provenance",
        b'{"argv":["clang","-c","a.c"]}\n',
    )
    mismatch_root = _write_v2_bundle(
        tmp_path,
        _manifest("execution"),
        mismatch_files,
        name="cross-version-face-mismatch",
    )
    with pytest.raises(BundleError, match="face filenames must match"):
        verify_bundle(mismatch_root)

    # 2. Face filename must match plan.build_spec.kind when build_spec.kind is present.
    kind_files = _base_files(execution=True, campaign=False)
    kind_files["plan.json"] = (
        "plan",
        json.dumps(
            {
                "schema_version": 2,
                "build_provenance_rules_version": "build-provenance-v1",
                "build_spec": {"kind": "make"},
            }
        ).encode("utf-8")
        + b"\n",
    )
    kind_root = _write_v2_bundle(
        tmp_path,
        _manifest("execution"),
        kind_files,
        name="face-kind-mismatch",
    )
    with pytest.raises(BundleError, match="build_spec.kind"):
        verify_bundle(kind_root)

    # 3. Blocked bundle carrying 2 build_provenance faces in one version is rejected.
    blocked_manifest = _manifest("blocked")
    blocked_files = _blocked_files(blocked_manifest)
    blocked_files["build/vulnerable/build_provenance/compile_commands.json"] = (
        "build_provenance",
        b"[]\n",
    )
    blocked_files["build/vulnerable/build_provenance/cc-shim.log"] = (
        "build_provenance",
        b'{"argv":["clang","-c","a.c"]}\n',
    )
    blocked_root = _write_v2_bundle(
        tmp_path,
        blocked_manifest,
        blocked_files,
        name="blocked-two-faces",
    )
    with pytest.raises(BundleError, match="at most one build_provenance face"):
        verify_bundle(blocked_root)

    # 4. Contradictory report.verdict or evidence_complete=True on partial bundle rejected.
    for label, report_doc in (
        (
            "verdict-contradiction",
            {
                "verdict": "REPRODUCED",
                "rule": None,
                "missing": ["build:fixed"],
                "build_provenance_rules_version": "build-provenance-v1",
            },
        ),
        (
            "evidence-complete-true",
            {
                "verdict": "INCONCLUSIVE",
                "rule": None,
                "missing": ["build:fixed"],
                "evidence_complete": True,
                "build_provenance_rules_version": "build-provenance-v1",
            },
        ),
    ):
        partial_files = _partial_execution_files()
        partial_files["report.json"] = (
            "report_json",
            json.dumps(report_doc).encode("utf-8") + b"\n",
        )
        root = _write_v2_bundle(
            tmp_path,
            _manifest("execution", verdict="INCONCLUSIVE", reason="TIMEOUT"),
            partial_files,
            name=f"partial-contradiction-{label}",
        )
        with pytest.raises(BundleError, match="missing required roles|does not match manifest|rule must be null"):
            verify_bundle(root)


def test_b1_partial_failed_enforces_state_reason_rule_and_non_hollow_evidence(
    tmp_path,
):
    """JayNey B-1: FAILED and INCONCLUSIVE share full partial guard against hollow/contradictory shells."""
    base_hollow = {
        path: item
        for path, item in _partial_execution_files().items()
        if not path.startswith("build/")
    }

    # 1. FAILED hollow shell (0 probe/build/replay + no missing/error) is rejected.
    hollow_failed = dict(base_hollow)
    hollow_failed["report.json"] = (
        "report_json",
        json.dumps(
            {
                "verdict": "FAILED",
                "state": "FAILED",
                "reason_code": "BUILD_PROVENANCE_MISSING",
                "rule": None,
                "build_provenance_rules_version": "build-provenance-v1",
                "build_provenance": _report_build_provenance(comparable=False),
            }
        ).encode("utf-8")
        + b"\n",
    )
    root_hollow = _write_v2_bundle(
        tmp_path,
        _manifest("execution", verdict="FAILED", reason="BUILD_PROVENANCE_MISSING"),
        hollow_failed,
        name="b1-failed-hollow-shell",
    )
    with pytest.raises(BundleError, match="missing required roles"):
        verify_bundle(root_hollow)

    # 2. FAILED with omitted rule, non-null rule, state mismatch, reason mismatch, or null/invalid reason rejected.
    for label, manifest_reason, report_doc in (
        (
            "failed-omitted-rule",
            "BUILD_PROVENANCE_MISSING",
            {
                "verdict": "FAILED",
                "state": "FAILED",
                "reason_code": "BUILD_PROVENANCE_MISSING",
                "error": "boom",
                "build_provenance_rules_version": "build-provenance-v1",
                "build_provenance": _report_build_provenance(comparable=False),
            },
        ),
        (
            "failed-non-null-rule",
            "BUILD_PROVENANCE_MISSING",
            {
                "verdict": "FAILED",
                "state": "FAILED",
                "reason_code": "BUILD_PROVENANCE_MISSING",
                "rule": {"verdict": "FAILED"},
                "error": "boom",
                "build_provenance_rules_version": "build-provenance-v1",
                "build_provenance": _report_build_provenance(comparable=False),
            },
        ),
        (
            "failed-state-mismatch",
            "BUILD_PROVENANCE_MISSING",
            {
                "verdict": "FAILED",
                "state": "REPRODUCED",
                "reason_code": "BUILD_PROVENANCE_MISSING",
                "rule": None,
                "error": "boom",
                "build_provenance_rules_version": "build-provenance-v1",
                "build_provenance": _report_build_provenance(comparable=False),
            },
        ),
        (
            "failed-reason-mismatch",
            "BUILD_PROVENANCE_MISSING",
            {
                "verdict": "FAILED",
                "state": "FAILED",
                "reason_code": "BUILD_FAILED",
                "rule": None,
                "error": "boom",
                "build_provenance_rules_version": "build-provenance-v1",
                "build_provenance": _report_build_provenance(comparable=False),
            },
        ),
        (
            "failed-null-reason",
            None,
            {
                "verdict": "FAILED",
                "state": "FAILED",
                "reason_code": None,
                "rule": None,
                "error": "boom",
                "build_provenance_rules_version": "build-provenance-v1",
                "build_provenance": _report_build_provenance(comparable=False),
            },
        ),
        (
            "inconclusive-state-mismatch",
            "TIMEOUT",
            {
                "verdict": "INCONCLUSIVE",
                "state": "REPRODUCED",
                "reason_code": "TIMEOUT",
                "rule": None,
                "error": "timed out",
                "build_provenance_rules_version": "build-provenance-v1",
                "build_provenance": _report_build_provenance(comparable=False),
            },
        ),
    ):
        verdict = "INCONCLUSIVE" if label.startswith("inconclusive") else "FAILED"
        files = _partial_execution_files()
        files["report.json"] = (
            "report_json",
            json.dumps(report_doc).encode("utf-8") + b"\n",
        )
        root = _write_v2_bundle(
            tmp_path,
            _manifest("execution", verdict=verdict, reason=manifest_reason),
            files,
            name=f"b1-{label}",
        )
        with pytest.raises(BundleError, match="missing required roles|does not match manifest|rule must be null"):
            verify_bundle(root)

    # 3. Legitimate pre-build FAILED bundle with non-empty error diagnostic verifies cleanly.
    valid_prebuild_failed = dict(base_hollow)
    valid_prebuild_failed["report.json"] = (
        "report_json",
        json.dumps(
            {
                "verdict": "FAILED",
                "state": "FAILED",
                "reason_code": "BUILD_PROVENANCE_MISSING",
                "rule": None,
                "error": "build_spec rejected before probe",
                "evidence_complete": False,
                "build_provenance_rules_version": "build-provenance-v1",
                "build_provenance": _report_build_provenance(comparable=False),
            }
        ).encode("utf-8")
        + b"\n",
    )
    ok_root = _write_v2_bundle(
        tmp_path,
        _manifest("execution", verdict="FAILED", reason="BUILD_PROVENANCE_MISSING"),
        valid_prebuild_failed,
        name="b1-valid-prebuild-failed",
    )
    assert verify_bundle(ok_root).manifest["verdict"] == "FAILED"


def test_b2_report_build_provenance_closed_schema_types_and_consistency(tmp_path):
    """JayNey B-2: report.json['build_provenance'] enforces closed 3-key schema, types and consistency."""
    # 1. Missing build_provenance rejected on both execution and campaign.
    for bundle_kind in ("execution", "campaign"):
        files = _base_files(
            execution=bundle_kind == "execution",
            campaign=bundle_kind == "campaign",
        )
        files["report.json"] = (
            "report_json",
            b'{"build_provenance_rules_version":"build-provenance-v1"}\n',
        )
        root = _write_v2_bundle(
            tmp_path,
            _manifest(
                bundle_kind,
                verdict=None if bundle_kind == "campaign" else "INCONCLUSIVE",
                reason=None if bundle_kind == "campaign" else "EVIDENCE_INCOMPLETE",
            ),
            files,
            name=f"b2-missing-{bundle_kind}",
        )
        with pytest.raises(BundleError, match="build_provenance"):
            verify_bundle(root)

    # 2. Structural & type violations fail closed.
    bad_payloads = [
        ("extra-top-key", {**_report_build_provenance(), "extra": 1}),
        (
            "missing-comparable",
            {
                "vulnerable": {"face": "compile_commands.json", "declared": [], "effective": []},
                "fixed": {"face": "compile_commands.json", "declared": [], "effective": []},
            },
        ),
        ("int-comparable", {**_report_build_provenance(), "comparable": 1}),
        (
            "extra-version-key",
            {
                "vulnerable": {
                    "face": "compile_commands.json",
                    "declared": [],
                    "effective": [],
                    "extra": True,
                },
                "fixed": {"face": "compile_commands.json", "declared": [], "effective": []},
                "comparable": True,
            },
        ),
        (
            "non-list-declared",
            {
                "vulnerable": {
                    "face": "compile_commands.json",
                    "declared": "-O1",
                    "effective": [],
                },
                "fixed": {"face": "compile_commands.json", "declared": [], "effective": []},
                "comparable": True,
            },
        ),
        (
            "non-str-effective-item",
            {
                "vulnerable": {"face": "compile_commands.json", "declared": [], "effective": [1]},
                "fixed": {"face": "compile_commands.json", "declared": [], "effective": []},
                "comparable": True,
            },
        ),
        (
            "archived-face-mismatch",
            {
                "vulnerable": {"face": "compile_commands.json", "declared": [], "effective": []},
                "fixed": {"face": "cc-shim.log", "declared": [], "effective": []},
                "comparable": True,
            },
        ),
    ]
    for label, bad_prov in bad_payloads:
        files = _base_files(execution=True, campaign=False)
        files["report.json"] = (
            "report_json",
            json.dumps(
                {
                    "build_provenance_rules_version": "build-provenance-v1",
                    "build_provenance": bad_prov,
                }
            ).encode("utf-8")
            + b"\n",
        )
        root = _write_v2_bundle(
            tmp_path,
            _manifest("execution"),
            files,
            name=f"b2-{label}",
        )
        with pytest.raises(BundleError) as raised:
            verify_bundle(root)
        assert raised.value.reason_code == "INVALID_MANIFEST", label

    # 3. Partial bundle with comparable=True but missing fixed archived face is rejected.
    partial_comp = _partial_execution_files()
    partial_comp["report.json"] = (
        "report_json",
        json.dumps(
            {
                "rule": None,
                "build_provenance_rules_version": "build-provenance-v1",
                "build_provenance": _report_build_provenance(comparable=True),
            }
        ).encode("utf-8")
        + b"\n",
    )
    partial_comp_root = _write_v2_bundle(
        tmp_path,
        _manifest("execution", verdict="INCONCLUSIVE", reason="TIMEOUT"),
        partial_comp,
        name="b2-partial-comparable-missing-face",
    )
    with pytest.raises(BundleError, match="comparable=true"):
        verify_bundle(partial_comp_root)

    # 4. Partial bundle with plan.build_spec.kind='make' rejects report face='compile_commands.json'.
    partial_kind = {
        path: item
        for path, item in _partial_execution_files().items()
        if not path.startswith("build/")
    }
    partial_kind["plan.json"] = (
        "plan",
        json.dumps(
            {
                "schema_version": 2,
                "build_provenance_rules_version": "build-provenance-v1",
                "build_spec": {"kind": "make"},
            }
        ).encode("utf-8")
        + b"\n",
    )
    partial_kind["report.json"] = (
        "report_json",
        json.dumps(
            {
                "rule": None,
                "error": "make failed",
                "build_provenance_rules_version": "build-provenance-v1",
                "build_provenance": _report_build_provenance(
                    face="compile_commands.json", comparable=False
                ),
            }
        ).encode("utf-8")
        + b"\n",
    )
    partial_kind_root = _write_v2_bundle(
        tmp_path,
        _manifest("execution", verdict="FAILED", reason="BUILD_PROVENANCE_MISSING"),
        partial_kind,
        name="b2-partial-plan-kind-face-mismatch",
    )
    with pytest.raises(BundleError, match="build_spec.kind"):
        verify_bundle(partial_kind_root)


def test_s1_rejects_non_mapping_build_spec_and_dirty_rules_version(tmp_path):
    """JayNey S-1: non-mapping plan.build_spec and whitespace/control rules_version fail closed."""
    for label, bad_spec in (("list", ["cmake"]), ("str", "cmake"), ("int", 42)):
        files = _base_files(execution=True, campaign=False)
        files["plan.json"] = (
            "plan",
            json.dumps(
                {
                    "schema_version": 2,
                    "build_provenance_rules_version": "build-provenance-v1",
                    "build_spec": bad_spec,
                }
            ).encode("utf-8")
            + b"\n",
        )
        root = _write_v2_bundle(
            tmp_path,
            _manifest("execution"),
            files,
            name=f"s1-bad-build-spec-{label}",
        )
        with pytest.raises(BundleError, match="build_spec must be a JSON object"):
            verify_bundle(root)

    for label, dirty_version in (
        ("leading-space", " build-provenance-v1"),
        ("trailing-space", "build-provenance-v1 "),
        ("newline", "build-provenance-v1\n"),
    ):
        manifest = _manifest("execution")
        manifest["build_provenance_rules_version"] = dirty_version
        files = _base_files(execution=True, campaign=False)
        files["plan.json"] = (
            "plan",
            json.dumps({"build_provenance_rules_version": dirty_version}).encode("utf-8")
            + b"\n",
        )
        files["report.json"] = (
            "report_json",
            json.dumps(
                {
                    "build_provenance_rules_version": dirty_version,
                    "build_provenance": _report_build_provenance(),
                }
            ).encode("utf-8")
            + b"\n",
        )
        root = _write_v2_bundle(
            tmp_path, manifest, files, name=f"s1-dirty-rules-{label}"
        )
        with pytest.raises(BundleError, match="build_provenance_rules_version"):
            verify_bundle(root)

        blocked_manifest = _manifest("blocked")
        blocked_manifest["build_provenance_rules_version"] = dirty_version
        blocked_root = _write_v2_bundle(
            tmp_path,
            blocked_manifest,
            _blocked_files(blocked_manifest),
            name=f"s1-blocked-dirty-rules-{label}",
        )
        with pytest.raises(BundleError, match="build_provenance_rules_version"):
            verify_bundle(blocked_root)


def test_s2_campaign_crash_seed_supports_seed_digest_nested_fuzz_and_count_lower_bound(
    tmp_path,
):
    """JayNey S-2: seed_digest, nested fuzz dict, and crash_seed count lower bound."""
    # 1. Single seed_digest requires >= 1 crash_seed.
    files = _base_files(execution=False, campaign=True)
    files["fuzz/provenance.json"] = (
        "fuzz_provenance",
        json.dumps({"seed_digest": DIGEST}).encode("utf-8") + b"\n",
    )
    root = _write_v2_bundle(
        tmp_path,
        _manifest("campaign", verdict=None, reason=None),
        files,
        name="s2-seed-digest-missing",
    )
    with pytest.raises(BundleError, match="crash_seed"):
        verify_bundle(root)

    # 2. Two fuzz_provenance files with 2 distinct seed_digests require >= 2 crash_seeds.
    files["fuzz/provenance-2.json"] = (
        "fuzz_provenance",
        json.dumps({"seed_digest": OTHER_DIGEST}).encode("utf-8") + b"\n",
    )
    files["fuzz/crashes/seed-001.bin"] = ("crash_seed", b"CRASH-1\n")
    root_one_seed = _write_v2_bundle(
        tmp_path,
        _manifest("campaign", verdict=None, reason=None),
        files,
        name="s2-two-digests-one-seed",
    )
    with pytest.raises(BundleError, match="at least 2"):
        verify_bundle(root_one_seed)

    files["fuzz/crashes/seed-002.bin"] = ("crash_seed", b"CRASH-2\n")
    root_two_seeds = _write_v2_bundle(
        tmp_path,
        _manifest("campaign", verdict=None, reason=None),
        files,
        name="s2-two-digests-two-seeds",
    )
    assert verify_bundle(root_two_seeds).manifest["bundle_kind"] == "campaign"

    # 3. Nested report.json["fuzz"] = {"crashes": 2} enforces count >= 2.
    nested_files = _base_files(execution=False, campaign=True)
    nested_files["report.json"] = (
        "report_json",
        json.dumps(
            {
                "schema_version": 2,
                "bundle_kind": "campaign",
                "build_provenance_rules_version": "build-provenance-v1",
                "build_provenance": _report_build_provenance(),
                "fuzz": {"crashes": 2},
            }
        ).encode("utf-8")
        + b"\n",
    )
    nested_files["fuzz/crashes/seed-001.bin"] = ("crash_seed", b"CRASH-1\n")
    nested_short = _write_v2_bundle(
        tmp_path,
        _manifest("campaign", verdict=None, reason=None),
        nested_files,
        name="s2-nested-fuzz-short",
    )
    with pytest.raises(BundleError, match="at least 2"):
        verify_bundle(nested_short)

    nested_files["fuzz/crashes/seed-002.bin"] = ("crash_seed", b"CRASH-2\n")
    nested_ok = _write_v2_bundle(
        tmp_path,
        _manifest("campaign", verdict=None, reason=None),
        nested_files,
        name="s2-nested-fuzz-ok",
    )
    assert verify_bundle(nested_ok).manifest["bundle_kind"] == "campaign"

    # 4. Malformed nested fuzz or empty seed_digest fails closed.
    for label, bad_prov in (
        ("bad-fuzz-type", {"fuzz": "not-an-object"}),
        ("empty-seed-digest", {"seed_digest": ""}),
    ):
        bad_files = _base_files(execution=False, campaign=True)
        bad_files["fuzz/provenance.json"] = (
            "fuzz_provenance",
            json.dumps(bad_prov).encode("utf-8") + b"\n",
        )
        bad_root = _write_v2_bundle(
            tmp_path,
            _manifest("campaign", verdict=None, reason=None),
            bad_files,
            name=f"s2-{label}",
        )
        with pytest.raises(BundleError) as raised:
            verify_bundle(bad_root)
        assert raised.value.reason_code == "INVALID_MANIFEST", label


def test_s3_and_s4_exact_build_provenance_artifact_and_blocked_cross_version_faces(
    tmp_path,
):
    """JayNey S-3 & S-4: reject build/<v>/build_provenance artifact and blocked cross-version face mismatch."""
    # S-3 (execution): exact path build/vulnerable/build_provenance as build_artifact rejected.
    exec_files = _partial_execution_files()
    del exec_files["build/vulnerable/build_provenance/compile_commands.json"]
    exec_files["build/vulnerable/build_provenance"] = ("build_artifact", b"evil\n")
    exec_root = _write_v2_bundle(
        tmp_path,
        _manifest("execution", verdict="FAILED", reason="BUILD_PROVENANCE_MISSING"),
        exec_files,
        name="s3-exec-exact-build-provenance-artifact",
    )
    with pytest.raises(BundleError, match="collides"):
        verify_bundle(exec_root)

    # S-3 (blocked): exact path build/vulnerable/build_provenance as build_artifact rejected.
    blocked_manifest = _manifest("blocked")
    blocked_s3 = _blocked_files(blocked_manifest)
    blocked_s3["build/vulnerable/build_provenance"] = ("build_artifact", b"evil\n")
    blocked_s3_root = _write_v2_bundle(
        tmp_path,
        blocked_manifest,
        blocked_s3,
        name="s3-blocked-exact-build-provenance-artifact",
    )
    with pytest.raises(BundleError, match="collides"):
        verify_bundle(blocked_s3_root)

    # S-4 (blocked): mismatched cross-version build_provenance face filenames rejected.
    blocked_s4_manifest = _manifest("blocked")
    blocked_s4 = _blocked_files(blocked_s4_manifest)
    blocked_s4["build/vulnerable/build_provenance/compile_commands.json"] = (
        "build_provenance",
        b"[]\n",
    )
    blocked_s4["build/fixed/build_provenance/cc-shim.log"] = (
        "build_provenance",
        b'{"argv":["clang","-c","a.c"]}\n',
    )
    blocked_s4_root = _write_v2_bundle(
        tmp_path,
        blocked_s4_manifest,
        blocked_s4,
        name="s4-blocked-face-mismatch",
    )
    with pytest.raises(BundleError, match="face filenames must match"):
        verify_bundle(blocked_s4_root)


def _bound_report(**fields):
    report = {
        "build_provenance_rules_version": "build-provenance-v1",
        "build_provenance": _report_build_provenance(),
    }
    report.update(fields)
    return ("report_json", json.dumps(report, sort_keys=True).encode("utf-8") + b"\n")


def _complete_with_report(**fields):
    files = _base_files(execution=True, campaign=False)
    files["report.json"] = _bound_report(**fields)
    return files


def _campaign_with_report(**fields):
    files = _base_files(execution=False, campaign=True)
    files["report.json"] = _bound_report(**fields)
    return files


def _pre_build_failed_files():
    """FAILED before any build, in the shape ``_finish_failed`` writes (§8)."""
    files = _partial_execution_files()
    for relative in [path for path in files if path.startswith("build/")]:
        del files[relative]
    files["report.json"] = _bound_report(
        verdict="FAILED",
        state="FAILED",
        reason_code="BUILD_FAILED",
        rule=None,
        missing=["execution failed"],
        error="BUILD_FAILED: vulnerable build exited 2",
        evidence_complete=False,
        build_provenance=_report_build_provenance(comparable=False),
    )
    return files


@pytest.mark.parametrize(
    ("bundle_kind", "verdict", "reason", "files", "match"),
    [
        pytest.param(
            "execution", "REPRODUCED", None,
            _complete_with_report(verdict="REPRODUCED", state="NOT_REPRODUCED"),
            "state", id="complete-state-drift",
        ),
        pytest.param(
            "execution", "INCONCLUSIVE", "EVIDENCE_INCOMPLETE",
            _complete_with_report(verdict="REPRODUCED", state="REPRODUCED"),
            "verdict", id="complete-verdict-drift",
        ),
        pytest.param(
            "execution", "INCONCLUSIVE", "EVIDENCE_INCOMPLETE",
            _complete_with_report(reason_code="BUILD_FAILED"),
            "reason_code", id="complete-reason-drift",
        ),
        pytest.param(
            "execution", "INCONCLUSIVE", "EVIDENCE_INCOMPLETE",
            _complete_with_report(
                rule={"verdict": "REPRODUCED", "reason_code": None}
            ),
            "rule", id="complete-rule-verdict-drift",
        ),
        pytest.param(
            "execution", "FAILED", "BUILD_PROVENANCE_MISSING",
            _complete_with_report(
                verdict="FAILED",
                state="FAILED",
                reason_code="BUILD_PROVENANCE_MISSING",
                rule={"verdict": "FAILED", "reason_code": "BUILD_PROVENANCE_MISSING"},
            ),
            "rule", id="failed-with-rule-trace",
        ),
        pytest.param(
            "campaign", None, None,
            _campaign_with_report(verdict=None, state="REPRODUCED"),
            "state", id="campaign-state-not-null",
        ),
        pytest.param(
            "execution", "FAILED", "BUILD_PROVENANCE_MISSING",
            {
                **_partial_execution_files(),
                "report.json": _bound_report(
                    verdict="FAILED",
                    state="REPRODUCED",
                    reason_code="BUILD_FAILED",
                    rule={"verdict": "REPRODUCED"},
                    build_provenance=_report_build_provenance(comparable=False),
                ),
            },
            "state", id="partial-failed-self-contradictory",
        ),
        pytest.param(
            "execution", "INCONCLUSIVE", "EVIDENCE_INCOMPLETE",
            {
                **_partial_execution_files(),
                "report.json": _bound_report(
                    state="REPRODUCED",
                    rule=None,
                    build_provenance=_report_build_provenance(comparable=False),
                ),
            },
            "state", id="partial-inconclusive-state-drift",
        ),
    ],
)
def test_v2_report_verdict_state_reason_are_bound_to_manifest(
    tmp_path, bundle_kind, verdict, reason, files, match
):
    """B-1 (§8, §12.5): report verdict/state/reason_code/rule never contradict the manifest."""
    root = _write_v2_bundle(
        tmp_path,
        _manifest(bundle_kind, verdict=verdict, reason=reason),
        files,
        name=f"bound-{bundle_kind}",
    )
    with pytest.raises(BundleError, match=match):
        verify_bundle(root)


def test_v2_pre_build_failed_bundle_in_writer_shape_verifies(tmp_path):
    """B-1 anti-false-kill: ``_finish_failed`` before any build still verifies."""
    root = _write_v2_bundle(
        tmp_path,
        _manifest("execution", verdict="FAILED", reason="BUILD_FAILED"),
        _pre_build_failed_files(),
        name="pre-build-failed",
    )
    verified = verify_bundle(root)
    assert verified.manifest["verdict"] == "FAILED"
    assert not any(path.startswith("build/") for path in verified.file_data)

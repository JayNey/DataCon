"""T12/TC-16: a validation round reuses the campaign build and stays self-contained.

The validation plan's ``build_ref`` is the single authority for the two build
artifact/log digests. The bundle must ship its own copy of the build records,
replays, envelope and budget snapshot, plus a ``reuse_origin`` that points back
to the archived campaign (job, generation, bundle digest and both artifacts).
Any per-version digest disagreement is a ``REUSE_MISMATCH`` and must not be
silently accepted as reusable evidence.
"""

from __future__ import annotations

from copy import deepcopy
import hashlib
import json
from uuid import uuid4

import pytest
from test_evidence_v2 import _base_files, _manifest, _write_v2_bundle
from test_plan_family import ROUND_PLAN_V2

from datacon.contracts import plan_digest
from datacon.evidence import BundleError, verify_bundle

DIGEST = "sha256:" + "a" * 64
OTHER_DIGEST = "sha256:" + "b" * 64
VERSIONS = ("vulnerable", "fixed")
BUILD_LOG = b"build ok\n"
BUILD_ARTIFACT = b"binary\n"
BUILD_LOG_DIGEST = "sha256:" + hashlib.sha256(BUILD_LOG).hexdigest()
BUILD_ARTIFACT_DIGEST = "sha256:" + hashlib.sha256(BUILD_ARTIFACT).hexdigest()
_UNSET = object()


def _artifacts() -> dict[str, dict[str, str]]:
    # Both build versions ship the same fixture bytes, so their digests are
    # real SHA-256 values of build.log / parser rather than arbitrary tokens.
    return {
        "vulnerable": {
            "artifact_digest": BUILD_ARTIFACT_DIGEST,
            "build_log_digest": BUILD_LOG_DIGEST,
        },
        "fixed": {
            "artifact_digest": BUILD_ARTIFACT_DIGEST,
            "build_log_digest": BUILD_LOG_DIGEST,
        },
    }


def _campaign_build_ref() -> dict:
    return {
        "source_job_id": str(uuid4()),
        "generation": 3,
        "build_inputs_digest": OTHER_DIGEST,
        "artifacts": _artifacts(),
    }


def _reuse_origin(
    build_ref: dict,
    *,
    artifacts: dict | None = None,
    source_job_id: str | None = None,
    generation: int | None = None,
) -> dict:
    return {
        "source_job_id": source_job_id or build_ref["source_job_id"],
        "generation": build_ref["generation"] if generation is None else generation,
        "campaign_bundle_digest": DIGEST,
        "artifacts": deepcopy(artifacts or build_ref["artifacts"]),
    }


def _validation_plan(build_ref: dict) -> dict:
    plan = deepcopy(ROUND_PLAN_V2)
    plan["build_ref"] = deepcopy(build_ref)
    return plan


def _validation_manifest(
    plan: dict,
    build_ref: dict,
    reuse_origin: dict,
    *,
    plan_digest_override: str | object = _UNSET,
) -> dict:
    manifest = _manifest("execution")
    manifest["experiment_digest"] = OTHER_DIGEST
    manifest["plan_digest"] = (
        plan_digest(plan)
        if plan_digest_override is _UNSET
        else plan_digest_override
    )
    manifest["build_ref"] = build_ref
    manifest["reuse_origin"] = reuse_origin
    return manifest


def _validation_files(
    plan: dict,
    *,
    report_build_ref: dict | None | object = _UNSET,
    report_reuse_origin: dict | None | object = _UNSET,
) -> dict:
    files = _base_files(execution=True, campaign=False)
    files["plan.json"] = (
        "plan",
        json.dumps(plan, sort_keys=True).encode() + b"\n",
    )
    # A complete validation report mirrors the manifest provenance pointers.
    report = {
        "schema_version": 2,
        "build_ref": None,
        "reuse_origin": None,
    }
    files["report.json"] = (
        "report_json",
        json.dumps(report, sort_keys=True).encode() + b"\n",
    )
    return files


def _write_validation(
    tmp_path,
    name: str,
    *,
    build_ref: dict | None = None,
    plan: dict | None = None,
    manifest_build_ref: dict | None = None,
    reuse_origin: dict | None = None,
    plan_digest_override: str | object = _UNSET,
    report_build_ref: dict | None | object = _UNSET,
    report_reuse_origin: dict | None | object = _UNSET,
):
    build_ref = _campaign_build_ref() if build_ref is None else build_ref
    plan = _validation_plan(build_ref) if plan is None else plan
    origin = _reuse_origin(build_ref) if reuse_origin is None else reuse_origin
    manifest = _validation_manifest(
        plan,
        build_ref if manifest_build_ref is None else manifest_build_ref,
        origin,
        plan_digest_override=plan_digest_override,
    )
    files = _validation_files(plan)
    resolved_report_build_ref = (
        manifest["build_ref"]
        if report_build_ref is _UNSET
        else report_build_ref
    )
    resolved_report_origin = (
        manifest["reuse_origin"]
        if report_reuse_origin is _UNSET
        else report_reuse_origin
    )
    report = {
        "schema_version": 2,
        "build_ref": resolved_report_build_ref,
        "reuse_origin": resolved_report_origin,
    }
    files["report.json"] = (
        "report_json",
        json.dumps(report, sort_keys=True).encode() + b"\n",
    )
    return _write_v2_bundle(tmp_path, manifest, files, name=name)


def _rewrite_manifested_file(root, relative: str, data: bytes) -> None:
    target = root / relative
    target.write_bytes(data)
    manifest_path = root / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    for entry in manifest["files"]:
        if entry["path"] == relative:
            entry["size_bytes"] = len(data)
            entry["sha256"] = hashlib.sha256(data).hexdigest()
            break
    else:
        raise AssertionError(f"{relative} is not listed in the manifest")
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")


def test_validation_reuses_campaign_build_and_detects_mismatch(tmp_path):
    build_ref = _campaign_build_ref()
    root = _write_validation(tmp_path, "reuse-validation", build_ref=build_ref)

    verified = verify_bundle(root)
    assert verified.manifest["reuse_origin"]["artifacts"] == build_ref["artifacts"]
    assert verified.manifest["build_ref"]["artifacts"] == build_ref["artifacts"]
    # The validation bundle is self-contained: no campaign directory exists
    # next to it, yet its own build bytes and six replays verify offline.
    assert not list(tmp_path.glob("campaign*"))
    assert len(
        [path for path in verified.file_data if path.startswith("replay/")]
    ) == 18
    assert verified.file_data["build/vulnerable/build.log"] == BUILD_LOG
    assert verified.file_data["build/vulnerable/parser"] == BUILD_ARTIFACT

    # Any per-version artifact or build-log digest disagreement between the
    # reuse pointer and the authoritative build_ref is a REUSE_MISMATCH.
    for version in VERSIONS:
        for field in ("artifact_digest", "build_log_digest"):
            mismatched = deepcopy(build_ref["artifacts"])
            mismatched[version][field] = "sha256:" + "f" * 64
            mismatched_manifest = _write_validation(
                tmp_path,
                f"reuse-mismatch-{version}-{field}",
                build_ref=build_ref,
                reuse_origin=_reuse_origin(build_ref, artifacts=mismatched),
            )
            with pytest.raises(BundleError) as raised:
                verify_bundle(mismatched_manifest)
            assert raised.value.reason_code == "REUSE_MISMATCH", (
                f"{version} {field} mismatch was not a REUSE_MISMATCH"
            )


def test_validation_rejects_tampered_build_bytes(tmp_path):
    """Manifest self-hashes are not proof that the campaign build was reused."""
    for relative in ("build/vulnerable/build.log", "build/fixed/parser"):
        root = _write_validation(
            tmp_path,
            "reuse-tampered-" + relative.replace("/", "-"),
        )
        _rewrite_manifested_file(root, relative, b"tampered build bytes\n")
        with pytest.raises(BundleError) as raised:
            verify_bundle(root)
        assert raised.value.reason_code == "REUSE_MISMATCH"
        assert relative in raised.value.message


def test_validation_plan_digest_and_report_are_bound(tmp_path):
    build_ref = _campaign_build_ref()

    # The plan is the authority: a plan whose build_ref differs from the
    # manifest/reuse_origin digests must be rejected even when those two agree.
    stale_plan = _validation_plan(build_ref)
    stale_plan["build_ref"]["artifacts"]["fixed"]["artifact_digest"] = (
        "sha256:" + "e" * 64
    )
    stale_root = _write_validation(
        tmp_path,
        "reuse-plan-mismatch",
        build_ref=build_ref,
        plan=stale_plan,
        manifest_build_ref=build_ref,
        plan_digest_override=plan_digest(stale_plan),
    )
    with pytest.raises(BundleError) as raised:
        verify_bundle(stale_root)
    assert raised.value.reason_code == "REUSE_MISMATCH"

    # A plan edit that does not update manifest.plan_digest is caught as a
    # digest mismatch instead of silently being treated as the authority.
    tampered_plan = _validation_plan(build_ref)
    tampered_root = _write_validation(tmp_path, "reuse-plan-tamper")
    tampered_plan["round_no"] = 3
    _rewrite_manifested_file(
        tampered_root,
        "plan.json",
        json.dumps(tampered_plan, sort_keys=True).encode() + b"\n",
    )
    with pytest.raises(BundleError) as raised:
        verify_bundle(tampered_root)
    assert raised.value.reason_code == "DIGEST_MISMATCH"

    # The report cannot disagree with the manifest about the reused build.
    report_mismatch_root = _write_validation(
        tmp_path,
        "reuse-report-mismatch",
        build_ref=build_ref,
        report_build_ref={
            **build_ref,
            "generation": build_ref["generation"] + 1,
        },
    )
    with pytest.raises(BundleError) as raised:
        verify_bundle(report_mismatch_root)
    assert raised.value.reason_code == "REUSE_MISMATCH"

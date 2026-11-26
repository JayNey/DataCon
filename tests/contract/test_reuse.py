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
import json
from uuid import uuid4

import pytest
from test_evidence_v2 import _base_files, _manifest, _write_v2_bundle

from datacon.evidence import BundleError, verify_bundle

DIGEST = "sha256:" + "a" * 64
OTHER_DIGEST = "sha256:" + "b" * 64
VERSIONS = ("vulnerable", "fixed")


def _artifacts() -> dict[str, dict[str, str]]:
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


def _validation_files(plan_build_ref: dict) -> dict:
    files = _base_files(execution=True, campaign=False)
    plan = {"schema_version": 2, "build_ref": plan_build_ref}
    files["plan.json"] = (
        "plan",
        json.dumps(plan, sort_keys=True).encode() + b"\n",
    )
    return files


def _validation_manifest(build_ref: dict, reuse_origin: dict) -> dict:
    manifest = _manifest("execution")
    manifest["experiment_digest"] = OTHER_DIGEST
    manifest["build_ref"] = build_ref
    manifest["reuse_origin"] = reuse_origin
    return manifest


def test_validation_reuses_campaign_build_and_detects_mismatch(tmp_path):
    build_ref = _campaign_build_ref()
    manifest = _validation_manifest(build_ref, _reuse_origin(build_ref))
    root = _write_v2_bundle(
        tmp_path,
        manifest,
        _validation_files(build_ref),
        name="reuse-validation",
    )

    verified = verify_bundle(root)
    assert verified.manifest["reuse_origin"]["artifacts"] == build_ref["artifacts"]
    assert verified.manifest["build_ref"]["artifacts"] == build_ref["artifacts"]
    # The validation bundle is self-contained: no campaign directory exists
    # next to it, yet the two build records and six replays verify offline.
    assert not list(tmp_path.glob("campaign*"))
    assert len(
        [path for path in verified.file_data if path.startswith("replay/")]
    ) == 18

    # Any per-version artifact or build-log digest disagreement between the
    # reuse pointer and the authoritative build_ref is a REUSE_MISMATCH.
    for version in VERSIONS:
        for field in ("artifact_digest", "build_log_digest"):
            mismatched = deepcopy(build_ref["artifacts"])
            mismatched[version][field] = "sha256:" + "f" * 64
            mismatched_manifest = _validation_manifest(
                build_ref,
                _reuse_origin(build_ref, artifacts=mismatched),
            )
            mismatch_root = _write_v2_bundle(
                tmp_path,
                mismatched_manifest,
                _validation_files(build_ref),
                name=f"reuse-mismatch-{version}-{field}",
            )
            with pytest.raises(BundleError) as raised:
                verify_bundle(mismatch_root)
            assert raised.value.reason_code == "REUSE_MISMATCH", (
                f"{version} {field} mismatch was not a REUSE_MISMATCH"
            )

    # The plan is the authority: a plan build_ref that differs from the
    # manifest/reuse_origin digests must be rejected even when those two agree.
    stale_plan_build_ref = deepcopy(build_ref)
    stale_plan_build_ref["artifacts"]["fixed"]["artifact_digest"] = (
        "sha256:" + "e" * 64
    )
    stale_plan_root = _write_v2_bundle(
        tmp_path,
        _validation_manifest(build_ref, _reuse_origin(build_ref)),
        _validation_files(stale_plan_build_ref),
        name="reuse-plan-mismatch",
    )
    with pytest.raises(BundleError) as raised:
        verify_bundle(stale_plan_root)
    assert raised.value.reason_code == "REUSE_MISMATCH"

"""TDD contract tests for T07/T08 release manifest, promotion gate, smoke block, B03 acceptance, and rollback."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from datacon import evidence, release
from datacon.tools.sandbox import BuildResult, ProbeReport, ReplayResult

REPO_ROOT = Path(__file__).resolve().parents[2]
B03_PATH = REPO_ROOT / "tests" / "fixtures" / "cases" / "B03-admission.json"


def _sha(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _sample_rc_manifest() -> dict:
    return release.build_release_candidate_manifest(
        source_commit="a" * 40,
        control_plane_image_digest="sha256:" + "1" * 64,
        wheel_digest="sha256:" + "2" * 64,
        toolchain_image_digest="sha256:f5ce959d91f059acf5a4b3f1c19f46713c4b2881c7d7cd1d5143ca1d1412277f",
        migrations_dir=REPO_ROOT / "migrations",
        sbom_digest="sha256:" + "3" * 64,
        test_report_digest="sha256:" + "4" * 64,
        scan_report_digest="sha256:" + "5" * 64,
    )


def test_release_candidate_manifest_requires_all_fields_and_valid_digests():
    manifest = _sample_rc_manifest()
    assert manifest["schema_version"] == 1
    assert manifest["contract_version"] == 1
    assert manifest["migration_version"] == "007_execution_evidence_invariant.sql"
    assert len(manifest["migrations"]) >= 7
    release.validate_release_candidate_manifest(manifest)

    for key in ("source_commit", "control_plane_image_digest", "wheel_digest", "sbom_digest"):
        broken = dict(manifest)
        broken.pop(key)
        with pytest.raises(release.ReleaseGateError, match=key):
            release.validate_release_candidate_manifest(broken)

    bad_digest = dict(manifest)
    bad_digest["wheel_digest"] = "sha256:short"
    with pytest.raises(release.ReleaseGateError, match="wheel_digest"):
        release.validate_release_candidate_manifest(bad_digest)


def test_sbom_generation_produces_cyclonedx_and_digest(tmp_path):
    sbom, sbom_digest = release.generate_sbom(
        pyproject_path=REPO_ROOT / "pyproject.toml",
        uv_lock_path=REPO_ROOT / "uv.lock",
        out_path=tmp_path / "sbom.cdx.json",
    )
    assert sbom["bomFormat"] == "CycloneDX"
    assert sbom["specVersion"] == "1.5"
    assert sbom_digest.startswith("sha256:")
    assert any(comp["name"] == "datacon" for comp in sbom["components"])


def test_promotion_gate_blocks_unverified_or_incompatible_candidate():
    manifest = _sample_rc_manifest()
    approval = {
        "approved_by": "release-maintainer",
        "approved_at": "2026-11-17T11:30:00Z",
        "candidate_digest": release.canonical_manifest_digest(manifest),
        "ci_passed": True,
        "contract_version": 1,
        "migration_compatible": True,
    }
    release.verify_promotion_gate(
        manifest,
        expected_manifest_digest=approval["candidate_digest"],
        approval=approval,
    )

    with pytest.raises(release.ReleaseGateError, match="digest"):
        release.verify_promotion_gate(
            manifest,
            expected_manifest_digest="sha256:" + "9" * 64,
            approval=approval,
        )

    unapproved = dict(approval, ci_passed=False)
    with pytest.raises(release.ReleaseGateError, match="CI"):
        release.verify_promotion_gate(
            manifest,
            expected_manifest_digest=approval["candidate_digest"],
            approval=unapproved,
        )


def test_smoke_failure_halts_promotion_and_triggers_rollback():
    manifest = _sample_rc_manifest()
    candidate_digest = release.canonical_manifest_digest(manifest)
    previous = {
        "image_digest": "sha256:" + "8" * 64,
        "config": {"policy_version": "1"},
        "migration_version": "007_execution_evidence_invariant.sql",
        "evidence_root": "/var/lib/datacon/evidence",
    }
    approval = {
        "approved_by": "release-maintainer",
        "approved_at": "2026-11-17T11:30:00Z",
        "candidate_digest": candidate_digest,
        "ci_passed": True,
        "contract_version": 1,
        "migration_compatible": True,
    }

    result = release.promote_and_smoke(
        manifest=manifest,
        expected_manifest_digest=candidate_digest,
        approval=approval,
        previous_release=previous,
        active_slots=0,
        smoke_checks={
            "cli_smoke": lambda: True,
            "db_readability": lambda: True,
            "sandbox_probe": lambda: False,
            "synthetic_regression": lambda: True,
        },
        rollback_fn=lambda prev: {"restored_image": prev["image_digest"], "ok": True},
    )
    assert result["status"] == "rolled_back"
    assert result["failed_check"] == "sandbox_probe"
    assert result["rollback"]["ok"] is True
    assert result["active_image_digest"] == previous["image_digest"]


def test_promotion_blocks_when_execution_slots_are_not_drained():
    manifest = _sample_rc_manifest()
    candidate_digest = release.canonical_manifest_digest(manifest)
    approval = {
        "approved_by": "release-maintainer",
        "approved_at": "2026-11-17T11:30:00Z",
        "candidate_digest": candidate_digest,
        "ci_passed": True,
        "contract_version": 1,
        "migration_compatible": True,
    }
    with pytest.raises(release.ReleaseGateError, match="slot"):
        release.promote_and_smoke(
            manifest=manifest,
            expected_manifest_digest=candidate_digest,
            approval=approval,
            previous_release={"image_digest": "sha256:" + "8" * 64},
            active_slots=1,
            smoke_checks={},
            rollback_fn=lambda prev: {},
        )


def test_b03_authorized_acceptance_workflow_reproduces_cve_2019_13224(tmp_path):
    admission = json.loads(B03_PATH.read_text(encoding="utf-8"))

    class FakeB03Sandbox:
        def probe(self, *, deadline_seconds: float = 120.0) -> ProbeReport:
            return ProbeReport(
                ok=True,
                checks={
                    "uid": "65534",
                    "seccomp": "2",
                    "no_new_privs": "1",
                    "cap_eff": "0000000000000000",
                    "cgroup_version": "2",
                },
                compiler_version="clang 19.1.7",
                image_digest=admission["build"]["toolchain_image"].split("@", 1)[1],
                limits={"cpu": 2, "memory_mib": 2048, "pids": 128, "scratch_mib": 512},
                raw="probe ok",
            )

        def build(self, version: str, **kwargs) -> BuildResult:
            artifact = f"onig-harness-{version}".encode("utf-8")
            img_digest = admission["build"]["toolchain_image"].split("@", 1)[1]
            return BuildResult(
                version=version,
                status="completed",
                exit_code=0,
                duration_seconds=1.2,
                container_id=f"cid-build-{version}",
                image_digest=img_digest,
                compile_args=tuple(kwargs.get("compile_args") or ()),
                artifact_digest=_sha(artifact),
                log=f"cmake build {version} ok\n".encode("utf-8"),
                log_truncated=False,
                artifact=artifact,
                metadata={"image_digest": img_digest},
            )

        def replay(self, version: str, phase: str, *, input_path: Path, **kwargs) -> ReplayResult:
            input_digest = _sha(input_path.read_bytes())
            if phase == "normal":
                return ReplayResult(
                    version=version,
                    phase=phase,
                    status="completed",
                    exit_code=0,
                    duration_seconds=0.1,
                    container_id=f"cid-{version}-{phase}",
                    input_digest=input_digest,
                    stdout=b"OK\n",
                    stderr=b"",
                    signature=None,
                    timed_out=False,
                    quota_hit=False,
                    log_truncated=False,
                    metadata={"image_digest": admission["build"]["toolchain_image"].split("@", 1)[1]},
                )
            if version == "vulnerable":
                stderr = (
                    b"==1==ERROR: AddressSanitizer: heap-use-after-free on address 0x602000000010\n"
                    b"    #0 0x401234 in onig_new_deluxe /work/src/regext.c:120:5\n"
                )
                from datacon.asan import parse_asan

                return ReplayResult(
                    version=version,
                    phase=phase,
                    status="completed",
                    exit_code=86,
                    duration_seconds=0.2,
                    container_id=f"cid-{version}-{phase}",
                    input_digest=input_digest,
                    stdout=b"",
                    stderr=stderr,
                    signature=parse_asan(stderr.decode("utf-8")),
                    timed_out=False,
                    quota_hit=False,
                    log_truncated=False,
                    metadata={"image_digest": admission["build"]["toolchain_image"].split("@", 1)[1]},
                )
            return ReplayResult(
                version=version,
                phase=phase,
                status="completed",
                exit_code=0,
                duration_seconds=0.1,
                container_id=f"cid-{version}-{phase}",
                input_digest=input_digest,
                stdout=b"MISMATCH_REJECTED\n",
                stderr=b"",
                signature=None,
                timed_out=False,
                quota_hit=False,
                log_truncated=False,
                metadata={"image_digest": admission["build"]["toolchain_image"].split("@", 1)[1]},
            )

    bundle_dir = tmp_path / "b03-bundle"
    acceptance = release.run_b03_acceptance(
        admission=admission,
        sandbox=FakeB03Sandbox(),
        normal_input=b"^[a-z]+$\n",
        candidate_input=b"redacted-authorized-input\n",
        bundle_out=bundle_dir,
        storage_ref="vault://datacon/private/b03/CVE-2019-13224/manifest.json",
    )
    assert acceptance["verdict"] == "REPRODUCED"
    assert acceptance["reason_code"] == "ASAN_SIGNATURE_MATCHED"
    assert acceptance["replay_count"] == 6
    assert acceptance["bundle_verified"] is True
    assert acceptance["manifest_digest"].startswith("sha256:")
    verified = evidence.verify_bundle(bundle_dir)
    assert verified.manifest["verdict"] == "REPRODUCED"
    assert "raw_candidate_input" not in acceptance
    assert "asan_raw_log" not in acceptance

"""TDD contract tests for T07/T08 release manifest, promotion gate, smoke block, B03 acceptance, and rollback."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import shutil

import pytest

from datacon import evidence, release
from datacon.tools.sandbox import BuildResult, ProbeReport, ReplayResult

REPO_ROOT = Path(__file__).resolve().parents[2]
B03_PATH = REPO_ROOT / "tests" / "fixtures" / "cases" / "B03-admission.json"
CASES = REPO_ROOT / "tests" / "fixtures" / "cases"


def _sha(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _sample_rc_manifest(**overrides) -> dict:
    kwargs = dict(
        source_commit="a" * 40,
        control_plane_image_id="sha256:" + "1" * 64,
        wheel_digest="sha256:" + "2" * 64,
        migrations_dir=REPO_ROOT / "migrations",
        sbom_digest="sha256:" + "3" * 64,
        test_report_digest="sha256:" + "4" * 64,
        scan_report_digest="sha256:" + "5" * 64,
    )
    kwargs.update(overrides)
    return release.build_release_candidate_manifest(**kwargs)


def _approval(manifest: dict, **overrides) -> dict:
    approval = {
        "approved_by": "release-maintainer",
        "approved_at": "2026-11-17T06:00:00Z",
        "candidate_digest": release.canonical_manifest_digest(manifest),
        "ci_passed": True,
        "contract_version": 1,
        "migration_compatible": True,
    }
    approval.update(overrides)
    return approval


def _previous() -> dict:
    return {
        "image_id": "sha256:" + "8" * 64,
        "config": {"policy_version": "1"},
        "migration_version": "007_execution_evidence_invariant.sql",
        "evidence_root": "/var/lib/datacon/evidence",
    }


def _backend(*, slots: int = 0, previous: dict | None = None) -> release.DictPromotionBackend:
    return release.DictPromotionBackend(
        active_release=previous or _previous(), active_slots=slots
    )


def _write_evidence_artifacts(tmp_path: Path) -> Path:
    artifacts = tmp_path / "artifacts"
    artifacts.mkdir(parents=True)
    for index, name in enumerate(release.TEST_REPORT_FILES, start=1):
        (artifacts / name).write_text(
            f'<testsuite tests="{index}" skipped="0" failures="0" errors="0"/>',
            encoding="utf-8",
        )
    (artifacts / release.SCAN_REPORT_FILE).write_text(
        json.dumps({"Results": [{"Vulnerabilities": []}]}), encoding="utf-8"
    )
    (artifacts / release.SBOM_REPORT_FILE).write_text(
        '{"bomFormat":"CycloneDX"}\n', encoding="utf-8"
    )
    (artifacts / "datacon-0.1.0-py3-none-any.whl").write_bytes(b"wheel-bytes")
    return artifacts


def _manifest_for_artifacts(artifacts: Path, **overrides) -> dict:
    kwargs = dict(
        source_commit="a" * 40,
        control_plane_image_id="sha256:" + "1" * 64,
        wheel_digest=_sha((artifacts / "datacon-0.1.0-py3-none-any.whl").read_bytes()),
        migrations_dir=REPO_ROOT / "migrations",
        sbom_digest=_sha((artifacts / release.SBOM_REPORT_FILE).read_bytes()),
        test_report_digest=release.digest_test_reports(
            [artifacts / name for name in release.TEST_REPORT_FILES]
        ),
        scan_report_digest=_sha((artifacts / release.SCAN_REPORT_FILE).read_bytes()),
    )
    kwargs.update(overrides)
    return release.build_release_candidate_manifest(**kwargs)


def test_release_candidate_manifest_rejects_unknown_missing_and_bad_digests():
    manifest = _sample_rc_manifest()
    assert manifest["schema_version"] == 1
    assert manifest["contract_version"] == 1
    assert manifest["migration_version"] == "008_release_events.sql"
    assert len(manifest["migrations"]) >= 8
    release.validate_release_candidate_manifest(manifest)

    for key in ("source_commit", "control_plane_image_id", "wheel_digest", "sbom_digest"):
        broken = dict(manifest)
        broken.pop(key)
        with pytest.raises(release.ReleaseGateError, match=key):
            release.validate_release_candidate_manifest(broken)

    bad_digest = dict(manifest)
    bad_digest["wheel_digest"] = "sha256:short"
    with pytest.raises(release.ReleaseGateError, match="wheel_digest"):
        release.validate_release_candidate_manifest(bad_digest)

    extra = dict(manifest)
    extra["unexpected"] = True
    with pytest.raises(release.ReleaseGateError, match="unknown fields"):
        release.validate_release_candidate_manifest(extra)

    reversed_migrations = dict(manifest)
    reversed_migrations["migrations"] = list(reversed(manifest["migrations"]))
    reversed_migrations["migration_version"] = reversed_migrations["migrations"][-1]["file"]
    with pytest.raises(release.ReleaseGateError, match="sorted"):
        release.validate_release_candidate_manifest(reversed_migrations)

    duplicate = dict(manifest)
    duplicate["migrations"] = [
        manifest["migrations"][0],
        dict(manifest["migrations"][0]),
    ]
    duplicate["migration_version"] = manifest["migrations"][0]["file"]
    with pytest.raises(release.ReleaseGateError, match="duplicate"):
        release.validate_release_candidate_manifest(duplicate)

    wrong_version = dict(manifest)
    wrong_version["migration_version"] = manifest["migrations"][0]["file"]
    with pytest.raises(release.ReleaseGateError, match="migration_version"):
        release.validate_release_candidate_manifest(wrong_version)


def test_manifest_disk_verification_rejects_replaced_migration(tmp_path):
    migrations = tmp_path / "migrations"
    shutil.copytree(REPO_ROOT / "migrations", migrations)
    manifest = _sample_rc_manifest(migrations_dir=migrations)
    release.verify_manifest_against_disk(manifest, migrations)

    target = migrations / manifest["migration_version"]
    target.write_text("-- replaced\n", encoding="utf-8")
    with pytest.raises(release.ReleaseGateError, match="digest"):
        release.verify_manifest_against_disk(manifest, migrations)


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


def test_verify_manifest_evidence_accepts_real_files_and_rejects_tampering(tmp_path):
    artifacts = _write_evidence_artifacts(tmp_path / "positive")
    manifest = _manifest_for_artifacts(artifacts)
    computed = release.verify_manifest_evidence(
        manifest, artifacts, migrations_dir=REPO_ROOT / "migrations"
    )
    assert computed["test_report_digest"] == manifest["test_report_digest"]
    assert manifest["test_report_digest"] != manifest["scan_report_digest"]

    tampered_scan = dict(manifest)
    tampered_scan["scan_report_digest"] = "sha256:" + "9" * 64
    with pytest.raises(release.ReleaseGateError, match="scan_report_digest"):
        release.verify_manifest_evidence(tampered_scan, artifacts)

    report_dir = _write_evidence_artifacts(tmp_path / "test-tamper")
    (report_dir / release.TEST_REPORT_FILES[0]).write_text(
        '<testsuite tests="9" skipped="0" failures="1" errors="0"/>', encoding="utf-8"
    )
    with pytest.raises(release.ReleaseGateError, match="test_report_digest"):
        release.verify_manifest_evidence(manifest, report_dir)

    scan_dir = _write_evidence_artifacts(tmp_path / "scan-tamper")
    (scan_dir / release.SCAN_REPORT_FILE).write_text(
        '{"Results": [], "tampered": true}', encoding="utf-8"
    )
    with pytest.raises(release.ReleaseGateError, match="scan_report_digest"):
        release.verify_manifest_evidence(manifest, scan_dir)

    wheel_dir = _write_evidence_artifacts(tmp_path / "wheel-tamper")
    (wheel_dir / "datacon-0.1.0-py3-none-any.whl").write_bytes(b"other-wheel")
    with pytest.raises(release.ReleaseGateError, match="wheel_digest"):
        release.verify_manifest_evidence(manifest, wheel_dir)


def test_promotion_gate_blocks_unverified_stale_or_incompatible_candidate():
    manifest = _sample_rc_manifest()
    approval = _approval(manifest)
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

    with pytest.raises(release.ReleaseGateError, match="CI"):
        release.verify_promotion_gate(
            manifest,
            expected_manifest_digest=approval["candidate_digest"],
            approval=_approval(manifest, ci_passed=False),
        )

    with pytest.raises(release.ReleaseGateError, match="approved_at"):
        release.verify_promotion_gate(
            manifest,
            expected_manifest_digest=approval["candidate_digest"],
            approval={k: v for k, v in approval.items() if k != "approved_at"},
        )

    with pytest.raises(release.ReleaseGateError, match="expired"):
        release.verify_promotion_gate(
            manifest,
            expected_manifest_digest=approval["candidate_digest"],
            approval=_approval(manifest, approved_at="2026-11-10T00:00:00Z"),
            now=release.datetime(2026, 11, 17, tzinfo=release.timezone.utc),
        )


def test_promotion_switches_state_audits_once_and_is_idempotent():
    manifest = _sample_rc_manifest()
    backend = _backend()
    approval = _approval(manifest)

    result = release.promote_and_smoke(
        manifest=manifest,
        expected_manifest_digest=approval["candidate_digest"],
        approval=approval,
        backend=backend,
        smoke_checks={"cli_smoke": lambda: True, "db_readability": lambda: True},
        rollback_fn=lambda prev: {"restored_image": prev["image_id"], "ok": True},
    )
    assert result["status"] == "promoted"
    assert len(backend.switches) == 1
    assert backend.switches[0]["image_id"] == manifest["control_plane_image_id"]
    assert backend.active_release()["image_id"] == manifest["control_plane_image_id"]
    assert len(backend.audits) == 1

    repeated = release.promote_and_smoke(
        manifest=manifest,
        expected_manifest_digest=approval["candidate_digest"],
        approval=approval,
        backend=backend,
        smoke_checks={"cli_smoke": lambda: True},
        rollback_fn=lambda prev: {"restored_image": prev["image_id"], "ok": True},
    )
    assert repeated == result
    assert len(backend.switches) == 1
    assert len(backend.audits) == 1


def test_replayed_approval_after_a_state_change_is_rejected():
    manifest = _sample_rc_manifest()
    backend = _backend()
    approval = _approval(manifest)
    release.promote_and_smoke(
        manifest=manifest,
        expected_manifest_digest=approval["candidate_digest"],
        approval=approval,
        backend=backend,
        smoke_checks={"cli_smoke": lambda: True},
        rollback_fn=lambda prev: {"restored_image": prev["image_id"], "ok": True},
    )
    previous = _previous()
    backend.switch(
        image_id=previous["image_id"],
        config=previous["config"],
        migration_version=previous["migration_version"],
        evidence_root=previous["evidence_root"],
        action="rollback",
        candidate_digest=approval["candidate_digest"],
    )
    with pytest.raises(release.ReleaseGateError, match="stale approval"):
        release.promote_and_smoke(
            manifest=manifest,
            expected_manifest_digest=approval["candidate_digest"],
            approval=approval,
            backend=backend,
            smoke_checks={"cli_smoke": lambda: True},
            rollback_fn=lambda prev: {"restored_image": prev["image_id"], "ok": True},
        )


def test_smoke_failure_restores_previous_release_and_changes_active_state():
    manifest = _sample_rc_manifest()
    previous = _previous()
    backend = _backend(previous=previous)
    approval = _approval(manifest)

    def rollback(prev):
        backend.switch(
            image_id=prev["image_id"],
            config=prev["config"],
            migration_version=prev["migration_version"],
            evidence_root=prev["evidence_root"],
            action="rollback",
            candidate_digest=approval["candidate_digest"],
        )
        return {"restored_image": prev["image_id"], "ok": True}

    result = release.promote_and_smoke(
        manifest=manifest,
        expected_manifest_digest=approval["candidate_digest"],
        approval=approval,
        backend=backend,
        smoke_checks={
            "cli_smoke": lambda: True,
            "sandbox_probe": lambda: False,
            "synthetic_regression": lambda: True,
        },
        rollback_fn=rollback,
    )
    assert result["status"] == "rolled_back"
    assert result["failed_check"] == "sandbox_probe"
    assert result["rollback"]["ok"] is True
    assert backend.active_release()["image_id"] == previous["image_id"]
    assert backend.active_release()["migration_version"] == previous["migration_version"]
    assert any(item["action"] == "rollback" for item in backend.switches)


def test_promotion_blocks_when_execution_slots_are_not_drained():
    manifest = _sample_rc_manifest()
    approval = _approval(manifest)
    with pytest.raises(release.ReleaseGateError, match="slot"):
        release.promote_and_smoke(
            manifest=manifest,
            expected_manifest_digest=approval["candidate_digest"],
            approval=approval,
            backend=_backend(slots=1),
            smoke_checks={"cli_smoke": lambda: True},
            rollback_fn=lambda prev: {},
        )


def test_previous_release_requires_every_persisted_field():
    manifest = _sample_rc_manifest()
    approval = _approval(manifest)
    for missing in ("image_id", "config", "migration_version", "evidence_root"):
        previous = _previous()
        previous.pop(missing)
        backend = release.DictPromotionBackend.__new__(release.DictPromotionBackend)
        backend._active = previous  # type: ignore[attr-defined]
        backend._slots = 0  # type: ignore[attr-defined]
        backend.promotions = {}  # type: ignore[attr-defined]
        backend.switches = []  # type: ignore[attr-defined]
        backend.audits = []  # type: ignore[attr-defined]
        with pytest.raises(release.ReleaseGateError, match=missing):
            release.promote_and_smoke(
                manifest=manifest,
                expected_manifest_digest=approval["candidate_digest"],
                approval=approval,
                backend=backend,
                smoke_checks={"cli_smoke": lambda: True},
                rollback_fn=lambda prev: {},
            )


def test_rollback_fn_exception_or_invalid_result_fails_closed():
    manifest = _sample_rc_manifest()
    approval = _approval(manifest)

    def raising(prev):
        raise RuntimeError("docker load failed")

    with pytest.raises(release.ReleaseGateError, match="rollback failed"):
        release.promote_and_smoke(
            manifest=manifest,
            expected_manifest_digest=approval["candidate_digest"],
            approval=approval,
            backend=_backend(),
            smoke_checks={"cli_smoke": lambda: False},
            rollback_fn=raising,
        )

    with pytest.raises(release.ReleaseGateError, match="did not restore"):
        release.promote_and_smoke(
            manifest=manifest,
            expected_manifest_digest=approval["candidate_digest"],
            approval=approval,
            backend=_backend(),
            smoke_checks={"cli_smoke": lambda: False},
            rollback_fn=lambda prev: {"ok": True, "restored_image": "sha256:" + "0" * 64},
        )


def test_rollback_release_restores_target_config_and_migration():
    target = {
        "image_id": "sha256:" + "7" * 64,
        "config": {"policy_version": "0"},
        "migration_version": "007_execution_evidence_invariant.sql",
        "evidence_root": "/var/lib/datacon/evidence",
    }
    current = _previous()
    backend = _backend(previous=current)
    result = release.rollback_release(
        target_release=target,
        backend=backend,
        smoke_checks={"cli_smoke": lambda: True},
        approved_by="reviewer-1",
        candidate_digest="sha256:" + "6" * 64,
    )
    assert result["status"] == "rolled_back"
    assert backend.active_release()["image_id"] == target["image_id"]
    assert backend.active_release()["migration_version"] == target["migration_version"]
    assert backend.active_release()["config"] == target["config"]


# ---------------------------------------------------------------------------
# B03 real-material acceptance
# ---------------------------------------------------------------------------


def _b03_case_root(tmp_path: Path) -> Path:
    root = tmp_path / "b03-case"
    root.mkdir(exist_ok=True)
    for name in ("harness.c", "build.sh", "dependencies.lock", "fix.patch", "advisory.json"):
        shutil.copy2(CASES / name, root / name)
    shutil.copy2(CASES / "fixture-repo.bundle", root / "b03-repo.bundle")
    for version in ("vulnerable", "fixed"):
        (root / version).mkdir(exist_ok=True)
        shutil.copy2(CASES / version / "parser.c", root / version / "parser.c")
    (root / "inputs").mkdir(exist_ok=True)
    shutil.copy2(CASES / "inputs" / "normal.txt", root / "inputs" / "normal.txt")
    shutil.copy2(CASES / "inputs" / "candidate.txt", root / "inputs" / "candidate.txt")
    return root


def _frozen_admission() -> dict:
    admission = json.loads(B03_PATH.read_text(encoding="utf-8"))
    admission["asan_signature"]["status"] = "frozen"
    admission["expected_verdict_status"] = "frozen"
    admission["repository"]["source_path"] = "parser.c"
    return admission


def _review_for(admission: dict, root: Path) -> dict:
    normal = (root / "inputs" / "normal.txt").read_bytes()
    candidate = (root / "inputs" / "candidate.txt").read_bytes()
    prepared = release.prepare_b03_plan(
        admission=admission,
        materials=release.B03CaseMaterials.load(root),
        normal_input=normal,
        candidate_input=candidate,
    )
    return {
        "reviewer_id": "internal-reviewer",
        "decision": "approve",
        "plan_digest": prepared["plan_digest"],
        "decided_at": "2026-11-17T11:30:00Z",
    }


class FakeB03Sandbox:
    def __init__(
        self,
        *,
        probe_ok: bool = True,
        build_status: str = "completed",
        toolchain: str,
    ):
        self.probe_ok = probe_ok
        self.build_status = build_status
        self.toolchain = toolchain
        self.replays: list[tuple[str, str]] = []

    def probe(self, *, deadline_seconds: float = 120.0) -> ProbeReport:
        return ProbeReport(
            ok=self.probe_ok,
            checks={
                "uid": "65534",
                "seccomp": "2",
                "no_new_privs": "1",
                "cap_eff": "0000000000000000",
                "cgroup_version": "2",
            },
            compiler_version="clang 19.1.7",
            image_digest=self.toolchain.split("@", 1)[1],
            limits={"cpu": 2, "memory_mib": 2048, "pids": 128, "scratch_mib": 512},
            raw="probe ok",
        )

    def build(self, version: str, **kwargs) -> BuildResult:
        artifact = f"onig-harness-{version}".encode("utf-8")
        return BuildResult(
            version=version,
            status=self.build_status,
            exit_code=0 if self.build_status == "completed" else 1,
            duration_seconds=1.2,
            container_id=f"cid-build-{version}",
            image_digest=self.toolchain.split("@", 1)[1],
            compile_args=tuple(kwargs.get("compile_args") or ()),
            artifact_digest=_sha(artifact) if self.build_status == "completed" else None,
            log=f"cmake build {version} ok\n".encode("utf-8"),
            log_truncated=False,
            artifact=artifact if self.build_status == "completed" else b"",
            metadata={"image_digest": self.toolchain.split("@", 1)[1]},
        )

    def replay(self, version: str, phase: str, **kwargs) -> ReplayResult:
        self.replays.append((version, phase))
        input_digest = _sha(Path(kwargs["input_path"]).read_bytes())
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
                metadata={"image_digest": self.toolchain.split("@", 1)[1]},
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
                metadata={"image_digest": self.toolchain.split("@", 1)[1]},
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
            metadata={"image_digest": self.toolchain.split("@", 1)[1]},
        )


def _run_b03(tmp_path, admission, sandbox, review):
    root = _b03_case_root(tmp_path)
    return release.run_b03_acceptance(
        admission=admission,
        sandbox=sandbox,
        normal_input=(root / "inputs" / "normal.txt").read_bytes(),
        candidate_input=(root / "inputs" / "candidate.txt").read_bytes(),
        bundle_out=tmp_path / "b03-bundle",
        storage_ref="vault://datacon/private/b03/CVE-2019-13224/manifest.json",
        review=review,
        case_root=root,
    )


def test_b03_repo_pending_admission_is_rejected(tmp_path):
    root = _b03_case_root(tmp_path)
    admission = json.loads(B03_PATH.read_text(encoding="utf-8"))
    assert admission["expected_verdict_status"] == "pending_t05_replay"
    review = _review_for(_frozen_admission(), root)
    sandbox = FakeB03Sandbox(toolchain=admission["build"]["toolchain_image"])
    with pytest.raises(release.ReleaseGateError, match="asan_signature.status"):
        _run_b03(tmp_path, admission, sandbox, review)


def test_b03_missing_or_mismatched_review_is_rejected(tmp_path):
    root = _b03_case_root(tmp_path)
    admission = _frozen_admission()
    sandbox = FakeB03Sandbox(toolchain=admission["build"]["toolchain_image"])
    with pytest.raises(release.ReleaseGateError, match="review"):
        _run_b03(tmp_path, admission, sandbox, {})
    review = _review_for(admission, root)
    review["plan_digest"] = "sha256:" + "0" * 64
    with pytest.raises(release.ReleaseGateError, match="plan_digest"):
        _run_b03(tmp_path, admission, sandbox, review)


def test_b03_probe_failure_and_build_failure_are_rejected_before_replay(tmp_path):
    root = _b03_case_root(tmp_path)
    admission = _frozen_admission()
    review = _review_for(admission, root)

    failing_probe = FakeB03Sandbox(
        probe_ok=False, toolchain=admission["build"]["toolchain_image"]
    )
    with pytest.raises(release.ReleaseGateError, match="probe"):
        _run_b03(tmp_path, admission, failing_probe, review)

    failing_build = FakeB03Sandbox(
        build_status="failed", toolchain=admission["build"]["toolchain_image"]
    )
    with pytest.raises(release.ReleaseGateError, match="did not complete"):
        _run_b03(tmp_path, admission, failing_build, review)
    assert failing_build.replays == []


def test_b03_missing_bundle_advisory_or_material_digest_is_rejected(tmp_path):
    root = _b03_case_root(tmp_path)
    (root / "b03-repo.bundle").unlink()
    with pytest.raises(release.ReleaseGateError, match="b03-repo.bundle"):
        release.B03CaseMaterials.load(root)

    (tmp_path / "advisory-missing").mkdir()
    root = _b03_case_root(tmp_path / "advisory-missing")
    (root / "advisory.json").unlink()
    with pytest.raises(release.ReleaseGateError, match="advisory.json"):
        release.B03CaseMaterials.load(root)

    (tmp_path / "second").mkdir()
    root = _b03_case_root(tmp_path / "second")
    (root / "advisory.json").write_text("{\"wrong\": true}\n", encoding="utf-8")
    materials = release.B03CaseMaterials.load(root)
    assert materials.digests["advisory.json"] == _sha((root / "advisory.json").read_bytes())


def test_b03_frozen_admission_reproduces_with_real_material_files(tmp_path):
    root = _b03_case_root(tmp_path)
    admission = _frozen_admission()
    review = _review_for(admission, root)
    sandbox = FakeB03Sandbox(toolchain=admission["build"]["toolchain_image"])

    acceptance = release.run_b03_acceptance(
        admission=admission,
        sandbox=sandbox,
        normal_input=(root / "inputs" / "normal.txt").read_bytes(),
        candidate_input=(root / "inputs" / "candidate.txt").read_bytes(),
        bundle_out=tmp_path / "b03-bundle",
        storage_ref="vault://datacon/private/b03/CVE-2019-13224/manifest.json",
        review=review,
        case_root=root,
    )
    assert acceptance["verdict"] == "REPRODUCED"
    assert acceptance["reason_code"] == "ASAN_SIGNATURE_MATCHED"
    assert acceptance["replay_count"] == 6
    assert acceptance["bundle_verified"] is True
    assert acceptance["manifest_digest"].startswith("sha256:")
    assert acceptance["review"] == review

    bundle = tmp_path / "b03-bundle"
    verified = evidence.verify_bundle(bundle)
    assert verified.manifest["verdict"] == "REPRODUCED"
    assert (bundle / "materials" / "b03-repo.bundle").is_file()
    assert (bundle / "materials" / "advisory.json").is_file()
    assert _sha((bundle / "materials" / "b03-repo.bundle").read_bytes()) == _sha(
        (root / "b03-repo.bundle").read_bytes()
    )
    assert json.loads((bundle / "review.json").read_text(encoding="utf-8")) == review

    (bundle / "materials" / "harness.c").write_bytes(b"tampered\n")
    with pytest.raises(evidence.BundleError, match="mismatch"):
        evidence.verify_bundle(bundle)

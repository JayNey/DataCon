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
        "approved_at": release._utc_now(),
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
        "manifest_digest": "sha256:" + "9" * 64,
        "source_commit": "a" * 40,
    }


def _ledger() -> dict[str, str]:
    return {
        path.name: _sha(path.read_bytes())
        for path in sorted((REPO_ROOT / "migrations").glob("*.sql"))
    }


def _backend(
    *,
    slots: int = 0,
    previous: dict | None = None,
    b03_acceptances: dict[str, dict] | None = None,
) -> release.DictPromotionBackend:
    return release.DictPromotionBackend(
        active_release=previous or _previous(),
        active_slots=slots,
        migrations=_ledger(),
        b03_acceptances=b03_acceptances,
    )


def _write_evidence_artifacts(tmp_path: Path) -> Path:
    artifacts = tmp_path / "artifacts"
    artifacts.mkdir(parents=True)
    for index, name in enumerate(release.TEST_REPORT_FILES, start=1):
        cases = "".join(
            f'<testcase name="t{item}" />' for item in range(index)
        )
        (artifacts / name).write_text(
            f'<testsuite tests="{index}" skipped="0" failures="0" errors="0">'
            f"{cases}</testsuite>",
            encoding="utf-8",
        )
    (artifacts / release.SCAN_REPORT_FILE).write_text(
        json.dumps(
            {
                "SchemaVersion": 2,
                "ArtifactName": "datacon-control-plane:candidate",
                "Results": [{"Target": "image", "Vulnerabilities": []}],
            }
        ),
        encoding="utf-8",
    )
    (artifacts / release.SBOM_REPORT_FILE).write_text(
        json.dumps(
            {
                "bomFormat": "CycloneDX",
                "specVersion": "1.5",
                "components": [
                    {"type": "library", "name": "libc6", "purl": "pkg:deb/debian/libc6@2.36"},
                    {"type": "library", "name": "psycopg", "purl": "pkg:pypi/psycopg@3.2.1"},
                ],
            }
        )
        + "\n",
        encoding="utf-8",
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
    latest_migration = sorted(
        (REPO_ROOT / "migrations").glob("*.sql")
    )[-1].name
    assert manifest["migration_version"] == latest_migration
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

    extra_in_first_migration = dict(manifest)
    extra_in_first_migration["migrations"] = [
        dict(manifest["migrations"][0], unexpected=True),
        *[dict(item) for item in manifest["migrations"][1:]],
    ]
    with pytest.raises(release.ReleaseGateError, match="unknown fields"):
        release.validate_release_candidate_manifest(extra_in_first_migration)


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


def test_sbom_report_requires_deb_and_pypi_components(tmp_path):
    def write_sbom(name, components):
        path = tmp_path / name
        path.write_text(
            json.dumps(
                {
                    "bomFormat": "CycloneDX",
                    "specVersion": "1.5",
                    "components": components,
                }
            ),
            encoding="utf-8",
        )
        return path

    both = write_sbom(
        "both.json",
        [
            {"type": "library", "name": "libc6", "purl": "pkg:deb/debian/libc6@2.36"},
            {"type": "library", "name": "psycopg", "purl": "pkg:pypi/psycopg@3.2.1"},
        ],
    )
    summary = release.verify_sbom_report(both)
    assert summary["deb_components"] == 1
    assert summary["pypi_components"] == 1

    with pytest.raises(release.ReleaseGateError, match="pkg:deb/"):
        release.verify_sbom_report(
            write_sbom(
                "pypi-only.json",
                [{"type": "library", "name": "psycopg", "purl": "pkg:pypi/psycopg@3.2.1"}],
            )
        )
    with pytest.raises(release.ReleaseGateError, match="pkg:pypi/"):
        release.verify_sbom_report(
            write_sbom(
                "deb-only.json",
                [{"type": "library", "name": "libc6", "purl": "pkg:deb/debian/libc6@2.36"}],
            )
        )
    with pytest.raises(release.ReleaseGateError, match="CycloneDX"):
        path = tmp_path / "not-cyclonedx.json"
        path.write_text('{"components": []}\n', encoding="utf-8")
        release.verify_sbom_report(path)


def test_verify_manifest_evidence_keeps_sbom_digest_only(tmp_path):
    # verify_manifest_evidence must keep binding the SBOM by file digest; the
    # image-component check is a separate build-time gate.
    artifacts = _write_evidence_artifacts(tmp_path / "python-only")
    (artifacts / release.SBOM_REPORT_FILE).write_text(
        json.dumps(
            {
                "bomFormat": "CycloneDX",
                "specVersion": "1.5",
                "components": [
                    {"type": "library", "name": "psycopg", "purl": "pkg:pypi/psycopg@3.2.1"}
                ],
            }
        ),
        encoding="utf-8",
    )
    manifest = _manifest_for_artifacts(artifacts)
    computed = release.verify_manifest_evidence(manifest, artifacts)
    assert computed["sbom_digest"] == manifest["sbom_digest"]


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


def test_verify_manifest_evidence_checks_content_not_only_digests(tmp_path):
    report_dir = _write_evidence_artifacts(tmp_path / "content-report")
    (report_dir / release.TEST_REPORT_FILES[0]).write_text(
        '<testsuite tests="1" skipped="0" failures="0" errors="0">'
        '<testcase name="hidden"><failure message="boom" /></testcase>'
        "</testsuite>",
        encoding="utf-8",
    )
    report_manifest = _manifest_for_artifacts(report_dir)
    with pytest.raises(release.ReleaseGateError, match="JUnit|disagree|zero skips"):
        release.verify_manifest_evidence(report_manifest, report_dir)

    scan_dir = _write_evidence_artifacts(tmp_path / "content-scan")
    (scan_dir / release.SCAN_REPORT_FILE).write_text(
        json.dumps({"SchemaVersion": 2, "Results": []}), encoding="utf-8"
    )
    scan_manifest = _manifest_for_artifacts(scan_dir)
    with pytest.raises(release.ReleaseGateError, match="scan|Results|target"):
        release.verify_manifest_evidence(scan_manifest, scan_dir)


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

    with pytest.raises(release.ReleaseGateError, match="contract_version"):
        release.verify_promotion_gate(
            manifest,
            expected_manifest_digest=approval["candidate_digest"],
            approval=_approval(manifest, contract_version=True),
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


def test_promotion_requires_a_passed_b03_acceptance_before_switching():
    manifest = _sample_rc_manifest()
    approval = _approval(manifest)
    digest = approval["candidate_digest"]
    previous = _previous()

    missing = _backend(b03_acceptances={})
    with pytest.raises(release.ReleaseGateError, match="B03"):
        release.promote_and_smoke(
            manifest=manifest,
            expected_manifest_digest=digest,
            approval=approval,
            backend=missing,
            smoke_checks={"cli_smoke": lambda: True},
            rollback_fn=lambda prev: {"restored_image": prev["image_id"], "ok": True},
        )
    assert missing.switches == []
    assert missing.audits == []
    assert missing.active_release()["image_id"] == previous["image_id"]

    failed = _backend(
        b03_acceptances={digest: {"status": "failed", "candidate_digest": digest}}
    )
    with pytest.raises(release.ReleaseGateError, match="status"):
        release.promote_and_smoke(
            manifest=manifest,
            expected_manifest_digest=digest,
            approval=approval,
            backend=failed,
            smoke_checks={"cli_smoke": lambda: True},
            rollback_fn=lambda prev: {"restored_image": prev["image_id"], "ok": True},
        )
    assert failed.switches == []

    mismatched = _backend(
        b03_acceptances={
            digest: {
                "status": "passed",
                "candidate_digest": "sha256:" + "f" * 64,
            }
        }
    )
    with pytest.raises(release.ReleaseGateError, match="candidate_digest"):
        release.promote_and_smoke(
            manifest=manifest,
            expected_manifest_digest=digest,
            approval=approval,
            backend=mismatched,
            smoke_checks={"cli_smoke": lambda: True},
            rollback_fn=lambda prev: {"restored_image": prev["image_id"], "ok": True},
        )
    assert mismatched.switches == []

    wrong_environment = _backend(
        b03_acceptances={
            digest: {
                "status": "passed",
                "candidate_digest": digest,
                "environment": "prod",
            }
        }
    )
    with pytest.raises(release.ReleaseGateError, match="environment"):
        release.promote_and_smoke(
            manifest=manifest,
            expected_manifest_digest=digest,
            approval=approval,
            backend=wrong_environment,
            smoke_checks={"cli_smoke": lambda: True},
            rollback_fn=lambda prev: {"restored_image": prev["image_id"], "ok": True},
        )
    assert wrong_environment.switches == []

    passed = _backend(
        b03_acceptances={digest: {"status": "passed", "candidate_digest": digest}}
    )
    result = release.promote_and_smoke(
        manifest=manifest,
        expected_manifest_digest=digest,
        approval=approval,
        backend=passed,
        smoke_checks={"cli_smoke": lambda: True},
        rollback_fn=lambda prev: {"restored_image": prev["image_id"], "ok": True},
    )
    assert result["status"] == "promoted"
    assert passed.active_release()["image_id"] == manifest["control_plane_image_id"]


def test_promotion_fails_closed_when_the_backend_cannot_prove_b03():
    manifest = _sample_rc_manifest()
    approval = _approval(manifest)
    backend = _backend()
    backend.b03_acceptance_for = None  # type: ignore[method-assign]
    with pytest.raises(release.ReleaseGateError, match="cannot prove B03"):
        release.promote_and_smoke(
            manifest=manifest,
            expected_manifest_digest=approval["candidate_digest"],
            approval=approval,
            backend=backend,
            smoke_checks={"cli_smoke": lambda: True},
            rollback_fn=lambda prev: {"restored_image": prev["image_id"], "ok": True},
        )
    assert backend.switches == []
    assert backend.audits == []


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
    candidate_image = manifest["control_plane_image_id"]
    observed: dict[str, str] = {}

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

    def cli_smoke():
        observed["cli_active"] = backend.active_release()["image_id"]
        return True

    def failing_probe():
        observed["probe_active"] = backend.active_release()["image_id"]
        return False

    result = release.promote_and_smoke(
        manifest=manifest,
        expected_manifest_digest=approval["candidate_digest"],
        approval=approval,
        backend=backend,
        smoke_checks={
            "cli_smoke": cli_smoke,
            "sandbox_probe": failing_probe,
            "synthetic_regression": lambda: True,
        },
        rollback_fn=rollback,
    )
    # The candidate must actually have been active while the smoke ran.
    assert observed == {
        "cli_active": candidate_image,
        "probe_active": candidate_image,
    }
    assert [item["action"] for item in backend.switches] == ["promote", "rollback"]
    assert result["status"] == "rolled_back"
    assert result["failed_check"] == "sandbox_probe"
    assert result["rollback"]["ok"] is True
    assert result["previous_image_id"] == candidate_image
    assert result["active_image_id"] == previous["image_id"]
    assert backend.audits[-1]["previous_image_id"] == candidate_image
    assert backend.audits[-1]["active_image_id"] == previous["image_id"]
    assert backend.active_release()["image_id"] == previous["image_id"]
    assert backend.active_release()["migration_version"] == previous["migration_version"]
    assert backend.active_release()["config"] == previous["config"]
    assert backend.active_release()["evidence_root"] == previous["evidence_root"]


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
        backend._migrations = _ledger()  # type: ignore[attr-defined]
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


def test_noop_rollback_fn_fails_closed_after_a_real_candidate_switch():
    manifest = _sample_rc_manifest()
    previous = _previous()
    backend = _backend(previous=previous)
    approval = _approval(manifest)
    observed: dict[str, str] = {}

    def noop_rollback(prev):
        # Deliberately does not call backend.switch.
        return {"restored_image": prev["image_id"], "ok": True}

    with pytest.raises(release.ReleaseGateError, match="did not restore|state transition"):
        release.promote_and_smoke(
            manifest=manifest,
            expected_manifest_digest=approval["candidate_digest"],
            approval=approval,
            backend=backend,
            smoke_checks={
                "cli_smoke": lambda: observed.setdefault(
                    "active", backend.active_release()["image_id"]
                )
                and False
            },
            rollback_fn=noop_rollback,
        )
    assert observed["active"] == manifest["control_plane_image_id"]
    # The failed attempt is fully rolled back, leaving the previous release.
    assert backend.active_release()["image_id"] == previous["image_id"]


def test_sloppy_backend_that_only_changes_image_id_fails_closed():
    manifest = _sample_rc_manifest()
    previous = _previous()
    approval = _approval(manifest)

    class SloppyBackend(release.DictPromotionBackend):
        def switch(self, **kwargs):
            # Simulates a backend that forgets config/migration/evidence_root.
            self.switches.append(dict(kwargs))
            self._active = {"image_id": kwargs["image_id"]}

    sloppy = SloppyBackend(
        active_release=previous, migrations=_ledger()
    )
    with pytest.raises(release.ReleaseGateError, match="exact image/config|migration"):
        release.promote_and_smoke(
            manifest=manifest,
            expected_manifest_digest=approval["candidate_digest"],
            approval=approval,
            backend=sloppy,
            smoke_checks={"cli_smoke": lambda: True},
            rollback_fn=lambda prev: {"restored_image": prev["image_id"], "ok": True},
        )


def test_rollback_release_requires_a_real_manifest_digest():
    target = {
        "image_id": "sha256:" + "7" * 64,
        "config": {"policy_version": "0"},
        "migration_version": "007_execution_evidence_invariant.sql",
        "evidence_root": "/var/lib/datacon/evidence",
    }
    with pytest.raises(release.ReleaseGateError, match="manifest_digest"):
        release.rollback_release(
            target_release=target,
            backend=_backend(),
            smoke_checks={"cli_smoke": lambda: True},
            approved_by="reviewer-1",
            candidate_digest="sha256:" + "6" * 64,
        )


def test_rollback_release_rejects_crossing_an_incompatible_migration(monkeypatch):
    target = {
        "image_id": "sha256:" + "7" * 64,
        "config": {"policy_version": "0"},
        "migration_version": "003_attempts_generation.sql",
        "evidence_root": "/var/lib/datacon/evidence",
        "manifest_digest": "sha256:" + "9" * 64,
    }
    backend = _backend()
    with pytest.raises(release.ReleaseGateError, match="backward-compatibility"):
        release.rollback_release(
            target_release=target,
            backend=backend,
            smoke_checks={"cli_smoke": lambda: True},
            approved_by="reviewer-1",
            candidate_digest="sha256:" + "6" * 64,
        )


def test_rollback_release_rejects_a_ledger_that_does_not_match():
    ledger = _ledger()
    ledger.pop("007_execution_evidence_invariant.sql")
    backend = release.DictPromotionBackend(
        active_release=_previous(), migrations=ledger
    )
    target = {
        "image_id": "sha256:" + "7" * 64,
        "config": {"policy_version": "0"},
        "migration_version": "007_execution_evidence_invariant.sql",
        "evidence_root": "/var/lib/datacon/evidence",
        "manifest_digest": "sha256:" + "9" * 64,
    }
    with pytest.raises(release.ReleaseGateError, match="not in the applied"):
        release.rollback_release(
            target_release=target,
            backend=backend,
            smoke_checks={"cli_smoke": lambda: True},
            approved_by="reviewer-1",
            candidate_digest="sha256:" + "6" * 64,
        )


def test_promotion_rejects_a_manifest_ledger_mismatch():
    manifest = _sample_rc_manifest()
    approval = _approval(manifest)
    ledger = _ledger()
    ledger["008_release_events.sql"] = "sha256:" + "0" * 64
    backend = release.DictPromotionBackend(
        active_release=_previous(), migrations=ledger
    )
    with pytest.raises(release.ReleaseGateError, match="migration ledger"):
        release.promote_and_smoke(
            manifest=manifest,
            expected_manifest_digest=approval["candidate_digest"],
            approval=approval,
            backend=backend,
            smoke_checks={"cli_smoke": lambda: True},
            rollback_fn=lambda prev: {"restored_image": prev["image_id"], "ok": True},
        )


def test_rollback_release_restores_target_config_and_migration():
    target = {
        "image_id": "sha256:" + "7" * 64,
        "config": {"policy_version": "0"},
        "migration_version": "007_execution_evidence_invariant.sql",
        "evidence_root": "/var/lib/datacon/evidence",
        "manifest_digest": "sha256:" + "9" * 64,
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


def test_rollback_release_rejects_active_execution_slots():
    target = {
        "image_id": "sha256:" + "7" * 64,
        "config": {"policy_version": "0"},
        "migration_version": "007_execution_evidence_invariant.sql",
        "evidence_root": "/var/lib/datacon/evidence",
        "manifest_digest": "sha256:" + "9" * 64,
    }
    with pytest.raises(release.ReleaseGateError, match="slot"):
        release.rollback_release(
            target_release=target,
            backend=_backend(slots=1),
            smoke_checks={"cli_smoke": lambda: True},
            approved_by="reviewer-1",
            candidate_digest="sha256:" + "6" * 64,
        )


def test_dict_backend_allows_repromotion_after_smoke_rollback():
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

    failed_once = release.promote_and_smoke(
        manifest=manifest,
        expected_manifest_digest=approval["candidate_digest"],
        approval=approval,
        backend=backend,
        smoke_checks={"cli_smoke": lambda: False},
        rollback_fn=rollback,
    )
    assert failed_once["status"] == "rolled_back"

    failed_twice = release.promote_and_smoke(
        manifest=manifest,
        expected_manifest_digest=approval["candidate_digest"],
        approval=approval,
        backend=backend,
        smoke_checks={"cli_smoke": lambda: False},
        rollback_fn=rollback,
    )
    assert failed_twice["status"] == "rolled_back"

    succeeded = release.promote_and_smoke(
        manifest=manifest,
        expected_manifest_digest=approval["candidate_digest"],
        approval=approval,
        backend=backend,
        smoke_checks={"cli_smoke": lambda: True},
        rollback_fn=rollback,
    )
    assert succeeded["status"] == "promoted"
    assert backend.active_release()["image_id"] == manifest["control_plane_image_id"]
    assert [audit["status"] for audit in backend.audits] == [
        "rolled_back",
        "rolled_back",
        "promoted",
    ]


def test_cli_release_slots_reads_active_slots_once(monkeypatch, capsys):
    from datacon import cli

    calls = 0

    class FlappingStore:
        def __init__(self, dsn, *, environment):
            pass

        def active_slots(self):
            nonlocal calls
            calls += 1
            return 1 if calls == 1 else 0

        def active_release(self):
            return {"image_id": "sha256:" + "8" * 64}

    monkeypatch.setenv("DATACON_DATABASE_URL", "postgresql://unused")
    monkeypatch.setattr(cli.state, "ReleaseStore", FlappingStore)
    code = cli.main(["release", "slots", "--environment", "internal-lab"])
    assert code == 0
    assert calls == 1
    output = json.loads(capsys.readouterr().out)
    assert output["active_slots"] == 1
    assert output["drained"] is False


def test_cli_release_bootstrap_persists_a_validated_baseline(monkeypatch, capsys):
    from datacon import cli

    captured: dict = {}

    class FakeStore:
        def __init__(self, dsn, *, environment):
            captured["dsn"] = dsn
            captured["environment"] = environment

        def bootstrap_release(self, **kwargs):
            captured.update(kwargs)

    monkeypatch.setenv("DATACON_DATABASE_URL", "postgresql://unused")
    monkeypatch.setattr(cli.state, "ReleaseStore", FakeStore)
    image = "sha256:" + "a" * 64
    code = cli.main(
        [
            "release",
            "bootstrap",
            "--image-id",
            image,
            "--migration-version",
            "008_release_events.sql",
            "--evidence-root",
            "/var/lib/datacon/evidence",
            "--config",
            '{"policy_version":"1"}',
        ]
    )
    assert code == 0
    assert captured["image_id"] == image
    assert captured["config"] == {"policy_version": "1"}
    output = json.loads(capsys.readouterr().out)
    assert output["baseline"] is True
    assert output["image_id"] == image

    bad = cli.main(
        [
            "release",
            "bootstrap",
            "--image-id",
            "sha256:short",
            "--migration-version",
            "008_release_events.sql",
            "--evidence-root",
            "/var/lib/datacon/evidence",
        ]
    )
    assert bad == 2


def test_cli_migrate_reports_the_applied_ledger(monkeypatch, capsys):
    from datacon import cli

    monkeypatch.setenv("DATACON_DATABASE_URL", "postgresql://unused")
    monkeypatch.setattr(
        cli.state,
        "apply_migrations_dsn",
        lambda dsn, migrations_dir: {
            "001_create_jobs.sql": "sha256:" + "1" * 64,
            "008_release_events.sql": "sha256:" + "8" * 64,
        },
    )
    code = cli.main(["migrate", "--migrations-dir", "migrations"])
    assert code == 0
    output = json.loads(capsys.readouterr().out)
    assert output["count"] == 2
    assert output["applied"] == [
        "001_create_jobs.sql",
        "008_release_events.sql",
    ]


def test_write_smoke_evidence_bundle_is_verifiable_and_world_readable(tmp_path):
    bundle_dir = tmp_path / "smoke-bundle"
    digest = release.write_smoke_evidence_bundle(
        bundle_dir, cases_dir=REPO_ROOT / "tests" / "fixtures" / "cases"
    )
    verified = evidence.verify_bundle(bundle_dir)
    assert verified.manifest_digest == digest
    assert verified.manifest["verdict"] == "REPRODUCED"
    assert (bundle_dir.stat().st_mode & 0o777) == 0o755
    assert ((bundle_dir / "manifest.json").stat().st_mode & 0o777) == 0o444


# ---------------------------------------------------------------------------
# B03 real-material acceptance
# ---------------------------------------------------------------------------


def _b03_case_root(tmp_path: Path) -> Path:
    root = tmp_path / "b03-case"
    root.mkdir(parents=True, exist_ok=True)
    for name in ("harness.c", "build.sh", "dependencies.lock", "fix.patch"):
        shutil.copy2(CASES / name, root / name)
    advisory = json.loads((CASES / "advisory.json").read_text(encoding="utf-8"))
    admission = json.loads(B03_PATH.read_text(encoding="utf-8"))
    advisory["cve_id"] = admission["cve_id"]
    advisory["vulnerable_commit"] = admission["versions"]["vulnerable"]["commit"]
    advisory["fixed_commit"] = admission["versions"]["fixed"]["commit"]
    for src in advisory.get("sources", []):
        src["vulnerable_commit"] = advisory["vulnerable_commit"]
        src["fixed_commit"] = advisory["fixed_commit"]
    (root / "advisory.json").write_text(json.dumps(advisory, indent=2) + "\n", encoding="utf-8")
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
    # The checked-in fixture is the real frozen lab record. These contract
    # tests use a synthetic fake sandbox, so pin the signature they exercise
    # instead of depending on the fixture's real ASan frame.
    admission["asan_signature"] = {
        "error": "heap-use-after-free",
        "function": "onig_new_deluxe",
        "source": "src/regext.c",
        "status": "frozen",
    }
    admission["expected_verdict_status"] = "frozen"
    admission["repository"]["source_path"] = "parser.c"
    admission["harness"]["candidate_clean_exit_code"] = 0
    admission["harness"]["expected_stdout"] = {
        "normal": "OK\n",
        "candidate_clean": "MISMATCH_REJECTED\n",
    }
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
        "decided_at": release._utc_now(),
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
                "errors": [],
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


def test_b03_pending_admission_is_rejected(tmp_path):
    # Build an explicit pending copy so this regression test does not depend on
    # whether the checked-in fixture has already been frozen by the lab.
    root = _b03_case_root(tmp_path)
    admission = _frozen_admission()
    admission["asan_signature"]["status"] = "expected_pending_t05_replay"
    admission["expected_verdict_status"] = "pending_t05_replay"
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


def test_b03_fixed_build_failure_cleans_up_vulnerable_artifact_and_staging_dirs(tmp_path):
    import os

    root = _b03_case_root(tmp_path)
    admission = _frozen_admission()
    review = _review_for(admission, root)

    class FailOnFixedSandbox(FakeB03Sandbox):
        def __init__(self, **kwargs):
            super().__init__(**kwargs)
            self.observed_modes: dict[str, int] = {}

        def build(self, version: str, **kwargs):
            materials_dir = Path(kwargs["materials_dir"])
            self.observed_modes["staging_root"] = materials_dir.stat().st_mode & 0o777
            self.observed_modes["build_sh"] = (materials_dir / "build.sh").stat().st_mode & 0o777
            self.observed_modes["input"] = (
                materials_dir / "inputs" / "normal.txt"
            ).stat().st_mode & 0o777
            if version == "fixed":
                return BuildResult(
                    version=version,
                    status="failed",
                    exit_code=1,
                    duration_seconds=0.5,
                    container_id="cid-fail-fixed",
                    image_digest=self.toolchain.split("@", 1)[1],
                    compile_args=tuple(kwargs.get("compile_args") or ()),
                    artifact_digest=None,
                    log=b"fixed build failed\n",
                    log_truncated=False,
                    artifact=b"",
                    metadata={"image_digest": self.toolchain.split("@", 1)[1]},
                )
            return super().build(version, **kwargs)

    out_dir = tmp_path / "out"
    out_dir.mkdir()
    sandbox = FailOnFixedSandbox(toolchain=admission["build"]["toolchain_image"])
    old_umask = os.umask(0o077)
    try:
        with pytest.raises(release.ReleaseGateError, match="fixed build did not complete"):
            release.run_b03_acceptance(
                admission=admission,
                sandbox=sandbox,
                normal_input=(root / "inputs" / "normal.txt").read_bytes(),
                candidate_input=(root / "inputs" / "candidate.txt").read_bytes(),
                bundle_out=out_dir / "b03-bundle",
                storage_ref="vault://datacon/private/b03/CVE-2019-13224/manifest.json",
                review=review,
                case_root=root,
            )
    finally:
        os.umask(old_umask)

    assert sandbox.observed_modes["staging_root"] == 0o755
    assert sandbox.observed_modes["build_sh"] == 0o444
    assert sandbox.observed_modes["input"] == 0o444
    leftovers = [p.name for p in out_dir.iterdir() if p.name.startswith(".b03-")]
    assert leftovers == []


def test_b03_multifile_source_trees_verify_and_detect_any_tampered_file(tmp_path):
    root = _b03_case_root(tmp_path)
    (root / "vulnerable" / "helper.c").write_text("int helper_v(void) { return 1; }\n", encoding="utf-8")
    (root / "fixed" / "helper.c").write_text("int helper_v(void) { return 2; }\n", encoding="utf-8")

    admission = _frozen_admission()
    admission["asan_signature"]["operation"] = "READ"
    admission["asan_signature"]["access_size"] = 4
    # This replay exercises multi-file staging with a partial signature, so the
    # deterministically computed verdict is INCONCLUSIVE rather than the default.
    admission["expected_verdict"] = "INCONCLUSIVE"
    review = _review_for(admission, root)

    prepared = release.prepare_b03_plan(
        admission=admission,
        materials=release.B03CaseMaterials.load(root),
        normal_input=(root / "inputs" / "normal.txt").read_bytes(),
        candidate_input=(root / "inputs" / "candidate.txt").read_bytes(),
    )
    assert prepared["asan_signature"]["operation"] == "READ"
    assert prepared["asan_signature"]["access_size"] == 4
    expected_lines = len((root / "vulnerable" / "parser.c").read_bytes().splitlines())
    assert prepared["plan"]["analysis"]["symbols"][0]["end_line"] == expected_lines

    import uuid as uuid_mod

    explicit_job_id = str(uuid_mod.uuid4())
    sandbox = FakeB03Sandbox(toolchain=admission["build"]["toolchain_image"])
    bundle_out = tmp_path / "b03-multifile-bundle"
    acceptance = release.run_b03_acceptance(
        admission=admission,
        sandbox=sandbox,
        normal_input=(root / "inputs" / "normal.txt").read_bytes(),
        candidate_input=(root / "inputs" / "candidate.txt").read_bytes(),
        bundle_out=bundle_out,
        storage_ref="vault://datacon/private/b03/CVE-2019-13224/manifest.json",
        review=review,
        case_root=root,
        job_id=explicit_job_id,
    )
    assert acceptance["bundle_verified"] is True
    verified = evidence.verify_bundle(bundle_out)
    assert verified.manifest["job_id"] == explicit_job_id
    assert (bundle_out / "materials" / "vulnerable" / "helper.c").is_file()
    assert (bundle_out / "materials" / "fixed" / "helper.c").is_file()

    # Tampering with ANY source file in the multi-file tree must trigger DIGEST_MISMATCH.
    (bundle_out / "materials" / "vulnerable" / "helper.c").write_bytes(b"int helper_v(void) { return 999; }\n")
    with pytest.raises(evidence.BundleError) as exc_info:
        evidence.verify_bundle(bundle_out)
    assert exc_info.value.reason_code == "DIGEST_MISMATCH"


def test_b03_rejects_malformed_admission_and_mismatched_advisory(tmp_path):
    root = _b03_case_root(tmp_path)
    materials = release.B03CaseMaterials.load(root)
    normal = (root / "inputs" / "normal.txt").read_bytes()
    candidate = (root / "inputs" / "candidate.txt").read_bytes()

    for mutator in (
        lambda adm: adm.pop("cve_id"),
        lambda adm: adm["asan_signature"].pop("error"),
        lambda adm: adm["asan_signature"].pop("function"),
        lambda adm: adm["asan_signature"].pop("source"),
        lambda adm: adm["build"].pop("toolchain_image"),
        lambda adm: adm["repository"].pop("url"),
        lambda adm: adm["advisory"].pop("nvd"),
        lambda adm: adm["harness"].__setitem__("normal_exit_code", True),
    ):
        broken = _frozen_admission()
        mutator(broken)
        with pytest.raises(release.ReleaseGateError):
            release.prepare_b03_plan(
                admission=broken,
                materials=materials,
                normal_input=normal,
                candidate_input=candidate,
            )

    # Mismatched CVE in advisory.json must be rejected.
    bad_cve_root = tmp_path / "bad-cve"
    bad_cve_root_case = _b03_case_root(bad_cve_root)
    adv = json.loads((bad_cve_root_case / "advisory.json").read_text(encoding="utf-8"))
    adv["cve_id"] = "CVE-2099-9999"
    (bad_cve_root_case / "advisory.json").write_text(json.dumps(adv), encoding="utf-8")
    with pytest.raises(release.ReleaseGateError, match="advisory"):
        release.prepare_b03_plan(
            admission=_frozen_admission(),
            materials=release.B03CaseMaterials.load(bad_cve_root_case),
            normal_input=normal,
            candidate_input=candidate,
        )

    # Mismatched commit in advisory.json must be rejected.
    bad_commit_root = tmp_path / "bad-commit"
    bad_commit_case = _b03_case_root(bad_commit_root)
    adv2 = json.loads((bad_commit_case / "advisory.json").read_text(encoding="utf-8"))
    adv2["fixed_commit"] = "0" * 40
    (bad_commit_case / "advisory.json").write_text(json.dumps(adv2), encoding="utf-8")
    with pytest.raises(release.ReleaseGateError, match="advisory"):
        release.prepare_b03_plan(
            admission=_frozen_admission(),
            materials=release.B03CaseMaterials.load(bad_commit_case),
            normal_input=normal,
            candidate_input=candidate,
        )


def test_manifest_rejects_future_created_at_and_nonconsecutive_migration_numbers():
    with pytest.raises(release.ReleaseGateError, match="future"):
        _sample_rc_manifest(created_at="2099-01-01T00:00:00Z")

    manifest = _sample_rc_manifest()
    broken = dict(manifest)
    broken["migrations"] = [manifest["migrations"][0], *manifest["migrations"][2:]]
    broken["migration_version"] = broken["migrations"][-1]["file"]
    with pytest.raises(release.ReleaseGateError, match="consecutively"):
        release.validate_release_candidate_manifest(broken)


def test_b03_inputs_symlink_is_rejected(tmp_path):
    root = _b03_case_root(tmp_path)
    (root / "inputs" / "normal.txt").unlink()
    (root / "inputs" / "normal.txt").symlink_to(root / "inputs" / "candidate.txt")
    with pytest.raises(release.ReleaseGateError, match="symlink"):
        release.B03CaseMaterials.load(root)


def test_b03_wrong_probe_values_fail_before_any_build_or_replay(tmp_path):
    root = _b03_case_root(tmp_path)
    admission = _frozen_admission()
    review = _review_for(admission, root)

    class BadProbeSandbox(FakeB03Sandbox):
        def __init__(self, **kwargs):
            super().__init__(**kwargs)
            self.build_calls = 0
            self.replay_calls = 0

        def probe(self, *, deadline_seconds: float = 120.0) -> ProbeReport:
            good = super().probe(deadline_seconds=deadline_seconds)
            checks = dict(good.checks)
            checks["uid"] = "0"
            return ProbeReport(
                ok=True,
                checks=checks,
                compiler_version=good.compiler_version,
                image_digest=good.image_digest,
                limits=dict(good.limits),
                raw=good.raw,
            )

        def build(self, version: str, **kwargs):
            self.build_calls += 1
            return super().build(version, **kwargs)

        def replay(self, version: str, phase: str, **kwargs):
            self.replay_calls += 1
            return super().replay(version, phase, **kwargs)

    sandbox = BadProbeSandbox(toolchain=admission["build"]["toolchain_image"])
    with pytest.raises(release.ReleaseGateError, match="uid=.*65534|isolation check"):
        _run_b03(tmp_path, admission, sandbox, review)
    assert sandbox.build_calls == 0
    assert sandbox.replay_calls == 0


def test_b03_empty_advisory_is_rejected(tmp_path):
    root = _b03_case_root(tmp_path)
    (root / "advisory.json").write_text("{}\n", encoding="utf-8")
    admission = _frozen_admission()
    with pytest.raises(release.ReleaseGateError, match="advisory"):
        release.prepare_b03_plan(
            admission=admission,
            materials=release.B03CaseMaterials.load(root),
            normal_input=(root / "inputs" / "normal.txt").read_bytes(),
            candidate_input=(root / "inputs" / "candidate.txt").read_bytes(),
        )


def test_b03_review_expiry_and_future_times_are_rejected(tmp_path):
    root = _b03_case_root(tmp_path)
    admission = _frozen_admission()
    valid_review = _review_for(admission, root)
    sandbox = FakeB03Sandbox(toolchain=admission["build"]["toolchain_image"])

    expired = dict(valid_review, decided_at="2020-01-01T00:00:00Z")
    with pytest.raises(release.ReleaseGateError, match="expired"):
        _run_b03(tmp_path, admission, sandbox, expired)

    future = dict(valid_review, decided_at="2099-01-01T00:00:00Z")
    with pytest.raises(release.ReleaseGateError, match="future"):
        _run_b03(tmp_path, admission, sandbox, future)


def test_b03_verdict_must_match_the_frozen_expected_verdict(tmp_path):
    root = _b03_case_root(tmp_path)
    admission = _frozen_admission()
    admission["expected_verdict"] = "NOT_REPRODUCED"
    review = _review_for(admission, root)
    sandbox = FakeB03Sandbox(toolchain=admission["build"]["toolchain_image"])
    with pytest.raises(release.ReleaseGateError, match="expected_verdict"):
        _run_b03(tmp_path, admission, sandbox, review)


def test_b03_total_file_cap_fails_closed(tmp_path, monkeypatch):
    root = _b03_case_root(tmp_path)
    monkeypatch.setattr(release, "_MAX_B03_TOTAL_FILES", 3)
    with pytest.raises(release.ReleaseGateError, match="file cap"):
        release.B03CaseMaterials.load(root)


def test_b03_probe_mismatched_limits_or_errors_fail_before_build_or_replay(tmp_path):
    root = _b03_case_root(tmp_path)
    admission = _frozen_admission()
    review = _review_for(admission, root)

    class CustomProbeSandbox(FakeB03Sandbox):
        def __init__(self, *, limits=None, checks_extra=None, **kwargs):
            super().__init__(**kwargs)
            self._limits = limits
            self._checks_extra = checks_extra or {}
            self.build_calls = 0
            self.replay_calls = 0

        def probe(self, *, deadline_seconds: float = 120.0) -> ProbeReport:
            good = super().probe(deadline_seconds=deadline_seconds)
            checks = dict(good.checks)
            checks.update(self._checks_extra)
            return ProbeReport(
                ok=True,
                checks=checks,
                compiler_version=good.compiler_version,
                image_digest=good.image_digest,
                limits=dict(good.limits) if self._limits is None else self._limits,
                raw=good.raw,
            )

        def build(self, version: str, **kwargs):
            self.build_calls += 1
            return super().build(version, **kwargs)

        def replay(self, version: str, phase: str, **kwargs):
            self.replay_calls += 1
            return super().replay(version, phase, **kwargs)

    wrong_cpu = CustomProbeSandbox(
        toolchain=admission["build"]["toolchain_image"],
        limits={"cpu": 1, "memory_mib": 2048, "pids": 128, "scratch_mib": 512},
    )
    with pytest.raises(release.ReleaseGateError, match="limits"):
        _run_b03(tmp_path, admission, wrong_cpu, review)
    assert wrong_cpu.build_calls == 0
    assert wrong_cpu.replay_calls == 0

    bool_cpu = CustomProbeSandbox(
        toolchain=admission["build"]["toolchain_image"],
        limits={"cpu": True, "memory_mib": 2048, "pids": 128, "scratch_mib": 512},
    )
    with pytest.raises(release.ReleaseGateError, match="limits"):
        _run_b03(tmp_path, admission, bool_cpu, review)
    assert bool_cpu.build_calls == 0
    assert bool_cpu.replay_calls == 0

    probe_errors = CustomProbeSandbox(
        toolchain=admission["build"]["toolchain_image"],
        checks_extra={"errors": ["seccomp mode mismatch"]},
    )
    with pytest.raises(release.ReleaseGateError, match="errors"):
        _run_b03(tmp_path, admission, probe_errors, review)
    assert probe_errors.build_calls == 0
    assert probe_errors.replay_calls == 0


def test_b03_checks_reject_deferred_critical_checks_and_require_pass(tmp_path):
    root = _b03_case_root(tmp_path)
    materials = release.B03CaseMaterials.load(root)
    normal = (root / "inputs" / "normal.txt").read_bytes()
    candidate = (root / "inputs" / "candidate.txt").read_bytes()

    for check_id in (
        "public_advisory",
        "fixed_commit",
        "offline_build",
        "license",
        "shared_harness",
    ):
        deferred = _frozen_admission()
        for entry in deferred["checks"]:
            if entry["id"] == check_id:
                entry["status"] = "deferred"
                entry["owner_task"] = "T08"
        with pytest.raises(release.ReleaseGateError, match=check_id):
            release.prepare_b03_plan(
                admission=deferred,
                materials=materials,
                normal_input=normal,
                candidate_input=candidate,
            )

        missing = _frozen_admission()
        missing["checks"] = [
            entry for entry in missing["checks"] if entry["id"] != check_id
        ]
        with pytest.raises(release.ReleaseGateError, match=check_id):
            release.prepare_b03_plan(
                admission=missing,
                materials=materials,
                normal_input=normal,
                candidate_input=candidate,
            )


def test_b03_requires_explicit_harness_stdout_and_clean_exit_code(tmp_path):
    root = _b03_case_root(tmp_path)
    materials = release.B03CaseMaterials.load(root)
    normal = (root / "inputs" / "normal.txt").read_bytes()
    candidate = (root / "inputs" / "candidate.txt").read_bytes()

    no_stdout = _frozen_admission()
    no_stdout["harness"].pop("expected_stdout")
    with pytest.raises(release.ReleaseGateError, match="expected_stdout"):
        release.prepare_b03_plan(
            admission=no_stdout,
            materials=materials,
            normal_input=normal,
            candidate_input=candidate,
        )

    no_clean_exit = _frozen_admission()
    no_clean_exit["harness"].pop("candidate_clean_exit_code")
    with pytest.raises(release.ReleaseGateError, match="candidate_clean_exit_code"):
        release.prepare_b03_plan(
            admission=no_clean_exit,
            materials=materials,
            normal_input=normal,
            candidate_input=candidate,
        )

    custom = _frozen_admission()
    custom["harness"]["candidate_clean_exit_code"] = 7
    custom["harness"]["expected_stdout"] = {
        "normal": "CUSTOM_NORMAL\n",
        "candidate_clean": "CUSTOM_CLEAN\n",
    }
    prepared = release.prepare_b03_plan(
        admission=custom,
        materials=materials,
        normal_input=normal,
        candidate_input=candidate,
    )
    assert prepared["expected_exit"]["candidate_clean"] == 7
    assert prepared["expected_stdout"] == {
        "normal": "CUSTOM_NORMAL\n",
        "candidate_clean": "CUSTOM_CLEAN\n",
    }

    class CustomStdoutSandbox(FakeB03Sandbox):
        def replay(self, version: str, phase: str, **kwargs) -> ReplayResult:
            res = super().replay(version, phase, **kwargs)
            if phase == "normal":
                return ReplayResult(
                    version=res.version,
                    phase=res.phase,
                    status=res.status,
                    exit_code=0,
                    duration_seconds=res.duration_seconds,
                    container_id=res.container_id,
                    input_digest=res.input_digest,
                    stdout=b"CUSTOM_NORMAL\n",
                    stderr=res.stderr,
                    signature=res.signature,
                    timed_out=res.timed_out,
                    quota_hit=res.quota_hit,
                    log_truncated=res.log_truncated,
                    metadata=res.metadata,
                )
            if version == "fixed":
                return ReplayResult(
                    version=res.version,
                    phase=res.phase,
                    status=res.status,
                    exit_code=7,
                    duration_seconds=res.duration_seconds,
                    container_id=res.container_id,
                    input_digest=res.input_digest,
                    stdout=b"CUSTOM_CLEAN\n",
                    stderr=res.stderr,
                    signature=res.signature,
                    timed_out=res.timed_out,
                    quota_hit=res.quota_hit,
                    log_truncated=res.log_truncated,
                    metadata=res.metadata,
                )
            return res

    review = _review_for(custom, root)
    acceptance = _run_b03(
        tmp_path,
        custom,
        CustomStdoutSandbox(toolchain=custom["build"]["toolchain_image"]),
        review,
    )
    assert acceptance["verdict"] == "REPRODUCED"


def test_single_environment_and_identical_release_guard(monkeypatch, capsys):
    from datacon import cli, state

    with pytest.raises(state.ReleaseStateError, match="internal-lab"):
        state.ReleaseStore("postgresql://unused", environment="prod")

    monkeypatch.setenv("DATACON_DATABASE_URL", "postgresql://unused")
    for argv in (
        ["release", "slots", "--environment", "prod"],
        [
            "release",
            "bootstrap",
            "--environment",
            "prod",
            "--image-id",
            "sha256:" + "a" * 64,
            "--migration-version",
            "008_release_events.sql",
            "--evidence-root",
            "/var/lib/datacon/evidence",
        ],
    ):
        assert cli.main(argv) == 2
        err = json.loads(capsys.readouterr().err)
        assert err["reason_code"] == "INVALID_RELEASE_STATE"

    manifest = _sample_rc_manifest()
    approval = _approval(manifest)
    identical_previous = {
        "image_id": manifest["control_plane_image_id"],
        "config": {
            "contract_version": manifest["contract_version"],
            "migration_version": manifest["migration_version"],
        },
        "migration_version": manifest["migration_version"],
        "evidence_root": "/var/lib/datacon/evidence",
    }
    backend = _backend(previous=identical_previous)
    with pytest.raises(release.ReleaseGateError, match="identical|active release"):
        release.promote_and_smoke(
            manifest=manifest,
            expected_manifest_digest=approval["candidate_digest"],
            approval=approval,
            backend=backend,
            smoke_checks={"cli_smoke": lambda: True},
            rollback_fn=lambda prev: {"restored_image": prev["image_id"], "ok": True},
        )


def test_validate_evidence_bundle_path_enforces_containment_and_no_symlinks(tmp_path):
    from datacon import state

    evidence_root = tmp_path / "evidence"
    evidence_root.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    valid = evidence_root / "job-1" / "generation-1"
    valid.mkdir(parents=True)

    resolved = state._validate_evidence_bundle_path(str(valid), str(evidence_root))
    assert resolved == valid.resolve()

    # Hosted VM scenario: evidence_root does not exist locally, but path is lexically inside.
    remote_root = "/var/lib/datacon/remote-evidence"
    remote_bundle = f"{remote_root}/job-1/generation-1"
    remote_resolved = state._validate_evidence_bundle_path(remote_bundle, remote_root)
    assert str(remote_resolved).endswith("remote-evidence/job-1/generation-1")

    # Symlink inside evidence_root is rejected.
    sym = evidence_root / "sym-job"
    sym.symlink_to(outside)
    with pytest.raises(state.ReleaseStateError, match="symlink|evidence_path"):
        state._validate_evidence_bundle_path(str(sym / "generation-1"), str(evidence_root))

    # Symlink as evidence_root itself is rejected.
    sym_root = tmp_path / "sym-root"
    sym_root.symlink_to(evidence_root)
    with pytest.raises(state.ReleaseStateError, match="symlink"):
        state._validate_evidence_bundle_path(str(sym_root / "job-1"), str(sym_root))

    # Symlink in an ancestor directory of evidence_root is rejected.
    sym_parent = tmp_path / "sym-parent"
    sym_parent.symlink_to(tmp_path)
    nested_root = sym_parent / "evidence"
    with pytest.raises(state.ReleaseStateError, match="symlink"):
        state._validate_evidence_bundle_path(str(nested_root / "job-1"), str(nested_root))

    # Parent traversal and outside paths are rejected.
    with pytest.raises(state.ReleaseStateError, match="traversal|escape|evidence_path"):
        state._validate_evidence_bundle_path(
            f"{evidence_root}/../outside", str(evidence_root)
        )
    with pytest.raises(state.ReleaseStateError, match="inside|evidence_path"):
        state._validate_evidence_bundle_path(str(outside), str(evidence_root))

    # Relative evidence_path must never be silently re-rooted under evidence_root.
    with pytest.raises(state.ReleaseStateError, match="relative|absolute|evidence_path"):
        state._validate_evidence_bundle_path(
            ".datacon/evidence/job-1/generation-1", str(evidence_root)
        )


def test_b03_tightened_boundaries_probe_errors_status_toolchain_and_inputs(tmp_path):
    root = _b03_case_root(tmp_path)
    materials = release.B03CaseMaterials.load(root)
    normal = (root / "inputs" / "normal.txt").read_bytes()
    candidate = (root / "inputs" / "candidate.txt").read_bytes()

    # 1. Explicit status allowlist rejects unapproved status values.
    unknown_status = _frozen_admission()
    unknown_status["status"] = "pending_review"
    with pytest.raises(release.ReleaseGateError, match="status"):
        release.prepare_b03_plan(
            admission=unknown_status,
            materials=materials,
            normal_input=normal,
            candidate_input=candidate,
        )

    # 2. Full toolchain_image must match TOOLCHAIN_IMAGE, not only the digest suffix.
    spoofed_repo = _frozen_admission()
    spoofed_repo["build"]["toolchain_image"] = (
        "evil.invalid/backdoor@" + release.TOOLCHAIN_IMAGE_DIGEST
    )
    with pytest.raises(release.ReleaseGateError, match="toolchain"):
        release.prepare_b03_plan(
            admission=spoofed_repo,
            materials=materials,
            normal_input=normal,
            candidate_input=candidate,
        )

    # 3. Missing checks['errors'] in probe must fail closed before build/replay.
    admission = _frozen_admission()
    review = _review_for(admission, root)

    class MissingErrorsProbeSandbox(FakeB03Sandbox):
        def __init__(self, **kwargs):
            super().__init__(**kwargs)
            self.build_calls = 0

        def probe(self, *, deadline_seconds: float = 120.0) -> ProbeReport:
            good = super().probe(deadline_seconds=deadline_seconds)
            checks = dict(good.checks)
            checks.pop("errors", None)
            return ProbeReport(
                ok=True,
                checks=checks,
                compiler_version=good.compiler_version,
                image_digest=good.image_digest,
                limits=dict(good.limits),
                raw=good.raw,
            )

        def build(self, version: str, **kwargs):
            self.build_calls += 1
            return super().build(version, **kwargs)

    missing_err_sb = MissingErrorsProbeSandbox(
        toolchain=admission["build"]["toolchain_image"]
    )
    with pytest.raises(release.ReleaseGateError, match="errors"):
        _run_b03(tmp_path, admission, missing_err_sb, review)
    assert missing_err_sb.build_calls == 0

    # 4. run_b03_acceptance rejects input bytes that differ from case_root on disk.
    with pytest.raises(release.ReleaseGateError, match="normal_input"):
        release.run_b03_acceptance(
            admission=admission,
            sandbox=FakeB03Sandbox(toolchain=admission["build"]["toolchain_image"]),
            normal_input=b"tampered-normal\n",
            candidate_input=candidate,
            bundle_out=tmp_path / "b03-bad-normal",
            storage_ref="vault://datacon/private/b03/CVE-2019-13224/manifest.json",
            review=review,
            case_root=root,
        )
    with pytest.raises(release.ReleaseGateError, match="candidate_input"):
        release.run_b03_acceptance(
            admission=admission,
            sandbox=FakeB03Sandbox(toolchain=admission["build"]["toolchain_image"]),
            normal_input=normal,
            candidate_input=b"tampered-candidate\n",
            bundle_out=tmp_path / "b03-bad-candidate",
            storage_ref="vault://datacon/private/b03/CVE-2019-13224/manifest.json",
            review=review,
            case_root=root,
        )


def test_promote_preflight_runs_outside_transaction_and_rollback_post_switch_checks():
    from contextlib import contextmanager

    manifest = _sample_rc_manifest()
    approval = _approval(manifest)
    events: list[str] = []

    class TrackingBackend(release.DictPromotionBackend):
        @contextmanager
        def transaction(self):
            events.append("tx_enter")
            try:
                with super().transaction():
                    yield self
            finally:
                events.append("tx_exit")

    backend = TrackingBackend(active_release=_previous(), migrations=_ledger())
    result = release.promote_and_smoke(
        manifest=manifest,
        expected_manifest_digest=approval["candidate_digest"],
        approval=approval,
        backend=backend,
        preflight_checks={
            "cli_smoke": lambda: events.append("preflight_cli") is None,
        },
        smoke_checks={
            "db_readability": lambda: events.append("tx_smoke_db") is None,
        },
        rollback_fn=lambda prev: {"restored_image": prev["image_id"], "ok": True},
    )
    assert result["status"] == "promoted"
    assert events.index("preflight_cli") < events.index("tx_enter")
    assert events.index("tx_enter") < events.index("tx_smoke_db") < events.index("tx_exit")
    assert result["smoke_results"]["cli_smoke"] is True
    assert result["smoke_results"]["db_readability"] is True

    # A failing preflight check blocks promotion before entering transaction().
    events.clear()
    backend2 = TrackingBackend(active_release=_previous(), migrations=_ledger())
    with pytest.raises(release.ReleaseGateError, match="preflight"):
        release.promote_and_smoke(
            manifest=manifest,
            expected_manifest_digest=approval["candidate_digest"],
            approval=approval,
            backend=backend2,
            preflight_checks={"cli_smoke": lambda: False},
            smoke_checks={"db_readability": lambda: True},
            rollback_fn=lambda prev: {"restored_image": prev["image_id"], "ok": True},
        )
    assert events == []

    # rollback_release supports post_switch_checks and rolls back transaction on failure.
    target = _previous()
    with pytest.raises(release.ReleaseGateError, match="post-switch"):
        release.rollback_release(
            target_release=target,
            backend=backend,
            smoke_checks={"cli_smoke": lambda: True},
            post_switch_checks={"slots_check": lambda: False},
            approved_by="reviewer-1",
            candidate_digest=approval["candidate_digest"],
        )
    assert backend.active_release()["image_id"] == manifest["control_plane_image_id"]


def test_rollback_release_rejects_target_equal_to_active():
    active = {
        "image_id": "sha256:" + "a" * 64,
        "config": {"contract_version": 1, "migration_version": "008_release_events.sql"},
        "migration_version": "008_release_events.sql",
        "evidence_root": "/var/lib/datacon/evidence",
    }
    backend = release.DictPromotionBackend(
        active_release=active,
        migrations=_ledger(),
    )
    with pytest.raises(release.ReleaseGateError, match="already the active release"):
        release.rollback_release(
            target_release=dict(active),
            backend=backend,
            smoke_checks={"db": lambda: True},
            post_switch_checks={"active": lambda: True},
            approved_by="ops",
            candidate_digest="sha256:" + "e" * 64,
            manifest_digest="sha256:" + "f" * 64,
        )
    assert backend.switches == []
    assert backend.audits == []
    assert backend.active_release() == active

    # Concurrent switch during smoke_checks makes in-tx `latest` equal to `target`.
    # Even bypassing the pre-smoke check, the in-transaction guard must fail with
    # "already the active release" rather than switching or recording an audit.
    target = {
        "image_id": "sha256:" + "b" * 64,
        "config": {"contract_version": 1, "migration_version": "008_release_events.sql"},
        "migration_version": "008_release_events.sql",
        "evidence_root": "/var/lib/datacon/evidence",
    }
    raced_backend = release.DictPromotionBackend(
        active_release=active,
        migrations=_ledger(),
    )
    switches_before_race: list[dict] = []

    def concurrent_switch_during_smoke():
        raced_backend.switch(
            image_id=target["image_id"],
            config=target["config"],
            migration_version=target["migration_version"],
            evidence_root=target["evidence_root"],
            action="rollback",
            candidate_digest="sha256:" + "d" * 64,
        )
        switches_before_race.append(dict(raced_backend.switches[-1]))
        return True

    with pytest.raises(release.ReleaseGateError, match="already the active release"):
        release.rollback_release(
            target_release=dict(target),
            backend=raced_backend,
            smoke_checks={"concurrent": concurrent_switch_during_smoke},
            post_switch_checks={"active": lambda: True},
            approved_by="ops",
            candidate_digest="sha256:" + "e" * 64,
            manifest_digest="sha256:" + "f" * 64,
        )
    assert len(raced_backend.switches) == len(switches_before_race) == 1
    assert raced_backend.audits == []


def test_rollback_pre_switch_container_check_failure_leaves_active_unchanged():
    previous = _previous()
    backend = _backend(previous=previous)
    manifest = _sample_rc_manifest()
    approval = _approval(manifest)
    promoted = release.promote_and_smoke(
        manifest=manifest,
        expected_manifest_digest=approval["candidate_digest"],
        approval=approval,
        backend=backend,
        smoke_checks={"cli_smoke": lambda: True},
        rollback_fn=lambda prev: {"restored_image": prev["image_id"], "ok": True},
    )
    assert promoted["status"] == "promoted"
    switches_before = len(backend.switches)
    audits_before = len(backend.audits)

    with pytest.raises(release.ReleaseGateError, match="release_slots"):
        release.rollback_release(
            target_release=previous,
            backend=backend,
            smoke_checks={
                "cli_smoke": lambda: True,
                "release_slots": lambda: False,
            },
            post_switch_checks={"active_release_restored": lambda: True},
            approved_by="ops",
            candidate_digest=approval["candidate_digest"],
        )
    assert len(backend.switches) == switches_before
    assert len(backend.audits) == audits_before
    assert backend.active_release()["image_id"] == manifest["control_plane_image_id"]


def test_promote_requires_real_archived_bundle_when_strict(tmp_path):
    from datacon import state

    missing_root = tmp_path / "unmounted-evidence"

    class _FakeBundleStore:
        def __init__(self, bundle: dict[str, str] | None):
            self.bundle = bundle
            self.strict_calls: list[bool] = []

        def latest_evidence_bundle(
            self, *, require_active_root: bool = True, strict: bool = False
        ):
            self.strict_calls.append(strict)
            if not require_active_root:
                return self.bundle
            if self.bundle is None and strict:
                raise state.ReleaseStateError(
                    "no archived evidence bundle found under active evidence_root"
                )
            return self.bundle

    skip_approval = {
        "approved_by": "ops",
        "allow_skip_archived_bundle": True,
        "archived_bundle_skip_reason": "initial bootstrap environment without archived jobs",
    }

    with pytest.raises(release.ReleaseGateError, match="evidence volume mounted"):
        release.archived_bundle_preflight(
            evidence_root=missing_root,
            store=_FakeBundleStore(None),
            verify_fn=lambda path, digest: True,
        )

    skipped = release.archived_bundle_preflight(
        evidence_root=missing_root,
        store=_FakeBundleStore(None),
        verify_fn=lambda path, digest: True,
        require_archived_bundle=False,
        skip_reason="initial bootstrap environment without archived jobs",
        approval=skip_approval,
    )
    assert skipped["status"] == "skipped"
    assert "initial bootstrap" in skipped["reason"]
    assert skipped["check_fn"] is None

    # Mounted evidence_root with NO archived bundle must call latest_evidence_bundle(strict=True)
    # and fail closed instead of silently passing strict=False.
    mounted_empty = tmp_path / "mounted-empty-evidence"
    mounted_empty.mkdir()
    empty_store = _FakeBundleStore(None)
    with pytest.raises((release.ReleaseGateError, state.ReleaseStateError), match="no archived evidence bundle"):
        release.archived_bundle_preflight(
            evidence_root=mounted_empty,
            store=empty_store,
            verify_fn=lambda path, digest: True,
            require_archived_bundle=True,
        )
    assert empty_store.strict_calls == [True]

    evidence_root = tmp_path / "mounted-evidence"
    bundle_dir = evidence_root / "job-1" / "generation-1"
    bundle_dir.mkdir(parents=True)
    digest = "sha256:" + "a" * 64
    found = release.archived_bundle_preflight(
        evidence_root=evidence_root,
        store=_FakeBundleStore({"path": str(bundle_dir), "digest": digest}),
        verify_fn=lambda path, d: path == str(bundle_dir) and d == digest,
    )
    assert found["status"] == "required"
    assert found["bundle_path"] == str(bundle_dir)
    assert found["bundle_digest"] == digest
    assert found["check_fn"]() is True


def test_archived_bundle_preflight_rejects_ancestor_symlink_and_active_root_mismatch(tmp_path):
    real_parent = tmp_path / "real-parent"
    real_parent.mkdir()
    sym_parent = tmp_path / "sym-parent"
    sym_parent.symlink_to(real_parent)
    sym_root = sym_parent / "evidence"
    real_bundle = real_parent / "evidence" / "job-1" / "gen-1"
    real_bundle.mkdir(parents=True)

    class _ActiveStore:
        def __init__(self, active_root: str, bundle: dict[str, str] | None = None):
            self._active_root = active_root
            self._bundle = bundle

        def active_release(self):
            return {
                "image_id": "sha256:" + "a" * 64,
                "config": {"policy_version": "1"},
                "migration_version": "008_release_events.sql",
                "evidence_root": self._active_root,
            }

        def latest_evidence_bundle(
            self, *, require_active_root: bool = True, strict: bool = False
        ):
            return self._bundle

    with pytest.raises(release.ReleaseGateError, match="symlink"):
        release.archived_bundle_preflight(
            evidence_root=sym_root,
            store=_ActiveStore(
                str(sym_root),
                {
                    "path": str(sym_root / "job-1" / "gen-1"),
                    "digest": "sha256:" + "a" * 64,
                },
            ),
            verify_fn=lambda path, d: True,
        )

    actual_root = tmp_path / "actual-evidence"
    actual_root.mkdir()
    other_root = tmp_path / "other-evidence"
    other_root.mkdir()
    with pytest.raises(release.ReleaseGateError, match="evidence_root"):
        release.archived_bundle_preflight(
            evidence_root=other_root,
            store=_ActiveStore(str(actual_root)),
            verify_fn=lambda path, d: True,
            require_archived_bundle=False,
            skip_reason="should fail before skipping",
        )


def test_persist_b03_evidence_bundle_rejects_symlink_ancestor(tmp_path):
    root = _b03_case_root(tmp_path)
    admission = _frozen_admission()
    review = _review_for(admission, root)
    bundle_out = tmp_path / "temp-bundle-sym"
    acceptance = release.run_b03_acceptance(
        admission=admission,
        sandbox=FakeB03Sandbox(toolchain=admission["build"]["toolchain_image"]),
        normal_input=(root / "inputs" / "normal.txt").read_bytes(),
        candidate_input=(root / "inputs" / "candidate.txt").read_bytes(),
        bundle_out=bundle_out,
        storage_ref="vault://datacon/private/b03/CVE-2019-13224/manifest.json",
        review=review,
        case_root=root,
        job_id="11111111-1111-4111-8111-111111111111",
    )
    real_parent = tmp_path / "real-b03"
    real_parent.mkdir()
    sym_parent = tmp_path / "sym-b03"
    sym_parent.symlink_to(real_parent)
    with pytest.raises(release.ReleaseGateError, match="symlink"):
        release.persist_b03_evidence_bundle(
            bundle_out,
            persist_root=sym_parent / "persistent-b03",
            job_id="11111111-1111-4111-8111-111111111111",
            expected_manifest_digest=acceptance["manifest_digest"],
        )


def test_latest_evidence_bundle_require_active_root_false_validates_all_rows(monkeypatch):
    from datacon import state

    rows = [
        {
            "evidence_path": "/var/lib/datacon/evidence/job-1/gen-1",
            "evidence_digest": "sha256:" + "a" * 64,
        },
        {
            "evidence_path": ".datacon/relative/job-0/gen-1",
            "evidence_digest": "sha256:" + "b" * 64,
        },
    ]

    class _FakeConn:
        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

        def execute(self, query, params=None):
            class _Cursor:
                def fetchone(self):
                    if "to_regclass" in query:
                        return {
                            "migrations_tbl": "schema_migrations",
                            "release_tbl": "release_state",
                            "events_tbl": "release_events",
                        }
                    return None

                def fetchall(self):
                    if "FROM jobs" in query:
                        return rows
                    return []

            return _Cursor()

    store_handle = state.ReleaseStore("postgresql://unused")
    monkeypatch.setattr(store_handle, "_connect", lambda: _FakeConn())
    with pytest.raises(state.ReleaseStateError, match="absolute|evidence_path"):
        store_handle.latest_evidence_bundle(require_active_root=False)


def test_release_store_connection_ensures_release_tables_and_cli_slots_exits_2(
    monkeypatch, capsys
):
    from datacon import cli, state

    class _EmptySchemaConnection:
        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

        def execute(self, query, params=None):
            class _Cursor:
                def fetchone(self):
                    if "to_regclass" in query:
                        return {
                            "migrations_tbl": None,
                            "release_tbl": None,
                            "events_tbl": None,
                        }
                    raise AssertionError(f"unexpected query on unmigrated DB: {query}")

            return _Cursor()

    store_handle = state.ReleaseStore("postgresql://unused")
    monkeypatch.setattr(store_handle, "_connect", lambda: _EmptySchemaConnection())
    for method in (
        store_handle.active_slots,
        store_handle.active_release,
        store_handle.events,
        lambda: store_handle.promotion_for("sha256:" + "a" * 64),
        lambda: store_handle.release_for_image("sha256:" + "a" * 64),
        store_handle.latest_evidence_bundle,
    ):
        with pytest.raises(state.ReleaseStateError, match="datacon migrate"):
            method()

    class _UnmigratedStore:
        def __init__(self, dsn, *, environment):
            pass

        def active_slots(self):
            raise state.ReleaseStateError(
                "release tables are missing; run `datacon migrate`"
            )

    monkeypatch.setenv("DATACON_DATABASE_URL", "postgresql://unused")
    monkeypatch.setattr(cli.state, "ReleaseStore", _UnmigratedStore)
    rc = cli.main(["release", "slots", "--environment", "internal-lab"])
    assert rc == 2
    err = json.loads(capsys.readouterr().err)
    assert err["reason_code"] == "INVALID_RELEASE_STATE"
    assert "datacon migrate" in err["message"]


def test_persist_b03_evidence_bundle_copies_verifies_and_detects_tampering(tmp_path):
    from datacon import evidence

    root = _b03_case_root(tmp_path)
    admission = _frozen_admission()
    review = _review_for(admission, root)
    bundle_out = tmp_path / "temp-bundle"
    acceptance = release.run_b03_acceptance(
        admission=admission,
        sandbox=FakeB03Sandbox(toolchain=admission["build"]["toolchain_image"]),
        normal_input=(root / "inputs" / "normal.txt").read_bytes(),
        candidate_input=(root / "inputs" / "candidate.txt").read_bytes(),
        bundle_out=bundle_out,
        storage_ref="vault://datacon/private/b03/CVE-2019-13224/manifest.json",
        review=review,
        case_root=root,
        job_id="11111111-1111-4111-8111-111111111111",
    )
    persist_root = tmp_path / "persistent-b03"
    persisted = release.persist_b03_evidence_bundle(
        bundle_out,
        persist_root=persist_root,
        job_id="11111111-1111-4111-8111-111111111111",
        expected_manifest_digest=acceptance["manifest_digest"],
    )
    shutil.rmtree(bundle_out)
    persisted_dir = Path(persisted["bundle_path"])
    assert persisted_dir.is_dir()
    assert persisted["bundle_verified"] is True
    assert persisted["bundle_manifest_digest"] == acceptance["manifest_digest"]
    verified = evidence.verify_bundle(persisted_dir)
    assert verified.manifest_digest == acceptance["manifest_digest"]

    # Tampering a persisted file must cause verify_bundle to fail closed.
    target_file = persisted_dir / "report.md"
    target_file.write_text(target_file.read_text(encoding="utf-8") + "tampered\n", encoding="utf-8")
    with pytest.raises(evidence.BundleError):
        evidence.verify_bundle(persisted_dir)


def test_b03_pass_checks_require_nonempty_evidence():
    with pytest.raises(release.ReleaseGateError, match="evidence"):
        release._validate_b03_checks(
            {
                "public_advisory": "pass",
                "fixed_commit": "pass",
                "offline_build": "pass",
                "license": "pass",
                "shared_harness": "pass",
            }
        )
    for bad_evidence in (None, "", "   "):
        checks = json.loads(B03_PATH.read_text(encoding="utf-8"))["checks"]
        if bad_evidence is None:
            checks[0].pop("evidence", None)
        else:
            checks[0]["evidence"] = bad_evidence
        with pytest.raises(release.ReleaseGateError, match="evidence"):
            release._validate_b03_checks(checks)

    valid_checks = json.loads(B03_PATH.read_text(encoding="utf-8"))["checks"]
    release._validate_b03_checks(valid_checks)


def test_review_bundle_readability_requires_65534_readable_files_and_dirs(tmp_path):
    bundle = tmp_path / "bundle"
    bundle.mkdir()
    review = bundle / "review.json"
    review.write_text('{"decision":"approve"}\n', encoding="utf-8")

    bundle.chmod(0o755)
    review.chmod(0o644)
    digest = release.verify_review_bundle_readability(bundle)
    assert digest == release._sha256_file(review)

    review.chmod(0o444)
    assert release.verify_review_bundle_readability(bundle) == digest

    review.chmod(0o600)
    with pytest.raises(release.ReleaseGateError, match="readable|mode"):
        release.verify_review_bundle_readability(bundle)

    review.chmod(0o644)
    bundle.chmod(0o700)
    with pytest.raises(release.ReleaseGateError, match="traversable|mode"):
        release.verify_review_bundle_readability(bundle)

    bundle.chmod(0o755)
    review.unlink()
    review.symlink_to(tmp_path / "outside-review.json")
    with pytest.raises(release.ReleaseGateError, match="symlink"):
        release.verify_review_bundle_readability(bundle)

    review.unlink()
    with pytest.raises(release.ReleaseGateError, match="missing review.json"):
        release.verify_review_bundle_readability(bundle)


def test_archived_bundle_preflight_rejects_unreadable_bundle_permissions_before_container(
    tmp_path,
):
    evidence_root = tmp_path / "mounted-evidence"
    bundle_dir = evidence_root / "job-1" / "generation-1"
    bundle_dir.mkdir(parents=True)
    manifest_file = bundle_dir / "manifest.json"
    manifest_file.write_text("{}", encoding="utf-8")

    class _Store:
        def latest_evidence_bundle(self, *, require_active_root=True, strict=False):
            return {"path": str(bundle_dir), "digest": "sha256:" + "a" * 64}

    verify_calls = 0

    def counting_verify(path, digest):
        nonlocal verify_calls
        verify_calls += 1
        return True

    # Private file 0o600 must fail closed before entering the container.
    manifest_file.chmod(0o600)
    with pytest.raises(release.ReleaseGateError, match="65534|permission|mode|readable"):
        release.archived_bundle_preflight(
            evidence_root=evidence_root,
            store=_Store(),
            verify_fn=counting_verify,
        )
    assert verify_calls == 0

    # Private directory 0o700 must also fail closed before entering the container.
    manifest_file.chmod(0o644)
    bundle_dir.chmod(0o700)
    try:
        with pytest.raises(release.ReleaseGateError, match="65534|permission|mode|traversable"):
            release.archived_bundle_preflight(
                evidence_root=evidence_root,
                store=_Store(),
                verify_fn=counting_verify,
            )
        assert verify_calls == 0
    finally:
        bundle_dir.chmod(0o755)


def test_persist_b03_evidence_bundle_uses_shared_readonly_permissions(tmp_path):
    import os
    import stat

    root = _b03_case_root(tmp_path)
    admission = _frozen_admission()
    review = _review_for(admission, root)
    bundle_out = tmp_path / "temp-bundle-perm"
    old_umask = os.umask(0o077)
    try:
        acceptance = release.run_b03_acceptance(
            admission=admission,
            sandbox=FakeB03Sandbox(toolchain=admission["build"]["toolchain_image"]),
            normal_input=(root / "inputs" / "normal.txt").read_bytes(),
            candidate_input=(root / "inputs" / "candidate.txt").read_bytes(),
            bundle_out=bundle_out,
            storage_ref="vault://datacon/private/b03/CVE-2019-13224/manifest.json",
            review=review,
            case_root=root,
            job_id="11111111-1111-4111-8111-111111111111",
        )
        persist_root = tmp_path / "persistent-b03-perm"
        persisted = release.persist_b03_evidence_bundle(
            bundle_out,
            persist_root=persist_root,
            job_id="11111111-1111-4111-8111-111111111111",
            expected_manifest_digest=acceptance["manifest_digest"],
        )
    finally:
        os.umask(old_umask)

    persisted_dir = Path(persisted["bundle_path"])
    assert (stat.S_IMODE(persist_root.stat().st_mode) & 0o005) == 0o005
    assert (stat.S_IMODE(persisted_dir.stat().st_mode) & 0o005) == 0o005
    for item in persisted_dir.rglob("*"):
        mode = stat.S_IMODE(item.stat().st_mode)
        if item.is_dir():
            assert (mode & 0o005) == 0o005, (item, oct(mode))
            assert (mode & 0o022) == 0, (item, oct(mode))
        else:
            assert (mode & 0o004) == 0o004, (item, oct(mode))
            assert (mode & 0o022) == 0, (item, oct(mode))


def test_skip_archived_bundle_requires_signed_approval_binding(tmp_path):
    manifest = _sample_rc_manifest()
    base_approval = _approval(manifest)
    digest = base_approval["candidate_digest"]

    # Default require_archived_bundle=True stays backward compatible with legacy approval.
    assert (
        release.verify_promotion_gate(
            manifest, expected_manifest_digest=digest, approval=base_approval
        )
        == digest
    )

    # Without allow_skip_archived_bundle=True, skipping fails closed.
    with pytest.raises(release.ReleaseGateError, match="allow_skip_archived_bundle"):
        release.verify_promotion_gate(
            manifest,
            expected_manifest_digest=digest,
            approval=base_approval,
            require_archived_bundle=False,
            skip_reason="initial bootstrap",
        )

    # Missing archived_bundle_skip_reason on approval fails closed.
    no_reason = dict(base_approval, allow_skip_archived_bundle=True)
    with pytest.raises(release.ReleaseGateError, match="archived_bundle_skip_reason"):
        release.verify_promotion_gate(
            manifest,
            expected_manifest_digest=digest,
            approval=no_reason,
            require_archived_bundle=False,
            skip_reason="initial bootstrap",
        )

    # Mismatched reason between workflow input and signed approval fails closed.
    signed_skip = dict(
        base_approval,
        allow_skip_archived_bundle=True,
        archived_bundle_skip_reason="approved lab bootstrap",
    )
    with pytest.raises(release.ReleaseGateError, match="does not match"):
        release.verify_promotion_gate(
            manifest,
            expected_manifest_digest=digest,
            approval=signed_skip,
            require_archived_bundle=False,
            skip_reason="arbitrary one-char x",
        )

    # Matching signed skip approval succeeds.
    assert (
        release.verify_promotion_gate(
            manifest,
            expected_manifest_digest=digest,
            approval=signed_skip,
            require_archived_bundle=False,
            skip_reason="approved lab bootstrap",
        )
        == digest
    )

    # archived_bundle_preflight also enforces approval binding when skipping.
    missing_root = tmp_path / "unmounted"

    class _NoBundleStore:
        def latest_evidence_bundle(self, *, require_active_root=True, strict=False):
            return None

    with pytest.raises(release.ReleaseGateError, match="allow_skip_archived_bundle"):
        release.archived_bundle_preflight(
            evidence_root=missing_root,
            store=_NoBundleStore(),
            verify_fn=lambda p, d: True,
            require_archived_bundle=False,
            skip_reason="x",
            approval=base_approval,
        )


def test_rollback_migrations_enforce_sha256_and_reject_same_ordinal_extras():
    target = {
        "image_id": "sha256:" + "7" * 64,
        "config": {"policy_version": "0"},
        "migration_version": "007_execution_evidence_invariant.sql",
        "evidence_root": "/var/lib/datacon/evidence",
        "manifest_digest": "sha256:" + "9" * 64,
    }

    # 1. Tampered sha256 on a crossed migration (008_release_events.sql) must fail closed.
    tampered_ledger = _ledger()
    tampered_ledger["008_release_events.sql"] = "sha256:" + "0" * 64
    with pytest.raises(release.ReleaseGateError, match="digest|008_release_events"):
        release.rollback_release(
            target_release=target,
            backend=release.DictPromotionBackend(
                active_release=_previous(), migrations=tampered_ledger
            ),
            smoke_checks={"cli_smoke": lambda: True},
            approved_by="reviewer-1",
            candidate_digest="sha256:" + "6" * 64,
        )

    # 2. Extra migration sharing target's ordinal (007_extra.sql) must fail closed.
    dup_ordinal_ledger = _ledger()
    dup_ordinal_ledger["007_extra.sql"] = "sha256:" + "a" * 64
    with pytest.raises(release.ReleaseGateError, match="same-ordinal|007_extra"):
        release.rollback_release(
            target_release=target,
            backend=release.DictPromotionBackend(
                active_release=_previous(), migrations=dup_ordinal_ledger
            ),
            smoke_checks={"cli_smoke": lambda: True},
            approved_by="reviewer-1",
            candidate_digest="sha256:" + "6" * 64,
        )


def test_bootstrap_release_rejects_non_consecutive_schema_migrations(monkeypatch):
    from datacon import state

    gapped_rows = [
        {"file": "001_create_jobs.sql"},
        {"file": "002_workflow.sql"},
        {"file": "003_attempts_generation.sql"},
        {"file": "004_legacy_binary_sync.sql"},
        {"file": "005_execution_evidence.sql"},
        {"file": "006_attempt_journal_provenance.sql"},
        # 007 missing!
        {"file": "008_release_events.sql"},
    ]

    class _FakeConn:
        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

        def execute(self, query, params=None):
            class _Cursor:
                def fetchone(self):
                    if "to_regclass" in query:
                        return {
                            "migrations_tbl": "schema_migrations",
                            "release_tbl": "release_state",
                            "events_tbl": "release_events",
                        }
                    return None

                def fetchall(self):
                    if "FROM schema_migrations" in query:
                        return gapped_rows
                    return []

            return _Cursor()

    store_handle = state.ReleaseStore("postgresql://unused")
    monkeypatch.setattr(store_handle, "_connect", lambda: _FakeConn())
    with pytest.raises(state.ReleaseStateError, match="consecutive|gap"):
        store_handle.bootstrap_release(
            image_id="sha256:" + "a" * 64,
            config={"policy_version": "1"},
            migration_version="008_release_events.sql",
            evidence_root="/var/lib/datacon/evidence",
        )


def test_release_contract_version_is_not_derived_from_contracts_schema():
    import importlib

    from datacon import contracts

    original = contracts.SCHEMA_VERSION
    contracts.SCHEMA_VERSION = 2
    try:
        importlib.reload(release)
        assert release.CONTRACT_VERSION == 1, (
            "release contract version tracked contracts.SCHEMA_VERSION"
        )
        manifest = release.build_release_candidate_manifest(
            source_commit="b" * 40,
            control_plane_image_id="sha256:" + "1" * 64,
            wheel_digest="sha256:" + "2" * 64,
            migrations_dir=REPO_ROOT / "migrations",
            sbom_digest="sha256:" + "3" * 64,
            test_report_digest="sha256:" + "4" * 64,
            scan_report_digest="sha256:" + "5" * 64,
        )
        assert manifest["contract_version"] == 1, (
            "v2 contract constant changed the release manifest contract_version"
        )
    finally:
        contracts.SCHEMA_VERSION = original
        importlib.reload(release)


def test_release_manifest_keeps_contract_version_one(tmp_path):
    from datacon import contracts

    assert contracts.SCHEMA_VERSION == 1
    assert contracts.SCHEMA_VERSION_V2 == 2
    assert release.CONTRACT_VERSION == 1

    manifest = _sample_rc_manifest()
    assert manifest["contract_version"] == 1
    assert manifest["schema_version"] == 1
    assert manifest["toolchain_image_digest"] == release.TOOLCHAIN_IMAGE_DIGEST
    assert release._candidate_config(manifest)["contract_version"] == 1
    release.validate_release_candidate_manifest(manifest)

    manifest_v2 = dict(manifest, contract_version=contracts.SCHEMA_VERSION_V2)
    with pytest.raises(release.ReleaseGateError, match="contract_version"):
        release.validate_release_candidate_manifest(manifest_v2)

    approval_v2 = _approval(manifest, contract_version=contracts.SCHEMA_VERSION_V2)
    with pytest.raises(release.ReleaseGateError, match="contract_version"):
        release.verify_promotion_gate(
            manifest,
            expected_manifest_digest=approval_v2["candidate_digest"],
            approval=approval_v2,
        )

    backend = _backend()
    with pytest.raises(release.ReleaseGateError, match="contract_version"):
        release.promote_and_smoke(
            manifest=manifest,
            expected_manifest_digest=approval_v2["candidate_digest"],
            approval=approval_v2,
            backend=backend,
            smoke_checks={"cli_smoke": lambda: True},
            rollback_fn=lambda prev: {"restored_image": prev["image_id"], "ok": True},
        )
    assert backend.switches == []
    assert backend.audits == []

    # B03 acceptance path stays on v1 compatibility (schema_version=1, pinned v1 toolchain).
    root = _b03_case_root(tmp_path)
    admission = _frozen_admission()
    assert admission["schema_version"] == 1
    assert admission["build"]["toolchain_image"] == release.TOOLCHAIN_IMAGE
    review = _review_for(admission, root)
    bundle_out = tmp_path / "b03-v1-bundle"
    acceptance = release.run_b03_acceptance(
        admission=admission,
        sandbox=FakeB03Sandbox(toolchain=release.TOOLCHAIN_IMAGE),
        normal_input=(root / "inputs" / "normal.txt").read_bytes(),
        candidate_input=(root / "inputs" / "candidate.txt").read_bytes(),
        bundle_out=bundle_out,
        storage_ref="vault://datacon/private/b03/CVE-2019-13224/manifest.json",
        review=review,
        case_root=root,
        job_id="22222222-2222-4222-8222-222222222222",
    )
    assert acceptance["schema_version"] == 1
    verified = evidence.verify_bundle(bundle_out)
    assert verified.manifest["schema_version"] == 1
    report = json.loads(verified.file_data["report.json"])
    assert report["schema_version"] == 1


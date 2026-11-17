"""Static contract tests for the release workflow (B3, B4, SF1, SF3).

These tests are a supplement, not a replacement for a real workflow dispatch.
They catch the original "echo-only" regression and verify that the workflow
still calls the production promotion/rollback paths.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from datacon import release

REPO_ROOT = Path(__file__).resolve().parents[2]
CI = REPO_ROOT / ".github" / "workflows" / "ci.yml"
RELEASE = REPO_ROOT / ".github" / "workflows" / "release.yml"


def _load(path: Path) -> dict:
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def _run_text(job: dict) -> str:
    return "\n".join(
        step.get("run", "")
        for step in job.get("steps", [])
        if isinstance(step, dict)
    )


def _steps(job: dict) -> list[dict]:
    return [step for step in job.get("steps", []) if isinstance(step, dict)]


def test_release_workflow_is_not_echo_only():
    document = _load(RELEASE)
    jobs = document["jobs"]
    assert 'echo "Promoting' not in _run_text(jobs["promote-internal"])
    assert 'echo "Rolling back' not in _run_text(jobs["rollback-internal"])
    assert "test -n" not in _run_text(jobs["rollback-internal"])


def test_build_candidate_saves_image_and_real_test_scan_evidence():
    job = _load(RELEASE)["jobs"]["build-candidate"]
    text = _run_text(job)
    assert "docker save" in text
    assert release.CANDIDATE_IMAGE_TAR in text or "control-plane-image.tar" in text
    assert "aquasec/trivy@" in text
    assert "--findings" in text
    assert "--require-scan" in text
    assert "evaluate_scan_report" in text
    assert "digest_test_reports" in text
    assert "verify_manifest_evidence" in text
    assert any(
        step.get("uses", "").startswith("actions/upload-artifact@")
        for step in _steps(job)
    )


def test_promote_job_downloads_verifies_loads_smokes_and_audits():
    job = _load(RELEASE)["jobs"]["promote-internal"]
    assert job["environment"] == "internal-lab"
    text = _run_text(job)
    assert "download-artifact" not in text  # it is a `uses:` step
    assert any(
        step.get("uses", "").startswith("actions/download-artifact@")
        for step in _steps(job)
    )
    for required in (
        "canonical_manifest_digest",
        "verify_manifest_evidence",
        "docker load",
        "docker image inspect",
        "promote_and_smoke",
        "ReleaseStore",
        "rollback_fn",
        "status",
    ):
        assert required in text, required
    assert "DATACON_RELEASE_APPROVAL" in text
    assert "artifact_run_id is required" in text
    assert '"promoted"' in text


def test_rollback_job_validates_input_via_env_and_uses_real_rollback():
    job = _load(RELEASE)["jobs"]["rollback-internal"]
    assert job["environment"] == "internal-lab"
    assert "TARGET_DIGEST" in job["env"]
    text = _run_text(job)
    assert '[[ ! "${TARGET_DIGEST}" =~ ^sha256:[0-9a-f]{64}$ ]]' in text
    assert "download-artifact" not in text
    assert any(
        step.get("uses", "").startswith("actions/download-artifact@")
        for step in _steps(job)
    )
    assert "docker load" in text
    assert "rollback_release" in text
    assert "release_for_image" in text


def test_release_workflow_passes_untrusted_inputs_through_env():
    document = _load(RELEASE)
    for job in document["jobs"].values():
        text = _run_text(job)
        assert "github.event." not in text
        assert "inputs." not in text


def test_test_report_job_produces_four_junit_reports():
    job = _load(RELEASE)["jobs"]["test-report"]
    text = _run_text(job)
    for label in ("postgres", "docker", "asan", "contract"):
        assert f"--junitxml=\"$RUNNER_TEMP/release-junit/${{label}}.xml\"" in text or label in text
    assert "check_junit_report" in text
    assert any(
        step.get("uses", "").startswith("actions/upload-artifact@")
        for step in _steps(job)
    )


def test_b03_job_requires_authorized_runner_and_upload_only_summary():
    job = _load(RELEASE)["jobs"]["b03-internal"]
    assert job["environment"] == "internal-lab"
    assert job["runs-on"] == ["self-hosted", "linux", "x64", "datacon-internal"]
    condition = job["if"]
    assert "run_b03" in condition
    text = _run_text(job)
    assert "run_b03_acceptance" in text
    assert "B03CaseMaterials" in text
    assert "b03-acceptance-summary.json" in text
    upload = [
        step
        for step in _steps(job)
        if step.get("uses", "").startswith("actions/upload-artifact@")
    ]
    assert len(upload) == 1
    assert upload[0]["with"]["path"] == "b03-acceptance-summary.json"


def test_toolchain_digest_is_single_sourced_across_workflows():
    ci_text = CI.read_text(encoding="utf-8")
    release_text = RELEASE.read_text(encoding="utf-8")
    assert release.TOOLCHAIN_IMAGE_DIGEST in ci_text
    assert release.TOOLCHAIN_IMAGE_DIGEST in release_text
    assert ci_text.count(release.TOOLCHAIN_IMAGE_DIGEST) >= 1
    assert release_text.count(release.TOOLCHAIN_IMAGE_DIGEST) >= 1


def test_ci_has_a_real_image_build_and_smoke_job():
    document = _load(CI)
    image_job = document["jobs"]["image"]
    text = _run_text(image_job)
    assert "docker build -t datacon-ci ." in text
    assert "docker run --rm datacon-ci --help" in text
    assert "docker run --rm datacon-ci worker --help" in text
    assert "uid=65534" in text
    assert "docker --version" in text or "--entrypoint docker" in text
    assert "git --version" in text or "--entrypoint git" in text
    assert "clang --version" in text or "--entrypoint clang" in text


def test_ci_test_job_runs_b04_with_injected_model_and_partition_check():
    job = _load(CI)["jobs"]["test"]
    text = _run_text(job)
    assert "OfflineContractModel" in text
    assert "model_factory" in text
    assert "model_invocations" in text
    assert "check_test_partition_counts" in text
    assert "status=0" in text
    assert "exit \"$status\"" in text


def test_no_continue_on_error_anywhere():
    for path in (CI, RELEASE):
        document = _load(path)
        text = path.read_text(encoding="utf-8")
        assert "continue-on-error" not in text
        assert document["permissions"] == {"contents": "read"}

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


def test_promote_job_requires_test_report_and_build_candidate_without_always():
    job = _load(RELEASE)["jobs"]["promote-internal"]
    needs = job.get("needs")
    if isinstance(needs, str):
        needs_set = {needs}
    else:
        needs_set = set(needs or ())
    assert needs_set == {"test-report", "build-candidate"}
    condition = job.get("if", "")
    assert "always()" not in condition
    assert "!cancelled()" in condition
    assert "needs.test-report.result == 'success'" in condition
    assert "needs.build-candidate.result == 'success'" in condition
    assert "needs.build-candidate.result == 'skipped'" in condition


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
        "verify-bundle",
    ):
        assert required in text, required
    assert "lambda: True" not in text
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
    assert "db_readability" in text


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
    assert "materials.normal_input" in text
    assert "materials.candidate_input" in text
    assert 'normal.txt").read_bytes()' not in text
    assert "b03-acceptance-summary.json" in text
    assert "REPRODUCED" in text
    assert "ASAN_SIGNATURE_MATCHED" in text
    assert 'acceptance["replay_count"] != 6' in text or 'acceptance["replay_count"] == 6' in text
    assert 'acceptance["bundle_verified"]' in text
    assert "GITHUB_RUN_ATTEMPT" in text
    assert "job_id=job_id" in text
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
        text = path.read_text(encoding="utf-8")
        assert "continue-on-error" not in text


def test_workflows_use_minimal_read_only_permissions():
    ci_permissions = _load(CI)["permissions"]
    release_permissions = _load(RELEASE)["permissions"]
    # ci.yml has no cross-run artifact reads; release.yml needs actions: read
    # for actions/download-artifact with run-id + github-token.
    assert ci_permissions == {"contents": "read"}
    assert release_permissions == {"contents": "read", "actions": "read"}
    for document in (_load(CI), _load(RELEASE)):
        for level in document["permissions"].values():
            assert level == "read"


def test_internal_jobs_are_restricted_to_main_or_a_release_tag():
    jobs = _load(RELEASE)["jobs"]
    for name in (
        "build-candidate",
        "promote-internal",
        "rollback-internal",
        "b03-internal",
    ):
        condition = jobs[name]["if"]
        assert "github.ref == 'refs/heads/main'" in condition, name
        assert "startsWith(github.ref, 'refs/tags/v')" in condition, name


def test_cross_run_artifacts_are_provenance_checked():
    jobs = _load(RELEASE)["jobs"]
    for name in ("promote-internal", "rollback-internal"):
        steps = _steps(jobs[name])
        downloads = [
            step
            for step in steps
            if step.get("uses", "").startswith("actions/download-artifact@")
        ]
        cross_run = [step for step in downloads if "run-id" in step.get("with", {})]
        assert cross_run
        for step in cross_run:
            # Untrusted run ids are passed through env, never directly from an
            # expression into a reusable action input.
            assert step["with"]["run-id"] == "${{ env.ARTIFACT_RUN_ID }}"
            assert step["with"]["github-token"] == "${{ secrets.GITHUB_TOKEN }}"
        run_text = _run_text(jobs[name])
        assert "api.github.com" in run_text
        assert "merge-base" in run_text
        assert "GITHUB_REF" in run_text
    promote_text = _run_text(jobs["promote-internal"])
    assert "VERIFIED_RUN_HEAD_SHA" in promote_text
    assert 'manifest["source_commit"]' in promote_text


def test_b1_protected_refs_verify_origin_main_ancestry_and_reject_none_head_branch():
    jobs = _load(RELEASE)["jobs"]
    for name in (
        "build-candidate",
        "promote-internal",
        "rollback-internal",
        "b03-internal",
    ):
        steps = _steps(jobs[name])
        text = _run_text(jobs[name])
        assert "/compare/main..." in text, name
        assert '"identical"' in text and '"behind"' in text, name
        assert "git fetch --no-tags origin main:refs/remotes/origin/main" in text, name
        assert (
            'git merge-base --is-ancestor "${GITHUB_SHA}" refs/remotes/origin/main'
            in text
        ), name

        verify_indices = [
            idx
            for idx, step in enumerate(steps)
            if step.get("name") == "Verify protected ref"
        ]
        assert len(verify_indices) == 1, (name, verify_indices)
        checkout_idx = next(
            idx
            for idx, step in enumerate(steps)
            if step.get("uses", "").startswith("actions/checkout@")
        )
        setup_python_idx = next(
            idx
            for idx, step in enumerate(steps)
            if step.get("uses", "").startswith("actions/setup-python@")
        )
        uv_sync_idx = next(
            idx
            for idx, step in enumerate(steps)
            if "uv sync --frozen" in step.get("run", "")
        )
        git_ancestry_idx = next(
            idx
            for idx, step in enumerate(steps)
            if 'git merge-base --is-ancestor "${GITHUB_SHA}" refs/remotes/origin/main'
            in step.get("run", "")
        )
        # Pre-checkout Compare API check must gate checkout; post-checkout git
        # ancestry check must gate setup-python and uv sync --frozen.
        assert verify_indices[0] < checkout_idx, name
        assert checkout_idx < git_ancestry_idx < setup_python_idx < uv_sync_idx, name

    for name in ("promote-internal", "rollback-internal"):
        text = _run_text(jobs[name])
        assert "head_branch not in (None" not in text, name
        assert "isinstance(head_branch, str)" in text, name
        assert '"refs/remotes/origin/main"' in text, name

    promote_text = _run_text(jobs["promote-internal"])
    assert (
        '["git", "merge-base", "--is-ancestor", manifest["source_commit"], "refs/remotes/origin/main"]'
        in promote_text
    )


def test_protected_secrets_are_scoped_after_ref_verification_and_uv_sync():
    jobs = _load(RELEASE)["jobs"]

    promote = jobs["promote-internal"]
    assert "DATACON_DATABASE_URL" not in promote.get("env", {})
    assert "DATACON_RELEASE_APPROVAL" not in promote.get("env", {})
    for step in _steps(promote):
        uses = step.get("uses", "")
        run = step.get("run", "")
        if (
            uses.startswith(("actions/checkout@", "actions/setup-python@", "actions/download-artifact@"))
            or "uv sync --frozen" in run
        ):
            step_env = step.get("env", {})
            assert "DATACON_DATABASE_URL" not in step_env
            assert "DATACON_RELEASE_APPROVAL" not in step_env

    rollback = jobs["rollback-internal"]
    assert "DATACON_DATABASE_URL" not in rollback.get("env", {})
    for step in _steps(rollback):
        uses = step.get("uses", "")
        run = step.get("run", "")
        if (
            uses.startswith(("actions/checkout@", "actions/setup-python@", "actions/download-artifact@"))
            or "uv sync --frozen" in run
        ):
            assert "DATACON_DATABASE_URL" not in step.get("env", {})

    b03 = jobs["b03-internal"]
    b03_secrets = {"DATACON_B03_CASE_ROOT", "DATACON_B03_ADMISSION", "DATACON_B03_REVIEW"}
    assert not (b03_secrets & set(b03.get("env", {})))
    for step in _steps(b03):
        uses = step.get("uses", "")
        run = step.get("run", "")
        if (
            uses.startswith(("actions/checkout@", "actions/setup-python@", "actions/upload-artifact@"))
            or "uv sync --frozen" in run
            or step.get("name") == "Verify protected ref"
        ):
            assert not (b03_secrets & set(step.get("env", {})))


def test_s1_s4_s5_s8_promote_and_rollback_safety_contracts():
    jobs = _load(RELEASE)["jobs"]

    promote_steps = _steps(jobs["promote-internal"])
    promote_text = _run_text(jobs["promote-internal"])
    assert "worker --once" not in promote_text
    assert "release slots --environment internal-lab" in promote_text
    assert "verify_promotion_gate" in promote_text
    assert "preflight_checks" in promote_text
    assert "timeout=60" in promote_text
    assert "timeout 60 docker run" in promote_text
    assert "evidence_root_path.exists()" in promote_text
    assert "archived_real_bundle" in promote_text

    approval_step_idx = next(
        idx
        for idx, step in enumerate(promote_steps)
        if "DATACON_RELEASE_APPROVAL" in step.get("run", "")
    )
    first_db_or_container_idx = next(
        idx
        for idx, step in enumerate(promote_steps)
        if "DATACON_DATABASE_URL" in step.get("run", "")
        or "docker run" in step.get("run", "")
    )
    assert approval_step_idx <= first_db_or_container_idx

    rollback_text = _run_text(jobs["rollback-internal"])
    assert 'candidate_digest=os.environ["TARGET_DIGEST"]' not in rollback_text
    assert 'target.get("candidate_digest") or target.get("manifest_digest")' in rollback_text
    assert "verify-bundle" in rollback_text
    assert "release slots --environment internal-lab" in rollback_text
    assert "post_switch_checks" in rollback_text
    assert "timeout=60" in rollback_text

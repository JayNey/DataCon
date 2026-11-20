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
VULN_SCAN = REPO_ROOT / ".github" / "workflows" / "vuln-scan.yml"
DOCKERFILE = REPO_ROOT / "Dockerfile"


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


def _dockerfile_instructions(text: str) -> list[str]:
    """Return logical Dockerfile instructions with continuations folded."""
    instructions: list[str] = []
    buffer = ""
    for raw in text.splitlines():
        line = raw.rstrip()
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        if line.endswith("\\"):
            buffer += line[:-1] + " "
            continue
        buffer += line
        instructions.append(" ".join(buffer.split()))
        buffer = ""
    if buffer.strip():
        instructions.append(" ".join(buffer.split()))
    return instructions


def _runtime_apt_packages() -> set[str]:
    text = DOCKERFILE.read_text(encoding="utf-8")
    installs = [
        instruction
        for instruction in _dockerfile_instructions(text)
        if instruction.startswith("RUN ") and "apt-get install" in instruction
    ]
    assert len(installs) == 1, "expected a single apt-get install layer"
    install = installs[0]
    tail = install.split("--no-install-recommends", 1)[1]
    return set(tail.split("&&", 1)[0].split())


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
    assert "needs.build-candidate.result == 'skipped'" in condition
    assert "github.event_name == 'workflow_dispatch'" in condition
    assert "github.ref == 'refs/heads/main'" in condition
    assert "refs/tags/v" not in condition


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
    run_suite_script = REPO_ROOT / "scripts" / "run_suite.sh"
    assert run_suite_script.is_file()
    assert "scripts/run_suite.sh" in text
    assert "check_junit_report" in run_suite_script.read_text(encoding="utf-8")
    assert any(
        step.get("uses", "").startswith("actions/upload-artifact@")
        for step in _steps(job)
    )


def test_b03_job_requires_authorized_runner_and_candidate_artifact():
    job = _load(RELEASE)["jobs"]["b03-internal"]
    assert job["environment"] == "internal-lab"
    assert job["runs-on"] == ["self-hosted", "linux", "x64", "datacon-internal"]
    condition = job["if"]
    assert "run_b03" in condition
    assert "artifact_run_id" in condition
    assert job["env"]["ARTIFACT_RUN_ID"] == "${{ github.event.inputs.artifact_run_id }}"
    assert "DATACON_B03_CASE_ROOT" not in job.get("env", {})
    assert "DATACON_DATABASE_URL" not in job.get("env", {})

    steps = _steps(job)
    download = next(
        step
        for step in steps
        if step.get("uses", "").startswith("actions/download-artifact@")
    )
    assert download["with"]["name"] == "release-candidate-artifacts"
    assert download["with"]["run-id"] == "${{ env.ARTIFACT_RUN_ID }}"

    text = _run_text(job)
    for required in (
        "control-plane-image.tar",
        "release-candidate-manifest.json",
        "release-manifest.json",
        "canonical_manifest_digest",
        "validate_release_candidate_manifest",
        "docker load",
        "docker image inspect",
        "control_plane_image_id",
        "--network host",
        "--group-add",
        "/var/run/docker.sock",
        "--user 65534:65534",
        "/app/.venv/bin/python",
        "B03CaseMaterials",
        "prepare_b03_plan",
        "run_b03_acceptance",
        "persist_b03_evidence_bundle",
        "record_b03_acceptance",
        "ReleaseStore",
        "b03-acceptance-summary.json",
        "DATACON_DATABASE_URL",
    ):
        assert required in text, required
    assert "materials.normal_input" in text
    assert "materials.candidate_input" in text
    assert 'normal.txt").read_bytes()' not in text
    assert "bundle_path" not in text
    assert "ASAN_SIGNATURE_MATCHED" in text
    assert 'acceptance["replay_count"] != 6' in text
    assert 'acceptance["bundle_verified"]' in text
    assert "GITHUB_RUN_ID" in text

    record_step = next(
        step for step in steps if "record_b03_acceptance" in step.get("run", "")
    )
    assert record_step["env"]["DATACON_DATABASE_URL"] == "${{ secrets.DATACON_DATABASE_URL }}"

    upload = [
        step
        for step in steps
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
    # clang moved out of the runtime image (it runs only inside the pinned
    # silkeh/clang sandbox container), and dockerd/containerd/runc are host
    # daemon concerns: the smoke step must assert all four are absent.
    for absent_tool in ("clang", "dockerd", "containerd", "runc"):
        assert f"! command -v {absent_tool}" in text, absent_tool


def test_runtime_image_installs_only_the_docker_client_not_daemon_or_clang():
    packages = _runtime_apt_packages()
    # git is a real worker dependency (local bare repos) and ca-certificates is
    # needed for TLS, so both stay; everything else must not creep back in.
    assert {"ca-certificates", "docker-cli", "git"} <= packages
    for banned in ("clang", "docker.io", "containerd", "runc", "dockerd", "iptables"):
        assert banned not in packages, f"{banned} must stay out of the runtime image"


def test_ci_vuln_job_rescans_image_and_always_uploads_the_report():
    document = _load(CI)
    assert "vuln" in document["jobs"], "ci.yml must expose the vulnerability gate on PRs"
    job = document["jobs"]["vuln"]
    assert job["needs"] == "image"
    text = _run_text(job)

    assert "docker build -t datacon-ci ." in text
    assert f"aquasec/trivy@{release.TRIVY_IMAGE_DIGEST}" in text
    assert "-v /var/run/docker.sock:/var/run/docker.sock" in text
    assert '--findings "$out/trivy.json"' in text
    assert "--waivers .github/security-waivers.json --require-scan" in text
    assert "-m datacon.ci_gates" in text
    # The report is small; an image tar upload is forbidden.
    assert "docker save" not in text

    uploads = [
        step
        for step in _steps(job)
        if str(step.get("uses", "")).startswith("actions/upload-artifact@")
    ]
    assert len(uploads) == 1
    upload = uploads[0]
    # A failing gate must still publish the report, otherwise triage degrades
    # to a single log line, which is exactly what the incident exposed.
    assert upload.get("if") == "always()"
    assert upload["with"]["name"] == "trivy-report"
    assert upload["with"]["path"].endswith("trivy-report/trivy.json")

    triggers = _load(CI).get("on", _load(CI).get(True))
    assert "schedule" not in triggers, "the weekly scan belongs in vuln-scan.yml, not ci.yml"


def test_vuln_scan_workflow_is_weekly_dispatchable_and_runs_the_real_gate():
    document = _load(VULN_SCAN)
    triggers = document.get("on", document.get(True))
    assert {"cron": "0 3 * * 1"} in triggers["schedule"]
    assert "workflow_dispatch" in triggers

    assert document["permissions"] == {"contents": "read"}
    job = document["jobs"]["scan"]
    text = _run_text(job)
    assert "docker build -t datacon-ci ." in text
    assert f"aquasec/trivy@{release.TRIVY_IMAGE_DIGEST}" in text
    assert "-v /var/run/docker.sock:/var/run/docker.sock" in text
    assert '--findings "$out/trivy.json"' in text
    assert "--waivers .github/security-waivers.json --require-scan" in text
    assert "-m datacon.ci_gates" in text

    uploads = [
        step
        for step in _steps(job)
        if str(step.get("uses", "")).startswith("actions/upload-artifact@")
    ]
    assert len(uploads) == 1
    assert uploads[0].get("if") == "always()"
    assert uploads[0]["with"]["name"] == "trivy-report"
    assert uploads[0]["with"]["path"].endswith("trivy-report/trivy.json")


def test_trivy_digest_is_single_sourced_across_workflows():
    assert release.TRIVY_IMAGE == f"aquasec/trivy@{release.TRIVY_IMAGE_DIGEST}"
    assert release.TRIVY_IMAGE_DIGEST.startswith("sha256:")
    assert len(release.TRIVY_IMAGE_DIGEST) == len("sha256:") + 64
    for path in (CI, RELEASE, VULN_SCAN):
        text = path.read_text(encoding="utf-8")
        assert f"aquasec/trivy@{release.TRIVY_IMAGE_DIGEST}" in text, path


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
    for path in (CI, RELEASE, VULN_SCAN):
        text = path.read_text(encoding="utf-8")
        assert "continue-on-error" not in text


def test_workflows_use_minimal_read_only_permissions():
    ci_permissions = _load(CI)["permissions"]
    release_permissions = _load(RELEASE)["permissions"]
    vuln_scan_permissions = _load(VULN_SCAN)["permissions"]
    # ci.yml has no cross-run artifact reads; release.yml needs actions: read
    # for actions/download-artifact with run-id + github-token.
    assert ci_permissions == {"contents": "read"}
    assert release_permissions == {"contents": "read", "actions": "read"}
    assert vuln_scan_permissions == {"contents": "read"}
    for document in (_load(CI), _load(RELEASE), _load(VULN_SCAN)):
        for level in document["permissions"].values():
            assert level == "read"


def test_internal_jobs_are_restricted_to_main_or_a_release_tag():
    jobs = _load(RELEASE)["jobs"]
    build_cond = jobs["build-candidate"]["if"]
    assert "github.ref == 'refs/heads/main'" in build_cond
    assert "startsWith(github.ref, 'refs/tags/v')" in build_cond
    for name in (
        "promote-internal",
        "rollback-internal",
        "b03-internal",
    ):
        condition = jobs[name]["if"]
        assert "github.ref == 'refs/heads/main'" in condition, name
        assert "github.event_name == 'workflow_dispatch'" in condition, name
        assert "refs/tags/v" not in condition, name


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
    document = _load(RELEASE)
    jobs = document["jobs"]

    promote_steps = _steps(jobs["promote-internal"])
    promote_text = _run_text(jobs["promote-internal"])
    assert "worker --once" not in promote_text
    assert "release slots --environment internal-lab" in promote_text
    assert "verify_promotion_gate" in promote_text
    assert "preflight_checks" in promote_text
    assert "archived_bundle_preflight" in promote_text
    assert "archived_real_bundle" in promote_text

    _assert_secrets_scoped(document)
    _assert_smoke_timeouts(document)

    rollback_text = _run_text(jobs["rollback-internal"])
    assert 'candidate_digest=os.environ["TARGET_DIGEST"]' not in rollback_text
    assert 'target.get("candidate_digest") or target.get("manifest_digest")' in rollback_text
    assert "verify-bundle" in rollback_text
    assert "post_switch_checks" in rollback_text


def _eval_gha_condition(
    expr: str,
    *,
    event_name: str,
    ref: str,
    action: str = "build",
    run_b03: bool = False,
    artifact_run_id: str = "12345",
    test_report_result: str = "success",
    build_candidate_result: str = "skipped",
    cancelled: bool = False,
) -> bool:
    """Evaluate a GitHub Actions job `if:` expression structurally in Python."""
    import re

    translated = expr.strip()
    replacements = {
        "github.event_name": repr(event_name),
        "github.ref": repr(ref),
        "github.event.inputs.action": repr(action),
        "github.event.inputs.run_b03": repr("true" if run_b03 else "false"),
        "github.event.inputs.artifact_run_id": repr(artifact_run_id),
        "needs.test-report.result": repr(test_report_result),
        "needs.build-candidate.result": repr(build_candidate_result),
    }
    for key, val in replacements.items():
        translated = translated.replace(key, val)
    translated = translated.replace("!cancelled()", repr(not cancelled))
    translated = re.sub(
        r"startsWith\(([^,]+),\s*([^)]+)\)",
        r"(\1).startswith(\2)",
        translated,
    )
    translated = translated.replace("&&", " and ").replace("||", " or ")
    return bool(eval(translated, {"__builtins__": {}}, {}))  # noqa: S307


def _extract_python_heredocs(script: str) -> list[str]:
    import re
    import textwrap

    blocks = re.findall(
        r"<<'?PY'?[^\n]*\n(.*?)\n[ \t]*PY(?:\n|$)", script, flags=re.S
    )
    return [textwrap.dedent(block) for block in blocks]


def _assert_secrets_scoped(document: dict) -> None:
    import json

    jobs = document["jobs"]

    promote = jobs["promote-internal"]
    promote_secrets = ("DATACON_DATABASE_URL", "DATACON_RELEASE_APPROVAL")
    for secret in promote_secrets:
        assert secret not in promote.get("env", {}), f"promote job env leaks {secret}"
    promote_steps = _steps(promote)
    approval_idx = next(
        idx
        for idx, step in enumerate(promote_steps)
        if "verify_promotion_gate" in step.get("run", "")
    )
    for idx, step in enumerate(promote_steps[:approval_idx]):
        step_env = step.get("env", {})
        step_run = step.get("run", "")
        step_with = json.dumps(step.get("with", {}))
        for secret in promote_secrets:
            assert secret not in step_env, f"promote step {idx} env leaks {secret}"
            assert secret not in step_run, f"promote step {idx} run references {secret}"
            assert secret not in step_with, f"promote step {idx} with references {secret}"
    first_db_or_container_idx = next(
        idx
        for idx, step in enumerate(promote_steps)
        if "DATACON_DATABASE_URL" in step.get("env", {})
        or "DATACON_DATABASE_URL" in step.get("run", "")
        or "docker run" in step.get("run", "")
    )
    assert approval_idx < first_db_or_container_idx

    rollback = jobs["rollback-internal"]
    assert "DATACON_DATABASE_URL" not in rollback.get("env", {})
    rollback_steps = _steps(rollback)
    restore_idx = next(
        idx
        for idx, step in enumerate(rollback_steps)
        if "rollback_release" in step.get("run", "")
    )
    for idx, step in enumerate(rollback_steps[:restore_idx]):
        step_env = step.get("env", {})
        step_run = step.get("run", "")
        step_with = json.dumps(step.get("with", {}))
        assert "DATACON_DATABASE_URL" not in step_env, (
            f"rollback step {idx} leaks DATACON_DATABASE_URL"
        )
        assert "DATACON_DATABASE_URL" not in step_run, (
            f"rollback step {idx} references DATACON_DATABASE_URL"
        )
        assert "DATACON_DATABASE_URL" not in step_with, (
            f"rollback step {idx} with references DATACON_DATABASE_URL"
        )

    b03 = jobs["b03-internal"]
    b03_secrets = ("DATACON_B03_CASE_ROOT", "DATACON_B03_ADMISSION", "DATACON_B03_REVIEW")
    assert not (set(b03_secrets) & set(b03.get("env", {})))
    b03_steps = _steps(b03)
    b03_run_idx = next(
        idx
        for idx, step in enumerate(b03_steps)
        if "run_b03_acceptance" in step.get("run", "")
    )
    for idx, step in enumerate(b03_steps[:b03_run_idx]):
        step_env = step.get("env", {})
        step_run = step.get("run", "")
        step_with = json.dumps(step.get("with", {}))
        for secret in b03_secrets:
            assert secret not in step_env, f"b03 step {idx} env leaks {secret}"
            assert secret not in step_run, f"b03 step {idx} run references {secret}"
            assert secret not in step_with, f"b03 step {idx} with references {secret}"


def _assert_smoke_timeouts(document: dict) -> None:
    import ast
    import re
    import shlex

    subprocess_methods = {"run", "Popen", "check_call", "check_output", "call"}

    def _resolve_target(expr: ast.AST, sp_mods: set[str], os_mods: set[str], fn_aliases: dict[str, str]) -> str | None:
        if isinstance(expr, ast.Name):
            return fn_aliases.get(expr.id)
        if isinstance(expr, ast.Attribute) and isinstance(expr.value, ast.Name):
            if expr.value.id in sp_mods and expr.attr in subprocess_methods:
                return f"subprocess.{expr.attr}"
            if expr.value.id in os_mods and expr.attr == "system":
                return "os.system"
        if (
            isinstance(expr, ast.Call)
            and isinstance(expr.func, ast.Name)
            and expr.func.id == "getattr"
            and len(expr.args) >= 2
            and isinstance(expr.args[0], ast.Name)
            and isinstance(expr.args[1], ast.Constant)
            and isinstance(expr.args[1].value, str)
        ):
            if expr.args[0].id in sp_mods and expr.args[1].value in subprocess_methods:
                return f"subprocess.{expr.args[1].value}"
            if expr.args[0].id in os_mods and expr.args[1].value == "system":
                return "os.system"
        return None

    jobs = document["jobs"]
    for job_name in ("promote-internal", "rollback-internal"):
        found_python_docker = False
        for step in _steps(jobs[job_name]):
            run_script = step.get("run", "")
            for block in _extract_python_heredocs(run_script):
                tree = ast.parse(block)
                sp_mods: set[str] = set()
                os_mods: set[str] = set()
                fn_aliases: dict[str, str] = {}
                list_vars: dict[str, list[Any]] = {}

                for node in ast.walk(tree):
                    if isinstance(node, ast.Import):
                        for alias in node.names:
                            bound = alias.asname or alias.name
                            if alias.name == "subprocess":
                                sp_mods.add(bound)
                            elif alias.name == "os":
                                os_mods.add(bound)
                    elif isinstance(node, ast.ImportFrom):
                        if node.module == "subprocess":
                            for alias in node.names:
                                if alias.name in subprocess_methods:
                                    fn_aliases[alias.asname or alias.name] = f"subprocess.{alias.name}"
                        elif node.module == "os":
                            for alias in node.names:
                                if alias.name == "system":
                                    fn_aliases[alias.asname or alias.name] = "os.system"

                # Walk statements in source order to resolve local aliases accurately.
                for node in ast.walk(tree):
                    if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
                        target_name = node.targets[0].id
                        if isinstance(node.value, ast.Name):
                            if node.value.id in sp_mods:
                                sp_mods.add(target_name)
                            elif node.value.id in os_mods:
                                os_mods.add(target_name)
                        resolved = _resolve_target(node.value, sp_mods, os_mods, fn_aliases)
                        if resolved is not None:
                            fn_aliases[target_name] = resolved
                        if isinstance(node.value, ast.List) and node.value.elts:
                            first = node.value.elts[0]
                            if isinstance(first, ast.Constant):
                                list_vars[target_name] = [first.value]
                    elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name) and node.value is not None:
                        target_name = node.target.id
                        resolved = _resolve_target(node.value, sp_mods, os_mods, fn_aliases)
                        if resolved is not None:
                            fn_aliases[target_name] = resolved

                for node in ast.walk(tree):
                    if not isinstance(node, ast.Call):
                        continue
                    target = _resolve_target(node.func, sp_mods, os_mods, fn_aliases)
                    if target is None:
                        continue
                    if target == "os.system":
                        raise AssertionError(f"{job_name}: os.system is forbidden in smoke checks (no timeout)")
                    if target == "subprocess.Popen":
                        raise AssertionError(f"{job_name}: subprocess.Popen is forbidden in smoke checks without bounded run(..., timeout=...)")

                    cmd_is_docker = False
                    if node.args:
                        arg0 = node.args[0]
                        if isinstance(arg0, ast.List) and arg0.elts:
                            if isinstance(arg0.elts[0], ast.Constant) and arg0.elts[0].value == "docker":
                                cmd_is_docker = True
                                found_python_docker = True
                        elif isinstance(arg0, ast.Name) and list_vars.get(arg0.id, [None])[0] == "docker":
                            cmd_is_docker = True
                            found_python_docker = True
                    timeout_kw = next(
                        (kw for kw in node.keywords if kw.arg == "timeout"),
                        None,
                    )
                    assert timeout_kw is not None, (
                        f"{job_name}: {target} missing timeout= keyword"
                    )
                    assert isinstance(timeout_kw.value, ast.Constant) and isinstance(
                        timeout_kw.value.value, (int, float)
                    ) and 0 < timeout_kw.value.value <= 300, (
                        f"{job_name}: {target} timeout must be positive <= 300"
                    )
                    if cmd_is_docker:
                        assert timeout_kw.value.value == 60
            # Check shell-level `docker run` commands outside Python heredocs.
            outside_heredoc = re.sub(
                r"<<'?PY'?\n.*?\n[ \t]*PY(?:\n|$)",
                "\n",
                run_script,
                flags=re.S,
            )
            outside_heredoc = re.sub(r"\\\n[ \t]*", " ", outside_heredoc)
            for raw_line in outside_heredoc.splitlines():
                stripped = raw_line.strip()
                if not stripped or stripped.startswith("#"):
                    continue
                tokens = shlex.split(stripped, comments=True)
                for pos in range(len(tokens) - 1):
                    if tokens[pos] == "docker" and tokens[pos + 1] == "run":
                        assert pos >= 2 and tokens[pos - 2] == "timeout" and tokens[pos - 1].isdigit() and int(tokens[pos - 1]) > 0, (
                            f"{job_name}: shell docker run must be guarded by `timeout <secs>`: {raw_line!r}"
                        )
        assert found_python_docker, f"{job_name}: expected Python subprocess docker smoke check"


def test_secret_jobs_only_run_on_main_workflow_dispatch_never_tags():
    jobs = _load(RELEASE)["jobs"]
    build_if = jobs["build-candidate"]["if"]
    promote_if = jobs["promote-internal"]["if"]
    rollback_if = jobs["rollback-internal"]["if"]
    b03_if = jobs["b03-internal"]["if"]

    # Tag push builds candidate without secrets, and NEVER triggers promote/rollback/b03.
    assert _eval_gha_condition(build_if, event_name="push", ref="refs/tags/v1.0.0") is True
    assert _eval_gha_condition(
        promote_if,
        event_name="push",
        ref="refs/tags/v1.0.0",
        build_candidate_result="success",
    ) is False
    assert _eval_gha_condition(rollback_if, event_name="push", ref="refs/tags/v1.0.0") is False
    assert _eval_gha_condition(b03_if, event_name="push", ref="refs/tags/v1.0.0", run_b03=True) is False

    # Dispatch on a tag or feature branch never enters secret jobs.
    for bad_ref in ("refs/tags/v1.0.0", "refs/heads/feat/pr7"):
        assert _eval_gha_condition(
            promote_if,
            event_name="workflow_dispatch",
            ref=bad_ref,
            action="promote",
            build_candidate_result="skipped",
        ) is False
        assert _eval_gha_condition(
            rollback_if,
            event_name="workflow_dispatch",
            ref=bad_ref,
            action="rollback",
        ) is False
        assert _eval_gha_condition(
            b03_if,
            event_name="workflow_dispatch",
            ref=bad_ref,
            run_b03=True,
        ) is False

    # Main workflow_dispatch enters promote/rollback/b03 as requested.
    assert _eval_gha_condition(
        promote_if,
        event_name="workflow_dispatch",
        ref="refs/heads/main",
        action="promote",
        build_candidate_result="skipped",
    ) is True
    assert _eval_gha_condition(
        rollback_if,
        event_name="workflow_dispatch",
        ref="refs/heads/main",
        action="rollback",
    ) is True
    assert _eval_gha_condition(
        b03_if,
        event_name="workflow_dispatch",
        ref="refs/heads/main",
        run_b03=True,
    ) is True
    assert _eval_gha_condition(
        b03_if,
        event_name="workflow_dispatch",
        ref="refs/heads/main",
        run_b03=True,
        artifact_run_id="",
    ) is False

    # Promote must not carry dead push/build-candidate fallback expressions.
    promote = jobs["promote-internal"]
    assert "needs.build-candidate.outputs.manifest_digest" not in promote["env"]["EXPECTED_MANIFEST_DIGEST"]
    assert not any(
        step.get("if") == "github.event_name != 'workflow_dispatch'"
        for step in _steps(promote)
    )


def test_test_report_has_main_and_tag_ref_guard():
    job = _load(RELEASE)["jobs"]["test-report"]
    cond = job.get("if", "")
    assert cond, "test-report must declare a ref guard"
    assert _eval_gha_condition(cond, event_name="push", ref="refs/heads/main") is True
    assert _eval_gha_condition(cond, event_name="push", ref="refs/tags/v1.0.0") is True
    assert _eval_gha_condition(cond, event_name="workflow_dispatch", ref="refs/heads/main") is True
    assert _eval_gha_condition(cond, event_name="workflow_dispatch", ref="refs/tags/v1.0.0") is True
    assert _eval_gha_condition(cond, event_name="workflow_dispatch", ref="refs/heads/feat/branch") is False
    assert _eval_gha_condition(cond, event_name="pull_request", ref="refs/pull/7/merge") is False


def test_sensitive_internal_jobs_use_datacon_internal_runner():
    jobs = _load(RELEASE)["jobs"]
    expected_runner = ["self-hosted", "linux", "x64", "datacon-internal"]
    for job_name in ("promote-internal", "rollback-internal", "b03-internal"):
        assert jobs[job_name]["runs-on"] == expected_runner, job_name
        assert jobs[job_name]["runs-on"] != "ubuntu-latest", job_name


def test_promote_archived_bundle_is_fail_closed_by_default_and_audited_when_skipped(
    tmp_path, monkeypatch
):
    import sys
    import types

    promote = _load(RELEASE)["jobs"]["promote-internal"]
    promote_steps = _steps(promote)
    assert "REQUIRE_ARCHIVED_BUNDLE" in promote["env"]
    assert "ARCHIVED_BUNDLE_SKIP_REASON" in promote["env"]
    promote_step = next(
        step for step in promote_steps if "archived_bundle_preflight" in step.get("run", "")
    )
    blocks = _extract_python_heredocs(promote_step["run"])
    assert len(blocks) == 1
    code = compile(blocks[0], "<promote-heredoc>", "exec")

    def _run_promote_heredoc(req_env: str, skip_reason: str, preflight_mode: str):
        art_dir = tmp_path / f"art-{req_env or 'empty'}-{preflight_mode}"
        art_dir.mkdir(exist_ok=True)
        (art_dir / "release-candidate-manifest.json").write_text(
            '{"control_plane_image_id": "sha256:' + "c" * 64 + '"}',
            encoding="utf-8",
        )
        captured: dict = {}

        class _FakeStore:
            def __init__(self, dsn):
                self.dsn = dsn

            def active_release(self):
                return {
                    "image_id": "sha256:" + "0" * 64,
                    "config": {"policy_version": "1"},
                    "migration_version": "008_release_events.sql",
                    "evidence_root": "/var/lib/datacon/evidence",
                }

        def _fake_preflight(
            *,
            evidence_root,
            store,
            verify_fn,
            require_archived_bundle=True,
            skip_reason=None,
            approval=None,
        ):
            captured["preflight_args"] = {
                "evidence_root": evidence_root,
                "require_archived_bundle": require_archived_bundle,
                "skip_reason": skip_reason,
                "approval": approval,
            }
            if preflight_mode == "verified":
                return {
                    "status": "required",
                    "bundle_path": "/var/lib/datacon/evidence/job-1/gen-1",
                    "bundle_digest": "sha256:" + "d" * 64,
                    "check_fn": lambda: True,
                }
            return {
                "status": "skipped",
                "reason": skip_reason,
                "check_fn": None,
            }

        def _fake_promote_and_smoke(**kwargs):
            captured["promote_kwargs"] = kwargs
            return {"status": "promoted", "smoke_results": {}}

        fake_release = types.ModuleType("datacon.release")
        fake_release.RELEASE_MANIFEST_FILE = "release-candidate-manifest.json"
        fake_release.PROMOTION_RESULT_FILE = "promotion-result.json"
        fake_release.write_smoke_evidence_bundle = lambda *a, **kw: "sha256:" + "e" * 64
        fake_release.archived_bundle_preflight = _fake_preflight
        fake_release.promote_and_smoke = _fake_promote_and_smoke
        fake_release.canonical_manifest_digest = lambda m: "sha256:" + "f" * 64

        fake_state = types.ModuleType("datacon.state")
        fake_state.ReleaseStore = _FakeStore

        fake_datacon = types.ModuleType("datacon")
        fake_datacon.release = fake_release
        fake_datacon.state = fake_state

        fake_psycopg = types.ModuleType("psycopg")
        fake_psycopg.connect = lambda *a, **kw: None

        monkeypatch.setitem(sys.modules, "datacon", fake_datacon)
        monkeypatch.setitem(sys.modules, "datacon.release", fake_release)
        monkeypatch.setitem(sys.modules, "datacon.state", fake_state)
        monkeypatch.setitem(sys.modules, "psycopg", fake_psycopg)
        monkeypatch.setenv("EXPECTED_MANIFEST_DIGEST", "sha256:" + "f" * 64)
        approval_doc = {"approved_by": "ops"}
        if req_env == "false":
            approval_doc["allow_skip_archived_bundle"] = True
            approval_doc["archived_bundle_skip_reason"] = skip_reason
        monkeypatch.setenv("DATACON_RELEASE_APPROVAL", json.dumps(approval_doc))
        monkeypatch.setenv("DATACON_DATABASE_URL", "postgresql://unused")
        monkeypatch.setenv("REQUIRE_ARCHIVED_BUNDLE", req_env)
        monkeypatch.setenv("ARCHIVED_BUNDLE_SKIP_REASON", skip_reason)
        monkeypatch.setattr(sys, "argv", ["promote.py", str(art_dir)])

        ns = {"__name__": "__main__"}
        exec(code, ns, ns)  # noqa: S102
        return captured

    import json
    import pytest

    with pytest.raises(SystemExit, match="REQUIRE_ARCHIVED_BUNDLE"):
        _run_promote_heredoc("invalid", "", "verified")

    for req_val in ("", "true"):
        cap = _run_promote_heredoc(req_val, "", "verified")
        assert cap["preflight_args"]["require_archived_bundle"] is True
        assert cap["preflight_args"]["skip_reason"] is None
        assert "archived_real_bundle" in cap["promote_kwargs"]["preflight_checks"]
        assert cap["promote_kwargs"]["audit_metadata"] == {
            "archived_real_bundle": "verified",
            "archived_real_bundle_path": "/var/lib/datacon/evidence/job-1/gen-1",
        }

    cap_skip = _run_promote_heredoc("false", "initial bootstrap lab", "skipped")
    assert cap_skip["preflight_args"]["require_archived_bundle"] is False
    assert cap_skip["preflight_args"]["skip_reason"] == "initial bootstrap lab"
    assert cap_skip["preflight_args"]["approval"]["allow_skip_archived_bundle"] is True
    assert cap_skip["promote_kwargs"]["require_archived_bundle"] is False
    assert cap_skip["promote_kwargs"]["skip_reason"] == "initial bootstrap lab"
    assert "archived_real_bundle" not in cap_skip["promote_kwargs"]["preflight_checks"]
    assert cap_skip["promote_kwargs"]["audit_metadata"] == {
        "archived_real_bundle": "skipped",
        "archived_real_bundle_skip_reason": "initial bootstrap lab",
    }


def test_no_secret_in_any_step_before_approval():
    _assert_secrets_scoped(_load(RELEASE))


def test_smoke_subprocess_calls_have_timeout():
    _assert_smoke_timeouts(_load(RELEASE))


def test_secret_scoping_helper_rejects_secret_inserted_before_approval():
    import copy
    import pytest

    base_doc = _load(RELEASE)

    mutated_promote = copy.deepcopy(base_doc)
    mutated_promote["jobs"]["promote-internal"]["steps"].insert(
        1,
        {
            "name": "Injected leak before approval",
            "env": {"DATACON_DATABASE_URL": "${{ secrets.DATACON_DATABASE_URL }}"},
            "run": "echo oops",
        },
    )
    with pytest.raises(AssertionError):
        _assert_secrets_scoped(mutated_promote)

    mutated_rollback = copy.deepcopy(base_doc)
    mutated_rollback["jobs"]["rollback-internal"]["steps"].insert(
        1,
        {
            "name": "Injected rollback leak",
            "env": {"DATACON_DATABASE_URL": "${{ secrets.DATACON_DATABASE_URL }}"},
            "run": "echo oops",
        },
    )
    with pytest.raises(AssertionError):
        _assert_secrets_scoped(mutated_rollback)


def test_timeout_helper_rejects_commented_or_removed_timeout():
    import copy
    import pytest

    base_doc = _load(RELEASE)

    mutated_py = copy.deepcopy(base_doc)
    for step in mutated_py["jobs"]["promote-internal"]["steps"]:
        if "timeout=60" in step.get("run", ""):
            step["run"] = step["run"].replace("timeout=60,", "# timeout=60")
    with pytest.raises(AssertionError):
        _assert_smoke_timeouts(mutated_py)

    mutated_sh = copy.deepcopy(base_doc)
    for step in mutated_sh["jobs"]["promote-internal"]["steps"]:
        if "timeout 60 docker run" in step.get("run", ""):
            step["run"] = step["run"].replace("timeout 60 docker run", "docker run")
    with pytest.raises(AssertionError):
        _assert_smoke_timeouts(mutated_sh)


def test_b03_persists_bundle_before_cleanup_and_uploads_only_a_sanitized_summary(tmp_path):
    import ast
    import os
    import subprocess

    b03 = _load(RELEASE)["jobs"]["b03-internal"]
    b03_steps = _steps(b03)
    run_step = next(
        step for step in b03_steps if "run_b03_acceptance" in step.get("run", "")
    )
    assert "DATACON_B03_EVIDENCE_DIR" in run_step.get("env", {})
    assert "${{ secrets.DATACON_B03_EVIDENCE_DIR" not in str(run_step.get("env", {}))
    run_text = run_step["run"]
    shell_guard = run_text.split("uv run")[0]
    guard_env = dict(
        os.environ,
        DATACON_B03_CASE_ROOT="/tmp/case",
        DATACON_B03_ADMISSION="/tmp/admission.json",
        DATACON_B03_REVIEW='{"reviewer":"ops"}',
        DATACON_B03_EVIDENCE_DIR="",
    )
    guard_proc = subprocess.run(
        ["bash", "-c", shell_guard],
        env=guard_env,
        capture_output=True,
        text=True,
        timeout=15,
    )
    assert guard_proc.returncode != 0
    assert "DATACON_B03_EVIDENCE_DIR" in guard_proc.stderr

    blocks = _extract_python_heredocs(run_text)
    assert blocks
    acceptance_block = next(
        block for block in blocks if "run_b03_acceptance" in block
    )
    tree = ast.parse(acceptance_block)
    try_nodes = [node for node in ast.walk(tree) if isinstance(node, ast.Try)]
    assert try_nodes
    persist_in_try = any(
        isinstance(node, ast.Attribute) and node.attr == "persist_b03_evidence_bundle"
        for try_node in try_nodes
        for stmt in try_node.body
        for node in ast.walk(stmt)
    )
    assert persist_in_try, "persist_b03_evidence_bundle must run inside try before finally cleanup"
    assert "shutil.rmtree(bundle_out" in acceptance_block
    assert "DATACON_B03_RECORD=" in acceptance_block

    summary_step = next(
        step for step in b03_steps if "b03-acceptance-summary.json" in step.get("run", "")
    )
    summary_blocks = _extract_python_heredocs(summary_step["run"])
    assert summary_blocks
    summary_tree = ast.parse(summary_blocks[0])
    summary_assign = next(
        node
        for node in ast.walk(summary_tree)
        if isinstance(node, ast.Assign)
        and any(isinstance(t, ast.Name) and t.id == "summary" for t in node.targets)
        and isinstance(node.value, ast.Dict)
    )
    summary_map = {
        k.value: v
        for k, v in zip(summary_assign.value.keys, summary_assign.value.values)
        if isinstance(k, ast.Constant) and isinstance(k.value, str)
    }
    for key in (
        "candidate_digest",
        "b03_manifest_digest",
        "storage_ref",
        "run_id",
    ):
        assert key in summary_map, f"summary missing {key}"
    assert "bundle_path" not in summary_map
    assert "bundle_path" not in summary_blocks[0]
    assert "DATACON_B03_CASE_ROOT" not in summary_step["run"]


def test_rollback_runs_release_slots_compatibility_in_pre_switch_smoke_not_post_commit():
    import ast
    import json
    import subprocess
    import types

    rollback = _load(RELEASE)["jobs"]["rollback-internal"]
    steps = _steps(rollback)
    assert not any(
        "release slots" in step.get("run", "") and "rollback_release" not in step.get("run", "")
        for step in steps
    ), "post-commit release slots gating step must not exist"
    restore_step = next(
        step for step in steps if "rollback_release" in step.get("run", "")
    )
    blocks = _extract_python_heredocs(restore_step["run"])
    assert blocks
    tree = ast.parse(blocks[0])
    rb_call = next(
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "rollback_release"
    )
    smoke_kw = next(kw for kw in rb_call.keywords if kw.arg == "smoke_checks")
    assert isinstance(smoke_kw.value, ast.Dict)
    smoke_keys = {k.value for k in smoke_kw.value.keys if isinstance(k, ast.Constant)}
    assert "release_slots" in smoke_keys
    assert "active_release_restored" in restore_step["run"]

    # Verify `current = store.active_release()` is read and checked before switching,
    # and test the extracted `release_slots_compatible` function with positive/negative payloads.
    active_release_calls = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "active_release"
        and isinstance(node.func.value, ast.Name)
        and node.func.value.id == "store"
    ]
    assert len(active_release_calls) >= 2, (
        "rollback script must read current = store.active_release() before switching "
        "as well as inside active_release_restored()"
    )
    compat_fn = next(
        node
        for node in tree.body
        if isinstance(node, ast.FunctionDef) and node.name == "release_slots_compatible"
    )
    fn_module = ast.Module(body=[compat_fn], type_ignores=[])
    ast.fix_missing_locations(fn_module)
    current_image = "sha256:" + "1" * 64
    fake_proc = types.SimpleNamespace(returncode=0, stdout="")

    class _FakeSubprocess:
        TimeoutExpired = subprocess.TimeoutExpired

        @staticmethod
        def run(*args, **kwargs):
            return fake_proc

    ns = {
        "subprocess": _FakeSubprocess,
        "json": json,
        "current": {"image_id": current_image},
        "target_image": "sha256:" + "0" * 64,
    }
    exec(compile(fn_module, "<release-slots-compatible>", "exec"), ns, ns)  # noqa: S102
    compat = ns["release_slots_compatible"]

    # Positive case: internal-lab, integer active_slots, matching active_release.image_id
    fake_proc.returncode = 0
    fake_proc.stdout = json.dumps(
        {
            "environment": "internal-lab",
            "active_slots": 0,
            "active_release": {"image_id": current_image},
            "drained": True,
        }
    )
    assert compat() is True

    # Negative cases: wrong environment, wrong image_id, non-int active_slots, non-dict active_release, bad exit/json
    for bad_payload in (
        {"environment": "prod", "active_slots": 0, "active_release": {"image_id": current_image}},
        {"environment": "internal-lab", "active_slots": 0, "active_release": {"image_id": "sha256:" + "9" * 64}},
        {"environment": "internal-lab", "active_slots": True, "active_release": {"image_id": current_image}},
        {"environment": "internal-lab", "active_slots": "0", "active_release": {"image_id": current_image}},
        {"environment": "internal-lab", "active_slots": 0, "active_release": None},
    ):
        fake_proc.returncode = 0
        fake_proc.stdout = json.dumps(bad_payload)
        assert compat() is False, bad_payload

    fake_proc.stdout = "not-json"
    assert compat() is False
    fake_proc.returncode = 1
    fake_proc.stdout = json.dumps(
        {"environment": "internal-lab", "active_slots": 0, "active_release": {"image_id": current_image}}
    )
    assert compat() is False


def test_run_suite_script_respects_both_pytest_and_junit_exit_codes(tmp_path):
    import os
    import subprocess

    script = REPO_ROOT / "scripts" / "run_suite.sh"
    assert script.is_file()
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    fake_uv = fake_bin / "uv"
    fake_uv.write_text(
        "#!/usr/bin/env bash\n"
        "set -uo pipefail\n"
        "shift 2 # drop: run --frozen\n"
        'cmd="$1"\n'
        'if [ "$cmd" = "pytest" ]; then\n'
        '  for arg in "$@"; do\n'
        '    case "$arg" in --junitxml=*) xml="${arg#--junitxml=}" ;; esac\n'
        "  done\n"
        '  mkdir -p "$(dirname "$xml")"\n'
        '  printf \'%s\' "$FAKE_JUNIT_XML" > "$xml"\n'
        '  exit "${FAKE_PYTEST_RC:-0}"\n'
        "fi\n"
        f'exec "{REPO_ROOT / ".venv" / "bin" / "python"}" "${{@:2}}"\n',
        encoding="utf-8",
    )
    fake_uv.chmod(0o755)

    valid_xml = (
        '<testsuite tests="1" skipped="0" failures="0" errors="0">'
        '<testcase name="ok" /></testsuite>'
    )
    fail_xml = (
        '<testsuite tests="1" skipped="0" failures="1" errors="0">'
        '<testcase name="bad"><failure message="boom" /></testcase></testsuite>'
    )
    base_env = dict(os.environ)
    base_env["PATH"] = f"{fake_bin}:{base_env['PATH']}"
    base_env["PYTHONPATH"] = str(REPO_ROOT / "src")

    # 1. pytest exits 1 even with a valid all-pass JUnit XML -> MUST fail (non-zero).
    env1 = dict(base_env, FAKE_PYTEST_RC="1", FAKE_JUNIT_XML=valid_xml)
    r1 = subprocess.run(
        ["bash", str(script), "contract", "contract", str(tmp_path / "r1.xml")],
        env=env1,
        capture_output=True,
        text=True,
        timeout=15,
    )
    assert r1.returncode != 0, f"expected failure when pytest_rc=1: {r1.stdout} {r1.stderr}"

    # 2. pytest exits 0 with failing JUnit XML -> MUST fail (non-zero).
    env2 = dict(base_env, FAKE_PYTEST_RC="0", FAKE_JUNIT_XML=fail_xml)
    r2 = subprocess.run(
        ["bash", str(script), "contract", "contract", str(tmp_path / "r2.xml")],
        env=env2,
        capture_output=True,
        text=True,
        timeout=15,
    )
    assert r2.returncode != 0

    # 3. pytest exits 0 with valid all-pass JUnit XML -> MUST succeed (0).
    env3 = dict(base_env, FAKE_PYTEST_RC="0", FAKE_JUNIT_XML=valid_xml)
    r3 = subprocess.run(
        ["bash", str(script), "contract", "contract", str(tmp_path / "r3.xml")],
        env=env3,
        capture_output=True,
        text=True,
        timeout=15,
    )
    assert r3.returncode == 0, r3.stderr


def test_workflows_use_shared_run_suite_script():
    ci_text = _run_text(_load(CI)["jobs"]["test"])
    rel_text = _run_text(_load(RELEASE)["jobs"]["test-report"])
    assert "scripts/run_suite.sh" in ci_text
    assert "scripts/run_suite.sh" in rel_text


def test_rollback_supports_baseline_and_expired_artifact_local_digest_path_with_audit_provenance():
    import pytest

    doc = _load(RELEASE)
    rollback = doc["jobs"]["rollback-internal"]
    steps = _steps(rollback)
    text = _run_text(rollback)

    # 1. Cross-run download step is gated on non-empty ARTIFACT_RUN_ID while preserving strict provenance.
    dl_step = next(
        step
        for step in steps
        if step.get("uses", "").startswith("actions/download-artifact@")
    )
    assert dl_step.get("if") == "env.ARTIFACT_RUN_ID != ''"
    assert dl_step["with"]["run-id"] == "${{ env.ARTIFACT_RUN_ID }}"

    # 2. Verify protected ref allows empty ARTIFACT_RUN_ID, while rejecting non-numeric ARTIFACT_RUN_ID.
    verify_step = next(step for step in steps if step.get("name") == "Verify protected ref")
    verify_blocks = _extract_python_heredocs(verify_step["run"])
    assert verify_blocks
    for bad_id in ("abc", "123abc", " 123"):
        ns = {}
        import os

        old = os.environ.get("ARTIFACT_RUN_ID")
        os.environ["ARTIFACT_RUN_ID"] = bad_id
        try:
            with pytest.raises(SystemExit):
                exec(compile(verify_blocks[0], "<verify-ref>", "exec"), ns, ns)  # noqa: S102
        finally:
            if old is None:
                os.environ.pop("ARTIFACT_RUN_ID", None)
            else:
                os.environ["ARTIFACT_RUN_ID"] = old

    # 3. Validate/load steps do NOT unconditionally fail when ARTIFACT_RUN_ID is empty,
    #    and verify immutable TARGET_DIGEST via `docker image inspect`.
    assert "artifact_run_id is required to load" not in text
    assert 'docker image inspect "${TARGET_DIGEST}"' in text or 'docker image inspect "$TARGET_DIGEST"' in text
    assert "DATACON_IMAGE_ARCHIVE_DIR" in rollback.get("env", {}) or "DATACON_IMAGE_ARCHIVE_DIR" in text

    # 4. Smoke & restore step strictly requires persisted release_events provenance (action in bootstrap/promote/rollback)
    #    and candidate_digest / manifest_digest; never falls back to unrecorded images.
    restore_step = next(step for step in steps if "rollback_release" in step.get("run", ""))
    restore_run = restore_step["run"]
    assert "release_for_image" in restore_run
    assert 'target.get("action") not in ("bootstrap", "promote", "rollback")' in restore_run or 'in ("bootstrap", "promote", "rollback")' in restore_run
    assert 'os.environ["TARGET_DIGEST"]' in restore_run


def test_secret_scoping_helper_rejects_b03_run_and_with_leaks():
    import copy
    import pytest

    base_doc = _load(RELEASE)

    mutated_b03_run = copy.deepcopy(base_doc)
    mutated_b03_run["jobs"]["b03-internal"]["steps"].insert(
        1,
        {
            "name": "Leak B03 secret in run",
            "run": "echo DATACON_B03_CASE_ROOT",
        },
    )
    with pytest.raises(AssertionError):
        _assert_secrets_scoped(mutated_b03_run)

    mutated_b03_with = copy.deepcopy(base_doc)
    mutated_b03_with["jobs"]["b03-internal"]["steps"].insert(
        1,
        {
            "name": "Leak B03 secret in with",
            "uses": "actions/checkout@11d5960a326750d5838078e36cf38b85af677262",
            "with": {"path": "${{ secrets.DATACON_B03_ADMISSION }}"},
        },
    )
    with pytest.raises(AssertionError):
        _assert_secrets_scoped(mutated_b03_with)

    mutated_rb_with = copy.deepcopy(base_doc)
    mutated_rb_with["jobs"]["rollback-internal"]["steps"].insert(
        1,
        {
            "name": "Leak rollback secret in with",
            "uses": "actions/checkout@11d5960a326750d5838078e36cf38b85af677262",
            "with": {"token": "${{ secrets.DATACON_DATABASE_URL }}"},
        },
    )
    with pytest.raises(AssertionError):
        _assert_secrets_scoped(mutated_rb_with)


def test_timeout_helper_rejects_aliased_subprocess_and_os_system():
    import copy
    import pytest

    base_doc = _load(RELEASE)

    # 1. Local variable alias: `runner = subprocess.run; runner(["docker", ...])` without timeout=
    mutated_alias = copy.deepcopy(base_doc)
    for step in mutated_alias["jobs"]["promote-internal"]["steps"]:
        if "timeout=60" in step.get("run", ""):
            step["run"] = step["run"].replace(
                "import sys\n",
                "import sys\nrunner = subprocess.run\nrunner(['docker', 'ps'])\n",
            )
            break
    with pytest.raises(AssertionError):
        _assert_smoke_timeouts(mutated_alias)

    # 2. subprocess.check_call without timeout=
    mutated_check_call = copy.deepcopy(base_doc)
    for step in mutated_check_call["jobs"]["rollback-internal"]["steps"]:
        if "timeout=60" in step.get("run", ""):
            step["run"] = step["run"].replace(
                "import sys\n",
                "import sys\nsubprocess.check_call(['docker', 'ps'])\n",
            )
            break
    with pytest.raises(AssertionError):
        _assert_smoke_timeouts(mutated_check_call)

    # 3. subprocess.Popen
    mutated_popen = copy.deepcopy(base_doc)
    for step in mutated_popen["jobs"]["promote-internal"]["steps"]:
        if "timeout=60" in step.get("run", ""):
            step["run"] = step["run"].replace(
                "import sys\n",
                "import sys\nsubprocess.Popen(['docker', 'ps'])\n",
            )
            break
    with pytest.raises(AssertionError):
        _assert_smoke_timeouts(mutated_popen)

    # 4. os.system
    mutated_os = copy.deepcopy(base_doc)
    for step in mutated_os["jobs"]["rollback-internal"]["steps"]:
        if "timeout=60" in step.get("run", ""):
            step["run"] = step["run"].replace(
                "import sys\n",
                "import sys\nos.system('docker ps')\n",
            )
            break
    with pytest.raises(AssertionError):
        _assert_smoke_timeouts(mutated_os)

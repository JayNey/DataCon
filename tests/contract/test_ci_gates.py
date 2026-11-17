"""TDD contract tests for T07 CI merge gates, supply-chain checks, and Dockerfile."""

from __future__ import annotations

import json
from pathlib import Path
import shutil

import pytest

from datacon import ci_gates, release

REPO_ROOT = Path(__file__).resolve().parents[2]


def test_markdown_relative_links_reject_broken_and_accept_valid(tmp_path):
    (tmp_path / "docs").mkdir()
    (tmp_path / "docs" / "target.md").write_text("# Target\n", encoding="utf-8")
    good = tmp_path / "docs" / "good.md"
    good.write_text("See [target](target.md) and [ext](https://example.invalid).\n", encoding="utf-8")
    bad = tmp_path / "docs" / "bad.md"
    bad.write_text("Broken [missing](does-not-exist.md).\n", encoding="utf-8")

    assert ci_gates.check_markdown_links([good], root=tmp_path) == []
    errors = ci_gates.check_markdown_links([bad], root=tmp_path)
    assert len(errors) == 1
    assert "does-not-exist.md" in errors[0]


def test_req_and_tc_reference_consistency(tmp_path):
    doc = tmp_path / "README.md"
    doc.write_text("Covers REQ-01, REQ-10, TC-01, TC-10.\n", encoding="utf-8")
    assert ci_gates.check_req_tc_consistency([doc]) == []

    bad_doc = tmp_path / "BAD.md"
    bad_doc.write_text("Unknown REQ-99 and TC-42.\n", encoding="utf-8")
    errors = ci_gates.check_req_tc_consistency([bad_doc])
    assert any("REQ-99" in err for err in errors)
    assert any("TC-42" in err for err in errors)


def _workflow(tmp_path: Path, body: str) -> Path:
    path = tmp_path / "workflow.yml"
    path.write_text(body, encoding="utf-8")
    return path


def test_workflow_security_accepts_pinned_least_privilege_workflow(tmp_path):
    good = _workflow(
        tmp_path,
        "name: Good\n"
        "on:\n"
        "  pull_request:\n"
        "permissions:\n"
        "  contents: read\n"
        "jobs:\n"
        "  test:\n"
        "    steps:\n"
        "      - uses: actions/checkout@11d5960a326750d5838078e36cf38b85af677262 # v4\n",
    )
    assert ci_gates.check_workflow_security([good]) == []


def test_workflow_security_rejects_commented_permissions_and_mutable_tags(tmp_path):
    bad = _workflow(
        tmp_path,
        "name: Bad\n"
        "on:\n"
        "  pull_request:\n"
        "permissions:\n"
        "  # contents: read\n"
        "  pull-requests: write\n"
        "jobs:\n"
        "  test:\n"
        "    steps:\n"
        "      - uses: actions/checkout@v4\n",
    )
    errors = ci_gates.check_workflow_security([bad])
    assert any("not allowed" in err for err in errors)
    assert any("40-char" in err or "SHA" in err for err in errors)


def test_workflow_security_rejects_continue_on_error_true(tmp_path):
    for value in ("true", "True", "yes"):
        bad = _workflow(
            tmp_path,
            "name: Bad\n"
            "on:\n"
            "  pull_request:\n"
            "permissions:\n"
            "  contents: read\n"
            "jobs:\n"
            "  test:\n"
            "    steps:\n"
            "      - uses: actions/checkout@11d5960a326750d5838078e36cf38b85af677262\n"
            f"        continue-on-error: {value}\n",
        )
        errors = ci_gates.check_workflow_security([bad])
        assert any("continue-on-error" in err for err in errors), (value, errors)


def test_workflow_security_rejects_write_permissions_and_pull_request_target(tmp_path):
    for permission in (
        "  contents: write\n",
        "  id-token: write\n",
        "  packages: write\n",
        "  security-events: write\n",
        "  pull-requests: write\n",
    ):
        bad = _workflow(
            tmp_path,
            "name: Bad\n"
            "on:\n"
            "  pull_request_target:\n"
            "permissions:\n"
            f"{permission}"
            "jobs:\n"
            "  test:\n"
            "    steps:\n"
            "      - uses: actions/checkout@11d5960a326750d5838078e36cf38b85af677262\n",
        )
        errors = ci_gates.check_workflow_security([bad])
        assert any("pull_request_target" in err for err in errors)
        assert any("permission" in err for err in errors)


def test_workflow_security_rejects_write_all(tmp_path):
    bad = _workflow(
        tmp_path,
        "name: Bad\n"
        "on:\n"
        "  pull_request:\n"
        "permissions: write-all\n"
        "jobs:\n"
        "  test:\n"
        "    steps:\n"
        "      - uses: actions/checkout@11d5960a326750d5838078e36cf38b85af677262\n",
    )
    errors = ci_gates.check_workflow_security([bad])
    assert any("permissions must be a mapping" in err for err in errors)

    empty = tmp_path / "empty.yml"
    empty.write_text(
        "name: Empty\n"
        "on:\n"
        "  pull_request:\n"
        "permissions: {}\n"
        "jobs:\n"
        "  test:\n"
        "    steps:\n"
        "      - uses: actions/checkout@11d5960a326750d5838078e36cf38b85af677262\n",
        encoding="utf-8",
    )
    errors = ci_gates.check_workflow_security([empty])
    assert any("contents: read" in err for err in errors)


def test_workflow_security_rejects_run_expressions_and_untrusted_checkout_ref(tmp_path):
    expression = _workflow(
        tmp_path,
        "name: Bad\n"
        "on:\n"
        "  workflow_dispatch:\n"
        "permissions:\n"
        "  contents: read\n"
        "jobs:\n"
        "  test:\n"
        "    steps:\n"
        "      - uses: actions/checkout@11d5960a326750d5838078e36cf38b85af677262\n"
        "        with:\n"
        "          ref: ${{ github.event.pull_request.head.sha }}\n"
        "      - run: echo \"${{ inputs.target_digest }}\"\n",
    )
    errors = ci_gates.check_workflow_security([expression])
    assert any("checkout ref comes from an expression" in err for err in errors)
    assert any("untrusted '${{ ... }}'" in err for err in errors)

    env_ref = tmp_path / "env-ref.yml"
    env_ref.write_text(
        "name: Bad\n"
        "on:\n"
        "  pull_request:\n"
        "permissions:\n"
        "  contents: read\n"
        "jobs:\n"
        "  test:\n"
        "    steps:\n"
        "      - uses: actions/checkout@11d5960a326750d5838078e36cf38b85af677262\n"
        "        with:\n"
        "          ref: ${{ env.REF }}\n",
        encoding="utf-8",
    )
    errors = ci_gates.check_workflow_security([env_ref])
    assert any("checkout ref comes from an expression" in err for err in errors)


def test_junit_gate_rejects_failures_skips_and_empty_suites(tmp_path):
    ok = tmp_path / "ok.xml"
    ok.write_text('<testsuite tests="3" skipped="0" failures="0" errors="0"/>', encoding="utf-8")
    assert ci_gates.check_junit_report(ok, label="contract") == {
        "label": "contract",
        "total": 3,
        "skipped": 0,
        "failures": 0,
        "errors": 0,
    }

    skipped = tmp_path / "skip.xml"
    skipped.write_text('<testsuite tests="3" skipped="1" failures="0" errors="0"/>', encoding="utf-8")
    with pytest.raises(ci_gates.GateError, match="zero skips"):
        ci_gates.check_junit_report(skipped, label="postgres")

    failed = tmp_path / "fail.xml"
    failed.write_text('<testsuite tests="3" skipped="0" failures="1" errors="0"/>', encoding="utf-8")
    with pytest.raises(ci_gates.GateError, match="zero skips"):
        ci_gates.check_junit_report(failed, label="asan")

    empty = tmp_path / "empty.xml"
    empty.write_text('<testsuite tests="0" skipped="0" failures="0" errors="0"/>', encoding="utf-8")
    with pytest.raises(ci_gates.GateError, match="did not run"):
        ci_gates.check_junit_report(empty, label="docker")


def test_vulnerability_scan_blocks_critical_high_and_invalid_waivers(tmp_path):
    findings = [
        {"id": "CVE-2025-1111", "severity": "HIGH", "package": "demo"},
        {"id": "CVE-2025-2222", "severity": "LOW", "package": "demo2"},
    ]
    with pytest.raises(ci_gates.GateError, match="CVE-2025-1111"):
        ci_gates.evaluate_scan_findings(findings, waivers=[], today="2026-11-17")

    expired_waiver = [
        {
            "id": "CVE-2025-1111",
            "scope": "dev-only",
            "impact": "none in container",
            "owner": "sec-team",
            "expires_at": "2026-11-01",
        }
    ]
    with pytest.raises(ci_gates.GateError, match="expired"):
        ci_gates.evaluate_scan_findings(findings, waivers=expired_waiver, today="2026-11-17")

    incomplete_waiver = [
        {
            "id": "CVE-2025-1111",
            "scope": "dev-only",
            "expires_at": "2026-12-31",
        }
    ]
    with pytest.raises(ci_gates.GateError, match="missing"):
        ci_gates.evaluate_scan_findings(findings, waivers=incomplete_waiver, today="2026-11-17")

    valid_waiver = [
        {
            "id": "CVE-2025-1111",
            "scope": "test dependency only",
            "impact": "not shipped in control plane image",
            "owner": "security-owner",
            "expires_at": "2026-12-31",
        }
    ]
    summary = ci_gates.evaluate_scan_findings(findings, waivers=valid_waiver, today="2026-11-17")
    assert summary["blocked"] == 0
    assert summary["waived"] == 1


def test_trivy_report_is_parsed_and_required():
    clean = {"Results": [{"Target": "image", "Vulnerabilities": []}]}
    assert ci_gates.parse_trivy_findings(clean) == []
    high = {
        "Results": [
            {
                "Vulnerabilities": [
                    {
                        "VulnerabilityID": "CVE-2025-3333",
                        "Severity": "HIGH",
                        "PkgName": "openssl",
                    }
                ]
            }
        ]
    }
    assert ci_gates.parse_trivy_findings(high) == [
        {"id": "CVE-2025-3333", "severity": "HIGH", "package": "openssl"}
    ]
    with pytest.raises(ci_gates.GateError, match="Results"):
        ci_gates.parse_trivy_findings({"not": "a scan"})


def test_secret_scanner_detects_leaked_credentials_everywhere(tmp_path):
    clean = tmp_path / "clean.py"
    clean.write_text('dsn = os.environ["DATACON_DATABASE_URL"]\n', encoding="utf-8")
    assert ci_gates.scan_secrets([clean]) == []

    leak_root = tmp_path / "repo"
    (leak_root / "tests").mkdir(parents=True)
    (leak_root / "examples").mkdir()
    leak = leak_root / "tests" / "leak_probe.py"
    leak.write_text(
        "DSN = 'postgresql://" + "user:" + "hunter2" + "@db.internal:5432/app'\n"
        "KEY = '" + "AKIA" + "A" * 16 + "'\n"
        "PAT = '" + "gh" + "p_" + "A" * 30 + "'\n"
        "PRIVATE = '" + "-----BEGIN " + "OPENSSH PRIVATE KEY-----'\n",
        encoding="utf-8",
    )
    (leak_root / "Dockerfile").write_text(
        "ENV TOKEN='" + "super-secret-token-value" + "'\n", encoding="utf-8"
    )
    (leak_root / "examples" / "leak.json").write_text(
        '{"password": "' + "example-password" + '"}\n', encoding="utf-8"
    )
    files = ci_gates.iter_repo_files(leak_root)
    names = {path.relative_to(leak_root).as_posix() for path in files}
    assert "tests/leak_probe.py" in names
    assert "Dockerfile" in names
    assert "examples/leak.json" in names
    hits = ci_gates.scan_secrets(files)
    assert any("tests/leak_probe.py" in hit for hit in hits)
    assert any("Dockerfile" in hit for hit in hits)

    # The full gate must surface the same leak, not just the helper.
    repo = tmp_path / "full-repo"
    (repo / ".github" / "workflows").mkdir(parents=True)
    (repo / "src").mkdir()
    (repo / "examples").mkdir()
    (repo / "tests").mkdir()
    shutil.copy2(REPO_ROOT / "pyproject.toml", repo / "pyproject.toml")
    shutil.copy2(REPO_ROOT / "uv.lock", repo / "uv.lock")
    shutil.copy2(REPO_ROOT / "requirements-ci.txt", repo / "requirements-ci.txt")
    shutil.copy2(REPO_ROOT / "examples" / "request.json", repo / "examples" / "request.json")
    (repo / "README.md").write_text("# Fixture\n", encoding="utf-8")
    (repo / ".github" / "workflows" / "good.yml").write_text(
        "name: Good\n"
        "on:\n"
        "  pull_request:\n"
        "permissions:\n"
        "  contents: read\n"
        "jobs:\n"
        "  test:\n"
        "    steps:\n"
        "      - uses: actions/checkout@11d5960a326750d5838078e36cf38b85af677262\n",
        encoding="utf-8",
    )
    (repo / "tests" / "leak_probe.py").write_text(
        "DSN = 'postgresql://" + "user:" + "hunter2" + "@db.internal:5432/app'\n",
        encoding="utf-8",
    )
    full = ci_gates.run_repo_static_gates(repo)
    assert full["ok"] is False
    assert any("tests/leak_probe.py" in error for error in full["errors"])


def test_dependency_lock_rejects_commented_requirement_and_bad_pyproject(tmp_path):
    root = tmp_path / "repo"
    root.mkdir()
    shutil.copy2(REPO_ROOT / "pyproject.toml", root / "pyproject.toml")
    shutil.copy2(REPO_ROOT / "uv.lock", root / "uv.lock")
    (root / "requirements-ci.txt").write_text(
        "# uv==0.12.7 --hash=sha256:" + "a" * 64 + "\n", encoding="utf-8"
    )
    errors = ci_gates.check_dependency_lock(root)
    assert any("requirements-ci.txt" in err for err in errors)

    pyproject = (root / "pyproject.toml").read_text(encoding="utf-8")
    (root / "pyproject.toml").write_text(
        pyproject.replace('required-version = "==0.12.7"', 'required-version = "==9.9.9"'),
        encoding="utf-8",
    )
    errors = ci_gates.check_dependency_lock(root)
    assert any("required-version" in err for err in errors)


def test_scan_findings_gate_is_wired_into_repo_static_gates(tmp_path):
    clean = tmp_path / "clean.json"
    clean.write_text(json.dumps({"Results": [{"Vulnerabilities": []}]}), encoding="utf-8")
    report = ci_gates.run_repo_static_gates(
        REPO_ROOT, findings_path=clean, require_scan=True
    )
    assert report["scan"]["status"] == "evaluated", report
    assert report["scan"]["total"] == 0

    high = tmp_path / "high.json"
    high.write_text(
        json.dumps(
            {
                "Results": [
                    {
                        "Vulnerabilities": [
                            {
                                "VulnerabilityID": "CVE-2025-4444",
                                "Severity": "CRITICAL",
                                "PkgName": "demo",
                            }
                        ]
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    report = ci_gates.run_repo_static_gates(REPO_ROOT, findings_path=high)
    assert report["ok"] is False
    assert any("CVE-2025-4444" in error for error in report["errors"])

    missing = ci_gates.run_repo_static_gates(REPO_ROOT, require_scan=True)
    assert missing["ok"] is False
    assert any("scanner report is required" in error for error in missing["errors"])


def test_partition_check_rejects_overlap_and_gaps(tmp_path):
    assert ci_gates.check_test_partition_counts(
        10,
        {"postgres": 4, "docker": 2, "asan": 1, "contract": 3},
        expected_groups=["postgres", "docker", "asan", "contract"],
    ) == []
    overlap = ci_gates.check_test_partition_counts(
        10,
        {"postgres": 5, "docker": 2, "asan": 2, "contract": 3},
        expected_groups=["postgres", "docker", "asan", "contract"],
    )
    assert any("not a partition" in error for error in overlap)
    gap = ci_gates.check_test_partition_counts(
        10,
        {"postgres": 4, "docker": 2, "asan": 1, "contract": 2},
        expected_groups=["postgres", "docker", "asan", "contract"],
    )
    assert any("not a partition" in error for error in gap)
    missing = ci_gates.check_test_partition_counts(
        10,
        {"postgres": 4, "docker": 2, "asan": 1},
        expected_groups=["postgres", "docker", "asan", "contract"],
    )
    assert any("missing groups" in error for error in missing)


def test_release_manifest_boundaries_are_enforced():
    manifest = release.build_release_candidate_manifest(
        source_commit="a" * 40,
        control_plane_image_id="sha256:" + "1" * 64,
        wheel_digest="sha256:" + "2" * 64,
        migrations_dir=REPO_ROOT / "migrations",
        sbom_digest="sha256:" + "3" * 64,
        test_report_digest="sha256:" + "4" * 64,
        scan_report_digest="sha256:" + "5" * 64,
    )
    extra = dict(manifest, unexpected=True)
    with pytest.raises(release.ReleaseGateError, match="unknown"):
        release.validate_release_candidate_manifest(extra)
    reversed_migrations = dict(manifest, migrations=list(reversed(manifest["migrations"])))
    reversed_migrations["migration_version"] = reversed_migrations["migrations"][-1]["file"]
    with pytest.raises(release.ReleaseGateError, match="sorted"):
        release.validate_release_candidate_manifest(reversed_migrations)


def test_repo_ci_gates_and_dockerfile_pass():
    report = ci_gates.run_repo_static_gates(REPO_ROOT)
    assert report["ok"] is True, json.dumps(report, indent=2)

    dockerfile = REPO_ROOT / "Dockerfile"
    assert dockerfile.is_file()
    content = dockerfile.read_text(encoding="utf-8")
    assert "USER " in content
    assert "USER root" not in content
    assert "migrations" in content
    assert "uv.lock" in content
    assert (REPO_ROOT / ".dockerignore").is_file()

    release_wf = REPO_ROOT / ".github" / "workflows" / "release.yml"
    assert release_wf.is_file()
    assert ci_gates.check_workflow_security(
        [REPO_ROOT / ".github" / "workflows" / "ci.yml", release_wf]
    ) == []

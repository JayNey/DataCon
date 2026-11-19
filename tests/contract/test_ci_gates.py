"""TDD contract tests for T07 CI merge gates, supply-chain checks, and Dockerfile."""

from __future__ import annotations

import json
from pathlib import Path
import re
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


def test_workflow_security_rejects_unpinned_reusable_workflow_and_branch_run_expressions(tmp_path):
    reusable_bad = tmp_path / "reusable-bad.yml"
    reusable_bad.write_text(
        "name: BadReusable\n"
        "on:\n"
        "  workflow_dispatch:\n"
        "permissions:\n"
        "  contents: read\n"
        "jobs:\n"
        "  call-other:\n"
        "    uses: org/repo/.github/workflows/deploy.yml@main\n",
        encoding="utf-8",
    )
    errors = ci_gates.check_workflow_security([reusable_bad])
    assert any("reusable" in err.lower() or "40-char" in err for err in errors)

    reusable_good = tmp_path / "reusable-good.yml"
    reusable_good.write_text(
        "name: GoodReusable\n"
        "on:\n"
        "  workflow_dispatch:\n"
        "permissions:\n"
        "  contents: read\n"
        "jobs:\n"
        "  call-sha:\n"
        "    uses: org/repo/.github/workflows/deploy.yml@" + "a" * 40 + "\n"
        "  call-local:\n"
        "    uses: ./.github/workflows/ci.yml\n",
        encoding="utf-8",
    )
    assert ci_gates.check_workflow_security([reusable_good]) == []

    head_ref = tmp_path / "head-ref.yml"
    head_ref.write_text(
        "name: BadRef\n"
        "on:\n"
        "  pull_request:\n"
        "permissions:\n"
        "  contents: read\n"
        "jobs:\n"
        "  test:\n"
        "    steps:\n"
        "      - run: echo \"${{ github.head_ref }}\"\n"
        "      - run: echo \"${{ github.ref_name }}\"\n",
        encoding="utf-8",
    )
    errors = ci_gates.check_workflow_security([head_ref])
    assert len(errors) == 2
    assert all("untrusted '${{ ... }}'" in err for err in errors)


def _junit(
    tests: int,
    *,
    skipped: int = 0,
    failures: int = 0,
    errors: int = 0,
) -> str:
    cases = []
    for index in range(tests):
        if index < failures:
            child = "<failure message=\"boom\" />"
        elif index < failures + errors:
            child = "<error message=\"boom\" />"
        elif index < failures + errors + skipped:
            child = "<skipped />"
        else:
            child = ""
        cases.append(f'<testcase name="t{index}">{child}</testcase>')
    return (
        f'<testsuite tests="{tests}" skipped="{skipped}" '
        f'failures="{failures}" errors="{errors}">'
        + "".join(cases)
        + "</testsuite>"
    )


def test_junit_gate_rejects_failures_skips_and_empty_suites(tmp_path):
    ok = tmp_path / "ok.xml"
    ok.write_text(_junit(3), encoding="utf-8")
    assert ci_gates.check_junit_report(ok, label="contract") == {
        "label": "contract",
        "total": 3,
        "skipped": 0,
        "failures": 0,
        "errors": 0,
    }

    skipped = tmp_path / "skip.xml"
    skipped.write_text(_junit(3, skipped=1), encoding="utf-8")
    with pytest.raises(ci_gates.GateError, match="zero skips"):
        ci_gates.check_junit_report(skipped, label="postgres")

    failed = tmp_path / "fail.xml"
    failed.write_text(_junit(3, failures=1), encoding="utf-8")
    with pytest.raises(ci_gates.GateError, match="zero skips"):
        ci_gates.check_junit_report(failed, label="asan")

    empty = tmp_path / "empty.xml"
    empty.write_text(_junit(0), encoding="utf-8")
    with pytest.raises(ci_gates.GateError, match="did not run"):
        ci_gates.check_junit_report(empty, label="docker")


def test_junit_gate_rejects_attribute_child_contradictions_and_deep_nesting(tmp_path):
    spoofed = tmp_path / "spoofed.xml"
    spoofed.write_text(
        '<testsuite tests="1" skipped="0" failures="0" errors="0">'
        '<testcase name="hidden"><failure message="boom" /></testcase>'
        "</testsuite>",
        encoding="utf-8",
    )
    with pytest.raises(ci_gates.GateError, match="disagree|contradictory"):
        ci_gates.check_junit_report(spoofed, label="contract")

    miscounted = tmp_path / "miscounted.xml"
    miscounted.write_text(
        '<testsuite tests="2" skipped="0" failures="0" errors="0">'
        '<testcase name="only-one" /></testsuite>',
        encoding="utf-8",
    )
    with pytest.raises(ci_gates.GateError, match="contradictory"):
        ci_gates.check_junit_report(miscounted, label="contract")

    nested = tmp_path / "nested.xml"
    nested.write_text(
        "<testsuites><testsuite tests=\"1\" skipped=\"0\" failures=\"0\" "
        "errors=\"0\"><testcase name=\"ok\" /></testsuite>"
        "<testsuite tests=\"2\" skipped=\"1\" failures=\"0\" errors=\"0\">"
        "<testcase name=\"a\" /><testcase name=\"b\"><skipped /></testcase>"
        "</testsuite></testsuites>",
        encoding="utf-8",
    )
    with pytest.raises(ci_gates.GateError, match="zero skips"):
        ci_gates.check_junit_report(nested, label="postgres")


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

    invalid_calendar_waiver = [
        {
            "id": "CVE-2025-1111",
            "scope": "dev-only",
            "impact": "none in container",
            "owner": "sec-team",
            "expires_at": "2026-02-31",
        }
    ]
    with pytest.raises(ci_gates.GateError, match="expires_at"):
        ci_gates.evaluate_scan_findings(
            findings, waivers=invalid_calendar_waiver, today="2026-11-17"
        )

    valid_waiver = [
        {
            "id": "CVE-2025-1111",
            "scope": "package:demo",
            "impact": "not shipped in control plane image",
            "owner": "security-owner",
            "expires_at": "2026-12-31",
        }
    ]
    summary = ci_gates.evaluate_scan_findings(findings, waivers=valid_waiver, today="2026-11-17")
    assert summary["blocked"] == 0
    assert summary["waived"] == 1


def test_scan_gate_reports_every_blocked_finding_in_one_error():
    findings = [
        {"id": "CVE-2025-0001", "severity": "HIGH", "package": "bsdutils"},
        {"id": "CVE-2025-0002", "severity": "CRITICAL", "package": "libssl3"},
        {"id": "CVE-2025-0003", "severity": "LOW", "package": "ignored"},
        {"id": "CVE-2025-0004", "severity": "HIGH", "package": "python3.12"},
    ]
    waivers = [
        {
            "id": "CVE-2025-0001",
            "scope": "package:bsdutils",
            "impact": "not reachable in the control-plane entrypoint",
            "owner": "sec-team",
            "expires_at": "2026-12-31",
        }
    ]
    with pytest.raises(ci_gates.GateError) as captured:
        ci_gates.evaluate_scan_findings(findings, waivers=waivers, today="2026-11-17")

    # One error, one line per blocked finding: the waived and LOW findings must
    # not create extra lines, and the loop must not stop at the first block.
    lines = str(captured.value).splitlines()
    assert lines == [
        "unwaived CRITICAL vulnerability finding: CVE-2025-0002 (scope=libssl3)",
        "unwaived HIGH vulnerability finding: CVE-2025-0004 (scope=python3.12)",
    ]
    summary = captured.value.scan_summary
    assert summary["total"] == 4
    assert summary["blocked"] == 2
    assert summary["waived"] == 1
    assert summary["blocked_findings"] == [
        {"severity": "CRITICAL", "id": "CVE-2025-0002", "scope": "libssl3"},
        {"severity": "HIGH", "id": "CVE-2025-0004", "scope": "python3.12"},
    ]


def test_scan_gate_json_output_lists_all_blocked_findings(tmp_path, capsys):
    report = tmp_path / "trivy.json"
    report.write_text(
        json.dumps(
            {
                "SchemaVersion": 2,
                "ArtifactName": "datacon-ci",
                "Results": [
                    {
                        "Target": "datacon-ci (debian 12.11)",
                        "Vulnerabilities": [
                            {
                                "VulnerabilityID": "CVE-2025-1001",
                                "Severity": "HIGH",
                                "PkgName": "bsdutils",
                            },
                            {
                                "VulnerabilityID": "CVE-2025-1002",
                                "Severity": "CRITICAL",
                                "PkgName": "libssl3",
                            },
                            {
                                "VulnerabilityID": "CVE-2025-1003",
                                "Severity": "MEDIUM",
                                "PkgName": "ignored",
                            },
                        ],
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    waivers = tmp_path / "waivers.json"
    waivers.write_text("[]\n", encoding="utf-8")

    exit_code = ci_gates.main(
        [
            "--root",
            str(REPO_ROOT),
            "--findings",
            str(report),
            "--waivers",
            str(waivers),
            "--json",
        ]
    )
    assert exit_code == 1
    payload = json.loads(capsys.readouterr().out)
    assert payload["total"] == 3
    assert payload["blocked"] == 2
    assert payload["waived"] == 0
    assert payload["blocked_findings"] == [
        {"severity": "HIGH", "id": "CVE-2025-1001", "scope": "bsdutils"},
        {"severity": "CRITICAL", "id": "CVE-2025-1002", "scope": "libssl3"},
    ]


def test_trivy_report_is_parsed_and_required():
    clean = {"SchemaVersion": 2, "ArtifactName": "image", "Results": [{"Target": "image", "Vulnerabilities": []}]}
    assert ci_gates.parse_trivy_findings(clean) == []
    high = {
        "SchemaVersion": 2,
        "ArtifactName": "image",
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
        {"id": "CVE-2025-3333", "severity": "HIGH", "package": "openssl", "target": ""}
    ]
    with pytest.raises(ci_gates.GateError, match="SchemaVersion|Results"):
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
        "# uv==0.13.7 --hash=sha256:" + "a" * 64 + "\n", encoding="utf-8"
    )
    errors = ci_gates.check_dependency_lock(root)
    assert any("requirements-ci.txt" in err for err in errors)

    shutil.copy2(REPO_ROOT / "requirements-ci.txt", root / "requirements-ci.txt")
    pyproject = (REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8")
    expected_required = 'required-version = ">=0.13.7,<0.14"'
    expected_build = 'requires = ["uv_build>=0.13.7,<0.14"]'
    assert expected_required in pyproject
    assert expected_build in pyproject

    for bad_required in (
        "==9.9.9",
        ">=0.13.7",
        ">=0.13.7,<0.15",
        ">=0.13.8,<0.14",
        "==0.12.7",
    ):
        mutated = pyproject.replace(
            expected_required, f'required-version = "{bad_required}"'
        )
        assert mutated != pyproject
        (root / "pyproject.toml").write_text(mutated, encoding="utf-8")
        errors = ci_gates.check_dependency_lock(root)
        assert any("required-version" in err for err in errors), (bad_required, errors)

    for bad_build_line in (
        "",
        'requires = ["uv_build==0.12.7"]',
        'requires = ["uv_build==0.13.7"]',
        'requires = ["uv_build>=0.13.7"]',
        'requires = ["uv_build>=0.13.7,<0.15"]',
    ):
        mutated = pyproject.replace(expected_build, bad_build_line)
        assert mutated != pyproject
        (root / "pyproject.toml").write_text(mutated, encoding="utf-8")
        errors = ci_gates.check_dependency_lock(root)
        assert any("build-system" in err for err in errors), (bad_build_line, errors)

    # Extra unpinned/unhashed dependency line alongside valid uv pin must fail.
    extra_dep_root = tmp_path / "extra-dep"
    extra_dep_root.mkdir()
    shutil.copy2(REPO_ROOT / "pyproject.toml", extra_dep_root / "pyproject.toml")
    shutil.copy2(REPO_ROOT / "uv.lock", extra_dep_root / "uv.lock")
    valid_uv_line = (REPO_ROOT / "requirements-ci.txt").read_text(encoding="utf-8")
    (extra_dep_root / "requirements-ci.txt").write_text(
        valid_uv_line + "\nrequests>=2.0\n", encoding="utf-8"
    )
    errors = ci_gates.check_dependency_lock(extra_dep_root)
    assert any("requirements-ci.txt" in err for err in errors)


def test_scan_findings_gate_is_wired_into_repo_static_gates(tmp_path):
    clean = tmp_path / "clean.json"
    clean.write_text(
        json.dumps({"SchemaVersion": 2, "ArtifactName": "image", "Results": [{"Target": "image", "Vulnerabilities": []}]}),
        encoding="utf-8",
    )
    report = ci_gates.run_repo_static_gates(
        REPO_ROOT, findings_path=clean, require_scan=True
    )
    assert report["scan"]["status"] == "evaluated", report
    assert report["scan"]["total"] == 0

    high = tmp_path / "high.json"
    high.write_text(
        json.dumps(
            {
                "SchemaVersion": 2,
                "ArtifactName": "image",
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


def test_trivy_gate_rejects_empty_or_metadata_less_reports(tmp_path):
    empty = tmp_path / "empty.json"
    empty.write_text(json.dumps({"SchemaVersion": 2, "Results": []}), encoding="utf-8")
    with pytest.raises(ci_gates.GateError, match="no scan targets"):
        ci_gates.evaluate_scan_report(empty)

    metadata_less = tmp_path / "metadata-less.json"
    metadata_less.write_text(json.dumps({"Results": [{"Vulnerabilities": []}]}), encoding="utf-8")
    with pytest.raises(ci_gates.GateError, match="SchemaVersion|metadata"):
        ci_gates.evaluate_scan_report(metadata_less)

    duplicate_keys = tmp_path / "duplicate.json"
    duplicate_keys.write_text(
        '{"SchemaVersion": 2, "SchemaVersion": 2, "Results": []}', encoding="utf-8"
    )
    with pytest.raises(ci_gates.GateError, match="strictly|duplicate"):
        ci_gates.evaluate_scan_report(duplicate_keys)


def test_waiver_scope_is_bound_to_the_package_or_target(tmp_path):
    findings = [
        {"id": "CVE-2025-7777", "severity": "CRITICAL", "package": "pkg-a", "target": "img"},
        {"id": "CVE-2025-7777", "severity": "CRITICAL", "package": "openssl", "target": "img"},
    ]
    waiver = [
        {
            "id": "CVE-2025-7777",
            "scope": "package:pkg-a",
            "impact": "not reachable in pkg-a build",
            "owner": "sec-team",
            "expires_at": "2026-12-31",
        }
    ]
    with pytest.raises(ci_gates.GateError, match="openssl"):
        ci_gates.evaluate_scan_findings(findings, waivers=waiver, today="2026-11-17")

    only_pkg_a = [findings[0]]
    summary = ci_gates.evaluate_scan_findings(
        only_pkg_a, waivers=waiver, today="2026-11-17"
    )
    assert summary["waived"] == 1 and summary["blocked"] == 0

    conflicting = [waiver[0], dict(waiver[0])]
    with pytest.raises(ci_gates.GateError, match="duplicate|conflicting"):
        ci_gates.evaluate_scan_findings(
            only_pkg_a, waivers=conflicting, today="2026-11-17"
        )


def test_workflow_security_rejects_with_injection_but_allows_env_indirection(tmp_path):
    bad = _workflow(
        tmp_path,
        "name: Bad\n"
        "on:\n"
        "  workflow_dispatch:\n"
        "permissions:\n"
        "  contents: read\n"
        "jobs:\n"
        "  test:\n"
        "    steps:\n"
        "      - uses: actions/github-script@60a0d83039c74a4aee543508d2ffcb1c3799cdea\n"
        "        with:\n"
        "          script: console.log('${{ github.event.pull_request.title }}')\n",
    )
    errors = ci_gates.check_workflow_security([bad])
    assert any("with.script" in error for error in errors)

    good = tmp_path / "good-env.yml"
    good.write_text(
        "name: Good\n"
        "on:\n"
        "  pull_request:\n"
        "permissions:\n"
        "  contents: read\n"
        "jobs:\n"
        "  test:\n"
        "    env:\n"
        "      TITLE: ${{ github.event.pull_request.title }}\n"
        "    steps:\n"
        "      - run: echo \"$TITLE\"\n",
        encoding="utf-8",
    )
    assert ci_gates.check_workflow_security([good]) == []


def test_workflow_security_reports_yaml_anchor_cycles_instead_of_crashing(tmp_path):
    cyclic = tmp_path / "cyclic.yml"
    cyclic.write_text(
        "name: Cyclic\n"
        "on:\n"
        "  pull_request:\n"
        "permissions:\n"
        "  contents: read\n"
        "jobs:\n"
        "  test:\n"
        "    steps:\n"
        "      - run: echo ok\n"
        "        env:\n"
        "          LOOP: &loop [*loop]\n",
        encoding="utf-8",
    )
    errors = ci_gates.check_workflow_security([cyclic])
    assert any("circular" in error for error in errors)


def test_static_gates_scan_yaml_workflows_too(tmp_path):
    root = tmp_path / "repo"
    (root / ".github" / "workflows").mkdir(parents=True)
    (root / "src").mkdir()
    (root / "examples").mkdir()
    (root / "tests").mkdir()
    shutil.copy2(REPO_ROOT / "pyproject.toml", root / "pyproject.toml")
    shutil.copy2(REPO_ROOT / "uv.lock", root / "uv.lock")
    shutil.copy2(REPO_ROOT / "requirements-ci.txt", root / "requirements-ci.txt")
    shutil.copy2(REPO_ROOT / "examples" / "request.json", root / "examples" / "request.json")
    (root / "README.md").write_text("# Fixture\n", encoding="utf-8")
    (root / ".github" / "workflows" / "good.yml").write_text(
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
    (root / ".github" / "workflows" / "evil.yaml").write_text(
        "name: Evil\n"
        "on:\n"
        "  pull_request_target:\n"
        "permissions: write-all\n"
        "jobs:\n"
        "  test:\n"
        "    steps:\n"
        "      - uses: actions/checkout@v4\n"
        "      - run: echo \"${{ github.event.pull_request.head.sha }}\"\n",
        encoding="utf-8",
    )
    report = ci_gates.run_repo_static_gates(root)
    assert report["ok"] is False
    assert report["checked_workflows"] == 2
    assert any("evil.yaml" in error for error in report["errors"])


def test_dependency_lock_checks_version_constraints_not_only_names(tmp_path):
    root = tmp_path / "repo"
    root.mkdir()
    shutil.copy2(REPO_ROOT / "uv.lock", root / "uv.lock")
    shutil.copy2(REPO_ROOT / "requirements-ci.txt", root / "requirements-ci.txt")
    pyproject = (REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8")
    mutated = re.sub(
        r'"psycopg\[binary\][^"]*"', '"psycopg[binary]>=9.9"', pyproject, count=1
    )
    assert mutated != pyproject
    (root / "pyproject.toml").write_text(mutated, encoding="utf-8")
    errors = ci_gates.check_dependency_lock(root)
    assert any("psycopg" in error and "constraint" in error for error in errors)


def test_workflow_security_rejects_steps_and_needs_outputs_but_allows_env(tmp_path):
    bad = _workflow(
        tmp_path,
        "name: BadOutputs\n"
        "on:\n"
        "  workflow_dispatch:\n"
        "permissions:\n"
        "  contents: read\n"
        "jobs:\n"
        "  test:\n"
        "    steps:\n"
        "      - run: echo \"${{ steps.meta.outputs.title }}\"\n"
        "      - run: echo \"${{ needs.build.outputs.tag }}\"\n"
        "      - uses: actions/github-script@60a0d83039c74a4aee543508d2ffcb1c3799cdea\n"
        "        with:\n"
        "          script: console.log('${{ steps.meta.outputs.title }}')\n"
        "      - uses: actions/github-script@60a0d83039c74a4aee543508d2ffcb1c3799cdea\n"
        "        with:\n"
        "          script: console.log('${{ needs.build.outputs.tag }}')\n",
    )
    errors = ci_gates.check_workflow_security([bad])
    assert sum("steps.meta.outputs.title" in err for err in errors) == 2
    assert sum("needs.build.outputs.tag" in err for err in errors) == 2

    good = tmp_path / "good-outputs-env.yml"
    good.write_text(
        "name: GoodOutputs\n"
        "on:\n"
        "  workflow_dispatch:\n"
        "permissions:\n"
        "  contents: read\n"
        "jobs:\n"
        "  test:\n"
        "    env:\n"
        "      TAG: ${{ needs.build.outputs.tag }}\n"
        "    steps:\n"
        "      - env:\n"
        "          TITLE: ${{ steps.meta.outputs.title }}\n"
        "        run: echo \"$TITLE $TAG\"\n",
        encoding="utf-8",
    )
    assert ci_gates.check_workflow_security([good]) == []


def test_workflow_security_rejects_bracket_tojson_env_matrix_ref_and_runs_on_injections(tmp_path):
    bypass = _workflow(
        tmp_path,
        "name: Bypasses\n"
        "on:\n"
        "  pull_request:\n"
        "permissions:\n"
        "  contents: read\n"
        "jobs:\n"
        "  dyn:\n"
        "    runs-on: ${{ github.event.pull_request.head.label }}\n"
        "    strategy:\n"
        "      matrix:\n"
        "        target: ${{ fromJSON(github.event.inputs.targets) }}\n"
        "    env:\n"
        "      TITLE: ${{ github.event.pull_request.title }}\n"
        "    steps:\n"
        "      - run: echo \"${{ github['event']['pull_request']['title'] }}\"\n"
        "      - run: echo \"${{ github[\"event\"][\"pull_request\"][\"title\"] }}\"\n"
        "      - run: echo \"${{ inputs['target_digest'] }}\"\n"
        "      - run: echo \"${{ toJSON(github) }}\"\n"
        "      - run: echo \"${{ format('{0}', github.actor) }}\"\n"
        "      - run: echo \"${{ env.TITLE }}\"\n"
        "      - run: echo \"${{ matrix.target }}\"\n"
        "      - run: echo \"${{ github.ref }}\"\n"
        "      - run: echo \"${{ github.actor }}\"\n"
        "      - run: echo \"${{ github.triggering_actor }}\"\n"
        "      - uses: actions/github-script@60a0d83039c74a4aee543508d2ffcb1c3799cdea\n"
        "        with:\n"
        "          script: console.log('${{ env.TITLE }}')\n"
        "      - uses: actions/github-script@60a0d83039c74a4aee543508d2ffcb1c3799cdea\n"
        "        with:\n"
        "          script: console.log('${{ toJSON(github) }}')\n",
    )
    errors = ci_gates.check_workflow_security([bypass])
    assert any("runs-on" in err for err in errors), errors
    assert any("strategy.matrix" in err for err in errors), errors
    assert any("github['event']" in err for err in errors), errors
    assert any('github["event"]' in err for err in errors), errors
    assert any("inputs['target_digest']" in err for err in errors), errors
    assert any("tojson(github)" in err for err in errors), errors
    assert any("format(" in err for err in errors), errors
    assert any("env.title" in err for err in errors), errors
    assert any("matrix.target" in err for err in errors), errors
    assert any("github.ref" in err for err in errors), errors
    assert any("github.actor" in err for err in errors), errors
    assert any("github.triggering_actor" in err for err in errors), errors
    assert sum("with.script" in err for err in errors) == 2


def test_workflow_security_reports_top_level_anchor_cycle_in_on_without_crashing(tmp_path):
    cyclic_on = _workflow(
        tmp_path,
        "name: CyclicOn\n"
        "on:\n"
        "  pull_request:\n"
        "    branches: &b [*b]\n"
        "permissions:\n"
        "  contents: read\n"
        "jobs:\n"
        "  test:\n"
        "    steps:\n"
        "      - run: echo ok\n",
    )
    errors = ci_gates.check_workflow_security([cyclic_on])
    assert any("circular" in err for err in errors), errors


def test_waiver_rejects_empty_package_or_target_prefix():
    findings = [
        {"id": "CVE-2025-7777", "severity": "CRITICAL", "package": "", "target": ""},
    ]
    for bad_scope in ("package:", "package:   ", "target:", "target: "):
        waiver = [
            {
                "id": "CVE-2025-7777",
                "scope": bad_scope,
                "impact": "empty target bypass",
                "owner": "sec-team",
                "expires_at": "2026-12-31",
            }
        ]
        with pytest.raises(ci_gates.GateError, match="scope"):
            ci_gates.evaluate_scan_findings(findings, waivers=waiver, today="2026-11-17")
        assert ci_gates._waiver_scope_matches(bad_scope, findings[0]) is False


def test_workflow_security_rejects_secrets_inherit_external_secrets_and_with_key_expressions(
    tmp_path,
):
    ext_inherit = tmp_path / "ext-inherit.yml"
    ext_inherit.write_text(
        "name: p\n"
        "on: pull_request\n"
        "permissions:\n"
        "  contents: read\n"
        "jobs:\n"
        "  steal:\n"
        "    uses: attacker/repo/.github/workflows/steal.yml@" + "1" * 40 + "\n"
        "    secrets: inherit\n",
        encoding="utf-8",
    )
    errors = ci_gates.check_workflow_security([ext_inherit])
    assert errors and any("secrets" in err.lower() for err in errors), errors

    ext_mapping = tmp_path / "ext-mapping.yml"
    ext_mapping.write_text(
        "name: p\n"
        "on: pull_request\n"
        "permissions:\n"
        "  contents: read\n"
        "jobs:\n"
        "  steal:\n"
        "    uses: attacker/repo/.github/workflows/steal.yml@" + "1" * 40 + "\n"
        "    secrets:\n"
        "      TOKEN: ${{ secrets.GITHUB_TOKEN }}\n",
        encoding="utf-8",
    )
    errors = ci_gates.check_workflow_security([ext_mapping])
    assert errors and any("external reusable workflow" in err for err in errors), errors

    local_inherit = tmp_path / "local-inherit.yml"
    local_inherit.write_text(
        "name: p\n"
        "on: pull_request\n"
        "permissions:\n"
        "  contents: read\n"
        "jobs:\n"
        "  call:\n"
        "    uses: ./.github/workflows/ci.yml\n"
        "    secrets: inherit\n",
        encoding="utf-8",
    )
    errors = ci_gates.check_workflow_security([local_inherit])
    assert errors and any("inherit" in err for err in errors), errors

    local_mapping = tmp_path / "local-mapping.yml"
    local_mapping.write_text(
        "name: p\n"
        "on: pull_request\n"
        "permissions:\n"
        "  contents: read\n"
        "jobs:\n"
        "  call:\n"
        "    uses: ./.github/workflows/ci.yml\n"
        "    secrets:\n"
        "      TOKEN: ${{ secrets.GITHUB_TOKEN }}\n",
        encoding="utf-8",
    )
    assert ci_gates.check_workflow_security([local_mapping]) == []

    bad_with_key = tmp_path / "bad-with-key.yml"
    bad_with_key.write_text(
        "name: p\n"
        "on: pull_request\n"
        "permissions:\n"
        "  contents: read\n"
        "jobs:\n"
        "  test:\n"
        "    steps:\n"
        "      - uses: actions/checkout@11d5960a326750d5838078e36cf38b85af677262\n"
        "        with:\n"
        "          '${{ github.event.issue.title }}': x\n",
        encoding="utf-8",
    )
    errors = ci_gates.check_workflow_security([bad_with_key])
    assert errors and any("static identifier" in err or "key" in err.lower() for err in errors), errors

    good_with = tmp_path / "good-with.yml"
    good_with.write_text(
        "name: p\n"
        "on: pull_request\n"
        "permissions:\n"
        "  contents: read\n"
        "jobs:\n"
        "  test:\n"
        "    steps:\n"
        "      - uses: actions/download-artifact@d3f86a106a0bac45b974a628896c90dbdf5c8093\n"
        "        with:\n"
        "          name: release-candidate\n"
        "          github-token: ${{ secrets.GITHUB_TOKEN }}\n"
        "    env:\n"
        "      SECRET_VAL: ${{ secrets.SOME_SECRET }}\n",
        encoding="utf-8",
    )
    assert ci_gates.check_workflow_security([good_with]) == []


def test_workflow_security_rejects_yaml_alias_bomb_within_budget(tmp_path):
    import time

    lines = [
        "name: Bomb",
        "on: pull_request",
        "permissions:",
        "  contents: read",
        "jobs:",
        "  test:",
        "    steps:",
        "      - run: echo ok",
        "x-bomb:",
        '  x0: &a0 ["x", "y"]',
    ]
    for idx in range(1, 31):
        lines.append(f"  x{idx}: &a{idx} [*a{idx - 1}, *a{idx - 1}]")
    bomb = tmp_path / "bomb.yml"
    bomb.write_text("\n".join(lines) + "\n", encoding="utf-8")

    started = time.monotonic()
    errors = ci_gates.check_workflow_security([bomb])
    elapsed = time.monotonic() - started
    assert elapsed < 1.0, f"alias bomb took {elapsed:.2f}s"
    assert errors and any("budget" in err or "expands beyond" in err for err in errors), errors

    # Direct walker/string iterator must raise GateError (not hang or RecursionError).
    doc = ci_gates._load_workflow(bomb)
    with pytest.raises(ci_gates.GateError, match="expands beyond|budget"):
        for _ in ci_gates._walk_yaml(doc):
            pass
    with pytest.raises(ci_gates.GateError, match="expands beyond|budget"):
        for _ in ci_gates._iter_yaml_strings(doc, prefix="root"):
            pass

    # Real repository workflows remain well inside the node budget.
    real_workflows = [
        REPO_ROOT / ".github" / "workflows" / "ci.yml",
        REPO_ROOT / ".github" / "workflows" / "release.yml",
    ]
    assert ci_gates.check_workflow_security(real_workflows) == []


def test_codeowners_protects_ci_trusted_root():
    codeowners = REPO_ROOT / ".github" / "CODEOWNERS"
    assert codeowners.is_file(), ".github/CODEOWNERS must exist to protect CI trusted root"
    text = codeowners.read_text(encoding="utf-8")
    for required in (
        "/.github/",
        "/src/datacon/ci_gates.py",
        "/scripts/run_suite.sh",
        "/tests/contract/test_ci_gates.py",
        "/tests/contract/test_release_workflow.py",
    ):
        assert required in text, f"{required} missing from .github/CODEOWNERS"


def test_workflow_security_rejects_deeply_nested_yaml_without_recursion_error(tmp_path):
    nested = "[" * 2000 + "1" + "]" * 2000
    deep = _workflow(
        tmp_path,
        "name: Deep\n"
        "on: pull_request\n"
        "permissions:\n"
        "  contents: read\n"
        f"x-deep: {nested}\n"
        "jobs:\n"
        "  test:\n"
        "    steps:\n"
        "      - run: echo ok\n",
    )
    with pytest.raises(ci_gates.GateError):
        ci_gates._load_workflow(deep)
    errors = ci_gates.check_workflow_security([deep])
    assert errors and any("YAML" in err or "recursion" in err.lower() for err in errors)


def test_workflow_security_bounds_on_trigger_memory_amplification(tmp_path):
    import time

    big_str = "a" * 100_000
    lines = [
        "name: TriggerBomb",
        "on:",
        f'  x0: &t0 ["{big_str}", "{big_str}"]',
    ]
    # 13 levels => 2^14 - 1 = 16,383 nodes (< 150k node budget), but >1.6GB if json.dumps runs.
    for idx in range(1, 14):
        lines.append(f"  x{idx}: &t{idx} [*t{idx - 1}, *t{idx - 1}]")
    lines.extend(
        [
            "permissions:",
            "  contents: read",
            "jobs:",
            "  test:",
            "    steps:",
            "      - run: echo ok",
        ]
    )
    bomb = tmp_path / "trigger-bomb.yml"
    bomb.write_text("\n".join(lines) + "\n", encoding="utf-8")

    started = time.monotonic()
    errors = ci_gates.check_workflow_security([bomb])
    elapsed = time.monotonic() - started
    assert elapsed < 1.0, f"trigger amplification check took {elapsed:.2f}s"
    assert errors and any("budget" in err or "trigger" in err.lower() for err in errors), errors


def test_workflow_security_checks_step_local_actions_and_direct_secrets_in_run(tmp_path):
    # 1. Step-level local ./ path traversal is rejected.
    repo = tmp_path / "repo"
    (repo / ".github" / "workflows").mkdir(parents=True)
    traversal = repo / ".github" / "workflows" / "traversal.yml"
    traversal.write_text(
        "name: Traversal\n"
        "on: pull_request\n"
        "permissions:\n"
        "  contents: read\n"
        "jobs:\n"
        "  test:\n"
        "    steps:\n"
        "      - uses: ./../../outside\n",
        encoding="utf-8",
    )
    errors = ci_gates.check_workflow_security([traversal], root=repo)
    assert errors and any("traverse" in err or ".." in err for err in errors), errors

    # 2. Local composite action.yml is recursively validated for SHA pins and injections.
    bad_action_dir = repo / ".github" / "actions" / "bad-composite"
    bad_action_dir.mkdir(parents=True)
    (bad_action_dir / "action.yml").write_text(
        "name: BadComposite\n"
        "runs:\n"
        "  using: composite\n"
        "  steps:\n"
        "    - uses: actions/checkout@v4\n"
        "    - shell: bash\n"
        "      run: echo \"${{ github.event.issue.title }}\"\n"
        "    - shell: bash\n"
        "      run: echo \"${{ secrets.INNER_SECRET }}\"\n",
        encoding="utf-8",
    )
    use_bad = repo / ".github" / "workflows" / "use-bad.yml"
    use_bad.write_text(
        "name: UseBad\n"
        "on: pull_request\n"
        "permissions:\n"
        "  contents: read\n"
        "jobs:\n"
        "  test:\n"
        "    steps:\n"
        "      - uses: ./.github/actions/bad-composite\n",
        encoding="utf-8",
    )
    errors = ci_gates.check_workflow_security([use_bad], root=repo)
    assert any("40-char" in err or "SHA" in err for err in errors), errors
    assert any("github.event.issue.title" in err for err in errors), errors
    assert any("secrets.inner_secret" in err.lower() for err in errors), errors

    # Valid local composite action passes.
    good_action_dir = repo / ".github" / "actions" / "good-composite"
    good_action_dir.mkdir(parents=True)
    (good_action_dir / "action.yaml").write_text(
        "name: GoodComposite\n"
        "runs:\n"
        "  using: composite\n"
        "  steps:\n"
        "    - uses: actions/checkout@11d5960a326750d5838078e36cf38b85af677262\n"
        "    - shell: bash\n"
        "      env:\n"
        "        TITLE: ${{ github.event.issue.title }}\n"
        "      run: echo \"$TITLE\"\n",
        encoding="utf-8",
    )
    use_good = repo / ".github" / "workflows" / "use-good.yml"
    use_good.write_text(
        "name: UseGood\n"
        "on: pull_request\n"
        "permissions:\n"
        "  contents: read\n"
        "jobs:\n"
        "  test:\n"
        "    steps:\n"
        "      - uses: ./.github/actions/good-composite\n",
        encoding="utf-8",
    )
    assert ci_gates.check_workflow_security([use_good], root=repo) == []

    # 3. Direct ${{ secrets.* }} in run: is rejected; env: indirection & with.github-token allowed.
    direct_secret = _workflow(
        tmp_path,
        "name: DirectSecret\n"
        "on: workflow_dispatch\n"
        "permissions:\n"
        "  contents: read\n"
        "jobs:\n"
        "  test:\n"
        "    steps:\n"
        "      - run: echo \"${{ secrets.DEPLOY_KEY }}\"\n"
        "      - run: echo \"${{ secrets['OTHER_KEY'] }}\"\n",
    )
    errors = ci_gates.check_workflow_security([direct_secret])
    assert sum("secrets" in err.lower() for err in errors) == 2, errors

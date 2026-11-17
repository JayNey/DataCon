"""TDD contract tests for T07 CI merge gates, supply-chain checks, and Dockerfile."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from datacon import ci_gates

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


def test_workflow_pinning_rejects_mutable_tags_and_excess_permissions(tmp_path):
    good = tmp_path / "good.yml"
    good.write_text(
        "name: Good\n"
        "permissions:\n"
        "  contents: read\n"
        "jobs:\n"
        "  test:\n"
        "    steps:\n"
        "      - uses: actions/checkout@11d5960a326750d5838078e36cf38b85af677262 # v4\n",
        encoding="utf-8",
    )
    assert ci_gates.check_workflow_security([good]) == []

    bad = tmp_path / "bad.yml"
    bad.write_text(
        "name: Bad\n"
        "permissions: write-all\n"
        "jobs:\n"
        "  test:\n"
        "    steps:\n"
        "      - uses: actions/checkout@v4\n"
        "        continue-on-error: true\n",
        encoding="utf-8",
    )
    errors = ci_gates.check_workflow_security([bad])
    assert any("40-char" in err or "SHA" in err for err in errors)
    assert any("continue-on-error" in err for err in errors)
    assert any("permissions" in err for err in errors)


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


def test_vulnerability_scan_blocks_critical_high_and_invalid_waivers():
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


def test_secret_scanner_detects_leaked_credentials(tmp_path):
    clean = tmp_path / "clean.py"
    clean.write_text('dsn = os.environ["DATACON_DATABASE_URL"]\n', encoding="utf-8")
    assert ci_gates.scan_secrets([clean]) == []

    leaked = tmp_path / "leaked.txt"
    leaked.write_text(
        "DATACON_DATABASE_URL=postgresql://datacon:supersecretpass@db.internal:5432/datacon\n"
        "-----BEGIN OPENSSH PRIVATE KEY-----\n",
        encoding="utf-8",
    )
    hits = ci_gates.scan_secrets([leaked])
    assert len(hits) >= 2


def test_repo_ci_gates_and_dockerfile_pass():
    report = ci_gates.run_repo_static_gates(REPO_ROOT)
    assert report["ok"] is True, json.dumps(report, indent=2)

    dockerfile = REPO_ROOT / "Dockerfile"
    assert dockerfile.is_file()
    content = dockerfile.read_text(encoding="utf-8")
    assert "@sha256:" in content
    assert "USER " in content
    assert "USER root" not in content
    assert "migrations" in content
    assert "uv.lock" in content

    release_wf = REPO_ROOT / ".github" / "workflows" / "release.yml"
    assert release_wf.is_file()
    assert ci_gates.check_workflow_security(
        [REPO_ROOT / ".github" / "workflows" / "ci.yml", release_wf]
    ) == []

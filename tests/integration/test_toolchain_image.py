"""Docker integration tests for the pinned toolchain image boundary (T13c, ADR-005 #9).

These tests verify the live pinned image against the v1/v2 toolchain boundary.
They follow tests/e2e/test_mvp_docker.py: CI fails if Docker or the pinned
image is unavailable, while local environments skip cleanly.
"""

from __future__ import annotations

import os
import shutil
import subprocess

import pytest

from datacon import release, toolchain, verdict

pytestmark = [pytest.mark.postgres, pytest.mark.docker]

_V2_IMAGE_DIGEST = "sha256:" + "b" * 64
_V2_IMAGE_REF = f"ghcr.io/datacon/toolchain-v2:2.0@{_V2_IMAGE_DIGEST}"


def _is_ci() -> bool:
    return os.getenv("CI", "").lower() not in ("", "0", "false", "no")


@pytest.fixture(scope="module", autouse=True)
def require_docker():
    if shutil.which("docker") is None:
        if _is_ci():
            pytest.fail("Docker is required for the toolchain boundary gate")
        pytest.skip("Docker is not installed")
    version = subprocess.run(
        ["docker", "version", "--format", "{{.Server.Version}}"],
        capture_output=True,
        text=True,
        timeout=30,
    )
    if version.returncode != 0:
        if _is_ci():
            pytest.fail(
                f"Docker is required for the toolchain boundary gate: {version.stderr}"
            )
        pytest.skip("Docker daemon is unavailable")
    image_check = subprocess.run(
        ["docker", "image", "inspect", release.TOOLCHAIN_IMAGE],
        capture_output=True,
        text=True,
        timeout=30,
    )
    if image_check.returncode != 0:
        if _is_ci():
            pytest.fail(
                f"Pinned toolchain image {release.TOOLCHAIN_IMAGE} is absent in CI: "
                f"{image_check.stderr}"
            )
        pytest.skip(
            f"Pinned toolchain image {release.TOOLCHAIN_IMAGE} is not pulled locally"
        )


@pytest.fixture(scope="module")
def v1_probe_report(require_docker: None) -> toolchain.ToolchainProbeReport:
    """Run the read-only live container probe once per module."""
    return toolchain.verify_pinned_image_tool_boundary(image=release.TOOLCHAIN_IMAGE)


def test_oniguruma_case_uses_existing_toolchain_image(
    v1_probe_report: toolchain.ToolchainProbeReport,
):
    assert v1_probe_report.matches_v1_boundary is True, (
        f"pinned image drifted from v1 boundary: "
        f"unexpected_missing={sorted(v1_probe_report.unexpected_missing)}, "
        f"unexpected_present={sorted(v1_probe_report.unexpected_present)}"
    )
    expected_oniguruma = {
        toolchain.normalize_tool_name(tool)
        for tool in toolchain.ONIGURUMA_REQUIRED_TOOLS
    }
    assert expected_oniguruma <= v1_probe_report.available

    selection = toolchain.select_toolchain_image(toolchain.ONIGURUMA_REQUIRED_TOOLS)
    assert selection.image == release.TOOLCHAIN_IMAGE
    assert selection.image_digest == release.TOOLCHAIN_IMAGE_DIGEST
    assert selection.image_tier == "v1"
    assert selection.requires_v2 is False
    assert selection.missing_v1_tools == ()
    assert selection.unknown_tools == ()


def test_missing_tool_requires_toolchain_image_v2(
    v1_probe_report: toolchain.ToolchainProbeReport,
):
    assert v1_probe_report.unexpected_present == frozenset(), (
        f"tools expected absent from pinned v1 image were present: "
        f"{sorted(v1_probe_report.unexpected_present)}"
    )
    assert toolchain.V1_MISSING_TOOLS <= v1_probe_report.missing

    for missing_tool in sorted(toolchain.V1_MISSING_TOOLS):
        with pytest.raises(toolchain.ToolchainBoundaryError) as blocked:
            toolchain.select_toolchain_image(
                [*toolchain.ONIGURUMA_REQUIRED_TOOLS, missing_tool]
            )
        assert blocked.value.reason_code == toolchain.REASON_POLICY_DENIED
        assert verdict.reason_allowed_v2("BLOCKED", blocked.value.reason_code)
        assert blocked.value.sub_reason == toolchain.SUB_REASON_TOOLCHAIN_V2_REQUIRED
        assert missing_tool in blocked.value.missing_v1_tools

        routed = toolchain.select_toolchain_image(
            [*toolchain.ONIGURUMA_REQUIRED_TOOLS, missing_tool],
            toolchain_image_v2=_V2_IMAGE_REF,
        )
        assert routed.image == _V2_IMAGE_REF
        assert routed.image_digest == _V2_IMAGE_DIGEST
        assert routed.image_tier == "v2"
        assert routed.requires_v2 is True
        assert routed.missing_v1_tools == (missing_tool,)

        with pytest.raises(toolchain.ToolchainBoundaryError) as reused:
            toolchain.select_toolchain_image(
                [missing_tool],
                toolchain_image_v2=release.TOOLCHAIN_IMAGE,
            )
        assert reused.value.reason_code == toolchain.REASON_POLICY_DENIED
        assert verdict.reason_allowed_v2("BLOCKED", reused.value.reason_code)
        assert reused.value.sub_reason == toolchain.SUB_REASON_INVALID_TOOLCHAIN_V2

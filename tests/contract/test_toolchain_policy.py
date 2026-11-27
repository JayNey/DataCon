"""Offline contract tests for pinned toolchain boundary policy and probe helpers (T13c)."""

from __future__ import annotations

import json
from pathlib import Path
import re
import shutil
import subprocess
from typing import Any

import pytest

from datacon import release, toolchain, verdict
from datacon.tools import sandbox

_V2_DIGEST = "sha256:" + "a" * 64
_V2_IMAGE = f"ghcr.io/datacon/toolchain-v2:2.0@{_V2_DIGEST}"


def _valid_probe_lines(
    *,
    overrides: dict[str, str] | None = None,
) -> str:
    states = {
        **{tool: "present" for tool in sorted(toolchain.V1_AVAILABLE_TOOLS)},
        **{tool: "absent" for tool in sorted(toolchain.V1_MISSING_TOOLS)},
    }
    if overrides:
        states.update(overrides)
    return "\n".join(f"TOOL {name} {status}" for name, status in states.items()) + "\n"


def _assert_blocked_policy_error(
    error: toolchain.ToolchainBoundaryError,
    expected_sub_reason: str,
) -> None:
    assert error.reason_code == toolchain.REASON_POLICY_DENIED
    assert verdict.reason_allowed_v2("BLOCKED", error.reason_code)
    assert error.sub_reason == expected_sub_reason
    assert error.reason_code in str(error)
    assert expected_sub_reason in str(error)


def test_pinned_constants_single_source_from_release():
    assert toolchain.PINNED_TOOLCHAIN_IMAGE == release.TOOLCHAIN_IMAGE
    assert toolchain.PINNED_TOOLCHAIN_IMAGE_DIGEST == release.TOOLCHAIN_IMAGE_DIGEST
    assert toolchain.PINNED_TOOLCHAIN_IMAGE.endswith(
        "@" + toolchain.PINNED_TOOLCHAIN_IMAGE_DIGEST
    )
    # Guard against accidental literal duplication in src/datacon/toolchain.py.
    source_text = Path(toolchain.__file__).read_text(encoding="utf-8")
    digest_hex = release.TOOLCHAIN_IMAGE_DIGEST.split(":", 1)[1]
    assert digest_hex not in source_text


def test_toolchain_boundary_error_enforces_closed_v2_blocked_enum():
    err = toolchain.ToolchainBoundaryError(
        "missing tool",
        sub_reason=toolchain.SUB_REASON_TOOLCHAIN_V2_REQUIRED,
    )
    _assert_blocked_policy_error(err, toolchain.SUB_REASON_TOOLCHAIN_V2_REQUIRED)
    assert err.message == err.detail == "missing tool"

    with pytest.raises(ValueError, match="reason_code"):
        toolchain.ToolchainBoundaryError(
            "bad reason",
            sub_reason=toolchain.SUB_REASON_TOOLCHAIN_V2_REQUIRED,
            reason_code="TOOLCHAIN_IMAGE_V2_REQUIRED",
        )

    with pytest.raises(ValueError, match="sub_reason"):
        toolchain.ToolchainBoundaryError("missing sub_reason", sub_reason="   ")

    with pytest.raises(TypeError, match="missing_v1_tools"):
        toolchain.ToolchainBoundaryError(
            "bad missing tools",
            sub_reason=toolchain.SUB_REASON_TOOLCHAIN_V2_REQUIRED,
            missing_v1_tools="git",
        )

    with pytest.raises(TypeError, match="unknown_tools"):
        toolchain.ToolchainBoundaryError(
            "bad unknown tools",
            sub_reason=toolchain.SUB_REASON_TOOLCHAIN_V2_REQUIRED,
            unknown_tools=b"meson",  # type: ignore[arg-type]
        )


def test_v1_capability_sets_are_disjoint_and_complete():
    assert toolchain.V1_AVAILABLE_TOOLS.isdisjoint(toolchain.V1_MISSING_TOOLS)
    assert {"cmake", "make", "autoconf", "automake", "libfuzzer", "clang"} == set(
        toolchain.V1_AVAILABLE_TOOLS
    )
    assert {"pkg-config", "libtool", "ninja", "git"} == set(toolchain.V1_MISSING_TOOLS)


def test_empty_required_tools_routes_to_pinned_v1():
    selection = toolchain.select_toolchain_image([])
    assert selection.image == release.TOOLCHAIN_IMAGE
    assert selection.image_digest == release.TOOLCHAIN_IMAGE_DIGEST
    assert selection.image_tier == "v1"
    assert selection.requires_v2 is False
    assert selection.required_tools == ()
    assert selection.missing_v1_tools == ()
    assert selection.unknown_tools == ()

    # Even when toolchain_image_v2 is supplied, an empty requirement list stays on v1.
    still_v1 = toolchain.select_toolchain_image([], toolchain_image_v2=_V2_IMAGE)
    assert still_v1.image_tier == "v1"
    assert still_v1.requires_v2 is False
    assert still_v1.image == release.TOOLCHAIN_IMAGE


def test_oniguruma_class_case_routes_to_pinned_v1_without_v2():
    selection = toolchain.select_toolchain_image(toolchain.ONIGURUMA_REQUIRED_TOOLS)
    assert selection.image == release.TOOLCHAIN_IMAGE
    assert selection.image_digest == release.TOOLCHAIN_IMAGE_DIGEST
    assert selection.image_tier == "v1"
    assert selection.requires_v2 is False
    assert selection.missing_v1_tools == ()
    assert selection.unknown_tools == ()
    assert set(selection.required_tools) == {
        "cmake",
        "make",
        "autoconf",
        "automake",
        "libfuzzer",
    }

    # Even when toolchain_image_v2 is supplied, Oniguruma-class cases stay on v1.
    still_v1 = toolchain.select_toolchain_image(
        toolchain.ONIGURUMA_REQUIRED_TOOLS, toolchain_image_v2=_V2_IMAGE
    )
    assert still_v1.image_tier == "v1"
    assert still_v1.requires_v2 is False
    assert still_v1.image == release.TOOLCHAIN_IMAGE


@pytest.mark.parametrize(
    "variant",
    ["libFuzzer", "LIBFUZZER", "libfuzzer", "  libFuzzer  "],
)
def test_tool_name_normalization_handles_libfuzzer_casing(variant: str):
    assert toolchain.normalize_tool_name(variant) == "libfuzzer"
    selection = toolchain.select_toolchain_image(["CMAKE", " Make ", variant])
    assert selection.image_tier == "v1"
    assert selection.requires_v2 is False
    assert selection.required_tools == ("cmake", "make", "libfuzzer")


@pytest.mark.parametrize(
    "bad_tool",
    [
        "",
        "   ",
        "\t\n",
        "clang -O2",
        "make\n",
        "cma\u212ae",
        "$(id)",
        "--flag",
        "foo\x9bbar",
        123,
        None,
    ],
)
def test_invalid_tool_names_fail_closed(bad_tool: object):
    with pytest.raises(toolchain.ToolchainBoundaryError) as norm_caught:
        toolchain.normalize_tool_name(bad_tool)
    _assert_blocked_policy_error(
        norm_caught.value, toolchain.SUB_REASON_INVALID_TOOL_REQUIREMENT
    )

    with pytest.raises(toolchain.ToolchainBoundaryError) as caught:
        toolchain.select_toolchain_image([bad_tool])  # type: ignore[list-item]
    _assert_blocked_policy_error(
        caught.value, toolchain.SUB_REASON_INVALID_TOOL_REQUIREMENT
    )


@pytest.mark.parametrize(
    "bad_required_tools",
    [
        "cmake",
        b"cmake",
        bytearray(b"cmake"),
        memoryview(b"cmake"),
        {"cmake"},
        123,
    ],
)
def test_non_sequence_or_string_required_tools_fail_closed(bad_required_tools: Any):
    with pytest.raises(toolchain.ToolchainBoundaryError) as caught:
        toolchain.select_toolchain_image(bad_required_tools)
    _assert_blocked_policy_error(
        caught.value, toolchain.SUB_REASON_INVALID_TOOL_REQUIREMENT
    )


@pytest.mark.parametrize("missing_tool", ["pkg-config", "libtool", "ninja", "git"])
def test_missing_v1_tool_blocks_without_v2_and_routes_with_pinned_v2(missing_tool: str):
    with pytest.raises(toolchain.ToolchainBoundaryError) as caught:
        toolchain.select_toolchain_image(["cmake", "make", missing_tool])
    _assert_blocked_policy_error(
        caught.value, toolchain.SUB_REASON_TOOLCHAIN_V2_REQUIRED
    )
    assert caught.value.missing_v1_tools == (missing_tool,)
    assert caught.value.unknown_tools == ()
    assert missing_tool in str(caught.value)

    routed = toolchain.select_toolchain_image(
        ["cmake", "make", missing_tool], toolchain_image_v2=_V2_IMAGE
    )
    assert routed.image == _V2_IMAGE
    assert routed.image_digest == _V2_DIGEST
    assert routed.image_tier == "v2"
    assert routed.requires_v2 is True
    assert routed.missing_v1_tools == (missing_tool,)
    assert routed.unknown_tools == ()


def test_unknown_tool_fails_closed_without_v2_and_routes_with_pinned_v2():
    with pytest.raises(toolchain.ToolchainBoundaryError) as caught:
        toolchain.select_toolchain_image(["cmake", "meson"])
    _assert_blocked_policy_error(
        caught.value, toolchain.SUB_REASON_TOOLCHAIN_V2_REQUIRED
    )
    assert caught.value.missing_v1_tools == ()
    assert caught.value.unknown_tools == ("meson",)
    assert "meson" in str(caught.value)

    routed = toolchain.select_toolchain_image(
        ["cmake", "meson", "pkg-config"], toolchain_image_v2=_V2_IMAGE
    )
    assert routed.image_tier == "v2"
    assert routed.requires_v2 is True
    assert routed.missing_v1_tools == ("pkg-config",)
    assert routed.unknown_tools == ("meson",)


@pytest.mark.parametrize(
    "valid_v2",
    [
        f"ghcr.io/datacon/toolchain-v2:2.0@{_V2_DIGEST}",
        f"ghcr.io:443/datacon/toolchain-v2@{_V2_DIGEST}",
        f"localhost/datacon/toolchain-v2@{_V2_DIGEST}",
        f"localhost:5000/datacon/toolchain-v2:v2@{_V2_DIGEST}",
        f"registry:5000/datacon/toolchain-v2@{_V2_DIGEST}",
        f"internal-reg:1/datacon/toolchain-v2:2.0@{_V2_DIGEST}",
        f"internal-reg:65535/toolchain-v2@{_V2_DIGEST}",
        f"datacon/toolchain-v2@{_V2_DIGEST}",
        f"ghcr.io/my--org/my__tool@{_V2_DIGEST}",
    ],
)
def test_valid_pinned_v2_image_refs_including_internal_registries(valid_v2: str):
    routed = toolchain.select_toolchain_image(["ninja"], toolchain_image_v2=valid_v2)
    assert routed.image == valid_v2
    assert routed.image_digest == _V2_DIGEST
    assert routed.image_tier == "v2"
    assert routed.requires_v2 is True


@pytest.mark.parametrize(
    ("bad_v2", "expected_sub_reason"),
    [
        (None, toolchain.SUB_REASON_TOOLCHAIN_V2_REQUIRED),
        ("", toolchain.SUB_REASON_TOOLCHAIN_V2_REQUIRED),
        ("   ", toolchain.SUB_REASON_TOOLCHAIN_V2_REQUIRED),
        ("ghcr.io/datacon/toolchain-v2:latest", toolchain.SUB_REASON_INVALID_TOOLCHAIN_V2),
        ("datacon/toolchain-v2:v2", toolchain.SUB_REASON_INVALID_TOOLCHAIN_V2),
        ("registry:5000/datacon/toolchain-v2:latest", toolchain.SUB_REASON_INVALID_TOOLCHAIN_V2),
        (
            "ghcr.io/datacon/toolchain-v2@sha256:" + "A" * 64,
            toolchain.SUB_REASON_INVALID_TOOLCHAIN_V2,
        ),
        (
            "ghcr.io/datacon/toolchain-v2@sha256:short",
            toolchain.SUB_REASON_INVALID_TOOLCHAIN_V2,
        ),
        ("sha256:" + "a" * 64, toolchain.SUB_REASON_INVALID_TOOLCHAIN_V2),
        ("@sha256:" + "a" * 64, toolchain.SUB_REASON_INVALID_TOOLCHAIN_V2),
        (f" {_V2_IMAGE}", toolchain.SUB_REASON_INVALID_TOOLCHAIN_V2),
        (f"{_V2_IMAGE} ", toolchain.SUB_REASON_INVALID_TOOLCHAIN_V2),
        (
            f"ghcr.io/datacon/toolchain-v2@sha256:{'a' * 64}@sha256:{'b' * 64}",
            toolchain.SUB_REASON_INVALID_TOOLCHAIN_V2,
        ),
        (
            "ghcr.io/datacon/toolchain-v2\n@sha256:" + "a" * 64,
            toolchain.SUB_REASON_INVALID_TOOLCHAIN_V2,
        ),
        (f"registry:0/datacon/toolchain-v2@{_V2_DIGEST}", toolchain.SUB_REASON_INVALID_TOOLCHAIN_V2),
        (
            f"registry:05000/datacon/toolchain-v2@{_V2_DIGEST}",
            toolchain.SUB_REASON_INVALID_TOOLCHAIN_V2,
        ),
        (
            f"ghcr.io:65536/datacon/toolchain-v2@{_V2_DIGEST}",
            toolchain.SUB_REASON_INVALID_TOOLCHAIN_V2,
        ),
        (
            f"localhost:99999/datacon/toolchain-v2@{_V2_DIGEST}",
            toolchain.SUB_REASON_INVALID_TOOLCHAIN_V2,
        ),
        (
            f"ghcr.io/my___tool@{_V2_DIGEST}",
            toolchain.SUB_REASON_INVALID_TOOLCHAIN_V2,
        ),
        (
            f"ghcr.io/MyOrg/tool@{_V2_DIGEST}",
            toolchain.SUB_REASON_INVALID_TOOLCHAIN_V2,
        ),
        (
            f"-badhost:5000/datacon/toolchain-v2@{_V2_DIGEST}",
            toolchain.SUB_REASON_INVALID_TOOLCHAIN_V2,
        ),
        (
            f"registry:/datacon/toolchain-v2@{_V2_DIGEST}",
            toolchain.SUB_REASON_INVALID_TOOLCHAIN_V2,
        ),
        (
            f"ghcr.io/datacon/toolchain-v2@{release.TOOLCHAIN_IMAGE_DIGEST}",
            toolchain.SUB_REASON_INVALID_TOOLCHAIN_V2,
        ),
        (release.TOOLCHAIN_IMAGE, toolchain.SUB_REASON_INVALID_TOOLCHAIN_V2),
    ],
)
def test_invalid_or_reused_v2_image_reference_fails_closed(
    bad_v2: str | None,
    expected_sub_reason: str,
):
    with pytest.raises(toolchain.ToolchainBoundaryError) as caught:
        toolchain.select_toolchain_image(["ninja"], toolchain_image_v2=bad_v2)
    _assert_blocked_policy_error(caught.value, expected_sub_reason)
    assert caught.value.missing_v1_tools == ("ninja",)


def test_probe_script_checks_libfuzzer_via_clang_and_never_installs_packages():
    script = toolchain.render_toolchain_probe_script()
    assert "command -v libFuzzer" not in script
    assert "command -v libfuzzer" not in script
    assert "clang -print-resource-dir" in script
    assert "libclang_rt.fuzzer" in script
    assert "-fsanitize=fuzzer" in script
    assert "LLVMFuzzerTestOneInput" in script
    # Keep stdout protocol pure while allowing clang compile diagnostics on stderr.
    fuzzer_compile_lines = [
        line for line in script.splitlines() if "clang -fsanitize=fuzzer" in line
    ]
    assert len(fuzzer_compile_lines) == 1
    assert re.search(r">/dev/null(?:\s|;|$)", fuzzer_compile_lines[0])
    assert "2>&1" not in fuzzer_compile_lines[0]
    stdout_printfs = [
        line.strip()
        for line in script.splitlines()
        if "printf " in line and "> /work/" not in line
    ]
    assert stdout_printfs
    assert all(line.startswith("printf 'TOOL ") for line in stdout_printfs)
    for forbidden in ("apt-get", "apt ", "dpkg ", "pip ", "curl ", "wget "):
        assert forbidden not in script
    for tool in sorted(toolchain.PROBED_TOOLS - {"libfuzzer"}):
        assert tool in script


def test_probe_command_enforces_sandbox_isolation_flags():
    cmd = toolchain.build_toolchain_probe_command()
    assert cmd[:3] == ["docker", "run", "--rm"]
    assert "--network=none" in cmd
    assert "--read-only" in cmd
    assert "--cap-drop=ALL" in cmd
    assert "--security-opt=no-new-privileges:true" in cmd
    assert f"--security-opt=seccomp={sandbox.SECCOMP_PROFILE_PATH.resolve()}" in cmd
    assert "--user=65534:65534" in cmd
    assert "--pids-limit=128" in cmd
    assert "--memory=1024m" in cmd
    assert "--memory-swap=1024m" in cmd
    assert "--cpus=2" in cmd
    assert "--ipc=private" in cmd
    assert "--log-driver=none" in cmd
    assert "-w" in cmd and cmd[cmd.index("-w") + 1] == "/work"
    assert "--pull" in cmd and cmd[cmd.index("--pull") + 1] == "never"
    assert "--platform" in cmd and cmd[cmd.index("--platform") + 1] == "linux/amd64"
    env_values = [cmd[i + 1] for i, token in enumerate(cmd) if token == "-e"]
    assert "TMPDIR=/tmp" in env_values
    assert "HOME=/work" in env_values
    tmpfs_values = [cmd[i + 1] for i, token in enumerate(cmd) if token == "--tmpfs"]
    assert any(
        val.startswith("/work:") and "noexec" in val and "nosuid" in val and "nodev" in val
        for val in tmpfs_values
    )
    assert any(
        val.startswith("/tmp:") and "noexec" in val and "nosuid" in val and "nodev" in val
        for val in tmpfs_values
    )
    assert release.TOOLCHAIN_IMAGE in cmd
    # Reject unpinned image in probe command builder.
    with pytest.raises(toolchain.ToolchainBoundaryError) as caught:
        toolchain.build_toolchain_probe_command(image="silkeh/clang:19-bookworm")
    _assert_blocked_policy_error(
        caught.value, toolchain.SUB_REASON_TOOLCHAIN_PROBE_FAILED
    )


@pytest.mark.parametrize(
    "bad_docker_bin",
    ["", "   ", " docker", "docker ", "docker\x00", "docker\n", 123],
)
def test_probe_command_rejects_invalid_docker_bin(bad_docker_bin: Any):
    with pytest.raises(toolchain.ToolchainBoundaryError) as caught:
        toolchain.build_toolchain_probe_command(docker_bin=bad_docker_bin)
    _assert_blocked_policy_error(
        caught.value, toolchain.SUB_REASON_TOOLCHAIN_PROBE_FAILED
    )


@pytest.mark.parametrize("bad_seccomp", [123, "", "   ", "seccomp\x00.json"])
def test_probe_command_rejects_invalid_seccomp_path_types_and_controls(bad_seccomp: Any):
    with pytest.raises(toolchain.ToolchainBoundaryError) as caught:
        toolchain.build_toolchain_probe_command(seccomp_path=bad_seccomp)
    _assert_blocked_policy_error(
        caught.value, toolchain.SUB_REASON_TOOLCHAIN_PROBE_FAILED
    )


def test_probe_command_enforces_seccomp_digest_for_explicit_paths(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    # A verbatim copy of the pinned seccomp profile passes digest verification.
    valid_copy = tmp_path / "pinned-seccomp.json"
    shutil.copyfile(sandbox.SECCOMP_PROFILE_PATH, valid_copy)
    cmd = toolchain.build_toolchain_probe_command(seccomp_path=valid_copy)
    assert f"--security-opt=seccomp={valid_copy.resolve()}" in cmd

    # Symlink seccomp paths fail closed before resolving.
    symlink_path = tmp_path / "seccomp-link.json"
    symlink_path.symlink_to(valid_copy)
    with pytest.raises(toolchain.ToolchainBoundaryError, match="symlink") as link_err:
        toolchain.build_toolchain_probe_command(seccomp_path=symlink_path)
    _assert_blocked_policy_error(
        link_err.value, toolchain.SUB_REASON_TOOLCHAIN_PROBE_FAILED
    )

    # Relative path named "unconfined" resolves to an absolute path so Docker
    # cannot interpret it as the seccomp=unconfined keyword.
    unconfined_file = tmp_path / "unconfined"
    shutil.copyfile(sandbox.SECCOMP_PROFILE_PATH, unconfined_file)
    monkeypatch.chdir(tmp_path)
    rel_cmd = toolchain.build_toolchain_probe_command(seccomp_path="unconfined")
    assert "--security-opt=seccomp=unconfined" not in rel_cmd
    assert f"--security-opt=seccomp={unconfined_file.resolve()}" in rel_cmd

    # A tampered explicit seccomp profile fails closed even if syntactically valid JSON.
    tampered = tmp_path / "tampered-seccomp.json"
    tampered.write_text(
        json.dumps({"defaultAction": "SCMP_ACT_ALLOW", "syscalls": []}),
        encoding="utf-8",
    )
    with pytest.raises(toolchain.ToolchainBoundaryError, match="SECCOMP_PROFILE_DIGEST") as caught:
        toolchain.build_toolchain_probe_command(seccomp_path=tampered)
    _assert_blocked_policy_error(
        caught.value, toolchain.SUB_REASON_TOOLCHAIN_PROBE_FAILED
    )

    # Malformed/non-JSON seccomp profile maps SandboxPolicyError to ToolchainBoundaryError.
    malformed = tmp_path / "malformed-seccomp.json"
    malformed.write_text("{not valid json", encoding="utf-8")
    with pytest.raises(toolchain.ToolchainBoundaryError) as malformed_err:
        toolchain.build_toolchain_probe_command(seccomp_path=malformed)
    _assert_blocked_policy_error(
        malformed_err.value, toolchain.SUB_REASON_TOOLCHAIN_PROBE_FAILED
    )

    # Missing explicit seccomp file fails closed.
    with pytest.raises(toolchain.ToolchainBoundaryError) as missing_err:
        toolchain.build_toolchain_probe_command(seccomp_path=tmp_path / "absent.json")
    _assert_blocked_policy_error(
        missing_err.value, toolchain.SUB_REASON_TOOLCHAIN_PROBE_FAILED
    )


def test_parse_toolchain_probe_output_positive_and_boundary_drift():
    report = toolchain.parse_toolchain_probe_output(_valid_probe_lines().encode("utf-8"))
    assert report.matches_v1_boundary is True
    assert report.available == toolchain.V1_AVAILABLE_TOOLS
    assert report.missing == toolchain.V1_MISSING_TOOLS
    assert report.unexpected_missing == frozenset()
    assert report.unexpected_present == frozenset()
    assert report.results["libfuzzer"] is True
    assert report.results["pkg-config"] is False

    # Case-insensitive libFuzzer line is accepted.
    mixed_case = re.sub(r"\blibfuzzer\b", "libFuzzer", _valid_probe_lines())
    report_mixed = toolchain.parse_toolchain_probe_output(mixed_case)
    assert report_mixed.matches_v1_boundary is True
    assert "libfuzzer" in report_mixed.available

    # Boundary drift: missing expected tool and unexpected presence of v1-missing tool.
    drifted = toolchain.parse_toolchain_probe_output(
        _valid_probe_lines(overrides={"cmake": "absent", "ninja": "present"})
    )
    assert drifted.matches_v1_boundary is False
    assert drifted.unexpected_missing == frozenset({"cmake"})
    assert drifted.unexpected_present == frozenset({"ninja"})


@pytest.mark.parametrize(
    "bad_output",
    [
        "",
        "   \n\n",
        "TOOL cmake present\n",  # incomplete
        "TOOL cma\u212ae present\n",  # Kelvin sign non-ASCII tool name
        _valid_probe_lines().replace("cmake", "cma\u212ae"),  # full set with Kelvin sign
        _valid_probe_lines() + "TOOL cmake present\n",  # duplicate
        _valid_probe_lines() + "TOOL unknown_tool present\n",  # unknown tool
        _valid_probe_lines() + "TOOL cmake maybe\n",  # bad status
        _valid_probe_lines() + "garbage line\n",  # malformed line
        b"\xff\xfe",  # invalid UTF-8
        123,  # non-str/bytes
    ],
)
def test_parse_toolchain_probe_output_fails_closed_on_malformed_data(bad_output: Any):
    with pytest.raises(toolchain.ToolchainBoundaryError) as caught:
        toolchain.parse_toolchain_probe_output(bad_output)
    _assert_blocked_policy_error(
        caught.value, toolchain.SUB_REASON_INVALID_PROBE_OUTPUT
    )


@pytest.mark.parametrize(
    "bad_timeout",
    [0, -1, float("nan"), float("inf"), float("-inf"), True, "10"],
)
def test_verify_pinned_image_rejects_invalid_timeout_offline(
    monkeypatch: pytest.MonkeyPatch,
    bad_timeout: Any,
):
    def _must_not_run(*args: Any, **kwargs: Any) -> Any:
        raise AssertionError("subprocess.run must not be called on invalid timeout")

    monkeypatch.setattr(subprocess, "run", _must_not_run)
    with pytest.raises(toolchain.ToolchainBoundaryError, match="timeout_seconds") as caught:
        toolchain.verify_pinned_image_tool_boundary(timeout_seconds=bad_timeout)
    _assert_blocked_policy_error(
        caught.value, toolchain.SUB_REASON_TOOLCHAIN_PROBE_FAILED
    )


def test_probe_command_container_name_validation():
    default_cmd = toolchain.build_toolchain_probe_command()
    assert "--name" not in default_cmd

    named_cmd = toolchain.build_toolchain_probe_command(
        container_name="datacon-toolchain-probe-0123456789abcdef"
    )
    assert named_cmd[:5] == [
        "docker",
        "run",
        "--rm",
        "--name",
        "datacon-toolchain-probe-0123456789abcdef",
    ]

    for bad_name in ("", "   ", "--privileged", "BadName", "probe\x00name", 123):
        with pytest.raises(toolchain.ToolchainBoundaryError) as caught:
            toolchain.build_toolchain_probe_command(container_name=bad_name)  # type: ignore[arg-type]
        _assert_blocked_policy_error(
            caught.value, toolchain.SUB_REASON_TOOLCHAIN_PROBE_FAILED
        )


def test_verify_pinned_image_handles_timeout_expired_offline(
    monkeypatch: pytest.MonkeyPatch,
):
    calls: list[tuple[list[str], dict[str, Any]]] = []

    def _fake_run(cmd: list[str], **kwargs: Any) -> subprocess.CompletedProcess[bytes]:
        calls.append((cmd, kwargs))
        if len(calls) == 1:
            raise subprocess.TimeoutExpired(cmd=cmd, timeout=kwargs["timeout"])
        return subprocess.CompletedProcess(args=cmd, returncode=0, stdout=b"", stderr=b"")

    monkeypatch.setattr(subprocess, "run", _fake_run)
    with pytest.raises(toolchain.ToolchainBoundaryError, match="timed out") as caught:
        toolchain.verify_pinned_image_tool_boundary(
            docker_bin="/usr/bin/docker", timeout_seconds=12.5
        )
    _assert_blocked_policy_error(
        caught.value, toolchain.SUB_REASON_TOOLCHAIN_PROBE_FAILED
    )
    assert len(calls) == 2
    run_cmd, _ = calls[0]
    assert "--name" in run_cmd
    container_name = run_cmd[run_cmd.index("--name") + 1]
    assert container_name.startswith("datacon-toolchain-probe-")
    cleanup_cmd, cleanup_kwargs = calls[1]
    assert cleanup_cmd == ["/usr/bin/docker", "rm", "-f", container_name]
    assert cleanup_kwargs.get("capture_output") is True
    assert cleanup_kwargs.get("check") is False
    assert 0 < cleanup_kwargs.get("timeout", 0) <= 30


@pytest.mark.parametrize(
    "cleanup_error",
    [
        OSError("docker daemon gone"),
        subprocess.TimeoutExpired(cmd=["docker", "rm", "-f", "x"], timeout=15.0),
    ],
)
def test_verify_pinned_image_timeout_swallows_cleanup_errors_offline(
    monkeypatch: pytest.MonkeyPatch,
    cleanup_error: Exception,
):
    calls: list[list[str]] = []

    def _fake_run(cmd: list[str], **kwargs: Any) -> Any:
        calls.append(cmd)
        if len(calls) == 1:
            raise subprocess.TimeoutExpired(cmd=cmd, timeout=kwargs["timeout"])
        raise cleanup_error

    monkeypatch.setattr(subprocess, "run", _fake_run)
    with pytest.raises(toolchain.ToolchainBoundaryError, match="timed out") as caught:
        toolchain.verify_pinned_image_tool_boundary(timeout_seconds=5.0)
    _assert_blocked_policy_error(
        caught.value, toolchain.SUB_REASON_TOOLCHAIN_PROBE_FAILED
    )
    assert len(calls) == 2
    assert calls[1][:3] == ["docker", "rm", "-f"]


def test_verify_pinned_image_handles_oserror_offline(
    monkeypatch: pytest.MonkeyPatch,
):
    def _raise_oserror(*args: Any, **kwargs: Any) -> Any:
        raise FileNotFoundError("docker binary not found")

    monkeypatch.setattr(subprocess, "run", _raise_oserror)
    with pytest.raises(toolchain.ToolchainBoundaryError, match="docker binary not found") as caught:
        toolchain.verify_pinned_image_tool_boundary(docker_bin="missing-docker")
    _assert_blocked_policy_error(
        caught.value, toolchain.SUB_REASON_TOOLCHAIN_PROBE_FAILED
    )


@pytest.mark.parametrize(
    ("stderr_bytes", "expected_snippet"),
    [
        (b"permission denied while connecting to Docker daemon\n", "permission denied"),
        (b"   \n", "no stderr"),
        (b"docker daemon error \xff\xfe binary tail\n", "binary tail"),
    ],
)
def test_verify_pinned_image_handles_nonzero_exit_offline(
    monkeypatch: pytest.MonkeyPatch,
    stderr_bytes: bytes,
    expected_snippet: str,
):
    def _fake_run(cmd: list[str], **kwargs: Any) -> subprocess.CompletedProcess[bytes]:
        return subprocess.CompletedProcess(
            args=cmd, returncode=125, stdout=b"", stderr=stderr_bytes
        )

    monkeypatch.setattr(subprocess, "run", _fake_run)
    with pytest.raises(toolchain.ToolchainBoundaryError) as caught:
        toolchain.verify_pinned_image_tool_boundary()
    _assert_blocked_policy_error(
        caught.value, toolchain.SUB_REASON_TOOLCHAIN_PROBE_FAILED
    )
    assert "status 125" in str(caught.value)
    assert expected_snippet in str(caught.value)


def test_verify_pinned_image_success_offline_checks_subprocess_kwargs(
    monkeypatch: pytest.MonkeyPatch,
):
    captured: dict[str, Any] = {}

    def _fake_run(cmd: list[str], **kwargs: Any) -> subprocess.CompletedProcess[bytes]:
        captured["cmd"] = cmd
        captured["kwargs"] = kwargs
        return subprocess.CompletedProcess(
            args=cmd,
            returncode=0,
            stdout=_valid_probe_lines().encode("utf-8"),
            stderr=b"clang diagnostic on stderr is tolerated\n",
        )

    monkeypatch.setattr(subprocess, "run", _fake_run)
    report = toolchain.verify_pinned_image_tool_boundary(
        image=release.TOOLCHAIN_IMAGE,
        docker_bin="/usr/bin/docker",
        timeout_seconds=45.0,
    )
    assert "--name" in captured["cmd"]
    container_name = captured["cmd"][captured["cmd"].index("--name") + 1]
    assert container_name.startswith("datacon-toolchain-probe-")
    assert captured["cmd"] == toolchain.build_toolchain_probe_command(
        image=release.TOOLCHAIN_IMAGE,
        seccomp_path=None,
        docker_bin="/usr/bin/docker",
        container_name=container_name,
    )
    kwargs = captured["kwargs"]
    assert kwargs.get("capture_output") is True
    assert not kwargs.get("text", False)
    assert kwargs.get("check") is False
    assert kwargs.get("timeout") == 45.0
    assert not kwargs.get("shell", False)
    assert report.matches_v1_boundary is True
    assert report.available == toolchain.V1_AVAILABLE_TOOLS
    assert report.missing == toolchain.V1_MISSING_TOOLS
    assert report.stderr == "clang diagnostic on stderr is tolerated"


def test_verify_pinned_image_rejects_non_utf8_stdout_offline(
    monkeypatch: pytest.MonkeyPatch,
):
    def _fake_run(cmd: list[str], **kwargs: Any) -> subprocess.CompletedProcess[bytes]:
        return subprocess.CompletedProcess(
            args=cmd,
            returncode=0,
            stdout=b"TOOL cmake present\n\xff\xfe",
            stderr=b"",
        )

    monkeypatch.setattr(subprocess, "run", _fake_run)
    with pytest.raises(toolchain.ToolchainBoundaryError) as caught:
        toolchain.verify_pinned_image_tool_boundary()
    _assert_blocked_policy_error(
        caught.value, toolchain.SUB_REASON_INVALID_PROBE_OUTPUT
    )


def test_verify_pinned_image_surfaces_clang_stderr_on_libfuzzer_absent_offline(
    monkeypatch: pytest.MonkeyPatch,
):
    def _fake_run(cmd: list[str], **kwargs: Any) -> subprocess.CompletedProcess[bytes]:
        return subprocess.CompletedProcess(
            args=cmd,
            returncode=0,
            stdout=_valid_probe_lines(overrides={"libfuzzer": "absent"}).encode("utf-8"),
            stderr=b"clang: error: unable to link libclang_rt.fuzzer \xff\xfe\n",
        )

    monkeypatch.setattr(subprocess, "run", _fake_run)
    report = toolchain.verify_pinned_image_tool_boundary()
    assert report.matches_v1_boundary is False
    assert report.unexpected_missing == frozenset({"libfuzzer"})
    assert "clang: error: unable to link libclang_rt.fuzzer" in report.stderr
    assert "\ufffd" in report.stderr

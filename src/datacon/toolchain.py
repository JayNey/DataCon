"""Pinned toolchain image capability boundary and v1/v2 routing policy (T13c, ADR-005 #9)."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
import math
from pathlib import Path
import re
import subprocess
from types import MappingProxyType
from typing import Any, Literal

from datacon import release
from datacon.tools import sandbox

# Single source of truth for the pinned v1 toolchain image and digest.
PINNED_TOOLCHAIN_IMAGE: str = release.TOOLCHAIN_IMAGE
PINNED_TOOLCHAIN_IMAGE_DIGEST: str = release.TOOLCHAIN_IMAGE_DIGEST

# Capability sets established for the pinned v1 toolchain image (ADR-005 Decision #9).
V1_AVAILABLE_TOOLS: frozenset[str] = frozenset(
    {"clang", "cmake", "make", "autoconf", "automake", "libfuzzer"}
)
V1_MISSING_TOOLS: frozenset[str] = frozenset(
    {"pkg-config", "libtool", "ninja", "git"}
)
PROBED_TOOLS: frozenset[str] = V1_AVAILABLE_TOOLS | V1_MISSING_TOOLS
ONIGURUMA_REQUIRED_TOOLS: tuple[str, ...] = (
    "cmake",
    "make",
    "autoconf",
    "automake",
    "libFuzzer",
)

REASON_TOOLCHAIN_V2_REQUIRED = "TOOLCHAIN_IMAGE_V2_REQUIRED"
REASON_INVALID_TOOLCHAIN_V2 = "INVALID_TOOLCHAIN_IMAGE_V2"
REASON_INVALID_TOOL_REQUIREMENT = "INVALID_TOOL_REQUIREMENT"
REASON_INVALID_PROBE_OUTPUT = "INVALID_TOOLCHAIN_PROBE_OUTPUT"
REASON_TOOLCHAIN_PROBE_FAILED = "TOOLCHAIN_PROBE_FAILED"

_SHA256_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_REGISTRY_PREFIX_RE = (
    r"(?:(?:[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?"
    r"(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?)+|localhost)"
    r"(?::[0-9]{1,5})?/)"
)
_REPO_PATH_RE = r"[a-z0-9]+(?:[._-][a-z0-9]+)*(?:/[a-z0-9]+(?:[._-][a-z0-9]+)*)*"
_IMAGE_TAG_RE = r"(?::[A-Za-z0-9_][A-Za-z0-9._-]{0,127})?"
_IMAGE_REPO_RE = re.compile(f"^{_REGISTRY_PREFIX_RE}?{_REPO_PATH_RE}{_IMAGE_TAG_RE}$")
_PROBE_LINE_RE = re.compile(r"^TOOL\s+(\S+)\s+(present|absent)$")

_PROBE_COMMAND_TOOLS_PRESENT: tuple[str, ...] = (
    "clang",
    "cmake",
    "make",
    "autoconf",
    "automake",
)
_PROBE_COMMAND_TOOLS_ABSENT: tuple[str, ...] = (
    "pkg-config",
    "libtool",
    "ninja",
    "git",
)


class ToolchainBoundaryError(ValueError):
    """Fail-closed error for toolchain v1/v2 boundary, reference, or probe violations."""

    def __init__(
        self,
        detail: str,
        *,
        reason_code: str,
        missing_v1_tools: Sequence[str] = (),
        unknown_tools: Sequence[str] = (),
    ) -> None:
        self.reason_code = reason_code
        self.missing_v1_tools = tuple(missing_v1_tools)
        self.unknown_tools = tuple(unknown_tools)
        self.detail = detail
        super().__init__(f"{reason_code}: {detail}")


@dataclass(frozen=True)
class ToolchainSelection:
    """Deterministic toolchain image selection outcome for a case's tool requirements."""

    image: str
    image_digest: str
    image_tier: Literal["v1", "v2"]
    requires_v2: bool
    required_tools: tuple[str, ...]
    missing_v1_tools: tuple[str, ...]
    unknown_tools: tuple[str, ...]


@dataclass(frozen=True)
class ToolchainProbeReport:
    """Parsed live-container capability probe result against the v1 boundary."""

    available: frozenset[str]
    missing: frozenset[str]
    results: Mapping[str, bool]
    matches_v1_boundary: bool
    unexpected_missing: frozenset[str]
    unexpected_present: frozenset[str]


def normalize_tool_name(name: Any) -> str:
    """Normalize a single tool requirement name, failing closed on invalid input."""
    if not isinstance(name, str):
        raise ToolchainBoundaryError(
            f"tool requirement must be a string, got {type(name).__name__}",
            reason_code=REASON_INVALID_TOOL_REQUIREMENT,
        )
    if any(ord(ch) < 32 or ord(ch) == 127 for ch in name):
        raise ToolchainBoundaryError(
            f"tool requirement contains control characters: {name!r}",
            reason_code=REASON_INVALID_TOOL_REQUIREMENT,
        )
    normalized = name.strip().lower()
    if not normalized:
        raise ToolchainBoundaryError(
            "tool requirement must be a non-empty string",
            reason_code=REASON_INVALID_TOOL_REQUIREMENT,
        )
    if any(ch.isspace() for ch in normalized):
        raise ToolchainBoundaryError(
            f"tool requirement contains internal whitespace: {name!r}",
            reason_code=REASON_INVALID_TOOL_REQUIREMENT,
        )
    return normalized


def validate_pinned_image_ref(
    image: Any,
    *,
    label: str = "toolchain_image",
    reason_code: str = REASON_INVALID_TOOLCHAIN_V2,
    missing_v1_tools: Sequence[str] = (),
    unknown_tools: Sequence[str] = (),
) -> tuple[str, str]:
    """Validate that an image reference is ``<repo>@sha256:<64 lowercase hex>``."""
    if not isinstance(image, str) or not image:
        raise ToolchainBoundaryError(
            f"{label} must be a non-empty digest-pinned image reference",
            reason_code=reason_code,
            missing_v1_tools=missing_v1_tools,
            unknown_tools=unknown_tools,
        )
    if any(ch.isspace() or ord(ch) < 32 or ord(ch) == 127 for ch in image):
        raise ToolchainBoundaryError(
            f"{label} must not contain whitespace or control characters: {image!r}",
            reason_code=reason_code,
            missing_v1_tools=missing_v1_tools,
            unknown_tools=unknown_tools,
        )
    if image.count("@") != 1:
        raise ToolchainBoundaryError(
            f"{label} must be pinned by a single '@sha256:<digest>' suffix: {image!r}",
            reason_code=reason_code,
            missing_v1_tools=missing_v1_tools,
            unknown_tools=unknown_tools,
        )
    repo, _, digest = image.partition("@")
    if not _IMAGE_REPO_RE.fullmatch(repo):
        raise ToolchainBoundaryError(
            f"{label} has an invalid repository reference: {repo!r}",
            reason_code=reason_code,
            missing_v1_tools=missing_v1_tools,
            unknown_tools=unknown_tools,
        )
    if not _SHA256_DIGEST_RE.fullmatch(digest):
        raise ToolchainBoundaryError(
            f"{label} must use a lowercase sha256 digest: {digest!r}",
            reason_code=reason_code,
            missing_v1_tools=missing_v1_tools,
            unknown_tools=unknown_tools,
        )
    return image, digest


def select_toolchain_image(
    required_tools: Sequence[str],
    *,
    toolchain_image_v2: str | None = None,
) -> ToolchainSelection:
    """Select the pinned v1 image or route/fail-closed on toolchain image v2.

    Cases whose required tools are fully satisfied by ``V1_AVAILABLE_TOOLS``
    (including Oniguruma-class cases) always use ``release.TOOLCHAIN_IMAGE``.
    Any tool in ``V1_MISSING_TOOLS`` or outside ``V1_AVAILABLE_TOOLS`` requires
    an explicitly configured, digest-pinned ``toolchain_image_v2`` distinct from
    ``release.TOOLCHAIN_IMAGE_DIGEST``.
    """
    if isinstance(required_tools, (str, bytes)) or not isinstance(
        required_tools, Sequence
    ):
        raise ToolchainBoundaryError(
            "required_tools must be a sequence of tool names",
            reason_code=REASON_INVALID_TOOL_REQUIREMENT,
        )

    normalized_ordered = tuple(
        dict.fromkeys(normalize_tool_name(tool) for tool in required_tools)
    )
    normalized_set = set(normalized_ordered)
    missing_v1 = tuple(sorted(normalized_set & V1_MISSING_TOOLS))
    unknown = tuple(sorted(normalized_set - V1_AVAILABLE_TOOLS - V1_MISSING_TOOLS))

    if not missing_v1 and not unknown:
        return ToolchainSelection(
            image=PINNED_TOOLCHAIN_IMAGE,
            image_digest=PINNED_TOOLCHAIN_IMAGE_DIGEST,
            image_tier="v1",
            requires_v2=False,
            required_tools=normalized_ordered,
            missing_v1_tools=(),
            unknown_tools=(),
        )

    reasons: list[str] = []
    if missing_v1:
        reasons.append(f"missing_v1_tools={list(missing_v1)}")
    if unknown:
        reasons.append(f"unknown_tools={list(unknown)}")
    reason_summary = ", ".join(reasons)

    if toolchain_image_v2 is None or (
        isinstance(toolchain_image_v2, str) and not toolchain_image_v2.strip()
    ):
        raise ToolchainBoundaryError(
            f"case requires toolchain image v2 ({reason_summary}) "
            "but toolchain_image_v2 is not configured",
            reason_code=REASON_TOOLCHAIN_V2_REQUIRED,
            missing_v1_tools=missing_v1,
            unknown_tools=unknown,
        )

    validated_image, validated_digest = validate_pinned_image_ref(
        toolchain_image_v2,
        label="toolchain_image_v2",
        reason_code=REASON_INVALID_TOOLCHAIN_V2,
        missing_v1_tools=missing_v1,
        unknown_tools=unknown,
    )
    if validated_digest == PINNED_TOOLCHAIN_IMAGE_DIGEST:
        raise ToolchainBoundaryError(
            "toolchain_image_v2 must not reuse the pinned v1 toolchain digest "
            f"({PINNED_TOOLCHAIN_IMAGE_DIGEST})",
            reason_code=REASON_INVALID_TOOLCHAIN_V2,
            missing_v1_tools=missing_v1,
            unknown_tools=unknown,
        )

    return ToolchainSelection(
        image=validated_image,
        image_digest=validated_digest,
        image_tier="v2",
        requires_v2=True,
        required_tools=normalized_ordered,
        missing_v1_tools=missing_v1,
        unknown_tools=unknown,
    )


def render_toolchain_probe_script() -> str:
    """Return a pure POSIX ``/bin/sh`` script probing the v1 image tool boundary.

    Checks CLI tools via ``command -v`` and verifies ``libFuzzer`` via the clang
    resource directory (``libclang_rt.fuzzer*.a``) plus compiling a minimal
    ``LLVMFuzzerTestOneInput`` target with ``clang -fsanitize=fuzzer`` in ``/work``.
    Never installs any package.
    """
    present_list = " ".join(_PROBE_COMMAND_TOOLS_PRESENT)
    absent_list = " ".join(_PROBE_COMMAND_TOOLS_ABSENT)
    return "\n".join(
        [
            "set -eu",
            f"for tool in {present_list}; do",
            '  if command -v "$tool" >/dev/null 2>&1; then',
            "    printf 'TOOL %s present\\n' \"$tool\"",
            "  else",
            "    printf 'TOOL %s absent\\n' \"$tool\"",
            "  fi",
            "done",
            "libfuzzer_ok=0",
            "if command -v clang >/dev/null 2>&1; then",
            '  resdir="$(clang -print-resource-dir 2>/dev/null || true)"',
            '  if [ -n "$resdir" ] && find "$resdir" -name \'libclang_rt.fuzzer*.a\' 2>/dev/null | grep -q .; then',
            "    printf 'int LLVMFuzzerTestOneInput(const unsigned char *d, unsigned long s){(void)d;(void)s;return 0;}\\n' > /work/fuzzer_probe.c",
            "    if clang -fsanitize=fuzzer /work/fuzzer_probe.c -o /work/fuzzer_probe >/dev/null 2>&1; then",
            "      libfuzzer_ok=1",
            "    fi",
            "    rm -f /work/fuzzer_probe.c /work/fuzzer_probe",
            "  fi",
            "fi",
            'if [ "$libfuzzer_ok" -eq 1 ]; then',
            "  printf 'TOOL libfuzzer present\\n'",
            "else",
            "  printf 'TOOL libfuzzer absent\\n'",
            "fi",
            f"for tool in {absent_list}; do",
            '  if command -v "$tool" >/dev/null 2>&1; then',
            "    printf 'TOOL %s present\\n' \"$tool\"",
            "  else",
            "    printf 'TOOL %s absent\\n' \"$tool\"",
            "  fi",
            "done",
        ]
    )


def parse_toolchain_probe_output(output: str | bytes) -> ToolchainProbeReport:
    """Parse probe stdout strictly, failing closed on malformed or incomplete data."""
    if isinstance(output, bytes):
        try:
            text = output.decode("utf-8")
        except UnicodeDecodeError as error:
            raise ToolchainBoundaryError(
                f"toolchain probe output is not valid UTF-8: {error}",
                reason_code=REASON_INVALID_PROBE_OUTPUT,
            ) from error
    elif isinstance(output, str):
        text = output
    else:
        raise ToolchainBoundaryError(
            f"toolchain probe output must be str or bytes, got {type(output).__name__}",
            reason_code=REASON_INVALID_PROBE_OUTPUT,
        )

    parsed: dict[str, bool] = {}
    for line_no, raw_line in enumerate(text.splitlines(), start=1):
        stripped = raw_line.strip()
        if not stripped:
            continue
        match = _PROBE_LINE_RE.fullmatch(stripped)
        if match is None:
            raise ToolchainBoundaryError(
                f"malformed probe line {line_no}: {raw_line!r}",
                reason_code=REASON_INVALID_PROBE_OUTPUT,
            )
        tool_name = normalize_tool_name(match.group(1))
        if tool_name not in PROBED_TOOLS:
            raise ToolchainBoundaryError(
                f"unexpected tool in probe output at line {line_no}: {tool_name!r}",
                reason_code=REASON_INVALID_PROBE_OUTPUT,
            )
        if tool_name in parsed:
            raise ToolchainBoundaryError(
                f"duplicate probe entry for tool {tool_name!r} at line {line_no}",
                reason_code=REASON_INVALID_PROBE_OUTPUT,
            )
        parsed[tool_name] = match.group(2) == "present"

    missing_entries = sorted(PROBED_TOOLS - set(parsed))
    if missing_entries:
        raise ToolchainBoundaryError(
            f"incomplete probe output; missing entries for: {', '.join(missing_entries)}",
            reason_code=REASON_INVALID_PROBE_OUTPUT,
        )

    available = frozenset(name for name, present in parsed.items() if present)
    missing = frozenset(name for name, present in parsed.items() if not present)
    unexpected_missing = V1_AVAILABLE_TOOLS - available
    unexpected_present = V1_MISSING_TOOLS - missing
    matches_v1_boundary = not unexpected_missing and not unexpected_present
    return ToolchainProbeReport(
        available=available,
        missing=missing,
        results=MappingProxyType(dict(sorted(parsed.items()))),
        matches_v1_boundary=matches_v1_boundary,
        unexpected_missing=unexpected_missing,
        unexpected_present=unexpected_present,
    )


def build_toolchain_probe_command(
    *,
    image: str = PINNED_TOOLCHAIN_IMAGE,
    seccomp_path: Path | str | None = None,
    docker_bin: str = "docker",
) -> list[str]:
    """Construct an isolated one-shot ``docker run`` command to probe the image."""
    validated_image, _ = validate_pinned_image_ref(
        image,
        label="image",
        reason_code=REASON_TOOLCHAIN_PROBE_FAILED,
    )
    if not isinstance(docker_bin, str) or not docker_bin.strip():
        raise ToolchainBoundaryError(
            "docker_bin must be a non-empty executable name or path",
            reason_code=REASON_TOOLCHAIN_PROBE_FAILED,
        )
    seccomp_file = (
        Path(seccomp_path) if seccomp_path is not None else sandbox.SECCOMP_PROFILE_PATH
    )
    if not seccomp_file.is_file():
        raise ToolchainBoundaryError(
            f"pinned seccomp profile is missing: {seccomp_file}",
            reason_code=REASON_TOOLCHAIN_PROBE_FAILED,
        )
    try:
        profile_digest = sandbox.seccomp_profile_digest(seccomp_file)
    except sandbox.SandboxPolicyError as error:
        raise ToolchainBoundaryError(
            f"pinned seccomp profile is invalid: {error}",
            reason_code=REASON_TOOLCHAIN_PROBE_FAILED,
        ) from error
    if (
        seccomp_path is None
        and profile_digest != sandbox.SECCOMP_PROFILE_DIGEST
    ):
        raise ToolchainBoundaryError(
            "default seccomp profile digest does not match pinned SECCOMP_PROFILE_DIGEST",
            reason_code=REASON_TOOLCHAIN_PROBE_FAILED,
        )

    return [
        docker_bin,
        "run",
        "--rm",
        "--platform",
        "linux/amd64",
        "--pull",
        "never",
        "--network=none",
        "--read-only",
        "--cap-drop=ALL",
        "--security-opt=no-new-privileges:true",
        f"--security-opt=seccomp={seccomp_file}",
        "--user=65534:65534",
        "--pids-limit=128",
        "--memory=1024m",
        "--memory-swap=1024m",
        "--cpus=2",
        "--ipc=private",
        "--tmpfs",
        "/work:rw,noexec,nosuid,nodev,size=128m,mode=1777",
        "--tmpfs",
        "/tmp:rw,noexec,nosuid,nodev,size=64m,mode=1777",
        "-w",
        "/work",
        "-e",
        "TMPDIR=/tmp",
        validated_image,
        "/bin/sh",
        "-c",
        render_toolchain_probe_script(),
    ]


def verify_pinned_image_tool_boundary(
    *,
    image: str = PINNED_TOOLCHAIN_IMAGE,
    docker_bin: str = "docker",
    timeout_seconds: float = 60.0,
) -> ToolchainProbeReport:
    """Run the isolated container probe against the pinned image and parse results."""
    if (
        isinstance(timeout_seconds, bool)
        or not isinstance(timeout_seconds, (int, float))
        or not math.isfinite(timeout_seconds)
        or timeout_seconds <= 0
    ):
        raise ToolchainBoundaryError(
            f"timeout_seconds must be a positive finite number, got {timeout_seconds!r}",
            reason_code=REASON_TOOLCHAIN_PROBE_FAILED,
        )
    cmd = build_toolchain_probe_command(
        image=image,
        seccomp_path=None,
        docker_bin=docker_bin,
    )
    try:
        completed = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
            check=False,
        )
    except subprocess.TimeoutExpired as error:
        raise ToolchainBoundaryError(
            f"toolchain probe container timed out after {timeout_seconds}s",
            reason_code=REASON_TOOLCHAIN_PROBE_FAILED,
        ) from error
    except OSError as error:
        raise ToolchainBoundaryError(
            f"failed to execute toolchain probe command: {error}",
            reason_code=REASON_TOOLCHAIN_PROBE_FAILED,
        ) from error

    if completed.returncode != 0:
        stderr_snippet = completed.stderr.strip()[:500]
        raise ToolchainBoundaryError(
            f"toolchain probe container exited with status {completed.returncode}: "
            f"{stderr_snippet or 'no stderr'}",
            reason_code=REASON_TOOLCHAIN_PROBE_FAILED,
        )
    return parse_toolchain_probe_output(completed.stdout)

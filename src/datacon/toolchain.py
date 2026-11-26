"""Pinned toolchain image capability boundary and v1/v2 routing policy (T13c, ADR-005 #9)."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, replace
import math
from pathlib import Path
import re
import subprocess
from types import MappingProxyType
from typing import Any, Literal, NoReturn

from datacon import release, verdict
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

REASON_POLICY_DENIED = "POLICY_DENIED"

SUB_REASON_TOOLCHAIN_V2_REQUIRED = "TOOLCHAIN_IMAGE_V2_REQUIRED"
SUB_REASON_INVALID_TOOLCHAIN_V2 = "INVALID_TOOLCHAIN_IMAGE_V2"
SUB_REASON_INVALID_TOOL_REQUIREMENT = "INVALID_TOOL_REQUIREMENT"
SUB_REASON_INVALID_PROBE_OUTPUT = "INVALID_TOOLCHAIN_PROBE_OUTPUT"
SUB_REASON_TOOLCHAIN_PROBE_FAILED = "TOOLCHAIN_PROBE_FAILED"

_SHA256_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_DNS_LABEL_RE = r"[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?"
_FQDN_RE = rf"{_DNS_LABEL_RE}(?:\.{_DNS_LABEL_RE})+"
_REGISTRY_PREFIX_RE = (
    rf"(?:(?:(?:{_FQDN_RE}|localhost)(?::(?P<fqdn_port>[0-9]+))?)"
    rf"|(?:{_DNS_LABEL_RE}:(?P<label_port>[0-9]+)))/"
)
_REPO_PATH_RE = (
    r"[a-z0-9]+(?:(?:[._]|__|[-]+)[a-z0-9]+)*"
    r"(?:/[a-z0-9]+(?:(?:[._]|__|[-]+)[a-z0-9]+)*)*"
)
_IMAGE_TAG_RE = r"(?::[A-Za-z0-9_][A-Za-z0-9._-]{0,127})?"
_IMAGE_REPO_RE = re.compile(
    f"^(?:{_REGISTRY_PREFIX_RE})?{_REPO_PATH_RE}{_IMAGE_TAG_RE}$"
)
_TOOL_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9._+-]{0,63}$")
_PROBE_LINE_RE = re.compile(r"^TOOL\s+(\S+)\s+(present|absent)$")


class ToolchainBoundaryError(ValueError):
    """Fail-closed error for toolchain v1/v2 boundary, reference, or probe violations.

    ``reason_code`` always belongs to the closed v0.2 ``BLOCKED`` reason enum
    (default ``"POLICY_DENIED"``), validated fail-closed via
    ``verdict.reason_allowed_v2("BLOCKED", reason_code)``. ``sub_reason``
    carries the fine-grained diagnostic token for audit attribution.
    """

    def __init__(
        self,
        detail: str,
        *,
        sub_reason: str,
        reason_code: str = REASON_POLICY_DENIED,
        missing_v1_tools: Sequence[str] = (),
        unknown_tools: Sequence[str] = (),
    ) -> None:
        if not verdict.reason_allowed_v2("BLOCKED", reason_code):
            raise ValueError(
                "reason_code must be an allowed v0.2 BLOCKED reason, "
                f"got {reason_code!r}"
            )
        if not isinstance(sub_reason, str) or not sub_reason.strip():
            raise ValueError("sub_reason must be a non-empty string")
        for field_name, field_value in (
            ("missing_v1_tools", missing_v1_tools),
            ("unknown_tools", unknown_tools),
        ):
            if isinstance(
                field_value, (str, bytes, bytearray, memoryview)
            ) or not isinstance(field_value, Sequence):
                raise TypeError(
                    f"{field_name} must be a sequence of tool names, "
                    f"got {type(field_value).__name__}"
                )
        self.reason_code = reason_code
        self.sub_reason = sub_reason
        self.missing_v1_tools = tuple(missing_v1_tools)
        self.unknown_tools = tuple(unknown_tools)
        self.detail = detail
        super().__init__(f"{reason_code} ({sub_reason}): {detail}")

    @property
    def message(self) -> str:
        """Return the detail message (consistent with SandboxError/ExecutionBlocked)."""
        return self.detail


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
    stderr: str = ""


def normalize_tool_name(name: Any) -> str:
    """Normalize a single tool requirement name, failing closed on invalid input."""
    if not isinstance(name, str):
        raise ToolchainBoundaryError(
            f"tool requirement must be a string, got {type(name).__name__}",
            sub_reason=SUB_REASON_INVALID_TOOL_REQUIREMENT,
        )
    if not name.isascii():
        raise ToolchainBoundaryError(
            f"tool requirement must be ASCII: {name!r}",
            sub_reason=SUB_REASON_INVALID_TOOL_REQUIREMENT,
        )
    if any(ord(ch) < 32 or ord(ch) == 127 for ch in name):
        raise ToolchainBoundaryError(
            f"tool requirement contains control characters: {name!r}",
            sub_reason=SUB_REASON_INVALID_TOOL_REQUIREMENT,
        )
    normalized = name.strip().lower()
    if not normalized:
        raise ToolchainBoundaryError(
            "tool requirement must be a non-empty string",
            sub_reason=SUB_REASON_INVALID_TOOL_REQUIREMENT,
        )
    if not _TOOL_NAME_RE.fullmatch(normalized):
        raise ToolchainBoundaryError(
            f"tool requirement contains invalid characters: {name!r}",
            sub_reason=SUB_REASON_INVALID_TOOL_REQUIREMENT,
        )
    return normalized


def validate_pinned_image_ref(
    image: Any,
    *,
    label: str = "toolchain_image",
    sub_reason: str = SUB_REASON_INVALID_TOOLCHAIN_V2,
    reason_code: str = REASON_POLICY_DENIED,
    missing_v1_tools: Sequence[str] = (),
    unknown_tools: Sequence[str] = (),
) -> tuple[str, str]:
    """Validate that an image reference is ``<repo>@sha256:<64 lowercase hex>``."""

    def _fail(detail: str) -> NoReturn:
        raise ToolchainBoundaryError(
            detail,
            sub_reason=sub_reason,
            reason_code=reason_code,
            missing_v1_tools=missing_v1_tools,
            unknown_tools=unknown_tools,
        )

    if not isinstance(image, str) or not image:
        _fail(f"{label} must be a non-empty digest-pinned image reference")
    if any(ch.isspace() or ord(ch) < 32 or ord(ch) == 127 for ch in image):
        _fail(f"{label} must not contain whitespace or control characters: {image!r}")
    if image.count("@") != 1:
        _fail(
            f"{label} must be pinned by a single '@sha256:<digest>' suffix: {image!r}"
        )
    repo, _, digest = image.partition("@")
    repo_match = _IMAGE_REPO_RE.fullmatch(repo)
    if repo_match is None:
        _fail(f"{label} has an invalid repository reference: {repo!r}")
    port_str = repo_match.group("fqdn_port") or repo_match.group("label_port")
    if port_str is not None and (
        port_str.startswith("0")
        or len(port_str) > 5
        or not (1 <= int(port_str) <= 65535)
    ):
        _fail(f"{label} has an invalid registry port: {port_str!r}")
    if not _SHA256_DIGEST_RE.fullmatch(digest):
        _fail(f"{label} must use a lowercase sha256 digest: {digest!r}")
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
    if isinstance(
        required_tools, (str, bytes, bytearray, memoryview)
    ) or not isinstance(required_tools, Sequence):
        raise ToolchainBoundaryError(
            "required_tools must be a sequence of tool names",
            sub_reason=SUB_REASON_INVALID_TOOL_REQUIREMENT,
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
            sub_reason=SUB_REASON_TOOLCHAIN_V2_REQUIRED,
            missing_v1_tools=missing_v1,
            unknown_tools=unknown,
        )

    validated_image, validated_digest = validate_pinned_image_ref(
        toolchain_image_v2,
        label="toolchain_image_v2",
        sub_reason=SUB_REASON_INVALID_TOOLCHAIN_V2,
        missing_v1_tools=missing_v1,
        unknown_tools=unknown,
    )
    if validated_digest == PINNED_TOOLCHAIN_IMAGE_DIGEST:
        raise ToolchainBoundaryError(
            "toolchain_image_v2 must not reuse the pinned v1 toolchain digest "
            f"({PINNED_TOOLCHAIN_IMAGE_DIGEST})",
            sub_reason=SUB_REASON_INVALID_TOOLCHAIN_V2,
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
    cli_tools = " ".join(sorted(PROBED_TOOLS - {"libfuzzer"}))
    return "\n".join(
        [
            "set -eu",
            f"for tool in {cli_tools}; do",
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
            "    if clang -fsanitize=fuzzer /work/fuzzer_probe.c -o /work/fuzzer_probe >/dev/null; then",
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
                sub_reason=SUB_REASON_INVALID_PROBE_OUTPUT,
            ) from error
    elif isinstance(output, str):
        text = output
    else:
        raise ToolchainBoundaryError(
            f"toolchain probe output must be str or bytes, got {type(output).__name__}",
            sub_reason=SUB_REASON_INVALID_PROBE_OUTPUT,
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
                sub_reason=SUB_REASON_INVALID_PROBE_OUTPUT,
            )
        raw_tool = match.group(1)
        if not raw_tool.isascii():
            raise ToolchainBoundaryError(
                f"non-ASCII tool name in probe line {line_no}: {raw_line!r}",
                sub_reason=SUB_REASON_INVALID_PROBE_OUTPUT,
            )
        tool_name = raw_tool.lower()
        if tool_name not in PROBED_TOOLS:
            raise ToolchainBoundaryError(
                f"unexpected tool in probe output at line {line_no}: {tool_name!r}",
                sub_reason=SUB_REASON_INVALID_PROBE_OUTPUT,
            )
        if tool_name in parsed:
            raise ToolchainBoundaryError(
                f"duplicate probe entry for tool {tool_name!r} at line {line_no}",
                sub_reason=SUB_REASON_INVALID_PROBE_OUTPUT,
            )
        parsed[tool_name] = match.group(2) == "present"

    missing_entries = sorted(PROBED_TOOLS - set(parsed))
    if missing_entries:
        raise ToolchainBoundaryError(
            f"incomplete probe output; missing entries for: {', '.join(missing_entries)}",
            sub_reason=SUB_REASON_INVALID_PROBE_OUTPUT,
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
        sub_reason=SUB_REASON_TOOLCHAIN_PROBE_FAILED,
    )
    if (
        not isinstance(docker_bin, str)
        or not docker_bin
        or docker_bin != docker_bin.strip()
        or any(ord(ch) < 32 or ord(ch) == 127 for ch in docker_bin)
    ):
        raise ToolchainBoundaryError(
            "docker_bin must be a non-empty executable name or path without "
            "leading/trailing whitespace or control characters",
            sub_reason=SUB_REASON_TOOLCHAIN_PROBE_FAILED,
        )
    if seccomp_path is None:
        raw_path = sandbox.SECCOMP_PROFILE_PATH
    else:
        if not isinstance(seccomp_path, (str, Path)):
            raise ToolchainBoundaryError(
                f"seccomp_path must be a str or Path, got {type(seccomp_path).__name__}",
                sub_reason=SUB_REASON_TOOLCHAIN_PROBE_FAILED,
            )
        if isinstance(seccomp_path, str) and (
            not seccomp_path.strip()
            or any(ord(ch) < 32 or ord(ch) == 127 for ch in seccomp_path)
        ):
            raise ToolchainBoundaryError(
                "seccomp_path must be a non-empty path without control characters",
                sub_reason=SUB_REASON_TOOLCHAIN_PROBE_FAILED,
            )
        raw_path = Path(seccomp_path)
    try:
        if raw_path.is_symlink():
            raise ToolchainBoundaryError(
                f"pinned seccomp profile path must not be a symlink: {raw_path}",
                sub_reason=SUB_REASON_TOOLCHAIN_PROBE_FAILED,
            )
        seccomp_file = raw_path.resolve(strict=True)
    except (OSError, ValueError) as error:
        if isinstance(error, ToolchainBoundaryError):
            raise
        raise ToolchainBoundaryError(
            f"pinned seccomp profile is missing or unreadable: {raw_path} ({error})",
            sub_reason=SUB_REASON_TOOLCHAIN_PROBE_FAILED,
        ) from error
    if not seccomp_file.is_file():
        raise ToolchainBoundaryError(
            f"pinned seccomp profile is not a regular file: {seccomp_file}",
            sub_reason=SUB_REASON_TOOLCHAIN_PROBE_FAILED,
        )
    try:
        profile_digest = sandbox.seccomp_profile_digest(seccomp_file)
    except sandbox.SandboxPolicyError as error:
        raise ToolchainBoundaryError(
            f"pinned seccomp profile is invalid: {error}",
            sub_reason=SUB_REASON_TOOLCHAIN_PROBE_FAILED,
        ) from error
    if profile_digest != sandbox.SECCOMP_PROFILE_DIGEST:
        raise ToolchainBoundaryError(
            f"seccomp profile digest {profile_digest} does not match pinned "
            f"SECCOMP_PROFILE_DIGEST ({sandbox.SECCOMP_PROFILE_DIGEST})",
            sub_reason=SUB_REASON_TOOLCHAIN_PROBE_FAILED,
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
        "--log-driver=none",
        "--tmpfs",
        "/work:rw,noexec,nosuid,nodev,size=128m,mode=1777",
        "--tmpfs",
        "/tmp:rw,noexec,nosuid,nodev,size=64m,mode=1777",
        "-w",
        "/work",
        "-e",
        "TMPDIR=/tmp",
        "-e",
        "HOME=/work",
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
            sub_reason=SUB_REASON_TOOLCHAIN_PROBE_FAILED,
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
            timeout=timeout_seconds,
            check=False,
        )
    except subprocess.TimeoutExpired as error:
        raise ToolchainBoundaryError(
            f"toolchain probe container timed out after {timeout_seconds}s",
            sub_reason=SUB_REASON_TOOLCHAIN_PROBE_FAILED,
        ) from error
    except OSError as error:
        raise ToolchainBoundaryError(
            f"failed to execute toolchain probe command: {error}",
            sub_reason=SUB_REASON_TOOLCHAIN_PROBE_FAILED,
        ) from error

    raw_stderr: Any = completed.stderr
    if isinstance(raw_stderr, bytes):
        stderr_text = raw_stderr.decode("utf-8", "replace").strip()
    elif isinstance(raw_stderr, str):
        stderr_text = raw_stderr.strip()
    else:
        stderr_text = ""

    if completed.returncode != 0:
        raise ToolchainBoundaryError(
            f"toolchain probe container exited with status {completed.returncode}: "
            f"{stderr_text[:500] or 'no stderr'}",
            sub_reason=SUB_REASON_TOOLCHAIN_PROBE_FAILED,
        )
    report = parse_toolchain_probe_output(completed.stdout)
    return replace(report, stderr=stderr_text[:2000])

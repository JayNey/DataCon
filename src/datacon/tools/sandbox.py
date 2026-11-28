"""One-shot Docker sandbox for building and replaying untrusted targets.

The sandbox is deliberately a thin, auditable adapter over the Docker CLI. It
never invokes a shell on the host with target-derived text: mount sources are
validator-checked absolute paths, container commands are fixed templates, and
every container is labelled and removed after use.
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from pathlib import Path, PurePosixPath
import hashlib
import json
import os
import posixpath
import re
import shlex
import shutil
import stat
import subprocess
import threading
import time
import uuid
from typing import Any, Mapping, Sequence

from datacon import build_provenance, fileio, jsonutil
from datacon.asan import ASanSignature, parse_asan
from datacon.cases import MAX_MATERIAL_BYTES

MIB = 1024 * 1024
# One union budget for stdout and stderr. Output is captured live from the
# attached container stream (log driver "none"), so there is no on-disk Docker
# log to rotate and no host log-directory access.
MAX_LOG_BYTES = 16 * 1024 * 1024
MAX_PROVENANCE_FACE_BYTES = MAX_LOG_BYTES
CAPTURE_CHUNK_BYTES = 64 * 1024
MAX_ARTIFACT_BYTES = 128 * 1024 * 1024
MAX_PREVIEW_BYTES = 512
STREAM_ROLES = ("stdout", "stderr")
DEFAULT_CC_SHIM_LOG_PATH = "/work/.datacon-cc-shim.log"
DEFAULT_CC_SHIM_COMPILER = "clang"
DEFAULT_CXX_SHIM_COMPILER = "clang++"
_UNSAFE_WORK_PATH_CHARS = " \t\r\n'\"`$;\x00"
_SAFE_SYSTEM_PATH = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
_IMAGE_DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
_SAFE_NAME = re.compile(r"[^a-z0-9_.-]+")
_PROBE_TIMEOUT = 120

# A fixed profile shipped with the package makes the seccomp boundary
# auditable. We never rely on "no seccomp=unconfined argument" as proof that a
# daemon default profile is active, and we never accept an arbitrary profile:
# the plan records this profile's canonical digest, the create command sends
# the exact file, and the inspect output is checked against the same digest.
SECCOMP_PROFILE_PATH = (
    Path(__file__).resolve().parents[1] / "data" / "seccomp" / "default.json"
)


def _canonical_json_digest(document: Any) -> str:
    payload = json.dumps(
        document, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")
    return "sha256:" + hashlib.sha256(payload).hexdigest()


def seccomp_profile_digest(path: Path | str = SECCOMP_PROFILE_PATH) -> str:
    """Return the digest of the fixed profile's canonical JSON document."""
    try:
        document = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError, UnicodeError) as error:
        raise SandboxPolicyError(
            f"the fixed seccomp profile is not readable: {error}"
        ) from error
    if not isinstance(document, dict) or not isinstance(
        document.get("defaultAction"), str
    ):
        raise SandboxPolicyError("the fixed seccomp profile is not a profile object")
    return _canonical_json_digest(document)


SECCOMP_PROFILE_DIGEST = seccomp_profile_digest()


class SandboxError(RuntimeError):
    """Base class for sandbox failures with a contract reason code."""

    reason_code = "SANDBOX_ERROR"

    def __init__(self, message: str, *, reason_code: str | None = None):
        super().__init__(message)
        self.message = message
        if reason_code is not None:
            self.reason_code = reason_code


class SandboxPolicyError(SandboxError):
    """The requested isolation or a required limit cannot be enforced."""

    reason_code = "POLICY_DENIED"


class SandboxUnavailable(SandboxPolicyError):
    """Docker or the pinned image is unavailable."""


@dataclass(frozen=True)
class IsolationPolicy:
    network: str = "none"
    user: str = "65534:65534"
    read_only_root: bool = True
    cap_drop: tuple[str, ...] = ("ALL",)
    no_new_privileges: bool = True
    seccomp: str = "runtime/default"
    seccomp_profile_digest: str | None = None

    @classmethod
    def from_plan(cls, value: Mapping[str, Any]) -> "IsolationPolicy":
        if not isinstance(value, Mapping):
            raise SandboxPolicyError("plan isolation must be an object")
        caps = value.get("cap_drop")
        if not isinstance(caps, list) or not all(isinstance(item, str) for item in caps):
            raise SandboxPolicyError("plan isolation cap_drop is invalid")
        digest = value.get("seccomp_profile_digest")
        if digest is None:
            # Legacy plans predate the explicit profile. Fail closed at the
            # policy boundary instead of silently claiming a daemon default.
            raise SandboxPolicyError(
                "the plan has no explicit seccomp profile digest"
            )
        return cls(
            network=value.get("network", ""),
            user=value.get("user", ""),
            read_only_root=value.get("read_only_root") is True,
            cap_drop=tuple(caps),
            no_new_privileges=value.get("no_new_privileges") is True,
            seccomp=value.get("seccomp", ""),
            seccomp_profile_digest=digest,
        )

    def validate(self) -> None:
        if self.network != "none":
            raise SandboxPolicyError("target containers must use network none")
        if not isinstance(self.user, str) or not re.fullmatch(
            r"[1-9][0-9]*(?::[1-9][0-9]*)?", self.user
        ):
            raise SandboxPolicyError("target containers must run as a non-root uid")
        if self.read_only_root is not True:
            raise SandboxPolicyError("target root filesystem must be read-only")
        if "ALL" not in self.cap_drop:
            raise SandboxPolicyError("target containers must drop ALL capabilities")
        if self.no_new_privileges is not True:
            raise SandboxPolicyError("no-new-privileges must be enabled")
        if self.seccomp not in ("runtime/default", "docker/default"):
            raise SandboxPolicyError("a default seccomp profile is required")
        if (
            not isinstance(self.seccomp_profile_digest, str)
            or not _DIGEST.fullmatch(self.seccomp_profile_digest)
        ):
            raise SandboxPolicyError(
                "an explicit seccomp profile digest is required"
            )
        if not SECCOMP_PROFILE_PATH.is_file():
            raise SandboxPolicyError("the fixed seccomp profile is missing")
        if seccomp_profile_digest() != self.seccomp_profile_digest:
            raise SandboxPolicyError(
                "the plan seccomp profile digest does not match the fixed profile"
            )


@dataclass(frozen=True)
class ResourceLimits:
    cpu: int
    memory_mib: int
    pids: int
    scratch_mib: int

    def validate(self) -> None:
        for name, value in (
            ("cpu", self.cpu),
            ("memory_mib", self.memory_mib),
            ("pids", self.pids),
            ("scratch_mib", self.scratch_mib),
        ):
            if type(value) is not int or value <= 0:
                raise SandboxPolicyError(f"resource limit {name} must be positive")
        if self.scratch_mib < 32:
            raise SandboxPolicyError("scratch_mib must be at least 32 MiB")


@dataclass(frozen=True)
class ProbeReport:
    ok: bool
    checks: dict[str, Any]
    compiler_version: str
    image_digest: str
    raw: str
    limits: dict[str, Any] = field(default_factory=dict)
    cleanup_errors: tuple[str, ...] = ()


@dataclass(frozen=True)
class BuildOutput:
    """One verified ``BuildSpec.outputs`` artifact and its D39 archive path."""

    relative_path: str
    archive_path: str
    data: bytes
    digest: str


@dataclass(frozen=True)
class BuildResult:
    version: str
    status: str
    exit_code: int | None
    duration_seconds: float
    container_id: str | None
    image_digest: str
    compile_args: tuple[str, ...]
    artifact_digest: str | None
    log: bytes
    log_truncated: bool
    artifact: bytes | None
    metadata: dict[str, Any]
    capture_error: str | None = None
    truncated_roles: tuple[str, ...] = ()
    provenance_face: bytes | None = None
    provenance_face_name: str | None = None
    outputs: tuple[BuildOutput, ...] = ()

    def as_dict(self) -> dict[str, Any]:
        payload = {
            "version": self.version,
            "status": self.status,
            "exit_code": self.exit_code,
            "duration_seconds": self.duration_seconds,
            "container_id": self.container_id,
            "image_digest": self.image_digest,
            "compile_args": list(self.compile_args),
            "artifact_digest": self.artifact_digest,
            "log_digest": "sha256:" + hashlib.sha256(self.log).hexdigest(),
            "log_truncated": self.log_truncated,
            "truncated_roles": list(self.truncated_roles),
            "capture_error": self.capture_error,
            **self.metadata,
        }
        payload["capture_error"] = self.capture_error
        payload["truncated_roles"] = list(self.truncated_roles)
        # Never expose raw provenance_face bytes in JSON metadata.
        payload.pop("provenance_face", None)
        if self.provenance_face_name is not None:
            payload["provenance_face_name"] = self.provenance_face_name
        if self.provenance_face is not None:
            payload["provenance_face_size"] = len(self.provenance_face)
            if not isinstance(payload.get("provenance_face_sha256"), str):
                payload["provenance_face_sha256"] = (
                    "sha256:" + hashlib.sha256(self.provenance_face).hexdigest()
                )
        return payload


@dataclass(frozen=True)
class BuildSpecExecutionPlan:
    """Validated, fixed-template execution plan for a v2 ``BuildSpec``."""

    kind: str
    configure: tuple[str, ...]
    build: tuple[str, ...]
    install: tuple[str, ...]
    env: dict[str, str]
    outputs: tuple[str, ...]
    primary_output: str
    primary_output_container_path: str
    output_container_paths: tuple[tuple[str, str], ...]
    provenance_face_name: str
    provenance_face_container_path: str | None
    cc_shim_destination: str | None = None
    cxx_shim_destination: str | None = None
    cmake_build_dir: str | None = None
    container_command: tuple[str, ...] = ()


@dataclass(frozen=True)
class ReplayResult:
    version: str
    phase: str
    status: str
    exit_code: int | None
    duration_seconds: float
    container_id: str | None
    input_digest: str
    stdout: bytes
    stderr: bytes
    signature: ASanSignature | None
    timed_out: bool
    quota_hit: bool
    log_truncated: bool
    metadata: dict[str, Any]
    capture_error: str | None = None
    truncated_roles: tuple[str, ...] = ()

    def as_dict(self) -> dict[str, Any]:
        # Raw stdout/stderr are evidence files, not metadata. Keeping the full
        # text here would copy every log into the report, execution metadata and
        # the database attempt row. Record only stable digests, lengths and a
        # bounded preview; readers reconstruct observations from the files.
        payload = {
            "version": self.version,
            "phase": self.phase,
            "status": self.status,
            "exit_code": self.exit_code,
            "duration_seconds": self.duration_seconds,
            "container_id": self.container_id,
            "input_digest": self.input_digest,
            "stdout_sha256": "sha256:" + hashlib.sha256(self.stdout).hexdigest(),
            "stdout_bytes": len(self.stdout),
            "stdout_preview": self.stdout[:MAX_PREVIEW_BYTES].decode(
                "utf-8", "replace"
            ),
            "stderr_sha256": "sha256:" + hashlib.sha256(self.stderr).hexdigest(),
            "stderr_bytes": len(self.stderr),
            "stderr_preview": self.stderr[:MAX_PREVIEW_BYTES].decode(
                "utf-8", "replace"
            ),
            "signature": self.signature.as_dict() if self.signature else None,
            "timed_out": self.timed_out,
            "quota_hit": self.quota_hit,
            "log_truncated": self.log_truncated,
            "truncated_roles": list(self.truncated_roles),
            "capture_error": self.capture_error,
            **self.metadata,
        }
        payload["capture_error"] = self.capture_error
        payload["truncated_roles"] = list(self.truncated_roles)
        return payload


FUZZ_MAX_CRASH_FILES = 8
FUZZ_MAX_CRASH_BYTES = 8 * MIB
FUZZ_MAX_CORPUS_FILES = 4096
FUZZ_STARTUP_GRACE_SECONDS = 30.0
FUZZER_CONTAINER_PATH = "/artifact/fuzzer"
CORPUS_CONTAINER_PATH = "/corpus"
_FUZZ_RESULT = re.compile(rb"DATACON_FUZZ_RESULT code=(-?\d+) crashes=(\d+)")


@dataclass(frozen=True)
class FuzzResult:
    """One bounded libFuzzer search in a one-shot container (never a verdict)."""

    status: str
    exit_code: int | None
    duration_seconds: float
    container_id: str | None
    rng_seed: int
    max_total_time_seconds: int
    log: bytes
    log_truncated: bool
    crashes: tuple[bytes, ...]
    crash_truncated: bool
    metadata: dict[str, Any]
    capture_error: str | None = None

    def as_dict(self) -> dict[str, Any]:
        # The raw log and crash bytes are evidence files; the journal and the
        # attempt row only carry digests, sizes and counts.
        return {
            "status": self.status,
            "exit_code": self.exit_code,
            "duration_seconds": self.duration_seconds,
            "container_id": self.container_id,
            "rng_seed": self.rng_seed,
            "max_total_time_seconds": self.max_total_time_seconds,
            "log_sha256": "sha256:" + hashlib.sha256(self.log).hexdigest(),
            "log_bytes": len(self.log),
            "log_truncated": self.log_truncated,
            "crash_count": len(self.crashes),
            "crash_truncated": self.crash_truncated,
            "capture_error": self.capture_error,
            "metadata": dict(self.metadata),
        }


def render_fuzz_runner_script() -> str:
    """The fixed fuzz container template; every operand is a positional argument.

    The fuzzer writes new inputs only to ``/work/new`` (bounded tmpfs) and crash
    artifacts only to ``/work/crashes``; the seed corpus is a read-only bind
    mount at ``/corpus``. At most ``$6`` regular crash files are moved to
    ``/work/crash-N`` for the host copy, then the container waits for release.
    """
    return "\n".join(
        [
            "set -u",
            '_seed=$1; _time=$2; _len=$3; _rss=$4; _timeout=$5; _max=$6',
            "mkdir /work/new /work/crashes || exit 1",
            f'{FUZZER_CONTAINER_PATH} -seed="$_seed" -max_total_time="$_time" '
            '-max_len="$_len" -rss_limit_mb="$_rss" -timeout="$_timeout" '
            "-print_final_stats=1 -artifact_prefix=/work/crashes/ "
            f"/work/new {CORPUS_CONTAINER_PATH}",
            "_code=$?",
            "_i=0",
            "for _f in /work/crashes/crash-*; do",
            '  [ "$_i" -lt "$_max" ] || break',
            '  if [ -f "$_f" ] && [ ! -L "$_f" ]; then',
            '    mv -- "$_f" "/work/crash-$_i" && _i=$((_i + 1))',
            "  fi",
            "done",
            r"printf '\nDATACON_FUZZ_RESULT code=%s crashes=%s\n' "
            '"$_code" "$_i" >&2',
            "cat /sys/fs/cgroup/pids.events > /work/pids.events 2>/dev/null || true",
            "cat /sys/fs/cgroup/memory.events > /work/memory.events 2>/dev/null || true",
            "touch /work/done",
            "while [ ! -e /work/release ]; do sleep 0.1; done",
            "exit 0",
        ]
    ) + "\n"


def fuzz_runner_command(
    *,
    rng_seed: int,
    max_total_time: int,
    max_len: int,
    rss_limit_mb: int,
    input_timeout_seconds: int,
    max_crashes: int = FUZZ_MAX_CRASH_FILES,
) -> list[str]:
    """Return the exact argv of the fuzz container (no shell splicing)."""
    for label, value, minimum in (
        ("rng_seed", rng_seed, 1),
        ("max_total_time", max_total_time, 1),
        ("max_len", max_len, 1),
        ("rss_limit_mb", rss_limit_mb, 1),
        ("input_timeout_seconds", input_timeout_seconds, 1),
        ("max_crashes", max_crashes, 1),
    ):
        if type(value) is not int or value < minimum:
            raise SandboxPolicyError(f"fuzz {label} must be an integer >= {minimum}")
    return [
        "/bin/sh",
        "-c",
        render_fuzz_runner_script(),
        "datacon-fuzz-runner",
        str(rng_seed),
        str(max_total_time),
        str(max_len),
        str(rss_limit_mb),
        str(input_timeout_seconds),
        str(max_crashes),
    ]


def validate_fuzz_corpus_dir(corpus_dir: Path | str) -> list[Path]:
    """The corpus mount is a flat directory of regular, read-only files only."""
    directory = Path(corpus_dir)
    if directory.is_symlink() or not directory.is_dir():
        raise SandboxPolicyError("fuzz corpus must be a real directory")
    files: list[Path] = []
    for child in sorted(directory.iterdir()):
        info = child.lstat()
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
            raise SandboxPolicyError(
                f"fuzz corpus may only contain regular files: {child.name}"
            )
        if info.st_mode & 0o222:
            raise SandboxPolicyError(
                f"fuzz corpus file must be read-only: {child.name}"
            )
        files.append(child)
    if not files:
        raise SandboxPolicyError("fuzz corpus is empty")
    if len(files) > FUZZ_MAX_CORPUS_FILES:
        raise SandboxPolicyError("fuzz corpus has too many files")
    if directory.stat().st_mode & 0o222 & ~0o200:
        raise SandboxPolicyError("fuzz corpus directory must not be group/other writable")
    return files


def _absolute_mount(source: str | os.PathLike[str]) -> str:
    path = Path(source)
    if not path.is_absolute():
        raise SandboxPolicyError("bind mount sources must be absolute")
    if path.is_symlink():
        raise SandboxPolicyError("bind mount sources must not be symlinks")
    try:
        resolved = path.resolve(strict=True)
    except OSError as error:
        raise SandboxPolicyError(f"bind mount source is not readable: {error}") from error
    return str(resolved)


def _mount_option(source: str, destination: str, readonly: bool) -> str:
    if not destination.startswith("/") or ".." in Path(destination).parts:
        raise SandboxPolicyError(f"invalid mount destination: {destination}")
    resolved = _absolute_mount(source)
    if not Path(resolved).exists():
        raise SandboxPolicyError(f"mount source does not exist: {source}")
    option = f"type=bind,src={resolved},dst={destination}"
    if readonly:
        option += ",readonly"
    return option


def _scratch_sizes(scratch_mib: int) -> tuple[int, int]:
    tmp_mib = min(64, max(16, scratch_mib // 8))
    work_mib = scratch_mib - tmp_mib
    if work_mib < 16:
        raise SandboxPolicyError("scratch budget is too small for work and tmp")
    return work_mib, tmp_mib


def container_create_args(
    *,
    image: str,
    platform: str,
    policy: IsolationPolicy,
    limits: ResourceLimits,
    name: str,
    command: Sequence[str],
    mounts: Sequence[tuple[str, str, bool]],
    env: Mapping[str, str] | None = None,
    labels: Mapping[str, str] | None = None,
    docker: str = "docker",
    job_id: str | None = None,
    generation: int | None = None,
) -> list[str]:
    """Return the exact ``docker create`` argument vector."""
    policy.validate()
    limits.validate()
    if not isinstance(image, str) or "@" not in image:
        raise SandboxPolicyError("the toolchain image must be pinned by digest")
    tag, _, digest = image.partition("@")
    if not tag or not _IMAGE_DIGEST.fullmatch(digest):
        raise SandboxPolicyError("the toolchain image digest is invalid")
    if platform != "linux/amd64":
        raise SandboxPolicyError("the MVP sandbox platform is linux/amd64")
    if not isinstance(name, str) or not re.fullmatch(r"[a-z0-9][a-z0-9_.-]{0,62}", name):
        raise SandboxPolicyError("container name is invalid")
    if not command or any(not isinstance(item, str) for item in command):
        raise SandboxPolicyError("container command is invalid")

    work_mib, tmp_mib = _scratch_sizes(limits.scratch_mib)
    args = [
        docker,
        "create",
        "--name",
        name,
        "--platform",
        platform,
        "--pull",
        "never",
        "--network",
        "none",
        "--user",
        policy.user,
        "--read-only",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges",
        "--security-opt",
        f"seccomp={SECCOMP_PROFILE_PATH}",
        "--pids-limit",
        str(limits.pids),
        "--memory",
        f"{limits.memory_mib}m",
        "--memory-swap",
        f"{limits.memory_mib}m",
        "--cpus",
        str(limits.cpu),
        "--ipc",
        "private",
        # No Docker log driver. Output is captured live from an attach started
        # before the container runs; there is no host log file to read and no
        # rotation window that could silently drop evidence.
        "--log-driver",
        "none",
        "--tmpfs",
        f"/work:rw,exec,size={work_mib}m,mode=1777",
        "--tmpfs",
        f"/tmp:rw,exec,size={tmp_mib}m,mode=1777",
        "-w",
        "/work",
    ]
    if limits.scratch_mib > 0:
        pass
    for key, value in sorted((env or {}).items()):
        if (
            key.upper().startswith(("GITHUB_", "AWS_", "TOKEN", "SECRET"))
            or (
                key.upper().startswith("DATACON_")
                and key.upper() != "DATACON_BUILD_VERSION"
            )
        ):
            raise SandboxPolicyError(f"credential-like environment variable is not allowed: {key}")
        if not key or any(character in key for character in " =\x00"):
            raise SandboxPolicyError("container environment key is invalid")
        if any(character in value for character in "\x00"):
            raise SandboxPolicyError("container environment value is invalid")
        args.extend(["-e", f"{key}={value}"])
    for source, destination, readonly in mounts:
        args.extend(["--mount", _mount_option(source, destination, readonly)])
    if job_id:
        labels = {**(labels or {}), "datacon.job_id": job_id}
    if generation is not None:
        if type(generation) is not int or generation < 0:
            raise SandboxPolicyError("container generation must be a non-negative integer")
        labels = {**(labels or {}), "datacon.generation": str(generation)}
    for key, value in sorted((labels or {}).items()):
        args.extend(["--label", f"{key}={value}"])
    args.extend([image, *command])
    return args


def _close_enough(actual: Any, expected: int) -> bool:
    return type(actual) is int and actual == expected


def _validate_security_options(
    config: Mapping[str, Any], policy: IsolationPolicy
) -> None:
    """Accept exactly one no-new-privileges flag and one pinned seccomp profile.

    An allowlist, not a denylist: Docker's inspect output may contain options
    such as ``no-new-privileges:false`` or ``apparmor=unconfined`` that a
    ``startswith`` check would happily accept. Anything beyond the exact
    approved pair is a policy failure.
    """
    security = [str(item) for item in config.get("SecurityOpt") or []]
    no_new_privileges = [
        item
        for item in security
        if item.lower()
        in ("no-new-privileges", "no-new-privileges:true", "no-new-privileges=true")
    ]
    if len(no_new_privileges) != 1:
        raise SandboxPolicyError(
            "exactly one effective no-new-privileges option is required"
        )
    seccomp_options = [
        item for item in security if item.lower().startswith("seccomp=")
    ]
    if len(seccomp_options) != 1:
        raise SandboxPolicyError("exactly one explicit seccomp profile is required")
    if len(security) != 2:
        raise SandboxPolicyError(
            "container has unapproved security options: "
            + ", ".join(security)
        )
    value = seccomp_options[0].split("=", 1)[1]
    if value.strip().lower() in ("", "unconfined", "default", "runtime/default", "docker/default"):
        raise SandboxPolicyError(
            "seccomp must use an explicit, digest-pinned profile"
        )
    try:
        document = json.loads(value)
    except (TypeError, ValueError) as error:
        raise SandboxPolicyError(
            "the running seccomp profile is not inspectable"
        ) from error
    if not isinstance(document, dict):
        raise SandboxPolicyError("the running seccomp profile is not an object")
    if _canonical_json_digest(document) != policy.seccomp_profile_digest:
        raise SandboxPolicyError(
            "the running seccomp profile does not match the approved digest"
        )


def _validate_mounts(
    config: Mapping[str, Any],
    mounts: Sequence[tuple[str, str, bool]],
) -> None:
    declared: dict[str, tuple[str, bool]] = {}
    for source, destination, readonly in mounts:
        if not destination.startswith("/") or ".." in Path(destination).parts:
            raise SandboxPolicyError(f"invalid declared mount destination: {destination}")
        if destination in declared:
            raise SandboxPolicyError(f"duplicate declared mount destination: {destination}")
        try:
            resolved = str(Path(source).resolve(strict=True))
        except OSError as error:
            raise SandboxPolicyError(
                f"declared mount source is not readable: {error}"
            ) from error
        declared[destination] = (resolved, bool(readonly))

    actual: list[tuple[str, str, bool]] = []
    inspected = config.get("Mounts")
    if isinstance(inspected, list) and inspected:
        for mount in inspected:
            if not isinstance(mount, Mapping):
                raise SandboxPolicyError("container mount metadata is invalid")
            if mount.get("Type") != "bind":
                raise SandboxPolicyError("only read-only bind mounts are allowed")
            destination = mount.get("Destination")
            source = mount.get("Source")
            if not isinstance(destination, str) or not isinstance(source, str):
                raise SandboxPolicyError("container mount metadata is incomplete")
            if not Path(source).is_absolute():
                raise SandboxPolicyError("a bind mount source is not absolute")
            actual.append((source, destination, mount.get("RW") is False))
    else:
        binds = config.get("Binds") or []
        if not isinstance(binds, list):
            raise SandboxPolicyError("container bind metadata is invalid")
        for bind in binds:
            parts = str(bind).split(":")
            if len(parts) < 3 or parts[2] not in ("ro", "readonly"):
                raise SandboxPolicyError("a bind mount is writable")
            bind_source = Path(parts[0])
            if not bind_source.is_absolute():
                raise SandboxPolicyError("a bind mount source is not absolute")
            actual.append((str(bind_source), parts[1], True))

    seen: set[str] = set()
    for source, destination, readonly in actual:
        if destination in seen:
            raise SandboxPolicyError(f"duplicate container mount: {destination}")
        seen.add(destination)
        allowed = declared.get(destination)
        if allowed is None:
            raise SandboxPolicyError(
                f"container has an undeclared bind mount destination: {destination}"
            )
        allowed_source, allowed_readonly = allowed
        if not readonly or not allowed_readonly:
            raise SandboxPolicyError(f"bind mount {destination} is writable")
        try:
            resolved_source = str(Path(source).resolve(strict=True))
        except OSError as error:
            raise SandboxPolicyError(
                f"container mount source is not readable: {error}"
            ) from error
        if resolved_source != allowed_source:
            raise SandboxPolicyError(
                f"bind mount source for {destination} is not the declared source"
            )
    if seen != set(declared):
        missing = sorted(set(declared) - seen)
        raise SandboxPolicyError(
            "expected read-only bind mounts are missing: " + ", ".join(missing)
        )


def validate_host_config(
    config: Mapping[str, Any],
    policy: IsolationPolicy,
    limits: ResourceLimits,
    *,
    mounts: Sequence[tuple[str, str, bool]] = (),
) -> None:
    """Fail closed unless inspect output shows every requested control.

    ``mounts`` is the exact list given to ``docker create``. Inspect output may
    not add any other bind mount, even a read-only one.
    """
    policy.validate()
    limits.validate()
    if config.get("NetworkMode") != "none":
        raise SandboxPolicyError("container network mode is not none")
    if config.get("User") != policy.user:
        raise SandboxPolicyError("container user differs from the plan")
    if config.get("ReadonlyRootfs") is not True:
        raise SandboxPolicyError("container root filesystem is writable")
    cap_drop = {str(item).upper() for item in config.get("CapDrop") or []}
    if "ALL" not in cap_drop:
        raise SandboxPolicyError("container did not drop ALL capabilities")
    if config.get("CapAdd"):
        raise SandboxPolicyError("container added capabilities")
    _validate_security_options(config, policy)
    if config.get("Privileged") is True:
        raise SandboxPolicyError("container is privileged")
    if not _close_enough(config.get("PidsLimit"), limits.pids):
        raise SandboxPolicyError("PID limit is not active")
    memory = limits.memory_mib * MIB
    if not _close_enough(config.get("Memory"), memory):
        raise SandboxPolicyError("memory limit is not active")
    if not _close_enough(config.get("MemorySwap"), memory):
        raise SandboxPolicyError("memory+swap limit is not active")
    nano = config.get("NanoCpus")
    quota = config.get("CpuQuota")
    period = config.get("CpuPeriod")
    cpu_ok = _close_enough(nano, limits.cpu * 1_000_000_000)
    if not cpu_ok and period:
        cpu_ok = quota == limits.cpu * period
    if not cpu_ok:
        raise SandboxPolicyError("CPU limit is not active")
    if config.get("Devices"):
        raise SandboxPolicyError("container has host devices")
    if config.get("IpcMode") not in (None, "private"):
        raise SandboxPolicyError("container IPC namespace is not private")
    for namespace in ("PidMode", "UTSMode", "UsernsMode"):
        if config.get(namespace) not in (None, "", "private"):
            raise SandboxPolicyError(
                f"container {namespace} must be private, not {config.get(namespace)!r}"
            )
    if config.get("CgroupnsMode") not in (None, "", "private"):
        raise SandboxPolicyError(
            "container cgroup namespace must be private, not "
            f"{config.get('CgroupnsMode')!r}"
        )
    if config.get("Devices"):
        raise SandboxPolicyError("container has host devices")
    if config.get("DeviceRequests"):
        raise SandboxPolicyError("container has host device requests")
    log_config = config.get("LogConfig") or {}
    if not isinstance(log_config, Mapping):
        raise SandboxPolicyError("container log config is invalid")
    if log_config.get("Type") != "none":
        raise SandboxPolicyError(
            "container log driver must be none; output is captured by attach"
        )
    log_options = log_config.get("Config") or {}
    if not isinstance(log_options, Mapping):
        raise SandboxPolicyError("container log options are invalid")
    if log_options:
        raise SandboxPolicyError("container log driver none takes no log options")

    _validate_mounts(config, mounts)

    tmpfs = config.get("Tmpfs") or {}
    if not isinstance(tmpfs, dict) or "/work" not in tmpfs or "/tmp" not in tmpfs:
        raise SandboxPolicyError("bounded writable workspaces are missing")
    total = 0
    for target, options in tmpfs.items():
        match = re.search(r"(?:^|,)size=([0-9]+)m(?:,|$)", str(options))
        if match is None:
            raise SandboxPolicyError(f"{target} has no bounded size")
        total += int(match.group(1))
    if total > limits.scratch_mib:
        raise SandboxPolicyError("writable workspace exceeds the scratch budget")


def _run_bytes(
    args: Sequence[str],
    *,
    timeout: float,
    input_bytes: bytes | None = None,
) -> subprocess.CompletedProcess:
    try:
        return subprocess.run(
            list(args),
            input=input_bytes,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
            check=False,
        )
    except FileNotFoundError as error:
        raise SandboxUnavailable("docker CLI is not available") from error
    except PermissionError as error:
        raise SandboxUnavailable("docker CLI is not executable") from error
    except subprocess.TimeoutExpired as error:
        raise SandboxError(
            "docker command timed out", reason_code="TIMEOUT"
        ) from error


def _truncate_log(data: bytes) -> tuple[bytes, bool]:
    if len(data) <= MAX_LOG_BYTES:
        return data, False
    return data[:MAX_LOG_BYTES], True


class _UnionCapture:
    """Collect stdout/stderr under one shared byte budget.

    Both streams are read concurrently by their own threads. The first
    ``MAX_LOG_BYTES`` bytes across *both* streams are retained; a chunk that
    does not fit is truncated record-wise and the owning role is marked in
    ``truncated_roles``. Once the budget is exhausted the readers keep draining
    their pipes so the target is never blocked by a full pipe, but the extra
    bytes are discarded. Allocation and read failures are recorded instead of
    being mistaken for a clean, complete capture.
    """

    def __init__(self, budget: int = MAX_LOG_BYTES):
        if type(budget) is not int or budget <= 0:
            raise ValueError("capture budget must be a positive integer")
        self._budget = budget
        self._remaining = budget
        self._lock = threading.Lock()
        self._chunks: dict[str, list[bytes]] = {role: [] for role in STREAM_ROLES}
        self.truncated_roles: set[str] = set()
        self.errors: list[str] = []

    def consume(self, role: str, chunk: bytes) -> None:
        if role not in STREAM_ROLES:
            raise ValueError(f"unknown capture role: {role}")
        if not chunk:
            return
        with self._lock:
            if self._remaining > 0:
                take = min(len(chunk), self._remaining)
                self._chunks[role].append(chunk[:take])
                self._remaining -= take
                if take == len(chunk):
                    return
            self.truncated_roles.add(role)

    def record_error(self, message: str) -> None:
        with self._lock:
            self.errors.append(message)

    def data(self, role: str) -> bytes:
        with self._lock:
            return b"".join(self._chunks[role])

    def snapshot(self) -> tuple[bytes, bytes, tuple[str, ...], tuple[str, ...]]:
        with self._lock:
            stdout = b"".join(self._chunks["stdout"])
            stderr = b"".join(self._chunks["stderr"])
            roles = tuple(sorted(self.truncated_roles))
            errors = tuple(self.errors)
        return stdout, stderr, roles, errors


def _drain_stream(role: str, stream: Any, capture: _UnionCapture) -> None:
    """Read one attach pipe until EOF, never blocking the sibling stream."""
    try:
        fd = stream.fileno()
    except (AttributeError, OSError, ValueError):
        fd = None
    try:
        while True:
            if fd is not None:
                chunk = os.read(fd, CAPTURE_CHUNK_BYTES)
            else:
                chunk = stream.read(CAPTURE_CHUNK_BYTES)
            if not chunk:
                break
            capture.consume(role, chunk)
    except (AttributeError, OSError, ValueError) as error:
        capture.record_error(f"{role} capture failed: {error}")
    finally:
        try:
            stream.close()
        except (AttributeError, OSError, ValueError):
            pass



def _read_bounded_file(
    path: Path, *, max_bytes: int, label: str, reason_code: str
) -> bytes:
    """Read an untrusted input through the shared bounded, no-follow reader.

    The material, artifact and input paths can be replaced by a symlink, a FIFO
    or an oversized file. ``read_regular_file_bounded`` rejects all three
    before the payload is buffered; map its failure to the existing sandbox
    reason codes instead of letting a raw OSError or MemoryError escape.
    """
    try:
        return fileio.read_regular_file_bounded(path, max_bytes=max_bytes)
    except fileio.UnsafeFileError as error:
        raise SandboxError(f"{label}: {error.message}", reason_code=reason_code) from error


def _extract_compile_args(recipe: bytes) -> tuple[str, ...]:
    """Extract the fixed compiler arguments from the reviewed build recipe."""
    try:
        text = recipe.decode("utf-8")
    except UnicodeError:
        return ()
    text = text.replace("\\\n", " ")
    for line in text.splitlines():
        stripped = line.strip()
        if "clang" not in stripped or stripped.startswith("#"):
            continue
        try:
            tokens = shlex.split(stripped)
        except ValueError:
            continue
        try:
            index = tokens.index("clang")
        except ValueError:
            continue
        return tuple(
            token
            for token in tokens[index + 1 :]
            if token.startswith("-")
        )
    return ()


def _validate_work_container_path(path: str, *, label: str) -> str:
    if (
        not isinstance(path, str)
        or not path.startswith("/work/")
        or any(character in path for character in _UNSAFE_WORK_PATH_CHARS)
        or ".." in PurePosixPath(path).parts
    ):
        raise SandboxPolicyError(f"unsafe {label}: {path!r}")
    normalized = posixpath.normpath(path)
    if not normalized.startswith("/work/"):
        raise SandboxPolicyError(f"unsafe {label}: {path!r}")
    return normalized


def _validate_build_spec_output(raw_output: str, index: int) -> tuple[str, str]:
    try:
        return build_provenance.validate_build_spec_output_path(raw_output, index)
    except ValueError as error:
        raise SandboxError(
            str(error), reason_code=build_provenance.BUILD_PROVENANCE_MISSING
        ) from error


def _select_primary_output(outputs: Sequence[str]) -> str:
    if "parser" in outputs:
        return "parser"
    for item in outputs:
        if PurePosixPath(item).name == "parser":
            return item
    return outputs[0]


def _validate_shim_destination(
    destination: Any,
    *,
    allowed_basenames: Sequence[str] | frozenset[str],
    label: str,
) -> str:
    if not build_provenance.is_controlled_shim_path(
        destination, allowed_basenames=allowed_basenames
    ):
        raise SandboxError(
            f"unsafe {label} mount destination: {destination!r}",
            reason_code=build_provenance.BUILD_PROVENANCE_MISSING,
        )
    return posixpath.normpath(str(destination))


def _ensure_safe_dir_component(
    parent_fd: int,
    name: str,
    *,
    mode: int,
    exclusive: bool,
    label: str,
) -> int:
    dir_flags = (
        os.O_RDONLY
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    if exclusive:
        try:
            os.mkdir(name, mode, dir_fd=parent_fd)
        except FileExistsError as error:
            raise SandboxPolicyError(
                f"the one-shot {label} directory already exists"
            ) from error
        except OSError as error:
            raise SandboxPolicyError(
                f"cannot create {label} directory safely: {error}"
            ) from error
        try:
            fd = os.open(name, dir_flags, dir_fd=parent_fd)
        except OSError as error:
            raise SandboxPolicyError(
                f"cannot open {label} directory without following a symlink: {error}"
            ) from error
    else:
        try:
            fd = os.open(name, dir_flags, dir_fd=parent_fd)
        except FileNotFoundError:
            try:
                os.mkdir(name, mode, dir_fd=parent_fd)
            except FileExistsError:
                pass
            except OSError as error:
                raise SandboxPolicyError(
                    f"cannot create {label} directory safely: {error}"
                ) from error
            try:
                fd = os.open(name, dir_flags, dir_fd=parent_fd)
            except OSError as error:
                raise SandboxPolicyError(
                    f"cannot open {label} directory without following a symlink: {error}"
                ) from error
        except OSError as error:
            raise SandboxPolicyError(
                f"cannot open {label} directory without following a symlink: {error}"
            ) from error
    try:
        info = os.fstat(fd)
        if not stat.S_ISDIR(info.st_mode):
            raise SandboxPolicyError(f"{label} is not a real directory")
    except BaseException:
        os.close(fd)
        raise
    return fd


def _create_safe_build_work_dir(
    run_root: Path, version: str
) -> tuple[int, Path, str, tuple[int, int]]:
    """Create a one-shot build staging dir under ``run_root`` without following symlinks."""
    try:
        root_lstat = os.lstat(run_root)
    except FileNotFoundError:
        try:
            run_root.mkdir(mode=0o700, parents=True, exist_ok=True)
        except OSError as error:
            raise SandboxPolicyError(
                f"sandbox run_root cannot be created safely: {error}"
            ) from error
    except OSError as error:
        raise SandboxPolicyError(
            f"sandbox run_root cannot be inspected: {error}"
        ) from error
    else:
        if stat.S_ISLNK(root_lstat.st_mode) or not stat.S_ISDIR(root_lstat.st_mode):
            raise SandboxPolicyError(
                "sandbox run_root must be a real directory, not a symlink"
            )

    dir_flags = (
        os.O_RDONLY
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    try:
        root_fd = os.open(run_root, dir_flags)
    except OSError as error:
        raise SandboxPolicyError(
            f"sandbox run_root cannot be opened without following a symlink: {error}"
        ) from error

    build_fd: int | None = None
    version_fd: int | None = None
    work_fd: int | None = None
    try:
        build_fd = _ensure_safe_dir_component(
            root_fd, "build", mode=0o755, exclusive=False, label="build root"
        )
        version_fd = _ensure_safe_dir_component(
            build_fd,
            version,
            mode=0o755,
            exclusive=False,
            label=f"build/{version}",
        )
        leaf = uuid.uuid4().hex
        work_fd = _ensure_safe_dir_component(
            version_fd,
            leaf,
            mode=0o755,
            exclusive=True,
            label="build work",
        )
        os.fchmod(work_fd, 0o755)
        work = run_root / "build" / version / leaf
        by_fd = os.fstat(work_fd)
        by_path = os.lstat(work)
        if stat.S_ISLNK(by_path.st_mode) or not stat.S_ISDIR(by_path.st_mode):
            raise SandboxPolicyError("build work directory is not a real directory")
        if (by_fd.st_dev, by_fd.st_ino) != (by_path.st_dev, by_path.st_ino):
            raise SandboxPolicyError(
                "build work directory identity changed after creation"
            )
        result_fd = work_fd
        work_fd = None
        return result_fd, work, leaf, (by_fd.st_dev, by_fd.st_ino)
    except SandboxPolicyError:
        raise
    except OSError as error:
        raise SandboxPolicyError(
            f"cannot prepare build work directory safely: {error}"
        ) from error
    finally:
        if work_fd is not None:
            os.close(work_fd)
        if version_fd is not None:
            os.close(version_fd)
        if build_fd is not None:
            os.close(build_fd)
        os.close(root_fd)


def _verify_bound_shim_file(
    work_fd: int, work: Path, shim_name: str, *, label: str
) -> Path:
    shim_path = work / shim_name
    try:
        by_dir_fd = os.lstat(shim_name, dir_fd=work_fd)
        by_path = os.lstat(shim_path)
    except OSError as error:
        raise SandboxPolicyError(
            f"cannot verify {label} before mounting: {error}"
        ) from error
    if (
        stat.S_ISLNK(by_dir_fd.st_mode)
        or not stat.S_ISREG(by_dir_fd.st_mode)
        or stat.S_ISLNK(by_path.st_mode)
        or not stat.S_ISREG(by_path.st_mode)
        or (by_dir_fd.st_dev, by_dir_fd.st_ino) != (by_path.st_dev, by_path.st_ino)
    ):
        raise SandboxPolicyError(
            f"{label} failed symlink/inode boundary verification before mounting"
        )
    return shim_path


def _cleanup_safe_build_work_dir(
    run_root: Path,
    version: str,
    leaf: str,
    work_identity: tuple[int, int],
    shim_names: Sequence[str],
) -> None:
    """Remove staged shim files and the per-build temp dir without following symlinks."""
    dir_flags = (
        os.O_RDONLY
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    root_fd: int | None = None
    build_fd: int | None = None
    version_fd: int | None = None
    work_fd: int | None = None
    try:
        root_fd = os.open(run_root, dir_flags)
        build_fd = os.open("build", dir_flags, dir_fd=root_fd)
        version_fd = os.open(version, dir_flags, dir_fd=build_fd)
        work_fd = os.open(leaf, dir_flags, dir_fd=version_fd)
        info = os.fstat(work_fd)
        if (info.st_dev, info.st_ino) != work_identity:
            return
        for shim_name in shim_names:
            try:
                os.unlink(shim_name, dir_fd=work_fd)
            except OSError:
                pass
        os.close(work_fd)
        work_fd = None
        try:
            os.rmdir(leaf, dir_fd=version_fd)
        except OSError:
            pass
    except OSError:
        pass
    finally:
        if work_fd is not None:
            os.close(work_fd)
        if version_fd is not None:
            os.close(version_fd)
        if build_fd is not None:
            os.close(build_fd)
        if root_fd is not None:
            os.close(root_fd)


def render_cc_shim_script(
    *,
    real_compiler: str = DEFAULT_CC_SHIM_COMPILER,
    log_path: str = DEFAULT_CC_SHIM_LOG_PATH,
) -> str:
    """Render a POSIX ``/bin/sh`` + ``awk`` cc-shim wrapper script.

    Each invocation writes one strict JSONL line
    ``{"cwd": ..., "compiler": ..., "argv": [...]}`` to a private fragment
    below ``${log_path}.d`` with full RFC 8259 string escaping (quotes,
    backslashes, control characters, spaces). No two shim processes ever share
    a writable file or lock: the build runner later merges the completed
    fragments into the fixed ``log_path`` as a single writer
    (``render_cc_shim_merge_script``). This removes the 8 KiB stdio append
    interleaving window instead of trying to make it rarer.

    A fragment is emitted to a ``mktemp`` file and atomically renamed only
    after the full JSON line is flushed, so a killed shim never leaves a
    partial line for the merger. Then the real compiler is ``exec``-ed with
    exact verbatim ``"$@"`` and its exit code.
    """
    if (
        not isinstance(real_compiler, str)
        or not real_compiler.strip()
        or build_provenance.has_control_chars(real_compiler)
    ):
        raise SandboxPolicyError("real_compiler must be a non-empty string without control chars")
    if (
        not isinstance(log_path, str)
        or not log_path.strip()
        or build_provenance.has_control_chars(log_path)
    ):
        raise SandboxPolicyError("log_path must be a non-empty string without control chars")

    quoted_compiler = shlex.quote(real_compiler)
    quoted_log_path = shlex.quote(log_path)
    awk_program = (
        "function emit_json_str(s,    i, n, ch) {\n"
        '  printf "%s", "\\""\n'
        "  n = length(s)\n"
        "  for (i = 1; i <= n; i++) {\n"
        "    ch = substr(s, i, 1)\n"
        '    if (ch == "\\\\") printf "%s", "\\\\\\\\"\n'
        '    else if (ch == "\\"") printf "%s", "\\\\\\""\n'
        '    else if (ch == "\\b") printf "%s", "\\\\b"\n'
        '    else if (ch == "\\f") printf "%s", "\\\\f"\n'
        '    else if (ch == "\\n") printf "%s", "\\\\n"\n'
        '    else if (ch == "\\r") printf "%s", "\\\\r"\n'
        '    else if (ch == "\\t") printf "%s", "\\\\t"\n'
        '    else if (ch in ctrl) printf "%s", ctrl[ch]\n'
        '    else printf "%s", ch\n'
        "  }\n"
        '  printf "%s", "\\""\n'
        "}\n"
        "BEGIN {\n"
        "  for (c = 1; c < 32; c++) {\n"
        '    ctrl[sprintf("%c", c)] = sprintf("\\\\u%04x", c)\n'
        "  }\n"
        '  printf "%s", "{\\"cwd\\":"\n'
        "  emit_json_str(ARGV[1])\n"
        '  printf "%s", ",\\"compiler\\":"\n'
        "  emit_json_str(ARGV[2])\n"
        '  printf "%s", ",\\"argv\\":["\n'
        "  emit_json_str(ARGV[2])\n"
        "  for (i = 3; i < ARGC; i++) {\n"
        '    printf "%s", ","\n'
        "    emit_json_str(ARGV[i])\n"
        "  }\n"
        '  printf "]}\\n"\n'
        "  exit 0\n"
        "}\n"
    )
    return (
        "#!/bin/sh\n"
        "set -e\n"
        f'PATH="{_SAFE_SYSTEM_PATH}${{PATH:+:$PATH}}"\n'
        "export PATH\n"
        f"_datacon_real_compiler={quoted_compiler}\n"
        f"_datacon_log_path={quoted_log_path}\n"
        '_datacon_log_dir="${_datacon_log_path}.d"\n'
        '_datacon_tmp=""\n'
        "_datacon_cleanup_tmp() {\n"
        '  if [ -n "$_datacon_tmp" ]; then rm -f -- "$_datacon_tmp"; fi\n'
        "}\n"
        "trap '_datacon_cleanup_tmp; exit 130' INT\n"
        "trap '_datacon_cleanup_tmp; exit 143' TERM\n"
        "trap '_datacon_cleanup_tmp; exit 129' HUP\n"
        "trap '_datacon_cleanup_tmp' EXIT\n"
        'if [ -L "$_datacon_log_path" ] || [ -L "$_datacon_log_dir" ]; then\n'
        "  exit 1\n"
        "fi\n"
        # Create the one fragment directory without following a planted
        # symlink. ``mkdir -p`` would traverse an existing symlink.
        'if ! mkdir -- "$_datacon_log_dir" 2>/dev/null; then\n'
        '  if [ -L "$_datacon_log_dir" ] || [ ! -d "$_datacon_log_dir" ]; then exit 1; fi\n'
        "fi\n"
        'if [ -L "$_datacon_log_path" ] || [ -L "$_datacon_log_dir" ]; then\n'
        "  exit 1\n"
        "fi\n"
        "_datacon_cwd=$(pwd -P)\n"
        "_datacon_emit_log() {\n"
        f"  LC_ALL=C awk -- '{awk_program}' "
        '"$_datacon_cwd" "$_datacon_real_compiler" "$@"\n'
        "}\n"
        '_datacon_tmp=$(mktemp "$_datacon_log_dir/.fragment.XXXXXX") || exit 1\n'
        '_datacon_emit_log "$@" > "$_datacon_tmp" || exit 1\n'
        '_datacon_suffix=${_datacon_tmp##*.}\n'
        '_datacon_fragment="$_datacon_log_dir/fragment-$$-$_datacon_suffix.jsonl"\n'
        'mv -- "$_datacon_tmp" "$_datacon_fragment" || exit 1\n'
        '_datacon_tmp=""\n'
        'trap - EXIT INT TERM HUP\n'
        'exec "$_datacon_real_compiler" "$@"\n'
    )


def _cc_shim_merge_shell_lines(log_expression: str) -> list[str]:
    """Return the single-writer fragment merge body used by sh and the runner."""
    return [
        # The runner enables ``set -f`` for its fixed argv vectors; the merger
        # runs in a subshell, so restore globbing only here to expand the
        # per-invocation fragment names.
        "set +f",
        "LC_ALL=C",
        "export LC_ALL",
        f"_datacon_log_path={log_expression}",
        '_datacon_log_dir="${_datacon_log_path}.d"',
        'if [ -L "$_datacon_log_path" ] || [ -L "$_datacon_log_dir" ]; then',
        "  exit 1",
        "fi",
        'if [ ! -d "$_datacon_log_dir" ]; then',
        "  exit 0",
        "fi",
        '_datacon_tmp="${_datacon_log_path}.merge.$$"',
        ': > "$_datacon_tmp" || exit 1',
        "_datacon_seen=0",
        'for _datacon_fragment in "$_datacon_log_dir"/fragment-*.jsonl; do',
        '  [ -f "$_datacon_fragment" ] || continue',
        '  if [ -L "$_datacon_fragment" ]; then exit 1; fi',
        '  cat -- "$_datacon_fragment" >> "$_datacon_tmp" || exit 1',
        "  _datacon_seen=$((_datacon_seen + 1))",
        "done",
        'if [ "$_datacon_seen" -gt 0 ]; then',
        '  if [ -L "$_datacon_log_path" ]; then exit 1; fi',
        '  mv -- "$_datacon_tmp" "$_datacon_log_path" || exit 1',
        "else",
        '  rm -f -- "$_datacon_tmp"',
        "fi",
        'for _datacon_fragment in "$_datacon_log_dir"/fragment-*.jsonl; do',
        '  [ -f "$_datacon_fragment" ] || continue',
        '  rm -f -- "$_datacon_fragment" || exit 1',
        "done",
        'rmdir -- "$_datacon_log_dir" 2>/dev/null || true',
        "exit 0",
    ]


def render_cc_shim_merge_script(log_path: str = DEFAULT_CC_SHIM_LOG_PATH) -> str:
    """Return the single-writer merger for completed cc-shim fragments.

    The build runner calls this after every build process has exited. It is the
    only writer of the fixed face path: fragments are sorted by name and
    concatenated into a temporary file that is atomically renamed, so a
    concurrent reader can never observe an interleaved line.
    """
    if (
        not isinstance(log_path, str)
        or not log_path.strip()
        or build_provenance.has_control_chars(log_path)
    ):
        raise SandboxPolicyError("log_path must be a non-empty string without control chars")
    return "\n".join(
        ["#!/bin/sh", "set -e", "LC_ALL=C", "export LC_ALL"]
        + _cc_shim_merge_shell_lines(shlex.quote(log_path))
    ) + "\n"

def merge_cc_shim_log(log_path: Path | str) -> Path:
    """Merge completed cc-shim fragments into ``log_path`` with one writer.

    Mirrors :func:`render_cc_shim_merge_script` for host-side tests and
    tooling. The log and fragment directory must not be symlinks; fragments
    are sorted by name so the merge order is deterministic. The merged bytes
    are written to an exclusive temporary file and atomically renamed, then
    the consumed fragments are removed. A missing fragment directory is a
    no-op (no log is created), which keeps "no compiler ran" observable as a
    missing provenance face.
    """
    log = Path(log_path)
    fragment_dir = log.with_name(log.name + ".d")
    if log.is_symlink() or fragment_dir.is_symlink():
        raise SandboxPolicyError("cc-shim log and fragment directory must not be symlinks")
    if not fragment_dir.is_dir():
        return log
    fragments: list[Path] = []
    for item in sorted(fragment_dir.iterdir()):
        if not (item.name.startswith("fragment-") and item.name.endswith(".jsonl")):
            continue
        if item.is_symlink():
            raise SandboxPolicyError(f"cc-shim fragment must not be a symlink: {item}")
        if item.is_file():
            fragments.append(item)
    payload = b"".join(item.read_bytes() for item in fragments)
    if not fragments:
        return log
    temporary = log.with_name(f".{log.name}.merge.{os.getpid()}.{uuid.uuid4().hex}")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(temporary, flags, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
    except BaseException:
        try:
            os.unlink(temporary)
        except OSError:
            pass
        raise
    os.replace(temporary, log)
    for item in fragments:
        item.unlink()
    try:
        fragment_dir.rmdir()
    except OSError:
        pass
    return log

def render_build_runner_script(
    *,
    stage_fixture: bool = True,
    emit_result_marker: bool = True,
    wait_for_release: bool = True,
    cc_shim_merge_log: str | None = None,
) -> str:
    """Return the fixed POSIX ``/bin/sh`` runner template for ``BuildSpec`` argv arrays.

    Zero user arguments are ever interpolated into this script: ``primary_output``,
    pre-build cleanup targets, and the length-prefixed ``configure`` / ``build`` /
    ``install`` argv vectors are passed exclusively via positional parameters
    (``$1..$N``) and dispatched in isolated subshells via ``(exec "$@")`` with
    ``set -f`` (no ``eval``, no shell word-splitting, no runner state mutation).
    """
    lines = [
        "set -f",
        "_datacon_out=$1",
        "shift",
        "",
        "_datacon_has_symlink_in_work() {",
        "  _p=$1",
        '  case "$_p" in',
        "    /work/*)",
        "      (",
        "        set -f",
        "        IFS=/",
        "        _cur=/work",
        "        for _seg in ${_p#/work/}; do",
        '          [ -n "$_seg" ] || continue',
        '          _cur="$_cur/$_seg"',
        '          if [ -L "$_cur" ]; then',
        "            exit 0",
        "          fi",
        "        done",
        "        exit 1",
        "      )",
        "      ;;",
        "    *)",
        '      [ -L "$_p" ]',
        "      ;;",
        "  esac",
        "}",
        "",
        "_datacon_clean_path() {",
        "  _p=$1",
        '  case "$_p" in',
        "    /work/*)",
        "      (",
        "        set -f",
        "        IFS=/",
        "        _cur=/work",
        "        for _seg in ${_p#/work/}; do",
        '          [ -n "$_seg" ] || continue',
        '          _cur="$_cur/$_seg"',
        '          if [ -L "$_cur" ]; then',
        '            rm -f -- "$_cur" 2>/dev/null || true',
        "            exit 0",
        "          fi",
        "        done",
        '        rm -f -- "$_p" 2>/dev/null || true',
        '        rmdir -- "$_p" 2>/dev/null || true',
        "      )",
        "      ;;",
        "    *)",
        '      rm -f -- "$_p" 2>/dev/null || true',
        "      ;;",
        "  esac",
        "}",
        "",
        "_datacon_run_first_n() {",
        "  _n=$1",
        "  shift",
        "  _total=$#",
        "  _i=0",
        '  while [ "$_i" -lt "$_n" ]; do',
        "    _arg=$1",
        "    shift",
        '    if [ "$#" -eq 0 ]; then',
        '      set -- "$_arg"',
        "    else",
        '      set -- "$@" "$_arg"',
        "    fi",
        "    _i=$((_i + 1))",
        "  done",
        "  _drop=$((_total - _n))",
        '  while [ "$_drop" -gt 0 ]; do',
        "    shift",
        "    _drop=$((_drop - 1))",
        "  done",
        '  (case "$1" in -*) exit 126 ;; esac; exec "$@")',
        "}",
    ]
    if stage_fixture:
        lines.extend(
            [
                f'PATH="{_SAFE_SYSTEM_PATH}${{PATH:+:$PATH}}"',
                "export PATH",
                "if [ -d /fixture ]; then",
                "  if ! cp -RP /fixture/. /work/; then",
                '    echo "datacon-build-runner: staging copy from /fixture failed" >&2',
                "    exit 1",
                "  fi",
                "  if ! chmod -R u+w /work 2>/dev/null; then",
                '    echo "datacon-build-runner: warning: chmod -R u+w /work failed" >&2',
                "  fi",
                "fi",
            ]
        )
    lines.extend(
        [
            "_n_clean=$1",
            "shift",
            "_i_clean=0",
            'while [ "$_i_clean" -lt "$_n_clean" ]; do',
            '  _datacon_clean_path "$1"',
            "  shift",
            "  _i_clean=$((_i_clean + 1))",
            "done",
            "_datacon_code=0",
            "_n_cfg=$1",
            "shift",
            'if [ "$_n_cfg" -gt 0 ]; then',
            '  _datacon_run_first_n "$_n_cfg" "$@"',
            "  _datacon_code=$?",
            '  shift "$_n_cfg"',
            "fi",
            "_n_bld=$1",
            "shift",
            'if [ "$_datacon_code" -eq 0 ] && [ "$_n_bld" -gt 0 ]; then',
            '  _datacon_run_first_n "$_n_bld" "$@"',
            "  _datacon_code=$?",
            "fi",
            'if [ "$_n_bld" -gt 0 ]; then',
            '  shift "$_n_bld"',
            "fi",
            "_n_inst=$1",
            "shift",
            'if [ "$_datacon_code" -eq 0 ] && [ "$_n_inst" -gt 0 ]; then',
            '  _datacon_run_first_n "$_n_inst" "$@"',
            "  _datacon_code=$?",
            "fi",
            'if [ "$_n_inst" -gt 0 ]; then',
            '  shift "$_n_inst"',
            "fi",
        ]
    )
    if cc_shim_merge_log is not None:
        lines.extend(
            [
                "# Every shim wrote a private fragment; this runner is the only",
                "# writer of the fixed face, after all build processes exited.",
                '_datacon_merge_log=$1',
                "shift",
                "(",
                *_cc_shim_merge_shell_lines('"$_datacon_merge_log"'),
                ") || exit 1",
            ]
        )
    if emit_result_marker:
        lines.extend(
            [
                'if ! _datacon_has_symlink_in_work "$_datacon_out" && [ ! -L "$_datacon_out" ] && [ -f "$_datacon_out" ]; then',
                '  _datacon_size=$(wc -c < "$_datacon_out" 2>/dev/null | tr -d " ")',
                '  [ -n "$_datacon_size" ] || _datacon_size=0',
                '  _datacon_digest=$(sha256sum -- "$_datacon_out" 2>/dev/null | cut -d" " -f1)',
                '  [ -n "$_datacon_digest" ] || _datacon_digest=missing',
                "else",
                "  _datacon_size=-1",
                "  _datacon_digest=missing",
                "fi",
                r"printf '\nDATACON_BUILD_RESULT code=%s size=%s digest=%s\n' "
                '"$_datacon_code" "$_datacon_size" "$_datacon_digest" >&2',
                "cat /sys/fs/cgroup/pids.events > /work/pids.events 2>/dev/null || true",
                "cat /sys/fs/cgroup/memory.events > /work/memory.events 2>/dev/null || true",
            ]
        )
    if wait_for_release:
        lines.extend(
            [
                "touch /work/done",
                "while [ ! -e /work/release ]; do sleep 0.1; done",
            ]
        )
    lines.append('exit "$_datacon_code"')
    return "\n".join(lines) + "\n"


def build_runner_command(
    plan: BuildSpecExecutionPlan,
    *,
    stage_fixture: bool = True,
    emit_result_marker: bool = True,
    wait_for_release: bool = True,
    build_version: str | None = None,
) -> list[str]:
    """Assemble the exact argv command vector for executing ``plan`` without shell splicing."""
    clean_paths: list[str] = []
    seen_clean: set[str] = set()
    for _rel, container_path in plan.output_container_paths:
        if container_path not in seen_clean:
            clean_paths.append(container_path)
            seen_clean.add(container_path)
    if (
        plan.provenance_face_container_path is not None
        and plan.provenance_face_container_path not in seen_clean
    ):
        clean_paths.append(plan.provenance_face_container_path)
        seen_clean.add(plan.provenance_face_container_path)
        if plan.kind == "make":
            fragment_dir = f"{plan.provenance_face_container_path}.d"
            if fragment_dir not in seen_clean:
                clean_paths.append(fragment_dir)
                seen_clean.add(fragment_dir)
    merge_log = (
        plan.provenance_face_container_path if plan.kind == "make" else None
    )
    build_argv = list(plan.build)
    if plan.kind == "shell" and build_version is not None:
        # v1 always ran ``/bin/sh /fixture/build.sh {version}``. Keep the same
        # fixed positional contract for v2 shell recipes instead of making the
        # version an author-controlled argv element.
        build_argv.append(build_version)
    return [
        "/bin/sh",
        "-c",
        render_build_runner_script(
            stage_fixture=stage_fixture,
            emit_result_marker=emit_result_marker,
            wait_for_release=wait_for_release,
            cc_shim_merge_log=merge_log,
        ),
        "datacon-build-runner",
        plan.primary_output_container_path,
        str(len(clean_paths)),
        *clean_paths,
        str(len(plan.configure)),
        *plan.configure,
        str(len(build_argv)),
        *build_argv,
        str(len(plan.install)),
        *plan.install,
        *([merge_log] if merge_log is not None else []),
    ]


def prepare_build_spec_execution(
    build_spec: Mapping[str, Any],
    *,
    cc_shim_log_path: str = DEFAULT_CC_SHIM_LOG_PATH,
) -> BuildSpecExecutionPlan:
    """Validate a v2 ``BuildSpec`` fail-closed and build a fixed-template execution plan.

    Raises ``SandboxError(..., reason_code="BUILD_PROVENANCE_MISSING")`` before
    any container is created whenever freeze validation or path safety fails.
    """
    decision = build_provenance.validate_build_spec_for_freeze(build_spec)
    if not decision.ok:
        raise SandboxError(
            decision.error_detail or "build_spec failed provenance freeze validation",
            reason_code=build_provenance.BUILD_PROVENANCE_MISSING,
        )

    kind = str(build_spec["kind"])
    face_name = build_provenance.FACE_FILENAMES[kind]
    raw_outputs = build_spec["outputs"]
    output_pairs = tuple(
        _validate_build_spec_output(item, index)
        for index, item in enumerate(raw_outputs)
    )
    outputs = tuple(rel for rel, _container in output_pairs)
    primary_output = _select_primary_output(outputs)
    primary_output_container_path = f"/work/{primary_output}"

    build_argv = tuple(build_spec["build"])
    install_argv = tuple(build_spec.get("install") or ())
    env = dict(build_spec["env"])
    env_err = build_provenance.validate_build_spec_env(env)
    if env_err is not None:
        raise SandboxError(
            env_err, reason_code=build_provenance.BUILD_PROVENANCE_MISSING
        )

    configure_argv: tuple[str, ...] = ()
    cmake_build_dir: str | None = None
    provenance_face_container_path: str | None = None
    cc_shim_destination: str | None = None
    cxx_shim_destination: str | None = None

    if kind == "cmake":
        raw_configure = list(build_spec["configure"])
        cmd_err = build_provenance.validate_build_spec_commands(
            kind, configure=raw_configure, build=build_argv, install=install_argv
        )
        if cmd_err is not None:
            raise SandboxError(
                cmd_err, reason_code=build_provenance.BUILD_PROVENANCE_MISSING
            )
        try:
            cmake_build_dir, provenance_face_container_path = (
                build_provenance.extract_cmake_build_dir(raw_configure)
            )
        except ValueError as error:
            raise SandboxError(
                str(error), reason_code=build_provenance.BUILD_PROVENANCE_MISSING
            ) from error
        if not build_provenance.cmake_has_export_compile_commands(raw_configure):
            raw_configure.append("-DCMAKE_EXPORT_COMPILE_COMMANDS=ON")
        configure_argv = tuple(raw_configure)
    elif kind == "make":
        cmd_err = build_provenance.validate_build_spec_commands(
            kind, build=build_argv, install=install_argv
        )
        if cmd_err is not None:
            raise SandboxError(
                cmd_err, reason_code=build_provenance.BUILD_PROVENANCE_MISSING
            )
        provenance_face_container_path = _validate_work_container_path(
            cc_shim_log_path, label="cc-shim log path"
        )
        cc_shim_destination = _validate_shim_destination(
            env["CC"],
            allowed_basenames=build_provenance.CC_SHIM_BASENAMES,
            label="cc-shim",
        )
        if "CXX" in env:
            cxx_dest = _validate_shim_destination(
                env["CXX"],
                allowed_basenames=build_provenance.CXX_SHIM_BASENAMES,
                label="cxx-shim",
            )
            if cxx_dest != cc_shim_destination:
                cxx_shim_destination = cxx_dest
    elif kind == "shell":
        cmd_err = build_provenance.validate_build_spec_commands(
            kind, build=build_argv, install=install_argv
        )
        if cmd_err is not None:
            raise SandboxError(
                cmd_err, reason_code=build_provenance.BUILD_PROVENANCE_MISSING
            )
        provenance_face_container_path = None

    base_plan = BuildSpecExecutionPlan(
        kind=kind,
        configure=configure_argv,
        build=build_argv,
        install=install_argv,
        env=env,
        outputs=outputs,
        primary_output=primary_output,
        primary_output_container_path=primary_output_container_path,
        output_container_paths=output_pairs,
        provenance_face_name=face_name,
        provenance_face_container_path=provenance_face_container_path,
        cc_shim_destination=cc_shim_destination,
        cxx_shim_destination=cxx_shim_destination,
        cmake_build_dir=cmake_build_dir,
    )
    command = tuple(build_runner_command(base_plan))
    return replace(base_plan, container_command=command)


def _quota_events(files: Mapping[str, bytes]) -> list[str]:
    hits: list[str] = []
    pids = files.get("/work/pids.events", b"").decode("utf-8", "replace")
    memory = files.get("/work/memory.events", b"").decode("utf-8", "replace")
    for line in pids.splitlines():
        parts = line.split()
        if len(parts) == 2 and parts[0] == "max":
            try:
                if int(parts[1]) > 0:
                    hits.append("pids")
            except ValueError:
                pass
    for line in memory.splitlines():
        parts = line.split()
        if len(parts) == 2 and parts[0] in ("oom", "oom_kill"):
            try:
                if int(parts[1]) > 0:
                    hits.append("memory")
            except ValueError:
                pass
    return sorted(set(hits))


def evaluate_probe_values(
    values: Mapping[str, str],
    policy: IsolationPolicy,
    limits: ResourceLimits,
    *,
    exit_code: int,
    oom_killed: bool,
) -> tuple[bool, dict[str, Any]]:
    """Judge container-internal probe values without trusting ``unknown``.

    cgroup v2 is read first; when it is absent the probe reports explicit v1
    values. A missing or ``max`` value means the limit cannot be proven and
    therefore fails closed.
    """
    checks: dict[str, Any] = {
        "probe_exit_code": exit_code,
        "uid": values.get("uid"),
        "seccomp": values.get("seccomp"),
        "seccomp_filters": values.get("seccomp_filters"),
        "no_new_privs": values.get("no_new_privs"),
        "cap_eff": values.get("cap_eff"),
        "cgroup_version": values.get("cgroup_version"),
        "network_links": values.get("links", ""),
        "ipv6_links": values.get("ipv6_links", ""),
        "routes": values.get("routes", ""),
        "ipv6_routes": values.get("ipv6_routes", ""),
        "pids_max": values.get("pids"),
        "memory_max": values.get("memory"),
        "cpu_max": values.get("cpu"),
        "cpu_quota_us": values.get("cpu_quota_us"),
        "cpu_period_us": values.get("cpu_period_us"),
        "work_mib": values.get("work_mib"),
        "tmp_mib": values.get("tmp_mib"),
        "oom_killed": oom_killed,
    }
    errors: list[str] = []

    def require(condition: bool, message: str) -> None:
        if not condition:
            errors.append(message)

    require(exit_code == 0, "probe exited non-zero")
    require(values.get("uid") == policy.user.split(":")[0], "container uid is not the planned uid")
    require(values.get("seccomp") == "2", "seccomp filter mode is not enabled")
    filters = values.get("seccomp_filters")
    require(
        isinstance(filters, str) and filters.isdigit() and int(filters) >= 1,
        "seccomp filter count is not provable",
    )
    require(values.get("no_new_privs") == "1", "no-new-privileges is not effective")
    capability = values.get("cap_eff")
    try:
        require(
            isinstance(capability, str) and int(capability, 16) == 0,
            "effective capabilities are not empty",
        )
    except (TypeError, ValueError):
        require(False, "effective capabilities are not provable")
    require(
        values.get("links", "") == "",
        "a non-loopback network interface is up or unprovable",
    )
    require(values.get("ipv6_links", "") == "", "non-loopback IPv6 addresses exist")
    require(values.get("routes", "") == "", "IPv4 routes exist")
    require(values.get("ipv6_routes", "") == "", "IPv6 routes exist")
    require(
        values.get("pids") == str(limits.pids),
        "PID limit is missing, unlimited or differs",
    )
    require(
        values.get("memory") == str(limits.memory_mib * MIB),
        "memory limit is missing, unlimited or differs",
    )
    cpu_max = values.get("cpu")
    if cpu_max not in (None, "", "unknown"):
        parts = str(cpu_max).split()
        require(
            len(parts) == 2
            and parts[0].isdigit()
            and parts[0] == str(limits.cpu * 100_000)
            and parts[1].isdigit()
            and int(parts[1]) > 0,
            "CPU cgroup v2 limit is missing, unlimited or differs",
        )
    else:
        quota = values.get("cpu_quota_us")
        period = values.get("cpu_period_us")
        try:
            quota_value = int(str(quota))
            period_value = int(str(period))
        except (TypeError, ValueError):
            quota_value = period_value = -1
        require(
            quota_value > 0
            and period_value > 0
            and quota_value == limits.cpu * period_value,
            "CPU cgroup v1 limit is missing, unlimited or differs",
        )
    try:
        work_mib = int(str(values.get("work_mib")))
        tmp_mib = int(str(values.get("tmp_mib")))
    except (TypeError, ValueError):
        work_mib = tmp_mib = -1
    require(work_mib > 0 and tmp_mib > 0, "writable tmpfs sizes are not provable")
    require(
        work_mib + tmp_mib <= limits.scratch_mib + 2,
        "writable tmpfs exceeds the scratch budget",
    )
    require(not oom_killed, "probe container was OOM-killed")
    checks["errors"] = errors
    return not errors, checks


class DockerSandbox:
    """A small Docker CLI adapter with one-shot, labelled containers."""

    def __init__(
        self,
        *,
        image: str,
        platform: str,
        policy: IsolationPolicy,
        limits: ResourceLimits,
        docker: str = "docker",
        job_id: str,
        run_root: Path | str,
        generation: int | None = None,
        pull_timeout: float = 600.0,
    ):
        policy.validate()
        limits.validate()
        if "@" not in image:
            raise SandboxPolicyError("the toolchain image must be pinned by digest")
        _, _, digest = image.partition("@")
        if not _IMAGE_DIGEST.fullmatch(digest):
            raise SandboxPolicyError("the toolchain image digest is invalid")
        if platform != "linux/amd64":
            raise SandboxPolicyError("the MVP sandbox platform is linux/amd64")
        self.image = image
        self.image_digest = digest
        self.platform = platform
        self.policy = policy
        self.limits = limits
        self.docker = docker
        self.job_id = str(job_id)
        if generation is not None and (
            type(generation) is not int or generation < 0
        ):
            raise SandboxPolicyError(
                "container generation must be a non-negative integer"
            )
        self.generation = generation
        self.run_root = Path(run_root)
        self.pull_timeout = pull_timeout
        self.cleanup_errors: list[str] = []

    # -- low-level helpers -------------------------------------------------
    def _name(self, suffix: str) -> str:
        raw = f"datacon-{self.job_id[:8]}-{suffix}-{uuid.uuid4().hex[:8]}".lower()
        return _SAFE_NAME.sub("-", raw)[:63]

    def _docker(self, args: Sequence[str], *, timeout: float = 60.0) -> subprocess.CompletedProcess:
        result = _run_bytes([self.docker, *args], timeout=timeout)
        return result

    def _inspect(self, name: str) -> dict[str, Any]:
        result = self._docker(["inspect", name], timeout=30)
        if result.returncode != 0:
            raise SandboxError(
                f"cannot inspect container {name}: {result.stderr.decode('utf-8', 'replace')[:500]}"
            )
        try:
            payload = json.loads(result.stdout)
            return payload[0]
        except (ValueError, IndexError, TypeError) as error:
            raise SandboxError("docker inspect returned malformed JSON") from error

    def _remove(self, name: str, *, retries: int = 1) -> tuple[bool, str | None]:
        """Remove a container and report whether Docker really removed it.

        ``docker rm -f`` can fail while the CLI itself exits non-zero or the
        daemon is unavailable. Swallowing that made reclaim_job count failed
        removals as cleaned. Return the outcome instead so callers can add a
        note, surface a cleanup error, or refuse to claim success.
        """
        last_error: str | None = None
        for attempt in range(retries + 1):
            try:
                result = self._docker(["rm", "-f", name], timeout=30)
            except SandboxError as error:
                last_error = error.message
            else:
                if result.returncode == 0:
                    return True, None
                stderr = result.stderr.decode("utf-8", "replace").strip()
                if "no such container" in stderr.lower():
                    return True, None
                last_error = stderr or f"docker rm exited {result.returncode}"
            if attempt < retries:
                time.sleep(0.1)
        message = f"cannot remove container {name}: {last_error}"
        self.cleanup_errors.append(message)
        return False, message

    def _cleanup_failure(self, name: str) -> str | None:
        ok, detail = self._remove(name)
        return None if ok else detail

    def available(self) -> tuple[bool, str]:
        try:
            result = self._docker(
                ["version", "--format", "{{.Server.Version}}"], timeout=20
            )
        except SandboxError as error:
            return False, error.message
        if result.returncode != 0:
            return False, result.stderr.decode("utf-8", "replace")[:500]
        return True, result.stdout.decode("utf-8", "replace").strip()

    def ensure_image(self) -> None:
        result = self._docker(["image", "inspect", self.image], timeout=60)
        if result.returncode == 0:
            return
        pull = self._docker(["pull", self.image], timeout=self.pull_timeout)
        if pull.returncode != 0:
            raise SandboxUnavailable(
                "the pinned toolchain image is unavailable: "
                + pull.stderr.decode("utf-8", "replace")[:500]
            )
        check = self._docker(["image", "inspect", self.image], timeout=60)
        if check.returncode != 0:
            raise SandboxUnavailable("the pinned toolchain image cannot be inspected")

    def reclaim_job(self) -> int:
        """Remove containers from this job that belong to strictly older generations.

        A worker whose lease expired may still be running containers. Those
        containers carry the generation that created them; only generations
        strictly older than this worker are removed. A missing or malformed
        generation label is reported instead of being treated as legacy, and
        generation=None is refused rather than deleting every generation.
        """
        if self.generation is None:
            raise SandboxPolicyError(
                "reclaim_job requires an explicit generation; refusing to "
                "delete an unbounded container set"
            )
        result = self._docker(
            [
                "ps",
                "-aq",
                "--filter",
                f"label=datacon.job_id={self.job_id}",
            ],
            timeout=30,
        )
        if result.returncode != 0:
            detail = result.stderr.decode("utf-8", "replace").strip()
            raise SandboxError(
                "cannot list job containers: " + (detail or "docker ps failed")
            )
        removed = 0
        for name in result.stdout.decode("utf-8", "replace").split():
            if not name:
                continue
            try:
                inspect = self._inspect(name)
            except SandboxError as error:
                message = f"cannot inspect container {name} for reclaim: {error.message}"
                self.cleanup_errors.append(message)
                continue
            labels = (inspect.get("Config") or {}).get("Labels") or {}
            raw_generation = labels.get("datacon.generation")
            try:
                if isinstance(raw_generation, str):
                    container_generation = int(raw_generation)
                else:
                    raise ValueError("generation label is missing")
                if not 0 <= container_generation < self.generation:
                    continue
            except (TypeError, ValueError):
                self.cleanup_errors.append(
                    f"container {name} has a missing or malformed "
                    f"datacon.generation label: {raw_generation!r}"
                )
                continue
            ok, detail = self._remove(name)
            if ok:
                removed += 1
            elif detail is not None:
                self.cleanup_errors.append(detail)
        if self.cleanup_errors:
            raise SandboxError(
                "container cleanup reported errors: "
                + "; ".join(self.cleanup_errors)
            )
        return removed

    # -- containers --------------------------------------------------------
    def _create(
        self,
        *,
        suffix: str,
        command: Sequence[str],
        mounts: Sequence[tuple[str, str, bool]],
        env: Mapping[str, str] | None = None,
    ) -> tuple[str, dict[str, Any]]:
        name = self._name(suffix)
        args = container_create_args(
            image=self.image,
            platform=self.platform,
            policy=self.policy,
            limits=self.limits,
            name=name,
            command=command,
            mounts=mounts,
            env=env,
            docker=self.docker,
            job_id=self.job_id,
            generation=self.generation,
            labels={"datacon.run": suffix},
        )
        created = self._docker(args[1:], timeout=120)
        if created.returncode != 0:
            ok, detail = self._remove(name)
            message = (
                "cannot create sandbox container: "
                + created.stderr.decode("utf-8", "replace")[:500]
            )
            if not ok and detail is not None:
                message += f"; cleanup also failed: {detail}"
            raise SandboxError(message)
        # Once ``docker create`` succeeds the container exists. Any inspect or
        # policy failure below must remove it before propagating, otherwise a
        # malformed container survives its generation and keeps running.
        try:
            inspect = self._inspect(name)
            config = dict(inspect.get("HostConfig", {}))
            config["User"] = inspect.get("Config", {}).get("User", "")
            config["Mounts"] = inspect.get("Mounts", [])
            validate_host_config(
                config, self.policy, self.limits, mounts=mounts
            )
            return name, config
        except BaseException as error:
            ok, detail = self._remove(name)
            if not ok and detail is not None:
                add_note = getattr(error, "add_note", None)
                if callable(add_note):
                    add_note(f"container cleanup also failed: {detail}")
            raise

    def _copy_work_path(
        self, name: str, relative: str, limit: int
    ) -> tuple[bytes, int, bool]:
        """Read one bounded regular tmpfs file while refusing symlinks under ``/work``."""
        safe_path = _validate_work_container_path(
            relative, label="sandbox stream path"
        )
        safe_check = (
            'set -f; '
            'case "$_p" in /work/*) ;; *) exit 1 ;; esac; '
            'IFS=/; _cur=/work; '
            'for _seg in ${_p#/work/}; do '
            '[ -n "$_seg" ] || continue; '
            '_cur="$_cur/$_seg"; '
            'if [ -L "$_cur" ]; then exit 1; fi; '
            'done; '
            'if [ -L "$_p" ] || [ ! -f "$_p" ]; then exit 1; fi; '
        )
        size_result = self._docker(
            [
                "exec",
                name,
                "sh",
                "-c",
                '_p=$1; ' + safe_check + 'wc -c < "$_p" 2>/dev/null',
                "datacon-copy-size",
                safe_path,
            ],
            timeout=30,
        )
        if size_result.returncode != 0:
            return b"", 0, False
        try:
            size = int(size_result.stdout.decode("ascii", "replace").strip())
        except ValueError:
            return b"", 0, False
        data_result = self._docker(
            [
                "exec",
                name,
                "sh",
                "-c",
                '_lim=$1; _p=$2; ' + safe_check + 'head -c "$_lim" -- "$_p"',
                "datacon-copy-data",
                str(limit + 1),
                safe_path,
            ],
            timeout=60,
        )
        if data_result.returncode != 0:
            return b"", 0, False
        data = data_result.stdout
        return data[:limit], size, size > limit or len(data) > limit

    def _start_attached(self, name: str) -> subprocess.Popen:
        """Start a container with stdout/stderr attached before it runs.

        ``docker start --attach`` asks the daemon to wire the output streams
        before starting the process, so the first byte is not lost even though
        the container uses ``--log-driver none``. The CLI demultiplexes the two
        streams onto its own stdout/stderr; both pipes are drained concurrently.
        """
        try:
            return subprocess.Popen(
                [self.docker, "start", "-a", name],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                close_fds=True,
            )
        except FileNotFoundError as error:
            raise SandboxUnavailable("docker CLI is not available") from error
        except PermissionError as error:
            raise SandboxUnavailable("docker CLI is not executable") from error
        except OSError as error:
            raise SandboxError(
                f"cannot attach to sandbox container: {error}"
            ) from error

    def _kill(self, name: str) -> None:
        try:
            self._docker(["kill", name], timeout=30)
        except SandboxError:
            pass

    def _start_and_wait(
        self,
        name: str,
        *,
        deadline_seconds: float,
        artifact: bool = False,
        extra_copy_paths: Sequence[tuple[str, int]] = (),
    ) -> tuple[
        bytes,
        bytes,
        dict[str, bytes],
        set[str],
        dict[str, Any],
        bool,
        int | None,
        str | None,
    ]:
        """Start a container and capture its output from a live attach.

        The target never owns the completion signal: replay uses ``exec`` so
        the target is PID 1 and ``docker wait`` reports its exit code. Stdout
        and stderr come from ``docker start --attach`` (log driver ``none``),
        read concurrently under one 16 MiB union budget, so a target that
        writes ``/work/done`` early cannot shorten the collection window.

        Builds also need their parser from the tmpfs before the container
        stops. ``/work/done`` is only an optimization that prompts an early
        artifact copy: the wrapper prints the artifact size and digest after
        the build command exits, the host compares them after ``docker wait``,
        and any mismatch fails the build instead of accepting a partial file.
        """
        files: dict[str, bytes] = {}
        truncated: set[str] = set()
        timed_out = False
        exit_code: int | None = None
        cleanup_error: str | None = None
        state: dict[str, Any] = {}
        capture = _UnionCapture()
        capture_errors: list[str] = []
        started = time.monotonic()
        process: subprocess.Popen | None = None
        readers: list[threading.Thread] = []
        try:
            process = self._start_attached(name)
            readers = [
                threading.Thread(
                    target=_drain_stream,
                    args=("stdout", process.stdout, capture),
                    daemon=True,
                ),
                threading.Thread(
                    target=_drain_stream,
                    args=("stderr", process.stderr, capture),
                    daemon=True,
                ),
            ]
            for reader in readers:
                reader.start()

            if artifact:
                while time.monotonic() - started < deadline_seconds:
                    check = self._docker(
                        ["exec", name, "test", "-e", "/work/done"], timeout=10
                    )
                    if check.returncode == 0:
                        break
                    if process.poll() is not None:
                        try:
                            running = (
                                self._inspect(name).get("State", {}).get("Running")
                            )
                        except SandboxError:
                            running = None
                        if running is True:
                            capture_errors.append(
                                "docker start -a exited before the container stopped"
                            )
                            self._kill(name)
                        break
                    try:
                        running = (
                            self._inspect(name).get("State", {}).get("Running")
                        )
                    except SandboxError:
                        running = False
                    if running is False:
                        break
                    time.sleep(0.1)
                else:
                    timed_out = True
                # The parser lives on the container tmpfs and disappears when
                # the container is removed, so copy it while the container may
                # still be alive. The wrapper's post-exit digest decides later
                # whether these bytes are the completed artifact.
                copy_targets: list[tuple[str, int]] = [
                    ("/work/parser", MAX_ARTIFACT_BYTES),
                    ("/work/pids.events", MAX_LOG_BYTES),
                    ("/work/memory.events", MAX_LOG_BYTES),
                ]
                seen_targets = {item[0] for item in copy_targets}
                for extra_path, extra_limit in extra_copy_paths:
                    safe_extra = _validate_work_container_path(
                        extra_path, label="sandbox copy path"
                    )
                    if safe_extra not in seen_targets:
                        copy_targets.append((safe_extra, extra_limit))
                        seen_targets.add(safe_extra)
                for relative, limit in copy_targets:
                    data, _size, was_truncated = self._copy_work_path(
                        name, relative, limit
                    )
                    if data or was_truncated:
                        files[relative] = data
                        if was_truncated:
                            truncated.add(relative)
                if not timed_out and not capture_errors:
                    self._docker(
                        ["exec", name, "touch", "/work/release"], timeout=10
                    )

            if timed_out:
                self._kill(name)

            # The attached CLI returns when the container stops and propagates
            # the container status. Wait for it here while enforcing the
            # deadline. A separate concurrent ``docker wait`` is deliberately
            # not used: waiting on a container that has not started yet can
            # return 0 and make a still-running capture look complete.
            deadline_exceeded_at: float | None = None
            while process.poll() is None:
                now = time.monotonic()
                if not timed_out and now - started >= deadline_seconds:
                    timed_out = True
                    deadline_exceeded_at = now
                    self._kill(name)
                if (
                    deadline_exceeded_at is not None
                    and now - deadline_exceeded_at >= 30.0
                ):
                    capture_errors.append(
                        "docker start -a did not finish after the container "
                        "was stopped"
                    )
                    try:
                        process.kill()
                    except OSError:
                        pass
                    break
                time.sleep(0.05)

            try:
                start_rc = process.wait(timeout=30)
            except subprocess.TimeoutExpired:
                start_rc = None
                capture_errors.append(
                    "docker start -a did not finish after the container stopped"
                )
                try:
                    process.kill()
                except OSError:
                    pass
                try:
                    process.wait(timeout=5)
                except (subprocess.TimeoutExpired, OSError):
                    pass

            inspect_payload: dict[str, Any] | None = None
            inspect_error: str | None = None
            try:
                inspect_payload = self._inspect(name)
                raw_state = inspect_payload.get("State")
                state = dict(raw_state) if isinstance(raw_state, Mapping) else {}
            except SandboxError as error:
                state = {}
                inspect_error = error.message

            not_terminal = False
            if not timed_out and inspect_payload is not None:
                if state.get("Running") is True:
                    # The attach CLI exited while the container keeps running:
                    # the capture window is gone. Re-check after a short grace
                    # to avoid racing the normal exit path.
                    time.sleep(0.2)
                    try:
                        second_state = dict(self._inspect(name).get("State", {}))
                    except SandboxError:
                        second_state = None
                    if second_state is None or second_state.get("Running") is True:
                        capture_errors.append(
                            "docker start -a exited before the container stopped"
                        )
                        self._kill(name)
                    else:
                        state = second_state
                elif (
                    state.get("Running") is not False
                    or state.get("Status") not in ("exited", "dead")
                ):
                    not_terminal = True
                    capture_errors.append(
                        "container state after attach is not terminal: "
                        f"Running={state.get('Running')!r} "
                        f"Status={state.get('Status')!r}"
                    )
                    self._kill(name)

            wait = None
            wait_error: str | None = None
            if not not_terminal:
                try:
                    wait = self._docker(["wait", name], timeout=30)
                except SandboxError as error:
                    wait_error = error.message
            else:
                wait_error = "container did not reach a terminal state"
            if wait is not None:
                if wait.returncode == 0:
                    raw_wait = wait.stdout.decode("ascii", "replace").strip()
                    try:
                        exit_code = int(raw_wait)
                    except ValueError:
                        exit_code = None
                        wait_error = (
                            "docker wait returned a non-integer exit code: "
                            f"{raw_wait[:120]!r}"
                        )
                else:
                    detail = wait.stderr.decode("utf-8", "replace").strip()
                    wait_error = (
                        f"docker wait failed (rc={wait.returncode}): "
                        + (detail[:300] or "no stderr")
                    )
            elif wait_error is None:
                wait_error = "docker wait did not report a result"

            if exit_code is None:
                candidate = state.get("ExitCode")
                if (
                    state.get("Running") is False
                    and state.get("Status") in ("exited", "dead")
                    and type(candidate) is int
                ):
                    exit_code = candidate
                elif not timed_out:
                    reason = wait_error or "docker wait did not report an exit code"
                    if inspect_error is not None:
                        reason += f"; inspect failed: {inspect_error}"
                    else:
                        reason += (
                            f"; container state Running={state.get('Running')!r} "
                            f"Status={state.get('Status')!r}"
                        )
                    capture_errors.append(reason)

            # ``docker start -a`` propagates the container's exit status as the
            # CLI status on a normal, attached completion. That is not a
            # capture failure when it matches the authoritative ``docker wait``
            # code. Any other non-zero CLI status (including a start/attach
            # error) leaves the output window unproven.
            if (
                start_rc is not None
                and start_rc != 0
                and start_rc != exit_code
            ):
                capture_errors.append(f"docker start -a failed (rc={start_rc})")

            for reader in readers:
                reader.join(timeout=30)
            if any(reader.is_alive() for reader in readers):
                capture_errors.append("container output streams did not close")
            stdout, stderr, truncated_roles, read_errors = capture.snapshot()
            truncated.update(truncated_roles)
            capture_errors.extend(read_errors)
            if capture_errors:
                state["_capture_error"] = "; ".join(
                    dict.fromkeys(capture_errors)
                )
        finally:
            if process is not None:
                try:
                    process.wait(timeout=5)
                except (subprocess.TimeoutExpired, OSError):
                    try:
                        process.kill()
                    except OSError:
                        pass
                    try:
                        process.wait(timeout=5)
                    except (subprocess.TimeoutExpired, OSError):
                        pass
            for reader in readers:
                if reader.ident is not None:
                    reader.join(timeout=5)
            cleanup_error = self._cleanup_failure(name)
        return (
            stdout,
            stderr,
            files,
            truncated,
            state,
            timed_out,
            exit_code,
            cleanup_error,
        )

    def probe(self, *, deadline_seconds: float = _PROBE_TIMEOUT) -> ProbeReport:
        # The old implementation used the stable ``run_root/probe`` directory,
        # which let an attacker pre-plant a symlink before mkdir/chmod/write.
        # A fresh one-shot directory cannot be predicted, and the legacy name
        # is rejected if it is a symlink so an old layout is never followed.
        legacy = self.run_root / "probe"
        if legacy.is_symlink():
            raise SandboxPolicyError("the probe directory must not be a symlink")
        probe_root = self.run_root / f"probe-{uuid.uuid4().hex}"
        self.run_root.mkdir(mode=0o700, parents=True, exist_ok=True)
        try:
            probe_root.mkdir(mode=0o755)
        except FileExistsError as error:
            raise SandboxPolicyError(
                "the one-shot probe directory already exists"
            ) from error
        info = probe_root.lstat()
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
            raise SandboxPolicyError("the probe directory is not a real directory")
        probe_root.chmod(0o755)
        marker = probe_root / "marker.txt"
        try:
            fileio.write_regular_file(
                marker, b"read-only probe\n", mode=0o444
            )
        except fileio.UnsafeFileError as error:
            raise SandboxPolicyError(
                f"the probe marker cannot be written safely: {error.message}"
            ) from error
        self.ensure_image()
        name = self._name("probe")
        cleanup_errors: list[str] = []
        script = r"""
set -u
uid=$(id -u)
if [ "$uid" = "0" ]; then echo "uid=0"; exit 20; fi
if touch /datacon-root-write 2>/dev/null; then exit 21; fi
if touch /fixture/.write-probe 2>/dev/null; then exit 22; fi
touch /work/.write-probe || exit 23
if [ -e /var/run/docker.sock ]; then exit 24; fi
links=$(for iface in /sys/class/net/*; do
  name=$(basename "$iface")
  [ "$name" = "lo" ] && continue
  [ -d "$iface" ] || continue
  state=$(cat "$iface/operstate" 2>/dev/null || echo unknown)
  [ "$state" = "down" ] || printf '%s:%s ' "$name" "$state"
done)
ipv6_links=$(awk '$NF != "lo" { print }' /proc/net/if_inet6 2>/dev/null || true)
routes=$(awk 'NR > 1 { print }' /proc/net/route)
# network=none still creates kernel pseudo-devices and loopback IPv6 routes.
# Any non-loopback route or address is a failure; down pseudo-devices with no
# address cannot carry traffic and are not a usable interface.
ipv6_routes=$(awk 'NF > 0 && $NF != "lo" { print }' /proc/net/ipv6_route 2>/dev/null || true)
if [ -n "$routes" ] || [ -n "$ipv6_routes" ] || [ -n "$links" ] || [ -n "$ipv6_links" ]; then exit 25; fi
seccomp=$(awk '/^Seccomp:/ {print $2}' /proc/self/status)
seccomp_filters=$(awk '/^Seccomp_filters:/ {print $2}' /proc/self/status)
no_new_privs=$(awk '/^NoNewPrivs:/ {print $2}' /proc/self/status)
cap_eff=$(awk '/^CapEff:/ {print $2}' /proc/self/status)
if [ "$seccomp" != "2" ]; then exit 26; fi
if [ "${seccomp_filters:-unknown}" = "unknown" ] && [ ! -f /proc/self/status ]; then exit 27; fi
cgroup_version=unknown
pids=unknown
memory=unknown
cpu=unknown
cpu_quota_us=unknown
cpu_period_us=unknown
if [ -f /sys/fs/cgroup/cgroup.controllers ]; then
  cgroup_version=2
  pids=$(cat /sys/fs/cgroup/pids.max 2>/dev/null || echo unknown)
  memory=$(cat /sys/fs/cgroup/memory.max 2>/dev/null || echo unknown)
  cpu=$(cat /sys/fs/cgroup/cpu.max 2>/dev/null || echo unknown)
elif [ -d /sys/fs/cgroup/pids ] || [ -d /sys/fs/cgroup/memory ]; then
  cgroup_version=1
  pids=$(cat /sys/fs/cgroup/pids/pids.max 2>/dev/null || echo unknown)
  memory=$(cat /sys/fs/cgroup/memory/memory.limit_in_bytes 2>/dev/null || echo unknown)
  cpu_quota_us=$(cat /sys/fs/cgroup/cpu/cpu.cfs_quota_us 2>/dev/null || echo unknown)
  cpu_period_us=$(cat /sys/fs/cgroup/cpu/cpu.cfs_period_us 2>/dev/null || echo unknown)
fi
work_mib=$(df -Pm /work | awk 'NR==2 {print $2}')
tmp_mib=$(df -Pm /tmp | awk 'NR==2 {print $2}')
compiler=$(clang --version | head -n 1)
printf 'uid=%s\nseccomp=%s\nseccomp_filters=%s\nno_new_privs=%s\ncap_eff=%s\ncgroup_version=%s\npids=%s\nmemory=%s\ncpu=%s\ncpu_quota_us=%s\ncpu_period_us=%s\nwork_mib=%s\ntmp_mib=%s\ncompiler=%s\nlinks=%s\nipv6_links=%s\nroutes=%s\nipv6_routes=%s\n' \
  "$uid" "$seccomp" "${seccomp_filters:-unknown}" "${no_new_privs:-unknown}" "${cap_eff:-unknown}" \
  "$cgroup_version" "$pids" "$memory" "$cpu" "$cpu_quota_us" "$cpu_period_us" \
  "$work_mib" "$tmp_mib" "$compiler" "$links" "$ipv6_links" "$routes" "$ipv6_routes"
"""
        args = container_create_args(
            image=self.image,
            platform=self.platform,
            policy=self.policy,
            limits=self.limits,
            name=name,
            command=["/bin/sh", "-c", script],
            mounts=[(str(probe_root), "/fixture", True)],
            env={"TMPDIR": "/work", "HOME": "/work"},
            docker=self.docker,
            job_id=self.job_id,
            generation=self.generation,
            labels={"datacon.run": "probe"},
        )
        try:
            created = self._docker(args[1:], timeout=120)
            if created.returncode != 0:
                raise SandboxUnavailable(
                    "cannot create isolation probe: "
                    + created.stderr.decode("utf-8", "replace")[:500]
                )
            inspect = self._inspect(name)
            config = dict(inspect.get("HostConfig", {}))
            config["User"] = inspect.get("Config", {}).get("User", "")
            config["Mounts"] = inspect.get("Mounts", [])
            validate_host_config(
                config,
                self.policy,
                self.limits,
                mounts=[(str(probe_root), "/fixture", True)],
            )
            (
                probe_stdout,
                probe_stderr,
                _probe_files,
                probe_truncated,
                state,
                timed_out,
                exit_code,
                cleanup_error,
            ) = self._start_and_wait(name, deadline_seconds=deadline_seconds)
            if cleanup_error is not None:
                cleanup_errors.append(cleanup_error)
            if timed_out:
                raise SandboxPolicyError("isolation probe timed out")
            capture_error = state.pop("_capture_error", None)
            if capture_error is not None:
                raise SandboxPolicyError(
                    "isolation probe output was not captured: " + capture_error
                )
            if probe_truncated:
                raise SandboxPolicyError(
                    "isolation probe output exceeded the capture budget"
                )
            if exit_code is None:
                raise SandboxPolicyError("isolation probe did not complete")
            raw = (probe_stdout + probe_stderr).decode("utf-8", "replace")
        finally:
            ok, detail = self._remove(name)
            if not ok and detail is not None:
                cleanup_errors.append(detail)
            marker.unlink(missing_ok=True)
            if not probe_root.is_symlink():
                shutil.rmtree(probe_root, ignore_errors=True)
        values: dict[str, str] = {}
        for line in raw.splitlines():
            key, separator, value = line.partition("=")
            if separator:
                values[key.strip()] = value.strip()
        oom_killed = bool(state.get("OOMKilled"))
        ok, checks = evaluate_probe_values(
            values,
            self.policy,
            self.limits,
            exit_code=exit_code,
            oom_killed=oom_killed,
        )
        if not ok:
            raise SandboxPolicyError(
                "isolation probe did not confirm the requested policy: "
                + json.dumps(checks, sort_keys=True)
            )
        return ProbeReport(
            ok=True,
            checks=checks,
            compiler_version=values.get("compiler", "unknown"),
            image_digest=self.image_digest,
            raw=raw,
            limits={
                "cpu": self.limits.cpu,
                "memory_mib": self.limits.memory_mib,
                "pids": self.limits.pids,
                "scratch_mib": self.limits.scratch_mib,
            },
            cleanup_errors=tuple(cleanup_errors),
        )

    def build(
        self,
        version: str,
        *,
        materials_dir: Path | str,
        compile_args: Sequence[str] = (),
        deadline_seconds: float = 300.0,
        expected_materials: Mapping[str, str] | None = None,
        build_spec: Mapping[str, Any] | None = None,
    ) -> BuildResult:
        if version not in ("vulnerable", "fixed"):
            raise SandboxError("build version is invalid")
        plan: BuildSpecExecutionPlan | None = None
        if build_spec is not None:
            # Fail closed BEFORE creating or starting any Docker container.
            plan = prepare_build_spec_execution(build_spec)
        materials = Path(materials_dir)
        if materials.is_symlink() or not materials.is_dir():
            raise SandboxError(
                "reviewed material root is missing",
                reason_code="MATERIAL_MISSING",
            )
        for relative, digest in (expected_materials or {}).items():
            path = materials / relative
            if path.is_symlink() or not path.is_file():
                raise SandboxError(
                    f"reviewed material is missing: {relative}",
                    reason_code="MATERIAL_MISSING",
                )
            data = _read_bounded_file(
                path,
                max_bytes=MAX_MATERIAL_BYTES,
                label=f"reviewed material is not readable: {relative}",
                reason_code="MATERIAL_MISSING",
            )
            actual = "sha256:" + hashlib.sha256(data).hexdigest()
            if actual != digest:
                raise SandboxError(
                    f"reviewed material changed before build: {relative}",
                    reason_code="PLAN_MISMATCH",
                )
        if plan is not None:
            assert build_spec is not None
            return self._build_with_spec(
                version=version,
                materials=materials,
                build_spec=build_spec,
                plan=plan,
                compile_args=compile_args,
                deadline_seconds=deadline_seconds,
            )
        if not (materials / "build.sh").is_file():
            raise SandboxError("reviewed build recipe is missing")
        work = self.run_root / "build" / version / uuid.uuid4().hex
        work.mkdir(parents=True, exist_ok=True)
        # The build command's stdout/stderr go to the live attach capture, not
        # to a target-writable file. The wrapper only reports the artifact
        # size/digest after the command exits and then waits for the host to
        # acknowledge the copy; the host's exit code comes from docker wait.
        wrapper = (
            f"/bin/sh /fixture/build.sh {version}; "
            "code=$?; "
            "if [ -f /work/parser ]; then "
            "size=$(wc -c < /work/parser 2>/dev/null || echo 0); "
            "digest=$(sha256sum /work/parser 2>/dev/null | cut -d' ' -f1); "
            "else size=-1; digest=missing; fi; "
            f"printf '\\nDATACON_BUILD_RESULT code=%s size=%s digest=%s\\n' "
            '"$code" "$size" "$digest" >&2; '
            "cat /sys/fs/cgroup/pids.events > /work/pids.events 2>/dev/null || true; "
            "cat /sys/fs/cgroup/memory.events > /work/memory.events 2>/dev/null || true; "
            "touch /work/done; "
            "while [ ! -e /work/release ]; do sleep 0.1; done; "
            "exit $code"
        )
        started = time.monotonic()
        name = None
        try:
            name, _ = self._create(
                suffix=f"build-{version}",
                command=["/bin/sh", "-c", wrapper],
                mounts=[(str(materials), "/fixture", True)],
                env={
                    "TMPDIR": "/work",
                    "HOME": "/work",
                    "ASAN_OPTIONS": "detect_leaks=0",
                },
            )
            (
                stdout,
                stderr,
                files,
                truncated_streams,
                state,
                timed_out,
                exit_code,
                cleanup_error,
            ) = self._start_and_wait(
                name, deadline_seconds=deadline_seconds, artifact=True
            )
            duration = time.monotonic() - started
            report_match = None
            for match in re.finditer(
                rb"DATACON_BUILD_RESULT code=(-?\d+) size=(-?\d+) digest=([0-9a-f]{64}|missing)",
                stderr,
            ):
                report_match = match
            reported_code = reported_size = reported_digest = None
            if report_match is not None:
                reported_code = int(report_match.group(1))
                reported_size = int(report_match.group(2))
                reported_digest = report_match.group(3).decode("ascii")
            log_bytes = re.sub(
                rb"\n?DATACON_BUILD_RESULT code=-?\d+ size=-?\d+ digest=(?:[0-9a-f]{64}|missing)\n?",
                b"\n",
                stdout + stderr,
            )
            capture_error = state.pop("_capture_error", None)
            log, log_truncated = _truncate_log(log_bytes)
            truncated = log_truncated or bool(truncated_streams)
            truncated_roles = tuple(
                role for role in STREAM_ROLES if role in truncated_streams
            )
            artifact = files.get("/work/parser")
            if artifact is not None and len(artifact) > MAX_ARTIFACT_BYTES:
                artifact = None
                truncated = True
            if capture_error is not None:
                artifact = None
                truncated = True
            artifact_digest = (
                "sha256:" + hashlib.sha256(artifact).hexdigest()
                if artifact is not None
                else None
            )
            # Early ``done`` writes are only a prompt to copy the tmpfs. The
            # wrapper's post-command size/digest decides whether the bytes we
            # copied are the completed artifact; a mismatch fails the build.
            if artifact is not None and reported_digest is not None:
                if (
                    reported_digest == "missing"
                    or reported_size != len(artifact)
                    or artifact_digest is None
                    or reported_digest != artifact_digest.split(":", 1)[1]
                    or reported_code != exit_code
                ):
                    artifact = None
                    artifact_digest = None
                    log_truncated = True
            elif artifact is not None:
                artifact = None
                artifact_digest = None
                log_truncated = True
            quota_hits = _quota_events(files)
            status = (
                "completed"
                if exit_code == 0 and artifact is not None and capture_error is None
                else "build_failed"
            )
            if timed_out:
                status = "timeout"
            elif capture_error is not None:
                status = "infra_error"
            elif state.get("OOMKilled") or quota_hits:
                status = "resource_limited"
            metadata = {
                "build_command": ["/bin/sh", "/fixture/build.sh", version],
                "build_recipe_digest": _digest_bytes(materials / "build.sh"),
                "exit_code": exit_code,
                "timed_out": timed_out,
                "oom_killed": bool(state.get("OOMKilled")),
                "limits_hit": quota_hits,
                "truncated_roles": list(truncated_roles),
            }
            if capture_error is not None:
                metadata["capture_error"] = capture_error
            if cleanup_error is not None:
                metadata["cleanup_errors"] = [cleanup_error]
            return BuildResult(
                version=version,
                status=status,
                exit_code=exit_code,
                duration_seconds=duration,
                container_id=name,
                image_digest=self.image_digest,
                compile_args=tuple(compile_args),
                artifact_digest=artifact_digest,
                log=log,
                log_truncated=truncated or log_truncated,
                artifact=artifact,
                metadata=metadata,
                capture_error=capture_error,
                truncated_roles=truncated_roles,
            )
        finally:
            # _start_and_wait already removed the container. If it could not,
            # the error is carried in metadata/log_truncated above. A container
            # left behind is reported through self.cleanup_errors.
            pass

    def _stage_shim(
        self,
        *,
        work_fd: int,
        work: Path,
        shim_name: str,
        real_compiler: str,
        log_path: str,
        destination: str,
        mounts: list[tuple[str, str, bool]],
        shim_names: list[str],
    ) -> None:
        script = render_cc_shim_script(
            real_compiler=real_compiler,
            log_path=log_path,
        )
        try:
            fileio.write_regular_file(
                shim_name,
                script.encode("utf-8"),
                mode=0o555,
                dir_fd=work_fd,
                parent_path=work,
            )
        except fileio.UnsafeFileError as error:
            raise SandboxPolicyError(
                f"cannot write {shim_name} script safely: {error.message}"
            ) from error
        shim_names.append(shim_name)
        shim_path = _verify_bound_shim_file(
            work_fd, work, shim_name, label=shim_name
        )
        mounts.append((str(shim_path), destination, True))

    def _build_with_spec(
        self,
        *,
        version: str,
        materials: Path,
        build_spec: Mapping[str, Any],
        plan: BuildSpecExecutionPlan,
        compile_args: Sequence[str],
        deadline_seconds: float,
    ) -> BuildResult:
        work_fd, work, work_leaf, work_identity = _create_safe_build_work_dir(
            self.run_root, version
        )
        mounts: list[tuple[str, str, bool]] = [(str(materials), "/fixture", True)]
        shim_names: list[str] = []
        started = time.monotonic()
        name: str | None = None
        try:
            try:
                if plan.kind == "make":
                    assert plan.cc_shim_destination is not None
                    assert plan.provenance_face_container_path is not None
                    self._stage_shim(
                        work_fd=work_fd,
                        work=work,
                        shim_name="cc-shim",
                        real_compiler=DEFAULT_CC_SHIM_COMPILER,
                        log_path=plan.provenance_face_container_path,
                        destination=plan.cc_shim_destination,
                        mounts=mounts,
                        shim_names=shim_names,
                    )
                    if plan.cxx_shim_destination is not None:
                        self._stage_shim(
                            work_fd=work_fd,
                            work=work,
                            shim_name="cxx-shim",
                            real_compiler=DEFAULT_CXX_SHIM_COMPILER,
                            log_path=plan.provenance_face_container_path,
                            destination=plan.cxx_shim_destination,
                            mounts=mounts,
                            shim_names=shim_names,
                        )
            finally:
                os.close(work_fd)
                work_fd = -1

            container_env: dict[str, str] = {
                "TMPDIR": "/work",
                "HOME": "/work",
                "ASAN_OPTIONS": "detect_leaks=0",
                "DATACON_BUILD_VERSION": version,
            }
            container_env.update(plan.env)
            effective_env_error = build_provenance.validate_effective_build_env(
                container_env,
                allowed_executor_keys={
                    "TMPDIR",
                    "HOME",
                    "ASAN_OPTIONS",
                    "DATACON_BUILD_VERSION",
                },
            )
            if effective_env_error is not None:
                raise SandboxError(
                    effective_env_error,
                    reason_code=build_provenance.BUILD_PROVENANCE_MISSING,
                )

            extra_copy_paths: list[tuple[str, int]] = []
            seen_copy_paths: set[str] = {
                "/work/parser",
                "/work/pids.events",
                "/work/memory.events",
            }
            for _rel, container_path in plan.output_container_paths:
                if container_path not in seen_copy_paths:
                    extra_copy_paths.append((container_path, MAX_ARTIFACT_BYTES))
                    seen_copy_paths.add(container_path)
            if (
                plan.provenance_face_container_path is not None
                and plan.provenance_face_container_path not in seen_copy_paths
            ):
                extra_copy_paths.append(
                    (plan.provenance_face_container_path, MAX_PROVENANCE_FACE_BYTES)
                )
                seen_copy_paths.add(plan.provenance_face_container_path)

            name, _ = self._create(
                suffix=f"build-{version}",
                command=build_runner_command(plan, build_version=version),
                mounts=mounts,
                env=container_env,
            )
            (
                stdout,
                stderr,
                files,
                truncated_streams,
                state,
                timed_out,
                exit_code,
                cleanup_error,
            ) = self._start_and_wait(
                name,
                deadline_seconds=deadline_seconds,
                artifact=True,
                extra_copy_paths=extra_copy_paths,
            )
            duration = time.monotonic() - started
            report_match = None
            for match in re.finditer(
                rb"DATACON_BUILD_RESULT code=(-?\d+) size=(-?\d+) digest=([0-9a-f]{64}|missing)",
                stderr,
            ):
                report_match = match
            reported_code = reported_size = reported_digest = None
            if report_match is not None:
                reported_code = int(report_match.group(1))
                reported_size = int(report_match.group(2))
                reported_digest = report_match.group(3).decode("ascii")
            log_bytes = re.sub(
                rb"\n?DATACON_BUILD_RESULT code=-?\d+ size=-?\d+ digest=(?:[0-9a-f]{64}|missing)\n?",
                b"",
                stdout + stderr,
            )
            capture_error = state.pop("_capture_error", None)
            log, log_truncated = _truncate_log(log_bytes)
            declared_copy_paths: set[str] = {
                container_path for _rel, container_path in plan.output_container_paths
            }
            if plan.provenance_face_container_path is not None:
                declared_copy_paths.add(plan.provenance_face_container_path)
            relevant_truncated_streams = {
                item
                for item in truncated_streams
                if item != "/work/parser" or "/work/parser" in declared_copy_paths
            }
            truncated = log_truncated or bool(relevant_truncated_streams)
            truncated_roles = tuple(
                role for role in STREAM_ROLES if role in truncated_streams
            )
            artifact = files.get(plan.primary_output_container_path)
            if (
                plan.primary_output_container_path in truncated_streams
                or (artifact is not None and len(artifact) > MAX_ARTIFACT_BYTES)
            ):
                artifact = None
                truncated = True
            if capture_error is not None:
                artifact = None
                truncated = True
            artifact_digest = (
                "sha256:" + hashlib.sha256(artifact).hexdigest()
                if artifact is not None
                else None
            )
            if artifact is not None and reported_digest is not None:
                if (
                    reported_digest == "missing"
                    or reported_size != len(artifact)
                    or artifact_digest is None
                    or reported_digest != artifact_digest.split(":", 1)[1]
                    or reported_code != exit_code
                ):
                    artifact = None
                    artifact_digest = None
                    truncated = True
            elif artifact is not None:
                artifact = None
                artifact_digest = None
                truncated = True

            provenance_face_name = plan.provenance_face_name
            provenance_face: bytes | None = None
            provenance_face_truncated = False
            if plan.kind == "shell":
                provenance_face_truncated = log_truncated or bool(
                    truncated_streams & set(STREAM_ROLES)
                )
                if capture_error is None and not provenance_face_truncated:
                    provenance_face = log
            else:
                face_path = plan.provenance_face_container_path
                assert face_path is not None
                if face_path in truncated_streams:
                    provenance_face_truncated = True
                    truncated = True
                if capture_error is None and not provenance_face_truncated:
                    raw_face = files.get(face_path)
                    if (
                        raw_face is not None
                        and len(raw_face) > MAX_PROVENANCE_FACE_BYTES
                    ):
                        provenance_face_truncated = True
                        truncated = True
                    else:
                        provenance_face = raw_face

            quota_hits = _quota_events(files)
            outputs_meta: dict[str, Any] = {}
            output_artifacts: list[BuildOutput] = []
            outputs_valid = True
            for rel_out, c_path in plan.output_container_paths:
                out_bytes = (
                    artifact
                    if c_path == plan.primary_output_container_path
                    else files.get(c_path)
                )
                valid = (
                    out_bytes is not None
                    and c_path not in truncated_streams
                    and len(out_bytes) <= MAX_ARTIFACT_BYTES
                )
                if valid and out_bytes is not None:
                    out_digest = "sha256:" + hashlib.sha256(out_bytes).hexdigest()
                    outputs_meta[rel_out] = {
                        "size_bytes": len(out_bytes),
                        "sha256": out_digest,
                    }
                    archive_path = (
                        "parser"
                        if plan.primary_output == "parser"
                        and len(plan.outputs) == 1
                        else rel_out
                    )
                    output_artifacts.append(
                        BuildOutput(
                            relative_path=rel_out,
                            archive_path=archive_path,
                            data=out_bytes,
                            digest=out_digest,
                        )
                    )
                else:
                    outputs_meta[rel_out] = None
                    outputs_valid = False
            status = (
                "completed"
                if (
                    exit_code == 0
                    and artifact is not None
                    and outputs_valid
                    and capture_error is None
                )
                else "build_failed"
            )
            if timed_out:
                status = "timeout"
            elif capture_error is not None:
                status = "infra_error"
            elif state.get("OOMKilled") or quota_hits:
                status = "resource_limited"

            metadata: dict[str, Any] = {
                "build_spec_kind": plan.kind,
                "build_command": list(plan.build),
                "build_recipe_digest": jsonutil.digest_json(dict(build_spec)),
                "outputs": outputs_meta,
                "primary_output": plan.primary_output,
                "provenance_face_name": provenance_face_name,
                "provenance_face_truncated": provenance_face_truncated,
                "exit_code": exit_code,
                "timed_out": timed_out,
                "oom_killed": bool(state.get("OOMKilled")),
                "limits_hit": quota_hits,
                "truncated_roles": list(truncated_roles),
            }
            if plan.configure:
                metadata["configure_command"] = list(plan.configure)
            if plan.install:
                metadata["install_command"] = list(plan.install)
            if provenance_face is not None:
                metadata["provenance_face_size"] = len(provenance_face)
                metadata["provenance_face_sha256"] = (
                    "sha256:" + hashlib.sha256(provenance_face).hexdigest()
                )
            if capture_error is not None:
                metadata["capture_error"] = capture_error
            if cleanup_error is not None:
                metadata["cleanup_errors"] = [cleanup_error]

            resolved_compile_args = (
                tuple(compile_args)
                if compile_args
                else tuple(build_spec["declared_compile_flags"])
            )
            return BuildResult(
                version=version,
                status=status,
                exit_code=exit_code,
                duration_seconds=duration,
                container_id=name,
                image_digest=self.image_digest,
                compile_args=resolved_compile_args,
                artifact_digest=artifact_digest,
                log=log,
                log_truncated=truncated or log_truncated,
                artifact=artifact,
                metadata=metadata,
                capture_error=capture_error,
                truncated_roles=truncated_roles,
                provenance_face=provenance_face,
                provenance_face_name=provenance_face_name,
                outputs=tuple(output_artifacts),
            )
        finally:
            if work_fd >= 0:
                os.close(work_fd)
            _cleanup_safe_build_work_dir(
                self.run_root, version, work_leaf, work_identity, shim_names
            )

    def replay(
        self,
        version: str,
        phase: str,
        *,
        artifact_path: Path | str,
        input_path: Path | str,
        asan_options: str,
        timeout_seconds: float,
        deadline_seconds: float | None = None,
        expected_artifact_digest: str | None = None,
        expected_input_digest: str | None = None,
    ) -> ReplayResult:
        artifact = Path(artifact_path)
        input_file = Path(input_path)
        if not artifact.is_file() or artifact.is_symlink():
            raise SandboxError("built artifact is missing")
        if expected_artifact_digest is not None:
            artifact_bytes = _read_bounded_file(
                artifact,
                max_bytes=MAX_ARTIFACT_BYTES,
                label="built artifact is not readable",
                reason_code="EVIDENCE_WRITE_FAILED",
            )
            actual = "sha256:" + hashlib.sha256(artifact_bytes).hexdigest()
            if actual != expected_artifact_digest:
                raise SandboxError(
                    "built artifact changed before replay",
                    reason_code="PLAN_MISMATCH",
                )
        if not input_file.is_file() or input_file.is_symlink():
            raise SandboxError("replay input is missing")
        # Hash the exact bytes before the container exists. The result records
        # this digest instead of re-reading the input after the run, so a
        # post-run replacement cannot be mistaken for the executed bytes.
        input_bytes = _read_bounded_file(
            input_file,
            max_bytes=MAX_MATERIAL_BYTES,
            label="replay input is not readable",
            reason_code="MATERIAL_MISSING",
        )
        input_digest = "sha256:" + hashlib.sha256(input_bytes).hexdigest()
        if (
            expected_input_digest is not None
            and input_digest != expected_input_digest
        ):
            raise SandboxError(
                "replay input changed before replay",
                reason_code="PLAN_MISMATCH",
            )
        timeout = timeout_seconds
        if deadline_seconds is not None:
            timeout = min(timeout, max(0.5, deadline_seconds))
        artifact.chmod(0o555)
        input_file.chmod(0o444)
        # The target is PID 1. Its exit status is the container's status via
        # docker wait, and its stdout/stderr come from the live attach capture;
        # the target never writes a completion flag or an exit-code file.
        name = None
        started = time.monotonic()
        try:
            name, _ = self._create(
                suffix=f"replay-{version}-{phase}",
                command=["/bin/sh", "-c", "exec /artifact/parser < /input/input"],
                mounts=[
                    (str(artifact), "/artifact/parser", True),
                    (str(input_file), "/input/input", True),
                ],
                env={
                    "TMPDIR": "/work",
                    "HOME": "/work",
                    "ASAN_OPTIONS": asan_options,
                },
            )
            (
                raw_stdout,
                raw_stderr,
                _files,
                _truncated_streams,
                state,
                timed_out,
                exit_code,
                cleanup_error,
            ) = self._start_and_wait(name, deadline_seconds=timeout)
        finally:
            pass
        duration = time.monotonic() - started
        capture_error = state.pop("_capture_error", None)
        stdout, truncated_out = _truncate_log(raw_stdout)
        stderr, truncated_err = _truncate_log(raw_stderr)
        truncated_roles = tuple(
            role for role in STREAM_ROLES if role in _truncated_streams
        )
        log_truncated = (
            truncated_out
            or truncated_err
            or bool(_truncated_streams)
            or capture_error is not None
            or exit_code is None
        )
        signature = parse_asan(stderr.decode("utf-8", "replace"))
        quota_hit = (
            bool(state.get("OOMKilled"))
            or (exit_code == 137 and not timed_out)
        )
        status = "completed"
        if timed_out:
            status = "timeout"
        elif capture_error is not None or exit_code is None:
            status = "infra_error"
        elif quota_hit:
            status = "resource_limited"
        metadata: dict[str, Any] = {
            "image_digest": self.image_digest,
            "asan_options": asan_options,
            "oom_killed": bool(state.get("OOMKilled")),
            "limits_hit": [],
            "timeout_seconds": timeout,
            "truncated_roles": list(truncated_roles),
        }
        if capture_error is not None:
            metadata["capture_error"] = capture_error
        if cleanup_error is not None:
            metadata["cleanup_errors"] = [cleanup_error]
        return ReplayResult(
            version=version,
            phase=phase,
            status=status,
            exit_code=exit_code,
            duration_seconds=duration,
            container_id=name,
            input_digest=input_digest,
            stdout=stdout,
            stderr=stderr,
            signature=signature,
            timed_out=timed_out,
            quota_hit=quota_hit,
            log_truncated=log_truncated,
            metadata=metadata,
            capture_error=capture_error,
            truncated_roles=truncated_roles,
        )


    def fuzz(
        self,
        *,
        fuzzer_path: Path | str,
        corpus_dir: Path | str,
        rng_seed: int,
        max_total_time: int,
        deadline_seconds: float,
        max_len: int,
        asan_options: str,
        input_timeout_seconds: int = 10,
        expected_fuzzer_digest: str | None = None,
    ) -> FuzzResult:
        """Run one time-bounded libFuzzer search in the standard isolation profile.

        The container is created by the same ``container_create_args`` baseline
        as build/replay (no network, non-root, read-only root, cap-drop ALL,
        no-new-privileges, pinned seccomp) and ``validate_host_config`` proves
        it after create. Only the fuzzer binary and the seed corpus are bind
        mounted, both read-only; every write lands on the bounded ``/work``
        tmpfs. No Docker socket, evidence or campaign directory is mounted.
        """
        fuzzer = Path(fuzzer_path)
        if fuzzer.is_symlink() or not fuzzer.is_file():
            raise SandboxError("built fuzzer is missing")
        if expected_fuzzer_digest is not None:
            data = _read_bounded_file(
                fuzzer,
                max_bytes=MAX_ARTIFACT_BYTES,
                label="built fuzzer is not readable",
                reason_code="EVIDENCE_WRITE_FAILED",
            )
            actual = "sha256:" + hashlib.sha256(data).hexdigest()
            if actual != expected_fuzzer_digest:
                raise SandboxError(
                    "built fuzzer changed before fuzzing", reason_code="PLAN_MISMATCH"
                )
        validate_fuzz_corpus_dir(corpus_dir)
        fuzzer.chmod(0o555)
        rss_limit_mb = max(64, self.limits.memory_mib - 256)
        command = fuzz_runner_command(
            rng_seed=rng_seed,
            max_total_time=max_total_time,
            max_len=max_len,
            rss_limit_mb=rss_limit_mb,
            input_timeout_seconds=input_timeout_seconds,
        )
        started = time.monotonic()
        name, _ = self._create(
            suffix="fuzz",
            command=command,
            mounts=[
                (str(fuzzer), FUZZER_CONTAINER_PATH, True),
                (str(Path(corpus_dir)), CORPUS_CONTAINER_PATH, True),
            ],
            env={
                "TMPDIR": "/work",
                "HOME": "/work",
                "ASAN_OPTIONS": asan_options,
            },
        )
        (
            raw_stdout,
            raw_stderr,
            files,
            truncated_files,
            state,
            timed_out,
            exit_code,
            cleanup_error,
        ) = self._start_and_wait(
            name,
            deadline_seconds=deadline_seconds,
            artifact=True,
            extra_copy_paths=[
                (f"/work/crash-{index}", FUZZ_MAX_CRASH_BYTES)
                for index in range(FUZZ_MAX_CRASH_FILES)
            ],
        )
        duration = time.monotonic() - started
        capture_error = state.pop("_capture_error", None)
        log, log_truncated = _truncate_log(raw_stderr + raw_stdout)
        markers = list(_FUZZ_RESULT.finditer(raw_stderr))
        fuzzer_code: int | None = None
        reported_crashes = 0
        if markers:
            fuzzer_code = int(markers[-1].group(1))
            reported_crashes = int(markers[-1].group(2))
        elif not timed_out and capture_error is None:
            capture_error = "the fuzz runner did not report a result"
        crashes: list[bytes] = []
        crash_truncated = False
        for index in range(min(reported_crashes, FUZZ_MAX_CRASH_FILES)):
            path = f"/work/crash-{index}"
            if path in truncated_files:
                crash_truncated = True
                continue
            data = files.get(path)
            if data is None:
                capture_error = capture_error or (
                    f"reported crash {index} could not be copied"
                )
                continue
            crashes.append(data)
        oom = bool(state.get("OOMKilled"))
        status = "completed"
        if timed_out:
            status = "timeout"
        elif capture_error is not None or exit_code is None:
            status = "infra_error"
        elif oom:
            status = "resource_limited"
        metadata: dict[str, Any] = {
            "image_digest": self.image_digest,
            "asan_options": asan_options,
            "fuzzer_exit_code": fuzzer_code,
            "reported_crashes": reported_crashes,
            "oom_killed": oom,
            "deadline_seconds": deadline_seconds,
            "max_len": max_len,
            "rss_limit_mb": rss_limit_mb,
            "input_timeout_seconds": input_timeout_seconds,
            "limits_hit": _quota_events(files),
        }
        if cleanup_error is not None:
            metadata["cleanup_errors"] = [cleanup_error]
        return FuzzResult(
            status=status,
            exit_code=fuzzer_code,
            duration_seconds=duration,
            container_id=name,
            rng_seed=rng_seed,
            max_total_time_seconds=max_total_time,
            log=log,
            log_truncated=log_truncated or "stderr" in truncated_files,
            crashes=tuple(crashes),
            crash_truncated=crash_truncated,
            metadata=metadata,
            capture_error=capture_error,
        )


def _digest_bytes(path: Path) -> str:
    data = _read_bounded_file(
        path,
        max_bytes=MAX_MATERIAL_BYTES,
        label="build recipe is not readable",
        reason_code="MATERIAL_MISSING",
    )
    return "sha256:" + hashlib.sha256(data).hexdigest()

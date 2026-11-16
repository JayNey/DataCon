"""One-shot Docker sandbox for building and replaying untrusted targets.

The sandbox is deliberately a thin, auditable adapter over the Docker CLI. It
never invokes a shell on the host with target-derived text: mount sources are
validator-checked absolute paths, container commands are fixed templates, and
every container is labelled and removed after use.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
import hashlib
import json
import os
import re
import shlex
import shutil
import stat
import subprocess
import time
import uuid
from typing import Any, Iterable, Mapping, Sequence

from datacon import fileio
from datacon.asan import ASanSignature, parse_asan
from datacon.cases import MAX_MATERIAL_BYTES

MIB = 1024 * 1024
MAX_LOG_BYTES = 16 * 1024 * 1024
MAX_ARTIFACT_BYTES = 128 * 1024 * 1024
# Docker's json-file driver rotates at this size. It bounds the disk a hostile
# stdout/stderr producer can consume and the memory `docker logs` can return.
LOG_MAX_BYTES = 32 * 1024 * 1024
LOG_MAX_FILES = 1
MAX_PREVIEW_BYTES = 512
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
            "capture_error": self.capture_error,
            **self.metadata,
        }
        payload["capture_error"] = self.capture_error
        return payload


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
            "capture_error": self.capture_error,
            **self.metadata,
        }
        payload["capture_error"] = self.capture_error
        return payload


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
    log_max_bytes: int = LOG_MAX_BYTES,
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
        "--log-driver",
        "json-file",
        "--log-opt",
        f"max-size={log_max_bytes}b",
        "--log-opt",
        f"max-file={LOG_MAX_FILES}",
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
        if key.upper().startswith(("DATACON_", "GITHUB_", "AWS_", "TOKEN", "SECRET")):
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


def _parse_log_size(value: Any) -> int:
    """Parse Docker's ``max-size`` value (bytes with an optional unit)."""
    text = str(value).strip().lower()
    if not text:
        raise ValueError("empty log size")
    multiplier = 1
    if text[-1] in ("b", "k", "m", "g"):
        suffix = text[-1]
        text = text[:-1]
        multiplier = {
            "b": 1,
            "k": 1024,
            "m": 1024 * 1024,
            "g": 1024 * 1024 * 1024,
        }[suffix]
    return int(text) * multiplier


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
            source = Path(parts[0])
            if not source.is_absolute():
                raise SandboxPolicyError("a bind mount source is not absolute")
            actual.append((str(source), parts[1], True))

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
    log_max_bytes: int = LOG_MAX_BYTES,
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
    for field in ("PidMode", "UTSMode", "UsernsMode"):
        if config.get(field) not in (None, "", "private"):
            raise SandboxPolicyError(
                f"container {field} must be private, not {config.get(field)!r}"
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
    if log_config.get("Type") not in ("json-file", "local"):
        raise SandboxPolicyError("container log driver is not the bounded json-file")
    log_options = log_config.get("Config") or {}
    if not isinstance(log_options, Mapping):
        raise SandboxPolicyError("container log options are invalid")
    try:
        configured_size = _parse_log_size(log_options.get("max-size"))
        configured_files = int(str(log_options.get("max-file")))
    except (TypeError, ValueError) as error:
        raise SandboxPolicyError("container log rotation is not bounded") from error
    if configured_size != log_max_bytes or configured_files != LOG_MAX_FILES:
        raise SandboxPolicyError("container log rotation differs from the policy")

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
        """Read one bounded tmpfs file while the container is still alive."""
        if not relative.startswith("/work/") or any(
            character in relative for character in " \t\r\n'\"`$;"
        ):
            raise SandboxPolicyError("unsafe sandbox stream path")
        size_result = self._docker(
            ["exec", name, "sh", "-c", f"wc -c < {relative} 2>/dev/null || echo 0"],
            timeout=30,
        )
        try:
            size = int(size_result.stdout.decode("ascii", "replace").strip())
        except ValueError:
            size = 0
        data_result = self._docker(
            ["exec", name, "sh", "-c", f"head -c {limit + 1} -- {relative}"],
            timeout=60,
        )
        data = data_result.stdout if data_result.returncode == 0 else b""
        return data[:limit], size, size > limit or len(data) > limit

    def _start_and_wait(
        self,
        name: str,
        *,
        deadline_seconds: float,
        artifact: bool = False,
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
        """Start a container and make its real exit authoritative.

        The target never owns the completion signal: replay uses ``exec`` so
        the target is PID 1 and ``docker wait`` reports its exit code. Stdout
        and stderr are read from the bounded json-file log, so a target that
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
        stdout = b""
        stderr = b""
        state: dict[str, Any] = {}
        started = time.monotonic()
        start = self._docker(["start", name], timeout=30)
        if start.returncode != 0:
            cleanup_error = self._cleanup_failure(name)
            message = "cannot start sandbox container: " + start.stderr.decode(
                "utf-8", "replace"
            )[:500]
            if cleanup_error is not None:
                message += f"; cleanup also failed: {cleanup_error}"
            raise SandboxError(message)
        try:
            if artifact:
                while time.monotonic() - started < deadline_seconds:
                    check = self._docker(
                        ["exec", name, "test", "-e", "/work/done"], timeout=10
                    )
                    if check.returncode == 0:
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
                for relative, limit in (
                    ("/work/parser", MAX_ARTIFACT_BYTES),
                    ("/work/pids.events", MAX_LOG_BYTES),
                    ("/work/memory.events", MAX_LOG_BYTES),
                ):
                    data, _size, was_truncated = self._copy_work_path(
                        name, relative, limit
                    )
                    if data or was_truncated:
                        files[relative] = data
                        if was_truncated:
                            truncated.add(relative)
                if not timed_out:
                    self._docker(
                        ["exec", name, "touch", "/work/release"], timeout=10
                    )
            if timed_out:
                try:
                    self._docker(["kill", name], timeout=30)
                except SandboxError:
                    pass
            remaining = max(1.0, deadline_seconds - (time.monotonic() - started))
            wait_error: str | None = None
            try:
                wait = self._docker(["wait", name], timeout=remaining)
            except SandboxError as error:
                if error.reason_code != "TIMEOUT":
                    raise
                timed_out = True
                try:
                    self._docker(["kill", name], timeout=30)
                except SandboxError:
                    pass
                wait = self._docker(["wait", name], timeout=30)
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
            inspect_payload: dict[str, Any] | None = None
            inspect_error: str | None = None
            try:
                inspect_payload = self._inspect(name)
                raw_state = inspect_payload.get("State")
                state = dict(raw_state) if isinstance(raw_state, Mapping) else {}
            except SandboxError as error:
                state = {}
                inspect_error = error.message
            capture_errors: list[str] = []
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
            logs = self._docker(["logs", name], timeout=60)
            if logs.returncode == 0:
                stdout = logs.stdout
                stderr = logs.stderr
            else:
                detail = logs.stderr.decode("utf-8", "replace").strip()
                capture_errors.append(
                    f"docker logs failed (rc={logs.returncode}): "
                    + (detail[:300] or "no stderr")
                )
                truncated.add("logs")
            if capture_errors:
                state["_capture_error"] = "; ".join(capture_errors)
        finally:
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
            start = self._docker(["start", name], timeout=30)
            if start.returncode != 0:
                raise SandboxUnavailable("cannot start isolation probe")
            try:
                wait = self._docker(["wait", name], timeout=deadline_seconds)
            except SandboxError as error:
                if error.reason_code == "TIMEOUT":
                    raise SandboxPolicyError("isolation probe timed out") from error
                raise
            if wait.returncode != 0:
                raise SandboxPolicyError("isolation probe did not complete")
            logs = self._docker(["logs", name], timeout=30)
            raw = (logs.stdout + logs.stderr).decode("utf-8", "replace")
            exit_code = int(wait.stdout.decode("utf-8", "replace").strip() or "1")
            inspect = self._inspect(name)
            state = inspect.get("State", {})
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
    ) -> BuildResult:
        if version not in ("vulnerable", "fixed"):
            raise SandboxError("build version is invalid")
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
        if not (materials / "build.sh").is_file():
            raise SandboxError("reviewed build recipe is missing")
        work = self.run_root / "build" / version / uuid.uuid4().hex
        work.mkdir(parents=True, exist_ok=True)
        # The build command's stdout/stderr go to the bounded container log,
        # not to a target-writable file. The wrapper only reports the artifact
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
            elif state.get("OOMKilled") or quota_hits:
                status = "resource_limited"
            elif capture_error is not None:
                status = "infra_error"
            metadata = {
                "build_command": ["/bin/sh", "/fixture/build.sh", version],
                "build_recipe_digest": _digest_bytes(materials / "build.sh"),
                "exit_code": exit_code,
                "timed_out": timed_out,
                "oom_killed": bool(state.get("OOMKilled")),
                "limits_hit": quota_hits,
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
            )
        finally:
            # _start_and_wait already removed the container. If it could not,
            # the error is carried in metadata/log_truncated above. A container
            # left behind is reported through self.cleanup_errors.
            pass

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
        # docker wait, and its stdout/stderr go to the bounded Docker log; the
        # target never writes a completion flag or an exit-code file.
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
        log_truncated = (
            truncated_out or truncated_err or bool(_truncated_streams)
        )
        signature = parse_asan(stderr.decode("utf-8", "replace"))
        quota_hit = (
            bool(state.get("OOMKilled"))
            or (exit_code == 137 and not timed_out)
        )
        status = "completed"
        if timed_out:
            status = "timeout"
        elif quota_hit:
            status = "resource_limited"
        elif capture_error is not None or exit_code is None:
            status = "infra_error"
        metadata: dict[str, Any] = {
            "image_digest": self.image_digest,
            "asan_options": asan_options,
            "oom_killed": bool(state.get("OOMKilled")),
            "limits_hit": [],
            "timeout_seconds": timeout,
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
        )


def _digest_bytes(path: Path) -> str:
    data = _read_bounded_file(
        path,
        max_bytes=MAX_MATERIAL_BYTES,
        label="build recipe is not readable",
        reason_code="MATERIAL_MISSING",
    )
    return "sha256:" + hashlib.sha256(data).hexdigest()

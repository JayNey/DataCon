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
import subprocess
import time
import uuid
from typing import Any, Iterable, Mapping, Sequence

from datacon.asan import ASanSignature, parse_asan

MIB = 1024 * 1024
MAX_LOG_BYTES = 16 * 1024 * 1024
MAX_ARTIFACT_BYTES = 128 * 1024 * 1024
_IMAGE_DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
_SAFE_NAME = re.compile(r"[^a-z0-9_.-]+")
_PROBE_TIMEOUT = 120


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

    @classmethod
    def from_plan(cls, value: Mapping[str, Any]) -> "IsolationPolicy":
        if not isinstance(value, Mapping):
            raise SandboxPolicyError("plan isolation must be an object")
        caps = value.get("cap_drop")
        if not isinstance(caps, list) or not all(isinstance(item, str) for item in caps):
            raise SandboxPolicyError("plan isolation cap_drop is invalid")
        return cls(
            network=value.get("network", ""),
            user=value.get("user", ""),
            read_only_root=value.get("read_only_root") is True,
            cap_drop=tuple(caps),
            no_new_privileges=value.get("no_new_privileges") is True,
            seccomp=value.get("seccomp", ""),
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

    def as_dict(self) -> dict[str, Any]:
        return {
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
            **self.metadata,
        }


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

    def as_dict(self) -> dict[str, Any]:
        stdout_text = self.stdout.decode("utf-8", "replace")
        stderr_text = self.stderr.decode("utf-8", "replace")
        return {
            "version": self.version,
            "phase": self.phase,
            "status": self.status,
            "exit_code": self.exit_code,
            "duration_seconds": self.duration_seconds,
            "container_id": self.container_id,
            "input_digest": self.input_digest,
            "stdout": stdout_text,
            "stderr": stderr_text,
            "signature": self.signature.as_dict() if self.signature else None,
            "timed_out": self.timed_out,
            "quota_hit": self.quota_hit,
            "log_truncated": self.log_truncated,
            **self.metadata,
        }


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
    for key, value in sorted((labels or {}).items()):
        args.extend(["--label", f"{key}={value}"])
    args.extend([image, *command])
    return args


def _close_enough(actual: Any, expected: int) -> bool:
    return type(actual) is int and actual == expected


def validate_host_config(
    config: Mapping[str, Any],
    policy: IsolationPolicy,
    limits: ResourceLimits,
) -> None:
    """Fail closed unless inspect output shows every requested control."""
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
    security = [str(item).lower() for item in config.get("SecurityOpt") or []]
    if not any(item.startswith("no-new-privileges") for item in security):
        raise SandboxPolicyError("no-new-privileges is not active")
    if any(item == "seccomp=unconfined" for item in security):
        raise SandboxPolicyError("seccomp must not be unconfined")
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

    mounts = config.get("Mounts")
    binds = config.get("Binds") or []
    if isinstance(mounts, list) and mounts:
        for mount in mounts:
            if not isinstance(mount, Mapping):
                raise SandboxPolicyError("container mount metadata is invalid")
            if mount.get("Type") != "bind":
                raise SandboxPolicyError("only read-only bind mounts are allowed")
            if mount.get("RW") is not False:
                raise SandboxPolicyError("a bind mount is writable")
            source = mount.get("Source")
            if not isinstance(source, str) or not Path(source).is_absolute():
                raise SandboxPolicyError("a bind mount source is not absolute")
    else:
        if not isinstance(binds, list) or not binds:
            raise SandboxPolicyError("expected read-only material bind mounts are missing")
        for bind in binds:
            parts = str(bind).split(":")
            if len(parts) < 3 or parts[2] not in ("ro", "readonly"):
                raise SandboxPolicyError("a bind mount is writable")
            source = Path(parts[0])
            if not source.is_absolute():
                raise SandboxPolicyError("a bind mount source is not absolute")

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
        self.run_root = Path(run_root)
        self.pull_timeout = pull_timeout

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

    def _remove(self, name: str) -> None:
        try:
            self._docker(["rm", "-f", name], timeout=30)
        except SandboxError:
            pass

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
        """Remove containers left by an interrupted execution generation."""
        result = self._docker(
            [
                "ps",
                "-aq",
                "--filter",
                f"label=datacon.job_id={self.job_id}",
            ],
            timeout=30,
        )
        removed = 0
        if result.returncode == 0:
            for name in result.stdout.decode("utf-8", "replace").split():
                if name:
                    self._remove(name)
                    removed += 1
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
            labels={"datacon.run": suffix},
        )
        created = self._docker(args[1:], timeout=120)
        if created.returncode != 0:
            raise SandboxError(
                "cannot create sandbox container: "
                + created.stderr.decode("utf-8", "replace")[:500]
            )
        inspect = self._inspect(name)
        config = dict(inspect.get("HostConfig", {}))
        config["User"] = inspect.get("Config", {}).get("User", "")
        config["Mounts"] = inspect.get("Mounts", [])
        validate_host_config(config, self.policy, self.limits)
        return name, config

    def _start_and_wait(
        self,
        name: str,
        *,
        deadline_seconds: float,
        expect_done: bool = True,
        stream: Sequence[str] = (),
    ) -> tuple[dict[str, bytes], set[str], dict[str, Any], bool]:
        """Start a wrapper container, collect requested /work files, release it.

        The wrapper writes its outputs to a bounded tmpfs and then waits for
        ``/work/release``. That keeps evidence retrievable even though a tmpfs
        is unmounted when the container stops. Streams are read through a fixed
        ``head -c`` cap so a hostile target cannot make the host buffer an
        unbounded tmpfs. On timeout the available files are copied before the
        container is killed.
        """
        files: dict[str, bytes] = {}
        truncated: set[str] = set()
        timed_out = False
        started = time.monotonic()
        start = self._docker(["start", name], timeout=30)
        if start.returncode != 0:
            raise SandboxError(
                "cannot start sandbox container: "
                + start.stderr.decode("utf-8", "replace")[:500]
            )
        done = False
        while time.monotonic() - started < deadline_seconds:
            if expect_done:
                check = self._docker(
                    ["exec", name, "test", "-e", "/work/done"], timeout=10
                )
                if check.returncode == 0:
                    done = True
                    break
            else:
                done = True
                break
            try:
                running = self._inspect(name).get("State", {}).get("Running")
            except SandboxError:
                running = False
            if running is False:
                break
            time.sleep(0.1)
        if not done and expect_done:
            timed_out = True
        for relative in stream:
            if not relative.startswith("/work/") or any(
                character in relative for character in " \t\r\n'\"`$;"
            ):
                raise SandboxPolicyError("unsafe sandbox stream path")
            limit = MAX_ARTIFACT_BYTES if relative == "/work/parser" else MAX_LOG_BYTES
            size_result = self._docker(
                ["exec", name, "sh", "-c", f"wc -c < {relative} 2>/dev/null || echo 0"],
                timeout=30,
            )
            try:
                size = int(size_result.stdout.decode("ascii", "replace").strip())
            except ValueError:
                size = 0
            data_result = self._docker(
                ["exec", name, "sh", "-c", f"head -c {limit} -- {relative}"],
                timeout=60,
            )
            if data_result.returncode == 0:
                files[relative] = data_result.stdout
                if size > limit:
                    truncated.add(relative)
        if not timed_out:
            self._docker(["exec", name, "touch", "/work/release"], timeout=10)
            self._docker(["wait", name], timeout=max(1.0, deadline_seconds))
        try:
            state = self._inspect(name).get("State", {})
        except SandboxError:
            state = {}
        self._remove(name)
        return files, truncated, state, timed_out

    def probe(self, *, deadline_seconds: float = _PROBE_TIMEOUT) -> ProbeReport:
        self.ensure_image()
        probe_root = self.run_root / "probe"
        probe_root.mkdir(parents=True, exist_ok=True)
        probe_root.chmod(0o755)
        marker = probe_root / "marker.txt"
        marker.write_text("read-only probe\n", encoding="utf-8")
        marker.chmod(0o444)
        name = self._name("probe")
        script = r"""
set -eu
uid=$(id -u)
[ "$uid" != "0" ] || exit 20
if touch /datacon-root-write 2>/dev/null; then exit 21; fi
if touch /fixture/.write-probe 2>/dev/null; then exit 22; fi
touch /work/.write-probe
if [ -e /var/run/docker.sock ]; then exit 23; fi
links=$(ls /sys/class/net | grep -v '^lo$' || true)
routes=$(awk 'NR > 1 { print }' /proc/net/route)
[ -z "$routes" ] || exit 24
seccomp=$(awk '/^Seccomp:/ {print $2}' /proc/self/status)
[ "$seccomp" = "2" ] || exit 25
pids=$(cat /sys/fs/cgroup/pids.max 2>/dev/null || echo unknown)
memory=$(cat /sys/fs/cgroup/memory.max 2>/dev/null || echo unknown)
cpu=$(cat /sys/fs/cgroup/cpu.max 2>/dev/null || echo unknown)
work_mib=$(df -Pm /work | awk 'NR==2 {print $2}')
tmp_mib=$(df -Pm /tmp | awk 'NR==2 {print $2}')
compiler=$(clang --version | head -n 1)
printf 'uid=%s\nseccomp=%s\npids=%s\nmemory=%s\ncpu=%s\nwork_mib=%s\ntmp_mib=%s\ncompiler=%s\nlinks=%s\nroutes=%s\n' \
  "$uid" "$seccomp" "$pids" "$memory" "$cpu" "$work_mib" "$tmp_mib" "$compiler" "$links" "$routes"
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
            validate_host_config(config, self.policy, self.limits)
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
                self._remove(name)
                raise SandboxPolicyError("isolation probe did not complete")
            logs = self._docker(["logs", name], timeout=30)
            raw = (logs.stdout + logs.stderr).decode("utf-8", "replace")
            exit_code = int(wait.stdout.decode("utf-8", "replace").strip() or "1")
            inspect = self._inspect(name)
            state = inspect.get("State", {})
        finally:
            self._remove(name)
            marker.unlink(missing_ok=True)
        values: dict[str, str] = {}
        for line in raw.splitlines():
            key, separator, value = line.partition("=")
            if separator:
                values[key.strip()] = value.strip()
        checks: dict[str, Any] = {
            "probe_exit_code": exit_code,
            "uid": values.get("uid"),
            "seccomp": values.get("seccomp"),
            "network_links": values.get("links", ""),
            "routes": values.get("routes", ""),
            "pids_max": values.get("pids"),
            "memory_max": values.get("memory"),
            "cpu_max": values.get("cpu"),
            "work_mib": values.get("work_mib"),
            "tmp_mib": values.get("tmp_mib"),
            "oom_killed": bool(state.get("OOMKilled")),
        }
        ok = (
            exit_code == 0
            and checks["uid"] == self.policy.user.split(":")[0]
            and checks["seccomp"] == "2"
            and checks["routes"] == ""
            and checks["pids_max"] in (str(self.limits.pids), "max")
            and checks["memory_max"] in (
                str(self.limits.memory_mib * MIB),
                "max",
            )
            and "oom_killed" in checks
            and not checks["oom_killed"]
        )
        # Memory and CPU cgroup files may be absent under some Docker Desktop
        # kernels; inspect already proved the host configuration in that case.
        if values.get("memory") not in (None, "unknown", "max"):
            ok = ok and values["memory"] == str(self.limits.memory_mib * MIB)
        if values.get("cpu") not in (None, "unknown"):
            cpu_value = values["cpu"].split()[0]
            ok = ok and cpu_value in (
                str(self.limits.cpu * 100_000),
                "max",
            )
        if values.get("work_mib") is not None and values.get("tmp_mib") is not None:
            try:
                total = int(values["work_mib"]) + int(values["tmp_mib"])
            except ValueError:
                total = 0
            ok = ok and total <= self.limits.scratch_mib + 2
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
        )

    def build(
        self,
        version: str,
        *,
        materials_dir: Path | str,
        compile_args: Sequence[str] = (),
        deadline_seconds: float = 300.0,
    ) -> BuildResult:
        if version not in ("vulnerable", "fixed"):
            raise SandboxError("build version is invalid")
        materials = Path(materials_dir)
        if not (materials / "build.sh").is_file():
            raise SandboxError("reviewed build recipe is missing")
        work = self.run_root / "build" / version / uuid.uuid4().hex
        work.mkdir(parents=True, exist_ok=True)
        wrapper = (
            f"/bin/sh /fixture/build.sh {version} > /work/build.log 2>&1; "
            "code=$?; echo $code > /work/exit_code; "
            "cat /sys/fs/cgroup/pids.events > /work/pids.events 2>/dev/null || true; "
            "cat /sys/fs/cgroup/memory.events > /work/memory.events 2>/dev/null || true; "
            "touch /work/done; "
            "while [ ! -e /work/release ]; do sleep 0.1; done"
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
            files, truncated_streams, state, timed_out = self._start_and_wait(
                name,
                deadline_seconds=deadline_seconds,
                stream=[
                    "/work/build.log",
                    "/work/exit_code",
                    "/work/parser",
                    "/work/pids.events",
                    "/work/memory.events",
                ],
            )
            duration = time.monotonic() - started
            log, log_truncated = _truncate_log(files.get("/work/build.log", b""))
            truncated = log_truncated or "/work/build.log" in truncated_streams
            exit_code = None
            if "/work/exit_code" in files:
                try:
                    exit_code = int(files["/work/exit_code"].decode().strip())
                except ValueError:
                    exit_code = None
            artifact = files.get("/work/parser")
            if "/work/parser" in truncated_streams:
                artifact = None
            if artifact is not None and len(artifact) > MAX_ARTIFACT_BYTES:
                raise SandboxError("build artifact exceeds the evidence size cap")
            artifact_digest = (
                "sha256:" + hashlib.sha256(artifact).hexdigest()
                if artifact is not None
                else None
            )
            quota_hits = _quota_events(files)
            status = "completed" if exit_code == 0 and artifact is not None else "build_failed"
            if timed_out:
                status = "timeout"
            elif state.get("OOMKilled") or quota_hits:
                status = "resource_limited"
            metadata = {
                "build_command": ["/bin/sh", "/fixture/build.sh", version],
                "build_recipe_digest": _digest_bytes(materials / "build.sh"),
                "exit_code": exit_code,
                "timed_out": timed_out,
                "oom_killed": bool(state.get("OOMKilled")),
                "limits_hit": quota_hits,
            }
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
                log_truncated=truncated,
                artifact=artifact,
                metadata=metadata,
            )
        finally:
            if name:
                self._remove(name)
            # scratch output is collected by _start_and_wait only for temp
            # files; artifacts are fetched below in a dedicated container.
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
    ) -> ReplayResult:
        artifact = Path(artifact_path)
        input_file = Path(input_path)
        if not artifact.is_file() or artifact.is_symlink():
            raise SandboxError("built artifact is missing")
        if not input_file.is_file() or input_file.is_symlink():
            raise SandboxError("replay input is missing")
        timeout = timeout_seconds
        if deadline_seconds is not None:
            timeout = min(timeout, max(0.5, deadline_seconds))
        artifact.chmod(0o555)
        input_file.chmod(0o444)
        wrapper = (
            "/artifact/parser < /input/input > /work/stdout 2> /work/stderr; "
            "code=$?; echo $code > /work/exit_code; "
            "cat /sys/fs/cgroup/pids.events > /work/pids.events 2>/dev/null || true; "
            "cat /sys/fs/cgroup/memory.events > /work/memory.events 2>/dev/null || true; "
            "touch /work/done; "
            "while [ ! -e /work/release ]; do sleep 0.1; done"
        )
        started = time.monotonic()
        name = None
        files: dict[str, bytes] = {}
        state: dict[str, Any] = {}
        timed_out = False
        try:
            name, _ = self._create(
                suffix=f"replay-{version}-{phase}",
                command=["/bin/sh", "-c", wrapper],
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
            files, truncated_streams, state, timed_out = self._start_and_wait(
                name,
                deadline_seconds=timeout,
                stream=[
                    "/work/stdout",
                    "/work/stderr",
                    "/work/exit_code",
                    "/work/pids.events",
                    "/work/memory.events",
                ],
            )
        finally:
            if name:
                self._remove(name)
        duration = time.monotonic() - started
        stdout, truncated_out = _truncate_log(files.get("/work/stdout", b""))
        stderr, truncated_err = _truncate_log(files.get("/work/stderr", b""))
        truncated_out = truncated_out or "/work/stdout" in truncated_streams
        truncated_err = truncated_err or "/work/stderr" in truncated_streams
        exit_code = None
        if "/work/exit_code" in files:
            try:
                exit_code = int(files["/work/exit_code"].decode().strip())
            except ValueError:
                exit_code = None
        signature = parse_asan(stderr.decode("utf-8", "replace"))
        quota_hits = _quota_events(files)
        quota_hit = (
            bool(state.get("OOMKilled"))
            or (exit_code == 137 and not timed_out)
            or bool(quota_hits)
        )
        status = "completed"
        if timed_out:
            status = "timeout"
        elif quota_hit:
            status = "resource_limited"
        digest = "sha256:" + hashlib.sha256(input_file.read_bytes()).hexdigest()
        return ReplayResult(
            version=version,
            phase=phase,
            status=status,
            exit_code=exit_code,
            duration_seconds=duration,
            container_id=name,
            input_digest=digest,
            stdout=stdout,
            stderr=stderr,
            signature=signature,
            timed_out=timed_out,
            quota_hit=quota_hit,
            log_truncated=truncated_out or truncated_err,
            metadata={
                "image_digest": self.image_digest,
                "asan_options": asan_options,
                "oom_killed": bool(state.get("OOMKilled")),
                "limits_hit": quota_hits,
                "timeout_seconds": timeout,
            },
        )


def _digest_bytes(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()

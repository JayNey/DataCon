"""TC-05/TC-06/TC-15 P2 T13b: BuildSpec execution, cc-shim, D4 separation, D39 archiving.

Pure contract tests (no Docker daemon, no PostgreSQL). Covers:
1. CMake template auto-injection of ``-DCMAKE_EXPORT_COMPILE_COMMANDS=ON`` and
   verbatim argv execution without shell splicing.
2. Local ``subprocess.run`` end-to-end execution of the generated ``cc-shim``
   wrapper against a stub compiler, verifying JSONL output and end-to-end
   ``build_provenance.parse_provenance_face(kind="make", ...)`` parsing.
3. Pre-container fail-closed rejection (zero ``_create`` calls) for invalid
   ``cmake``, ``make``, and ``shell`` specs.
4. D4 build material separation on v2 vs v1 backward compatibility.
5. v2 execution provenance pipeline: comparable CMake/Make/Shell archiving at
   fixed D39 paths + closed 3-key ``report.build_provenance`` +
   ``evidence.verify_bundle``, and fail-closed ``FAILED`` /
   ``BUILD_PROVENANCE_MISSING`` with zero replays on missing/non-comparable/drifted
   faces or pre-container errors.
"""

from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import stat
import subprocess
import sys
from typing import Any
from uuid import UUID, uuid4

import pytest

from datacon import build_provenance, contracts, evidence, execution, jsonutil
from datacon.asan import ASanSignature
from datacon.cases import load_registry
from datacon.tools.sandbox import (
    SECCOMP_PROFILE_DIGEST,
    BuildResult,
    DockerSandbox,
    IsolationPolicy,
    ProbeReport,
    ReplayResult,
    ResourceLimits,
    SandboxError,
    build_runner_command,
    prepare_build_spec_execution,
    render_cc_shim_script,
)

FIXTURE_CASES = Path(__file__).resolve().parents[1] / "fixtures" / "cases"
POLICY = IsolationPolicy(
    network="none",
    user="65534:65534",
    read_only_root=True,
    cap_drop=("ALL",),
    no_new_privileges=True,
    seccomp="runtime/default",
    seccomp_profile_digest=SECCOMP_PROFILE_DIGEST,
)
LIMITS = ResourceLimits(cpu=2, memory_mib=2048, pids=128, scratch_mib=512)
IMAGE = "silkeh/clang:19-bookworm@sha256:" + "a" * 64
DECLARED_FLAGS = ["-fsanitize=address", "-g", "-O1", "-Iinclude", "-D_GNU_SOURCE"]


def _sha256_prefixed(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _cmake_spec(
    *,
    configure: list[str] | None = None,
    build: list[str] | None = None,
    install: list[str] | None = None,
    env: dict[str, str] | None = None,
    outputs: list[str] | None = None,
    declared_compile_flags: list[str] | None = None,
) -> dict[str, Any]:
    return {
        "kind": "cmake",
        "configure": (
            list(configure)
            if configure is not None
            else [
                "cmake",
                "-S",
                ".",
                "-B",
                "build",
                "-DCMAKE_BUILD_TYPE=RelWithDebInfo",
                "-DCMAKE_C_COMPILER=clang",
            ]
        ),
        "build": (
            list(build)
            if build is not None
            else ["cmake", "--build", "build", "--target", "parser"]
        ),
        "install": list(install) if install is not None else [],
        "env": (
            dict(env)
            if env is not None
            else {
                "CC": "clang",
                "CFLAGS": "-fsanitize=address -g -O1 -Iinclude -D_GNU_SOURCE",
            }
        ),
        "outputs": list(outputs) if outputs is not None else ["build/parser"],
        "declared_compile_flags": (
            list(declared_compile_flags)
            if declared_compile_flags is not None
            else list(DECLARED_FLAGS)
        ),
        "shell_recipe_digest": None,
        "shell_face_digest": None,
        "shell_face_review": None,
    }


def _make_spec(
    *,
    cc: str | None = "/opt/datacon/cc-shim",
    declared_compile_flags: list[str] | None = None,
) -> dict[str, Any]:
    env: dict[str, str] = {
        "CFLAGS": "-fsanitize=address -g -O1 -Iinclude -D_GNU_SOURCE",
    }
    if cc is not None:
        env["CC"] = cc
    return {
        "kind": "make",
        "build": ["make", "-C", "src", "parser"],
        "install": [],
        "env": env,
        "outputs": ["src/parser"],
        "declared_compile_flags": (
            list(declared_compile_flags)
            if declared_compile_flags is not None
            else list(DECLARED_FLAGS)
        ),
        "shell_recipe_digest": None,
        "shell_face_digest": None,
        "shell_face_review": None,
    }


def _shell_spec(
    *,
    face_digest: str | None,
    review: dict[str, Any] | None,
    declared_compile_flags: list[str] | None = None,
) -> dict[str, Any]:
    return {
        "kind": "shell",
        "build": ["sh", "./build.sh"],
        "install": [],
        "env": {"CC": "clang"},
        "outputs": ["out/parser"],
        "declared_compile_flags": (
            list(declared_compile_flags)
            if declared_compile_flags is not None
            else list(DECLARED_FLAGS)
        ),
        "shell_recipe_digest": "sha256:" + "1" * 64,
        "shell_face_digest": face_digest,
        "shell_face_review": review,
    }


def _cmake_compile_commands_bytes(
    *,
    flags: list[str],
    directory: str = "/work/build",
    source: str = "/work/src/parser.c",
) -> bytes:
    payload = [
        {
            "directory": directory,
            "file": source,
            "arguments": ["clang", *flags, "-c", source, "-o", "parser.o"],
        }
    ]
    return json.dumps(payload).encode("utf-8")


def _make_cc_shim_log_bytes(
    *,
    flags: list[str],
    cwd: str = "/work",
    source: str = "src/parser.c",
) -> bytes:
    records = [
        {
            "cwd": cwd,
            "compiler": "clang",
            "argv": ["/opt/datacon/cc-shim", *flags, "-c", source, "-o", "parser.o"],
        },
        {
            "cwd": cwd,
            "compiler": "clang",
            "argv": ["/opt/datacon/cc-shim", "-o", "src/parser", "parser.o"],
        },
    ]
    return ("\n".join(json.dumps(item) for item in records) + "\n").encode("utf-8")


def _make_sandbox(tmp_path: Path) -> DockerSandbox:
    return DockerSandbox(
        image=IMAGE,
        platform="linux/amd64",
        policy=POLICY,
        limits=LIMITS,
        job_id=str(uuid4()),
        run_root=tmp_path / "sandbox-run",
        generation=1,
    )


def _setup_fixture_plan_and_job(
    *,
    version: int,
    build_spec: dict[str, Any] | None = None,
    compile_flags: list[str] | None = None,
    round_no: int | None = 1,
    job_kind: str = "round",
) -> tuple[dict[str, Any], dict[str, Any], str, dict[str, Any]]:
    registry = load_registry(str(FIXTURE_CASES))
    case = registry.case("fixture-c-parser")
    manifest = case.manifest
    manifest_case = case.manifest_case
    materials = manifest["materials"]
    source_vuln = manifest["versions"]["vulnerable"]
    source_fixed = manifest["versions"]["fixed"]
    used_materials = {
        key: materials[key]
        for key in {
            manifest["harness"],
            manifest["build_recipe"],
            manifest["dependencies"],
            case.repository["patch"],
            source_vuln,
            source_fixed,
            manifest_case["inputs"]["candidate"],
            manifest_case["inputs"]["normal"],
        }
    }
    case_config = {
        "case_id": case.case_id,
        "cve_id": case.cve_id,
        "benchmark_id": case.benchmark_id,
        "registry_entry": case.entry,
        "manifest_case": manifest_case,
        "materials": used_materials,
        "image": manifest["image"],
        "platform": manifest["platform"],
        "toolchain": manifest["toolchain"],
        "asan_options": manifest["asan_options"],
        "asan_signature": manifest["asan_signature"],
    }
    analysis = {
        "diff_digest": materials[case.repository["patch"]],
        "changed_paths": ["parser.c"],
        "symbols": [
            {
                "name": "parse_token",
                "path": "parser.c",
                "role": "definition",
                "revision": "vulnerable",
                "start_line": 1,
                "end_line": 20,
            }
        ],
        "findings": [
            {
                "kind": "hypothesis",
                "statement": "buffer write past allocation",
                "confidence": "high",
                "evidence_refs": ["patch:fix.patch#hunk-1"],
            }
        ],
    }
    analysis_dig = contracts.analysis_digest(analysis)
    image_digest = manifest["image"].split("@", 1)[1]
    plan: dict[str, Any] = {
        "case_id": case.case_id,
        "cve_id": case.cve_id,
        "case_config_digest": jsonutil.digest_json(case_config),
        "repository": {
            "origin": case.repository["origin"],
            "bundle_digest": case.repository["bundle_digest"],
            "patch_digest": materials[case.repository["patch"]],
        },
        "revisions": dict(case.repository["commits"]),
        "dependencies_digest": materials[manifest["dependencies"]],
        "image_digest": image_digest,
        "platform": manifest["platform"],
        "toolchain": manifest["toolchain"],
        "asan_options": manifest["asan_options"],
        "build_recipe_digest": materials[manifest["build_recipe"]],
        "harness_digest": materials[manifest["harness"]],
        "inputs": {
            "normal": materials[manifest_case["inputs"]["normal"]],
            "candidate": materials[manifest_case["inputs"]["candidate"]],
        },
        "expected_exit": dict(manifest_case["expected_exit"]),
        "asan_signature": dict(manifest["asan_signature"]),
        "limits": dict(manifest["limits"]),
        "isolation": dict(registry.document["isolation"]),
        "intel": {
            "snapshot": case.advisory["path"],
            "collected_at": "2099-01-01T00:00:00Z",
            "content_digest": case.advisory["digest"],
            "sources": ["https://github.com/JayNey/DataCon"],
        },
        "analysis": analysis,
        "analysis_digest": analysis_dig,
        "policy_version": registry.document["policy_version"],
    }

    job_id = uuid4()
    family_id = str(uuid4())
    envelope_digest = "sha256:" + "5" * 64
    if version == 2:
        spec = deepcopy(build_spec) if build_spec is not None else _cmake_spec()
        flags = (
            list(compile_flags)
            if compile_flags is not None
            else list(spec["declared_compile_flags"])
        )
        plan.update(
            {
                "schema_version": 2,
                "family_id": family_id,
                "parent_job_id": family_id,
                "round_no": round_no,
                "parent_approval_digest": None,
                "envelope_digest": envelope_digest,
                "build_ref": None,
                "build_spec": spec,
                "compile_flags": flags,
                "experiment_digest": None,
                "build_provenance_rules_version": build_provenance.RULES_VERSION,
                "build_recipe_digest": jsonutil.digest_json(spec),
            }
        )
        if round_no is None:
            plan["inputs"] = None

    plan_dig = contracts.plan_digest(plan)
    now = datetime.now(timezone.utc)
    job: dict[str, Any] = {
        "job_id": job_id,
        "generation": 1,
        "state": "RUNNING",
        "job_contract_version": version,
        "execute_deadline_at": now + timedelta(seconds=600),
        "request": {
            "schema_version": version,
            "cve_id": case.cve_id,
            "target": {
                "kind": "source",
                "case_id": case.case_id,
                "goal": "verify build provenance",
            },
            "limits": dict(manifest["limits"]),
        },
    }
    if version == 2:
        job["family_id"] = family_id
        job["parent_job_id"] = family_id
        job["job_kind"] = job_kind
        job["round_no"] = round_no
    review = {
        "reviewer_id": "reviewer-01",
        "decision": "approve",
        "plan_digest": plan_dig,
        "decided_at": now,
    }
    return job, plan, plan_dig, review


class _InMemoryState:
    """Minimal in-memory state backend for contract tests (no PostgreSQL)."""

    def __init__(
        self,
        job: dict[str, Any],
        plan: dict[str, Any],
        plan_digest: str,
        review: dict[str, Any],
    ) -> None:
        self.job = deepcopy(job)
        self.plan = deepcopy(plan)
        self.plan_digest = plan_digest
        self.review = deepcopy(review)
        self.attempts: list[dict[str, Any]] = []
        self.finished_calls: list[dict[str, Any]] = []

    def install(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(execution.state, "load_job", self.load_job)
        monkeypatch.setattr(execution.state, "get_plan", self.get_plan)
        monkeypatch.setattr(execution.state, "get_review", self.get_review)
        monkeypatch.setattr(
            execution.state, "attempts_for_step", self.attempts_for_step
        )
        monkeypatch.setattr(
            execution.state,
            "attempts_for_step_across_generations",
            self.attempts_for_step_across_generations,
        )
        monkeypatch.setattr(execution.state, "record_attempt", self.record_attempt)
        monkeypatch.setattr(
            execution.state, "execution_attempts", self.execution_attempts
        )
        monkeypatch.setattr(execution.state, "mark_archiving", self.mark_archiving)
        monkeypatch.setattr(
            execution.state, "assert_archive_fence", self.assert_archive_fence
        )
        monkeypatch.setattr(execution.state, "finish_execution", self.finish_execution)

    def load_job(self, dsn: str, job_id: UUID) -> dict[str, Any] | None:
        return deepcopy(self.job) if str(job_id) == str(self.job["job_id"]) else None

    def get_plan(self, dsn: str, job_id: UUID) -> dict[str, Any] | None:
        if str(job_id) != str(self.job["job_id"]):
            return None
        return {"plan": deepcopy(self.plan), "plan_digest": self.plan_digest}

    def get_review(self, dsn: str, job_id: UUID) -> dict[str, Any] | None:
        if str(job_id) in (str(self.job["job_id"]), str(self.job.get("family_id"))):
            return deepcopy(self.review)
        return None

    def attempts_for_step(
        self,
        dsn: str,
        job_id: UUID,
        *,
        stage: str,
        step_key: str,
        generation: int,
    ) -> list[dict[str, Any]]:
        return [
            deepcopy(row)
            for row in self.attempts
            if row["step_key"] == step_key and row["generation"] == generation
        ]

    def attempts_for_step_across_generations(
        self,
        dsn: str,
        job_id: UUID,
        *,
        stage: str,
        step_key: str,
    ) -> list[dict[str, Any]]:
        return [deepcopy(row) for row in self.attempts if row["step_key"] == step_key]

    def record_attempt(
        self,
        dsn: str,
        job_id: UUID,
        *,
        stage: str,
        step_key: str,
        attempt_no: int,
        generation: int,
        input_digest: str | None = None,
        status: str,
        result: Any = None,
        container_id: str | None = None,
        attempt_token: str | None = None,
    ) -> bool:
        for row in self.attempts:
            if (
                row["step_key"] == step_key
                and row["attempt_no"] == attempt_no
                and row["generation"] == generation
            ):
                row["status"] = status
                if result is not None:
                    row["result"] = deepcopy(result)
                if container_id is not None:
                    row["container_id"] = container_id
                if attempt_token is not None:
                    row["attempt_token"] = attempt_token
                return True
        self.attempts.append(
            {
                "step_key": step_key,
                "attempt_no": attempt_no,
                "generation": generation,
                "input_digest": input_digest,
                "status": status,
                "result": deepcopy(result),
                "container_id": container_id,
                "attempt_token": attempt_token,
                "started_at": datetime.now(timezone.utc),
                "finished_at": datetime.now(timezone.utc),
            }
        )
        return True

    def execution_attempts(
        self, dsn: str, job_id: UUID, generation: int
    ) -> list[dict[str, Any]]:
        return [deepcopy(row) for row in self.attempts if row["generation"] == generation]

    def mark_archiving(self, dsn: str, job_id: UUID, *, generation: int) -> bool:
        self.job["state"] = "ARCHIVING"
        return True

    def assert_archive_fence(self, dsn: str, job_id: UUID, *, generation: int) -> bool:
        return True

    def finish_execution(self, dsn: str, job_id: UUID, **kwargs: Any) -> bool:
        self.finished_calls.append(dict(kwargs))
        self.job["state"] = kwargs.get("state", self.job["state"])
        return True


class _FakeSandbox:
    """Fake sandbox for end-to-end v2 execution provenance pipeline tests."""

    def __init__(
        self,
        *,
        image_digest: str,
        build_recipe_digest: str,
        faces: dict[str, bytes | None],
        face_name: str,
        build_error: SandboxError | None = None,
        build_logs: dict[str, bytes] | None = None,
    ) -> None:
        self.image_digest = image_digest
        self.build_recipe_digest = build_recipe_digest
        self.faces = faces
        self.face_name = face_name
        self.build_error = build_error
        self.build_logs = build_logs or {
            "vulnerable": b"building vulnerable...\n",
            "fixed": b"building fixed...\n",
        }
        self.build_calls: list[dict[str, Any]] = []
        self.replay_calls: list[dict[str, Any]] = []

    def probe(self, *, deadline_seconds: float = 120.0) -> ProbeReport:
        return ProbeReport(
            ok=True,
            checks={
                "uid": "65534",
                "seccomp": "2",
                "no_new_privs": "1",
                "cap_eff": "0000000000000000",
                "cgroup_version": "2",
                "errors": [],
            },
            compiler_version="clang 19.1.7",
            image_digest=self.image_digest,
            raw="uid=65534\n",
            limits={
                "cpu": 2,
                "memory_mib": 2048,
                "pids": 128,
                "scratch_mib": 512,
            },
        )

    def build(
        self,
        version: str,
        *,
        materials_dir: Path | str,
        compile_args: Any = (),
        deadline_seconds: float = 300.0,
        expected_materials: Any = None,
        build_spec: Any = None,
    ) -> BuildResult:
        staged_files = sorted(
            path.relative_to(Path(materials_dir)).as_posix()
            for path in Path(materials_dir).rglob("*")
            if path.is_file()
        )
        self.build_calls.append(
            {
                "version": version,
                "build_spec": deepcopy(build_spec),
                "staged_files": staged_files,
            }
        )
        if self.build_error is not None:
            raise self.build_error
        artifact = f"ELF-{version}".encode("utf-8")
        raw_face = self.faces.get(version)
        log = self.build_logs.get(version, b"build ok\n")
        return BuildResult(
            version=version,
            status="completed",
            exit_code=0,
            duration_seconds=0.2,
            container_id=f"fake-build-{version}",
            image_digest=self.image_digest,
            compile_args=tuple(compile_args),
            artifact_digest=_sha256_prefixed(artifact),
            log=log,
            log_truncated=False,
            artifact=artifact,
            metadata={
                "build_spec_kind": build_spec["kind"] if isinstance(build_spec, dict) else None,
                "build_recipe_digest": self.build_recipe_digest,
                "provenance_face_name": self.face_name,
            },
            provenance_face=raw_face,
            provenance_face_name=self.face_name,
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
        deadline_seconds: float,
        expected_artifact_digest: str | None = None,
        expected_input_digest: str | None = None,
    ) -> ReplayResult:
        self.replay_calls.append(
            {
                "version": version,
                "phase": phase,
                "input_digest": expected_input_digest,
            }
        )
        assert expected_input_digest is not None
        if phase == "normal":
            return ReplayResult(
                version=version,
                phase=phase,
                status="completed",
                exit_code=0,
                duration_seconds=0.05,
                container_id=f"fake-replay-{version}-{phase}",
                input_digest=expected_input_digest,
                stdout=b"OK\n",
                stderr=b"",
                signature=None,
                timed_out=False,
                quota_hit=False,
                log_truncated=False,
                metadata={
                    "image_digest": self.image_digest,
                    "asan_options": asan_options,
                },
            )
        if version == "vulnerable":
            sig = ASanSignature(
                error="heap-buffer-overflow",
                operation="WRITE",
                access_size=1,
                function="parse_token",
                source="parser.c",
            )
            asan_err = (
                "ERROR: AddressSanitizer: heap-buffer-overflow on address 0x1\n"
                "WRITE of size 1 at 0x1 thread T0\n"
                "    #0 0x123 in parse_token parser.c:12\n"
            ).encode("utf-8")
            return ReplayResult(
                version=version,
                phase=phase,
                status="completed",
                exit_code=86,
                duration_seconds=0.05,
                container_id=f"fake-replay-{version}-{phase}",
                input_digest=expected_input_digest,
                stdout=b"",
                stderr=asan_err,
                signature=sig,
                timed_out=False,
                quota_hit=False,
                log_truncated=False,
                metadata={
                    "image_digest": self.image_digest,
                    "asan_options": asan_options,
                },
            )
        return ReplayResult(
            version=version,
            phase=phase,
            status="completed",
            exit_code=0,
            duration_seconds=0.05,
            container_id=f"fake-replay-{version}-{phase}",
            input_digest=expected_input_digest,
            stdout=b"ABCD\n",
            stderr=b"",
            signature=None,
            timed_out=False,
            quota_hit=False,
            log_truncated=False,
            metadata={
                "image_digest": self.image_digest,
                "asan_options": asan_options,
            },
        )


def _configure_isolated_roots(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> tuple[Path, Path]:
    run_root = tmp_path / "runs"
    evidence_root = tmp_path / "evidence"
    staging_root = tmp_path / "staging"
    secret_file = tmp_path / "secrets" / "journal.key"
    monkeypatch.setenv("DATACON_RUN_ROOT", str(run_root))
    monkeypatch.setenv("DATACON_EVIDENCE_ROOT", str(evidence_root))
    monkeypatch.setenv("DATACON_STAGING_ROOT", str(staging_root))
    monkeypatch.setenv("DATACON_JOURNAL_SECRET_FILE", str(secret_file))
    return run_root, evidence_root


# ---------------------------------------------------------------------------
# 1. CMake template auto-injection and zero free shell splicing
# ---------------------------------------------------------------------------


def test_cmake_auto_injects_export_compile_commands_and_avoids_duplication():
    spec_without = _cmake_spec()
    plan = prepare_build_spec_execution(spec_without)
    assert "-DCMAKE_EXPORT_COMPILE_COMMANDS=ON" in plan.configure, (
        "cmake template must auto-inject -DCMAKE_EXPORT_COMPILE_COMMANDS=ON when omitted"
    )
    assert plan.provenance_face_name == "compile_commands.json"
    assert plan.provenance_face_container_path == "/work/build/compile_commands.json"

    spec_with = _cmake_spec(
        configure=[
            "cmake",
            "-S",
            ".",
            "-B",
            "build",
            "-DCMAKE_EXPORT_COMPILE_COMMANDS=ON",
        ]
    )
    plan_with = prepare_build_spec_execution(spec_with)
    occurrences = [
        arg for arg in plan_with.configure if "CMAKE_EXPORT_COMPILE_COMMANDS" in arg
    ]
    assert len(occurrences) == 1, (
        f"explicit ON flag must not be duplicated: {plan_with.configure!r}"
    )


def test_cmake_runner_preserves_shell_metacharacters_without_shell_splicing(tmp_path):
    """Execute the real fixed runner template via subprocess.run and verify verbatim argv."""
    pwn_marker = tmp_path / "pwned-by-shell"
    dump_file = tmp_path / "argv-dump.json"
    dumper = tmp_path / "dump_argv.py"
    dumper.write_text(
        "import json, sys\n"
        f"with open({str(dump_file)!r}, 'a', encoding='utf-8') as f:\n"
        "    f.write(json.dumps(sys.argv[1:]) + '\\n')\n",
        encoding="utf-8",
    )

    tricky_args = [
        f"-DPWN=$(touch {pwn_marker})",
        f"-DBACKTICK=`touch {pwn_marker}`",
        f"-DSEMI=1; touch {pwn_marker}",
        "-DSPACE=hello world",
        '-DQUOTES="nested \'quotes\'"',
        "-DGLOB=*",
    ]
    spec = _cmake_spec(
        configure=[sys.executable, str(dumper), "-S", ".", "-B", "build", *tricky_args],
        build=[sys.executable, str(dumper), "build-step", "; echo pwn", "$(id)"],
        install=[sys.executable, str(dumper), "install-step", "a b 'c' \"d\""],
    )
    plan = prepare_build_spec_execution(spec)
    cmd = build_runner_command(
        plan,
        stage_fixture=False,
        emit_result_marker=False,
        wait_for_release=False,
    )

    proc = subprocess.run(
        cmd,
        cwd=tmp_path,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    assert proc.returncode == 0, (
        f"runner command failed rc={proc.returncode} stderr={proc.stderr.decode('utf-8', 'replace')}"
    )
    assert not pwn_marker.exists(), (
        "shell metacharacters in BuildSpec were evaluated instead of passed verbatim!"
    )

    lines = [
        json.loads(line)
        for line in dump_file.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    assert len(lines) == 3, f"expected configure/build/install invocations, got {lines!r}"
    assert lines[0] == [
        "-S",
        ".",
        "-B",
        "build",
        *tricky_args,
        "-DCMAKE_EXPORT_COMPILE_COMMANDS=ON",
    ], f"configure argv was altered or shell-expanded: {lines[0]!r}"
    assert lines[1] == ["build-step", "; echo pwn", "$(id)"], (
        f"build argv was altered or shell-expanded: {lines[1]!r}"
    )
    assert lines[2] == ["install-step", "a b 'c' \"d\""], (
        f"install argv was altered or shell-expanded: {lines[2]!r}"
    )


def test_cmake_explicit_off_and_unsafe_paths_rejected_before_create(
    tmp_path, monkeypatch
):
    sandbox = _make_sandbox(tmp_path)
    create_calls = 0

    def _fail_if_called(*args: Any, **kwargs: Any) -> Any:
        nonlocal create_calls
        create_calls += 1
        raise AssertionError("_create must not be called for invalid BuildSpec")

    monkeypatch.setattr(sandbox, "_create", _fail_if_called)
    materials = tmp_path / "materials"
    materials.mkdir()

    bad_specs = [
        _cmake_spec(
            configure=[
                "cmake",
                "-S",
                ".",
                "-B",
                "build",
                "-DCMAKE_EXPORT_COMPILE_COMMANDS=OFF",
            ]
        ),
        _cmake_spec(
            configure=["cmake", "-S", ".", "-B", "build"],
            env={"CC": "clang", "CMAKE_EXPORT_COMPILE_COMMANDS": "0"},
        ),
        _cmake_spec(configure=["cmake", "-S", ".", "-B", "../escape"]),
        _cmake_spec(outputs=["../etc/passwd"]),
        _cmake_spec(outputs=["/etc/passwd"]),
    ]
    for idx, spec in enumerate(bad_specs):
        with pytest.raises(SandboxError) as exc_info:
            sandbox.build(
                "vulnerable",
                materials_dir=materials,
                build_spec=spec,
            )
        assert exc_info.value.reason_code == build_provenance.BUILD_PROVENANCE_MISSING, (
            f"bad cmake spec #{idx} must fail closed with BUILD_PROVENANCE_MISSING"
        )
    assert create_calls == 0, "no Docker container may be created for invalid cmake specs"


# ---------------------------------------------------------------------------
# 2. Real cc-shim execution via subprocess.run -> parse_provenance_face
# ---------------------------------------------------------------------------


def test_cc_shim_executes_locally_and_parses_end_to_end(tmp_path):
    repo_root = tmp_path / "repo"
    (repo_root / "src").mkdir(parents=True)
    log_path = tmp_path / "cc-shim.log"
    received_file = tmp_path / "stub-received.jsonl"

    stub_cc = tmp_path / "stub-clang"
    stub_cc.write_text(
        f"#!{sys.executable}\n"
        "import json, os, sys\n"
        f"with open({str(received_file)!r}, 'a', encoding='utf-8') as f:\n"
        "    f.write(json.dumps(sys.argv[1:]) + '\\n')\n"
        "if '--fail-42' in sys.argv:\n"
        "    sys.exit(42)\n"
        "sys.exit(0)\n",
        encoding="utf-8",
    )
    stub_cc.chmod(0o755)

    shim_path = tmp_path / "cc-shim"
    shim_path.write_text(
        render_cc_shim_script(
            real_compiler=str(stub_cc),
            log_path=str(log_path),
        ),
        encoding="utf-8",
    )
    shim_path.chmod(0o755)

    inc_with_spaces = str(repo_root / "include dir")
    tricky_define = r'-DMSG="hello \"world\" \\ path"'
    invocations = [
        (
            repo_root,
            [
                "-fsanitize=address",
                "-g",
                "-I",
                inc_with_spaces,
                tricky_define,
                "-c",
                "src/a.c",
                "-o",
                "a.o",
            ],
            0,
        ),
        (
            repo_root / "src",
            [
                "-fsanitize=address",
                "-g",
                "-I../include dir",
                tricky_define,
                "-c",
                "b.c",
                "-o",
                "b.o",
            ],
            0,
        ),
        # Pure link call (.o only) must be logged by shim and excluded by parser.
        (
            repo_root,
            ["-fsanitize=address", "-o", "parser", "a.o", "b.o"],
            0,
        ),
        # Non-zero exit code must be propagated verbatim by exec.
        (
            repo_root,
            ["--fail-42", "-o", "fail.o", "a.o"],
            42,
        ),
    ]

    for cwd, argv, expected_rc in invocations:
        proc = subprocess.run(
            [str(shim_path), *argv],
            cwd=cwd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        assert proc.returncode == expected_rc, (
            f"cc-shim did not preserve compiler exit code {expected_rc}: "
            f"got {proc.returncode}, stderr={proc.stderr.decode('utf-8', 'replace')}"
        )

    raw_log = log_path.read_bytes()
    records = [
        jsonutil.loads_strict(line)
        for line in raw_log.decode("utf-8").splitlines()
        if line.strip()
    ]
    assert len(records) == 4, f"expected 4 JSONL shim records, got {len(records)}"
    for idx, ((cwd, argv, _), rec) in enumerate(zip(invocations, records, strict=True)):
        assert set(rec.keys()) == {"cwd", "compiler", "argv"}, (
            f"shim record #{idx} has unexpected keys: {rec.keys()}"
        )
        assert rec["cwd"] == str(cwd), f"shim record #{idx} cwd mismatch"
        assert rec["compiler"] == str(stub_cc), f"shim record #{idx} compiler mismatch"
        assert rec["argv"] == [str(stub_cc), *argv], (
            f"shim record #{idx} argv was mangled: {rec['argv']!r}"
        )

    parsed = build_provenance.parse_provenance_face(
        kind="make",
        raw_face=raw_log,
        repo_root=repo_root,
    )
    assert parsed.kind == "make"
    assert parsed.face_name == "cc-shim.log"
    assert list(parsed.units.keys()) == ["src/a.c", "src/b.c"], (
        f"pure .o link calls must be excluded and CUs sorted: {parsed.units!r}"
    )
    assert parsed.units["src/a.c"] == parsed.units["src/b.c"], (
        f"both CUs should normalize to identical flag sequences: {parsed.units!r}"
    )
    assert "-Iinclude dir" in parsed.units["src/a.c"], (
        f"space-containing -I path must normalize relative to repo_root: {parsed.units['src/a.c']!r}"
    )
    assert tricky_define in parsed.units["src/a.c"], (
        f"escaped quotes/backslashes in -D must survive JSONL round-trip: {parsed.units['src/a.c']!r}"
    )


# ---------------------------------------------------------------------------
# 3. Pre-container fail-closed for make without cc-shim and shell without face
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "label,spec",
    [
        ("make-missing-cc", _make_spec(cc=None)),
        ("make-raw-clang", _make_spec(cc="clang")),
        ("make-usr-bin-clang", _make_spec(cc="/usr/bin/clang")),
        ("make-traversal-cc-shim", _make_spec(cc="/opt/../cc-shim")),
        ("shell-missing-face-digest", _shell_spec(face_digest=None, review={
            "reviewer_id": "rev-1",
            "reviewed_at": "2099-01-01T00:00:00Z",
            "face_kind": "build_log",
        })),
        ("shell-missing-face-review", _shell_spec(
            face_digest="sha256:" + "2" * 64,
            review=None,
        )),
    ],
)
def test_invalid_make_and_shell_specs_fail_closed_before_container_create(
    tmp_path, monkeypatch, label, spec
):
    sandbox = _make_sandbox(tmp_path)
    create_calls = 0

    def _fail_if_called(*args: Any, **kwargs: Any) -> Any:
        nonlocal create_calls
        create_calls += 1
        raise AssertionError(f"_create must not be called for {label}")

    monkeypatch.setattr(sandbox, "_create", _fail_if_called)
    materials = tmp_path / "materials"
    materials.mkdir()

    with pytest.raises(SandboxError) as exc_info:
        sandbox.build("vulnerable", materials_dir=materials, build_spec=spec)
    assert exc_info.value.reason_code == build_provenance.BUILD_PROVENANCE_MISSING, (
        f"{label} must fail closed with BUILD_PROVENANCE_MISSING, got {exc_info.value.reason_code!r}"
    )
    assert create_calls == 0, f"{label} must invoke _create zero times"


# ---------------------------------------------------------------------------
# 4. D4 build material separation (v2 excludes inputs; v1 preserves aliases)
# ---------------------------------------------------------------------------


def test_d4_material_separation_v2_excludes_inputs_while_v1_preserves_aliases(
    tmp_path, monkeypatch
):
    run_root, _ = _configure_isolated_roots(tmp_path, monkeypatch)

    # --- v2 path ---
    v2_job, v2_plan, v2_plan_digest, v2_review = _setup_fixture_plan_and_job(
        version=2, build_spec=_cmake_spec()
    )
    v2_state = _InMemoryState(v2_job, v2_plan, v2_plan_digest, v2_review)
    v2_state.install(monkeypatch)
    v2_ctx = execution._load_context(
        "dsn",
        v2_job["job_id"],
        1,
        case_root=str(FIXTURE_CASES),
        run_root=run_root,
    )
    v2_gen_root = execution._generation_root(v2_ctx)
    v2_materials_dir, v2_inputs, v2_digests = execution._materialize(
        v2_ctx, v2_gen_root, anchor=run_root
    )
    assert all(not key.startswith("inputs/") for key in v2_digests), (
        f"v2 _material_digests must not contain any inputs/* entries: {sorted(v2_digests)}"
    )
    assert "inputs/normal.txt" not in v2_digests
    assert "inputs/candidate.txt" not in v2_digests
    v2_material_files = {
        p.relative_to(v2_materials_dir).as_posix()
        for p in v2_materials_dir.rglob("*")
        if p.is_file()
    }
    assert all(not rel.startswith("inputs/") for rel in v2_material_files), (
        f"v2 materialized build dir must not contain inputs/*: {sorted(v2_material_files)}"
    )
    # Replay inputs exist in their separate directory outside build materials.
    assert v2_inputs["normal"].is_file() and v2_inputs["candidate"].is_file()
    assert v2_materials_dir not in v2_inputs["normal"].parents

    v2_staging, v2_staged = execution._stage_materials(
        v2_ctx, v2_materials_dir, v2_digests, "v2-d4-test"
    )
    try:
        staged_on_disk = {
            p.relative_to(v2_staging).as_posix()
            for p in v2_staging.rglob("*")
            if p.is_file()
        }
        assert all(not rel.startswith("inputs/") for rel in staged_on_disk), (
            f"v2 staged build dir must not contain inputs/*: {sorted(staged_on_disk)}"
        )
        assert all(not rel.startswith("inputs/") for rel in v2_staged), (
            f"v2 staged_materials must not contain inputs/*: {sorted(v2_staged)}"
        )
    finally:
        execution._discard_staging(v2_staging)

    # Even if a caller passes a directory/digest map that contains inputs/* to
    # _stage_materials on v2, D4 filtering must strip them out of staging.
    dirty_dir = tmp_path / "dirty-v2-materials"
    dirty_dir.mkdir()
    (dirty_dir / "inputs").mkdir()
    (dirty_dir / "inputs" / "normal.txt").write_bytes(b"ok\n")
    (dirty_dir / "inputs" / "candidate.txt").write_bytes(b"boom\n")
    (dirty_dir / "harness.c").write_bytes(b"int main(){return 0;}\n")
    dirty_digests = {
        "inputs/normal.txt": _sha256_prefixed(b"ok\n"),
        "inputs/candidate.txt": _sha256_prefixed(b"boom\n"),
        "harness.c": _sha256_prefixed(b"int main(){return 0;}\n"),
    }
    clean_staging, clean_staged = execution._stage_materials(
        v2_ctx, dirty_dir, dirty_digests, "v2-d4-defensive"
    )
    try:
        assert set(clean_staged) == {"harness.c"}, (
            f"v2 _stage_materials must strip inputs/* defensively: {clean_staged!r}"
        )
        assert not (clean_staging / "inputs").exists()
    finally:
        execution._discard_staging(clean_staging)

    # --- v1 path (100% frozen compatibility) ---
    v1_job, v1_plan, v1_plan_digest, v1_review = _setup_fixture_plan_and_job(version=1)
    v1_state = _InMemoryState(v1_job, v1_plan, v1_plan_digest, v1_review)
    v1_state.install(monkeypatch)
    v1_ctx = execution._load_context(
        "dsn",
        v1_job["job_id"],
        1,
        case_root=str(FIXTURE_CASES),
        run_root=run_root,
    )
    v1_gen_root = execution._generation_root(v1_ctx)
    v1_materials_dir, _, v1_digests = execution._materialize(
        v1_ctx, v1_gen_root, anchor=run_root
    )
    assert "inputs/normal.txt" in v1_digests, "v1 must keep inputs/normal.txt alias"
    assert "inputs/candidate.txt" in v1_digests, "v1 must keep inputs/candidate.txt alias"
    v1_staging, v1_staged = execution._stage_materials(
        v1_ctx, v1_materials_dir, v1_digests, "v1-compat-test"
    )
    try:
        assert "inputs/normal.txt" in v1_staged
        assert "inputs/candidate.txt" in v1_staged
        assert (v1_staging / "inputs" / "normal.txt").is_file()
        assert (v1_staging / "inputs" / "candidate.txt").is_file()
    finally:
        execution._discard_staging(v1_staging)


# ---------------------------------------------------------------------------
# 5. v2 execution provenance pipeline: comparable success + D39 + verify_bundle
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("kind", ["cmake", "make", "shell"])
def test_v2_comparable_builds_archive_d39_faces_report_and_verify_bundle(
    tmp_path, monkeypatch, kind
):
    run_root, _ = _configure_isolated_roots(tmp_path, monkeypatch)

    if kind == "cmake":
        spec = _cmake_spec()
        face_name = "compile_commands.json"
        vuln_face = _cmake_compile_commands_bytes(
            # Relative to /work/build -> normalizes to -Iinclude
            flags=["-fsanitize=address", "-g", "-O1", "-I../include", "-D_GNU_SOURCE"]
        )
        fixed_face = _cmake_compile_commands_bytes(
            # Connected/split + absolute path equivalent form must verify comparable!
            flags=["-fsanitize=address", "-g", "-O1", "-I", "/work/include", "-D", "_GNU_SOURCE"]
        )
    elif kind == "make":
        spec = _make_spec()
        face_name = "cc-shim.log"
        vuln_face = _make_cc_shim_log_bytes(flags=DECLARED_FLAGS)
        fixed_face = _make_cc_shim_log_bytes(
            flags=["-fsanitize=address", "-g", "-O1", "-I", "include", "-D_GNU_SOURCE"]
        )
    else:
        baseline = (
            "2099-01-01T00:00:00Z /work clang -fsanitize=address -g -O1 -Iinclude "
            "-D_GNU_SOURCE src/parser.c -o out/parser\n"
        )
        expected_shell_digest = build_provenance.shell_face_digest(
            baseline, repo_root="/work"
        )
        spec = _shell_spec(
            face_digest=expected_shell_digest,
            review={
                "reviewer_id": "reviewer-01",
                "reviewed_at": "2099-01-01T00:00:00Z",
                "face_kind": "build_log",
            },
        )
        face_name = "shell-face.log"
        # Different timestamps must normalize identically to shell_face_digest.
        vuln_face = (
            "2099-02-02T11:22:33Z /work clang -fsanitize=address -g -O1 -Iinclude "
            "-D_GNU_SOURCE src/parser.c -o out/parser\n"
        ).encode("utf-8")
        fixed_face = (
            "2099-03-03T22:11:00Z /work clang -fsanitize=address -g -O1 -Iinclude "
            "-D_GNU_SOURCE src/parser.c -o out/parser\n"
        ).encode("utf-8")

    job, plan, plan_digest, review = _setup_fixture_plan_and_job(
        version=2, build_spec=spec
    )
    mem_state = _InMemoryState(job, plan, plan_digest, review)
    mem_state.install(monkeypatch)

    fake_sandbox = _FakeSandbox(
        image_digest=plan["image_digest"],
        build_recipe_digest=plan["build_recipe_digest"],
        faces={"vulnerable": vuln_face, "fixed": fixed_face},
        face_name=face_name,
    )

    result = execution.run_execution(
        "dsn",
        job["job_id"],
        1,
        case_root=str(FIXTURE_CASES),
        run_root=run_root,
        sandbox=fake_sandbox,
    )

    assert result.state == "REPRODUCED", f"{kind}: expected REPRODUCED, got {result}"
    assert result.evidence_path is not None
    assert len(fake_sandbox.build_calls) == 2
    assert len(fake_sandbox.replay_calls) == 6
    # Verify D4 at runtime: no inputs/* were ever mounted into build containers.
    for call in fake_sandbox.build_calls:
        assert call["build_spec"] == spec
        assert all(not rel.startswith("inputs/") for rel in call["staged_files"]), (
            f"v2 build container received input files: {call['staged_files']!r}"
        )

    # Offline v2 bundle verification must pass!
    verified = evidence.verify_bundle(result.evidence_path)
    assert verified.manifest["schema_version"] == 2
    assert verified.manifest["build_provenance_rules_version"] == build_provenance.RULES_VERSION

    files_by_path = {entry["path"]: entry for entry in verified.manifest["files"]}
    for version, expected_raw in (("vulnerable", vuln_face), ("fixed", fixed_face)):
        expected_entry = build_provenance.archive_face_entry(
            kind=kind, version=version, raw_face=expected_raw
        )
        assert expected_entry.path in files_by_path, (
            f"{kind}: missing D39 provenance face at {expected_entry.path}"
        )
        manifest_entry = files_by_path[expected_entry.path]
        assert manifest_entry["role"] == "build_provenance"
        assert manifest_entry["sha256"] == expected_entry.sha256
        assert len(manifest_entry["sha256"]) == 64
        assert verified.file_data[expected_entry.path] == expected_raw

    report = json.loads(verified.file_data["report.json"].decode("utf-8"))
    assert report["schema_version"] == 2
    assert report["build_provenance_rules_version"] == build_provenance.RULES_VERSION
    prov = report["build_provenance"]
    assert set(prov.keys()) == {"vulnerable", "fixed", "comparable"}, (
        f"report.build_provenance must be strictly closed 3-key schema, got {set(prov.keys())}"
    )
    assert prov["comparable"] is True
    for version in ("vulnerable", "fixed"):
        assert set(prov[version].keys()) == {"face", "declared", "effective"}
        assert prov[version]["face"] == face_name
        assert prov[version]["declared"] == DECLARED_FLAGS
        assert prov[version]["effective"] == DECLARED_FLAGS


def test_v2_campaign_report_includes_build_provenance_while_blocked_omits(
    tmp_path, monkeypatch
):
    run_root, _ = _configure_isolated_roots(tmp_path, monkeypatch)
    spec = _cmake_spec()
    job, plan, plan_digest, review = _setup_fixture_plan_and_job(
        version=2, build_spec=spec, round_no=None, job_kind="campaign"
    )
    mem_state = _InMemoryState(job, plan, plan_digest, review)
    mem_state.install(monkeypatch)
    ctx = execution._load_context(
        "dsn",
        job["job_id"],
        1,
        case_root=str(FIXTURE_CASES),
        run_root=run_root,
    )
    summary = {
        "vulnerable": {
            "face": "compile_commands.json",
            "declared": list(DECLARED_FLAGS),
            "effective": list(DECLARED_FLAGS),
        },
        "fixed": {
            "face": "compile_commands.json",
            "declared": list(DECLARED_FLAGS),
            "effective": list(DECLARED_FLAGS),
        },
        "comparable": True,
    }

    campaign_report, _ = execution._build_report(
        ctx,
        verdict=None,
        verdict_reason=None,
        decision=None,
        builds={},
        runs=[],
        probe=None,
        evidence_refs=["report.json", "report.md"],
        missing=[],
        build_provenance_summary=summary,
        bundle_kind="campaign",
    )
    assert campaign_report["schema_version"] == 2
    assert campaign_report["bundle_kind"] == "campaign"
    assert campaign_report["verdict"] is None
    assert campaign_report["state"] is None
    assert campaign_report["build_provenance_rules_version"] == build_provenance.RULES_VERSION
    assert set(campaign_report["build_provenance"].keys()) == {
        "vulnerable",
        "fixed",
        "comparable",
    }
    assert campaign_report["build_provenance"]["comparable"] is True

    blocked_report, _ = execution._build_report(
        ctx,
        verdict="BLOCKED",
        verdict_reason="POLICY_DENIED",
        decision=None,
        builds={},
        runs=[],
        probe=None,
        evidence_refs=["report.json", "report.md"],
        missing=["blocked"],
        error="POLICY_DENIED: blocked",
        bundle_kind="blocked",
    )
    assert blocked_report["bundle_kind"] == "blocked"
    assert "build_provenance" not in blocked_report


# ---------------------------------------------------------------------------
# 5b. Fail-closed provenance failures: FAILED + BUILD_PROVENANCE_MISSING, 0 replays
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "scenario",
    [
        "missing_fixed_face",
        "include_order_difference",
        "declared_flag_missing_from_effective",
        "drifted_shell_face",
        "pre_container_sandbox_error",
    ],
)
def test_v2_provenance_failure_fails_closed_without_replay_or_inconclusive_downgrade(
    tmp_path, monkeypatch, scenario
):
    run_root, _ = _configure_isolated_roots(tmp_path, monkeypatch)
    build_error: SandboxError | None = None

    if scenario == "missing_fixed_face":
        spec = _cmake_spec()
        face_name = "compile_commands.json"
        faces: dict[str, bytes | None] = {
            "vulnerable": _cmake_compile_commands_bytes(flags=DECLARED_FLAGS),
            "fixed": None,
        }
        expected_archived_versions = ("vulnerable",)
    elif scenario == "include_order_difference":
        # ADR-005 order counterexample: -I a -I b != -I b -I a
        flags_ab = ["-fsanitize=address", "-g", "-I", "a", "-I", "b"]
        flags_ba = ["-fsanitize=address", "-g", "-I", "b", "-I", "a"]
        spec = _make_spec(declared_compile_flags=["-fsanitize=address", "-g"])
        face_name = "cc-shim.log"
        faces = {
            "vulnerable": _make_cc_shim_log_bytes(flags=flags_ab),
            "fixed": _make_cc_shim_log_bytes(flags=flags_ba),
        }
        expected_archived_versions = ("vulnerable", "fixed")
    elif scenario == "declared_flag_missing_from_effective":
        spec = _cmake_spec(declared_compile_flags=["-fsanitize=address", "-g", "-O1"])
        face_name = "compile_commands.json"
        faces = {
            "vulnerable": _cmake_compile_commands_bytes(
                flags=["-fsanitize=address", "-g"]
            ),
            "fixed": _cmake_compile_commands_bytes(
                flags=["-fsanitize=address", "-g"]
            ),
        }
        expected_archived_versions = ("vulnerable", "fixed")
    elif scenario == "drifted_shell_face":
        baseline = "2099-01-01T00:00:00Z /work clang -fsanitize=address -g src/parser.c\n"
        spec = _shell_spec(
            face_digest=build_provenance.shell_face_digest(baseline, repo_root="/work"),
            review={
                "reviewer_id": "reviewer-01",
                "reviewed_at": "2099-01-01T00:00:00Z",
                "face_kind": "build_log",
            },
            declared_compile_flags=["-fsanitize=address", "-g"],
        )
        face_name = "shell-face.log"
        faces = {
            "vulnerable": baseline.encode("utf-8"),
            "fixed": b"2099-01-01T00:00:00Z /work clang -O3 -DEXTRA src/parser.c\n",
        }
        expected_archived_versions = ("vulnerable", "fixed")
    else:
        spec = _cmake_spec()
        face_name = "compile_commands.json"
        faces = {}
        expected_archived_versions = ()
        build_error = SandboxError(
            "build_spec rejected before container creation",
            reason_code=build_provenance.BUILD_PROVENANCE_MISSING,
        )

    job, plan, plan_digest, review = _setup_fixture_plan_and_job(
        version=2, build_spec=spec
    )
    mem_state = _InMemoryState(job, plan, plan_digest, review)
    mem_state.install(monkeypatch)

    fake_sandbox = _FakeSandbox(
        image_digest=plan["image_digest"],
        build_recipe_digest=plan["build_recipe_digest"],
        faces=faces,
        face_name=face_name,
        build_error=build_error,
    )

    result = execution.run_execution(
        "dsn",
        job["job_id"],
        1,
        case_root=str(FIXTURE_CASES),
        run_root=run_root,
        sandbox=fake_sandbox,
    )

    assert result.state == "FAILED", (
        f"{scenario}: must fail closed as FAILED (NEVER INCONCLUSIVE), got {result.state!r}"
    )
    assert result.reason_code == build_provenance.BUILD_PROVENANCE_MISSING, (
        f"{scenario}: expected BUILD_PROVENANCE_MISSING, got {result.reason_code!r}"
    )
    assert result.verdict is None, (
        f"{scenario}: FAILED provenance mismatch must not emit an outcome verdict"
    )
    assert len(fake_sandbox.replay_calls) == 0, (
        f"{scenario}: must NEVER enter 6-replay phase (got {len(fake_sandbox.replay_calls)} calls)"
    )
    assert result.evidence_path is not None, (
        f"{scenario}: evidence bundle preserving logs/faces/diff must be archived"
    )

    bundle_root = Path(result.evidence_path)
    manifest = json.loads((bundle_root / "manifest.json").read_text(encoding="utf-8"))
    report = json.loads((bundle_root / "report.json").read_text(encoding="utf-8"))

    assert manifest["schema_version"] == 2
    assert manifest["verdict"] == "FAILED"
    assert manifest["reason_code"] == build_provenance.BUILD_PROVENANCE_MISSING
    assert manifest["build_provenance_rules_version"] == build_provenance.RULES_VERSION

    assert report["schema_version"] == 2
    assert report["state"] == "FAILED"
    assert report["verdict"] == "FAILED"
    assert report["reason_code"] == build_provenance.BUILD_PROVENANCE_MISSING
    assert report["build_provenance_rules_version"] == build_provenance.RULES_VERSION
    assert set(report["build_provenance"].keys()) == {
        "vulnerable",
        "fixed",
        "comparable",
    }
    assert report["build_provenance"]["comparable"] is False
    assert isinstance(report["error"], str) and "BUILD_PROVENANCE_MISSING:" in report["error"]
    assert report["replays"] == []

    files_by_path = {entry["path"]: entry for entry in manifest["files"]}
    for version in expected_archived_versions:
        log_rel = f"build/{version}/build.log"
        assert log_rel in files_by_path, f"{scenario}: missing preserved {log_rel}"
        assert (bundle_root / log_rel).read_bytes() == fake_sandbox.build_logs[version]
        face_rel = f"build/{version}/build_provenance/{face_name}"
        assert face_rel in files_by_path, f"{scenario}: missing preserved {face_rel}"
        assert files_by_path[face_rel]["role"] == "build_provenance"
        assert (bundle_root / face_rel).read_bytes() == faces[version]

    # Double-check permission bits on archived files are non-writable (0444).
    mode = stat.S_IMODE((bundle_root / "report.json").stat().st_mode)
    assert mode == 0o444

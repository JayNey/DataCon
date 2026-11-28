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
import os
from pathlib import Path
import stat
import shutil
import subprocess
import time
import sys
from typing import Any
from uuid import UUID, uuid4

import pytest

from datacon import build_provenance, contracts, evidence, execution, jsonutil
from datacon.asan import ASanSignature
from datacon.cases import load_registry
from datacon.tools import sandbox as sandbox_mod
from datacon.tools.model_outlet import (
    DEFAULT_REDACTION_VERSION,
    MODEL_AUDIT_FIELDS,
    MODEL_AUDIT_SUMMARY_FIELDS,
    verify_model_audit_document,
)
from datacon.tools.sandbox import (
    MAX_ARTIFACT_BYTES,
    MAX_PROVENANCE_FACE_BYTES,
    SECCOMP_PROFILE_DIGEST,
    BuildOutput,
    BuildResult,
    DockerSandbox,
    IsolationPolicy,
    ProbeReport,
    ReplayResult,
    ResourceLimits,
    SandboxError,
    SandboxPolicyError,
    build_runner_command,
    merge_cc_shim_log,
    prepare_build_spec_execution,
    render_build_runner_script,
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
_FIXTURE_BUILD_RECIPE_DIGEST = (
    "sha256:" + hashlib.sha256((FIXTURE_CASES / "build.sh").read_bytes()).hexdigest()
)


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
        "shell_recipe_digest": _FIXTURE_BUILD_RECIPE_DIGEST,
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
    fixed_envelope = contracts.fixed_envelope(
        harness_digest=materials[manifest["harness"]],
        accepted_signature_set=[dict(manifest["asan_signature"])],
        max_total_seconds=manifest["limits"]["execute_seconds"],
    )
    envelope_digest = contracts.envelope_digest(fixed_envelope)
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
        job["envelope"] = deepcopy(fixed_envelope)
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
        self.budget_charges: list[dict[str, int]] = []
        self.admission: dict[str, Any] | None = None
        self.family_envelope: dict[str, Any] | None = None

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
        monkeypatch.setattr(
            execution.state,
            "execution_attempts_across_generations",
            self.execution_attempts_across_generations,
        )
        monkeypatch.setattr(execution.state, "mark_archiving", self.mark_archiving)
        monkeypatch.setattr(
            execution.state, "assert_archive_fence", self.assert_archive_fence
        )
        monkeypatch.setattr(execution.state, "finish_execution", self.finish_execution)
        monkeypatch.setattr(
            execution.state,
            "family_budget_summary",
            self.family_budget_summary,
        )
        monkeypatch.setattr(
            execution.state, "load_budget_ledger", self.load_budget_ledger
        )
        monkeypatch.setattr(
            execution.state, "charge_step_budget", self.charge_step_budget
        )
        monkeypatch.setattr(
            execution.state,
            "recover_uncharged_attempts",
            lambda _dsn, **_kwargs: 0,
        )
        monkeypatch.setattr(
            execution.state, "get_family_envelope", self.get_family_envelope
        )
        monkeypatch.setattr(
            execution.state, "get_admission", self.get_admission
        )

    def get_family_envelope(
        self, dsn: str, family_id: UUID | str, envelope_digest: str
    ) -> dict[str, Any] | None:
        envelope = self.family_envelope
        if envelope is None:
            envelope = self.job.get("envelope")
        if isinstance(envelope, dict) and (
            contracts.envelope_digest(envelope) == envelope_digest
        ):
            return deepcopy(envelope)
        return None

    def get_admission(
        self, dsn: str, job_id: UUID | str
    ) -> dict[str, Any] | None:
        return deepcopy(self.admission) if self.admission is not None else None

    def family_budget_summary(
        self, dsn: str, family_id: UUID | str
    ) -> dict[str, int]:
        envelope = self.job.get("envelope")
        if isinstance(envelope, dict):
            max_total = int(envelope["max_total_seconds"])
            max_fuzz = int(envelope["max_fuzz_seconds"])
        else:
            max_total = 1200
            max_fuzz = 0
        spent = sum(int(charge["seconds"]) for charge in self.budget_charges)
        spent_fuzz = sum(
            int(charge["fuzz_seconds"]) for charge in self.budget_charges
        )
        return {
            "max_total_seconds": max_total,
            "max_fuzz_seconds": max_fuzz,
            "spent_seconds": spent,
            "spent_fuzz_seconds": spent_fuzz,
            "remaining_seconds": max_total - spent,
            "remaining_fuzz_seconds": max_fuzz - spent_fuzz,
        }

    def load_budget_ledger(
        self, dsn: str, family_id: UUID | str
    ) -> dict[str, Any] | None:
        summary = self.family_budget_summary(dsn, family_id)
        return {
            "family_id": str(family_id),
            "max_total_seconds": summary["max_total_seconds"],
            "max_fuzz_seconds": summary["max_fuzz_seconds"],
            "remaining_total_seconds": summary["remaining_seconds"],
            "remaining_fuzz_seconds": summary["remaining_fuzz_seconds"],
        }

    def charge_step_budget(self, dsn: str, **kwargs: Any) -> Any:
        """Record T12 step charges with the real §7 formula, in memory."""
        key = (str(kwargs["job_id"]), kwargs["step_key"], kwargs["attempt_no"])
        for charge in self.budget_charges:
            if charge.get("key") == key:
                return execution.state.BudgetChargeOutcome(
                    "recovered", None, dict(charge), {}
                )
        ledger = self.load_budget_ledger(dsn, kwargs["family_id"])
        seconds, fuzz_seconds = execution.state.compute_budget_charge(
            ledger,
            charge_kind=kwargs["charge_kind"],
            elapsed_seconds=kwargs["elapsed_seconds"],
            elapsed_fuzz_seconds=kwargs.get("elapsed_fuzz_seconds", 0),
        )
        charge = {
            "key": key,
            "charge_kind": kwargs["charge_kind"],
            "seconds": seconds,
            "fuzz_seconds": fuzz_seconds,
        }
        self.budget_charges.append(charge)
        return execution.state.BudgetChargeOutcome(
            "charged", None, dict(charge), ledger
        )

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

    def execution_attempts_across_generations(
        self, dsn: str, job_id: UUID
    ) -> list[dict[str, Any]]:
        return [deepcopy(row) for row in self.attempts]

    def mark_archiving(self, dsn: str, job_id: UUID, *, generation: int) -> bool:
        self.job["state"] = "ARCHIVING"
        return True

    def assert_archive_fence(self, dsn: str, job_id: UUID, *, generation: int) -> bool:
        return True

    def finish_execution(self, dsn: str, job_id: UUID, **kwargs: Any) -> bool:
        evidence_status = kwargs.get("evidence_status")
        if evidence_status != "archived":
            if evidence_status not in (None, "failed"):
                raise execution.state.StateError(
                    "evidence_status must be archived or failed"
                )
            if (
                kwargs.get("verdict") is not None
                or kwargs.get("verdict_reason") is not None
            ):
                raise execution.state.StateError(
                    "a verdict requires archived evidence"
                )
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
        build_error_by_version: dict[str, SandboxError] | None = None,
        build_logs: dict[str, bytes] | None = None,
        build_outputs: dict[str, bytes] | None = None,
    ) -> None:
        self.image_digest = image_digest
        self.build_recipe_digest = build_recipe_digest
        self.faces = faces
        self.face_name = face_name
        self.build_error = build_error
        self.build_error_by_version = dict(build_error_by_version or {})
        self.build_logs = build_logs or {
            "vulnerable": b"building vulnerable...\n",
            "fixed": b"building fixed...\n",
        }
        self.build_outputs = dict(build_outputs or {})
        self.probe_calls: int = 0
        self.build_calls: list[dict[str, Any]] = []
        self.replay_calls: list[dict[str, Any]] = []

    def probe(self, *, deadline_seconds: float = 120.0) -> ProbeReport:
        self.probe_calls += 1
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
        if version in self.build_error_by_version:
            raise self.build_error_by_version[version]
        if self.build_error is not None:
            raise self.build_error
        artifact = f"ELF-{version}".encode("utf-8")
        raw_face = self.faces.get(version)
        log = self.build_logs.get(version, b"build ok\n")
        outputs: tuple[BuildOutput, ...] = ()
        primary_output: str | None = None
        if self.build_outputs:
            for rel_out, data in self.build_outputs.items():
                outputs += (
                    BuildOutput(
                        relative_path=rel_out,
                        archive_path=rel_out,
                        data=data,
                        digest=_sha256_prefixed(data),
                    ),
                )
                if primary_output is None or (
                    rel_out.rsplit("/", 1)[-1] == "parser"
                ):
                    primary_output = rel_out
            artifact = next(
                item.data
                for item in outputs
                if item.relative_path == primary_output
            )
            artifact_digest = _sha256_prefixed(artifact)
        else:
            artifact_digest = _sha256_prefixed(artifact)
        return BuildResult(
            version=version,
            status="completed",
            exit_code=0,
            duration_seconds=0.2,
            container_id=f"fake-build-{version}",
            image_digest=self.image_digest,
            compile_args=tuple(compile_args),
            artifact_digest=artifact_digest,
            log=log,
            log_truncated=False,
            artifact=artifact,
            metadata={
                "build_spec_kind": build_spec["kind"] if isinstance(build_spec, dict) else None,
                "build_recipe_digest": self.build_recipe_digest,
                "provenance_face_name": self.face_name,
                **({"primary_output": primary_output} if primary_output else {}),
            },
            provenance_face=raw_face,
            provenance_face_name=self.face_name,
            outputs=outputs,
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
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    fake_cmake = fake_bin / "cmake"
    fake_cmake.write_text(
        f"#!{sys.executable}\n"
        "import json, sys\n"
        f"with open({str(dump_file)!r}, 'a', encoding='utf-8') as f:\n"
        "    f.write(json.dumps(sys.argv[1:]) + '\\n')\n",
        encoding="utf-8",
    )
    fake_cmake.chmod(0o755)

    tricky_args = [
        f"-DPWN=$(touch {pwn_marker})",
        f"-DBACKTICK=`touch {pwn_marker}`",
        f"-DSEMI=1; touch {pwn_marker}",
        "-DSPACE=hello world",
        '-DQUOTES="nested \'quotes\'"',
        "-DGLOB=*",
    ]
    spec = _cmake_spec(
        configure=["cmake", "-S", ".", "-B", "build", *tricky_args],
        build=["cmake", "--build", "build", "--target", "; echo pwn", "$(id)"],
        install=["cmake", "--install", "build", "--prefix", "a b 'c' \"d\""],
    )
    plan = prepare_build_spec_execution(spec)
    cmd = build_runner_command(
        plan,
        stage_fixture=False,
        emit_result_marker=False,
        wait_for_release=False,
    )

    env = {**os.environ, "PATH": f"{fake_bin}:{os.environ.get('PATH', '')}"}
    proc = subprocess.run(
        cmd,
        cwd=tmp_path,
        env=env,
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
    assert lines[1] == ["--build", "build", "--target", "; echo pwn", "$(id)"], (
        f"build argv was altered or shell-expanded: {lines[1]!r}"
    )
    assert lines[2] == ["--install", "build", "--prefix", "a b 'c' \"d\""], (
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

    merge_cc_shim_log(log_path)
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
    else:
        spec = _cmake_spec()
        face_name = "compile_commands.json"
        faces = {}
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
    # B-6: the T13a partial layout accepts this bundle, so the produced
    # build evidence is preserved and the archive passes offline verification.
    assert result.evidence_path is not None, (
        f"{scenario}: partial FAILED evidence must now be archived"
    )
    verified = evidence.verify_bundle(result.evidence_path)
    manifest = verified.manifest
    report = json.loads(verified.file_data["report.json"])
    assert manifest["verdict"] == "FAILED"
    assert manifest["reason_code"] == build_provenance.BUILD_PROVENANCE_MISSING
    assert report["state"] == "FAILED"
    assert report["verdict"] == "FAILED"
    assert report["reason_code"] == build_provenance.BUILD_PROVENANCE_MISSING
    assert report["replays"] == []
    assert "envelope.json" in verified.file_data
    assert "budget/snapshot.json" in verified.file_data
    for version, raw_face in faces.items():
        if raw_face is None:
            continue
        log_rel = f"build/{version}/build.log"
        assert log_rel in verified.file_data
        assert verified.file_data[log_rel] == fake_sandbox.build_logs[version]
        face_rel = f"build/{version}/build_provenance/{face_name}"
        assert face_rel in verified.file_data
        assert verified.file_data[face_rel] == raw_face


# ---------------------------------------------------------------------------
# 6. Direct DockerSandbox._build_with_spec hardening & edge-case coverage
# ---------------------------------------------------------------------------


def _build_result_marker(artifact: bytes | None, *, code: int = 0) -> bytes:
    if artifact is None:
        return f"\nDATACON_BUILD_RESULT code={code} size=-1 digest=missing\n".encode("ascii")
    digest = hashlib.sha256(artifact).hexdigest()
    return (
        f"\nDATACON_BUILD_RESULT code={code} size={len(artifact)} digest={digest}\n"
    ).encode("ascii")


def test_build_with_spec_make_mounts_cc_and_cxx_shims_readonly_and_cleans_up_temp_dir(
    tmp_path, monkeypatch
):
    sandbox = _make_sandbox(tmp_path)
    materials = tmp_path / "materials"
    materials.mkdir()

    spec = _make_spec(cc="/opt/datacon/bin/cc-shim")
    spec["env"]["CXX"] = "/usr/local/bin/cxx-shim"

    artifact_bytes = b"ELF-make-parser"
    shim_log_bytes = _make_cc_shim_log_bytes(flags=DECLARED_FLAGS)

    observed_create: list[dict[str, Any]] = []
    observed_start: list[dict[str, Any]] = []
    staged_work_dirs: list[Path] = []
    staged_shim_paths: list[Path] = []

    def fake_create(*, suffix, command, mounts, env=None):
        observed_create.append(
            {
                "suffix": suffix,
                "command": list(command),
                "mounts": list(mounts),
                "env": dict(env or {}),
            }
        )
        # Inspect staged shims while the container would be alive.
        mount_map = {dst: (Path(src), ro) for src, dst, ro in mounts}
        assert mount_map["/fixture"] == (materials, True)
        cc_src, cc_ro = mount_map["/opt/datacon/bin/cc-shim"]
        cxx_src, cxx_ro = mount_map["/usr/local/bin/cxx-shim"]
        assert cc_ro is True and cxx_ro is True
        assert not cc_src.is_symlink() and cc_src.is_file()
        assert not cxx_src.is_symlink() and cxx_src.is_file()
        assert stat.S_IMODE(cc_src.stat().st_mode) == 0o555
        assert stat.S_IMODE(cxx_src.stat().st_mode) == 0o555
        cc_text = cc_src.read_text(encoding="utf-8")
        cxx_text = cxx_src.read_text(encoding="utf-8")
        assert "_datacon_real_compiler=clang\n" in cc_text
        assert "_datacon_real_compiler=clang++\n" in cxx_text
        assert "/work/.datacon-cc-shim.log" in cc_text
        assert "/work/.datacon-cc-shim.log" in cxx_text
        assert cc_src.parent == cxx_src.parent
        staged_work_dirs.append(cc_src.parent)
        staged_shim_paths.extend([cc_src, cxx_src])
        return "fake-make-cid", {}

    def fake_start_and_wait(
        name, *, deadline_seconds, artifact=False, extra_copy_paths=()
    ):
        observed_start.append(
            {
                "name": name,
                "artifact": artifact,
                "extra_copy_paths": list(extra_copy_paths),
            }
        )
        return (
            b"make stdout\n",
            b"make stderr\n" + _build_result_marker(artifact_bytes, code=0),
            {
                "/work/src/parser": artifact_bytes,
                "/work/.datacon-cc-shim.log": shim_log_bytes,
            },
            set(),
            {"Running": False, "Status": "exited", "ExitCode": 0},
            False,
            0,
            None,
        )

    monkeypatch.setattr(sandbox, "_create", fake_create)
    monkeypatch.setattr(sandbox, "_start_and_wait", fake_start_and_wait)

    result = sandbox.build("vulnerable", materials_dir=materials, build_spec=spec)

    assert result.status == "completed"
    assert result.artifact == artifact_bytes
    assert result.artifact_digest == _sha256_prefixed(artifact_bytes)
    assert result.provenance_face == shim_log_bytes
    assert result.provenance_face_name == "cc-shim.log"
    assert result.log_truncated is False
    assert result.metadata["provenance_face_truncated"] is False
    assert len(observed_create) == 1
    assert len(observed_start) == 1
    assert observed_start[0]["extra_copy_paths"] == [
        ("/work/src/parser", MAX_ARTIFACT_BYTES),
        ("/work/.datacon-cc-shim.log", MAX_PROVENANCE_FACE_BYTES),
    ]
    # Both shim files AND the per-build temp directory must be removed in finally.
    assert len(staged_work_dirs) == 1
    for shim_path in staged_shim_paths:
        assert not shim_path.exists(), f"shim file leaked after build: {shim_path}"
    assert not staged_work_dirs[0].exists(), (
        f"per-build temp dir leaked after build: {staged_work_dirs[0]}"
    )

    # Also verify cleanup happens when _create raises.
    staged_work_dirs.clear()
    staged_shim_paths.clear()

    def failing_create(*, suffix, command, mounts, env=None):
        mount_map = {dst: Path(src) for src, dst, _ in mounts}
        cc_src = mount_map["/opt/datacon/bin/cc-shim"]
        cxx_src = mount_map["/usr/local/bin/cxx-shim"]
        staged_work_dirs.append(cc_src.parent)
        staged_shim_paths.extend([cc_src, cxx_src])
        raise SandboxError("simulated docker create failure")

    monkeypatch.setattr(sandbox, "_create", failing_create)
    with pytest.raises(SandboxError, match="simulated docker create failure"):
        sandbox.build("vulnerable", materials_dir=materials, build_spec=spec)
    assert len(staged_work_dirs) == 1
    for shim_path in staged_shim_paths:
        assert not shim_path.exists()
    assert not staged_work_dirs[0].exists()


@pytest.mark.parametrize("symlink_level", ["run_root", "build", "version"])
def test_build_with_spec_rejects_symlinks_under_untrusted_run_root(
    tmp_path, monkeypatch, symlink_level
):
    outside = tmp_path / "outside-target"
    outside.mkdir()
    run_root = tmp_path / "untrusted-run-root"
    if symlink_level == "run_root":
        run_root.symlink_to(outside)
    elif symlink_level == "build":
        run_root.mkdir()
        (run_root / "build").symlink_to(outside)
    else:
        (run_root / "build").mkdir(parents=True)
        (run_root / "build" / "vulnerable").symlink_to(outside)

    sandbox = DockerSandbox(
        image=IMAGE,
        platform="linux/amd64",
        policy=POLICY,
        limits=LIMITS,
        job_id=str(uuid4()),
        run_root=run_root,
        generation=1,
    )
    create_calls = 0

    def fail_create(*args: Any, **kwargs: Any) -> Any:
        nonlocal create_calls
        create_calls += 1
        raise AssertionError("_create must not be called when run_root contains a symlink")

    monkeypatch.setattr(sandbox, "_create", fail_create)
    materials = tmp_path / "materials"
    materials.mkdir()

    with pytest.raises(SandboxPolicyError):
        sandbox.build(
            "vulnerable",
            materials_dir=materials,
            build_spec=_make_spec(),
        )
    assert create_calls == 0
    assert list(outside.iterdir()) == [], (
        f"symlink boundary was crossed at {symlink_level}: {list(outside.iterdir())!r}"
    )


def test_build_with_spec_insource_cmake_reads_work_compile_commands_and_handles_B_variants(
    tmp_path, monkeypatch
):
    # Omitted -B (in-source build) must target /work/compile_commands.json.
    for insource_cfg in (["cmake", "."], ["cmake", "-S", "."]):
        plan = prepare_build_spec_execution(
            _cmake_spec(
                configure=insource_cfg,
                build=["cmake", "--build", ".", "--target", "parser"],
                outputs=["parser"],
            )
        )
        assert plan.cmake_build_dir == "."
        assert plan.provenance_face_container_path == "/work/compile_commands.json"

    # Connected -B<dir> must target /work/<dir>/compile_commands.json.
    connected_plan = prepare_build_spec_execution(
        _cmake_spec(configure=["cmake", "-S", ".", "-Bcustom_out"])
    )
    assert connected_plan.cmake_build_dir == "custom_out"
    assert (
        connected_plan.provenance_face_container_path
        == "/work/custom_out/compile_commands.json"
    )

    # Dangling -B without a value must fail closed.
    with pytest.raises(SandboxError) as exc_info:
        prepare_build_spec_execution(
            _cmake_spec(configure=["cmake", "-S", ".", "-B"])
        )
    assert exc_info.value.reason_code == build_provenance.BUILD_PROVENANCE_MISSING

    # End-to-end mocked _build_with_spec on in-source CMake.
    sandbox = _make_sandbox(tmp_path)
    materials = tmp_path / "materials"
    materials.mkdir()
    spec = _cmake_spec(
        configure=["cmake", "."],
        build=["cmake", "--build", ".", "--target", "parser"],
        outputs=["parser"],
    )
    artifact_bytes = b"ELF-insource-cmake"
    face_bytes = _cmake_compile_commands_bytes(
        flags=DECLARED_FLAGS, directory="/work", source="/work/src/parser.c"
    )
    captured_extra: list[tuple[str, int]] = []

    monkeypatch.setattr(sandbox, "_create", lambda **kwargs: ("fake-cmake-cid", {}))

    def fake_start(name, *, deadline_seconds, artifact=False, extra_copy_paths=()):
        captured_extra.extend(extra_copy_paths)
        return (
            b"cmake ok\n",
            _build_result_marker(artifact_bytes, code=0),
            {
                "/work/parser": artifact_bytes,
                "/work/compile_commands.json": face_bytes,
            },
            set(),
            {"Running": False, "Status": "exited", "ExitCode": 0},
            False,
            0,
            None,
        )

    monkeypatch.setattr(sandbox, "_start_and_wait", fake_start)
    result = sandbox.build("vulnerable", materials_dir=materials, build_spec=spec)
    assert result.status == "completed"
    assert result.provenance_face == face_bytes
    assert result.provenance_face_name == "compile_commands.json"
    assert ("/work/compile_commands.json", MAX_PROVENANCE_FACE_BYTES) in captured_extra
    # Ensure no per-build temp dir leaked for cmake either.
    version_dir = sandbox.run_root / "build" / "vulnerable"
    assert version_dir.is_dir() and list(version_dir.iterdir()) == []


def test_build_with_spec_missing_primary_output_never_falls_back_to_work_parser_or_sets_log_truncated(
    tmp_path, monkeypatch
):
    sandbox = _make_sandbox(tmp_path)
    materials = tmp_path / "materials"
    materials.mkdir()

    # 1. CMake build declaring build/parser, which was NOT produced while an unrelated
    # /work/parser exists in the container tmpfs.
    cmake_spec = _cmake_spec(outputs=["build/parser"])
    face_bytes = _cmake_compile_commands_bytes(flags=DECLARED_FLAGS)

    monkeypatch.setattr(sandbox, "_create", lambda **kwargs: ("fake-missing-cid", {}))

    def fake_start_missing(
        name, *, deadline_seconds, artifact=False, extra_copy_paths=()
    ):
        return (
            b"build output\n",
            _build_result_marker(None, code=0),
            {
                "/work/parser": b"UNRELATED-STALE-BINARY",
                "/work/build/compile_commands.json": face_bytes,
            },
            set(),
            {"Running": False, "Status": "exited", "ExitCode": 0},
            False,
            0,
            None,
        )

    monkeypatch.setattr(sandbox, "_start_and_wait", fake_start_missing)
    cmake_res = sandbox.build(
        "vulnerable", materials_dir=materials, build_spec=cmake_spec
    )
    assert cmake_res.status == "build_failed"
    assert cmake_res.artifact is None
    assert cmake_res.artifact_digest is None
    assert cmake_res.log_truncated is False, (
        "missing primary output must not falsely flag log_truncated=True"
    )
    assert cmake_res.capture_error is None
    assert cmake_res.metadata["outputs"]["build/parser"] is None
    assert cmake_res.provenance_face == face_bytes

    # 2. Shell build declaring out/parser missing while unrelated /work/parser exists
    # must also keep log_truncated=False and provenance_face_truncated=False.
    shell_spec = _shell_spec(
        face_digest="sha256:" + "3" * 64,
        review={
            "reviewer_id": "reviewer-01",
            "reviewed_at": "2099-01-01T00:00:00Z",
            "face_kind": "build_log",
        },
    )
    shell_res = sandbox.build(
        "vulnerable", materials_dir=materials, build_spec=shell_spec
    )
    assert shell_res.status == "build_failed"
    assert shell_res.artifact is None
    assert shell_res.log_truncated is False
    assert shell_res.metadata["provenance_face_truncated"] is False
    assert shell_res.provenance_face == shell_res.log


@pytest.mark.parametrize("mode", ["truncated_stream", "oversize_bytes", "shell_stream_truncated"])
def test_build_with_spec_provenance_face_truncation_and_oversize_fail_closed(
    tmp_path, monkeypatch, mode
):
    sandbox = _make_sandbox(tmp_path)
    materials = tmp_path / "materials"
    materials.mkdir()
    artifact_bytes = b"ELF-ok"

    monkeypatch.setattr(sandbox, "_create", lambda **kwargs: ("fake-trunc-cid", {}))

    if mode == "shell_stream_truncated":
        spec = _shell_spec(
            face_digest="sha256:" + "4" * 64,
            review={
                "reviewer_id": "reviewer-01",
                "reviewed_at": "2099-01-01T00:00:00Z",
                "face_kind": "build_log",
            },
        )
        out_path = "/work/out/parser"

        def fake_start_shell(
            name, *, deadline_seconds, artifact=False, extra_copy_paths=()
        ):
            return (
                b"truncated log...",
                _build_result_marker(artifact_bytes, code=0),
                {out_path: artifact_bytes},
                {"stdout"},
                {"Running": False, "Status": "exited", "ExitCode": 0},
                False,
                0,
                None,
            )

        monkeypatch.setattr(sandbox, "_start_and_wait", fake_start_shell)
        result = sandbox.build("vulnerable", materials_dir=materials, build_spec=spec)
        assert result.provenance_face is None
        assert result.metadata["provenance_face_truncated"] is True
        assert result.log_truncated is True
        return

    spec = _cmake_spec()
    face_path = "/work/build/compile_commands.json"
    if mode == "oversize_bytes":
        monkeypatch.setattr(sandbox_mod, "MAX_PROVENANCE_FACE_BYTES", 64)
        face_payload = b"[" + b" " * 128 + b"]"
        truncated_set: set[str] = set()
    else:
        face_payload = _cmake_compile_commands_bytes(flags=DECLARED_FLAGS)
        truncated_set = {face_path}

    captured_extra: list[tuple[str, int]] = []

    def fake_start_cmake(
        name, *, deadline_seconds, artifact=False, extra_copy_paths=()
    ):
        captured_extra.extend(extra_copy_paths)
        return (
            b"cmake build\n",
            _build_result_marker(artifact_bytes, code=0),
            {
                "/work/build/parser": artifact_bytes,
                face_path: face_payload,
            },
            truncated_set,
            {"Running": False, "Status": "exited", "ExitCode": 0},
            False,
            0,
            None,
        )

    monkeypatch.setattr(sandbox, "_start_and_wait", fake_start_cmake)
    result = sandbox.build("vulnerable", materials_dir=materials, build_spec=spec)
    assert (face_path, sandbox_mod.MAX_PROVENANCE_FACE_BYTES) in captured_extra
    assert result.provenance_face is None
    assert result.metadata["provenance_face_truncated"] is True
    assert result.log_truncated is True


@pytest.mark.parametrize(
    "bad_cc,bad_cxx",
    [
        ("/work/cc-shim", None),
        ("/work/bin/cc-shim", None),
        ("//work/cc-shim", None),
        ("/tmp/cc-shim", None),
        ("/tmp/bin/cc-shim", None),
        ("/fixture/cc-shim", None),
        ("/proc/cc-shim", None),
        ("/sys/cc-shim", None),
        ("/dev/cc-shim", None),
        ("/opt/datacon/cc-shim", "/work/cxx-shim"),
        ("/opt/datacon/cc-shim", "/tmp/bin/cxx-shim"),
    ],
)
def test_shim_destination_rejects_conflicting_mount_prefixes_before_create(
    tmp_path, monkeypatch, bad_cc, bad_cxx
):
    sandbox = _make_sandbox(tmp_path)
    create_calls = 0

    def fail_create(*args: Any, **kwargs: Any) -> Any:
        nonlocal create_calls
        create_calls += 1
        raise AssertionError("_create must not be called for conflicting shim destination")

    monkeypatch.setattr(sandbox, "_create", fail_create)
    materials = tmp_path / "materials"
    materials.mkdir()

    spec = _make_spec(cc=bad_cc)
    if bad_cxx is not None:
        spec["env"]["CXX"] = bad_cxx

    with pytest.raises(SandboxError) as exc_info:
        sandbox.build("vulnerable", materials_dir=materials, build_spec=spec)
    assert exc_info.value.reason_code == build_provenance.BUILD_PROVENANCE_MISSING
    assert create_calls == 0


@pytest.mark.parametrize(
    "good_cc,good_cxx",
    [
        ("/opt/datacon/cc-shim", None),
        ("/opt/datacon/bin/cc-shim", "/opt/datacon/bin/cxx-shim"),
        ("/usr/local/bin/cc-shim", "/usr/local/bin/cxx-shim"),
    ],
)
def test_shim_destination_allows_spec_valid_readonly_rootfs_paths(good_cc, good_cxx):
    spec = _make_spec(cc=good_cc)
    if good_cxx is not None:
        spec["env"]["CXX"] = good_cxx
    plan = prepare_build_spec_execution(spec)
    assert plan.cc_shim_destination == good_cc
    assert plan.cxx_shim_destination == good_cxx


# ---------------------------------------------------------------------------
# 7. plan.compile_flags vs build_spec.declared_compile_flags consistency
# ---------------------------------------------------------------------------


def test_v2_compile_flags_normalized_equivalent_passes_end_to_end(
    tmp_path, monkeypatch
):
    run_root, _ = _configure_isolated_roots(tmp_path, monkeypatch)
    # Split/absolute form in plan.compile_flags vs connected/relative form in build_spec.
    spec = _cmake_spec(
        declared_compile_flags=[
            "-fsanitize=address",
            "-g",
            "-O1",
            "-Iinclude",
            "-D_GNU_SOURCE",
        ]
    )
    equivalent_plan_flags = [
        "-fsanitize=address",
        "-g",
        "-O1",
        "-I",
        "/work/include",
        "-D",
        "_GNU_SOURCE",
    ]
    job, plan, plan_digest, review = _setup_fixture_plan_and_job(
        version=2, build_spec=spec, compile_flags=equivalent_plan_flags
    )
    mem_state = _InMemoryState(job, plan, plan_digest, review)
    mem_state.install(monkeypatch)

    face = _cmake_compile_commands_bytes(
        flags=["-fsanitize=address", "-g", "-O1", "-I../include", "-D_GNU_SOURCE"]
    )
    fake_sandbox = _FakeSandbox(
        image_digest=plan["image_digest"],
        build_recipe_digest=plan["build_recipe_digest"],
        faces={"vulnerable": face, "fixed": face},
        face_name="compile_commands.json",
    )

    result = execution.run_execution(
        "dsn",
        job["job_id"],
        1,
        case_root=str(FIXTURE_CASES),
        run_root=run_root,
        sandbox=fake_sandbox,
    )
    assert result.state == "REPRODUCED"
    assert len(fake_sandbox.build_calls) == 2
    assert len(fake_sandbox.replay_calls) == 6


@pytest.mark.parametrize(
    "label,plan_flags,spec_flags",
    [
        (
            "extra_flag_in_build_spec",
            ["-fsanitize=address", "-g"],
            ["-fsanitize=address", "-g", "-O1"],
        ),
        (
            "order_difference",
            ["-fsanitize=address", "-I", "a", "-I", "b"],
            ["-fsanitize=address", "-I", "b", "-I", "a"],
        ),
    ],
)
def test_v2_compile_flags_vs_declared_compile_flags_mismatch_fails_closed(
    tmp_path, monkeypatch, label, plan_flags, spec_flags
):
    run_root, _ = _configure_isolated_roots(tmp_path, monkeypatch)
    spec = _cmake_spec(declared_compile_flags=spec_flags)
    job, plan, plan_digest, review = _setup_fixture_plan_and_job(
        version=2, build_spec=spec, compile_flags=plan_flags
    )
    mem_state = _InMemoryState(job, plan, plan_digest, review)
    mem_state.install(monkeypatch)

    face = _cmake_compile_commands_bytes(flags=spec_flags)
    fake_sandbox = _FakeSandbox(
        image_digest=plan["image_digest"],
        build_recipe_digest=plan["build_recipe_digest"],
        faces={"vulnerable": face, "fixed": face},
        face_name="compile_commands.json",
    )

    result = execution.run_execution(
        "dsn",
        job["job_id"],
        1,
        case_root=str(FIXTURE_CASES),
        run_root=run_root,
        sandbox=fake_sandbox,
    )
    assert result.state == "FAILED", f"{label}: expected FAILED, got {result}"
    assert result.reason_code == build_provenance.BUILD_PROVENANCE_MISSING
    assert result.verdict is None
    assert len(fake_sandbox.build_calls) == 0, f"{label}: must not build on mismatch"
    assert len(fake_sandbox.replay_calls) == 0, f"{label}: must run 0 replays"
    assert result.evidence_path is not None
    verified = evidence.verify_bundle(result.evidence_path)
    report = json.loads(verified.file_data["report.json"])
    assert verified.manifest["verdict"] == "FAILED"
    assert report["reason_code"] == build_provenance.BUILD_PROVENANCE_MISSING
    assert report["build_provenance"]["comparable"] is False
    assert "plan.compile_flags" in str(report["error"])


# ---------------------------------------------------------------------------
# 8. _archive_only recovery on v2 preserves FAILED / BUILD_PROVENANCE_MISSING
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "scenario",
    [
        "missing_face_zero_replays",
        "deleted_face_with_six_non_crashing_replays",
        "non_comparable_faces_with_six_replays",
        "compile_flags_mismatch_in_archive_only",
    ],
)
def test_v2_archive_only_recovery_never_downgrades_provenance_failure(
    tmp_path, monkeypatch, scenario
):
    run_root, _ = _configure_isolated_roots(tmp_path, monkeypatch)

    if scenario == "non_comparable_faces_with_six_replays":
        spec = _make_spec(declared_compile_flags=["-fsanitize=address", "-g"])
        face_name = "cc-shim.log"
        vuln_face: bytes | None = _make_cc_shim_log_bytes(
            flags=["-fsanitize=address", "-g", "-I", "a", "-I", "b"]
        )
        fixed_face: bytes | None = _make_cc_shim_log_bytes(
            flags=["-fsanitize=address", "-g", "-I", "b", "-I", "a"]
        )
        plan_compile_flags: list[str] | None = None
    elif scenario == "compile_flags_mismatch_in_archive_only":
        spec = _cmake_spec(declared_compile_flags=["-fsanitize=address", "-g", "-O1"])
        face_name = "compile_commands.json"
        vuln_face = _cmake_compile_commands_bytes(
            flags=["-fsanitize=address", "-g", "-O1"]
        )
        fixed_face = _cmake_compile_commands_bytes(
            flags=["-fsanitize=address", "-g", "-O1"]
        )
        plan_compile_flags = ["-fsanitize=address", "-g"]
    else:
        spec = _cmake_spec()
        face_name = "compile_commands.json"
        vuln_face = _cmake_compile_commands_bytes(flags=DECLARED_FLAGS)
        fixed_face = (
            None
            if scenario == "missing_face_zero_replays"
            else _cmake_compile_commands_bytes(flags=DECLARED_FLAGS)
        )
        plan_compile_flags = None

    job, plan, plan_digest, review = _setup_fixture_plan_and_job(
        version=2, build_spec=spec, compile_flags=plan_compile_flags
    )
    # Generation 2 recovers an ARCHIVING job whose steps ran in generation 1.
    job["state"] = "ARCHIVING"
    job["generation"] = 2
    mem_state = _InMemoryState(job, plan, plan_digest, review)
    mem_state.install(monkeypatch)

    ctx = execution._load_context(
        "dsn",
        job["job_id"],
        2,
        case_root=str(FIXTURE_CASES),
        run_root=run_root,
    )
    work_root = execution._work_root(ctx)
    gen1_root = work_root / "generation-1"

    # Seed completed probe attempt from generation 1.
    probe_payload = {
        "tool_id": "sandbox.probe",
        "job_id": ctx.job_id_text,
        "generation": 1,
        "plan_digest": plan_digest,
        "status": "completed",
        "ok": True,
        "checks": {"uid": "65534", "errors": []},
        "compiler_version": "clang 19.1.7",
        "image_digest": plan["image_digest"],
    }
    mem_state.record_attempt(
        "dsn",
        job["job_id"],
        stage="execute",
        step_key="sandbox.probe",
        attempt_no=1,
        generation=1,
        input_digest=plan_digest,
        status="completed",
        result=probe_payload,
    )

    # Seed completed build attempts (vulnerable & fixed) on disk under generation 1.
    face_paths: dict[str, Path] = {}
    for version, raw_face in (("vulnerable", vuln_face), ("fixed", fixed_face)):
        bdir = gen1_root / "build" / version
        bdir.mkdir(parents=True, exist_ok=True)
        log_bytes = f"build {version}\n".encode("utf-8")
        art_bytes = f"ELF-{version}".encode("utf-8")
        log_file = bdir / "build.log"
        art_file = bdir / "parser"
        log_file.write_bytes(log_bytes)
        art_file.write_bytes(art_bytes)
        files_map: dict[str, Any] = {
            "log": str(log_file.relative_to(work_root)),
            "artifact": str(art_file.relative_to(work_root)),
        }
        digests_map: dict[str, Any] = {
            "log": _sha256_prefixed(log_bytes),
            "artifact": _sha256_prefixed(art_bytes),
        }
        if raw_face is not None:
            fdir = bdir / "build_provenance"
            fdir.mkdir(parents=True, exist_ok=True)
            ffile = fdir / face_name
            ffile.write_bytes(raw_face)
            face_paths[version] = ffile
            files_map["provenance_face"] = str(ffile.relative_to(work_root))
            digests_map["provenance_face"] = _sha256_prefixed(raw_face)
        build_payload = {
            "tool_id": "sandbox.build",
            "job_id": ctx.job_id_text,
            "generation": 1,
            "plan_digest": plan_digest,
            "input_digest": plan["analysis_digest"],
            "status": "completed",
            "version": version,
            "container_id": f"gen1-build-{version}",
            "artifact_digest": _sha256_prefixed(art_bytes),
            "attempt_no": 1,
            "files": files_map,
            "file_digests": digests_map,
            "build_spec_kind": spec["kind"],
            "provenance_face_name": face_name,
        }
        mem_state.record_attempt(
            "dsn",
            job["job_id"],
            stage="execute",
            step_key=f"build:{version}",
            attempt_no=1,
            generation=1,
            input_digest=plan["analysis_digest"],
            status="completed",
            result=build_payload,
        )

    # For scenarios with 6 replays, seed clean non-crashing replays (which would
    # otherwise yield NOT_REPRODUCED if provenance were bypassed!).
    if scenario != "missing_face_zero_replays":
        for version in ("vulnerable", "fixed"):
            for phase in ("normal", "candidate_1", "candidate_2"):
                rdir = gen1_root / "replay" / version / phase
                rdir.mkdir(parents=True, exist_ok=True)
                out_bytes = b"OK\n" if phase == "normal" else b"ABCD\n"
                err_bytes = b""
                out_file = rdir / "stdout.log"
                err_file = rdir / "stderr.log"
                out_file.write_bytes(out_bytes)
                err_file.write_bytes(err_bytes)
                in_digest = (
                    plan["inputs"]["normal"]
                    if phase == "normal"
                    else plan["inputs"]["candidate"]
                )
                replay_payload = {
                    "tool_id": "sandbox.replay",
                    "job_id": ctx.job_id_text,
                    "generation": 1,
                    "plan_digest": plan_digest,
                    "input_digest": in_digest,
                    "artifact_digest": _sha256_prefixed(f"ELF-{version}".encode("utf-8")),
                    "status": "completed",
                    "version": version,
                    "phase": phase,
                    "exit_code": 0,
                    "duration_seconds": 0.05,
                    "container_id": f"gen1-replay-{version}-{phase}",
                    "signature": None,
                    "timed_out": False,
                    "quota_hit": False,
                    "log_truncated": False,
                    "capture_error": None,
                    "truncated_roles": [],
                    "attempt_no": 1,
                    "files": {
                        "stdout": str(out_file.relative_to(work_root)),
                        "stderr": str(err_file.relative_to(work_root)),
                    },
                    "file_digests": {
                        "stdout": _sha256_prefixed(out_bytes),
                        "stderr": _sha256_prefixed(err_bytes),
                    },
                }
                mem_state.record_attempt(
                    "dsn",
                    job["job_id"],
                    stage="execute",
                    step_key=f"replay:{version}:{phase}",
                    attempt_no=1,
                    generation=1,
                    input_digest=in_digest,
                    status="completed",
                    result=replay_payload,
                )

    if scenario == "deleted_face_with_six_non_crashing_replays":
        # Remove the fixed provenance face from disk before _archive_only runs.
        face_paths["fixed"].unlink()

    result = execution.run_execution(
        "dsn",
        job["job_id"],
        2,
        case_root=str(FIXTURE_CASES),
        run_root=run_root,
    )
    assert result.state == "FAILED", (
        f"{scenario}: _archive_only must stay FAILED (never INCONCLUSIVE/NOT_REPRODUCED), "
        f"got {result}"
    )
    assert result.reason_code == build_provenance.BUILD_PROVENANCE_MISSING
    assert result.verdict is None
    assert result.evidence_path is not None
    verified = evidence.verify_bundle(result.evidence_path)
    assert verified.manifest["verdict"] == "FAILED"
    assert verified.manifest["reason_code"] == build_provenance.BUILD_PROVENANCE_MISSING


# ---------------------------------------------------------------------------
# 9. Regression tests for B1-B5 and non-blocking #1-#6
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "sandbox_reason,expected_reason",
    [
        ("TIMEOUT", "TIMEOUT"),
        ("SANDBOX_ERROR", "RUN_INCOMPLETE"),
    ],
)
def test_b1_v2_partial_inconclusive_build_timeout_and_sandbox_error_preserve_evidence(
    tmp_path, monkeypatch, sandbox_reason, expected_reason
):
    """B1: v2 partial INCONCLUSIVE (0 replays) preserves verdict, reason, and partial logs."""
    run_root, _ = _configure_isolated_roots(tmp_path, monkeypatch)
    spec = _cmake_spec()
    vuln_face = _cmake_compile_commands_bytes(flags=DECLARED_FLAGS)

    job, plan, plan_digest, review = _setup_fixture_plan_and_job(
        version=2, build_spec=spec
    )
    mem_state = _InMemoryState(job, plan, plan_digest, review)
    mem_state.install(monkeypatch)

    fake_sandbox = _FakeSandbox(
        image_digest=plan["image_digest"],
        build_recipe_digest=plan["build_recipe_digest"],
        faces={"vulnerable": vuln_face, "fixed": None},
        face_name="compile_commands.json",
        build_error_by_version={
            "fixed": SandboxError(
                f"simulated fixed build {sandbox_reason}",
                reason_code=sandbox_reason,
            )
        },
    )

    result = execution.run_execution(
        "dsn",
        job["job_id"],
        1,
        case_root=str(FIXTURE_CASES),
        run_root=run_root,
        sandbox=fake_sandbox,
    )

    assert result.state == "INCONCLUSIVE", (
        f"v2 partial {sandbox_reason} must stay INCONCLUSIVE (not FAILED / EVIDENCE_WRITE_FAILED), got {result}"
    )
    assert result.verdict == "INCONCLUSIVE"
    assert result.verdict_reason == expected_reason
    assert result.reason_code == expected_reason
    assert result.evidence_path is not None
    assert len(fake_sandbox.replay_calls) == 0
    verified = evidence.verify_bundle(result.evidence_path)
    report = json.loads(verified.file_data["report.json"])
    assert verified.manifest["verdict"] == "INCONCLUSIVE"
    assert verified.manifest["reason_code"] == expected_reason
    assert report["verdict"] == "INCONCLUSIVE"
    assert report["reason_code"] == expected_reason
    assert report["rule"] is None
    assert report["replays"] == []
    assert "build/vulnerable/build.log" in verified.file_data
    assert (
        "build/vulnerable/build_provenance/compile_commands.json"
        in verified.file_data
    )


@pytest.mark.parametrize(
    "label,bad_spec,face_name",
    [
        (
            "bad_shell_missing_digest_and_review",
            _shell_spec(face_digest=None, review=None),
            "shell-face.log",
        ),
        (
            "bad_make_non_shim_cc",
            _make_spec(cc="/usr/bin/clang"),
            "cc-shim.log",
        ),
        (
            "bad_make_missing_cc_env",
            _make_spec(cc=None),
            "cc-shim.log",
        ),
        (
            "bad_cmake_export_off",
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
            "compile_commands.json",
        ),
    ],
)
def test_b2_invalid_build_spec_fails_closed_before_probe_and_in_defense_in_depth(
    tmp_path, monkeypatch, label, bad_spec, face_name
):
    """B2: invalid BuildSpec fails closed before sandbox.probe AND on reuse/custom-sandbox paths."""
    run_root, _ = _configure_isolated_roots(tmp_path, monkeypatch)
    job, plan, plan_digest, review = _setup_fixture_plan_and_job(
        version=2, build_spec=bad_spec
    )
    mem_state = _InMemoryState(job, plan, plan_digest, review)
    mem_state.install(monkeypatch)

    fake_sandbox = _FakeSandbox(
        image_digest=plan["image_digest"],
        build_recipe_digest=plan["build_recipe_digest"],
        faces={},
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

    assert result.state == "FAILED", f"{label}: expected FAILED, got {result}"
    assert result.reason_code == build_provenance.BUILD_PROVENANCE_MISSING
    assert result.verdict is None
    assert fake_sandbox.probe_calls == 0, f"{label}: sandbox.probe must never be called"
    assert len(fake_sandbox.build_calls) == 0, f"{label}: sandbox.build must never be called"
    assert len(fake_sandbox.replay_calls) == 0, f"{label}: sandbox.replay must never be called"

    # Defense-in-depth: even if builds were reused or produced by a custom sandbox
    # with syntactically valid provenance faces on disk, _verify_v2_build_provenance
    # must still reject the invalid BuildSpec.
    mem_state.job["state"] = "RUNNING"
    ctx = execution._load_context(
        "dsn",
        job["job_id"],
        1,
        case_root=str(FIXTURE_CASES),
        run_root=run_root,
    )
    work_root = execution._work_root(ctx)
    gen_root = work_root / "generation-1"
    raw_face = (
        _cmake_compile_commands_bytes(flags=DECLARED_FLAGS)
        if bad_spec["kind"] == "cmake"
        else (
            _make_cc_shim_log_bytes(flags=DECLARED_FLAGS)
            if bad_spec["kind"] == "make"
            else b"2099-01-01T00:00:00Z /work clang -fsanitize=address -g src/parser.c\n"
        )
    )
    reused_builds: dict[str, dict[str, Any]] = {}
    for version in ("vulnerable", "fixed"):
        fdir = gen_root / "build" / version / "build_provenance"
        fdir.mkdir(parents=True, exist_ok=True)
        ffile = fdir / face_name
        ffile.write_bytes(raw_face)
        reused_builds[version] = {
            "files": {"provenance_face": str(ffile.relative_to(work_root))},
            "file_digests": {"provenance_face": _sha256_prefixed(raw_face)},
            "provenance_face_name": face_name,
        }

    outcome = execution._verify_v2_build_provenance(ctx, work_root, reused_builds)
    assert outcome.comparable is False, (
        f"{label}: defense-in-depth _verify_v2_build_provenance must fail closed"
    )
    assert outcome.error_detail


@pytest.mark.parametrize(
    "label,bad_spec",
    [
        ("shell-sh-c", {**_shell_spec(face_digest="sha256:" + "a" * 64, review={"reviewer_id": "r", "reviewed_at": "2099-01-01T00:00:00Z", "face_kind": "build_log"}), "build": ["sh", "-c", "echo pwn"]}),
        ("shell-eval", {**_shell_spec(face_digest="sha256:" + "a" * 64, review={"reviewer_id": "r", "reviewed_at": "2099-01-01T00:00:00Z", "face_kind": "build_log"}), "build": ["eval", "echo pwn"]}),
        ("shell-python3-c", {**_shell_spec(face_digest="sha256:" + "a" * 64, review={"reviewer_id": "r", "reviewed_at": "2099-01-01T00:00:00Z", "face_kind": "build_log"}), "build": ["python3", "-c", "import os"]}),
        ("cmake-sh-c", _cmake_spec(configure=["sh", "-c", "cmake ."])),
        ("cmake-python3-c", _cmake_spec(build=["python3", "-c", "print(1)"])),
        ("cmake-script-mode", _cmake_spec(configure=["cmake", "-P", "evil.cmake"])),
        ("make-eval", {**_make_spec(), "build": ["eval", "make"]}),
        ("make-sh-c", {**_make_spec(), "build": ["sh", "-c", "make"]}),
        ("make-cli-cc-override", {**_make_spec(), "build": ["make", "CC=clang", "parser"]}),
        ("make-cli-cxx-override", {**_make_spec(), "build": ["make", "CXX=clang++", "parser"]}),
        ("make-cli-eval-flag", {**_make_spec(), "build": ["make", "--eval=all:;echo pwn"]}),
        ("make-cli-env-override-flag", {**_make_spec(), "build": ["make", "-e", "parser"]}),
        ("make-cli-cc-after-double-dash", {**_make_spec(), "build": ["make", "--", "CC=clang"]}),
    ],
)
def test_b3_template_closedness_rejects_arbitrary_commands_and_overrides(label, bad_spec):
    """B3: both freeze validation and prepare_build_spec_execution enforce closed templates."""
    decision = build_provenance.validate_build_spec_for_freeze(bad_spec)
    assert decision.ok is False, f"{label}: freeze validation must reject"
    assert decision.reason_code == build_provenance.BUILD_PROVENANCE_MISSING

    with pytest.raises(SandboxError) as exc_info:
        prepare_build_spec_execution(bad_spec)
    assert exc_info.value.reason_code == build_provenance.BUILD_PROVENANCE_MISSING


def test_b3_runner_subshell_isolation_blocks_eval_mutating_runner_state(tmp_path):
    """B3: runner executes each step in an isolated subshell via exec so eval cannot overwrite _datacon_out."""
    target_out = tmp_path / "never_created_parser"
    script = render_build_runner_script(
        stage_fixture=False,
        emit_result_marker=True,
        wait_for_release=False,
    )
    cmd = [
        "/bin/sh",
        "-c",
        script,
        "datacon-build-runner",
        str(target_out),
        "0",  # _n_clean
        "0",  # _n_cfg
        "2",  # _n_bld
        "eval",
        "_datacon_out=/etc/passwd",
        "0",  # _n_inst
    ]
    proc = subprocess.run(
        cmd,
        cwd=tmp_path,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    stderr_text = proc.stderr.decode("utf-8", "replace")
    assert proc.returncode != 0, "exec eval inside subshell must fail instead of executing builtin"
    assert "DATACON_BUILD_RESULT code=" in stderr_text
    assert "size=-1 digest=missing" in stderr_text, (
        f"_datacon_out was mutated to an existing file! stderr={stderr_text!r}"
    )


def test_b4_runner_prebuild_cleanup_and_symlink_rejection_and_copy_work_path(
    tmp_path, monkeypatch
):
    """B4: runner cleans pre-existing faces/outputs and rejects symlinks in marker and _copy_work_path."""
    # 1. Pre-build cleanup removes stale outputs and provenance face before build runs.
    stale_out = tmp_path / "stale_parser"
    stale_face = tmp_path / "stale_compile_commands.json"
    stale_out.write_bytes(b"STALE-BINARY")
    stale_face.write_bytes(b'[{"stale": true}]')

    script = render_build_runner_script(
        stage_fixture=False,
        emit_result_marker=True,
        wait_for_release=False,
    )
    cmd_clean = [
        "/bin/sh",
        "-c",
        script,
        "datacon-build-runner",
        str(stale_out),
        "2",
        str(stale_out),
        str(stale_face),
        "0",
        "1",
        shutil.which("true") or "/usr/bin/true",
        "0",
    ]
    proc_clean = subprocess.run(
        cmd_clean, cwd=tmp_path, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False
    )
    assert proc_clean.returncode == 0
    assert not stale_out.exists(), "pre-existing output must be cleaned before build"
    assert not stale_face.exists(), "pre-existing provenance face must be cleaned before build"
    assert "size=-1 digest=missing" in proc_clean.stderr.decode("utf-8", "replace")

    # 2. Runner marker refuses symlinked output produced during build.
    secret = tmp_path / "secret.txt"
    secret.write_bytes(b"TOP-SECRET-CONTENT")
    symlink_out = tmp_path / "symlink_parser"
    cmd_symlink = [
        "/bin/sh",
        "-c",
        script,
        "datacon-build-runner",
        str(symlink_out),
        "1",
        str(symlink_out),
        "0",
        "4",
        "/bin/ln",
        "-s",
        str(secret),
        str(symlink_out),
        "0",
    ]
    proc_sym = subprocess.run(
        cmd_symlink, cwd=tmp_path, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False
    )
    assert proc_sym.returncode == 0
    assert symlink_out.is_symlink()
    assert "size=-1 digest=missing" in proc_sym.stderr.decode("utf-8", "replace"), (
        "runner result marker must reject symlinked outputs"
    )

    # 3. _copy_work_path rejects symlinked outputs, symlinked provenance faces, and symlinked dirs.
    fake_work = tmp_path / "fake_work"
    (fake_work / "build").mkdir(parents=True)
    regular_file = fake_work / "build" / "parser"
    regular_file.write_bytes(b"REGULAR-ELF")
    leaf_symlink_out = fake_work / "build" / "symlink_out"
    leaf_symlink_out.symlink_to(secret)
    leaf_symlink_face = fake_work / "build" / "compile_commands.json"
    leaf_symlink_face.symlink_to(secret)
    outside_dir = tmp_path / "outside_dir"
    outside_dir.mkdir()
    (outside_dir / "compile_commands.json").write_bytes(b"[]")
    (fake_work / "symlink_dir").symlink_to(outside_dir)

    sandbox = _make_sandbox(tmp_path)

    def local_docker(args, *, timeout=30):
        # Execute the exact POSIX sh -c check emitted by _copy_work_path against fake_work.
        assert args[:4] == ["exec", "fake-cid", "sh", "-c"]
        shell_snippet = args[4].replace("/work", str(fake_work))
        shell_args = [arg.replace("/work", str(fake_work)) for arg in args[5:]]
        return subprocess.run(
            ["/bin/sh", "-c", shell_snippet, *shell_args],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )

    monkeypatch.setattr(sandbox, "_docker", local_docker)

    data_ok, size_ok, trunc_ok = sandbox._copy_work_path(
        "fake-cid", "/work/build/parser", MAX_ARTIFACT_BYTES
    )
    assert (data_ok, size_ok, trunc_ok) == (b"REGULAR-ELF", len(b"REGULAR-ELF"), False)

    for symlink_target in (
        "/work/build/symlink_out",
        "/work/build/compile_commands.json",
        "/work/symlink_dir/compile_commands.json",
    ):
        assert sandbox._copy_work_path(
            "fake-cid", symlink_target, MAX_PROVENANCE_FACE_BYTES
        ) == (b"", 0, False), f"_copy_work_path must refuse symlink path {symlink_target}"


@pytest.mark.parametrize("lock_mode", ["flock", "mkdir_fallback"])
def test_b5_cc_shim_concurrent_large_flags_produces_valid_jsonl(tmp_path, lock_mode):
    """B5: parallel cc-shim invocations with >16 KiB flags emit 100% valid non-interleaved JSONL."""
    stub_cc = tmp_path / "stub-clang"
    stub_cc.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    stub_cc.chmod(0o755)

    log_path = tmp_path / f"cc-shim-{lock_mode}.log"
    shim_script = render_cc_shim_script(
        real_compiler=str(stub_cc),
        log_path=str(log_path),
    )
    # B-1: the shared-append fallback is gone. Both parameterizations exercise
    # the same private-fragment protocol; no shim ever opens a shared log or a
    # shared lock, so there is no 8 KiB interleaving window to schedule into.
    assert "command -v flock" not in shim_script
    assert "flock -x" not in shim_script
    assert ".lock" not in shim_script
    assert 'fragment-$$-' in shim_script
    if lock_mode == "mkdir_fallback":
        assert "mkdir" in shim_script
    shim_path = tmp_path / f"cc-shim-{lock_mode}"
    shim_path.write_text(shim_script, encoding="utf-8")
    shim_path.chmod(0o755)

    workers = 12
    # >16 KiB per invocation (well above 4 KiB PIPE_BUF).
    big_chunk = "X" * 100
    procs: list[subprocess.Popen[bytes]] = []
    for idx in range(workers):
        large_flags = [f"-DW{idx}_K{k}={big_chunk}" for k in range(170)]
        assert sum(len(f) for f in large_flags) > 16 * 1024
        procs.append(
            subprocess.Popen(
                [str(shim_path), *large_flags, "-c", f"src/unit_{idx}.c", "-o", f"u_{idx}.o"],
                cwd=tmp_path,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
        )

    for idx, proc in enumerate(procs):
        _out, err = proc.communicate(timeout=30)
        assert proc.returncode == 0, (
            f"worker {idx} failed rc={proc.returncode} stderr={err.decode('utf-8', 'replace')}"
        )

    merge_cc_shim_log(log_path)
    raw_lines = [
        line for line in log_path.read_text(encoding="utf-8").splitlines() if line.strip()
    ]
    assert len(raw_lines) == workers, (
        f"{lock_mode}: expected {workers} JSONL lines, got {len(raw_lines)}"
    )
    seen_units: set[str] = set()
    for line_no, line in enumerate(raw_lines, start=1):
        rec = jsonutil.loads_strict(line)
        assert isinstance(rec, dict) and set(rec.keys()) == {"cwd", "compiler", "argv"}
        assert len(rec["argv"]) == 1 + 170 + 4, f"line {line_no} truncated/interleaved"
        seen_units.add(rec["argv"][-3])
    assert seen_units == {f"src/unit_{idx}.c" for idx in range(workers)}


def test_b1_cc_shim_fragment_merge_is_single_writer_and_complete(tmp_path):
    """B-1: the merger concatenates completed fragments without interleaving.

    This is the deterministic half of the concurrency test: 12 fragments of
    >16 KiB are pre-created (including a deliberately adversarial byte order
    that would corrupt a shared append), then the single-writer merger is run
    and every resulting line must be strict JSON.
    """
    log_path = tmp_path / "cc-shim.log"
    fragment_dir = log_path.with_name(log_path.name + ".d")
    fragment_dir.mkdir()
    for idx in range(12):
        flags = ["-DW%d_K%d=%s" % (idx, k, "Y" * 100) for k in range(170)]
        record = json.dumps(
            {
                "cwd": str(tmp_path),
                "compiler": "clang",
                "argv": ["clang", *flags, "-c", f"src/unit_{idx}.c", "-o", f"u_{idx}.o"],
            },
            separators=(",", ":"),
        ).encode("utf-8") + b"\n"
        assert len(record) > 16 * 1024
        # Reverse creation order so lexical merge order is not creation order.
        (fragment_dir / f"fragment-{11 - idx:02d}-nonce.jsonl").write_bytes(record)
    merge_cc_shim_log(log_path)
    raw_lines = log_path.read_text(encoding="utf-8").splitlines()
    assert len(raw_lines) == 12
    assert not fragment_dir.exists()
    seen: set[str] = set()
    for line in raw_lines:
        record = jsonutil.loads_strict(line)
        assert isinstance(record, dict)
        assert set(record) == {"cwd", "compiler", "argv"}
        assert len(record["argv"]) == 1 + 170 + 4
        seen.add(record["argv"][-3])
    assert seen == {f"src/unit_{idx}.c" for idx in range(12)}


@pytest.mark.parametrize(
    "forbidden_key",
    ["PATH", "LD_PRELOAD", "LD_LIBRARY_PATH", "TMPDIR", "HOME", "ASAN_OPTIONS", "DATACON_SECRET"],
)
def test_nonblocking_1_forbidden_env_keys_rejected_in_freeze_and_prepare(forbidden_key):
    """#1: dangerous env keys (PATH, LD_PRELOAD, etc.) are rejected in BuildSpec.env."""
    for spec in (_cmake_spec(), _make_spec()):
        spec["env"][forbidden_key] = "/tmp/evil"
        decision = build_provenance.validate_build_spec_for_freeze(spec)
        assert decision.ok is False, f"freeze must reject env.{forbidden_key}"
        assert decision.reason_code == build_provenance.BUILD_PROVENANCE_MISSING
        with pytest.raises(SandboxError) as exc_info:
            prepare_build_spec_execution(spec)
        assert exc_info.value.reason_code == build_provenance.BUILD_PROVENANCE_MISSING


@pytest.mark.parametrize(
    "label,bad_spec",
    [
        ("cmake-abs-B", _cmake_spec(configure=["cmake", "-S", ".", "-B", "/etc"])),
        ("cmake-traversal-B", _cmake_spec(configure=["cmake", "-S", ".", "-B", "../escape"])),
        ("make-work-cc-shim", _make_spec(cc="/work/cc-shim")),
        ("make-tmp-cc-shim", _make_spec(cc="/tmp/cc-shim")),
        ("outputs-semicolon", _cmake_spec(outputs=["build/parser;id"])),
        ("outputs-whitespace", _cmake_spec(outputs=["build/par ser"])),
        ("outputs-subshell", _cmake_spec(outputs=["build/$(id)"])),
        ("env-key-with-equals", _cmake_spec(env={"CC": "clang", "FOO=BAR": "1"})),
        ("env-key-starts-with-digit", _cmake_spec(env={"CC": "clang", "1BAD": "1"})),
    ],
)
def test_nonblocking_2_freeze_and_prepare_parity(label, bad_spec):
    """#2: validate_build_spec_for_freeze and prepare_build_spec_execution reject identically."""
    decision = build_provenance.validate_build_spec_for_freeze(bad_spec)
    assert decision.ok is False, f"{label}: freeze validation must reject"
    assert decision.reason_code == build_provenance.BUILD_PROVENANCE_MISSING

    with pytest.raises(SandboxError) as exc_info:
        prepare_build_spec_execution(bad_spec)
    assert exc_info.value.reason_code == build_provenance.BUILD_PROVENANCE_MISSING


@pytest.mark.parametrize("bad_cxx", ["clang++", "/usr/bin/g++", "/work/cxx-shim"])
def test_nonblocking_3_make_explicit_non_shim_cxx_rejected(bad_cxx):
    """#3: make BuildSpec with explicit non-shim env.CXX fails closed."""
    spec = _make_spec()
    spec["env"]["CXX"] = bad_cxx
    decision = build_provenance.validate_build_spec_for_freeze(spec)
    assert decision.ok is False
    assert decision.reason_code == build_provenance.BUILD_PROVENANCE_MISSING

    with pytest.raises(SandboxError) as exc_info:
        prepare_build_spec_execution(spec)
    assert exc_info.value.reason_code == build_provenance.BUILD_PROVENANCE_MISSING


def test_nonblocking_4_provenance_parser_and_normalizer_edge_cases():
    """#4: out-of-repo conftest filtering, -M/-MM skip, empty token lookahead, -include-pth."""
    # 1. CMake face with /tmp/conftest.c and -MM dependency gen entry alongside real CU.
    cmake_payload = json.dumps(
        [
            {
                "directory": "/work/build",
                "file": "/tmp/conftest.c",
                "arguments": ["clang", "-O0", "-c", "/tmp/conftest.c", "-o", "/tmp/conftest.o"],
            },
            {
                "directory": "/work/build",
                "file": "/work/src/parser.c",
                "arguments": ["clang", "-MM", "-I../include", "/work/src/parser.c"],
            },
            {
                "directory": "/work/build",
                "file": "/work/src/parser.c",
                "arguments": [
                    "clang",
                    "-fsanitize=address",
                    "-g",
                    "-c",
                    "/work/src/parser.c",
                    "-o",
                    "parser.o",
                ],
            },
        ]
    ).encode("utf-8")
    parsed_cmake = build_provenance.parse_provenance_face(
        kind="cmake", raw_face=cmake_payload, repo_root="/work"
    )
    assert list(parsed_cmake.units.keys()) == ["src/parser.c"]
    assert parsed_cmake.units["src/parser.c"] == ["-fsanitize=address", "-g"]

    # 2. Make cc-shim face with /tmp/conftest.c and -M/-MM dependency gen entries.
    make_lines = "\n".join(
        json.dumps(rec)
        for rec in [
            {
                "cwd": "/work",
                "compiler": "clang",
                "argv": ["clang", "-O0", "-c", "/tmp/conftest.c", "-o", "/tmp/conftest.o"],
            },
            {
                "cwd": "/work",
                "compiler": "clang",
                "argv": ["clang", "-M", "src/parser.c"],
            },
            {
                "cwd": "/work",
                "compiler": "clang",
                "argv": ["clang", "-MM", "src/parser.c"],
            },
            {
                "cwd": "/work",
                "compiler": "clang",
                "argv": ["clang", "-fsanitize=address", "-g", "-c", "src/parser.c", "-o", "p.o"],
            },
        ]
    ).encode("utf-8")
    parsed_make = build_provenance.parse_provenance_face(
        kind="make", raw_face=make_lines, repo_root="/work"
    )
    assert list(parsed_make.units.keys()) == ["src/parser.c"]
    assert parsed_make.units["src/parser.c"] == ["-fsanitize=address", "-g"]

    # 3. Empty token between -I and its directory argument.
    assert build_provenance.normalize_compile_flags(
        ["-I", "", "include", "-g"], repo_root="/work"
    ) == ["-Iinclude", "-g"]

    # 4. -include-pth / -include-pch / -isystem-after are NOT split as -include / -isystem.
    assert build_provenance.normalize_compile_flags(
        ["-include-pth", "a.pth", "-include-pch", "b.pch", "-isystem-after", "/usr/include"],
        repo_root="/work",
    ) == ["-include-pth", "a.pth", "-include-pch", "b.pch", "-isystem-after", "/usr/include"]


def _seed_archive_only_v2_job(
    *,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    spec: dict[str, Any],
    face_name: str,
    faces_by_version: dict[str, bytes | None],
    with_replays: bool,
    reproduced_crash: bool = False,
) -> tuple[dict[str, Any], Path]:
    run_root, _ = _configure_isolated_roots(tmp_path, monkeypatch)
    job, plan, plan_digest, review = _setup_fixture_plan_and_job(
        version=2, build_spec=spec
    )
    job["state"] = "ARCHIVING"
    job["generation"] = 2
    mem_state = _InMemoryState(job, plan, plan_digest, review)
    mem_state.install(monkeypatch)

    ctx = execution._load_context(
        "dsn",
        job["job_id"],
        2,
        case_root=str(FIXTURE_CASES),
        run_root=run_root,
    )
    work_root = execution._work_root(ctx)
    gen1_root = work_root / "generation-1"

    probe_payload = {
        "tool_id": "sandbox.probe",
        "job_id": ctx.job_id_text,
        "generation": 1,
        "plan_digest": plan_digest,
        "status": "completed",
        "ok": True,
        "checks": {"uid": "65534", "errors": []},
        "compiler_version": "clang 19.1.7",
        "image_digest": plan["image_digest"],
    }
    mem_state.record_attempt(
        "dsn",
        job["job_id"],
        stage="execute",
        step_key="sandbox.probe",
        attempt_no=1,
        generation=1,
        input_digest=plan_digest,
        status="completed",
        result=probe_payload,
    )

    for version, raw_face in faces_by_version.items():
        bdir = gen1_root / "build" / version
        bdir.mkdir(parents=True, exist_ok=True)
        log_bytes = f"build {version}\n".encode("utf-8")
        art_bytes = f"ELF-{version}".encode("utf-8")
        log_file = bdir / "build.log"
        art_file = bdir / "parser"
        log_file.write_bytes(log_bytes)
        art_file.write_bytes(art_bytes)
        files_map: dict[str, Any] = {
            "log": str(log_file.relative_to(work_root)),
            "artifact": str(art_file.relative_to(work_root)),
        }
        digests_map: dict[str, Any] = {
            "log": _sha256_prefixed(log_bytes),
            "artifact": _sha256_prefixed(art_bytes),
        }
        if raw_face is not None:
            fdir = bdir / "build_provenance"
            fdir.mkdir(parents=True, exist_ok=True)
            ffile = fdir / face_name
            ffile.write_bytes(raw_face)
            files_map["provenance_face"] = str(ffile.relative_to(work_root))
            digests_map["provenance_face"] = _sha256_prefixed(raw_face)
        build_payload = {
            "tool_id": "sandbox.build",
            "job_id": ctx.job_id_text,
            "generation": 1,
            "plan_digest": plan_digest,
            "input_digest": plan["analysis_digest"],
            "status": "completed",
            "version": version,
            "container_id": f"gen1-build-{version}",
            "artifact_digest": _sha256_prefixed(art_bytes),
            "attempt_no": 1,
            "files": files_map,
            "file_digests": digests_map,
            "build_spec_kind": spec["kind"],
            "provenance_face_name": face_name,
        }
        mem_state.record_attempt(
            "dsn",
            job["job_id"],
            stage="execute",
            step_key=f"build:{version}",
            attempt_no=1,
            generation=1,
            input_digest=plan["analysis_digest"],
            status="completed",
            result=build_payload,
        )

    if with_replays:
        for version in ("vulnerable", "fixed"):
            for phase in ("normal", "candidate_1", "candidate_2"):
                rdir = gen1_root / "replay" / version / phase
                rdir.mkdir(parents=True, exist_ok=True)
                is_vuln_crash = (
                    reproduced_crash and version == "vulnerable" and phase != "normal"
                )
                out_bytes = b"OK\n" if phase == "normal" else (b"" if is_vuln_crash else b"ABCD\n")
                err_bytes = (
                    (
                        "ERROR: AddressSanitizer: heap-buffer-overflow on address 0x1\n"
                        "WRITE of size 1 at 0x1 thread T0\n"
                        "    #0 0x123 in parse_token parser.c:12\n"
                    ).encode("utf-8")
                    if is_vuln_crash
                    else b""
                )
                sig = (
                    {
                        "error": "heap-buffer-overflow",
                        "operation": "WRITE",
                        "access_size": 1,
                        "function": "parse_token",
                        "source": "parser.c",
                    }
                    if is_vuln_crash
                    else None
                )
                out_file = rdir / "stdout.log"
                err_file = rdir / "stderr.log"
                out_file.write_bytes(out_bytes)
                err_file.write_bytes(err_bytes)
                in_digest = (
                    plan["inputs"]["normal"]
                    if phase == "normal"
                    else plan["inputs"]["candidate"]
                )
                replay_payload = {
                    "tool_id": "sandbox.replay",
                    "job_id": ctx.job_id_text,
                    "generation": 1,
                    "plan_digest": plan_digest,
                    "input_digest": in_digest,
                    "artifact_digest": _sha256_prefixed(f"ELF-{version}".encode("utf-8")),
                    "status": "completed",
                    "version": version,
                    "phase": phase,
                    "exit_code": 86 if is_vuln_crash else 0,
                    "duration_seconds": 0.05,
                    "container_id": f"gen1-replay-{version}-{phase}",
                    "signature": sig,
                    "timed_out": False,
                    "quota_hit": False,
                    "log_truncated": False,
                    "capture_error": None,
                    "truncated_roles": [],
                    "attempt_no": 1,
                    "files": {
                        "stdout": str(out_file.relative_to(work_root)),
                        "stderr": str(err_file.relative_to(work_root)),
                    },
                    "file_digests": {
                        "stdout": _sha256_prefixed(out_bytes),
                        "stderr": _sha256_prefixed(err_bytes),
                    },
                }
                mem_state.record_attempt(
                    "dsn",
                    job["job_id"],
                    stage="execute",
                    step_key=f"replay:{version}:{phase}",
                    attempt_no=1,
                    generation=1,
                    input_digest=in_digest,
                    status="completed",
                    result=replay_payload,
                )

    return job, run_root


def test_nonblocking_5_archive_only_v2_normal_recovery_and_single_build_provenance(
    tmp_path, monkeypatch
):
    """#5: normal v2 _archive_only recovers REPRODUCED; single-build corrupt face -> BUILD_PROVENANCE_MISSING."""
    # A. Normal v2 recovery with 2 comparable builds + 6 replays -> REPRODUCED + verify_bundle.
    face = _cmake_compile_commands_bytes(
        flags=["-fsanitize=address", "-g", "-O1", "-I../include", "-D_GNU_SOURCE"]
    )
    job_ok, run_root_ok = _seed_archive_only_v2_job(
        tmp_path=tmp_path / "ok",
        monkeypatch=monkeypatch,
        spec=_cmake_spec(),
        face_name="compile_commands.json",
        faces_by_version={"vulnerable": face, "fixed": face},
        with_replays=True,
        reproduced_crash=True,
    )
    res_ok = execution.run_execution(
        "dsn",
        job_ok["job_id"],
        2,
        case_root=str(FIXTURE_CASES),
        run_root=run_root_ok,
    )
    assert res_ok.state == "REPRODUCED", f"expected normal v2 archive recovery REPRODUCED, got {res_ok}"
    assert res_ok.evidence_path is not None
    verified = evidence.verify_bundle(res_ok.evidence_path)
    assert verified.manifest["verdict"] == "REPRODUCED"
    paths = {entry["path"] for entry in verified.manifest["files"]}
    assert "build/vulnerable/build_provenance/compile_commands.json" in paths
    assert "build/fixed/build_provenance/compile_commands.json" in paths

    # B. Single completed build with corrupt JSON face -> FAILED / BUILD_PROVENANCE_MISSING.
    job_corrupt, run_root_corrupt = _seed_archive_only_v2_job(
        tmp_path=tmp_path / "single_corrupt",
        monkeypatch=monkeypatch,
        spec=_cmake_spec(),
        face_name="compile_commands.json",
        faces_by_version={"vulnerable": b"{not valid json"},
        with_replays=False,
    )
    res_corrupt = execution.run_execution(
        "dsn",
        job_corrupt["job_id"],
        2,
        case_root=str(FIXTURE_CASES),
        run_root=run_root_corrupt,
    )
    assert res_corrupt.state == "FAILED", (
        f"single-build corrupt face must fail closed as FAILED, got {res_corrupt}"
    )
    assert res_corrupt.reason_code == build_provenance.BUILD_PROVENANCE_MISSING

    # C. Single completed build with valid face missing declared flag -> FAILED / BUILD_PROVENANCE_MISSING.
    incomplete_flags_face = _cmake_compile_commands_bytes(flags=["-fsanitize=address"])
    job_missing_flag, run_root_missing_flag = _seed_archive_only_v2_job(
        tmp_path=tmp_path / "single_missing_flag",
        monkeypatch=monkeypatch,
        spec=_cmake_spec(),
        face_name="compile_commands.json",
        faces_by_version={"vulnerable": incomplete_flags_face},
        with_replays=False,
    )
    res_missing_flag = execution.run_execution(
        "dsn",
        job_missing_flag["job_id"],
        2,
        case_root=str(FIXTURE_CASES),
        run_root=run_root_missing_flag,
    )
    assert res_missing_flag.state == "FAILED"
    assert res_missing_flag.reason_code == build_provenance.BUILD_PROVENANCE_MISSING

    # D. Single completed build with valid conforming face -> INCONCLUSIVE / EVIDENCE_INCOMPLETE.
    job_valid_single, run_root_valid_single = _seed_archive_only_v2_job(
        tmp_path=tmp_path / "single_valid",
        monkeypatch=monkeypatch,
        spec=_cmake_spec(),
        face_name="compile_commands.json",
        faces_by_version={"vulnerable": face},
        with_replays=False,
    )
    res_valid_single = execution.run_execution(
        "dsn",
        job_valid_single["job_id"],
        2,
        case_root=str(FIXTURE_CASES),
        run_root=run_root_valid_single,
    )
    assert res_valid_single.state == "INCONCLUSIVE"
    assert res_valid_single.reason_code == "EVIDENCE_INCOMPLETE"


def test_nonblocking_6_persist_build_oversize_face_and_campaign_inputs_none_and_multi_outputs(
    tmp_path, monkeypatch
):
    """#6: _persist_build oversize pre-check, campaign inputs=None guard, and multi-outputs."""
    # A. _persist_build rejects >MAX_PROVENANCE_FACE_BYTES BEFORE writing face to disk.
    run_root, _ = _configure_isolated_roots(tmp_path / "oversize", monkeypatch)
    job, plan, plan_digest, review = _setup_fixture_plan_and_job(
        version=2, build_spec=_cmake_spec()
    )
    mem_state = _InMemoryState(job, plan, plan_digest, review)
    mem_state.install(monkeypatch)
    ctx = execution._load_context(
        "dsn", job["job_id"], 1, case_root=str(FIXTURE_CASES), run_root=run_root
    )
    gen_root = execution._generation_root(ctx)
    gen_root.mkdir(parents=True, exist_ok=True)
    artifact = b"ELF-bin"
    oversize_face = b"x" * (MAX_PROVENANCE_FACE_BYTES + 1)
    build_result = BuildResult(
        version="vulnerable",
        status="completed",
        exit_code=0,
        duration_seconds=0.1,
        container_id="cid-1",
        image_digest=plan["image_digest"],
        compile_args=tuple(DECLARED_FLAGS),
        artifact_digest=_sha256_prefixed(artifact),
        log=b"ok\n",
        log_truncated=False,
        artifact=artifact,
        metadata={},
        provenance_face=oversize_face,
        provenance_face_name="compile_commands.json",
    )
    with pytest.raises(execution.ExecutionFailed) as exc_info:
        execution._persist_build("dsn", ctx, build_result, attempt_no=1, token="tok-1")
    assert exc_info.value.reason_code == build_provenance.BUILD_PROVENANCE_MISSING
    face_dir = gen_root / "build" / "vulnerable" / "build_provenance"
    assert not face_dir.exists(), (
        "oversize provenance face must be rejected before creating or writing to run_root"
    )

    # B. Campaign plan (inputs=None) in run_execution blocks cleanly without TypeError.
    camp_run_root, _ = _configure_isolated_roots(tmp_path / "campaign", monkeypatch)
    camp_job, camp_plan, camp_digest, camp_review = _setup_fixture_plan_and_job(
        version=2, build_spec=_cmake_spec(), round_no=None, job_kind="campaign"
    )
    assert camp_plan["inputs"] is None
    camp_state = _InMemoryState(camp_job, camp_plan, camp_digest, camp_review)
    camp_state.install(monkeypatch)
    camp_sandbox = _FakeSandbox(
        image_digest=camp_plan["image_digest"],
        build_recipe_digest=camp_plan["build_recipe_digest"],
        faces={},
        face_name="compile_commands.json",
    )
    camp_result = execution.run_execution(
        "dsn",
        camp_job["job_id"],
        1,
        case_root=str(FIXTURE_CASES),
        run_root=camp_run_root,
        sandbox=camp_sandbox,
    )
    assert camp_result.state == "BLOCKED"
    assert camp_result.reason_code == "MATERIAL_MISSING"
    assert camp_sandbox.probe_calls == 0
    assert len(camp_sandbox.build_calls) == 0
    assert len(camp_sandbox.replay_calls) == 0
    assert camp_result.evidence_path is not None
    evidence.verify_bundle(camp_result.evidence_path)

    # C. Multi-outputs BuildSpec cleans and copies all outputs and picks parser as primary.
    multi_spec = _cmake_spec(outputs=["build/libhelper.so", "build/parser"])
    multi_plan = prepare_build_spec_execution(multi_spec)
    assert multi_plan.primary_output == "build/parser"
    assert multi_plan.output_container_paths == (
        ("build/libhelper.so", "/work/build/libhelper.so"),
        ("build/parser", "/work/build/parser"),
    )
    runner_cmd = build_runner_command(multi_plan)
    assert "/work/build/libhelper.so" in runner_cmd
    assert "/work/build/parser" in runner_cmd
    assert "/work/build/compile_commands.json" in runner_cmd

    sandbox = _make_sandbox(tmp_path / "multi")
    materials = tmp_path / "multi-materials"
    materials.mkdir()
    helper_bytes = b"ELF-libhelper"
    parser_bytes = b"ELF-parser"
    face_bytes = _cmake_compile_commands_bytes(flags=DECLARED_FLAGS)
    captured_extra: list[tuple[str, int]] = []

    monkeypatch.setattr(sandbox, "_create", lambda **kwargs: ("fake-multi-cid", {}))

    def fake_start_multi(name, *, deadline_seconds, artifact=False, extra_copy_paths=()):
        captured_extra.extend(extra_copy_paths)
        return (
            b"multi ok\n",
            _build_result_marker(parser_bytes, code=0),
            {
                "/work/build/libhelper.so": helper_bytes,
                "/work/build/parser": parser_bytes,
                "/work/build/compile_commands.json": face_bytes,
            },
            set(),
            {"Running": False, "Status": "exited", "ExitCode": 0},
            False,
            0,
            None,
        )

    monkeypatch.setattr(sandbox, "_start_and_wait", fake_start_multi)
    multi_res = sandbox.build("vulnerable", materials_dir=materials, build_spec=multi_spec)
    assert multi_res.status == "completed"
    assert multi_res.artifact == parser_bytes
    assert multi_res.artifact_digest == _sha256_prefixed(parser_bytes)
    assert multi_res.metadata["outputs"] == {
        "build/libhelper.so": {
            "size_bytes": len(helper_bytes),
            "sha256": _sha256_prefixed(helper_bytes),
        },
        "build/parser": {
            "size_bytes": len(parser_bytes),
            "sha256": _sha256_prefixed(parser_bytes),
        },
    }
    assert ("/work/build/libhelper.so", MAX_ARTIFACT_BYTES) in captured_extra
    assert ("/work/build/parser", MAX_ARTIFACT_BYTES) in captured_extra
    assert ("/work/build/compile_commands.json", MAX_PROVENANCE_FACE_BYTES) in captured_extra


# ---------------------------------------------------------------------------
# 10. PR #54 review B-1..B-5/S-1..S-5 regressions
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "label,spec",
    [
        (
            "cmake-build-etc",
            _cmake_spec(build=["cmake", "--build", "/etc"]),
        ),
        (
            "cmake-install-tmp",
            _cmake_spec(install=["cmake", "--install", "/tmp/evil"]),
        ),
        (
            "cmake-install-prefix-tmp",
            _cmake_spec(
                install=["cmake", "--install", "build", "--prefix", "/tmp/evil"]
            ),
        ),
        (
            "cmake-source-etc",
            _cmake_spec(configure=["cmake", "-S", "/etc", "-B", "build"]),
        ),
        (
            "cmake-install-prefix-var",
            _cmake_spec(
                configure=[
                    "cmake",
                    "-S",
                    ".",
                    "-B",
                    "build",
                    "-DCMAKE_INSTALL_PREFIX=/tmp/evil",
                ]
            ),
        ),
        (
            "make-directory-etc",
            _make_spec(),
        ),
        (
            "make-file-passwd",
            {**_make_spec(), "build": ["make", "-f", "/etc/passwd"]},
        ),
        (
            "make-include-etc",
            {**_make_spec(), "build": ["make", "-I", "/etc", "parser"]},
        ),
        (
            "make-old-file-etc",
            {**_make_spec(), "build": ["make", "-o", "/etc/passwd", "parser"]},
        ),
        (
            "make-long-file-etc",
            {**_make_spec(), "build": ["make", "--file=/etc/passwd"]},
        ),
        (
            "destdir-tmp",
            _cmake_spec(env={"CC": "clang", "DESTDIR": "/tmp/evil"}),
        ),
    ],
)
def test_b5_cmake_make_external_paths_rejected_before_container(label, spec):
    """B-5: build/install/source/Makefile paths outside /work are rejected."""
    if label == "make-directory-etc":
        spec = {**spec, "build": ["make", "-C", "/etc", "parser"]}
    decision = build_provenance.validate_build_spec_for_freeze(spec)
    assert decision.ok is False, f"{label}: freeze must reject external path"
    assert decision.reason_code == build_provenance.BUILD_PROVENANCE_MISSING
    with pytest.raises(SandboxError) as exc_info:
        prepare_build_spec_execution(spec)
    assert exc_info.value.reason_code == build_provenance.BUILD_PROVENANCE_MISSING


@pytest.mark.parametrize(
    "spec",
    [
        _cmake_spec(
            configure=["cmake", "-S", ".", "-B", "/work/build"],
            build=["cmake", "--build", "/work/build"],
        ),
        _cmake_spec(
            configure=[
                "cmake",
                "-S",
                "src",
                "-B",
                "build",
                "-DCMAKE_INSTALL_PREFIX=/work/install",
            ],
            install=["cmake", "--install", "build", "--prefix", "/work/install"],
        ),
        {**_make_spec(), "build": ["make", "-C", "src", "parser"]},
    ],
)
def test_b5_work_and_relative_paths_still_allowed(spec):
    """B-5 positive control: /work paths and safe relative paths still freeze."""
    decision = build_provenance.validate_build_spec_for_freeze(spec)
    assert decision.ok is True, decision.error_detail
    prepare_build_spec_execution(spec)


@pytest.mark.parametrize(
    "configure,expected",
    [
        (
            [
                "cmake",
                "-S",
                ".",
                "-B",
                "build",
                "-DCMAKE_EXPORT_COMPILE_COMMANDS=ON",
                "-U",
                "CMAKE_EXPORT_COMPILE_COMMANDS",
            ],
            True,
        ),
        (
            [
                "cmake",
                "-S",
                ".",
                "-B",
                "build",
                "-DCMAKE_EXPORT_COMPILE_COMMANDS=ON",
            ],
            False,
        ),
        (
            [
                "cmake",
                "-S",
                ".",
                "-B",
                "build",
                "-DCMAKE_EXPORT_COMPILE_COMMANDS=OFF",
            ],
            True,
        ),
        (
            [
                "cmake",
                "-S",
                ".",
                "-B",
                "build",
                "-U",
                "CMAKE_EXPORT_COMPILE_COMMANDS",
                "-DCMAKE_EXPORT_COMPILE_COMMANDS=ON",
            ],
            False,
        ),
    ],
)
def test_s5_export_compile_commands_follows_configure_order(configure, expected):
    """S-5: -U after an ON define disables the face; a later ON re-enables it."""
    assert build_provenance.cmake_disables_compile_commands(configure) is expected
    spec = _cmake_spec(configure=configure)
    decision = build_provenance.validate_build_spec_for_freeze(spec)
    assert decision.ok is (not expected), decision.error_detail


@pytest.mark.parametrize(
    "forbidden_key",
    [
        "MAKEFLAGS",
        "GNUMAKEFLAGS",
        "MFLAGS",
        "MAKEOVERRIDES",
        "SHELL",
        "ENV",
        "BASH_ENV",
        "makeflags",
        "gnumakeflags",
    ],
)
def test_b4_make_control_env_keys_rejected_in_freeze_and_prepare(forbidden_key):
    """B-4: Make flags/SHELL can no longer override the cc-shim CC."""
    for spec in (_make_spec(), _cmake_spec()):
        spec["env"][forbidden_key] = "CC=clang"
        decision = build_provenance.validate_build_spec_for_freeze(spec)
        assert decision.ok is False, f"freeze must reject env.{forbidden_key}"
        with pytest.raises(SandboxError) as exc_info:
            prepare_build_spec_execution(spec)
        assert (
            exc_info.value.reason_code == build_provenance.BUILD_PROVENANCE_MISSING
        )


def test_b4_effective_container_env_rejects_make_override_after_merge():
    """B-4 defense in depth: the final container env is re-validated."""
    error = build_provenance.validate_effective_build_env(
        {
            "TMPDIR": "/work",
            "HOME": "/work",
            "ASAN_OPTIONS": "detect_leaks=0",
            "DATACON_BUILD_VERSION": "fixed",
            "CFLAGS": "-O1",
        },
        allowed_executor_keys={
            "TMPDIR",
            "HOME",
            "ASAN_OPTIONS",
            "DATACON_BUILD_VERSION",
        },
    )
    assert error is None
    for key in ("MAKEFLAGS", "GNUMAKEFLAGS", "MFLAGS", "SHELL"):
        error = build_provenance.validate_effective_build_env(
            {key: "CC=clang"},
            allowed_executor_keys={"TMPDIR", "HOME", "ASAN_OPTIONS"},
        )
        assert error is not None and key in error


def test_b3_shell_recipe_digest_must_match_materialized_build_sh(tmp_path, monkeypatch):
    """B-3: a forged shell_recipe_digest fails closed before any build container."""
    run_root, _ = _configure_isolated_roots(tmp_path, monkeypatch)
    baseline = (
        "2099-01-01T00:00:00Z /work clang -fsanitize=address -g src/parser.c\n"
    )
    spec = _shell_spec(
        face_digest=build_provenance.shell_face_digest(baseline, repo_root="/work"),
        review={
            "reviewer_id": "reviewer-01",
            "reviewed_at": "2099-01-01T00:00:00Z",
            "face_kind": "build_log",
        },
    )
    spec["shell_recipe_digest"] = "sha256:" + "0" * 64
    job, plan, plan_digest, review = _setup_fixture_plan_and_job(
        version=2, build_spec=spec
    )
    mem_state = _InMemoryState(job, plan, plan_digest, review)
    mem_state.install(monkeypatch)
    fake_sandbox = _FakeSandbox(
        image_digest=plan["image_digest"],
        build_recipe_digest=plan["build_recipe_digest"],
        faces={"vulnerable": baseline.encode(), "fixed": baseline.encode()},
        face_name="shell-face.log",
    )
    result = execution.run_execution(
        "dsn",
        job["job_id"],
        1,
        case_root=str(FIXTURE_CASES),
        run_root=run_root,
        sandbox=fake_sandbox,
    )
    assert result.state == "BLOCKED"
    assert result.reason_code == build_provenance.BUILD_PROVENANCE_MISSING
    assert fake_sandbox.build_calls == []
    # The forged recipe digest blocks before context reconstruction, so no
    # execution bundle is published (there are no build artifacts to verify).
    assert result.evidence_path is None


def test_b3_shell_build_script_must_name_manifest_build_recipe(tmp_path, monkeypatch):
    """B-3: a shell recipe digest cannot authorize a different script operand."""
    run_root, _ = _configure_isolated_roots(tmp_path, monkeypatch)
    baseline = (
        "2099-01-01T00:00:00Z /work clang -fsanitize=address -g src/parser.c\n"
    )
    spec = _shell_spec(
        face_digest=build_provenance.shell_face_digest(baseline, repo_root="/work"),
        review={
            "reviewer_id": "reviewer-01",
            "reviewed_at": "2099-01-01T00:00:00Z",
            "face_kind": "build_log",
        },
    )
    spec["build"] = ["sh", "./other.sh"]
    job, plan, plan_digest, review = _setup_fixture_plan_and_job(
        version=2, build_spec=spec
    )
    mem_state = _InMemoryState(job, plan, plan_digest, review)
    mem_state.install(monkeypatch)
    result = execution.run_execution(
        "dsn",
        job["job_id"],
        1,
        case_root=str(FIXTURE_CASES),
        run_root=run_root,
        sandbox=_FakeSandbox(
            image_digest=plan["image_digest"],
            build_recipe_digest=plan["build_recipe_digest"],
            faces={},
            face_name="shell-face.log",
        ),
    )
    assert result.state == "BLOCKED"
    assert result.reason_code == "PLAN_MISMATCH"


def test_s3_declared_flags_are_a_flat_multiset_across_compile_units():
    """S-3: two CUs may each contribute a different declared flag."""
    face = json.dumps(
        [
            {
                "directory": "/work",
                "file": "/work/src/a.c",
                "arguments": [
                    "clang",
                    "-DFEATURE_A",
                    "-c",
                    "/work/src/a.c",
                    "-o",
                    "a.o",
                ],
            },
            {
                "directory": "/work",
                "file": "/work/src/b.c",
                "arguments": [
                    "clang",
                    "-DFEATURE_B",
                    "-c",
                    "/work/src/b.c",
                    "-o",
                    "b.o",
                ],
            },
        ]
    ).encode()
    result = build_provenance.verify_build_provenance(
        kind="cmake",
        declared_compile_flags=["-DFEATURE_A", "-DFEATURE_B"],
        vulnerable_face=face,
        fixed_face=face,
        repo_root="/work",
    )
    assert result.comparable is True, result.error_detail


def test_s3_patch_explained_unit_does_not_mask_unexplained_missing_unit():
    """S-3: only patch-changed source paths are exempt from unit symmetry."""
    vuln_face = json.dumps(
        [
            {
                "directory": "/work",
                "file": "/work/src/a.c",
                "arguments": ["clang", "-g", "-c", "/work/src/a.c", "-o", "a.o"],
            },
            {
                "directory": "/work",
                "file": "/work/src/added.c",
                "arguments": ["clang", "-g", "-c", "/work/src/added.c", "-o", "b.o"],
            },
        ]
    ).encode()
    fixed_face = json.dumps(
        [
            {
                "directory": "/work",
                "file": "/work/src/a.c",
                "arguments": ["clang", "-g", "-c", "/work/src/a.c", "-o", "a.o"],
            }
        ]
    ).encode()
    explained = build_provenance.verify_build_provenance(
        kind="cmake",
        declared_compile_flags=["-g"],
        vulnerable_face=vuln_face,
        fixed_face=fixed_face,
        repo_root="/work",
        patch_explained_units=["src/added.c"],
    )
    assert explained.comparable is True, explained.error_detail
    unexplained = build_provenance.verify_build_provenance(
        kind="cmake",
        declared_compile_flags=["-g"],
        vulnerable_face=vuln_face,
        fixed_face=fixed_face,
        repo_root="/work",
    )
    assert unexplained.comparable is False


def test_b2_build_with_spec_passes_version_to_container_command_and_env(
    tmp_path, monkeypatch
):
    """B-2: vulnerable and fixed builds differ in the audited container command."""
    sandbox = _make_sandbox(tmp_path)
    materials = tmp_path / "materials"
    materials.mkdir()
    (materials / "build.sh").write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    observed: list[dict[str, Any]] = []
    artifact_bytes = b"ELF-version-aware"

    def fake_create(*, suffix, command, mounts, env=None):
        observed.append(
            {
                "suffix": suffix,
                "command": list(command),
                "env": dict(env or {}),
            }
        )
        return (f"cid-{suffix}", {})

    def fake_start(name, *, deadline_seconds, artifact=False, extra_copy_paths=()):
        return (
            b"build ok\n",
            _build_result_marker(artifact_bytes, code=0),
            {"/work/out/parser": artifact_bytes},
            set(),
            {"Running": False, "Status": "exited", "ExitCode": 0},
            False,
            0,
            None,
        )

    monkeypatch.setattr(sandbox, "_create", fake_create)
    monkeypatch.setattr(sandbox, "_start_and_wait", fake_start)
    spec = _shell_spec(
        face_digest="sha256:" + "a" * 64,
        review={
            "reviewer_id": "reviewer-01",
            "reviewed_at": "2099-01-01T00:00:00Z",
            "face_kind": "build_log",
        },
    )
    for version in ("vulnerable", "fixed"):
        result = sandbox.build(
            version, materials_dir=materials, build_spec=spec
        )
        assert result.status == "completed", result.metadata

    vulnerable, fixed = observed
    assert vulnerable["command"] != fixed["command"]
    assert "vulnerable" in vulnerable["command"]
    assert "fixed" in fixed["command"]
    assert vulnerable["env"]["DATACON_BUILD_VERSION"] == "vulnerable"
    assert fixed["env"]["DATACON_BUILD_VERSION"] == "fixed"


def test_s1_missing_or_truncated_secondary_output_fails_the_build(
    tmp_path, monkeypatch
):
    """S-1: every declared output is required, not just the primary parser."""
    sandbox = _make_sandbox(tmp_path)
    materials = tmp_path / "materials"
    materials.mkdir()
    parser = b"ELF-parser"
    helper = b"ELF-helper"
    spec = _cmake_spec(outputs=["out/helper", "out/parser"])
    monkeypatch.setattr(sandbox, "_create", lambda **kwargs: ("fake-cid", {}))

    def run_case(files: dict[str, bytes], truncated: set[str]) -> BuildResult:
        monkeypatch.setattr(
            sandbox,
            "_start_and_wait",
            lambda name, **kwargs: (
                b"build ok\n",
                _build_result_marker(parser, code=0),
                files,
                truncated,
                {"Running": False, "Status": "exited", "ExitCode": 0},
                False,
                0,
                None,
            ),
        )
        return sandbox.build("vulnerable", materials_dir=materials, build_spec=spec)

    ok = run_case({"/work/out/helper": helper, "/work/out/parser": parser}, set())
    assert ok.status == "completed"
    assert {item.relative_path for item in ok.outputs} == {
        "out/helper",
        "out/parser",
    }

    missing = run_case({"/work/out/parser": parser}, set())
    assert missing.status == "build_failed"
    assert missing.metadata["outputs"]["out/helper"] is None

    truncated = run_case(
        {"/work/out/helper": helper, "/work/out/parser": parser},
        {"/work/out/helper"},
    )
    assert truncated.status == "build_failed"

    # A symlinked secondary output is not copied at all (the copy path refuses
    # it), so it is missing from the captured map and fails closed.
    symlinked = run_case({"/work/out/parser": parser}, set())
    assert symlinked.status == "build_failed"


def test_s1_custom_outputs_archive_at_d39_paths_and_verify(
    tmp_path, monkeypatch
):
    """S-1: BuildSpec.outputs relative paths are preserved under build/{version}/."""
    run_root, _ = _configure_isolated_roots(tmp_path, monkeypatch)
    baseline = (
        "2099-01-01T00:00:00Z /work clang -fsanitize=address -g src/parser.c\n"
    )
    spec = _shell_spec(
        face_digest=build_provenance.shell_face_digest(baseline, repo_root="/work"),
        review={
            "reviewer_id": "reviewer-01",
            "reviewed_at": "2099-01-01T00:00:00Z",
            "face_kind": "build_log",
        },
    )
    spec["outputs"] = ["out/parser"]
    job, plan, plan_digest, review = _setup_fixture_plan_and_job(
        version=2, build_spec=spec
    )
    mem_state = _InMemoryState(job, plan, plan_digest, review)
    mem_state.install(monkeypatch)
    custom = b"ELF-custom-parser"
    fake_sandbox = _FakeSandbox(
        image_digest=plan["image_digest"],
        build_recipe_digest=plan["build_recipe_digest"],
        faces={"vulnerable": baseline.encode(), "fixed": baseline.encode()},
        face_name="shell-face.log",
        build_outputs={"out/parser": custom},
    )
    result = execution.run_execution(
        "dsn",
        job["job_id"],
        1,
        case_root=str(FIXTURE_CASES),
        run_root=run_root,
        sandbox=fake_sandbox,
    )
    assert result.state == "REPRODUCED", (result, mem_state.finished_calls)
    verified = evidence.verify_bundle(result.evidence_path)
    for version in ("vulnerable", "fixed"):
        path = f"build/{version}/out/parser"
        assert path in verified.file_data
        assert verified.file_data[path] == custom


def test_s2_staging_copy_failure_is_fatal(tmp_path):
    """S-2: a failed /fixture -> /work copy exits non-zero instead of `|| true`."""
    fixture = tmp_path / "fixture"
    fixture.mkdir()
    (fixture / "src.c").write_text("int main(void){return 0;}\n", encoding="utf-8")
    # A regular file at /work makes the staging copy fail even when the test
    # runs as root (chmod-based denials do not stop root).
    work = tmp_path / "work"
    work.write_text("not a directory\n", encoding="utf-8")
    out = tmp_path / "parser"
    script = render_build_runner_script(
        stage_fixture=True,
        emit_result_marker=True,
        wait_for_release=False,
    )
    script = script.replace("/fixture", str(fixture)).replace("/work", str(work))
    cmd = [
        "/bin/sh",
        "-c",
        script,
        "datacon-build-runner",
        str(out),
        "0",
        "0",
        "0",
        "0",
    ]
    proc = subprocess.run(
        cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False
    )
    assert proc.returncode != 0
    stderr = proc.stderr.decode("utf-8", "replace")
    assert "staging copy from" in stderr and "failed" in stderr


def test_s4_stale_lock_is_irrelevant_and_symlinked_log_is_rejected(tmp_path):
    """S-4: no shared lock remains; stale lock never blocks and symlinks fail."""
    target = tmp_path / "outside.log"
    target.write_text("do-not-touch\n", encoding="utf-8")
    log_path = tmp_path / "cc-shim.log"
    stale_lock = tmp_path / "cc-shim.log.lock"
    stale_lock.mkdir()
    stub_cc = tmp_path / "stub-clang"
    stub_cc.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    stub_cc.chmod(0o755)
    shim_path = tmp_path / "cc-shim"
    shim_path.write_text(
        render_cc_shim_script(real_compiler=str(stub_cc), log_path=str(log_path)),
        encoding="utf-8",
    )
    shim_path.chmod(0o755)
    started = time.monotonic()
    proc = subprocess.run(
        [str(shim_path), "-c", "src/a.c", "-o", "a.o"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        timeout=5,
    )
    assert proc.returncode == 0
    assert time.monotonic() - started < 5
    assert stale_lock.is_dir(), "the shim must not need or delete an unrelated lock"
    merge_cc_shim_log(log_path)
    assert jsonutil.loads_strict(log_path.read_text(encoding="utf-8").strip())

    log_path.unlink()
    log_path.symlink_to(target)
    proc = subprocess.run(
        [str(shim_path), "-c", "src/a.c", "-o", "a.o"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        timeout=5,
    )
    assert proc.returncode != 0
    assert target.read_text(encoding="utf-8") == "do-not-touch\n"


def test_s4_term_during_shim_does_not_leave_a_lock(tmp_path):
    """S-4: TERM exits the shim and leaves no lock/temp artifact to block retries."""
    import select

    log_path = tmp_path / "cc-shim.log"
    stub_cc = tmp_path / "slow-clang"
    stub_cc.write_text("#!/bin/sh\necho READY\nexec sleep 30\n", encoding="utf-8")
    stub_cc.chmod(0o755)
    shim_path = tmp_path / "cc-shim"
    shim_path.write_text(
        render_cc_shim_script(real_compiler=str(stub_cc), log_path=str(log_path)),
        encoding="utf-8",
    )
    shim_path.chmod(0o755)
    proc = subprocess.Popen(
        [str(shim_path), "-c", "src/a.c", "-o", "a.o"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    try:
        assert proc.stdout is not None
        readable, _, _ = select.select([proc.stdout], [], [], 5.0)
        assert readable, "stub compiler did not signal readiness before timeout"
        assert proc.stdout.readline() == b"READY\n"
    finally:
        proc.terminate()
        proc.communicate(timeout=5)
    assert not (tmp_path / "cc-shim.log.lock").exists()
    # A completed fragment is harmless and will be merged by the runner; only
    # an in-flight temp (or a leftover lock) could block a retry.
    assert not list(tmp_path.glob("cc-shim.log.d/.fragment.*"))


def test_b7_reproduced_bundle_uses_real_envelope_and_six_field_budget(
    tmp_path, monkeypatch
):
    """B-7: no 2-key envelope, no v0.1 7-field report budget."""
    run_root, _ = _configure_isolated_roots(tmp_path, monkeypatch)
    spec = _cmake_spec()
    face = _cmake_compile_commands_bytes(
        flags=["-fsanitize=address", "-g", "-O1", "-I../include", "-D_GNU_SOURCE"]
    )
    job, plan, plan_digest, review = _setup_fixture_plan_and_job(
        version=2, build_spec=spec
    )
    mem_state = _InMemoryState(job, plan, plan_digest, review)
    mem_state.install(monkeypatch)
    fake_sandbox = _FakeSandbox(
        image_digest=plan["image_digest"],
        build_recipe_digest=plan["build_recipe_digest"],
        faces={"vulnerable": face, "fixed": face},
        face_name="compile_commands.json",
    )
    result = execution.run_execution(
        "dsn",
        job["job_id"],
        1,
        case_root=str(FIXTURE_CASES),
        run_root=run_root,
        sandbox=fake_sandbox,
    )
    assert result.state == "REPRODUCED", result
    verified = evidence.verify_bundle(result.evidence_path)
    envelope = json.loads(verified.file_data["envelope.json"])
    assert len(envelope) == 11
    assert contracts.normalize_envelope(envelope) == envelope
    assert contracts.envelope_digest(envelope) == plan["envelope_digest"]
    snapshot = json.loads(verified.file_data["budget/snapshot.json"])
    assert set(snapshot) == {
        "max_total_seconds",
        "max_fuzz_seconds",
        "spent_seconds",
        "spent_fuzz_seconds",
        "remaining_seconds",
        "remaining_fuzz_seconds",
    }
    report = json.loads(verified.file_data["report.json"])
    assert report["budget"] == snapshot
    assert "review.json" in verified.file_data
    assert "admission.json" not in verified.file_data


def test_b7_missing_envelope_body_fails_closed_without_fake_evidence(
    tmp_path, monkeypatch
):
    """B-7: without a T12 envelope reader the executor publishes no fake body."""
    run_root, _ = _configure_isolated_roots(tmp_path, monkeypatch)
    spec = _cmake_spec()
    face = _cmake_compile_commands_bytes(flags=DECLARED_FLAGS)
    job, plan, plan_digest, review = _setup_fixture_plan_and_job(
        version=2, build_spec=spec
    )
    job.pop("envelope", None)
    mem_state = _InMemoryState(job, plan, plan_digest, review)
    mem_state.install(monkeypatch)
    fake_sandbox = _FakeSandbox(
        image_digest=plan["image_digest"],
        build_recipe_digest=plan["build_recipe_digest"],
        faces={"vulnerable": face, "fixed": face},
        face_name="compile_commands.json",
    )
    result = execution.run_execution(
        "dsn",
        job["job_id"],
        1,
        case_root=str(FIXTURE_CASES),
        run_root=run_root,
        sandbox=fake_sandbox,
    )
    assert result.state == "BLOCKED"
    assert result.reason_code == "MATERIAL_MISSING"
    assert result.evidence_path is None
    assert fake_sandbox.build_calls == []
    finished = mem_state.finished_calls[-1]
    assert "approved envelope body is not available" in str(
        finished.get("evidence_error")
    )


def _real_sandbox(tmp_path: Path) -> DockerSandbox:
    return DockerSandbox(
        image=(
            "silkeh/clang:19-bookworm@sha256:"
            "f5ce959d91f059acf5a4b3f1c19f46713c4b2881c7d7cd1d5143ca1d1412277f"
        ),
        platform="linux/amd64",
        policy=POLICY,
        limits=LIMITS,
        job_id=str(uuid4()),
        run_root=tmp_path / "real-sandbox-run",
        generation=1,
    )


def _shell_build_spec_for_real_build() -> dict[str, Any]:
    spec = _shell_spec(
        face_digest="sha256:" + "a" * 64,
        review={
            "reviewer_id": "reviewer-01",
            "reviewed_at": "2099-01-01T00:00:00Z",
            "face_kind": "build_log",
        },
        declared_compile_flags=[
            "-fsanitize=address",
            "-g",
            "-O0",
            "-fno-omit-frame-pointer",
        ],
    )
    spec["outputs"] = ["parser"]
    return spec


@pytest.mark.postgres
@pytest.mark.docker
def test_s7_real_docker_builds_both_versions_and_archives_d39(tmp_path, monkeypatch):
    """S-7: real Docker dual-version hashes differ and both D39 trees exist."""
    run_root, _ = _configure_isolated_roots(tmp_path, monkeypatch)
    spec = _shell_build_spec_for_real_build()
    job, plan, plan_digest, review = _setup_fixture_plan_and_job(
        version=2, build_spec=spec
    )
    mem_state = _InMemoryState(job, plan, plan_digest, review)
    mem_state.install(monkeypatch)
    context = execution._load_context(
        "dsn",
        job["job_id"],
        1,
        case_root=str(FIXTURE_CASES),
        run_root=run_root,
    )
    sandbox = _real_sandbox(tmp_path)
    results = {}
    for version in ("vulnerable", "fixed"):
        result = sandbox.build(
            version,
            materials_dir=FIXTURE_CASES,
            build_spec=spec,
            expected_materials=None,
        )
        assert result.status == "completed", (version, result.metadata, result.log)
        assert result.artifact_digest is not None
        results[version] = result
        execution._persist_build(
            "dsn", context, result, attempt_no=1, token=f"tok-{version}"
        )
    assert (
        results["vulnerable"].artifact_digest
        != results["fixed"].artifact_digest
    ), "the vulnerable and fixed artifacts must be different binaries"
    # B-2: the fixed version is visible in the audited runner command and env.
    vulnerable_cmd = build_runner_command(
        prepare_build_spec_execution(spec), build_version="vulnerable"
    )
    fixed_cmd = build_runner_command(
        prepare_build_spec_execution(spec), build_version="fixed"
    )
    assert vulnerable_cmd != fixed_cmd
    assert "vulnerable" in vulnerable_cmd and "fixed" in fixed_cmd

    generation_root = execution._generation_root(context)
    for version in ("vulnerable", "fixed"):
        artifact = generation_root / "build" / version / "parser"
        assert artifact.is_file() and not artifact.is_symlink()
        assert artifact.read_bytes() == results[version].artifact
        assert (generation_root / "build" / version / "build.log").is_file()
    assert (
        generation_root / "build" / "vulnerable" / "parser"
    ).read_bytes() != (
        generation_root / "build" / "fixed" / "parser"
    ).read_bytes()


@pytest.mark.postgres
@pytest.mark.docker
def test_s7_real_docker_make_face_has_per_file_flags(tmp_path):
    """S-7: a real make build logs two compile units with distinct -D flags."""
    materials = tmp_path / "make-materials"
    (materials / "src").mkdir(parents=True)
    (materials / "src" / "a.c").write_text(
        "int a(void){return 1;}\n", encoding="utf-8"
    )
    (materials / "src" / "b.c").write_text(
        "int b(void){return 2;}\n", encoding="utf-8"
    )
    (materials / "main.c").write_text(
        "int a(void); int b(void); int main(void){return a()+b()-3;}\n",
        encoding="utf-8",
    )
    (materials / "Makefile").write_text(
        "all:\n"
        "\tmkdir -p out\n"
        "\t$(CC) -DFEATURE_A -c src/a.c -o out/a.o\n"
        "\t$(CC) -DFEATURE_B -c src/b.c -o out/b.o\n"
        "\t$(CC) main.c out/a.o out/b.o -o out/parser\n",
        encoding="utf-8",
    )
    spec = {
        "kind": "make",
        "build": ["make", "all"],
        "install": [],
        "env": {"CC": "/usr/local/bin/cc-shim"},
        "outputs": ["out/parser"],
        "declared_compile_flags": ["-DFEATURE_A", "-DFEATURE_B"],
        "shell_recipe_digest": None,
        "shell_face_digest": None,
        "shell_face_review": None,
    }
    sandbox = _real_sandbox(tmp_path)
    result = sandbox.build("vulnerable", materials_dir=materials, build_spec=spec)
    assert result.status == "completed", (result.metadata, result.log)
    assert result.provenance_face is not None
    parsed = build_provenance.parse_provenance_face(
        kind="make", raw_face=result.provenance_face, repo_root="/work"
    )
    assert {"src/a.c", "src/b.c"} <= set(parsed.units)
    assert "-DFEATURE_A" in parsed.units["src/a.c"]
    assert "-DFEATURE_B" in parsed.units["src/b.c"]


def test_b7_policy_round_writes_admission_not_review(tmp_path, monkeypatch):
    """B-7: a policy-admitted round archives admission.json and no review."""
    run_root, _ = _configure_isolated_roots(tmp_path, monkeypatch)
    spec = _cmake_spec()
    face = _cmake_compile_commands_bytes(
        flags=["-fsanitize=address", "-g", "-O1", "-I../include", "-D_GNU_SOURCE"]
    )
    job, plan, plan_digest, review = _setup_fixture_plan_and_job(
        version=2, build_spec=spec
    )
    plan["parent_approval_digest"] = "sha256:" + "e" * 64
    plan_digest = contracts.plan_digest(plan)
    mem_state = _InMemoryState(job, plan, plan_digest, review)
    mem_state.install(monkeypatch)
    # A guided family's human review is bound to the first plan, not this
    # later round. It must not be reused as the round's approval.
    mem_state.review = {
        "reviewer_id": "family-reviewer",
        "decision": "approve",
        "plan_digest": "sha256:" + "9" * 64,
        "decided_at": review["decided_at"],
    }
    mem_state.admission = {
        "admission_id": str(uuid4()),
        "job_id": str(job["job_id"]),
        "parent_job_id": str(job["parent_job_id"]),
        "round_no": plan["round_no"],
        "approval_kind": "policy",
        "envelope_digest": plan["envelope_digest"],
        "parent_approval_digest": "sha256:" + "e" * 64,
        "seed_digest": plan["inputs"]["candidate"],
        "predicate_version": "admission-v1",
        "recomputable": True,
        "supporting_bundle_digest": None,
        "decided_at": "2099-01-01T00:00:00Z",
    }
    fake_sandbox = _FakeSandbox(
        image_digest=plan["image_digest"],
        build_recipe_digest=plan["build_recipe_digest"],
        faces={"vulnerable": face, "fixed": face},
        face_name="compile_commands.json",
    )
    result = execution.run_execution(
        "dsn",
        job["job_id"],
        1,
        case_root=str(FIXTURE_CASES),
        run_root=run_root,
        sandbox=fake_sandbox,
    )
    assert result.state == "REPRODUCED", result
    verified = evidence.verify_bundle(result.evidence_path)
    assert "admission.json" in verified.file_data
    assert "review.json" not in verified.file_data
    report = json.loads(verified.file_data["report.json"])
    assert report["review"] is None
    assert json.loads(verified.file_data["admission.json"])[
        "approval_kind"
    ] == "policy"


def test_b7_approved_envelope_is_read_from_the_family_store(tmp_path, monkeypatch):
    """B-7: execution reads the approved envelope through the T12 getter."""
    run_root, _ = _configure_isolated_roots(tmp_path, monkeypatch)
    spec = _cmake_spec()
    face = _cmake_compile_commands_bytes(
        flags=["-fsanitize=address", "-g", "-O1", "-I../include", "-D_GNU_SOURCE"]
    )
    job, plan, plan_digest, review = _setup_fixture_plan_and_job(
        version=2, build_spec=spec
    )
    approved_envelope = job.pop("envelope")
    mem_state = _InMemoryState(job, plan, plan_digest, review)
    mem_state.family_envelope = approved_envelope
    mem_state.install(monkeypatch)
    fake_sandbox = _FakeSandbox(
        image_digest=plan["image_digest"],
        build_recipe_digest=plan["build_recipe_digest"],
        faces={"vulnerable": face, "fixed": face},
        face_name="compile_commands.json",
    )
    result = execution.run_execution(
        "dsn",
        job["job_id"],
        1,
        case_root=str(FIXTURE_CASES),
        run_root=run_root,
        sandbox=fake_sandbox,
    )
    assert result.state == "REPRODUCED", result
    verified = evidence.verify_bundle(result.evidence_path)
    envelope = json.loads(verified.file_data["envelope.json"])
    assert contracts.envelope_digest(envelope) == plan["envelope_digest"]


def _reviewed_shell_spec(build: list[str]) -> dict[str, Any]:
    return {
        **_shell_spec(
            face_digest="sha256:" + "a" * 64,
            review={
                "reviewer_id": "reviewer-01",
                "reviewed_at": "2099-01-01T00:00:00Z",
                "face_kind": "build_log",
            },
        ),
        "build": list(build),
    }


@pytest.mark.parametrize(
    "forbidden_key",
    [
        "MAKEFLAGS",
        "GNUMAKEFLAGS",
        "MAKEOVERRIDES",
        "MAKEFILES",
        "MFLAGS",
        "BASH_ENV",
        "ENV",
    ],
)
def test_n1_make_and_shell_env_override_vars_rejected_in_freeze_and_prepare(
    forbidden_key: str,
):
    """N1: Make/shell env override variables are rejected in BuildSpec.env."""
    for spec in (
        _cmake_spec(),
        _make_spec(),
        _reviewed_shell_spec(["sh", "./build.sh"]),
    ):
        spec["env"][forbidden_key] = "CC=clang"
        decision = build_provenance.validate_build_spec_for_freeze(spec)
        assert decision.ok is False, (
            f"freeze must reject env.{forbidden_key} for kind={spec['kind']}"
        )
        assert decision.reason_code == build_provenance.BUILD_PROVENANCE_MISSING

        with pytest.raises(SandboxError) as exc_info:
            prepare_build_spec_execution(spec)
        assert exc_info.value.reason_code == build_provenance.BUILD_PROVENANCE_MISSING


@pytest.mark.parametrize(
    "label,bad_spec",
    [
        (
            "make-cli-makeflags",
            {**_make_spec(), "build": ["make", "MAKEFLAGS=CC=clang"]},
        ),
        (
            "make-cli-gnumakeflags",
            {**_make_spec(), "build": ["make", "GNUMAKEFLAGS=--eval=CC:=clang"]},
        ),
        (
            "make-cli-makeoverrides",
            {**_make_spec(), "build": ["make", "MAKEOVERRIDES=CC=clang"]},
        ),
        (
            "make-cli-makefiles",
            {**_make_spec(), "build": ["make", "MAKEFILES=evil.mk"]},
        ),
        (
            "cmake-build-native-makeflags",
            _cmake_spec(build=["cmake", "--build", "build", "--", "MAKEFLAGS=CC=clang"]),
        ),
    ],
)
def test_n1_make_cli_env_override_vars_rejected_in_freeze_and_prepare(
    label: str, bad_spec: dict[str, Any]
):
    """N1: Make/CMake native CLI variable overrides for Make env vars are rejected."""
    decision = build_provenance.validate_build_spec_for_freeze(bad_spec)
    assert decision.ok is False, f"{label}: freeze validation must reject"
    assert decision.reason_code == build_provenance.BUILD_PROVENANCE_MISSING

    with pytest.raises(SandboxError) as exc_info:
        prepare_build_spec_execution(bad_spec)
    assert exc_info.value.reason_code == build_provenance.BUILD_PROVENANCE_MISSING


@pytest.mark.parametrize(
    "label,bad_spec",
    [
        ("make-abbrev-ev-eq", {**_make_spec(), "build": ["make", "--ev=CC:=clang"]}),
        (
            "make-abbrev-ev-arg",
            {**_make_spec(), "build": ["make", "--ev", "$(eval CC:=clang)"]},
        ),
        ("make-abbrev-eva-eq", {**_make_spec(), "build": ["make", "--eva=CC:=clang"]}),
        ("make-abbrev-en", {**_make_spec(), "build": ["make", "--en"]}),
        ("make-attached-E", {**_make_spec(), "build": ["make", "-ECC:=clang"]}),
        ("make-bundled-ke", {**_make_spec(), "build": ["make", "-ke", "parser"]}),
        ("make-bundled-se", {**_make_spec(), "build": ["make", "-se", "parser"]}),
        (
            "cmake-build-native-abbrev-ev",
            _cmake_spec(build=["cmake", "--build", "build", "--", "--ev=CC:=clang"]),
        ),
    ],
)
def test_n2_make_abbreviated_long_and_attached_short_flags_rejected(
    label: str, bad_spec: dict[str, Any]
):
    """N2: GNU Make getopt_long abbreviations (--ev/--en), attached -E, and bundled -e fail closed."""
    decision = build_provenance.validate_build_spec_for_freeze(bad_spec)
    assert decision.ok is False, f"{label}: freeze validation must reject"
    assert decision.reason_code == build_provenance.BUILD_PROVENANCE_MISSING

    with pytest.raises(SandboxError) as exc_info:
        prepare_build_spec_execution(bad_spec)
    assert exc_info.value.reason_code == build_provenance.BUILD_PROVENANCE_MISSING


@pytest.mark.parametrize(
    "valid_build",
    [
        ["make", "-f", "Makefile", "parser"],
        ["make", "-fMakefile", "parser"],
        ["make", "-C", "release", "parser"],
        ["make", "-Crelease", "parser"],
    ],
)
def test_n2_valid_make_short_arg_flags_remain_allowed(valid_build: list[str]):
    """N2: valid make -f/-C flags (separate or attached, even containing 'e') remain allowed."""
    spec = {**_make_spec(), "build": valid_build}
    decision = build_provenance.validate_build_spec_for_freeze(spec)
    assert decision.ok is True, f"valid make build {valid_build!r} must pass: {decision.error_detail}"
    plan = prepare_build_spec_execution(spec)
    assert list(plan.build) == valid_build


@pytest.mark.parametrize(
    "label,bad_build",
    [
        ("sh-plus-e-c", ["sh", "+e", "-c", "id"]),
        ("bin-sh-plus-f-c", ["/bin/sh", "+f", "-c", "env"]),
        ("direct-plus-e", ["+e"]),
        ("direct-plus-script-path", ["+e/build.sh"]),
    ],
)
def test_n3_shell_plus_option_prefix_rejected_in_freeze_and_prepare(
    label: str, bad_build: list[str]
):
    """N3: POSIX sh '+' option prefixes are rejected in both sh and direct-script branches."""
    spec = _reviewed_shell_spec(bad_build)
    decision = build_provenance.validate_build_spec_for_freeze(spec)
    assert decision.ok is False, f"{label}: freeze validation must reject"
    assert decision.reason_code == build_provenance.BUILD_PROVENANCE_MISSING

    with pytest.raises(SandboxError) as exc_info:
        prepare_build_spec_execution(spec)
    assert exc_info.value.reason_code == build_provenance.BUILD_PROVENANCE_MISSING


@pytest.mark.parametrize(
    "valid_build",
    [
        ["sh", "./build.sh"],
        ["./build.sh"],
    ],
)
def test_n3_valid_shell_relative_scripts_remain_allowed(valid_build: list[str]):
    """N3: valid relative shell script invocations continue to pass freeze and prepare."""
    spec = _reviewed_shell_spec(valid_build)
    decision = build_provenance.validate_build_spec_for_freeze(spec)
    assert decision.ok is True, f"valid shell build {valid_build!r} must pass: {decision.error_detail}"
    plan = prepare_build_spec_execution(spec)
    assert list(plan.build) == valid_build


@pytest.mark.parametrize(
    "label,configure_argv",
    [
        (
            "cmake-attached-P",
            ["cmake", "-S", ".", "-B", "build", "-Pevil.cmake"],
        ),
        (
            "cmake-separate-P",
            ["cmake", "-S", ".", "-B", "build", "-P", "evil.cmake"],
        ),
    ],
)
def test_nonblocking_cmake_configure_attached_and_separate_P_rejected(
    label: str, configure_argv: list[str]
):
    """Non-blocking: cmake configure rejects both attached -P<file> and separate -P <file>."""
    spec = _cmake_spec(configure=configure_argv)
    decision = build_provenance.validate_build_spec_for_freeze(spec)
    assert decision.ok is False, f"{label}: freeze validation must reject"
    assert decision.reason_code == build_provenance.BUILD_PROVENANCE_MISSING

    with pytest.raises(SandboxError) as exc_info:
        prepare_build_spec_execution(spec)
    assert exc_info.value.reason_code == build_provenance.BUILD_PROVENANCE_MISSING


# ---------------------------------------------------------------------------
# PR-A regression tests (D1, D2, NB1, NB3, NB4)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "label,configure_argv",
    [
        (
            "typed-bool-off-single",
            [
                "cmake",
                "-S",
                ".",
                "-B",
                "build",
                "-DCMAKE_EXPORT_COMPILE_COMMANDS:BOOL=OFF",
            ],
        ),
        (
            "typed-bool-off-two-token",
            [
                "cmake",
                "-S",
                ".",
                "-B",
                "build",
                "-D",
                "CMAKE_EXPORT_COMPILE_COMMANDS:BOOL=OFF",
            ],
        ),
        (
            "wildcard-unset-after-on",
            [
                "cmake",
                "-S",
                ".",
                "-B",
                "build",
                "-DCMAKE_EXPORT_COMPILE_COMMANDS=ON",
                "-UCMAKE_EXPORT_COMPILE_*",
            ],
        ),
        (
            "wildcard-unset-two-token",
            [
                "cmake",
                "-S",
                ".",
                "-B",
                "build",
                "-DCMAKE_EXPORT_COMPILE_COMMANDS=ON",
                "-U",
                "CMAKE_EXPORT_*",
            ],
        ),
        (
            "typed-install-prefix-escape-single",
            [
                "cmake",
                "-S",
                ".",
                "-B",
                "build",
                "-DCMAKE_INSTALL_PREFIX:PATH=/etc",
            ],
        ),
        (
            "typed-install-prefix-escape-two-token",
            [
                "cmake",
                "-S",
                ".",
                "-B",
                "build",
                "-D",
                "CMAKE_INSTALL_PREFIX:FILEPATH=/etc",
            ],
        ),
        (
            "typed-runtime-output-escape",
            [
                "cmake",
                "-S",
                ".",
                "-B",
                "build",
                "-DCMAKE_RUNTIME_OUTPUT_DIRECTORY:PATH=/tmp/evil",
            ],
        ),
        (
            "install-prefix-flag-two-token",
            [
                "cmake",
                "-S",
                ".",
                "-B",
                "build",
                "--install-prefix",
                "/etc",
            ],
        ),
        (
            "install-prefix-flag-equals",
            [
                "cmake",
                "-S",
                ".",
                "-B",
                "build",
                "--install-prefix=/etc",
            ],
        ),
        (
            "lowercase-on-cannot-override-off",
            [
                "cmake",
                "-S",
                ".",
                "-B",
                "build",
                "-DCMAKE_EXPORT_COMPILE_COMMANDS=OFF",
                "-Dcmake_export_compile_commands=ON",
            ],
        ),
        (
            "per-config-runtime-output-escape",
            [
                "cmake",
                "-S",
                ".",
                "-B",
                "build",
                "-DCMAKE_RUNTIME_OUTPUT_DIRECTORY_RELEASE=/etc",
            ],
        ),
        (
            "per-config-archive-output-typed-escape",
            [
                "cmake",
                "-S",
                ".",
                "-B",
                "build",
                "-DCMAKE_ARCHIVE_OUTPUT_DIRECTORY_DEBUG:PATH=/etc",
            ],
        ),
        (
            "per-config-library-output-escape",
            [
                "cmake",
                "-S",
                ".",
                "-B",
                "build",
                "-DCMAKE_LIBRARY_OUTPUT_DIRECTORY_MINSIZEREL=/etc",
            ],
        ),
        (
            "quoted-install-prefix-double",
            [
                "cmake",
                "-S",
                ".",
                "-B",
                "build",
                '-DCMAKE_INSTALL_PREFIX="/etc"',
            ],
        ),
        (
            "quoted-install-prefix-single",
            [
                "cmake",
                "-S",
                ".",
                "-B",
                "build",
                "-DCMAKE_INSTALL_PREFIX='/etc'",
            ],
        ),
    ],
)
def test_d1_cmake_typed_vars_wildcard_unset_and_install_prefix_fail_closed(
    label: str, configure_argv: list[str]
):
    """D1: typed -D<VAR>:<TYPE>=..., wildcard -U, and --install-prefix fail closed."""
    spec = _cmake_spec(configure=configure_argv)
    decision = build_provenance.validate_build_spec_for_freeze(spec)
    assert decision.ok is False, f"{label}: freeze validation must reject"
    assert decision.reason_code == build_provenance.BUILD_PROVENANCE_MISSING

    with pytest.raises(SandboxError) as exc_info:
        prepare_build_spec_execution(spec)
    assert exc_info.value.reason_code == build_provenance.BUILD_PROVENANCE_MISSING


def test_d1_cmake_has_export_and_disables_share_typed_and_unset_semantics():
    """D1: cmake_has_export_compile_commands agrees with cmake_disables_compile_commands."""
    typed_off = [
        "cmake",
        "-S",
        ".",
        "-B",
        "build",
        "-DCMAKE_EXPORT_COMPILE_COMMANDS:BOOL=OFF",
    ]
    assert build_provenance.cmake_disables_compile_commands(typed_off) is True
    assert build_provenance.cmake_has_export_compile_commands(typed_off) is False

    wildcard_unset = [
        "cmake",
        "-S",
        ".",
        "-B",
        "build",
        "-DCMAKE_EXPORT_COMPILE_COMMANDS=ON",
        "-UCMAKE_EXPORT_COMPILE_*",
    ]
    assert build_provenance.cmake_disables_compile_commands(wildcard_unset) is True
    assert build_provenance.cmake_has_export_compile_commands(wildcard_unset) is False

    # Lowercase variable does NOT enable CMake's case-sensitive export; auto-inject =ON.
    lowercase_only = [
        "cmake",
        "-S",
        ".",
        "-B",
        "build",
        "-Dcmake_export_compile_commands=ON",
    ]
    assert build_provenance.cmake_disables_compile_commands(lowercase_only) is False
    assert build_provenance.cmake_has_export_compile_commands(lowercase_only) is False
    lower_plan = prepare_build_spec_execution(_cmake_spec(configure=lowercase_only))
    assert "-DCMAKE_EXPORT_COMPILE_COMMANDS=ON" in lower_plan.configure

    # Valid typed =ON and valid --install-prefix inside /work remain allowed.
    valid_typed = [
        "cmake",
        "-S",
        ".",
        "-B",
        "build",
        "-DCMAKE_EXPORT_COMPILE_COMMANDS:BOOL=ON",
        "-DCMAKE_INSTALL_PREFIX:PATH=/work/install",
        "--install-prefix",
        "stage",
    ]
    assert build_provenance.cmake_disables_compile_commands(valid_typed) is False
    assert build_provenance.cmake_has_export_compile_commands(valid_typed) is True
    spec = _cmake_spec(configure=valid_typed)
    assert build_provenance.validate_build_spec_for_freeze(spec).ok is True
    plan = prepare_build_spec_execution(spec)
    assert list(plan.configure) == valid_typed


@pytest.mark.parametrize("install_argv", [["make", "install"], []])
def test_d2_make_runner_merges_cc_shim_fragments_with_and_without_install(
    tmp_path: Path, install_argv: list[str]
):
    """D2: make runner shifts install argv before cc_shim_merge_log so fragments always merge."""
    from dataclasses import replace

    work = tmp_path / "work"
    work.mkdir()
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    log_path = work / ".datacon-cc-shim.log"
    frag_dir = work / ".datacon-cc-shim.log.d"

    stub_cc = bin_dir / "real-clang"
    stub_cc.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    stub_cc.chmod(0o755)
    shim_path = bin_dir / "cc-shim"
    shim_path.write_text(
        render_cc_shim_script(real_compiler=str(stub_cc), log_path=str(log_path)),
        encoding="utf-8",
    )
    shim_path.chmod(0o755)

    fake_make = bin_dir / "make"
    fake_make.write_text(
        "#!/bin/sh\n"
        "set -eu\n"
        'if [ "${1:-}" = "install" ]; then\n'
        f'  "{shim_path}" -fsanitize=address -g -O1 -Iinclude -D_GNU_SOURCE -c src/inst.c -o inst.o\n'
        f'  printf "installed\\n" > "{work}/installed.flag"\n'
        "else\n"
        f'  "{shim_path}" -fsanitize=address -g -O1 -Iinclude -D_GNU_SOURCE -c src/parser.c -o parser.o\n'
        f'  printf "ELF-PARSER" > "{work}/parser"\n'
        "fi\n",
        encoding="utf-8",
    )
    fake_make.chmod(0o755)

    spec = {
        **_make_spec(),
        "build": ["make", "parser"],
        "install": install_argv,
        "outputs": ["parser"],
    }
    plan = prepare_build_spec_execution(spec)
    plan_for_host = replace(
        plan,
        primary_output_container_path=str(work / "parser"),
        output_container_paths=(("parser", str(work / "parser")),),
        provenance_face_container_path=str(log_path),
    )
    cmd = build_runner_command(
        plan_for_host,
        stage_fixture=False,
        emit_result_marker=True,
        wait_for_release=False,
    )
    env = os.environ.copy()
    env["PATH"] = f"{bin_dir}:{env.get('PATH', '')}"
    proc = subprocess.run(
        cmd,
        cwd=str(work),
        env=env,
        capture_output=True,
        text=True,
        timeout=15,
        check=False,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "DATACON_BUILD_RESULT code=0 size=10 " in proc.stderr
    assert log_path.is_file(), "cc-shim fragments were not merged into target log"
    assert not frag_dir.exists(), "fragment directory must be cleaned after merge"
    lines = [
        jsonutil.loads_strict(line)
        for line in log_path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    expected_count = 2 if install_argv else 1
    assert len(lines) == expected_count
    if install_argv:
        assert (work / "installed.flag").is_file()


@pytest.mark.parametrize(
    "reserved_output",
    [
        "metadata.json",
        "metadata.json/sub",
        "build.log",
        "build.log/sub",
        "build_provenance",
        "build_provenance/compile_commands.json",
        "build_provenance/nested/file.log",
    ],
)
def test_nb1_reserved_d39_build_output_paths_rejected(reserved_output: str):
    """NB1: build_spec.outputs rejects D39 reserved build file/directory names."""
    with pytest.raises(ValueError, match="reserved"):
        build_provenance.validate_build_spec_output_path(reserved_output, 0)

    spec = _cmake_spec(outputs=[reserved_output])
    decision = build_provenance.validate_build_spec_for_freeze(spec)
    assert decision.ok is False
    assert decision.reason_code == build_provenance.BUILD_PROVENANCE_MISSING

    with pytest.raises(SandboxError) as exc_info:
        prepare_build_spec_execution(spec)
    assert exc_info.value.reason_code == build_provenance.BUILD_PROVENANCE_MISSING


def test_nb1_custom_primary_output_replays_and_reuses_build_step(
    tmp_path: Path, monkeypatch
):
    """NB1: outputs=['bin/custom_target'] succeeds in replay and build step reuse."""
    run_root, _ = _configure_isolated_roots(tmp_path, monkeypatch)
    spec = _cmake_spec(outputs=["bin/custom_target"])
    face = _cmake_compile_commands_bytes(
        flags=["-fsanitize=address", "-g", "-O1", "-I../include", "-D_GNU_SOURCE"]
    )
    job, plan, plan_digest, review = _setup_fixture_plan_and_job(
        version=2, build_spec=spec
    )
    mem_state = _InMemoryState(job, plan, plan_digest, review)
    mem_state.install(monkeypatch)
    fake_sandbox = _FakeSandbox(
        image_digest=plan["image_digest"],
        build_recipe_digest=plan["build_recipe_digest"],
        faces={"vulnerable": face, "fixed": face},
        face_name="compile_commands.json",
        build_outputs={"bin/custom_target": b"ELF-CUSTOM-TARGET"},
    )
    result = execution.run_execution(
        "dsn",
        job["job_id"],
        1,
        case_root=str(FIXTURE_CASES),
        run_root=run_root,
        sandbox=fake_sandbox,
    )
    assert result.state == "REPRODUCED", (result, mem_state.finished_calls)
    assert len(fake_sandbox.replay_calls) == 6
    assert len(fake_sandbox.build_calls) == 2

    # Second generation reuses the persisted custom primary output without rebuilding.
    mem_state.job["generation"] = 2
    mem_state.job["state"] = "RUNNING"
    second_sandbox = _FakeSandbox(
        image_digest=plan["image_digest"],
        build_recipe_digest=plan["build_recipe_digest"],
        faces={"vulnerable": face, "fixed": face},
        face_name="compile_commands.json",
        build_outputs={"bin/custom_target": b"ELF-CUSTOM-TARGET"},
    )
    second = execution.run_execution(
        "dsn",
        job["job_id"],
        2,
        case_root=str(FIXTURE_CASES),
        run_root=run_root,
        sandbox=second_sandbox,
    )
    assert second.state == "REPRODUCED", second
    assert second_sandbox.build_calls == [], "custom primary output build should be reused"


def test_nb3_policy_admission_parent_approval_digest_mismatch_blocked(
    tmp_path: Path, monkeypatch
):
    """NB3: policy admission with mismatched parent_approval_digest fails closed at load and recheck."""
    run_root, _ = _configure_isolated_roots(tmp_path, monkeypatch)
    spec = _cmake_spec()
    face = _cmake_compile_commands_bytes(
        flags=["-fsanitize=address", "-g", "-O1", "-I../include", "-D_GNU_SOURCE"]
    )
    plan_parent_approval = "sha256:" + "e" * 64
    wrong_parent_approval = "sha256:" + "f" * 64

    job, plan, plan_digest, review = _setup_fixture_plan_and_job(
        version=2, build_spec=spec
    )
    plan["parent_approval_digest"] = plan_parent_approval
    plan_digest = contracts.plan_digest(plan)
    mem_state = _InMemoryState(job, plan, plan_digest, review)
    mem_state.install(monkeypatch)
    mem_state.review = {
        "reviewer_id": "family-reviewer",
        "decision": "approve",
        "plan_digest": "sha256:" + "9" * 64,
        "decided_at": review["decided_at"],
    }
    mem_state.admission = {
        "admission_id": str(uuid4()),
        "job_id": str(job["job_id"]),
        "parent_job_id": str(job["parent_job_id"]),
        "round_no": plan["round_no"],
        "approval_kind": "policy",
        "envelope_digest": plan["envelope_digest"],
        "parent_approval_digest": wrong_parent_approval,
        "seed_digest": plan["inputs"]["candidate"],
        "predicate_version": "admission-v1",
        "recomputable": True,
        "supporting_bundle_digest": None,
        "decided_at": "2099-01-01T00:00:00Z",
    }
    fake_sandbox = _FakeSandbox(
        image_digest=plan["image_digest"],
        build_recipe_digest=plan["build_recipe_digest"],
        faces={"vulnerable": face, "fixed": face},
        face_name="compile_commands.json",
    )
    result = execution.run_execution(
        "dsn",
        job["job_id"],
        1,
        case_root=str(FIXTURE_CASES),
        run_root=run_root,
        sandbox=fake_sandbox,
    )
    assert result.state == "BLOCKED"
    assert result.reason_code == "PLAN_MISMATCH"
    assert fake_sandbox.probe_calls == 0

    # Also verify pre-execution recheck (_assert_context_unchanged) rejects drift
    # on parent_approval_digest, parent_job_id, round_no, and seed_digest.
    mem_state.job["state"] = "RUNNING"
    mem_state.admission["parent_approval_digest"] = plan_parent_approval
    context = execution._load_context(
        "dsn", job["job_id"], 1, case_root=str(FIXTURE_CASES), run_root=run_root
    )
    for field, bad_value in (
        ("parent_approval_digest", wrong_parent_approval),
        ("parent_job_id", str(uuid4())),
        ("round_no", (plan["round_no"] or 1) + 99),
        ("seed_digest", "sha256:" + "0" * 64),
    ):
        original = mem_state.admission[field]
        mem_state.admission[field] = bad_value
        try:
            with pytest.raises(execution.ExecutionBlocked) as exc_info:
                execution._assert_context_unchanged("dsn", context)
            assert exc_info.value.reason_code == "PLAN_MISMATCH", field
        finally:
            mem_state.admission[field] = original


def test_nb4_merge_cc_shim_log_rejects_symlink_fragment(tmp_path: Path):
    """NB4: merge_cc_shim_log fails closed with SandboxPolicyError on symlinked fragment."""
    log_path = tmp_path / "cc-shim.log"
    frag_dir = tmp_path / "cc-shim.log.d"
    frag_dir.mkdir()
    secret = tmp_path / "secret.txt"
    secret.write_text('{"cwd":"/work","argv":["clang","-c","a.c"]}\n', encoding="utf-8")
    (frag_dir / "fragment-1-aaaa.jsonl").symlink_to(secret)

    with pytest.raises(SandboxPolicyError, match="symlink"):
        merge_cc_shim_log(log_path)
    assert not log_path.exists()


def test_d3_complete_inconclusive_verify_failure_lands_failed_never_stale(
    tmp_path: Path, monkeypatch
):
    """D3: when archive verify_bundle fails on a complete INCONCLUSIVE, land FAILED without StateError/STALE."""
    run_root, _ = _configure_isolated_roots(tmp_path, monkeypatch)
    spec = _cmake_spec()
    face = _cmake_compile_commands_bytes(
        flags=["-fsanitize=address", "-g", "-O1", "-I../include", "-D_GNU_SOURCE"]
    )
    job, plan, plan_digest, review = _setup_fixture_plan_and_job(
        version=2, build_spec=spec
    )
    mem_state = _InMemoryState(job, plan, plan_digest, review)
    mem_state.install(monkeypatch)
    fake_sandbox = _FakeSandbox(
        image_digest=plan["image_digest"],
        build_recipe_digest=plan["build_recipe_digest"],
        faces={"vulnerable": face, "fixed": face},
        face_name="compile_commands.json",
    )

    def _fail_verify(_target):
        raise evidence.BundleError("INVALID_MANIFEST", "simulated verification failure")

    monkeypatch.setattr(execution, "verify_bundle", _fail_verify)
    result = execution.run_execution(
        "dsn",
        job["job_id"],
        1,
        case_root=str(FIXTURE_CASES),
        run_root=run_root,
        sandbox=fake_sandbox,
    )
    assert result.state == "FAILED", result
    assert result.reason_code == "EVIDENCE_WRITE_FAILED"
    assert result.verdict is None
    finished = mem_state.finished_calls[-1]
    assert finished["state"] == "FAILED"
    assert finished["reason_code"] == "EVIDENCE_WRITE_FAILED"
    assert finished["verdict"] is None
    assert finished["verdict_reason"] is None
    assert finished["evidence_status"] == "failed"
    assert "simulated verification failure" in str(finished.get("evidence_error", ""))


def test_d3_nb2_partial_failed_and_pre_rule_inconclusive_archive_cleanly(
    tmp_path: Path, monkeypatch
):
    """D3/NB2: legitimate partial FAILED and pre-rule INCONCLUSIVE bundles archive via verify_bundle."""
    for kind, build_err, expected_state, expected_reason, expected_verdict in (
        (
            "failed-provenance",
            SandboxError(
                "missing provenance face",
                reason_code=build_provenance.BUILD_PROVENANCE_MISSING,
            ),
            "FAILED",
            build_provenance.BUILD_PROVENANCE_MISSING,
            None,
        ),
        (
            "pre-rule-timeout",
            SandboxError("build container timed out", reason_code="TIMEOUT"),
            "INCONCLUSIVE",
            "TIMEOUT",
            "INCONCLUSIVE",
        ),
    ):
        case_tmp = tmp_path / kind
        case_tmp.mkdir()
        run_root, _ = _configure_isolated_roots(case_tmp, monkeypatch)
        spec = _cmake_spec()
        face = _cmake_compile_commands_bytes(
            flags=["-fsanitize=address", "-g", "-O1", "-I../include", "-D_GNU_SOURCE"]
        )
        job, plan, plan_digest, review = _setup_fixture_plan_and_job(
            version=2, build_spec=spec
        )
        mem_state = _InMemoryState(job, plan, plan_digest, review)
        mem_state.install(monkeypatch)
        fake_sandbox = _FakeSandbox(
            image_digest=plan["image_digest"],
            build_recipe_digest=plan["build_recipe_digest"],
            faces={"vulnerable": face, "fixed": None},
            face_name="compile_commands.json",
            build_error_by_version={"fixed": build_err},
        )
        result = execution.run_execution(
            "dsn",
            job["job_id"],
            1,
            case_root=str(FIXTURE_CASES),
            run_root=run_root,
            sandbox=fake_sandbox,
        )
        assert result.state == expected_state, (kind, result)
        assert result.reason_code == expected_reason
        assert result.verdict == expected_verdict
        assert result.evidence_path is not None
        verified = evidence.verify_bundle(result.evidence_path)
        assert verified.manifest["verdict"] == expected_state
        assert verified.manifest["reason_code"] == expected_reason
        finished = mem_state.finished_calls[-1]
        assert finished["evidence_status"] == "archived"


def test_policy_round_blocked_mid_execution_archives_blocked_bundle(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    """Issue #63: a policy round blocked mid-execution still archives.

    The policy round's approval document is admission.json, but the blocked
    bundle contract forbids admission.json. The writer must drop it so the
    real block reason (POLICY_DENIED) reaches BLOCKED with an evidence
    bundle, instead of degrading to FAILED(EVIDENCE_WRITE_FAILED) with no
    evidence after the verifier rejects the bundle.
    """
    run_root, _ = _configure_isolated_roots(tmp_path, monkeypatch)
    spec = _cmake_spec()
    face = _cmake_compile_commands_bytes(
        flags=["-fsanitize=address", "-g", "-O1", "-I../include", "-D_GNU_SOURCE"]
    )
    parent_approval = "sha256:" + "e" * 64
    job, plan, plan_digest, review = _setup_fixture_plan_and_job(
        version=2, build_spec=spec
    )
    plan["parent_approval_digest"] = parent_approval
    plan_digest = contracts.plan_digest(plan)
    mem_state = _InMemoryState(job, plan, plan_digest, review)
    mem_state.install(monkeypatch)
    # The family's human review is bound to the first plan, not this later
    # round: the round is admitted by policy only.
    mem_state.review = {
        "reviewer_id": "family-reviewer",
        "decision": "approve",
        "plan_digest": "sha256:" + "9" * 64,
        "decided_at": review["decided_at"],
    }
    mem_state.admission = {
        "admission_id": str(uuid4()),
        "job_id": str(job["job_id"]),
        "parent_job_id": str(job["parent_job_id"]),
        "round_no": plan["round_no"],
        "approval_kind": "policy",
        "envelope_digest": plan["envelope_digest"],
        "parent_approval_digest": parent_approval,
        "seed_digest": plan["inputs"]["candidate"],
        "predicate_version": "admission-v1",
        "recomputable": True,
        "supporting_bundle_digest": None,
        "decided_at": "2099-01-01T00:00:00Z",
    }
    fake_sandbox = _FakeSandbox(
        image_digest=plan["image_digest"],
        build_recipe_digest=plan["build_recipe_digest"],
        faces={"vulnerable": face, "fixed": face},
        face_name="compile_commands.json",
    )
    original_build = fake_sandbox.build

    def build(version: str, **kwargs: Any):
        if version == "fixed":
            raise SandboxPolicyError("seccomp profile mismatch")
        return original_build(version, **kwargs)

    fake_sandbox.build = build
    result = execution.run_execution(
        "dsn",
        job["job_id"],
        1,
        case_root=str(FIXTURE_CASES),
        run_root=run_root,
        sandbox=fake_sandbox,
    )
    assert result.state == "BLOCKED", result
    assert result.reason_code == "POLICY_DENIED"
    assert result.evidence_path, "blocked policy round archived no evidence"
    finished = mem_state.finished_calls[-1]
    assert finished["state"] == "BLOCKED"
    assert finished["reason_code"] == "POLICY_DENIED"
    assert finished.get("evidence_error") is None
    assert finished["evidence_path"] == result.evidence_path
    verified = evidence.verify_bundle(result.evidence_path)
    assert "admission.json" not in verified.file_data
    # A blocked policy round carries neither approval document: not its
    # admission (forbidden on blocked bundles) and not the family's
    # first-plan review (a policy round is never human-reviewed).
    assert "review.json" not in verified.file_data
    report = json.loads(verified.file_data["report.json"])
    assert report["bundle_kind"] == "blocked"
    assert report["reason_code"] == "POLICY_DENIED"
    assert report["review"] is None



def test_policy_round_failed_partial_bundle_keeps_admission_only(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    """SF-3 contrast for #63: a policy round that FAILS (not blocked).

    The partial FAILED bundle is an execution bundle, which must carry
    exactly one approval document: this round's admission.json, never the
    family's review.json. If a future change wrongly passes blocked= to
    this path too, the admission would vanish and the verifier would
    reject the bundle.
    """
    run_root, _ = _configure_isolated_roots(tmp_path, monkeypatch)
    spec = _cmake_spec()
    face = _cmake_compile_commands_bytes(
        flags=["-fsanitize=address", "-g", "-O1", "-I../include", "-D_GNU_SOURCE"]
    )
    parent_approval = "sha256:" + "e" * 64
    job, plan, plan_digest, review = _setup_fixture_plan_and_job(
        version=2, build_spec=spec
    )
    plan["parent_approval_digest"] = parent_approval
    plan_digest = contracts.plan_digest(plan)
    mem_state = _InMemoryState(job, plan, plan_digest, review)
    mem_state.install(monkeypatch)
    mem_state.review = {
        "reviewer_id": "family-reviewer",
        "decision": "approve",
        "plan_digest": "sha256:" + "9" * 64,
        "decided_at": review["decided_at"],
    }
    mem_state.admission = {
        "admission_id": str(uuid4()),
        "job_id": str(job["job_id"]),
        "parent_job_id": str(job["parent_job_id"]),
        "round_no": plan["round_no"],
        "approval_kind": "policy",
        "envelope_digest": plan["envelope_digest"],
        "parent_approval_digest": parent_approval,
        "seed_digest": plan["inputs"]["candidate"],
        "predicate_version": "admission-v1",
        "recomputable": True,
        "supporting_bundle_digest": None,
        "decided_at": "2099-01-01T00:00:00Z",
    }
    build_error = SandboxError(
        "missing provenance face",
        reason_code=build_provenance.BUILD_PROVENANCE_MISSING,
    )
    fake_sandbox = _FakeSandbox(
        image_digest=plan["image_digest"],
        build_recipe_digest=plan["build_recipe_digest"],
        faces={"vulnerable": face, "fixed": None},
        face_name="compile_commands.json",
        build_error_by_version={"fixed": build_error},
    )
    result = execution.run_execution(
        "dsn",
        job["job_id"],
        1,
        case_root=str(FIXTURE_CASES),
        run_root=run_root,
        sandbox=fake_sandbox,
    )
    assert result.state == "FAILED", result
    assert result.reason_code == build_provenance.BUILD_PROVENANCE_MISSING
    assert result.evidence_path, "failed policy round archived no evidence"
    verified = evidence.verify_bundle(result.evidence_path)
    assert "admission.json" in verified.file_data
    assert "review.json" not in verified.file_data

def test_human_review_round_blocked_still_archives(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    """Contrast for issue #63: a human-review round blocked mid-execution.

    The round is approved by a review bound to this plan; flipping the
    decision to reject between the two builds trips the pre-container
    recheck (PLAN_MISMATCH) and the blocked bundle carries review.json,
    which the blocked contract allows. The admission gate on blocked
    bundles must not disturb this path.
    """
    run_root, _ = _configure_isolated_roots(tmp_path, monkeypatch)
    spec = _cmake_spec()
    face = _cmake_compile_commands_bytes(
        flags=["-fsanitize=address", "-g", "-O1", "-I../include", "-D_GNU_SOURCE"]
    )
    job, plan, plan_digest, review = _setup_fixture_plan_and_job(
        version=2, build_spec=spec
    )
    mem_state = _InMemoryState(job, plan, plan_digest, review)
    mem_state.install(monkeypatch)
    fake_sandbox = _FakeSandbox(
        image_digest=plan["image_digest"],
        build_recipe_digest=plan["build_recipe_digest"],
        faces={"vulnerable": face, "fixed": face},
        face_name="compile_commands.json",
    )
    original_build = fake_sandbox.build

    def build(version: str, **kwargs: Any):
        result = original_build(version, **kwargs)
        if version == "vulnerable":
            mem_state.review = {**mem_state.review, "decision": "reject"}
        return result

    fake_sandbox.build = build
    result = execution.run_execution(
        "dsn",
        job["job_id"],
        1,
        case_root=str(FIXTURE_CASES),
        run_root=run_root,
        sandbox=fake_sandbox,
    )
    assert result.state == "BLOCKED", result
    assert result.reason_code == "PLAN_MISMATCH"
    assert result.evidence_path, "blocked review round archived no evidence"
    finished = mem_state.finished_calls[-1]
    assert finished["state"] == "BLOCKED"
    assert finished["reason_code"] == "PLAN_MISMATCH"
    assert finished.get("evidence_error") is None
    verified = evidence.verify_bundle(result.evidence_path)
    assert "review.json" in verified.file_data
    assert "admission.json" not in verified.file_data


def test_evidence_artifacts_policy_blocked_never_falls_back_to_review(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    """SF-1 pin for #63: the elif must not fire for a policy round.

    The production path clears ``context.review`` when it adopts an
    admission, so the end-to-end test cannot see this; this coordinate
    simulates the unguarded state - a context that carries both the
    admission and the family review - and requires the blocked write to
    carry neither approval document.
    """
    run_root, _ = _configure_isolated_roots(tmp_path, monkeypatch)
    spec = _cmake_spec()
    parent_approval = "sha256:" + "e" * 64
    job, plan, plan_digest, review = _setup_fixture_plan_and_job(
        version=2, build_spec=spec
    )
    plan["parent_approval_digest"] = parent_approval
    plan_digest = contracts.plan_digest(plan)
    mem_state = _InMemoryState(job, plan, plan_digest, review)
    mem_state.install(monkeypatch)
    mem_state.review = {
        "reviewer_id": "family-reviewer",
        "decision": "approve",
        "plan_digest": "sha256:" + "9" * 64,
        "decided_at": review["decided_at"],
    }
    mem_state.admission = {
        "admission_id": str(uuid4()),
        "job_id": str(job["job_id"]),
        "parent_job_id": str(job["parent_job_id"]),
        "round_no": plan["round_no"],
        "approval_kind": "policy",
        "envelope_digest": plan["envelope_digest"],
        "parent_approval_digest": parent_approval,
        "seed_digest": plan["inputs"]["candidate"],
        "predicate_version": "admission-v1",
        "recomputable": True,
        "supporting_bundle_digest": None,
        "decided_at": "2099-01-01T00:00:00Z",
    }
    context = execution._load_context(
        "dsn",
        job["job_id"],
        1,
        case_root=str(FIXTURE_CASES),
        run_root=run_root,
    )
    # The unguarded precondition: both approval documents on one context.
    context.review = review

    artifacts = execution._evidence_artifacts(
        context,
        run_root / "run",
        builds={},
        runs=[],
        probe=None,
        execution_metadata={},
        blocked=True,
    )

    assert "admission.json" not in artifacts
    assert "review.json" not in artifacts


@pytest.mark.parametrize(
    ("remaining", "expected_state", "expected_replays"),
    [(5, "INCONCLUSIVE", 2), (2, "FAILED", 0)],
    ids=["during-replay", "before-replay"],
)
def test_v2_runtime_budget_exhaustion_archives_partial_bundle(
    tmp_path, monkeypatch, remaining, expected_state, expected_replays
):
    """T12 A2 (改9 §7 runtime): an exhausted family budget stops the child.

    Every container step is charged one second by the fake step clock. With
    the budget drained mid-replay the child archives an INCONCLUSIVE partial
    bundle; drained before any replay it archives FAILED. Both carry
    ``BUDGET_EXHAUSTED``, verify offline, and no further container starts.
    """
    run_root, _ = _configure_isolated_roots(tmp_path, monkeypatch)
    job, plan, plan_digest, review = _setup_fixture_plan_and_job(
        version=2, build_spec=_cmake_spec()
    )
    mem_state = _InMemoryState(job, plan, plan_digest, review)
    mem_state.install(monkeypatch)
    max_total = int(job["envelope"]["max_total_seconds"])
    mem_state.budget_charges.append(
        {
            "key": ("earlier-child", "build:vulnerable", 1),
            "charge_kind": "general",
            "seconds": max_total - remaining,
            "fuzz_seconds": 0,
        }
    )
    ticks = iter(range(0, 10_000))
    monkeypatch.setattr(execution, "STEP_CLOCK", lambda: float(next(ticks)))
    fake_sandbox = _FakeSandbox(
        image_digest=plan["image_digest"],
        build_recipe_digest=plan["build_recipe_digest"],
        faces={
            version: _cmake_compile_commands_bytes(
                flags=["-fsanitize=address", "-g", "-O1", "-I../include", "-D_GNU_SOURCE"]
            )
            for version in ("vulnerable", "fixed")
        },
        face_name="compile_commands.json",
    )

    result = execution.run_execution(
        "dsn",
        job["job_id"],
        1,
        case_root=str(FIXTURE_CASES),
        run_root=run_root,
        sandbox=fake_sandbox,
    )

    assert result.state == expected_state, result
    assert result.reason_code == "BUDGET_EXHAUSTED"
    assert len(fake_sandbox.replay_calls) == expected_replays
    # probe + builds + replays that started were each charged; nothing more.
    started_steps = 1 + len(fake_sandbox.build_calls) + expected_replays
    assert len(mem_state.budget_charges) == 1 + started_steps
    assert sum(c["seconds"] for c in mem_state.budget_charges) == max_total
    verified = evidence.verify_bundle(result.evidence_path)
    assert verified.manifest["verdict"] == expected_state
    assert verified.manifest["reason_code"] == "BUDGET_EXHAUSTED"
    snapshot = json.loads(verified.file_data["budget/snapshot.json"])
    assert snapshot["remaining_seconds"] == 0
    assert snapshot["spent_seconds"] == max_total


# ---------------------------------------------------------------------------
# R2 writer: the v2 execution/campaign bundles archive the offline model audit
# ---------------------------------------------------------------------------


def test_v2_execution_bundle_archives_offline_model_audit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    """R2 (delta §8): a completed v2 execution bundle archives the audit.

    This fixed round was analyzed offline - no model call happened - so the
    archive writes the honest offline audit: the closed 11-field
    model/audit.json under the model_audit role and exactly its 6-field
    summary in report.model_audit (never a missing object, never a null
    provider). The writer-side self-check re-derives the binding offline.
    """
    run_root, _ = _configure_isolated_roots(tmp_path, monkeypatch)
    spec = _cmake_spec()
    face = _cmake_compile_commands_bytes(
        flags=["-fsanitize=address", "-g", "-O1", "-I../include", "-D_GNU_SOURCE"]
    )
    job, plan, plan_digest, review = _setup_fixture_plan_and_job(
        version=2, build_spec=spec
    )
    mem_state = _InMemoryState(job, plan, plan_digest, review)
    mem_state.install(monkeypatch)
    fake_sandbox = _FakeSandbox(
        image_digest=plan["image_digest"],
        build_recipe_digest=plan["build_recipe_digest"],
        faces={"vulnerable": face, "fixed": face},
        face_name="compile_commands.json",
    )
    result = execution.run_execution(
        "dsn",
        job["job_id"],
        1,
        case_root=str(FIXTURE_CASES),
        run_root=run_root,
        sandbox=fake_sandbox,
    )
    assert result.state == "REPRODUCED", result
    verified = evidence.verify_bundle(result.evidence_path)
    assert "model/audit.json" in verified.file_data
    document = json.loads(verified.file_data["model/audit.json"])
    # The closed 11-field schema of delta §8 - exactly, never more.
    assert set(document) == set(MODEL_AUDIT_FIELDS)
    assert document["provider"] == "offline"
    assert document["outcome"] == "offline"
    assert document["model_version"] is None
    assert document["prompt_version"] is None
    assert document["request_digest"] is None
    assert document["response_digest"] is None
    assert document["duration_seconds"] == 0
    # The audit is anchored to the child job this bundle belongs to, and the
    # offline stage is the hypothesis aggregator.
    assert document["job_id"] == str(job["job_id"])
    assert document["stage"] == "hypothesis_aggregator"
    # Offline sends nothing: the digest is computed over the empty field set.
    assert document["allowed_fields_digest"] == jsonutil.digest_json([])
    assert document["redaction_version"] == DEFAULT_REDACTION_VERSION
    report = json.loads(verified.file_data["report.json"])
    assert report["bundle_kind"] == "execution"
    assert set(report["model_audit"]) == set(MODEL_AUDIT_SUMMARY_FIELDS)
    assert report["model_audit"] == {
        field: document[field] for field in MODEL_AUDIT_SUMMARY_FIELDS
    }
    # Writer-side self-check: the archived document validates offline and
    # binds to this bundle's job and report summary.
    verify_model_audit_document(
        document,
        job_id=str(job["job_id"]),
        report_model_audit=report["model_audit"],
    )


def test_v2_campaign_bundle_archives_offline_model_audit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    """R2 (delta §8): the campaign writer path archives the same audit.

    The campaign bundle is composed from the same two producers as the
    execution bundle (``_build_report`` with ``bundle_kind="campaign"`` plus
    ``_evidence_artifacts`` on a campaign context), so a campaign carries the
    closed 11-field model/audit.json and the 6-field report.model_audit
    exactly like a fixed round.
    """
    run_root, _ = _configure_isolated_roots(tmp_path, monkeypatch)
    job, plan, plan_digest, review = _setup_fixture_plan_and_job(
        version=2, build_spec=_cmake_spec(), round_no=None, job_kind="campaign"
    )
    mem_state = _InMemoryState(job, plan, plan_digest, review)
    mem_state.install(monkeypatch)
    context = execution._load_context(
        "dsn",
        job["job_id"],
        1,
        case_root=str(FIXTURE_CASES),
        run_root=run_root,
    )
    report, _ = execution._build_report(
        context,
        verdict=None,
        verdict_reason=None,
        decision=None,
        builds={},
        runs=[],
        probe=None,
        evidence_refs=["report.json", "report.md"],
        missing=[],
        bundle_kind="campaign",
    )
    artifacts = execution._evidence_artifacts(
        context,
        run_root / "run",
        builds={},
        runs=[],
        probe=None,
        execution_metadata={},
    )
    assert report["bundle_kind"] == "campaign"
    assert set(report["model_audit"]) == set(MODEL_AUDIT_SUMMARY_FIELDS)
    role, data = artifacts["model/audit.json"]
    assert role == "model_audit"
    document = json.loads(data)
    assert set(document) == set(MODEL_AUDIT_FIELDS)
    assert document["provider"] == "offline"
    assert document["outcome"] == "offline"
    assert document["model_version"] is None
    assert document["prompt_version"] is None
    assert document["request_digest"] is None
    assert document["response_digest"] is None
    assert document["duration_seconds"] == 0
    assert document["job_id"] == str(job["job_id"])
    assert document["stage"] == "hypothesis_aggregator"
    assert document["allowed_fields_digest"] == jsonutil.digest_json([])
    assert document["redaction_version"] == DEFAULT_REDACTION_VERSION
    assert report["model_audit"] == {
        field: document[field] for field in MODEL_AUDIT_SUMMARY_FIELDS
    }
    verify_model_audit_document(
        document,
        job_id=str(job["job_id"]),
        report_model_audit=report["model_audit"],
    )


def test_blocked_bundle_does_not_carry_model_audit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    """R2 (delta §8): a v2 blocked bundle carries no model audit.

    The model_audit role is required for execution and campaign bundles only;
    a blocked bundle archives the block reason, not an analysis audit, so
    neither model/audit.json nor the report summary may appear there.
    """
    run_root, _ = _configure_isolated_roots(tmp_path, monkeypatch)
    spec = _cmake_spec()
    face = _cmake_compile_commands_bytes(
        flags=["-fsanitize=address", "-g", "-O1", "-I../include", "-D_GNU_SOURCE"]
    )
    parent_approval = "sha256:" + "e" * 64
    job, plan, plan_digest, review = _setup_fixture_plan_and_job(
        version=2, build_spec=spec
    )
    plan["parent_approval_digest"] = parent_approval
    plan_digest = contracts.plan_digest(plan)
    mem_state = _InMemoryState(job, plan, plan_digest, review)
    mem_state.install(monkeypatch)
    mem_state.review = {
        "reviewer_id": "family-reviewer",
        "decision": "approve",
        "plan_digest": "sha256:" + "9" * 64,
        "decided_at": review["decided_at"],
    }
    mem_state.admission = {
        "admission_id": str(uuid4()),
        "job_id": str(job["job_id"]),
        "parent_job_id": str(job["parent_job_id"]),
        "round_no": plan["round_no"],
        "approval_kind": "policy",
        "envelope_digest": plan["envelope_digest"],
        "parent_approval_digest": parent_approval,
        "seed_digest": plan["inputs"]["candidate"],
        "predicate_version": "admission-v1",
        "recomputable": True,
        "supporting_bundle_digest": None,
        "decided_at": "2099-01-01T00:00:00Z",
    }
    fake_sandbox = _FakeSandbox(
        image_digest=plan["image_digest"],
        build_recipe_digest=plan["build_recipe_digest"],
        faces={"vulnerable": face, "fixed": face},
        face_name="compile_commands.json",
    )
    original_build = fake_sandbox.build

    def build(version: str, **kwargs: Any):
        if version == "fixed":
            raise SandboxPolicyError("seccomp profile mismatch")
        return original_build(version, **kwargs)

    fake_sandbox.build = build
    result = execution.run_execution(
        "dsn",
        job["job_id"],
        1,
        case_root=str(FIXTURE_CASES),
        run_root=run_root,
        sandbox=fake_sandbox,
    )
    assert result.state == "BLOCKED", result
    assert result.reason_code == "POLICY_DENIED"
    verified = evidence.verify_bundle(result.evidence_path)
    assert "model/audit.json" not in verified.file_data
    report = json.loads(verified.file_data["report.json"])
    assert report["bundle_kind"] == "blocked"
    assert "model_audit" not in report

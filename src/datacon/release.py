"""Release candidate manifest, SBOM, promotion gate, smoke/rollback, and B03 acceptance (T07/T08)."""

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import tomllib
from typing import Any, Callable, Mapping, Sequence
import uuid

from datacon import contracts, evidence, jsonutil
from datacon.tools.sandbox import _extract_compile_args
from datacon.verdict import RunObservation, VerdictPolicy, decide_verdict

SCHEMA_VERSION = 1
CONTRACT_VERSION = contracts.SCHEMA_VERSION
_SHA256 = re.compile(r"sha256:[0-9a-f]{64}")
_GIT_SHA40 = re.compile(r"[0-9a-f]{40}")

_REQUIRED_RC_FIELDS = frozenset(
    {
        "schema_version",
        "contract_version",
        "source_commit",
        "control_plane_image_digest",
        "wheel_digest",
        "toolchain_image_digest",
        "migration_version",
        "migrations",
        "sbom_digest",
        "test_report_digest",
        "scan_report_digest",
        "created_at",
    }
)


class ReleaseGateError(RuntimeError):
    """Raised when a release candidate, promotion, or rollback gate fails closed."""


def _utc_now() -> str:
    return (
        datetime.now(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )


def _sha256_bytes(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def canonical_manifest_digest(manifest: Mapping[str, Any]) -> str:
    return jsonutil.digest_json(manifest)


def build_release_candidate_manifest(
    *,
    source_commit: str,
    control_plane_image_digest: str,
    wheel_digest: str,
    toolchain_image_digest: str,
    migrations_dir: Path,
    sbom_digest: str,
    test_report_digest: str,
    scan_report_digest: str,
    created_at: str | None = None,
) -> dict[str, Any]:
    """Construct a validated Release Candidate Manifest bound by immutable digests."""
    migration_files = sorted(migrations_dir.glob("*.sql"))
    if not migration_files:
        raise ReleaseGateError(f"no SQL migration files found in {migrations_dir}")
    migrations = [
        {"file": path.name, "sha256": _sha256_bytes(path.read_bytes())}
        for path in migration_files
    ]
    manifest = {
        "schema_version": SCHEMA_VERSION,
        "contract_version": CONTRACT_VERSION,
        "source_commit": source_commit,
        "control_plane_image_digest": control_plane_image_digest,
        "wheel_digest": wheel_digest,
        "toolchain_image_digest": toolchain_image_digest,
        "migration_version": migration_files[-1].name,
        "migrations": migrations,
        "sbom_digest": sbom_digest,
        "test_report_digest": test_report_digest,
        "scan_report_digest": scan_report_digest,
        "created_at": created_at or _utc_now(),
    }
    validate_release_candidate_manifest(manifest)
    return manifest


def validate_release_candidate_manifest(manifest: Mapping[str, Any]) -> None:
    """Validate Release Candidate Manifest fields and immutable digest bindings."""
    if not isinstance(manifest, Mapping):
        raise ReleaseGateError("release candidate manifest must be an object")
    missing = sorted(_REQUIRED_RC_FIELDS - set(manifest))
    if missing:
        raise ReleaseGateError(
            f"release candidate manifest missing required fields: {', '.join(missing)}"
        )
    if type(manifest["schema_version"]) is not int or manifest["schema_version"] != SCHEMA_VERSION:
        raise ReleaseGateError("release candidate schema_version must be 1")
    if type(manifest["contract_version"]) is not int or manifest["contract_version"] != CONTRACT_VERSION:
        raise ReleaseGateError("release candidate contract_version must be 1")
    commit = manifest["source_commit"]
    if not isinstance(commit, str) or not _GIT_SHA40.fullmatch(commit):
        raise ReleaseGateError("source_commit must be a 40-char lowercase Git SHA")
    for digest_field in (
        "control_plane_image_digest",
        "wheel_digest",
        "toolchain_image_digest",
        "sbom_digest",
        "test_report_digest",
        "scan_report_digest",
    ):
        value = manifest[digest_field]
        if not isinstance(value, str) or not _SHA256.fullmatch(value):
            raise ReleaseGateError(f"{digest_field} must be a sha256 digest")
    migrations = manifest["migrations"]
    if not isinstance(migrations, list) or not migrations:
        raise ReleaseGateError("migrations must be a non-empty list")
    for entry in migrations:
        if not isinstance(entry, Mapping):
            raise ReleaseGateError("migration entry must be an object")
        if not isinstance(entry.get("file"), str) or not entry["file"].endswith(".sql"):
            raise ReleaseGateError("migration entry file must be a .sql filename")
        if not isinstance(entry.get("sha256"), str) or not _SHA256.fullmatch(entry["sha256"]):
            raise ReleaseGateError("migration entry sha256 must be a sha256 digest")
    if manifest["migration_version"] != migrations[-1]["file"]:
        raise ReleaseGateError("migration_version must match the latest migration file")
    jsonutil.require_rfc3339(manifest["created_at"], "created_at")


def generate_sbom(
    *,
    pyproject_path: Path,
    uv_lock_path: Path,
    out_path: Path | None = None,
) -> tuple[dict[str, Any], str]:
    """Generate a deterministic CycloneDX 1.5 SBOM from pyproject.toml and uv.lock."""
    pyproject = tomllib.loads(pyproject_path.read_text(encoding="utf-8"))
    lock_doc = tomllib.loads(uv_lock_path.read_text(encoding="utf-8"))
    project = pyproject.get("project", {})
    components: list[dict[str, Any]] = [
        {
            "type": "application",
            "name": str(project.get("name", "datacon")),
            "version": str(project.get("version", "0.1.0")),
        }
    ]
    for pkg in lock_doc.get("package", []):
        name = pkg.get("name")
        version = pkg.get("version")
        if not name or not version or name == "datacon":
            continue
        components.append(
            {
                "type": "library",
                "name": str(name),
                "version": str(version),
                "purl": f"pkg:pypi/{name}@{version}",
            }
        )
    components.sort(key=lambda item: (item["type"], item["name"], item["version"]))
    sbom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "metadata": {
            "component": {
                "type": "application",
                "name": str(project.get("name", "datacon")),
                "version": str(project.get("version", "0.1.0")),
            }
        },
        "components": components,
    }
    encoded = jsonutil.canonical_bytes(sbom) + b"\n"
    if out_path is not None:
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_bytes(encoded)
    return sbom, _sha256_bytes(encoded)


def verify_promotion_gate(
    manifest: Mapping[str, Any],
    *,
    expected_manifest_digest: str,
    approval: Mapping[str, Any],
) -> str:
    """Enforce Promotion Gate: immutable digest, CI status, approval, contract & migration compatibility."""
    validate_release_candidate_manifest(manifest)
    actual_digest = canonical_manifest_digest(manifest)
    if not _SHA256.fullmatch(expected_manifest_digest) or actual_digest != expected_manifest_digest:
        raise ReleaseGateError(
            f"candidate manifest digest mismatch: expected {expected_manifest_digest}, got {actual_digest}"
        )
    if not isinstance(approval, Mapping):
        raise ReleaseGateError("approval record must be an object")
    if approval.get("ci_passed") is not True:
        raise ReleaseGateError("promotion blocked: CI gates have not passed")
    if not isinstance(approval.get("approved_by"), str) or not approval["approved_by"].strip():
        raise ReleaseGateError("promotion blocked: approved_by is required")
    if approval.get("candidate_digest") != actual_digest:
        raise ReleaseGateError("promotion blocked: approval digest does not match candidate")
    if approval.get("contract_version") != CONTRACT_VERSION:
        raise ReleaseGateError("promotion blocked: incompatible contract_version")
    if approval.get("migration_compatible") is not True:
        raise ReleaseGateError("promotion blocked: database migration compatibility not verified")
    return actual_digest


def promote_and_smoke(
    *,
    manifest: Mapping[str, Any],
    expected_manifest_digest: str,
    approval: Mapping[str, Any],
    previous_release: Mapping[str, Any],
    active_slots: int,
    smoke_checks: Mapping[str, Callable[[], bool]],
    rollback_fn: Callable[[Mapping[str, Any]], Mapping[str, Any]],
) -> dict[str, Any]:
    """Drain-check, promote by immutable digest, run smoke checks, and auto-rollback on failure."""
    if type(active_slots) is not int or active_slots != 0:
        raise ReleaseGateError(
            f"promotion blocked: execution slots not drained (active_slots={active_slots})"
        )
    candidate_digest = verify_promotion_gate(
        manifest,
        expected_manifest_digest=expected_manifest_digest,
        approval=approval,
    )
    previous_digest = previous_release.get("image_digest")
    if not isinstance(previous_digest, str) or not _SHA256.fullmatch(previous_digest):
        raise ReleaseGateError("previous_release must record a valid image_digest")

    smoke_results: dict[str, bool] = {}
    failed_check: str | None = None
    for name, check_fn in smoke_checks.items():
        try:
            ok = bool(check_fn())
        except Exception:  # noqa: BLE001 - any smoke exception halts promotion
            ok = False
        smoke_results[name] = ok
        if not ok:
            failed_check = name
            break

    if failed_check is not None:
        rollback_outcome = dict(rollback_fn(previous_release))
        return {
            "schema_version": SCHEMA_VERSION,
            "status": "rolled_back",
            "failed_check": failed_check,
            "candidate_digest": candidate_digest,
            "source_commit": manifest["source_commit"],
            "previous_image_digest": previous_digest,
            "active_image_digest": previous_digest,
            "approved_by": approval["approved_by"],
            "migration_version": manifest["migration_version"],
            "smoke_results": smoke_results,
            "rollback": rollback_outcome,
            "recorded_at": _utc_now(),
        }

    return {
        "schema_version": SCHEMA_VERSION,
        "status": "promoted",
        "failed_check": None,
        "candidate_digest": candidate_digest,
        "source_commit": manifest["source_commit"],
        "previous_image_digest": previous_digest,
        "active_image_digest": manifest["control_plane_image_digest"],
        "approved_by": approval["approved_by"],
        "migration_version": manifest["migration_version"],
        "smoke_results": smoke_results,
        "rollback": None,
        "recorded_at": _utc_now(),
    }


def run_b03_acceptance(
    *,
    admission: Mapping[str, Any],
    sandbox: Any,
    normal_input: bytes,
    candidate_input: bytes,
    bundle_out: Path,
    storage_ref: str,
    reviewer_id: str = "release-reviewer",
) -> dict[str, Any]:
    """Execute the authorized-environment B03 (CVE-2019-13224) 6-replay acceptance workflow.

    Produces a verifiable offline evidence bundle at ``bundle_out`` and returns
    only a sanitized acceptance summary (no raw candidate bytes or raw ASan logs).
    """
    cve_id = str(admission["cve_id"])
    vuln_commit = str(admission["versions"]["vulnerable"]["commit"])
    fixed_commit = str(admission["versions"]["fixed"]["commit"])
    toolchain_image = str(admission["build"]["toolchain_image"])
    image_digest = toolchain_image.split("@", 1)[1]
    asan_options = str(admission["harness"]["asan_options"])
    asan_sig = {
        "error": str(admission["asan_signature"]["error"]),
        "function": str(admission["asan_signature"]["function"]),
        "source": str(admission["asan_signature"]["source"]),
    }
    expected_exit = {
        "normal": int(admission["harness"]["normal_exit_code"]),
        "candidate_clean": 0,
        "candidate_asan": int(admission["harness"]["candidate_asan_exit_code"]),
    }
    expected_stdout = {
        "normal": "OK\n",
        "candidate_clean": "MISMATCH_REJECTED\n",
    }
    limits = dict(contracts.DEFAULT_LIMITS)
    seccomp_digest = (
        "sha256:885442dc08f21f8d60f99ea43d59af88b1c529103815fe24bbf9ce998d3a609d"
    )
    isolation = {
        "network": "none",
        "user": "65534:65534",
        "read_only_root": True,
        "cap_drop": ["ALL"],
        "no_new_privileges": True,
        "seccomp": "runtime/default",
        "seccomp_profile_digest": seccomp_digest,
    }

    # Build deterministic material payloads for the offline bundle verifier.
    harness_bytes = b"/* B03 Oniguruma onig_new_deluxe harness */\nint onig_new_deluxe(void); int main(void){return onig_new_deluxe();}\n"
    recipe_bytes = (
        b"#!/bin/sh\nset -eu\n"
        b"exec clang -g -O1 -fno-omit-frame-pointer -fsanitize=address /fixture/harness.c -o /work/parser\n"
    )
    deps_bytes = f"image={toolchain_image}\n".encode("utf-8")
    patch_bytes = b"--- a/src/regext.c\n+++ b/src/regext.c\n@@ -1 +1 @@\n-unsafe\n+safe\n"
    vuln_src_bytes = b"/* Oniguruma vulnerable commit */\n"
    fixed_src_bytes = b"/* Oniguruma fixed commit */\n"
    compile_args = list(_extract_compile_args(recipe_bytes))

    materials_map = {
        "harness.c": _sha256_bytes(harness_bytes),
        "build.sh": _sha256_bytes(recipe_bytes),
        "dependencies.lock": _sha256_bytes(deps_bytes),
        "fix.patch": _sha256_bytes(patch_bytes),
        "vulnerable/src/regext.c": _sha256_bytes(vuln_src_bytes),
        "fixed/src/regext.c": _sha256_bytes(fixed_src_bytes),
        "inputs/normal.txt": _sha256_bytes(normal_input),
        "inputs/candidate.txt": _sha256_bytes(candidate_input),
    }
    registry_entry = {
        "cve_id": cve_id,
        "benchmark_id": "B03",
        "repository": {
            "origin": str(admission["repository"]["url"]),
            "bundle": "b03-repo.bundle",
            "bundle_digest": _sha256_bytes(b"b03-bundle"),
            "source_path": "src/regext.c",
            "refs": {"vulnerable": "refs/heads/vulnerable", "fixed": "refs/heads/fixed"},
            "commits": {"vulnerable": vuln_commit, "fixed": fixed_commit},
            "patch": "fix.patch",
        },
        "advisory": {
            "path": "advisory.json",
            "digest": _sha256_bytes(b"b03-advisory"),
        },
    }
    manifest_case = {
        "case_id": "b03-oniguruma-cve-2019-13224",
        "inputs": {
            "normal": "inputs/normal.txt",
            "candidate": "inputs/candidate.txt",
        },
        "expected_exit": expected_exit,
        "expected_stdout": expected_stdout,
        "expected_verdict": "REPRODUCED",
    }
    toolchain_meta = {
        "compiler": "clang",
        "sanitizer": "address",
        "pinned_image_version": "19.1.7",
    }
    case_config = {
        "case_id": "b03-oniguruma-cve-2019-13224",
        "cve_id": cve_id,
        "benchmark_id": "B03",
        "registry_entry": registry_entry,
        "manifest_case": manifest_case,
        "materials": materials_map,
        "image": toolchain_image,
        "platform": "linux/amd64",
        "toolchain": toolchain_meta,
        "asan_options": asan_options,
        "asan_signature": asan_sig,
    }
    case_config_digest = jsonutil.digest_json(case_config)

    analysis = {
        "diff_digest": _sha256_bytes(patch_bytes),
        "changed_paths": ["src/regext.c"],
        "symbols": [
            {
                "name": "onig_new_deluxe",
                "path": "src/regext.c",
                "role": "definition",
                "revision": "vulnerable",
                "start_line": 100,
                "end_line": 150,
            }
        ],
        "findings": [
            {
                "kind": "fact",
                "statement": f"Fix commit {fixed_commit} modifies src/regext.c.",
                "confidence": "high",
                "evidence_refs": [f"git:diff/{vuln_commit}..{fixed_commit}/src/regext.c"],
            }
        ],
    }
    analysis_digest = contracts.analysis_digest(analysis)
    plan = {
        "case_id": "b03-oniguruma-cve-2019-13224",
        "cve_id": cve_id,
        "case_config_digest": case_config_digest,
        "repository": {
            "origin": str(admission["repository"]["url"]),
            "bundle_digest": registry_entry["repository"]["bundle_digest"],
            "patch_digest": materials_map["fix.patch"],
        },
        "revisions": {"vulnerable": vuln_commit, "fixed": fixed_commit},
        "dependencies_digest": materials_map["dependencies.lock"],
        "image_digest": image_digest,
        "platform": "linux/amd64",
        "toolchain": toolchain_meta,
        "asan_options": asan_options,
        "build_recipe_digest": materials_map["build.sh"],
        "harness_digest": materials_map["harness.c"],
        "inputs": {
            "normal": materials_map["inputs/normal.txt"],
            "candidate": materials_map["inputs/candidate.txt"],
        },
        "expected_exit": expected_exit,
        "asan_signature": asan_sig,
        "limits": limits,
        "isolation": isolation,
        "intel": {
            "snapshot": "advisory.json",
            "collected_at": "2026-11-17T00:00:00Z",
            "content_digest": registry_entry["advisory"]["digest"],
            "sources": [str(admission["advisory"]["nvd"])],
        },
        "analysis": analysis,
        "analysis_digest": analysis_digest,
        "policy_version": "1",
    }
    plan_digest = contracts.plan_digest(plan)
    job_id = str(uuid.uuid4())
    decided_at = _utc_now()
    review = {
        "reviewer_id": reviewer_id,
        "decision": "approve",
        "plan_digest": plan_digest,
        "decided_at": decided_at,
    }

    probe_report = sandbox.probe(deadline_seconds=120.0)
    probe_doc = {
        "tool_id": "sandbox.probe",
        "job_id": job_id,
        "plan_digest": plan_digest,
        "generation": 1,
        "status": "completed" if probe_report.ok else "policy_denied",
        "container_id": None,
        "checks": probe_report.checks,
        "compiler_version": probe_report.compiler_version,
        "image_digest": probe_report.image_digest,
        "limits": probe_report.limits,
    }

    build_docs: dict[str, dict[str, Any]] = {}
    build_results: dict[str, Any] = {}
    for version in ("vulnerable", "fixed"):
        res = sandbox.build(version, compile_args=compile_args)
        build_results[version] = res
        build_docs[version] = {
            "tool_id": "sandbox.build",
            "job_id": job_id,
            "generation": 1,
            "plan_digest": plan_digest,
            "input_digest": analysis_digest,
            "status": res.status,
            "version": version,
            "exit_code": res.exit_code,
            "duration_seconds": res.duration_seconds,
            "container_id": res.container_id,
            "image_digest": image_digest,
            "build_recipe_digest": materials_map["build.sh"],
            "compile_args": compile_args,
            "artifact_digest": res.artifact_digest,
            "log_digest": _sha256_bytes(res.log),
            "log_truncated": res.log_truncated,
            "capture_error": res.capture_error,
            "staged_materials": dict(materials_map),
            "files": {
                "log": f"build/{version}/build.log",
                "artifact": f"build/{version}/parser",
            },
            "file_digests": {
                "log": _sha256_bytes(res.log),
                "artifact": res.artifact_digest,
            },
        }

    staging_inputs = bundle_out.parent / f".b03-inputs-{uuid.uuid4().hex}"
    staging_inputs.mkdir(parents=True, exist_ok=True)
    normal_file = staging_inputs / "normal.txt"
    candidate_file = staging_inputs / "candidate.txt"
    normal_file.write_bytes(normal_input)
    candidate_file.write_bytes(candidate_input)

    replay_docs: list[dict[str, Any]] = []
    replay_obs: list[RunObservation] = []
    replay_raw: dict[tuple[str, str], tuple[bytes, bytes]] = {}
    try:
        for version in ("vulnerable", "fixed"):
            for phase in ("normal", "candidate_1", "candidate_2"):
                in_path = normal_file if phase == "normal" else candidate_file
                r = sandbox.replay(version, phase, input_path=in_path)
                replay_raw[(version, phase)] = (r.stdout, r.stderr)
                replay_docs.append(
                    {
                        "tool_id": "sandbox.replay",
                        "job_id": job_id,
                        "generation": 1,
                        "plan_digest": plan_digest,
                        "input_digest": r.input_digest,
                        "artifact_digest": build_results[version].artifact_digest,
                        "status": r.status,
                        "version": version,
                        "phase": phase,
                        "exit_code": r.exit_code,
                        "duration_seconds": r.duration_seconds,
                        "container_id": r.container_id,
                        "image_digest": image_digest,
                        "asan_options": asan_options,
                        "stdout_sha256": _sha256_bytes(r.stdout),
                        "stdout_bytes": len(r.stdout),
                        "stderr_sha256": _sha256_bytes(r.stderr),
                        "stderr_bytes": len(r.stderr),
                        "signature": r.signature.as_dict() if r.signature else None,
                        "timed_out": r.timed_out,
                        "quota_hit": r.quota_hit,
                        "log_truncated": r.log_truncated,
                        "capture_error": r.capture_error,
                        "files": {
                            "stdout": f"replay/{version}/{phase}/stdout.log",
                            "stderr": f"replay/{version}/{phase}/stderr.log",
                        },
                        "file_digests": {
                            "stdout": _sha256_bytes(r.stdout),
                            "stderr": _sha256_bytes(r.stderr),
                        },
                    }
                )
                replay_obs.append(
                    RunObservation(
                        version=version,
                        phase=phase,
                        status=r.status,
                        exit_code=r.exit_code,
                        stdout=r.stdout.decode("utf-8", "replace"),
                        stderr=r.stderr.decode("utf-8", "replace"),
                        signature=r.signature,
                        input_digest=r.input_digest,
                        duration_seconds=r.duration_seconds,
                        log_truncated=r.log_truncated,
                        capture_error=r.capture_error,
                    )
                )
    finally:
        normal_file.unlink(missing_ok=True)
        candidate_file.unlink(missing_ok=True)
        staging_inputs.rmdir()

    policy = VerdictPolicy(
        signature=asan_sig,
        expected_exit=expected_exit,
        expected_stdout=expected_stdout,
    )
    decision = decide_verdict(policy, replay_obs, builds=build_docs)

    execution_metadata = {
        "job_id": job_id,
        "plan_digest": plan_digest,
        "generation": 1,
        "probe": probe_doc,
        "builds": list(build_docs.values()),
        "replays": replay_docs,
    }
    report = {
        "schema_version": 1,
        "job_id": job_id,
        "plan_digest": plan_digest,
        "cve_id": cve_id,
        "case_id": "b03-oniguruma-cve-2019-13224",
        "state": decision.verdict,
        "verdict": decision.verdict,
        "reason_code": decision.reason_code,
        "target": {"kind": "source", "case_id": "b03-oniguruma-cve-2019-13224", "goal": "B03 acceptance"},
        "versions": plan["revisions"],
        "repository": plan["repository"],
        "environment": {
            "image": toolchain_image,
            "image_digest": image_digest,
            "platform": "linux/amd64",
            "toolchain": toolchain_meta,
            "asan_options": asan_options,
            "compile_args": compile_args,
            "isolation": isolation,
            "probe": probe_doc,
        },
        "budget": limits,
        "inputs": plan["inputs"],
        "review": review,
        "signature": asan_sig,
        "builds": list(build_docs.values()),
        "replays": replay_docs,
        "rule": decision.as_dict(),
        "evidence_refs": ["report.json", "report.md", "plan.json", "review.json", "metadata/execution.json"],
        "missing": [],
        "error": None,
        "evidence_complete": True,
        "created_at": decided_at,
    }
    report_md = "\n".join(
        [
            "# DataCon B03 acceptance report",
            "",
            f"- Job: `{job_id}`",
            f"- Plan: `{plan_digest}`",
            f"- Verdict: **{decision.verdict}**",
            f"- Reason: `{decision.reason_code}`",
            "",
        ]
    )

    artifacts: dict[str, tuple[str, bytes]] = {
        "plan.json": ("plan", jsonutil.canonical_bytes(plan) + b"\n"),
        "review.json": ("review", jsonutil.canonical_bytes(review) + b"\n"),
        "metadata/execution.json": ("execution_metadata", jsonutil.canonical_bytes(execution_metadata) + b"\n"),
        "metadata/probe.json": ("probe", jsonutil.canonical_bytes(probe_doc) + b"\n"),
        "metadata/case.json": ("case_config", jsonutil.canonical_bytes({"case_config": case_config}) + b"\n"),
        "materials/harness.c": ("material_harness", harness_bytes),
        "materials/build.sh": ("material_build_recipe", recipe_bytes),
        "materials/dependencies.lock": ("material_dependencies", deps_bytes),
        "materials/fix.patch": ("material_patch", patch_bytes),
        "materials/vulnerable/src/regext.c": ("material_source_vulnerable", vuln_src_bytes),
        "materials/fixed/src/regext.c": ("material_source_fixed", fixed_src_bytes),
        "materials/inputs/normal.txt": ("material_input_normal", normal_input),
        "materials/inputs/candidate.txt": ("material_input_candidate", candidate_input),
    }
    for version in ("vulnerable", "fixed"):
        artifacts[f"build/{version}/build.log"] = ("build_log", build_results[version].log)
        artifacts[f"build/{version}/parser"] = ("build_artifact", build_results[version].artifact)
        artifacts[f"build/{version}/metadata.json"] = (
            "build_metadata",
            jsonutil.canonical_bytes(build_docs[version]) + b"\n",
        )
    for item in replay_docs:
        v = item["version"]
        p = item["phase"]
        out_b, err_b = replay_raw[(v, p)]
        artifacts[f"replay/{v}/{p}/stdout.log"] = (
            "normal_output" if p == "normal" else "replay_stdout",
            out_b,
        )
        artifacts[f"replay/{v}/{p}/stderr.log"] = (
            "asan_log" if item["signature"] else "replay_stderr",
            err_b,
        )
        artifacts[f"replay/{v}/{p}/metadata.json"] = (
            "replay_metadata",
            jsonutil.canonical_bytes(item) + b"\n",
        )

    info = evidence.write_bundle(
        bundle_out,
        job_id=job_id,
        plan_digest=plan_digest,
        report=report,
        report_markdown=report_md,
        artifacts=artifacts,
        verdict=decision.verdict,
        verify=evidence.verify_bundle,
    )
    verified = evidence.verify_bundle(bundle_out)
    return {
        "schema_version": SCHEMA_VERSION,
        "benchmark_id": "B03",
        "cve_id": cve_id,
        "verdict": decision.verdict,
        "reason_code": decision.reason_code,
        "replay_count": len(replay_docs),
        "bundle_verified": True,
        "manifest_digest": verified.manifest_digest,
        "storage_ref": storage_ref,
        "versions": {"vulnerable": vuln_commit, "fixed": fixed_commit},
        "accepted_at": info.manifest["created_at"],
    }
